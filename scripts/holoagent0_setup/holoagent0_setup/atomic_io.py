"""Canonical, durable, no-follow artifact I/O for HoloAgent0 evidence."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import stat
from typing import Mapping


@dataclass(frozen=True)
class ArtifactDescriptor:
    relative_path: str
    sha256: str
    size: int
    inode: int
    device: int


class AtomicIOError(OSError):
    """A path or durability invariant could not be established."""


class AtomicPublicationAmbiguity(AtomicIOError):
    """This call published a specific inode but could not prove final durability."""

    def __init__(self, message: str, expected_artifact: ArtifactDescriptor) -> None:
        super().__init__(message)
        self.expected_artifact = expected_artifact


class CanonicalJSONError(ValueError):
    """Input exceeds the closed canonical evidence data model."""


_MAX_CANONICAL_DEPTH = 64
_MAX_COLLECTION_ITEMS = 1024
_MAX_STRING_BYTES = 1024 * 1024
_MAX_OUTPUT_BYTES = 8 * 1024 * 1024


class _BoundedWriter:
    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._data = bytearray()

    def append(self, text: str) -> None:
        encoded = text.encode("utf-8")
        if len(self._data) + len(encoded) > self._limit:
            raise CanonicalJSONError("canonical JSON output exceeds the byte bound")
        self._data.extend(encoded)

    def finish(self) -> bytes:
        return bytes(self._data)


def canonical_json_bytes(value: object) -> bytes:
    """Return RFC 8785-compatible UTF-8 JSON for the bounded evidence model."""

    try:
        writer = _BoundedWriter(_MAX_OUTPUT_BYTES)
        _encode(value, 0, writer)
        return writer.finish()
    except CanonicalJSONError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise CanonicalJSONError(f"canonical JSON encoding failed: {error}") from error


def _encode(value: object, depth: int, writer: _BoundedWriter) -> None:
    if depth > _MAX_CANONICAL_DEPTH:
        raise CanonicalJSONError("canonical JSON exceeds the depth bound")
    if value is None:
        writer.append("null")
        return
    if value is True:
        writer.append("true")
        return
    if value is False:
        writer.append("false")
        return
    value_type = type(value)
    if value_type is int:
        if not -(2**53 - 1) <= value <= 2**53 - 1:
            raise ValueError("integer is outside the interoperable JSON range")
        writer.append(str(value))
        return
    if value_type is float:
        writer.append(_encode_float(value))
        return
    if value_type is str:
        writer.append(_encoded_string(value))
        return
    if value_type is list:
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise CanonicalJSONError("canonical JSON collection exceeds the item bound")
        writer.append("[")
        for index, item in enumerate(value):
            if index:
                writer.append(",")
            _encode(item, depth + 1, writer)
        writer.append("]")
        return
    if value_type is dict:
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise CanonicalJSONError("canonical JSON collection exceeds the item bound")
        if any(type(key) is not str for key in value):
            raise CanonicalJSONError(
                "canonical JSON object keys must use the exact builtin string type"
            )
        for key in value:
            _validate_string(key)
        writer.append("{")
        ordered = sorted(
            value, key=lambda item: item.encode("utf-16-be", "surrogatepass")
        )
        for index, key in enumerate(ordered):
            if index:
                writer.append(",")
            writer.append(_encoded_string(key))
            writer.append(":")
            _encode(value[key], depth + 1, writer)
        writer.append("}")
        return
    if isinstance(value, (int, float, str, list, tuple, Mapping)):
        raise CanonicalJSONError(
            "canonical JSON values must use exact builtin JSON types"
        )
    raise CanonicalJSONError(f"unsupported canonical JSON value: {value_type.__name__}")


def _validate_string(value: str) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise CanonicalJSONError(
            "canonical JSON string contains a surrogate"
        ) from error
    if len(encoded) > _MAX_STRING_BYTES:
        raise CanonicalJSONError("canonical JSON string exceeds the byte bound")


def _encoded_string(value: str) -> str:
    _validate_string(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _encode_float(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("canonical JSON numbers must be finite")
    if value == 0:
        return "0"
    absolute = abs(value)
    rendered = repr(value).lower()
    if 1e-6 <= absolute < 1e21:
        fixed = format(Decimal(rendered), "f")
        if "." in fixed:
            fixed = fixed.rstrip("0").rstrip(".")
        return fixed
    mantissa, exponent = rendered.split("e") if "e" in rendered else (rendered, "0")
    mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
    exponent_value = int(exponent)
    sign = "+" if exponent_value >= 0 else ""
    return f"{mantissa}e{sign}{exponent_value}"


def atomic_write_json(
    path: Path,
    value: Mapping[str, object],
    mode: int = 0o600,
    *,
    relative_to: Path | None = None,
    parent_fd: int | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
) -> ArtifactDescriptor:
    """Durably replace *path* with same-directory canonical JSON."""

    return _atomic_write(
        path,
        canonical_json_bytes(value),
        mode,
        False,
        relative_to,
        parent_fd,
        expected_parent_identity,
    )


def atomic_write_json_no_replace(
    path: Path,
    value: Mapping[str, object],
    mode: int = 0o600,
    *,
    relative_to: Path | None = None,
    parent_fd: int | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
) -> ArtifactDescriptor:
    """Durably install canonical JSON only when *path* does not exist."""

    return _atomic_write(
        path,
        canonical_json_bytes(value),
        mode,
        True,
        relative_to,
        parent_fd,
        expected_parent_identity,
    )


def _atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    no_replace: bool,
    relative_to: Path | None,
    parent_fd: int | None,
    expected_parent_identity: tuple[int, int] | None,
) -> ArtifactDescriptor:
    if mode & ~0o777 or mode & 0o022:
        raise AtomicIOError("artifact mode must not grant group/other write access")
    path = Path(path)
    parent = path.parent
    try:
        absolute_parent = Path(os.path.abspath(parent))
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise AtomicIOError(f"artifact parent is unavailable: {parent}") from error
    if resolved_parent != absolute_parent:
        raise AtomicIOError("artifact resolved parent differs from lexical parent")
    if not path.name or path.name in {".", ".."}:
        raise AtomicIOError("artifact path has no safe filename")
    relative_path = _relative_path(resolved_parent / path.name, relative_to)

    directory_fd = -1
    temporary_fd = -1
    installed_fd = -1
    temporary_name = f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    installed = False
    publication_proof: ArtifactDescriptor | None = None
    try:
        if parent_fd is None:
            directory_fd = os.open(
                resolved_parent,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
        else:
            directory_fd = os.dup(parent_fd)
        directory_stat = os.fstat(directory_fd)
        _require_directory_identity(
            directory_stat, resolved_parent, expected_parent_identity
        )
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=directory_fd,
        )
        os.fchmod(temporary_fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(temporary_fd, view)
            if written <= 0:
                raise OSError("short artifact write")
            view = view[written:]
        os.fsync(temporary_fd)
        temporary_stat = os.fstat(temporary_fd)
        _require_regular_owned_mode(temporary_stat, mode)
        publication_proof = ArtifactDescriptor(
            relative_path=relative_path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            inode=temporary_stat.st_ino,
            device=temporary_stat.st_dev,
        )
        if no_replace:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        else:
            os.replace(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        installed = True
        if no_replace:
            os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
        _require_directory_identity(
            os.fstat(directory_fd), resolved_parent, expected_parent_identity
        )
        installed_fd = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        installed_stat = os.fstat(installed_fd)
        _require_regular_owned_mode(installed_stat, mode)
        if (
            installed_stat.st_dev,
            installed_stat.st_ino,
            installed_stat.st_size,
        ) != (
            temporary_stat.st_dev,
            temporary_stat.st_ino,
            len(data),
        ):
            raise AtomicIOError("installed artifact identity differs from temporary")
        if _read_all(installed_fd, _MAX_OUTPUT_BYTES) != data:
            raise AtomicIOError("installed artifact content differs from temporary")
        if _stable_file_identity(os.fstat(installed_fd)) != _stable_file_identity(
            installed_stat
        ):
            raise AtomicIOError("installed artifact changed during verification")
        _require_directory_identity(
            os.fstat(directory_fd), resolved_parent, expected_parent_identity
        )
        return_descriptor = _descriptor(relative_path, data, installed_stat)
        _require_stable_requested_binding(
            path,
            relative_to,
            directory_fd,
            installed_fd,
            installed_stat,
            mode,
            data,
            "installed artifact path was replaced or binding changed",
        )
        return return_descriptor
    except FileExistsError:
        raise
    except (OSError, ValueError) as error:
        message = f"atomic write failed for {path.name}: {error}"
        if installed and publication_proof is not None:
            raise AtomicPublicationAmbiguity(message, publication_proof) from error
        raise AtomicIOError(message) from error
    finally:
        if installed_fd >= 0:
            os.close(installed_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if directory_fd >= 0:
            if not installed or no_replace:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            os.close(directory_fd)


def read_json_secure(
    path: Path,
    *,
    expected_mode: int = 0o600,
    relative_to: Path | None = None,
    directory_fd: int | None = None,
) -> tuple[object, ArtifactDescriptor]:
    """Read one stable regular JSON artifact through an ``O_NOFOLLOW`` fd."""

    path = Path(path)
    if not path.name or path.name in {".", ".."}:
        raise AtomicIOError("artifact path has no safe filename")
    walked_directory_fd = -1
    try:
        _lexical_parent, walked_directory_fd, relative_path = _walk_lexical_parent(
            path, relative_to
        )
        directory_stat = os.fstat(walked_directory_fd)
        _require_owned_directory(directory_stat)
        if directory_fd is not None:
            supplied_stat = os.fstat(directory_fd)
            if (supplied_stat.st_dev, supplied_stat.st_ino) != (
                directory_stat.st_dev,
                directory_stat.st_ino,
            ):
                raise AtomicIOError(
                    "artifact path parent differs from retained directory"
                )
    except (AtomicIOError, OSError) as error:
        if walked_directory_fd >= 0:
            os.close(walked_directory_fd)
        if isinstance(error, AtomicIOError):
            raise
        raise AtomicIOError("artifact retained directory is unavailable") from error

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path.name, flags, dir_fd=walked_directory_fd)
    except OSError as error:
        os.close(walked_directory_fd)
        raise AtomicIOError(f"secure artifact open failed: {path}") from error
    try:
        data, before = _read_stable_regular(fd, expected_mode, _MAX_OUTPUT_BYTES)
        try:
            path_stat = os.stat(
                path.name, dir_fd=walked_directory_fd, follow_symlinks=False
            )
        except OSError as error:
            raise AtomicIOError("artifact path was replaced while read") from error
        if (path_stat.st_dev, path_stat.st_ino) != (before.st_dev, before.st_ino):
            raise AtomicIOError("artifact path was replaced while read")
        _require_regular_owned_mode(path_stat, expected_mode)
        value = _decode_canonical_json(data, path)
        return_descriptor = _descriptor(relative_path, data, before)
        _require_stable_requested_binding(
            path,
            relative_to,
            walked_directory_fd,
            fd,
            before,
            expected_mode,
            data,
            "artifact requested binding changed while read",
        )
        return value, return_descriptor
    finally:
        os.close(fd)
        os.close(walked_directory_fd)


def _walk_lexical_parent(path: Path, relative_to: Path | None) -> tuple[Path, int, str]:
    absolute_path = Path(os.path.abspath(path))
    descriptor_root = (
        Path("/") if relative_to is None else Path(os.path.abspath(relative_to))
    )
    try:
        relative_path = absolute_path.relative_to(descriptor_root)
    except ValueError as error:
        raise AtomicIOError("artifact path escapes descriptor root") from error
    if not relative_path.name or relative_path.name in {".", ".."}:
        raise AtomicIOError("artifact path has no safe filename")

    current_fd = -1
    try:
        current_fd = _open_directory_path_no_follow(descriptor_root)
        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        for component in relative_path.parts[:-1]:
            if component in {"", ".", ".."}:
                raise AtomicIOError("artifact path contains an unsafe ancestor")
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        descriptor_path = (
            absolute_path.name if relative_to is None else relative_path.as_posix()
        )
        return absolute_path.parent, current_fd, descriptor_path
    except AtomicIOError:
        if current_fd >= 0:
            os.close(current_fd)
        raise
    except OSError as error:
        if current_fd >= 0:
            os.close(current_fd)
        raise AtomicIOError(
            "artifact lexical ancestor walk failed (symlink or unavailable)"
        ) from error


def _open_directory_path_no_follow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _require_walked_parent_identity(
    path: Path,
    relative_to: Path | None,
    expected_identity: tuple[int, int],
) -> None:
    walked_fd = -1
    try:
        _parent, walked_fd, _relative = _walk_lexical_parent(path, relative_to)
        walked_stat = os.fstat(walked_fd)
        if (walked_stat.st_dev, walked_stat.st_ino) != expected_identity:
            raise AtomicIOError("artifact lexical parent was replaced")
    finally:
        if walked_fd >= 0:
            os.close(walked_fd)


def _decode_canonical_json(data: bytes, path: Path) -> object:
    try:
        if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            raise ValueError("JSON byte-order marks are prohibited")
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite number {token}")
            ),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
        if canonical_json_bytes(value) != data:
            raise ValueError("JSON bytes are not canonical")
        return value
    except (
        CanonicalJSONError,
        OverflowError,
        RecursionError,
        UnicodeError,
        ValueError,
    ) as error:
        raise AtomicIOError(f"artifact contains invalid JSON: {path}") from error


def _read_stable_regular(
    fd: int, expected_mode: int, limit: int
) -> tuple[bytes, os.stat_result]:
    before = os.fstat(fd)
    _require_regular_owned_mode(before, expected_mode)
    if before.st_size > limit:
        raise AtomicIOError("artifact exceeds the JSON input size bound")
    data = _read_all(fd, limit)
    after = os.fstat(fd)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise AtomicIOError("artifact changed while read")
    return data, after


def _require_stable_requested_binding(
    path: Path,
    relative_to: Path | None,
    retained_parent_fd: int,
    retained_file_fd: int,
    expected_file_stat: os.stat_result,
    expected_mode: int,
    expected_data: bytes,
    message: str,
) -> None:
    """Validate retained bytes and requested binding in one bounded cycle."""

    before_parent_fd = -1
    before_path_fd = -1
    after_parent_fd = -1
    final_parent_fd = -1
    final_path_fd = -1
    try:
        _parent, before_parent_fd, _relative = _walk_lexical_parent(path, relative_to)
        retained_parent_before = os.fstat(retained_parent_fd)
        before_parent = os.fstat(before_parent_fd)
        _require_owned_directory(retained_parent_before)
        _require_owned_directory(before_parent)
        parent_snapshot = _stable_file_identity(retained_parent_before)
        if _stable_file_identity(before_parent) != parent_snapshot:
            raise AtomicIOError(message)

        _require_path_identity(
            path.name,
            before_parent_fd,
            expected_file_stat,
            expected_mode,
            message,
        )
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        before_path_fd = os.open(path.name, flags, dir_fd=before_parent_fd)
        before_path_stat = os.fstat(before_path_fd)
        _require_regular_owned_mode(before_path_stat, expected_mode)
        file_snapshot = _stable_file_identity(expected_file_stat)
        if _stable_file_identity(before_path_stat) != file_snapshot:
            raise AtomicIOError(message)

        final_data, retained_file_after = _read_stable_regular(
            retained_file_fd, expected_mode, _MAX_OUTPUT_BYTES
        )
        if (
            final_data != expected_data
            or _stable_file_identity(retained_file_after) != file_snapshot
        ):
            raise AtomicIOError(message)

        _parent, after_parent_fd, _relative = _walk_lexical_parent(path, relative_to)
        retained_parent_after = os.fstat(retained_parent_fd)
        after_parent = os.fstat(after_parent_fd)
        _require_owned_directory(retained_parent_after)
        _require_owned_directory(after_parent)
        if (
            _stable_file_identity(retained_parent_after) != parent_snapshot
            or _stable_file_identity(after_parent) != parent_snapshot
        ):
            raise AtomicIOError(message)
        _require_path_identity(
            path.name,
            after_parent_fd,
            expected_file_stat,
            expected_mode,
            message,
        )

        # Rewalk once more after the path-stat check. The final path-bound open
        # and fstat are the last external identity observations in the cycle.
        _parent, final_parent_fd, _relative = _walk_lexical_parent(path, relative_to)
        final_parent = os.fstat(final_parent_fd)
        if _stable_file_identity(final_parent) != parent_snapshot:
            raise AtomicIOError(message)
        final_path_fd = os.open(path.name, flags, dir_fd=final_parent_fd)
        final_path_stat = os.fstat(final_path_fd)
        _require_regular_owned_mode(final_path_stat, expected_mode)
        if _stable_file_identity(final_path_stat) != file_snapshot:
            raise AtomicIOError(message)
    except AtomicIOError:
        raise
    except OSError as error:
        raise AtomicIOError(message) from error
    finally:
        if final_path_fd >= 0:
            os.close(final_path_fd)
        if final_parent_fd >= 0:
            os.close(final_parent_fd)
        if after_parent_fd >= 0:
            os.close(after_parent_fd)
        if before_path_fd >= 0:
            os.close(before_path_fd)
        if before_parent_fd >= 0:
            os.close(before_parent_fd)


def _require_owned_directory(directory_stat: os.stat_result) -> None:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise AtomicIOError("artifact parent is not a directory")
    if directory_stat.st_uid != os.getuid():
        raise AtomicIOError("artifact parent owner does not match the current user")


def _require_regular_owned_mode(file_stat: os.stat_result, mode: int) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise AtomicIOError("artifact is not a regular file")
    if file_stat.st_uid != os.getuid():
        raise AtomicIOError("artifact owner does not match the current user")
    actual_mode = stat.S_IMODE(file_stat.st_mode)
    if actual_mode != mode:
        raise AtomicIOError(
            f"artifact mode mismatch: expected {mode:#o}, observed {actual_mode:#o}"
        )


def _stable_file_identity(file_stat: os.stat_result) -> tuple[int, ...]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_nlink,
        file_stat.st_uid,
        file_stat.st_gid,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _require_directory_identity(
    directory_stat: os.stat_result,
    lexical_parent: Path,
    expected_identity: tuple[int, int] | None,
) -> None:
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise AtomicIOError("artifact parent is not a directory")
    if directory_stat.st_uid != os.getuid():
        raise AtomicIOError("artifact parent owner does not match the current user")
    identity = (directory_stat.st_dev, directory_stat.st_ino)
    if expected_identity is not None and identity != expected_identity:
        raise AtomicIOError("artifact parent identity differs from retained directory")
    try:
        lexical_stat = os.stat(lexical_parent, follow_symlinks=False)
    except OSError as error:
        raise AtomicIOError("artifact parent was replaced") from error
    if (lexical_stat.st_dev, lexical_stat.st_ino) != identity:
        raise AtomicIOError("artifact parent was replaced")


def _read_all(fd: int, limit: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise AtomicIOError("artifact exceeds the JSON input size bound")
        chunks.append(chunk)


def _reject_duplicate_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _require_path_identity(
    name: str,
    directory_fd: int,
    expected: os.stat_result,
    mode: int,
    message: str,
) -> None:
    try:
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise AtomicIOError(message) from error
    if _stable_file_identity(observed) != _stable_file_identity(expected):
        raise AtomicIOError(message)
    _require_regular_owned_mode(observed, mode)


def _relative_path(path: Path, relative_to: Path | None) -> str:
    if relative_to is None:
        return path.name
    try:
        return path.relative_to(Path(relative_to).resolve(strict=True)).as_posix()
    except (OSError, ValueError) as error:
        raise AtomicIOError("artifact path escapes descriptor root") from error


def _descriptor(
    relative_path: str,
    data: bytes,
    file_stat: os.stat_result,
) -> ArtifactDescriptor:
    return ArtifactDescriptor(
        relative_path=relative_path,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        inode=file_stat.st_ino,
        device=file_stat.st_dev,
    )
