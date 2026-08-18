"""Read-only gates for the pinned semantic source and asset closures."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import stat
import subprocess
from typing import Any, Mapping


SOURCE_LOCK_SCHEMA = "holoagent0-semantic-source-manifest-v1"
ASSET_LOCK_SCHEMA = "holoagent0-icra-ic4f-assets-v1"
SOURCE_COMMIT = "ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8"
REVIEWED_README_OVERRIDE = (
    "nav_agent/README.md",
    "d862782b3661e2f2cf155d6e006f11c27063a6b0",
    "100644",
    "291eea5e1969497760c5c48c62a4a04623a09eb6",
)
APPROVED_PATH_COUNT = 73
APPROVED_PATH_SET_SHA256 = (
    "968b39b7a16021b65e4d0adbcc33528007d42c7d4c52aee03f9c70c563ad50dc"
)
CANONICAL_ASSET_ALGORITHM = "sha256-content-lines-v1"
REVIEWED_GIT = Path("/usr/bin/git")
READ_CHUNK_BYTES = 1024 * 1024
GIT_TIMEOUT_SECONDS = 15
GIT_OUTPUT_LIMIT_BYTES = 1024 * 1024
# TODO(Task 4): remove this temporary host-bound compatibility constant together
# with the Mapping branches in measure_approved_asset_roots/verify_asset_lock.
# New callers must construct HandoverPaths from the two deployment roots.
APPROVED_ASSET_ROOTS = {
    "graph": Path(
        "/home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/"
        "icra_ic4f/graph_20260629211448"
    ),
    "dataset": Path("/mnt/data/jihun/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f"),
    "checkpoint": Path(
        "/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/open_clip_pytorch_model.bin"
    ),
}
APPROVED_ASSETS = (
    (
        "graph",
        "directory",
        "scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448",
        1229,
        150_066_065,
        "6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050",
    ),
    (
        "dataset",
        "directory",
        "rgbd_datasets/icra_ic4f",
        5360,
        2_391_476_669,
        "a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913",
    ),
    (
        "checkpoint",
        "file",
        "checkpoints/open_clip_pytorch_model.bin",
        1,
        1_710_631_365,
        "5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b",
    ),
)


class SourceGateError(RuntimeError):
    """A pinned source invariant failed."""

    def __init__(
        self, reason: str, detail: str, *, paths: tuple[str, ...] = ()
    ) -> None:
        self.reason = reason
        self.paths = paths
        super().__init__(f"{reason}: {detail}")


class AssetGateError(RuntimeError):
    """A pinned semantic asset invariant failed."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}")


@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    mode: int


@dataclass(frozen=True, init=False)
class HandoverPaths:
    repository_root: Path
    data_root: Path
    graph: Path
    dataset: Path
    checkpoint: Path
    asset_lock: Path
    identities: tuple[PathIdentity, ...]

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError("HandoverPaths must be constructed with from_roots")

    @classmethod
    def from_roots(cls, repository_root: Path, data_root: Path) -> "HandoverPaths":
        """Derive and retain the complete path closure from exactly two roots."""
        repository = _normalized_absolute_path(
            repository_root, "repository_root", "HANDOVER"
        )
        data = _normalized_absolute_path(data_root, "data_root", "HANDOVER")
        root_specs = (
            ("repository_root", repository, "directory"),
            ("data_root", data, "directory"),
        )
        root_identities = tuple(
            _snapshot_handover_path(path, role, kind) for role, path, kind in root_specs
        )
        if _paths_overlap(repository, data):
            raise AssetGateError(
                "HANDOVER_PATH_OVERLAP",
                "repository_root and data_root must be disjoint",
            )

        graph = (
            data
            / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
        )
        dataset = data / "fsr_vln/rgbd_datasets/icra_ic4f"
        checkpoint = data / "fsr_vln/checkpoints/open_clip_pytorch_model.bin"
        asset_lock = (
            repository / "scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json"
        )
        derived_specs = (
            ("graph", graph, "directory"),
            ("dataset", dataset, "directory"),
            ("checkpoint", checkpoint, "regular_file"),
            ("asset_lock", asset_lock, "regular_file"),
        )
        derived_identities = tuple(
            _snapshot_handover_path(path, role, kind)
            for role, path, kind in derived_specs
        )
        instance = object.__new__(cls)
        for field, value in (
            ("repository_root", repository),
            ("data_root", data),
            ("graph", graph),
            ("dataset", dataset),
            ("checkpoint", checkpoint),
            ("asset_lock", asset_lock),
            ("identities", root_identities + derived_identities),
        ):
            object.__setattr__(instance, field, value)
        return instance

    def revalidate(self) -> None:
        """Fail closed unless every retained path still names its exact object."""
        kinds = (
            "directory",
            "directory",
            "directory",
            "directory",
            "regular_file",
            "regular_file",
        )
        roles = (
            "repository_root",
            "data_root",
            "graph",
            "dataset",
            "checkpoint",
            "asset_lock",
        )
        for expected, role, kind in zip(self.identities, roles, kinds):
            try:
                actual = _snapshot_handover_path(expected.path, role, kind)
            except AssetGateError as error:
                raise AssetGateError(
                    "HANDOVER_PATH_IDENTITY_CHANGED",
                    f"{role}: {error}",
                ) from error
            if actual != expected:
                raise AssetGateError(
                    "HANDOVER_PATH_IDENTITY_CHANGED",
                    f"{role}: device, inode, or mode changed",
                )


def _normalized_absolute_path(value: Path, role: str, prefix: str) -> Path:
    try:
        raw = os.fspath(value)
    except TypeError as error:
        raise AssetGateError(
            f"{prefix}_PATH_INVALID", f"{role}: path-like value required"
        ) from error
    if not isinstance(raw, str):
        raise AssetGateError(f"{prefix}_PATH_INVALID", f"{role}: text path required")
    path = Path(raw)
    if not path.is_absolute():
        raise AssetGateError(f"{prefix}_PATH_NOT_ABSOLUTE", f"{role}: {raw}")
    if raw != os.path.normpath(raw) or raw != path.as_posix():
        raise AssetGateError(f"{prefix}_PATH_NOT_NORMALIZED", f"{role}: {raw}")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _identity_triplet(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode


def _lstat_without_symlink_components(path: Path, role: str) -> os.stat_result:
    current = Path(path.anchor)
    final = current.lstat()
    for component in path.parts[1:]:
        current /= component
        final = current.lstat()
        if stat.S_ISLNK(final.st_mode):
            raise AssetGateError(
                "HANDOVER_PATH_ALIAS",
                f"{role}: symlink component is forbidden: {current}",
            )
    return final


def _open_absolute_no_follow(path: Path, *, directory: bool) -> int:
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path.anchor, directory_flags)
    try:
        components = path.parts[1:]
        for index, component in enumerate(components):
            final = index == len(components) - 1
            flags = (
                directory_flags
                if not final or directory
                else os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            )
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _snapshot_handover_path(path: Path, role: str, kind: str) -> PathIdentity:
    try:
        before = _lstat_without_symlink_components(path, role)
        expected_type = stat.S_ISDIR if kind == "directory" else stat.S_ISREG
        if not expected_type(before.st_mode):
            raise AssetGateError(
                "HANDOVER_PATH_TYPE_MISMATCH",
                f"{role}: expected {kind}: {path}",
            )
        descriptor = _open_absolute_no_follow(path, directory=kind == "directory")
        try:
            opened = os.fstat(descriptor)
            after = os.stat(path, follow_symlinks=False)
        finally:
            os.close(descriptor)
        if _identity_triplet(before) != _identity_triplet(opened) or _identity_triplet(
            before
        ) != _identity_triplet(after):
            raise AssetGateError(
                "HANDOVER_PATH_IDENTITY_CHANGED",
                f"{role}: identity changed while validating: {path}",
            )
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise AssetGateError(
                "HANDOVER_PATH_ALIAS", f"{role}: cannot resolve strictly: {path}"
            ) from error
        if resolved != path:
            raise AssetGateError(
                "HANDOVER_PATH_ALIAS",
                f"{role}: spelling does not equal strict resolution: {path}",
            )
        return PathIdentity(path, before.st_dev, before.st_ino, before.st_mode)
    except AssetGateError:
        raise
    except FileNotFoundError as error:
        raise AssetGateError("HANDOVER_PATH_UNAVAILABLE", f"{role}: {path}") from error
    except OSError as error:
        raise AssetGateError(
            "HANDOVER_PATH_UNAVAILABLE", f"{role}: {path}: {error}"
        ) from error


@dataclass(frozen=True)
class SourceEntry:
    path: str
    mode: str
    kind: str
    git_oid: str


@dataclass(frozen=True)
class ReviewedSourceOverride:
    path: str
    commit: str
    mode: str
    git_oid: str


@dataclass(frozen=True)
class SourceLock:
    schema_version: str
    commit: str
    path_set_sha256: str
    entries: tuple[SourceEntry, ...]
    reviewed_overrides: tuple[ReviewedSourceOverride, ...]


@dataclass(frozen=True)
class SourceVerification:
    commit: str
    verified_count: int
    provenance: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class AssetSpec:
    role: str
    kind: str
    relative_path: str
    file_count: int
    byte_count: int | None
    sha256: str
    files: tuple["AssetFileSpec", ...]


@dataclass(frozen=True)
class AssetFileSpec:
    relative_path: str
    kind: str
    mode: str
    byte_size: int
    sha256: str
    symlink_target: str | None


@dataclass(frozen=True)
class CycloneConfigSpec:
    role: str
    participant_index: int
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class AssetLock:
    schema_version: str
    canonical_manifest_algorithm: str
    graph_identity: str
    graph_counts: tuple[int, int, int]
    structured_query_sha256: str
    room_name_mapping: tuple[str, str, str]
    room_name_mapping_sha256: str
    assets: tuple[AssetSpec, ...]
    cyclone_config_set_sha256: str
    cyclone_configs: tuple[CycloneConfigSpec, ...]


@dataclass(frozen=True)
class AssetManifest:
    file_count: int
    byte_count: int
    sha256: str
    files: tuple[AssetFileSpec, ...]


def _closed(document: Mapping[str, Any], keys: set[str], subject: str) -> None:
    actual = set(document)
    if actual != keys:
        raise ValueError(
            f"{subject} uses a closed schema; expected {sorted(keys)}, "
            f"got {sorted(actual)}"
        )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON object key: {key}")
        document[key] = value
    return document


def _read_document(source: Path | Mapping[str, Any], error_type: type[RuntimeError]):
    if isinstance(source, Mapping):
        return dict(source)
    try:
        document = json.loads(
            Path(source).read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise error_type("LOCK_INVALID", str(error)) from error
    if not isinstance(document, dict):
        raise error_type("LOCK_INVALID", "lock root must be an object")
    return document


def _safe_relative_path(value: Any, subject: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{subject} must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ValueError(f"{subject} must be a normalized repository-relative path")
    return value


def _safe_asset_relative_path(value: Any, subject: str) -> str:
    if not isinstance(value, str) or not value or value == ".":
        raise ValueError(f"{subject} must be a normalized relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or path.as_posix() != value
    ):
        raise ValueError(f"{subject} must be a normalized relative POSIX path")
    return value


def _hex_digest(value: Any, length: int, subject: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{subject} must be {length} lowercase hexadecimal characters")
    return value


def load_source_lock(source: Path | Mapping[str, Any]) -> SourceLock:
    """Load and fully validate the closed 73-path source lock."""
    try:
        document = _read_document(source, SourceGateError)
        _closed(
            document,
            {
                "schema_version",
                "commit",
                "path_set_sha256",
                "entries",
                "reviewed_overrides",
            },
            "source lock",
        )
        if document["schema_version"] != SOURCE_LOCK_SCHEMA:
            raise ValueError("unsupported source lock schema")
        if document["commit"] != SOURCE_COMMIT:
            raise ValueError("source lock commit is not the approved immutable commit")
        path_set_digest = _hex_digest(
            document["path_set_sha256"], 64, "source path-set digest"
        )
        raw_entries = document["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError("source entries must be an array")
        entries = []
        for raw in raw_entries:
            if not isinstance(raw, dict):
                raise ValueError("source entry must be an object")
            _closed(raw, {"path", "mode", "kind", "git_oid"}, "source entry")
            path = _safe_relative_path(raw["path"], "source entry path")
            mode = raw["mode"]
            if mode not in {"100644", "100755", "120000"}:
                raise ValueError(f"unsupported source mode for {path}")
            if raw["kind"] != "blob":
                raise ValueError(f"source entry {path} is not a Git blob")
            entries.append(
                SourceEntry(
                    path=path,
                    mode=mode,
                    kind="blob",
                    git_oid=_hex_digest(raw["git_oid"], 40, f"Git OID for {path}"),
                )
            )

        raw_overrides = document["reviewed_overrides"]
        if not isinstance(raw_overrides, list) or len(raw_overrides) != 1:
            raise ValueError("source lock must contain the one reviewed override")
        raw_override = raw_overrides[0]
        if not isinstance(raw_override, dict):
            raise ValueError("reviewed override must be an object")
        _closed(
            raw_override,
            {"path", "commit", "mode", "git_oid"},
            "reviewed override",
        )
        override_mode = raw_override["mode"]
        if override_mode != "100644":
            raise ValueError("reviewed override mode is not the approved README mode")
        override = ReviewedSourceOverride(
            path=_safe_relative_path(raw_override["path"], "reviewed override path"),
            commit=_hex_digest(raw_override["commit"], 40, "reviewed override commit"),
            mode=override_mode,
            git_oid=_hex_digest(
                raw_override["git_oid"], 40, "reviewed override Git OID"
            ),
        )
        if (override.path, override.commit, override.mode, override.git_oid) != (
            REVIEWED_README_OVERRIDE
        ):
            raise ValueError("reviewed override differs from the approved README pin")

        paths = tuple(entry.path for entry in entries)
        calculated = hashlib.sha256(
            "".join(f"{path}\n" for path in paths).encode("utf-8")
        ).hexdigest()
        if (
            len(paths) != APPROVED_PATH_COUNT
            or paths != tuple(sorted(paths))
            or len(set(paths)) != len(paths)
            or path_set_digest != APPROVED_PATH_SET_SHA256
            or calculated != APPROVED_PATH_SET_SHA256
        ):
            raise ValueError("source entries do not match the exact approved path set")
        override_entry = next(
            (entry for entry in entries if entry.path == override.path), None
        )
        if (
            override_entry is None
            or override_entry.mode != override.mode
            or override_entry.git_oid != override.git_oid
        ):
            raise ValueError("reviewed override is not bound to its source entry")
        return SourceLock(
            schema_version=SOURCE_LOCK_SCHEMA,
            commit=SOURCE_COMMIT,
            path_set_sha256=path_set_digest,
            entries=tuple(entries),
            reviewed_overrides=(override,),
        )
    except SourceGateError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise SourceGateError("SOURCE_LOCK_INVALID", str(error)) from error


def _run_git(repository_root: Path, arguments: list[str]) -> str:
    if REVIEWED_GIT.is_symlink() or not REVIEWED_GIT.is_file():
        raise SourceGateError("SOURCE_GIT_UNAVAILABLE", str(REVIEWED_GIT))
    try:
        completed = subprocess.run(
            [str(REVIEWED_GIT), *arguments],
            cwd=repository_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except subprocess.TimeoutExpired as error:
        raise SourceGateError("SOURCE_GIT_UNAVAILABLE", "git timed out") from error
    output_size = len(completed.stdout.encode("utf-8")) + len(
        completed.stderr.encode("utf-8")
    )
    if output_size > GIT_OUTPUT_LIMIT_BYTES:
        raise SourceGateError(
            "SOURCE_GIT_UNAVAILABLE", "git output exceeded the reviewed bound"
        )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "git failed"
        raise SourceGateError("SOURCE_GIT_UNAVAILABLE", detail)
    return completed.stdout


def verify_manifest_git_objects(
    repository_root: Path, source: Path | Mapping[str, Any]
) -> SourceVerification:
    """Verify the lock against Git objects without touching the worktree."""
    root = Path(repository_root).resolve(strict=True)
    lock = load_source_lock(source)
    overridden_paths = {override.path for override in lock.reviewed_overrides}
    baseline_entries = tuple(
        entry for entry in lock.entries if entry.path not in overridden_paths
    )
    output = _run_git(
        root,
        ["ls-tree", lock.commit, "--", *(entry.path for entry in baseline_entries)],
    )
    actual_lines = tuple(output.rstrip("\n").splitlines())
    expected_lines = tuple(
        f"{entry.mode} {entry.kind} {entry.git_oid}\t{entry.path}"
        for entry in baseline_entries
    )
    if actual_lines != expected_lines:
        raise SourceGateError("SOURCE_GIT_MISMATCH", "pinned tree closure mismatch")
    for override in lock.reviewed_overrides:
        override_output = _run_git(
            root, ["ls-tree", override.commit, "--", override.path]
        ).rstrip("\n")
        expected_override = f"{override.mode} blob {override.git_oid}\t{override.path}"
        if override_output != expected_override:
            raise SourceGateError(
                "SOURCE_GIT_MISMATCH", "reviewed README provenance mismatch"
            )
    for entry in lock.entries:
        _run_git(root, ["cat-file", "-e", f"{entry.git_oid}^{{blob}}"])
    return SourceVerification(
        commit=lock.commit,
        verified_count=len(lock.entries),
        provenance=(
            (lock.commit, len(baseline_entries)),
            *((override.commit, 1) for override in lock.reviewed_overrides),
        ),
    )


def _git_blob_oid(content: bytes) -> str:
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def _stream_regular_fd(fd: int, subject: str) -> tuple[int, str, int]:
    """Return size, SHA-256 and mode from one already-open identity-stable FD."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise OSError(f"not a regular file: {subject}")
    digest = hashlib.sha256()
    observed = 0
    while True:
        chunk = os.read(fd, READ_CHUNK_BYTES)
        if not chunk:
            break
        observed += len(chunk)
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    confirmation = hashlib.sha256()
    confirmed = 0
    while True:
        chunk = os.read(fd, READ_CHUNK_BYTES)
        if not chunk:
            break
        confirmed += len(chunk)
        confirmation.update(chunk)
    after = os.fstat(fd)
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mode,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mode,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or (
        observed != before.st_size
        or confirmed != before.st_size
        or digest.digest() != confirmation.digest()
    ):
        raise OSError(f"file identity changed while hashing: {subject}")
    return observed, digest.hexdigest(), before.st_mode


def _stream_regular_file(path: Path) -> tuple[int, str, int]:
    """Return size, SHA-256 and mode from one identity-stable no-follow FD."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        return _stream_regular_fd(fd, str(path))
    finally:
        os.close(fd)


def _open_parent_beneath(root: Path, relative_path: str) -> tuple[int, str]:
    """Open an entry's parent without following any intermediate symlink."""
    parts = PurePosixPath(relative_path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise OSError(f"unsafe relative path: {relative_path}")
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, parts[-1]
    except Exception:
        os.close(directory_fd)
        raise


def _stream_git_blob_beneath(root: Path, relative_path: str) -> tuple[str, int]:
    parent_fd, name = _open_parent_beneath(root, relative_path)
    file_fd = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        file_fd = os.open(name, flags, dir_fd=parent_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError(f"not a regular file: {relative_path}")
        digest = hashlib.sha1()
        digest.update(f"blob {before.st_size}\0".encode("ascii"))
        observed = 0
        while True:
            chunk = os.read(file_fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        os.lseek(file_fd, 0, os.SEEK_SET)
        confirmation = hashlib.sha1()
        confirmation.update(f"blob {before.st_size}\0".encode("ascii"))
        confirmed = 0
        while True:
            chunk = os.read(file_fd, READ_CHUNK_BYTES)
            if not chunk:
                break
            confirmed += len(chunk)
            confirmation.update(chunk)
        after = os.fstat(file_fd)
        path_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        path_identity = (
            path_after.st_dev,
            path_after.st_ino,
            path_after.st_size,
            path_after.st_mode,
            path_after.st_mtime_ns,
            path_after.st_ctime_ns,
        )
        if identity_before != identity_after or identity_before != path_identity:
            raise OSError(f"file identity changed while hashing: {relative_path}")
        if (
            observed != before.st_size
            or confirmed != before.st_size
            or digest.digest() != confirmation.digest()
        ):
            raise OSError(f"file size changed while hashing: {relative_path}")
        return digest.hexdigest(), before.st_mode
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def verify_worktree_entry(repository_root: Path, entry: SourceEntry) -> None:
    """Verify one existing path; this function never restores or edits it."""
    root = Path(repository_root).resolve(strict=True)
    if entry.mode == "120000":
        try:
            parent_fd, name = _open_parent_beneath(root, entry.path)
            try:
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISLNK(before.st_mode):
                    actual_oid = "not-a-symlink"
                else:
                    target = os.readlink(name, dir_fd=parent_fd)
                    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if _identity(before) != _identity(after):
                        actual_oid = "symlink-identity-changed"
                    else:
                        actual_oid = _git_blob_oid(os.fsencode(target))
            finally:
                os.close(parent_fd)
        except FileNotFoundError as error:
            raise SourceGateError(
                "SOURCE_MISSING", entry.path, paths=(entry.path,)
            ) from error
        except OSError as error:
            raise SourceGateError(
                "SOURCE_PATH_ESCAPE", entry.path, paths=(entry.path,)
            ) from error
    else:
        try:
            actual_oid, opened_mode = _stream_git_blob_beneath(root, entry.path)
        except FileNotFoundError as error:
            raise SourceGateError(
                "SOURCE_MISSING", entry.path, paths=(entry.path,)
            ) from error
        except OSError as error:
            raise SourceGateError(
                "SOURCE_PATH_ESCAPE", entry.path, paths=(entry.path,)
            ) from error
        executable = bool(opened_mode & stat.S_IXUSR)
        expected_executable = entry.mode == "100755"
        if executable != expected_executable:
            actual_oid = f"{actual_oid}:mode"
    if actual_oid != entry.git_oid:
        raise SourceGateError("SOURCE_BLOB_MISMATCH", entry.path, paths=(entry.path,))


def verify_source_worktree(
    repository_root: Path, source: Path | Mapping[str, Any]
) -> SourceVerification:
    """Verify all locked paths and report every mismatch deterministically."""
    lock = load_source_lock(source)
    failures: list[tuple[str, str]] = []
    for entry in lock.entries:
        try:
            verify_worktree_entry(repository_root, entry)
        except SourceGateError as error:
            failures.append((entry.path, error.reason))
    if failures:
        paths = tuple(path for path, _reason in failures)
        reasons = {reason for _path, reason in failures}
        reason = reasons.pop() if len(reasons) == 1 else "SOURCE_WORKTREE_MISMATCH"
        raise SourceGateError(reason, ", ".join(paths), paths=paths)
    return SourceVerification(
        commit=lock.commit,
        verified_count=len(lock.entries),
        provenance=(
            (lock.commit, len(lock.entries) - len(lock.reviewed_overrides)),
            *((override.commit, 1) for override in lock.reviewed_overrides),
        ),
    )


def load_asset_lock(source: Path | Mapping[str, Any]) -> AssetLock:
    """Load the closed semantic asset and Cyclone role lock."""
    try:
        document = _read_document(source, AssetGateError)
        _closed(
            document,
            {
                "schema_version",
                "canonical_manifest_algorithm",
                "graph_identity",
                "graph_counts",
                "structured_query_sha256",
                "room_name_mapping",
                "room_name_mapping_sha256",
                "assets",
                "cyclone_config_set_sha256",
                "cyclone_configs",
            },
            "asset lock",
        )
        if document["schema_version"] != ASSET_LOCK_SCHEMA:
            raise ValueError("unsupported asset lock schema")
        if document["canonical_manifest_algorithm"] != CANONICAL_ASSET_ALGORITHM:
            raise ValueError("unsupported canonical asset manifest algorithm")
        if document["graph_identity"] != "icra_ic4f/graph_20260629211448":
            raise ValueError("unexpected semantic graph identity")
        counts_document = document["graph_counts"]
        if not isinstance(counts_document, dict):
            raise ValueError("graph_counts must be an object")
        _closed(counts_document, {"floors", "rooms", "objects"}, "graph counts")
        graph_counts = tuple(
            counts_document[key] for key in ("floors", "rooms", "objects")
        )
        if graph_counts != (1, 3, 497):
            raise ValueError("unexpected semantic graph counts")
        query_digest = _hex_digest(
            document["structured_query_sha256"], 64, "structured query digest"
        )
        if query_digest != (
            "ddcbd21de5223595c515e595192e505289f44b91252ba46643f833a007983047"
        ):
            raise ValueError("unexpected structured query digest")
        room_mapping_document = document["room_name_mapping"]
        if room_mapping_document != ["Pantry", "Office", "Hallway"]:
            raise ValueError("unexpected pinned room-name mapping")
        room_mapping_digest = _hex_digest(
            document["room_name_mapping_sha256"], 64, "room-name mapping digest"
        )
        if room_mapping_digest != (
            "05a9439d16575a1fd76d0bf7bccd7d9f62a24424ac5516f2728c4e04b51d4845"
        ):
            raise ValueError("unexpected room-name mapping digest")

        assets = []
        for raw in document["assets"]:
            if not isinstance(raw, dict):
                raise ValueError("asset must be an object")
            _closed(
                raw,
                {
                    "role",
                    "kind",
                    "relative_path",
                    "file_count",
                    "byte_count",
                    "sha256",
                    "files",
                },
                "asset",
            )
            file_count = raw["file_count"]
            if (
                not isinstance(file_count, int)
                or isinstance(file_count, bool)
                or file_count < 1
            ):
                raise ValueError("asset file_count must be a positive integer")
            byte_count = raw["byte_count"]
            if (
                not isinstance(byte_count, int)
                or isinstance(byte_count, bool)
                or byte_count < 0
            ):
                raise ValueError("asset byte_count must be a non-negative integer")
            raw_files = raw["files"]
            if not isinstance(raw_files, list):
                raise ValueError("asset files must be an array")
            files = []
            for raw_file in raw_files:
                if not isinstance(raw_file, dict):
                    raise ValueError("asset file entry must be an object")
                _closed(
                    raw_file,
                    {
                        "relative_path",
                        "kind",
                        "mode",
                        "byte_size",
                        "sha256",
                        "symlink_target",
                    },
                    "asset file entry",
                )
                relative_path = _safe_asset_relative_path(
                    raw_file["relative_path"], "asset file path"
                )
                kind = raw_file["kind"]
                if kind not in {"regular_file", "symlink"}:
                    raise ValueError(f"unsupported asset file kind for {relative_path}")
                mode = raw_file["mode"]
                if (
                    not isinstance(mode, str)
                    or len(mode) != 4
                    or any(character not in "01234567" for character in mode)
                ):
                    raise ValueError(f"invalid asset mode for {relative_path}")
                byte_size = raw_file["byte_size"]
                if (
                    not isinstance(byte_size, int)
                    or isinstance(byte_size, bool)
                    or byte_size < 0
                ):
                    raise ValueError(f"invalid asset byte size for {relative_path}")
                symlink_target = raw_file["symlink_target"]
                if kind == "regular_file":
                    if symlink_target is not None:
                        raise ValueError(
                            f"regular asset file has a symlink target: {relative_path}"
                        )
                elif not isinstance(symlink_target, str) or not symlink_target:
                    raise ValueError(
                        f"symlink asset entry lacks its target: {relative_path}"
                    )
                elif _symlink_target_escapes(relative_path, symlink_target):
                    raise ValueError(
                        f"symlink target escapes asset root: {relative_path}"
                    )
                digest = _hex_digest(
                    raw_file["sha256"], 64, f"asset digest for {relative_path}"
                )
                if kind == "symlink":
                    expected_digest = hashlib.sha256(
                        b"symlink\0" + os.fsencode(symlink_target)
                    ).hexdigest()
                    if digest != expected_digest or byte_size != 0:
                        raise ValueError(
                            f"symlink metadata is inconsistent: {relative_path}"
                        )
                files.append(
                    AssetFileSpec(
                        relative_path=relative_path,
                        kind=kind,
                        mode=mode,
                        byte_size=byte_size,
                        sha256=digest,
                        symlink_target=symlink_target,
                    )
                )
            paths = tuple(file.relative_path for file in files)
            if paths != tuple(sorted(paths, key=os.fsencode)) or len(paths) != len(
                set(paths)
            ):
                raise ValueError("asset file paths must be bytewise sorted unique")
            if len(files) != file_count:
                raise ValueError("asset file_count differs from its exact inventory")
            if sum(file.byte_size for file in files) != byte_count:
                raise ValueError("asset byte_count differs from its exact inventory")
            root_digest = _canonical_asset_digest(tuple(files))
            if raw["kind"] == "file":
                if len(files) != 1 or files[0].kind != "regular_file":
                    raise ValueError("file asset must contain one regular file")
                root_digest = files[0].sha256
            locked_digest = _hex_digest(raw["sha256"], 64, "asset digest")
            if root_digest != locked_digest:
                raise ValueError("asset root digest differs from its exact inventory")
            assets.append(
                AssetSpec(
                    role=raw["role"],
                    kind=raw["kind"],
                    relative_path=_safe_relative_path(
                        raw["relative_path"], "logical asset path"
                    ),
                    file_count=file_count,
                    byte_count=byte_count,
                    sha256=locked_digest,
                    files=tuple(files),
                )
            )
        if tuple(asset.role for asset in assets) != (
            "graph",
            "dataset",
            "checkpoint",
        ):
            raise ValueError("asset roles are not the approved closed set")
        if (
            tuple(
                (
                    asset.role,
                    asset.kind,
                    asset.relative_path,
                    asset.file_count,
                    asset.byte_count,
                    asset.sha256,
                )
                for asset in assets
            )
            != APPROVED_ASSETS
        ):
            raise ValueError("assets do not match the approved pinned set")

        configs = []
        for raw in document["cyclone_configs"]:
            if not isinstance(raw, dict):
                raise ValueError("Cyclone config must be an object")
            _closed(
                raw,
                {"role", "participant_index", "relative_path", "sha256"},
                "Cyclone config",
            )
            configs.append(
                CycloneConfigSpec(
                    role=raw["role"],
                    participant_index=raw["participant_index"],
                    relative_path=_safe_relative_path(
                        raw["relative_path"], "Cyclone config path"
                    ),
                    sha256=_hex_digest(raw["sha256"], 64, "Cyclone config digest"),
                )
            )
        expected_roles = (
            ("fixture", 0),
            ("query_publisher", 1),
            ("result_subscriber", 2),
            ("graph_inspector", 3),
        )
        if (
            tuple((config.role, config.participant_index) for config in configs)
            != expected_roles
        ):
            raise ValueError("Cyclone roles are not the approved closed set")
        config_set_digest = _hex_digest(
            document["cyclone_config_set_sha256"], 64, "Cyclone config-set digest"
        )
        return AssetLock(
            schema_version=ASSET_LOCK_SCHEMA,
            canonical_manifest_algorithm=CANONICAL_ASSET_ALGORITHM,
            graph_identity=document["graph_identity"],
            graph_counts=graph_counts,  # type: ignore[arg-type]
            structured_query_sha256=query_digest,
            room_name_mapping=tuple(room_mapping_document),  # type: ignore[arg-type]
            room_name_mapping_sha256=room_mapping_digest,
            assets=tuple(assets),
            cyclone_config_set_sha256=config_set_digest,
            cyclone_configs=tuple(configs),
        )
    except AssetGateError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise AssetGateError("ASSET_LOCK_INVALID", str(error)) from error


def _symlink_target_escapes(relative_path: str, target: str) -> bool:
    if not target or "\0" in target or PurePosixPath(target).is_absolute():
        return True
    parent = PurePosixPath(relative_path).parent.as_posix()
    combined = posixpath.normpath(posixpath.join(parent, target))
    return combined == ".." or combined.startswith("../") or combined.startswith("/")


def _canonical_asset_digest(files: tuple[AssetFileSpec, ...]) -> str:
    digest = hashlib.sha256()
    for entry in files:
        try:
            line = f"{entry.sha256}  {entry.relative_path}\n".encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("asset paths must be valid UTF-8") from error
        digest.update(line)
    return digest.hexdigest()


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _mode_string(mode: int) -> str:
    return f"{stat.S_IMODE(mode):04o}"


def _scan_asset_directory(
    directory_fd: int, prefix: PurePosixPath
) -> list[AssetFileSpec]:
    before = os.fstat(directory_fd)
    if not stat.S_ISDIR(before.st_mode):
        raise OSError("asset directory FD is not a directory")
    initial_inventory = tuple(
        (name, _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)))
        for name in sorted(os.listdir(directory_fd), key=os.fsencode)
    )
    names = [name for name, _metadata in initial_inventory]
    entries: list[AssetFileSpec] = []
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    for name in names:
        relative = (prefix / name).as_posix()
        _safe_asset_relative_path(relative, "asset file path")
        initial = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(initial.st_mode):
            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
            try:
                if _identity(os.fstat(child_fd)) != _identity(initial):
                    raise OSError(f"asset directory identity changed: {relative}")
                entries.extend(_scan_asset_directory(child_fd, PurePosixPath(relative)))
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(initial.st_mode):
            file_fd = os.open(name, file_flags, dir_fd=directory_fd)
            try:
                if _identity(os.fstat(file_fd)) != _identity(initial):
                    raise OSError(f"asset file identity changed: {relative}")
                byte_size, digest, opened_mode = _stream_regular_fd(file_fd, relative)
            finally:
                os.close(file_fd)
            entries.append(
                AssetFileSpec(
                    relative_path=relative,
                    kind="regular_file",
                    mode=_mode_string(opened_mode),
                    byte_size=byte_size,
                    sha256=digest,
                    symlink_target=None,
                )
            )
        elif stat.S_ISLNK(initial.st_mode):
            target = os.readlink(name, dir_fd=directory_fd)
            if _symlink_target_escapes(relative, target):
                raise AssetGateError(
                    "ASSET_PATH_ESCAPE", f"symlink escapes asset root: {relative}"
                )
            entries.append(
                AssetFileSpec(
                    relative_path=relative,
                    kind="symlink",
                    mode=_mode_string(initial.st_mode),
                    byte_size=0,
                    sha256=hashlib.sha256(
                        b"symlink\0" + os.fsencode(target)
                    ).hexdigest(),
                    symlink_target=target,
                )
            )
        else:
            raise AssetGateError(
                "ASSET_INVALID", f"unsupported asset entry: {relative}"
            )
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _identity(initial) != _identity(after):
            raise OSError(f"asset path identity changed: {relative}")
    final_inventory = tuple(
        (name, _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)))
        for name in sorted(os.listdir(directory_fd), key=os.fsencode)
    )
    if initial_inventory != final_inventory:
        raise OSError("asset directory inventory changed while hashing")
    if _identity(before) != _identity(os.fstat(directory_fd)):
        raise OSError("asset directory identity changed while hashing")
    return entries


def canonical_asset_manifest(root: Path) -> AssetManifest:
    """Build an exact, byte-sorted inventory with no-follow streaming reads."""
    root = Path(root)
    try:
        root_before = root.lstat()
        if stat.S_ISLNK(root_before.st_mode):
            raise AssetGateError("ASSET_INVALID", f"asset root is a symlink: {root}")
        if stat.S_ISDIR(root_before.st_mode):
            flags = (
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0)
            )
            root_fd = os.open(root, flags)
            try:
                if _identity(root_before) != _identity(os.fstat(root_fd)):
                    raise OSError("asset root identity changed before traversal")
                files = tuple(
                    sorted(
                        _scan_asset_directory(root_fd, PurePosixPath()),
                        key=lambda entry: os.fsencode(entry.relative_path),
                    )
                )
            finally:
                os.close(root_fd)
        elif stat.S_ISREG(root_before.st_mode):
            byte_size, digest, opened_mode = _stream_regular_file(root)
            files = (
                AssetFileSpec(
                    relative_path=root.name,
                    kind="regular_file",
                    mode=_mode_string(opened_mode),
                    byte_size=byte_size,
                    sha256=digest,
                    symlink_target=None,
                ),
            )
        else:
            raise AssetGateError("ASSET_INVALID", f"unsupported asset root: {root}")
        if _identity(root_before) != _identity(root.lstat()):
            raise OSError("asset root identity changed while hashing")
    except FileNotFoundError as error:
        raise AssetGateError("ASSET_UNAVAILABLE", str(root)) from error
    except AssetGateError:
        raise
    except OSError as error:
        raise AssetGateError("ASSET_IDENTITY_CHANGED", str(error)) from error
    root_digest = _canonical_asset_digest(files)
    if stat.S_ISREG(root_before.st_mode):
        root_digest = files[0].sha256
    return AssetManifest(
        file_count=len(files),
        byte_count=sum(entry.byte_size for entry in files),
        sha256=root_digest,
        files=files,
    )


def verify_asset_inventory(root: Path, asset: AssetSpec) -> AssetManifest:
    """Compare the complete on-disk inventory with one immutable lock entry."""
    measured = canonical_asset_manifest(root)
    if (
        measured.file_count != asset.file_count
        or measured.byte_count != asset.byte_count
        or measured.sha256 != asset.sha256
        or measured.files != asset.files
    ):
        raise AssetGateError("ASSET_INVENTORY_MISMATCH", asset.role)
    return measured


def prepare_handover_run_directory(path: Path, paths: HandoverPaths) -> PathIdentity:
    """Open one isolated empty run directory without following path aliases."""
    if not isinstance(paths, HandoverPaths):
        raise AssetGateError(
            "RUN_PATH_INVALID", "a validated HandoverPaths instance is required"
        )
    paths.revalidate()
    run = _normalized_absolute_path(path, "run_directory", "RUN")
    restricted = (
        paths.repository_root,
        paths.data_root,
        paths.graph,
        paths.dataset,
        paths.checkpoint,
        paths.asset_lock,
    )
    if any(_paths_overlap(run, retained) for retained in restricted):
        raise AssetGateError(
            "RUN_PATH_OVERLAP",
            f"run_directory overlaps a retained handover path: {run}",
        )

    parent = run.parent
    try:
        parent_identity = _snapshot_handover_path(
            parent, "run_directory parent", "directory"
        )
    except AssetGateError as error:
        if error.reason == "HANDOVER_PATH_ALIAS":
            reason = "RUN_PATH_ALIAS"
        elif error.reason == "HANDOVER_PATH_UNAVAILABLE":
            reason = "RUN_PARENT_UNAVAILABLE"
        else:
            reason = "RUN_PATH_INVALID"
        raise AssetGateError(reason, str(error)) from error

    parent_fd = -1
    run_fd = -1
    try:
        parent_fd = _open_absolute_no_follow(parent, directory=True)
        if _identity_triplet(os.fstat(parent_fd)) != (
            parent_identity.device,
            parent_identity.inode,
            parent_identity.mode,
        ):
            raise AssetGateError(
                "RUN_IDENTITY_CHANGED", "run_directory parent changed before use"
            )
        try:
            initial = os.stat(run.name, dir_fd=parent_fd, follow_symlinks=False)
            exists = True
        except FileNotFoundError:
            exists = False
            try:
                os.mkdir(run.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError as error:
                raise AssetGateError(
                    "RUN_IDENTITY_CHANGED",
                    "run_directory appeared during atomic creation",
                ) from error
            initial = os.stat(run.name, dir_fd=parent_fd, follow_symlinks=False)

        if stat.S_ISLNK(initial.st_mode):
            raise AssetGateError("RUN_PATH_ALIAS", f"run_directory is a symlink: {run}")
        if not stat.S_ISDIR(initial.st_mode):
            raise AssetGateError(
                "RUN_PATH_INVALID", f"run_directory is not a directory: {run}"
            )
        flags = (
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        run_fd = os.open(run.name, flags, dir_fd=parent_fd)
        opened = os.fstat(run_fd)
        if _identity_triplet(initial) != _identity_triplet(opened):
            raise AssetGateError(
                "RUN_IDENTITY_CHANGED", "run_directory changed while opening"
            )
        if not exists:
            os.fchmod(run_fd, 0o700)
            opened = os.fstat(run_fd)
        if os.listdir(run_fd):
            raise AssetGateError(
                "RUN_DIRECTORY_NOT_EMPTY",
                f"run_directory must be explicitly empty: {run}",
            )
        after_fd = os.fstat(run_fd)
        after_path = os.stat(run.name, dir_fd=parent_fd, follow_symlinks=False)
        if _identity_triplet(opened) != _identity_triplet(
            after_fd
        ) or _identity_triplet(opened) != _identity_triplet(after_path):
            raise AssetGateError(
                "RUN_IDENTITY_CHANGED", "run_directory changed while validating"
            )
        try:
            parent_after = _snapshot_handover_path(
                parent, "run_directory parent", "directory"
            )
        except AssetGateError as error:
            raise AssetGateError("RUN_IDENTITY_CHANGED", str(error)) from error
        if parent_after != parent_identity:
            raise AssetGateError(
                "RUN_IDENTITY_CHANGED", "run_directory parent identity changed"
            )
        paths.revalidate()
        return PathIdentity(run, opened.st_dev, opened.st_ino, opened.st_mode)
    except AssetGateError:
        raise
    except OSError as error:
        raise AssetGateError("RUN_IDENTITY_CHANGED", str(error)) from error
    finally:
        if run_fd >= 0:
            os.close(run_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _validated_asset_roots(asset_roots: Mapping[str, Path]) -> dict[str, Path]:
    if not isinstance(asset_roots, Mapping) or set(asset_roots) != set(
        APPROVED_ASSET_ROOTS
    ):
        raise AssetGateError(
            "ASSET_ROOT_MISMATCH", "asset roots must use the exact approved role set"
        )
    validated = {}
    for role, approved in APPROVED_ASSET_ROOTS.items():
        candidate = Path(asset_roots[role])
        if not candidate.is_absolute() or candidate != approved:
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH", f"{role} does not use its approved root"
            )
        validated[role] = candidate
    return validated


def measure_approved_asset_roots(
    asset_roots: HandoverPaths | Mapping[str, Path],
) -> dict[str, AssetManifest]:
    """Measure only the three explicitly approved roots, never searched roots."""
    if isinstance(asset_roots, HandoverPaths):
        asset_roots.revalidate()
        roots = {
            "graph": asset_roots.graph,
            "dataset": asset_roots.dataset,
            "checkpoint": asset_roots.checkpoint,
        }
        measured = {
            role: canonical_asset_manifest(root) for role, root in roots.items()
        }
        asset_roots.revalidate()
        return measured
    # TODO(Task 4): remove this legacy Mapping branch after semantic migration.
    roots = _validated_asset_roots(asset_roots)
    return {role: canonical_asset_manifest(roots[role]) for role in roots}


def verify_asset_lock(
    asset_roots: HandoverPaths | Mapping[str, Path],
    source: Path | Mapping[str, Any] | None = None,
) -> tuple[AssetManifest, ...]:
    """Verify pinned assets in place; missing assets never receive substitutes."""
    if isinstance(asset_roots, HandoverPaths):
        if source is not None:
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH",
                "HandoverPaths verification always uses its derived asset_lock",
            )
        asset_roots.revalidate()
        roots = {
            "graph": asset_roots.graph,
            "dataset": asset_roots.dataset,
            "checkpoint": asset_roots.checkpoint,
        }
        lock = load_asset_lock(asset_roots.asset_lock)
        if tuple(asset.role for asset in lock.assets) != tuple(roots):
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH", "asset lock does not use the exact role set"
            )
        results = tuple(
            verify_asset_inventory(roots[asset.role], asset) for asset in lock.assets
        )
        asset_roots.revalidate()
        return results
    # TODO(Task 4): remove this legacy Mapping branch after semantic migration.
    if source is None:
        raise AssetGateError(
            "ASSET_ROOT_MISMATCH", "legacy asset verification requires its lock"
        )
    roots = _validated_asset_roots(asset_roots)
    lock = load_asset_lock(source)
    results = []
    for asset in lock.assets:
        results.append(verify_asset_inventory(roots[asset.role], asset))
    return tuple(results)
