"""Closed standalone invocation and retained run-root creation authority."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import sys
from typing import Callable, Literal, NoReturn, Sequence


_DIRECTORY_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
_RUN_ID_PATTERN = re.compile(r"workstation-offline-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}\Z")


class InvocationError(ValueError):
    """The public invocation or retained path authority is invalid."""


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise InvocationError("invalid offline invocation")


@dataclass(frozen=True)
class _InvocationSources:
    now_utc: Callable[[], datetime]
    token_bytes: Callable[[int], bytes]
    cwd: Callable[[], Path]
    effective_uid: Callable[[], int]


def _lexical_absolute(path: Path | str, *, cwd: Path) -> Path:
    encoded = os.fspath(path)
    cwd_encoded = os.fspath(cwd)
    if (
        type(encoded) is not str
        or not encoded
        or "\x00" in encoded
        or type(cwd_encoded) is not str
        or not cwd_encoded
        or "\x00" in cwd_encoded
        or not os.path.isabs(cwd_encoded)
    ):
        raise InvocationError("offline output root is invalid")
    if not os.path.isabs(encoded):
        encoded = os.path.join(cwd_encoded, encoded)
    return Path(os.path.normpath(encoded))


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _validate_walk(fds: Sequence[int], names: Sequence[str]) -> None:
    for parent_fd, child_fd, name in zip(fds, fds[1:], names):
        opened = os.fstat(child_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or not _same_identity(opened, named)
        ):
            raise InvocationError("offline output path identity is invalid")


def _validate_output_root(identity: os.stat_result, effective_uid: int) -> None:
    if (
        not stat.S_ISDIR(identity.st_mode)
        or identity.st_uid != effective_uid
        or stat.S_IMODE(identity.st_mode) != 0o700
    ):
        raise InvocationError("offline output root is unsafe")


def _open_output_root(
    output_root: Path, *, effective_uid: int, create_final: bool
) -> tuple[int, tuple[int, int]]:
    if (
        not output_root.is_absolute()
        or type(effective_uid) is not int
        or effective_uid < 0
    ):
        raise InvocationError("offline output root is invalid")
    components = output_root.parts[1:]
    fds: list[int] = []
    names: list[str] = []
    retained_fd = -1
    try:
        fds.append(os.open("/", _DIRECTORY_OPEN_FLAGS))
        for index, component in enumerate(components):
            final = index == len(components) - 1
            try:
                child_fd = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=fds[-1],
                )
            except FileNotFoundError:
                if not final or not create_final:
                    raise InvocationError("offline output parent is unavailable")
                _validate_walk(fds, names)
                parent = os.fstat(fds[-1])
                if (
                    not stat.S_ISDIR(parent.st_mode)
                    or parent.st_uid != effective_uid
                    or parent.st_mode & 0o022
                ):
                    raise InvocationError("offline output parent is unsafe")
                os.mkdir(component, mode=0o700, dir_fd=fds[-1])
                child_fd = os.open(
                    component,
                    _DIRECTORY_OPEN_FLAGS,
                    dir_fd=fds[-1],
                )
            fds.append(child_fd)
            names.append(component)
        _validate_walk(fds, names)
        final_identity = os.fstat(fds[-1])
        _validate_output_root(final_identity, effective_uid)
        retained_fd = fds.pop()
        return retained_fd, (final_identity.st_dev, final_identity.st_ino)
    except InvocationError:
        raise
    except OSError as error:
        raise InvocationError("offline output root is unavailable") from error
    finally:
        for descriptor in reversed(fds):
            os.close(descriptor)


class RunRootAuthority:
    """One-shot retained authority to create exactly one generated run root."""

    __slots__ = (
        "_consumed",
        "_effective_uid",
        "_expected_run_root",
        "_output_root",
        "_output_root_fd",
        "_output_root_identity",
        "_run_basename",
    )

    def __new__(cls, *_args: object, **_kwargs: object) -> "RunRootAuthority":
        raise InvocationError("run root authority must be opened")

    @classmethod
    def open(
        cls,
        output_root: Path | str,
        run_basename: str,
        *,
        effective_uid: int | None = None,
    ) -> "RunRootAuthority":
        if (
            type(run_basename) is not str
            or _RUN_ID_PATTERN.fullmatch(run_basename) is None
        ):
            raise InvocationError("run root basename is invalid")
        observed_uid = os.geteuid() if effective_uid is None else effective_uid
        if type(observed_uid) is not int or observed_uid < 0:
            raise InvocationError("effective uid is invalid")
        absolute_root = _lexical_absolute(output_root, cwd=Path.cwd())
        descriptor = -1
        try:
            descriptor, identity = _open_output_root(
                absolute_root,
                effective_uid=observed_uid,
                create_final=True,
            )
            authority = object.__new__(RunRootAuthority)
            authority._consumed = True
            authority._effective_uid = observed_uid
            authority._expected_run_root = absolute_root / run_basename
            authority._output_root = absolute_root
            authority._output_root_fd = descriptor
            authority._output_root_identity = identity
            authority._run_basename = run_basename
            authority._consumed = False
            return authority
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            raise

    @property
    def expected_run_root(self) -> Path:
        return self._expected_run_root

    @property
    def consumed(self) -> bool:
        return self._consumed

    def _validate_retained_output_root(self, descriptor: int) -> None:
        if (
            type(self._effective_uid) is not int
            or self._effective_uid != os.geteuid()
            or type(self._output_root_identity) is not tuple
            or len(self._output_root_identity) != 2
            or any(type(value) is not int for value in self._output_root_identity)
        ):
            raise InvocationError("retained output root authority is invalid")
        retained = os.fstat(descriptor)
        _validate_output_root(retained, self._effective_uid)
        if (retained.st_dev, retained.st_ino) != self._output_root_identity:
            raise InvocationError("retained output root identity drifted")
        observed_fd = -1
        try:
            observed_fd, observed_identity = _open_output_root(
                self._output_root,
                effective_uid=self._effective_uid,
                create_final=False,
            )
            if observed_identity != self._output_root_identity:
                raise InvocationError("output root path identity drifted")
        finally:
            if observed_fd >= 0:
                os.close(observed_fd)

    def create(self, expected_run_root: Path | str) -> Path:
        if getattr(self, "_consumed", True):
            raise InvocationError("run root authority is already consumed")
        self._consumed = True
        descriptor = getattr(self, "_output_root_fd", -1)
        self._output_root_fd = -1
        child_fd = -1
        try:
            if (
                type(self._run_basename) is not str
                or _RUN_ID_PATTERN.fullmatch(self._run_basename) is None
                or not isinstance(self._output_root, Path)
                or not self._output_root.is_absolute()
                or not isinstance(self._expected_run_root, Path)
                or self._expected_run_root != self._output_root / self._run_basename
                or not isinstance(expected_run_root, (str, os.PathLike))
                or Path(expected_run_root) != self._expected_run_root
            ):
                raise InvocationError("run root path is not authorized")
            self._validate_retained_output_root(descriptor)
            os.mkdir(self._run_basename, mode=0o700, dir_fd=descriptor)
            child_fd = os.open(
                self._run_basename,
                _DIRECTORY_OPEN_FLAGS,
                dir_fd=descriptor,
            )
            opened = os.fstat(child_fd)
            named = os.stat(
                self._run_basename,
                dir_fd=descriptor,
                follow_symlinks=False,
            )
            if not _same_identity(opened, named):
                raise InvocationError("created run root identity drifted")
            _validate_output_root(opened, self._effective_uid)
            _validate_output_root(named, self._effective_uid)
            self._validate_retained_output_root(descriptor)
            return self._expected_run_root
        except InvocationError:
            raise
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise InvocationError("run root creation failed") from error
        finally:
            if child_fd >= 0:
                os.close(child_fd)
            if descriptor >= 0:
                os.close(descriptor)

    def close(self) -> None:
        if getattr(self, "_consumed", True):
            return
        self._consumed = True
        descriptor = getattr(self, "_output_root_fd", -1)
        self._output_root_fd = -1
        if descriptor >= 0:
            os.close(descriptor)

    def __reduce_ex__(self, _protocol: int) -> NoReturn:
        raise TypeError("RunRootAuthority cannot be serialized")

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass


@dataclass(frozen=True)
class OfflineInvocation:
    mode: Literal["workstation_offline"]
    output_root: Path
    run_id: str
    invocation_role: Literal["standalone", "child"]
    parent_run_id: str | None
    lineage_nonce: str | None
    run_root_authority: RunRootAuthority | None = None

    @classmethod
    def parse(cls, argv: Sequence[str] | None = None) -> "OfflineInvocation":
        return _parse_offline_invocation(argv)

    @property
    def result_path(self) -> Path:
        return self.output_root / self.run_id / "result.json"


_SYSTEM_SOURCES = _InvocationSources(
    now_utc=lambda: datetime.now(timezone.utc),
    token_bytes=os.urandom,
    cwd=Path.cwd,
    effective_uid=os.geteuid,
)


def _parse_offline_invocation(
    argv: Sequence[str] | None = None,
    *,
    sources: _InvocationSources = _SYSTEM_SOURCES,
) -> OfflineInvocation:
    if type(sources) is not _InvocationSources:
        raise InvocationError("offline invocation sources are invalid")
    arguments = list(sys.argv[1:] if argv is None else argv)
    if any(type(argument) is not str for argument in arguments):
        raise InvocationError("invalid offline invocation")
    parser = _ClosedArgumentParser(allow_abbrev=False)
    parser.add_argument("--output-root", required=True)
    parsed = parser.parse_args(arguments)
    occurrences = sum(
        argument == "--output-root" or argument.startswith("--output-root=")
        for argument in arguments
    )
    if occurrences != 1:
        raise InvocationError("invalid offline invocation")
    try:
        observed_uid = sources.effective_uid()
        if type(observed_uid) is not int or observed_uid < 0:
            raise InvocationError("effective uid is invalid")
        output_root = _lexical_absolute(parsed.output_root, cwd=sources.cwd())
        now = sources.now_utc()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise InvocationError("offline invocation clock is invalid")
        if now.utcoffset().total_seconds() != 0:
            raise InvocationError("offline invocation clock is not UTC")
        random_material = sources.token_bytes(16)
        if type(random_material) is not bytes or len(random_material) != 16:
            raise InvocationError("offline invocation randomness is invalid")
        run_id = (
            f"workstation-offline-{now.strftime('%Y%m%dT%H%M%SZ')}-"
            f"{random_material.hex()}"
        )
        authority = RunRootAuthority.open(
            output_root,
            run_id,
            effective_uid=observed_uid,
        )
    except InvocationError:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise InvocationError("invalid offline invocation") from error
    try:
        return OfflineInvocation(
            mode="workstation_offline",
            output_root=output_root,
            run_id=run_id,
            invocation_role="standalone",
            parent_run_id=None,
            lineage_nonce=None,
            run_root_authority=authority,
        )
    except Exception:
        authority.close()
        raise
