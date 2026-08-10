#!/bin/bash
set -euo pipefail
PATH='/usr/bin:/bin'
export PATH
exec /usr/bin/python3.10 - "$0" "$@" <<'PY'
# BEGIN_PROVISIONER_PYTHON
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import signal
import stat
import subprocess
import sys
import tarfile
import time
from typing import Sequence


SOURCE_URL = "https://strace.io/files/6.6/strace-6.6.tar.xz"
SOURCE_SIZE = 2420364
SOURCE_SHA256 = "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
TOP_DIRECTORY = "strace-6.6"
PYTHON = "/usr/bin/python3.10"
DOCKER = "/usr/bin/docker"
BUILD_ENV = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"}
BLOCKING_PHASES = frozenset(
    {
        "archive_transfer",
        "archive_validation",
        "archive_extraction",
        "elf_validation",
        "elf_version",
    }
)
APPROVAL_MARKER = ".holoagent0-install-approved.json"
USAGE = "usage: {script} [--archive ARCHIVE] (--output-dir OUTPUT_DIR | --candidate-evidence FILE)"


class ProvisioningError(RuntimeError):
    pass


class ProcessIdentityError(ProvisioningError):
    pass


class OwnedProcessTimeout(ProvisioningError):
    def __init__(self, argv):
        super().__init__(f"owned process exceeded deadline: {argv[0]}")
        self.argv = tuple(argv)


class OwnedCleanupError(ProvisioningError):
    pass


class PathIdentityError(ProvisioningError):
    pass


class DockerOwnershipError(ProvisioningError):
    pass


class DockerCleanupError(ProvisioningError):
    pass


class ArchiveValidationError(ProvisioningError):
    pass


class CliError(ProvisioningError):
    pass


class PublicationError(ProvisioningError):
    pass


class ProvisioningInterrupted(ProvisioningError):
    def __init__(self, status: int):
        super().__init__(f"interrupted with status {status}")
        self.status = status


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pgid: int
    sid: int
    start_time: int
    state: str


@dataclass(frozen=True)
class ElfPins:
    size: int
    sha256: str
    version_sha256: str
    recipe_sha256: str = ""
    container_image_digest: str = ""


@dataclass
class SourceArchive:
    path: Path
    fd: int
    device: int
    inode: int

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def read_process_identity(pid: int) -> ProcessIdentity:
    text = Path(f"/proc/{int(pid)}/stat").read_text(encoding="ascii")
    closing = text.rfind(")")
    if closing < 0:
        raise ProcessIdentityError("malformed process identity")
    fields = text[closing + 2 :].split()
    if len(fields) < 20:
        raise ProcessIdentityError("short process identity")
    return ProcessIdentity(
        int(pid), int(fields[2]), int(fields[3]), int(fields[19]), fields[0]
    )


class SignalLatch:
    _STATUSES = {signal.SIGHUP: 129, signal.SIGINT: 130, signal.SIGTERM: 143}

    def __init__(self) -> None:
        self._status = 0

    @property
    def status(self) -> int:
        return self._status

    def record(self, signum: int, _frame=None) -> None:
        if self._status == 0:
            self._status = self._STATUSES.get(signum, 3)

    def install(self) -> None:
        for signum in self._STATUSES:
            signal.signal(signum, self.record)

    @contextmanager
    def block_for_cleanup(self):
        # Handlers only latch an integer and return.  Keeping them installed makes
        # the first signal observable during cleanup while Python retries EINTR.
        yield

    def final_status(self, *, cleanup_succeeded: bool, ordinary_status: int) -> int:
        if not cleanup_succeeded:
            return 3
        return self._status or ordinary_status


class OwnedSessionRunner:
    def __init__(
        self,
        *,
        term_grace=0.5,
        kill_grace=1.0,
        identity_reader=read_process_identity,
        signal_latch=None,
    ):
        self.term_grace = float(term_grace)
        self.kill_grace = float(kill_grace)
        self.identity_reader = identity_reader
        self.signal_latch = signal_latch

    def run(self, argv, *, timeout, env=None, on_verified=None, pass_fds=()):
        if not argv or timeout <= 0:
            raise ValueError("owned command and positive timeout are required")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OwnedCleanupError("pidfd process ownership is unavailable")
        if self.signal_latch is not None and self.signal_latch.status:
            raise ProvisioningInterrupted(self.signal_latch.status)
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        inherited = tuple(sorted({release_read, *(int(fd) for fd in pass_fds)}))
        command = [
            PYTHON,
            "-c",
            _RELEASE_TRAMPOLINE,
            str(release_read),
            *map(str, argv),
        ]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            pass_fds=inherited,
            start_new_session=True,
            close_fds=True,
        )
        os.close(release_read)
        pidfd = -1
        released = False
        identity = None
        try:
            pidfd = os.pidfd_open(process.pid, 0)
            first = self.identity_reader(process.pid)
            second = self.identity_reader(process.pid)
            if (
                not _same_process_identity(first, second)
                or first.pid != first.pgid
                or first.pid != first.sid
            ):
                raise ProcessIdentityError(
                    "child did not establish a stable new session"
                )
            identity = first
            if process.poll() is not None:
                raise ProcessIdentityError("child exited before session verification")
            if on_verified is not None:
                on_verified(identity)
            final = self.identity_reader(process.pid)
            if self.signal_latch is not None and self.signal_latch.status:
                raise ProvisioningInterrupted(self.signal_latch.status)
            if (
                not _same_process_identity(final, identity)
                or process.poll() is not None
            ):
                raise ProcessIdentityError("child identity changed before release")
            os.write(release_write, b"G")
            released = True
            os.close(release_write)
            release_write = -1
            deadline = time.monotonic() + timeout
            timed_out = False
            interrupted = 0
            while process.poll() is None:
                if self.signal_latch is not None and self.signal_latch.status:
                    interrupted = self.signal_latch.status
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                time.sleep(0.005)
            returncode = process.poll()
            if returncode is None:
                self._cleanup_session(identity, process)
                returncode = process.poll()
            else:
                self._cleanup_descendants(identity)
            stdout, stderr = process.communicate(timeout=0.2)
            if interrupted:
                raise ProvisioningInterrupted(interrupted)
            if timed_out:
                raise OwnedProcessTimeout(argv)
            return subprocess.CompletedProcess(tuple(argv), returncode, stdout, stderr)
        except BaseException:
            if not released:
                self._abort_unreleased(process, pidfd)
            elif identity is not None and process.poll() is None:
                self._cleanup_session(identity, process)
            raise
        finally:
            if release_write >= 0:
                os.close(release_write)
            if pidfd >= 0:
                os.close(pidfd)

    def _abort_unreleased(self, process, pidfd):
        if process.poll() is None:
            if pidfd >= 0:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
            else:
                raise OwnedCleanupError("unreleased child has no pidfd")
        deadline = time.monotonic() + self.kill_grace
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.005)
        if process.poll() is None:
            raise OwnedCleanupError("unreleased child survived bounded cleanup")
        process.communicate(timeout=0.2)

    def _session_members(self, sid):
        members = []
        for item in Path("/proc").iterdir():
            if not item.name.isdigit():
                continue
            try:
                identity = read_process_identity(int(item.name))
            except (
                FileNotFoundError,
                ProcessLookupError,
                PermissionError,
                ProvisioningError,
            ):
                continue
            if identity.sid == sid and identity.state != "Z":
                members.append(identity)
        return members

    @staticmethod
    def _signal_identity(identity, signum):
        try:
            pidfd = os.pidfd_open(identity.pid, 0)
        except ProcessLookupError:
            return
        try:
            current = read_process_identity(identity.pid)
            if current.start_time != identity.start_time or current.sid != identity.sid:
                raise ProcessIdentityError("process identity changed during cleanup")
            signal.pidfd_send_signal(pidfd, signum)
        except (FileNotFoundError, ProcessLookupError):
            return
        finally:
            os.close(pidfd)

    def _sweep(self, identity, signum, grace):
        for member in self._session_members(identity.sid):
            self._signal_identity(member, signum)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if not self._session_members(identity.sid):
                return True
            time.sleep(0.005)
        return not self._session_members(identity.sid)

    def _cleanup_session(self, identity, process):
        if not self._sweep(identity, signal.SIGTERM, self.term_grace):
            if not self._sweep(identity, signal.SIGKILL, self.kill_grace):
                raise OwnedCleanupError("owned session survived SIGKILL deadline")
        deadline = time.monotonic() + self.kill_grace
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.005)
        if process.poll() is None:
            raise OwnedCleanupError("owned leader was not reaped")

    def _cleanup_descendants(self, identity):
        if self._session_members(identity.sid):
            if not self._sweep(identity, signal.SIGTERM, self.term_grace):
                if not self._sweep(identity, signal.SIGKILL, self.kill_grace):
                    raise OwnedCleanupError(
                        "owned descendant survived SIGKILL deadline"
                    )


_RELEASE_TRAMPOLINE = r"""
import os
import sys
release_fd = int(sys.argv[1])
command = sys.argv[2:]
token = os.read(release_fd, 1)
os.close(release_fd)
if token != b"G" or not command:
    raise SystemExit(125)
os.execvpe(command[0], command, os.environ)
"""


def _same_process_identity(left, right):
    return (
        left.pid,
        left.pgid,
        left.sid,
        left.start_time,
    ) == (
        right.pid,
        right.pgid,
        right.sid,
        right.start_time,
    )


@dataclass
class OwnedPath:
    name: str
    device: int
    inode: int
    fd: int
    is_directory: bool


@dataclass
class StagedInstall:
    path: Path
    parent_fd: int
    root_fd: int
    elf_fd: int
    root_device: int
    root_inode: int
    elf_device: int
    elf_inode: int

    @property
    def parent(self):
        return self.path.parent

    def close(self):
        for attribute in ("elf_fd", "root_fd", "parent_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                os.close(fd)
                setattr(self, attribute, -1)


class OwnedPathRegistry:
    def __init__(self, parent: Path):
        self.parent = Path(parent)
        if (
            not self.parent.is_absolute()
            or self.parent.resolve(strict=True) != self.parent
        ):
            raise PathIdentityError(
                "owned parent must be an absolute canonical directory"
            )
        self.parent_fd = os.open(
            self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )

    def create_file(self, name: str, *, mode: int) -> OwnedPath:
        self._validate_name(name)
        fd = os.open(
            name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            mode,
            dir_fd=self.parent_fd,
        )
        os.fchmod(fd, mode)
        value = os.fstat(fd)
        return OwnedPath(name, value.st_dev, value.st_ino, fd, False)

    def create_directory(self, name: str, *, mode: int) -> OwnedPath:
        self._validate_name(name)
        os.mkdir(name, mode=mode, dir_fd=self.parent_fd)
        fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=self.parent_fd,
        )
        os.fchmod(fd, mode)
        value = os.fstat(fd)
        return OwnedPath(name, value.st_dev, value.st_ino, fd, True)

    def remove_file(self, entry: OwnedPath) -> None:
        self._remove_root(entry, directory=False)

    def remove_tree(self, entry: OwnedPath) -> None:
        current = self._lstat(entry.name)
        if current is None:
            self._close_entry(entry)
            raise PathIdentityError("owned directory disappeared")
        if not self._matches(current, entry) or not stat.S_ISDIR(current.st_mode):
            if stat.S_ISLNK(current.st_mode):
                os.unlink(entry.name, dir_fd=self.parent_fd)
                os.fsync(self.parent_fd)
            self._close_entry(entry)
            raise PathIdentityError("owned directory identity changed")
        retained = os.fstat(entry.fd)
        if not self._matches(retained, entry):
            self._close_entry(entry)
            raise PathIdentityError("retained directory identity changed")
        self._clear_directory(entry.fd)
        os.rmdir(entry.name, dir_fd=self.parent_fd)
        os.fsync(self.parent_fd)
        self._close_entry(entry)

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def forget(self, entry: OwnedPath) -> None:
        self._close_entry(entry)

    @staticmethod
    def _validate_name(name):
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise PathIdentityError("owned path must be a single safe component")

    @staticmethod
    def _matches(value, entry):
        return (value.st_dev, value.st_ino) == (entry.device, entry.inode)

    def _lstat(self, name):
        try:
            return os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _close_entry(entry):
        if entry.fd >= 0:
            os.close(entry.fd)
            entry.fd = -1

    def _remove_root(self, entry, *, directory):
        current = self._lstat(entry.name)
        if current is None:
            self._close_entry(entry)
            raise PathIdentityError("owned path disappeared")
        expected_kind = (
            stat.S_ISDIR(current.st_mode)
            if directory
            else stat.S_ISREG(current.st_mode)
        )
        if not self._matches(current, entry) or not expected_kind:
            if stat.S_ISLNK(current.st_mode):
                os.unlink(entry.name, dir_fd=self.parent_fd)
                os.fsync(self.parent_fd)
            self._close_entry(entry)
            raise PathIdentityError("owned path identity changed")
        retained = os.fstat(entry.fd)
        if not self._matches(retained, entry):
            self._close_entry(entry)
            raise PathIdentityError("retained path identity changed")
        os.unlink(entry.name, dir_fd=self.parent_fd)
        os.fsync(self.parent_fd)
        self._close_entry(entry)

    def _clear_directory(self, directory_fd):
        for name in os.listdir(directory_fd):
            value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(value.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (value.st_dev, value.st_ino):
                        raise PathIdentityError("nested directory identity changed")
                    self._clear_directory(child_fd)
                finally:
                    os.close(child_fd)
                final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) != (value.st_dev, value.st_ino):
                    raise PathIdentityError("nested directory changed before removal")
                os.rmdir(name, dir_fd=directory_fd)
            else:
                final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (final.st_dev, final.st_ino) != (value.st_dev, value.st_ino):
                    raise PathIdentityError("nested path changed before removal")
                os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)


class DockerOwner:
    def __init__(self, docker, runner, *, name, nonce, stabilization, command_timeout):
        self.docker = docker
        self.runner = runner
        self.name = name
        self.nonce = nonce
        self.stabilization = float(stabilization)
        self.command_timeout = float(command_timeout)
        self.attempted = False

    def run_container(self, args, *, timeout, env=None):
        if self._inventory(env):
            raise DockerOwnershipError("container name was already present")
        self.attempted = True
        primary = None
        result = None
        try:
            result = self.runner.run(
                [
                    self.docker,
                    "run",
                    "--name",
                    self.name,
                    "--label",
                    f"holoagent0.strace.owner={self.nonce}",
                    *map(str, args),
                ],
                timeout=timeout,
                env=env,
            )
        except BaseException as error:
            primary = error
        try:
            self.cleanup(env=env)
        except BaseException as cleanup_error:
            raise DockerCleanupError(
                "owned container cleanup failed"
            ) from cleanup_error
        if primary is not None:
            raise primary
        return result

    def cleanup(self, *, env=None):
        deadline = time.monotonic() + self.stabilization
        while True:
            rows = self._inventory(env)
            for row_name, labels in rows:
                if row_name != self.name:
                    continue
                expected = f"holoagent0.strace.owner={self.nonce}"
                if expected not in labels.split(","):
                    raise DockerOwnershipError("container name has a foreign owner")
                inspected = self._command(
                    [
                        self.docker,
                        "inspect",
                        "--format",
                        '{{ index .Config.Labels "holoagent0.strace.owner" }}',
                        self.name,
                    ],
                    env,
                )
                if inspected.stdout.decode("utf-8", "strict").strip() != self.nonce:
                    raise DockerOwnershipError("container label identity changed")
                removed = self._command(
                    [self.docker, "rm", "--force", self.name], env, cleanup=True
                )
                if removed.returncode != 0:
                    raise DockerCleanupError("docker rm failed")
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        if any(name == self.name for name, _labels in self._inventory(env)):
            raise DockerCleanupError("owned container remained after stabilization")
        self.attempted = False

    def _command(self, argv, env, *, cleanup=False):
        try:
            result = self.runner.run(argv, timeout=self.command_timeout, env=env)
        except (OwnedProcessTimeout, OwnedCleanupError) as error:
            raise DockerCleanupError("bounded docker command failed") from error
        if result.returncode != 0 and not cleanup:
            raise DockerCleanupError("docker inspection failed")
        return result

    def _inventory(self, env):
        result = self._command(
            [
                self.docker,
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                f"name=^/{self.name}$",
                "--format",
                "{{.Names}}|{{.Labels}}",
            ],
            env,
        )
        rows = []
        for raw in result.stdout.decode("utf-8", "strict").splitlines():
            if not raw:
                continue
            if raw.count("|") != 1:
                raise DockerCleanupError("undecodable docker inventory")
            rows.append(tuple(raw.split("|", 1)))
        return rows


def run_blocking_phase(phase, argv, runner, *, deadline, **kwargs):
    if phase not in BLOCKING_PHASES or deadline <= 0:
        raise ProvisioningError("invalid blocking phase")
    return runner.run(argv, timeout=deadline, **kwargs)


def validate_archive_members(path: Path, expected_top: str) -> None:
    try:
        with tarfile.open(path, mode="r:xz") as archive_file:
            members = archive_file.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise ArchiveValidationError("invalid archive") from error
    if not members:
        raise ArchiveValidationError("empty archive")
    for member in members:
        path_value = PurePosixPath(member.name)
        if (
            path_value.is_absolute()
            or not path_value.parts
            or path_value.parts[0] != expected_top
            or any(part in {"", ".", ".."} for part in path_value.parts)
        ):
            raise ArchiveValidationError("archive member outside exact top directory")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ArchiveValidationError("unsupported archive member type")
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname)
            if target.is_absolute():
                raise ArchiveValidationError("absolute archive link target")
            base = path_value.parent if member.issym() else PurePosixPath()
            resolved = []
            for part in (base / target).parts:
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not resolved:
                        raise ArchiveValidationError("escaping archive link target")
                    resolved.pop()
                else:
                    resolved.append(part)
            if not resolved or resolved[0] != expected_top:
                raise ArchiveValidationError("escaping archive link target")


def build_container_argv(image_digest, source, build, install, *, uid, gid):
    if not re_fullmatch_sha256_digest(image_digest):
        raise ProvisioningError("invalid build container digest")
    command = (
        "cd /build && /src/configure --prefix=/out --disable-gcc-Werror "
        "&& make -j1 && make install"
    )
    return [
        DOCKER,
        "run",
        "--pull=never",
        "--network=none",
        "--user",
        f"{uid}:{gid}",
        "--env",
        "LC_ALL=C",
        "--env",
        "LANG=C",
        "--env",
        "TZ=UTC",
        "--env",
        "SOURCE_DATE_EPOCH=0",
        "--volume",
        f"{source}:/src:ro",
        "--volume",
        f"{build}:/build",
        "--volume",
        f"{install}:/out",
        f"docker.io/library/gcc@{image_digest}",
        "/bin/sh",
        command,
    ]


def re_fullmatch_sha256_digest(value):
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
    ):
        return False
    return all(character in "0123456789abcdef" for character in value[7:])


def measure_elf_pins(path, runner, *, deadline):
    path = Path(path)
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or path.is_symlink():
        raise PublicationError("runtime must be a regular non-symlink ELF")
    validation = run_blocking_phase(
        "elf_validation",
        [PYTHON, "-c", _ELF_VALIDATOR, str(path)],
        runner,
        deadline=deadline,
    )
    if validation.returncode != 0:
        raise PublicationError("runtime is not linux-x86_64 ELF")
    version = run_blocking_phase(
        "elf_version", [str(path), "--version"], runner, deadline=deadline
    )
    if version.returncode != 0:
        raise PublicationError("runtime version command failed")
    return ElfPins(
        value.st_size,
        _hash_path(path),
        hashlib.sha256(version.stdout).hexdigest(),
    )


def retain_staged_install(path, pins, runner, *, deadline):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise PublicationError("staging path must use a canonical parent")
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    root_fd = -1
    bin_fd = -1
    elf_fd = -1
    try:
        root_fd = os.open(
            path.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        root_value = os.fstat(root_fd)
        bin_fd = os.open(
            "bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
        )
        elf_fd = os.open("strace", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bin_fd)
        elf_value = os.fstat(elf_fd)
        if not stat.S_ISREG(elf_value.st_mode):
            raise PublicationError("staged runtime is not a regular file")
        measurement = StagedInstall(
            path,
            parent_fd,
            root_fd,
            elf_fd,
            root_value.st_dev,
            root_value.st_ino,
            elf_value.st_dev,
            elf_value.st_ino,
        )
        parent_fd = root_fd = elf_fd = -1
    finally:
        if bin_fd >= 0:
            os.close(bin_fd)
        for fd in (elf_fd, root_fd, parent_fd):
            if fd >= 0:
                os.close(fd)
    _verify_retained_measurement(measurement, pins, runner, deadline)
    return measurement


def publish_candidate_evidence(
    destination, evidence, *, before_commit=None, signal_latch=None
):
    destination = _canonical_destination(destination)
    registry = OwnedPathRegistry(destination.parent)
    stage = registry.create_file(
        f".holoagent0-candidate-{secrets.token_hex(16)}", mode=0o600
    )
    linked = False
    try:
        payload = (
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        _write_fd(stage.fd, payload)
        os.fsync(stage.fd)
        if before_commit is not None:
            before_commit(destination.parent / stage.name)
        _raise_if_interrupted(signal_latch)
        current = os.stat(stage.name, dir_fd=registry.parent_fd, follow_symlinks=False)
        retained = os.fstat(stage.fd)
        if (current.st_dev, current.st_ino) != (stage.device, stage.inode) or (
            retained.st_dev,
            retained.st_ino,
        ) != (stage.device, stage.inode):
            raise PublicationError("candidate staging identity changed")
        os.link(
            stage.name,
            destination.name,
            src_dir_fd=registry.parent_fd,
            dst_dir_fd=registry.parent_fd,
            follow_symlinks=False,
        )
        linked = True
        _raise_if_interrupted(signal_latch)
        os.unlink(stage.name, dir_fd=registry.parent_fd)
        os.fsync(registry.parent_fd)
        _raise_if_interrupted(signal_latch)
        registry.forget(stage)
    except BaseException as error:
        try:
            if linked:
                published = os.stat(
                    destination.name, dir_fd=registry.parent_fd, follow_symlinks=False
                )
                if (published.st_dev, published.st_ino) != (stage.device, stage.inode):
                    raise PublicationError("AMBIGUOUS_CANDIDATE_COMMIT")
                os.unlink(destination.name, dir_fd=registry.parent_fd)
            current = registry._lstat(stage.name)
            if current is not None:
                if stat.S_ISLNK(current.st_mode) or (
                    current.st_dev,
                    current.st_ino,
                ) == (
                    stage.device,
                    stage.inode,
                ):
                    os.unlink(stage.name, dir_fd=registry.parent_fd)
                else:
                    raise PublicationError("candidate cleanup identity changed")
            os.fsync(registry.parent_fd)
            registry.forget(stage)
        except BaseException as cleanup_error:
            raise PublicationError("AMBIGUOUS_CANDIDATE_COMMIT") from cleanup_error
        if isinstance(error, FileExistsError):
            raise
        raise PublicationError("candidate publication failed") from error
    finally:
        registry.close()


def publish_install_directory(
    staged,
    destination,
    quarantine,
    measurement,
    pins,
    runner,
    *,
    deadline,
    after_rename=None,
    after_approval=None,
    signal_latch=None,
):
    staged = Path(staged)
    destination = _canonical_destination(destination)
    quarantine = _canonical_destination(quarantine)
    if staged.parent != destination.parent or destination.parent != quarantine.parent:
        raise PublicationError("publication paths must use the same parent")
    if staged != measurement.path or destination.parent != measurement.parent:
        raise PublicationError("staging measurement path changed")
    _verify_staging_name(measurement)
    _verify_retained_measurement(measurement, pins, runner, deadline)
    _raise_if_interrupted(signal_latch)
    committed = False
    installed_fd = -1
    try:
        _rename_no_replace(
            measurement.parent_fd, staged.name, measurement.parent_fd, destination.name
        )
        committed = True
        os.fsync(measurement.parent_fd)
        installed_fd = os.open(
            destination.name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=measurement.parent_fd,
        )
        installed_value = os.fstat(installed_fd)
        if (installed_value.st_dev, installed_value.st_ino) != (
            measurement.root_device,
            measurement.root_inode,
        ):
            raise PublicationError("published install identity changed")
        if after_rename is not None:
            after_rename(destination)
        _raise_if_interrupted(signal_latch)
        marker = _approval_payload(measurement, pins)
        marker_fd = os.open(
            APPROVAL_MARKER,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=installed_fd,
        )
        try:
            _write_fd(marker_fd, marker)
            os.fsync(marker_fd)
        finally:
            os.close(marker_fd)
        os.fsync(installed_fd)
        if after_approval is not None:
            after_approval(destination)
        _raise_if_interrupted(signal_latch)
        _verify_approved_install_at(
            measurement.parent_fd,
            destination.name,
            pins,
            runner,
            deadline=deadline,
        )
        _raise_if_interrupted(signal_latch)
        os.fsync(measurement.parent_fd)
    except BaseException as error:
        if committed:
            try:
                current = os.stat(
                    destination.name,
                    dir_fd=measurement.parent_fd,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) != (
                    measurement.root_device,
                    measurement.root_inode,
                ):
                    raise PublicationError("AMBIGUOUS_INSTALL_IDENTITY")
                _rename_no_replace(
                    measurement.parent_fd,
                    destination.name,
                    measurement.parent_fd,
                    quarantine.name,
                )
                os.fsync(measurement.parent_fd)
            except BaseException as rollback_error:
                raise PublicationError("AMBIGUOUS_INSTALL_COMMIT") from rollback_error
            raise PublicationError("ROLLED_BACK_INSTALL_COMMIT") from error
        raise
    finally:
        if installed_fd >= 0:
            os.close(installed_fd)


def verify_approved_install(destination, pins, runner, *, deadline):
    destination = _canonical_destination(destination)
    parent_fd = os.open(
        destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        _verify_approved_install_at(
            parent_fd, destination.name, pins, runner, deadline=deadline
        )
    finally:
        os.close(parent_fd)


def _verify_approved_install_at(parent_fd, destination_name, pins, runner, *, deadline):
    installed_fd = os.open(
        destination_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    bin_fd = marker_fd = elf_fd = -1
    try:
        installed = os.fstat(installed_fd)
        marker_fd = os.open(
            APPROVAL_MARKER, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=installed_fd
        )
        marker_value = os.fstat(marker_fd)
        if (
            not stat.S_ISREG(marker_value.st_mode)
            or marker_value.st_mode & 0o777 != 0o600
        ):
            raise PublicationError("invalid approval marker")
        payload = os.read(marker_fd, 8193)
        if len(payload) > 8192:
            raise PublicationError("oversized approval marker")
        marker = _closed_json(payload)
        if marker != _approval_payload_from_values(installed, marker, pins):
            raise PublicationError("approval marker is not closed or identity-bound")
        bin_fd = os.open(
            "bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=installed_fd
        )
        elf_fd = os.open("strace", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bin_fd)
        elf_value = os.fstat(elf_fd)
        if (elf_value.st_dev, elf_value.st_ino) != (
            marker["elf_device"],
            marker["elf_inode"],
        ):
            raise PublicationError("approved ELF identity changed")
        _verify_elf_fd(elf_fd, pins, runner, deadline)
    finally:
        for fd in (elf_fd, marker_fd, bin_fd, installed_fd):
            if fd >= 0:
                os.close(fd)


def _raise_if_interrupted(latch):
    if latch is not None and latch.status:
        raise ProvisioningInterrupted(latch.status)


def _canonical_destination(value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path == Path("/"):
        raise PublicationError("destination must be absolute and canonical")
    if path.parent.resolve(strict=True) != path.parent:
        raise PublicationError("destination parent must not traverse a symlink")
    return path


def _rename_no_replace(source_fd, source, destination_fd, destination):
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise PublicationError("renameat2 is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if (
        renameat2(
            source_fd, os.fsencode(source), destination_fd, os.fsencode(destination), 1
        )
        == 0
    ):
        return
    number = ctypes.get_errno()
    if number == errno.EEXIST:
        raise FileExistsError(number, os.strerror(number), destination)
    raise OSError(number, os.strerror(number), destination)


def _write_fd(fd, payload):
    os.ftruncate(fd, 0)
    os.lseek(fd, 0, os.SEEK_SET)
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _hash_fd(fd):
    position = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    os.lseek(fd, position, os.SEEK_SET)
    return digest.hexdigest()


def _hash_path(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _verify_elf_fd(fd, pins, runner, deadline):
    value = os.fstat(fd)
    if not stat.S_ISREG(value.st_mode) or value.st_size != pins.size:
        raise PublicationError("ELF size changed")
    if _hash_fd(fd) != pins.sha256:
        raise PublicationError("ELF digest changed")
    version = run_blocking_phase(
        "elf_version",
        [f"/proc/self/fd/{fd}", "--version"],
        runner,
        deadline=deadline,
        pass_fds=(fd,),
    )
    if (
        version.returncode != 0
        or hashlib.sha256(version.stdout).hexdigest() != pins.version_sha256
    ):
        raise PublicationError("ELF version output changed")


def _verify_retained_measurement(measurement, pins, runner, deadline):
    root = os.fstat(measurement.root_fd)
    elf = os.fstat(measurement.elf_fd)
    if (root.st_dev, root.st_ino) != (measurement.root_device, measurement.root_inode):
        raise PublicationError("retained staging directory changed")
    if (elf.st_dev, elf.st_ino) != (measurement.elf_device, measurement.elf_inode):
        raise PublicationError("retained staging ELF changed")
    _verify_elf_fd(measurement.elf_fd, pins, runner, deadline)


def _verify_staging_name(measurement):
    root = os.stat(
        measurement.path.name,
        dir_fd=measurement.parent_fd,
        follow_symlinks=False,
    )
    if not stat.S_ISDIR(root.st_mode) or (root.st_dev, root.st_ino) != (
        measurement.root_device,
        measurement.root_inode,
    ):
        raise PublicationError("staging directory name changed")
    bin_fd = os.open(
        "bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=measurement.root_fd
    )
    try:
        current_fd = os.open("strace", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bin_fd)
        try:
            current = os.fstat(current_fd)
            if (current.st_dev, current.st_ino) != (
                measurement.elf_device,
                measurement.elf_inode,
            ):
                raise PublicationError("staging ELF name changed")
        finally:
            os.close(current_fd)
    finally:
        os.close(bin_fd)


def _approval_payload(measurement, pins):
    value = {
        "schema_version": "holoagent0.strace-install-approval.v1",
        "state": "APPROVED",
        "install_device": measurement.root_device,
        "install_inode": measurement.root_inode,
        "staging_device": measurement.root_device,
        "staging_inode": measurement.root_inode,
        "elf_device": measurement.elf_device,
        "elf_inode": measurement.elf_inode,
        "elf_size": pins.size,
        "elf_sha256": pins.sha256,
        "version_output_sha256": pins.version_sha256,
        "recipe_sha256": pins.recipe_sha256,
        "container_image_digest": pins.container_image_digest,
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _approval_payload_from_values(installed, marker, pins):
    required = {
        "schema_version",
        "state",
        "install_device",
        "install_inode",
        "staging_device",
        "staging_inode",
        "elf_device",
        "elf_inode",
        "elf_size",
        "elf_sha256",
        "version_output_sha256",
        "recipe_sha256",
        "container_image_digest",
    }
    if set(marker) != required:
        return None
    expected = dict(marker)
    expected.update(
        {
            "schema_version": "holoagent0.strace-install-approval.v1",
            "state": "APPROVED",
            "install_device": installed.st_dev,
            "install_inode": installed.st_ino,
            "staging_device": installed.st_dev,
            "staging_inode": installed.st_ino,
            "elf_size": pins.size,
            "elf_sha256": pins.sha256,
            "version_output_sha256": pins.version_sha256,
            "recipe_sha256": pins.recipe_sha256,
            "container_image_digest": pins.container_image_digest,
        }
    )
    return expected


def _closed_json(payload):
    def closed(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PublicationError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(
            payload,
            object_pairs_hook=closed,
            parse_constant=lambda token: (_ for _ in ()).throw(PublicationError(token)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError("invalid approval marker JSON") from error


_ELF_VALIDATOR = r"""
from pathlib import Path
import struct
import sys
header = Path(sys.argv[1]).read_bytes()[:20]
if len(header) != 20 or header[:4] != b"\x7fELF":
    raise SystemExit(1)
if header[4] != 2 or header[5] != 1 or struct.unpack("<H", header[18:20])[0] != 62:
    raise SystemExit(1)
"""


_ARCHIVE_VALIDATOR_PROGRAM = r"""
from pathlib import PurePosixPath
import sys
import tarfile
archive_path, expected_top = sys.argv[1:]
try:
    with tarfile.open(archive_path, mode="r:xz") as archive_file:
        members = archive_file.getmembers()
except (OSError, tarfile.TarError):
    raise SystemExit(1)
if not members:
    raise SystemExit(1)
for member in members:
    path = PurePosixPath(member.name)
    if path.is_absolute() or not path.parts or path.parts[0] != expected_top:
        raise SystemExit(1)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SystemExit(1)
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise SystemExit(1)
    if member.issym() or member.islnk():
        target = PurePosixPath(member.linkname)
        if target.is_absolute():
            raise SystemExit(1)
        base = path.parent if member.issym() else PurePosixPath()
        parts = []
        for part in (base / target).parts:
            if part in {"", "."}:
                continue
            if part == "..":
                if not parts:
                    raise SystemExit(1)
                parts.pop()
            else:
                parts.append(part)
        if not parts or parts[0] != expected_top:
            raise SystemExit(1)
"""


def candidate_evidence(recipe_sha256, container_image_digest, pins):
    return {
        "schema_version": "holoagent0.strace-candidate-evidence.v1",
        "measurement_kind": "CANDIDATE_MEASUREMENT",
        "recipe_sha256": recipe_sha256,
        "container_image_digest": container_image_digest,
        "elf_size": pins.size,
        "elf_sha256": pins.sha256,
        "version_output_sha256": pins.version_sha256,
    }


def transfer_archive(source, snapshot, runner, *, deadline):
    if source is None:
        argv = [
            "/usr/bin/curl",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
            str(snapshot),
            SOURCE_URL,
        ]
    else:
        argv = [
            "/usr/bin/cp",
            "--reflink=never",
            "--",
            f"/proc/self/fd/{source.fd}",
            str(snapshot),
        ]
    result = run_blocking_phase(
        "archive_transfer",
        argv,
        runner,
        deadline=deadline,
        pass_fds=() if source is None else (source.fd,),
    )
    if result.returncode != 0:
        raise ArchiveValidationError("archive transfer failed")


def validate_build_pins(row, script_path):
    build = row["build"]
    if (
        build["review_state"] != "REVIEWED"
        or not build["recipe_sha256"]
        or not re_fullmatch_sha256_digest(build["container_image_digest"])
    ):
        raise ProvisioningError("PENDING_REPRODUCIBLE_BUILD")
    if _hash_path(script_path) != build["recipe_sha256"]:
        raise ProvisioningError("reviewed build recipe sha256 mismatch")


def validate_runtime_pins(row):
    runtime = row["runtime"]
    values = (
        runtime["elf_size"],
        runtime["elf_sha256"],
        runtime["version_output_sha256"],
    )
    if runtime["review_state"] != "REVIEWED" or any(
        value in {None, ""} for value in values
    ):
        raise ProvisioningError("runtime pins are required for reviewed install")
    return ElfPins(
        int(runtime["elf_size"]),
        runtime["elf_sha256"],
        runtime["version_output_sha256"],
        row["build"]["recipe_sha256"],
        row["build"]["container_image_digest"],
    )


def _parse_cli(script_path, argv):
    archive = output = candidate = None
    index = 0
    while index < len(argv):
        option = argv[index]
        if option not in {"--archive", "--output-dir", "--candidate-evidence"}:
            raise CliError(USAGE.format(script=script_path))
        if index + 1 >= len(argv):
            raise CliError(USAGE.format(script=script_path))
        value = argv[index + 1]
        if option == "--archive":
            if archive is not None:
                raise CliError(USAGE.format(script=script_path))
            archive = Path(value)
        elif option == "--output-dir":
            if output is not None:
                raise CliError(USAGE.format(script=script_path))
            output = _canonical_destination(value)
        else:
            if candidate is not None:
                raise CliError(USAGE.format(script=script_path))
            candidate = _canonical_destination(value)
        index += 2
    if (output is None) == (candidate is None):
        raise CliError(USAGE.format(script=script_path))
    if archive is not None:
        if not archive.is_absolute() or ".." in archive.parts:
            raise CliError("archive must be an absolute canonical path")
    return archive, output, candidate


def _load_policy(path):
    def closed(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ProvisioningError("duplicate policy key")
            result[key] = value
        return result

    try:
        value = json.loads(
            Path(path).read_bytes(),
            object_pairs_hook=closed,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ProvisioningError(token)
            ),
        )
        if (
            value["schema_version"] != "holoagent0.trace-tool-policy.v1"
            or len(value["rows"]) != 1
        ):
            raise ProvisioningError("invalid trace-tool policy")
        return value["rows"][0]
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProvisioningError("invalid trace-tool policy") from error


def _validate_local_source(path, runner, deadline):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError as error:
        raise ArchiveValidationError(
            "archive must be a regular non-symlink file"
        ) from error
    except OSError as error:
        raise ArchiveValidationError(
            "archive must be a regular non-symlink file"
        ) from error
    try:
        value = os.fstat(fd)
        named = path.lstat()
        if not stat.S_ISREG(value.st_mode) or (named.st_dev, named.st_ino) != (
            value.st_dev,
            value.st_ino,
        ):
            raise ArchiveValidationError("archive must be a regular non-symlink file")
        size, digest = _bounded_file_measurement(
            fd, runner, phase="archive_validation", deadline=deadline
        )
        if size != SOURCE_SIZE:
            raise ArchiveValidationError("source archive size mismatch")
        if digest != SOURCE_SHA256:
            raise ArchiveValidationError("source archive sha256 mismatch")
        return SourceArchive(path, fd, value.st_dev, value.st_ino)
    except BaseException:
        os.close(fd)
        raise


def _validate_snapshot(path, runner, deadline):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        size, digest = _bounded_file_measurement(
            fd, runner, phase="archive_validation", deadline=deadline
        )
        if size != SOURCE_SIZE:
            raise ArchiveValidationError("source archive size mismatch")
        if digest != SOURCE_SHA256:
            raise ArchiveValidationError("source archive sha256 mismatch")
        result = run_blocking_phase(
            "archive_validation",
            [
                PYTHON,
                "-c",
                _ARCHIVE_VALIDATOR_PROGRAM,
                f"/proc/self/fd/{fd}",
                TOP_DIRECTORY,
            ],
            runner,
            deadline=deadline,
            pass_fds=(fd,),
        )
        if result.returncode != 0:
            raise ArchiveValidationError("source archive member validation failed")
    finally:
        os.close(fd)


def _bounded_file_measurement(fd, runner, *, phase, deadline):
    before = os.fstat(fd)
    result = run_blocking_phase(
        phase,
        ["/usr/bin/sha256sum", "--", f"/proc/self/fd/{fd}"],
        runner,
        deadline=deadline,
        pass_fds=(fd,),
    )
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise ArchiveValidationError("file identity changed during measurement")
    if result.returncode != 0:
        raise ArchiveValidationError("file digest command failed")
    token = result.stdout.decode("ascii", "strict").split()
    if (
        len(token) < 1
        or len(token[0]) != 64
        or any(character not in "0123456789abcdef" for character in token[0])
    ):
        raise ArchiveValidationError("invalid file digest output")
    return before.st_size, token[0]


def provision(script_path: Path, argv: Sequence[str]) -> int:
    latch = SignalLatch()
    latch.install()
    archive, output, candidate = _parse_cli(script_path, argv)
    script_path = script_path.resolve(strict=True)
    row = _load_policy(script_path.parent / "policies/holoagent0-trace-tool-v1.json")
    runner = OwnedSessionRunner(signal_latch=latch)
    source_archive = None
    if archive is None:
        validate_build_pins(row, script_path)
    else:
        source_archive = _validate_local_source(archive, runner, 120.0)

    destination = output if output is not None else candidate
    parent = (
        destination.parent
        if output is not None
        else Path(os.environ.get("TMPDIR", "/tmp"))
    )
    registry = None
    root = None
    output_registry = None
    output_stage = None
    measurement = None
    docker_owner = None
    cleanup_succeeded = True
    ordinary_status = 0
    try:
        _raise_if_interrupted(latch)
        registry = OwnedPathRegistry(parent.resolve(strict=True))
        root = registry.create_directory(
            f".holoagent0-strace-{secrets.token_hex(16)}", mode=0o700
        )
        root_path = registry.parent / root.name
        snapshot = root_path / "strace-6.6.tar.xz"
        transfer_archive(source_archive, snapshot, runner, deadline=120.0)
        if source_archive is not None:
            current = os.fstat(source_archive.fd)
            if (current.st_dev, current.st_ino) != (
                source_archive.device,
                source_archive.inode,
            ):
                raise ArchiveValidationError("source archive identity changed")
            source_archive.close()
        _validate_snapshot(snapshot, runner, 120.0)
        if archive is not None:
            validate_build_pins(row, script_path)
        if output is not None:
            runtime_pins = validate_runtime_pins(row)
            output_registry = OwnedPathRegistry(output.parent)
            output_stage = output_registry.create_directory(
                f".holoagent0-strace-install-{secrets.token_hex(16)}", mode=0o700
            )
            install_path = output.parent / output_stage.name
        else:
            os.mkdir("install", 0o700, dir_fd=root.fd)
            install_path = root_path / "install"
            runtime_pins = None
        os.mkdir("source", 0o700, dir_fd=root.fd)
        os.mkdir("build", 0o700, dir_fd=root.fd)
        source_path = root_path / "source"
        build_path = root_path / "build"
        extraction = run_blocking_phase(
            "archive_extraction",
            [
                "/usr/bin/tar",
                "--extract",
                "--xz",
                "--file",
                str(snapshot),
                "--directory",
                str(source_path),
                "--no-same-owner",
                "--no-same-permissions",
                TOP_DIRECTORY,
            ],
            runner,
            deadline=120.0,
        )
        if extraction.returncode != 0:
            raise ArchiveValidationError("source extraction failed")
        build_argv = build_container_argv(
            row["build"]["container_image_digest"],
            source_path / TOP_DIRECTORY,
            build_path,
            install_path,
            uid=os.getuid(),
            gid=os.getgid(),
        )
        nonce = secrets.token_hex(16)
        docker_owner = DockerOwner(
            DOCKER,
            runner,
            name=f"holoagent0-strace-{nonce}",
            nonce=nonce,
            stabilization=1.0,
            command_timeout=3.0,
        )
        built = docker_owner.run_container(
            build_argv[2:], timeout=3600.0, env={**os.environ, **BUILD_ENV}
        )
        if built.returncode != 0:
            raise ProvisioningError("reproducible strace build failed")
        measured = measure_elf_pins(install_path / "bin/strace", runner, deadline=10.0)
        measured = ElfPins(
            measured.size,
            measured.sha256,
            measured.version_sha256,
            row["build"]["recipe_sha256"],
            row["build"]["container_image_digest"],
        )
        if candidate is not None:
            publish_candidate_evidence(
                candidate,
                candidate_evidence(
                    row["build"]["recipe_sha256"],
                    row["build"]["container_image_digest"],
                    measured,
                ),
                signal_latch=latch,
            )
        else:
            if measured != runtime_pins:
                raise ProvisioningError("built runtime does not match reviewed pins")
            measurement = retain_staged_install(
                install_path, runtime_pins, runner, deadline=10.0
            )
            quarantine = (
                output.parent / f".holoagent0-strace-quarantine-{secrets.token_hex(16)}"
            )
            publish_install_directory(
                install_path,
                output,
                quarantine,
                measurement,
                runtime_pins,
                runner,
                deadline=10.0,
                signal_latch=latch,
            )
            output_registry.forget(output_stage)
            output_stage = None
    except ProvisioningInterrupted as error:
        ordinary_status = error.status
    finally:
        with latch.block_for_cleanup():
            try:
                if source_archive is not None:
                    source_archive.close()
                if docker_owner is not None:
                    docker_owner.cleanup(env={**os.environ, **BUILD_ENV})
                if measurement is not None:
                    measurement.close()
                if output_registry is not None and output_stage is not None:
                    output_registry.remove_tree(output_stage)
                if registry is not None and root is not None:
                    registry.remove_tree(root)
            except BaseException:
                cleanup_succeeded = False
            finally:
                if output_registry is not None:
                    output_registry.close()
                if registry is not None:
                    registry.close()
    return latch.final_status(
        cleanup_succeeded=cleanup_succeeded, ordinary_status=ordinary_status
    )


def main(argv: Sequence[str]) -> int:
    if not argv:
        return 2
    script_path = Path(argv[0])
    try:
        return provision(script_path, argv[1:])
    except CliError as error:
        print(error, file=sys.stderr)
        return 2
    except ArchiveValidationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except ProvisioningInterrupted as error:
        return error.status
    except ProvisioningError as error:
        print(f"error: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__" and len(sys.argv) > 1:
    raise SystemExit(main(sys.argv[1:]))
# END_PROVISIONER_PYTHON
PY
