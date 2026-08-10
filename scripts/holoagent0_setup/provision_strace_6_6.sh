#!/usr/bin/env -S /usr/bin/python3.10 -I -S
# BEGIN_PROVISIONER_PYTHON
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
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
import threading
import time
from typing import Sequence


SOURCE_URL = "https://strace.io/files/6.6/strace-6.6.tar.xz"
SOURCE_SIZE = 2420364
SOURCE_SHA256 = "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
TOP_DIRECTORY = "strace-6.6"
PYTHON = "/usr/bin/python3.10"
DOCKER = "/usr/bin/docker"
DEFAULT_DOCKER_HOST = "unix:///var/run/docker.sock"
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
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
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


class OwnedOutputLimitError(OwnedCleanupError):
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
    def __init__(self, message, *, transition=None):
        super().__init__(message)
        self.transition = transition


class ProvisioningInterrupted(PublicationError):
    def __init__(self, status: int, *, transition=None):
        super().__init__(f"interrupted with status {status}", transition=transition)
        self.status = status


@dataclass(frozen=True)
class CleanupReport:
    failures: tuple

    @property
    def succeeded(self):
        return not self.failures


@dataclass(frozen=True)
class PublicationTransition:
    state: str
    destination: str
    quarantine: str
    device: int
    inode: int


@dataclass(frozen=True)
class DockerIdentity:
    container_id: str
    name: str
    nonce: str


def aggregate_cleanup(actions):
    failures = []
    for name, action in actions:
        try:
            action()
        except BaseException:
            failures.append(name)
    return CleanupReport(tuple(failures))


def closed_command_env(extra=None):
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "0",
    }
    if extra:
        allowed = {
            "DOCKER_CONFIG",
            "DOCKER_HOST",
            "FAKE_DOCKER_STATE",
            "FAKE_DOCKER_BEHAVIOR",
        }
        unknown = set(extra) - allowed
        if unknown:
            raise ProvisioningError(
                f"unapproved command environment: {sorted(unknown)}"
            )
        docker_host = extra.get("DOCKER_HOST")
        if docker_host is not None:
            socket_path = Path(docker_host.removeprefix("unix://"))
            if (
                not docker_host.startswith("unix:///")
                or ".." in socket_path.parts
                or not socket_path.is_absolute()
            ):
                raise ProvisioningError("DOCKER_HOST must be an absolute Unix socket")
        docker_config = extra.get("DOCKER_CONFIG")
        if docker_config is not None:
            prefix = f"/proc/{os.getpid()}/fd/"
            suffix = docker_config.removeprefix(prefix)
            if (
                not docker_config.startswith(prefix)
                or not suffix.isdigit()
                or not stat.S_ISDIR(os.fstat(int(suffix)).st_mode)
            ):
                raise ProvisioningError(
                    "DOCKER_CONFIG must identify a retained local directory"
                )
        environment.update(extra)
    return environment


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


@dataclass
class SealedArchive:
    fd: int
    device: int
    inode: int
    sealed: bool = False

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


@dataclass
class DockerClientContext:
    directory_fd: int
    device: int
    inode: int
    environment: dict

    def close(self):
        if self.directory_fd >= 0:
            value = os.fstat(self.directory_fd)
            if (value.st_dev, value.st_ino) != (self.device, self.inode):
                raise PathIdentityError("Docker client config identity changed")
            os.close(self.directory_fd)
            self.directory_fd = -1


def isolated_python_argv(program, *arguments):
    return [PYTHON, "-I", "-S", "-c", program, *map(str, arguments)]


def create_sealable_archive(name):
    if not isinstance(name, str) or not name or "/" in name or "\0" in name:
        raise ArchiveValidationError("invalid retained archive name")
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    fd = os.memfd_create(name, flags)
    value = os.fstat(fd)
    return SealedArchive(fd, value.st_dev, value.st_ino)


def seal_retained_archive(archive):
    if archive.sealed:
        verify_sealed_archive(archive)
        return
    value = os.fstat(archive.fd)
    if (value.st_dev, value.st_ino) != (archive.device, archive.inode):
        raise ArchiveValidationError("retained archive identity changed before sealing")
    seals = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    try:
        fcntl.fcntl(archive.fd, fcntl.F_ADD_SEALS, seals)
    except OSError as error:
        raise ArchiveValidationError("retained archive sealing failed") from error
    archive.sealed = True
    verify_sealed_archive(archive)


def verify_sealed_archive(archive):
    value = os.fstat(archive.fd)
    if (value.st_dev, value.st_ino) != (archive.device, archive.inode):
        raise ArchiveValidationError("sealed archive identity changed")
    required = (
        fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    )
    try:
        actual = fcntl.fcntl(archive.fd, fcntl.F_GET_SEALS)
    except OSError as error:
        raise ArchiveValidationError("sealed archive verification failed") from error
    if actual & required != required:
        raise ArchiveValidationError("retained archive is not immutable")
    if not archive.sealed:
        raise ArchiveValidationError("retained archive seal state was not recorded")


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

    def for_cleanup(self):
        return OwnedSessionRunner(
            term_grace=self.term_grace,
            kill_grace=self.kill_grace,
            identity_reader=self.identity_reader,
            signal_latch=None,
        )

    def run(self, argv, *, timeout, env=None, on_verified=None, pass_fds=()):
        if not argv or timeout <= 0:
            raise ValueError("owned command and positive timeout are required")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OwnedCleanupError("pidfd process ownership is unavailable")
        if self.signal_latch is not None and self.signal_latch.status:
            raise ProvisioningInterrupted(self.signal_latch.status)
        _enable_subreaper()
        baseline = _direct_child_identities(os.getpid())
        release_read, release_write = os.pipe2(os.O_CLOEXEC)
        inherited = tuple(sorted({release_read, *(int(fd) for fd in pass_fds)}))
        command = isolated_python_argv(_RELEASE_TRAMPOLINE)
        command.extend((str(release_read), *map(str, argv)))
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
        tracked = {}
        drainers = ()
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
            stdout_buffer = bytearray()
            stderr_buffer = bytearray()
            output_overflow = threading.Event()
            capture_budget = CaptureBudget()
            drainers = (
                _start_drain(
                    process.stdout, stdout_buffer, output_overflow, capture_budget
                ),
                _start_drain(
                    process.stderr, stderr_buffer, output_overflow, capture_budget
                ),
            )
            deadline = time.monotonic() + timeout
            timed_out = False
            interrupted = 0
            while process.poll() is None:
                self._discover_descendants(identity, baseline, tracked)
                if self.signal_latch is not None and self.signal_latch.status:
                    interrupted = self.signal_latch.status
                    break
                if output_overflow.is_set():
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
            self._cleanup_tracked(identity, baseline, tracked)
            for drainer in drainers:
                drainer.join(self.kill_grace)
                if drainer.is_alive():
                    raise OwnedCleanupError("owned output drainer did not terminate")
            stdout = bytes(stdout_buffer)
            stderr = bytes(stderr_buffer)
            if interrupted:
                raise ProvisioningInterrupted(interrupted)
            if output_overflow.is_set():
                raise OwnedOutputLimitError("owned output exceeded capture policy")
            if timed_out:
                raise OwnedProcessTimeout(argv)
            return subprocess.CompletedProcess(tuple(argv), returncode, stdout, stderr)
        except BaseException as primary:
            try:
                primary.command_released = released
            except (AttributeError, TypeError):
                pass
            cleanup_error = None
            try:
                if not released:
                    self._abort_unreleased(process, pidfd)
                elif identity is not None:
                    try:
                        if process.poll() is None:
                            self._cleanup_session(identity, process)
                        else:
                            self._cleanup_descendants(identity)
                    finally:
                        self._cleanup_tracked(identity, baseline, tracked)
                for drainer in drainers:
                    drainer.join(self.kill_grace)
                    if drainer.is_alive():
                        raise OwnedCleanupError(
                            "owned output drainer did not terminate"
                        )
            except BaseException as error:
                cleanup_error = error
            if cleanup_error is not None:
                raise OwnedCleanupError(
                    "owned process cleanup failed after command error"
                ) from cleanup_error
            raise primary
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

    def _discover_descendants(self, leader, baseline, tracked):
        records = _process_records()
        owned = {leader.pid, *(value.identity.pid for value in tracked.values())}
        changed = True
        while changed:
            changed = False
            for identity, parent_pid in records.values():
                key = (identity.pid, identity.start_time)
                if key in baseline or identity.pid in owned:
                    continue
                adopted = (
                    parent_pid == os.getpid()
                    and identity.start_time >= leader.start_time
                )
                if parent_pid not in owned and not adopted:
                    continue
                try:
                    pidfd = os.pidfd_open(identity.pid, 0)
                except ProcessLookupError:
                    continue
                tracked[key] = TrackedProcess(identity, pidfd)
                owned.add(identity.pid)
                changed = True

    def _cleanup_tracked(self, leader, baseline, tracked):
        discovery_error = None
        try:
            self._discover_descendants(leader, baseline, tracked)
        except BaseException as error:
            discovery_error = error
        if not tracked:
            if discovery_error is not None:
                raise OwnedCleanupError(
                    "descendant discovery failed during cleanup"
                ) from discovery_error
            return
        self._signal_tracked(tracked, signal.SIGTERM)
        deadline = time.monotonic() + self.term_grace
        while time.monotonic() < deadline:
            try:
                self._discover_descendants(leader, baseline, tracked)
            except BaseException as error:
                discovery_error = discovery_error or error
            if not _live_tracked(tracked):
                _close_tracked(tracked)
                if discovery_error is not None:
                    raise OwnedCleanupError(
                        "descendant discovery failed during cleanup"
                    ) from discovery_error
                return
            time.sleep(0.005)
        self._signal_tracked(tracked, signal.SIGKILL)
        deadline = time.monotonic() + self.kill_grace
        while time.monotonic() < deadline:
            try:
                self._discover_descendants(leader, baseline, tracked)
            except BaseException as error:
                discovery_error = discovery_error or error
            if not _live_tracked(tracked):
                _close_tracked(tracked)
                if discovery_error is not None:
                    raise OwnedCleanupError(
                        "descendant discovery failed during cleanup"
                    ) from discovery_error
                return
            time.sleep(0.005)
        _close_tracked(tracked)
        raise OwnedCleanupError("escaped descendant survived SIGKILL deadline")

    @staticmethod
    def _signal_tracked(tracked, signum):
        for value in tracked.values():
            try:
                current = read_process_identity(value.identity.pid)
                if not _same_process_identity(current, value.identity):
                    raise ProcessIdentityError("tracked descendant identity changed")
                signal.pidfd_send_signal(value.pidfd, signum)
            except (FileNotFoundError, ProcessLookupError):
                continue


_RELEASE_TRAMPOLINE = r"""
import ctypes
import errno
import os
import sys

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filters", ctypes.POINTER(SockFilter)),
    ]

def install_escape_filter():
    if os.uname().machine != "x86_64":
        raise SystemExit(126)
    load_word_absolute = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_constant = 0x06
    audit_arch_x86_64 = 0xC000003E
    seccomp_allow = 0x7FFF0000
    seccomp_errno = 0x00050000 | errno.EPERM
    seccomp_enosys = 0x00050000 | errno.ENOSYS
    seccomp_kill_process = 0x80000000
    namespace_flags = (
        0x00020000
        | 0x02000000
        | 0x04000000
        | 0x08000000
        | 0x10000000
        | 0x20000000
        | 0x40000000
    )
    instructions = [
        (load_word_absolute, 0, 0, 4),
        (jump_equal, 1, 0, audit_arch_x86_64),
        (return_constant, 0, 0, seccomp_kill_process),
        (load_word_absolute, 0, 0, 0),
    ]
    for syscall_number in (112, 272, 308):
        instructions.extend(
            [
                (jump_equal, 0, 1, syscall_number),
                (return_constant, 0, 0, seccomp_errno),
            ]
        )
    instructions.extend(
        [
            (jump_equal, 0, 1, 435),
            (return_constant, 0, 0, seccomp_enosys),
        ]
    )
    instructions.extend(
        [
            (jump_equal, 0, 3, 56),
            (load_word_absolute, 0, 0, 16),
            (jump_bits_set, 0, 1, namespace_flags),
            (return_constant, 0, 0, seccomp_errno),
            (return_constant, 0, 0, seccomp_allow),
        ]
    )
    filters = (SockFilter * len(instructions))(
        *(SockFilter(*instruction) for instruction in instructions)
    )
    program = SockFprog(len(filters), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise SystemExit(126)
    if libc.prctl(22, 2, ctypes.byref(program)) != 0:
        raise SystemExit(126)

release_fd = int(sys.argv[1])
command = sys.argv[2:]
install_escape_filter()
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
class TrackedProcess:
    identity: ProcessIdentity
    pidfd: int


class CaptureBudget:
    def __init__(self):
        self.lock = threading.Lock()
        self.used = 0

    def append(self, destination, block, overflow):
        with self.lock:
            available = MAX_CAPTURE_BYTES - self.used
            if available <= 0:
                overflow.set()
                return
            accepted = block[:available]
            destination.extend(accepted)
            self.used += len(accepted)
            if len(accepted) != len(block):
                overflow.set()


def _start_drain(stream, destination, overflow, budget):
    def drain():
        while True:
            block = stream.read(65536)
            if not block:
                return
            budget.append(destination, block, overflow)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    return thread


def _enable_subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        number = ctypes.get_errno()
        raise OwnedCleanupError(f"PR_SET_CHILD_SUBREAPER failed: {number}")


def _process_records():
    records = {}
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            text = (item / "stat").read_text(encoding="ascii")
            closing = text.rfind(")")
            fields = text[closing + 2 :].split()
            identity = ProcessIdentity(
                int(item.name),
                int(fields[2]),
                int(fields[3]),
                int(fields[19]),
                fields[0],
            )
            records[identity.pid] = (identity, int(fields[1]))
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            continue
    return records


def _direct_child_identities(parent_pid):
    return {
        (identity.pid, identity.start_time)
        for identity, candidate_parent in _process_records().values()
        if candidate_parent == parent_pid
    }


def _live_tracked(tracked):
    live = False
    for key, value in tuple(tracked.items()):
        try:
            current = read_process_identity(value.identity.pid)
        except (FileNotFoundError, ProcessLookupError):
            os.close(value.pidfd)
            tracked.pop(key)
            continue
        if current.state == "Z":
            try:
                os.waitpid(current.pid, os.WNOHANG)
            except ChildProcessError:
                pass
            os.close(value.pidfd)
            tracked.pop(key)
            continue
        if not _same_process_identity(current, value.identity):
            os.close(value.pidfd)
            tracked.pop(key)
            raise ProcessIdentityError("tracked descendant PID was reused")
        live = True
    return live


def _close_tracked(tracked):
    for value in tracked.values():
        os.close(value.pidfd)
    tracked.clear()


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
            self._close_entry(entry)
            raise PathIdentityError("owned directory identity changed")
        retained = os.fstat(entry.fd)
        if not self._matches(retained, entry):
            self._close_entry(entry)
            raise PathIdentityError("retained directory identity changed")
        try:
            self._clear_directory(entry.fd)
            current = self._lstat(entry.name)
            retained = os.fstat(entry.fd)
            if (
                current is None
                or not stat.S_ISDIR(current.st_mode)
                or not self._matches(current, entry)
                or not self._matches(retained, entry)
            ):
                raise PathIdentityError(
                    "owned directory identity changed after clearing"
                )
            os.rmdir(entry.name, dir_fd=self.parent_fd)
            os.fsync(self.parent_fd)
        finally:
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


def retained_fd_path(fd, suffix=None):
    value = f"/proc/{os.getpid()}/fd/{int(fd)}"
    if suffix is None:
        return Path(value)
    relative = PurePosixPath(suffix)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise PathIdentityError("retained FD suffix must be a safe relative path")
    return Path(value).joinpath(*relative.parts)


def _validated_local_docker_host(ambient):
    host = ambient.get("DOCKER_HOST", DEFAULT_DOCKER_HOST)
    if not isinstance(host, str) or not host.startswith("unix:///"):
        raise ProvisioningError("Docker host must be an absolute local Unix socket")
    socket_path = Path(host.removeprefix("unix://"))
    if (
        not socket_path.is_absolute()
        or ".." in socket_path.parts
        or os.path.normpath(str(socket_path)) != str(socket_path)
    ):
        raise ProvisioningError("Docker socket path must be absolute and canonical")
    try:
        value = os.stat(socket_path, follow_symlinks=False)
    except OSError as error:
        raise ProvisioningError("Docker host socket is unavailable") from error
    if not stat.S_ISSOCK(value.st_mode):
        raise ProvisioningError("Docker host must identify a local Unix socket")
    return host


def create_docker_client_context(root_fd, ambient):
    root = os.fstat(root_fd)
    if not stat.S_ISDIR(root.st_mode):
        raise PathIdentityError("Docker client root must be a retained directory")
    host = _validated_local_docker_host(ambient)
    name = "docker-client"
    os.mkdir(name, mode=0o700, dir_fd=root_fd)
    directory_fd = -1
    config_fd = -1
    try:
        directory_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        os.fchmod(directory_fd, 0o700)
        directory = os.fstat(directory_fd)
        config_fd = os.open(
            "config.json",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=directory_fd,
        )
        os.fchmod(config_fd, 0o600)
        _write_fd(config_fd, b"{}\n")
        os.fsync(config_fd)
        os.close(config_fd)
        config_fd = -1
        os.fsync(directory_fd)
        environment = closed_command_env(
            {
                "DOCKER_HOST": host,
                "DOCKER_CONFIG": str(retained_fd_path(directory_fd)),
            }
        )
        return DockerClientContext(
            directory_fd,
            directory.st_dev,
            directory.st_ino,
            environment,
        )
    except BaseException:
        if config_fd >= 0:
            os.close(config_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
        raise


def create_owned_file_at(directory_fd, name, *, mode):
    OwnedPathRegistry._validate_name(name)
    fd = os.open(
        name,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        mode,
        dir_fd=directory_fd,
    )
    os.fchmod(fd, mode)
    value = os.fstat(fd)
    return OwnedPath(name, value.st_dev, value.st_ino, fd, False)


def close_owned_path(entry):
    if entry is not None and entry.fd >= 0:
        os.close(entry.fd)
        entry.fd = -1


class DockerOwner:
    def __init__(
        self,
        docker,
        runner,
        *,
        cleanup_runner=None,
        name,
        nonce,
        stabilization,
        command_timeout,
    ):
        self.docker = docker
        self.runner = runner
        self.cleanup_runner = cleanup_runner or runner.for_cleanup()
        self.name = name
        self.nonce = nonce
        self.stabilization = float(stabilization)
        self.command_timeout = float(command_timeout)
        self.attempted = False
        self.created_identity = None
        self._active_identity = None
        self._create_outcome_uncertain = False

    def run_container(self, args, *, timeout, env=None):
        if self._inventory(env):
            raise DockerOwnershipError("container name was already present")
        primary = None
        result = None
        try:
            try:
                created = self.runner.run(
                    [
                        self.docker,
                        "create",
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
                released = getattr(
                    error, "command_released", isinstance(error, OwnedProcessTimeout)
                )
                if released:
                    self.attempted = True
                    self._create_outcome_uncertain = True
                raise
            self.attempted = True
            self._create_outcome_uncertain = True
            if created.returncode != 0:
                raise DockerOwnershipError("docker create failed")
            try:
                container_id = created.stdout.decode("ascii", "strict").strip()
            except UnicodeDecodeError as error:
                raise DockerOwnershipError(
                    "docker create returned an undecodable ID"
                ) from error
            if not _fullmatch_container_id(container_id):
                raise DockerOwnershipError("docker create returned an invalid ID")
            identity = DockerIdentity(container_id, self.name, self.nonce)
            self.created_identity = identity
            self._active_identity = identity
            self._create_outcome_uncertain = False
            self._verify_bound_identity(identity, env)
            result = self.runner.run(
                [self.docker, "start", "--attach", container_id],
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
        removed = False
        while True:
            rows = self._inventory(env)
            if self._active_identity is None:
                if rows:
                    if not self.attempted:
                        raise DockerOwnershipError(
                            "container name was not created by this owner"
                        )
                    raise DockerCleanupError(
                        "response-less docker create outcome remained unresolved"
                    )
            elif rows:
                if rows != [self._active_identity]:
                    raise DockerOwnershipError(
                        "container identity changed after create"
                    )
                self._verify_bound_identity(self._active_identity, env)
            elif not removed:
                raise DockerOwnershipError(
                    "create-returned container identity disappeared"
                )

            if self._active_identity is not None and not removed:
                result = self._command(
                    [
                        self.docker,
                        "rm",
                        "--force",
                        self._active_identity.container_id,
                    ],
                    env,
                    cleanup=True,
                )
                if result.returncode != 0:
                    raise DockerCleanupError("docker rm failed")
                removed = True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        remaining = self._inventory(env)
        if remaining:
            raise DockerCleanupError("owned container remained after stabilization")
        if self.attempted and self._active_identity is None:
            raise DockerCleanupError("docker create outcome remained unresolved")
        if self._create_outcome_uncertain and not removed:
            raise DockerCleanupError("docker create outcome remained unresolved")
        self.attempted = False
        self._active_identity = None
        self._create_outcome_uncertain = False

    def _verify_bound_identity(self, identity, env):
        inspected = self._command(
            [
                self.docker,
                "inspect",
                "--format",
                '{{.Id}}|{{.Name}}|{{ index .Config.Labels "holoagent0.strace.owner" }}',
                identity.container_id,
            ],
            env,
        )
        verified = _parse_inspected_identity(inspected.stdout)
        if verified != identity:
            raise DockerOwnershipError("container label identity changed")
        current = self._inventory(env)
        if current != [identity]:
            raise DockerOwnershipError("container identity changed during verification")

    def _command(self, argv, env, *, cleanup=False):
        try:
            result = self.cleanup_runner.run(
                argv, timeout=self.command_timeout, env=env
            )
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
                "{{.Names}}|{{.Labels}}|{{.ID}}",
            ],
            env,
        )
        rows = []
        try:
            inventory = result.stdout.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise DockerCleanupError("undecodable docker inventory") from error
        for raw in inventory.splitlines():
            if not raw:
                continue
            if raw.count("|") != 2:
                raise DockerCleanupError("undecodable docker inventory")
            name, labels, container_id = raw.split("|", 2)
            expected = f"holoagent0.strace.owner={self.nonce}"
            nonce = self.nonce if expected in labels.split(",") else ""
            if not _fullmatch_container_id(container_id):
                raise DockerCleanupError("docker inventory returned an invalid ID")
            if name != self.name:
                raise DockerCleanupError("docker inventory returned an unexpected name")
            rows.append(DockerIdentity(container_id, name, nonce))
        return rows


def _fullmatch_container_id(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _parse_inspected_identity(payload):
    try:
        text = payload.decode("utf-8", "strict").strip()
    except UnicodeDecodeError as error:
        raise DockerOwnershipError("undecodable docker identity") from error
    if text.count("|") != 2:
        raise DockerOwnershipError("undecodable docker identity")
    container_id, name, nonce = text.split("|", 2)
    if name.startswith("/"):
        name = name[1:]
    if not _fullmatch_container_id(container_id):
        raise DockerOwnershipError("docker inspect returned an invalid ID")
    return DockerIdentity(container_id, name, nonce)


def run_blocking_phase(phase, argv, runner, *, deadline, **kwargs):
    if phase not in BLOCKING_PHASES or deadline <= 0:
        raise ProvisioningError("invalid blocking phase")
    kwargs.setdefault("env", closed_command_env())
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
        "-eu",
        "-c",
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


def measure_elf_pins(path, runner, *, deadline, require_exact=False):
    path = Path(path)
    named = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise PublicationError("runtime must be a regular non-symlink ELF")
        return _measure_elf_fd(fd, runner, deadline, require_exact=require_exact)
    finally:
        os.close(fd)


@contextmanager
def _exclusive_elf_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            raise PublicationError("runtime ELF is already being modified") from error
        raise PublicationError("runtime ELF lock failed") from error
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)


def _measure_elf_fd(fd, runner, deadline, *, require_exact=False):
    with _exclusive_elf_lock(fd):
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise PublicationError("runtime must be a regular non-symlink ELF")
        retained = f"/proc/self/fd/{fd}"
        validation = run_blocking_phase(
            "elf_validation",
            isolated_python_argv(_ELF_VALIDATOR, retained),
            runner,
            deadline=deadline,
            pass_fds=(fd,),
        )
        if validation.returncode != 0:
            raise PublicationError("runtime is not linux-x86_64 ELF")
        digest = _parse_elf_validator_digest(validation.stdout)
        version = run_blocking_phase(
            "elf_version",
            [retained, "--version"],
            runner,
            deadline=deadline,
            pass_fds=(fd,),
        )
        if version.returncode != 0:
            raise PublicationError("runtime version command failed")
        if require_exact:
            require_strace_6_6(version.stdout)
        final_digest = hash_retained_fd(fd, runner, deadline=deadline)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise PublicationError("runtime identity changed during measurement")
        if final_digest != digest:
            raise PublicationError("runtime bytes changed during measurement")
        return ElfPins(
            before.st_size,
            digest,
            hashlib.sha256(version.stdout).hexdigest(),
        )


def require_strace_6_6(output):
    first_line = bytes(output).split(b"\n", 1)[0]
    if first_line != b"strace -- version 6.6":
        raise PublicationError("unexpected strace version output")


def verify_strace_version(path, runner, *, deadline):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = run_blocking_phase(
            "elf_version",
            [f"/proc/self/fd/{fd}", "--version"],
            runner,
            deadline=deadline,
            pass_fds=(fd,),
        )
    finally:
        os.close(fd)
    if result.returncode != 0:
        raise PublicationError("runtime version command failed")
    require_strace_6_6(result.stdout)
    return hashlib.sha256(result.stdout).hexdigest()


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


def retain_owned_staged_install(path, parent_fd, owned_root, pins, runner, *, deadline):
    measurement = open_owned_staged_install(path, parent_fd, owned_root)
    try:
        _verify_staging_name(measurement)
        _verify_retained_measurement(measurement, pins, runner, deadline)
    except BaseException:
        measurement.close()
        raise
    return measurement


def open_owned_staged_install(path, parent_fd, owned_root):
    path = Path(path)
    retained_parent = os.dup(parent_fd)
    root_fd = os.dup(owned_root.fd)
    bin_fd = elf_fd = -1
    try:
        root_value = os.fstat(root_fd)
        if (root_value.st_dev, root_value.st_ino) != (
            owned_root.device,
            owned_root.inode,
        ):
            raise PublicationError("owned staging directory identity changed")
        bin_fd = os.open(
            "bin", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd
        )
        elf_fd = os.open("strace", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=bin_fd)
        elf_value = os.fstat(elf_fd)
        if not stat.S_ISREG(elf_value.st_mode):
            raise PublicationError("staged runtime is not a regular file")
        measurement = StagedInstall(
            path,
            retained_parent,
            root_fd,
            elf_fd,
            root_value.st_dev,
            root_value.st_ino,
            elf_value.st_dev,
            elf_value.st_ino,
        )
        retained_parent = root_fd = elf_fd = -1
    finally:
        if bin_fd >= 0:
            os.close(bin_fd)
        for fd in (elf_fd, root_fd, retained_parent):
            if fd >= 0:
                os.close(fd)
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
        if isinstance(error, ProvisioningInterrupted):
            raise error
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
    before_marker=None,
    before_rename=None,
    after_rename=None,
    after_approval=None,
    after_rollback_prepared=None,
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
    with _exclusive_elf_lock(measurement.elf_fd):
        return _publish_install_directory_locked(
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=deadline,
            before_marker=before_marker,
            before_rename=before_rename,
            after_rename=after_rename,
            after_approval=after_approval,
            after_rollback_prepared=after_rollback_prepared,
            signal_latch=signal_latch,
        )


def _publish_install_directory_locked(
    staged,
    destination,
    quarantine,
    measurement,
    pins,
    runner,
    *,
    deadline,
    before_marker=None,
    before_rename=None,
    after_rename=None,
    after_approval=None,
    after_rollback_prepared=None,
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
    _verify_retained_measurement(
        measurement, pins, runner, deadline, elf_lock_held=True
    )
    _raise_if_interrupted(signal_latch)
    committed = False
    installed_fd = -1
    marker_fd = -1
    marker_device = None
    marker_inode = None
    transition = PublicationTransition(
        "STAGED",
        str(destination),
        str(quarantine),
        measurement.root_device,
        measurement.root_inode,
    )
    try:
        if before_marker is not None:
            before_marker(staged)
        _raise_if_interrupted(signal_latch)
        marker = _approval_payload(measurement, pins)
        marker_fd = os.open(
            APPROVAL_MARKER,
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=measurement.root_fd,
        )
        marker_value = os.fstat(marker_fd)
        if not stat.S_ISREG(marker_value.st_mode):
            raise PublicationError("approval marker is not a regular file")
        marker_device = marker_value.st_dev
        marker_inode = marker_value.st_ino
        _write_fd(marker_fd, marker)
        os.fchmod(marker_fd, 0o600)
        os.fsync(marker_fd)
        _verify_retained_marker_name(
            measurement.root_fd,
            marker_fd,
            marker_device,
            marker_inode,
        )
        os.fsync(measurement.root_fd)
        _verify_approved_install_at(
            measurement.parent_fd,
            staged.name,
            pins,
            runner,
            deadline=deadline,
            retained_elf_fd=measurement.elf_fd,
            elf_lock_held=True,
            retained_marker_fd=marker_fd,
            retained_marker_device=marker_device,
            retained_marker_inode=marker_inode,
        )
        if before_rename is not None:
            before_rename(staged)
        _raise_if_interrupted(signal_latch)
        installed_fd = os.dup(measurement.root_fd)
        _rename_no_replace(
            measurement.parent_fd, staged.name, measurement.parent_fd, destination.name
        )
        committed = True
        transition = PublicationTransition(
            "PUBLISHED",
            str(destination),
            str(quarantine),
            measurement.root_device,
            measurement.root_inode,
        )
        os.fsync(measurement.parent_fd)
        installed_value = os.fstat(installed_fd)
        if (installed_value.st_dev, installed_value.st_ino) != (
            measurement.root_device,
            measurement.root_inode,
        ):
            raise PublicationError("published install identity changed")
        if after_rename is not None:
            after_rename(destination)
        _raise_if_interrupted(signal_latch)
        if after_approval is not None:
            after_approval(destination)
        _raise_if_interrupted(signal_latch)
        _verify_approved_install_at(
            measurement.parent_fd,
            destination.name,
            pins,
            runner,
            deadline=deadline,
            retained_elf_fd=measurement.elf_fd,
            elf_lock_held=True,
            retained_marker_fd=marker_fd,
            retained_marker_device=marker_device,
            retained_marker_inode=marker_inode,
        )
        _raise_if_interrupted(signal_latch)
        os.fsync(measurement.parent_fd)
        return transition
    except BaseException as error:
        if committed:
            try:
                _transition_marker_state(
                    installed_fd,
                    "ROLLBACK_PREPARED",
                    retained_marker_fd=marker_fd,
                    retained_marker_device=marker_device,
                    retained_marker_inode=marker_inode,
                    rollback_state="PREPARED",
                )
                transition = PublicationTransition(
                    "ROLLBACK_PREPARED",
                    str(destination),
                    str(quarantine),
                    measurement.root_device,
                    measurement.root_inode,
                )
                if after_rollback_prepared is not None:
                    after_rollback_prepared(destination)
                _verify_retained_directory_name(
                    measurement.parent_fd,
                    destination.name,
                    installed_fd,
                    measurement.root_device,
                    measurement.root_inode,
                )
            except BaseException as rollback_error:
                raise PublicationError(
                    "AMBIGUOUS_INSTALL_COMMIT", transition=transition
                ) from rollback_error
            if isinstance(error, ProvisioningInterrupted) or (
                signal_latch is not None and signal_latch.status
            ):
                interruption = (
                    error
                    if isinstance(error, ProvisioningInterrupted)
                    else ProvisioningInterrupted(signal_latch.status)
                )
                interruption.transition = transition
                interruption.args = (
                    f"ROLLED_BACK_INSTALL_COMMIT: interrupted with status "
                    f"{interruption.status}",
                )
                raise interruption
            raise PublicationError(
                "ROLLED_BACK_INSTALL_COMMIT", transition=transition
            ) from error
        if isinstance(error, (FileExistsError, ProvisioningInterrupted)):
            raise
        if isinstance(error, PublicationError):
            if error.transition is None:
                error.transition = transition
            raise
        raise PublicationError(
            "STAGED_INSTALL_NOT_PUBLISHED", transition=transition
        ) from error
    finally:
        if marker_fd >= 0:
            os.close(marker_fd)
        if installed_fd >= 0:
            os.close(installed_fd)


def _verify_retained_directory_name(parent_fd, name, retained_fd, device, inode):
    try:
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        retained = os.fstat(retained_fd)
    except OSError as error:
        raise PublicationError("retained directory name changed") from error
    expected = (device, inode)
    if (
        not stat.S_ISDIR(named.st_mode)
        or not stat.S_ISDIR(retained.st_mode)
        or (named.st_dev, named.st_ino) != expected
        or (retained.st_dev, retained.st_ino) != expected
    ):
        raise PublicationError("retained directory name changed")


def _verify_retained_marker_name(
    directory_fd,
    retained_marker_fd,
    retained_marker_device,
    retained_marker_inode,
):
    if retained_marker_fd is None or retained_marker_fd < 0:
        raise PublicationError("retained approval marker is unavailable")
    if retained_marker_device is None or retained_marker_inode is None:
        raise PublicationError("retained approval marker identity is unavailable")
    try:
        named = os.stat(
            APPROVAL_MARKER,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        retained = os.fstat(retained_marker_fd)
    except OSError as error:
        raise PublicationError("approval marker identity changed") from error
    expected = (retained_marker_device, retained_marker_inode)
    if (
        not stat.S_ISREG(named.st_mode)
        or not stat.S_ISREG(retained.st_mode)
        or (named.st_dev, named.st_ino) != expected
        or (retained.st_dev, retained.st_ino) != expected
    ):
        raise PublicationError("approval marker identity changed")


def _transition_marker_state(
    directory_fd,
    state,
    *,
    retained_marker_fd,
    retained_marker_device,
    retained_marker_inode,
    **fields,
):
    if state != "ROLLBACK_PREPARED":
        raise PublicationError("invalid rollback marker transition")
    _verify_retained_marker_name(
        directory_fd,
        retained_marker_fd,
        retained_marker_device,
        retained_marker_inode,
    )
    value = os.fstat(retained_marker_fd)
    if not stat.S_ISREG(value.st_mode):
        raise PublicationError("rollback marker identity changed")
    payload = os.pread(retained_marker_fd, 8193, 0)
    if len(payload) > 8192:
        raise PublicationError("oversized rollback marker")
    marker = _closed_json(payload)
    if marker.get("state") != "APPROVED":
        raise PublicationError("invalid rollback marker source state")
    marker["state"] = state
    marker.update(fields)
    encoded = (
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    _write_fd(retained_marker_fd, encoded)
    os.fchmod(retained_marker_fd, 0o600)
    os.fsync(retained_marker_fd)
    _verify_retained_marker_name(
        directory_fd,
        retained_marker_fd,
        retained_marker_device,
        retained_marker_inode,
    )
    os.fsync(directory_fd)
    _verify_retained_marker_name(
        directory_fd,
        retained_marker_fd,
        retained_marker_device,
        retained_marker_inode,
    )


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


def _verify_approved_install_at(
    parent_fd,
    destination_name,
    pins,
    runner,
    *,
    deadline,
    retained_elf_fd=None,
    elf_lock_held=False,
    retained_marker_fd=None,
    retained_marker_device=None,
    retained_marker_inode=None,
):
    installed_fd = os.open(
        destination_name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_fd,
    )
    bin_fd = marker_fd = elf_fd = -1
    try:
        installed = os.fstat(installed_fd)
        if retained_marker_fd is None:
            marker_fd = os.open(
                APPROVAL_MARKER,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=installed_fd,
            )
            marker_value = os.fstat(marker_fd)
            payload = os.read(marker_fd, 8193)
        else:
            _verify_retained_marker_name(
                installed_fd,
                retained_marker_fd,
                retained_marker_device,
                retained_marker_inode,
            )
            marker_value = os.fstat(retained_marker_fd)
            payload = os.pread(retained_marker_fd, 8193, 0)
        if (
            not stat.S_ISREG(marker_value.st_mode)
            or marker_value.st_mode & 0o777 != 0o600
        ):
            raise PublicationError("invalid approval marker")
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
        if elf_lock_held:
            if retained_elf_fd is None:
                raise PublicationError("locked ELF verification lacks retained fd")
            retained_value = os.fstat(retained_elf_fd)
            if (retained_value.st_dev, retained_value.st_ino) != (
                elf_value.st_dev,
                elf_value.st_ino,
            ):
                raise PublicationError("retained approved ELF identity changed")
            _verify_elf_fd_locked(retained_elf_fd, pins, runner, deadline)
        else:
            if retained_elf_fd is not None:
                raise PublicationError("retained ELF requires an existing lock")
            _verify_elf_fd(elf_fd, pins, runner, deadline)
        if retained_marker_fd is not None:
            _verify_retained_marker_name(
                installed_fd,
                retained_marker_fd,
                retained_marker_device,
                retained_marker_inode,
            )
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


def hash_retained_fd(fd, runner, *, deadline, hasher="/usr/bin/sha256sum"):
    before = os.fstat(fd)
    result = run_blocking_phase(
        "elf_validation",
        [hasher, "--", f"/proc/self/fd/{fd}"],
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
        raise PublicationError("retained file changed during hashing")
    if result.returncode != 0:
        raise PublicationError("owned hasher failed")
    try:
        fields = result.stdout.decode("ascii", "strict").split()
    except UnicodeDecodeError as error:
        raise PublicationError("owned hasher returned undecodable output") from error
    if (
        len(fields) < 1
        or len(fields[0]) != 64
        or any(character not in "0123456789abcdef" for character in fields[0])
    ):
        raise PublicationError("owned hasher returned invalid digest")
    return fields[0]


def _verify_elf_fd(fd, pins, runner, deadline):
    with _exclusive_elf_lock(fd):
        _verify_elf_fd_locked(fd, pins, runner, deadline)


def _verify_elf_fd_locked(fd, pins, runner, deadline):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != pins.size:
        raise PublicationError("ELF size changed")
    retained = f"/proc/self/fd/{fd}"
    validation = run_blocking_phase(
        "elf_validation",
        isolated_python_argv(_ELF_VALIDATOR, retained),
        runner,
        deadline=deadline,
        pass_fds=(fd,),
    )
    if validation.returncode != 0:
        raise PublicationError("ELF ABI changed")
    initial_digest = _parse_elf_validator_digest(validation.stdout)
    if initial_digest != pins.sha256:
        raise PublicationError("ELF digest changed")
    version = run_blocking_phase(
        "elf_version",
        [retained, "--version"],
        runner,
        deadline=deadline,
        pass_fds=(fd,),
    )
    if (
        version.returncode != 0
        or hashlib.sha256(version.stdout).hexdigest() != pins.version_sha256
    ):
        raise PublicationError("ELF version output changed")
    final_digest = hash_retained_fd(fd, runner, deadline=deadline)
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ):
        raise PublicationError("ELF identity changed during verification")
    if final_digest != initial_digest:
        raise PublicationError("ELF bytes changed during verification")


def _parse_elf_validator_digest(payload):
    try:
        value = bytes(payload).decode("ascii", "strict").strip()
    except UnicodeDecodeError as error:
        raise PublicationError("ELF validator returned an invalid digest") from error
    if len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise PublicationError("ELF validator returned an invalid digest")
    return value


def _verify_retained_measurement(
    measurement, pins, runner, deadline, *, elf_lock_held=False
):
    root = os.fstat(measurement.root_fd)
    elf = os.fstat(measurement.elf_fd)
    if (root.st_dev, root.st_ino) != (measurement.root_device, measurement.root_inode):
        raise PublicationError("retained staging directory changed")
    if (elf.st_dev, elf.st_ino) != (measurement.elf_device, measurement.elf_inode):
        raise PublicationError("retained staging ELF changed")
    if elf_lock_held:
        _verify_elf_fd_locked(measurement.elf_fd, pins, runner, deadline)
    else:
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
import hashlib
import struct
import sys
digest = hashlib.sha256()
with open(sys.argv[1], "rb", buffering=0) as stream:
    header = stream.read(20)
    digest.update(header)
    while True:
        block = stream.read(65536)
        if not block:
            break
        digest.update(block)
if len(header) != 20 or header[:4] != b"\x7fELF":
    raise SystemExit(1)
if header[4] != 2 or header[5] != 1 or struct.unpack("<H", header[18:20])[0] != 62:
    raise SystemExit(1)
print(digest.hexdigest())
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


def archive_transfer_argv(source, snapshot):
    if source is None:
        return [
            "/usr/bin/curl",
            "--disable",
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--noproxy",
            "*",
            "--output",
            str(snapshot),
            SOURCE_URL,
        ]
    return [
        "/usr/bin/cp",
        "--reflink=never",
        "--",
        f"/proc/self/fd/{source.fd}",
        str(snapshot),
    ]


def transfer_archive(source, snapshot, runner, *, deadline, snapshot_fd=None):
    target = (
        retained_fd_path(snapshot_fd) if snapshot_fd is not None else Path(snapshot)
    )
    argv = archive_transfer_argv(source, target)
    passed = [] if source is None else [source.fd]
    if snapshot_fd is not None:
        passed.append(snapshot_fd)
    result = run_blocking_phase(
        "archive_transfer",
        argv,
        runner,
        deadline=deadline,
        pass_fds=tuple(passed),
    )
    if result.returncode != 0:
        raise ArchiveValidationError("archive transfer failed")


def validate_build_pins(row, script_path, runner, deadline=10.0):
    build = row["build"]
    if (
        build["review_state"] != "REVIEWED"
        or not build["recipe_sha256"]
        or not re_fullmatch_sha256_digest(build["container_image_digest"])
    ):
        raise ProvisioningError("PENDING_REPRODUCIBLE_BUILD")
    fd = os.open(script_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        digest = hash_retained_fd(fd, runner, deadline=deadline)
    finally:
        os.close(fd)
    if digest != build["recipe_sha256"]:
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


def _validate_snapshot_fd(fd, runner, deadline):
    size, digest = _bounded_file_measurement(
        fd, runner, phase="archive_validation", deadline=deadline
    )
    if size != SOURCE_SIZE:
        raise ArchiveValidationError("source archive size mismatch")
    if digest != SOURCE_SHA256:
        raise ArchiveValidationError("source archive sha256 mismatch")
    validator_argv = isolated_python_argv(_ARCHIVE_VALIDATOR_PROGRAM)
    validator_argv.extend((f"/proc/self/fd/{fd}", TOP_DIRECTORY))
    result = run_blocking_phase(
        "archive_validation",
        validator_argv,
        runner,
        deadline=deadline,
        pass_fds=(fd,),
    )
    if result.returncode != 0:
        raise ArchiveValidationError("source archive member validation failed")


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
    try:
        token = result.stdout.decode("ascii", "strict").split()
    except UnicodeDecodeError as error:
        raise ArchiveValidationError("invalid file digest output") from error
    if (
        len(token) < 1
        or len(token[0]) != 64
        or any(character not in "0123456789abcdef" for character in token[0])
    ):
        raise ArchiveValidationError("invalid file digest output")
    return before.st_size, token[0]


def cleanup_publication_stage(registry, entry, transition):
    if transition is not None and transition.state in {
        "PUBLISHED",
        "ROLLBACK_PREPARED",
    }:
        registry.forget(entry)
        raise PublicationError(
            "published install has an unresolved cleanup transition",
            transition=transition,
        )
    registry.remove_tree(entry)


def provision(script_path: Path, argv: Sequence[str]) -> int:
    latch = SignalLatch()
    latch.install()
    archive, output, candidate = _parse_cli(script_path, argv)
    script_path = script_path.resolve(strict=True)
    row = _load_policy(script_path.parent / "policies/holoagent0-trace-tool-v1.json")
    runner = OwnedSessionRunner(signal_latch=latch)
    cleanup_runner = runner.for_cleanup()
    source_archive = None
    if archive is None:
        validate_build_pins(row, script_path, runner)
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
    snapshot = None
    output_registry = None
    output_stage = None
    measurement = None
    docker_owner = None
    docker_client = None
    publication_transition = None
    docker_environment = None
    cleanup_succeeded = True
    ordinary_status = 0
    primary_error = None
    try:
        _raise_if_interrupted(latch)
        registry = OwnedPathRegistry(parent.resolve(strict=True))
        root = registry.create_directory(
            f".holoagent0-strace-{secrets.token_hex(16)}", mode=0o700
        )
        docker_client = create_docker_client_context(root.fd, os.environ)
        docker_environment = docker_client.environment
        snapshot = create_sealable_archive("holoagent0-strace-6.6")
        transfer_archive(
            source_archive,
            retained_fd_path(snapshot.fd),
            runner,
            deadline=120.0,
            snapshot_fd=snapshot.fd,
        )
        if source_archive is not None:
            current = os.fstat(source_archive.fd)
            if (current.st_dev, current.st_ino) != (
                source_archive.device,
                source_archive.inode,
            ):
                raise ArchiveValidationError("source archive identity changed")
            source_archive.close()
        seal_retained_archive(snapshot)
        _validate_snapshot_fd(snapshot.fd, runner, 120.0)
        verify_sealed_archive(snapshot)
        if archive is not None:
            validate_build_pins(row, script_path, runner)
        if output is not None:
            runtime_pins = validate_runtime_pins(row)
            output_registry = OwnedPathRegistry(output.parent)
            output_stage = output_registry.create_directory(
                f".holoagent0-strace-install-{secrets.token_hex(16)}", mode=0o700
            )
            install_path = retained_fd_path(output_stage.fd)
        else:
            os.mkdir("install", 0o700, dir_fd=root.fd)
            install_path = retained_fd_path(root.fd, "install")
            runtime_pins = None
        os.mkdir("source", 0o700, dir_fd=root.fd)
        os.mkdir("build", 0o700, dir_fd=root.fd)
        source_path = retained_fd_path(root.fd, "source")
        build_path = retained_fd_path(root.fd, "build")
        verify_sealed_archive(snapshot)
        extraction = run_blocking_phase(
            "archive_extraction",
            [
                "/usr/bin/tar",
                "--extract",
                "--xz",
                "--file",
                str(retained_fd_path(snapshot.fd)),
                "--directory",
                str(retained_fd_path(root.fd, "source")),
                "--no-same-owner",
                "--no-same-permissions",
                TOP_DIRECTORY,
            ],
            runner,
            deadline=120.0,
            pass_fds=(snapshot.fd, root.fd),
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
            cleanup_runner=cleanup_runner,
            name=f"holoagent0-strace-{nonce}",
            nonce=nonce,
            stabilization=1.0,
            command_timeout=3.0,
        )
        built = docker_owner.run_container(
            build_argv[2:], timeout=3600.0, env=docker_environment
        )
        if built.returncode != 0:
            raise ProvisioningError("reproducible strace build failed")
        if output is not None:
            measurement = open_owned_staged_install(
                output.parent / output_stage.name,
                output_registry.parent_fd,
                output_stage,
            )
            _verify_staging_name(measurement)
            measured = _measure_elf_fd(
                measurement.elf_fd, runner, 10.0, require_exact=True
            )
        else:
            measured = measure_elf_pins(
                install_path / "bin/strace",
                runner,
                deadline=10.0,
                require_exact=True,
            )
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
            _verify_retained_measurement(measurement, runtime_pins, runner, 10.0)
            quarantine = (
                output.parent / f".holoagent0-strace-quarantine-{secrets.token_hex(16)}"
            )
            try:
                publication_transition = publish_install_directory(
                    output.parent / output_stage.name,
                    output,
                    quarantine,
                    measurement,
                    runtime_pins,
                    runner,
                    deadline=10.0,
                    signal_latch=latch,
                )
            except (PublicationError, ProvisioningInterrupted) as error:
                publication_transition = error.transition
                if (
                    publication_transition is not None
                    and publication_transition.state
                    in {"PUBLISHED", "ROLLBACK_PREPARED"}
                ):
                    output_stage.name = output.name
                raise
            output_registry.forget(output_stage)
            output_stage = None
    except BaseException as error:
        primary_error = error
        if isinstance(error, ProvisioningInterrupted):
            ordinary_status = error.status
    finally:
        with latch.block_for_cleanup():
            actions = []
            if source_archive is not None:
                actions.append(("source_archive", source_archive.close))
            if docker_owner is not None:
                actions.append(
                    (
                        "docker",
                        lambda: docker_owner.cleanup(env=docker_environment),
                    )
                )
            if docker_client is not None:
                actions.append(("docker_client", docker_client.close))
            if measurement is not None:
                actions.append(("measurement", measurement.close))
            if snapshot is not None:
                actions.append(("snapshot", lambda: close_owned_path(snapshot)))
            if output_registry is not None and output_stage is not None:
                actions.append(
                    (
                        "output",
                        lambda: cleanup_publication_stage(
                            output_registry,
                            output_stage,
                            publication_transition,
                        ),
                    )
                )
            if registry is not None and root is not None:
                actions.append(("root", lambda: registry.remove_tree(root)))
            if output_registry is not None:
                actions.append(("output_registry", output_registry.close))
            if registry is not None:
                actions.append(("registry", registry.close))
            report = aggregate_cleanup(actions)
            cleanup_succeeded = report.succeeded
    if not cleanup_succeeded:
        return 3
    if latch.status:
        return latch.final_status(
            cleanup_succeeded=cleanup_succeeded, ordinary_status=ordinary_status
        )
    if primary_error is not None and not isinstance(
        primary_error, ProvisioningInterrupted
    ):
        raise primary_error
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


if __name__ == "__main__" and "__file__" in globals():
    raise SystemExit(main(sys.argv))
# END_PROVISIONER_PYTHON
