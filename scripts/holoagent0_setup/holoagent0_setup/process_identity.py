"""Fail-closed Linux process identities for local supervisor coordination."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat


class ProcessIdentityError(RuntimeError):
    """A complete, stable process identity could not be established."""


_MAX_PROC_STAT_BYTES = 16 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ProcessIdentity:
    """Immutable binding to a Linux process and its executable bytes."""

    pid: int
    pgid: int
    start_time: int
    executable_path: str
    executable_sha256: str

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise ProcessIdentityError("pid must be an exact positive integer")
        if type(self.pgid) is not int or self.pgid <= 0:
            raise ProcessIdentityError("pgid must be an exact positive integer")
        if type(self.start_time) is not int or self.start_time <= 0:
            raise ProcessIdentityError("start_time must be an exact positive integer")
        if type(self.executable_path) is not str:
            raise ProcessIdentityError("executable_path must be an exact string")
        if not self.executable_path or not os.path.isabs(self.executable_path):
            raise ProcessIdentityError("executable_path must be absolute")
        try:
            self.executable_path.encode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ProcessIdentityError(
                "executable_path contains invalid Unicode"
            ) from error
        if type(self.executable_sha256) is not str:
            raise ProcessIdentityError("executable_sha256 must be an exact string")
        if len(self.executable_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.executable_sha256
        ):
            raise ProcessIdentityError("executable_sha256 must be lowercase SHA-256")

    def as_dict(self) -> dict[str, object]:
        """Return the closed broker representation."""

        return {
            "pid": self.pid,
            "pgid": self.pgid,
            "start_time": self.start_time,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
        }

    @classmethod
    def from_dict(cls, value: object) -> ProcessIdentity:
        """Build an identity from an exact closed broker object."""

        if type(value) is not dict or set(value) != {
            "pid",
            "pgid",
            "start_time",
            "executable_path",
            "executable_sha256",
        }:
            raise ProcessIdentityError("process identity object is not closed")
        return cls(
            pid=value["pid"],
            pgid=value["pgid"],
            start_time=value["start_time"],
            executable_path=value["executable_path"],
            executable_sha256=value["executable_sha256"],
        )

    def matches_proc(self, proc_root: Path = Path("/proc")) -> bool:
        """Compare the complete tuple, returning false on every observation defect."""

        try:
            return read_process_identity(proc_root, self.pid) == self
        except Exception:
            return False


def read_process_identity(proc_root: Path, pid: int) -> ProcessIdentity:
    """Read one stable process/executable identity through Linux ``/proc``."""

    if type(pid) is not int or pid <= 0:
        raise ProcessIdentityError("pid must be an exact positive integer")
    root_fd = -1
    pid_fd = -1
    try:
        root = Path(proc_root)
        pid_dir = root / str(pid)
        stat_path = pid_dir / "stat"
        exe_link = pid_dir / "exe"
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        root_path_stat = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(root_path_stat.st_mode):
            raise ProcessIdentityError("proc root is not a direct directory")
        root_fd = os.open(root, directory_flags)
        root_fd_stat = os.fstat(root_fd)
        if _file_identity(root_path_stat) != _file_identity(root_fd_stat):
            raise ProcessIdentityError("proc root binding changed")
        pid_fd = os.open(str(pid), directory_flags, dir_fd=root_fd)
        pid_fd_stat = os.fstat(pid_fd)
        if not stat.S_ISDIR(pid_fd_stat.st_mode):
            raise ProcessIdentityError("proc pid entry is not a directory")

        stat_before = _read_proc_stat(stat_path, pid)
        link_before = os.readlink(exe_link)
        executable_path = _closed_executable_path(link_before)
        path_before = os.stat(executable_path, follow_symlinks=False)
        _require_executable(path_before)

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        executable_fd = os.open(executable_path, flags)
        try:
            fd_before = os.fstat(executable_fd)
            _require_executable(fd_before)
            if _file_identity(fd_before) != _file_identity(path_before):
                raise ProcessIdentityError("executable path binding changed")
            proc_exe_before = os.stat(exe_link)
            if _file_identity(proc_exe_before) != _file_identity(fd_before):
                raise ProcessIdentityError("proc executable binding mismatch")
            executable_sha256 = _sha256_fd(executable_fd)
            fd_after = os.fstat(executable_fd)
            if _stable_file_identity(fd_before) != _stable_file_identity(fd_after):
                raise ProcessIdentityError("executable changed while hashing")
        finally:
            os.close(executable_fd)

        stat_after = _read_proc_stat(stat_path, pid)
        link_after = os.readlink(exe_link)
        path_after = os.stat(executable_path, follow_symlinks=False)
        proc_exe_after = os.stat(exe_link)
        if stat_before != stat_after:
            raise ProcessIdentityError("process identity changed while observed")
        if link_before != link_after:
            raise ProcessIdentityError("proc executable link changed while observed")
        if _stable_file_identity(path_before) != _stable_file_identity(
            path_after
        ) or _file_identity(proc_exe_after) != _file_identity(path_after):
            raise ProcessIdentityError("executable binding changed while observed")
        root_path_after = os.stat(root, follow_symlinks=False)
        pid_path_after = os.stat(str(pid), dir_fd=root_fd, follow_symlinks=False)
        if _file_identity(root_path_after) != _file_identity(
            root_fd_stat
        ) or _file_identity(pid_path_after) != _file_identity(pid_fd_stat):
            raise ProcessIdentityError("proc path binding changed while observed")

        pgid, _session, start_time = stat_before
        return ProcessIdentity(
            pid=pid,
            pgid=pgid,
            start_time=start_time,
            executable_path=executable_path,
            executable_sha256=executable_sha256,
        )
    except ProcessIdentityError:
        raise
    except (OSError, ValueError, UnicodeError) as error:
        raise ProcessIdentityError("could not establish process identity") from error
    finally:
        if pid_fd >= 0:
            os.close(pid_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _read_proc_stat(path: Path, expected_pid: int) -> tuple[int, int, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        chunks: list[bytes] = []
        size = 0
        while True:
            try:
                chunk = os.read(fd, min(4096, _MAX_PROC_STAT_BYTES - size + 1))
            except InterruptedError:
                continue
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > _MAX_PROC_STAT_BYTES:
                raise ProcessIdentityError("proc stat exceeds the byte bound")
        after = os.fstat(fd)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise ProcessIdentityError("proc stat changed while read")
    finally:
        os.close(fd)
    try:
        raw = b"".join(chunks).decode("ascii", errors="strict").strip()
        open_parenthesis = raw.find("(")
        close_parenthesis = raw.rfind(")")
        if open_parenthesis <= 0 or close_parenthesis <= open_parenthesis:
            raise ValueError("malformed comm")
        if int(raw[:open_parenthesis].strip()) != expected_pid:
            raise ValueError("pid mismatch")
        fields = raw[close_parenthesis + 1 :].split()
        if len(fields) < 20:
            raise ValueError("short proc stat")
        pgid = int(fields[2])  # field 5
        session = int(fields[3])  # field 6
        start_time = int(fields[19])  # field 22
        if pgid <= 0 or session <= 0 or start_time <= 0:
            raise ValueError("invalid process group, session, or start time")
        if pgid != session:
            raise ProcessIdentityError(
                "process group must belong to the reported process session"
            )
        return pgid, session, start_time
    except (UnicodeError, ValueError) as error:
        raise ProcessIdentityError("proc stat is malformed") from error


def _closed_executable_path(link_value: str) -> str:
    if type(link_value) is not str or not os.path.isabs(link_value):
        raise ProcessIdentityError("proc executable path is not absolute")
    if link_value.endswith(" (deleted)"):
        raise ProcessIdentityError("proc executable was deleted")
    normalized = os.path.normpath(link_value)
    if normalized != link_value:
        raise ProcessIdentityError("proc executable path is not normalized")
    return normalized


def _require_executable(file_stat: os.stat_result) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise ProcessIdentityError("executable is not a regular file")
    if not file_stat.st_mode & 0o111:
        raise ProcessIdentityError("executable has no execute mode bit")
    if file_stat.st_uid not in {0, os.getuid()}:
        raise ProcessIdentityError("executable owner is not trusted")
    if file_stat.st_mode & 0o022:
        raise ProcessIdentityError("executable is group/world writable")


def _sha256_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        try:
            chunk = os.read(fd, _HASH_CHUNK_BYTES)
        except InterruptedError:
            continue
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _file_identity(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    return file_stat.st_dev, file_stat.st_ino, file_stat.st_mode, file_stat.st_uid


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
