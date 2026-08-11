"""Black-box tests for the native offline launch boundary."""

from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import platform
import resource
import signal
import socket
import subprocess
import sys

import pytest


NATIVE_ROOT = Path(__file__).resolve().parents[1] / "native"
TRACEE_LAUNCHER = NATIVE_ROOT / "build" / "tracee_launcher"
FINALIZER_ONLY = NATIVE_ROOT / "build" / "finalizer_only"
NATIVE_TEST_PROBE = NATIVE_ROOT / "build" / "native_test_probe"


@pytest.fixture(scope="session", autouse=True)
def _build_native_helpers():
    completed = subprocess.run(
        ["make", "-C", str(NATIVE_ROOT), "clean", "all"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout.decode("utf-8", errors="replace")


def _run_launcher(
    finalizer_args: tuple[str, ...] = ("--inspect",),
    *,
    executable: Path = FINALIZER_ONLY,
    pass_fds: tuple[int, ...] = (),
    mappings: tuple[tuple[int, int, str], ...] = (),
    stdio_override: tuple[int, object] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object] | None]:
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    command = [
        str(TRACEE_LAUNCHER),
        "--report-fd",
        str(report_write),
    ]
    for source, target, direction in mappings:
        command.extend(("--pass-fd", f"{source}:{target}:{direction}"))
    command.extend(("--", str(executable), *finalizer_args))

    stdio: dict[str, object] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if stdio_override is not None:
        descriptor, replacement = stdio_override
        stdio[("stdin", "stdout", "stderr")[descriptor]] = replacement

    try:
        completed = subprocess.run(
            command,
            check=False,
            pass_fds=tuple(sorted({report_write, *pass_fds})),
            timeout=5,
            **stdio,
        )
    finally:
        os.close(report_write)
    with os.fdopen(report_read, "rb") as report:
        payload = report.read()
    return completed, json.loads(payload) if payload else None


def _run_probe(
    arguments: tuple[str, ...],
) -> tuple[subprocess.CompletedProcess[bytes], dict[str, object] | None]:
    return _run_launcher(arguments, executable=NATIVE_TEST_PROBE)


def _stdout_json(completed: subprocess.CompletedProcess[bytes]) -> dict[str, object]:
    assert completed.stdout is not None
    return json.loads(completed.stdout)


@contextmanager
def _fd_limit_supporting(minimum_fd: int):
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard_limit != resource.RLIM_INFINITY and hard_limit <= minimum_fd:
        pytest.skip("RLIMIT_NOFILE cannot represent the reviewed high-FD case")
    raised_limit = soft_limit <= minimum_fd
    if raised_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, (minimum_fd + 1, hard_limit))
    try:
        yield
    finally:
        if raised_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))


def test_native_makefile_builds_pie_executables():
    for executable in (TRACEE_LAUNCHER, FINALIZER_ONLY, NATIVE_TEST_PROBE):
        assert executable.is_file()
        assert os.access(executable, os.X_OK)
        elf_header = executable.read_bytes()[:20]
        assert elf_header[:4] == b"\x7fELF"
        byte_order = {1: "little", 2: "big"}[elf_header[5]]
        assert int.from_bytes(elf_header[16:18], byte_order) == 3  # ET_DYN PIE

    assert (NATIVE_ROOT / ".gitignore").read_bytes() == b"/build/\n"


def test_tracee_launcher_rejects_passed_inherited_socket():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as inherited:
        completed, report = _run_launcher(pass_fds=(inherited.fileno(),))

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def test_tracee_launcher_rejects_unmapped_inherited_pipe():
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    try:
        completed, report = _run_launcher(pass_fds=(read_end,))
    finally:
        os.close(read_end)
        os.close(write_end)

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def test_tracee_launcher_rejects_inherited_socket_above_reviewed_target_limit():
    minimum_fd = 70_000
    high_fd = -1
    with _fd_limit_supporting(minimum_fd):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as inherited:
                high_fd = fcntl.fcntl(
                    inherited.fileno(), fcntl.F_DUPFD_CLOEXEC, minimum_fd
                )
                assert high_fd >= minimum_fd
                completed, report = _run_launcher(pass_fds=(high_fd,))
        finally:
            if high_fd >= 0:
                os.close(high_fd)

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def test_tracee_launcher_accepts_high_source_fd_for_reviewed_pipe_target():
    minimum_fd = 70_000
    high_fd = -1
    with _fd_limit_supporting(minimum_fd):
        read_end, write_end = os.pipe2(os.O_CLOEXEC)
        try:
            high_fd = fcntl.fcntl(read_end, fcntl.F_DUPFD_CLOEXEC, minimum_fd)
            completed, report = _run_launcher(
                pass_fds=(high_fd,), mappings=((high_fd, 9, "read"),)
            )
        finally:
            if high_fd >= 0:
                os.close(high_fd)
            os.close(read_end)
            os.close(write_end)

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed)["fds"] == [0, 1, 2, 9]


def test_tracee_launcher_accepts_high_write_only_report_fd():
    minimum_fd = 70_000
    high_fd = -1
    with _fd_limit_supporting(minimum_fd):
        report_read, report_write = os.pipe2(os.O_CLOEXEC)
        try:
            high_fd = fcntl.fcntl(report_write, fcntl.F_DUPFD_CLOEXEC, minimum_fd)
            completed = subprocess.run(
                [
                    str(TRACEE_LAUNCHER),
                    "--report-fd",
                    str(high_fd),
                    "--",
                    str(FINALIZER_ONLY),
                    "--inspect",
                ],
                check=False,
                pass_fds=(high_fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
        finally:
            if high_fd >= 0:
                os.close(high_fd)
            os.close(report_write)
            with os.fdopen(report_read, "rb") as report:
                report_payload = report.read()

    assert completed.returncode == 0, completed.stderr
    assert report_payload == b""


@pytest.mark.parametrize("descriptor", [0, 1, 2])
def test_tracee_launcher_rejects_socket_in_standard_descriptor(descriptor):
    inherited, peer = socket.socketpair()
    with inherited, peer:
        completed, report = _run_launcher(stdio_override=(descriptor, inherited))
        inherited.close()
        peer.settimeout(0.05)
        assert peer.recv(1) == b""

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def test_tracee_launcher_rejects_non_devnull_stdin(tmp_path):
    stdin_path = tmp_path / "stdin"
    stdin_path.write_bytes(b"not devnull")
    with stdin_path.open("rb") as inherited:
        completed, report = _run_launcher(stdio_override=(0, inherited))

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


@pytest.mark.parametrize("descriptor", [1, 2])
def test_tracee_launcher_rejects_character_device_output(descriptor):
    with open("/dev/null", "wb") as inherited:
        completed, report = _run_launcher(stdio_override=(descriptor, inherited))

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def _assert_rejected_pass_fd(fd: int) -> None:
    completed, report = _run_launcher(pass_fds=(fd,), mappings=((fd, 9, "read"),))
    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


def test_tracee_launcher_rejects_regular_and_named_fifo_pass_fds(tmp_path):
    regular_path = tmp_path / "regular"
    regular_path.write_bytes(b"not a broker pipe")
    regular_fd = os.open(regular_path, os.O_RDONLY | os.O_CLOEXEC)
    fifo_path = tmp_path / "named-fifo"
    os.mkfifo(fifo_path)
    fifo_fd = os.open(fifo_path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        _assert_rejected_pass_fd(regular_fd)
        _assert_rejected_pass_fd(fifo_fd)
    finally:
        os.close(regular_fd)
        os.close(fifo_fd)


def test_tracee_launcher_rejects_unknown_directory_pass_fd(tmp_path):
    directory_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _assert_rejected_pass_fd(directory_fd)
    finally:
        os.close(directory_fd)


@pytest.mark.skipif(not hasattr(os, "eventfd"), reason="eventfd unavailable")
def test_tracee_launcher_rejects_unknown_eventfd():
    event_fd = os.eventfd(0, os.EFD_CLOEXEC)
    try:
        _assert_rejected_pass_fd(event_fd)
    finally:
        os.close(event_fd)


def test_tracee_launcher_relocates_only_the_explicit_pipe_manifest():
    source, writer = os.pipe2(os.O_CLOEXEC)
    try:
        completed, report = _run_launcher(
            ("--inspect",), pass_fds=(source,), mappings=((source, 9, "read"),)
        )
    finally:
        os.close(source)
        os.close(writer)

    assert completed.returncode == 0, completed.stderr
    assert report is None
    inspection = _stdout_json(completed)
    assert inspection["fds"] == [0, 1, 2, 9]
    assert inspection["fd_types"] == {
        "0": "character_device",
        "1": "pipe",
        "2": "pipe",
        "9": "pipe",
    }
    assert inspection["pid"] == inspection["pgid"] == inspection["sid"]
    assert inspection["no_new_privs"] == 1
    assert inspection["parent_death_signal"] == signal.SIGKILL


def test_tracee_launcher_requires_exact_readable_devnull_stdin():
    wrong_mode = os.open("/dev/null", os.O_WRONLY | os.O_CLOEXEC)
    try:
        completed, report = _run_launcher(stdio_override=(0, wrong_mode))
    finally:
        os.close(wrong_mode)

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


@pytest.mark.parametrize("descriptor", [1, 2])
def test_tracee_launcher_rejects_read_only_regular_output(descriptor, tmp_path):
    output_path = tmp_path / "output"
    output_path.write_bytes(b"")
    wrong_mode = os.open(output_path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        completed, report = _run_launcher(stdio_override=(descriptor, wrong_mode))
    finally:
        os.close(wrong_mode)

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


@pytest.mark.parametrize(
    ("declared_direction", "use_write_end"),
    [("read", True), ("write", False)],
)
def test_tracee_launcher_rejects_broker_pipe_end_with_wrong_declared_direction(
    declared_direction, use_write_end
):
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    source = write_end if use_write_end else read_end
    try:
        completed, report = _run_launcher(
            pass_fds=(source,), mappings=((source, 9, declared_direction),)
        )
    finally:
        os.close(read_end)
        os.close(write_end)

    assert completed.returncode == 30
    assert report == {"reason": "INHERITED_SOCKET_FD"}


@pytest.mark.parametrize(
    ("declared_direction", "use_write_end"),
    [("read", False), ("write", True)],
)
def test_tracee_launcher_accepts_broker_pipe_end_with_declared_direction(
    declared_direction, use_write_end
):
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    source = write_end if use_write_end else read_end
    try:
        completed, report = _run_launcher(
            pass_fds=(source,), mappings=((source, 9, declared_direction),)
        )
    finally:
        os.close(read_end)
        os.close(write_end)

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed)["fds"] == [0, 1, 2, 9]


@pytest.mark.parametrize("mapping", ["{source}:9", "{source}:9:sideways"])
def test_tracee_launcher_rejects_pass_fd_without_closed_direction_role(mapping):
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    try:
        completed = subprocess.run(
            [
                str(TRACEE_LAUNCHER),
                "--report-fd",
                str(report_write),
                "--pass-fd",
                mapping.format(source=read_end),
                "--",
                str(FINALIZER_ONLY),
                "--inspect",
            ],
            check=False,
            pass_fds=(read_end, report_write),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    finally:
        os.close(read_end)
        os.close(write_end)
        os.close(report_read)
        os.close(report_write)

    assert completed.returncode == 64


def test_tracee_launcher_retains_reviewed_mapping_target_ceiling():
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    try:
        completed, report = _run_launcher(
            pass_fds=(read_end,), mappings=((read_end, 70_000, "read"),)
        )
    finally:
        os.close(read_end)
        os.close(write_end)

    assert completed.returncode == 64
    assert report is None


def test_tracee_launcher_requires_write_only_report_pipe():
    report_read, report_write = os.pipe2(os.O_CLOEXEC)
    try:
        completed = subprocess.run(
            [
                str(TRACEE_LAUNCHER),
                "--report-fd",
                str(report_read),
                "--",
                str(FINALIZER_ONLY),
                "--inspect",
            ],
            check=False,
            pass_fds=(report_read,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    finally:
        os.close(report_read)
        os.close(report_write)

    assert completed.returncode == 30


@pytest.mark.parametrize(
    "syscall_name",
    [
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "pidfd_getfd",
        "ptrace",
        "clone_untraced",
    ],
)
def test_seccomp_denies_each_reviewed_bypass(syscall_name):
    completed, report = _run_probe(("--probe", syscall_name))

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed) == {
        "probe": syscall_name,
        "result": -1,
        "errno": errno.EPERM,
    }


def test_clone3_gets_reviewed_fallback_errno():
    completed, report = _run_probe(("--probe", "clone3"))

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed) == {
        "probe": "clone3",
        "result": -1,
        "errno": errno.ENOSYS,
    }


@pytest.mark.skipif(platform.machine() != "x86_64", reason="x32 is x86_64-only")
def test_x32_compat_abi_is_rejected_instead_of_remapped_to_native():
    completed, report = _run_probe(("--probe", "x32_ptrace"))

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed) == {
        "probe": "x32_ptrace",
        "result": -1,
        "errno": errno.ENOSYS,
    }


def test_x32_guard_precedes_native_syscall_dispatch():
    policy_source = (NATIVE_ROOT / "seccomp_policy.c").read_text(encoding="utf-8")
    guard = policy_source.index("__X32_SYSCALL_BIT")
    guard_errno = policy_source.index("ERRNO_ACTION(ENOSYS)", guard)
    first_native_dispatch = policy_source.index("__NR_io_uring_setup")

    assert guard < guard_errno < first_native_dispatch
    assert "0x3fffffff" not in policy_source


@pytest.mark.parametrize("syscall_name", ["getpid", "clone_plain"])
def test_seccomp_leaves_unlisted_process_syscalls_usable(syscall_name):
    completed, report = _run_probe(("--probe", syscall_name))

    assert completed.returncode == 0, completed.stderr
    assert report is None
    probe = _stdout_json(completed)
    assert probe["probe"] == syscall_name
    assert probe["result"] >= 0
    assert probe["errno"] == 0


def test_seccomp_leaves_ordinary_unix_message_syscalls_usable():
    policy_source = (NATIVE_ROOT / "seccomp_policy.c").read_text(encoding="utf-8")
    for syscall_name in ("sendmsg", "recvmsg", "sendmmsg", "recvmmsg"):
        assert syscall_name not in policy_source

    ambient = subprocess.run(
        [str(NATIVE_TEST_PROBE), "--message-round-trip"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )
    ambient_result = _stdout_json(ambient)
    if ambient.returncode != 0:
        denied = {
            ambient_result["sendmsg_errno"],
            ambient_result["recvmsg_errno"],
            ambient_result["sendmmsg_errno"],
            ambient_result["recvmmsg_errno"],
        }
        assert errno.EPERM in denied
        pytest.skip(f"ambient syscall policy denies Unix messaging: {denied}")

    completed, report = _run_probe(("--message-round-trip",))

    assert completed.returncode == 0, completed.stderr
    assert report is None
    assert _stdout_json(completed) == {
        "sendmsg": True,
        "recvmsg": True,
        "sendmmsg": True,
        "recvmmsg": True,
        "sendmsg_errno": 0,
        "recvmsg_errno": 0,
        "sendmmsg_errno": 0,
        "recvmmsg_errno": 0,
    }


def test_finalizer_only_rejects_unknown_work_and_returns_boundedly():
    completed, report = _run_launcher(("--not-approved",))

    assert completed.returncode == 64
    assert report is None
    assert completed.stderr == b"finalizer_only: unsupported operation\n"

    completed, report = _run_launcher(("--probe", "getpid"))
    assert completed.returncode == 64
    assert report is None
    assert completed.stderr == b"finalizer_only: unsupported operation\n"


def test_native_deadline_unblocks_inherited_sigalrm_mask():
    launcher_arguments = [
        str(TRACEE_LAUNCHER),
        "--",
        str(NATIVE_TEST_PROBE),
        "--block-forever",
    ]
    wrapper = (
        "import os, signal, sys; "
        "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM}); "
        "os.execv(sys.argv[1], sys.argv[1:])"
    )
    completed = subprocess.run(
        [sys.executable, "-c", wrapper, *launcher_arguments],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=6,
    )

    assert completed.returncode == 124
