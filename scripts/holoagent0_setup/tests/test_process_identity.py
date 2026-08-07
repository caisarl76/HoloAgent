"""Linux process-identity validation tests."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import holoagent0_setup.process_identity as identity_module
from holoagent0_setup.process_identity import (
    ProcessIdentity,
    ProcessIdentityError,
    read_process_identity,
)


def _write_proc_fixture(
    root: Path,
    executable: Path,
    *,
    pid: int = 321,
    pgid: int = 300,
    session: int = 300,
    start_time: int = 987654,
    comm: str = "worker (with spaces) name",
) -> Path:
    pid_dir = root / str(pid)
    pid_dir.mkdir(parents=True)
    fields = ["0"] * 50  # fields 3 through 52
    fields[0] = "S"
    fields[1] = "1"
    fields[2] = str(pgid)
    fields[3] = str(session)
    fields[19] = str(start_time)
    (pid_dir / "stat").write_text(
        f"{pid} ({comm}) {' '.join(fields)}\n", encoding="ascii"
    )
    (pid_dir / "exe").symlink_to(executable)
    return pid_dir


def test_reads_complete_identity_and_stat_field_22_despite_comm_parentheses(tmp_path):
    executable = tmp_path / "coordinator"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    proc_root = tmp_path / "proc"
    _write_proc_fixture(proc_root, executable)

    identity = read_process_identity(proc_root, 321)

    assert identity == ProcessIdentity(
        pid=321,
        pgid=300,
        start_time=987654,
        executable_path=str(executable.resolve()),
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    assert identity.matches_proc(proc_root)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"pid": True},
        {"pid": 0},
        {"pgid": -1},
        {"start_time": True},
        {"executable_path": "relative"},
        {"executable_path": "/\ud800"},
        {"executable_sha256": "A" * 64},
        {"executable_sha256": "0" * 63},
    ],
)
def test_process_identity_is_frozen_and_closed(kwargs):
    values = {
        "pid": 1,
        "pgid": 1,
        "start_time": 1,
        "executable_path": "/bin/tool",
        "executable_sha256": "0" * 64,
    }
    values.update(kwargs)
    with pytest.raises(ProcessIdentityError):
        ProcessIdentity(**values)


def test_matches_proc_compares_every_field_and_fails_closed(tmp_path):
    executable = tmp_path / "coordinator"
    executable.write_bytes(b"stable")
    executable.chmod(0o700)
    proc_root = tmp_path / "proc"
    _write_proc_fixture(proc_root, executable)
    identity = read_process_identity(proc_root, 321)

    fields = ["pid", "pgid", "start_time", "executable_path", "executable_sha256"]
    replacements = [322, 301, 987655, "/different", "1" * 64]
    for field, replacement in zip(fields, replacements):
        values = identity.as_dict()
        values[field] = replacement
        assert not ProcessIdentity(**values).matches_proc(proc_root)
    assert not identity.matches_proc(proc_root / "missing")


@pytest.mark.parametrize("malformation", ["missing_close", "short", "bad_number"])
def test_malformed_proc_stat_is_normalized(malformation, tmp_path):
    executable = tmp_path / "coordinator"
    executable.write_bytes(b"stable")
    executable.chmod(0o700)
    proc_root = tmp_path / "proc"
    pid_dir = _write_proc_fixture(proc_root, executable)
    if malformation == "missing_close":
        raw = "321 (oops S 1 2 3"
    elif malformation == "short":
        raw = "321 (ok) S 1"
    else:
        raw = (pid_dir / "stat").read_text().replace("987654", "bad")
    (pid_dir / "stat").write_text(raw, encoding="ascii")
    with pytest.raises(ProcessIdentityError):
        read_process_identity(proc_root, 321)


def test_generic_identity_accepts_process_group_distinct_from_session(tmp_path):
    executable = tmp_path / "coordinator"
    executable.write_bytes(b"stable")
    executable.chmod(0o700)
    proc_root = tmp_path / "proc"
    _write_proc_fixture(proc_root, executable, pgid=300, session=299)
    identity = read_process_identity(proc_root, 321)
    assert identity.pid == 321
    assert identity.pgid == 300


def test_reads_live_non_session_leader_process_group():
    pid = os.posix_spawn(
        "/usr/bin/python3.10",
        ["/usr/bin/python3.10", "-c", "import time; time.sleep(0.4)"],
        os.environ,
        setpgroup=0,
    )
    try:
        assert os.getpgid(pid) == pid
        assert os.getsid(pid) != pid
        identity = read_process_identity(Path("/proc"), pid)
        assert identity.pid == identity.pgid == pid
        assert identity.matches_proc()
        assert not identity.matches_coordinator_session()
    finally:
        waited_pid, status = os.waitpid(pid, 0)
        assert waited_pid == pid
        assert os.waitstatus_to_exitcode(status) == 0


def test_rejects_symlinked_executable_target_non_executable_and_content_change(
    tmp_path,
):
    target = tmp_path / "target"
    target.write_bytes(b"stable")
    target.chmod(0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    proc_root = tmp_path / "proc"
    pid_dir = _write_proc_fixture(proc_root, alias)
    with pytest.raises(ProcessIdentityError):
        read_process_identity(proc_root, 321)

    (pid_dir / "exe").unlink()
    (pid_dir / "exe").symlink_to(target)
    target.chmod(0o600)
    with pytest.raises(ProcessIdentityError):
        read_process_identity(proc_root, 321)


def test_detects_proc_exe_binding_replacement_without_leaking_raw_oserror(
    monkeypatch, tmp_path
):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for path in (first, second):
        path.write_bytes(path.name.encode())
        path.chmod(0o700)
    proc_root = tmp_path / "proc"
    _write_proc_fixture(proc_root, first)
    original = os.readlink
    calls = 0

    def replaced(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls >= 2:
            return str(second)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "readlink", replaced)
    with pytest.raises(ProcessIdentityError):
        read_process_identity(proc_root, 321)


def test_detects_proc_pid_directory_replacement_even_with_identical_contents(
    monkeypatch, tmp_path
):
    executable = tmp_path / "coordinator"
    executable.write_bytes(b"stable")
    executable.chmod(0o700)
    proc_root = tmp_path / "proc"
    pid_dir = _write_proc_fixture(proc_root, executable)
    replacement = _write_proc_fixture(proc_root / "replacement-root", executable)
    replacement_target = proc_root / "replacement"
    replacement.rename(replacement_target)
    original = os.readlink
    replaced = False

    def replace_after_first_link(path, *args, **kwargs):
        nonlocal replaced
        value = original(path, *args, **kwargs)
        if not replaced:
            replaced = True
            pid_dir.rename(proc_root / "old-321")
            replacement_target.rename(pid_dir)
        return value

    monkeypatch.setattr(os, "readlink", replace_after_first_link)
    with pytest.raises(ProcessIdentityError):
        read_process_identity(proc_root, 321)


def test_matches_proc_normalizes_unexpected_observation_failure(monkeypatch):
    identity = ProcessIdentity(1, 1, 1, "/bin/tool", "0" * 64)

    def fail(*_args, **_kwargs):
        raise RuntimeError("observer defect")

    monkeypatch.setattr(identity_module, "read_process_identity", fail)
    assert not identity.matches_proc()
