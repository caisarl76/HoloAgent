from __future__ import annotations

import builtins
import _thread
import errno
import fcntl
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from types import ModuleType, SimpleNamespace

import pytest

import holoagent0_setup.chatbot_gate as chatbot_gate

from holoagent0_setup.chatbot_gate import (
    OfflineStartupSideEffectAttempt,
    REQUIRED_IMPORTS,
    REQUIRED_PROVIDER_VARIABLES,
    _run_chatbot_gates_core as run_chatbot_gates,
    classify_external_readiness,
    enumerate_audio_devices,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CHATBOT_ROOT = REPOSITORY_ROOT / "agentic_robot/chatbot/g1"
PYPROJECT = CHATBOT_ROOT / "pyproject.toml"
CONFIG = CHATBOT_ROOT / "g1.json"
CHATBOT_CHILD_SOURCE = REPOSITORY_ROOT / "scripts/holoagent0_setup/chatbot_child.py"
CHATBOT_MANIFEST_RELATIVE = Path(
    "scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt"
)
CHATBOT_CHILD_RELATIVE = Path("scripts/holoagent0_setup/chatbot_child.py")
CHATBOT_GATE_RELATIVE = Path(
    "scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py"
)


def test_chatbot_required_imports_cover_all_seven_runtime_dependencies():
    assert REQUIRED_IMPORTS == (
        "aiohttp",
        "loguru",
        "numpy",
        "openai",
        "pyaudio",
        "pydub",
        "websockets",
    )


def test_chatbot_gate_import_does_not_require_agentos_or_yaml(monkeypatch):
    module_name = "holoagent0_setup.chatbot_gate"
    loaded = sys.modules.pop(module_name)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "yaml" or name.endswith("agentos_gate"):
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    try:
        reloaded = importlib.import_module(module_name)
        assert reloaded.REQUIRED_IMPORTS == REQUIRED_IMPORTS
    finally:
        sys.modules[module_name] = loaded


@pytest.mark.parametrize("install_mode", ["no_op", "veto"])
def test_chatbot_guard_requires_audited_installation_acknowledgement(install_mode):
    package_root = str(Path(chatbot_gate.__file__).resolve().parents[1])
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from holoagent0_setup.chatbot_gate import _PythonOfflineSideEffectGuard

if sys.argv[2] == "no_op":
    sys.addaudithook = lambda _hook: None
else:
    def veto(_hook):
        raise RuntimeError("vetoed")
    sys.addaudithook = veto

try:
    with _PythonOfflineSideEffectGuard():
        pass
except RuntimeError:
    raise SystemExit(0)
raise SystemExit(9)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, package_root, install_mode],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0


def test_chatbot_guard_supports_repeated_distinct_instances():
    with chatbot_gate.ChatbotOfflineSideEffectGuard():
        pass
    with chatbot_gate.ChatbotOfflineSideEffectGuard():
        pass


def test_chatbot_guard_instance_is_explicitly_single_use():
    guard = chatbot_gate.ChatbotOfflineSideEffectGuard()

    with guard:
        pass

    with pytest.raises(RuntimeError, match="single-use"):
        with guard:
            pass


def test_chatbot_deadline_restores_handler_when_timer_activation_fails(monkeypatch):
    previous_handler = object()
    handler_calls = []
    timer_calls = []

    monkeypatch.setattr(signal, "getitimer", lambda _which: (0.0, 0.0))
    monkeypatch.setattr(signal, "getsignal", lambda _signum: previous_handler)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda signum, handler: handler_calls.append((signum, handler)),
    )

    def setitimer(which, delay):
        timer_calls.append((which, delay))
        if delay:
            raise RuntimeError("activation failed")

    monkeypatch.setattr(signal, "setitimer", setitimer)

    with pytest.raises(RuntimeError, match="activation failed"):
        with chatbot_gate._WholeReadinessDeadline(1.0):
            pass

    assert timer_calls == [(signal.ITIMER_REAL, 1.0), (signal.ITIMER_REAL, 0.0)]
    assert handler_calls[-1] == (signal.SIGALRM, previous_handler)


def test_chatbot_deadline_restores_handler_when_timer_cancellation_fails(
    monkeypatch,
):
    previous_handler = object()
    handler_calls = []

    monkeypatch.setattr(signal, "getitimer", lambda _which: (0.0, 0.0))
    monkeypatch.setattr(signal, "getsignal", lambda _signum: previous_handler)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda signum, handler: handler_calls.append((signum, handler)),
    )

    def setitimer(_which, delay):
        if not delay:
            raise RuntimeError("cancellation failed")

    monkeypatch.setattr(signal, "setitimer", setitimer)

    with pytest.raises(RuntimeError, match="cancellation failed"):
        with chatbot_gate._WholeReadinessDeadline(1.0):
            pass

    assert handler_calls[-1] == (signal.SIGALRM, previous_handler)


class DependencyProbe:
    def __init__(self, missing: tuple[str, ...] = ()) -> None:
        self.missing = set(missing)
        self.queries: list[str] = []

    def __call__(self, name: str) -> bool:
        self.queries.append(name)
        return name not in self.missing


def _devices(*, audio: bool):
    if not audio:
        return ()
    return (
        {
            "name": "Fixture USB AUDIO DEVICE revision",
            "maxInputChannels": 1,
            "maxOutputChannels": 2,
        },
    )


def _statuses(result):
    return [(gate["id"], gate["status"], gate["reason"]) for gate in result.gates]


def _configuration_measurements(result):
    return {row["name"]: row["value"] for row in result.gates[1]["measurements"]}


def _child_result_bytes(result):
    return (
        json.dumps(
            {
                "exit_code": result.exit_code,
                "gates": list(result.gates),
                "label": result.label,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _passing_child_result_bytes():
    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={
            name: "fixture-provider-secret" for name in REQUIRED_PROVIDER_VARIABLES
        },
    )
    assert result.label == "PASS_HOLOAGENT0_OFFLINE"
    return _child_result_bytes(result)


def _write_child_fixture(tmp_path, body):
    script = tmp_path / "chatbot-child-fixture.py"
    script.write_text(body, encoding="utf-8")
    return ("/usr/bin/python3.10", "-I", "-B", str(script))


def _child_control_bytes():
    return chatbot_gate._encode_chatbot_child_control(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        timeout_seconds=0.5,
    )


def _git_blob_oid(payload):
    digest = hashlib.sha1()
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _source_authority_fixture(tmp_path):
    root = tmp_path / "authority-root"
    child_path = root / CHATBOT_CHILD_RELATIVE
    gate_path = root / CHATBOT_GATE_RELATIVE
    manifest_path = root / CHATBOT_MANIFEST_RELATIVE
    child_payload = b'print("retained-child")\n'
    gate_payload = b'VALUE = "retained-gate"\n'
    child_path.parent.mkdir(parents=True)
    gate_path.parent.mkdir(parents=True)
    manifest_path.parent.mkdir(parents=True)
    child_path.write_bytes(child_payload)
    gate_path.write_bytes(gate_payload)
    child_path.chmod(0o644)
    gate_path.chmod(0o644)
    rows = sorted(
        (
            f"100644 {_git_blob_oid(child_payload)}\t{CHATBOT_CHILD_RELATIVE}\n",
            f"100644 {_git_blob_oid(gate_payload)}\t{CHATBOT_GATE_RELATIVE}\n",
        )
    )
    manifest_payload = "".join(rows).encode("utf-8")
    manifest_path.write_bytes(manifest_payload)
    manifest_path.chmod(0o644)
    authority = chatbot_gate.ChatbotSourceAuthority(
        repository_root=root,
        tracked_manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
    )
    return authority, child_payload, gate_payload


def _production_source_authority():
    return _source_authority_from_root(REPOSITORY_ROOT)


def _source_authority_from_root(repository_root):
    manifest_payload = (repository_root / CHATBOT_MANIFEST_RELATIVE).read_bytes()
    return chatbot_gate.ChatbotSourceAuthority(
        repository_root=repository_root,
        tracked_manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
    )


def _read_descriptor(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(iter(lambda: os.read(descriptor, 1024 * 1024), b""))


def test_chatbot_source_authority_is_a_required_public_argument():
    parameter = inspect.signature(chatbot_gate.run_chatbot_gates).parameters[
        "source_authority"
    ]

    assert parameter.default is inspect.Parameter.empty


def test_sealed_source_snapshots_use_retained_fds_after_path_replacement(tmp_path):
    authority, child_payload, gate_payload = _source_authority_fixture(tmp_path)
    replaced = []

    def replace_open_path(stage, relative_path, _descriptor):
        if stage != "after_open":
            return
        path = authority.repository_root / relative_path
        displaced = path.with_name(f"{path.name}.retained")
        path.replace(displaced)
        path.write_bytes(b"malicious replacement\n")
        path.chmod(0o644)
        replaced.append(relative_path)

    snapshots = chatbot_gate._prepare_chatbot_source_snapshots(
        authority,
        _source_hook=replace_open_path,
    )
    try:
        assert _read_descriptor(snapshots[0]) == child_payload
        assert _read_descriptor(snapshots[1]) == gate_payload
        for descriptor in snapshots:
            assert (
                fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
                & chatbot_gate.REQUIRED_CHATBOT_SOURCE_SEALS
                == chatbot_gate.REQUIRED_CHATBOT_SOURCE_SEALS
            )
    finally:
        for descriptor in snapshots:
            os.close(descriptor)

    assert replaced == [
        CHATBOT_MANIFEST_RELATIVE,
        CHATBOT_CHILD_RELATIVE,
        CHATBOT_GATE_RELATIVE,
    ]


def test_source_authority_rejects_in_place_mutation_during_stable_read(tmp_path):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)

    def mutate_open_inode(stage, relative_path, _descriptor):
        if stage == "after_read" and relative_path == CHATBOT_GATE_RELATIVE:
            path = authority.repository_root / relative_path
            with path.open("r+b", buffering=0) as stream:
                stream.seek(0, os.SEEK_END)
                assert stream.write(b"X") == 1

    with pytest.raises(
        chatbot_gate.ChatbotSourceAuthorityError,
        match="changed during verification",
    ):
        chatbot_gate._prepare_chatbot_source_snapshots(
            authority,
            _source_hook=mutate_open_inode,
        )


def test_source_authority_rejects_incomplete_seals_and_closes_snapshots(
    tmp_path,
    monkeypatch,
):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    descriptors = []
    real_create = os.memfd_create
    real_fcntl = fcntl.fcntl

    def record_memfd(name, flags):
        descriptor = real_create(name, flags)
        descriptors.append(descriptor)
        return descriptor

    def omit_write_seal(descriptor, operation, argument=0):
        if operation == fcntl.F_GET_SEALS:
            return fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        return real_fcntl(descriptor, operation, argument)

    monkeypatch.setattr(chatbot_gate, "_create_chatbot_source_memfd", record_memfd)
    monkeypatch.setattr(fcntl, "fcntl", omit_write_seal)

    with pytest.raises(
        chatbot_gate.ChatbotSourceAuthorityError,
        match="sealed chatbot source snapshot is incomplete",
    ):
        chatbot_gate._prepare_chatbot_source_snapshots(authority)

    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize(
    "defect",
    [
        "relative_root",
        "root_symlink",
        "wrong_manifest_digest",
        "manifest_executable",
        "source_executable",
        "source_nonregular",
        "manifest_noncanonical",
        "duplicate_source_row",
        "missing_source_row",
        "wrong_source_oid",
    ],
)
def test_source_authority_rejects_every_unreviewed_variant(tmp_path, defect):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    root = authority.repository_root
    manifest_path = root / CHATBOT_MANIFEST_RELATIVE
    child_path = root / CHATBOT_CHILD_RELATIVE
    if defect == "relative_root":
        authority = chatbot_gate.ChatbotSourceAuthority(
            repository_root=Path("relative-authority-root"),
            tracked_manifest_sha256=authority.tracked_manifest_sha256,
        )
    elif defect == "root_symlink":
        symlink = tmp_path / "authority-symlink"
        symlink.symlink_to(root, target_is_directory=True)
        authority = chatbot_gate.ChatbotSourceAuthority(
            repository_root=symlink,
            tracked_manifest_sha256=authority.tracked_manifest_sha256,
        )
    elif defect == "wrong_manifest_digest":
        authority = chatbot_gate.ChatbotSourceAuthority(
            repository_root=root,
            tracked_manifest_sha256="0" * 64,
        )
    elif defect == "manifest_executable":
        manifest_path.chmod(0o755)
    elif defect == "source_executable":
        child_path.chmod(0o755)
    elif defect == "source_nonregular":
        child_path.unlink()
        child_path.mkdir()
    else:
        rows = manifest_path.read_text(encoding="utf-8").splitlines(keepends=True)
        if defect == "manifest_noncanonical":
            manifest_path.write_text("".join(rows).rstrip("\n"), encoding="utf-8")
        elif defect == "duplicate_source_row":
            manifest_path.write_text("".join((*rows, rows[0])), encoding="utf-8")
        elif defect == "missing_source_row":
            manifest_path.write_text("".join(rows[1:]), encoding="utf-8")
        else:
            metadata, relative = rows[0].split("\t", 1)
            mode, _oid = metadata.split(" ", 1)
            rows[0] = f"{mode} {'0' * 40}\t{relative}"
            manifest_path.write_text("".join(rows), encoding="utf-8")
        authority = _source_authority_from_root(root)

    with pytest.raises(chatbot_gate.ChatbotSourceAuthorityError):
        chatbot_gate._prepare_chatbot_source_snapshots(authority)


def test_source_authority_requires_effective_uid_ownership(tmp_path, monkeypatch):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)

    with pytest.raises(
        chatbot_gate.ChatbotSourceAuthorityError,
        match="root identity is invalid",
    ):
        chatbot_gate._prepare_chatbot_source_snapshots(authority)


def test_source_authority_closes_retained_repository_descriptors(tmp_path, monkeypatch):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    descriptors = []
    real_open = chatbot_gate._open_chatbot_authority_relative

    def record_open(root_descriptor, relative_path):
        descriptor = real_open(root_descriptor, relative_path)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(chatbot_gate, "_open_chatbot_authority_relative", record_open)

    snapshots = chatbot_gate._prepare_chatbot_source_snapshots(authority)
    try:
        assert len(descriptors) == 3
        for descriptor in descriptors:
            with pytest.raises(OSError):
                os.fstat(descriptor)
    finally:
        for descriptor in snapshots:
            os.close(descriptor)


def test_source_authority_rejects_failed_sealing_and_closes_snapshot(
    tmp_path,
    monkeypatch,
):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    descriptors = []
    real_create = os.memfd_create
    real_fcntl = fcntl.fcntl

    def record_memfd(name, flags):
        descriptor = real_create(name, flags)
        descriptors.append(descriptor)
        return descriptor

    def fail_add_seals(descriptor, operation, argument=0):
        if operation == fcntl.F_ADD_SEALS:
            raise OSError(errno.EIO, "injected seal failure")
        return real_fcntl(descriptor, operation, argument)

    monkeypatch.setattr(chatbot_gate, "_create_chatbot_source_memfd", record_memfd)
    monkeypatch.setattr(fcntl, "fcntl", fail_add_seals)

    with pytest.raises(chatbot_gate.ChatbotSourceAuthorityError):
        chatbot_gate._prepare_chatbot_source_snapshots(authority)

    assert descriptors
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize(
    ("module", "attribute"),
    [
        (os, "memfd_create"),
        (os, "MFD_ALLOW_SEALING"),
        (os, "MFD_CLOEXEC"),
        (fcntl, "F_ADD_SEALS"),
        (fcntl, "F_GET_SEALS"),
        (fcntl, "F_SEAL_WRITE"),
        (fcntl, "F_SEAL_GROW"),
        (fcntl, "F_SEAL_SHRINK"),
        (fcntl, "F_SEAL_SEAL"),
    ],
)
def test_source_authority_requires_every_memfd_sealing_api(
    tmp_path,
    monkeypatch,
    module,
    attribute,
):
    authority, _child_payload, _gate_payload = _source_authority_fixture(tmp_path)
    monkeypatch.delattr(module, attribute)

    with pytest.raises(chatbot_gate.ChatbotSourceAuthorityError):
        chatbot_gate._prepare_chatbot_source_snapshots(authority)


def test_sealed_source_child_loads_only_the_gate_descriptor():
    source = CHATBOT_CHILD_SOURCE.read_text(encoding="utf-8")

    assert "SourceFileLoader" in source
    assert "sys.modules[" in source
    assert "exec_module" in source
    assert "sys.path" not in source
    assert "from holoagent0_setup" not in source


def _assert_closed_child_failure(result):
    assert _statuses(result) == [
        ("chatbot.dependencies", "FAIL", "CHATBOT_DEPENDENCY_MISSING"),
        ("chatbot.configuration", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)


def _assert_process_group_absent(pgid):
    with pytest.raises(ProcessLookupError):
        os.killpg(pgid, 0)


class _MockSpawnedChatbotChild:
    def __init__(self, *, wait_fails=False):
        self.pid = 43210
        self.returncode = None
        self.wait_calls = 0
        self.kill_calls = 0
        self.wait_fails = wait_fails

    def poll(self):
        return self.returncode

    def kill(self):
        self.kill_calls += 1
        raise ProcessLookupError(errno.ESRCH, "already exited")

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_fails:
            raise subprocess.TimeoutExpired(("mock-chatbot-child",), timeout)
        if self.returncode is None:
            self.returncode = -signal.SIGKILL
        return self.returncode


def _wait_status(pid, *, code=None, status=0):
    return SimpleNamespace(
        si_pid=pid,
        si_code=os.CLD_EXITED if code is None else code,
        si_status=status,
    )


def _process_record(pid, pgid, state, start_time):
    return chatbot_gate._ProcessRecord(pid, pgid, state, start_time)


def test_waitid_owned_child_path_never_polls_or_reaps_before_cleanup(monkeypatch):
    payload = _passing_child_result_bytes()
    process = _MockSpawnedChatbotChild()
    waitid_calls = []
    killpg_calls = []

    def poll():
        raise AssertionError("Popen.poll must never be called")

    def wait(timeout=None):
        assert timeout == 1.0
        process.wait_calls += 1
        process.returncode = 0
        return 0

    def popen(_command, **kwargs):
        kwargs["stdout"].write(payload)
        kwargs["stdout"].flush()
        return process

    def waitid(idtype, pid, options):
        waitid_calls.append((idtype, pid, options))
        return _wait_status(pid)

    def killpg(pgid, signum):
        killpg_calls.append((pgid, signum))
        assert signum == 0
        raise ProcessLookupError(errno.ESRCH, "group absent")

    process.poll = poll
    process.wait = wait
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(os, "waitid", waitid)
    monkeypatch.setattr(
        os,
        "waitpid",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("os.waitpid must never be called")
        ),
    )
    monkeypatch.setattr(os, "killpg", killpg)
    monkeypatch.setattr(chatbot_gate, "_bind_owned_child", lambda _process: identity)
    monkeypatch.setattr(chatbot_gate.resource, "prlimit", lambda *_args: None)
    monkeypatch.setattr(chatbot_gate, "_write_all", lambda *_args: None)
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "Z", 123),),
        raising=False,
    )

    result = chatbot_gate._run_owned_chatbot_child(
        command=("/usr/bin/python3.10", "-I", "-B", "/mock-child.py"),
        control=_child_control_bytes(),
        timeout_seconds=0.5,
    )

    assert result.label == "PASS_HOLOAGENT0_OFFLINE"
    assert process.wait_calls == 1
    assert waitid_calls
    assert all(
        call
        == (
            os.P_PID,
            process.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
        for call in waitid_calls
    )
    assert killpg_calls == [(process.pid, 0)]


def test_waitid_echild_is_containment_ambiguity(monkeypatch):
    identity = chatbot_gate._OwnedChildIdentity(43210, 43210, 123)
    monkeypatch.setattr(
        os,
        "waitid",
        lambda *_args: (_ for _ in ()).throw(ChildProcessError(errno.ECHILD)),
    )

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._observe_owned_root_exit(identity)


@pytest.mark.parametrize(
    "observed",
    [
        SimpleNamespace(si_pid=43211, si_code=os.CLD_EXITED, si_status=0),
        SimpleNamespace(si_pid=43210, si_code=-1, si_status=0),
        SimpleNamespace(si_pid=43210, si_code=os.CLD_EXITED, si_status=256),
    ],
)
def test_waitid_malformed_status_is_containment_ambiguity(monkeypatch, observed):
    identity = chatbot_gate._OwnedChildIdentity(43210, 43210, 123)
    monkeypatch.setattr(os, "waitid", lambda *_args: observed)

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._observe_owned_root_exit(identity)


def test_unreaped_root_zombie_is_not_signaled_and_is_reaped_once(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    signals = []
    status = chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 0)
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "Z", 123),),
        raising=False,
    )

    def wait(timeout=None):
        assert timeout == 1.0
        process.wait_calls += 1
        process.returncode = 0
        return 0

    def killpg(_pgid, signum):
        if signum:
            signals.append(signum)
            return None
        raise ProcessLookupError(errno.ESRCH, "group absent")

    process.poll = lambda: (_ for _ in ()).throw(
        AssertionError("Popen.poll must never be called")
    )
    process.wait = wait
    monkeypatch.setattr(os, "killpg", killpg)

    residual = chatbot_gate._finalize_owned_child(process, identity, status)

    assert residual is False
    assert signals == []
    assert process.wait_calls == 1


def test_unreaped_term_grace_stops_at_root_only_zombie(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    descendant = _process_record(process.pid + 1, process.pid, "S", 456)
    root_live = _process_record(process.pid, process.pid, "S", 123)
    root_zombie = _process_record(process.pid, process.pid, "Z", 123)
    observations = iter(((root_live, descendant), (root_zombie,)))
    wait_statuses = iter(
        (None, chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 0))
    )
    signals = []
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: next(observations),
        raising=False,
    )
    monkeypatch.setattr(
        chatbot_gate,
        "_observe_owned_root_exit",
        lambda _identity: next(wait_statuses),
        raising=False,
    )
    monkeypatch.setattr(chatbot_gate, "CHATBOT_CHILD_TERM_GRACE_SECONDS", 0.01)
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0

    def killpg(_pgid, signum):
        if signum:
            signals.append(signum)
            return None
        raise ProcessLookupError(errno.ESRCH, "group absent")

    monkeypatch.setattr(os, "killpg", killpg)

    residual = chatbot_gate._finalize_owned_child(process, identity, None)

    assert residual is True
    assert signals == [signal.SIGTERM]


def test_unreaped_term_resistant_group_escalates_to_kill(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    descendant = _process_record(process.pid + 1, process.pid, "S", 456)
    root_live = _process_record(process.pid, process.pid, "S", 123)
    root_zombie = _process_record(process.pid, process.pid, "Z", 123)
    killed = False
    signals = []

    def enumerate_group(_pgid):
        return (root_zombie,) if killed else (root_live, descendant)

    def observe_exit(_identity):
        if killed:
            return chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 0)
        return None

    def killpg(_pgid, signum):
        nonlocal killed
        if signum:
            signals.append(signum)
            if signum == signal.SIGKILL:
                killed = True
            return None
        raise ProcessLookupError(errno.ESRCH, "group absent")

    monkeypatch.setattr(
        chatbot_gate, "_enumerate_process_group", enumerate_group, raising=False
    )
    monkeypatch.setattr(
        chatbot_gate, "_observe_owned_root_exit", observe_exit, raising=False
    )
    monkeypatch.setattr(chatbot_gate, "CHATBOT_CHILD_TERM_GRACE_SECONDS", 0.0)
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0
    monkeypatch.setattr(os, "killpg", killpg)

    residual = chatbot_gate._finalize_owned_child(process, identity, None)

    assert residual is True
    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_unreaped_wait_status_must_match_final_returncode(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    status = chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 7)
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "Z", 123),),
        raising=False,
    )
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0
    monkeypatch.setattr(
        os,
        "killpg",
        lambda _pgid, _signum: (_ for _ in ()).throw(
            ProcessLookupError(errno.ESRCH, "group absent")
        ),
    )

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._finalize_owned_child(process, identity, status)


def test_pid_reuse_identity_mismatch_never_signals_unrelated_group(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    signals = []
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "S", 999),),
        raising=False,
    )
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0
    monkeypatch.setattr(
        os,
        "killpg",
        lambda _pgid, signum: signals.append(signum),
    )

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._finalize_owned_child(process, identity, None)

    assert all(signum == 0 for signum in signals)


@pytest.mark.parametrize(
    "records",
    [
        (_process_record(43211, 43210, "S", 123),),
        (_process_record(43210, 43211, "S", 123),),
    ],
)
def test_pid_reuse_pid_or_pgid_mismatch_never_signals_unrelated_group(
    monkeypatch, records
):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    signals = []
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: records,
        raising=False,
    )
    monkeypatch.setattr(
        chatbot_gate,
        "_observe_owned_root_exit",
        lambda _identity: None,
        raising=False,
    )
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0
    monkeypatch.setattr(os, "killpg", lambda _pgid, signum: signals.append(signum))

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._finalize_owned_child(process, identity, None)

    assert all(signum == 0 for signum in signals)


def test_unreaped_final_group_probe_requires_esrch(monkeypatch):
    process = _MockSpawnedChatbotChild()
    identity = chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 123)
    status = chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 0)
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "Z", 123),),
        raising=False,
    )
    process.wait = lambda timeout=None: setattr(process, "returncode", 0) or 0
    monkeypatch.setattr(os, "killpg", lambda _pgid, _signum: None)

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._finalize_owned_child(process, identity, status)


def _proc_stat_payload(pid, pgid, state, start_time):
    fields = [state, "1", str(pgid), *("0" for _ in range(16)), str(start_time)]
    return f"{pid} (fixture process) {' '.join(fields)}\n"


def test_group_enumeration_ignores_only_vanished_proc_entries(tmp_path):
    retained = tmp_path / "100"
    vanished = tmp_path / "101"
    retained.mkdir()
    vanished.mkdir()
    (retained / "stat").write_text(
        _proc_stat_payload(100, 42, "S", 123),
        encoding="ascii",
    )

    records = chatbot_gate._enumerate_process_group(42, _proc_root=tmp_path)

    assert records == (_process_record(100, 42, "S", 123),)


def test_group_enumeration_fails_closed_on_non_enoent_ambiguity(tmp_path):
    malformed = tmp_path / "100"
    malformed.mkdir()
    (malformed / "stat").write_text("malformed\n", encoding="ascii")

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._enumerate_process_group(42, _proc_root=tmp_path)


def test_sigchld_must_be_default_before_popen(monkeypatch):
    popen_called = False

    def popen(*_args, **_kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("Popen must not be called")

    monkeypatch.setattr(signal, "getsignal", lambda _signum: signal.SIG_IGN)
    monkeypatch.setattr(subprocess, "Popen", popen)

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._run_owned_chatbot_child(
            command=("/usr/bin/python3.10", "-I", "-B", "/mock-child.py"),
            control=_child_control_bytes(),
            timeout_seconds=0.5,
        )

    assert popen_called is False


def test_unreaped_prebind_failure_uses_only_pid_directed_kill(monkeypatch):
    process = _MockSpawnedChatbotChild()
    group_signals = []
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        chatbot_gate,
        "_bind_owned_child",
        lambda _process: (_ for _ in ()).throw(OSError("bind failed")),
    )
    monkeypatch.setattr(
        os, "killpg", lambda _pgid, signum: group_signals.append(signum)
    )

    result = chatbot_gate._run_owned_chatbot_child(
        command=("/usr/bin/python3.10", "-I", "-B", "/mock-child.py"),
        control=_child_control_bytes(),
        timeout_seconds=0.5,
    )

    _assert_closed_child_failure(result)
    assert process.kill_calls == 1
    assert process.wait_calls == 1
    assert group_signals == []


def test_sealed_source_descriptors_are_the_only_popen_pass_fds_and_close(
    monkeypatch,
):
    descriptors = (
        os.memfd_create("chatbot-entry-test", os.MFD_CLOEXEC),
        os.memfd_create("chatbot-gate-test", os.MFD_CLOEXEC),
    )
    process = _MockSpawnedChatbotChild()
    process.returncode = 0
    popen_calls = []

    def popen(command, **kwargs):
        popen_calls.append((command, kwargs))
        assert kwargs["pass_fds"] == descriptors
        for descriptor in descriptors:
            os.fstat(descriptor)
        return process

    def killpg(_pgid, _signum):
        raise ProcessLookupError(errno.ESRCH, "group absent")

    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(os, "killpg", killpg)
    monkeypatch.setattr(
        chatbot_gate,
        "_bind_owned_child",
        lambda _process: chatbot_gate._OwnedChildIdentity(process.pid, process.pid, 1),
    )
    monkeypatch.setattr(chatbot_gate.resource, "prlimit", lambda *_args: None)
    monkeypatch.setattr(chatbot_gate, "_write_all", lambda *_args: None)
    monkeypatch.setattr(
        chatbot_gate,
        "_observe_owned_root_exit",
        lambda _identity: chatbot_gate._ChildWaitStatus(process.pid, os.CLD_EXITED, 0),
    )
    monkeypatch.setattr(
        chatbot_gate,
        "_enumerate_process_group",
        lambda _pgid: (_process_record(process.pid, process.pid, "Z", 1),),
    )

    result = chatbot_gate._run_owned_chatbot_child(
        command=(
            "/usr/bin/python3.10",
            "-I",
            "-B",
            f"/proc/self/fd/{descriptors[0]}",
            str(descriptors[1]),
        ),
        control=_child_control_bytes(),
        timeout_seconds=0.5,
        source_descriptors=descriptors,
    )

    _assert_closed_child_failure(result)
    assert len(popen_calls) == 1
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_source_descriptors_close_when_popen_fails(monkeypatch):
    descriptors = (
        os.memfd_create("chatbot-entry-spawn-failure", os.MFD_CLOEXEC),
        os.memfd_create("chatbot-gate-spawn-failure", os.MFD_CLOEXEC),
    )

    def fail_popen(*_args, **kwargs):
        assert kwargs["pass_fds"] == descriptors
        raise OSError(errno.EIO, "injected spawn failure")

    monkeypatch.setattr(subprocess, "Popen", fail_popen)

    result = chatbot_gate._run_owned_chatbot_child(
        command=(
            "/usr/bin/python3.10",
            "-I",
            "-B",
            f"/proc/self/fd/{descriptors[0]}",
            str(descriptors[1]),
        ),
        control=_child_control_bytes(),
        timeout_seconds=0.5,
        source_descriptors=descriptors,
    )

    _assert_closed_child_failure(result)
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize("failure_phase", ["bind", "prlimit", "transport"])
def test_chatbot_spawn_exception_paths_mandatorily_reap_and_empty_group(
    monkeypatch,
    failure_phase,
):
    process = _MockSpawnedChatbotChild()
    group_live = True
    group_killed = False
    kill_signals = []

    def killpg(pgid, signum):
        nonlocal group_live, group_killed
        assert pgid == process.pid
        if signum == 0:
            if group_live:
                return None
            raise ProcessLookupError(errno.ESRCH, "group absent")
        kill_signals.append(signum)
        if signum == signal.SIGKILL:
            group_killed = True

    def observe_exit(_identity):
        if group_killed:
            return chatbot_gate._ChildWaitStatus(
                process.pid, os.CLD_KILLED, signal.SIGKILL
            )
        return None

    def enumerate_group(_pgid):
        if group_killed:
            return (_process_record(process.pid, process.pid, "Z", 123),)
        return (
            _process_record(process.pid, process.pid, "S", 123),
            _process_record(process.pid + 1, process.pid, "S", 456),
        )

    def wait(timeout=None):
        nonlocal group_live
        assert timeout == 1.0
        process.wait_calls += 1
        process.returncode = -signal.SIGKILL
        group_live = False
        return process.returncode

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(os, "killpg", killpg)
    monkeypatch.setattr(chatbot_gate, "CHATBOT_CHILD_TERM_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(chatbot_gate, "_observe_owned_root_exit", observe_exit)
    monkeypatch.setattr(chatbot_gate, "_enumerate_process_group", enumerate_group)
    process.wait = wait
    identity = chatbot_gate._OwnedChildIdentity(
        process.pid,
        process.pid,
        123,
    )
    if failure_phase == "bind":
        monkeypatch.setattr(
            chatbot_gate,
            "_bind_owned_child",
            lambda _process: (_ for _ in ()).throw(OSError("bind failed")),
        )
    else:
        monkeypatch.setattr(
            chatbot_gate,
            "_bind_owned_child",
            lambda _process: identity,
        )
        if failure_phase == "prlimit":
            monkeypatch.setattr(
                chatbot_gate.resource,
                "prlimit",
                lambda *_args: (_ for _ in ()).throw(OSError("prlimit failed")),
            )
        else:
            monkeypatch.setattr(chatbot_gate.resource, "prlimit", lambda *_args: None)
            monkeypatch.setattr(
                chatbot_gate,
                "_write_all",
                lambda *_args: (_ for _ in ()).throw(OSError("transport failed")),
            )

    result = chatbot_gate._run_owned_chatbot_child(
        command=("/usr/bin/python3.10", "-I", "-B", "/mock-child.py"),
        control=_child_control_bytes(),
        timeout_seconds=0.5,
    )

    _assert_closed_child_failure(result)
    assert process.wait_calls == 1
    assert process.returncode == -signal.SIGKILL
    assert group_live is False
    if failure_phase == "bind":
        assert process.kill_calls == 1
        assert kill_signals == []
    else:
        assert kill_signals == [signal.SIGTERM, signal.SIGKILL]


def test_chatbot_unproven_spawn_cleanup_raises_containment_error(monkeypatch):
    process = _MockSpawnedChatbotChild(wait_fails=True)
    group_signals = []

    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        os, "killpg", lambda _pgid, signum: group_signals.append(signum)
    )
    monkeypatch.setattr(
        chatbot_gate,
        "_bind_owned_child",
        lambda _process: (_ for _ in ()).throw(OSError("bind failed")),
    )

    with pytest.raises(chatbot_gate.ChatbotChildContainmentError):
        chatbot_gate._run_owned_chatbot_child(
            command=("/usr/bin/python3.10", "-I", "-B", "/mock-child.py"),
            control=_child_control_bytes(),
            timeout_seconds=0.5,
        )

    assert process.wait_calls == 1
    assert process.returncode is None
    assert process.kill_calls == 1
    assert group_signals == []


@pytest.mark.parametrize(
    "mutation",
    [
        "dependency_false_on_pass",
        "configuration_side_effect_on_pass",
        "audio_match_count_inconsistent",
        "dependency_pass_with_later_not_run",
    ],
)
def test_chatbot_child_result_acceptance_rejects_inconsistent_evidence(mutation):
    document = json.loads(_passing_child_result_bytes())
    if mutation == "dependency_false_on_pass":
        document["gates"][0]["measurements"][0]["value"] = False
    elif mutation == "configuration_side_effect_on_pass":
        document["gates"][1]["measurements"][0]["value"] = True
    elif mutation == "audio_match_count_inconsistent":
        document["gates"][3]["measurements"][2]["value"] = 0
    else:
        for gate in document["gates"][1:]:
            gate["status"] = "NOT_RUN"
            gate["reason"] = "EARLIER_BLOCKING_GATE"
            gate["measurements"] = []
        document["label"] = "FAIL_CHATBOT"
        document["exit_code"] = 1
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    with pytest.raises(ValueError):
        chatbot_gate._decode_chatbot_child_result(payload)


@pytest.mark.parametrize("boolean_exit_code", [False, True])
def test_chatbot_child_result_rejects_boolean_exit_codes(boolean_exit_code):
    source = (
        _passing_child_result_bytes()
        if boolean_exit_code is False
        else _child_result_bytes(chatbot_gate._closed_child_failure())
    )
    document = json.loads(source)
    document["exit_code"] = boolean_exit_code
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    with pytest.raises(ValueError):
        chatbot_gate._decode_chatbot_child_result(payload)


def test_chatbot_child_result_rejects_all_false_dependency_side_effect_block():
    document = json.loads(_child_result_bytes(chatbot_gate._closed_child_failure()))
    document["gates"][0]["measurements"] = [
        {"name": "process_spawn_attempted", "value": False, "unit": None},
        {"name": "network_attempted", "value": False, "unit": None},
        {"name": "microphone_attempted", "value": False, "unit": None},
    ]
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    with pytest.raises(ValueError):
        chatbot_gate._decode_chatbot_child_result(payload)


def test_chatbot_child_result_accepts_caught_seventh_probe_side_effect():
    cached_popen = subprocess.Popen
    calls = []

    def dependency_probe(name):
        calls.append(name)
        if name == REQUIRED_IMPORTS[-1]:
            try:
                cached_popen(["/definitely-missing-seventh-probe"])
            except Exception:
                return True
            raise AssertionError("guarded process constructor did not raise")
        return True

    core_result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=dependency_probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={name: "present" for name in REQUIRED_PROVIDER_VARIABLES},
    )

    decoded = chatbot_gate._decode_chatbot_child_result(
        chatbot_gate._encode_chatbot_child_result(core_result)
    )

    assert decoded == core_result
    assert calls == list(REQUIRED_IMPORTS)
    assert decoded.gates[0]["measurements"][-3:] == [
        {"name": "process_spawn_attempted", "value": True, "unit": None},
        {"name": "network_attempted", "value": False, "unit": None},
        {"name": "microphone_attempted", "value": False, "unit": None},
    ]


def test_chatbot_child_transport_is_closed_private_and_credential_free(
    tmp_path, monkeypatch
):
    pid_path = tmp_path / "child.pid"
    secret = "transport-secret-must-not-enter-control-or-argv"
    for name in REQUIRED_PROVIDER_VARIABLES:
        monkeypatch.setenv(name, secret)
    payload = _passing_child_result_bytes()
    command = _write_child_fixture(
        tmp_path,
        "import json,os,stat,sys\n"
        f"open({str(pid_path)!r},'w').write(str(os.getpid()))\n"
        "raw=sys.stdin.buffer.read()\n"
        "document=json.loads(raw)\n"
        "assert raw == (json.dumps(document,sort_keys=True,separators=(',',':'))+'\\n').encode()\n"
        "assert set(document) == {'schema_version','pyproject_path','configuration_path','timeout_seconds'}\n"
        "assert stat.S_IMODE(os.fstat(1).st_mode) == 0o600\n"
        "assert os.getpid() == os.getpgrp()\n"
        f"values=[os.environ.get(name) for name in {REQUIRED_PROVIDER_VARIABLES!r}]\n"
        "assert all(values) and len(set(values)) == 1\n"
        f"sys.stdout.buffer.write({payload!r})\n",
    )
    control = _child_control_bytes()

    result = chatbot_gate._run_owned_chatbot_child(
        command=command,
        control=control,
        timeout_seconds=0.5,
    )

    pgid = int(pid_path.read_text(encoding="utf-8"))
    assert result.label == "PASS_HOLOAGENT0_OFFLINE"
    assert secret not in repr(command)
    assert secret.encode() not in control
    assert secret.encode() not in payload
    assert secret not in repr(result)
    _assert_process_group_absent(pgid)


def test_chatbot_fresh_exec_does_not_inherit_parent_core_or_cached_callable(
    tmp_path,
    monkeypatch,
):
    child_pyproject = tmp_path / "pyproject.toml"
    child_pyproject.write_text("[project]\ndependencies = []\n", encoding="utf-8")
    inherited_pass = chatbot_gate._decode_chatbot_child_result(
        _passing_child_result_bytes()
    )
    marker = []
    marker_path = tmp_path / "parent-worker-marker"
    scheduled = threading.Event()
    stop_worker = threading.Event()
    cached_schedule = scheduled.set

    def baseline_parent_worker():
        while not stop_worker.wait(0.01):
            if scheduled.is_set():
                time.sleep(0.2)
                marker_path.write_text("scheduled", encoding="utf-8")
                return

    baseline_worker = threading.Thread(target=baseline_parent_worker, daemon=True)
    baseline_worker.start()
    assert baseline_worker.is_alive()

    def inherited_parent_core(**_kwargs):
        marker.append("called")
        cached_schedule()
        return inherited_pass

    monkeypatch.setattr(chatbot_gate, "_run_chatbot_gates_core", inherited_parent_core)

    try:
        result = chatbot_gate.run_chatbot_gates(
            source_authority=_production_source_authority(),
            pyproject_path=child_pyproject,
            configuration_path=CONFIG,
            startup_timeout_seconds=0.5,
        )
        time.sleep(0.3)
    finally:
        stop_worker.set()
        baseline_worker.join(timeout=1.0)

    assert result.label != "PASS_HOLOAGENT0_OFFLINE"
    assert marker == []
    assert baseline_worker.is_alive() is False
    assert scheduled.is_set() is False
    assert marker_path.exists() is False


def test_chatbot_actual_child_core_rejects_cached_low_level_waiting_worker(
    tmp_path,
):
    marker_path = tmp_path / "late-marker"
    pid_path = tmp_path / "child.pid"
    package_root = Path(chatbot_gate.__file__).resolve().parents[1]
    command = _write_child_fixture(
        tmp_path,
        "import _thread,os,sys,threading,time\n"
        f"sys.path.insert(0,{str(package_root)!r})\n"
        "import holoagent0_setup.chatbot_gate as gate\n"
        f"open({str(pid_path)!r},'w').write(str(os.getpid()))\n"
        "cached_start=_thread.start_new_thread\n"
        "sys.stdin.buffer.read()\n"
        "started=threading.Event()\n"
        "def worker():\n"
        "    started.set()\n"
        "    time.sleep(0.25)\n"
        f"    open({str(marker_path)!r},'w').write('escaped')\n"
        "def startup(_configuration,_spies):\n"
        "    cached_start(worker,())\n"
        "    assert started.wait(0.2)\n"
        f"result=gate._run_chatbot_gates_core(pyproject_path=gate.Path({str(PYPROJECT)!r}),configuration_path=gate.Path({str(CONFIG)!r}),dependency_probe=lambda _name: True,audio_enumerator=lambda: ({{'name':'USB Audio Device','maxInputChannels':1,'maxOutputChannels':1}},),startup_checker=startup,environment={{name:'valid-provider-secret' for name in gate.REQUIRED_PROVIDER_VARIABLES}},startup_timeout_seconds=0.5)\n"
        "sys.stdout.buffer.write(gate._encode_chatbot_child_result(result))\n",
    )

    result = chatbot_gate._run_owned_chatbot_child(
        command=command,
        control=_child_control_bytes(),
        timeout_seconds=0.5,
    )
    time.sleep(0.35)

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["process_spawn_attempted"] is True
    assert marker_path.exists() is False
    _assert_process_group_absent(int(pid_path.read_text(encoding="utf-8")))


def test_chatbot_rejects_success_until_residual_owned_process_group_is_empty(
    tmp_path,
):
    marker_path = tmp_path / "escaped-marker"
    pid_path = tmp_path / "child.pid"
    descendant_path = tmp_path / "escaped-descendant.py"
    descendant_path.write_text(
        "import time\n"
        "time.sleep(1.0)\n"
        f"open({str(marker_path)!r},'w').write('escaped')\n",
        encoding="utf-8",
    )
    payload = _passing_child_result_bytes()
    command = _write_child_fixture(
        tmp_path,
        "import os,signal,subprocess,sys,time\n"
        f"open({str(pid_path)!r},'w').write(str(os.getpid()))\n"
        "sys.stdin.buffer.read()\n"
        "descendant=None\n"
        "def cleanup(_signum,_frame):\n"
        "    if descendant is not None:\n"
        "        try:\n"
        "            descendant.terminate()\n"
        "        except ProcessLookupError:\n"
        "            pass\n"
        "        try:\n"
        "            descendant.wait(timeout=0.5)\n"
        "        except subprocess.TimeoutExpired:\n"
        "            descendant.kill()\n"
        "            descendant.wait(timeout=0.5)\n"
        "    raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM,cleanup)\n"
        f"descendant=subprocess.Popen([sys.executable,{str(descendant_path)!r}])\n"
        f"sys.stdout.buffer.write({payload!r})\n"
        "sys.stdout.buffer.flush()\n"
        "time.sleep(2.0)\n",
    )

    result = chatbot_gate._run_owned_chatbot_child(
        command=command,
        control=_child_control_bytes(),
        timeout_seconds=0.5,
    )
    time.sleep(0.6)

    _assert_closed_child_failure(result)
    assert marker_path.exists() is False
    _assert_process_group_absent(int(pid_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    "defect", ["timeout", "signal", "malformed", "noncanonical", "oversized"]
)
def test_chatbot_child_transport_defects_fail_closed_and_reap_group(tmp_path, defect):
    pid_path = tmp_path / f"{defect}.pid"
    setup = (
        "import os,signal,sys,time\n"
        f"open({str(pid_path)!r},'w').write(str(os.getpid()))\n"
        "sys.stdin.buffer.read()\n"
    )
    actions = {
        "timeout": "time.sleep(2.0)\n",
        "signal": "os.kill(os.getpid(),signal.SIGTERM)\n",
        "malformed": "sys.stdout.write('not-json\\n')\n",
        "noncanonical": (
            f"sys.stdout.buffer.write(b' '+{_passing_child_result_bytes()!r})\n"
        ),
        "oversized": "sys.stdout.write('x'*70000);sys.stdout.flush();time.sleep(2.0)\n",
    }
    command = _write_child_fixture(tmp_path, setup + actions[defect])

    result = chatbot_gate._run_owned_chatbot_child(
        command=command,
        control=_child_control_bytes(),
        timeout_seconds=0.05,
    )

    _assert_closed_child_failure(result)
    _assert_process_group_absent(int(pid_path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("credentials", "audio", "label", "exit_code"),
    [
        (True, True, "PASS_HOLOAGENT0_OFFLINE", 0),
        (False, True, "READY_CREDENTIALS_REQUIRED", 10),
        (True, False, "READY_AUDIO_HARDWARE_REQUIRED", 10),
        (False, False, "READY_CREDENTIALS_AND_AUDIO_REQUIRED", 10),
    ],
)
def test_chatbot_qualification_matrix(credentials, audio, label, exit_code):
    result = classify_external_readiness(credentials=credentials, audio=audio)

    assert (result.label, result.exit_code) == (label, exit_code)


@pytest.mark.parametrize(
    ("credentials", "audio", "expected_statuses", "label", "exit_code"),
    [
        (
            True,
            True,
            [
                ("chatbot.credentials", "PASS", "OK"),
                ("chatbot.audio_hardware", "PASS", "OK"),
            ],
            "PASS_HOLOAGENT0_OFFLINE",
            0,
        ),
        (
            False,
            True,
            [
                ("chatbot.credentials", "QUALIFIED", "CREDENTIALS_MISSING"),
                ("chatbot.audio_hardware", "PASS", "OK"),
            ],
            "READY_CREDENTIALS_REQUIRED",
            10,
        ),
        (
            True,
            False,
            [
                ("chatbot.credentials", "PASS", "OK"),
                ("chatbot.audio_hardware", "QUALIFIED", "AUDIO_HARDWARE_MISSING"),
            ],
            "READY_AUDIO_HARDWARE_REQUIRED",
            10,
        ),
        (
            False,
            False,
            [
                ("chatbot.credentials", "QUALIFIED", "CREDENTIALS_MISSING"),
                ("chatbot.audio_hardware", "QUALIFIED", "AUDIO_HARDWARE_MISSING"),
            ],
            "READY_CREDENTIALS_AND_AUDIO_REQUIRED",
            10,
        ),
    ],
)
def test_chatbot_gates_apply_qualification_matrix_without_leaking_values(
    credentials, audio, expected_statuses, label, exit_code
):
    sentinel = "provider-secret-must-never-enter-evidence"
    environment = (
        {name: sentinel for name in REQUIRED_PROVIDER_VARIABLES} if credentials else {}
    )
    probe = DependencyProbe()
    startup_calls = []

    def startup_checker(configuration, spies):
        assert configuration["audio_device"]["channels"] == 1
        assert spies.attempted_kinds == ()
        startup_calls.append(True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: _devices(audio=audio),
        startup_checker=startup_checker,
        environment=environment,
    )

    assert _statuses(result)[:2] == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "PASS", "OK"),
    ]
    assert _statuses(result)[2:] == expected_statuses
    assert (result.label, result.exit_code) == (label, exit_code)
    assert probe.queries == list(REQUIRED_IMPORTS)
    assert startup_calls == [True]
    assert sentinel not in repr(result)
    assert all(gate["log_paths"] == [] for gate in result.gates)
    assert [gate["role"] for gate in result.gates] == [
        "required",
        "required",
        "qualification",
        "qualification",
    ]

    credentials_measurements = result.gates[2]["measurements"]
    assert [row["name"] for row in credentials_measurements] == [
        f"{name}_present" for name in REQUIRED_PROVIDER_VARIABLES
    ]
    assert all(row["value"] is credentials for row in credentials_measurements)
    assert all(sentinel not in repr(row) for row in credentials_measurements)


def test_chatbot_dependency_failure_is_blocking_and_queries_exact_seven_modules():
    probe = DependencyProbe(("pyaudio",))
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "FAIL", "CHATBOT_DEPENDENCY_MISSING"),
        ("chatbot.configuration", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert probe.queries == list(REQUIRED_IMPORTS)
    assert calls == []


def test_chatbot_dependency_probe_exception_is_redacted_and_does_not_skip_queries():
    secret = "dependency-probe-secret-must-not-escape"
    queries = []

    def probe(name):
        queries.append(name)
        if name == "pyaudio":
            raise RuntimeError(secret)
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert result.label == "FAIL_CHATBOT"
    assert queries == list(REQUIRED_IMPORTS)
    assert secret not in repr(result)


def test_chatbot_dependency_probe_is_bounded_and_attributed_to_dependencies():
    calls = []

    def blocked_probe(name):
        calls.append(name)
        time.sleep(0.05)
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=blocked_probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
        startup_timeout_seconds=0.01,
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == [REQUIRED_IMPORTS[0]]


def test_chatbot_uses_one_deadline_across_dependencies_and_startup():
    first_probe = True

    def slow_probe(_name):
        nonlocal first_probe
        if first_probe:
            first_probe = False
            time.sleep(0.1)
        return True

    def slow_startup(_configuration, _spies):
        time.sleep(0.1)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=slow_probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=slow_startup,
        environment={},
        startup_timeout_seconds=0.15,
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"


def test_chatbot_audio_enumerator_is_bounded_as_configuration():
    def blocked_audio():
        time.sleep(0.05)
        return _devices(audio=True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=blocked_audio,
        startup_checker=lambda *_args: None,
        environment={},
        startup_timeout_seconds=0.01,
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"


@pytest.mark.parametrize("invalid_bound", [0.0, -1.0, 31.0, 1])
def test_chatbot_rejects_invalid_whole_readiness_bounds_before_callbacks(
    invalid_bound,
):
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=lambda name: calls.append(name) or True,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
        startup_timeout_seconds=invalid_bound,
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == []


def test_chatbot_rejects_oversized_pyproject_before_dependency_probe(tmp_path):
    oversized = tmp_path / "pyproject.toml"
    oversized.write_text(
        PYPROJECT.read_text(encoding="utf-8") + "\n#" + "x" * 70_000,
        encoding="utf-8",
    )
    calls = []

    result = run_chatbot_gates(
        pyproject_path=oversized,
        configuration_path=CONFIG,
        dependency_probe=lambda name: calls.append(name) or True,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert calls == []


def test_chatbot_rejects_oversized_json_before_startup_or_audio(tmp_path):
    oversized = tmp_path / "g1.json"
    oversized.write_bytes(CONFIG.read_bytes() + b" " * 70_000)
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=oversized,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == []


def test_chatbot_hostile_environment_mapping_cannot_leak_a_credential_value():
    secret = "environment-secret-must-not-escape"

    class HostileEnvironment(dict):
        def __contains__(self, _key):
            raise RuntimeError(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=HostileEnvironment(),
    )

    assert result.label == "READY_CREDENTIALS_REQUIRED"
    assert secret not in repr(result)


@pytest.mark.parametrize("attempt", ["process", "network"])
def test_chatbot_rechecks_guard_after_hostile_credential_mapping(attempt):
    secret = "hostile-credential-side-effect-secret-must-not-escape"
    cached_popen = subprocess.Popen
    cached_socket = socket.socket

    class HostileEnvironment(dict):
        attempted = False

        def __contains__(self, _key):
            if not self.attempted:
                self.attempted = True
                try:
                    if attempt == "process":
                        cached_popen([secret])
                    else:
                        cached_socket(socket.AF_INET, socket.SOCK_STREAM).close()
                except OfflineStartupSideEffectAttempt:
                    pass
            return True

        def __getitem__(self, _key):
            return secret

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=HostileEnvironment(),
    )

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    evidence = _configuration_measurements(result)
    evidence_name = (
        "process_spawn_attempted" if attempt == "process" else "network_attempted"
    )
    assert evidence[evidence_name] is True
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        " \t\n",
        "x",
        "xxxx",
        "  XxXx  ",
        "placeholder",
        "PlaceHolder",
        "changeme",
        "ChangeMe",
    ],
)
def test_chatbot_credentials_reject_short_and_closed_placeholder_values(
    invalid_value,
):
    valid_secret = "valid-provider-secret-must-not-enter-evidence"
    environment = {name: valid_secret for name in REQUIRED_PROVIDER_VARIABLES}
    environment[REQUIRED_PROVIDER_VARIABLES[2]] = invalid_value

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    measurements = result.gates[2]["measurements"]
    assert _statuses(result)[2] == (
        "chatbot.credentials",
        "QUALIFIED",
        "CREDENTIALS_MISSING",
    )
    assert (result.label, result.exit_code) == (
        "READY_CREDENTIALS_REQUIRED",
        10,
    )
    assert [row["value"] for row in measurements] == [True, True, False, True, True]
    assert all(type(row["value"]) is bool for row in measurements)
    assert valid_secret not in repr(result)


def test_chatbot_credentials_accept_five_valid_non_placeholder_values():
    values = (
        "real-key",
        "replace-me",
        "your-key-here",
        "abcd",
        "placeholder-real",
    )
    environment = dict(zip(REQUIRED_PROVIDER_VARIABLES, values, strict=True))

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    assert _statuses(result)[2] == ("chatbot.credentials", "PASS", "OK")
    assert (result.label, result.exit_code) == ("PASS_HOLOAGENT0_OFFLINE", 0)
    assert all(value not in repr(result) for value in values)


def test_chatbot_credentials_report_only_presence_with_one_missing_variable():
    secret = "partial-provider-secret-must-not-enter-evidence"
    environment = {name: secret for name in REQUIRED_PROVIDER_VARIABLES}
    del environment[REQUIRED_PROVIDER_VARIABLES[2]]

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    measurements = result.gates[2]["measurements"]
    assert [row["value"] for row in measurements] == [
        True,
        True,
        False,
        True,
        True,
    ]
    assert (result.label, result.exit_code) == (
        "READY_CREDENTIALS_REQUIRED",
        10,
    )
    assert secret not in repr(result)


def test_chatbot_invalid_json_is_blocking_and_never_reaches_startup_or_audio(tmp_path):
    invalid = tmp_path / "g1.json"
    invalid.write_text('{"audio_device":', encoding="utf-8")
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=invalid,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert calls == []


@pytest.mark.parametrize("attempt", ["process_spawn", "network", "microphone"])
def test_chatbot_configuration_startup_fails_closed_on_side_effect_spy(attempt):
    secret = "secret exception text must not escape"

    def startup_checker(_configuration, spies):
        getattr(spies, attempt)(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": False,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


def test_chatbot_guard_blocks_and_records_cached_subprocess_constructor():
    secret = "/definitely-missing-provider-secret"
    cached_popen = subprocess.Popen

    def startup_checker(_configuration, _spies):
        cached_popen([secret])

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["process_spawn_attempted"] is True
    assert secret not in repr(result)


def test_chatbot_guard_blocks_and_records_direct_socket_operation():
    secret = "socket-secret-must-not-escape"

    def startup_checker(_configuration, _spies):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["network_attempted"] is True
    assert secret not in repr(result)


def test_chatbot_guard_blocks_loaded_pyaudio_stream_open(monkeypatch):
    secret = "microphone-secret-must-not-escape"
    opened = []
    pyaudio_module = ModuleType("pyaudio")

    class FakePyAudio:
        def open(self, *_args, **_kwargs):
            opened.append(True)

    pyaudio_module.PyAudio = FakePyAudio
    monkeypatch.setitem(sys.modules, "pyaudio", pyaudio_module)

    def startup_checker(_configuration, _spies):
        pyaudio_module.PyAudio().open(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["microphone_attempted"] is True
    assert opened == []
    assert secret not in repr(result)


def test_chatbot_guard_blocks_loaded_audio_device_stream_method(monkeypatch):
    secret = "audio-device-secret-must-not-escape"
    started = []
    audio_device_module = ModuleType("chatbot.audio.audio_device")

    class FakeAudioDevice:
        def start_streams(self, *_args, **_kwargs):
            started.append(True)

    audio_device_module.AudioDevice = FakeAudioDevice
    monkeypatch.setitem(sys.modules, "chatbot.audio.audio_device", audio_device_module)

    def startup_checker(_configuration, _spies):
        audio_device_module.AudioDevice().start_streams(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["microphone_attempted"] is True
    assert started == []
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("operation", "expected_measurement"),
    [
        ("cached_process", "process_spawn_attempted"),
        ("direct_socket", "network_attempted"),
    ],
)
def test_chatbot_guard_classifies_dependency_side_effect_as_dependency_failure(
    operation, expected_measurement
):
    secret = "/definitely-missing-dependency-provider-secret"
    cached_popen = subprocess.Popen
    calls = []

    def dependency_probe(name):
        calls.append(name)
        if operation == "cached_process":
            cached_popen([secret])
        else:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=dependency_probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "FAIL", "CHATBOT_DEPENDENCY_MISSING"),
        ("chatbot.configuration", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.gates[0]["measurements"] == [
        {
            "name": "process_spawn_attempted",
            "value": expected_measurement == "process_spawn_attempted",
            "unit": None,
        },
        {
            "name": "network_attempted",
            "value": expected_measurement == "network_attempted",
            "unit": None,
        },
        {"name": "microphone_attempted", "value": False, "unit": None},
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert calls == [REQUIRED_IMPORTS[0]]
    assert secret not in repr(result)


def test_chatbot_guard_detects_dependency_side_effect_even_when_probe_catches_it():
    secret = "/definitely-missing-caught-provider-secret"
    cached_popen = subprocess.Popen
    calls = []

    def dependency_probe(name):
        calls.append(name)
        try:
            cached_popen([secret])
        except Exception:
            return True
        raise AssertionError("guarded process constructor did not raise")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=dependency_probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[:2] == [
        ("chatbot.dependencies", "FAIL", "CHATBOT_DEPENDENCY_MISSING"),
        ("chatbot.configuration", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.gates[0]["measurements"] == [
        {
            "name": f"{REQUIRED_IMPORTS[0]}_importable",
            "value": True,
            "unit": None,
        },
        {"name": "process_spawn_attempted", "value": True, "unit": None},
        {"name": "network_attempted", "value": False, "unit": None},
        {"name": "microphone_attempted", "value": False, "unit": None},
    ]
    assert calls == [REQUIRED_IMPORTS[0]]
    assert secret not in repr(result)


@pytest.mark.parametrize("import_style", ["standard", "importlib", "cached"])
@pytest.mark.parametrize("module_kind", ["pyaudio", "audio_device"])
def test_chatbot_guard_blocks_late_imported_audio_stream_entry_points(
    tmp_path, monkeypatch, request, import_style, module_kind
):
    secret = "late-audio-provider-secret-must-not-escape"
    if module_kind == "pyaudio":
        module_name = "pyaudio"
        module_path = tmp_path / "pyaudio.py"
        side_effect_name = "OPENED"
        module_path.write_text(
            "OPENED = []\n"
            "class PyAudio:\n"
            "    def open(self, *_args, **_kwargs):\n"
            "        OPENED.append(True)\n",
            encoding="utf-8",
        )
    else:
        package = tmp_path / "fixture_chatbot_audio"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        module_name = "fixture_chatbot_audio.audio_device"
        module_path = package / "audio_device.py"
        side_effect_name = "STARTED"
        module_path.write_text(
            "STARTED = []\n"
            "class AudioDevice:\n"
            "    def start_streams(self, *_args, **_kwargs):\n"
            "        STARTED.append(True)\n",
            encoding="utf-8",
        )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    request.addfinalizer(lambda: sys.modules.pop(module_name, None))
    if module_kind == "audio_device":
        request.addfinalizer(lambda: sys.modules.pop("fixture_chatbot_audio", None))
    cached_importer = importlib.import_module

    def startup_checker(_configuration, _spies):
        if import_style == "standard":
            module = builtins.__import__(module_name, fromlist=("*",))
        elif import_style == "importlib":
            module = importlib.import_module(module_name)
        else:
            module = cached_importer(module_name)
        if module_kind == "pyaudio":
            module.PyAudio().open(secret)
        else:
            module.AudioDevice().start_streams(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    measurements = _configuration_measurements(result)
    imported = sys.modules[module_name]
    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert measurements == {
        "process_spawn_attempted": False,
        "network_attempted": False,
        "microphone_attempted": True,
    }
    assert getattr(imported, side_effect_name) == []
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("operation", "expected_measurement"),
    [
        ("cached_process", "process_spawn_attempted"),
        ("cached_socket", "network_attempted"),
        ("late_microphone", "microphone_attempted"),
    ],
)
def test_chatbot_configuration_fails_when_startup_catches_real_guard_attempt(
    tmp_path, monkeypatch, request, operation, expected_measurement
):
    secret = "/definitely-missing-caught-startup-secret"
    cached_popen = subprocess.Popen
    cached_socket = socket.socket
    audio_calls = []
    opened = []
    if operation == "late_microphone":
        module_path = tmp_path / "pyaudio.py"
        module_path.write_text(
            "OPENED = []\n"
            "class PyAudio:\n"
            "    def open(self, *_args, **_kwargs):\n"
            "        OPENED.append(True)\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.delitem(sys.modules, "pyaudio", raising=False)
        request.addfinalizer(lambda: sys.modules.pop("pyaudio", None))

    def startup_checker(_configuration, _spies):
        try:
            if operation == "cached_process":
                cached_popen([secret])
            elif operation == "cached_socket":
                cached_socket(socket.AF_INET, socket.SOCK_STREAM).close()
            else:
                module = importlib.import_module("pyaudio")
                opened.append(module)
                module.PyAudio().open(secret)
        except OfflineStartupSideEffectAttempt:
            return
        raise AssertionError("guarded startup operation did not raise")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: audio_calls.append(True) or _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": expected_measurement == "process_spawn_attempted",
        "network_attempted": expected_measurement == "network_attempted",
        "microphone_attempted": expected_measurement == "microphone_attempted",
    }
    assert audio_calls == []
    if opened:
        assert opened[0].OPENED == []
    assert secret not in repr(result)


def test_chatbot_configuration_fails_when_audio_inventory_catches_guard_attempt():
    secret = "/definitely-missing-caught-audio-secret"
    cached_popen = subprocess.Popen
    process_returned = []

    def audio_enumerator():
        try:
            cached_popen([secret])
        except OfflineStartupSideEffectAttempt:
            return _devices(audio=True)
        process_returned.append(True)
        return _devices(audio=True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=audio_enumerator,
        startup_checker=lambda *_args: None,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert process_returned == []
    assert secret not in repr(result)


def test_chatbot_guard_rejects_cached_waiting_worker_escape_and_cleans_fixture():
    secret = "waiting-worker-secret-must-not-escape"
    cached_start = _thread.start_new_thread
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def wait_worker():
        try:
            started.set()
            release.wait(2.0)
        finally:
            finished.set()

    def startup_checker(_configuration, _spies):
        cached_start(wait_worker, ())
        assert started.wait(1.0)

    try:
        result = run_chatbot_gates(
            pyproject_path=PYPROJECT,
            configuration_path=CONFIG,
            dependency_probe=DependencyProbe(),
            audio_enumerator=lambda: _devices(audio=True),
            startup_checker=startup_checker,
            environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
        )
    finally:
        release.set()
        assert finished.wait(2.0)

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "thread_entry",
    [
        "thread_start",
        pytest.param(
            "threading_start_new",
            marks=pytest.mark.skipif(
                not callable(getattr(threading, "_start_new_thread", None)),
                reason="interpreter does not expose threading._start_new_thread",
            ),
        ),
        "low_level_start_new",
    ],
)
def test_chatbot_configuration_fails_when_startup_catches_thread_attempt(
    thread_entry,
):
    secret = "caught-thread-secret-must-not-escape"
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    worker = None

    def wait_worker():
        try:
            started.set()
            release.wait(2.0)
        finally:
            finished.set()

    def startup_checker(_configuration, _spies):
        nonlocal worker
        try:
            if thread_entry == "thread_start":
                worker = threading.Thread(target=wait_worker, daemon=True)
                worker.start()
            elif thread_entry == "threading_start_new":
                threading._start_new_thread(wait_worker, ())
            else:
                _thread.start_new_thread(wait_worker, ())
        except OfflineStartupSideEffectAttempt:
            return
        assert started.wait(1.0)

    try:
        result = run_chatbot_gates(
            pyproject_path=PYPROJECT,
            configuration_path=CONFIG,
            dependency_probe=DependencyProbe(),
            audio_enumerator=lambda: _devices(audio=True),
            startup_checker=startup_checker,
            environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
        )
    finally:
        release.set()
        if worker is not None and worker.ident is not None:
            worker.join(timeout=2.0)
        elif started.is_set():
            finished.wait(2.0)

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


def test_audio_inventory_never_opens_a_stream_and_records_no_device_names():
    calls = []

    class FakeAudio:
        def get_device_count(self):
            return 1

        def get_device_info_by_index(self, index):
            assert index == 0
            return {
                "name": "sensitive USB AUDIO DEVICE serial name",
                "maxInputChannels": 1,
                "maxOutputChannels": 2,
            }

        def open(self, *_args, **_kwargs):
            raise AssertionError("offline inventory must never open a stream")

        def terminate(self):
            calls.append("terminate")

    class FakePyAudioModule:
        @staticmethod
        def PyAudio():
            calls.append("construct")
            return FakeAudio()

    inventory = enumerate_audio_devices(FakePyAudioModule(), "usb audio device")

    assert inventory.input_count == 1
    assert inventory.output_count == 1
    assert inventory.matching_full_duplex_count == 1
    assert repr(inventory) == (
        "AudioInventory(input_count=1, output_count=1, matching_full_duplex_count=1)"
    )
    assert "sensitive" not in repr(inventory)
    assert calls == ["construct", "terminate"]


def test_chatbot_split_input_output_devices_do_not_satisfy_configured_audio():
    split_devices = (
        {
            "name": "USB Audio Device microphone",
            "maxInputChannels": 1,
            "maxOutputChannels": 0,
        },
        {
            "name": "USB Audio Device speaker",
            "maxInputChannels": 0,
            "maxOutputChannels": 2,
        },
    )

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: split_devices,
        startup_checker=lambda *_args: None,
        environment={
            name: "valid-provider-secret" for name in REQUIRED_PROVIDER_VARIABLES
        },
    )

    assert _statuses(result)[3] == (
        "chatbot.audio_hardware",
        "QUALIFIED",
        "AUDIO_HARDWARE_MISSING",
    )
    measurements = {
        row["name"]: row["value"] for row in result.gates[3]["measurements"]
    }
    assert measurements["matching_full_duplex_device_count"] == 0
    assert measurements["configured_full_duplex_device_present"] is False
    assert "USB Audio Device" not in repr(result)


def test_chatbot_requires_configured_name_match_on_the_full_duplex_device():
    unrelated_device = (
        {
            "name": "Built-in Audio Duplex",
            "maxInputChannels": 1,
            "maxOutputChannels": 2,
        },
    )

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: unrelated_device,
        startup_checker=lambda *_args: None,
        environment={
            name: "valid-provider-secret" for name in REQUIRED_PROVIDER_VARIABLES
        },
    )

    assert _statuses(result)[3][1:] == (
        "QUALIFIED",
        "AUDIO_HARDWARE_MISSING",
    )


def test_chatbot_rejects_structurally_incomplete_configuration(tmp_path):
    invalid = tmp_path / "g1.json"
    invalid.write_text(json.dumps({"audio_device": {}}), encoding="utf-8")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=invalid,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"
