"""Task 8 supervisor authority, bootstrap, and fault-injection contracts."""

from __future__ import annotations

import copy
import fcntl
import json
import hashlib
import os
from pathlib import Path
import shutil
import threading
import signal
import stat
import subprocess
import sys
import time

import pytest

import holoagent0_setup.supervisor as supervisor_module
from holoagent0_setup.constants import OFFLINE_GATE_ORDER
from holoagent0_setup.contract import ContractSet
from holoagent0_setup.invocation import RunRootAuthority
from holoagent0_setup.cyclone_policy import CONFIG_ROLES, EXPECTED_CONFIG_SHA256
from holoagent0_setup.coordinator import LinuxHandoffMarker, Task4SignalBarrier
from holoagent0_setup.atomic_io import (
    ArtifactDescriptor,
    AtomicPublicationAmbiguity,
    canonical_json_bytes,
)
from holoagent0_setup.process_identity import ProcessIdentity
from holoagent0_setup.process_identity import read_process_identity
from holoagent0_setup.evidence import (
    AppendOnlyJournal,
    EvidenceBinder,
    EvidenceContext,
    TraceRuntimeEvidence,
)
from holoagent0_setup.signal_handoff import (
    CoordinatorSignalHandoff,
    SignalObservation,
    SignalReady,
    SignalReadyAccepted,
)
from holoagent0_setup.signal_handoff import TraceUnblockEvidence
from holoagent0_setup.trace_policy import PolicyViolation
from holoagent0_setup.supervisor import (
    AuthoritativeEvaluation,
    AuthoritativeResultPublisher,
    BootstrapEngine,
    BootstrapFacts,
    BootstrapInvocation,
    BootstrapRuntime,
    EvidenceSupervisor,
    ExitkillCapabilityProbe,
    ExitkillProbeEvidence,
    LaunchArbiter,
    LinuxProcessOperations,
    MandatoryFinalizers,
    OwnedProcessLease,
    OwnedProcessController,
    ProductionMandatoryFinalizers,
    PublicationEvidenceFactory,
    SynchronousSignalCollector,
    SupervisorSignalRuntime,
    SupervisorNetworkBoundary,
    SupervisorError,
    SupervisorSafetyFacts,
    SupervisorOwnershipBroker,
    ProductionBrokerChannels,
    ConcurrentSupervisorBrokerRuntime,
    SupervisorViolationSink,
    TraceLaunchRuntime,
    LiveTraceLaunchOutcome,
    TraceLaunchSpec,
    TraceSession,
    TraceRuntimeGuard,
    SupervisorScenario,
)


PACKAGE_ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]


def _complete_bootstrap_inputs(*, live_fixture_passed=True):
    return {
        "schema_version": "holoagent0.bootstrap-report.v1",
        "toolchain": {
            "expected": {"strace_version": "6.6"},
            "observed": {"strace_version": "6.6"},
        },
        "initial_fd_manifest": [],
        "final_fd_manifest": [],
        "sanitation_actions": [],
        "rebinding_actions": [],
        "live_fixture_passed": live_fixture_passed,
    }


def _production_run_root(tmp_path, label):
    output_root = tmp_path / f"{label}-output"
    output_root.mkdir(mode=0o700)
    output_root.chmod(0o700)
    suffix = hashlib.sha256(label.encode("utf-8")).hexdigest()[:32]
    run_id = f"workstation-offline-20260818T010203Z-{suffix}"
    return output_root / run_id, run_id, RunRootAuthority.open(output_root, run_id)


def _gate(result, gate_id):
    return next(gate for gate in result.gates if gate["id"] == gate_id)


def _signal_ready(identity, *, nonce="6" * 64):
    return SignalReady(
        run_nonce=nonce,
        sequence=1,
        identity=identity,
        blocked_signals=("HUP", "INT", "TERM"),
        dispositions=(("HUP", True), ("INT", True), ("TERM", True)),
    )


class _HandoffMarkerOperations:
    def __init__(self, identity):
        self.pid = identity.pid
        self.name = "coordinator"

    def current_pid(self):
        return self.pid

    def get_name(self):
        return self.name

    def set_name(self, value):
        self.name = value


def _handoff_marker(identity, *, nonce="a" * 64):
    return LinuxHandoffMarker(
        nonce,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=_HandoffMarkerOperations(identity),
    )


def _signal_unblock_record(identity, *, record_index=0):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "rt_sigprocmask",
        "transition": {
            "operation": "rt_sigprocmask",
            "how": "SIG_UNBLOCK",
            "mask": ["HUP", "INT", "TERM"],
            "old_mask": ["HUP", "INT", "TERM"],
            "sigset_size": 8,
        },
        "result": {"value": 0},
    }


def _functional_record(identity, *, record_index):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "prctl",
        "result": {"value": 0},
    }


def _handoff_marker_record(identity, *, record_index, phase, nonce="6" * 64):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "prctl",
        "handoff_marker": {"phase": phase, "token": nonce[:12]},
        "result": {"value": 0},
    }


def _handoff_name_record(identity, *, record_index, phase, nonce="6" * 64):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "prctl",
        "handoff_name_observation": {"phase": phase, "token": nonce[:12]},
        "result": {"value": 0},
    }


def _readiness_getpid_record(identity, *, record_index):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "getpid",
        "result": {"value": identity.pid},
    }


def _readiness_signal_action_record(identity, signal_name, *, record_index):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "rt_sigaction",
        "transition": {
            "operation": "rt_sigaction",
            "signal": signal_name,
            "action": {
                "handler": "CUSTOM",
                "mask": [],
                "flags": ["SA_RESTORER", "SA_ONSTACK"],
                "restorer": True,
            },
            "old_action": {
                "handler": "DEFAULT",
                "mask": [],
                "flags": [],
                "restorer": False,
            },
            "sigset_size": 8,
        },
        "result": {"value": 0},
    }


def _readiness_signal_query_record(identity, signal_name, *, record_index):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "rt_sigaction",
        "transition": {
            "operation": "rt_sigaction",
            "signal": signal_name,
            "action": None,
            "old_action": {
                "handler": "DEFAULT",
                "mask": [],
                "flags": [],
                "restorer": False,
            },
            "sigset_size": 8,
        },
        "result": {"value": 0},
    }


def _readiness_mask_observation_record(
    identity, *, record_index, old_mask=("HUP", "INT", "TERM")
):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "rt_sigprocmask",
        "transition": {
            "operation": "rt_sigprocmask",
            "how": "SIG_BLOCK",
            "mask": [],
            "old_mask": list(old_mask),
            "sigset_size": 8,
        },
        "result": {"value": 0},
    }


def _readiness_broker_write_record(identity, *, record_index, fd=21, count=512):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "write",
        "fds": [{"fd": fd}],
        "lengths": {"count": count},
        "result": {"value": count},
    }


def _readiness_broker_read_record(identity, *, record_index, fd=22, count, result):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "read",
        "fds": [{"fd": fd}],
        "lengths": {"count": count},
        "result": {"value": result},
    }


def _readiness_pselect_record(identity, *, record_index, fd, direction, pipe_inode):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "pselect6",
        "wait": {
            "nfds": fd + 1,
            "direction": direction,
            "fd": {
                "fd": fd,
                "provenance": {"kind": "pipe", "inode": pipe_inode},
            },
            "timeout": {"seconds": 0, "nanoseconds": 999_000_000},
        },
        "result": {
            "value": 1,
            "ready": {"direction": direction, "fd": {"fd": fd}},
            "timeout_left": {"seconds": 0, "nanoseconds": 998_000_000},
        },
    }


def _readiness_dup_record(
    identity,
    *,
    record_index,
    source_fd,
    created_fd,
    cloexec=True,
    minimum_fd=0,
):
    provenance = {"kind": "pipe", "inode": source_fd * 1000}
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "fcntl",
        "transition": {
            "operation": "fcntl_dup",
            "source_fd": {"fd": source_fd, "provenance": provenance},
            "created_fd": {"fd": created_fd, "provenance": provenance},
            "cloexec": cloexec,
            "minimum_fd": minimum_fd,
        },
        "result": {
            "value": created_fd,
            "fd": {"fd": created_fd, "provenance": provenance},
        },
    }


def _readiness_fcntl_getfl_record(identity, *, record_index, fd, pipe_inode, flags):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "fcntl",
        "transition": {
            "operation": "fcntl_getfl",
            "source_fd": {
                "fd": fd,
                "provenance": {"kind": "pipe", "inode": pipe_inode},
            },
            "status_flags": [flags],
        },
        "result": {
            "value": 1 if flags == "O_WRONLY" else 0,
            "flags": [flags],
        },
    }


def _readiness_fd_stat_record(identity, *, record_index, fd, pipe_inode):
    descriptor = {
        "fd": fd,
        "provenance": {"kind": "pipe", "inode": pipe_inode},
    }
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "newfstatat",
        "validation": {
            "operation": "fd_stat",
            "fd": descriptor,
            "file_type": "fifo",
            "mode": 0o600,
            "inode": pipe_inode,
        },
        "result": {"value": 0},
    }


def _readiness_readlink_record(identity, *, record_index, fd, pipe_inode):
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "readlink",
        "validation": {
            "operation": "fd_readlink",
            "fd": fd,
            "target_provenance": {"kind": "pipe", "inode": pipe_inode},
            "count": 4096,
        },
        "result": {"value": len(f"pipe:[{pipe_inode}]")},
    }


def _readiness_close_record(identity, *, record_index, fd, pipe_inode=None):
    provenance = {"kind": "pipe"}
    if pipe_inode is not None:
        provenance["inode"] = pipe_inode
    return {
        "kind": "syscall",
        "pid": identity.pid,
        "record_index": record_index,
        "entry_index": record_index,
        "exit_index": record_index,
        "syscall": "close",
        "transition": {
            "operation": "close",
            "closed_fd": {"fd": fd, "provenance": provenance},
        },
        "result": {"value": 0},
    }


def _readiness_protocol_records(
    identity, *, request_write_fd=13, acceptance_read_fd=14
):
    handler_records = [
        _readiness_signal_action_record(identity, name, record_index=index)
        for index, name in enumerate(("HUP", "INT", "TERM"), start=3)
    ]
    handler_records[1]["transition"]["old_action"] = copy.deepcopy(
        handler_records[1]["transition"]["action"]
    )
    return [
        _handoff_marker_record(identity, record_index=0, phase="READINESS_BEGIN"),
        _handoff_name_record(identity, record_index=1, phase="READINESS"),
        _readiness_mask_observation_record(identity, record_index=2),
        *handler_records,
        _readiness_mask_observation_record(identity, record_index=6),
        _readiness_dup_record(
            identity,
            record_index=7,
            source_fd=request_write_fd,
            created_fd=21,
        ),
        _readiness_fd_stat_record(
            identity,
            record_index=8,
            fd=21,
            pipe_inode=request_write_fd * 1000,
        ),
        _readiness_readlink_record(
            identity,
            record_index=9,
            fd=21,
            pipe_inode=request_write_fd * 1000,
        ),
        _readiness_fcntl_getfl_record(
            identity,
            record_index=10,
            fd=21,
            pipe_inode=request_write_fd * 1000,
            flags="O_WRONLY",
        ),
        _readiness_pselect_record(
            identity,
            record_index=11,
            fd=21,
            direction="write",
            pipe_inode=request_write_fd * 1000,
        ),
        _readiness_broker_write_record(identity, record_index=12, fd=21),
        _readiness_close_record(identity, record_index=13, fd=21),
        _readiness_close_record(identity, record_index=14, fd=request_write_fd),
        _readiness_dup_record(
            identity,
            record_index=15,
            source_fd=acceptance_read_fd,
            created_fd=22,
        ),
        _readiness_fd_stat_record(
            identity,
            record_index=16,
            fd=22,
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_readlink_record(
            identity,
            record_index=17,
            fd=22,
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_fcntl_getfl_record(
            identity,
            record_index=18,
            fd=22,
            pipe_inode=acceptance_read_fd * 1000,
            flags="O_RDONLY",
        ),
        _readiness_pselect_record(
            identity,
            record_index=19,
            fd=22,
            direction="read",
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_broker_read_record(
            identity, record_index=20, fd=22, count=4, result=4
        ),
        _readiness_pselect_record(
            identity,
            record_index=21,
            fd=22,
            direction="read",
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_broker_read_record(
            identity, record_index=22, fd=22, count=512, result=512
        ),
        _readiness_pselect_record(
            identity,
            record_index=23,
            fd=22,
            direction="read",
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_broker_read_record(
            identity, record_index=24, fd=22, count=1, result=0
        ),
        _readiness_close_record(identity, record_index=25, fd=22),
        _signal_unblock_record(identity, record_index=26),
        _readiness_mask_observation_record(identity, record_index=27, old_mask=()),
        _readiness_close_record(
            identity,
            record_index=28,
            fd=acceptance_read_fd,
            pipe_inode=acceptance_read_fd * 1000,
        ),
        _readiness_getpid_record(identity, record_index=29),
        _handoff_name_record(identity, record_index=30, phase="READINESS"),
        _handoff_marker_record(identity, record_index=31, phase="FUNCTIONAL_BEGIN"),
    ]


def _write_canonical_trace(path, records):
    path.write_bytes(
        b"".join(canonical_json_bytes(record) + b"\n" for record in records)
    )
    path.chmod(0o400)


def _reindex_trace_records(records):
    for index, record in enumerate(records):
        record.update(record_index=index, entry_index=index, exit_index=index)
    return records


def test_clean_bootstrap_commits_full_coordinator():
    decision = BootstrapEngine().evaluate(BootstrapFacts.clean())
    assert decision.launch_state == "COORDINATOR_LAUNCH_COMMITTED"
    assert decision.coordinator_launch_committed is True
    assert decision.trace_state == "FULL"
    assert decision.first_signal is None


def test_bootstrap_runtime_initializes_closed_zero_state(tmp_path):
    runtime = BootstrapRuntime(ContractSet(PACKAGE_ROOT))
    invocation = BootstrapInvocation(
        run_root=tmp_path / "run",
        run_id="run-1",
        run_nonce="a" * 64,
        facts=BootstrapFacts.clean().replaced(source_ok=False),
        bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
    )

    state = runtime.run(invocation)

    assert state.decision.trace_state == "NOT_STARTED"
    assert state.ledger.head.generation == 0
    assert state.ledger.head.sealed is False
    assert state.ownership_journal.seal().record_count == 0
    assert state.violation_journal.seal().record_count == 0
    for name in ("host_observer_pre.json", "host_observer_post.json"):
        observer = json.loads((state.run_root / name).read_text(encoding="utf-8"))
        assert observer["state"] == "NOT_RUN"
        assert observer["cause_gate"] == "safety.workstation_preflight"
    report = json.loads(
        (state.run_root / "bootstrap_report.json").read_text(encoding="utf-8")
    )
    assert report["terminal_launch_state"] == state.decision.launch_state


def test_production_bootstrap_creates_run_root_through_retained_authority(
    tmp_path, reviewed_trace_contract, monkeypatch
):
    run_root, run_id, authority = _production_run_root(tmp_path, "retained-authority")
    original_mkdir = Path.mkdir
    original_create = RunRootAuthority.create
    authority_calls = []

    def prohibit_run_root_pathname_fallback(path, *args, **kwargs):
        if path == run_root:
            pytest.fail("production bootstrap used a pathname mkdir fallback")
        return original_mkdir(path, *args, **kwargs)

    def count_authority_call(observed_authority, path):
        authority_calls.append((observed_authority, path))
        return original_create(observed_authority, path)

    monkeypatch.setattr(Path, "mkdir", prohibit_run_root_pathname_fallback)
    monkeypatch.setattr(RunRootAuthority, "create", count_authority_call)
    invocation = BootstrapInvocation(
        run_root=run_root,
        run_id=run_id,
        run_nonce="a" * 64,
        facts=BootstrapFacts.clean(),
        bootstrap_report=_complete_bootstrap_inputs(),
        run_root_authority=authority,
    )

    state = BootstrapRuntime(
        reviewed_trace_contract,
        require_run_root_authority=True,
    ).run(invocation)

    assert state.run_root == run_root
    assert stat.S_IMODE(state.run_root.stat().st_mode) == 0o700
    assert authority.consumed is True
    assert authority_calls == [(authority, run_root)]


def test_production_bootstrap_rejects_missing_run_root_authority(
    tmp_path, reviewed_trace_contract
):
    runtime = BootstrapRuntime(
        reviewed_trace_contract,
        require_run_root_authority=True,
    )

    with pytest.raises(SupervisorError, match="zero-state"):
        runtime.run(
            BootstrapInvocation(
                run_root=tmp_path / "forbidden-path-fallback",
                run_id="workstation-offline-20260818T010203Z-" + "a" * 32,
                run_nonce="a" * 64,
                facts=BootstrapFacts.clean(),
                bootstrap_report=_complete_bootstrap_inputs(),
            )
        )

    assert not (tmp_path / "forbidden-path-fallback").exists()


def test_production_bootstrap_binds_run_id_to_run_root_authority(
    tmp_path, reviewed_trace_contract
):
    run_root, _run_id, authority = _production_run_root(tmp_path, "run-id-binding")

    with pytest.raises(SupervisorError, match="zero-state"):
        BootstrapRuntime(
            reviewed_trace_contract,
            require_run_root_authority=True,
        ).run(
            BootstrapInvocation(
                run_root=run_root,
                run_id="workstation-offline-20260818T010203Z-" + "f" * 32,
                run_nonce="a" * 64,
                facts=BootstrapFacts.clean(),
                bootstrap_report=_complete_bootstrap_inputs(),
                run_root_authority=authority,
            )
        )

    assert authority.consumed is True
    assert not run_root.exists()


class _ExplodingRunRoot:
    def __fspath__(self):
        raise RuntimeError("injected run-root conversion failure")


@pytest.mark.parametrize("invalid_run_root", [None, _ExplodingRunRoot()])
def test_production_bootstrap_closes_authority_when_run_root_conversion_fails(
    tmp_path, reviewed_trace_contract, invalid_run_root
):
    run_root, run_id, authority = _production_run_root(
        tmp_path, f"invalid-run-root-{type(invalid_run_root).__name__}"
    )
    descriptor = authority._output_root_fd

    with pytest.raises(SupervisorError, match="zero-state"):
        BootstrapRuntime(
            reviewed_trace_contract,
            require_run_root_authority=True,
        ).run(
            BootstrapInvocation(
                run_root=invalid_run_root,
                run_id=run_id,
                run_nonce="a" * 64,
                facts=BootstrapFacts.clean(),
                bootstrap_report=_complete_bootstrap_inputs(),
                run_root_authority=authority,
            )
        )

    assert authority.consumed is True
    assert not run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_bootstrap_state_retains_dynamic_owned_tracee_authority(
    tmp_path, process_identities
):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    runtime = BootstrapRuntime(
        ContractSet(PACKAGE_ROOT), owned_process_controller=controller
    )
    state = runtime.run(
        BootstrapInvocation(
            run_root=tmp_path / "run-owned",
            run_id="run-owned",
            run_nonce="9" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report=_complete_bootstrap_inputs(),
        )
    )

    assert state.owned_tracees() == ()
    lease = controller.acquire(identity)
    assert state.owned_tracees() == (lease,)
    assert controller.cleanup((lease,))


@pytest.mark.parametrize(
    "signal,exit_code", [("HUP", 129), ("INT", 130), ("TERM", 143)]
)
def test_precoordinator_signal_uses_finalizer_only(signal, exit_code):
    result = EvidenceSupervisor().run(SupervisorScenario.clean(precommit_signal=signal))
    assert result.trace_state == "FINALIZER_ONLY"
    assert [gate["id"] for gate in result.gates] == list(OFFLINE_GATE_ORDER)
    assert all(gate["status"] == "PASS" for gate in result.gates[:2])
    assert all(
        gate["status"] == "NOT_RUN" and gate["reason"] == "INTERRUPTED_BEFORE_GATE"
        for gate in result.gates[2:23]
    )
    assert all(gate["status"] == "PASS" for gate in result.gates[23:])
    assert result.primary_blocking_gate is None
    assert result.blocking_gates == ()
    assert result.label == "INTERRUPTED"
    assert result.exit_code == exit_code
    assert result.functional_coordinator_started is False


def test_precoordinator_signal_cannot_hide_postflight_or_evidence_failure():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(
            precommit_signal="TERM",
            cleanup_complete=False,
            evidence_binding_ok=False,
        )
    )
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert _gate(result, "offline.evidence_binding")["status"] == "FAIL"
    assert result.primary_blocking_gate == "safety.workstation_postflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30


def test_precoordinator_signal_cannot_hide_trace_or_network_failure():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(
            precommit_signal="INT",
            trace_fault="TRACE_INCOMPLETE",
            network_violation="UNEXPECTED_NETWORK_ATTEMPT",
        )
    )
    assert _gate(result, "offline.trace_integrity")["status"] == "FAIL"
    assert _gate(result, "offline.network_policy")["status"] == "FAIL"
    assert result.primary_blocking_gate == "offline.network_policy"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30


def test_precoordinator_tracer_loss_with_live_tracee_forces_postflight_safety():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(
            precommit_signal="HUP",
            trace_fault="TRACER_EXITED",
            tracees_live=True,
        )
    )
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert result.primary_blocking_gate == "safety.workstation_postflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30


def test_launch_arbiter_has_one_linearized_winner_and_first_signal_only():
    arbiter = LaunchArbiter()
    arbiter.collect_signal("TERM")
    arbiter.collect_signal("INT")
    arbiter.bootstrap_clean()
    assert arbiter.snapshot().state == "PRE_COORDINATOR_INTERRUPTED"
    assert arbiter.snapshot().first_signal == "TERM"
    assert not arbiter.try_commit()

    committed = LaunchArbiter()
    committed.bootstrap_clean()
    assert committed.try_commit()
    committed.collect_signal("HUP")
    assert committed.snapshot().state == "COORDINATOR_LAUNCH_COMMITTED"
    assert committed.snapshot().first_signal == "HUP"


def test_signal_commit_race_never_produces_mixed_launch_state():
    for _ in range(25):
        arbiter = LaunchArbiter()
        arbiter.bootstrap_clean()
        barrier = threading.Barrier(3)
        threads = [
            threading.Thread(
                target=lambda: (barrier.wait(), arbiter.collect_signal("TERM"))
            ),
            threading.Thread(target=lambda: (barrier.wait(), arbiter.try_commit())),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()
        snapshot = arbiter.snapshot()
        assert snapshot.state in {
            "PRE_COORDINATOR_INTERRUPTED",
            "COORDINATOR_LAUNCH_COMMITTED",
        }
        assert snapshot.coordinator_launch_committed == (
            snapshot.state == "COORDINATOR_LAUNCH_COMMITTED"
        )


def test_real_synchronous_signal_collector_blocks_and_latches_precommit_term():
    arbiter = LaunchArbiter()
    collector = SynchronousSignalCollector(arbiter.collect_signal)
    collector.start()
    try:
        os.kill(os.getpid(), signal.SIGTERM)
        assert collector.wait_first(1.0) == "TERM"
        arbiter.bootstrap_clean()
        assert not arbiter.try_commit()
        assert arbiter.snapshot().state == "PRE_COORDINATOR_INTERRUPTED"
        assert arbiter.snapshot().first_signal == "TERM"
    finally:
        collector.close(restore_mask=True)


def test_signal_collector_refuses_late_start_after_worker_thread_exists():
    release = threading.Event()
    worker = threading.Thread(target=release.wait)
    worker.start()
    try:
        collector = SynchronousSignalCollector(lambda _name: None)
        with pytest.raises(RuntimeError, match="before any other thread"):
            collector.start()
    finally:
        release.set()
        worker.join(timeout=1)


def test_signal_runtime_composes_commit_acceptance_and_exactly_once_forward(
    process_identities,
):
    identity = process_identities[2]
    forwarded = []
    forwarded_event = threading.Event()

    def forward(pgid, signal_name):
        forwarded.append((pgid, signal_name))
        forwarded_event.set()

    runtime = SupervisorSignalRuntime(
        "a" * 64,
        forwarder=forward,
        identity_validator=lambda observed: observed == identity,
    )
    runtime.start()
    assert runtime.commit_and_spawn(lambda: identity) == identity

    class SignalOperations:
        def __init__(self):
            self.blocked = True
            self.handlers = (object(), object(), object())

        def observe(self):
            return SignalObservation(
                frozenset({"HUP", "INT", "TERM"}) if self.blocked else frozenset(),
                (("HUP", True), ("INT", True), ("TERM", True)),
                self.handlers,
            )

        def unblock_reviewed(self):
            self.blocked = False

    coordinator_handoff = CoordinatorSignalHandoff(
        "a" * 64, identity, signal_operations=SignalOperations()
    )
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    errors = []

    def accept():
        try:
            runtime.accept_readiness(request_read, response_write)
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    thread = threading.Thread(target=accept)
    thread.start()
    barrier = Task4SignalBarrier(
        coordinator_handoff,
        request_write_fd=request_write,
        acceptance_read_fd=response_read,
        blocked_signals=frozenset({"HUP", "INT", "TERM"}),
        dispositions={"HUP": True, "INT": True, "TERM": True},
        handoff_marker=_handoff_marker(identity),
    )
    try:
        barrier.complete_two_way_acceptance()
        barrier.record_functional_progress()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []
        os.kill(os.getpid(), signal.SIGTERM)
        assert forwarded_event.wait(1)
        assert forwarded == [(identity.pgid, "TERM")]
        launch, handoff = runtime.snapshot()
        assert launch.coordinator_launch_committed
        assert handoff.acceptance_count == 1
        assert handoff.forward_count == 1
    finally:
        runtime.close(restore_mask=True)


def test_signal_runtime_requires_terminal_trace_verification_before_ready(
    process_identities,
):
    identity = process_identities[2]
    runtime = SupervisorSignalRuntime(
        "a" * 64,
        forwarder=lambda _pgid, _signal_name: None,
        identity_validator=lambda observed: observed == identity,
    )
    runtime.start()
    assert runtime.commit_and_spawn(lambda: identity) == identity

    class SignalOperations:
        def __init__(self):
            self.blocked = True
            self.handlers = (object(), object(), object())

        def observe(self):
            return SignalObservation(
                frozenset({"HUP", "INT", "TERM"}) if self.blocked else frozenset(),
                (("HUP", True), ("INT", True), ("TERM", True)),
                self.handlers,
            )

        def unblock_reviewed(self):
            self.blocked = False

    coordinator_handoff = CoordinatorSignalHandoff(
        "a" * 64, identity, signal_operations=SignalOperations()
    )
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    accept_thread = threading.Thread(
        target=lambda: runtime.accept_readiness(request_read, response_write)
    )
    accept_thread.start()
    barrier = Task4SignalBarrier(
        coordinator_handoff,
        request_write_fd=request_write,
        acceptance_read_fd=response_read,
        blocked_signals=frozenset({"HUP", "INT", "TERM"}),
        dispositions={"HUP": True, "INT": True, "TERM": True},
        handoff_marker=_handoff_marker(identity),
    )
    try:
        barrier.complete_two_way_acceptance()
        accept_thread.join(timeout=1)
        coordinator = coordinator_handoff.snapshot()
        evidence = TraceUnblockEvidence(
            run_nonce="a" * 64,
            identity=identity,
            request_sequence=coordinator.request_sequence,
            request_sha256=coordinator.request_sha256,
            unblock_trace_record_index=4,
            first_functional_trace_record_index=None,
            functional_count=0,
        )
        runtime.finalize_trace_readiness(
            coordinator,
            evidence,
            trusted_verifier=lambda observed: observed == evidence,
        )
        _launch, supervisor = runtime.snapshot()
        assert supervisor.terminal_state == "READY"
    finally:
        runtime.close(restore_mask=True)


def test_inherited_socket_uses_sanitized_finalizer_only_safety_branch():
    facts = BootstrapFacts.clean().replaced(inherited_fd_safe=False)
    result = EvidenceSupervisor().run(SupervisorScenario(bootstrap=facts))
    assert result.launch_state == "FINALIZER_ONLY_BOOTSTRAP_FAILURE"
    assert result.trace_state == "FINALIZER_ONLY"
    assert (
        _gate(result, "safety.workstation_preflight")["reason"] == "INHERITED_SOCKET_FD"
    )
    assert result.primary_blocking_gate == "safety.workstation_preflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30
    assert result.functional_coordinator_started is False


def test_failed_sanitation_uses_not_started_and_postflight_safety_branch():
    facts = BootstrapFacts.clean().replaced(
        inherited_fd_safe=False, sanitation_ok=False
    )
    result = EvidenceSupervisor().run(SupervisorScenario(bootstrap=facts))
    assert result.launch_state == "NOT_STARTED_BOOTSTRAP_FAILURE"
    assert result.trace_state == "NOT_STARTED"
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert _gate(result, "offline.trace_integrity")["reason"] == "TRACE_NOT_STARTED"
    assert _gate(result, "offline.network_policy")["status"] == "SKIPPED"
    assert (
        _gate(result, "offline.network_policy")["reason"] == "DEPENDENCY_NOT_AVAILABLE"
    )
    assert result.primary_blocking_gate == "safety.workstation_preflight"
    assert result.exit_code == 30


@pytest.mark.parametrize(
    "field,gate",
    [
        ("source_ok", "source.repository"),
        ("runtime_ok", "runtime.workstation"),
        ("trace_capability_ok", "runtime.workstation"),
    ],
)
def test_toolchain_bootstrap_failure_never_uses_unapproved_tracer(field, gate):
    facts = BootstrapFacts.clean().replaced(**{field: False})
    result = EvidenceSupervisor().run(SupervisorScenario(bootstrap=facts))
    assert result.trace_state == "NOT_STARTED"
    assert result.functional_coordinator_started is False
    assert _gate(result, gate)["status"] == "FAIL"
    assert (
        _gate(result, "offline.trace_integrity")["reason"] == "TRACE_BOOTSTRAP_FAILED"
    )


@pytest.mark.parametrize("field", ["source_ok", "runtime_ok", "trace_capability_ok"])
def test_early_bootstrap_failure_carries_unsafe_inherited_fd_to_postflight(field):
    facts = BootstrapFacts.clean().replaced(
        **{field: False}, inherited_fd_safe=False, sanitation_ok=True
    )
    result = EvidenceSupervisor().run(SupervisorScenario(bootstrap=facts))
    assert _gate(result, "safety.workstation_preflight")["status"] == "NOT_RUN"
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert result.primary_blocking_gate == "safety.workstation_postflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30


def test_tracer_loss_with_live_tracee_is_safety_and_stops_progression():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(trace_fault="TRACER_EXITED", tracees_live=True)
    )
    assert _gate(result, "offline.trace_integrity")["reason"] == "TRACER_EXITED"
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert result.primary_blocking_gate == "safety.workstation_postflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30
    assert result.progress_stopped is True


def test_normalizer_loss_with_live_tracee_is_same_safety_precedence():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(trace_fault="TRACE_DECODE_FAILED", tracees_live=True)
    )
    assert _gate(result, "offline.trace_integrity")["reason"] == "TRACE_DECODE_FAILED"
    assert _gate(result, "safety.workstation_postflight")["status"] == "FAIL"
    assert result.label == "FAIL_SAFETY"


def test_tracer_loss_after_proved_teardown_is_harness_only():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(trace_fault="TRACER_EXITED", tracees_live=False)
    )
    assert _gate(result, "safety.workstation_postflight")["status"] == "PASS"
    assert result.primary_blocking_gate == "offline.trace_integrity"
    assert result.label == "FAIL_HARNESS"
    assert result.exit_code == 40


def test_violation_survives_later_trace_and_evidence_defects():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(
            trace_fault="TRACE_INCOMPLETE",
            network_violation="UNEXPECTED_NETWORK_ATTEMPT",
            evidence_binding_ok=False,
        )
    )
    assert _gate(result, "offline.trace_integrity")["status"] == "FAIL"
    assert _gate(result, "offline.network_policy")["status"] == "FAIL"
    assert _gate(result, "offline.evidence_binding")["status"] == "FAIL"
    assert result.primary_blocking_gate == "offline.network_policy"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30


@pytest.mark.parametrize(
    "ledger_state", ["MISSING", "UNSEALED", "WRONG_NONCE", "INVALID_CHAIN"]
)
def test_bad_ledger_synthesizes_gate24_before_supervisor_finalizers(ledger_state):
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(ledger_state=ledger_state)
    )
    assert _gate(result, "safety.workstation_postflight")["reason"] in {
        "POSTFLIGHT_FAILED",
        "LEDGER_CHAIN_INVALID",
    }
    assert result.finalizer_order == (
        "safety.workstation_postflight",
        "offline.trace_integrity",
        "offline.network_policy",
        "offline.evidence_binding",
    )
    assert result.label == "FAIL_SAFETY"


def test_missing_exitkill_verification_is_trace_bootstrap_failure():
    facts = BootstrapFacts.clean().replaced(exitkill_verified=False)
    result = EvidenceSupervisor().run(SupervisorScenario(bootstrap=facts))
    assert result.trace_state == "NOT_STARTED"
    assert _gate(result, "runtime.workstation")["status"] == "FAIL"
    assert (
        _gate(result, "offline.trace_integrity")["reason"] == "TRACE_BOOTSTRAP_FAILED"
    )


def test_evidence_mutation_is_harness_when_safety_is_decidable():
    result = EvidenceSupervisor().run(
        SupervisorScenario.clean(evidence_binding_ok=False)
    )
    assert result.primary_blocking_gate == "offline.evidence_binding"
    assert result.label == "FAIL_HARNESS"
    assert result.exit_code == 40


class FakeProcessOperations:
    def __init__(self, identities, *, alive=None, stubborn_groups=None):
        self.identities = dict(identities)
        self.alive = set(self.identities) if alive is None else set(alive)
        self.groups = {
            identity.pgid
            for identity in self.identities.values()
            if identity.pid in self.alive
        }
        self.stubborn_groups = (
            set() if stubborn_groups is None else set(stubborn_groups)
        )
        self.opened = []
        self.signals = []
        self.closed = []
        self.reaped = []
        self.absence_proofs = []

    def open_pidfd(self, identity):
        if self.identities.get(identity.pid) != identity:
            raise RuntimeError("identity mismatch")
        pidfd = identity.pid + 10_000
        self.opened.append((identity.pid, pidfd))
        return pidfd

    def identity_matches(self, identity):
        return self.identities.get(identity.pid) == identity

    def group_identity_matches(self, identity):
        return identity.pid == identity.pgid and self.identity_matches(identity)

    def is_alive(self, pidfd):
        return pidfd - 10_000 in self.alive

    def send_signal(self, pidfd, signal_number):
        pid = pidfd - 10_000
        self.signals.append((pid, signal_number))
        if signal_number == signal.SIGKILL:
            self.alive.discard(pid)

    def send_group_signal(self, pidfd, identity, signal_number):
        pid = pidfd - 10_000
        if pid != identity.pid:
            raise RuntimeError("pidfd identity mismatch")
        if pid not in self.alive or not self.group_identity_matches(identity):
            raise RuntimeError("group identity mismatch")
        self.signals.append(("group", identity.pgid, signal_number))
        if signal_number == signal.SIGKILL:
            self.alive.discard(pid)
            self.groups.discard(identity.pgid)
        elif identity.pgid not in self.stubborn_groups:
            self.alive.discard(pid)
            self.groups.discard(identity.pgid)

    def send_retained_group_signal(self, pidfd, identity, signal_number):
        assert pidfd == identity.pid + 10_000
        assert signal_number == signal.SIGKILL
        self.signals.append(("group", identity.pgid, signal_number))
        self.groups.discard(identity.pgid)

    def wait_dead(self, pidfd, timeout_seconds):
        return pidfd - 10_000 not in self.alive

    def wait_group_gone(self, pgid, timeout_seconds):
        return pgid not in self.groups

    def reap(self, identity, pidfd, timeout_seconds):
        if identity.pid in self.alive:
            return False
        self.reaped.append(identity.pid)
        return True

    def prove_owned_absent(self, identity, pidfd):
        absent = identity.pid not in self.alive and identity.pgid not in self.groups
        self.absence_proofs.append((identity.pid, absent))
        return absent

    def close_pidfd(self, pidfd):
        self.closed.append(pidfd)


class FakeJournal:
    def __init__(self, events, *, fail=False):
        self.events = events
        self.fail = fail

    def append(self, kind, payload):
        self.events.append(("journal", kind, payload))
        if self.fail:
            raise RuntimeError("journal failed")


class FakeOwnershipClient:
    def __init__(self, events, *, fail=False):
        self.events = events
        self.fail = fail

    def append_identity(self, identity):
        self.events.append(("ownership_ack", identity.pid))
        if self.fail:
            raise RuntimeError("ownership acknowledgement failed")


@pytest.fixture
def process_identities():
    return (
        ProcessIdentity(101, 101, 10, "/bin/tracer", "a" * 64),
        ProcessIdentity(102, 102, 11, "/bin/normalizer", "b" * 64),
        ProcessIdentity(103, 103, 12, "/bin/tracee", "c" * 64),
    )


def test_owned_process_is_acknowledged_before_exec(process_identities):
    events = []
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)

    controller.exec_after_ownership_ack(
        lease,
        FakeOwnershipClient(events),
        lambda: events.append(("exec", identity.pid)),
    )

    assert events[0] == ("ownership_ack", identity.pid)
    assert events[1] == ("exec", identity.pid)
    assert operations.opened == [(identity.pid, identity.pid + 10_000)]
    assert operations.closed == []
    assert controller.cleanup((lease,))


def test_failed_ownership_acknowledgement_prevents_exec(process_identities):
    events = []
    identity = process_identities[2]
    controller = OwnedProcessController(FakeProcessOperations({identity.pid: identity}))
    lease = controller.acquire(identity)
    with pytest.raises(RuntimeError, match="acknowledgement failed"):
        controller.exec_after_ownership_ack(
            lease,
            FakeOwnershipClient(events, fail=True),
            lambda: events.append(("exec", identity.pid)),
        )
    assert all(event[0] != "exec" for event in events)
    assert controller.cleanup((lease,))


def test_direct_journal_adapter_is_rejected_before_exec(process_identities):
    events = []
    identity = process_identities[2]
    controller = OwnedProcessController(FakeProcessOperations({identity.pid: identity}))
    lease = controller.acquire(identity)
    with pytest.raises(RuntimeError, match="ownership client"):
        controller.exec_after_ownership_ack(
            lease,
            FakeJournal(events),
            lambda: events.append(("exec", identity.pid)),
        )
    assert events == []
    assert controller.cleanup((lease,))


def test_raw_identity_cannot_enter_acknowledged_exec(process_identities):
    identity = process_identities[2]
    controller = OwnedProcessController(FakeProcessOperations({identity.pid: identity}))

    with pytest.raises(RuntimeError, match="lease authority"):
        controller.exec_after_ownership_ack(
            identity,
            FakeOwnershipClient([]),
            lambda: pytest.fail("raw identity reached exec"),
        )


def test_identity_change_after_ownership_ack_prevents_exec(process_identities):
    events = []
    identity = process_identities[2]

    class ReusedAfterJournal(FakeProcessOperations):
        def identity_matches(self, observed):
            return not any(event[0] == "ownership_ack" for event in events)

    operations = ReusedAfterJournal({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)
    with pytest.raises(RuntimeError, match="identity"):
        controller.exec_after_ownership_ack(
            lease,
            FakeOwnershipClient(events),
            lambda: events.append(("exec", identity.pid)),
        )
    assert all(event[0] != "exec" for event in events)
    assert operations.closed == []
    assert not controller.cleanup((lease,))
    # An identity mismatch is not proof of absence.  The controller therefore
    # retains the pidfd-backed lease for later safety recovery instead of
    # consuming the only authority it has over the recorded child.
    assert operations.closed == []
    assert controller.active_leases() == (lease,)


def test_retained_lease_survives_ack_and_exec_until_absence_verification(
    process_identities,
):
    events = []
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)

    assert type(lease) is OwnedProcessLease
    assert lease.identity == identity
    controller.exec_after_ownership_ack(
        lease,
        FakeOwnershipClient(events),
        lambda: events.append(("exec", identity.pid)),
    )
    assert operations.closed == []

    operations.alive.discard(identity.pid)
    operations.groups.discard(identity.pgid)
    assert controller.verify_absent((lease,)) is True
    assert operations.signals == []
    assert operations.reaped == [identity.pid]
    assert operations.absence_proofs == [(identity.pid, True)]
    assert operations.closed == [identity.pid + 10_000]


def test_live_retained_lease_is_not_signaled_by_verify_then_cleanup_can_terminate(
    process_identities,
):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)

    assert controller.verify_absent((lease,)) is False
    assert operations.signals == []
    assert operations.closed == []

    assert controller.cleanup((lease,)) is True
    assert operations.signals == [("group", identity.pgid, signal.SIGTERM)]
    assert operations.closed == [identity.pid + 10_000]


def test_reaped_leader_lease_is_retained_until_descendant_group_cleanup(
    process_identities,
):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)
    operations.alive.discard(identity.pid)

    assert controller.verify_absent((lease,)) is False
    assert controller.active_leases() == (lease,)
    assert operations.closed == []

    assert controller.cleanup((lease,)) is True
    assert operations.signals == [("group", identity.pgid, signal.SIGKILL)]
    assert controller.active_leases() == ()
    assert operations.closed == [identity.pid + 10_000]


def test_cleanup_rejects_identity_without_retained_lease(process_identities):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)

    with pytest.raises(RuntimeError, match="lease inventory"):
        controller.cleanup((identity,))
    assert operations.opened == []
    assert operations.signals == []


def test_supervisor_ownership_ack_retains_local_pidfd_lease(
    tmp_path, process_identities
):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    message = {
        "type": "OWNERSHIP_RECORD",
        "run_nonce": "7" * 64,
        "sequence": 1,
        "identity": identity.as_dict(),
        "role": "action_child",
    }
    try:
        supervisor_module.write_frame(record_write, message)
        broker = SupervisorOwnershipBroker(
            journal,
            run_nonce="7" * 64,
            record_read_fd=record_read,
            acceptance_write_fd=acceptance_write,
            owned_process_controller=controller,
            participant_identity_validator=lambda _identity: True,
        )
        lease = broker.serve_once()
        acknowledgement = supervisor_module.read_frame(acceptance_read)

        assert type(lease) is OwnedProcessLease
        assert lease.identity == identity
        assert controller.active_leases() == (lease,)
        assert acknowledgement["type"] == "OWNERSHIP_ACCEPTED"
    finally:
        for descriptor in (
            record_read,
            record_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(descriptor)
        for lease in controller.active_leases():
            operations.alive.clear()
            operations.groups.clear()
            controller.verify_absent((lease,))


def _participant_identity(index):
    return ProcessIdentity(
        pid=700 + index,
        pgid=700 + index,
        start_time=9000 + index,
        executable_path=f"/opt/holoagent0/participant-{index}",
        executable_sha256=chr(ord("a") + index) * 64,
    )


def _ownership_message(identity, *, sequence=1):
    return {
        "type": "OWNERSHIP_RECORD",
        "run_nonce": "7" * 64,
        "sequence": sequence,
        "identity": identity.as_dict(),
        "role": "action_child",
    }


def _participant_message(index, identity=None):
    identity = identity or _participant_identity(index)
    return {
        "type": "PARTICIPANT_RECORD",
        "run_nonce": "7" * 64,
        "sequence": index + 2,
        "identity": identity.as_dict(),
        "role": CONFIG_ROLES[index],
        "participant_index": index,
        "config_digest": EXPECTED_CONFIG_SHA256[index],
    }


def test_ownership_broker_externally_validates_exact_four_participants(tmp_path):
    action = ProcessIdentity(
        pid=699,
        pgid=699,
        start_time=8999,
        executable_path="/opt/holoagent0/action-child",
        executable_sha256="f" * 64,
    )
    identities = [action, *(_participant_identity(index) for index in range(4))]
    operations = FakeProcessOperations(
        {identity.pid: identity for identity in identities}
    )
    controller = OwnedProcessController(operations)
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    try:
        supervisor_module.write_frame(record_write, _ownership_message(action))
        for index in range(4):
            supervisor_module.write_frame(record_write, _participant_message(index))
        broker = SupervisorOwnershipBroker(
            journal,
            run_nonce="7" * 64,
            record_read_fd=record_read,
            acceptance_write_fd=acceptance_write,
            owned_process_controller=controller,
            participant_identity_validator=lambda _identity: True,
        )
        accepted = broker.serve_until_complete()
        acknowledgements = [
            supervisor_module.read_frame(acceptance_read) for _ in range(5)
        ]

        assert accepted.action_lease.identity == action
        assert tuple(item.identity for item in accepted.participants) == tuple(
            identities[1:]
        )
        assert tuple(item.participant_index for item in accepted.participants) == (
            0,
            1,
            2,
            3,
        )
        assert supervisor_module._participant_policy_authority(accepted) == {
            identity.pid: {
                "index": index,
                "config_digest": EXPECTED_CONFIG_SHA256[index],
            }
            for index, identity in enumerate(identities[1:])
        }
        assert [item["type"] for item in acknowledgements] == [
            "OWNERSHIP_ACCEPTED",
            "PARTICIPANT_ACCEPTED",
            "PARTICIPANT_ACCEPTED",
            "PARTICIPANT_ACCEPTED",
            "PARTICIPANT_ACCEPTED",
        ]
        assert journal.seal().record_count == 5
        with pytest.raises(SupervisorError, match="complete"):
            broker.serve_once()
    finally:
        for descriptor in (
            record_read,
            record_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(descriptor)


def test_ownership_broker_rejects_duplicate_and_missing_participants(tmp_path):
    action = ProcessIdentity(699, 699, 8999, "/bin/action", "f" * 64)
    participants = [_participant_identity(index) for index in range(4)]
    operations = FakeProcessOperations(
        {identity.pid: identity for identity in (action, *participants)}
    )
    controller = OwnedProcessController(operations)
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    try:
        supervisor_module.write_frame(record_write, _ownership_message(action))
        supervisor_module.write_frame(record_write, _participant_message(0))
        supervisor_module.write_frame(
            record_write, _participant_message(1, identity=participants[0])
        )
        broker = SupervisorOwnershipBroker(
            journal,
            run_nonce="7" * 64,
            record_read_fd=record_read,
            acceptance_write_fd=acceptance_write,
            owned_process_controller=controller,
            participant_identity_validator=lambda _identity: True,
        )
        with pytest.raises(SupervisorError, match="distinct"):
            broker.serve_until_complete()
        assert len((tmp_path / "ownership.ndjson").read_text().splitlines()) == 2
    finally:
        for descriptor in (
            record_read,
            record_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(descriptor)


def test_live_trace_launch_does_not_claim_participants_before_registration():
    assert "participant_identities" not in LiveTraceLaunchOutcome.__dataclass_fields__


def test_ownership_broker_rejects_participant_not_externally_stopped(tmp_path):
    action = ProcessIdentity(699, 699, 8999, "/bin/action", "f" * 64)
    participant = _participant_identity(0)
    operations = FakeProcessOperations(
        {identity.pid: identity for identity in (action, participant)}
    )
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    try:
        supervisor_module.write_frame(record_write, _ownership_message(action))
        supervisor_module.write_frame(record_write, _participant_message(0))
        broker = SupervisorOwnershipBroker(
            journal,
            run_nonce="7" * 64,
            record_read_fd=record_read,
            acceptance_write_fd=acceptance_write,
            owned_process_controller=OwnedProcessController(operations),
            participant_identity_validator=lambda _identity: False,
        )
        broker.serve_once()
        with pytest.raises(SupervisorError, match="stopped"):
            broker.serve_once()
        assert len((tmp_path / "ownership.ndjson").read_text().splitlines()) == 1
    finally:
        for descriptor in (
            record_read,
            record_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(descriptor)


def test_concurrent_production_brokers_accept_real_child_ledger_and_ownership(
    tmp_path,
):
    contract = ContractSet(PACKAGE_ROOT)
    run_root = tmp_path / "broker-runtime"
    run_root.mkdir()
    store = supervisor_module.LedgerStore.create(
        run_root / "ledger", contract, "8" * 64, run_id="broker-runtime"
    )
    ownership = AppendOnlyJournal.create(
        run_root / "ownership.ndjson",
        relative_to=run_root,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    candidate_read, candidate_write = os.pipe()
    ledger_accept_read, ledger_accept_write = os.pipe()
    ownership_read, ownership_write = os.pipe()
    ownership_accept_read, ownership_accept_write = os.pipe()
    deadline = time.monotonic() + 5.0
    script = r"""
import copy,json,os,signal,subprocess
from pathlib import Path
from holoagent0_setup.coordinator import Task3LedgerClient,Task4OwnershipClient
from holoagent0_setup.cyclone_policy import CONFIG_ROLES,EXPECTED_CONFIG_SHA256
from holoagent0_setup.process_identity import read_process_identity
document=json.loads(os.environ['INITIAL_LEDGER'])
identity=read_process_identity(Path('/proc'),os.getpid())
owner=Task4OwnershipClient(run_nonce='8'*64,record_write_fd=int(os.environ['OWN_W']),acceptance_read_fd=int(os.environ['OWN_R']),deadline=float(os.environ['DEADLINE']))
owner.append_identity(identity)
participants=[]
for index in range(4):
    process=subprocess.Popen(['/bin/sleep','30'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    process.send_signal(signal.SIGSTOP)
    os.waitpid(process.pid,os.WUNTRACED)
    participant=read_process_identity(Path('/proc'),process.pid)
    owner.append_participant(participant,participant_index=index,role=CONFIG_ROLES[index],config_digest=EXPECTED_CONFIG_SHA256[index])
    participants.append(process)
owner.require_participant_registration_complete()
for process in participants:
    process.send_signal(signal.SIGCONT)
    os.killpg(process.pid,signal.SIGKILL)
    process.wait()
client=Task3LedgerClient(candidate_write_fd=int(os.environ['LEDGER_W']),acceptance_read_fd=int(os.environ['LEDGER_R']),initial_document=document,initial_digest=os.environ['INITIAL_DIGEST'],deadline=float(os.environ['DEADLINE']))
gates=copy.deepcopy(document['gates'])
for gate in gates[:24]: gate.update(status='PASS',reason='OK')
client.submit(gates,sealed=True)
"""
    environment = {
        "PYTHONPATH": str(PACKAGE_ROOT),
        "INITIAL_LEDGER": json.dumps(store.current, separators=(",", ":")),
        "INITIAL_DIGEST": store.head.digest,
        "OWN_W": str(ownership_write),
        "OWN_R": str(ownership_accept_read),
        "LEDGER_W": str(candidate_write),
        "LEDGER_R": str(ledger_accept_read),
        "DEADLINE": str(deadline),
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    child = subprocess.Popen(
        ["/usr/bin/python3", "-c", script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env=environment,
        pass_fds=(
            candidate_write,
            ledger_accept_read,
            ownership_write,
            ownership_accept_read,
        ),
        start_new_session=True,
    )
    for descriptor in (
        candidate_write,
        ledger_accept_read,
        ownership_write,
        ownership_accept_read,
    ):
        os.close(descriptor)

    class BrokerProcessOperations:
        def __init__(self):
            self.identities = {}

        def open_pidfd(self, identity):
            self.identities[identity.pid + 10_000] = identity
            return identity.pid + 10_000

        def identity_matches(self, identity):
            return self.identities.get(identity.pid + 10_000) == identity

        group_identity_matches = identity_matches

        def is_alive(self, _pidfd):
            return False

        def send_signal(self, *_args):
            return None

        def send_group_signal(self, *_args):
            return None

        def send_retained_group_signal(self, *_args):
            return None

        def wait_dead(self, *_args):
            return True

        def wait_group_gone(self, *_args):
            return True

        def reap(self, *_args):
            return False

        def prove_owned_absent(self, *_args):
            return True

        def close_pidfd(self, pidfd):
            self.identities.pop(pidfd, None)

    controller = OwnedProcessController(BrokerProcessOperations(), wait_seconds=1.0)
    channels = ProductionBrokerChannels(
        candidate_read,
        ledger_accept_write,
        ownership_read,
        ownership_accept_write,
    )
    try:
        try:
            accepted = ConcurrentSupervisorBrokerRuntime(
                store=store,
                ownership_journal=ownership,
                owned_process_controller=controller,
                channels=channels,
                deadline=deadline,
            ).collect()
        except Exception as error:
            child.wait(timeout=2)
            raise AssertionError(child.stderr.read().decode()) from error
        assert accepted.head.sealed is True
        assert accepted.document["sealed"] is True
        assert accepted.ownership.action_lease in controller.active_leases()
        assert len(accepted.ownership.participants) == 4
        assert all(
            item.lease in controller.active_leases()
            for item in accepted.ownership.participants
        )
        absent = False
        for _attempt in range(100):
            participant_absent = controller.verify_absent(
                tuple(item.lease for item in accepted.ownership.participants)
            )
            absent = participant_absent and controller.verify_absent(
                (accepted.ownership.action_lease,)
            )
            if absent:
                break
            time.sleep(0.01)
        assert absent is True
        child.poll()
        assert child.returncode in {None, 0}, child.stderr.read().decode()
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=1)
        for descriptor in channels.descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass
        store.close()


def test_retained_lease_cannot_cross_controller_authority(process_identities):
    identity = process_identities[2]
    operations = FakeProcessOperations({identity.pid: identity})
    owner = OwnedProcessController(operations)
    lease = owner.acquire(identity)

    with pytest.raises(RuntimeError, match="lease authority"):
        OwnedProcessController(operations).verify_absent((lease,))
    assert operations.signals == []
    assert operations.closed == []


def test_cleanup_signals_owned_group_then_reaps_and_proves_absence(
    process_identities,
):
    identity = process_identities[2]
    operations = FakeProcessOperations(
        {identity.pid: identity}, stubborn_groups={identity.pgid}
    )
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(identity)
    assert controller.cleanup((lease,))
    assert operations.signals == [
        ("group", identity.pgid, signal.SIGTERM),
        ("group", identity.pgid, signal.SIGKILL),
    ]
    assert operations.reaped == [identity.pid]
    assert operations.absence_proofs == [(identity.pid, True)]
    assert operations.closed == [identity.pid + 10_000]


def _live_process_identity(process):
    deadline = time.monotonic() + 2.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            return read_process_identity(Path("/proc"), process.pid)
        except Exception as error:
            last_error = error
            time.sleep(0.01)
    raise AssertionError("live child identity was not observable") from last_error


def test_real_cleanup_reaps_graceful_zombie_before_deciding_group_is_live(
    monkeypatch,
):
    child = subprocess.Popen(
        ["/bin/sleep", "30"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    identity = _live_process_identity(child)
    real_killpg = os.killpg
    signals = []

    def recording_killpg(pgid, signum):
        if signum in {signal.SIGTERM, signal.SIGKILL}:
            signals.append(signum)
        return real_killpg(pgid, signum)

    monkeypatch.setattr(supervisor_module.os, "killpg", recording_killpg)
    controller = OwnedProcessController(wait_seconds=0.2)
    lease = controller.acquire(identity)
    try:
        assert controller.cleanup((lease,)) is True
        assert signals == [signal.SIGTERM]
        assert not Path(f"/proc/{child.pid}").exists()
    finally:
        if child.poll() is None:
            real_killpg(identity.pgid, signal.SIGKILL)
            child.wait(timeout=1)


def test_real_success_accepts_coordinator_reaped_grandchild_without_waitid():
    coordinator = subprocess.Popen(
        [
            "/usr/bin/python3",
            "-c",
            (
                "import os,sys; "
                "read_fd,write_fd=os.pipe(); child=os.fork(); "
                "(os.close(write_fd),os.setsid(),print(os.getpid(),flush=True),"
                " os.read(read_fd,1),os._exit(0)) if child == 0 else None; "
                "os.close(read_fd); sys.stdin.buffer.read(1); "
                "os.write(write_fd,b'x'); os.close(write_fd); os.waitpid(child,0); "
                "print('reaped',flush=True); sys.stdin.buffer.read(1)"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    assert coordinator.stdout is not None
    assert coordinator.stdin is not None
    action_pid = int(coordinator.stdout.readline().decode("ascii").strip())
    identity = _live_process_identity(type("Process", (), {"pid": action_pid})())
    controller = OwnedProcessController(wait_seconds=0.2)
    lease = controller.acquire(identity)
    try:
        coordinator.stdin.write(b"1")
        coordinator.stdin.flush()
        assert coordinator.stdout.readline() == b"reaped\n"
        assert controller.verify_absent((lease,)) is True
        assert controller.active_leases() == ()
    finally:
        if coordinator.poll() is None:
            try:
                coordinator.stdin.write(b"2")
                coordinator.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            coordinator.wait(timeout=1)


def test_real_cleanup_escalates_stubborn_group_from_term_to_kill(monkeypatch):
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "print('ready', flush=True); time.sleep(30)"
            ),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    assert child.stdout is not None and child.stdout.readline() == "ready\n"
    identity = _live_process_identity(child)
    real_killpg = os.killpg
    signals = []

    def recording_killpg(pgid, signum):
        if signum in {signal.SIGTERM, signal.SIGKILL}:
            signals.append(signum)
        return real_killpg(pgid, signum)

    monkeypatch.setattr(supervisor_module.os, "killpg", recording_killpg)
    controller = OwnedProcessController(wait_seconds=0.1)
    lease = controller.acquire(identity)
    try:
        assert controller.cleanup((lease,)) is True
        assert signals == [signal.SIGTERM, signal.SIGKILL]
        assert not Path(f"/proc/{child.pid}").exists()
    finally:
        if child.poll() is None:
            real_killpg(identity.pgid, signal.SIGKILL)
            child.wait(timeout=1)


def test_real_reaped_leader_retains_authority_to_kill_descendant_group():
    child = subprocess.Popen(
        [
            "/usr/bin/python3",
            "-c",
            (
                "import os,signal,time; "
                "pid=os.fork(); "
                "(signal.signal(signal.SIGTERM, signal.SIG_IGN), "
                " time.sleep(30), os._exit(0)) if pid == 0 else None; "
                "print(pid, flush=True); os.read(0, 1)"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    assert child.stdout is not None
    descendant_pid = int(child.stdout.readline().strip())
    identity = _live_process_identity(child)
    controller = OwnedProcessController(wait_seconds=0.2)
    lease = controller.acquire(identity)
    assert child.stdin is not None
    child.stdin.close()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{child.pid}/stat").read_text().split()[2]
        except OSError:
            state = None
        if state == "Z":
            break
        time.sleep(0.01)
    try:
        assert controller.verify_absent((lease,)) is False
        assert controller.active_leases() == (lease,)
        assert controller.cleanup((lease,)) is True
        assert controller.active_leases() == ()
        deadline = time.monotonic() + 1.0
        while Path(f"/proc/{descendant_pid}").exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not Path(f"/proc/{descendant_pid}").exists()
    finally:
        try:
            os.killpg(identity.pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if child.poll() is None:
            child.wait(timeout=1)


def test_cleanup_refuses_nonleader_process_group_without_signal(process_identities):
    identity = process_identities[2]
    nonleader = ProcessIdentity(
        identity.pid,
        identity.pgid + 10,
        identity.start_time,
        identity.executable_path,
        identity.executable_sha256,
    )
    operations = FakeProcessOperations({nonleader.pid: nonleader})

    with pytest.raises(RuntimeError, match="identity changed"):
        OwnedProcessController(operations).acquire(nonleader)
    assert operations.signals == []
    assert operations.reaped == []


def test_cleanup_does_not_signal_group_after_identity_reuse(process_identities):
    identity = process_identities[2]
    replacement = ProcessIdentity(
        identity.pid,
        identity.pgid,
        identity.start_time + 1,
        identity.executable_path,
        identity.executable_sha256,
    )
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)
    operations.identities[identity.pid] = replacement

    assert not controller.cleanup((lease,))
    assert operations.signals == []
    assert operations.reaped == []


def test_cleanup_fails_when_exit_cannot_be_reaped(process_identities):
    identity = process_identities[2]

    class Unreapable(FakeProcessOperations):
        def reap(self, identity, pidfd, timeout_seconds):
            return False

    operations = Unreapable({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)

    assert not controller.cleanup((lease,))
    assert operations.signals == [("group", identity.pgid, signal.SIGTERM)]
    assert operations.absence_proofs == []


def test_cleanup_fails_when_owned_group_absence_cannot_be_proved(
    process_identities,
):
    identity = process_identities[2]

    class UnprovableAbsence(FakeProcessOperations):
        def prove_owned_absent(self, identity, pidfd):
            self.absence_proofs.append((identity.pid, False))
            return False

    operations = UnprovableAbsence({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)

    assert not controller.cleanup((lease,))
    assert operations.reaped == [identity.pid]
    assert operations.absence_proofs == [(identity.pid, False)]


def test_cleanup_uses_retained_group_authority_after_reaping_leader(
    process_identities,
):
    identity = process_identities[2]

    class LeaderExitsWithGroupRemaining(FakeProcessOperations):
        def send_group_signal(self, pidfd, identity, signal_number):
            super().send_group_signal(pidfd, identity, signal_number)
            if signal_number == signal.SIGTERM:
                self.alive.discard(identity.pid)
                self.groups.add(identity.pgid)

    operations = LeaderExitsWithGroupRemaining({identity.pid: identity})
    controller = OwnedProcessController(operations, wait_seconds=0)
    lease = controller.acquire(identity)

    assert controller.cleanup((lease,))
    assert operations.signals == [
        ("group", identity.pgid, signal.SIGTERM),
        ("group", identity.pgid, signal.SIGKILL),
    ]
    assert operations.reaped == [identity.pid]


def test_linux_group_signal_targets_verified_pgid_not_pidfd(
    monkeypatch, process_identities
):
    identity = process_identities[2]
    calls = []
    monkeypatch.setattr(ProcessIdentity, "matches_proc", lambda self: self == identity)
    monkeypatch.setattr(
        ProcessIdentity, "matches_coordinator_session", lambda self: self == identity
    )
    monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 77, raising=False)
    monkeypatch.setattr(LinuxProcessOperations, "is_alive", lambda self, pidfd: True)
    monkeypatch.setattr(os, "killpg", lambda pgid, signum: calls.append((pgid, signum)))

    operations = LinuxProcessOperations()
    pidfd = operations.open_pidfd(identity)
    operations.send_group_signal(pidfd, identity, signal.SIGTERM)

    assert calls == [(identity.pgid, signal.SIGTERM)]


def test_linux_reap_uses_bound_pidfd_waitid(monkeypatch, process_identities):
    identity = process_identities[2]
    calls = []
    wait_result = type("WaitResult", (), {"si_pid": identity.pid})()
    monkeypatch.setattr(ProcessIdentity, "matches_proc", lambda self: self == identity)
    monkeypatch.setattr(os, "pidfd_open", lambda pid, flags: 77, raising=False)
    monkeypatch.setattr(os, "P_PIDFD", 3, raising=False)
    monkeypatch.setattr(
        os,
        "waitid",
        lambda idtype, ident, options: (
            calls.append((idtype, ident, options)) or wait_result
        ),
    )
    monkeypatch.setattr(
        os, "waitpid", lambda pid, options: pytest.fail("numeric waitpid is unsafe")
    )
    operations = LinuxProcessOperations()
    pidfd = operations.open_pidfd(identity)

    assert operations.reap(identity, pidfd, 0)
    assert calls == [(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)]


def test_pid_reuse_identity_mismatch_is_fail_closed_without_signal(process_identities):
    identity = process_identities[2]
    replacement = ProcessIdentity(
        identity.pid,
        identity.pgid,
        identity.start_time + 1,
        identity.executable_path,
        identity.executable_sha256,
    )
    operations = FakeProcessOperations({identity.pid: identity})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(identity)
    operations.identities[identity.pid] = replacement
    assert not controller.cleanup((lease,))
    assert operations.signals == []


@pytest.fixture
def reviewed_trace_contract(tmp_path, process_identities):
    root = tmp_path / "contract"
    shutil.copytree(PACKAGE_ROOT / "schemas", root / "schemas")
    shutil.copytree(PACKAGE_ROOT / "policies", root / "policies")
    policy_path = root / "policies/holoagent0-trace-tool-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    row = policy["rows"][0]
    row["build"].update(
        recipe_sha256="1" * 64,
        container_image_digest="sha256:" + "2" * 64,
        review_state="REVIEWED",
    )
    row["runtime"].update(
        elf_size=1,
        elf_sha256=process_identities[0].executable_sha256,
        version_output_sha256="4" * 64,
        review_state="REVIEWED",
    )
    row["parser"].update(sha256="5" * 64, review_state="REVIEWED")
    row["fixtures"].update(manifest_sha256="7" * 64, review_state="REVIEWED")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return ContractSet(root)


@pytest.fixture
def reviewed_exitkill_contract(tmp_path):
    root = tmp_path / "exitkill-contract"
    shutil.copytree(PACKAGE_ROOT / "schemas", root / "schemas")
    shutil.copytree(PACKAGE_ROOT / "policies", root / "policies")
    executable = root / "trace/install/bin/strace"
    executable.parent.mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", executable)
    executable.chmod(0o755)
    payload = executable.read_bytes()
    policy_path = root / "policies/holoagent0-trace-tool-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    row = policy["rows"][0]
    row["build"].update(
        recipe_sha256="1" * 64,
        container_image_digest="sha256:" + "2" * 64,
        review_state="REVIEWED",
    )
    row["runtime"].update(
        elf_size=len(payload),
        elf_sha256=hashlib.sha256(payload).hexdigest(),
        version_output_sha256="4" * 64,
        review_state="REVIEWED",
    )
    row["parser"].update(sha256="5" * 64, review_state="REVIEWED")
    row["fixtures"].update(manifest_sha256="7" * 64, review_state="REVIEWED")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return ContractSet(root), executable


def test_exitkill_capability_probe_binds_exact_reviewed_elf_and_runner(
    reviewed_exitkill_contract,
):
    contract, executable = reviewed_exitkill_contract
    observed = []

    def runner(spec):
        observed.append((spec, os.fstat(spec.strace_fd).st_ino))
        return ExitkillProbeEvidence(
            helper_pid=123,
            child_subreaper=True,
            tracer_pid=124,
            tracee_pid=125,
            tracer_reaped=True,
            tracee_reaped=True,
            tracee_exit_signal=signal.SIGKILL,
            terminal_absence=True,
        )

    assert ExitkillCapabilityProbe(contract, runner=runner).verify() is True
    assert len(observed) == 1
    spec, retained_inode = observed[0]
    assert spec.strace_path == executable
    assert retained_inode == executable.stat().st_ino
    assert spec.strace_sha256 == hashlib.sha256(executable.read_bytes()).hexdigest()
    row = contract.trace_tool_rows()[0]
    assert spec.options == tuple(row["argv"]["options"])
    assert spec.environment == (("LC_ALL", "C"), ("TZ", "UTC"))


def test_exitkill_capability_probe_fails_closed_on_runner_failure(
    reviewed_exitkill_contract,
):
    contract, _executable = reviewed_exitkill_contract
    with pytest.raises(RuntimeError, match="live EXITKILL capability"):
        ExitkillCapabilityProbe(contract, runner=lambda _spec: False).verify()


def test_exitkill_capability_requires_explicit_adopted_tracee_reap_evidence(
    reviewed_exitkill_contract,
):
    contract, _executable = reviewed_exitkill_contract
    incomplete = ExitkillProbeEvidence(
        helper_pid=123,
        child_subreaper=True,
        tracer_pid=124,
        tracee_pid=125,
        tracer_reaped=True,
        tracee_reaped=False,
        tracee_exit_signal=signal.SIGKILL,
        terminal_absence=True,
    )

    with pytest.raises(RuntimeError, match="tracee reap evidence"):
        ExitkillCapabilityProbe(contract, runner=lambda _spec: incomplete).verify()


def test_exitkill_capability_runs_in_isolated_verified_subreaper(
    reviewed_exitkill_contract, monkeypatch
):
    contract, _executable = reviewed_exitkill_contract
    parent_pid = os.getpid()

    def fake_worker(_spec):
        helper_pid = os.getpid()
        return ExitkillProbeEvidence(
            helper_pid=helper_pid,
            child_subreaper=supervisor_module._child_subreaper_enabled(),
            tracer_pid=helper_pid + 1,
            tracee_pid=helper_pid + 2,
            tracer_reaped=True,
            tracee_reaped=True,
            tracee_exit_signal=signal.SIGKILL,
            terminal_absence=True,
        )

    monkeypatch.setattr(supervisor_module, "_run_exitkill_probe_worker", fake_worker)
    observed = []

    def capture(spec):
        evidence = supervisor_module._run_live_exitkill_probe(spec)
        observed.append(evidence)
        return evidence

    assert ExitkillCapabilityProbe(contract, runner=capture).verify() is True
    assert observed[0].helper_pid != parent_pid
    assert observed[0].child_subreaper is True


def test_exitkill_helper_waits_for_parent_identity_acceptance_before_worker(
    reviewed_exitkill_contract, monkeypatch, tmp_path
):
    contract, _executable = reviewed_exitkill_contract
    worker_started = tmp_path / "worker-started"
    original_wait = supervisor_module._wait_helper_group_identity

    def fake_worker(_spec):
        worker_started.write_text("started", encoding="ascii")
        helper_pid = os.getpid()
        return ExitkillProbeEvidence(
            helper_pid=helper_pid,
            child_subreaper=supervisor_module._child_subreaper_enabled(),
            tracer_pid=helper_pid + 1,
            tracee_pid=helper_pid + 2,
            tracer_reaped=True,
            tracee_reaped=True,
            tracee_exit_signal=signal.SIGKILL,
            terminal_absence=True,
        )

    def delayed_parent_validation(helper_pid):
        time.sleep(0.1)
        assert not worker_started.exists()
        return original_wait(helper_pid)

    monkeypatch.setattr(supervisor_module, "_run_exitkill_probe_worker", fake_worker)
    monkeypatch.setattr(
        supervisor_module, "_wait_helper_group_identity", delayed_parent_validation
    )

    assert ExitkillCapabilityProbe(contract).verify() is True
    assert worker_started.exists()


def test_exitkill_capability_raw_trace_uses_only_cloexec_anonymous_pipe():
    read_fd, write_fd = supervisor_module._open_exitkill_trace_pipe()
    try:
        assert stat.S_ISFIFO(os.fstat(read_fd).st_mode)
        assert stat.S_ISFIFO(os.fstat(write_fd).st_mode)
        assert fcntl.fcntl(read_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        assert fcntl.fcntl(write_fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_exitkill_helper_failure_boundedly_removes_its_descendant_group(
    reviewed_exitkill_contract, monkeypatch, tmp_path
):
    contract, _executable = reviewed_exitkill_contract
    descendant_record = tmp_path / "descendant.pid"

    def failed_worker(_spec):
        descendant = os.fork()
        if descendant == 0:
            while True:
                signal.pause()
        descendant_record.write_text(str(descendant), encoding="ascii")
        raise RuntimeError("injected worker failure")

    monkeypatch.setattr(supervisor_module, "_run_exitkill_probe_worker", failed_worker)

    with pytest.raises(RuntimeError, match="helper failed"):
        ExitkillCapabilityProbe(contract).verify()

    descendant = int(descendant_record.read_text(encoding="ascii"))
    deadline = time.monotonic() + 1.0
    while Path(f"/proc/{descendant}").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not Path(f"/proc/{descendant}").exists()


def test_exitkill_cleanup_signals_group_before_reaping_helper(monkeypatch):
    events = []
    monkeypatch.setattr(
        supervisor_module,
        "_read_helper_group_identity",
        lambda pid: events.append(("identity", pid)) or (pid, pid, 91),
    )
    monkeypatch.setattr(
        supervisor_module.os,
        "killpg",
        lambda pgid, signum: events.append(("killpg", pgid, signum)),
    )
    monkeypatch.setattr(
        supervisor_module,
        "_process_group_exists",
        lambda _pgid: False,
    )
    monkeypatch.setattr(
        supervisor_module.os,
        "waitpid",
        lambda pid, options: events.append(("reap", pid, options)) or (pid, 0),
    )

    supervisor_module._cleanup_exitkill_helper_group(
        123, expected_identity=(123, 123, 91), terminate=True
    )

    assert events.index(("killpg", 123, signal.SIGKILL)) < events.index(
        ("reap", 123, 0)
    )


def test_exitkill_capability_probe_fails_before_runner_when_runtime_is_unavailable(
    reviewed_trace_contract,
):
    called = False

    def runner(_spec):
        nonlocal called
        called = True
        return True

    with pytest.raises(RuntimeError, match="runtime is unavailable"):
        ExitkillCapabilityProbe(reviewed_trace_contract, runner=runner).verify()
    assert called is False


@pytest.mark.skipif(
    os.environ.get("HOLOAGENT0_RUN_LIVE_EXITKILL_PROBE") != "1",
    reason="controlled live EXITKILL capability probe is opt-in",
)
def test_reviewed_runtime_has_live_exitkill_capability():
    assert ExitkillCapabilityProbe(ContractSet(PACKAGE_ROOT)).verify() is True


def test_trace_guard_requires_distinct_bound_identities_and_pinned_exitkill(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, _tracee = process_identities
    operations = FakeProcessOperations({tracer.pid: tracer, normalizer.pid: normalizer})
    guard = TraceRuntimeGuard(operations)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)
    assert guard.poll() == {"tracer": True, "normalizer": True}
    guard.close()
    assert sorted(operations.closed) == sorted(
        [tracer.pid + 10_000, normalizer.pid + 10_000]
    )

    with pytest.raises(RuntimeError, match="EXITKILL"):
        TraceRuntimeGuard(operations).attach(
            tracer, normalizer, contract=ContractSet(PACKAGE_ROOT)
        )


def test_trace_guard_detects_loss_and_invokes_owned_cleanup(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations(
        {item.pid: item for item in process_identities},
        alive={normalizer.pid, tracee.pid},
    )
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)
    loss = guard.require_live_or_cleanup((lease,))
    assert loss.reason == "TRACER_EXITED"
    assert loss.cleanup_complete is True
    assert normalizer.pid in operations.reaped
    assert (normalizer.pid, True) in operations.absence_proofs
    assert tracer.pid in operations.reaped
    assert (tracer.pid, True) in operations.absence_proofs
    assert ("group", tracee.pgid, signal.SIGTERM) in operations.signals


def test_trace_loss_reaps_peer_that_exits_during_cleanup_transition(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities

    class PeerExitsAfterPoll(FakeProcessOperations):
        def __init__(self, identities):
            super().__init__(identities, alive={normalizer.pid, tracee.pid})
            self.normalizer_probes = 0

        def is_alive(self, pidfd):
            pid = pidfd - 10_000
            if pid == normalizer.pid:
                self.normalizer_probes += 1
                if self.normalizer_probes == 2:
                    self.alive.discard(pid)
                    self.groups.discard(normalizer.pgid)
            return super().is_alive(pidfd)

    operations = PeerExitsAfterPoll({item.pid: item for item in process_identities})
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)

    loss = guard.require_live_or_cleanup((lease,))

    assert loss.cleanup_complete is True
    assert normalizer.pid in operations.reaped
    assert (normalizer.pid, True) in operations.absence_proofs


def test_normalizer_loss_terminates_tracer_before_owned_cleanup(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations(
        {item.pid: item for item in process_identities},
        alive={tracer.pid, tracee.pid},
    )
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)
    loss = guard.require_live_or_cleanup((lease,))
    assert loss.reason == "TRACE_DECODE_FAILED"
    tracer_kill = operations.signals.index(("group", tracer.pgid, signal.SIGTERM))
    tracee_term = operations.signals.index(("group", tracee.pgid, signal.SIGTERM))
    assert tracer_kill < tracee_term
    assert loss.tracer_terminated is True
    assert sorted(operations.reaped) == sorted([tracer.pid, normalizer.pid, tracee.pid])


def test_trace_guard_blocking_monitor_detects_loss_without_caller_polling(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities

    class TracerDiesDuringMonitor(FakeProcessOperations):
        def __init__(self, identities):
            super().__init__(identities)
            self.probes = 0

        def is_alive(self, pidfd):
            pid = pidfd - 10_000
            if pid == tracer.pid:
                self.probes += 1
                if self.probes == 3:
                    self.alive.discard(pid)
                    self.groups.discard(tracer.pgid)
            return super().is_alive(pidfd)

    operations = TracerDiesDuringMonitor(
        {item.pid: item for item in process_identities}
    )
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)

    loss = guard.monitor_until(
        lambda: False,
        lambda: (lease,),
        timeout_seconds=0.2,
        poll_interval_seconds=0,
    )

    assert loss is not None
    assert loss.reason == "TRACER_EXITED"
    assert loss.cleanup_complete is True
    assert sorted(operations.reaped) == sorted([tracer.pid, normalizer.pid, tracee.pid])


def test_trace_guard_blocking_monitor_returns_only_after_clean_completion(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, _tracee = process_identities
    operations = FakeProcessOperations({tracer.pid: tracer, normalizer.pid: normalizer})
    guard = TraceRuntimeGuard(operations)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)
    calls = 0

    def completed():
        nonlocal calls
        calls += 1
        return calls == 3

    assert (
        guard.monitor_until(
            completed,
            lambda: (),
            timeout_seconds=0.2,
            poll_interval_seconds=0,
        )
        is None
    )
    assert calls == 3


def test_trace_guard_timeout_cleans_all_roles_before_failing(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations({item.pid: item for item in process_identities})
    controller = OwnedProcessController(operations, wait_seconds=0.01)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)

    with pytest.raises(RuntimeError, match="completion timed out"):
        guard.monitor_until(
            lambda: False,
            lambda: (lease,),
            timeout_seconds=0,
            poll_interval_seconds=0,
        )

    assert sorted(operations.reaped) == sorted([tracer.pid, normalizer.pid, tracee.pid])


def test_trace_launch_runtime_returns_closed_monitorable_session(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    events = []
    operations = FakeProcessOperations({item.pid: item for item in process_identities})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(tracee)

    def launcher(spec):
        events.append(("launch", spec.mode))
        return tracer, normalizer

    runtime = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=launcher,
        operations=operations,
        cleanup=controller,
    )
    session = runtime.launch(TraceLaunchSpec("FULL", owned_tracees=lambda: (lease,)))

    assert type(session) is TraceSession
    assert session.monitor(lambda: True, timeout_seconds=0.1) is None
    assert session.tracer_identity == tracer
    assert session.normalizer_identity == normalizer
    assert events == [("launch", "FULL")]


def test_production_bootstrap_uses_live_signal_handoff_and_observed_launch_report(
    tmp_path, reviewed_trace_contract, process_identities
):
    tracer, normalizer, coordinator = process_identities
    operations = FakeProcessOperations({item.pid: item for item in process_identities})
    barrier_threads = []
    coordinator_handoffs = []
    broker_fds = {}

    class SignalOperations:
        def __init__(self):
            self.blocked = True
            self.handlers = (object(), object(), object())

        def observe(self):
            return SignalObservation(
                frozenset({"HUP", "INT", "TERM"}) if self.blocked else frozenset(),
                (("HUP", True), ("INT", True), ("TERM", True)),
                self.handlers,
            )

        def unblock_reviewed(self):
            self.blocked = False

    def launcher(spec):
        assert spec.mode == "FULL"
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        handoff = CoordinatorSignalHandoff(
            "6" * 64, coordinator, signal_operations=SignalOperations()
        )
        barrier = Task4SignalBarrier(
            handoff,
            request_write_fd=request_write,
            acceptance_read_fd=response_read,
            blocked_signals=frozenset({"HUP", "INT", "TERM"}),
            dispositions={"HUP": True, "INT": True, "TERM": True},
            handoff_marker=_handoff_marker(coordinator, nonce="6" * 64),
        )

        def complete_barrier():
            barrier.complete_two_way_acceptance()
            barrier.record_functional_progress()

        coordinator_handoffs.append(handoff)
        broker_fds.update(request_write=request_write, response_read=response_read)
        thread = threading.Thread(target=complete_barrier)
        thread.start()
        barrier_threads.append(thread)
        return LiveTraceLaunchOutcome(
            tracer,
            normalizer,
            coordinator,
            request_read,
            response_write,
            request_write,
            response_read,
        )

    run_root, run_id, authority = _production_run_root(tmp_path, "production-live")
    bootstrap_runtime = BootstrapRuntime.production(
        reviewed_trace_contract,
        signal_forwarder=lambda _pgid, _name: None,
        signal_identity_validator=lambda observed: observed == coordinator,
    )
    state = bootstrap_runtime.run(
        BootstrapInvocation(
            run_root=run_root,
            run_id=run_id,
            run_nonce="6" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report=_complete_bootstrap_inputs(),
            run_root_authority=authority,
        )
    )
    assert not (state.run_root / "bootstrap_report.json").exists()

    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=launcher,
        operations=operations,
        cleanup=state.owned_process_controller,
    ).launch(state)
    for thread in barrier_threads:
        thread.join(timeout=1)
        assert not thread.is_alive()

    trace_records = _readiness_protocol_records(
        coordinator,
        request_write_fd=broker_fds["request_write"],
        acceptance_read_fd=broker_fds["response_read"],
    )
    trace_path = state.run_root / "trace.ndjson"
    trace_path.write_bytes(
        b"".join(canonical_json_bytes(record) + b"\n" for record in trace_records)
    )
    trace_path.chmod(0o400)
    with pytest.raises(supervisor_module.SupervisorError, match="readiness"):
        session.finalize_signal_readiness_from_trace()
    operations.alive.clear()
    operations.groups.clear()
    session.guard.wait_terminal(timeout_seconds=1, owned_tracees=session.owned_tracees)
    session.finalize_terminal()
    retained_trace = supervisor_module._open_sealed_trace(trace_path)
    session.finalize_signal_readiness_from_trace(retained_trace)

    report = json.loads(
        (state.run_root / "bootstrap_report.json").read_text(encoding="utf-8")
    )
    assert report["terminal_launch_state"] == "COORDINATOR_LAUNCH_COMMITTED"
    assert report["coordinator_launch_committed"] is True
    assert report["handoff"]["terminal_state"] == "READY"
    assert report["handoff"]["unblock_trace_record_index"] == 26
    assert report["handoff"]["first_functional_trace_record_index"] == 31
    assert report["handoff"]["signal_ready_identity"] == coordinator.as_dict()
    assert session.tracer_identity == tracer
    assert session.normalizer_identity == normalizer
    assert session.trace_state == "FULL"
    session.guard.close()
    state.signal_runtime.close(restore_mask=True)


def test_canonical_readiness_requires_exact_successful_signal_unblock(
    tmp_path, process_identities
):
    identity = process_identities[2]
    request = _signal_ready(identity)
    trace_path = tmp_path / "trace.ndjson"
    records = _readiness_protocol_records(identity)

    _write_canonical_trace(trace_path, records)
    coordinator, evidence = supervisor_module._canonical_trace_handoff_evidence(
        trace_path,
        request=request,
        request_write_fd=13,
        acceptance_read_fd=14,
    )

    assert coordinator.unblock_count == 1
    assert coordinator.functional_count == 1
    assert evidence.unblock_trace_record_index == 26
    assert evidence.first_functional_trace_record_index == 31


def test_canonical_readiness_allows_only_reviewed_setup_before_unblock(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    coordinator, evidence = supervisor_module._canonical_trace_handoff_evidence(
        trace_path,
        request=_signal_ready(identity),
        request_write_fd=13,
        acceptance_read_fd=14,
    )

    assert coordinator.functional_count == 1
    assert evidence.unblock_trace_record_index == 26
    assert evidence.first_functional_trace_record_index == 31


def test_canonical_readiness_ignores_cpython_startup_before_exact_handoff_region(
    tmp_path, process_identities
):
    identity = process_identities[2]
    startup_queries = [
        _readiness_signal_query_record(identity, name, record_index=index)
        for index, name in enumerate(("HUP", "INT", "TERM"))
    ]
    startup_action = _readiness_signal_action_record(identity, "INT", record_index=3)
    records = _reindex_trace_records(
        [
            *startup_queries,
            startup_action,
            {**_functional_record(identity, record_index=4), "syscall": "brk"},
            *_readiness_protocol_records(identity),
        ]
    )
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    coordinator, evidence = supervisor_module._canonical_trace_handoff_evidence(
        trace_path,
        request=_signal_ready(identity),
        request_write_fd=13,
        acceptance_read_fd=14,
    )

    assert coordinator.unblock_count == 1
    assert evidence.unblock_trace_record_index == 31


def test_canonical_readiness_rejects_duplicate_handoff_region(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    duplicate_anchor = copy.deepcopy(records[:5])
    records = _reindex_trace_records([*duplicate_anchor, *records])
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(supervisor_module.SupervisorError, match="ambiguous"):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_canonical_readiness_rejects_partial_handoff_region_before_exact_region(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    partial_anchor = copy.deepcopy(records[:2])
    records = _reindex_trace_records([*partial_anchor, *records])
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(supervisor_module.SupervisorError, match="ambiguous"):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_canonical_readiness_rejects_unreviewed_syscall_inside_handoff_region(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    records.insert(
        5, {**_functional_record(identity, record_index=5), "syscall": "brk"}
    )
    _reindex_trace_records(records)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda records: records[12]["fds"][0].update(fd=99),
        lambda records: records[7]["transition"]["source_fd"].update(fd=99),
    ],
    ids=("same-shape-write-wrong-fd", "request-alias-wrong-provenance"),
)
def test_canonical_readiness_rejects_wrong_broker_fd_provenance(
    tmp_path, process_identities, mutation
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    mutation(records)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda records: records.pop(8),
        lambda records: records.pop(9),
        lambda records: records.__setitem__(slice(8, 10), [records[9], records[8]]),
        lambda records: records[8]["validation"]["fd"].update(fd=99),
        lambda records: records[8]["validation"].update(inode=99),
        lambda records: records[9]["validation"].update(fd=99),
        lambda records: records[9]["validation"]["target_provenance"].update(inode=99),
        lambda records: records[10]["transition"].update(status_flags=["O_RDONLY"]),
        lambda records: records[18]["transition"].update(status_flags=["O_WRONLY"]),
        lambda records: records[7]["transition"].update(cloexec=False),
        lambda records: records[7]["transition"].update(minimum_fd=1),
    ],
    ids=(
        "missing-stat",
        "missing-readlink",
        "readlink-before-stat",
        "stat-wrong-fd",
        "stat-wrong-inode",
        "readlink-wrong-fd",
        "readlink-wrong-inode",
        "request-not-write-only",
        "acceptance-not-read-only",
        "duplicate-not-cloexec",
        "duplicate-nonzero-minimum",
    ),
)
def test_canonical_readiness_requires_exact_alias_validation_sequence(
    tmp_path, process_identities, mutation
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    mutation(records)
    _reindex_trace_records(records)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda records: records[11]["wait"]["fd"].update(fd=99),
        lambda records: records[11]["wait"].update(direction="read"),
        lambda records: records[19]["result"]["ready"].update(fd={"fd": 99}),
        lambda records: records.__setitem__(slice(11, 13), [records[12], records[11]]),
    ],
    ids=(
        "request-wait-wrong-fd",
        "request-wait-wrong-direction",
        "acceptance-ready-wrong-fd",
        "request-wait-after-write",
    ),
)
def test_canonical_readiness_binds_pselect_to_broker_alias_direction_and_phase(
    tmp_path, process_identities, mutation
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    mutation(records)
    _reindex_trace_records(records)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_canonical_readiness_rejects_out_of_order_broker_io(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    records[14], records[15] = records[15], records[14]
    for index, record in enumerate(records):
        record.update(record_index=index, entry_index=index, exit_index=index)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    "record_factory",
    [
        lambda identity: {
            **_functional_record(identity, record_index=0),
            "syscall": "openat",
        },
        lambda identity: _readiness_signal_action_record(
            identity, "USR1", record_index=0
        ),
        lambda identity: _readiness_broker_write_record(
            identity, record_index=0, count=4101
        ),
    ],
    ids=("functional-open", "unreviewed-handler", "oversize-broker-write"),
)
def test_canonical_readiness_rejects_unreviewed_pre_unblock_activity(
    tmp_path, process_identities, record_factory
):
    identity = process_identities[2]
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(
        trace_path,
        [
            record_factory(identity),
            _signal_unblock_record(identity, record_index=1),
            _functional_record(identity, record_index=2),
        ],
    )

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda record, _identity: record["transition"].update(how="SIG_BLOCK"),
        lambda record, _identity: record["transition"].update(mask=["HUP", "TERM"]),
        lambda record, _identity: record["transition"].update(
            old_mask={"address": "0x1"}
        ),
        lambda record, _identity: record["transition"].update(sigset_size=16),
        lambda record, identity: record.update(pid=identity.pid + 1),
        lambda record, _identity: record.update(
            result={"value": -1, "errno": "EINVAL"}
        ),
    ],
    ids=(
        "wrong-how",
        "wrong-mask",
        "old-mask-output",
        "wrong-sigset-size",
        "wrong-pid",
        "failed-result",
    ),
)
def test_canonical_readiness_rejects_nonmatching_unblock(
    tmp_path, process_identities, mutation
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    record = records[26]
    mutation(record, identity)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(supervisor_module.SupervisorError, match="signal unblock"):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_canonical_readiness_rejects_functional_progress_before_unblock(
    tmp_path, process_identities
):
    identity = process_identities[2]
    trace_path = tmp_path / "trace.ndjson"
    records = _readiness_protocol_records(identity)
    records[4] = _functional_record(identity, record_index=4)
    _write_canonical_trace(trace_path, records)

    with pytest.raises(
        supervisor_module.SupervisorError, match="before signal unblock"
    ):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        (
            lambda records, identity: records[8].update(pid=identity.pid + 1),
            "PID or TID",
        ),
        (lambda records, _identity: records.pop(1), "readiness name"),
        (
            lambda records, _identity: records.insert(2, copy.deepcopy(records[1])),
            "handler anchor",
        ),
        (
            lambda records, _identity: records[0]["handoff_marker"].update(
                token="0" * 12
            ),
            "boundaries",
        ),
        (
            lambda records, identity: records.insert(
                29, _functional_record(identity, record_index=29)
            ),
            "post-unblock",
        ),
        (
            lambda records, identity: records.insert(
                29,
                {
                    **_functional_record(identity, record_index=29),
                    "handoff_name_observation": {
                        "phase": "FUNCTIONAL",
                        "token": "6" * 12,
                    },
                },
            ),
            "post-unblock",
        ),
        (
            lambda records, _identity: records[27]["transition"].update(
                old_mask=["HUP", "INT", "TERM"]
            ),
            "post-unblock",
        ),
    ],
    ids=(
        "foreign-tid-in-global-interval",
        "missing-readiness-name-observation",
        "duplicate-readiness-name-observation",
        "spoofed-readiness-token",
        "arbitrary-post-unblock-action",
        "arbitrary-pr-get-name-post-unblock",
        "stale-blocked-mask-post-unblock",
    ),
)
def test_canonical_readiness_rejects_nonexact_global_handoff_interval(
    tmp_path, process_identities, mutation, match
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    mutation(records, identity)
    _reindex_trace_records(records)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(supervisor_module.SupervisorError, match=match):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_canonical_readiness_uses_functional_boundary_as_sole_progress_record(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    coordinator, evidence = supervisor_module._canonical_trace_handoff_evidence(
        trace_path,
        request=_signal_ready(identity),
        request_write_fd=13,
        acceptance_read_fd=14,
    )

    assert records[evidence.first_functional_trace_record_index]["handoff_marker"] == {
        "phase": "FUNCTIONAL_BEGIN",
        "token": "6" * 12,
    }
    assert coordinator.functional_count == evidence.functional_count == 1


def test_canonical_readiness_accepts_reviewed_signal_immediately_after_unblock(
    tmp_path, process_identities
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)[:27]
    records.append(
        {
            "kind": "signal",
            "pid": identity.pid,
            "record_index": 27,
            "signal": "SIGTERM",
        }
    )
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    coordinator, evidence = supervisor_module._canonical_trace_handoff_evidence(
        trace_path,
        request=_signal_ready(identity),
        request_write_fd=13,
        acceptance_read_fd=14,
    )

    assert coordinator.unblock_count == 1
    assert coordinator.functional_count == 0
    assert evidence.first_functional_trace_record_index is None
    assert evidence.functional_count == 0
    assert evidence.delivered_signal == "TERM"


@pytest.mark.parametrize("signal_name", ["SIGUSR1", None])
def test_canonical_interrupted_readiness_rejects_unreviewed_or_missing_signal(
    tmp_path, process_identities, signal_name
):
    identity = process_identities[2]
    records = _readiness_protocol_records(identity)[:27]
    if signal_name is not None:
        records.append(
            {
                "kind": "signal",
                "pid": identity.pid,
                "record_index": 27,
                "signal": signal_name,
            }
        )
    trace_path = tmp_path / "trace.ndjson"
    _write_canonical_trace(trace_path, records)

    with pytest.raises(supervisor_module.SupervisorError, match="signal delivery"):
        supervisor_module._canonical_trace_handoff_evidence(
            trace_path,
            request=_signal_ready(identity),
            request_write_fd=13,
            acceptance_read_fd=14,
        )


def test_production_precommit_signal_launches_only_finalizer_trace(
    tmp_path, reviewed_trace_contract, process_identities
):
    tracer, normalizer, _coordinator = process_identities
    operations = FakeProcessOperations({tracer.pid: tracer, normalizer.pid: normalizer})
    modes = []
    run_root, run_id, authority = _production_run_root(tmp_path, "precommit-live")
    runtime = BootstrapRuntime.production(
        reviewed_trace_contract,
        signal_forwarder=lambda _pgid, _name: None,
        signal_identity_validator=lambda _identity: False,
    )
    state = runtime.run(
        BootstrapInvocation(
            run_root=run_root,
            run_id=run_id,
            run_nonce="5" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report=_complete_bootstrap_inputs(),
            run_root_authority=authority,
        )
    )
    os.kill(os.getpid(), signal.SIGTERM)
    assert state.signal_runtime.wait_first_signal(1.0) == "TERM"

    def finalizer_launcher(spec):
        modes.append(spec.mode)
        assert spec.mode == "FINALIZER_ONLY"
        return tracer, normalizer

    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=finalizer_launcher,
        operations=operations,
        cleanup=state.owned_process_controller,
    ).launch(state)

    assert modes == ["FINALIZER_ONLY"]
    assert session.trace_state == "FINALIZER_ONLY"
    report = json.loads(
        (state.run_root / "bootstrap_report.json").read_text(encoding="utf-8")
    )
    assert report["terminal_launch_state"] == "PRE_COORDINATOR_INTERRUPTED"
    assert report["coordinator_launch_committed"] is False
    assert report["first_signal"] == "TERM"
    assert report["handoff"]["terminal_state"] == "NOT_APPLICABLE"
    session.guard.close()
    state.signal_runtime.close(restore_mask=True)


def test_production_bootstrap_failure_launches_finalizer_without_full_handoff(
    tmp_path, reviewed_trace_contract, process_identities
):
    tracer, normalizer, _coordinator = process_identities
    operations = FakeProcessOperations({tracer.pid: tracer, normalizer.pid: normalizer})
    modes = []
    run_root, run_id, authority = _production_run_root(
        tmp_path, "finalizer-bootstrap-failure"
    )
    runtime = BootstrapRuntime.production(
        reviewed_trace_contract,
        signal_forwarder=lambda _pgid, _name: None,
        signal_identity_validator=lambda _identity: False,
    )
    state = runtime.run(
        BootstrapInvocation(
            run_root=run_root,
            run_id=run_id,
            run_nonce="4" * 64,
            facts=BootstrapFacts.clean().replaced(inherited_fd_safe=False),
            bootstrap_report=_complete_bootstrap_inputs(),
            run_root_authority=authority,
        )
    )

    def finalizer_launcher(spec):
        modes.append(spec.mode)
        return tracer, normalizer

    session = None
    try:
        session = TraceLaunchRuntime(
            reviewed_trace_contract,
            launcher=finalizer_launcher,
            operations=operations,
            cleanup=state.owned_process_controller,
        ).launch(state)

        assert modes == ["FINALIZER_ONLY"]
        assert session.trace_state == "FINALIZER_ONLY"
    finally:
        if session is not None:
            session.guard.close()
        if state.signal_runtime._started:
            state.signal_runtime.close(restore_mask=True)


@pytest.mark.parametrize("lost_role", [None, "tracer", "normalizer"])
def test_full_readiness_deadline_monitors_attached_trace_roles(
    tmp_path, reviewed_trace_contract, process_identities, lost_role
):
    tracer, normalizer, coordinator = process_identities
    operations = FakeProcessOperations(
        {tracer.pid: tracer, normalizer.pid: normalizer},
        alive={
            identity.pid
            for name, identity in (("tracer", tracer), ("normalizer", normalizer))
            if name != lost_role
        },
    )
    run_root, run_id, authority = _production_run_root(
        tmp_path, f"readiness-{lost_role}"
    )
    runtime = BootstrapRuntime.production(
        reviewed_trace_contract,
        signal_forwarder=lambda _pgid, _name: None,
        signal_identity_validator=lambda observed: observed == coordinator,
    )
    state = runtime.run(
        BootstrapInvocation(
            run_root=run_root,
            run_id=run_id,
            run_nonce="2" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report=_complete_bootstrap_inputs(),
            run_root_authority=authority,
        )
    )
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()

    def launcher(_spec):
        return LiveTraceLaunchOutcome(
            tracer,
            normalizer,
            coordinator,
            request_read,
            response_write,
            request_write,
            response_read,
        )

    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="readiness|trace launch"):
            TraceLaunchRuntime(
                reviewed_trace_contract,
                launcher=launcher,
                operations=operations,
                cleanup=state.owned_process_controller,
                readiness_timeout_seconds=0.05,
            ).launch(state)
        assert time.monotonic() - started < 1.0
        assert operations.opened[:2] == [
            (tracer.pid, tracer.pid + 10_000),
            (normalizer.pid, normalizer.pid + 10_000),
        ]
        if lost_role is not None:
            surviving = normalizer if lost_role == "tracer" else tracer
            assert ("group", surviving.pgid, signal.SIGTERM) in operations.signals
    finally:
        for descriptor in (request_write, response_read):
            os.close(descriptor)
        if state.signal_runtime._started:
            state.signal_runtime.close(restore_mask=True)


def test_bootstrap_exception_closes_signal_collector_and_restores_mask(
    tmp_path, reviewed_trace_contract
):
    runtime_signals = SupervisorSignalRuntime(
        "3" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    runtime = BootstrapRuntime(reviewed_trace_contract, signal_runtime=runtime_signals)
    existing = tmp_path / "existing"
    existing.mkdir()
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    try:
        with pytest.raises(RuntimeError, match="zero-state"):
            runtime.run(
                BootstrapInvocation(
                    run_root=existing,
                    run_id="existing",
                    run_nonce="3" * 64,
                    facts=BootstrapFacts.clean(),
                    bootstrap_report={
                        "schema_version": "holoagent0.bootstrap-report.v1"
                    },
                )
            )
        assert runtime_signals._started is False
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    finally:
        if runtime_signals._started:
            runtime_signals.close(restore_mask=True)


def test_production_bootstrap_rejects_incomplete_caller_asserted_report(
    tmp_path, reviewed_trace_contract
):
    run_root, run_id, authority = _production_run_root(tmp_path, "incomplete-report")
    runtime = BootstrapRuntime.production(
        reviewed_trace_contract,
        signal_forwarder=lambda _pgid, _name: None,
        signal_identity_validator=lambda _identity: False,
    )
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    state = None
    try:
        with pytest.raises(RuntimeError, match="zero-state"):
            state = runtime.run(
                BootstrapInvocation(
                    run_root=run_root,
                    run_id=run_id,
                    run_nonce="0" * 64,
                    facts=BootstrapFacts.clean(),
                    bootstrap_report={
                        "schema_version": "holoagent0.bootstrap-report.v1"
                    },
                    run_root_authority=authority,
                )
            )
    finally:
        if state is not None and state.signal_runtime._started:
            state.signal_runtime.close(restore_mask=True)
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    assert authority.consumed is True
    assert not run_root.exists()


def test_trace_launch_runtime_collects_not_started_without_launch(
    tmp_path, reviewed_trace_contract
):
    bootstrap = BootstrapRuntime(reviewed_trace_contract).run(
        BootstrapInvocation(
            run_root=tmp_path / "not-started",
            run_id="run-not-started",
            run_nonce="b" * 64,
            facts=BootstrapFacts.clean().replaced(source_ok=False),
            bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
        )
    )

    def forbidden_launcher(_spec):
        pytest.fail("NOT_STARTED must not launch trace infrastructure")

    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=forbidden_launcher,
    ).launch(bootstrap)

    assert session.trace_state == "NOT_STARTED"
    assert session.tracer_identity is None
    assert session.normalizer_identity is None
    assert session.monitor(lambda: True, timeout_seconds=0.1) is None


def test_trace_launch_from_bootstrap_uses_retained_dynamic_owned_supplier(
    tmp_path, reviewed_trace_contract, process_identities
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations({item.pid: item for item in process_identities})
    controller = OwnedProcessController(operations)
    bootstrap = BootstrapRuntime(
        reviewed_trace_contract, owned_process_controller=controller
    ).run(
        BootstrapInvocation(
            run_root=tmp_path / "dynamic-tracees",
            run_id="dynamic-tracees",
            run_nonce="8" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
        )
    )
    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=lambda _spec: (tracer, normalizer),
        operations=operations,
        cleanup=controller,
    ).launch(bootstrap)

    assert session.owned_tracees() == ()
    lease = controller.acquire(tracee)
    assert session.owned_tracees() == (lease,)
    operations.alive.clear()
    operations.groups.clear()
    proof = session.finalize_terminal()
    session.accept_terminal_proof(proof, bundle="dynamic-bundle")


def test_active_terminal_proof_is_signal_free_and_closes_every_retained_pidfd(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations({item.pid: item for item in process_identities})
    controller = OwnedProcessController(operations)
    lease = controller.acquire(tracee)
    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=lambda _spec: (tracer, normalizer),
        operations=operations,
        cleanup=controller,
    ).launch(TraceLaunchSpec("FULL", owned_tracees=lambda: (lease,)))

    with pytest.raises(RuntimeError, match="terminal absence"):
        session.finalize_terminal()
    assert operations.signals == []
    assert operations.closed == []

    operations.alive.clear()
    operations.groups.clear()
    proof = session.finalize_terminal()
    session.accept_terminal_proof(proof, bundle="terminal-bundle")

    assert operations.signals == []
    assert sorted(operations.reaped) == sorted([tracer.pid, normalizer.pid, tracee.pid])
    assert sorted(operations.closed) == sorted(
        [item.pid + 10_000 for item in process_identities]
    )


@pytest.fixture
def not_started_trace_session(tmp_path, reviewed_trace_contract):
    bootstrap = BootstrapRuntime(reviewed_trace_contract).run(
        BootstrapInvocation(
            run_root=tmp_path / "terminal-trace",
            run_id="terminal-trace",
            run_nonce="d" * 64,
            facts=BootstrapFacts.clean().replaced(source_ok=False),
            bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
        )
    )
    return TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=lambda _spec: pytest.fail("NOT_STARTED launched trace infrastructure"),
    ).launch(bootstrap)


def _accepted_terminal_proof(session, bundle="bundle"):
    proof = session.finalize_terminal()
    session.accept_terminal_proof(proof, bundle=bundle)
    return proof


def test_result_publication_rejects_proof_bound_to_other_bundle(
    tmp_path, not_started_trace_session
):
    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=AcceptingContract(),
        binder=StableBinder([]),
        bundle="expected-bundle",
        secret_sentinels={"never-persist"},
    )

    proof = _accepted_terminal_proof(not_started_trace_session, "other-bundle")
    with pytest.raises(RuntimeError, match="evidence bundle"):
        publisher.publish(
            {
                "schema_version": "holoagent0.result.v1",
                "offline_evidence": {"bundle": "expected-bundle"},
            },
            proof,
        )


def test_result_publication_rejects_trace_mode_mismatch(
    tmp_path, not_started_trace_session
):
    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=AcceptingContract(),
        binder=StableBinder([]),
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )

    proof = _accepted_terminal_proof(not_started_trace_session)
    with pytest.raises(RuntimeError, match="trace mode"):
        publisher.publish(
            {
                "schema_version": "holoagent0.result.v1",
                "offline_evidence": {
                    "bundle": "bundle",
                    "trace": {"trace_state": "FULL"},
                },
            },
            proof,
        )


class AcceptingContract:
    def __init__(self):
        self.values = []

    def require_valid_result(self, value):
        self.values.append(value)


class StableBinder:
    def __init__(self, events):
        self.events = events

    def revalidate(self, bundle):
        self.events.append(("revalidate", bundle))

    def freeze_for_publication(self, bundle):
        self.events.append(("freeze", bundle))
        return "freeze-token"

    def register_publication_temporary(self, bundle, freeze, path):
        self.events.append(("register-temporary", bundle, freeze, path.name))

    def revalidate_for_publication(self, bundle, freeze):
        self.events.append(("publication-revalidate", bundle, freeze))
        return {"bundle": bundle}


def test_authoritative_result_publication_revalidates_then_writes_once(
    tmp_path, not_started_trace_session
):
    events = []
    contract = AcceptingContract()
    binder = StableBinder(events)
    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=contract,
        binder=binder,
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )
    proof = _accepted_terminal_proof(not_started_trace_session)
    descriptor = publisher.publish(
        {
            "schema_version": "holoagent0.result.v1",
            "offline_evidence": {"bundle": "bundle"},
        },
        proof,
    )
    assert events == [
        ("freeze", "bundle"),
        (
            "register-temporary",
            "bundle",
            "freeze-token",
            events[1][3],
        ),
        ("publication-revalidate", "bundle", "freeze-token"),
    ]
    assert events[1][3].startswith(".result.json.tmp-")
    assert descriptor.relative_path == "result.json"
    assert (tmp_path / "result.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(RuntimeError, match="already published"):
        publisher.publish({"schema_version": "holoagent0.result.v1"}, proof)


def test_result_publication_rejects_unaccepted_terminal_proof_before_freeze(
    tmp_path, not_started_trace_session
):
    events = []
    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=AcceptingContract(),
        binder=StableBinder(events),
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )

    with pytest.raises(RuntimeError, match="terminal trace proof"):
        publisher.publish(
            {
                "schema_version": "holoagent0.result.v1",
                "offline_evidence": {"bundle": "bundle"},
            },
            not_started_trace_session.finalize_terminal(),
        )
    assert events == []
    assert not (tmp_path / "result.json").exists()


@pytest.mark.parametrize("sentinel", ["secret-value", 'sec"ret', "line\nbreak"])
def test_authoritative_result_publication_rejects_secret_before_validation(
    tmp_path, sentinel, not_started_trace_session
):
    events = []
    contract = AcceptingContract()
    binder = StableBinder(events)
    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=contract,
        binder=binder,
        bundle="bundle",
        secret_sentinels={sentinel},
    )
    with pytest.raises(RuntimeError, match="secret sentinel"):
        publisher.publish(
            {"schema_version": "holoagent0.result.v1", "leak": sentinel},
            _accepted_terminal_proof(not_started_trace_session),
        )
    assert contract.values == []
    assert events == []
    assert not (tmp_path / "result.json").exists()


def test_authoritative_publication_failure_writes_only_bounded_emergency(
    tmp_path, not_started_trace_session
):
    class FailedFreeze(StableBinder):
        def freeze_for_publication(self, bundle):
            raise RuntimeError("mutated")

    publisher = AuthoritativeResultPublisher(
        tmp_path / "result.json",
        contract=AcceptingContract(),
        binder=FailedFreeze([]),
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )
    with pytest.raises(RuntimeError, match="mutated"):
        publisher.publish(
            {
                "schema_version": "holoagent0.result.v1",
                "offline_evidence": {"bundle": "bundle"},
            },
            _accepted_terminal_proof(not_started_trace_session),
        )
    descriptor = publisher.publish_emergency(
        stage="result_publication", safety_gates=()
    )
    assert descriptor.relative_path == "emergency.txt"
    assert not (tmp_path / "result.json").exists()
    assert (tmp_path / "emergency.txt").read_text(encoding="ascii") == (
        "HOLOAGENT0_EMERGENCY_V1\n"
        "stage=result_publication\n"
        "exit_code=40\n"
        "safety_gates=\n"
        "readiness_claim=NONE\n"
    )


def test_ambiguous_result_install_allows_only_bound_sibling_emergency(
    tmp_path, monkeypatch, not_started_trace_session
):
    result_path = tmp_path / "result.json"
    value = {
        "schema_version": "holoagent0.result.v1",
        "offline_evidence": {"bundle": "bundle"},
    }

    def install_then_fail(path, result, **_kwargs):
        payload = canonical_json_bytes(result)
        path.write_bytes(payload)
        path.chmod(0o600)
        installed = path.stat()
        raise AtomicPublicationAmbiguity(
            "directory fsync failed",
            ArtifactDescriptor(
                relative_path="result.json",
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
                inode=installed.st_ino,
                device=installed.st_dev,
            ),
        )

    monkeypatch.setattr(
        "holoagent0_setup.supervisor.atomic_write_json_no_replace",
        install_then_fail,
    )
    publisher = AuthoritativeResultPublisher(
        result_path,
        contract=AcceptingContract(),
        binder=StableBinder([]),
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )

    with pytest.raises(RuntimeError, match="ambiguous"):
        publisher.publish(value, _accepted_terminal_proof(not_started_trace_session))
    assert publisher.result_install_ambiguous is True
    assert publisher.result_authority_claimed is False
    assert not result_path.exists()
    quarantine = list(tmp_path.glob(".result.json.ambiguous-*"))
    assert len(quarantine) == 1
    assert quarantine[0].read_bytes() == canonical_json_bytes(value)

    publisher.publish_emergency(stage="result_publication")

    assert not result_path.exists()
    assert publisher.result_authority_claimed is False
    assert (
        (tmp_path / "emergency.txt")
        .read_text(encoding="ascii")
        .endswith("readiness_claim=NONE\n")
    )


def test_ambiguous_result_quarantine_tampering_prevents_emergency(
    tmp_path, monkeypatch, not_started_trace_session
):
    result_path = tmp_path / "result.json"

    def install_then_fail(path, result, **_kwargs):
        payload = canonical_json_bytes(result)
        path.write_bytes(payload)
        path.chmod(0o600)
        installed = path.stat()
        proof = ArtifactDescriptor(
            "result.json",
            hashlib.sha256(payload).hexdigest(),
            len(payload),
            installed.st_ino,
            installed.st_dev,
        )
        raise AtomicPublicationAmbiguity("fsync failed", proof)

    monkeypatch.setattr(
        "holoagent0_setup.supervisor.atomic_write_json_no_replace",
        install_then_fail,
    )
    publisher = AuthoritativeResultPublisher(
        result_path,
        contract=AcceptingContract(),
        binder=StableBinder([]),
        bundle="bundle",
        secret_sentinels={"never-persist"},
    )
    with pytest.raises(RuntimeError, match="ambiguous"):
        publisher.publish(
            {
                "schema_version": "holoagent0.result.v1",
                "offline_evidence": {"bundle": "bundle"},
            },
            _accepted_terminal_proof(not_started_trace_session),
        )
    quarantine = next(tmp_path.glob(".result.json.ambiguous-*"))
    quarantine.write_text("tampered", encoding="utf-8")

    with pytest.raises(RuntimeError, match="ambiguity proof"):
        publisher.publish_emergency(stage="result_publication")
    assert not (tmp_path / "emergency.txt").exists()


def test_trace_policy_violation_sink_writes_exact_evidence_and_safety_fact():
    events = []
    sink = SupervisorViolationSink(FakeJournal(events))
    violation = PolicyViolation("UNEXPECTED_NETWORK_ATTEMPT", 17, 501, "connect")

    sink.persist(violation)

    assert events == [
        (
            "journal",
            "TRACE_VIOLATION_RECORD",
            {
                "reason": "UNEXPECTED_NETWORK_ATTEMPT",
                "record_index": 17,
                "pid": 501,
                "operation": "connect",
            },
        )
    ]
    assert sink.snapshot() == ("offline.network_policy",)


def test_supervisor_violation_sink_uses_its_own_sequence_without_trace_index():
    events = []
    sink = SupervisorViolationSink(FakeJournal(events))

    sink.persist_supervisor(
        reason="UNEXPECTED_NETWORK_ATTEMPT", pid=501, operation="socket"
    )
    sink.persist_supervisor(
        reason="PROHIBITED_FD_TRANSFER", pid=501, operation="sendmsg"
    )

    assert events == [
        (
            "journal",
            "SUPERVISOR_VIOLATION_RECORD",
            {
                "reason": "UNEXPECTED_NETWORK_ATTEMPT",
                "event_sequence": 0,
                "pid": 501,
                "operation": "socket",
            },
        ),
        (
            "journal",
            "SUPERVISOR_VIOLATION_RECORD",
            {
                "reason": "PROHIBITED_FD_TRANSFER",
                "event_sequence": 1,
                "pid": 501,
                "operation": "sendmsg",
            },
        ),
    ]
    assert all("record_index" not in event[2] for event in events)
    assert sink.snapshot() == ("offline.network_policy",)


class OrderedStage:
    def __init__(self, events, name, output):
        self.events = events
        self.name = name
        self.output = output

    def run(self, value):
        self.events.append((self.name, value))
        return self.output

    def launch(self, value):
        return self.run(value)

    def collect(self, value):
        return self.run(value)

    def evaluate_and_bind(self, session, ledger):
        self.events.append((self.name, session, ledger))
        return self.output


class RecordingPublisher:
    def __init__(self, events):
        self.events = events

    def publish(self, result, _proof):
        self.events.append(("publish", result))

    def publish_emergency(self, *, stage, safety_gates):
        self.events.append(("emergency", stage, safety_gates))


def test_execute_authoritative_preserves_authority_order_and_returns_final_exit(
    not_started_trace_session,
):
    events = []
    evaluation = AuthoritativeEvaluation(
        {"result": "bound", "process_exit_code": 30},
        _accepted_terminal_proof(not_started_trace_session),
    )
    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=OrderedStage(events, "finalizers", evaluation),
        result_publisher=RecordingPublisher(events),
    )
    assert supervisor.execute_authoritative("invocation") == 30
    assert events == [
        ("bootstrap", "invocation"),
        ("trace", "state"),
        ("ledger", "session"),
        ("finalizers", "session", "ledger-head"),
        ("publish", {"result": "bound", "process_exit_code": 30}),
    ]


def test_authoritative_pipeline_always_closes_bootstrap_signal_runtime(
    tmp_path, reviewed_trace_contract
):
    signal_runtime = SupervisorSignalRuntime(
        "1" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    bootstrap = BootstrapRuntime(reviewed_trace_contract, signal_runtime=signal_runtime)
    invocation = BootstrapInvocation(
        run_root=tmp_path / "signal-close",
        run_id="signal-close",
        run_nonce="1" * 64,
        facts=BootstrapFacts.clean().replaced(source_ok=False),
        bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
    )

    class Ledger:
        def collect(self, _session):
            return "ledger"

    class Finalizers:
        def evaluate_and_bind(self, session, _ledger):
            proof = session.finalize_terminal()
            session.accept_terminal_proof(proof, bundle="bundle")
            return AuthoritativeEvaluation({"process_exit_code": 40}, proof)

        recover = None

    publisher = RecordingPublisher([])
    supervisor = EvidenceSupervisor(
        bootstrap_engine=bootstrap,
        trace_runtime=TraceLaunchRuntime(
            reviewed_trace_contract,
            launcher=lambda _spec: pytest.fail("NOT_STARTED launched a trace"),
        ),
        ledger_broker=Ledger(),
        finalizers=Finalizers(),
        result_publisher=publisher,
    )
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    try:
        assert supervisor.execute_authoritative(invocation) == 40
        assert signal_runtime._started is False
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    finally:
        if signal_runtime._started:
            signal_runtime.close(restore_mask=True)


def test_signal_runtime_close_failure_selects_emergency_before_result_publication(
    tmp_path, reviewed_trace_contract, monkeypatch
):
    signal_runtime = SupervisorSignalRuntime(
        "2" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    bootstrap = BootstrapRuntime(reviewed_trace_contract, signal_runtime=signal_runtime)
    invocation = BootstrapInvocation(
        run_root=tmp_path / "signal-close-failure",
        run_id="signal-close-failure",
        run_nonce="2" * 64,
        facts=BootstrapFacts.clean().replaced(source_ok=False),
        bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
    )

    class Ledger:
        def collect(self, _session):
            return "ledger"

    class Finalizers:
        def evaluate_and_bind(self, session, _ledger):
            proof = session.finalize_terminal()
            session.accept_terminal_proof(proof, bundle="bundle")
            return AuthoritativeEvaluation({"process_exit_code": 0}, proof)

        recover = None

    events = []
    publisher = RecordingPublisher(events)
    original_close = signal_runtime.close
    attempts = 0

    def fail_once(*, restore_mask):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise supervisor_module.SupervisorError("injected close failure")
        return original_close(restore_mask=restore_mask)

    monkeypatch.setattr(signal_runtime, "close", fail_once)
    supervisor = EvidenceSupervisor(
        bootstrap_engine=bootstrap,
        trace_runtime=TraceLaunchRuntime(
            reviewed_trace_contract,
            launcher=lambda _spec: pytest.fail("NOT_STARTED launched a trace"),
        ),
        ledger_broker=Ledger(),
        finalizers=Finalizers(),
        result_publisher=publisher,
    )

    assert supervisor.execute_authoritative(invocation) == 40
    assert events == [("emergency", "signal_runtime_finalization", ())]
    assert attempts == 2
    assert signal_runtime._started is False


def test_signal_runtime_cleanup_failure_preserves_retryable_ownership():
    runtime = SupervisorSignalRuntime(
        "3" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    runtime.start()
    original_close = runtime._collector.close
    attempts = 0

    def fail_once(*, restore_mask=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise supervisor_module.SupervisorError("injected collector failure")
        return original_close(restore_mask=restore_mask)

    runtime._collector.close = fail_once
    try:
        with pytest.raises(SupervisorError, match="cleanup failed"):
            runtime.close(restore_mask=True)
        assert runtime._started is True
        assert runtime._closing is False

        runtime.close(restore_mask=True)
        assert runtime._started is False
        assert runtime._closing is False
        assert attempts == 2
        assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask
    finally:
        if runtime._started:
            original_close(restore_mask=True)
            runtime._started = False
            runtime._closing = False


def test_persistent_collector_error_reports_failure_after_restoring_mask():
    runtime = SupervisorSignalRuntime(
        "5" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    runtime.start()
    runtime._collector._error = RuntimeError("persistent collector callback failure")

    with pytest.raises(SupervisorError, match="collector failed"):
        runtime.close(restore_mask=True)

    assert runtime._started is False
    assert runtime._closing is False
    assert runtime._collector._thread is None
    assert runtime._collector._previous_mask is None
    assert runtime._collector._error is None
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == original_mask


def test_bootstrap_cleanup_failure_is_not_swallowed(
    tmp_path, reviewed_trace_contract, monkeypatch
):
    runtime = SupervisorSignalRuntime(
        "4" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda _identity: False,
    )
    bootstrap = BootstrapRuntime(
        reviewed_trace_contract,
        signal_runtime=runtime,
        require_complete_report=True,
    )
    original_close = runtime.close
    attempts = 0

    def fail_once(*, restore_mask=False):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise SupervisorError("injected close failure")
        return original_close(restore_mask=restore_mask)

    monkeypatch.setattr(runtime, "close", fail_once)
    invocation = BootstrapInvocation(
        run_root=tmp_path / "bootstrap-cleanup-failure",
        run_id="bootstrap-cleanup-failure",
        run_nonce="4" * 64,
        facts=BootstrapFacts.clean(),
        bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
    )
    try:
        with pytest.raises(SupervisorError, match="zero-state cleanup failed"):
            bootstrap.run(invocation)
        assert runtime._started is True
        assert attempts == 1
    finally:
        if runtime._started:
            original_close(restore_mask=True)


def test_execute_authoritative_monitors_trace_while_ledger_collection_blocks(
    not_started_trace_session,
):
    events = []
    collection_started = threading.Event()
    collection_release = threading.Event()

    class MonitoredSession:
        trace_state = "FULL"

        def monitor(self, completed, *, timeout_seconds):
            events.append(("monitor", timeout_seconds))
            assert collection_started.wait(1)
            assert completed() is False
            collection_release.set()
            deadline = time.monotonic() + 1
            while not completed() and time.monotonic() < deadline:
                time.sleep(0.001)
            assert completed() is True
            return None

    session = MonitoredSession()

    class BlockingLedger:
        def collect(self, observed_session):
            assert observed_session is session
            events.append(("ledger-start",))
            collection_started.set()
            assert collection_release.wait(1)
            events.append(("ledger-end",))
            return "ledger-head"

    evaluation = AuthoritativeEvaluation(
        {"result": "bound", "process_exit_code": 40},
        _accepted_terminal_proof(not_started_trace_session),
    )
    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", session),
        ledger_broker=BlockingLedger(),
        finalizers=OrderedStage(events, "finalizers", evaluation),
        result_publisher=RecordingPublisher(events),
        trace_monitor_timeout_seconds=1.0,
    )

    assert supervisor.execute_authoritative("invocation") == 40
    names = [event[0] for event in events]
    assert names.index("ledger-start") < names.index("monitor")
    assert names.index("monitor") < names.index("ledger-end")
    assert names.index("ledger-end") < names.index("finalizers")


def test_authoritative_pipeline_installs_supervisor_audit_then_seccomp(
    not_started_trace_session,
):
    events = []

    class Boundary:
        def install_audit(self):
            events.append(("audit",))

        def install_seccomp(self):
            events.append(("seccomp",))

    evaluation = AuthoritativeEvaluation(
        {"process_exit_code": 40},
        _accepted_terminal_proof(not_started_trace_session),
    )
    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger"),
        finalizers=OrderedStage(events, "finalizers", evaluation),
        result_publisher=RecordingPublisher(events),
        network_boundary=Boundary(),
    )

    assert supervisor.execute_authoritative("invocation") == 40
    assert [event[0] for event in events] == [
        "audit",
        "bootstrap",
        "trace",
        "seccomp",
        "ledger",
        "finalizers",
        "publish",
    ]


def test_supervisor_network_boundary_requires_both_audit_and_seccomp_success():
    events = []
    boundary = SupervisorNetworkBoundary(
        audit_installer=lambda: events.append("audit") or True,
        seccomp_installer=lambda: events.append("seccomp") or True,
    )
    boundary.install_audit()
    boundary.install_seccomp()
    assert events == ["audit", "seccomp"]

    with pytest.raises(RuntimeError, match="audit"):
        SupervisorNetworkBoundary(
            audit_installer=lambda: False,
            seccomp_installer=lambda: True,
        ).install_audit()
    with pytest.raises(RuntimeError, match="seccomp"):
        SupervisorNetworkBoundary(
            audit_installer=lambda: True,
            seccomp_installer=lambda: False,
        ).install_seccomp()


def test_production_supervisor_network_boundary_denies_internet_socket_construction(
    tmp_path,
):
    script = r"""
import socket
import json
from pathlib import Path
from holoagent0_setup.evidence import AppendOnlyJournal
from holoagent0_setup.supervisor import SupervisorNetworkBoundary,SupervisorViolationSink
root=Path(__import__('os').environ['RUN_ROOT']); root.mkdir()
journal=AppendOnlyJournal.create(root/'violations.ndjson',relative_to=root,allowed_kinds={'TRACE_VIOLATION_RECORD','SUPERVISOR_VIOLATION_RECORD'})
boundary=SupervisorNetworkBoundary.production(SupervisorViolationSink(journal))
boundary.install_audit(); boundary.install_seccomp()
left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM); left.close(); right.close()
try: socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
except (PermissionError,RuntimeError): pass
else: raise SystemExit(9)
journal.seal()
records=[json.loads(line) for line in (root/'violations.ndjson').read_text().splitlines()]
assert len(records) == 1
assert records[0]['kind'] == 'SUPERVISOR_VIOLATION_RECORD'
assert records[0]['payload'] == {
    'reason':'UNEXPECTED_NETWORK_ATTEMPT',
    'event_sequence':0,
    'pid':__import__('os').getpid(),
    'operation':'socket',
}
raise SystemExit(0)
"""
    completed = subprocess.run(
        ["/usr/bin/python3", "-c", script],
        env={
            "PYTHONPATH": str(PACKAGE_ROOT),
            "RUN_ROOT": str(tmp_path / "network-boundary"),
            "LC_ALL": "C",
            "TZ": "UTC",
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr.decode()


def test_mandatory_finalizers_order_trace_network_evidence_and_result(
    not_started_trace_session,
):
    events = []

    class Binder:
        def bind(self, requirements):
            events.append(("evidence", requirements))
            return "bundle"

    finalizers = MandatoryFinalizers(
        trace_finalizer=lambda session: (
            events.append(("trace", session)) or ("trace", session.finalize_terminal())
        ),
        network_finalizer=lambda session, trace: (
            events.append(("network", session, trace)) or "network"
        ),
        binder=Binder(),
        evidence_requirements=lambda session, ledger: (
            events.append(("requirements", session, ledger)) or "requirements"
        ),
        result_builder=lambda session, ledger, trace, network, bundle: {
            "session": "terminal-session",
            "ledger": ledger,
            "trace": trace,
            "network": network,
            "bundle": bundle,
            "process_exit_code": 40,
        },
        recovery=lambda **kwargs: pytest.fail(f"unexpected recovery: {kwargs}"),
    )

    evaluation = finalizers.evaluate_and_bind(not_started_trace_session, "ledger")

    assert evaluation.process_exit == 40
    assert events == [
        ("trace", not_started_trace_session),
        ("network", not_started_trace_session, "trace"),
        ("requirements", not_started_trace_session, "ledger"),
        ("evidence", "requirements"),
    ]


def test_production_evidence_factory_forces_exact_publication_paths(
    tmp_path, reviewed_trace_contract, process_identities
):
    context = EvidenceContext(
        trace=TraceRuntimeEvidence(
            "NOT_STARTED", None, None, None, None, None, None, "EARLIER_BLOCKING_GATE"
        ),
        ledger_contract=reviewed_trace_contract,
        expected_run_id="run-production",
        expected_ledger_nonce="e" * 64,
        marker_token="marker-token",
        expected_host_observer_identity=process_identities[0],
        publication_paths=(tmp_path / "wrong.json",),
    )

    binder = PublicationEvidenceFactory(
        tmp_path,
        context=context,
        result_path=tmp_path / "result.json",
        emergency_path=tmp_path / "emergency.txt",
        secret_sentinels={"never-persist"},
    ).create()

    assert type(binder) is EvidenceBinder
    assert binder._context.publication_paths == (
        tmp_path / "result.json",
        tmp_path / "emergency.txt",
    )
    binder.close()

    with pytest.raises(RuntimeError, match="publication paths"):
        PublicationEvidenceFactory(
            tmp_path,
            context=context,
            result_path=tmp_path / "other.json",
            emergency_path=tmp_path / "emergency.txt",
        )


def test_production_host_observer_identity_uses_live_coordinator(
    process_identities,
):
    tracer, normalizer, coordinator = process_identities
    supervisor_identity = ProcessIdentity(
        999,
        999,
        999,
        "/usr/bin/python3.10",
        "f" * 64,
    )
    launch = LiveTraceLaunchOutcome(
        tracer,
        normalizer,
        coordinator,
        101,
        102,
        103,
        104,
    )

    assert (
        supervisor_module._production_host_observer_identity(
            trace_state="FULL",
            live_launch=launch,
            supervisor_identity=supervisor_identity,
        )
        == coordinator
    )
    assert (
        supervisor_module._production_host_observer_identity(
            trace_state="NOT_STARTED",
            live_launch=None,
            supervisor_identity=supervisor_identity,
        )
        == supervisor_identity
    )


@pytest.mark.parametrize("signal_name", ["HUP", "INT", "TERM"])
def test_authoritative_signal_comes_from_terminal_live_handoff(
    signal_name, process_identities
):
    _tracer, _normalizer, coordinator = process_identities
    runtime = SupervisorSignalRuntime(
        "9" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda observed: observed == coordinator,
    )
    runtime._started = True
    runtime._arbiter.bootstrap_clean()
    assert runtime._arbiter.try_commit() is True
    runtime._handoff = supervisor_module.SupervisorSignalHandoff(
        "9" * 64,
        forwarder=lambda _pgid, _name: None,
        identity_validator=lambda observed: observed == coordinator,
    )
    request = _signal_ready(coordinator, nonce="9" * 64)
    runtime._handoff._accepted_request = request
    runtime._handoff._accepted_response = SignalReadyAccepted(
        request.run_nonce,
        request.identity,
        request.sequence,
        request.canonical_sha256,
    )
    runtime._handoff._acceptance_count = 1
    runtime._handoff._last_accepted_identity = coordinator
    runtime._handoff._state = "READY"
    runtime._handoff.collect_signal(signal_name)

    assert supervisor_module._terminal_signal_from_runtime(runtime) == signal_name


def test_mandatory_finalizer_recovery_synthesizes_then_runs_all_finalizers(
    not_started_trace_session,
):
    events = []

    class Binder:
        def bind(self, requirements):
            events.append(("evidence", requirements))
            return "bundle"

    def recover(**kwargs):
        events.append(("recover", kwargs["stage"], str(kwargs["error"])))
        return not_started_trace_session, "recovered-ledger"

    finalizers = MandatoryFinalizers(
        trace_finalizer=lambda session: (
            events.append(("trace", session)) or ("trace", session.finalize_terminal())
        ),
        network_finalizer=lambda session, trace: (
            events.append(("network", session, trace)) or "network"
        ),
        binder=Binder(),
        evidence_requirements=lambda session, ledger: "requirements",
        result_builder=lambda *_args: {"process_exit_code": 30},
        recovery=recover,
    )

    evaluation = finalizers.recover(
        stage="trace_launch",
        error=RuntimeError("failed"),
        state="state",
        session=None,
        ledger=None,
    )

    assert evaluation.process_exit == 30
    assert events[:3] == [
        ("recover", "trace_launch", "failed"),
        ("trace", not_started_trace_session),
        ("network", not_started_trace_session, "trace"),
    ]


def test_execute_authoritative_uses_emergency_record_when_finalizers_fail():
    events = []

    class FailedFinalizers:
        def evaluate_and_bind(self, session, ledger):
            events.append(("finalizers", session, ledger))
            raise RuntimeError("finalizer failed")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=FailedFinalizers(),
        result_publisher=RecordingPublisher(events),
    )
    assert supervisor.execute_authoritative("invocation") == 40
    assert not any(event[0] == "publish" for event in events)
    assert events[-1] == ("emergency", "finalizer_evaluation", ())


def test_finalizer_failure_preserves_durable_network_safety_fact():
    events = []

    class Journal:
        def append(self, kind, payload):
            events.append(("journal", kind, payload))

    facts = SupervisorSafetyFacts(Journal())
    facts.persist(PolicyViolation("UNEXPECTED_NETWORK_ATTEMPT", 2, 501, "connect"))

    class FailedFinalizers:
        def evaluate_and_bind(self, session, ledger):
            raise RuntimeError("finalizer failed")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=FailedFinalizers(),
        result_publisher=RecordingPublisher(events),
        safety_facts=facts,
    )
    assert supervisor.execute_authoritative("invocation") == 30
    assert events[-1] == (
        "emergency",
        "finalizer_evaluation",
        ("offline.network_policy",),
    )


def test_production_replay_and_supervisor_audit_share_one_safety_latch():
    supervisor = EvidenceSupervisor.production(
        ContractSet(PACKAGE_ROOT),
        trace_launcher=lambda _specification: None,
        signal_forwarder=lambda _pgid, _signal_name: None,
        signal_identity_validator=lambda _identity: True,
        secret_sentinels={"never-persist"},
    )

    assert supervisor._finalizers._violation_sink is supervisor._safety_facts


def test_production_tracked_file_manifest_matches_git_index_exactly():
    completed = subprocess.run(
        ["git", "ls-files", "-s", "-z"],
        cwd=REPOSITORY_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    observed = []
    for encoded in completed.stdout.split(b"\0"):
        if not encoded:
            continue
        metadata, path = encoded.decode("utf-8", errors="strict").split("\t", 1)
        mode, oid, stage = metadata.split(" ")
        assert stage == "0"
        if path == supervisor_module._TRACKED_FILE_MANIFEST_REPO_PATH:
            continue
        if path == supervisor_module._TRACKED_MANIFEST_AUTHORITY_REPO_PATH:
            oid = supervisor_module._TRACKED_MANIFEST_SELF_OID
        observed.append(f"{mode} {oid}\t{path}")

    manifest = (PACKAGE_ROOT / supervisor_module._TRACKED_FILE_MANIFEST).read_text(
        encoding="utf-8"
    )
    assert manifest.splitlines() == observed


@pytest.mark.parametrize("mutation", ["remove", "add", "reorder", "replace"])
def test_production_tracked_manifest_pin_rejects_inventory_mutation(tmp_path, mutation):
    repository = tmp_path / "repository"
    contract_root = repository / "scripts/holoagent0_setup"
    manifest_path = contract_root / supervisor_module._TRACKED_FILE_MANIFEST
    authority = repository / supervisor_module._TRACKED_MANIFEST_AUTHORITY_REPO_PATH
    first = repository / "README.md"
    second = repository / "LICENSE"
    manifest_path.parent.mkdir(parents=True)
    authority.parent.mkdir(parents=True, exist_ok=True)
    authority.write_text("authority", encoding="utf-8")
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    rows = [
        f"100644 {supervisor_module._git_blob_sha1(second.read_bytes())}\tLICENSE",
        f"100644 {supervisor_module._git_blob_sha1(first.read_bytes())}\tREADME.md",
        ("100644 SELF\t" + supervisor_module._TRACKED_MANIFEST_AUTHORITY_REPO_PATH),
    ]
    rows.sort(key=lambda row: row.split("\t", 1)[1])
    original = ("\n".join(rows) + "\n").encode()
    expected_sha256 = hashlib.sha256(original).hexdigest()
    if mutation == "remove":
        rows.pop(0)
    elif mutation == "add":
        rows.append("100644 " + "a" * 40 + "\textra.txt")
    elif mutation == "reorder":
        rows[0], rows[1] = rows[1], rows[0]
    else:
        rows[0] = rows[0].replace("LICENSE", "COPYING")
    manifest_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    with pytest.raises(SupervisorError, match="digest"):
        supervisor_module._verify_git_tracked_manifest(
            manifest_path,
            repository,
            expected_sha256=expected_sha256,
            secret_sentinels=frozenset({"never-persist"}),
        )


def test_production_tracked_file_inventory_covers_code_outside_contract_root():
    tracked = supervisor_module._load_git_tracked_manifest(
        PACKAGE_ROOT, secret_sentinels=frozenset({"never-persist"})
    )

    assert REPOSITORY_ROOT / "README.md" in tracked.regular_paths
    assert (
        REPOSITORY_ROOT
        / "agentic_robot/agentOS/sandbox_test/long_horizon_text_runner.py"
        in tracked.regular_paths
    )
    assert all(
        ".git" not in path.relative_to(REPOSITORY_ROOT).parts
        for path in tracked.regular_paths
    )
    assert tracked.symlinks == ()


def test_supervisor_audit_violation_fails_network_gate_even_without_trace(
    reviewed_trace_contract,
):
    sink = SupervisorViolationSink(FakeJournal([]))
    sink.persist_supervisor(
        reason="UNEXPECTED_NETWORK_ATTEMPT", pid=501, operation="socket"
    )
    finalizers = supervisor_module.ProductionMandatoryFinalizers(
        reviewed_trace_contract,
        secret_sentinels={"never-persist"},
        violation_sink=sink,
    )
    session = type("Session", (), {"trace_state": "NOT_STARTED"})()

    trace_gate, network_gate = finalizers._finalizer_gates(session, (None, None), None)

    assert trace_gate["status"] == "FAIL"
    assert network_gate["id"] == "offline.network_policy"
    assert network_gate["status"] == "FAIL"
    assert network_gate["reason"] == "UNEXPECTED_NETWORK_ATTEMPT"


def test_late_trace_defect_cannot_override_latched_network_safety():
    events = []

    class Journal:
        def append(self, kind, payload):
            events.append(("journal", kind, payload))

    sink = SupervisorSafetyFacts(Journal())

    class FailedTraceFinalizers:
        def evaluate_and_bind(self, session, ledger):
            sink.persist(
                PolicyViolation("UNEXPECTED_NETWORK_ATTEMPT", 3, 501, "connect")
            )
            raise RuntimeError("later trace evidence defect")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=FailedTraceFinalizers(),
        result_publisher=RecordingPublisher(events),
        safety_facts=sink,
    )

    assert supervisor.execute_authoritative("invocation") == 30
    assert events[-1] == (
        "emergency",
        "finalizer_evaluation",
        ("offline.network_policy",),
    )


def test_finalizer_defect_preserves_failed_gate_from_sealed_ledger():
    events = []
    gates = [{"id": gate_id, "status": "NOT_RUN"} for gate_id in OFFLINE_GATE_ORDER]
    gates[23] = {
        "id": "safety.workstation_postflight",
        "status": "FAIL",
        "reason": "POSTFLIGHT_FAILED",
    }

    class Head:
        sealed = True

    class Ledger:
        head = Head()
        current = {"gates": gates}

    class State:
        ledger = Ledger()

    class FailedFinalizers:
        def evaluate_and_bind(self, session, ledger):
            raise RuntimeError("evidence binding failed after ledger seal")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", State()),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=FailedFinalizers(),
        result_publisher=RecordingPublisher(events),
    )

    assert supervisor.execute_authoritative("invocation") == 30
    assert events[-1] == (
        "emergency",
        "finalizer_evaluation",
        ("safety.workstation_postflight",),
    )


def test_durable_safety_facts_reject_incomplete_policy_violation():
    facts = SupervisorSafetyFacts(FakeJournal([]))
    with pytest.raises(RuntimeError, match="violation evidence"):
        facts.persist(
            PolicyViolation("UNEXPECTED_NETWORK_ATTEMPT", None, 501, "connect")
        )


@pytest.mark.parametrize(
    "reason,operation",
    [
        ("UNEXPECTED_NETWORK_ATTEMPT", "connect"),
        ("PROHIBITED_FD_TRANSFER", "sendmsg"),
        ("PROHIBITED_IO_URING", "io_uring_setup"),
    ],
)
def test_durable_safety_facts_accept_exact_trace_policy_records(reason, operation):
    events = []
    facts = SupervisorSafetyFacts(FakeJournal(events))
    facts.persist(PolicyViolation(reason, 7, 503, operation))
    assert facts.snapshot() == ("offline.network_policy",)
    assert events == [
        (
            "journal",
            "TRACE_VIOLATION_RECORD",
            {
                "reason": reason,
                "record_index": 7,
                "pid": 503,
                "operation": operation,
            },
        )
    ]


def test_recovery_exception_still_publishes_bounded_emergency():
    events = []

    class FailedLaunch:
        def launch(self, state):
            raise RuntimeError("spawn failed")

    class FailedRecovery:
        def recover(self, **_kwargs):
            raise RuntimeError("recovery failed")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=FailedLaunch(),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=FailedRecovery(),
        result_publisher=RecordingPublisher(events),
    )
    assert supervisor.execute_authoritative("invocation") == 40
    assert events[-1] == ("emergency", "finalizer_recovery", ())


def test_publication_defect_preserves_known_safety_precedence(
    not_started_trace_session,
):
    events = []
    safety_gate = {
        "id": "safety.workstation_postflight",
        "status": "FAIL",
    }
    evaluation = AuthoritativeEvaluation(
        {
            "label": "FAIL_SAFETY",
            "process_exit_code": 30,
            "gates": [safety_gate],
        },
        _accepted_terminal_proof(not_started_trace_session),
    )

    class FailedPublisher(RecordingPublisher):
        def publish(self, result, proof):
            raise RuntimeError("rename failed")

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=OrderedStage(events, "trace", "session"),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=OrderedStage(events, "finalizers", evaluation),
        result_publisher=FailedPublisher(events),
    )
    assert supervisor.execute_authoritative("invocation") == 30
    assert events[-1] == (
        "emergency",
        "result_publication",
        ("safety.workstation_postflight",),
    )


def test_authoritative_evaluation_derives_exit_from_published_result(
    not_started_trace_session,
):
    source = {"label": "FAIL_SAFETY", "process_exit_code": 30}
    evaluation = AuthoritativeEvaluation(
        source, _accepted_terminal_proof(not_started_trace_session)
    )
    source["process_exit_code"] = 40
    assert evaluation.process_exit == 30
    exposed = evaluation.result
    exposed["process_exit_code"] = 20
    assert evaluation.result["process_exit_code"] == 30
    with pytest.raises(RuntimeError, match="process exit"):
        AuthoritativeEvaluation(
            {"label": "FAIL_SAFETY"}, evaluation.trace_terminal_proof
        )


def test_launch_failure_enters_finalizer_recovery_and_still_publishes(
    not_started_trace_session,
):
    events = []

    class FailedLaunch:
        def launch(self, state):
            events.append(("trace", state))
            raise RuntimeError("spawn failed")

    class RecoveringFinalizers:
        def recover(self, *, stage, error, state, session, ledger):
            events.append(("recover", stage, str(error), state, session, ledger))
            return AuthoritativeEvaluation(
                {"label": "FAIL_HARNESS", "process_exit_code": 40},
                _accepted_terminal_proof(not_started_trace_session),
            )

    supervisor = EvidenceSupervisor(
        bootstrap_engine=OrderedStage(events, "bootstrap", "state"),
        trace_runtime=FailedLaunch(),
        ledger_broker=OrderedStage(events, "ledger", "ledger-head"),
        finalizers=RecoveringFinalizers(),
        result_publisher=RecordingPublisher(events),
    )
    assert supervisor.execute_authoritative("invocation") == 40
    assert events == [
        ("bootstrap", "invocation"),
        ("trace", "state"),
        ("recover", "trace_launch", "spawn failed", "state", None, None),
        ("publish", {"label": "FAIL_HARNESS", "process_exit_code": 40}),
    ]


def test_trace_loss_reports_cleanup_failure_instead_of_hiding_it(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations(
        {item.pid: item for item in process_identities},
        alive={normalizer.pid, tracee.pid},
    )

    class FailedCleanup:
        def cleanup(self, identities):
            assert identities == (tracee,)
            return False

    guard = TraceRuntimeGuard(operations, cleanup=FailedCleanup())
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)
    loss = guard.require_live_or_cleanup((tracee,))
    assert loss.reason == "TRACER_EXITED"
    assert loss.cleanup_complete is False


def test_wait_terminal_timeout_cleans_every_active_owned_lease(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations(
        {item.pid: item for item in process_identities},
        alive={tracer.pid, normalizer.pid, tracee.pid},
    )
    controller = OwnedProcessController(operations, wait_seconds=0)
    lease = controller.acquire(tracee)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)

    with pytest.raises(RuntimeError, match="terminal deadline"):
        guard.wait_terminal(
            timeout_seconds=0,
            owned_tracees=controller.active_leases,
        )

    assert lease not in controller.active_leases()
    assert ("group", tracee.pgid, signal.SIGTERM) in operations.signals


def test_terminal_proof_reuses_prior_infrastructure_reap(
    process_identities, reviewed_trace_contract
):
    tracer, normalizer, _tracee = process_identities

    class SingleReapOperations(FakeProcessOperations):
        def reap(self, identity, pidfd, timeout_seconds):
            if identity.pid in self.reaped:
                return False
            return super().reap(identity, pidfd, timeout_seconds)

    operations = SingleReapOperations({tracer.pid: tracer, normalizer.pid: normalizer})
    controller = OwnedProcessController(operations, wait_seconds=0)
    guard = TraceRuntimeGuard(operations, cleanup=controller)
    guard.attach(tracer, normalizer, contract=reviewed_trace_contract)

    assert guard._cleanup_monitor_timeout(()) is True
    assert guard.verify_terminal_absence(()) is True
    assert operations.reaped == [tracer.pid, normalizer.pid]
    assert operations.closed == [tracer.pid + 10_000, normalizer.pid + 10_000]


def test_committed_trace_loss_recovery_cleans_leases_and_seals_postflight_failure(
    tmp_path, reviewed_trace_contract, process_identities, monkeypatch
):
    tracer, normalizer, tracee = process_identities
    operations = FakeProcessOperations(
        {item.pid: item for item in process_identities},
        alive={tracee.pid},
    )
    controller = OwnedProcessController(operations, wait_seconds=0)
    state = BootstrapRuntime(
        reviewed_trace_contract,
        owned_process_controller=controller,
    ).run(
        BootstrapInvocation(
            run_root=tmp_path / "committed-recovery",
            run_id="committed-recovery",
            run_nonce="c" * 64,
            facts=BootstrapFacts.clean(),
            bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
        )
    )
    lease = controller.acquire(tracee)
    session = TraceLaunchRuntime(
        reviewed_trace_contract,
        launcher=lambda _spec: (tracer, normalizer),
        operations=operations,
        cleanup=controller,
    ).launch(state)
    finalizers = ProductionMandatoryFinalizers(
        reviewed_trace_contract,
        secret_sentinels={"never-persist"},
        violation_sink=SupervisorViolationSink(FakeJournal([])),
    )
    finalizers.prepare_invocation(
        BootstrapInvocation(
            run_root=state.run_root,
            run_id=state.ledger.run_id,
            run_nonce=state.ledger.run_nonce,
            facts=BootstrapFacts.clean(),
            bootstrap_report={"schema_version": "holoagent0.bootstrap-report.v1"},
        )
    )
    finalizers.bind_state(state)
    observed = {}

    def evaluate(session_value, accepted):
        observed["session"] = session_value
        observed["accepted"] = accepted
        return "recovered-evaluation"

    monkeypatch.setattr(finalizers, "evaluate_and_bind", evaluate)

    assert (
        finalizers.recover(
            stage="ledger_collect",
            error=RuntimeError("tracer exited"),
            state=state,
            session=session,
            ledger=None,
        )
        == "recovered-evaluation"
    )
    assert controller.active_leases() == ()
    assert lease._consumed is True
    assert state.ledger.head.sealed is True
    assert state.ledger.current["gates"][23]["status"] == "FAIL"
    assert state.ledger.current["gates"][23]["reason"] == "POSTFLIGHT_FAILED"
    assert observed == {"session": session, "accepted": state.ledger.current}


def test_production_factory_current_pending_policy_fails_closed_without_launch(
    tmp_path,
):
    script = r"""
import json
import sys
from pathlib import Path

from holoagent0_setup.contract import ContractSet
from holoagent0_setup.invocation import RunRootAuthority
from holoagent0_setup.supervisor import (
    BootstrapFacts,
    BootstrapInvocation,
    EvidenceSupervisor,
)

package_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
output_root.mkdir(mode=0o700)
run_id = "workstation-offline-20260818T010203Z-" + "a" * 32
run_root = output_root / run_id
launcher_calls = []
supervisor = EvidenceSupervisor.production(
    ContractSet(package_root),
    trace_launcher=lambda specification: launcher_calls.append(specification),
    signal_forwarder=lambda pgid, signal_name: None,
    signal_identity_validator=lambda identity: True,
    secret_sentinels={"task8-" + "production-sentinel"},
)
invocation = BootstrapInvocation(
    run_root=run_root,
    run_id=run_id,
    run_nonce="a" * 64,
    facts=BootstrapFacts.clean(),
    bootstrap_report={
        "schema_version": "holoagent0.bootstrap-report.v1",
        "toolchain": {
            "expected": {"strace_version": "6.6"},
            "observed": {"strace_version": "6.6"},
        },
        "initial_fd_manifest": [],
        "final_fd_manifest": [],
        "sanitation_actions": [],
        "rebinding_actions": [],
        "live_fixture_passed": False,
    },
    run_root_authority=RunRootAuthority.open(output_root, run_id),
)
exit_code = supervisor.execute_authoritative(invocation)
result = json.loads((run_root / "result.json").read_text(encoding="utf-8"))
print(json.dumps({
    "exit_code": exit_code,
    "launcher_calls": len(launcher_calls),
    "label": result["label"],
    "status": result["status"],
    "primary": result["primary_blocking_gate"],
    "result_exit": result["process_exit_code"],
    "emergency_exists": (run_root / "emergency.txt").exists(),
}))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PACKAGE_ROOT)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(PACKAGE_ROOT),
            str(tmp_path / "run"),
        ],
        cwd=PACKAGE_ROOT.parents[1],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed == {
        "exit_code": 40,
        "launcher_calls": 0,
        "label": "FAIL_HARNESS",
        "status": "FAIL",
        "primary": "offline.trace_integrity",
        "result_exit": 40,
        "emergency_exists": False,
    }


def test_production_pending_policy_preserves_unsafe_inherited_fd_precedence(tmp_path):
    script = r"""
import json
import sys
from pathlib import Path

from holoagent0_setup.contract import ContractSet
from holoagent0_setup.invocation import RunRootAuthority
from holoagent0_setup.supervisor import (
    BootstrapFacts,
    BootstrapInvocation,
    EvidenceSupervisor,
)

package_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
output_root.mkdir(mode=0o700)
run_id = "workstation-offline-20260818T010203Z-" + "b" * 32
run_root = output_root / run_id
launcher_calls = []
supervisor = EvidenceSupervisor.production(
    ContractSet(package_root),
    trace_launcher=lambda specification: launcher_calls.append(specification),
    signal_forwarder=lambda pgid, signal_name: None,
    signal_identity_validator=lambda identity: True,
    secret_sentinels={"task8-" + "production-sentinel"},
)
invocation = BootstrapInvocation(
    run_root=run_root,
    run_id=run_id,
    run_nonce="b" * 64,
    facts=BootstrapFacts.clean().replaced(inherited_fd_safe=False),
    bootstrap_report={
        "schema_version": "holoagent0.bootstrap-report.v1",
        "toolchain": {
            "expected": {"strace_version": "6.6"},
            "observed": {"strace_version": "6.6"},
        },
        "initial_fd_manifest": [
            {"fd": 9, "target": "socket:[12345]", "cloexec": False},
        ],
        "final_fd_manifest": [],
        "sanitation_actions": ["closed fd 9"],
        "rebinding_actions": [],
        "live_fixture_passed": False,
    },
    run_root_authority=RunRootAuthority.open(output_root, run_id),
)
exit_code = supervisor.execute_authoritative(invocation)
result = json.loads((run_root / "result.json").read_text(encoding="utf-8"))
gates = {gate["id"]: gate for gate in result["gates"]}
print(json.dumps({
    "exit_code": exit_code,
    "launcher_calls": len(launcher_calls),
    "label": result["label"],
    "primary": result["primary_blocking_gate"],
    "preflight": gates["safety.workstation_preflight"],
    "postflight": gates["safety.workstation_postflight"],
    "trace": gates["offline.trace_integrity"],
}))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PACKAGE_ROOT)
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(PACKAGE_ROOT),
            str(tmp_path / "unsafe-fd-run"),
        ],
        cwd=PACKAGE_ROOT.parents[1],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["exit_code"] == 30
    assert observed["launcher_calls"] == 0
    assert observed["label"] == "FAIL_SAFETY"
    assert observed["primary"] == "safety.workstation_postflight"
    assert observed["preflight"]["status"] == "NOT_RUN"
    assert observed["postflight"]["status"] == "FAIL"
    assert observed["postflight"]["reason"] == "POSTFLIGHT_FAILED"
    assert observed["trace"]["status"] == "FAIL"
