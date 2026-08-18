"""External authority primitives for the workstation-offline trace boundary.

The supervisor owns bootstrap linearization, process identity and pidfd
liveness, mandatory finalizer synthesis, and the sole result publication path.
The public CLI/factory is intentionally deferred to Task 13. Task 8 still owns
the concrete signal collector, pinned trace-liveness checks, process-group
cleanup, evidence freeze, and emergency-publication authorities used there.
"""

from __future__ import annotations

import copy
import ctypes
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import select
import signal
import socket
import stat
import subprocess
import sys
from threading import active_count, Event, get_ident, main_thread, RLock, Thread
import time
from typing import Callable, Mapping, Sequence

from .atomic_io import (
    ArtifactDescriptor,
    AtomicPublicationAmbiguity,
    atomic_write_bytes_no_replace,
    atomic_write_json_no_replace,
    canonical_json_bytes,
)
from .broker import BrokerProtocolError, MessageType, read_frame, write_frame
from .constants import OFFLINE_GATE_ORDER
from .contract import ContractSet
from .evidence import (
    AppendOnlyJournal,
    ArtifactRequirement,
    EvidenceBinder,
    EvidenceBundle,
    EvidenceContext,
    REQUIRED_OFFLINE_ARTIFACTS,
    TracePolicyReplayEvidence,
    TraceRuntimeEvidence,
    write_host_observer_artifact,
)
from .cyclone_policy import CONFIG_ROLES, CONFIG_SET_SHA256, EXPECTED_CONFIG_SHA256
from .ledger import LedgerCandidate, LedgerChainError, LedgerHead, LedgerStore
from .invocation import RunRootAuthority
from .process_identity import ProcessIdentity
from .process_identity import read_process_identity
from .result_policy import ResultPolicy
from .signal_handoff import (
    CoordinatorSnapshot,
    HandoffEvent,
    SignalHandoffError,
    SupervisorSignalHandoff,
    SupervisorSnapshot,
    TraceUnblockEvidence,
)
from .trace_policy import PolicyDecision, PolicyViolation, TracePolicy


_SIGNAL_ORDER = ("HUP", "INT", "TERM")
_SIGNALS = frozenset(_SIGNAL_ORDER)
_SIGNAL_EXIT = {"HUP": 129, "INT": 130, "TERM": 143}
_MOTION_EXECUTABLES = (
    "g1_pubvel_node",
    "g1_pubmove_node",
    "g1_pubcmd_node",
)
_ROLE_OVERRIDES = {
    "semantic.natural_language_parser": "diagnostic",
    "chatbot.credentials": "qualification",
    "chatbot.audio_hardware": "qualification",
    "safety.workstation_postflight": "finalizer",
    "offline.trace_integrity": "finalizer",
    "offline.network_policy": "finalizer",
    "offline.evidence_binding": "finalizer",
}
_FINALIZER_ORDER = tuple(OFFLINE_GATE_ORDER[-4:])
_NETWORK_REASONS = frozenset(
    {
        "UNEXPECTED_NETWORK_ATTEMPT",
        "PROHIBITED_FD_TRANSFER",
        "PROHIBITED_FD_ACQUISITION",
        "PROHIBITED_IO_URING",
        "UNTRACED_CHILD_ATTEMPT",
        "TRACE_BYPASS_ATTEMPT",
    }
)
_VIOLATION_RECORD_KINDS = frozenset(
    {"TRACE_VIOLATION_RECORD", "SUPERVISOR_VIOLATION_RECORD"}
)
_TRACKED_FILE_MANIFEST = "manifests/git-tracked-files-v1.txt"
_TRACKED_FILE_MANIFEST_REPO_PATH = (
    "scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt"
)
_TRACKED_MANIFEST_AUTHORITY_REPO_PATH = (
    "scripts/holoagent0_setup/holoagent0_setup/supervisor.py"
)
_TRACKED_MANIFEST_SELF_OID = "SELF"
_TRACKED_FILE_MANIFEST_SHA256 = (
    "c4c8cb17f13a14d6073ea1f72ce0aa8a1d1fc63df86b247a77b1ccf598ec9f99"
)
_SAFETY_FACT_REASONS = {
    "safety.workstation_preflight": frozenset(
        {
            "UNEXPECTED_CONTROL_PROCESS",
            "PROCESS_ALLOWLIST_MISMATCH",
            "GRAPH_ALLOWLIST_MISMATCH",
            "UNEXPECTED_DDS_PARTICIPANT",
            "UNEXPECTED_ROS_ENDPOINT",
            "INHERITED_SOCKET_FD",
        }
    ),
    "safety.workstation_postflight": frozenset(
        {
            "PROCESS_ALLOWLIST_MISMATCH",
            "GRAPH_ALLOWLIST_MISMATCH",
            "OWNERSHIP_MISMATCH",
            "CLEANUP_INCOMPLETE",
            "UNEXPECTED_DDS_PARTICIPANT",
            "UNEXPECTED_ROS_ENDPOINT",
            "POSTFLIGHT_FAILED",
            "LEDGER_CHAIN_INVALID",
        }
    ),
    "offline.network_policy": _NETWORK_REASONS,
}
_TRACE_REASONS = frozenset(
    {
        "TRACE_INCOMPLETE",
        "TRACE_DECODE_FAILED",
        "TRACE_NOT_STARTED",
        "TRACE_BOOTSTRAP_FAILED",
        "TRACER_EXITED",
    }
)


class SupervisorError(RuntimeError):
    """The external supervisor could not preserve its authority contract."""


class _SignalCollectorReportedError(SupervisorError):
    """The collector failed, but its thread and signal-mask ownership are closed."""


@dataclass(frozen=True)
class LaunchSnapshot:
    state: str
    first_signal: str | None
    coordinator_launch_committed: bool


class LaunchArbiter:
    """Linearize the first pre-commit signal against launch commitment."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._state = "BOOTSTRAPPING"
        self._first_signal: str | None = None

    def collect_signal(self, signal_name: str) -> None:
        if type(signal_name) is not str or signal_name not in _SIGNALS:
            raise SupervisorError("signal must be exactly HUP, INT, or TERM")
        with self._lock:
            if self._first_signal is None:
                self._first_signal = signal_name
            if self._state == "BOOTSTRAP_CLEAN":
                self._state = "PRE_COORDINATOR_INTERRUPTED"

    def bootstrap_clean(self) -> None:
        with self._lock:
            if self._state != "BOOTSTRAPPING":
                raise SupervisorError("bootstrap clean transition is out of order")
            self._state = (
                "PRE_COORDINATOR_INTERRUPTED"
                if self._first_signal is not None
                else "BOOTSTRAP_CLEAN"
            )

    def try_commit(self) -> bool:
        with self._lock:
            if self._state == "BOOTSTRAP_CLEAN":
                self._state = "COORDINATOR_LAUNCH_COMMITTED"
                return True
            if self._state in {
                "PRE_COORDINATOR_INTERRUPTED",
                "COORDINATOR_LAUNCH_COMMITTED",
            }:
                return False
            raise SupervisorError("coordinator commit preceded clean bootstrap")

    def snapshot(self) -> LaunchSnapshot:
        with self._lock:
            return LaunchSnapshot(
                state=self._state,
                first_signal=self._first_signal,
                coordinator_launch_committed=(
                    self._state == "COORDINATOR_LAUNCH_COMMITTED"
                ),
            )


class SynchronousSignalCollector:
    """Block and synchronously collect the reviewed termination signals."""

    _NUMBERS = {
        signal.SIGHUP: "HUP",
        signal.SIGINT: "INT",
        signal.SIGTERM: "TERM",
    }

    def __init__(self, callback: Callable[[str], object]) -> None:
        if not callable(callback):
            raise SupervisorError("signal collector callback is invalid")
        self._callback = callback
        self._stop = Event()
        self._observed = Event()
        self._first_signal: str | None = None
        self._thread: Thread | None = None
        self._previous_mask: set[signal.Signals] | None = None
        self._error: BaseException | None = None

    def start(self) -> None:
        if self._thread is not None:
            raise SupervisorError("signal collector is already started")
        try:
            native_tasks = {
                entry.name
                for entry in Path("/proc/self/task").iterdir()
                if entry.name.isdecimal()
            }
        except OSError as error:
            raise SupervisorError("native thread inventory is unavailable") from error
        if (
            main_thread().ident != get_ident()
            or active_count() != 1
            or native_tasks != {str(os.getpid())}
        ):
            raise SupervisorError("signal collector must start before any other thread")
        reviewed = set(self._NUMBERS)
        try:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
        except (OSError, RuntimeError, ValueError) as error:
            raise SupervisorError("reviewed signals could not be blocked") from error
        self._previous_mask = set(previous)
        thread = Thread(target=self._collect, name="holoagent0-sigwait", daemon=False)
        self._thread = thread
        thread.start()

    def wait_first(self, timeout_seconds: float) -> str | None:
        _require_cleanup_timeout(timeout_seconds)
        self._observed.wait(float(timeout_seconds))
        if self._error is not None:
            raise SupervisorError("signal collector failed") from self._error
        return self._first_signal

    def close(self, *, restore_mask: bool = False) -> None:
        if type(restore_mask) is not bool:
            raise SupervisorError("signal collector restore choice is invalid")
        thread = self._thread
        previous = self._previous_mask
        if thread is None or previous is None:
            raise SupervisorError("signal collector is not started")
        self._stop.set()
        thread.join(timeout=1.0)
        if thread.is_alive():
            raise SupervisorError("signal collector did not stop")
        collector_error = self._error
        if restore_mask:
            reviewed = set(self._NUMBERS)
            try:
                while signal.sigtimedwait(reviewed, 0) is not None:
                    pass
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            except (OSError, RuntimeError, ValueError) as error:
                raise SupervisorError(
                    "reviewed signal mask could not be restored"
                ) from error
        self._thread = None
        self._previous_mask = None
        self._error = None
        if collector_error is not None:
            raise _SignalCollectorReportedError(
                "signal collector failed after cleanup completed"
            ) from collector_error

    def _collect(self) -> None:
        reviewed = set(self._NUMBERS)
        try:
            while not self._stop.is_set():
                observed = signal.sigtimedwait(reviewed, 0.05)
                if observed is None:
                    continue
                name = self._NUMBERS.get(observed.si_signo)
                if name is None:
                    raise SupervisorError("signal collector observed an unknown signal")
                if self._first_signal is None:
                    self._first_signal = name
                    self._observed.set()
                self._callback(name)
        except BaseException as error:  # transported to the supervisor thread
            self._error = error
            self._observed.set()


class SupervisorSignalRuntime:
    """Atomically bridge signal collection, launch commit, and Task 4 handoff."""

    def __init__(
        self,
        run_nonce: str,
        *,
        forwarder: Callable[[int, str], object],
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
    ) -> None:
        if type(run_nonce) is not str or not run_nonce:
            raise SupervisorError("signal runtime nonce is invalid")
        if not callable(forwarder):
            raise SupervisorError("signal runtime forwarder is invalid")
        if identity_validator is not None and not callable(identity_validator):
            raise SupervisorError("signal identity validator is invalid")
        self._run_nonce = run_nonce
        self._forwarder = forwarder
        self._identity_validator = identity_validator
        self._arbiter = LaunchArbiter()
        self._handoff: SupervisorSignalHandoff | None = None
        self._collector = SynchronousSignalCollector(self._collect_signal)
        self._lock = RLock()
        self._started = False
        self._closing = False

    def start(self) -> None:
        with self._lock:
            if self._started:
                raise SupervisorError("signal runtime is already started")
            self._collector.start()
            self._started = True

    def commit_and_spawn(
        self, spawn: Callable[[], ProcessIdentity]
    ) -> ProcessIdentity | None:
        if not callable(spawn):
            raise SupervisorError("coordinator spawn action is invalid")
        with self._lock:
            if not self._started or self._handoff is not None:
                raise SupervisorError("signal runtime launch is out of order")
            self._arbiter.bootstrap_clean()
            if not self._arbiter.try_commit():
                self._handoff = SupervisorSignalHandoff.not_applicable(self._run_nonce)
                return None
            identity = spawn()
            if type(identity) is not ProcessIdentity:
                raise SupervisorError("spawned coordinator identity is invalid")
            self._handoff = SupervisorSignalHandoff(
                self._run_nonce,
                forwarder=self._forwarder,
                identity_validator=self._identity_validator,
            )
            return identity

    def accept_readiness(
        self,
        request_read_fd: int,
        response_write_fd: int,
        *,
        deadline: int | float | None = None,
    ) -> None:
        with self._lock:
            handoff = self._handoff
        if handoff is None:
            raise SupervisorError("coordinator launch was not committed")
        try:
            handoff.receive_and_accept(
                request_read_fd, response_write_fd, deadline=deadline
            )
        except (SignalHandoffError, OSError) as error:
            raise SupervisorError("signal readiness acceptance failed") from error
        finally:
            for descriptor in (request_read_fd, response_write_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def snapshot(self) -> tuple[LaunchSnapshot, SupervisorSnapshot | None]:
        with self._lock:
            return (
                self._arbiter.snapshot(),
                None if self._handoff is None else self._handoff.snapshot(),
            )

    def wait_first_signal(self, timeout_seconds: float) -> str | None:
        with self._lock:
            if not self._started:
                raise SupervisorError("signal runtime is not started")
        return self._collector.wait_first(timeout_seconds)

    def finalize_trace_readiness(
        self,
        coordinator_evidence: CoordinatorSnapshot,
        trace_evidence: TraceUnblockEvidence,
        *,
        trusted_verifier: Callable[[TraceUnblockEvidence], bool],
    ) -> None:
        """Permit terminal READY only after Task 4's trusted trace proof."""

        with self._lock:
            handoff = self._handoff
        if handoff is None:
            raise SupervisorError("coordinator signal handoff is unavailable")
        try:
            handoff.finalize_ready(
                coordinator_evidence, trace_evidence, trusted_verifier
            )
        except SignalHandoffError as error:
            raise SupervisorError(
                "terminal signal trace verification failed"
            ) from error

    def close(self, *, restore_mask: bool = False) -> None:
        with self._lock:
            if not self._started:
                raise SupervisorError("signal runtime is not started")
            if self._closing:
                raise SupervisorError("signal runtime cleanup is already in progress")
            self._closing = True
        try:
            self._collector.close(restore_mask=restore_mask)
        except _SignalCollectorReportedError as error:
            with self._lock:
                self._started = False
                self._closing = False
            raise SupervisorError("signal runtime collector failed") from error
        except Exception as error:
            with self._lock:
                self._closing = False
            # Ownership remains live so authoritative cleanup can retry.
            raise SupervisorError("signal runtime cleanup failed") from error
        with self._lock:
            self._started = False
            self._closing = False

    def _collect_signal(self, signal_name: str) -> None:
        with self._lock:
            self._arbiter.collect_signal(signal_name)
            if (
                self._handoff is not None
                and self._arbiter.snapshot().coordinator_launch_committed
            ):
                self._handoff.collect_signal(signal_name)


def _bootstrap_handoff_report(
    runtime: SupervisorSignalRuntime,
    coordinator: CoordinatorSnapshot,
    trace: TraceUnblockEvidence,
) -> dict[str, object]:
    launch, snapshot = runtime.snapshot()
    handoff = runtime._handoff
    if (
        snapshot is None
        or snapshot.terminal_state != "READY"
        or handoff is None
        or handoff._accepted_request is None
        or handoff._accepted_response is None
    ):
        raise SupervisorError("signal handoff report is not terminal READY")
    request = handoff._accepted_request
    acceptance = handoff._accepted_response
    states = ["AWAITING_READY", "AWAITING_ACCEPTANCE"]
    if any(event.state == "PENDING_FORWARD" for event in snapshot.events):
        states.append("PENDING_FORWARD")
    states.append("READY")
    return {
        "event_sequence": [
            {"sequence": index, "state": state} for index, state in enumerate(states)
        ],
        "terminal_state": "READY",
        "signal_ready_identity": request.identity.as_dict(),
        "signal_ready_sequence": request.sequence,
        "signal_ready_sha256": request.canonical_sha256,
        "signal_ready_accepted_sequence": acceptance.request_sequence,
        "signal_ready_accepted_sha256": hashlib.sha256(
            canonical_json_bytes(acceptance.as_message())
        ).hexdigest(),
        "inherited_mask": list(request.blocked_signals),
        "unblocked_mask": ["HUP", "INT", "TERM"],
        "pending_signal": snapshot.pending_signal,
        "acceptance_count": snapshot.acceptance_count,
        "forward_target_pgid": snapshot.forward_target_pgid,
        "forward_count": snapshot.forward_count,
        "unblock_trace_record_index": trace.unblock_trace_record_index,
        "first_functional_trace_record_index": (
            trace.first_functional_trace_record_index
        ),
    }


def _failed_bootstrap_handoff_report(
    runtime: SupervisorSignalRuntime,
) -> dict[str, object]:
    launch, snapshot = runtime.snapshot()
    handoff = runtime._handoff
    if (
        not launch.coordinator_launch_committed
        or snapshot is None
        or snapshot.terminal_state != "FAILED"
        or handoff is None
    ):
        raise SupervisorError("signal handoff report is not terminal FAILED")
    request = handoff._accepted_request
    acceptance = handoff._accepted_response
    accepted = request is not None and acceptance is not None
    states = ["AWAITING_READY"]
    if accepted:
        states.append("AWAITING_ACCEPTANCE")
    if any(event.state == "PENDING_FORWARD" for event in snapshot.events):
        states.append("PENDING_FORWARD")
    states.append("FAILED")
    return {
        "event_sequence": [
            {"sequence": index, "state": state} for index, state in enumerate(states)
        ],
        "terminal_state": "FAILED",
        "signal_ready_identity": None
        if request is None
        else request.identity.as_dict(),
        "signal_ready_sequence": None if request is None else request.sequence,
        "signal_ready_sha256": None if request is None else request.canonical_sha256,
        "signal_ready_accepted_sequence": (
            None if acceptance is None else acceptance.request_sequence
        ),
        "signal_ready_accepted_sha256": (
            None
            if acceptance is None
            else hashlib.sha256(
                canonical_json_bytes(acceptance.as_message())
            ).hexdigest()
        ),
        "inherited_mask": ["HUP", "INT", "TERM"],
        "unblocked_mask": [],
        "pending_signal": snapshot.pending_signal,
        "acceptance_count": snapshot.acceptance_count,
        "forward_target_pgid": snapshot.forward_target_pgid,
        "forward_count": snapshot.forward_count,
        "unblock_trace_record_index": None,
        "first_functional_trace_record_index": None,
    }


def _not_applicable_handoff_report(first_signal: str | None) -> dict[str, object]:
    return {
        "event_sequence": [],
        "terminal_state": "NOT_APPLICABLE",
        "signal_ready_identity": None,
        "signal_ready_sequence": None,
        "signal_ready_sha256": None,
        "signal_ready_accepted_sequence": None,
        "signal_ready_accepted_sha256": None,
        "inherited_mask": ["HUP", "INT", "TERM"],
        "unblocked_mask": [],
        "pending_signal": first_signal,
        "acceptance_count": 0,
        "forward_target_pgid": None,
        "forward_count": 0,
        "unblock_trace_record_index": None,
        "first_functional_trace_record_index": None,
    }


def _record_failed_signal_readiness(state: "BootstrapState") -> None:
    runtime = state.signal_runtime
    if runtime is None or state.bootstrap_report is None:
        raise SupervisorError("failed readiness has no bootstrap authority")
    handoff = runtime._handoff
    if handoff is None:
        raise SupervisorError("failed readiness has no handoff state")
    _launch, snapshot = runtime.snapshot()
    if snapshot is not None and snapshot.terminal_state is None:
        try:
            handoff.fail("canonical trace readiness verification failed")
        except SignalHandoffError:
            pass
    launch, _snapshot = runtime.snapshot()
    report = copy.deepcopy(dict(state.bootstrap_report))
    report.update(
        terminal_launch_state=launch.state,
        coordinator_launch_committed=True,
        first_signal=launch.first_signal,
        handoff=_failed_bootstrap_handoff_report(runtime),
    )
    path = state.run_root / "bootstrap_report.json"
    if not path.exists():
        atomic_write_json_no_replace(
            path,
            report,
            mode=0o400,
            relative_to=state.run_root,
        )


def _successful_trace_syscall(record: Mapping[str, object]) -> bool:
    result = record.get("result")
    return (
        type(result) is dict
        and type(result.get("value")) is int
        and result["value"] >= 0
    )


def _reviewed_signal_action(
    record: Mapping[str, object], *, expected_signal: str
) -> bool:
    transition = record.get("transition")
    if (
        type(transition) is not dict
        or set(transition)
        != {"operation", "signal", "action", "old_action", "sigset_size"}
        or transition.get("operation") != "rt_sigaction"
        or transition.get("signal") != expected_signal
        or transition.get("sigset_size") != 8
    ):
        return False
    action = transition.get("action")
    old_action = transition.get("old_action")
    if (
        type(action) is not dict
        or set(action) != {"handler", "mask", "flags", "restorer"}
        or action.get("handler") != "CUSTOM"
        or action.get("mask") != []
        or action.get("flags") != ["SA_RESTORER", "SA_ONSTACK"]
        or action.get("restorer") is not True
        or type(old_action) is not dict
        or set(old_action) != {"handler", "mask", "flags", "restorer"}
    ):
        return False
    expected_default = {
        "handler": "DEFAULT",
        "mask": [],
        "flags": [],
        "restorer": False,
    }
    if old_action != expected_default and old_action != action:
        return False
    return _successful_trace_syscall(record) and record["result"] == {"value": 0}


def _reviewed_mask_observation(
    record: Mapping[str, object], *, expected_old_mask: Sequence[str]
) -> bool:
    return bool(
        record.get("kind") == "syscall"
        and record.get("syscall") == "rt_sigprocmask"
        and record.get("transition")
        == {
            "operation": "rt_sigprocmask",
            "how": "SIG_BLOCK",
            "mask": [],
            "old_mask": list(expected_old_mask),
            "sigset_size": 8,
        }
        and record.get("result") == {"value": 0}
    )


def _readiness_fd(value: object) -> int | None:
    if type(value) is not dict or type(value.get("fd")) is not int:
        return None
    fd = value["fd"]
    return fd if fd >= 0 else None


class _ReadinessBrokerProtocol:
    """Bind readiness I/O to the two native-launcher pipe target roles."""

    _BROKER_SYSCALLS = frozenset(
        {
            "close",
            "fcntl",
            "fstat",
            "newfstatat",
            "pselect6",
            "read",
            "readlink",
            "write",
        }
    )

    def __init__(self, request_write_fd: int, acceptance_read_fd: int) -> None:
        if (
            type(request_write_fd) is not int
            or request_write_fd < 3
            or type(acceptance_read_fd) is not int
            or acceptance_read_fd < 3
            or request_write_fd == acceptance_read_fd
        ):
            raise SupervisorError("canonical signal broker binding is invalid")
        self._request_fd = request_write_fd
        self._acceptance_fd = acceptance_read_fd
        self._request_alias: int | None = None
        self._request_alias_binding: dict[str, object] | None = None
        self._acceptance_alias: int | None = None
        self._acceptance_alias_binding: dict[str, object] | None = None
        self._request_bytes = 0
        self._acceptance_bytes = 0
        self._acceptance_reads = 0
        self._acceptance_eof = False
        self._state = "REQUEST_DUP"

    @property
    def complete(self) -> bool:
        return self._state == "COMPLETE"

    @property
    def acceptance_provenance(self) -> dict[str, object] | None:
        binding = self._acceptance_alias_binding
        provenance = binding.get("provenance") if type(binding) is dict else None
        return copy.deepcopy(provenance) if type(provenance) is dict else None

    def consume(self, record: Mapping[str, object]) -> bool | None:
        syscall = record.get("syscall")
        transition = record.get("transition")
        operation = transition.get("operation") if type(transition) is dict else None
        is_duplicate = operation == "fcntl_dup"
        if syscall not in self._BROKER_SYSCALLS and not is_duplicate:
            return None
        if record.get("kind") != "syscall" or not _successful_trace_syscall(record):
            return False
        if is_duplicate:
            return self._consume_duplicate(record)
        if syscall in {"fstat", "newfstatat"}:
            return self._consume_stat(record)
        if syscall == "readlink":
            return self._consume_readlink(record)
        if syscall == "fcntl":
            return self._consume_getfl(record)
        if syscall == "pselect6":
            return self._consume_pselect(record)
        if syscall == "write":
            return self._consume_write(record)
        if syscall == "read":
            return self._consume_read(record)
        if syscall == "close":
            return self._consume_close(record)
        return False

    def _consume_duplicate(self, record: Mapping[str, object]) -> bool:
        transition = record.get("transition")
        if type(transition) is not dict:
            return False
        operation = transition.get("operation")
        required_keys = {
            "operation",
            "source_fd",
            "created_fd",
            "cloexec",
            "minimum_fd",
        }
        if set(transition) != required_keys:
            return False
        source = _readiness_fd(transition.get("source_fd"))
        created = _readiness_fd(transition.get("created_fd"))
        source_binding = transition.get("source_fd")
        created_binding = transition.get("created_fd")
        result = record.get("result")
        if (
            operation != "fcntl_dup"
            or transition.get("cloexec") is not True
            or transition.get("minimum_fd") != 0
            or created is None
            or type(source_binding) is not dict
            or type(created_binding) is not dict
            or source_binding.get("provenance") != created_binding.get("provenance")
            or result != {"value": created, "fd": created_binding}
            or created in {self._request_fd, self._acceptance_fd}
        ):
            return False
        if self._state == "REQUEST_DUP" and source == self._request_fd:
            self._request_alias = created
            self._request_alias_binding = copy.deepcopy(transition["created_fd"])
            self._state = "REQUEST_STAT"
            return True
        if self._state == "ACCEPTANCE_DUP" and source == self._acceptance_fd:
            if created == self._request_alias:
                return False
            self._acceptance_alias = created
            self._acceptance_alias_binding = copy.deepcopy(transition["created_fd"])
            self._state = "ACCEPTANCE_STAT"
            return True
        return False

    def _consume_stat(self, record: Mapping[str, object]) -> bool:
        validation = record.get("validation")
        if (
            type(validation) is not dict
            or set(validation) != {"operation", "fd", "file_type", "mode", "inode"}
            or validation.get("operation") != "fd_stat"
            or validation.get("file_type") != "fifo"
            or validation.get("mode") != 0o600
            or record.get("result") != {"value": 0}
        ):
            return False
        if self._state == "REQUEST_STAT":
            binding = self._request_alias_binding
            next_state = "REQUEST_READLINK"
        elif self._state == "ACCEPTANCE_STAT":
            binding = self._acceptance_alias_binding
            next_state = "ACCEPTANCE_READLINK"
        else:
            return False
        provenance = binding.get("provenance") if type(binding) is dict else None
        if (
            binding is None
            or validation.get("fd") != binding
            or type(provenance) is not dict
            or validation.get("inode") != provenance.get("inode")
        ):
            return False
        self._state = next_state
        return True

    def _consume_readlink(self, record: Mapping[str, object]) -> bool:
        validation = record.get("validation")
        if (
            type(validation) is not dict
            or set(validation) != {"operation", "fd", "target_provenance", "count"}
            or validation.get("operation") != "fd_readlink"
            or validation.get("count") != 4096
        ):
            return False
        if self._state == "REQUEST_READLINK":
            binding = self._request_alias_binding
            next_state = "REQUEST_GETFL"
        elif self._state == "ACCEPTANCE_READLINK":
            binding = self._acceptance_alias_binding
            next_state = "ACCEPTANCE_GETFL"
        else:
            return False
        if (
            type(binding) is not dict
            or validation.get("fd") != binding.get("fd")
            or validation.get("target_provenance") != binding.get("provenance")
        ):
            return False
        provenance = validation["target_provenance"]
        inode = provenance.get("inode") if type(provenance) is dict else None
        if type(inode) is not int or record.get("result") != {
            "value": len(f"pipe:[{inode}]")
        }:
            return False
        self._state = next_state
        return True

    def _consume_getfl(self, record: Mapping[str, object]) -> bool:
        transition = record.get("transition")
        if (
            type(transition) is not dict
            or set(transition) != {"operation", "source_fd", "status_flags"}
            or transition.get("operation") != "fcntl_getfl"
            or type(transition.get("status_flags")) is not list
        ):
            return False
        source_binding = transition.get("source_fd")
        source = _readiness_fd(source_binding)
        if (
            self._state == "REQUEST_GETFL"
            and source == self._request_alias
            and source_binding == self._request_alias_binding
            and transition.get("status_flags") == ["O_WRONLY"]
            and record.get("result") == {"value": 1, "flags": ["O_WRONLY"]}
        ):
            self._state = "REQUEST_WAIT"
            return True
        if (
            self._state == "ACCEPTANCE_GETFL"
            and source == self._acceptance_alias
            and source_binding == self._acceptance_alias_binding
            and transition.get("status_flags") == ["O_RDONLY"]
            and record.get("result") == {"value": 0, "flags": ["O_RDONLY"]}
        ):
            self._state = "ACCEPTANCE_WAIT"
            return True
        return False

    @staticmethod
    def _valid_timespec(value: object) -> bool:
        return bool(
            type(value) is dict
            and set(value) == {"seconds", "nanoseconds"}
            and type(value.get("seconds")) is int
            and value["seconds"] >= 0
            and type(value.get("nanoseconds")) is int
            and 0 <= value["nanoseconds"] < 1_000_000_000
        )

    @classmethod
    def _timespec_nanoseconds(cls, value: object) -> int | None:
        if not cls._valid_timespec(value):
            return None
        return value["seconds"] * 1_000_000_000 + value["nanoseconds"]

    def _consume_pselect(self, record: Mapping[str, object]) -> bool:
        wait = record.get("wait")
        result = record.get("result")
        if (
            type(wait) is not dict
            or set(wait) != {"nfds", "direction", "fd", "timeout"}
            or type(result) is not dict
            or set(result) != {"value", "ready", "timeout_left"}
            or result.get("value") != 1
            or type(result.get("ready")) is not dict
            or set(result["ready"]) != {"direction", "fd"}
        ):
            return False
        if self._state == "REQUEST_WAIT":
            direction = "write"
            alias = self._request_alias
            binding = self._request_alias_binding
            next_state = "REQUEST_WRITE"
        elif self._state == "ACCEPTANCE_WAIT":
            direction = "read"
            alias = self._acceptance_alias
            binding = self._acceptance_alias_binding
            next_state = "ACCEPTANCE_READ"
        else:
            return False
        timeout_ns = self._timespec_nanoseconds(wait.get("timeout"))
        timeout_left_ns = self._timespec_nanoseconds(result.get("timeout_left"))
        if (
            alias is None
            or binding is None
            or wait.get("nfds") != alias + 1
            or wait.get("direction") != direction
            or wait.get("fd") != binding
            or result["ready"].get("direction") != direction
            or result["ready"].get("fd") != {"fd": alias}
            or timeout_ns is None
            or timeout_left_ns is None
            or timeout_left_ns > timeout_ns
        ):
            return False
        self._state = next_state
        return True

    @staticmethod
    def _io_fields(record: Mapping[str, object]) -> tuple[int, int, int] | None:
        fds = record.get("fds")
        lengths = record.get("lengths")
        result = record.get("result")
        if (
            type(fds) is not list
            or len(fds) != 1
            or (fd := _readiness_fd(fds[0])) is None
            or type(lengths) is not dict
            or set(lengths) != {"count"}
            or type(lengths.get("count")) is not int
            or not 1 <= lengths["count"] <= 4100
            or type(result) is not dict
            or set(result) != {"value"}
            or type(result.get("value")) is not int
            or not 0 <= result["value"] <= lengths["count"]
        ):
            return None
        return fd, lengths["count"], result["value"]

    def _consume_write(self, record: Mapping[str, object]) -> bool:
        fields = self._io_fields(record)
        if fields is None:
            return False
        fd, _count, written = fields
        if self._state != "REQUEST_WRITE" or fd != self._request_alias or written <= 0:
            return False
        self._request_bytes += written
        if self._request_bytes > 4100:
            return False
        self._state = "REQUEST_WAIT"
        return True

    def _consume_read(self, record: Mapping[str, object]) -> bool:
        fields = self._io_fields(record)
        if fields is None:
            return False
        fd, _count, read = fields
        if (
            self._state != "ACCEPTANCE_READ"
            or fd != self._acceptance_alias
            or self._acceptance_eof
        ):
            return False
        if read == 0:
            if self._acceptance_reads < 2:
                return False
            self._acceptance_eof = True
            self._state = "ACCEPTANCE_EOF"
            return True
        self._acceptance_reads += 1
        self._acceptance_bytes += read
        if self._acceptance_bytes > 4100:
            return False
        self._state = "ACCEPTANCE_WAIT"
        return True

    def _consume_close(self, record: Mapping[str, object]) -> bool:
        transition = record.get("transition")
        if (
            type(transition) is not dict
            or set(transition) != {"operation", "closed_fd"}
            or transition.get("operation") != "close"
            or record.get("result") != {"value": 0}
        ):
            return False
        closed = _readiness_fd(transition.get("closed_fd"))
        if (
            self._state == "REQUEST_WAIT"
            and closed == self._request_alias
            and self._request_bytes > 0
        ):
            self._state = "REQUEST_BASE_CLOSE"
            return True
        if self._state == "REQUEST_BASE_CLOSE" and closed == self._request_fd:
            self._state = "ACCEPTANCE_DUP"
            return True
        if (
            self._state == "ACCEPTANCE_EOF"
            and closed == self._acceptance_alias
            and self._acceptance_eof
        ):
            self._state = "COMPLETE"
            return True
        return False


def _handoff_boundary(
    record: Mapping[str, object],
    *,
    pid: int,
    phase: str,
    token: str,
) -> bool:
    return bool(
        record.get("kind") == "syscall"
        and record.get("pid") == pid
        and record.get("syscall") == "prctl"
        and record.get("handoff_marker") == {"phase": phase, "token": token}
        and record.get("result") == {"value": 0}
    )


def _handoff_name_observation(
    record: Mapping[str, object], *, pid: int, phase: str, token: str
) -> bool:
    return bool(
        record.get("kind") == "syscall"
        and record.get("pid") == pid
        and record.get("syscall") == "prctl"
        and record.get("handoff_name_observation") == {"phase": phase, "token": token}
        and record.get("result") == {"value": 0}
    )


def _reviewed_getpid(record: Mapping[str, object], *, pid: int) -> bool:
    return bool(
        record.get("kind") == "syscall"
        and record.get("pid") == pid
        and record.get("syscall") == "getpid"
        and record.get("result") == {"value": pid}
    )


def _reviewed_base_close(
    record: Mapping[str, object],
    *,
    fd: int,
    provenance: Mapping[str, object],
) -> bool:
    transition = record.get("transition")
    closed_fd = transition.get("closed_fd") if type(transition) is dict else None
    return bool(
        record.get("kind") == "syscall"
        and record.get("syscall") == "close"
        and transition is not None
        and set(transition) == {"operation", "closed_fd"}
        and transition.get("operation") == "close"
        and type(closed_fd) is dict
        and closed_fd.get("fd") == fd
        and closed_fd.get("provenance") == provenance
        and record.get("result") == {"value": 0}
    )


@dataclass(frozen=True)
class _SealedTraceArtifact:
    payload: bytes
    sha256: str
    size: int
    inode: int
    device: int


def _open_sealed_trace(
    path: Path, *, allow_empty: bool = False
) -> _SealedTraceArtifact:
    """Open a terminal trace once and bind stable bytes to its filesystem identity."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o400
            or before.st_size > 64 * 1024 * 1024
            or (before.st_size == 0 and not allow_empty)
        ):
            raise SupervisorError("canonical signal trace is not sealed")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise SupervisorError("canonical signal trace is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise SupervisorError("canonical signal trace exceeded its bound identity")
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mode):
            raise SupervisorError("canonical signal trace changed during retention")
        payload = b"".join(chunks)
        return _SealedTraceArtifact(
            payload=payload,
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            inode=before.st_ino,
            device=before.st_dev,
        )
    except OSError as error:
        raise SupervisorError("canonical signal trace is unavailable") from error
    finally:
        if fd >= 0:
            os.close(fd)


def _canonical_trace_handoff_evidence(
    source: Path | _SealedTraceArtifact,
    *,
    request: object,
    request_write_fd: int,
    acceptance_read_fd: int,
) -> tuple[CoordinatorSnapshot, TraceUnblockEvidence]:
    """Derive readiness solely from the closed canonical supervisor trace."""

    if (
        type(getattr(request, "identity", None)) is not ProcessIdentity
        or type(getattr(request, "sequence", None)) is not int
        or type(getattr(request, "run_nonce", None)) is not str
    ):
        raise SupervisorError("canonical signal trace binding is invalid")
    if isinstance(source, Path):
        if source.name != "trace.ndjson" or not source.is_absolute():
            raise SupervisorError("canonical signal trace binding is invalid")
        retained = _open_sealed_trace(source)
    elif type(source) is _SealedTraceArtifact:
        retained = source
    else:
        raise SupervisorError("canonical signal trace binding is invalid")
    payload = retained.payload
    records: list[dict[str, object]] = []
    for expected_index, encoded in enumerate(payload.splitlines(keepends=True)):
        if not encoded.endswith(b"\n"):
            raise SupervisorError("canonical signal trace is unterminated")
        try:
            record = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SupervisorError("canonical signal trace is undecodable") from error
        if (
            type(record) is not dict
            or record.get("record_index") != expected_index
            or canonical_json_bytes(record) + b"\n" != encoded
        ):
            raise SupervisorError("canonical signal trace is noncanonical")
        records.append(record)
    identity = request.identity
    token = request.run_nonce[:12]
    boundary_records = [
        record for record in records if record.get("handoff_marker") is not None
    ]
    if len(boundary_records) not in {1, 2} or not _handoff_boundary(
        boundary_records[0],
        pid=identity.pid,
        phase="READINESS_BEGIN",
        token=token,
    ):
        raise SupervisorError(
            "canonical trace before signal unblock has ambiguous handoff boundaries"
        )
    readiness_index = boundary_records[0]["record_index"]
    functional_index = None
    if len(boundary_records) == 2:
        if not _handoff_boundary(
            boundary_records[1],
            pid=identity.pid,
            phase="FUNCTIONAL_BEGIN",
            token=token,
        ):
            raise SupervisorError(
                "canonical trace before signal unblock has ambiguous handoff boundaries"
            )
        functional_index = boundary_records[1]["record_index"]
    expected_unblock_transition = {
        "operation": "rt_sigprocmask",
        "how": "SIG_UNBLOCK",
        "mask": ["HUP", "INT", "TERM"],
        "old_mask": ["HUP", "INT", "TERM"],
        "sigset_size": 8,
    }
    unblock_records = [
        record
        for record in records
        if record.get("kind") == "syscall"
        and record.get("pid") == identity.pid
        and record.get("syscall") == "rt_sigprocmask"
        and record.get("transition") == expected_unblock_transition
        and record.get("result") == {"value": 0}
    ]
    if len(unblock_records) != 1:
        raise SupervisorError("canonical trace has no bound signal unblock")
    unblock_index = unblock_records[0]["record_index"]
    if not readiness_index < unblock_index or (
        functional_index is not None and unblock_index >= functional_index
    ):
        raise SupervisorError("canonical trace before signal unblock is out of order")
    closed_interval = records[readiness_index : unblock_index + 1]
    if any(record.get("pid") != identity.pid for record in closed_interval):
        raise SupervisorError(
            "canonical trace before signal unblock changed PID or TID"
        )
    cursor = readiness_index + 1
    if not _handoff_name_observation(
        records[cursor], pid=identity.pid, phase="READINESS", token=token
    ):
        raise SupervisorError(
            "canonical trace before signal unblock lacks readiness name observation"
        )
    cursor += 1
    if not _reviewed_mask_observation(records[cursor], expected_old_mask=_SIGNAL_ORDER):
        raise SupervisorError(
            "canonical trace before signal unblock lacks cleanup handler anchor"
        )
    cursor += 1
    for signal_name in _SIGNAL_ORDER:
        if not _reviewed_signal_action(records[cursor], expected_signal=signal_name):
            raise SupervisorError(
                "canonical trace before signal unblock has incomplete handler install"
            )
        cursor += 1
    if not _reviewed_mask_observation(records[cursor], expected_old_mask=_SIGNAL_ORDER):
        raise SupervisorError(
            "canonical trace before signal unblock lacks signal observation"
        )
    cursor += 1
    broker = _ReadinessBrokerProtocol(request_write_fd, acceptance_read_fd)
    for record in records[cursor:unblock_index]:
        broker_decision = broker.consume(record)
        if broker_decision is not True:
            raise SupervisorError(
                "canonical trace has functional progress before signal unblock"
            )
    if not broker.complete:
        raise SupervisorError(
            "canonical trace has functional progress before signal unblock"
        )
    if functional_index is None:
        post_unblock = records[unblock_index + 1 :]
        if (
            not post_unblock
            or post_unblock[0].get("kind") != "signal"
            or post_unblock[0].get("pid") != identity.pid
            or post_unblock[0].get("signal") not in {"SIGHUP", "SIGINT", "SIGTERM"}
        ):
            raise SupervisorError("canonical interrupted handoff lacks signal delivery")
        functional_count = 0
        delivered_signal = post_unblock[0]["signal"].removeprefix("SIG")
    else:
        post_unblock = records[unblock_index + 1 : functional_index]
        if len(post_unblock) != 4 or any(
            record.get("pid") != identity.pid for record in post_unblock
        ):
            raise SupervisorError("canonical post-unblock handoff is not exact")
        acceptance_provenance = broker.acceptance_provenance
        if (
            not _reviewed_mask_observation(post_unblock[0], expected_old_mask=())
            or acceptance_provenance is None
            or not _reviewed_base_close(
                post_unblock[1],
                fd=acceptance_read_fd,
                provenance=acceptance_provenance,
            )
            or not _reviewed_getpid(post_unblock[2], pid=identity.pid)
            or not _handoff_name_observation(
                post_unblock[3], pid=identity.pid, phase="READINESS", token=token
            )
        ):
            raise SupervisorError("canonical post-unblock handoff is not exact")
        functional_count = 1
        delivered_signal = None
    events = [
        HandoffEvent(0, "ready_sent", "AWAITING_ACCEPTANCE"),
        HandoffEvent(1, "acceptance_validated", "LIVE_READY"),
        HandoffEvent(2, "signals_unblocked", "LIVE_READY"),
    ]
    if functional_count:
        events.append(HandoffEvent(3, "functional", "LIVE_READY"))
    coordinator = CoordinatorSnapshot(
        role="COORDINATOR",
        state="LIVE_READY",
        terminal_state=None,
        request_sequence=request.sequence,
        request_sha256=request.canonical_sha256,
        acceptance_validated=True,
        unblock_count=1,
        functional_count=functional_count,
        events=tuple(events),
    )
    trace = TraceUnblockEvidence(
        run_nonce=request.run_nonce,
        identity=identity,
        request_sequence=request.sequence,
        request_sha256=request.canonical_sha256,
        unblock_trace_record_index=unblock_index,
        first_functional_trace_record_index=functional_index,
        functional_count=functional_count,
        delivered_signal=delivered_signal,
    )
    return coordinator, trace


def _validate_bootstrap_report_inputs(value: Mapping[str, object]) -> None:
    expected = {
        "schema_version",
        "toolchain",
        "initial_fd_manifest",
        "final_fd_manifest",
        "sanitation_actions",
        "rebinding_actions",
        "live_fixture_passed",
    }
    if type(value) is not dict or set(value) != expected:
        raise SupervisorError("production bootstrap report inputs are not closed")
    toolchain = value.get("toolchain")
    if (
        value.get("schema_version") != "holoagent0.bootstrap-report.v1"
        or type(toolchain) is not dict
        or set(toolchain) != {"expected", "observed"}
        or any(type(toolchain[name]) is not dict for name in ("expected", "observed"))
        or type(value.get("live_fixture_passed")) is not bool
    ):
        raise SupervisorError("production bootstrap report inputs are invalid")
    for name in ("initial_fd_manifest", "final_fd_manifest"):
        manifest = value.get(name)
        if type(manifest) is not list:
            raise SupervisorError("production bootstrap FD manifest is invalid")
        previous = -1
        for item in manifest:
            if (
                type(item) is not dict
                or set(item) != {"fd", "target", "cloexec"}
                or type(item["fd"]) is not int
                or item["fd"] <= previous
                or type(item["target"]) is not str
                or not item["target"]
                or type(item["cloexec"]) is not bool
            ):
                raise SupervisorError("production bootstrap FD manifest is invalid")
            previous = item["fd"]
    for name in ("sanitation_actions", "rebinding_actions"):
        actions = value.get(name)
        if type(actions) is not list or any(
            type(action) is not str or not action for action in actions
        ):
            raise SupervisorError("production bootstrap action evidence is invalid")


@dataclass(frozen=True)
class BootstrapFacts:
    source_ok: bool
    runtime_ok: bool
    inherited_fd_safe: bool
    sanitation_ok: bool
    trace_capability_ok: bool
    exitkill_verified: bool

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool
            for value in (
                self.source_ok,
                self.runtime_ok,
                self.inherited_fd_safe,
                self.sanitation_ok,
                self.trace_capability_ok,
                self.exitkill_verified,
            )
        ):
            raise SupervisorError("bootstrap facts must be exact booleans")

    @classmethod
    def clean(cls) -> "BootstrapFacts":
        return cls(True, True, True, True, True, True)

    def replaced(self, **changes: object) -> "BootstrapFacts":
        return replace(self, **changes)


@dataclass(frozen=True)
class BootstrapDecision:
    launch_state: str
    trace_state: str
    coordinator_launch_committed: bool
    first_signal: str | None
    gates: tuple[dict[str, object], ...]


class BootstrapEngine:
    """Resolve the authoritative bootstrap outcome table without side effects."""

    def evaluate(
        self, facts: BootstrapFacts, *, precommit_signal: str | None = None
    ) -> BootstrapDecision:
        if type(facts) is not BootstrapFacts:
            raise SupervisorError("bootstrap facts object is not exact")
        if precommit_signal is not None and precommit_signal not in _SIGNALS:
            raise SupervisorError("precommit signal is invalid")
        gates = _gate_skeleton()
        if not facts.source_ok:
            _set_gate(gates, 0, "FAIL", "SOURCE_MISMATCH")
            return _bootstrap_failure(
                gates,
                first_signal=precommit_signal,
                inherited_failure=False,
                sanitation_ok=facts.sanitation_ok,
            )
        _set_gate(gates, 0, "PASS", "OK")

        if not (
            facts.runtime_ok and facts.trace_capability_ok and facts.exitkill_verified
        ):
            reason = (
                "RUNTIME_MISMATCH" if not facts.runtime_ok else "TOOL_RUNTIME_ERROR"
            )
            _set_gate(gates, 1, "FAIL", reason)
            return _bootstrap_failure(
                gates,
                first_signal=precommit_signal,
                inherited_failure=False,
                sanitation_ok=facts.sanitation_ok,
            )
        _set_gate(gates, 1, "PASS", "OK")

        if not facts.inherited_fd_safe:
            _set_gate(gates, 2, "FAIL", "INHERITED_SOCKET_FD")
            return _bootstrap_failure(
                gates,
                first_signal=precommit_signal,
                inherited_failure=True,
                sanitation_ok=facts.sanitation_ok,
            )
        if not facts.sanitation_ok:
            _set_gate(gates, 2, "FAIL", "INHERITED_SOCKET_FD")
            return BootstrapDecision(
                "NOT_STARTED_BOOTSTRAP_FAILURE",
                "NOT_STARTED",
                False,
                precommit_signal,
                tuple(gates),
            )

        arbiter = LaunchArbiter()
        if precommit_signal is not None:
            arbiter.collect_signal(precommit_signal)
        arbiter.bootstrap_clean()
        if arbiter.try_commit():
            snapshot = arbiter.snapshot()
            return BootstrapDecision(
                snapshot.state,
                "FULL",
                True,
                snapshot.first_signal,
                tuple(gates),
            )
        snapshot = arbiter.snapshot()
        for gate in gates[2:23]:
            gate["reason"] = "INTERRUPTED_BEFORE_GATE"
        return BootstrapDecision(
            snapshot.state,
            "FINALIZER_ONLY",
            False,
            snapshot.first_signal,
            tuple(gates),
        )


@dataclass(frozen=True)
class BootstrapInvocation:
    run_root: Path
    run_id: str
    run_nonce: str
    facts: BootstrapFacts
    bootstrap_report: Mapping[str, object]
    precommit_signal: str | None = None
    run_root_authority: RunRootAuthority | None = None


@dataclass(frozen=True)
class BootstrapState:
    run_root: Path
    decision: BootstrapDecision
    ledger: LedgerStore
    ownership_journal: AppendOnlyJournal
    violation_journal: AppendOnlyJournal
    owned_process_controller: "OwnedProcessController"
    owned_tracees: Callable[[], Sequence["OwnedProcessLease"]]
    signal_runtime: SupervisorSignalRuntime | None = None
    bootstrap_report: Mapping[str, object] | None = None
    started_at: str = ""
    started_monotonic: float = 0.0


@dataclass(frozen=True)
class LiveTraceLaunchOutcome:
    """Observed identities and handoff pipes from one committed trace launch."""

    tracer_identity: ProcessIdentity
    normalizer_identity: ProcessIdentity
    coordinator_identity: ProcessIdentity
    signal_request_read_fd: int
    signal_acceptance_write_fd: int
    signal_request_write_fd: int
    signal_acceptance_read_fd: int
    broker_channels: "ProductionBrokerChannels | None" = None

    def __post_init__(self) -> None:
        identities = (
            self.tracer_identity,
            self.normalizer_identity,
            self.coordinator_identity,
        )
        descriptors = (
            self.signal_request_read_fd,
            self.signal_acceptance_write_fd,
            self.signal_request_write_fd,
            self.signal_acceptance_read_fd,
        )
        if any(type(identity) is not ProcessIdentity for identity in identities):
            raise SupervisorError("live trace launch identities are invalid")
        if len({identity.pid for identity in identities}) != 3:
            raise SupervisorError("live trace launch identities are not distinct")
        if any(type(fd) is not int or fd < 0 for fd in descriptors) or (
            self.signal_request_read_fd == self.signal_acceptance_write_fd
            or self.signal_request_write_fd == self.signal_acceptance_read_fd
        ):
            raise SupervisorError("live signal handoff descriptors are invalid")
        if (
            self.broker_channels is not None
            and type(self.broker_channels) is not ProductionBrokerChannels
        ):
            raise SupervisorError("live broker channels are invalid")


class BootstrapRuntime:
    """Initialize the complete zero-state evidence root before trace launch."""

    def __init__(
        self,
        contract: ContractSet,
        *,
        owned_process_controller: "OwnedProcessController | None" = None,
        signal_runtime: SupervisorSignalRuntime | None = None,
        signal_runtime_factory: Callable[[str], SupervisorSignalRuntime] | None = None,
        require_complete_report: bool = False,
        require_run_root_authority: bool = False,
    ) -> None:
        if type(contract) is not ContractSet:
            raise SupervisorError("bootstrap contract is not exact")
        self._contract = contract
        self._owned_process_controller = (
            owned_process_controller or OwnedProcessController()
        )
        if (
            signal_runtime is not None
            and type(signal_runtime) is not SupervisorSignalRuntime
        ):
            raise SupervisorError("bootstrap signal runtime is not exact")
        if signal_runtime_factory is not None and not callable(signal_runtime_factory):
            raise SupervisorError("bootstrap signal runtime factory is invalid")
        if signal_runtime is not None and signal_runtime_factory is not None:
            raise SupervisorError("bootstrap signal authority is ambiguous")
        self._signal_runtime = signal_runtime
        self._signal_runtime_factory = signal_runtime_factory
        if type(require_complete_report) is not bool:
            raise SupervisorError("bootstrap report requirement is invalid")
        self._require_complete_report = require_complete_report
        if type(require_run_root_authority) is not bool:
            raise SupervisorError("run root authority requirement is invalid")
        self._require_run_root_authority = require_run_root_authority

    @classmethod
    def production(
        cls,
        contract: ContractSet,
        *,
        signal_forwarder: Callable[[int, str], object],
        signal_identity_validator: Callable[[ProcessIdentity], bool],
        owned_process_controller: "OwnedProcessController | None" = None,
    ) -> "BootstrapRuntime":
        return cls(
            contract,
            owned_process_controller=owned_process_controller,
            signal_runtime_factory=lambda nonce: SupervisorSignalRuntime(
                nonce,
                forwarder=signal_forwarder,
                identity_validator=signal_identity_validator,
            ),
            require_complete_report=True,
            require_run_root_authority=True,
        )

    def run(self, invocation: BootstrapInvocation) -> BootstrapState:
        if type(invocation) is not BootstrapInvocation:
            raise SupervisorError("bootstrap invocation is not exact")
        authority: RunRootAuthority | None = None
        signal_runtime: SupervisorSignalRuntime | None = None
        try:
            authority = invocation.run_root_authority
            run_root = Path(invocation.run_root)
            started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            started_monotonic = time.monotonic()
            if (
                self._require_run_root_authority
                and type(authority) is not RunRootAuthority
            ):
                raise SupervisorError("production run root authority is missing")
            if (
                self._require_run_root_authority
                and invocation.run_id != authority.expected_run_root.name
            ):
                raise SupervisorError("production run id authority is inconsistent")
            signal_runtime = (
                self._signal_runtime_factory(invocation.run_nonce)
                if self._signal_runtime_factory is not None
                else self._signal_runtime
            )
            if signal_runtime is not None:
                signal_runtime.start()
            if self._require_complete_report:
                _validate_bootstrap_report_inputs(invocation.bootstrap_report)
            if self._require_run_root_authority:
                run_root = authority.create(run_root)
            else:
                run_root.mkdir(mode=0o700, parents=False, exist_ok=False)
            ledger = LedgerStore.create(
                run_root / "ledger",
                self._contract,
                invocation.run_nonce,
                run_id=invocation.run_id,
            )
            ownership = AppendOnlyJournal.create(
                run_root / "ownership_journal.ndjson",
                relative_to=run_root,
                allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
            )
            violations = AppendOnlyJournal.create(
                run_root / "violation_journal.ndjson",
                relative_to=run_root,
                allowed_kinds=_VIOLATION_RECORD_KINDS,
            )
            decision = BootstrapEngine().evaluate(
                invocation.facts,
                precommit_signal=invocation.precommit_signal,
            )
            report = copy.deepcopy(dict(invocation.bootstrap_report))
            report.update(
                terminal_launch_state=decision.launch_state,
                coordinator_launch_committed=decision.coordinator_launch_committed,
                first_signal=decision.first_signal,
            )
            if not decision.coordinator_launch_committed:
                report["handoff"] = _not_applicable_handoff_report(
                    decision.first_signal
                )
            if signal_runtime is None or not decision.coordinator_launch_committed:
                atomic_write_json_no_replace(
                    run_root / "bootstrap_report.json",
                    report,
                    mode=0o400,
                    relative_to=run_root,
                )
            if not decision.coordinator_launch_committed:
                early_unsafe_fd = (
                    not invocation.facts.inherited_fd_safe
                    and decision.gates[2]["status"] == "NOT_RUN"
                )
                if not invocation.facts.sanitation_ok or early_unsafe_fd:
                    cause_gate = "safety.workstation_postflight"
                    reason = "POSTFLIGHT_FAILED"
                else:
                    cause_gate = "safety.workstation_preflight"
                    reason = (
                        "INTERRUPTED_BEFORE_GATE"
                        if decision.launch_state == "PRE_COORDINATOR_INTERRUPTED"
                        else "EARLIER_BLOCKING_GATE"
                    )
                for phase in ("pre", "post"):
                    write_host_observer_artifact(
                        run_root / f"host_observer_{phase}.json",
                        relative_to=run_root,
                        state="NOT_RUN",
                        cause_gate=cause_gate,
                        reason=reason,
                    )
            return BootstrapState(
                run_root,
                decision,
                ledger,
                ownership,
                violations,
                self._owned_process_controller,
                self._owned_process_controller.active_leases,
                signal_runtime,
                report,
                started_at,
                started_monotonic,
            )
        except Exception as error:
            cleanup_error: BaseException | None = None
            if (
                self._require_run_root_authority
                and type(authority) is RunRootAuthority
                and not authority.consumed
            ):
                try:
                    authority.close()
                except Exception as observed_cleanup_error:
                    cleanup_error = observed_cleanup_error
            if signal_runtime is not None and signal_runtime._started:
                try:
                    signal_runtime.close(restore_mask=True)
                except Exception as observed_cleanup_error:
                    if cleanup_error is None:
                        cleanup_error = observed_cleanup_error
            if cleanup_error is not None:
                raise SupervisorError(
                    "bootstrap zero-state cleanup failed"
                ) from cleanup_error
            raise SupervisorError(
                "bootstrap zero-state initialization failed"
            ) from error


@dataclass(frozen=True)
class SupervisorScenario:
    bootstrap: BootstrapFacts
    precommit_signal: str | None = None
    ledger_state: str = "SEALED_PASS"
    trace_fault: str | None = None
    tracees_live: bool = False
    cleanup_complete: bool = True
    network_violation: str | None = None
    evidence_binding_ok: bool = True

    def __post_init__(self) -> None:
        if self.precommit_signal is not None and self.precommit_signal not in _SIGNALS:
            raise SupervisorError("scenario signal is invalid")
        if self.ledger_state not in {
            "SEALED_PASS",
            "MISSING",
            "UNSEALED",
            "WRONG_NONCE",
            "INVALID_CHAIN",
        }:
            raise SupervisorError("scenario ledger state is invalid")
        if self.trace_fault is not None and self.trace_fault not in _TRACE_REASONS:
            raise SupervisorError("scenario trace fault is invalid")
        if (
            self.network_violation is not None
            and self.network_violation not in _NETWORK_REASONS
        ):
            raise SupervisorError("scenario network violation is invalid")

    @classmethod
    def clean(cls, **changes: object) -> "SupervisorScenario":
        return replace(cls(BootstrapFacts.clean()), **changes)


@dataclass(frozen=True)
class SupervisorRunResult:
    launch_state: str
    trace_state: str
    gates: tuple[dict[str, object], ...]
    primary_blocking_gate: str | None
    blocking_gates: tuple[str, ...]
    label: str
    status: str
    exit_code: int
    functional_coordinator_started: bool
    progress_stopped: bool
    finalizer_order: tuple[str, str, str, str]
    first_signal: str | None


@dataclass(frozen=True, init=False)
class AuthoritativeEvaluation:
    _result: dict[str, object]
    _process_exit: int
    _trace_terminal_proof: "TraceTerminalProof"

    def __init__(
        self, result: dict[str, object], trace_terminal_proof: "TraceTerminalProof"
    ) -> None:
        if type(result) is not dict:
            raise SupervisorError("authoritative evaluation result is not exact")
        if (
            type(trace_terminal_proof) is not TraceTerminalProof
            or trace_terminal_proof._phase != "FINALIZER_ACCEPTED"
        ):
            raise SupervisorError("authoritative trace terminal proof is invalid")
        copied = copy.deepcopy(result)
        process_exit = copied.get("process_exit_code")
        if type(process_exit) is not int or process_exit not in {
            0,
            10,
            20,
            30,
            40,
            129,
            130,
            143,
        }:
            raise SupervisorError("authoritative process exit is invalid")
        object.__setattr__(self, "_result", copied)
        object.__setattr__(self, "_process_exit", process_exit)
        object.__setattr__(self, "_trace_terminal_proof", trace_terminal_proof)

    @property
    def result(self) -> dict[str, object]:
        return copy.deepcopy(self._result)

    @property
    def process_exit(self) -> int:
        return self._process_exit

    @property
    def trace_terminal_proof(self) -> "TraceTerminalProof":
        return self._trace_terminal_proof


class SupervisorViolationSink:
    """Persist exact trace-policy evidence before retaining safety precedence."""

    def __init__(self, violation_journal: object) -> None:
        if not callable(getattr(violation_journal, "append", None)):
            raise SupervisorError("violation journal is incomplete")
        self._journal = violation_journal
        self._network_failure = False
        self._primary_reason: str | None = None
        self._supervisor_sequence = 0
        self._lock = RLock()

    def persist(self, violation: PolicyViolation) -> None:
        if type(violation) is not PolicyViolation:
            raise SupervisorError("policy violation is not exact")
        if (
            violation.reason not in _NETWORK_REASONS
            or type(violation.record_index) is not int
            or violation.record_index < 0
            or type(violation.pid) is not int
            or violation.pid <= 0
            or type(violation.operation) is not str
            or not violation.operation
        ):
            raise SupervisorError("policy violation evidence is incomplete")
        with self._lock:
            self._journal.append(
                "TRACE_VIOLATION_RECORD",
                {
                    "reason": violation.reason,
                    "record_index": violation.record_index,
                    "pid": violation.pid,
                    "operation": violation.operation,
                },
            )
            self._network_failure = True
            if self._primary_reason is None:
                self._primary_reason = violation.reason

    def persist_supervisor(self, *, reason: str, pid: int, operation: str) -> None:
        """Persist a supervisor-observed event without inventing trace provenance."""

        if (
            reason not in _NETWORK_REASONS
            or type(pid) is not int
            or pid <= 0
            or type(operation) is not str
            or not operation
        ):
            raise SupervisorError("supervisor violation evidence is incomplete")
        with self._lock:
            sequence = self._supervisor_sequence
            self._journal.append(
                "SUPERVISOR_VIOLATION_RECORD",
                {
                    "reason": reason,
                    "event_sequence": sequence,
                    "pid": pid,
                    "operation": operation,
                },
            )
            self._supervisor_sequence = sequence + 1
            self._network_failure = True
            if self._primary_reason is None:
                self._primary_reason = reason

    def snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return ("offline.network_policy",) if self._network_failure else ()

    def primary_network_reason(self) -> str | None:
        with self._lock:
            return self._primary_reason


SupervisorSafetyFacts = SupervisorViolationSink


class SupervisorNetworkBoundary:
    """Install the two supervisor-only network construction barriers in order."""

    def __init__(
        self,
        *,
        audit_installer: Callable[[], object],
        seccomp_installer: Callable[[], object],
    ) -> None:
        if not callable(audit_installer) or not callable(seccomp_installer):
            raise SupervisorError("supervisor network boundary is incomplete")
        self._audit_installer = audit_installer
        self._seccomp_installer = seccomp_installer
        self._audit_installed = False
        self._seccomp_installed = False

    @classmethod
    def production(
        cls, violation_sink: SupervisorViolationSink
    ) -> "SupervisorNetworkBoundary":
        if type(violation_sink) is not SupervisorViolationSink:
            raise SupervisorError("production network violation sink is not exact")

        def install_audit() -> bool:
            def audit(event: str, arguments: tuple[object, ...]) -> None:
                if event != "socket.__new__" or len(arguments) < 2:
                    return
                family = arguments[1]
                if family not in {socket.AF_INET, socket.AF_INET6}:
                    return
                violation_sink.persist_supervisor(
                    reason="UNEXPECTED_NETWORK_ATTEMPT",
                    pid=os.getpid(),
                    operation="socket",
                )
                raise PermissionError(errno.EPERM, "internet sockets are prohibited")

            sys.addaudithook(audit)
            return True

        return cls(
            audit_installer=install_audit,
            seccomp_installer=_install_supervisor_socket_seccomp,
        )

    def install_audit(self) -> None:
        if self._audit_installed or self._audit_installer() is not True:
            raise SupervisorError("supervisor audit hook installation failed")
        self._audit_installed = True

    def install_seccomp(self) -> None:
        if not self._audit_installed:
            raise SupervisorError("supervisor seccomp preceded the audit hook")
        if self._seccomp_installed or self._seccomp_installer() is not True:
            raise SupervisorError("supervisor seccomp installation failed")
        self._seccomp_installed = True


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (("length", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter)))


def _install_supervisor_socket_seccomp() -> bool:
    """Deny new AF_INET/AF_INET6 sockets in the post-launch supervisor only."""

    machine = os.uname().machine
    if machine == "x86_64":
        audit_arch, socket_syscall = 0xC000003E, 41
    elif machine in {"aarch64", "arm64"}:
        audit_arch, socket_syscall = 0xC00000B7, 198
    else:
        raise SupervisorError("supervisor seccomp architecture is unreviewed")
    bpf_ld_w_abs = 0x20
    bpf_jmp_jeq_k = 0x15
    bpf_ret_k = 0x06
    seccomp_ret_allow = 0x7FFF0000
    seccomp_ret_kill = 0x80000000
    seccomp_ret_errno = 0x00050000 | errno.EPERM
    instructions = (_SockFilter * 10)(
        _SockFilter(bpf_ld_w_abs, 0, 0, 4),
        _SockFilter(bpf_jmp_jeq_k, 1, 0, audit_arch),
        _SockFilter(bpf_ret_k, 0, 0, seccomp_ret_kill),
        _SockFilter(bpf_ld_w_abs, 0, 0, 0),
        _SockFilter(bpf_jmp_jeq_k, 0, 4, socket_syscall),
        _SockFilter(bpf_ld_w_abs, 0, 0, 16),
        _SockFilter(bpf_jmp_jeq_k, 1, 0, socket.AF_INET),
        _SockFilter(bpf_jmp_jeq_k, 0, 1, socket.AF_INET6),
        _SockFilter(bpf_ret_k, 0, 0, seccomp_ret_errno),
        _SockFilter(bpf_ret_k, 0, 0, seccomp_ret_allow),
    )
    program = _SockFprog(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise SupervisorError("supervisor no-new-privileges setup failed")
    if libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise SupervisorError("supervisor seccomp filter setup failed")
    return True


class PublicationEvidenceFactory:
    """Construct the production binder with its only permitted publications."""

    def __init__(
        self,
        run_root: Path,
        *,
        context: EvidenceContext,
        result_path: Path,
        emergency_path: Path,
        secret_sentinels: Sequence[str] | set[str] | frozenset[str] = (),
    ) -> None:
        if type(context) is not EvidenceContext:
            raise SupervisorError("production evidence context is not exact")
        root = Path(os.path.abspath(run_root))
        try:
            if root.resolve(strict=True) != root:
                raise SupervisorError("production evidence root contains a symlink")
        except OSError as error:
            raise SupervisorError("production evidence root is unavailable") from error
        expected = (root / "result.json", root / "emergency.txt")
        supplied = tuple(
            Path(os.path.abspath(path)) for path in (result_path, emergency_path)
        )
        if supplied != expected:
            raise SupervisorError("production publication paths are not exact")
        self._root = root
        self._context = replace(context, publication_paths=expected)
        self._sentinels = tuple(secret_sentinels)

    def create(self) -> EvidenceBinder:
        return EvidenceBinder(
            self._root,
            context=self._context,
            secret_sentinels=self._sentinels,
        )


class DeferredProductionEvidenceBinder:
    """Create the binder only after coordinator-owned receipts are available."""

    def __init__(
        self,
        run_root: Path,
        *,
        context_supplier: Callable[[], EvidenceContext],
        result_path: Path,
        emergency_path: Path,
        secret_sentinels: Sequence[str] | set[str] | frozenset[str],
    ) -> None:
        if not callable(context_supplier):
            raise SupervisorError("deferred evidence context supplier is invalid")
        self._root = run_root
        self._supplier = context_supplier
        self._result_path = result_path
        self._emergency_path = emergency_path
        self._sentinels = secret_sentinels
        self._binder: EvidenceBinder | None = None

    def bind(self, requirements: object) -> object:
        if self._binder is not None:
            raise SupervisorError("deferred evidence binder is one-shot")
        context = self._supplier()
        if type(context) is not EvidenceContext:
            raise SupervisorError("deferred evidence context is not exact")
        self._binder = PublicationEvidenceFactory(
            self._root,
            context=context,
            result_path=self._result_path,
            emergency_path=self._emergency_path,
            secret_sentinels=self._sentinels,
        ).create()
        return self._binder.bind(requirements)

    def _require_binder(self) -> EvidenceBinder:
        if self._binder is None:
            raise SupervisorError("deferred evidence binder has not bound artifacts")
        return self._binder

    def revalidate(self, bundle: object) -> object:
        return self._require_binder().revalidate(bundle)

    def freeze_for_publication(self, bundle: object) -> object:
        return self._require_binder().freeze_for_publication(bundle)

    def register_publication_temporary(
        self, bundle: object, freeze: object, path: Path
    ) -> object:
        return self._require_binder().register_publication_temporary(
            bundle, freeze, path
        )

    def revalidate_for_publication(self, bundle: object, freeze: object) -> object:
        return self._require_binder().revalidate_for_publication(bundle, freeze)


class MandatoryFinalizers:
    """Own trace, policy, evidence, and recovery order after trace closure."""

    def __init__(
        self,
        *,
        trace_finalizer: Callable[[object], object],
        network_finalizer: Callable[[object, object], object],
        binder: object,
        evidence_requirements: Callable[[object, object], object],
        result_builder: Callable[
            [object, object, object, object, object], dict[str, object]
        ],
        recovery: Callable[..., tuple[object, object]],
    ) -> None:
        adapters = (
            trace_finalizer,
            network_finalizer,
            getattr(binder, "bind", None),
            evidence_requirements,
            result_builder,
            recovery,
        )
        if any(not callable(adapter) for adapter in adapters):
            raise SupervisorError("mandatory finalizer adapter is incomplete")
        self._trace_finalizer = trace_finalizer
        self._network_finalizer = network_finalizer
        self._binder = binder
        self._evidence_requirements = evidence_requirements
        self._result_builder = result_builder
        self._recovery = recovery
        self._bound_bundle: object | None = None

    @classmethod
    def production(
        cls,
        *,
        run_root: Path,
        evidence_context: EvidenceContext | Callable[[], EvidenceContext],
        result_path: Path,
        emergency_path: Path,
        secret_sentinels: Sequence[str] | set[str] | frozenset[str],
        trace_finalizer: Callable[[object], object],
        network_finalizer: Callable[[object, object], object],
        evidence_requirements: Callable[[object, object], object],
        result_builder: Callable[
            [object, object, object, object, object], dict[str, object]
        ],
        recovery: Callable[..., tuple[object, object]],
    ) -> "MandatoryFinalizers":
        binder = (
            DeferredProductionEvidenceBinder(
                run_root,
                context_supplier=evidence_context,
                result_path=result_path,
                emergency_path=emergency_path,
                secret_sentinels=secret_sentinels,
            )
            if callable(evidence_context)
            else PublicationEvidenceFactory(
                run_root,
                context=evidence_context,
                result_path=result_path,
                emergency_path=emergency_path,
                secret_sentinels=secret_sentinels,
            ).create()
        )
        return cls(
            trace_finalizer=trace_finalizer,
            network_finalizer=network_finalizer,
            binder=binder,
            evidence_requirements=evidence_requirements,
            result_builder=result_builder,
            recovery=recovery,
        )

    @property
    def evidence_binder(self) -> object:
        return self._binder

    @property
    def bound_bundle(self) -> object:
        if self._bound_bundle is None:
            raise SupervisorError("production evidence bundle is not yet bound")
        return self._bound_bundle

    def evaluate_and_bind(
        self, session: object, ledger: object
    ) -> AuthoritativeEvaluation:
        finalized = self._trace_finalizer(session)
        if type(finalized) is not tuple or len(finalized) != 2:
            raise SupervisorError("trace finalizer did not return terminal proof")
        trace, proof = finalized
        accept = getattr(session, "accept_terminal_proof", None)
        if not callable(accept):
            raise SupervisorError("trace session cannot accept terminal proof")
        network = self._network_finalizer(session, trace)
        requirements = self._evidence_requirements(session, ledger)
        bundle = self._binder.bind(requirements)
        self._bound_bundle = bundle
        accept(proof, bundle=bundle)
        result = self._result_builder(session, ledger, trace, network, bundle)
        if type(result) is not dict:
            raise SupervisorError("mandatory finalizer result is not exact")
        return AuthoritativeEvaluation(result, proof)

    def recover(
        self,
        *,
        stage: str,
        error: BaseException,
        state: object,
        session: object,
        ledger: object,
    ) -> AuthoritativeEvaluation:
        recovered = self._recovery(
            stage=stage,
            error=error,
            state=state,
            session=session,
            ledger=ledger,
        )
        if type(recovered) is not tuple or len(recovered) != 2:
            raise SupervisorError("mandatory recovery state is invalid")
        return self.evaluate_and_bind(*recovered)


class _DeferredViolationJournal:
    def __init__(self) -> None:
        self._target: AppendOnlyJournal | None = None
        self._pending: list[tuple[str, dict[str, object]]] = []

    def append(self, kind: str, payload: Mapping[str, object]) -> object:
        if type(payload) is not dict:
            raise SupervisorError("deferred violation payload is not exact")
        if self._target is None:
            self._pending.append((kind, copy.deepcopy(dict(payload))))
            return object()
        return self._target.append(kind, dict(payload))

    def bind(self, target: AppendOnlyJournal) -> None:
        if type(target) is not AppendOnlyJournal or self._target is not None:
            raise SupervisorError("deferred violation journal binding is invalid")
        self._target = target
        for kind, payload in self._pending:
            target.append(kind, payload)
        self._pending = []


class _ProductionBootstrapAdapter:
    def __init__(
        self,
        runtime: BootstrapRuntime,
        contract: ContractSet,
        violation_journal: _DeferredViolationJournal,
        finalizers: "ProductionMandatoryFinalizers",
    ) -> None:
        self._runtime = runtime
        self._contract = contract
        self._violations = violation_journal
        self._finalizers = finalizers

    def run(self, invocation: BootstrapInvocation) -> BootstrapState:
        if type(invocation) is not BootstrapInvocation:
            raise SupervisorError("production invocation is not exact")
        row = self._contract.trace_tool_rows()[0]
        reviewed = all(
            row[name].get("review_state") == "REVIEWED"
            for name in ("build", "runtime", "parser", "argv", "fixtures")
        )
        facts = invocation.facts.replaced(
            runtime_ok=invocation.facts.runtime_ok and reviewed,
            trace_capability_ok=invocation.facts.trace_capability_ok and reviewed,
            exitkill_verified=invocation.facts.exitkill_verified and reviewed,
        )
        effective = replace(invocation, facts=facts)
        self._finalizers.prepare_invocation(effective)
        state = self._runtime.run(effective)
        self._violations.bind(state.violation_journal)
        self._finalizers.bind_state(state)
        return state


def _git_blob_sha1(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def _is_sha256(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_tracked_regular(path: Path, *, expected_executable: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = -1
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        executable = bool(before.st_mode & 0o111)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or bool(expected_executable) != executable
            or before.st_size > 64 * 1024 * 1024
        ):
            raise SupervisorError("tracked file identity is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise SupervisorError("tracked file is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise SupervisorError("tracked file exceeded its bound size")
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mode):
            raise SupervisorError("tracked file changed during verification")
        return b"".join(chunks)
    except OSError as error:
        raise SupervisorError("tracked file is unavailable") from error
    finally:
        if fd >= 0:
            os.close(fd)


@dataclass(frozen=True)
class _TrackedFileInventory:
    regular_paths: tuple[Path, ...]
    symlinks: tuple[tuple[Path, str], ...]

    def __post_init__(self) -> None:
        if (
            not self.regular_paths
            or any(not isinstance(path, Path) for path in self.regular_paths)
            or any(
                type(row) is not tuple
                or len(row) != 2
                or not isinstance(row[0], Path)
                or not _is_git_oid(row[1])
                for row in self.symlinks
            )
        ):
            raise SupervisorError("tracked-file inventory is invalid")


def _load_git_tracked_manifest(
    contract_root: Path, *, secret_sentinels: frozenset[str]
) -> _TrackedFileInventory:
    """Verify and return the complete reviewed Git-tracked regular-file set."""

    root = Path(contract_root)
    repository_root = root.parents[1]
    manifest_path = root / _TRACKED_FILE_MANIFEST
    return _verify_git_tracked_manifest(
        manifest_path,
        repository_root,
        expected_sha256=_TRACKED_FILE_MANIFEST_SHA256,
        secret_sentinels=secret_sentinels,
    )


def _verify_git_tracked_manifest(
    manifest_path: Path,
    repository_root: Path,
    *,
    expected_sha256: str,
    secret_sentinels: frozenset[str],
) -> _TrackedFileInventory:
    if not _is_sha256(expected_sha256) or any(
        type(value) is not str or not value for value in secret_sentinels
    ):
        raise SupervisorError("tracked-file manifest authority is invalid")
    manifest_path = Path(manifest_path)
    repository_root = Path(repository_root)
    manifest_payload = _read_tracked_regular(manifest_path, expected_executable=False)
    if hashlib.sha256(manifest_payload).hexdigest() != expected_sha256:
        raise SupervisorError("tracked-file manifest digest is unreviewed")
    try:
        manifest_text = manifest_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SupervisorError("tracked-file manifest is undecodable") from error
    if not manifest_text.endswith("\n") or "\r" in manifest_text:
        raise SupervisorError("tracked-file manifest is noncanonical")
    rows: list[tuple[str, str, str]] = []
    for encoded in manifest_text.splitlines():
        try:
            metadata, relative = encoded.split("\t", 1)
            mode, oid = metadata.split(" ", 1)
        except ValueError as error:
            raise SupervisorError("tracked-file manifest row is invalid") from error
        posix = PurePosixPath(relative)
        if (
            mode not in {"100644", "100755", "120000"}
            or not relative
            or posix.is_absolute()
            or ".." in posix.parts
            or relative != posix.as_posix()
            or (oid != _TRACKED_MANIFEST_SELF_OID and not _is_git_oid(oid))
        ):
            raise SupervisorError("tracked-file manifest row is invalid")
        rows.append((mode, oid, relative))
    relative_paths = tuple(row[2] for row in rows)
    if (
        not rows
        or relative_paths != tuple(sorted(relative_paths))
        or len(relative_paths) != len(set(relative_paths))
        or _TRACKED_FILE_MANIFEST_REPO_PATH in relative_paths
        or relative_paths.count(_TRACKED_MANIFEST_AUTHORITY_REPO_PATH) != 1
    ):
        raise SupervisorError("tracked-file manifest inventory is invalid")
    retained: list[Path] = [manifest_path]
    symlinks: list[tuple[Path, str]] = []
    for mode, oid, relative in rows:
        path = repository_root / relative
        if relative == _TRACKED_MANIFEST_AUTHORITY_REPO_PATH:
            if mode != "100644" or oid != _TRACKED_MANIFEST_SELF_OID:
                raise SupervisorError("tracked-file manifest authority row is invalid")
            _read_tracked_regular(path, expected_executable=False)
            retained.append(path)
            continue
        if oid == _TRACKED_MANIFEST_SELF_OID:
            raise SupervisorError("tracked-file manifest has ambiguous self row")
        if mode == "120000":
            try:
                metadata = path.lstat()
                target = os.readlink(path).encode("utf-8", errors="strict")
            except (OSError, UnicodeError) as error:
                raise SupervisorError("tracked symlink is unavailable") from error
            if (
                not stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or _git_blob_sha1(target) != oid
                or any(value.encode("utf-8") in target for value in secret_sentinels)
            ):
                raise SupervisorError("tracked symlink identity is invalid")
            symlinks.append((path, oid))
            continue
        payload = _read_tracked_regular(path, expected_executable=mode == "100755")
        if _git_blob_sha1(payload) != oid:
            raise SupervisorError("tracked file differs from reviewed Git blob")
        retained.append(path)
    return _TrackedFileInventory(tuple(retained), tuple(symlinks))


def _is_git_oid(value: object) -> bool:
    return bool(
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


class ProductionMandatoryFinalizers:
    """Concrete supervisor-owned evidence and result finalization."""

    _GRAPH_SHA256 = "6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050"
    _DATASET_SHA256 = "a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913"
    _CHECKPOINT_SHA256 = (
        "5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b"
    )

    def __init__(
        self,
        contract: ContractSet,
        *,
        secret_sentinels: Sequence[str] | set[str] | frozenset[str],
        violation_sink: SupervisorViolationSink,
        tracked_paths: tuple[Path, ...] | None = None,
        tracked_symlinks: tuple[tuple[Path, str], ...] = (),
        terminal_timeout_seconds: float = 5.0,
    ) -> None:
        if type(contract) is not ContractSet:
            raise SupervisorError("production finalizer contract is not exact")
        if not secret_sentinels:
            raise SupervisorError("production secret sentinel set is empty")
        if type(violation_sink) is not SupervisorViolationSink:
            raise SupervisorError("production violation sink is not exact")
        _require_cleanup_timeout(terminal_timeout_seconds)
        self._contract = contract
        self._sentinels = frozenset(secret_sentinels)
        self._violation_sink = violation_sink
        if tracked_paths is not None and (
            type(tracked_paths) is not tuple
            or not tracked_paths
            or any(not isinstance(path, Path) for path in tracked_paths)
        ):
            raise SupervisorError("production tracked-file inventory is invalid")
        if type(tracked_symlinks) is not tuple or any(
            type(row) is not tuple
            or len(row) != 2
            or not isinstance(row[0], Path)
            or not _is_git_oid(row[1])
            for row in tracked_symlinks
        ):
            raise SupervisorError("production tracked-symlink inventory is invalid")
        self._tracked_paths = tracked_paths
        self._tracked_symlinks = tracked_symlinks
        self._timeout = float(terminal_timeout_seconds)
        self._invocation: BootstrapInvocation | None = None
        self._state: BootstrapState | None = None
        self._binder: EvidenceBinder | None = None
        self._bundle: EvidenceBundle | None = None
        self._publisher: AuthoritativeResultPublisher | None = None

    def prepare_invocation(self, invocation: BootstrapInvocation) -> None:
        if self._invocation is not None or type(invocation) is not BootstrapInvocation:
            raise SupervisorError("production invocation was already prepared")
        self._invocation = invocation

    def bind_state(self, state: BootstrapState) -> None:
        if self._state is not None or type(state) is not BootstrapState:
            raise SupervisorError("production bootstrap state was already bound")
        self._state = state

    @property
    def bound_bundle(self) -> EvidenceBundle:
        if self._bundle is None:
            raise SupervisorError("production evidence bundle is unavailable")
        return self._bundle

    def evaluate_and_bind(
        self, session: object, accepted: object
    ) -> AuthoritativeEvaluation:
        if type(session) is not TraceSession or self._state is None:
            raise SupervisorError("production finalization session is invalid")
        state = self._state
        trace_path = state.run_root / "trace.ndjson"
        if session.trace_state == "NOT_STARTED" and not trace_path.exists():
            atomic_write_bytes_no_replace(
                trace_path, b"", mode=0o400, relative_to=state.run_root
            )
        if session.trace_state != "NOT_STARTED":
            if session.guard is None:
                raise SupervisorError("started trace has no terminal guard")
            session.guard.wait_terminal(
                timeout_seconds=self._timeout,
                owned_tracees=session.owned_tracees,
            )
        proof = session.finalize_terminal()
        retained_trace = _open_sealed_trace(
            trace_path, allow_empty=session.trace_state == "NOT_STARTED"
        )
        if session.trace_state == "FULL":
            session.finalize_signal_readiness_from_trace(retained_trace)
        exits = (
            (None, None)
            if session.trace_state == "NOT_STARTED"
            else session.guard.exit_codes()
        )
        ledger_document = self._terminal_ledger(state, accepted)
        replay, policy = self._replay_trace(session, retained_trace, accepted)
        state.ownership_journal.seal()
        state.violation_journal.seal()
        self._write_ledger_manifest(state)
        trace_gate, network_gate = self._finalizer_gates(session, exits, policy)
        gates = copy.deepcopy(ledger_document["gates"])
        gates[24] = trace_gate
        gates[25] = network_gate
        gates[26] = _terminal_gate(gates[26], "PASS", "OK")
        trace_runtime = TraceRuntimeEvidence(
            session.trace_state,
            session.tracer_identity,
            session.normalizer_identity,
            exits[0],
            exits[1],
            (
                None
                if session.trace_state == "NOT_STARTED"
                else hashlib.sha256(
                    canonical_json_bytes(self._contract.trace_tool_rows()[0])
                ).hexdigest()
            ),
            None if session.trace_state == "NOT_STARTED" else True,
            (
                "TRACE_BOOTSTRAP_FAILED"
                if session.trace_state == "NOT_STARTED"
                else None
            ),
        )
        context = EvidenceContext(
            trace=trace_runtime,
            trace_policy_replay=replay,
            ledger_contract=self._contract,
            expected_run_id=state.ledger.run_id,
            expected_ledger_nonce=state.ledger.run_nonce,
            marker_token=state.ledger.run_nonce[:12],
            expected_host_observer_identity=_production_host_observer_identity(
                trace_state=session.trace_state,
                live_launch=session._live_launch,
                supervisor_identity=read_process_identity(Path("/proc"), os.getpid()),
            ),
            tracked_paths=(
                self._tracked_paths
                if self._tracked_paths is not None
                else (
                    self._contract.root / "schemas",
                    self._contract.root / "policies",
                )
            ),
            tracked_symlinks=self._tracked_symlinks,
            publication_paths=(
                state.run_root / "result.json",
                state.run_root / "emergency.txt",
            ),
        )
        self._binder = PublicationEvidenceFactory(
            state.run_root,
            context=context,
            result_path=state.run_root / "result.json",
            emergency_path=state.run_root / "emergency.txt",
            secret_sentinels=self._sentinels,
        ).create()
        requirements = _production_artifact_requirements(state.run_root)
        self._bundle = self._binder.bind(requirements)
        trace_artifact = self._bundle.artifacts["trace"]
        if (
            trace_artifact.sha256 != retained_trace.sha256
            or trace_artifact.size != retained_trace.size
            or trace_artifact.inode != retained_trace.inode
            or trace_artifact.device != retained_trace.device
        ):
            raise SupervisorError("bound trace differs from terminal retained trace")
        decision = ResultPolicy(self._contract).decide(
            "workstation_offline",
            gates,
            signal=_authoritative_terminal_signal(state),
        )
        result = self._build_result(state, gates, decision, self._bundle)
        session.accept_terminal_proof(proof, bundle=self._bundle)
        self._publisher = AuthoritativeResultPublisher(
            state.run_root / "result.json",
            contract=self._contract,
            binder=self._binder,
            bundle=self._bundle,
            secret_sentinels=self._sentinels,
        )
        return AuthoritativeEvaluation(result, proof)

    def recover(
        self,
        *,
        stage: str,
        error: BaseException,
        state: object,
        session: object,
        ledger: object,
    ) -> AuthoritativeEvaluation:
        """Recover a committed trace from retained process and ledger authority.

        Recovery is possible only after bootstrap created the immutable root and
        trace launch returned a bound session.  Earlier failures have no stable
        trace identity/evidence set and intentionally fall back to the bounded
        emergency publisher.
        """

        if (
            type(stage) is not str
            or not stage
            or not isinstance(error, BaseException)
            or type(state) is not BootstrapState
            or type(session) is not TraceSession
            or state is not self._state
        ):
            raise SupervisorError("production recovery lacks stable trace authority")
        active = tuple(state.owned_tracees())
        if session.trace_state == "NOT_STARTED":
            cleanup_complete = state.owned_process_controller.cleanup(active)
        else:
            guard = session.guard
            if guard is None:
                raise SupervisorError("production recovery lacks a trace guard")
            cleanup_complete = guard._cleanup_monitor_timeout(active)
        if cleanup_complete is not True or tuple(state.owned_tracees()):
            raise SupervisorError("production recovery cleanup was incomplete")
        self._seal_recovery_ledger(state)
        return self.evaluate_and_bind(session, state.ledger.current)

    @staticmethod
    def _seal_recovery_ledger(state: BootstrapState) -> None:
        if state.ledger.head.sealed:
            gates = state.ledger.current["gates"]
            if gates[23]["status"] != "FAIL":
                raise SupervisorError("sealed ledger cannot record recovery failure")
            return
        gates = copy.deepcopy(state.ledger.current["gates"])
        gates[23] = _terminal_gate(gates[23], "FAIL", "POSTFLIGHT_FAILED")
        window = state.ledger.current["semantic_dds_window"]
        if window == "OPEN":
            window = "CLOSED"
        state.ledger.seal(
            LedgerCandidate(
                generation=state.ledger.head.generation + 1,
                previous_generation=state.ledger.head.generation,
                previous_digest=state.ledger.head.digest,
                run_id=state.ledger.run_id,
                ledger_nonce=state.ledger.run_nonce,
                gates=gates,
                sealed=True,
                semantic_dds_window=window,
            )
        )

    def publish(
        self, result: Mapping[str, object], proof: TraceTerminalProof
    ) -> ArtifactDescriptor:
        if self._publisher is None:
            raise SupervisorError("production result publisher is unavailable")
        return self._publisher.publish(result, proof)

    def publish_emergency(
        self, *, stage: str, safety_gates: Sequence[str] = ()
    ) -> ArtifactDescriptor:
        invocation = self._invocation
        if invocation is None:
            raise SupervisorError("production emergency invocation is unavailable")
        invocation.run_root.mkdir(mode=0o700, parents=False, exist_ok=True)
        publisher = AuthoritativeResultPublisher(
            invocation.run_root / "result.json",
            contract=self._contract,
            binder=_UnavailableEvidenceBinder(),
            bundle=object(),
            secret_sentinels=self._sentinels,
        )
        return publisher.publish_emergency(stage=stage, safety_gates=safety_gates)

    def _terminal_ledger(
        self, state: BootstrapState, accepted: object
    ) -> dict[str, object]:
        if type(accepted) is AcceptedLedgerState:
            if accepted.head.sealed is not True:
                raise SupervisorError("FULL ledger is not sealed")
            return accepted.document
        if type(accepted) is not dict or accepted != state.ledger.current:
            raise SupervisorError("non-FULL ledger state is invalid")
        bootstrap_gates = [copy.deepcopy(gate) for gate in state.decision.gates]
        state.ledger.append(
            LedgerCandidate(
                generation=state.ledger.head.generation + 1,
                previous_generation=state.ledger.head.generation,
                previous_digest=state.ledger.head.digest,
                run_id=state.ledger.run_id,
                ledger_nonce=state.ledger.run_nonce,
                gates=bootstrap_gates,
                sealed=False,
                semantic_dds_window="NOT_ENTERED",
            )
        )
        gates = copy.deepcopy(state.ledger.current["gates"])
        invocation = self._invocation
        if invocation is None:
            raise SupervisorError("non-FULL bootstrap facts are unavailable")
        early_unsafe_fd = (
            not invocation.facts.inherited_fd_safe and gates[2]["status"] == "NOT_RUN"
        )
        postflight_passed = (
            invocation.facts.sanitation_ok
            and not early_unsafe_fd
            and not tuple(state.owned_tracees())
        )
        gates[23] = _terminal_gate(
            gates[23],
            "PASS" if postflight_passed else "FAIL",
            "OK" if postflight_passed else "POSTFLIGHT_FAILED",
        )
        head = state.ledger.seal(
            LedgerCandidate(
                generation=state.ledger.head.generation + 1,
                previous_generation=state.ledger.head.generation,
                previous_digest=state.ledger.head.digest,
                run_id=state.ledger.run_id,
                ledger_nonce=state.ledger.run_nonce,
                gates=gates,
                sealed=True,
                semantic_dds_window="NOT_ENTERED",
            )
        )
        if not head.sealed:
            raise SupervisorError("non-FULL ledger did not seal")
        return state.ledger.current

    def _replay_trace(
        self,
        session: TraceSession,
        retained_trace: _SealedTraceArtifact,
        accepted: object,
    ) -> tuple[TracePolicyReplayEvidence | None, PolicyDecision | None]:
        if session.trace_state == "NOT_STARTED":
            return None, None
        state = self._state
        assert state is not None
        initial_manifest = _trace_policy_initial_manifest(
            state.bootstrap_report["initial_fd_manifest"],
            coordinator_pid=(
                session._live_launch.coordinator_identity.pid
                if session.trace_state == "FULL" and session._live_launch is not None
                else os.getpid()
            ),
        )
        participants = {}
        if session.trace_state == "FULL":
            if type(accepted) is not AcceptedLedgerState:
                raise SupervisorError("FULL trace participant authority is incomplete")
            participants = _participant_policy_authority(accepted.ownership)
        coordinator_pid = next(iter(initial_manifest))
        replay = TracePolicyReplayEvidence(
            coordinator_pid=coordinator_pid,
            participants=participants,
            namespace_loopback_only=True,
            initial_fd_manifest=initial_manifest,
        )
        policy = TracePolicy(
            coordinator_pid=coordinator_pid,
            marker_token=state.ledger.run_nonce[:12],
            participants=participants,
            namespace_loopback_only=True,
            initial_fd_manifest=initial_manifest,
            violation_sink=self._violation_sink,
        )
        for record in _read_canonical_trace(retained_trace):
            policy.feed(record)
        return replay, policy.finalize(trace_integrity_ok=True)

    @staticmethod
    def _write_ledger_manifest(state: BootstrapState) -> None:
        generations = []
        for generation in range(state.ledger.head.generation + 1):
            path = state.run_root / "ledger" / f"generation-{generation:06d}.json"
            value = json.loads(path.read_bytes())
            generations.append(
                {
                    "generation": generation,
                    "relative_path": path.relative_to(state.run_root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size": path.stat().st_size,
                    "previous_generation": value["previous_generation"],
                    "previous_digest": value["previous_digest"],
                    "sealed": value["sealed"],
                }
            )
        atomic_write_json_no_replace(
            state.run_root / "ledger_chain_manifest.json",
            {
                "schema_version": "holoagent0.ledger-chain-manifest.v1",
                "accepted_generation": state.ledger.head.generation,
                "accepted_sha256": state.ledger.head.digest,
                "generation_count": len(generations),
                "generations": generations,
            },
            mode=0o400,
            relative_to=state.run_root,
        )
        state.ledger.close()

    def _finalizer_gates(
        self,
        session: TraceSession,
        exits: tuple[int | None, int | None],
        policy: PolicyDecision | None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        trace = _gate_skeleton()[24]
        network = _gate_skeleton()[25]
        safety_reason = self._violation_sink.primary_network_reason()
        if session.trace_state == "NOT_STARTED":
            return (
                _terminal_gate(trace, "FAIL", "TRACE_BOOTSTRAP_FAILED"),
                _terminal_gate(
                    network,
                    "FAIL" if safety_reason is not None else "SKIPPED",
                    safety_reason or "DEPENDENCY_NOT_AVAILABLE",
                ),
            )
        if exits[0] != 0:
            trace = _terminal_gate(trace, "FAIL", "TRACER_EXITED")
        elif exits[1] != 0:
            trace = _terminal_gate(trace, "FAIL", "TRACE_DECODE_FAILED")
        elif policy is None or policy.status == "SKIPPED":
            trace = _terminal_gate(trace, "FAIL", "TRACE_INCOMPLETE")
        else:
            trace = _terminal_gate(trace, "PASS", "OK")
        if safety_reason is not None:
            network = _terminal_gate(network, "FAIL", safety_reason)
        elif trace["status"] == "PASS":
            network = _terminal_gate(network, "PASS", "OK")
        else:
            network = _terminal_gate(network, "SKIPPED", "DEPENDENCY_NOT_AVAILABLE")
        return trace, network

    def _build_result(
        self,
        state: BootstrapState,
        gates: list[dict[str, object]],
        decision: object,
        bundle: EvidenceBundle,
    ) -> dict[str, object]:
        ended = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        root = self._contract.root
        digests = copy.deepcopy(self._contract._digests)
        trace_row = self._contract.trace_tool_rows()[0]
        source_manifest = root / "test-manifest-v1.txt"
        source_manifest_sha = hashlib.sha256(
            source_manifest.read_bytes() if source_manifest.exists() else b""
        ).hexdigest()
        result = {
            "schema_version": "holoagent0.result.v1",
            "run_id": state.ledger.run_id,
            "mode": "workstation_offline",
            "label": decision.label,
            "status": decision.status,
            "exit_class": decision.exit_class,
            "process_exit_code": decision.exit_code,
            "started_at": state.started_at,
            "ended_at": ended,
            "duration_monotonic_seconds": max(
                0.0, time.monotonic() - state.started_monotonic
            ),
            "hostname": os.uname().nodename,
            "architecture": os.uname().machine,
            "source_commit": _source_commit(),
            "redacted_environment": {
                "network_namespace": str(Path("/proc/self/ns/net").resolve()),
                "ros_domain_id": 77,
                "ros_localhost_only": True,
                "credential_variables_present": sorted(
                    key
                    for key in os.environ
                    if any(
                        marker in key.upper() for marker in ("KEY", "TOKEN", "SECRET")
                    )
                ),
                "proxy_variables_present": sorted(
                    key
                    for key in os.environ
                    if key.upper()
                    in {"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
                ),
            },
            "prohibited_commands": list(_MOTION_EXECUTABLES),
            **digests,
            "trace_parser_fixture_manifest_sha256": trace_row["fixtures"][
                "manifest_sha256"
            ],
            "cyclonedds_config_set_sha256": CONFIG_SET_SHA256,
            "source_manifest_sha256": source_manifest_sha,
            "configuration_sha256": CONFIG_SET_SHA256,
            "graph_sha256": self._GRAPH_SHA256,
            "dataset_sha256": self._DATASET_SHA256,
            "checkpoint_sha256": self._CHECKPOINT_SHA256,
            "invocation_role": "standalone",
            "parent_run_id": None,
            "lineage_nonce": None,
            "gates": gates,
            "primary_blocking_gate": decision.primary,
            "blocking_gates": list(decision.blocking_gates),
            "qualifications": list(decision.qualifications),
            "offline_evidence_bundle_sha256": bundle.bundle_sha256,
            "offline_evidence": bundle.as_result_evidence(),
        }
        return result


class _UnavailableEvidenceBinder:
    def revalidate(self, _bundle: object) -> None:
        raise SupervisorError("emergency output has no evidence bundle")

    freeze_for_publication = revalidate
    register_publication_temporary = revalidate
    revalidate_for_publication = revalidate


def _sealed_ledger_safety_gates(state: object) -> tuple[str, ...]:
    """Retain safety precedence from the already sealed coordinator ledger."""

    ledger = getattr(state, "ledger", None)
    head = getattr(ledger, "head", None)
    if getattr(head, "sealed", None) is not True:
        return ()
    try:
        document = ledger.current
    except Exception:
        return ()
    if type(document) is not dict:
        return ()
    gates = document.get("gates")
    if type(gates) is not list or len(gates) != len(OFFLINE_GATE_ORDER):
        return ()
    retained: list[str] = []
    for expected_id, gate in zip(OFFLINE_GATE_ORDER, gates, strict=True):
        if type(gate) is not dict or gate.get("id") != expected_id:
            return ()
        if gate.get("status") != "FAIL":
            continue
        if expected_id.startswith("safety.") or expected_id == "offline.network_policy":
            retained.append(expected_id)
    return tuple(retained)


class EvidenceSupervisor:
    """Apply bootstrap/finalizer authority and select the precedence outcome."""

    def __init__(
        self,
        *,
        bootstrap_engine: object | None = None,
        trace_runtime: object | None = None,
        ledger_broker: object | None = None,
        finalizers: object | None = None,
        result_publisher: object | None = None,
        safety_facts: SupervisorViolationSink | None = None,
        trace_monitor_timeout_seconds: float = 30.0,
        network_boundary: object | None = None,
    ) -> None:
        dependencies = (
            bootstrap_engine,
            trace_runtime,
            ledger_broker,
            finalizers,
            result_publisher,
        )
        if any(item is not None for item in dependencies) and any(
            item is None for item in dependencies
        ):
            raise SupervisorError("authoritative execution dependencies are incomplete")
        self._bootstrap_engine = bootstrap_engine
        self._trace_runtime = trace_runtime
        self._ledger_broker = ledger_broker
        self._finalizers = finalizers
        self._result_publisher = result_publisher
        if (
            safety_facts is not None
            and type(safety_facts) is not SupervisorViolationSink
        ):
            raise SupervisorError("supervisor safety facts are not exact")
        self._safety_facts = safety_facts
        _require_cleanup_timeout(trace_monitor_timeout_seconds)
        self._trace_monitor_timeout_seconds = float(trace_monitor_timeout_seconds)
        if network_boundary is not None and (
            not callable(getattr(network_boundary, "install_audit", None))
            or not callable(getattr(network_boundary, "install_seccomp", None))
        ):
            raise SupervisorError("supervisor network boundary is incomplete")
        self._network_boundary = network_boundary

    @classmethod
    def production(
        cls,
        contract: ContractSet,
        *,
        trace_launcher: Callable[
            ["TraceLaunchSpec"],
            tuple[ProcessIdentity, ProcessIdentity] | LiveTraceLaunchOutcome,
        ],
        signal_forwarder: Callable[[int, str], object],
        signal_identity_validator: Callable[[ProcessIdentity], bool],
        secret_sentinels: Sequence[str] | set[str] | frozenset[str],
        readiness_timeout_seconds: float = 5.0,
        trace_monitor_timeout_seconds: float = 30.0,
        process_operations: object | None = None,
    ) -> "EvidenceSupervisor":
        """Compose the concrete Task 8 authorities without asserting outcomes.

        The launcher supplies process identities and reviewed pipe endpoints;
        it does not supply policy decisions, exit statuses, evidence digests,
        gates, or a result.  Those remain supervisor-derived.  With the
        repository's intentionally pending trace-tool row, the bootstrap
        adapter deterministically selects the fail-closed NOT_STARTED path and
        never calls ``trace_launcher``.
        """

        if type(contract) is not ContractSet or not callable(trace_launcher):
            raise SupervisorError("production supervisor inputs are invalid")
        controller = OwnedProcessController(process_operations)
        deferred_violations = _DeferredViolationJournal()
        safety_facts = SupervisorViolationSink(deferred_violations)
        tracked_inventory = _load_git_tracked_manifest(
            contract.root, secret_sentinels=frozenset(secret_sentinels)
        )
        finalizers = ProductionMandatoryFinalizers(
            contract,
            secret_sentinels=secret_sentinels,
            violation_sink=safety_facts,
            tracked_paths=tracked_inventory.regular_paths,
            tracked_symlinks=tracked_inventory.symlinks,
        )
        bootstrap = _ProductionBootstrapAdapter(
            BootstrapRuntime.production(
                contract,
                signal_forwarder=signal_forwarder,
                signal_identity_validator=signal_identity_validator,
                owned_process_controller=controller,
            ),
            contract,
            deferred_violations,
            finalizers,
        )
        trace_runtime = TraceLaunchRuntime(
            contract,
            launcher=trace_launcher,
            operations=process_operations,
            cleanup=controller,
            readiness_timeout_seconds=readiness_timeout_seconds,
        )
        broker = ConcurrentSupervisorBrokerRuntime(owned_process_controller=controller)
        return cls(
            bootstrap_engine=bootstrap,
            trace_runtime=trace_runtime,
            ledger_broker=broker,
            finalizers=finalizers,
            result_publisher=finalizers,
            safety_facts=safety_facts,
            trace_monitor_timeout_seconds=trace_monitor_timeout_seconds,
            network_boundary=SupervisorNetworkBoundary.production(safety_facts),
        )

    def execute_authoritative(self, invocation: object) -> int:
        """Run the closed authority pipeline and publish only its final output."""

        if self._bootstrap_engine is None:
            raise SupervisorError(
                "authoritative execution dependencies are unavailable"
            )
        state = None
        session = None
        ledger = None
        stage = "bootstrap"
        evaluation: AuthoritativeEvaluation | None = None
        emergency_stage: str | None = None
        try:
            try:
                if self._network_boundary is not None:
                    self._network_boundary.install_audit()
                state = self._bootstrap_engine.run(invocation)
                stage = "trace_launch"
                session = self._trace_runtime.launch(state)
                if self._network_boundary is not None:
                    self._network_boundary.install_seccomp()
                stage = "ledger_collect"
                ledger = self._collect_ledger_with_trace_monitor(session)
            except Exception as error:
                recover = getattr(self._finalizers, "recover", None)
                if not callable(recover):
                    raise SupervisorError(
                        "pre-finalizer failure has no mandatory recovery path"
                    ) from error
                try:
                    evaluation = recover(
                        stage=stage,
                        error=error,
                        state=state,
                        session=session,
                        ledger=ledger,
                    )
                except Exception:
                    emergency_stage = "finalizer_recovery"
            else:
                try:
                    evaluation = self._finalizers.evaluate_and_bind(session, ledger)
                except Exception:
                    emergency_stage = "finalizer_evaluation"
            if (
                emergency_stage is None
                and type(evaluation) is not AuthoritativeEvaluation
            ):
                emergency_stage = "finalizer_evaluation"
            if not self._finalize_signal_runtime_before_publication(state):
                emergency_stage = "signal_runtime_finalization"
            if emergency_stage is not None:
                return self._publish_emergency(emergency_stage, evaluation, state=state)
            assert evaluation is not None
            try:
                self._result_publisher.publish(
                    evaluation.result, evaluation.trace_terminal_proof
                )
            except Exception:
                return self._publish_emergency(
                    "result_publication", evaluation, state=state
                )
            return evaluation.process_exit
        finally:
            signal_runtime = getattr(state, "signal_runtime", None)
            if (
                type(signal_runtime) is SupervisorSignalRuntime
                and signal_runtime._started
            ):
                try:
                    signal_runtime.close(restore_mask=True)
                except Exception:
                    # Publication never precedes the mandatory close attempt.
                    # This is only a best-effort retry after emergency selection.
                    pass

    @staticmethod
    def _finalize_signal_runtime_before_publication(state: object) -> bool:
        signal_runtime = getattr(state, "signal_runtime", None)
        if type(signal_runtime) is not SupervisorSignalRuntime:
            return True
        if not signal_runtime._started:
            return True
        try:
            signal_runtime.close(restore_mask=True)
        except Exception:
            return False
        return signal_runtime._started is False

    def _collect_ledger_with_trace_monitor(self, session: object) -> object:
        collect = getattr(self._ledger_broker, "collect", None)
        monitor = getattr(session, "monitor", None)
        if not callable(collect):
            raise SupervisorError("ledger collector is unavailable")
        if (
            not callable(monitor)
            or getattr(session, "trace_state", None) == "NOT_STARTED"
        ):
            return collect(session)

        completed = Event()
        outcome: dict[str, object] = {}

        def collect_worker() -> None:
            try:
                outcome["ledger"] = collect(session)
            except BaseException as error:
                outcome["error"] = error
            finally:
                completed.set()

        worker = Thread(
            target=collect_worker,
            name="holoagent0-ledger-collector",
            daemon=False,
        )
        worker.start()
        monitor_error: BaseException | None = None
        loss: object | None = None
        try:
            loss = monitor(
                completed.is_set,
                timeout_seconds=self._trace_monitor_timeout_seconds,
            )
        except BaseException as error:
            monitor_error = error
        worker.join(timeout=self._trace_monitor_timeout_seconds)
        if worker.is_alive():
            raise SupervisorError(
                "ledger collection remained live after trace cleanup"
            ) from monitor_error
        if monitor_error is not None:
            raise SupervisorError(
                "trace monitor failed during ledger collection"
            ) from monitor_error
        if loss is not None:
            reason = getattr(loss, "reason", "TRACE_INCOMPLETE")
            cleanup_complete = getattr(loss, "cleanup_complete", False)
            raise SupervisorError(
                f"trace runtime was lost during ledger collection: {reason}; "
                f"cleanup_complete={cleanup_complete}"
            )
        if "error" in outcome:
            raise SupervisorError("ledger collection failed") from outcome["error"]
        if "ledger" not in outcome:
            raise SupervisorError("ledger collection produced no terminal state")
        return outcome["ledger"]

    def _publish_emergency(
        self,
        stage: str,
        evaluation: AuthoritativeEvaluation | None,
        *,
        state: object | None = None,
    ) -> int:
        safety_gates: tuple[str, ...] = ()
        durable_safety = (
            () if self._safety_facts is None else self._safety_facts.snapshot()
        )
        if evaluation is not None:
            result = evaluation.result
            gates = result.get("gates", [])
            if type(gates) is list:
                safety_gates = tuple(
                    gate.get("id")
                    for gate in gates
                    if type(gate) is dict
                    and gate.get("status") == "FAIL"
                    and (
                        str(gate.get("id", "")).startswith("safety.")
                        or gate.get("id") == "offline.network_policy"
                    )
                )
        sealed_ledger_safety = _sealed_ledger_safety_gates(state)
        safety_gates = tuple(
            dict.fromkeys((*durable_safety, *sealed_ledger_safety, *safety_gates))
        )
        publisher = getattr(self._result_publisher, "publish_emergency", None)
        if not callable(publisher):
            raise SupervisorError("bounded emergency publisher is unavailable")
        try:
            publisher(stage=stage, safety_gates=safety_gates)
        except Exception as error:
            raise SupervisorError("bounded emergency publication failed") from error
        return 30 if safety_gates else 40

    def run(self, scenario: SupervisorScenario) -> SupervisorRunResult:
        if type(scenario) is not SupervisorScenario:
            raise SupervisorError("supervisor scenario object is not exact")
        decision = BootstrapEngine().evaluate(
            scenario.bootstrap, precommit_signal=scenario.precommit_signal
        )
        gates = [dict(gate) for gate in decision.gates]
        functional_started = decision.coordinator_launch_committed
        progress_stopped = False

        if decision.launch_state == "PRE_COORDINATOR_INTERRUPTED":
            _apply_nonfull_finalizers(gates, decision, scenario)
            return _classify(
                decision,
                gates,
                functional_started=False,
                progress_stopped=False,
            )

        if decision.launch_state != "COORDINATOR_LAUNCH_COMMITTED":
            _apply_nonfull_finalizers(gates, decision, scenario)
            return _classify(
                decision,
                gates,
                functional_started=False,
                progress_stopped=False,
            )

        for index in range(23):
            _set_gate(gates, index, "PASS", "OK")

        ledger_failed = scenario.ledger_state != "SEALED_PASS"
        live_trace_failure = scenario.trace_fault is not None and scenario.tracees_live
        postflight_failed = (
            ledger_failed or live_trace_failure or not scenario.cleanup_complete
        )
        if postflight_failed:
            reason = (
                "LEDGER_CHAIN_INVALID"
                if scenario.ledger_state in {"WRONG_NONCE", "INVALID_CHAIN"}
                else "POSTFLIGHT_FAILED"
            )
            _set_gate(gates, 23, "FAIL", reason)
            progress_stopped = live_trace_failure
        else:
            _set_gate(gates, 23, "PASS", "OK")

        if scenario.trace_fault is None:
            _set_gate(gates, 24, "PASS", "OK")
        else:
            _set_gate(gates, 24, "FAIL", scenario.trace_fault)

        if scenario.network_violation is not None:
            _set_gate(gates, 25, "FAIL", scenario.network_violation)
        elif scenario.trace_fault is None:
            _set_gate(gates, 25, "PASS", "OK")
        else:
            _set_gate(gates, 25, "SKIPPED", "DEPENDENCY_NOT_AVAILABLE")

        _set_gate(
            gates,
            26,
            "PASS" if scenario.evidence_binding_ok else "FAIL",
            "OK" if scenario.evidence_binding_ok else "EVIDENCE_BINDING_MISMATCH",
        )
        return _classify(
            decision,
            gates,
            functional_started=functional_started,
            progress_stopped=progress_stopped,
        )


class SupervisorLedgerBroker:
    """Own Task 3 persistence and acknowledge only durable candidate installs."""

    def __init__(
        self,
        store: LedgerStore,
        *,
        candidate_read_fd: int,
        acceptance_write_fd: int,
        deadline: int | float | None = None,
    ) -> None:
        if type(store) is not LedgerStore:
            raise SupervisorError("Task 3 ledger store is not exact")
        if (
            type(candidate_read_fd) is not int
            or candidate_read_fd < 0
            or type(acceptance_write_fd) is not int
            or acceptance_write_fd < 0
            or candidate_read_fd == acceptance_write_fd
        ):
            raise SupervisorError("ledger broker descriptors are invalid")
        self._store = store
        self._candidate_read_fd = candidate_read_fd
        self._acceptance_write_fd = acceptance_write_fd
        self._deadline = deadline
        self._next_sequence = 1
        self._pending_request: bytes | None = None
        self._pending_head: LedgerHead | None = None
        self._pending_acknowledgement: dict[str, object] | None = None

    def serve_once(self) -> LedgerHead:
        if self._store.head.sealed and self._pending_request is None:
            raise SupervisorError("sealed ledger cannot accept another candidate")

        def schema_valid(value: dict[str, object]) -> bool:
            return self._store.contract.validate_document(
                "holoagent0-offline-ledger-v1", value
            ).ok

        try:
            message = read_frame(
                self._candidate_read_fd,
                deadline=self._deadline,
                exact_one=False,
                ledger_validator=schema_valid,
            )
        except (BrokerProtocolError, OSError) as error:
            raise SupervisorError("ledger candidate receive failed") from error
        candidate_value = message.get("candidate")
        request_bytes = canonical_json_bytes(message)
        if (
            message.get("type") != MessageType.LEDGER_CANDIDATE.value
            or message.get("run_nonce") != self._store.run_nonce
            or message.get("sequence") != self._next_sequence
            or type(candidate_value) is not dict
        ):
            raise SupervisorError("ledger candidate binding mismatch")
        if self._pending_request is not None:
            if (
                request_bytes != self._pending_request
                or self._pending_head is None
                or self._pending_acknowledgement is None
            ):
                raise SupervisorError("ledger acknowledgement retry mismatch")
            head = self._pending_head
            acknowledgement = self._pending_acknowledgement
        else:
            try:
                candidate = LedgerCandidate(
                    generation=candidate_value["generation"],
                    previous_generation=candidate_value["previous_generation"],
                    previous_digest=candidate_value["previous_digest"],
                    run_id=candidate_value["run_id"],
                    ledger_nonce=candidate_value["ledger_nonce"],
                    gates=candidate_value["gates"],
                    sealed=candidate_value["sealed"],
                    semantic_dds_window=candidate_value["semantic_dds_window"],
                )
                head = (
                    self._store.seal(candidate)
                    if candidate.sealed
                    else self._store.append(candidate)
                )
            except (KeyError, LedgerChainError, TypeError) as error:
                raise SupervisorError(
                    "ledger candidate was not durably accepted"
                ) from error
            acknowledgement = {
                "type": MessageType.LEDGER_ACCEPTED.value,
                "run_nonce": self._store.run_nonce,
                "sequence": self._next_sequence,
                "generation": head.generation,
                "ledger_sha256": head.digest,
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            }
            self._pending_request = request_bytes
            self._pending_head = head
            self._pending_acknowledgement = acknowledgement
        try:
            write_frame(
                self._acceptance_write_fd,
                acknowledgement,
                deadline=self._deadline,
            )
        except (BrokerProtocolError, OSError) as error:
            raise SupervisorError("ledger acknowledgement write failed") from error
        self._pending_request = None
        self._pending_head = None
        self._pending_acknowledgement = None
        self._next_sequence += 1
        return head

    def serve_acknowledged(self, *, max_attempts: int = 2) -> LedgerHead:
        if type(max_attempts) is not int or not 1 <= max_attempts <= 2:
            raise SupervisorError("ledger acknowledgement retry bound is invalid")
        last_error: SupervisorError | None = None
        for _attempt in range(max_attempts):
            try:
                return self.serve_once()
            except SupervisorError as error:
                if self._pending_request is None:
                    raise
                last_error = error
        raise SupervisorError("ledger acknowledgement retry failed") from last_error

    def serve_until_sealed(self, *, max_generations: int = 64) -> dict[str, object]:
        if type(max_generations) is not int or not 1 <= max_generations <= 64:
            raise SupervisorError("ledger broker generation bound is invalid")
        for _ in range(max_generations):
            head = self.serve_acknowledged()
            if head.sealed:
                return self._store.current
        raise SupervisorError("ledger did not seal within the generation bound")


@dataclass(frozen=True)
class ParticipantOwnership:
    """Externally validated participant authority bound before DDS release."""

    identity: ProcessIdentity
    participant_index: int
    role: str
    config_digest: str
    lease: "OwnedProcessLease"

    def __post_init__(self) -> None:
        index = self.participant_index
        if (
            type(self.identity) is not ProcessIdentity
            or type(index) is not int
            or index not in range(4)
            or self.role != CONFIG_ROLES[index]
            or self.config_digest != EXPECTED_CONFIG_SHA256[index]
            or type(self.lease) is not OwnedProcessLease
            or self.lease.identity != self.identity
        ):
            raise SupervisorError("participant ownership binding is invalid")


@dataclass(frozen=True)
class AcceptedOwnershipState:
    """The sole participant authority accepted from the reviewed broker pipe."""

    action_lease: "OwnedProcessLease"
    participants: tuple[ParticipantOwnership, ...]

    def __post_init__(self) -> None:
        if (
            type(self.action_lease) is not OwnedProcessLease
            or type(self.participants) is not tuple
            or len(self.participants) != 4
            or tuple(item.participant_index for item in self.participants)
            != tuple(range(4))
            or len(
                {
                    self.action_lease.identity.pid,
                    *(item.identity.pid for item in self.participants),
                }
            )
            != 5
        ):
            raise SupervisorError("accepted ownership state is incomplete")


def _participant_policy_authority(
    ownership: AcceptedOwnershipState,
) -> dict[int, dict[str, object]]:
    if type(ownership) is not AcceptedOwnershipState:
        raise SupervisorError("participant policy authority is not broker-accepted")
    return {
        item.identity.pid: {
            "index": item.participant_index,
            "config_digest": item.config_digest,
        }
        for item in ownership.participants
    }


def _participant_is_stopped(identity: ProcessIdentity) -> bool:
    """Observe the exact identity in Linux signal/ptrace-stop before acceptance."""

    if type(identity) is not ProcessIdentity or not identity.matches_proc():
        return False
    try:
        raw = Path(f"/proc/{identity.pid}/stat").read_text(encoding="ascii")
        closing = raw.rfind(")")
        state = raw[closing + 2 :].split(maxsplit=1)[0]
    except (OSError, UnicodeError, IndexError):
        return False
    return state in {"T", "t"} and identity.matches_proc()


class SupervisorOwnershipBroker:
    """Append ownership records durably before returning a bound acknowledgement."""

    def __init__(
        self,
        journal: object,
        *,
        run_nonce: str,
        record_read_fd: int,
        acceptance_write_fd: int,
        owned_process_controller: "OwnedProcessController",
        participant_identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        deadline: int | float | None = None,
    ) -> None:
        if not callable(getattr(journal, "append", None)):
            raise SupervisorError("ownership journal is incomplete")
        if type(run_nonce) is not str or not run_nonce:
            raise SupervisorError("ownership run nonce is invalid")
        if (
            type(record_read_fd) is not int
            or record_read_fd < 0
            or type(acceptance_write_fd) is not int
            or acceptance_write_fd < 0
            or record_read_fd == acceptance_write_fd
        ):
            raise SupervisorError("ownership broker descriptors are invalid")
        self._journal = journal
        if type(owned_process_controller) is not OwnedProcessController:
            raise SupervisorError("ownership controller is not exact")
        self._owned_process_controller = owned_process_controller
        validator = participant_identity_validator or _participant_is_stopped
        if not callable(validator):
            raise SupervisorError("participant stopped-state validator is invalid")
        self._participant_identity_validator = validator
        self._run_nonce = run_nonce
        self._record_read_fd = record_read_fd
        self._acceptance_write_fd = acceptance_write_fd
        self._deadline = deadline
        self._next_sequence = 1
        self._pending_request: bytes | None = None
        self._pending_lease: OwnedProcessLease | None = None
        self._pending_participant: ParticipantOwnership | None = None
        self._pending_acknowledgement: dict[str, object] | None = None
        self._action_lease: OwnedProcessLease | None = None
        self._participants: list[ParticipantOwnership] = []
        self._registered_pids: set[int] = set()
        self._complete = False

    def serve_once(self) -> "OwnedProcessLease | ParticipantOwnership":
        if self._complete:
            raise SupervisorError("ownership registration is already complete")
        try:
            message = read_frame(
                self._record_read_fd,
                deadline=self._deadline,
                exact_one=False,
            )
        except (BrokerProtocolError, OSError) as error:
            raise SupervisorError("ownership record receive failed") from error
        expected_participant_index = self._next_sequence - 2
        action_record = self._next_sequence == 1
        if (
            message.get("run_nonce") != self._run_nonce
            or message.get("sequence") != self._next_sequence
            or (
                action_record
                and (
                    message.get("type") != MessageType.OWNERSHIP_RECORD.value
                    or message.get("role") != "action_child"
                )
            )
            or (
                not action_record
                and (
                    expected_participant_index not in range(4)
                    or message.get("type") != MessageType.PARTICIPANT_RECORD.value
                    or message.get("participant_index") != expected_participant_index
                    or message.get("role") != CONFIG_ROLES[expected_participant_index]
                    or message.get("config_digest")
                    != EXPECTED_CONFIG_SHA256[expected_participant_index]
                )
            )
        ):
            raise SupervisorError("ownership record binding mismatch")
        request_bytes = canonical_json_bytes(message)
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        try:
            if self._pending_request is not None:
                if (
                    request_bytes != self._pending_request
                    or self._pending_lease is None
                    or self._pending_acknowledgement is None
                ):
                    raise SupervisorError("ownership acknowledgement retry mismatch")
                lease = self._pending_lease
                participant = self._pending_participant
                acknowledgement = self._pending_acknowledgement
            else:
                identity = ProcessIdentity.from_dict(message["identity"])
                if identity.pid in self._registered_pids:
                    raise SupervisorError("ownership identities are not distinct")
                if (
                    not action_record
                    and self._participant_identity_validator(identity) is not True
                ):
                    raise SupervisorError(
                        "participant identity was not externally stopped"
                    )
                lease = self._owned_process_controller.acquire(identity)
                if (
                    not action_record
                    and self._participant_identity_validator(identity) is not True
                ):
                    raise SupervisorError(
                        "participant identity changed or resumed before acceptance"
                    )
                participant = None
                payload = {
                    "identity": identity.as_dict(),
                    "role": message["role"],
                    "request_sha256": request_sha256,
                }
                accepted_type = MessageType.OWNERSHIP_ACCEPTED
                if not action_record:
                    participant = ParticipantOwnership(
                        identity,
                        expected_participant_index,
                        message["role"],
                        message["config_digest"],
                        lease,
                    )
                    payload.update(
                        participant_index=expected_participant_index,
                        config_digest=message["config_digest"],
                    )
                    accepted_type = MessageType.PARTICIPANT_ACCEPTED
                self._journal.append(
                    "OWNERSHIP_RECORD" if action_record else "PARTICIPANT_RECORD",
                    payload,
                )
                acknowledgement = {
                    "type": accepted_type.value,
                    "run_nonce": self._run_nonce,
                    "sequence": self._next_sequence,
                    "request_sha256": request_sha256,
                }
                self._pending_request = request_bytes
                self._pending_lease = lease
                self._pending_participant = participant
                self._pending_acknowledgement = acknowledgement
            write_frame(
                self._acceptance_write_fd,
                acknowledgement,
                deadline=self._deadline,
            )
        except SupervisorError:
            raise
        except Exception as error:
            raise SupervisorError(
                "ownership record was not durably accepted"
            ) from error
        self._pending_request = None
        self._pending_lease = None
        self._pending_participant = None
        self._pending_acknowledgement = None
        self._registered_pids.add(lease.identity.pid)
        if action_record:
            self._action_lease = lease
        else:
            assert participant is not None
            self._participants.append(participant)
        self._next_sequence += 1
        if self._next_sequence == 6:
            self._complete = True
        return lease if action_record else participant

    def serve_acknowledged(
        self, *, max_attempts: int = 2
    ) -> "OwnedProcessLease | ParticipantOwnership":
        if type(max_attempts) is not int or not 1 <= max_attempts <= 2:
            raise SupervisorError("ownership acknowledgement retry bound is invalid")
        last_error: SupervisorError | None = None
        for _attempt in range(max_attempts):
            try:
                return self.serve_once()
            except SupervisorError as error:
                if self._pending_request is None:
                    raise
                last_error = error
        raise SupervisorError("ownership acknowledgement retry failed") from last_error

    def serve_until_complete(self) -> AcceptedOwnershipState:
        while not self._complete:
            self.serve_acknowledged()
        if self._action_lease is None:
            raise SupervisorError("ownership registration is incomplete")
        return AcceptedOwnershipState(
            self._action_lease,
            tuple(self._participants),
        )


@dataclass(frozen=True)
class ProductionBrokerChannels:
    candidate_read_fd: int
    ledger_acceptance_write_fd: int
    ownership_read_fd: int
    ownership_acceptance_write_fd: int

    def __post_init__(self) -> None:
        if (
            any(type(fd) is not int or fd < 0 for fd in self.descriptors)
            or len(set(self.descriptors)) != 4
        ):
            raise SupervisorError("production broker channels are invalid")

    @property
    def descriptors(self) -> tuple[int, int, int, int]:
        return (
            self.candidate_read_fd,
            self.ledger_acceptance_write_fd,
            self.ownership_read_fd,
            self.ownership_acceptance_write_fd,
        )


@dataclass(frozen=True)
class AcceptedLedgerState:
    document: dict[str, object]
    head: LedgerHead
    ownership: AcceptedOwnershipState

    def __post_init__(self) -> None:
        if (
            type(self.document) is not dict
            or type(self.head) is not LedgerHead
            or self.head.sealed is not True
            or type(self.ownership) is not AcceptedOwnershipState
        ):
            raise SupervisorError("accepted ledger state is invalid")


class ConcurrentSupervisorBrokerRuntime:
    """Serve the coordinator's ledger and ownership pipes concurrently."""

    def __init__(
        self,
        *,
        store: LedgerStore | None = None,
        ownership_journal: object | None = None,
        owned_process_controller: "OwnedProcessController | None" = None,
        channels: ProductionBrokerChannels | None = None,
        deadline: int | float | None = None,
    ) -> None:
        if store is not None and type(store) is not LedgerStore:
            raise SupervisorError("production ledger store is not exact")
        if ownership_journal is not None and not callable(
            getattr(ownership_journal, "append", None)
        ):
            raise SupervisorError("production ownership journal is incomplete")
        if (
            owned_process_controller is not None
            and type(owned_process_controller) is not OwnedProcessController
        ):
            raise SupervisorError("production ownership controller is not exact")
        if channels is not None and type(channels) is not ProductionBrokerChannels:
            raise SupervisorError("production broker channels are not exact")
        self._store = store
        self._ownership_journal = ownership_journal
        self._controller = owned_process_controller
        self._channels = channels
        self._deadline = deadline

    def collect(self, session: object | None = None) -> AcceptedLedgerState:
        store = self._store
        journal = self._ownership_journal
        controller = self._controller
        channels = self._channels
        if session is not None:
            if type(session) is not TraceSession:
                raise SupervisorError("production broker session is not exact")
            state = session._bootstrap_state
            launch = session._live_launch
            if state is None:
                raise SupervisorError("production broker session is unbound")
            store = state.ledger
            journal = state.ownership_journal
            controller = state.owned_process_controller
            if session.trace_state != "FULL":
                return store.current
            if launch is None:
                raise SupervisorError("FULL production broker launch is unbound")
            channels = launch.broker_channels
        if (
            type(store) is not LedgerStore
            or journal is None
            or type(controller) is not OwnedProcessController
            or type(channels) is not ProductionBrokerChannels
        ):
            raise SupervisorError("production broker runtime is incomplete")
        ledger_broker = SupervisorLedgerBroker(
            store,
            candidate_read_fd=channels.candidate_read_fd,
            acceptance_write_fd=channels.ledger_acceptance_write_fd,
            deadline=self._deadline,
        )
        ownership_broker = SupervisorOwnershipBroker(
            journal,
            run_nonce=store.run_nonce,
            record_read_fd=channels.ownership_read_fd,
            acceptance_write_fd=channels.ownership_acceptance_write_fd,
            owned_process_controller=controller,
            deadline=self._deadline,
        )
        ownership: dict[str, object] = {}
        completed = Event()

        def serve_ownership() -> None:
            try:
                ownership["state"] = ownership_broker.serve_until_complete()
            except BaseException as error:
                ownership["error"] = error
            finally:
                completed.set()

        worker = Thread(
            target=serve_ownership,
            name="holoagent0-ownership-broker",
            daemon=False,
        )
        worker.start()
        ledger_error: BaseException | None = None
        document: dict[str, object] | None = None
        try:
            document = ledger_broker.serve_until_sealed()
        except BaseException as error:
            ledger_error = error
        worker.join(timeout=5.0)
        if worker.is_alive():
            raise SupervisorError("ownership broker did not terminate")
        if "error" in ownership:
            raise SupervisorError("ownership broker collection failed") from ownership[
                "error"
            ]
        if ledger_error is not None:
            raise SupervisorError("ledger broker collection failed") from ledger_error
        accepted_ownership = ownership.get("state")
        if document is None or type(accepted_ownership) is not AcceptedOwnershipState:
            raise SupervisorError("broker collection produced no accepted state")
        return AcceptedLedgerState(document, store.head, accepted_ownership)


def _require_cleanup_timeout(timeout_seconds: float) -> None:
    if (
        type(timeout_seconds) not in {int, float}
        or not 0 <= float(timeout_seconds) <= 30
    ):
        raise SupervisorError("owned-process wait deadline is invalid")


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as error:
        if error.errno == errno.ESRCH:
            return False
        if error.errno == errno.EPERM:
            return True
        raise SupervisorError("owned process-group probe failed") from error
    return True


class LinuxProcessOperations:
    """Linux pidfd operations with full identity checks around acquisition."""

    def __init__(self) -> None:
        self._pidfd_identities: dict[int, ProcessIdentity] = {}
        self._reaped_groups: dict[int, int] = {}
        self._exit_codes: dict[ProcessIdentity, int] = {}

    def open_pidfd(self, identity: ProcessIdentity) -> int:
        if type(identity) is not ProcessIdentity or not identity.matches_proc():
            raise SupervisorError("process identity mismatch before pidfd_open")
        if not hasattr(os, "pidfd_open"):
            raise SupervisorError("pidfd_open is unavailable")
        try:
            pidfd = os.pidfd_open(identity.pid, 0)
        except OSError as error:
            raise SupervisorError("pidfd_open failed") from error
        if not identity.matches_proc():
            os.close(pidfd)
            raise SupervisorError("process identity changed during pidfd_open")
        if pidfd in self._pidfd_identities:
            os.close(pidfd)
            raise SupervisorError("pidfd registration collided")
        self._pidfd_identities[pidfd] = identity
        return pidfd

    @staticmethod
    def identity_matches(identity: ProcessIdentity) -> bool:
        return identity.matches_proc()

    @staticmethod
    def group_identity_matches(identity: ProcessIdentity) -> bool:
        return identity.pid == identity.pgid and identity.matches_coordinator_session()

    def is_alive(self, pidfd: int) -> bool:
        self._require_bound_pidfd(pidfd)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not poller.poll(0)

    def send_signal(self, pidfd: int, signal_number: int) -> None:
        self._require_bound_pidfd(pidfd)
        sender = getattr(signal, "pidfd_send_signal", None)
        if sender is None:
            raise SupervisorError("pidfd_send_signal is unavailable")
        try:
            sender(pidfd, signal_number, None, 0)
        except OSError as error:
            raise SupervisorError("pidfd signal failed") from error

    def send_group_signal(
        self, pidfd: int, identity: ProcessIdentity, signal_number: int
    ) -> None:
        """Signal a registered owned group without falling back to its leader."""

        self._require_bound_identity(pidfd, identity)
        if signal_number not in {signal.SIGTERM, signal.SIGKILL}:
            raise SupervisorError("owned process-group signal is not approved")
        if identity.pid != identity.pgid:
            raise SupervisorError("owned process is not its process-group leader")
        if not self.is_alive(pidfd) or not self.group_identity_matches(identity):
            raise SupervisorError("owned process-group identity changed")
        try:
            os.killpg(identity.pgid, signal_number)
        except ProcessLookupError:
            # The group may disappear after its last identity check. The caller
            # still has to prove terminal absence before cleanup can pass.
            return
        except OSError as error:
            raise SupervisorError("owned process-group signal failed") from error

    def send_retained_group_signal(
        self, pidfd: int, identity: ProcessIdentity, signal_number: int
    ) -> None:
        """Signal descendants after the exact group leader was reaped.

        Reaping the retained direct child prevents zombie leaders from making a
        dead group look live forever.  The group authority remains bound to the
        registered pidfd and the group ID recorded by that successful reap.
        """

        self._require_bound_identity(pidfd, identity)
        if signal_number != signal.SIGKILL:
            raise SupervisorError("retained process-group signal is not approved")
        if self._reaped_groups.get(pidfd) != identity.pgid:
            raise SupervisorError("retained process-group authority is unavailable")
        try:
            os.killpg(identity.pgid, signal_number)
        except ProcessLookupError:
            return
        except OSError as error:
            raise SupervisorError("retained process-group signal failed") from error

    def wait_dead(self, pidfd: int, timeout_seconds: float) -> bool:
        self._require_bound_pidfd(pidfd)
        _require_cleanup_timeout(timeout_seconds)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return bool(poller.poll(round(float(timeout_seconds) * 1000)))

    def wait_group_gone(self, pgid: int, timeout_seconds: float) -> bool:
        if type(pgid) is not int or pgid <= 0:
            raise SupervisorError("owned process group is invalid")
        _require_cleanup_timeout(timeout_seconds)
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            if not _process_group_exists(pgid):
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def reap(
        self, identity: ProcessIdentity, pidfd: int, timeout_seconds: float
    ) -> bool:
        """Boundedly reap the exact direct child registered by ``pidfd``."""

        self._require_bound_identity(pidfd, identity)
        _require_cleanup_timeout(timeout_seconds)
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            try:
                wait_result = os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
            except InterruptedError:
                continue
            except ChildProcessError:
                return False
            except OSError as error:
                if error.errno == errno.ECHILD:
                    return False
                raise SupervisorError("owned process reap failed") from error
            if wait_result is not None and wait_result.si_pid == identity.pid:
                self._reaped_groups[pidfd] = identity.pgid
                # Real ``waitid_result`` objects always expose ``si_code`` and
                # ``si_status``.  Keep the process-operations seam compatible
                # with the deliberately minimal identity-only test double;
                # absence of status fields there represents a clean exit, not
                # authority to infer a non-zero result.
                status = int(getattr(wait_result, "si_status", 0))
                status_kind = int(getattr(wait_result, "si_code", os.CLD_EXITED))
                self._exit_codes[identity] = (
                    status if status_kind == os.CLD_EXITED else min(255, 128 + status)
                )
                return True
            if wait_result is not None:
                raise SupervisorError("owned process reap returned the wrong pid")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def prove_owned_absent(self, identity: ProcessIdentity, pidfd: int) -> bool:
        """Prove the registered process identity and its complete group are gone."""

        self._require_bound_identity(pidfd, identity)
        return (
            not self.is_alive(pidfd)
            and not identity.matches_proc()
            and not _process_group_exists(identity.pgid)
        )

    def close_pidfd(self, pidfd: int) -> None:
        self._require_bound_pidfd(pidfd)
        try:
            os.close(pidfd)
        finally:
            self._pidfd_identities.pop(pidfd, None)
            self._reaped_groups.pop(pidfd, None)

    def exit_code(self, identity: ProcessIdentity) -> int:
        if type(identity) is not ProcessIdentity or identity not in self._exit_codes:
            raise SupervisorError("owned process exit status is unavailable")
        return self._exit_codes[identity]

    def _require_bound_pidfd(self, pidfd: int) -> None:
        if type(pidfd) is not int or pidfd < 0 or pidfd not in self._pidfd_identities:
            raise SupervisorError("pidfd is not registered")

    def _require_bound_identity(self, pidfd: int, identity: ProcessIdentity) -> None:
        self._require_bound_pidfd(pidfd)
        if type(identity) is not ProcessIdentity:
            raise SupervisorError("owned process identity is invalid")
        if self._pidfd_identities[pidfd] != identity:
            raise SupervisorError("pidfd is bound to a different process identity")


class OwnedProcessLease:
    """Opaque controller-owned pidfd ticket retained across action execution."""

    __slots__ = ("_consumed", "_identity", "_owner", "_pidfd", "_reaped")

    def __init__(
        self,
        identity: ProcessIdentity,
        pidfd: int,
        owner: object,
    ) -> None:
        self._identity = identity
        self._pidfd = pidfd
        self._owner = owner
        self._consumed = False
        self._reaped = False

    @property
    def identity(self) -> ProcessIdentity:
        return self._identity


class OwnedProcessController:
    """Retain pidfd ownership across acknowledged exec and bounded finalization."""

    def __init__(self, operations: object | None = None, *, wait_seconds: float = 1.0):
        self._operations = operations or LinuxProcessOperations()
        self._lease_authority = object()
        self._leases: dict[int, OwnedProcessLease] = {}
        if type(wait_seconds) not in {int, float} or not 0 <= wait_seconds <= 30:
            raise SupervisorError("owned-process wait is outside the bound")
        self._wait_seconds = float(wait_seconds)
        for method in (
            "open_pidfd",
            "identity_matches",
            "group_identity_matches",
            "is_alive",
            "send_signal",
            "send_group_signal",
            "send_retained_group_signal",
            "wait_dead",
            "wait_group_gone",
            "reap",
            "prove_owned_absent",
            "close_pidfd",
        ):
            if not callable(getattr(self._operations, method, None)):
                raise SupervisorError("process operation adapter is incomplete")

    def acquire(self, identity: ProcessIdentity) -> OwnedProcessLease:
        """Open and retain the exact action-child identity before it is released."""

        if type(identity) is not ProcessIdentity:
            raise SupervisorError("owned process identity is invalid")
        pidfd = -1
        try:
            pidfd = self._operations.open_pidfd(identity)
            if not self._operations.identity_matches(
                identity
            ) or not self._operations.group_identity_matches(identity):
                raise SupervisorError("owned process identity changed during acquire")
            lease = OwnedProcessLease(identity, pidfd, self._lease_authority)
            self._leases[id(lease)] = lease
            return lease
        except Exception:
            if pidfd >= 0:
                self._operations.close_pidfd(pidfd)
            raise

    def active_leases(self) -> tuple[OwnedProcessLease, ...]:
        """Return the current controller-owned writer inventory."""

        return tuple(
            lease
            for lease in self._leases.values()
            if not lease._consumed and lease._owner is self._lease_authority
        )

    def exec_after_ownership_ack(
        self,
        owned: OwnedProcessLease,
        ownership_client: object,
        exec_action: Callable[[], object],
    ) -> object:
        lease = self._require_lease(owned)
        append_identity = getattr(ownership_client, "append_identity", None)
        if not callable(append_identity) or not callable(exec_action):
            raise SupervisorError("ownership client/exec adapter is invalid")
        identity = lease.identity
        if not self._operations.identity_matches(identity):
            raise SupervisorError(
                "owned process identity changed before ownership acknowledgement"
            )
        append_identity(identity)
        if not self._operations.identity_matches(identity):
            raise SupervisorError("owned process identity changed before exec")
        return exec_action()

    def verify_absent(self, leases: Sequence[OwnedProcessLease]) -> bool:
        """Reap and prove successful action absence without sending a signal."""

        inventory = self._require_lease_inventory(leases)
        complete = True
        for lease in inventory:
            identity = lease.identity
            try:
                if self._operations.is_alive(lease._pidfd):
                    complete = False
                    continue
                if not lease._reaped:
                    # The normal coordinator path owns and reaps its action
                    # child.  From this external supervisor the child is a
                    # grandchild, so waitid(P_PIDFD) may correctly return
                    # ECHILD.  Reap opportunistically when adopted, but keep
                    # pidfd/identity/group absence as the mandatory proof.
                    lease._reaped = bool(
                        self._operations.reap(
                            identity, lease._pidfd, self._wait_seconds
                        )
                    )
                absent = self._operations.wait_group_gone(
                    identity.pgid, self._wait_seconds
                ) and self._operations.prove_owned_absent(identity, lease._pidfd)
                complete = absent and complete
                if absent:
                    self._consume_lease(lease)
            except Exception:
                complete = False
        return complete

    def cleanup(self, owned: Sequence[OwnedProcessLease]) -> bool:
        if type(owned) not in {tuple, list} or any(
            type(item) is not OwnedProcessLease for item in owned
        ):
            raise SupervisorError("owned process lease inventory is invalid")
        leases = list(self._require_lease_inventory(owned))
        identities = tuple(lease.identity for lease in leases)
        if len({identity.pid for identity in identities}) != len(identities) or len(
            {identity.pgid for identity in identities}
        ) != len(identities):
            raise SupervisorError("owned process inventory contains duplicate groups")
        complete = True
        for lease in leases:
            identity = lease.identity
            pidfd = lease._pidfd
            lease_complete = False
            try:
                if lease._reaped:
                    if not self._operations.wait_group_gone(identity.pgid, 0):
                        self._operations.send_retained_group_signal(
                            pidfd, identity, signal.SIGKILL
                        )
                    lease_complete = self._operations.wait_group_gone(
                        identity.pgid, self._wait_seconds
                    ) and self._operations.prove_owned_absent(identity, pidfd)
                    complete = lease_complete and complete
                    continue
                if self._operations.is_alive(pidfd):
                    if not self._operations.identity_matches(
                        identity
                    ) or not self._operations.group_identity_matches(identity):
                        complete = False
                        continue
                    self._operations.send_group_signal(pidfd, identity, signal.SIGTERM)
                    if self._operations.wait_dead(pidfd, self._wait_seconds):
                        if not self._operations.reap(
                            identity, pidfd, self._wait_seconds
                        ):
                            complete = False
                            continue
                        lease._reaped = True
                        if not self._operations.wait_group_gone(identity.pgid, 0):
                            self._operations.send_retained_group_signal(
                                pidfd, identity, signal.SIGKILL
                            )
                    else:
                        if not self._operations.identity_matches(
                            identity
                        ) or not self._operations.group_identity_matches(identity):
                            complete = False
                            continue
                        self._operations.send_group_signal(
                            pidfd, identity, signal.SIGKILL
                        )
                if not self._operations.wait_dead(pidfd, self._wait_seconds):
                    complete = False
                    continue
                if not lease._reaped:
                    if not self._operations.reap(identity, pidfd, self._wait_seconds):
                        complete = False
                        continue
                    lease._reaped = True
                if not self._operations.wait_group_gone(
                    identity.pgid, self._wait_seconds
                ):
                    complete = False
                    continue
                if not self._operations.prove_owned_absent(identity, pidfd):
                    complete = False
                else:
                    lease_complete = True
            except Exception:
                complete = False
            finally:
                if lease_complete:
                    try:
                        self._consume_lease(lease)
                    except Exception:
                        complete = False
        return complete

    def _require_lease(self, lease: OwnedProcessLease) -> OwnedProcessLease:
        if (
            type(lease) is not OwnedProcessLease
            or lease._owner is not self._lease_authority
            or self._leases.get(id(lease)) is not lease
            or lease._consumed
        ):
            raise SupervisorError("owned process lease authority is invalid")
        return lease

    def _require_lease_inventory(
        self, leases: Sequence[OwnedProcessLease]
    ) -> tuple[OwnedProcessLease, ...]:
        if type(leases) not in {tuple, list}:
            raise SupervisorError("owned process lease inventory is invalid")
        retained = tuple(self._require_lease(lease) for lease in leases)
        if len({lease.identity.pid for lease in retained}) != len(retained) or len(
            {lease.identity.pgid for lease in retained}
        ) != len(retained):
            raise SupervisorError("owned process inventory contains duplicate groups")
        return retained

    def _consume_lease(self, lease: OwnedProcessLease) -> None:
        self._require_lease(lease)
        try:
            self._operations.close_pidfd(lease._pidfd)
        finally:
            lease._consumed = True
            self._leases.pop(id(lease), None)


@dataclass(frozen=True)
class ExitkillProbeSpec:
    strace_path: Path
    strace_fd: int
    strace_sha256: str
    options: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    tracee_path: Path


@dataclass(frozen=True)
class ExitkillProbeEvidence:
    helper_pid: int
    child_subreaper: bool
    tracer_pid: int
    tracee_pid: int
    tracer_reaped: bool
    tracee_reaped: bool
    tracee_exit_signal: int
    terminal_absence: bool


class ExitkillCapabilityProbe:
    """Prove live EXITKILL behavior for the exact reviewed trace runtime."""

    def __init__(self, contract: ContractSet, *, runner: object | None = None) -> None:
        if type(contract) is not ContractSet:
            raise SupervisorError("EXITKILL contract is not the reviewed ContractSet")
        if runner is not None and not callable(runner):
            raise SupervisorError("EXITKILL probe runner is invalid")
        self._contract = contract
        self._runner = runner or _run_live_exitkill_probe

    def verify(self) -> bool:
        rows = self._contract.trace_tool_rows()
        if len(rows) != 1:
            raise SupervisorError("EXITKILL policy row is not unique")
        row = rows[0]
        runtime = row.get("runtime")
        argv = row.get("argv")
        if not isinstance(runtime, Mapping) or not isinstance(argv, Mapping):
            raise SupervisorError("EXITKILL policy is malformed")
        options = argv.get("options")
        environment = argv.get("environment")
        expected_digest = runtime.get("elf_sha256")
        expected_size = runtime.get("elf_size")
        if (
            runtime.get("review_state") != "REVIEWED"
            or argv.get("review_state") != "REVIEWED"
            or type(options) is not list
            or environment != {"LC_ALL": "C", "TZ": "UTC"}
            or "--kill-on-exit" not in options
            or type(expected_digest) is not str
            or type(expected_size) is not int
        ):
            raise SupervisorError("EXITKILL runtime is not reviewed")
        strace_path = _contract_runtime_path(
            self._contract.root, runtime.get("elf_path")
        )
        strace_fd = -1
        try:
            strace_fd = os.open(
                strace_path,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            )
            metadata = os.fstat(strace_fd)
            path_metadata = strace_path.lstat()
            digest = hashlib.sha256()
            while True:
                chunk = os.read(strace_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or strace_path.is_symlink()
                or (metadata.st_dev, metadata.st_ino)
                != (path_metadata.st_dev, path_metadata.st_ino)
                or not metadata.st_mode & stat.S_IXUSR
                or metadata.st_size != expected_size
                or digest.hexdigest() != expected_digest
            ):
                raise SupervisorError("reviewed EXITKILL runtime identity mismatch")
            spec = ExitkillProbeSpec(
                strace_path=strace_path,
                strace_fd=strace_fd,
                strace_sha256=expected_digest,
                options=tuple(options),
                environment=tuple(sorted(environment.items())),
                tracee_path=self._contract.root / "native/build/native_test_probe",
            )
            evidence = self._runner(spec)
        except FileNotFoundError as error:
            raise SupervisorError("reviewed EXITKILL runtime is unavailable") from error
        except Exception as error:
            if isinstance(error, SupervisorError):
                raise
            raise SupervisorError("live EXITKILL capability probe failed") from error
        finally:
            if strace_fd >= 0:
                os.close(strace_fd)
        if type(evidence) is not ExitkillProbeEvidence:
            raise SupervisorError("live EXITKILL capability was not verified")
        if evidence.tracee_reaped is not True:
            raise SupervisorError("live EXITKILL tracee reap evidence is missing")
        if not _valid_exitkill_evidence(evidence):
            raise SupervisorError("live EXITKILL capability evidence is invalid")
        return True


def _contract_runtime_path(root: Path, value: object) -> Path:
    if type(value) is not str or not value:
        raise SupervisorError("reviewed EXITKILL runtime path is invalid")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise SupervisorError("reviewed EXITKILL runtime path escapes the contract")
    prefix = ("scripts", "holoagent0_setup")
    if relative.parts[:2] == prefix:
        relative = Path(*relative.parts[2:])
    return root / relative


def _run_live_exitkill_probe(spec: ExitkillProbeSpec) -> ExitkillProbeEvidence:
    """Run the destructive ptrace check in one isolated child subreaper."""

    if type(spec) is not ExitkillProbeSpec:
        raise SupervisorError("EXITKILL probe specification is invalid")
    try:
        native_tasks = tuple(Path("/proc/self/task").iterdir())
    except OSError as error:
        raise SupervisorError("EXITKILL helper thread inventory failed") from error
    if len(native_tasks) != 1:
        raise SupervisorError("EXITKILL helper must fork before worker threads")
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    ready_read_fd, ready_write_fd = os.pipe2(os.O_CLOEXEC)
    accept_read_fd, accept_write_fd = os.pipe2(os.O_CLOEXEC)
    helper_pid = -1
    helper_identity: tuple[int, int, int] | None = None
    helper_succeeded = False
    try:
        helper_pid = os.fork()
        if helper_pid == 0:
            os.close(read_fd)
            os.close(ready_read_fd)
            os.close(accept_write_fd)
            exit_code = 70
            try:
                os.setsid()
                _set_child_subreaper()
                _write_all(ready_write_fd, b"READY")
                os.close(ready_write_fd)
                ready_write_fd = -1
                if os.read(accept_read_fd, 1) != b"1":
                    raise SupervisorError(
                        "EXITKILL helper identity was not parent-accepted"
                    )
                os.close(accept_read_fd)
                accept_read_fd = -1
                evidence = _run_exitkill_probe_worker(spec)
                payload = canonical_json_bytes(_exitkill_evidence_dict(evidence))
                if len(payload) > 4096:
                    raise SupervisorError("EXITKILL evidence exceeds pipe bound")
                _write_all(write_fd, payload)
                exit_code = 0
            except BaseException:
                try:
                    _write_all(write_fd, b'{"probe_failed":true}')
                except BaseException:
                    pass
            finally:
                try:
                    os.close(write_fd)
                finally:
                    for descriptor in (ready_write_fd, accept_read_fd):
                        if descriptor >= 0:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass
                    os._exit(exit_code)
        os.close(write_fd)
        write_fd = -1
        os.close(ready_write_fd)
        ready_write_fd = -1
        os.close(accept_read_fd)
        accept_read_fd = -1
        helper_identity = _wait_helper_group_identity(helper_pid)
        if _read_exact_bounded(ready_read_fd, 5, timeout_seconds=1.0) != b"READY":
            raise SupervisorError("EXITKILL helper readiness barrier failed")
        _write_all(accept_write_fd, b"1")
        os.close(accept_write_fd)
        accept_write_fd = -1
        payload, status = _collect_exitkill_helper(
            helper_pid, read_fd, timeout_seconds=8.0
        )
        if status.si_code != os.CLD_EXITED or status.si_status != 0:
            raise SupervisorError("EXITKILL helper failed")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SupervisorError("EXITKILL helper evidence is invalid") from error
        evidence = _exitkill_evidence_from_dict(value, helper_pid=helper_pid)
        helper_succeeded = True
        return evidence
    finally:
        if read_fd >= 0:
            try:
                os.close(read_fd)
            except OSError:
                pass
        if write_fd >= 0:
            try:
                os.close(write_fd)
            except OSError:
                pass
        for descriptor in (
            ready_read_fd,
            ready_write_fd,
            accept_read_fd,
            accept_write_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if helper_pid > 0:
            _cleanup_exitkill_helper_group(
                helper_pid,
                expected_identity=helper_identity,
                terminate=not helper_succeeded,
            )


def _run_exitkill_probe_worker(spec: ExitkillProbeSpec) -> ExitkillProbeEvidence:
    """Kill/reap tracer, then reap the EXITKILLed tracee as its subreaper."""

    try:
        tracee_stat = spec.tracee_path.lstat()
    except OSError as error:
        raise SupervisorError("EXITKILL native probe is unavailable") from error
    if (
        not stat.S_ISREG(tracee_stat.st_mode)
        or spec.tracee_path.is_symlink()
        or not tracee_stat.st_mode & stat.S_IXUSR
    ):
        raise SupervisorError("EXITKILL native probe identity is invalid")
    tracer: subprocess.Popen[bytes] | None = None
    tracee_pid: int | None = None
    tracee_pidfd = -1
    tracer_reaped = False
    tracee_reaped = False
    tracee_exit_signal = 0
    terminal_absence = False
    output_read_fd, output_write_fd = _open_exitkill_trace_pipe()
    try:
        options = tuple(
            option.replace("{output_fd}", str(output_write_fd))
            for option in spec.options
        )
        try:
            tracer = subprocess.Popen(
                [
                    f"/proc/self/fd/{spec.strace_fd}",
                    *options,
                    "--",
                    os.fspath(spec.tracee_path),
                    "--block-forever",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                pass_fds=(spec.strace_fd, output_write_fd),
                env=dict(spec.environment),
            )
            os.close(output_write_fd)
            output_write_fd = -1
            deadline = time.monotonic() + 2.0
            children_path = Path(f"/proc/{tracer.pid}/task/{tracer.pid}/children")
            while time.monotonic() < deadline:
                if tracer.poll() is not None:
                    return False
                try:
                    children = children_path.read_text(encoding="ascii").split()
                except OSError:
                    children = []
                if len(children) == 1 and children[0].isdecimal():
                    tracee_pid = int(children[0])
                    break
                time.sleep(0.01)
            if tracee_pid is None:
                raise SupervisorError("EXITKILL tracee identity was not observed")
            if not hasattr(os, "pidfd_open"):
                raise SupervisorError("EXITKILL tracee pidfd is unavailable")
            tracee_pidfd = os.pidfd_open(tracee_pid, 0)
            if not _pidfd_is_live(tracee_pidfd):
                raise SupervisorError("EXITKILL tracee was not live before tracer loss")
            os.kill(tracer.pid, signal.SIGKILL)
            tracer_status = tracer.wait(timeout=1.0)
            tracer_reaped = tracer_status == -signal.SIGKILL
            if not tracer_reaped:
                raise SupervisorError("EXITKILL tracer was not SIGKILL-reaped")
            tracee_status = _waitpid_exact(tracee_pid, timeout_seconds=2.0)
            tracee_reaped = tracee_status is not None
            if tracee_status is not None and os.WIFSIGNALED(tracee_status):
                tracee_exit_signal = os.WTERMSIG(tracee_status)
            terminal_absence = (
                tracee_reaped
                and not _pidfd_is_live(tracee_pidfd)
                and not Path(f"/proc/{tracee_pid}").exists()
            )
            return ExitkillProbeEvidence(
                helper_pid=os.getpid(),
                child_subreaper=_child_subreaper_enabled(),
                tracer_pid=tracer.pid,
                tracee_pid=tracee_pid,
                tracer_reaped=tracer_reaped,
                tracee_reaped=tracee_reaped,
                tracee_exit_signal=tracee_exit_signal,
                terminal_absence=terminal_absence,
            )
        finally:
            if tracer is not None and tracer.poll() is None:
                try:
                    os.kill(tracer.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    tracer.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
            if tracee_pidfd >= 0 and _pidfd_is_live(tracee_pidfd):
                try:
                    signal.pidfd_send_signal(tracee_pidfd, signal.SIGKILL, None, 0)
                except (AttributeError, ProcessLookupError):
                    pass
            if tracee_pid is not None and not tracee_reaped:
                _waitpid_exact(tracee_pid, timeout_seconds=1.0)
            if tracee_pidfd >= 0:
                os.close(tracee_pidfd)
    finally:
        if output_write_fd >= 0:
            os.close(output_write_fd)
        os.close(output_read_fd)


def _open_exitkill_trace_pipe() -> tuple[int, int]:
    """Return the transient raw-trace transport; never a persistent file."""

    try:
        return os.pipe2(os.O_CLOEXEC)
    except OSError as error:
        raise SupervisorError("EXITKILL raw trace pipe creation failed") from error


def _valid_exitkill_evidence(evidence: ExitkillProbeEvidence) -> bool:
    pids = (evidence.helper_pid, evidence.tracer_pid, evidence.tracee_pid)
    return (
        all(type(pid) is int and pid > 0 for pid in pids)
        and len(set(pids)) == 3
        and evidence.child_subreaper is True
        and evidence.tracer_reaped is True
        and evidence.tracee_reaped is True
        and evidence.tracee_exit_signal == signal.SIGKILL
        and evidence.terminal_absence is True
    )


def _exitkill_evidence_dict(evidence: ExitkillProbeEvidence) -> dict[str, object]:
    if type(evidence) is not ExitkillProbeEvidence:
        raise SupervisorError("EXITKILL worker evidence is not exact")
    return {
        "helper_pid": evidence.helper_pid,
        "child_subreaper": evidence.child_subreaper,
        "tracer_pid": evidence.tracer_pid,
        "tracee_pid": evidence.tracee_pid,
        "tracer_reaped": evidence.tracer_reaped,
        "tracee_reaped": evidence.tracee_reaped,
        "tracee_exit_signal": int(evidence.tracee_exit_signal),
        "terminal_absence": evidence.terminal_absence,
    }


def _exitkill_evidence_from_dict(
    value: object, *, helper_pid: int
) -> ExitkillProbeEvidence:
    expected = {
        "helper_pid",
        "child_subreaper",
        "tracer_pid",
        "tracee_pid",
        "tracer_reaped",
        "tracee_reaped",
        "tracee_exit_signal",
        "terminal_absence",
    }
    if type(value) is not dict or set(value) != expected:
        raise SupervisorError("EXITKILL helper evidence shape is invalid")
    if value["helper_pid"] != helper_pid:
        raise SupervisorError("EXITKILL helper evidence identity mismatch")
    evidence = ExitkillProbeEvidence(**value)
    if not _valid_exitkill_evidence(evidence):
        raise SupervisorError("EXITKILL helper evidence is incomplete")
    return evidence


def _set_child_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise SupervisorError("EXITKILL child subreaper setup failed") from OSError(
            error, os.strerror(error)
        )
    if not _child_subreaper_enabled(libc):
        raise SupervisorError("EXITKILL child subreaper setup was not retained")


def _child_subreaper_enabled(libc: object | None = None) -> bool:
    library = ctypes.CDLL(None, use_errno=True) if libc is None else libc
    value = ctypes.c_int(0)
    if library.prctl(37, ctypes.byref(value), 0, 0, 0) != 0:  # PR_GET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise SupervisorError("EXITKILL child subreaper query failed") from OSError(
            error, os.strerror(error)
        )
    return value.value == 1


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise SupervisorError("EXITKILL helper evidence write failed")
        view = view[written:]


def _read_exact_bounded(fd: int, size: int, *, timeout_seconds: float) -> bytes:
    if type(fd) is not int or fd < 0 or type(size) is not int or size <= 0:
        raise SupervisorError("bounded pipe read arguments are invalid")
    _require_cleanup_timeout(timeout_seconds)
    deadline = time.monotonic() + float(timeout_seconds)
    payload = bytearray()
    while len(payload) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SupervisorError("bounded pipe read timed out")
        readable, _, _ = select.select([fd], [], [], remaining)
        if not readable:
            raise SupervisorError("bounded pipe read timed out")
        chunk = os.read(fd, size - len(payload))
        if not chunk:
            raise SupervisorError("bounded pipe read ended early")
        payload.extend(chunk)
    return bytes(payload)


def _collect_exitkill_helper(
    helper_pid: int, read_fd: int, *, timeout_seconds: float
) -> tuple[bytes, object]:
    deadline = time.monotonic() + timeout_seconds
    payload = bytearray()
    eof = False
    status = None
    poller = select.poll()
    poller.register(read_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while time.monotonic() < deadline:
        if not eof:
            events = poller.poll(20)
            if events:
                chunk = os.read(read_fd, 4097 - len(payload))
                if chunk:
                    payload.extend(chunk)
                    if len(payload) > 4096:
                        raise SupervisorError("EXITKILL helper evidence exceeds bound")
                else:
                    eof = True
        if status is None:
            status = os.waitid(
                os.P_PID,
                helper_pid,
                os.WEXITED | os.WNOHANG | os.WNOWAIT,
            )
        if status is not None and (
            eof or status.si_code != os.CLD_EXITED or status.si_status != 0
        ):
            return bytes(payload), status
    raise SupervisorError("EXITKILL helper timed out")


def _wait_helper_group_identity(helper_pid: int) -> tuple[int, int, int]:
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            identity = _read_helper_group_identity(helper_pid)
        except SupervisorError:
            time.sleep(0.005)
            continue
        if identity[0] == identity[1] == helper_pid:
            return identity
        # The parent can observe the child between fork() and setsid().  It is
        # still our unreaped child, so wait for the reviewed isolated identity
        # instead of treating that scheduling window as a runtime failure.
        time.sleep(0.005)
    raise SupervisorError("EXITKILL helper identity was not retained")


def _read_helper_group_identity(helper_pid: int) -> tuple[int, int, int]:
    try:
        process_stat = Path(f"/proc/{helper_pid}/stat").read_text(encoding="ascii")
    except OSError as error:
        raise SupervisorError("EXITKILL helper identity is unavailable") from error
    fields = process_stat.rsplit(")", 1)[-1].split()
    if (
        len(fields) < 20
        or not fields[2].isdecimal()
        or not fields[3].isdecimal()
        or not fields[19].isdecimal()
    ):
        raise SupervisorError("EXITKILL helper identity is malformed")
    return int(fields[2]), int(fields[3]), int(fields[19])


def _cleanup_exitkill_helper_group(
    helper_pid: int,
    *,
    expected_identity: tuple[int, int, int] | None,
    terminate: bool,
) -> None:
    if expected_identity is None:
        # An unreaped direct child cannot have its numeric PID reused.  Kill
        # only that child while the parent still owns the wait relationship;
        # never infer or signal a process group without the retained tuple.
        try:
            os.kill(helper_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(helper_pid, 0)
        except ChildProcessError:
            pass
        return
    observed = _read_helper_group_identity(helper_pid)
    if (
        observed != expected_identity
        or observed[0] != helper_pid
        or observed[1] != helper_pid
    ):
        raise SupervisorError("EXITKILL helper identity changed before cleanup")
    try:
        if terminate:
            os.killpg(helper_pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(helper_pid, 0)
    except ChildProcessError:
        pass


def _pidfd_is_live(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)


def _waitpid_exact(pid: int, *, timeout_seconds: float) -> int | None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            waited = 0
        if waited == pid:
            return status
        time.sleep(0.01)
    return None


class TraceRuntimeGuard:
    """Retain tracer/normalizer pidfds and fail closed on either loss."""

    def __init__(
        self,
        operations: object | None = None,
        *,
        cleanup: OwnedProcessController | None = None,
    ) -> None:
        self._operations = operations or LinuxProcessOperations()
        self._cleanup = cleanup or OwnedProcessController(self._operations)
        self._identities: dict[str, ProcessIdentity] = {}
        self._pidfds: dict[str, int] = {}
        self._reaped_roles: set[str] = set()
        self._terminal_exit_codes: tuple[int, int] | None = None

    def attach(
        self,
        tracer: ProcessIdentity,
        normalizer: ProcessIdentity,
        *,
        contract: ContractSet,
    ) -> None:
        if self._pidfds:
            raise SupervisorError("trace runtime guard is already attached")
        self._require_pinned_exitkill(tracer, contract)
        if (
            type(tracer) is not ProcessIdentity
            or type(normalizer) is not ProcessIdentity
            or tracer.pid == normalizer.pid
            or tracer.pgid == normalizer.pgid
        ):
            raise SupervisorError("tracer and normalizer identities are not distinct")
        opened: dict[str, int] = {}
        try:
            opened["tracer"] = self._operations.open_pidfd(tracer)
            opened["normalizer"] = self._operations.open_pidfd(normalizer)
        except Exception as error:
            for pidfd in opened.values():
                try:
                    self._operations.close_pidfd(pidfd)
                except Exception:
                    pass
            raise SupervisorError("trace runtime identity binding failed") from error
        self._identities = {"tracer": tracer, "normalizer": normalizer}
        self._pidfds = opened
        self._reaped_roles = set()

    @staticmethod
    def _require_pinned_exitkill(
        tracer: ProcessIdentity, contract: ContractSet
    ) -> None:
        if type(contract) is not ContractSet:
            raise SupervisorError("trace contract is not the reviewed ContractSet")
        rows = contract.trace_tool_rows()
        if len(rows) != 1:
            raise SupervisorError("PTRACE_O_EXITKILL policy row is not unique")
        row = rows[0]
        runtime = row.get("runtime")
        argv = row.get("argv")
        if not isinstance(runtime, Mapping) or not isinstance(argv, Mapping):
            raise SupervisorError("PTRACE_O_EXITKILL policy is malformed")
        options = argv.get("options")
        if (
            runtime.get("review_state") != "REVIEWED"
            or runtime.get("elf_sha256") != tracer.executable_sha256
            or argv.get("review_state") != "REVIEWED"
            or type(options) is not list
            or "--kill-on-exit" not in options
        ):
            raise SupervisorError("PTRACE_O_EXITKILL was not pinned and verified")

    def poll(self) -> dict[str, bool]:
        if tuple(self._pidfds) != ("tracer", "normalizer"):
            raise SupervisorError("trace runtime guard is not attached")
        return {
            role: bool(
                self._operations.identity_matches(self._identities[role])
                and self._operations.is_alive(pidfd)
            )
            for role, pidfd in self._pidfds.items()
        }

    def require_live_or_cleanup(
        self, owned_tracees: Sequence[ProcessIdentity]
    ) -> "TraceLossReport | None":
        live = self.poll()
        if live["tracer"] and live["normalizer"]:
            return None
        tracer_terminated: bool | None = None
        infrastructure_complete = True
        if not live["normalizer"]:
            tracer_terminated = self._finalize_infrastructure_role(
                "tracer", was_live=live["tracer"]
            )
            infrastructure_complete = tracer_terminated
            infrastructure_complete = (
                self._finalize_infrastructure_role("normalizer", was_live=False)
                and infrastructure_complete
            )
        else:
            infrastructure_complete = self._finalize_infrastructure_role(
                "normalizer", was_live=True
            )
            infrastructure_complete = (
                self._finalize_infrastructure_role("tracer", was_live=False)
                and infrastructure_complete
            )
        tracees_complete = bool(self._cleanup.cleanup(owned_tracees))
        cleanup_complete = infrastructure_complete and tracees_complete
        if not live["tracer"]:
            return TraceLossReport("TRACER_EXITED", cleanup_complete, None)
        return TraceLossReport(
            "TRACE_DECODE_FAILED",
            cleanup_complete,
            tracer_terminated,
        )

    def monitor_until(
        self,
        completed: Callable[[], bool],
        owned_tracees: Callable[[], Sequence[ProcessIdentity]],
        *,
        timeout_seconds: float,
        poll_interval_seconds: float = 0.01,
    ) -> "TraceLossReport | None":
        """Continuously guard both infrastructure roles until completion."""

        if not callable(completed) or not callable(owned_tracees):
            raise SupervisorError("trace monitor callbacks are invalid")
        _require_cleanup_timeout(timeout_seconds)
        if (
            type(poll_interval_seconds) not in {int, float}
            or not 0 <= float(poll_interval_seconds) <= 1
        ):
            raise SupervisorError("trace monitor interval is invalid")
        deadline = time.monotonic() + float(timeout_seconds)
        while True:
            loss = self.require_live_or_cleanup(owned_tracees())
            if loss is not None:
                return loss
            if completed() is True:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                cleanup_complete = self._cleanup_monitor_timeout(owned_tracees())
                if not cleanup_complete:
                    raise SupervisorError(
                        "trace monitor completion timed out; cleanup incomplete"
                    )
                raise SupervisorError(
                    "trace monitor completion timed out after cleanup"
                )
            if poll_interval_seconds:
                time.sleep(min(float(poll_interval_seconds), remaining))

    def _cleanup_monitor_timeout(
        self, owned_tracees: Sequence[ProcessIdentity]
    ) -> bool:
        live = self.poll()
        infrastructure_complete = True
        for role in ("tracer", "normalizer"):
            infrastructure_complete = (
                self._finalize_infrastructure_role(role, was_live=live[role])
                and infrastructure_complete
            )
        return bool(self._cleanup.cleanup(owned_tracees)) and infrastructure_complete

    def _finalize_infrastructure_role(self, role: str, *, was_live: bool) -> bool:
        identity = self._identities[role]
        pidfd = self._pidfds[role]
        if role in self._reaped_roles:
            return bool(
                not self._operations.is_alive(pidfd)
                and self._operations.wait_group_gone(identity.pgid, 1.0)
                and self._operations.prove_owned_absent(identity, pidfd)
            )
        reaped = False
        try:
            currently_alive = self._operations.is_alive(pidfd)
            if was_live and currently_alive:
                if not self._operations.identity_matches(
                    identity
                ) or not self._operations.group_identity_matches(identity):
                    return False
                self._operations.send_group_signal(pidfd, identity, signal.SIGTERM)
                if self._operations.wait_dead(pidfd, 1.0):
                    if not self._operations.reap(identity, pidfd, 1.0):
                        return False
                    reaped = True
                    if not self._operations.wait_group_gone(identity.pgid, 0):
                        self._operations.send_retained_group_signal(
                            pidfd, identity, signal.SIGKILL
                        )
                else:
                    if not self._operations.identity_matches(
                        identity
                    ) or not self._operations.group_identity_matches(identity):
                        return False
                    self._operations.send_group_signal(pidfd, identity, signal.SIGKILL)
            if not self._operations.wait_dead(pidfd, 1.0):
                return False
            if not reaped:
                if not self._operations.reap(identity, pidfd, 1.0):
                    return False
            self._reaped_roles.add(role)
            if not self._operations.wait_group_gone(identity.pgid, 1.0):
                return False
            return bool(self._operations.prove_owned_absent(identity, pidfd))
        except Exception:
            return False

    def verify_terminal_absence(
        self, owned_tracees: Sequence[OwnedProcessLease]
    ) -> bool:
        """Prove terminal writer absence without sending any signal."""

        if tuple(self._pidfds) != ("tracer", "normalizer"):
            raise SupervisorError("trace runtime guard is not attached")
        if type(owned_tracees) not in {tuple, list} or any(
            type(lease) is not OwnedProcessLease for lease in owned_tracees
        ):
            raise SupervisorError("terminal owned-writer inventory is invalid")
        try:
            if any(self._operations.is_alive(pidfd) for pidfd in self._pidfds.values()):
                return False
            if not self._cleanup.verify_absent(owned_tracees):
                return False
            for role in ("tracer", "normalizer"):
                identity = self._identities[role]
                pidfd = self._pidfds[role]
                if role not in self._reaped_roles:
                    if not self._operations.reap(identity, pidfd, 1.0):
                        return False
                    self._reaped_roles.add(role)
                if not self._operations.wait_group_gone(identity.pgid, 1.0):
                    return False
                if not self._operations.prove_owned_absent(identity, pidfd):
                    return False
            getter = getattr(self._operations, "exit_code", None)
            if callable(getter):
                self._terminal_exit_codes = (
                    getter(self._identities["tracer"]),
                    getter(self._identities["normalizer"]),
                )
            self.close()
            return True
        except Exception:
            return False

    def wait_terminal(
        self,
        *,
        timeout_seconds: float,
        owned_tracees: Callable[[], Sequence[OwnedProcessLease]],
    ) -> None:
        if not callable(owned_tracees):
            raise SupervisorError("terminal owned-writer inventory is invalid")
        _require_cleanup_timeout(timeout_seconds)
        deadline = time.monotonic() + float(timeout_seconds)
        while any(self.poll().values()):
            if time.monotonic() >= deadline:
                self._cleanup_monitor_timeout(tuple(owned_tracees()))
                raise SupervisorError("trace roles exceeded the terminal deadline")
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))

    def exit_codes(self) -> tuple[int, int]:
        if self._terminal_exit_codes is None:
            raise SupervisorError("trace exit-status authority is unavailable")
        return self._terminal_exit_codes

    def close(self) -> None:
        for pidfd in self._pidfds.values():
            try:
                self._operations.close_pidfd(pidfd)
            except Exception as error:
                raise SupervisorError("trace pidfd close failed") from error
        self._pidfds = {}
        self._identities = {}


@dataclass(frozen=True)
class TraceLaunchSpec:
    mode: str
    owned_tracees: Callable[[], Sequence[OwnedProcessLease]]

    def __post_init__(self) -> None:
        if self.mode not in {"FULL", "FINALIZER_ONLY", "NOT_STARTED"} or not callable(
            self.owned_tracees
        ):
            raise SupervisorError("trace launch specification is invalid")


_TRACE_SESSION_CONSTRUCTOR = object()


class TraceTerminalProof:
    """Opaque one-shot binding for an exact terminal TraceSession."""

    __slots__ = (
        "_authority",
        "_bundle",
        "_owned_writer_count",
        "_phase",
        "_trace_state",
        "_writer_state",
    )

    def __init__(
        self,
        key: object,
        *,
        authority: object,
        trace_state: str,
        owned_writer_count: int,
        writer_state: str,
    ) -> None:
        if key is not _TRACE_SESSION_CONSTRUCTOR:
            raise SupervisorError("trace terminal proof constructor is private")
        self._authority = authority
        self._bundle: object | None = None
        self._trace_state = trace_state
        self._owned_writer_count = owned_writer_count
        self._writer_state = writer_state
        self._phase = "ISSUED"


class TraceSession:
    __slots__ = (
        "_authority",
        "_proof_issued",
        "_bootstrap_state",
        "_live_launch",
        "guard",
        "normalizer_identity",
        "owned_tracees",
        "trace_state",
        "tracer_identity",
    )

    def __init__(
        self,
        key: object,
        tracer_identity: ProcessIdentity | None,
        normalizer_identity: ProcessIdentity | None,
        guard: TraceRuntimeGuard | None,
        owned_tracees: Callable[[], Sequence[OwnedProcessLease]],
        trace_state: str,
        *,
        not_started_validated: bool,
        bootstrap_state: BootstrapState | None = None,
        live_launch: LiveTraceLaunchOutcome | None = None,
    ) -> None:
        if key is not _TRACE_SESSION_CONSTRUCTOR:
            raise SupervisorError("trace session constructor is private")
        self.tracer_identity = tracer_identity
        self.normalizer_identity = normalizer_identity
        self.guard = guard

        def active_owned_tracees() -> tuple[OwnedProcessLease, ...]:
            observed = owned_tracees()
            if type(observed) not in {tuple, list} or any(
                type(lease) is not OwnedProcessLease for lease in observed
            ):
                raise SupervisorError("trace owned-writer inventory is invalid")
            return tuple(lease for lease in observed if not lease._consumed)

        self.owned_tracees = active_owned_tracees
        self.trace_state = trace_state
        active = trace_state in {"FULL", "FINALIZER_ONLY"}
        identities = (tracer_identity, normalizer_identity)
        if (
            trace_state not in {"FULL", "FINALIZER_ONLY", "NOT_STARTED"}
            or not callable(owned_tracees)
            or active
            != (
                all(type(identity) is ProcessIdentity for identity in identities)
                and type(guard) is TraceRuntimeGuard
            )
            or (not active and any(item is not None for item in (*identities, guard)))
            or ((trace_state == "NOT_STARTED") != not_started_validated)
        ):
            raise SupervisorError("trace session is invalid")
        self._authority = object()
        self._proof_issued = False
        self._bootstrap_state = bootstrap_state
        self._live_launch = live_launch

    def finalize_signal_readiness(
        self,
        coordinator_evidence: CoordinatorSnapshot,
        trace_evidence: TraceUnblockEvidence,
        *,
        trusted_verifier: Callable[[TraceUnblockEvidence], bool],
    ) -> None:
        state = self._bootstrap_state
        launch = self._live_launch
        if (
            self.trace_state != "FULL"
            or state is None
            or state.signal_runtime is None
            or launch is None
            or state.bootstrap_report is None
        ):
            raise SupervisorError("live signal readiness is unavailable")
        state.signal_runtime.finalize_trace_readiness(
            coordinator_evidence,
            trace_evidence,
            trusted_verifier=trusted_verifier,
        )
        launch_snapshot, handoff = state.signal_runtime.snapshot()
        if handoff is None or handoff.terminal_state != "READY":
            raise SupervisorError("live signal readiness did not reach READY")
        report = copy.deepcopy(dict(state.bootstrap_report))
        report.update(
            terminal_launch_state=launch_snapshot.state,
            coordinator_launch_committed=True,
            first_signal=launch_snapshot.first_signal,
            handoff=_bootstrap_handoff_report(
                state.signal_runtime, coordinator_evidence, trace_evidence
            ),
        )
        atomic_write_json_no_replace(
            state.run_root / "bootstrap_report.json",
            report,
            mode=0o400,
            relative_to=state.run_root,
        )

    def finalize_signal_readiness_from_trace(
        self, retained_trace: _SealedTraceArtifact | None = None
    ) -> None:
        """Finalize FULL readiness from supervisor-retained state and trace bytes."""

        state = self._bootstrap_state
        if (
            self.trace_state != "FULL"
            or type(retained_trace) is not _SealedTraceArtifact
            or not self._proof_issued
            or state is None
            or state.signal_runtime is None
            or state.bootstrap_report is None
        ):
            raise SupervisorError("automatic signal readiness is unavailable")
        launch = self._live_launch
        if launch is None:
            raise SupervisorError("automatic readiness has no launch binding")
        handoff = state.signal_runtime._handoff
        request = None if handoff is None else handoff._accepted_request
        if request is None:
            raise SupervisorError("automatic readiness has no accepted request")
        try:
            coordinator, trace = _canonical_trace_handoff_evidence(
                retained_trace,
                request=request,
                request_write_fd=launch.signal_request_write_fd,
                acceptance_read_fd=launch.signal_acceptance_read_fd,
            )
            if trace.functional_count == 0:
                expected_signal = _terminal_signal_from_runtime(state.signal_runtime)
                if expected_signal is None or trace.delivered_signal != expected_signal:
                    raise SupervisorError(
                        "interrupted trace signal does not match supervisor authority"
                    )
            self.finalize_signal_readiness(
                coordinator,
                trace,
                trusted_verifier=lambda observed: observed is trace,
            )
        except Exception as error:
            _record_failed_signal_readiness(state)
            raise SupervisorError("automatic signal readiness failed") from error

    def monitor(
        self, completed: Callable[[], bool], *, timeout_seconds: float
    ) -> TraceLossReport | None:
        if self.trace_state == "NOT_STARTED":
            return None
        if self.guard is None:
            raise SupervisorError("active trace session has no runtime guard")
        return self.guard.monitor_until(
            completed,
            self.owned_tracees,
            timeout_seconds=timeout_seconds,
        )

    def finalize_terminal(self) -> TraceTerminalProof:
        if self._proof_issued:
            raise SupervisorError("trace terminal proof is one-shot")
        owned = tuple(self.owned_tracees())
        if self.trace_state == "NOT_STARTED":
            if owned:
                raise SupervisorError("NOT_STARTED trace has owned writers")
            writer_state = "NOT_STARTED"
        else:
            if self.guard is None or not self.guard.verify_terminal_absence(owned):
                raise SupervisorError("trace session terminal absence was not proven")
            if tuple(self.owned_tracees()):
                raise SupervisorError("trace session retained a terminal writer")
            writer_state = "ABSENT_REAPED_CLOSED"
        proof = TraceTerminalProof(
            _TRACE_SESSION_CONSTRUCTOR,
            authority=self._authority,
            trace_state=self.trace_state,
            owned_writer_count=0,
            writer_state=writer_state,
        )
        self._proof_issued = True
        return proof

    def accept_terminal_proof(
        self, proof: TraceTerminalProof, *, bundle: object
    ) -> None:
        if (
            type(proof) is not TraceTerminalProof
            or proof._authority is not self._authority
            or proof._phase != "ISSUED"
            or proof._trace_state != self.trace_state
            or bundle is None
        ):
            raise SupervisorError("trace terminal proof does not bind this session")
        proof._bundle = bundle
        proof._phase = "FINALIZER_ACCEPTED"


class TraceLaunchRuntime:
    """Launch and bind the reviewed tracer/normalizer pair as one session."""

    def __init__(
        self,
        contract: ContractSet,
        *,
        launcher: Callable[[TraceLaunchSpec], tuple[ProcessIdentity, ProcessIdentity]],
        operations: object | None = None,
        cleanup: OwnedProcessController | None = None,
        readiness_timeout_seconds: float = 5.0,
    ) -> None:
        if type(contract) is not ContractSet or not callable(launcher):
            raise SupervisorError("trace launch runtime adapters are invalid")
        self._contract = contract
        self._launcher = launcher
        self._operations = operations
        self._cleanup = cleanup
        if (
            type(readiness_timeout_seconds) not in {int, float}
            or not 0 < float(readiness_timeout_seconds) <= 30
        ):
            raise SupervisorError("signal readiness deadline is invalid")
        self._readiness_timeout_seconds = float(readiness_timeout_seconds)

    def launch(self, state: TraceLaunchSpec | BootstrapState) -> TraceSession:
        cleanup = self._cleanup
        if type(state) is TraceLaunchSpec:
            spec = state
        elif type(state) is BootstrapState:
            spec = TraceLaunchSpec(state.decision.trace_state, state.owned_tracees)
            if cleanup is None:
                cleanup = state.owned_process_controller
        else:
            raise SupervisorError("trace launch state is not exact")
        if spec.mode == "NOT_STARTED":
            if type(state) is not BootstrapState:
                raise SupervisorError("NOT_STARTED requires validated bootstrap state")
            return TraceSession(
                _TRACE_SESSION_CONSTRUCTOR,
                None,
                None,
                None,
                spec.owned_tracees,
                spec.mode,
                not_started_validated=True,
                bootstrap_state=state if type(state) is BootstrapState else None,
            )
        try:
            live_launch: LiveTraceLaunchOutcome | None = None
            if (
                type(state) is BootstrapState
                and state.signal_runtime is not None
                and spec.mode == "FULL"
            ):
                holder: dict[str, LiveTraceLaunchOutcome] = {}

                def committed_spawn() -> ProcessIdentity:
                    observed = self._launcher(spec)
                    if type(observed) is not LiveTraceLaunchOutcome:
                        raise SupervisorError(
                            "production trace launcher outcome is invalid"
                        )
                    holder["launch"] = observed
                    return observed.coordinator_identity

                coordinator = state.signal_runtime.commit_and_spawn(committed_spawn)
                if coordinator is None:
                    launch_snapshot, _handoff = state.signal_runtime.snapshot()
                    spec = TraceLaunchSpec("FINALIZER_ONLY", state.owned_tracees)
                    identities = self._launcher(spec)
                    report = copy.deepcopy(dict(state.bootstrap_report or {}))
                    report.update(
                        terminal_launch_state=launch_snapshot.state,
                        coordinator_launch_committed=False,
                        first_signal=launch_snapshot.first_signal,
                        handoff=_not_applicable_handoff_report(
                            launch_snapshot.first_signal
                        ),
                    )
                    atomic_write_json_no_replace(
                        state.run_root / "bootstrap_report.json",
                        report,
                        mode=0o400,
                        relative_to=state.run_root,
                    )
                else:
                    if "launch" not in holder:
                        raise SupervisorError(
                            "live coordinator launch outcome is unavailable"
                        )
                    live_launch = holder["launch"]
                    identities = (
                        live_launch.tracer_identity,
                        live_launch.normalizer_identity,
                    )
            else:
                identities = self._launcher(spec)
            if (
                type(identities) is not tuple
                or len(identities) != 2
                or any(type(identity) is not ProcessIdentity for identity in identities)
            ):
                raise SupervisorError("trace launcher identities are invalid")
            guard = TraceRuntimeGuard(
                self._operations,
                cleanup=cleanup,
            )
            guard.attach(*identities, contract=self._contract)
            if live_launch is not None:
                self._accept_readiness_with_liveness(
                    state,
                    live_launch,
                    guard,
                    spec.owned_tracees,
                )
            return TraceSession(
                _TRACE_SESSION_CONSTRUCTOR,
                *identities,
                guard,
                spec.owned_tracees,
                spec.mode,
                not_started_validated=False,
                bootstrap_state=state if type(state) is BootstrapState else None,
                live_launch=live_launch,
            )
        except Exception as error:
            raise SupervisorError("trace launch/session binding failed") from error

    def _accept_readiness_with_liveness(
        self,
        state: BootstrapState,
        launch: LiveTraceLaunchOutcome,
        guard: TraceRuntimeGuard,
        owned_tracees: Callable[[], Sequence[OwnedProcessLease]],
    ) -> None:
        completed = Event()
        outcome: dict[str, BaseException] = {}
        deadline = time.monotonic() + self._readiness_timeout_seconds

        def accept() -> None:
            try:
                if state.signal_runtime is None:
                    raise SupervisorError("live signal runtime disappeared")
                state.signal_runtime.accept_readiness(
                    launch.signal_request_read_fd,
                    launch.signal_acceptance_write_fd,
                    deadline=deadline,
                )
            except BaseException as error:
                outcome["error"] = error
            finally:
                completed.set()

        worker = Thread(
            target=accept,
            name="holoagent0-signal-readiness",
            daemon=False,
        )
        worker.start()
        loss: TraceLossReport | None = None
        while not completed.wait(0.005):
            loss = guard.require_live_or_cleanup(tuple(owned_tracees()))
            if loss is not None or time.monotonic() >= deadline:
                break
        remaining = max(0.0, deadline - time.monotonic())
        worker.join(timeout=remaining + 0.1)
        if worker.is_alive():
            guard._cleanup_monitor_timeout(tuple(owned_tracees()))
            raise SupervisorError("signal readiness worker exceeded its deadline")
        if loss is not None:
            raise SupervisorError(
                f"trace role failed during signal readiness: {loss.reason}"
            )
        if "error" in outcome or not completed.is_set():
            guard._cleanup_monitor_timeout(tuple(owned_tracees()))
            raise SupervisorError(
                "signal readiness acceptance failed"
            ) from outcome.get("error")
        if time.monotonic() > deadline:
            guard._cleanup_monitor_timeout(tuple(owned_tracees()))
            raise SupervisorError("signal readiness deadline expired")


@dataclass(frozen=True)
class TraceLossReport:
    reason: str
    cleanup_complete: bool
    tracer_terminated: bool | None

    def __post_init__(self) -> None:
        if self.reason not in {"TRACER_EXITED", "TRACE_DECODE_FAILED"}:
            raise SupervisorError("trace loss reason is invalid")
        if type(self.cleanup_complete) is not bool:
            raise SupervisorError("trace cleanup decision is invalid")
        if (
            self.tracer_terminated is not None
            and type(self.tracer_terminated) is not bool
        ):
            raise SupervisorError("tracer termination decision is invalid")
        if self.reason == "TRACER_EXITED" and self.tracer_terminated is not None:
            raise SupervisorError("lost tracer cannot have a termination decision")
        if self.reason == "TRACE_DECODE_FAILED" and self.tracer_terminated is None:
            raise SupervisorError(
                "normalizer loss requires a tracer termination decision"
            )


class AuthoritativeResultPublisher:
    """One-shot supervisor-owned validation and atomic result publication."""

    def __init__(
        self,
        result_path: Path,
        *,
        contract: object,
        binder: object,
        bundle: object,
        secret_sentinels: Sequence[str] | set[str] | frozenset[str],
    ) -> None:
        self._path = Path(result_path)
        self._contract = contract
        self._binder = binder
        self._bundle = bundle
        self._secret_sentinels = frozenset(secret_sentinels)
        self._published = False
        self._result_authoritative = False
        self._ambiguous_install: ArtifactDescriptor | None = None
        self._ambiguous_quarantine: Path | None = None
        if not callable(getattr(contract, "require_valid_result", None)):
            raise SupervisorError("result contract adapter is incomplete")
        if not callable(getattr(binder, "revalidate", None)):
            raise SupervisorError("evidence binder adapter is incomplete")
        if (
            not callable(getattr(binder, "freeze_for_publication", None))
            or not callable(getattr(binder, "register_publication_temporary", None))
            or not callable(getattr(binder, "revalidate_for_publication", None))
        ):
            raise SupervisorError("evidence publication freeze adapter is incomplete")
        if not self._secret_sentinels or any(
            type(value) is not str or not value for value in self._secret_sentinels
        ):
            raise SupervisorError("result secret sentinel set is invalid")

    def publish(
        self, result: Mapping[str, object], proof: TraceTerminalProof
    ) -> ArtifactDescriptor:
        if self._published or self._ambiguous_install is not None:
            raise SupervisorError("authoritative result was already published")
        if (
            type(proof) is not TraceTerminalProof
            or proof._phase != "FINALIZER_ACCEPTED"
            or proof._writer_state not in {"NOT_STARTED", "ABSENT_REAPED_CLOSED"}
            or proof._owned_writer_count != 0
        ):
            raise SupervisorError("result publication lacks terminal trace proof")
        if type(result) is not dict:
            raise SupervisorError("authoritative result must be an exact object")
        if _contains_secret_sentinel(result, self._secret_sentinels):
            raise SupervisorError("secret sentinel reached authoritative result")
        self._contract.require_valid_result(result)
        bundle = self._bundle() if callable(self._bundle) else self._bundle
        if bundle is None:
            raise SupervisorError("authoritative evidence bundle is unavailable")
        if proof._bundle is not bundle:
            raise SupervisorError(
                "terminal trace proof does not bind the exact evidence bundle"
            )
        offline_evidence = result.get("offline_evidence")
        if type(offline_evidence) is dict:
            trace = offline_evidence.get("trace")
            if type(trace) is dict and trace.get("trace_state") != proof._trace_state:
                raise SupervisorError(
                    "terminal trace proof does not bind the result trace mode"
                )
        freeze = self._binder.freeze_for_publication(bundle)

        def final_revalidation(staging_path: Path) -> None:
            self._binder.register_publication_temporary(bundle, freeze, staging_path)
            evidence = self._binder.revalidate_for_publication(bundle, freeze)
            if result.get("offline_evidence") != evidence:
                raise SupervisorError(
                    "authoritative result does not bind the frozen evidence"
                )

        try:
            descriptor = atomic_write_json_no_replace(
                self._path,
                result,
                mode=0o600,
                relative_to=self._path.parent,
                pre_publish=final_revalidation,
            )
        except AtomicPublicationAmbiguity as error:
            self._ambiguous_install = error.expected_artifact
            self._ambiguous_quarantine = self._quarantine_ambiguous_result(
                error.expected_artifact
            )
            raise SupervisorError(
                "authoritative result installation is ambiguous"
            ) from error
        except Exception as error:
            raise SupervisorError("authoritative result publication failed") from error
        proof._phase = "PUBLISHED"
        self._published = True
        self._result_authoritative = True
        return descriptor

    @property
    def result_install_ambiguous(self) -> bool:
        return self._ambiguous_install is not None

    @property
    def result_authority_claimed(self) -> bool:
        return self._result_authoritative

    def publish_emergency(
        self, *, stage: str, safety_gates: Sequence[str] = ()
    ) -> ArtifactDescriptor:
        """Publish only the bounded non-readiness record after authority failure."""

        if self._published:
            raise SupervisorError("emergency publication conflicts with result state")
        if self._path.exists():
            raise SupervisorError("emergency publication conflicts with result state")
        if (
            self._ambiguous_install is not None
            and not self._ambiguous_install_matches()
        ):
            raise SupervisorError("result ambiguity proof no longer matches")
        if type(stage) is not str or not stage or len(stage) > 64:
            raise SupervisorError("emergency stage is invalid")
        if type(safety_gates) not in {tuple, list} or any(
            type(gate) is not str
            or gate not in {*OFFLINE_GATE_ORDER, "offline.result_publication"}
            for gate in safety_gates
        ):
            raise SupervisorError("emergency safety gate inventory is invalid")
        exit_code = 30 if safety_gates else 40
        lines = [
            "HOLOAGENT0_EMERGENCY_V1",
            f"stage={stage}",
            f"exit_code={exit_code}",
            "safety_gates=" + ",".join(safety_gates),
            "readiness_claim=NONE",
            "",
        ]
        payload = "\n".join(lines).encode("ascii", errors="strict")
        try:
            descriptor = atomic_write_bytes_no_replace(
                self._path.with_name("emergency.txt"),
                payload,
                mode=0o600,
                relative_to=self._path.parent,
            )
        except Exception as error:
            raise SupervisorError("emergency publication failed") from error
        self._published = True
        return descriptor

    def _ambiguous_install_matches(self) -> bool:
        proof = self._ambiguous_install
        quarantine = self._ambiguous_quarantine
        if proof is None or quarantine is None or self._path.exists():
            return False
        try:
            metadata = quarantine.lstat()
            payload = quarantine.read_bytes()
        except OSError:
            return False
        return (
            stat.S_ISREG(metadata.st_mode)
            and not quarantine.is_symlink()
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_dev == proof.device
            and metadata.st_ino == proof.inode
            and metadata.st_size == proof.size
            and hashlib.sha256(payload).hexdigest() == proof.sha256
        )

    def _quarantine_ambiguous_result(self, proof: ArtifactDescriptor) -> Path:
        if not self._ambiguous_install_matches_at(self._path, proof):
            raise SupervisorError("ambiguous result identity cannot be quarantined")
        quarantine = self._path.with_name(
            f".{self._path.name}.ambiguous-{proof.sha256[:16]}"
        )
        directory_fd = -1
        try:
            directory_fd = os.open(
                self._path.parent,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
            )
            _rename_no_replace(
                directory_fd, self._path.name, directory_fd, quarantine.name
            )
            os.fsync(directory_fd)
        except OSError as error:
            raise SupervisorError("ambiguous result quarantine failed") from error
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)
        if self._path.exists() or not self._ambiguous_install_matches_at(
            quarantine, proof
        ):
            raise SupervisorError("ambiguous result quarantine is not stable")
        return quarantine

    @staticmethod
    def _ambiguous_install_matches_at(path: Path, proof: ArtifactDescriptor) -> bool:
        try:
            metadata = path.lstat()
            payload = path.read_bytes()
        except OSError:
            return False
        return (
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and metadata.st_dev == proof.device
            and metadata.st_ino == proof.inode
            and metadata.st_size == proof.size
            and hashlib.sha256(payload).hexdigest() == proof.sha256
        )


def _rename_no_replace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    result = renameat2(
        source_directory_fd,
        os.fsencode(source_name),
        destination_directory_fd,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _terminal_gate(
    gate: Mapping[str, object], status: str, reason: str
) -> dict[str, object]:
    """Return one exact terminal gate without mutating accepted ledger data."""

    if not isinstance(gate, Mapping) or status not in {
        "PASS",
        "FAIL",
        "SKIPPED",
        "NOT_RUN",
        "QUALIFIED",
    }:
        raise SupervisorError("terminal gate transition is invalid")
    terminal = copy.deepcopy(dict(gate))
    terminal["status"] = status
    terminal["reason"] = reason
    return terminal


def _production_artifact_requirements(
    run_root: Path,
) -> dict[str, ArtifactRequirement]:
    root = Path(os.path.abspath(run_root))
    names = {
        "trace": "trace.ndjson",
        "bootstrap_report": "bootstrap_report.json",
        "ledger_chain_manifest": "ledger_chain_manifest.json",
        "ownership_journal": "ownership_journal.ndjson",
        "violation_journal": "violation_journal.ndjson",
        "host_observer_pre": "host_observer_pre.json",
        "host_observer_post": "host_observer_post.json",
    }
    if tuple(names) != REQUIRED_OFFLINE_ARTIFACTS:
        raise SupervisorError("production artifact inventory is not exact")
    return {
        name: ArtifactRequirement(root / relative_path, expected_mode=0o400)
        for name, relative_path in names.items()
    }


def _production_host_observer_identity(
    *,
    trace_state: str,
    live_launch: LiveTraceLaunchOutcome | None,
    supervisor_identity: ProcessIdentity,
) -> ProcessIdentity:
    if type(supervisor_identity) is not ProcessIdentity:
        raise SupervisorError("supervisor observer fallback identity is invalid")
    if trace_state == "FULL":
        if type(live_launch) is not LiveTraceLaunchOutcome:
            raise SupervisorError("FULL host observer identity is unavailable")
        return live_launch.coordinator_identity
    if trace_state not in {"FINALIZER_ONLY", "NOT_STARTED"}:
        raise SupervisorError("host observer trace state is invalid")
    if live_launch is not None:
        raise SupervisorError("non-FULL host observer has a live coordinator")
    return supervisor_identity


def _terminal_signal_from_runtime(runtime: SupervisorSignalRuntime) -> str | None:
    if type(runtime) is not SupervisorSignalRuntime:
        raise SupervisorError("terminal signal runtime is invalid")
    launch, handoff = runtime.snapshot()
    if launch.coordinator_launch_committed:
        if handoff is None:
            raise SupervisorError("committed signal handoff is unavailable")
        signal_name = handoff.pending_signal
    else:
        signal_name = launch.first_signal
    if signal_name is not None and signal_name not in _SIGNALS:
        raise SupervisorError("terminal signal is invalid")
    return signal_name


def _authoritative_terminal_signal(state: BootstrapState) -> str | None:
    runtime = state.signal_runtime
    if type(runtime) is SupervisorSignalRuntime:
        return _terminal_signal_from_runtime(runtime)
    return state.decision.first_signal


def _trace_policy_initial_manifest(
    raw_manifest: object, *, coordinator_pid: int
) -> dict[int, list[dict[str, object]]]:
    """Translate the reviewed launcher FD report into policy provenance."""

    if type(coordinator_pid) is not int or coordinator_pid <= 0:
        raise SupervisorError("trace-policy coordinator identity is invalid")
    if type(raw_manifest) is not list or len(raw_manifest) > 256:
        raise SupervisorError("bootstrap FD manifest is invalid")
    entries: list[dict[str, object]] = []
    seen: set[int] = set()
    for raw in raw_manifest:
        if (
            type(raw) is not dict
            or set(raw) != {"fd", "target", "cloexec"}
            or type(raw.get("fd")) is not int
            or raw["fd"] < 0
            or raw["fd"] in seen
            or type(raw.get("target")) is not str
            or not raw["target"]
            or type(raw.get("cloexec")) is not bool
        ):
            raise SupervisorError("bootstrap FD manifest entry is invalid")
        target = raw["target"]
        entry: dict[str, object] = {
            "fd": raw["fd"],
            "cloexec": raw["cloexec"],
        }
        if target.startswith("pipe:[") and target.endswith("]"):
            inode_text = target[6:-1]
            if not inode_text.isdecimal():
                raise SupervisorError("bootstrap pipe provenance is invalid")
            entry.update(kind="pipe", inode=int(inode_text))
        elif target == "/dev/null":
            entry["kind"] = "character_device"
        elif target.startswith("/"):
            entry["kind"] = "regular_file"
        else:
            raise SupervisorError("bootstrap FD target is unreviewed")
        seen.add(raw["fd"])
        entries.append(entry)
    return {coordinator_pid: entries}


def _read_canonical_trace(
    source: Path | _SealedTraceArtifact,
) -> tuple[dict[str, object], ...]:
    retained = (
        _open_sealed_trace(source, allow_empty=True)
        if isinstance(source, Path)
        else source
    )
    if type(retained) is not _SealedTraceArtifact:
        raise SupervisorError("canonical trace source is invalid")
    payload = retained.payload
    records: list[dict[str, object]] = []
    for expected_index, raw_line in enumerate(payload.splitlines()):
        if not raw_line:
            raise SupervisorError("canonical trace contains an empty record")
        try:
            record = json.loads(raw_line)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SupervisorError("canonical trace record is invalid") from error
        if type(record) is not dict or record.get("record_index") != expected_index:
            raise SupervisorError("canonical trace order is invalid")
        records.append(record)
    return tuple(records)


def _source_commit() -> str:
    repository_root = Path(__file__).resolve().parents[3]
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SupervisorError("source commit is unavailable") from error
    commit = completed.stdout.strip()
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise SupervisorError("source commit is invalid")
    return commit


def _apply_nonfull_finalizers(
    gates: list[dict[str, object]],
    decision: BootstrapDecision,
    scenario: SupervisorScenario,
) -> None:
    early_unsafe_fd = (
        not scenario.bootstrap.inherited_fd_safe and gates[2]["status"] == "NOT_RUN"
    )
    postflight_pass = (
        scenario.bootstrap.sanitation_ok
        and scenario.cleanup_complete
        and not early_unsafe_fd
        and not (scenario.trace_fault is not None and scenario.tracees_live)
    )
    _set_gate(
        gates,
        23,
        "PASS" if postflight_pass else "FAIL",
        "OK" if postflight_pass else "POSTFLIGHT_FAILED",
    )

    if scenario.trace_fault is not None:
        _set_gate(gates, 24, "FAIL", scenario.trace_fault)
    elif decision.trace_state == "FINALIZER_ONLY":
        _set_gate(gates, 24, "PASS", "OK")
    else:
        trace_reason = (
            "TRACE_NOT_STARTED"
            if not scenario.bootstrap.sanitation_ok
            else "TRACE_BOOTSTRAP_FAILED"
        )
        _set_gate(gates, 24, "FAIL", trace_reason)

    if scenario.network_violation is not None:
        _set_gate(gates, 25, "FAIL", scenario.network_violation)
    elif gates[24]["status"] == "PASS":
        _set_gate(gates, 25, "PASS", "OK")
    else:
        _set_gate(gates, 25, "SKIPPED", "DEPENDENCY_NOT_AVAILABLE")

    _set_gate(
        gates,
        26,
        "PASS" if scenario.evidence_binding_ok else "FAIL",
        "OK" if scenario.evidence_binding_ok else "EVIDENCE_BINDING_MISMATCH",
    )


def _contains_secret_sentinel(value: object, sentinels: frozenset[str]) -> bool:
    if type(value) is str:
        return any(sentinel in value for sentinel in sentinels)
    if type(value) is dict:
        return any(
            _contains_secret_sentinel(key, sentinels)
            or _contains_secret_sentinel(child, sentinels)
            for key, child in value.items()
        )
    if type(value) in {list, tuple}:
        return any(_contains_secret_sentinel(child, sentinels) for child in value)
    return False


def _bootstrap_failure(
    gates: list[dict[str, object]],
    *,
    first_signal: str | None,
    inherited_failure: bool,
    sanitation_ok: bool,
) -> BootstrapDecision:
    finalizer_only = inherited_failure and sanitation_ok
    return BootstrapDecision(
        "FINALIZER_ONLY_BOOTSTRAP_FAILURE"
        if finalizer_only
        else "NOT_STARTED_BOOTSTRAP_FAILURE",
        "FINALIZER_ONLY" if finalizer_only else "NOT_STARTED",
        False,
        first_signal,
        tuple(gates),
    )


def _gate_skeleton() -> list[dict[str, object]]:
    return [
        {
            "id": gate_id,
            "status": "NOT_RUN",
            "role": _ROLE_OVERRIDES.get(gate_id, "required"),
            "reason": "EARLIER_BLOCKING_GATE",
            "measurements": [],
            "thresholds": [],
            "log_paths": [],
            "child_command_exit_code": None,
        }
        for gate_id in OFFLINE_GATE_ORDER
    ]


def _set_gate(
    gates: list[dict[str, object]], index: int, status: str, reason: str
) -> None:
    gates[index]["status"] = status
    gates[index]["reason"] = reason


def _classify(
    decision: BootstrapDecision,
    gates: list[dict[str, object]],
    *,
    functional_started: bool,
    progress_stopped: bool,
) -> SupervisorRunResult:
    blocking = tuple(gate["id"] for gate in gates if gate["status"] == "FAIL")
    safety = tuple(
        gate_id
        for gate_id in blocking
        if gate_id.startswith("safety.") or gate_id == "offline.network_policy"
    )
    harness = tuple(
        gate_id
        for gate_id in blocking
        if gate_id in {"offline.trace_integrity", "offline.evidence_binding"}
    )
    if safety:
        primary = safety[0]
        label, status, exit_code = "FAIL_SAFETY", "FAIL", 30
    elif harness:
        primary = harness[0]
        label, status, exit_code = "FAIL_HARNESS", "FAIL", 40
    elif decision.first_signal is not None:
        primary = None
        label, status = "INTERRUPTED", "INTERRUPTED"
        exit_code = _SIGNAL_EXIT[decision.first_signal]
    elif blocking:
        primary = blocking[0]
        first = primary.split(".", 1)[0]
        label = {
            "source": "FAIL_SOURCE",
            "runtime": "FAIL_RUNTIME",
            "openclaw": "FAIL_OPENCLAW",
            "skills": "FAIL_AGENTOS",
            "agentos": "FAIL_AGENTOS",
            "semantic": "FAIL_SEMANTIC",
            "chatbot": "FAIL_CHATBOT",
        }.get(first, "FAIL_HARNESS")
        status, exit_code = "FAIL", 20
    else:
        primary = None
        label, status, exit_code = "PASS_HOLOAGENT0_OFFLINE", "PASS", 0
    return SupervisorRunResult(
        launch_state=decision.launch_state,
        trace_state=decision.trace_state,
        gates=tuple(gates),
        primary_blocking_gate=primary,
        blocking_gates=blocking,
        label=label,
        status=status,
        exit_code=exit_code,
        functional_coordinator_started=functional_started,
        progress_stopped=progress_stopped,
        finalizer_order=_FINALIZER_ORDER,
        first_signal=decision.first_signal,
    )
