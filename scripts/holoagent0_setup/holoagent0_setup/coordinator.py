"""Fail-closed traced-coordinator core for the workstation offline profile."""

from __future__ import annotations

import copy
import ctypes
from dataclasses import dataclass, replace
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
from typing import Callable, Mapping, Protocol, Sequence

from .atomic_io import canonical_json_bytes
from .broker import (
    BrokerProtocolError,
    MessageType,
    prewarm_broker_codec,
    read_frame,
    write_frame,
)
from .constants import OFFLINE_GATE_ORDER
from .cyclone_policy import CONFIG_ROLES, EXPECTED_CONFIG_SHA256
from .process_identity import ProcessIdentity
from .signal_handoff import (
    CoordinatorSignalHandoff,
    SignalHandoffError,
    SignalHandoffInterrupted,
)


class CoordinatorError(RuntimeError):
    """Coordinator progress could not be proved safe."""


class CoordinatorInterrupted(CoordinatorError, SignalHandoffInterrupted):
    """A reviewed termination signal entered the installed cleanup path."""


_REQUIRED_ENVIRONMENT = {
    "START_G1_PUBVEL": "0",
    "G1_DRY_RUN": "1",
    "ALLOW_G1_MOTION": "0",
    "ROS_DOMAIN_ID": "77",
    "ROS_LOCALHOST_ONLY": "1",
    "ROS2CLI_DISABLE_DAEMON": "1",
    "RMW_IMPLEMENTATION": "rmw_cyclonedds_cpp",
}
_CONTROL_PROCESSES = frozenset({"g1_pubvel_node", "g1_pubmove_node", "g1_pubcmd_node"})
_CANONICAL_JSON_PREWARM_VALUE = {
    "signals": ["HUP", "INT", "TERM"],
    "state": "READY",
}
_CANONICAL_JSON_PREWARM_BYTES = b'{"signals":["HUP","INT","TERM"],"state":"READY"}'


def _prewarm_canonical_json_codec() -> None:
    """Load the reviewed JSON and broker codecs before the readiness boundary."""

    try:
        encoded = canonical_json_bytes(_CANONICAL_JSON_PREWARM_VALUE)
    except Exception as error:
        raise CoordinatorError("canonical JSON prewarm failed") from error
    if encoded != _CANONICAL_JSON_PREWARM_BYTES:
        raise CoordinatorError("canonical JSON prewarm result is invalid")
    try:
        prewarm_broker_codec()
    except BrokerProtocolError as error:
        raise CoordinatorError("canonical JSON prewarm failed") from error


@dataclass(frozen=True)
class CoordinatorEnvironment:
    """The exact safety-relevant environment inherited by the coordinator."""

    values: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, values: Mapping[str, object]) -> "CoordinatorEnvironment":
        if not isinstance(values, Mapping):
            raise CoordinatorError("coordinator environment is not a mapping")
        selected: list[tuple[str, str]] = []
        for name in _REQUIRED_ENVIRONMENT:
            value = values.get(name)
            if type(value) is not str:
                raise CoordinatorError(f"coordinator environment missing {name}")
            selected.append((name, value))
        return cls(tuple(selected))

    def validate(self) -> None:
        if (
            type(self.values) is not tuple
            or tuple(name for name, _value in self.values)
            != tuple(_REQUIRED_ENVIRONMENT)
            or any(
                type(name) is not str or type(value) is not str
                for name, value in self.values
            )
            or dict(self.values) != _REQUIRED_ENVIRONMENT
        ):
            raise CoordinatorError("coordinator environment posture is unsafe")


@dataclass(frozen=True)
class MotionPreflight:
    """Independent process/ROS/endpoint observations before functional work."""

    observed_processes: tuple[str, ...]
    ros_participants: tuple[str, ...]
    physical_endpoints: tuple[str, ...]

    @classmethod
    def clean(cls) -> "MotionPreflight":
        return cls((), (), ())

    def validate(self) -> None:
        if any(
            type(values) is not tuple
            for values in (
                self.observed_processes,
                self.ros_participants,
                self.physical_endpoints,
            )
        ) or any(
            type(value) is not str or not value
            for values in (
                self.observed_processes,
                self.ros_participants,
                self.physical_endpoints,
            )
            for value in values
        ):
            raise CoordinatorError("motion preflight process inventory is malformed")
        observed_names = {value.rsplit("/", 1)[-1] for value in self.observed_processes}
        if observed_names & _CONTROL_PROCESSES:
            raise CoordinatorError("Unitree control process was observed")
        if self.ros_participants:
            raise CoordinatorError("unexpected ROS participant was observed")
        if self.physical_endpoints:
            raise CoordinatorError("physical Unitree endpoint was observed")


class LinuxMotionPreflightScanner:
    """Build preflight evidence from Linux process state and trusted ROS probes."""

    def __init__(
        self,
        *,
        ros_participant_scanner: Callable[[], Sequence[str]],
        physical_endpoint_scanner: Callable[[], Sequence[str]],
        proc_root: Path = Path("/proc"),
    ) -> dict[str, object]:
        if not callable(ros_participant_scanner) or not callable(
            physical_endpoint_scanner
        ):
            raise CoordinatorError("motion preflight scanner dependency is invalid")
        self._proc_root = Path(proc_root)
        self._ros_participant_scanner = ros_participant_scanner
        self._physical_endpoint_scanner = physical_endpoint_scanner

    def scan(self) -> MotionPreflight:
        observed = _scan_control_processes(self._proc_root)
        try:
            participants = tuple(sorted(set(self._ros_participant_scanner())))
            endpoints = tuple(sorted(set(self._physical_endpoint_scanner())))
        except Exception as error:
            raise CoordinatorError(
                "motion preflight scanner dependency failed"
            ) from error
        result = MotionPreflight(observed, participants, endpoints)
        result.validate()
        return result


@dataclass(frozen=True)
class HostObservation:
    """Bounded host inventory whose authority is verified by its capturer."""

    phase: str
    observer_identity: ProcessIdentity
    network_namespace_inode: int | None
    process_inventory: tuple[str, ...]
    service_inventory: tuple[str, ...]
    listener_inventory: tuple[str, ...]
    process_inventory_sha256: str
    service_inventory_sha256: str
    listener_inventory_sha256: str
    inspection: TrustedHostInspection
    internet_socket_attempts: int = 0
    authority_mac: str = ""

    @classmethod
    def build(
        cls,
        *,
        observer_identity: ProcessIdentity,
        network_namespace_inode: int,
        process_inventory: Sequence[str],
        service_inventory: Sequence[str],
        listener_inventory: Sequence[str],
        inspection: TrustedHostInspection,
        internet_socket_attempts: int = 0,
        phase: str = "pre",
    ) -> HostObservation:
        processes = tuple(process_inventory)
        services = tuple(service_inventory)
        listeners = tuple(listener_inventory)
        if type(inspection) is not TrustedHostInspection:
            raise CoordinatorError("trusted host inspection is required")
        return cls(
            phase=phase,
            observer_identity=observer_identity,
            network_namespace_inode=network_namespace_inode,
            process_inventory=processes,
            service_inventory=services,
            listener_inventory=listeners,
            process_inventory_sha256=_inventory_digest(processes),
            service_inventory_sha256=_inventory_digest(services),
            listener_inventory_sha256=_inventory_digest(listeners),
            inspection=inspection,
            internet_socket_attempts=internet_socket_attempts,
        )

    @property
    def state(self) -> str:
        return "OBSERVED"

    @property
    def process_count(self) -> int:
        return len(self.process_inventory)

    @property
    def service_count(self) -> int:
        return len(self.service_inventory)

    @property
    def listener_count(self) -> int:
        return len(self.listener_inventory)

    @property
    def preexisting_openclaw(self) -> bool:
        return bool(self.service_inventory) or self.inspection.preexisting_openclaw

    def validate(self) -> None:
        if self.phase not in {"pre", "post"}:
            raise CoordinatorError("host observation phase is invalid")
        if type(self.observer_identity) is not ProcessIdentity:
            raise CoordinatorError("host observer identity is invalid")
        if (
            type(self.network_namespace_inode) is not int
            or self.network_namespace_inode <= 0
        ):
            raise CoordinatorError("host observation namespace is invalid")
        for inventory, digest in (
            (self.process_inventory, self.process_inventory_sha256),
            (self.service_inventory, self.service_inventory_sha256),
            (self.listener_inventory, self.listener_inventory_sha256),
        ):
            if (
                type(inventory) is not tuple
                or tuple(sorted(set(inventory))) != inventory
                or any(type(item) is not str or not item for item in inventory)
                or digest != _inventory_digest(inventory)
            ):
                raise CoordinatorError("host observation inventory binding is invalid")
        if (
            type(self.internet_socket_attempts) is not int
            or self.internet_socket_attempts < 0
        ):
            raise CoordinatorError("host observation count is invalid")
        if self.internet_socket_attempts:
            raise CoordinatorError("host-namespace internet socket attempt observed")
        if type(self.inspection) is not TrustedHostInspection:
            raise CoordinatorError("trusted host inspection is missing")
        self.inspection.validate()
        if self.listener_inventory != self.inspection.listener_inventory:
            raise CoordinatorError("host listener evidence is not command-bound")


@dataclass(frozen=True)
class HostObservationOutcome:
    """Evidence-lane representation of an observation or an honest absence."""

    phase: str
    state: str
    observation: HostObservation | None
    cause_gate: str | None
    reason: str | None

    @classmethod
    def observed(cls, observation: HostObservation) -> HostObservationOutcome:
        return cls(observation.phase, "OBSERVED", observation, None, None)

    @classmethod
    def not_run(
        cls, *, phase: str, cause_gate: str, reason: str
    ) -> HostObservationOutcome:
        return cls(phase, "NOT_RUN", None, cause_gate, reason)

    def validate(self) -> None:
        if self.phase not in {"pre", "post"}:
            raise CoordinatorError("host observation outcome phase is invalid")
        if self.state == "OBSERVED":
            if (
                type(self.observation) is not HostObservation
                or self.observation.phase != self.phase
                or self.cause_gate is not None
                or self.reason is not None
            ):
                raise CoordinatorError("observed host outcome is malformed")
            self.observation.validate()
            return
        allowed = {
            ("safety.workstation_preflight", "INTERRUPTED_BEFORE_GATE"),
            ("safety.workstation_preflight", "EARLIER_BLOCKING_GATE"),
            ("safety.workstation_postflight", "POSTFLIGHT_FAILED"),
        }
        if (
            self.state != "NOT_RUN"
            or self.observation is not None
            or (self.cause_gate, self.reason) not in allowed
        ):
            raise CoordinatorError("NOT_RUN host outcome is malformed")


@dataclass(frozen=True)
class DDSMarkerHandle:
    original_name: str
    begin_name: str


class _LinuxPrctlOperations:
    PR_SET_NAME = 15
    PR_GET_NAME = 16

    def __init__(self) -> None:
        self._libc = ctypes.CDLL(None, use_errno=True)

    @staticmethod
    def current_pid() -> int:
        return os.getpid()

    def get_name(self) -> str:
        buffer = ctypes.create_string_buffer(16)
        if self._libc.prctl(self.PR_GET_NAME, ctypes.byref(buffer), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_GET_NAME failed")
        return buffer.value.decode("ascii", errors="strict")

    def set_name(self, value: str) -> None:
        encoded = value.encode("ascii", errors="strict")
        if len(encoded) > 15 or not encoded:
            raise ValueError("process name is not representable")
        if self._libc.prctl(self.PR_SET_NAME, ctypes.c_char_p(encoded), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_NAME failed")


class LinuxDDSMarker:
    """Emit identity- and nonce-bound trace markers through Linux ``prctl``."""

    def __init__(
        self,
        nonce: str,
        coordinator_identity: ProcessIdentity,
        *,
        reviewed_process_name: str,
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        operations: object | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise CoordinatorError("DDS marker nonce is invalid")
        if type(coordinator_identity) is not ProcessIdentity:
            raise CoordinatorError("DDS marker coordinator identity is invalid")
        if (
            type(reviewed_process_name) is not str
            or not reviewed_process_name
            or not reviewed_process_name.isascii()
            or len(reviewed_process_name.encode("ascii")) > 15
            or reviewed_process_name.startswith(("H0B", "H0E", "H0R", "H0F"))
        ):
            raise CoordinatorError("DDS marker reviewed process name is invalid")
        self._nonce = nonce
        self._identity = coordinator_identity
        self._reviewed_process_name = reviewed_process_name
        self._operations = operations or _LinuxPrctlOperations()
        validator = identity_validator or (
            lambda identity: identity.matches_coordinator_session()
        )
        if not callable(validator):
            raise CoordinatorError("DDS marker identity validator is invalid")
        self._identity_validator = validator
        self._active = False
        self._handle: DDSMarkerHandle | None = None
        self._begin_emitted = False
        self._end_completed = False

    @property
    def begin_emitted(self) -> bool:
        return self._begin_emitted

    @property
    def end_completed(self) -> bool:
        return self._end_completed

    @property
    def active_handle(self) -> DDSMarkerHandle | None:
        return self._handle

    def begin(self) -> DDSMarkerHandle:
        if self._active:
            raise CoordinatorError("DDS BEGIN marker repeated")
        self._require_identity()
        original = ""
        begin_name = f"H0B{self._nonce[:12]}"
        handle: DDSMarkerHandle | None = None
        try:
            original = self._operations.get_name()
            if original != self._reviewed_process_name:
                raise CoordinatorError("DDS marker reviewed process name changed")
            handle = DDSMarkerHandle(original, begin_name)
            self._operations.set_name(begin_name)
            self._begin_emitted = True
            self._active = True
            self._handle = handle
            if self._operations.get_name() != begin_name:
                raise CoordinatorError("DDS BEGIN marker did not persist exactly")
        except Exception as error:
            if handle is not None and self._operations.get_name() == begin_name:
                self._begin_emitted = True
                self._active = True
                self._handle = handle
            if self._active and handle is not None:
                try:
                    self._complete_end(handle)
                except Exception as restore_error:
                    raise CoordinatorError(
                        "DDS BEGIN marker restore failed"
                    ) from restore_error
            if isinstance(error, CoordinatorInterrupted):
                raise
            if isinstance(error, CoordinatorError):
                raise
            raise CoordinatorError("DDS BEGIN marker failed") from error
        return handle

    def end(self, handle: DDSMarkerHandle) -> None:
        if type(handle) is not DDSMarkerHandle or not self._active:
            raise CoordinatorError("DDS marker handle is invalid")
        self._require_identity()
        self._complete_end(handle)

    def _complete_end(self, handle: DDSMarkerHandle) -> None:
        end_name = f"H0E{self._nonce[:12]}"
        interrupted: CoordinatorInterrupted | None = None
        try:
            if self._operations.get_name() != handle.begin_name:
                raise CoordinatorError("DDS BEGIN marker identity changed")
            try:
                self._operations.set_name(end_name)
            except CoordinatorInterrupted as error:
                interrupted = error
                if self._operations.get_name() != end_name:
                    raise
            if self._operations.get_name() != end_name:
                raise CoordinatorError("DDS END marker did not persist exactly")
            self._operations.set_name(handle.original_name)
            if self._operations.get_name() != handle.original_name:
                raise CoordinatorError("coordinator process name was not restored")
        except Exception as error:
            try:
                self._operations.set_name(handle.original_name)
                if self._operations.get_name() != handle.original_name:
                    raise CoordinatorError("coordinator process name was not restored")
            except Exception as restore_error:
                raise CoordinatorError(
                    "DDS END marker restore failed"
                ) from restore_error
            self._active = False
            self._handle = None
            if isinstance(error, CoordinatorInterrupted):
                raise
            raise CoordinatorError("DDS END marker failed") from error
        self._active = False
        self._handle = None
        self._end_completed = True
        if interrupted is not None:
            raise interrupted

    def _require_identity(self) -> None:
        if (
            self._operations.current_pid() != self._identity.pid
            or self._identity_validator(self._identity) is not True
        ):
            raise CoordinatorError("DDS marker coordinator identity mismatch")


@dataclass(frozen=True)
class HandoffMarkerEmission:
    phase: str
    token: str
    identity: ProcessIdentity


class LinuxHandoffMarker:
    """Emit and immediately restore the two coordinator handoff boundaries."""

    def __init__(
        self,
        nonce: str,
        coordinator_identity: ProcessIdentity,
        *,
        reviewed_process_name: str,
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        operations: object | None = None,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise CoordinatorError("handoff marker nonce is invalid")
        if type(coordinator_identity) is not ProcessIdentity:
            raise CoordinatorError("handoff marker coordinator identity is invalid")
        if (
            type(reviewed_process_name) is not str
            or not reviewed_process_name
            or not reviewed_process_name.isascii()
            or len(reviewed_process_name.encode("ascii")) > 15
            or reviewed_process_name.startswith(("H0B", "H0E", "H0R", "H0F"))
        ):
            raise CoordinatorError("handoff marker reviewed process name is invalid")
        self._nonce = nonce
        self._identity = coordinator_identity
        self._reviewed_process_name = reviewed_process_name
        self._operations = operations or _LinuxPrctlOperations()
        validator = identity_validator or (
            lambda identity: identity.matches_coordinator_session()
        )
        if not callable(validator):
            raise CoordinatorError("handoff marker identity validator is invalid")
        self._identity_validator = validator
        self._state = "READINESS"

    def emit_readiness_begin(self) -> HandoffMarkerEmission:
        if self._state != "READINESS":
            raise CoordinatorError("handoff marker is out of order")
        emission = self._emit("R", "READINESS_BEGIN")
        self._state = "FUNCTIONAL"
        return emission

    def emit_functional_begin(self) -> HandoffMarkerEmission:
        if self._state != "FUNCTIONAL":
            raise CoordinatorError("handoff marker is out of order")
        emission = self._emit("F", "FUNCTIONAL_BEGIN")
        self._state = "COMPLETE"
        return emission

    def restore_after_failure(self) -> None:
        if self._state == "FUNCTIONAL":
            if self._operations.get_name() != f"H0R{self._nonce[:12]}":
                raise CoordinatorError("handoff marker identity changed before restore")
            self._operations.set_name(self._reviewed_process_name)
            if self._operations.get_name() != self._reviewed_process_name:
                raise CoordinatorError("handoff marker restore failed")
            self._state = "FAILED"
            return
        if self._state in {"READINESS", "COMPLETE", "FAILED"}:
            if self._operations.get_name() != self._reviewed_process_name:
                raise CoordinatorError("handoff marker restore state is invalid")
            return
        raise CoordinatorError("handoff marker restore state is invalid")

    def _emit(self, prefix: str, phase: str) -> HandoffMarkerEmission:
        if self._operations.current_pid() != self._identity.pid:
            raise CoordinatorError("handoff marker coordinator identity mismatch")
        if (
            phase == "READINESS_BEGIN"
            and self._identity_validator(self._identity) is not True
        ):
            raise CoordinatorError("handoff marker coordinator identity mismatch")
        marker_name = f"H0{prefix}{self._nonce[:12]}"
        expected_name = (
            self._reviewed_process_name
            if phase == "READINESS_BEGIN"
            else f"H0R{self._nonce[:12]}"
        )
        try:
            if self._operations.get_name() != expected_name:
                raise CoordinatorError("handoff marker reviewed process name changed")
            self._operations.set_name(marker_name)
            if self._operations.get_name() != marker_name:
                raise CoordinatorError("handoff marker did not persist exactly")
            if phase == "FUNCTIONAL_BEGIN":
                self._operations.set_name(self._reviewed_process_name)
                if self._operations.get_name() != self._reviewed_process_name:
                    raise CoordinatorError("coordinator process name was not restored")
        except Exception as error:
            try:
                self._operations.set_name(self._reviewed_process_name)
                if self._operations.get_name() != self._reviewed_process_name:
                    raise CoordinatorError("coordinator process name was not restored")
            except Exception as restore_error:
                raise CoordinatorError(
                    "handoff marker restore failed"
                ) from restore_error
            self._state = "FAILED"
            if isinstance(error, CoordinatorInterrupted):
                raise
            if isinstance(error, CoordinatorError):
                raise
            raise CoordinatorError("handoff marker failed") from error
        return HandoffMarkerEmission(phase, self._nonce[:12], self._identity)


class LinuxHostObserver:
    """Read host process/listener evidence without constructing an IP socket."""

    def __init__(
        self,
        identity: ProcessIdentity,
        *,
        proc_root: Path = Path("/proc"),
        identity_validator: object | None = None,
        inspection_runtime: object | None = None,
        maximum_processes: int = 32768,
    ) -> None:
        if type(identity) is not ProcessIdentity:
            raise CoordinatorError("host observer identity is malformed")
        if type(maximum_processes) is not int or not 1 <= maximum_processes <= 32768:
            raise CoordinatorError("host process inventory bound is invalid")
        self._identity = identity
        self._proc_root = Path(proc_root)
        validator = identity_validator or (
            lambda observed: observed.matches_proc(self._proc_root)
        )
        if not callable(validator):
            raise CoordinatorError("host observer identity validator is invalid")
        self._identity_validator = validator
        if not callable(getattr(inspection_runtime, "inspect", None)):
            raise CoordinatorError("trusted host inspection runtime is required")
        self._inspection_runtime = inspection_runtime
        self._maximum_processes = maximum_processes
        self._namespace_fd = -1
        self._self_namespace_fd = -1
        self._namespace_inode: int | None = None
        self._secret = secrets.token_bytes(32)
        self._phases: list[str] = []
        self._pre_start_times: dict[int, int] | None = None
        self._outcomes = {
            phase: HostObservationOutcome.not_run(
                phase=phase,
                cause_gate="safety.workstation_preflight",
                reason="EARLIER_BLOCKING_GATE",
            )
            for phase in ("pre", "post")
        }

    def set_not_run(self, *, cause_gate: str, reason: str) -> None:
        for phase in ("pre", "post"):
            if self._outcomes[phase].state != "OBSERVED":
                outcome = HostObservationOutcome.not_run(
                    phase=phase, cause_gate=cause_gate, reason=reason
                )
                outcome.validate()
                self._outcomes[phase] = outcome

    def outcome(self, phase: str) -> HostObservationOutcome:
        try:
            return self._outcomes[phase]
        except KeyError as error:
            raise CoordinatorError(
                "host observation outcome phase is invalid"
            ) from error

    def capture(self, phase: str) -> HostObservation:
        if phase not in {"pre", "post"} or phase in self._phases:
            raise CoordinatorError("host observer phase is out of order")
        if phase == "post" and self._phases != ["pre"]:
            raise CoordinatorError("host post-observation preceded pre-observation")
        inode = self._require_namespace()
        processes, services = _read_host_process_inventory(
            self._proc_root, self._maximum_processes
        )
        start_times = _process_start_times(processes)
        if phase == "pre":
            self._pre_start_times = start_times
        elif self._pre_start_times is None or any(
            self._pre_start_times[pid] != start_times[pid]
            for pid in self._pre_start_times.keys() & start_times.keys()
        ):
            raise CoordinatorError("host process PID reuse was observed")
        if self._require_namespace() != inode:
            raise CoordinatorError("host observer namespace changed before inspection")
        try:
            inspection = self._inspection_runtime.inspect()
        except CoordinatorError:
            raise
        except Exception as error:
            raise CoordinatorError("trusted host inspection failed") from error
        if type(inspection) is not TrustedHostInspection:
            raise CoordinatorError("trusted host inspection result is malformed")
        inspection.validate()
        listeners = inspection.listener_inventory
        observation = HostObservation.build(
            phase=phase,
            observer_identity=self._identity,
            network_namespace_inode=inode,
            process_inventory=processes,
            service_inventory=services,
            listener_inventory=listeners,
            inspection=inspection,
        )
        observation = replace(
            observation, authority_mac=_host_observation_mac(self._secret, observation)
        )
        self.validate_capture(observation)
        self._phases.append(phase)
        self._outcomes[phase] = HostObservationOutcome.observed(observation)
        return observation

    def validate_capture(self, observation: HostObservation) -> None:
        if type(observation) is not HostObservation:
            raise CoordinatorError("host observation authority object is invalid")
        try:
            observation.validate()
            inode = self._require_namespace()
        except CoordinatorError as error:
            raise CoordinatorError(
                "host observation authority validation failed"
            ) from error
        expected = _host_observation_mac(self._secret, observation)
        if (
            observation.observer_identity != self._identity
            or observation.network_namespace_inode != inode
            or not hmac.compare_digest(observation.authority_mac, expected)
        ):
            raise CoordinatorError("host observation authority binding mismatch")

    def close(self) -> None:
        for attribute in ("_namespace_fd", "_self_namespace_fd"):
            fd = getattr(self, attribute)
            if fd >= 0:
                setattr(self, attribute, -1)
                os.close(fd)

    def _require_namespace(self) -> int:
        if os.getpid() != self._identity.pid:
            raise CoordinatorError("host observer current PID does not match identity")
        if (
            self._identity.matches_proc(self._proc_root) is not True
            or self._identity_validator(self._identity) is not True
        ):
            raise CoordinatorError("host observer process identity mismatch")
        path = self._proc_root / str(self._identity.pid) / "ns" / "net"
        self_path = self._proc_root / "self" / "ns" / "net"
        try:
            if self._namespace_fd < 0:
                self._namespace_fd = os.open(
                    path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                )
                self._namespace_inode = os.fstat(self._namespace_fd).st_ino
            if self._self_namespace_fd < 0:
                self._self_namespace_fd = os.open(
                    self_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                )
            path_inode = os.stat(path).st_ino
            self_path_inode = os.stat(self_path).st_ino
            fd_inode = os.fstat(self._namespace_fd).st_ino
            self_fd_inode = os.fstat(self._self_namespace_fd).st_ino
        except OSError as error:
            raise CoordinatorError(
                "host network namespace could not be retained"
            ) from error
        if (
            self._namespace_inode is None
            or self._namespace_inode <= 0
            or path_inode != self._namespace_inode
            or fd_inode != self._namespace_inode
            or self_path_inode != self._namespace_inode
            or self_fd_inode != self._namespace_inode
            or os.get_inheritable(self._namespace_fd)
            or os.get_inheritable(self._self_namespace_fd)
        ):
            raise CoordinatorError("host observer current network namespace changed")
        return self._namespace_inode


@dataclass(frozen=True)
class TrustedHostInspection:
    """Closed command evidence produced by the reviewed host inspection runtime."""

    gateway_status_command: tuple[str, ...]
    gateway_status_exit: int
    gateway_status_sha256: str
    gateway_status_state: str
    service_definitions: tuple[str, ...]
    listener_command: tuple[str, ...]
    listener_inventory: tuple[str, ...]

    def validate(self) -> None:
        if (
            type(self.gateway_status_command) is not tuple
            or self.gateway_status_command[-5:]
            != ("gateway", "status", "--deep", "--no-probe", "--json")
            or type(self.gateway_status_exit) is not int
            or not re.fullmatch(r"[0-9a-f]{64}", self.gateway_status_sha256)
            or self.gateway_status_state not in {"INACTIVE", "ACTIVE"}
            or type(self.service_definitions) is not tuple
            or tuple(sorted(set(self.service_definitions))) != self.service_definitions
            or type(self.listener_command) is not tuple
            or self.listener_command[-2:] != ("-H", "-ltnp")
            or type(self.listener_inventory) is not tuple
            or tuple(sorted(set(self.listener_inventory))) != self.listener_inventory
            or any(
                type(value) is not str or not value
                for values in (
                    self.gateway_status_command,
                    self.service_definitions,
                    self.listener_command,
                    self.listener_inventory,
                )
                for value in values
            )
        ):
            raise CoordinatorError("trusted host inspection is malformed")

    @property
    def preexisting_openclaw(self) -> bool:
        return (
            self.gateway_status_state == "ACTIVE"
            or bool(self.service_definitions)
            or any(
                "openclaw" in line.lower() or _listener_uses_default_openclaw_port(line)
                for line in self.listener_inventory
            )
        )


class LinuxHostInspectionRuntime:
    """Run the exact local-only OpenClaw and listener observation commands."""

    def __init__(
        self,
        *,
        openclaw_cli: Path,
        openclaw_cli_sha256: str,
        ss_executable: Path,
        ss_executable_sha256: str,
        service_roots: Sequence[Path],
        command_runner: Callable[[Sequence[str]], object] | None = None,
        maximum_output_bytes: int = 1024 * 1024,
    ) -> None:
        self._openclaw_cli = _require_absolute_observer_executable(
            openclaw_cli, openclaw_cli_sha256, "OpenClaw"
        )
        self._ss_executable = _require_absolute_observer_executable(
            ss_executable, ss_executable_sha256, "ss"
        )
        roots = tuple(Path(path) for path in service_roots)
        if (
            not roots
            or any(not path.is_absolute() for path in roots)
            or len(set(roots)) != len(roots)
        ):
            raise CoordinatorError("service-definition roots are invalid")
        if (
            type(maximum_output_bytes) is not int
            or not 4096 <= maximum_output_bytes <= 4 * 1024 * 1024
        ):
            raise CoordinatorError("host command output bound is invalid")
        self._service_roots = roots
        self._command_runner = command_runner or self._run_command
        if not callable(self._command_runner):
            raise CoordinatorError("host command runner is invalid")
        self._maximum_output_bytes = maximum_output_bytes

    def inspect(self) -> TrustedHostInspection:
        status_command = (
            str(self._openclaw_cli),
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        )
        status_exit, status_stdout = self._execute(status_command)
        try:
            status_document = json.loads(status_stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CoordinatorError("OpenClaw lifecycle status is malformed") from error
        if status_exit != 0:
            raise CoordinatorError("OpenClaw lifecycle status failed")
        status_state = _classify_openclaw_status(status_document)

        listener_command = (str(self._ss_executable), "-H", "-ltnp")
        listener_exit, listener_stdout = self._execute(listener_command)
        if listener_exit != 0:
            raise CoordinatorError("ss listener inspection failed")
        try:
            listener_text = listener_stdout.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise CoordinatorError("ss listener inspection is malformed") from error
        listener_inventory = tuple(
            sorted(
                set(line.strip() for line in listener_text.splitlines() if line.strip())
            )
        )
        if any(len(line.encode("utf-8")) > 16 * 1024 for line in listener_inventory):
            raise CoordinatorError("ss listener entry exceeds its bound")

        inspection = TrustedHostInspection(
            gateway_status_command=status_command,
            gateway_status_exit=status_exit,
            gateway_status_sha256=hashlib.sha256(status_stdout).hexdigest(),
            gateway_status_state=status_state,
            service_definitions=_scan_openclaw_service_definitions(self._service_roots),
            listener_command=listener_command,
            listener_inventory=listener_inventory,
        )
        inspection.validate()
        return inspection

    def _execute(self, command: tuple[str, ...]) -> tuple[int, bytes]:
        try:
            completed = self._command_runner(command)
            returncode = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except Exception as error:
            raise CoordinatorError("host observation command failed") from error
        if (
            type(returncode) is not int
            or type(stdout) is not bytes
            or type(stderr) is not bytes
            or len(stdout) > self._maximum_output_bytes
            or len(stderr) > self._maximum_output_bytes
        ):
            raise CoordinatorError("host observation command result is malformed")
        return returncode, stdout

    @staticmethod
    def _run_command(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            tuple(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
            env={"LC_ALL": "C", "TZ": "UTC"},
        )


class HostObservationWriterAdapter:
    """Validate coordinator evidence before delegating to the evidence lane."""

    def __init__(self, sink: object) -> None:
        writer = getattr(sink, "write_host_observer_artifact", None)
        if not callable(writer):
            raise CoordinatorError("trusted host observation writer is required")
        self._writer = writer
        self._receipts: dict[str, object] = {}

    @property
    def persisted_phases(self) -> frozenset[str]:
        return frozenset(self._receipts)

    def persist(self, outcome: HostObservationOutcome) -> object:
        if type(outcome) is not HostObservationOutcome:
            raise CoordinatorError("host observation writer input is malformed")
        outcome.validate()
        if outcome.phase in self._receipts:
            raise CoordinatorError("host observation artifact was already persisted")
        try:
            receipt = self._writer(outcome)
        except CoordinatorError:
            raise
        except Exception as error:
            raise CoordinatorError("host observation persistence failed") from error
        expected_path = f"host_observer_{outcome.phase}.json"
        close_receipt = getattr(receipt, "close", None)
        if getattr(receipt, "relative_path", None) != expected_path or not callable(
            close_receipt
        ):
            raise CoordinatorError("host observation writer receipt is invalid")
        try:
            close_receipt()
        except Exception as error:
            raise CoordinatorError("host observation receipt close failed") from error
        self._receipts[outcome.phase] = expected_path
        return expected_path


class HostObservationArtifactSink:
    """Map coordinator outcomes to the evidence lane's closed artifact writer."""

    def __init__(
        self,
        *,
        run_root: Path,
        artifact_writer: Callable[..., object],
    ) -> None:
        root = Path(run_root)
        try:
            root_stat = root.stat(follow_symlinks=False)
        except OSError as error:
            raise CoordinatorError("host artifact root is unavailable") from error
        if (
            not root.is_absolute()
            or not root.is_dir()
            or os.path.islink(root)
            or root_stat.st_nlink < 1
            or not callable(artifact_writer)
        ):
            raise CoordinatorError("host artifact writer configuration is invalid")
        self._run_root = root
        self._artifact_writer = artifact_writer

    def write_host_observer_artifact(self, outcome: HostObservationOutcome) -> object:
        if type(outcome) is not HostObservationOutcome:
            raise CoordinatorError("host artifact outcome is malformed")
        outcome.validate()
        observation = outcome.observation
        common: dict[str, object] = {
            "relative_to": self._run_root,
            "state": outcome.state,
            "cause_gate": outcome.cause_gate,
            "reason": outcome.reason,
        }
        if observation is not None:
            inspection = observation.inspection
            common.update(
                collector_identity=observation.observer_identity,
                network_namespace_inode=observation.network_namespace_inode,
                observed_processes=observation.process_inventory,
                observed_services=observation.service_inventory,
                observed_listeners=observation.listener_inventory,
                internet_socket_attempts=(),
                trusted_inspection={
                    "gateway_status_command": list(inspection.gateway_status_command),
                    "gateway_status_exit": inspection.gateway_status_exit,
                    "gateway_status_sha256": inspection.gateway_status_sha256,
                    "gateway_status_state": inspection.gateway_status_state,
                    "service_definitions": list(inspection.service_definitions),
                    "listener_command": list(inspection.listener_command),
                    "listener_inventory": list(inspection.listener_inventory),
                },
            )
        try:
            return self._artifact_writer(
                self._run_root / f"host_observer_{outcome.phase}.json",
                **common,
            )
        except CoordinatorError:
            raise
        except Exception as error:
            raise CoordinatorError("host observer artifact write failed") from error


@dataclass(frozen=True)
class LoopbackNamespaceProof:
    """Before/after proof for the isolated action child's network namespace."""

    before_inode: int
    after_inode: int
    interfaces: tuple[str, ...]
    addresses: tuple[str, ...]
    routes: tuple[str, ...]
    host_inode: int

    @classmethod
    def valid_fixture(cls) -> "LoopbackNamespaceProof":
        return cls(
            before_inode=1,
            after_inode=1,
            interfaces=("lo",),
            addresses=("127.0.0.1/8",),
            routes=("local 127.0.0.0/8",),
            host_inode=123,
        )

    def validate(self) -> None:
        if (
            type(self.before_inode) is not int
            or type(self.after_inode) is not int
            or self.before_inode <= 0
            or self.before_inode != self.after_inode
        ):
            raise CoordinatorError("action-child network namespace changed")
        if type(self.host_inode) is not int or self.host_inode <= 0:
            raise CoordinatorError("host network namespace identity is invalid")
        if self.before_inode == self.host_inode:
            raise CoordinatorError("action-child namespace is not isolated from host")
        if self.interfaces != ("lo",):
            raise CoordinatorError("action-child namespace is not loopback-only")
        if self.addresses != ("127.0.0.1/8",):
            raise CoordinatorError("action-child namespace has a non-loopback address")
        if self.routes != ("local 127.0.0.0/8",):
            raise CoordinatorError("action-child namespace has a non-loopback route")


@dataclass
class RetainedNamespaceCapture:
    """Identity-bound namespace FD retained across the isolated action."""

    identity: ProcessIdentity
    fd: int
    inode: int
    host_inode: int
    before: tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]


class LinuxNamespaceAuthority:
    """Capture loopback evidence from an identity-bound ``/proc/<pid>/net``."""

    def __init__(
        self,
        *,
        proc_root: Path = Path("/proc"),
        identity_validator: object | None = None,
    ) -> None:
        self._proc_root = Path(proc_root)
        validator = identity_validator or (
            lambda identity: identity.matches_proc(self._proc_root)
        )
        if not callable(validator):
            raise CoordinatorError("namespace identity validator is invalid")
        self._identity_validator = validator

    def begin(
        self, identity: ProcessIdentity, *, host_inode: int
    ) -> RetainedNamespaceCapture:
        if type(identity) is not ProcessIdentity:
            raise CoordinatorError("namespace process identity is malformed")
        if type(host_inode) is not int or host_inode <= 0:
            raise CoordinatorError("host namespace identity is invalid")
        if self._identity_validator(identity) is not True:
            raise CoordinatorError("namespace process identity did not match /proc")
        namespace_path = self._proc_root / str(identity.pid) / "ns" / "net"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(namespace_path, flags)
            namespace_stat = os.fstat(fd)
            inode = namespace_stat.st_ino
            if inode <= 0 or inode == host_inode or os.get_inheritable(fd):
                raise CoordinatorError(
                    "action-child namespace is not retained and isolated"
                )
            before = _read_loopback_namespace(self._proc_root, identity.pid)
            if self._identity_validator(identity) is not True:
                raise CoordinatorError(
                    "namespace process identity changed during capture"
                )
            proof = LoopbackNamespaceProof(inode, inode, *before, host_inode)
            proof.validate()
            return RetainedNamespaceCapture(identity, fd, inode, host_inode, before)
        except Exception:
            if "fd" in locals():
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise

    def finish(self, handle: RetainedNamespaceCapture) -> LoopbackNamespaceProof:
        if type(handle) is not RetainedNamespaceCapture or handle.fd < 0:
            raise CoordinatorError("retained namespace handle is invalid")
        try:
            if self._identity_validator(handle.identity) is not True:
                raise CoordinatorError(
                    "namespace process identity changed after action"
                )
            if os.fstat(handle.fd).st_ino != handle.inode:
                raise CoordinatorError("retained namespace identity changed")
            after = _read_loopback_namespace(self._proc_root, handle.identity.pid)
            if after != handle.before:
                raise CoordinatorError(
                    "loopback namespace evidence changed during action"
                )
            proof = LoopbackNamespaceProof(
                handle.inode,
                handle.inode,
                *after,
                handle.host_inode,
            )
            proof.validate()
            return proof
        except OSError as error:
            raise CoordinatorError(
                "retained namespace could not be revalidated"
            ) from error
        finally:
            self.abort(handle)

    @staticmethod
    def abort(handle: RetainedNamespaceCapture) -> None:
        if type(handle) is not RetainedNamespaceCapture:
            raise CoordinatorError("retained namespace handle is invalid")
        if handle.fd >= 0:
            fd = handle.fd
            handle.fd = -1
            os.close(fd)


@dataclass(frozen=True)
class SemanticFixtureOutcome:
    """Participant cleanup proof returned before the semantic DDS END marker."""

    gate: Mapping[str, object]
    cleanup_complete: bool
    participant_count: int
    socket_count: int

    def validate(self) -> None:
        if not isinstance(self.gate, Mapping) or self.gate.get("id") != (
            "semantic.fixture_query"
        ):
            raise CoordinatorError("semantic fixture gate is not exact")
        if (
            self.cleanup_complete is not True
            or type(self.participant_count) is not int
            or type(self.socket_count) is not int
            or self.participant_count != 0
            or self.socket_count != 0
        ):
            raise CoordinatorError(
                "semantic fixture left participants or sockets before END"
            )


@dataclass(frozen=True)
class ActionChildReport:
    """Bounded action-child result accepted before host postflight."""

    gates: tuple[Mapping[str, object], ...]
    semantic_fixture: SemanticFixtureOutcome
    namespace_proof: LoopbackNamespaceProof
    cleanup_complete: bool
    participant_count: int
    socket_count: int
    owned_identity: ProcessIdentity

    def validate(self) -> None:
        if type(self.gates) is not tuple or any(
            not isinstance(gate, Mapping) for gate in self.gates
        ):
            raise CoordinatorError("action-child gate report is malformed")
        if tuple(gate.get("id") for gate in self.gates) != OFFLINE_GATE_ORDER[4:23]:
            raise CoordinatorError("action-child gate order is not exact")
        if type(self.semantic_fixture) is not SemanticFixtureOutcome:
            raise CoordinatorError("semantic fixture outcome is malformed")
        self.semantic_fixture.validate()
        if self.gates[13] != self.semantic_fixture.gate:
            raise CoordinatorError("semantic fixture gate binding is invalid")
        if type(self.namespace_proof) is not LoopbackNamespaceProof:
            raise CoordinatorError("action-child namespace proof is malformed")
        self.namespace_proof.validate()
        if self.cleanup_complete is not True:
            raise CoordinatorError("action-child cleanup is incomplete")
        if (
            type(self.participant_count) is not int
            or type(self.socket_count) is not int
            or self.participant_count != 0
            or self.socket_count != 0
        ):
            raise CoordinatorError("action-child cleanup left participants or sockets")
        if type(self.owned_identity) is not ProcessIdentity:
            raise CoordinatorError("action-child ownership binding is malformed")


@dataclass(frozen=True)
class CoordinatorResult:
    sealed: bool
    postflight_passed: bool
    interrupted_signal: str | None = None


class Task4SignalBarrier:
    """Adapt the concrete Task 4 coordinator handoff to Task 8 ordering."""

    def __init__(
        self,
        handoff: CoordinatorSignalHandoff,
        *,
        request_write_fd: int,
        acceptance_read_fd: int,
        blocked_signals: frozenset[str],
        dispositions: Mapping[str, bool],
        handoff_marker: LinuxHandoffMarker,
        deadline: int | float | None = None,
    ) -> None:
        if type(handoff) is not CoordinatorSignalHandoff:
            raise CoordinatorError("Task 4 coordinator handoff is not exact")
        if type(handoff_marker) is not LinuxHandoffMarker:
            raise CoordinatorError("Task 4 handoff marker is not exact")
        if (
            type(request_write_fd) is not int
            or request_write_fd < 0
            or type(acceptance_read_fd) is not int
            or acceptance_read_fd < 0
            or request_write_fd == acceptance_read_fd
        ):
            raise CoordinatorError("signal broker descriptors are invalid")
        if type(blocked_signals) is not frozenset:
            raise CoordinatorError("blocked signal proof is not exact")
        if not isinstance(dispositions, Mapping):
            raise CoordinatorError("signal disposition proof is not a mapping")
        self._handoff = handoff
        self._handoff_marker = handoff_marker
        self._request_write_fd = request_write_fd
        self._acceptance_read_fd = acceptance_read_fd
        self._blocked_signals = blocked_signals
        self._dispositions = dict(dispositions)
        self._deadline = deadline
        self._accepted = False
        self._request_closed = False
        self._acceptance_closed = False

    def emit_readiness_begin(self) -> HandoffMarkerEmission:
        return self._handoff_marker.emit_readiness_begin()

    def emit_functional_begin(self) -> HandoffMarkerEmission:
        if not self._accepted or not (self._request_closed and self._acceptance_closed):
            raise CoordinatorError("functional marker preceded signal acceptance")
        return self._handoff_marker.emit_functional_begin()

    def restore_handoff_marker(self) -> None:
        self._handoff_marker.restore_after_failure()

    def complete_two_way_acceptance(self) -> None:
        if self._accepted:
            raise CoordinatorError("signal readiness barrier repeated")
        try:
            self._handoff.send_ready(
                self._request_write_fd,
                blocked=set(self._blocked_signals),
                dispositions=self._dispositions,
                deadline=self._deadline,
            )
            os.close(self._request_write_fd)
            self._request_closed = True
            self._handoff.receive_acceptance(
                self._acceptance_read_fd, deadline=self._deadline
            )
            os.close(self._acceptance_read_fd)
            self._acceptance_closed = True
        except CoordinatorInterrupted:
            self._close_broker_descriptors()
            raise
        except (SignalHandoffError, OSError) as error:
            self._close_broker_descriptors()
            raise CoordinatorError("SIGNAL_READY_ACCEPTED was not validated") from error
        if self._handoff.snapshot().acceptance_validated is not True:
            raise CoordinatorError("SIGNAL_READY_ACCEPTED was not validated")
        self._accepted = True

    def _close_broker_descriptors(self) -> None:
        """Close both coordinator-owned handoff descriptors exactly once."""

        if not self._request_closed:
            try:
                os.close(self._request_write_fd)
            except OSError:
                pass
            self._request_closed = True
        if not self._acceptance_closed:
            try:
                os.close(self._acceptance_read_fd)
            except OSError:
                pass
            self._acceptance_closed = True

    def record_functional_progress(self) -> None:
        if not self._accepted or not (self._request_closed and self._acceptance_closed):
            raise CoordinatorError("functional progress preceded signal acceptance")
        for descriptor in (self._request_write_fd, self._acceptance_read_fd):
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            raise CoordinatorError("signal broker descriptor remained open")
        try:
            self._handoff.record_functional_progress()
        except SignalHandoffError as error:
            raise CoordinatorError("functional progress was not authorized") from error


@dataclass(frozen=True)
class LedgerClientHead:
    generation: int
    digest: str
    sealed: bool


class Task3LedgerClient:
    """Submit candidates over Task 4 pipes; never own persistent ledger files."""

    def __init__(
        self,
        *,
        candidate_write_fd: int,
        acceptance_read_fd: int,
        initial_document: Mapping[str, object],
        initial_digest: str,
        deadline: int | float | None = None,
    ) -> None:
        if (
            type(candidate_write_fd) is not int
            or candidate_write_fd < 0
            or type(acceptance_read_fd) is not int
            or acceptance_read_fd < 0
            or candidate_write_fd == acceptance_read_fd
        ):
            raise CoordinatorError("ledger broker descriptors are invalid")
        if type(initial_document) is not dict:
            raise CoordinatorError("initial ledger acknowledgement is not exact")
        document = copy.deepcopy(initial_document)
        if (
            type(document.get("ledger_nonce")) is not str
            or type(document.get("run_id")) is not str
            or type(document.get("generation")) is not int
            or document.get("generation") < 0
            or type(initial_digest) is not str
            or len(initial_digest) != 64
            or any(character not in "0123456789abcdef" for character in initial_digest)
            or type(document.get("gates")) is not list
            or document.get("sealed") is not False
        ):
            raise CoordinatorError("initial ledger acknowledgement is malformed")
        self._candidate_write_fd = candidate_write_fd
        self._acceptance_read_fd = acceptance_read_fd
        _force_cloexec(self._candidate_write_fd)
        _force_cloexec(self._acceptance_read_fd)
        self._current = document
        self._head = LedgerClientHead(document["generation"], initial_digest, False)
        self._sequence = 1
        self._deadline = deadline

    @property
    def current(self) -> dict[str, object]:
        return copy.deepcopy(self._current)

    @property
    def head(self) -> LedgerClientHead:
        return self._head

    def submit(
        self,
        gates: list[Mapping[str, object]],
        *,
        sealed: bool,
        semantic_dds_window: str | None = None,
    ) -> None:
        if self._head.sealed:
            raise CoordinatorError("ledger client is already sealed")
        candidate = {
            "schema_version": "holoagent0.offline-ledger.v1",
            "run_id": self._current["run_id"],
            "ledger_nonce": self._current["ledger_nonce"],
            "generation": self._head.generation + 1,
            "previous_generation": self._head.generation,
            "previous_digest": self._head.digest,
            "sealed": sealed,
            "semantic_dds_window": (
                self._current["semantic_dds_window"]
                if semantic_dds_window is None
                else semantic_dds_window
            ),
            "gates": copy.deepcopy(gates),
        }
        message = {
            "type": MessageType.LEDGER_CANDIDATE.value,
            "run_nonce": candidate["ledger_nonce"],
            "sequence": self._sequence,
            "generation": candidate["generation"],
            "previous_generation": candidate["previous_generation"],
            "previous_digest": candidate["previous_digest"],
            "candidate": candidate,
        }
        request_sha256 = hashlib.sha256(canonical_json_bytes(message)).hexdigest()
        exchange_error: BaseException | None = None
        accepted: dict[str, object] | None = None
        for _attempt in range(2):
            try:
                write_frame(
                    self._candidate_write_fd,
                    message,
                    deadline=self._deadline,
                    ledger_validator=lambda value: value == candidate,
                )
                observed = read_frame(
                    self._acceptance_read_fd,
                    deadline=self._deadline,
                    exact_one=False,
                )
            except (BrokerProtocolError, OSError) as error:
                exchange_error = error
                continue
            if (
                observed.get("type") == MessageType.LEDGER_ACCEPTED.value
                and observed.get("run_nonce") == candidate["ledger_nonce"]
                and observed.get("sequence") == self._sequence
                and observed.get("generation") == candidate["generation"]
                and type(observed.get("ledger_sha256")) is str
                and observed.get("request_sha256") == request_sha256
            ):
                accepted = observed
                break
            exchange_error = CoordinatorError("ledger acknowledgement binding mismatch")
        if accepted is None:
            raise CoordinatorError("ledger broker exchange failed") from exchange_error
        self._current = copy.deepcopy(candidate)
        self._head = LedgerClientHead(
            candidate["generation"], accepted["ledger_sha256"], sealed
        )
        self._sequence += 1


class CoordinatorLedgerAdapter:
    """Translate coordinator transitions into acknowledged pipe candidates."""

    def __init__(self, client: Task3LedgerClient) -> None:
        if type(client) is not Task3LedgerClient:
            raise CoordinatorError("Task 3 ledger client is not exact")
        self._client = client
        self._pending_postflight_gates: list[Mapping[str, object]] | None = None

    @property
    def sealed(self) -> bool:
        return self._client.head.sealed

    def pass_preflight(self) -> None:
        gates = copy.deepcopy(self._client.current["gates"])
        if any(gate["status"] != "PASS" for gate in gates[:2]):
            raise CoordinatorError("bootstrap gates were not acknowledged")
        gates[2].update(status="PASS", reason="OK")
        self._append(gates)

    def open_dds_window(self) -> None:
        if self._client.current["semantic_dds_window"] != "NOT_ENTERED":
            raise CoordinatorError("semantic DDS window cannot be opened")
        self._append(
            copy.deepcopy(self._client.current["gates"]), semantic_dds_window="OPEN"
        )

    def accept_host_preexisting(self, observation: HostObservation) -> None:
        observation.validate()
        if observation.phase != "pre":
            raise CoordinatorError("host OpenClaw gate requires pre-observation")
        current = copy.deepcopy(self._client.current["gates"])
        if current[2]["status"] != "PASS":
            raise CoordinatorError("workstation preflight was not acknowledged")
        if current[3]["status"] != "NOT_RUN":
            raise CoordinatorError("host OpenClaw gate was already decided")
        failed = observation.preexisting_openclaw
        current[3].update(
            status="FAIL" if failed else "PASS",
            reason="PREEXISTING_OPENCLAW" if failed else "OK",
        )
        self._append(current)
        if failed:
            raise CoordinatorError("pre-existing OpenClaw state was observed")

    def close_dds_window(self) -> None:
        if self._client.current["semantic_dds_window"] != "OPEN":
            raise CoordinatorError("semantic DDS window cannot be closed")
        self._append(
            copy.deepcopy(self._client.current["gates"]), semantic_dds_window="CLOSED"
        )

    def accept_action_gates(self, gates: tuple[Mapping[str, object], ...]) -> None:
        if (
            type(gates) is not tuple
            or tuple(gate.get("id") for gate in gates) != OFFLINE_GATE_ORDER[4:23]
        ):
            raise CoordinatorError("action-child gate order is not exact")
        current = copy.deepcopy(self._client.current["gates"])
        if self._client.current["semantic_dds_window"] != "CLOSED":
            raise CoordinatorError("action gates preceded semantic DDS closure")
        if current[2]["status"] != "PASS":
            raise CoordinatorError("workstation preflight was not acknowledged")
        if current[3]["status"] != "PASS":
            raise CoordinatorError("host OpenClaw gate was not acknowledged")
        current[4:23] = copy.deepcopy(list(gates))
        self._append(current)

    def finalize_postflight(
        self,
        *,
        inner: ActionChildReport,
        host_pre: HostObservation,
        host_post: HostObservation,
    ) -> None:
        inner.validate()
        host_pre.validate()
        host_post.validate()
        if host_pre.phase != "pre" or host_post.phase != "post":
            raise CoordinatorError("host observation phases are not exact")
        if host_pre.observer_identity != host_post.observer_identity:
            raise CoordinatorError("host observer identity changed during action")
        if host_pre.network_namespace_inode != host_post.network_namespace_inode:
            raise CoordinatorError("host network namespace changed during action")
        if inner.namespace_proof.host_inode != host_pre.network_namespace_inode:
            raise CoordinatorError("namespace proof is not bound to host observation")
        gates = copy.deepcopy(self._client.current["gates"])
        gates[23].update(status="PASS", reason="OK")
        self._pending_postflight_gates = gates

    def seal(self) -> None:
        gates = self._pending_postflight_gates
        if gates is None:
            raise CoordinatorError("workstation postflight was not finalized")
        self._append(gates, sealed=True)
        self._pending_postflight_gates = None

    def finalize_failure(self, *, cleanup_complete: bool) -> None:
        if type(cleanup_complete) is not bool:
            raise CoordinatorError("cleanup completion proof is not exact")
        gates = copy.deepcopy(self._client.current["gates"])
        gates[23].update(status="FAIL", reason="POSTFLIGHT_FAILED")
        self._pending_postflight_gates = None
        self._append(gates, sealed=True)

    def finalize_interruption(self) -> None:
        current_document = self._client.current
        if current_document["semantic_dds_window"] == "OPEN":
            raise CoordinatorError("interruption cannot seal an OPEN DDS window")
        gates = copy.deepcopy(current_document["gates"])
        remaining = [
            index
            for index, gate in enumerate(gates[:23])
            if gate["status"] == "NOT_RUN"
        ]
        if remaining:
            if remaining != list(range(remaining[0], 23)):
                raise CoordinatorError("interruption suffix is not contiguous")
            for index in remaining:
                gates[index]["reason"] = "INTERRUPTED_BEFORE_GATE"
            self._append(gates)
            gates = copy.deepcopy(self._client.current["gates"])
        gates[23].update(status="PASS", reason="OK")
        self._pending_postflight_gates = gates

    def _append(
        self,
        gates: list[Mapping[str, object]],
        *,
        sealed: bool = False,
        semantic_dds_window: str | None = None,
    ) -> None:
        self._client.submit(
            gates, sealed=sealed, semantic_dds_window=semantic_dds_window
        )


class Task4OwnershipClient:
    """Durably acknowledge each supervisor-owned journal record before spawn."""

    def __init__(
        self,
        *,
        run_nonce: str,
        record_write_fd: int,
        acceptance_read_fd: int,
        deadline: int | float | None = None,
    ) -> None:
        if type(run_nonce) is not str or not run_nonce:
            raise CoordinatorError("ownership run nonce is invalid")
        if (
            type(record_write_fd) is not int
            or record_write_fd < 0
            or type(acceptance_read_fd) is not int
            or acceptance_read_fd < 0
            or record_write_fd == acceptance_read_fd
        ):
            raise CoordinatorError("ownership broker descriptors are invalid")
        self._run_nonce = run_nonce
        self._record_write_fd = record_write_fd
        self._acceptance_read_fd = acceptance_read_fd
        _force_cloexec(self._record_write_fd)
        _force_cloexec(self._acceptance_read_fd)
        self._deadline = deadline
        self._sequence = 1
        self._action_registered = False
        self._next_participant_index = 0

    def append_identity(self, identity: ProcessIdentity) -> None:
        if type(identity) is not ProcessIdentity:
            raise CoordinatorError("ownership identity is malformed")
        if self._action_registered:
            raise CoordinatorError("action-child ownership identity was repeated")
        message = {
            "type": MessageType.OWNERSHIP_RECORD.value,
            "run_nonce": self._run_nonce,
            "sequence": self._sequence,
            "identity": identity.as_dict(),
            "role": "action_child",
        }
        self._exchange(message)
        self._sequence += 1
        self._action_registered = True

    def append_participant(
        self,
        identity: ProcessIdentity,
        *,
        participant_index: int,
        role: str,
        config_digest: str,
    ) -> dict[str, object]:
        """Bind one stopped participant before its DDS activity is released."""

        if not self._action_registered:
            raise CoordinatorError("action-child ownership must precede participants")
        if self._next_participant_index == 4:
            raise CoordinatorError("participant registration is already complete")
        expected_index = self._next_participant_index
        if (
            type(identity) is not ProcessIdentity
            or type(participant_index) is not int
            or participant_index != expected_index
            or role != CONFIG_ROLES[expected_index]
            or config_digest != EXPECTED_CONFIG_SHA256[expected_index]
        ):
            raise CoordinatorError("participant registration order/binding is invalid")
        message = {
            "type": MessageType.PARTICIPANT_RECORD.value,
            "run_nonce": self._run_nonce,
            "sequence": self._sequence,
            "identity": identity.as_dict(),
            "role": role,
            "participant_index": participant_index,
            "config_digest": config_digest,
        }
        acknowledgement = self._exchange(message)
        self._sequence += 1
        self._next_participant_index += 1
        return acknowledgement

    def require_participant_registration_complete(self) -> None:
        if not self._action_registered or self._next_participant_index != 4:
            raise CoordinatorError("participant registration is incomplete")

    def _exchange(self, message: dict[str, object]) -> dict[str, object]:
        accepted_type = (
            MessageType.OWNERSHIP_ACCEPTED
            if message.get("type") == MessageType.OWNERSHIP_RECORD.value
            else MessageType.PARTICIPANT_ACCEPTED
        )
        request_sha256 = hashlib.sha256(canonical_json_bytes(message)).hexdigest()
        expected = {
            "type": accepted_type.value,
            "run_nonce": self._run_nonce,
            "sequence": self._sequence,
            "request_sha256": request_sha256,
        }
        exchange_error: BaseException | None = None
        accepted = False
        for _attempt in range(2):
            try:
                write_frame(self._record_write_fd, message, deadline=self._deadline)
                observed = read_frame(
                    self._acceptance_read_fd,
                    deadline=self._deadline,
                    exact_one=False,
                )
            except (BrokerProtocolError, OSError) as error:
                exchange_error = error
                continue
            if observed == expected:
                accepted = True
                break
            exchange_error = CoordinatorError(
                "ownership acknowledgement binding mismatch"
            )
        if not accepted:
            raise CoordinatorError(
                "ownership journal exchange failed"
            ) from exchange_error
        return expected


@dataclass(frozen=True)
class ParticipantRegistration:
    """One stopped child reported over the action child's existing IPC pipe."""

    identity: ProcessIdentity
    participant_index: int
    role: str
    config_digest: str

    def validate(self) -> None:
        index = self.participant_index
        if (
            type(self.identity) is not ProcessIdentity
            or type(index) is not int
            or index not in range(4)
            or self.role != CONFIG_ROLES[index]
            or self.config_digest != EXPECTED_CONFIG_SHA256[index]
        ):
            raise CoordinatorError("participant registration binding is invalid")


class ParticipantRegistrationRelay:
    """Relay child-IPC readiness over the coordinator's reviewed broker pipes.

    The later action-child adapter owns its already-approved pipe-only child IPC.
    It keeps each new participant stopped, calls :meth:`register` in the traced
    coordinator, and releases that child only after this relay receives the
    supervisor's identity/config-bound acknowledgement.  The functional child
    never inherits the coordinator/supervisor ownership broker descriptors.
    """

    def __init__(self, ownership_client: object) -> None:
        if not callable(getattr(ownership_client, "append_participant", None)):
            raise CoordinatorError("participant relay ownership client is incomplete")
        self._client = ownership_client
        self._state = "CREATED"
        self._next_index = 0

    def open(self) -> None:
        if self._state != "CREATED":
            raise CoordinatorError("participant registration window repeated")
        self._state = "OPEN"

    def register(self, registration: ParticipantRegistration) -> dict[str, object]:
        if self._state != "OPEN":
            raise CoordinatorError("participant registration window is closed")
        if type(registration) is not ParticipantRegistration:
            raise CoordinatorError("participant registration is not exact")
        registration.validate()
        if registration.participant_index != self._next_index:
            raise CoordinatorError("participant registration order is invalid")
        acknowledgement = self._client.append_participant(
            registration.identity,
            participant_index=registration.participant_index,
            role=registration.role,
            config_digest=registration.config_digest,
        )
        if (
            type(acknowledgement) is not dict
            or acknowledgement.get("type") != MessageType.PARTICIPANT_ACCEPTED.value
        ):
            raise CoordinatorError("participant supervisor acknowledgement is invalid")
        self._next_index += 1
        return acknowledgement

    def receive_child_ready(
        self,
        ready_read_fd: int,
        acceptance_write_fd: int,
        *,
        run_nonce: str,
        deadline: int | float | None = None,
    ) -> None:
        """Relay one child-IPC readiness record without sharing supervisor FDs."""

        try:
            message = read_frame(ready_read_fd, deadline=deadline, exact_one=False)
        except (BrokerProtocolError, OSError) as error:
            raise CoordinatorError(
                "child participant readiness receive failed"
            ) from error
        index = self._next_index
        if (
            message.get("type") != MessageType.PARTICIPANT_RECORD.value
            or message.get("run_nonce") != run_nonce
            or message.get("sequence") != index + 2
        ):
            raise CoordinatorError("child participant readiness binding is invalid")
        try:
            registration = ParticipantRegistration(
                ProcessIdentity.from_dict(message["identity"]),
                message["participant_index"],
                message["role"],
                message["config_digest"],
            )
            acknowledgement = self.register(registration)
            expected_hash = hashlib.sha256(canonical_json_bytes(message)).hexdigest()
            if acknowledgement != {
                "type": MessageType.PARTICIPANT_ACCEPTED.value,
                "run_nonce": run_nonce,
                "sequence": index + 2,
                "request_sha256": expected_hash,
            }:
                raise CoordinatorError(
                    "child participant acknowledgement binding is invalid"
                )
            write_frame(
                acceptance_write_fd,
                acknowledgement,
                deadline=deadline,
            )
        except (BrokerProtocolError, OSError, KeyError, TypeError) as error:
            raise CoordinatorError("child participant relay failed") from error

    def close_complete(self) -> None:
        if self._state != "OPEN" or self._next_index != 4:
            raise CoordinatorError("participant registration is incomplete")
        self._state = "CLOSED"


class CoordinatorCleanupHandlers:
    """Install reviewed handlers before readiness and own failure cleanup."""

    _SIGNALS = {
        signal.SIGHUP: "HUP",
        signal.SIGINT: "INT",
        signal.SIGTERM: "TERM",
    }

    def __init__(self, cleanup_controller: object) -> None:
        if any(
            not callable(getattr(cleanup_controller, method, None))
            for method in (
                "acquire",
                "cleanup",
                "exec_after_ownership_ack",
                "verify_absent",
            )
        ):
            raise CoordinatorError("owned cleanup controller is incomplete")
        self._controller = cleanup_controller
        self._previous: dict[int, object] = {}
        self._installed = False
        self._first_signal: str | None = None

    @property
    def first_signal(self) -> str | None:
        return self._first_signal

    def install(self) -> None:
        if self._installed:
            raise CoordinatorError("coordinator cleanup handlers repeated")
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if not set(self._SIGNALS).issubset(blocked):
            raise CoordinatorError("reviewed signals were not inherited blocked")
        try:
            for number in self._SIGNALS:
                self._previous[number] = signal.getsignal(number)
                signal.signal(number, self._handle)
        except (OSError, RuntimeError, ValueError) as error:
            self._restore_partial()
            raise CoordinatorError(
                "coordinator cleanup handler install failed"
            ) from error
        self._installed = True

    def cleanup(self, identities: Sequence[ProcessIdentity]) -> bool:
        if not self._installed:
            raise CoordinatorError("coordinator cleanup handlers are not installed")
        return bool(self._controller.cleanup(tuple(identities)))

    def acquire(self, identity: ProcessIdentity) -> object:
        if not self._installed:
            raise CoordinatorError("coordinator cleanup handlers are not installed")
        return self._controller.acquire(identity)

    def verify_absent(self, leases: Sequence[object]) -> bool:
        if not self._installed:
            raise CoordinatorError("coordinator cleanup handlers are not installed")
        return bool(self._controller.verify_absent(tuple(leases)))

    def exec_after_ownership_ack(
        self,
        lease: object,
        ownership_client: object,
        exec_action: Callable[[], object],
    ) -> object:
        if not self._installed:
            raise CoordinatorError("coordinator cleanup handlers are not installed")
        return self._controller.exec_after_ownership_ack(
            lease, ownership_client, exec_action
        )

    def restore(self) -> None:
        if not self._installed:
            return
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, set(self._SIGNALS))
            for number, previous in self._previous.items():
                signal.signal(number, previous)
        except (OSError, RuntimeError, ValueError) as error:
            raise CoordinatorError(
                "coordinator cleanup handler restore failed"
            ) from error
        finally:
            self._previous = {}
            self._installed = False

    def _restore_partial(self) -> None:
        for number, previous in self._previous.items():
            try:
                signal.signal(number, previous)
            except (OSError, RuntimeError, ValueError):
                pass
        self._previous = {}

    def _handle(self, signal_number: int, _frame: object) -> None:
        name = self._SIGNALS.get(signal_number)
        if name is None:
            raise CoordinatorError("unknown signal reached cleanup handler")
        if self._first_signal is not None:
            return
        self._first_signal = name
        raise CoordinatorInterrupted(f"coordinator interrupted by {name}")


class _SignalBarrier(Protocol):
    def emit_readiness_begin(self) -> HandoffMarkerEmission: ...

    def complete_two_way_acceptance(self) -> None: ...

    def emit_functional_begin(self) -> HandoffMarkerEmission: ...

    def record_functional_progress(self) -> None: ...

    def restore_handoff_marker(self) -> None: ...


class _Ledger(Protocol):
    sealed: bool

    def pass_preflight(self) -> None: ...

    def open_dds_window(self) -> None: ...

    def accept_host_preexisting(self, observation: HostObservation) -> None: ...

    def close_dds_window(self) -> None: ...

    def accept_action_gates(self, gates: tuple[Mapping[str, object], ...]) -> None: ...

    def finalize_postflight(
        self,
        *,
        inner: ActionChildReport,
        host_pre: HostObservation,
        host_post: HostObservation,
    ) -> None: ...

    def seal(self) -> None: ...

    def finalize_failure(self, *, cleanup_complete: bool) -> None: ...

    def finalize_interruption(self) -> None: ...


class _MotionPreflightScanner(Protocol):
    def scan(self) -> MotionPreflight: ...


class _DDSMarker(Protocol):
    def begin(self) -> DDSMarkerHandle: ...

    def end(self, handle: DDSMarkerHandle) -> None: ...


class _HostObserver(Protocol):
    def capture(self, phase: str) -> HostObservation: ...

    def validate_capture(self, observation: HostObservation) -> None: ...

    def close(self) -> None: ...


class _HostObservationWriter(Protocol):
    def persist(self, outcome: HostObservationOutcome) -> object: ...

    @property
    def persisted_phases(self) -> frozenset[str]: ...


class _ActionChild(Protocol):
    def prepare_ownership(self) -> Sequence[ProcessIdentity]: ...

    def run(
        self,
        environment: CoordinatorEnvironment,
        semantic_window: Callable[
            [Callable[[], SemanticFixtureOutcome]], SemanticFixtureOutcome
        ],
        participant_relay: ParticipantRegistrationRelay,
    ) -> ActionChildReport: ...


class _OwnershipJournal(Protocol):
    def append_identity(self, identity: ProcessIdentity) -> None: ...

    def append_participant(
        self,
        identity: ProcessIdentity,
        *,
        participant_index: int,
        role: str,
        config_digest: str,
    ) -> dict[str, object]: ...


class _CleanupRuntime(Protocol):
    def install(self) -> None: ...

    def acquire(self, identity: ProcessIdentity) -> object: ...

    def exec_after_ownership_ack(
        self,
        lease: object,
        ownership_client: object,
        exec_action: Callable[[], object],
    ) -> object: ...

    def cleanup(self, leases: Sequence[object]) -> bool: ...

    def verify_absent(self, leases: Sequence[object]) -> bool: ...

    def restore(self) -> None: ...


class _NamespaceAuthority(Protocol):
    def begin(
        self, identity: ProcessIdentity, *, host_inode: int
    ) -> RetainedNamespaceCapture: ...

    def finish(self, handle: RetainedNamespaceCapture) -> LoopbackNamespaceProof: ...

    def abort(self, handle: RetainedNamespaceCapture) -> None: ...


class TracedCoordinator:
    """Order coordinator actions so no functional work precedes authorization."""

    def __init__(
        self,
        *,
        signal_barrier: _SignalBarrier,
        ledger: _Ledger,
        host_observer: _HostObserver,
        host_observation_writer: _HostObservationWriter,
        action_child: _ActionChild,
        ownership_journal: _OwnershipJournal,
        environment: CoordinatorEnvironment,
        motion_preflight_scanner: _MotionPreflightScanner,
        cleanup_runtime: _CleanupRuntime,
        namespace_authority: _NamespaceAuthority,
        dds_marker: _DDSMarker,
    ) -> None:
        self.signal_barrier = signal_barrier
        self.ledger = ledger
        self.host_observer = host_observer
        self.host_observation_writer = host_observation_writer
        self.action_child = action_child
        self.ownership_journal = ownership_journal
        self.environment = environment
        self.motion_preflight_scanner = motion_preflight_scanner
        self.cleanup_runtime = cleanup_runtime
        self.namespace_authority = namespace_authority
        self.dds_marker = dds_marker

    def execute(self) -> CoordinatorResult:
        owned_leases: tuple[object, ...] = ()
        namespace_handle: RetainedNamespaceCapture | None = None
        marker_handle: DDSMarkerHandle | None = None
        marker_started = False
        marker_end_attempted = False
        dds_window_open = False
        host_pre: HostObservation | None = None
        host_post: HostObservation | None = None
        host_observer_closed = False
        try:
            _prewarm_canonical_json_codec()
            readiness_marker = self.signal_barrier.emit_readiness_begin()
            if (
                type(readiness_marker) is not HandoffMarkerEmission
                or readiness_marker.phase != "READINESS_BEGIN"
            ):
                raise CoordinatorError("readiness marker emission is invalid")
            self.cleanup_runtime.install()
            self.signal_barrier.complete_two_way_acceptance()
            functional_marker = self.signal_barrier.emit_functional_begin()
            if (
                type(functional_marker) is not HandoffMarkerEmission
                or functional_marker.phase != "FUNCTIONAL_BEGIN"
                or functional_marker.token != readiness_marker.token
                or functional_marker.identity != readiness_marker.identity
            ):
                raise CoordinatorError("functional marker emission is invalid")
            self.signal_barrier.record_functional_progress()
            self.environment.validate()
            scanner = self.motion_preflight_scanner
            if (
                not callable(getattr(scanner, "scan", None))
                or type(scanner) is MotionPreflight
            ):
                raise CoordinatorError("trusted motion preflight scanner is required")
            motion_preflight = scanner.scan()
            if type(motion_preflight) is not MotionPreflight:
                raise CoordinatorError("motion preflight scanner result is malformed")
            motion_preflight.validate()
            self.ledger.pass_preflight()
            _set_host_observations_not_run(
                self.host_observer,
                cause_gate="safety.workstation_postflight",
                reason="POSTFLIGHT_FAILED",
            )

            host_pre = self.host_observer.capture("pre")
            if type(host_pre) is not HostObservation:
                raise CoordinatorError("host pre-observation is malformed")
            self.host_observer.validate_capture(host_pre)
            if host_pre.phase != "pre":
                raise CoordinatorError("host pre-observation phase is invalid")
            pre_outcome = HostObservationOutcome.observed(host_pre)
            self.host_observation_writer.persist(pre_outcome)
            self.ledger.accept_host_preexisting(host_pre)

            prepared_identities = tuple(self.action_child.prepare_ownership())
            if len(prepared_identities) != 1:
                raise CoordinatorError("exactly one action-child identity is required")
            for identity in prepared_identities:
                if type(identity) is not ProcessIdentity:
                    raise CoordinatorError(
                        "action-child ownership identity is malformed"
                    )
                lease = self.cleanup_runtime.acquire(identity)
                if getattr(lease, "identity", None) != identity:
                    raise CoordinatorError("owned-process lease binding is invalid")
                owned_leases = (*owned_leases, lease)

            def run_authorized_action() -> ActionChildReport:
                nonlocal namespace_handle
                nonlocal dds_window_open
                nonlocal marker_handle
                nonlocal marker_started
                namespace_handle = self.namespace_authority.begin(
                    prepared_identities[0],
                    host_inode=host_pre.network_namespace_inode,
                )
                participant_relay = ParticipantRegistrationRelay(self.ownership_journal)

                def semantic_window(
                    semantic_action: Callable[[], SemanticFixtureOutcome],
                ) -> SemanticFixtureOutcome:
                    nonlocal dds_window_open
                    nonlocal marker_handle
                    nonlocal marker_started
                    nonlocal marker_end_attempted
                    if dds_window_open or marker_started:
                        raise CoordinatorError("semantic DDS window repeated")
                    self.ledger.open_dds_window()
                    dds_window_open = True
                    marker_handle = self.dds_marker.begin()
                    marker_started = True
                    participant_relay.open()
                    outcome = semantic_action()
                    if type(outcome) is not SemanticFixtureOutcome:
                        raise CoordinatorError("semantic fixture outcome is malformed")
                    outcome.validate()
                    participant_relay.close_complete()
                    marker_end_attempted = True
                    self.dds_marker.end(marker_handle)
                    marker_handle = None
                    self.ledger.close_dds_window()
                    dds_window_open = False
                    return outcome

                return self.action_child.run(
                    self.environment,
                    semantic_window,
                    participant_relay,
                )

            child_report = self.cleanup_runtime.exec_after_ownership_ack(
                owned_leases[0], self.ownership_journal, run_authorized_action
            )
            if type(child_report) is not ActionChildReport:
                raise CoordinatorError("action-child report is malformed")
            child_report.validate()
            if self.ledger.sealed is True:
                raise CoordinatorError("coordinator ledger sealed during action")
            if child_report.owned_identity != getattr(
                owned_leases[0], "identity", None
            ):
                raise CoordinatorError("action-child report ownership binding mismatch")
            trusted_namespace = self.namespace_authority.finish(namespace_handle)
            namespace_handle = None
            if child_report.namespace_proof != trusted_namespace:
                raise CoordinatorError(
                    "action-child report differs from trusted namespace capture"
                )
            if (
                child_report.namespace_proof.host_inode
                != host_pre.network_namespace_inode
            ):
                raise CoordinatorError(
                    "action-child namespace proof is not bound to host observation"
                )
            if not _verify_owned_absent(self.cleanup_runtime, owned_leases):
                raise CoordinatorError("coordinator owned-child absence was not proved")
            owned_leases = ()
            self.ledger.accept_action_gates(child_report.gates)

            host_post = self.host_observer.capture("post")
            if type(host_post) is not HostObservation:
                raise CoordinatorError("host post-observation is malformed")
            self.host_observer.validate_capture(host_post)
            if host_post.phase != "post":
                raise CoordinatorError("host post-observation phase is invalid")
            if host_pre.network_namespace_inode != host_post.network_namespace_inode:
                raise CoordinatorError("host network namespace changed during action")
            self.host_observation_writer.persist(
                HostObservationOutcome.observed(host_post)
            )
            if host_post.preexisting_openclaw:
                raise CoordinatorError("OpenClaw appeared during isolated action")
            self.host_observer.close()
            host_observer_closed = True
            self.ledger.finalize_postflight(
                inner=child_report, host_pre=host_pre, host_post=host_post
            )
            self.ledger.seal()
            if self.ledger.sealed is not True:
                raise CoordinatorError("coordinator ledger did not seal")
            return CoordinatorResult(sealed=True, postflight_passed=True)
        except CoordinatorInterrupted as interrupted:
            if host_pre is None:
                _set_host_observations_not_run(
                    self.host_observer,
                    cause_gate="safety.workstation_preflight",
                    reason="INTERRUPTED_BEFORE_GATE",
                )
            namespace_closed = _abort_namespace(
                self.namespace_authority, namespace_handle
            )
            namespace_handle = None
            child_cleanup_complete = _cleanup_owned(self.cleanup_runtime, owned_leases)
            if child_cleanup_complete:
                owned_leases = ()
            (
                marker_handle,
                marker_started,
                marker_end_attempted,
                marker_closed,
            ) = _finalize_marker_window(
                self.dds_marker,
                marker_handle,
                marker_started=marker_started,
                end_attempted=marker_end_attempted,
                cleanup_complete=child_cleanup_complete,
            )
            window_closed = not dds_window_open
            if dds_window_open and marker_started and marker_closed:
                try:
                    self.ledger.close_dds_window()
                    dds_window_open = False
                    window_closed = True
                except Exception:
                    window_closed = False
            host_post_safe = True
            if host_pre is not None and namespace_closed and child_cleanup_complete:
                try:
                    host_post = self.host_observer.capture("post")
                    self.host_observer.validate_capture(host_post)
                    self.host_observation_writer.persist(
                        HostObservationOutcome.observed(host_post)
                    )
                    host_post_safe = not host_post.preexisting_openclaw
                except Exception:
                    host_post = None
                    host_post_safe = False
            artifact_complete = _persist_terminal_host_artifacts(
                self.host_observation_writer,
                host_pre=host_pre,
                host_post=host_post,
                interrupted=True,
            )
            host_closed = host_observer_closed or _close_host_observer(
                self.host_observer
            )
            observation_finalized = (host_pre is None and host_post is None) or (
                host_pre is not None and host_post is not None
            )
            cleanup_complete = all(
                (
                    namespace_closed,
                    child_cleanup_complete,
                    marker_closed,
                    window_closed,
                    host_closed,
                    observation_finalized,
                    host_post_safe,
                    artifact_complete,
                )
            )
            if cleanup_complete:
                self.ledger.finalize_interruption()
                self.ledger.seal()
                signal_name = _interruption_signal(interrupted)
                return CoordinatorResult(True, True, signal_name)
            try:
                if dds_window_open:
                    raise CoordinatorError("semantic DDS window remained OPEN")
                if self.ledger.sealed is not True:
                    self.ledger.finalize_failure(cleanup_complete=False)
            except Exception as finalizer_error:
                raise CoordinatorError(
                    "coordinator failure finalization was incomplete"
                ) from finalizer_error
            raise CoordinatorError(
                "coordinator interruption cleanup failed"
            ) from interrupted
        except CoordinatorError as original:
            namespace_closed = _abort_namespace(
                self.namespace_authority, namespace_handle
            )
            host_closed = host_observer_closed or _close_host_observer(
                self.host_observer
            )
            child_cleanup_complete = _cleanup_owned(self.cleanup_runtime, owned_leases)
            if child_cleanup_complete:
                owned_leases = ()
            (
                marker_handle,
                marker_started,
                marker_end_attempted,
                marker_closed,
            ) = _finalize_marker_window(
                self.dds_marker,
                marker_handle,
                marker_started=marker_started,
                end_attempted=marker_end_attempted,
                cleanup_complete=child_cleanup_complete,
            )
            window_closed = not dds_window_open
            if dds_window_open and marker_started and marker_closed:
                try:
                    self.ledger.close_dds_window()
                    dds_window_open = False
                    window_closed = True
                except Exception:
                    window_closed = False
            artifact_complete = _persist_terminal_host_artifacts(
                self.host_observation_writer,
                host_pre=host_pre,
                host_post=host_post,
                interrupted=False,
            )
            cleanup_complete = (
                namespace_closed
                and host_closed
                and child_cleanup_complete
                and marker_closed
                and window_closed
                and artifact_complete
            )
            try:
                if dds_window_open:
                    raise CoordinatorError("semantic DDS window remained OPEN")
                if self.ledger.sealed is not True:
                    self.ledger.finalize_failure(cleanup_complete=cleanup_complete)
            except Exception as finalizer_error:
                raise CoordinatorError(
                    "coordinator failure finalization was incomplete"
                ) from finalizer_error
            if not cleanup_complete:
                raise CoordinatorError(
                    "coordinator owned-child cleanup failed"
                ) from original
            raise
        except Exception as error:
            namespace_closed = _abort_namespace(
                self.namespace_authority, namespace_handle
            )
            host_closed = host_observer_closed or _close_host_observer(
                self.host_observer
            )
            child_cleanup_complete = _cleanup_owned(self.cleanup_runtime, owned_leases)
            if child_cleanup_complete:
                owned_leases = ()
            (
                marker_handle,
                marker_started,
                marker_end_attempted,
                marker_closed,
            ) = _finalize_marker_window(
                self.dds_marker,
                marker_handle,
                marker_started=marker_started,
                end_attempted=marker_end_attempted,
                cleanup_complete=child_cleanup_complete,
            )
            window_closed = not dds_window_open
            if dds_window_open and marker_started and marker_closed:
                try:
                    self.ledger.close_dds_window()
                    dds_window_open = False
                    window_closed = True
                except Exception:
                    window_closed = False
            artifact_complete = _persist_terminal_host_artifacts(
                self.host_observation_writer,
                host_pre=host_pre,
                host_post=host_post,
                interrupted=False,
            )
            cleanup_complete = (
                namespace_closed
                and host_closed
                and child_cleanup_complete
                and marker_closed
                and window_closed
                and artifact_complete
            )
            try:
                if dds_window_open:
                    raise CoordinatorError("semantic DDS window remained OPEN")
                if self.ledger.sealed is not True:
                    self.ledger.finalize_failure(cleanup_complete=cleanup_complete)
            except Exception as finalizer_error:
                raise CoordinatorError(
                    "coordinator failure finalization was incomplete"
                ) from finalizer_error
            if not cleanup_complete:
                raise CoordinatorError(
                    "coordinator owned-child cleanup failed"
                ) from error
            raise CoordinatorError("coordinator dependency failed closed") from error
        finally:
            try:
                self.signal_barrier.restore_handoff_marker()
            except Exception as restore_error:
                raise CoordinatorError(
                    "coordinator handoff marker restore failed"
                ) from restore_error


def _force_cloexec(fd: int) -> None:
    try:
        os.set_inheritable(fd, False)
        flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    except OSError as error:
        raise CoordinatorError("broker descriptor CLOEXEC setup failed") from error
    if not flags & fcntl.FD_CLOEXEC:
        raise CoordinatorError("broker descriptor is inheritable")


def _cleanup_owned(cleanup_runtime: _CleanupRuntime, leases: Sequence[object]) -> bool:
    if not leases:
        return True
    try:
        return cleanup_runtime.cleanup(leases) is True
    except Exception:
        return False


def _persist_terminal_host_artifacts(
    writer: _HostObservationWriter,
    *,
    host_pre: HostObservation | None,
    host_post: HostObservation | None,
    interrupted: bool,
) -> bool:
    try:
        phases = writer.persisted_phases
    except Exception:
        return False
    if not isinstance(phases, frozenset) or not phases <= {"pre", "post"}:
        return False
    try:
        if "pre" not in phases:
            if host_pre is not None:
                return False
            writer.persist(
                HostObservationOutcome.not_run(
                    phase="pre",
                    cause_gate="safety.workstation_preflight",
                    reason=(
                        "INTERRUPTED_BEFORE_GATE"
                        if interrupted
                        else "EARLIER_BLOCKING_GATE"
                    ),
                )
            )
        phases = writer.persisted_phases
        if "post" not in phases:
            if host_post is not None:
                writer.persist(HostObservationOutcome.observed(host_post))
            elif host_pre is None:
                writer.persist(
                    HostObservationOutcome.not_run(
                        phase="post",
                        cause_gate="safety.workstation_preflight",
                        reason=(
                            "INTERRUPTED_BEFORE_GATE"
                            if interrupted
                            else "EARLIER_BLOCKING_GATE"
                        ),
                    )
                )
            else:
                writer.persist(
                    HostObservationOutcome.not_run(
                        phase="post",
                        cause_gate="safety.workstation_postflight",
                        reason="POSTFLIGHT_FAILED",
                    )
                )
        return writer.persisted_phases == frozenset({"pre", "post"})
    except Exception:
        return False


def _verify_owned_absent(
    cleanup_runtime: _CleanupRuntime, leases: Sequence[object]
) -> bool:
    if not leases:
        return True
    verifier = getattr(cleanup_runtime, "verify_absent", None)
    if not callable(verifier):
        return False
    try:
        return verifier(tuple(leases)) is True
    except Exception:
        return False


def _finalize_marker_window(
    marker: _DDSMarker,
    handle: DDSMarkerHandle | None,
    *,
    marker_started: bool,
    end_attempted: bool,
    cleanup_complete: bool,
) -> tuple[DDSMarkerHandle | None, bool, bool, bool]:
    begin_emitted = marker_started or getattr(marker, "begin_emitted", False) is True
    reported_end = getattr(marker, "end_completed", None)
    end_completed = reported_end is True or (
        reported_end is None and handle is None and end_attempted
    )
    active = getattr(marker, "active_handle", None)
    if handle is None and type(active) is DDSMarkerHandle:
        handle = active
    if (
        begin_emitted
        and not end_completed
        and handle is not None
        and cleanup_complete
        and not end_attempted
    ):
        end_attempted = True
        try:
            marker.end(handle)
        except Exception:
            end_completed = getattr(marker, "end_completed", False) is True
        else:
            end_completed = True
        if end_completed:
            handle = None
    return handle, begin_emitted, end_attempted, (not begin_emitted or end_completed)


def _abort_namespace(
    authority: _NamespaceAuthority, handle: RetainedNamespaceCapture | None
) -> bool:
    if handle is None:
        return True
    try:
        authority.abort(handle)
        return True
    except Exception:
        return False


def _close_host_observer(observer: _HostObserver) -> bool:
    try:
        observer.close()
        return True
    except Exception:
        return False


def _set_host_observations_not_run(
    observer: _HostObserver, *, cause_gate: str, reason: str
) -> None:
    setter = getattr(observer, "set_not_run", None)
    if callable(setter):
        setter(cause_gate=cause_gate, reason=reason)


def _interruption_signal(error: CoordinatorInterrupted) -> str:
    match = re.search(r"(?:HUP|INT|TERM)$", str(error))
    if match is None:
        raise CoordinatorError("coordinator interruption signal is unavailable")
    return match.group(0)


def _scan_control_processes(proc_root: Path) -> tuple[str, ...]:
    try:
        pid_roots = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdecimal()),
            key=lambda entry: int(entry.name),
        )
    except OSError as error:
        raise CoordinatorError("motion process inventory is unavailable") from error
    observed: set[str] = set()
    for pid_root in pid_roots:
        try:
            command = (
                _read_bounded_bytes(pid_root / "comm", 256)
                .decode("utf-8", errors="strict")
                .strip()
            )
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError) as error:
            raise CoordinatorError("motion process identity is unreadable") from error
        executable = ""
        try:
            executable = os.path.basename(os.readlink(pid_root / "exe"))
        except FileNotFoundError:
            continue
        except PermissionError:
            # ``comm`` remains a kernel-provided identity even when another
            # user's executable symlink is protected.
            pass
        except OSError as error:
            raise CoordinatorError("motion process executable is unreadable") from error
        for value in (command, executable):
            if value in _CONTROL_PROCESSES:
                observed.add(value)
    return tuple(sorted(observed))


def _read_loopback_namespace(
    proc_root: Path, pid: int
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    net_root = proc_root / str(pid) / "net"
    dev = _read_bounded_proc(net_root / "dev", 64 * 1024)
    route = _read_bounded_proc(net_root / "route", 64 * 1024)
    fib = _read_bounded_proc(net_root / "fib_trie", 1024 * 1024)
    inet6_path = net_root / "if_inet6"
    inet6 = _read_bounded_proc(inet6_path, 64 * 1024) if inet6_path.exists() else ""

    dev_lines = dev.splitlines()
    if len(dev_lines) < 3:
        raise CoordinatorError("network interface evidence is incomplete")
    interfaces: list[str] = []
    for line in dev_lines[2:]:
        if not line.strip():
            continue
        name, separator, _counters = line.partition(":")
        normalized = name.strip()
        if separator != ":" or not normalized or not normalized.isascii():
            raise CoordinatorError("network interface evidence is malformed")
        interfaces.append(normalized)
    if tuple(interfaces) != ("lo",):
        raise CoordinatorError("action-child namespace is not loopback-only")

    route_rows = [line for line in route.splitlines()[1:] if line.strip()]
    if route_rows:
        raise CoordinatorError("action-child namespace has a non-loopback route")
    if inet6.strip():
        raise CoordinatorError("action-child namespace has an IPv6 address")
    addresses = set(re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}", fib))
    if "127.0.0.1" not in addresses or any(
        not address.startswith("127.") for address in addresses
    ):
        raise CoordinatorError("action-child namespace address evidence is unsafe")
    if "127.0.0.0/8" not in fib:
        raise CoordinatorError("loopback route evidence is incomplete")
    return ("lo",), ("127.0.0.1/8",), ("local 127.0.0.0/8",)


def _read_bounded_proc(path: Path, maximum: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(4096, maximum - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise CoordinatorError("namespace evidence exceeds its byte bound")
        return b"".join(chunks).decode("ascii", errors="strict")
    except (OSError, UnicodeError) as error:
        raise CoordinatorError("namespace evidence could not be read") from error
    finally:
        if "fd" in locals():
            os.close(fd)


def _inventory_digest(values: Sequence[str]) -> str:
    return hashlib.sha256(canonical_json_bytes(list(values))).hexdigest()


def _host_observation_mac(secret: bytes, observation: HostObservation) -> str:
    payload = {
        "phase": observation.phase,
        "observer_identity": observation.observer_identity.as_dict(),
        "network_namespace_inode": observation.network_namespace_inode,
        "process_inventory": list(observation.process_inventory),
        "service_inventory": list(observation.service_inventory),
        "listener_inventory": list(observation.listener_inventory),
        "process_inventory_sha256": observation.process_inventory_sha256,
        "service_inventory_sha256": observation.service_inventory_sha256,
        "listener_inventory_sha256": observation.listener_inventory_sha256,
        "inspection": {
            "gateway_status_command": list(
                observation.inspection.gateway_status_command
            ),
            "gateway_status_exit": observation.inspection.gateway_status_exit,
            "gateway_status_sha256": observation.inspection.gateway_status_sha256,
            "gateway_status_state": observation.inspection.gateway_status_state,
            "service_definitions": list(observation.inspection.service_definitions),
            "listener_command": list(observation.inspection.listener_command),
            "listener_inventory": list(observation.inspection.listener_inventory),
        },
        "internet_socket_attempts": observation.internet_socket_attempts,
    }
    return hmac.new(secret, canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def _read_host_process_inventory(
    proc_root: Path, maximum_processes: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        pids = sorted(
            int(entry.name)
            for entry in proc_root.iterdir()
            if entry.name.isdecimal() and int(entry.name) > 0
        )
    except OSError as error:
        raise CoordinatorError("host process inventory is unavailable") from error
    if len(pids) > maximum_processes:
        raise CoordinatorError("host process inventory exceeds its bound")
    processes: list[str] = []
    services: list[str] = []
    for pid in pids:
        pid_root = proc_root / str(pid)
        try:
            before = _read_host_process_stat(pid_root / "stat", pid)
        except FileNotFoundError:
            continue
        executable = ""
        executable_kind = "NO_EXE"
        try:
            executable = os.readlink(pid_root / "exe")
        except FileNotFoundError:
            # Kernel threads have no executable link.  A second stat read below
            # distinguishes that stable state from an exiting process.
            pass
        except PermissionError:
            executable_kind = "UNREADABLE_EXE"
        except OSError as error:
            raise CoordinatorError("host process executable is unavailable") from error
        else:
            if not os.path.isabs(executable) or executable.endswith(" (deleted)"):
                raise CoordinatorError("host process executable identity is invalid")
            executable_kind = "EXEC"

        cmdline = b""
        try:
            cmdline = _read_bounded_bytes(pid_root / "cmdline", 64 * 1024)
        except (FileNotFoundError, PermissionError):
            # Empty kernel-thread command lines and protected command lines are
            # represented by the executable-kind token, not treated as churn.
            pass

        try:
            after = _read_host_process_stat(pid_root / "stat", pid)
        except FileNotFoundError:
            # The process exited during the bounded observation.  It is absent
            # from this generation instead of being recorded inconsistently.
            continue
        if before != after:
            raise CoordinatorError("host process identity changed during inventory")

        start_time, command = before
        identity_source = executable if executable_kind == "EXEC" else command
        identity_digest = hashlib.sha256(identity_source.encode("utf-8")).hexdigest()
        entry = f"{pid}:{start_time}:{executable_kind}:{identity_digest}"
        processes.append(entry)
        service_text = b" ".join(
            (
                command.encode("utf-8", errors="surrogateescape"),
                executable.encode("utf-8", errors="surrogateescape"),
                cmdline,
            )
        ).lower()
        if b"openclaw" in service_text:
            services.append(entry)
    return tuple(sorted(set(processes))), tuple(sorted(set(services)))


def _read_host_process_stat(path: Path, expected_pid: int) -> tuple[int, str]:
    raw = (
        _read_bounded_bytes(path, 16 * 1024)
        .decode("utf-8", errors="surrogateescape")
        .strip()
    )
    prefix = f"{expected_pid} ("
    close_parenthesis = raw.rfind(")")
    if not raw.startswith(prefix) or close_parenthesis < len(prefix):
        raise CoordinatorError("host process stat is malformed")
    command = raw[len(prefix) : close_parenthesis]
    fields = raw[close_parenthesis + 1 :].split()
    if not command or len(fields) < 20:
        raise CoordinatorError("host process stat is incomplete")
    try:
        start_time = int(fields[19])
    except ValueError as error:
        raise CoordinatorError("host process start time is malformed") from error
    if start_time <= 0:
        raise CoordinatorError("host process start time is invalid")
    return start_time, command


def _process_start_times(processes: Sequence[str]) -> dict[int, int]:
    result: dict[int, int] = {}
    for entry in processes:
        fields = entry.split(":", 3)
        if len(fields) != 4:
            raise CoordinatorError("host process inventory entry is malformed")
        try:
            pid, start_time = int(fields[0]), int(fields[1])
        except ValueError as error:
            raise CoordinatorError(
                "host process inventory identity is malformed"
            ) from error
        if pid <= 0 or start_time <= 0 or pid in result:
            raise CoordinatorError("host process inventory identity is invalid")
        result[pid] = start_time
    return result


def _read_bounded_bytes(path: Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(4096, maximum - size + 1))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise CoordinatorError("host process evidence exceeds its byte bound")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _require_absolute_observer_executable(
    path: Path, expected_sha256: str, label: str
) -> Path:
    candidate = Path(path)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise CoordinatorError(f"{label} observer executable digest is invalid")
    try:
        stat_result = candidate.stat(follow_symlinks=False)
    except OSError as error:
        raise CoordinatorError(f"{label} observer executable is unavailable") from error
    if (
        not candidate.is_absolute()
        or not candidate.is_file()
        or os.path.islink(candidate)
        or stat_result.st_size <= 0
    ):
        raise CoordinatorError(f"{label} observer executable is invalid")
    if _bounded_file_sha256(candidate, 64 * 1024 * 1024) != expected_sha256:
        raise CoordinatorError(f"{label} observer executable digest mismatch")
    return candidate


def _classify_openclaw_status(value: object) -> str:
    active_boolean_keys = {"active", "loaded", "listening", "running"}
    active_strings = {"active", "listening", "online", "running", "started"}
    inactive_strings = {"inactive", "offline", "stopped", "unloaded"}
    observations = 0

    def visit(item: object, key: str | None = None) -> bool:
        nonlocal observations
        if isinstance(item, Mapping):
            return any(visit(child, str(name).lower()) for name, child in item.items())
        if isinstance(item, list):
            return any(visit(child, key) for child in item)
        if key in active_boolean_keys and type(item) is bool:
            observations += 1
            return item
        if key in {"state", "status"} and isinstance(item, str):
            lowered = item.lower()
            if lowered in active_strings | inactive_strings:
                observations += 1
                return lowered in active_strings
        return False

    if not isinstance(value, Mapping):
        raise CoordinatorError("OpenClaw lifecycle status is not an object")
    active = visit(value)
    if observations == 0:
        raise CoordinatorError("OpenClaw lifecycle inactivity is ambiguous")
    return "ACTIVE" if active else "INACTIVE"


def _scan_openclaw_service_definitions(
    roots: Sequence[Path],
) -> tuple[str, ...]:
    records: list[str] = []
    for root in roots:
        try:
            entries = tuple(root.iterdir())
        except FileNotFoundError:
            continue
        except OSError as error:
            raise CoordinatorError("service-definition inventory failed") from error
        for entry in entries:
            if not entry.name.startswith("openclaw-gateway"):
                continue
            flags = (
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(entry, flags)
                stat_result = os.fstat(descriptor)
                content = bytearray()
                while True:
                    chunk = os.read(
                        descriptor, min(4096, 1024 * 1024 - len(content) + 1)
                    )
                    if not chunk:
                        break
                    content.extend(chunk)
                    if len(content) > 1024 * 1024:
                        raise CoordinatorError(
                            "service definition exceeds its byte bound"
                        )
            except OSError as error:
                raise CoordinatorError(
                    "service-definition identity is invalid"
                ) from error
            finally:
                if "descriptor" in locals():
                    os.close(descriptor)
                    del descriptor
            records.append(
                f"{entry}:{stat_result.st_mode & 0o7777:04o}:"
                f"{hashlib.sha256(content).hexdigest()}"
            )
    return tuple(sorted(set(records)))


def _bounded_file_sha256(path: Path, maximum: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum - size + 1))
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                raise CoordinatorError("observer executable exceeds its byte bound")
            digest.update(chunk)
        return digest.hexdigest()
    except OSError as error:
        raise CoordinatorError("observer executable digest failed") from error
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _listener_uses_default_openclaw_port(line: str) -> bool:
    return re.search(r"(?:^|[\s\]])[^\s]*:18789(?:\s|$)", line) is not None
