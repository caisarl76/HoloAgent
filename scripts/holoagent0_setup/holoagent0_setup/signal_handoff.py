"""Separate coordinator and supervisor roles for signal-readiness handoff."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import signal
from threading import RLock
from typing import Callable

from holoagent0_setup.atomic_io import canonical_json_bytes
from holoagent0_setup.broker import (
    BrokerProtocolError,
    MessageType,
    read_frame,
    validate_message,
    write_frame,
)
from holoagent0_setup.process_identity import ProcessIdentity, ProcessIdentityError


class SignalHandoffError(RuntimeError):
    """A role-local signal-readiness transition failed closed."""


_SIGNAL_SET = frozenset({"HUP", "INT", "TERM"})
_SIGNAL_ORDER = ("HUP", "INT", "TERM")
_SIGNAL_NUMBERS = {
    "HUP": signal.SIGHUP,
    "INT": signal.SIGINT,
    "TERM": signal.SIGTERM,
}


@dataclass(frozen=True)
class SignalObservation:
    """Observed state of the three reviewed signals in the current thread."""

    blocked_signals: frozenset[str]
    dispositions: tuple[tuple[str, bool], tuple[str, bool], tuple[str, bool]]
    handler_tokens: tuple[object, object, object] | None = None

    def __post_init__(self) -> None:
        if (
            type(self.blocked_signals) is not frozenset
            or not self.blocked_signals.issubset(_SIGNAL_SET)
            or any(type(name) is not str for name in self.blocked_signals)
        ):
            raise SignalHandoffError("observed signal mask is not exact")
        if type(self.dispositions) is not tuple or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not bool
            for item in self.dispositions
        ):
            raise SignalHandoffError("observed dispositions are not exact")
        if tuple(item[0] for item in self.dispositions) != _SIGNAL_ORDER:
            raise SignalHandoffError("observed dispositions are not closed")
        if (
            self.handler_tokens is None
            or type(self.handler_tokens) is not tuple
            or len(self.handler_tokens) != 3
        ):
            raise SignalHandoffError("observed handler identities are not exact")


@dataclass(frozen=True)
class SignalReady:
    run_nonce: str
    sequence: int
    identity: ProcessIdentity
    blocked_signals: tuple[str, str, str]
    dispositions: tuple[tuple[str, bool], tuple[str, bool], tuple[str, bool]]

    def as_message(self) -> dict[str, object]:
        message = {
            "type": MessageType.SIGNAL_READY.value,
            "run_nonce": self.run_nonce,
            "sequence": self.sequence,
            "identity": self.identity.as_dict(),
            "blocked_signals": list(self.blocked_signals),
            "dispositions": dict(self.dispositions),
        }
        try:
            return validate_message(message)
        except BrokerProtocolError as error:
            raise SignalHandoffError("invalid SIGNAL_READY object") from error

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.as_message())).hexdigest()

    def replaced(self, **changes: object) -> SignalReady:
        return replace(self, **changes)

    @classmethod
    def from_message(cls, message: object) -> SignalReady:
        try:
            value = validate_message(message)
            if value["type"] != MessageType.SIGNAL_READY.value:
                raise SignalHandoffError("pipe message is not SIGNAL_READY")
            return cls(
                run_nonce=value["run_nonce"],
                sequence=value["sequence"],
                identity=ProcessIdentity.from_dict(value["identity"]),
                blocked_signals=tuple(value["blocked_signals"]),
                dispositions=tuple(
                    (name, value["dispositions"][name]) for name in _SIGNAL_ORDER
                ),
            )
        except SignalHandoffError:
            raise
        except (BrokerProtocolError, ProcessIdentityError, TypeError) as error:
            raise SignalHandoffError("invalid SIGNAL_READY pipe message") from error


@dataclass(frozen=True)
class SignalReadyAccepted:
    run_nonce: str
    identity: ProcessIdentity
    request_sequence: int
    request_sha256: str

    def as_message(self) -> dict[str, object]:
        message = {
            "type": MessageType.SIGNAL_READY_ACCEPTED.value,
            "run_nonce": self.run_nonce,
            "identity": self.identity.as_dict(),
            "request_sequence": self.request_sequence,
            "request_sha256": self.request_sha256,
        }
        try:
            return validate_message(message)
        except BrokerProtocolError as error:
            raise SignalHandoffError("invalid SIGNAL_READY_ACCEPTED object") from error

    def replaced(self, **changes: object) -> SignalReadyAccepted:
        return replace(self, **changes)

    @classmethod
    def from_message(cls, message: object) -> SignalReadyAccepted:
        try:
            value = validate_message(message)
            if value["type"] != MessageType.SIGNAL_READY_ACCEPTED.value:
                raise SignalHandoffError("pipe message is not SIGNAL_READY_ACCEPTED")
            return cls(
                run_nonce=value["run_nonce"],
                identity=ProcessIdentity.from_dict(value["identity"]),
                request_sequence=value["request_sequence"],
                request_sha256=value["request_sha256"],
            )
        except SignalHandoffError:
            raise
        except (BrokerProtocolError, ProcessIdentityError, TypeError) as error:
            raise SignalHandoffError(
                "invalid SIGNAL_READY_ACCEPTED pipe message"
            ) from error


@dataclass(frozen=True)
class TraceUnblockEvidence:
    """Untrusted trace claim passed to a mandatory trusted verifier."""

    run_nonce: str
    identity: ProcessIdentity
    request_sequence: int
    request_sha256: str
    unblock_trace_record_index: int
    first_functional_trace_record_index: int | None
    functional_count: int

    def __post_init__(self) -> None:
        _require_nonce(self.run_nonce)
        if type(self.identity) is not ProcessIdentity:
            raise SignalHandoffError("trace evidence identity is invalid")
        if type(self.request_sequence) is not int or self.request_sequence <= 0:
            raise SignalHandoffError("trace evidence sequence is invalid")
        _require_digest(self.request_sha256, "trace evidence request digest")
        if (
            type(self.unblock_trace_record_index) is not int
            or self.unblock_trace_record_index < 0
        ):
            raise SignalHandoffError("trace unblock index is invalid")
        functional_index = self.first_functional_trace_record_index
        if functional_index is not None and (
            type(functional_index) is not int or functional_index < 0
        ):
            raise SignalHandoffError("first functional trace index is invalid")
        if type(self.functional_count) is not int or self.functional_count < 0:
            raise SignalHandoffError("trace functional count is invalid")


@dataclass(frozen=True)
class HandoffEvent:
    index: int
    name: str
    state: str


@dataclass(frozen=True)
class CoordinatorSnapshot:
    role: str
    state: str
    terminal_state: str | None
    request_sequence: int | None
    request_sha256: str | None
    acceptance_validated: bool
    unblock_count: int
    functional_count: int
    events: tuple[HandoffEvent, ...]


@dataclass(frozen=True)
class SupervisorSnapshot:
    role: str
    state: str
    terminal_state: str | None
    next_sequence: int
    acceptance_count: int
    forward_count: int
    pending_signal: str | None
    forward_target_pgid: int | None
    events: tuple[HandoffEvent, ...]


class _OSSignalOperations:
    def observe(self) -> SignalObservation:
        try:
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
            blocked_names = frozenset(
                name for name, number in _SIGNAL_NUMBERS.items() if number in blocked
            )
            handlers = tuple(
                signal.getsignal(number) for number in _SIGNAL_NUMBERS.values()
            )
            dispositions = tuple(
                (name, callable(handler))
                for name, handler in zip(_SIGNAL_ORDER, handlers)
            )
            return SignalObservation(blocked_names, dispositions, handlers)
        except (OSError, RuntimeError, ValueError) as error:
            raise SignalHandoffError(
                "could not observe current signal state"
            ) from error

    def unblock_reviewed(self) -> None:
        try:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, set(_SIGNAL_NUMBERS.values()))
        except (OSError, RuntimeError, ValueError) as error:
            raise SignalHandoffError("could not unblock reviewed signals") from error


class CoordinatorSignalHandoff:
    """Coordinator-local request, acceptance, unblock, and progression state."""

    def __init__(
        self,
        run_nonce: str,
        identity: ProcessIdentity,
        *,
        trace_verifier: Callable[[TraceUnblockEvidence], bool] | None = None,
        signal_operations: object | None = None,
        first_sequence: int = 1,
    ) -> None:
        _require_nonce(run_nonce)
        if type(identity) is not ProcessIdentity or identity.pid != identity.pgid:
            raise SignalHandoffError("coordinator identity must lead its process group")
        if trace_verifier is None or not callable(trace_verifier):
            raise SignalHandoffError("a trusted trace verifier is mandatory")
        if type(first_sequence) is not int or first_sequence <= 0:
            raise SignalHandoffError("first sequence must be positive")
        operations = signal_operations or _OSSignalOperations()
        if not callable(getattr(operations, "observe", None)) or not callable(
            getattr(operations, "unblock_reviewed", None)
        ):
            raise SignalHandoffError("signal operations interface is incomplete")
        self._lock = RLock()
        self._run_nonce = run_nonce
        self._identity = identity
        self._trace_verifier = trace_verifier
        self._signal_operations = operations
        self._next_sequence = first_sequence
        self._state = "AWAITING_READY"
        self._terminal_state: str | None = None
        self._sent_request: SignalReady | None = None
        self._installed_dispositions: (
            tuple[tuple[str, bool], tuple[str, bool], tuple[str, bool]] | None
        ) = None
        self._installed_handler_tokens: tuple[object, object, object] | None = None
        self._acceptance_validated = False
        self._unblock_count = 0
        self._functional_count = 0
        self._events: list[HandoffEvent] = []
        self._state_version = 0
        self._transition: str | None = None

    def send_ready(
        self,
        write_fd: int,
        *,
        blocked: set[str] | frozenset[str],
        dispositions: dict[str, bool] | None,
        deadline: int | float | None = None,
    ) -> SignalReady:
        """Observe and write one request; the descriptor remains caller-owned."""

        with self._lock:
            self._require_transition_idle()
            if self._sent_request is not None or self._state != "AWAITING_READY":
                return self._reject("coordinator ready request is out of order")
            proof = _require_signal_proof(blocked, dispositions)
            transition = "ready request"
            version = self._start_transition_locked(transition)
        try:
            observed = self._observe()
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("signal observation failed")
            raise SignalHandoffError("signal observation failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if observed.blocked_signals != _SIGNAL_SET:
                return self._reject("reviewed signals are not all blocked")
            if observed.dispositions != proof:
                return self._reject(
                    "caller dispositions differ from actual handler observation"
                )
            request = SignalReady(
                run_nonce=self._run_nonce,
                sequence=self._next_sequence,
                identity=self._identity,
                blocked_signals=_SIGNAL_ORDER,
                dispositions=proof,
            )
            self._event("handlers_observed")
            version = self._state_version
        try:
            write_frame(write_fd, request.as_message(), deadline=deadline)
        except (BrokerProtocolError, OSError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("ready request write failed")
            raise SignalHandoffError("ready request write failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            self._sent_request = request
            self._installed_dispositions = observed.dispositions
            self._installed_handler_tokens = observed.handler_tokens
            self._next_sequence += 1
            self._state = "AWAITING_ACCEPTANCE"
            self._event("ready_request_write")
            self._finish_transition_locked(transition)
            return request

    def receive_acceptance(
        self, read_fd: int, *, deadline: int | float | None = None
    ) -> SignalReadyAccepted:
        """Read exact acceptance, unblock in the OS, and re-observe the mask."""

        with self._lock:
            self._require_transition_idle()
            if self._state != "AWAITING_ACCEPTANCE" or self._sent_request is None:
                return self._reject("coordinator is not awaiting acceptance")
            transition = "acceptance"
            version = self._start_transition_locked(transition)
            request = self._sent_request
            installed_dispositions = self._installed_dispositions
            installed_handler_tokens = self._installed_handler_tokens
        try:
            message = read_frame(read_fd, deadline=deadline, exact_one=True)
            acceptance = SignalReadyAccepted.from_message(message)
        except (BrokerProtocolError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("acceptance response read failed")
            raise SignalHandoffError("acceptance response read failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            expected = _acceptance_for(request)
            if acceptance != expected:
                return self._reject("coordinator acceptance binding mismatch")
            self._acceptance_validated = True
            self._event("acceptance_validated")
            version = self._state_version
        try:
            self._signal_operations.unblock_reviewed()
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("reviewed signal unblock failed")
            raise SignalHandoffError("reviewed signal unblock failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
        try:
            observed = self._observe()
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("reviewed signal unblock failed")
            raise SignalHandoffError("reviewed signal unblock failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if observed.blocked_signals:
                return self._reject("reviewed signals remain blocked after unblock")
            if (
                observed.dispositions != installed_dispositions
                or observed.handler_tokens != installed_handler_tokens
            ):
                return self._reject("handler dispositions changed during unblock")
            self._unblock_count = 1
            self._state = "READY"
            self._event("signals_unblocked")
            self._finish_transition_locked(transition)
            return acceptance

    def record_functional_progress(self) -> None:
        with self._lock:
            self._require_transition_idle()
            if self._state != "READY" or self._unblock_count != 1:
                return self._reject("functional progress preceded OS unblock")
            self._functional_count += 1
            self._event("functional")

    def finalize_ready(self, evidence: TraceUnblockEvidence) -> None:
        with self._lock:
            self._require_transition_idle()
            if (
                self._state != "READY"
                or not self._acceptance_validated
                or self._unblock_count != 1
                or self._sent_request is None
            ):
                return self._reject("coordinator is not live-ready")
            if type(evidence) is not TraceUnblockEvidence:
                return self._reject("trusted trace evidence is required")
            request = self._sent_request
            if (
                evidence.run_nonce != request.run_nonce
                or evidence.identity != request.identity
                or evidence.request_sequence != request.sequence
                or evidence.request_sha256 != request.canonical_sha256
                or evidence.functional_count != self._functional_count
            ):
                return self._reject("trace evidence binding or count mismatch")
            functional_index = evidence.first_functional_trace_record_index
            if self._functional_count == 0:
                if functional_index is not None:
                    return self._reject(
                        "trace evidence has an unexpected functional index"
                    )
            elif functional_index is None or not (
                evidence.unblock_trace_record_index < functional_index
            ):
                return self._reject("trace evidence functional ordering is invalid")
            transition = "trace verification"
            version = self._start_transition_locked(transition)
        try:
            trusted = self._trace_verifier(evidence)
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("trusted trace verifier failed")
            raise SignalHandoffError("trusted trace verifier failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if trusted is not True:
                return self._reject("trusted trace verifier rejected evidence")
            self._transition = None
            self._terminal_state = "READY"
            self._event("terminal_ready")

    def fail(self, reason: str) -> None:
        with self._lock:
            self._require_nonterminal()
            _require_reason(reason)
            self._fail_locked(reason)

    def snapshot(self) -> CoordinatorSnapshot:
        with self._lock:
            request = self._sent_request
            return CoordinatorSnapshot(
                role="COORDINATOR",
                state=self._state,
                terminal_state=self._terminal_state,
                request_sequence=None if request is None else request.sequence,
                request_sha256=None if request is None else request.canonical_sha256,
                acceptance_validated=self._acceptance_validated,
                unblock_count=self._unblock_count,
                functional_count=self._functional_count,
                events=tuple(self._events),
            )

    def _observe(self) -> SignalObservation:
        try:
            observed = self._signal_operations.observe()
        except Exception as error:
            raise SignalHandoffError("signal observation failed") from error
        if type(observed) is not SignalObservation:
            raise SignalHandoffError("signal observer returned an invalid object")
        return observed

    def _require_nonterminal(self) -> None:
        if self._terminal_state is not None:
            raise SignalHandoffError(
                f"terminal coordinator state is immutable: {self._terminal_state}"
            )

    def _require_transition_idle(self) -> None:
        self._require_nonterminal()
        if self._transition is not None:
            self._reject("coordinator transition reentry")

    def _start_transition_locked(self, name: str) -> int:
        if self._transition is not None:
            self._reject("coordinator transition reentry")
        self._transition = name
        self._state_version += 1
        return self._state_version

    def _require_transition_unchanged_locked(self, name: str, version: int) -> None:
        if (
            self._terminal_state is not None
            or self._transition != name
            or self._state_version != version
        ):
            raise SignalHandoffError(f"coordinator state changed during {name}")

    def _finish_transition_locked(self, name: str) -> None:
        if self._transition != name:
            raise SignalHandoffError(f"coordinator state changed during {name}")
        self._transition = None
        self._state_version += 1

    def _event(self, name: str) -> None:
        self._events.append(HandoffEvent(len(self._events), name, self._state))
        self._state_version += 1

    def _reject(self, reason: str):
        self._require_nonterminal()
        self._fail_locked(reason)
        raise SignalHandoffError(reason)

    def _fail_locked(self, reason: str) -> None:
        self._require_nonterminal()
        self._state = "FAILED"
        self._terminal_state = "FAILED"
        self._transition = None
        self._event(f"failed:{reason}")


class SupervisorSignalHandoff:
    """Supervisor-local sequence, acceptance-write, and forwarding state."""

    def __init__(
        self,
        run_nonce: str,
        *,
        forwarder: Callable[[int, str], object] | None = None,
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        first_sequence: int = 1,
    ) -> None:
        _require_nonce(run_nonce)
        if forwarder is None or not callable(forwarder):
            raise SignalHandoffError("an explicit modeled forwarder is mandatory")
        if identity_validator is not None and not callable(identity_validator):
            raise SignalHandoffError("identity validator must be callable")
        if type(first_sequence) is not int or first_sequence <= 0:
            raise SignalHandoffError("first sequence must be positive")
        self._lock = RLock()
        self._run_nonce = run_nonce
        self._forwarder = forwarder
        self._identity_validator = identity_validator or (
            lambda identity: identity.matches_coordinator_session()
        )
        self._next_sequence = first_sequence
        self._state = "AWAITING_READY"
        self._terminal_state: str | None = None
        self._acceptance_count = 0
        self._forward_count = 0
        self._pending_signal: str | None = None
        self._forward_target_pgid: int | None = None
        self._last_accepted_identity: ProcessIdentity | None = None
        self._events: list[HandoffEvent] = []
        self._state_version = 0
        self._transition: str | None = None

    @classmethod
    def not_applicable(cls, run_nonce: str) -> SupervisorSignalHandoff:
        def prohibited_forward(_pgid: int, _name: str) -> object:
            raise SignalHandoffError("NOT_APPLICABLE cannot forward")

        handoff = cls(
            run_nonce,
            forwarder=prohibited_forward,
            identity_validator=lambda _identity: False,
        )
        with handoff._lock:
            handoff._state = "NOT_APPLICABLE"
            handoff._terminal_state = "NOT_APPLICABLE"
            handoff._event("not_applicable")
        return handoff

    def build_acceptance(self, request: SignalReady) -> SignalReadyAccepted:
        """Build a response without changing authorization or sequence state."""

        with self._lock:
            self._require_transition_idle()
            self._validate_request_structure(request)
            transition = "acceptance build"
            version = self._start_transition_locked(transition)
        valid_identity = self._validate_identity(request.identity)
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if not valid_identity:
                return self._reject("request process identity mismatch")
            acceptance = _acceptance_for(request)
            self._finish_transition_locked(transition)
            return acceptance

    def receive_and_accept(
        self,
        request_read_fd: int,
        response_write_fd: int,
        *,
        deadline: int | float | None = None,
    ) -> SignalReadyAccepted:
        """Read one request and authorize only after complete response write."""

        with self._lock:
            self._require_ready_acceptance_open()
        try:
            message = read_frame(request_read_fd, deadline=deadline, exact_one=True)
            request = SignalReady.from_message(message)
        except (BrokerProtocolError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("ready request read failed")
            raise SignalHandoffError("ready request read failed") from error
        with self._lock:
            self._require_ready_acceptance_open()
            try:
                self._validate_request_structure(request)
            except SignalHandoffError as error:
                self._fail_locked(str(error))
                raise
            transition = "readiness acceptance"
            version = self._start_transition_locked(transition)
        valid_identity = self._validate_identity(request.identity)
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if not valid_identity:
                return self._reject("request process identity mismatch")
            acceptance = _acceptance_for(request)
            self._event("ready_request_validated")
            version = self._state_version
        try:
            write_frame(
                response_write_fd,
                acceptance.as_message(),
                deadline=deadline,
            )
        except (BrokerProtocolError, OSError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("acceptance response write failed")
            raise SignalHandoffError("acceptance response write failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            self._acceptance_count = 1
            self._next_sequence += 1
            self._last_accepted_identity = request.identity
            self._state = "READY"
            self._event("acceptance_write")
            if self._pending_signal is None:
                self._finish_transition_locked(transition)
                return acceptance
            version = self._state_version
        valid_identity = self._validate_identity(request.identity)
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if not valid_identity:
                return self._reject("process identity changed before forward")
            pending_signal = self._pending_signal
        try:
            result = self._forwarder(request.identity.pgid, pending_signal)
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("modeled signal forward failed")
            raise SignalHandoffError("modeled signal forward failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if result is not None:
                return self._reject("modeled signal forward was not exact")
            self._forward_count = 1
            self._forward_target_pgid = request.identity.pgid
            self._event("signal_forward")
            self._finish_transition_locked(transition)
            return acceptance

    def collect_signal(self, signal_name: str) -> None:
        with self._lock:
            self._require_transition_idle()
            if type(signal_name) is not str or signal_name not in _SIGNAL_SET:
                raise SignalHandoffError("signal must be exactly HUP, INT, or TERM")
            if self._pending_signal is not None:
                return
            self._pending_signal = signal_name
            self._event("signal_latched")
            identity = self._last_accepted_identity
            if identity is None:
                self._state = "PENDING_FORWARD"
                self._state_version += 1
                return
            transition = "signal forward"
            version = self._start_transition_locked(transition)
        valid_identity = self._validate_identity(identity)
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if not valid_identity:
                return self._reject("process identity changed before forward")
            pending_signal = self._pending_signal
        try:
            result = self._forwarder(identity.pgid, pending_signal)
        except Exception as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("modeled signal forward failed")
            raise SignalHandoffError("modeled signal forward failed") from error
        with self._lock:
            self._require_transition_unchanged_locked(transition, version)
            if result is not None:
                return self._reject("modeled signal forward was not exact")
            self._forward_count = 1
            self._forward_target_pgid = identity.pgid
            self._event("signal_forward")
            self._finish_transition_locked(transition)

    def fail(self, reason: str) -> None:
        with self._lock:
            self._require_nonterminal()
            _require_reason(reason)
            self._fail_locked(reason)

    def snapshot(self) -> SupervisorSnapshot:
        with self._lock:
            return SupervisorSnapshot(
                role="SUPERVISOR",
                state=self._state,
                terminal_state=self._terminal_state,
                next_sequence=self._next_sequence,
                acceptance_count=self._acceptance_count,
                forward_count=self._forward_count,
                pending_signal=self._pending_signal,
                forward_target_pgid=self._forward_target_pgid,
                events=tuple(self._events),
            )

    def _validate_request_structure(self, request: SignalReady) -> None:
        if type(request) is not SignalReady:
            raise SignalHandoffError("request must be an exact SignalReady")
        request.as_message()
        if request.run_nonce != self._run_nonce:
            raise SignalHandoffError("request nonce mismatch")
        if request.sequence != self._next_sequence:
            raise SignalHandoffError("request sequence mismatch")
        if request.identity.pid != request.identity.pgid:
            raise SignalHandoffError("coordinator is not process-group leader")
        if request.blocked_signals != _SIGNAL_ORDER or any(
            value is not True for _name, value in request.dispositions
        ):
            raise SignalHandoffError("request signal proof is invalid")

    def _validate_identity(self, identity: ProcessIdentity) -> bool:
        try:
            return self._identity_validator(identity) is True
        except Exception:
            return False

    def _require_nonterminal(self) -> None:
        if self._terminal_state is not None:
            raise SignalHandoffError(
                f"terminal supervisor state is immutable: {self._terminal_state}"
            )

    def _require_transition_idle(self) -> None:
        self._require_nonterminal()
        if self._transition is not None:
            self._reject("supervisor transition reentry")

    def _start_transition_locked(self, name: str) -> int:
        if self._transition is not None:
            self._reject("supervisor transition reentry")
        self._transition = name
        self._state_version += 1
        return self._state_version

    def _require_transition_unchanged_locked(self, name: str, version: int) -> None:
        if (
            self._terminal_state is not None
            or self._transition != name
            or self._state_version != version
        ):
            raise SignalHandoffError(f"supervisor state changed during {name}")

    def _finish_transition_locked(self, name: str) -> None:
        if self._transition != name:
            raise SignalHandoffError(f"supervisor state changed during {name}")
        self._transition = None
        self._state_version += 1

    def _require_ready_acceptance_open(self) -> None:
        self._require_nonterminal()
        if self._transition == "readiness acceptance":
            raise SignalHandoffError("readiness already accepted")
        if self._transition is not None:
            self._reject("supervisor transition reentry")
        if self._acceptance_count != 0 or self._state not in {
            "AWAITING_READY",
            "PENDING_FORWARD",
        }:
            raise SignalHandoffError("readiness already accepted")

    def _event(self, name: str) -> None:
        self._events.append(HandoffEvent(len(self._events), name, self._state))
        self._state_version += 1

    def _reject(self, reason: str):
        self._require_nonterminal()
        self._fail_locked(reason)
        raise SignalHandoffError(reason)

    def _fail_locked(self, reason: str) -> None:
        self._require_nonterminal()
        self._state = "FAILED"
        self._terminal_state = "FAILED"
        self._transition = None
        self._event(f"failed:{reason}")


class SignalHandoff:
    """Fail-closed compatibility marker for the removed shared-role API."""

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise SignalHandoffError(
            "use explicit coordinator/supervisor signal handoff roles"
        )


def _acceptance_for(request: SignalReady) -> SignalReadyAccepted:
    return SignalReadyAccepted(
        run_nonce=request.run_nonce,
        identity=request.identity,
        request_sequence=request.sequence,
        request_sha256=request.canonical_sha256,
    )


def _require_signal_proof(
    blocked: set[str] | frozenset[str], dispositions: dict[str, bool] | None
) -> tuple[tuple[str, bool], tuple[str, bool], tuple[str, bool]]:
    if type(blocked) not in {set, frozenset} or blocked != _SIGNAL_SET:
        raise SignalHandoffError("blocked mask must contain exactly HUP/INT/TERM")
    if (
        dispositions is None
        or type(dispositions) is not dict
        or set(dispositions) != _SIGNAL_SET
        or any(type(value) is not bool or not value for value in dispositions.values())
    ):
        raise SignalHandoffError("explicit successful disposition proof is required")
    return tuple((name, dispositions[name]) for name in _SIGNAL_ORDER)


def _require_nonce(value: object) -> None:
    if type(value) is not str or not value:
        raise SignalHandoffError("run nonce must be a non-empty exact string")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as error:
        raise SignalHandoffError("run nonce contains invalid Unicode") from error
    if size > 256:
        raise SignalHandoffError("run nonce exceeds the reviewed byte bound")


def _require_digest(value: object, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SignalHandoffError(f"{name} must be lowercase SHA-256")


def _require_reason(reason: object) -> None:
    if type(reason) is not str or not reason:
        raise SignalHandoffError("failure reason must be a non-empty exact string")
