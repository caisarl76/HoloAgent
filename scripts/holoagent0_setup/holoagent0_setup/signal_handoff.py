"""Thread-safe, pipe-bound signal-readiness and forwarding barrier."""

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
    """The signal-readiness barrier failed closed."""


_SIGNAL_SET = frozenset({"HUP", "INT", "TERM"})
_SIGNAL_ORDER = ("HUP", "INT", "TERM")
_SIGNAL_NUMBERS = {
    "HUP": signal.SIGHUP,
    "INT": signal.SIGINT,
    "TERM": signal.SIGTERM,
}
_LIVE_STATES = {
    "AWAITING_READY",
    "AWAITING_ACCEPTANCE",
    "PENDING_FORWARD",
    "READY",
}


@dataclass(frozen=True)
class SignalObservation:
    """One actual or narrowly injected signal-mask/disposition observation."""

    blocked_signals: frozenset[str]
    dispositions: tuple[tuple[str, bool], tuple[str, bool], tuple[str, bool]]

    def __post_init__(self) -> None:
        if type(self.blocked_signals) is not frozenset or any(
            type(name) is not str for name in self.blocked_signals
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
            identity = ProcessIdentity.from_dict(value["identity"])
            return cls(
                run_nonce=value["run_nonce"],
                sequence=value["sequence"],
                identity=identity,
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
    """Immutable binding asserted by a later trace-observation boundary."""

    run_nonce: str
    identity: ProcessIdentity
    request_sequence: int
    request_sha256: str
    unblocked_signals: tuple[str, str, str]
    trace_record_index: int

    def __post_init__(self) -> None:
        if type(self.run_nonce) is not str or not self.run_nonce:
            raise SignalHandoffError("trace evidence nonce is invalid")
        if type(self.identity) is not ProcessIdentity:
            raise SignalHandoffError("trace evidence identity is invalid")
        if type(self.request_sequence) is not int or self.request_sequence <= 0:
            raise SignalHandoffError("trace evidence sequence is invalid")
        if (
            type(self.request_sha256) is not str
            or len(self.request_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.request_sha256
            )
        ):
            raise SignalHandoffError("trace evidence digest is invalid")
        if (
            type(self.unblocked_signals) is not tuple
            or self.unblocked_signals != _SIGNAL_ORDER
        ):
            raise SignalHandoffError("trace evidence unblock mask is invalid")
        if type(self.trace_record_index) is not int or self.trace_record_index < 0:
            raise SignalHandoffError("trace evidence index is invalid")


@dataclass(frozen=True)
class HandoffEvent:
    index: int
    name: str
    state: str


class SignalHandoff:
    """One lock protects immutable bindings, callbacks, counts, and event order."""

    def __init__(
        self,
        run_nonce: str,
        *,
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        signal_observer: Callable[[], SignalObservation] | None = None,
        acceptance_writer: Callable[[SignalReadyAccepted], object] | None = None,
        forwarder: Callable[[int, str], object] | None = None,
        first_sequence: int = 1,
    ) -> None:
        if type(run_nonce) is not str or not run_nonce:
            raise SignalHandoffError("run nonce must be a non-empty exact string")
        try:
            nonce_size = len(run_nonce.encode("utf-8", errors="strict"))
        except UnicodeError as error:
            raise SignalHandoffError("run nonce contains invalid Unicode") from error
        if nonce_size > 256:
            raise SignalHandoffError("run nonce exceeds the reviewed byte bound")
        if type(first_sequence) is not int or first_sequence <= 0:
            raise SignalHandoffError("first sequence must be an exact positive integer")
        for callback in (
            identity_validator,
            signal_observer,
            acceptance_writer,
            forwarder,
        ):
            if callback is not None and not callable(callback):
                raise SignalHandoffError("handoff callbacks must be callable")
        self._lock = RLock()
        self._run_nonce = run_nonce
        self._identity_validator = identity_validator or (
            lambda identity: identity.matches_coordinator_session()
        )
        self._signal_observer = signal_observer or _observe_current_signals
        self._acceptance_writer = acceptance_writer or (lambda _acceptance: None)
        self._forwarder = forwarder or (lambda _pgid, _signal_name: None)
        self._next_sequence = first_sequence
        self._state = "AWAITING_READY"
        self._terminal_state: str | None = None
        self._request: SignalReady | None = None
        self._expected_acceptance: SignalReadyAccepted | None = None
        self._acceptance_written = False
        self._acceptance_validated = False
        self._trace_evidence: TraceUnblockEvidence | None = None
        self._pending_signal: str | None = None
        self._acceptance_count = 0
        self._forward_count = 0
        self._unblock_count = 0
        self._functional_count = 0
        self._events: list[HandoffEvent] = []

    @classmethod
    def not_applicable(cls, run_nonce: str) -> SignalHandoff:
        handoff = cls(run_nonce)
        with handoff._lock:
            handoff._state = "NOT_APPLICABLE"
            handoff._terminal_state = "NOT_APPLICABLE"
            handoff._event("not_applicable")
        return handoff

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def terminal_state(self) -> str | None:
        with self._lock:
            return self._terminal_state

    @property
    def pending_signal(self) -> str | None:
        with self._lock:
            return self._pending_signal

    @property
    def acceptance_count(self) -> int:
        with self._lock:
            return self._acceptance_count

    @property
    def forward_count(self) -> int:
        with self._lock:
            return self._forward_count

    @property
    def unblock_count(self) -> int:
        with self._lock:
            return self._unblock_count

    @property
    def functional_count(self) -> int:
        with self._lock:
            return self._functional_count

    @property
    def events(self) -> tuple[HandoffEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def coordinator_ready(
        self,
        identity: ProcessIdentity,
        *,
        blocked: set[str] | frozenset[str],
        dispositions: dict[str, bool] | None = None,
    ) -> SignalReady:
        with self._lock:
            self._require_nonterminal()
            if self._request is not None or self._state not in {
                "AWAITING_READY",
                "PENDING_FORWARD",
            }:
                return self._reject("ready request is out of order")
            if type(identity) is not ProcessIdentity:
                return self._reject("ready identity must be exact ProcessIdentity")
            if identity.pid != identity.pgid:
                return self._reject("coordinator must be the process-group leader")
            if type(blocked) not in {set, frozenset} or blocked != _SIGNAL_SET:
                return self._reject("blocked mask must contain exactly HUP/INT/TERM")
            if dispositions is None:
                return self._reject("explicit disposition proof is required")
            if (
                type(dispositions) is not dict
                or set(dispositions) != _SIGNAL_SET
                or any(
                    type(value) is not bool or not value
                    for value in dispositions.values()
                )
            ):
                return self._reject(
                    "all reviewed signal dispositions must be installed"
                )
            try:
                observed = self._signal_observer()
            except Exception as error:
                self._fail_locked("signal observation failed")
                raise SignalHandoffError("signal observation failed") from error
            if type(observed) is not SignalObservation:
                return self._reject("signal observer returned an invalid object")
            if (
                observed.blocked_signals != frozenset(blocked)
                or dict(observed.dispositions) != dispositions
            ):
                return self._reject("caller proof differs from observed signal state")
            self._event("handlers_installed")
            request = SignalReady(
                run_nonce=self._run_nonce,
                sequence=self._next_sequence,
                identity=identity,
                blocked_signals=_SIGNAL_ORDER,
                dispositions=tuple(
                    (name, dispositions[name]) for name in _SIGNAL_ORDER
                ),
            )
            request.as_message()
            self._request = request
            self._next_sequence += 1
            self._event("ready_request")
            if self._pending_signal is None:
                self._state = "AWAITING_ACCEPTANCE"
            return request

    def coordinator_ready_to_pipe(
        self,
        write_fd: int,
        identity: ProcessIdentity,
        *,
        blocked: set[str] | frozenset[str],
        dispositions: dict[str, bool] | None = None,
        deadline: int | float | None = None,
    ) -> SignalReady:
        request = self.coordinator_ready(
            identity, blocked=blocked, dispositions=dispositions
        )
        try:
            write_frame(write_fd, request.as_message(), deadline=deadline)
        except (BrokerProtocolError, OSError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("ready request write failed")
            raise SignalHandoffError("ready request write failed") from error
        with self._lock:
            self._require_nonterminal()
            self._event("ready_request_write")
        return request

    def supervisor_accept(self, request: SignalReady) -> SignalReadyAccepted:
        return self._supervisor_accept_with_writer(request, self._acceptance_writer)

    def supervisor_accept_from_pipe(
        self,
        request_read_fd: int,
        response_write_fd: int,
        *,
        deadline: int | float | None = None,
    ) -> SignalReadyAccepted:
        with self._lock:
            self._require_nonterminal()
        try:
            message = read_frame(request_read_fd, deadline=deadline, exact_one=True)
            request = SignalReady.from_message(message)
        except (BrokerProtocolError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("ready request read failed")
            raise SignalHandoffError("ready request read failed") from error

        def pipe_writer(acceptance: SignalReadyAccepted) -> None:
            write_frame(response_write_fd, acceptance.as_message(), deadline=deadline)

        return self._supervisor_accept_with_writer(request, pipe_writer)

    def _supervisor_accept_with_writer(
        self,
        request: SignalReady,
        writer: Callable[[SignalReadyAccepted], object],
    ) -> SignalReadyAccepted:
        with self._lock:
            self._require_nonterminal()
            if self._state not in {"AWAITING_ACCEPTANCE", "PENDING_FORWARD"}:
                return self._reject("acceptance request is out of order")
            if self._acceptance_written or self._expected_acceptance is not None:
                return self._reject("duplicate supervisor acceptance")
            if type(request) is not SignalReady or request != self._request:
                return self._reject("acceptance request does not match bound request")
            if request.run_nonce != self._run_nonce:
                return self._reject("ready nonce mismatch")
            if request.sequence != self._next_sequence - 1:
                return self._reject("ready sequence is not monotonic")
            if not self._validate_identity(request.identity):
                return self._reject("ready process identity or session mismatch")
            request.as_message()
            self._event("acceptance_request_validated")
            acceptance = SignalReadyAccepted(
                run_nonce=self._run_nonce,
                identity=request.identity,
                request_sequence=request.sequence,
                request_sha256=request.canonical_sha256,
            )
            acceptance.as_message()
            try:
                writer_result = writer(acceptance)
            except Exception as error:
                self._fail_locked("acceptance write failed")
                raise SignalHandoffError("acceptance write failed") from error
            if writer_result is not None:
                return self._reject("acceptance write was partial")
            self._expected_acceptance = acceptance
            self._acceptance_written = True
            self._event("acceptance_write")
            if self._pending_signal is None:
                self._state = "AWAITING_ACCEPTANCE"
            return acceptance

    def coordinator_validate(self, acceptance: SignalReadyAccepted) -> None:
        with self._lock:
            self._require_nonterminal()
            if self._acceptance_validated:
                return self._reject("duplicate acceptance")
            if (
                not self._acceptance_written
                or self._expected_acceptance is None
                or type(acceptance) is not SignalReadyAccepted
            ):
                return self._reject("acceptance is missing")
            if acceptance != self._expected_acceptance:
                return self._reject(
                    "acceptance does not match immutable request binding"
                )
            acceptance.as_message()
            self._acceptance_validated = True
            self._acceptance_count = 1
            self._state = "READY"
            self._event("acceptance_validated")
            if self._pending_signal is not None:
                self._forward_locked()

    def coordinator_validate_from_pipe(
        self, read_fd: int, *, deadline: int | float | None = None
    ) -> None:
        with self._lock:
            self._require_nonterminal()
        try:
            message = read_frame(read_fd, deadline=deadline, exact_one=True)
            acceptance = SignalReadyAccepted.from_message(message)
        except (BrokerProtocolError, SignalHandoffError) as error:
            with self._lock:
                if self._terminal_state is None:
                    self._fail_locked("acceptance response read failed")
            raise SignalHandoffError("acceptance response read failed") from error
        self.coordinator_validate(acceptance)

    def coordinator_unblocked(self, evidence: TraceUnblockEvidence) -> None:
        with self._lock:
            self._require_nonterminal()
            if (
                not self._acceptance_validated
                or self._acceptance_count != 1
                or self._unblock_count != 0
                or self._request is None
            ):
                return self._reject("unblock is not authorized")
            if type(evidence) is not TraceUnblockEvidence:
                return self._reject("trace unblock evidence is required")
            expected = self._request
            if (
                evidence.run_nonce != self._run_nonce
                or evidence.identity != expected.identity
                or evidence.request_sequence != expected.sequence
                or evidence.request_sha256 != expected.canonical_sha256
                or evidence.unblocked_signals != _SIGNAL_ORDER
            ):
                return self._reject("trace unblock evidence binding mismatch")
            self._trace_evidence = evidence
            self._unblock_count = 1
            self._state = "READY"
            self._event("trace_unblock")

    def record_functional_progress(self) -> None:
        with self._lock:
            self._require_nonterminal()
            if (
                self._state != "READY"
                or self._trace_evidence is None
                or self._unblock_count != 1
            ):
                return self._reject(
                    "functional progression preceded trace-proven unblock"
                )
            self._functional_count += 1
            self._event("functional")

    def finalize_ready(self) -> None:
        with self._lock:
            self._require_nonterminal()
            if (
                not self._acceptance_validated
                or self._acceptance_count != 1
                or self._trace_evidence is None
                or self._unblock_count != 1
            ):
                return self._reject("terminal READY requires trace-unblock evidence")
            self._state = "READY"
            self._terminal_state = "READY"
            self._event("terminal_ready")

    def collect_signal(self, signal_name: str) -> None:
        with self._lock:
            self._require_nonterminal()
            if type(signal_name) is not str or signal_name not in _SIGNAL_SET:
                raise SignalHandoffError("signal must be exactly HUP, INT, or TERM")
            if self._pending_signal is not None:
                return
            self._pending_signal = signal_name
            self._event("signal_latched")
            if self._acceptance_validated and self._acceptance_count == 1:
                self._forward_locked()
            elif self._state in _LIVE_STATES:
                self._state = "PENDING_FORWARD"

    def fail(self, reason: str) -> None:
        with self._lock:
            self._require_nonterminal()
            if type(reason) is not str or not reason:
                raise SignalHandoffError("failure reason must be a non-empty string")
            self._fail_locked(reason)

    def _forward_locked(self) -> None:
        if self._forward_count or self._pending_signal is None:
            return
        if (
            not self._acceptance_validated
            or self._acceptance_count != 1
            or self._request is None
        ):
            return self._reject("forward preceded coordinator acceptance validation")
        identity = self._request.identity
        if not self._validate_identity(identity):
            return self._reject("process identity changed before forward")
        try:
            forward_result = self._forwarder(identity.pgid, self._pending_signal)
        except Exception as error:
            self._fail_locked("modeled signal forward failed")
            raise SignalHandoffError("modeled signal forward failed") from error
        if forward_result is not None:
            return self._reject("modeled signal forward was not exact")
        self._forward_count = 1
        self._event("signal_forward")

    def _validate_identity(self, identity: ProcessIdentity) -> bool:
        try:
            return self._identity_validator(identity) is True
        except Exception:
            return False

    def _require_nonterminal(self) -> None:
        if self._terminal_state is not None:
            raise SignalHandoffError(
                f"terminal handoff state is immutable: {self._terminal_state}"
            )

    def _event(self, name: str) -> None:
        self._events.append(HandoffEvent(len(self._events), name, self._state))

    def _reject(self, reason: str):
        self._require_nonterminal()
        self._fail_locked(reason)
        raise SignalHandoffError(reason)

    def _fail_locked(self, reason: str) -> None:
        self._require_nonterminal()
        self._state = "FAILED"
        self._terminal_state = "FAILED"
        self._event(f"failed:{reason}")


def _observe_current_signals() -> SignalObservation:
    try:
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        blocked_names = frozenset(
            name for name, number in _SIGNAL_NUMBERS.items() if number in blocked
        )
        dispositions = tuple(
            (
                name,
                callable(signal.getsignal(number)),
            )
            for name, number in _SIGNAL_NUMBERS.items()
        )
        return SignalObservation(blocked_names, dispositions)
    except (OSError, RuntimeError, ValueError) as error:
        raise SignalHandoffError("could not observe current signal state") from error
