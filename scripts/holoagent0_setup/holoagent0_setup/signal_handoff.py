"""Thread-safe two-way readiness and modeled signal-forwarding barrier."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from threading import RLock
from typing import Callable

from holoagent0_setup.atomic_io import canonical_json_bytes
from holoagent0_setup.broker import MessageType, validate_message
from holoagent0_setup.process_identity import ProcessIdentity


class SignalHandoffError(RuntimeError):
    """The signal readiness barrier failed closed."""


_SIGNAL_SET = frozenset({"HUP", "INT", "TERM"})
_SIGNAL_ORDER = ("HUP", "INT", "TERM")
_LIVE_STATES = {
    "AWAITING_READY",
    "AWAITING_ACCEPTANCE",
    "PENDING_FORWARD",
    "READY",
}


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
        return validate_message(message)

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.as_message())).hexdigest()

    def replaced(self, **changes: object) -> SignalReady:
        return replace(self, **changes)


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
        return validate_message(message)

    def replaced(self, **changes: object) -> SignalReadyAccepted:
        return replace(self, **changes)


@dataclass(frozen=True)
class HandoffEvent:
    index: int
    name: str
    state: str


class SignalHandoff:
    """One lock protects immutable bindings, counts, events, and callbacks."""

    def __init__(
        self,
        run_nonce: str,
        *,
        identity_validator: Callable[[ProcessIdentity], bool] | None = None,
        acceptance_writer: Callable[[SignalReadyAccepted], object] | None = None,
        forwarder: Callable[[int, str], object] | None = None,
        first_sequence: int = 1,
    ) -> None:
        if type(run_nonce) is not str or not run_nonce:
            raise SignalHandoffError("run nonce must be a non-empty exact string")
        if type(first_sequence) is not int or first_sequence <= 0:
            raise SignalHandoffError("first sequence must be an exact positive integer")
        for callback in (identity_validator, acceptance_writer, forwarder):
            if callback is not None and not callable(callback):
                raise SignalHandoffError("handoff callbacks must be callable")
        self._lock = RLock()
        self._run_nonce = run_nonce
        self._identity_validator = identity_validator or (
            lambda identity: identity.matches_proc()
        )
        self._acceptance_writer = acceptance_writer or (lambda _acceptance: None)
        self._forwarder = forwarder or (lambda _pgid, _signal_name: None)
        self._next_sequence = first_sequence
        self._state = "AWAITING_READY"
        self._terminal_state: str | None = None
        self._request: SignalReady | None = None
        self._acceptance: SignalReadyAccepted | None = None
        self._acceptance_validated = False
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
                dispositions = {name: True for name in _SIGNAL_ORDER}
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

    def supervisor_accept(self, request: SignalReady) -> SignalReadyAccepted:
        with self._lock:
            if self._state not in {"AWAITING_ACCEPTANCE", "PENDING_FORWARD"}:
                return self._reject("acceptance request is out of order")
            if self._acceptance_count != 0 or self._acceptance is not None:
                return self._reject("duplicate supervisor acceptance")
            if type(request) is not SignalReady or request != self._request:
                return self._reject("acceptance request does not match bound request")
            if request.run_nonce != self._run_nonce:
                return self._reject("ready nonce mismatch")
            if request.sequence != self._next_sequence - 1:
                return self._reject("ready sequence is not monotonic")
            if not self._validate_identity(request.identity):
                return self._reject("ready process identity mismatch")
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
                self._acceptance_writer(acceptance)
            except Exception as error:
                self._fail_locked("acceptance write failed")
                raise SignalHandoffError("acceptance write failed") from error
            self._acceptance = acceptance
            self._acceptance_count = 1
            self._event("acceptance_write")
            if self._pending_signal is not None:
                self._forward_locked()
            if self._state != "FAILED":
                self._state = "READY"
                self._event("supervisor_ready")
            return acceptance

    def coordinator_validate(self, acceptance: SignalReadyAccepted) -> None:
        with self._lock:
            if self._acceptance_validated:
                return self._reject("duplicate acceptance")
            if self._acceptance is None or type(acceptance) is not SignalReadyAccepted:
                return self._reject("acceptance is missing")
            expected = self._acceptance
            if acceptance != expected:
                return self._reject(
                    "acceptance does not match immutable request binding"
                )
            acceptance.as_message()
            self._acceptance_validated = True
            self._event("acceptance_validated")

    def coordinator_unblocked(self, unblocked: set[str] | frozenset[str]) -> None:
        with self._lock:
            if (
                not self._acceptance_validated
                or self._acceptance_count != 1
                or self._unblock_count != 0
            ):
                return self._reject("unblock is not authorized")
            if type(unblocked) not in {set, frozenset} or unblocked != _SIGNAL_SET:
                return self._reject("unblock mask must contain exactly HUP/INT/TERM")
            self._unblock_count = 1
            self._event("unblock")
            self._state = "READY"
            self._terminal_state = "READY"
            self._event("ready")

    def record_functional_progress(self) -> None:
        with self._lock:
            if (
                self._state != "READY"
                or self._terminal_state != "READY"
                or self._unblock_count != 1
            ):
                return self._reject("functional progression preceded verified unblock")
            self._functional_count += 1
            self._event("functional")

    def collect_signal(self, signal_name: str) -> None:
        with self._lock:
            if type(signal_name) is not str or signal_name not in _SIGNAL_SET:
                raise SignalHandoffError("signal must be exactly HUP, INT, or TERM")
            if self._state in {"FAILED", "NOT_APPLICABLE"}:
                return
            if self._pending_signal is not None:
                return
            self._pending_signal = signal_name
            self._event("signal_latched")
            if self._acceptance_count == 1:
                self._forward_locked()
            elif self._state in _LIVE_STATES:
                self._state = "PENDING_FORWARD"

    def fail(self, reason: str) -> None:
        with self._lock:
            if type(reason) is not str or not reason:
                raise SignalHandoffError("failure reason must be a non-empty string")
            self._fail_locked(reason)

    def _forward_locked(self) -> None:
        if self._forward_count or self._pending_signal is None:
            return
        if self._acceptance_count != 1 or self._request is None:
            return self._reject("forward preceded acceptance write")
        identity = self._request.identity
        if not self._validate_identity(identity):
            return self._reject("process identity changed before forward")
        try:
            self._forwarder(identity.pgid, self._pending_signal)
        except Exception as error:
            self._fail_locked("modeled signal forward failed")
            raise SignalHandoffError("modeled signal forward failed") from error
        self._forward_count = 1
        self._event("signal_forward")

    def _validate_identity(self, identity: ProcessIdentity) -> bool:
        try:
            return self._identity_validator(identity) is True
        except Exception:
            return False

    def _event(self, name: str) -> None:
        self._events.append(HandoffEvent(len(self._events), name, self._state))

    def _reject(self, reason: str):
        self._fail_locked(reason)
        raise SignalHandoffError(reason)

    def _fail_locked(self, reason: str) -> None:
        if self._state != "FAILED":
            self._state = "FAILED"
            self._terminal_state = "FAILED"
            self._event(f"failed:{reason}")
