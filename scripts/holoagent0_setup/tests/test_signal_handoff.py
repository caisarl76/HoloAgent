"""Separate coordinator/supervisor signal-readiness protocol tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import os
import signal
from threading import Event, Thread
import time

import pytest

import holoagent0_setup.signal_handoff as signal_handoff_module
from holoagent0_setup.broker import write_frame
from holoagent0_setup.process_identity import ProcessIdentity
from holoagent0_setup.signal_handoff import (
    CoordinatorSignalHandoff,
    CoordinatorSnapshot,
    SignalHandoff,
    SignalHandoffError,
    SignalObservation,
    SupervisorSignalHandoff,
    SupervisorSnapshot,
    TraceUnblockEvidence,
)


MASK = frozenset({"HUP", "INT", "TERM"})
DISPOSITIONS = (("HUP", True), ("INT", True), ("TERM", True))


class FakeSignalOperations:
    def __init__(self, *, change_disposition: bool = False) -> None:
        self.tokens = ("handler-hup", "handler-int", "handler-term")
        self.observation = SignalObservation(MASK, DISPOSITIONS, self.tokens)
        self.unblock_calls = 0
        self.change_disposition = change_disposition

    def observe(self) -> SignalObservation:
        return self.observation

    def unblock_reviewed(self) -> None:
        self.unblock_calls += 1
        dispositions = DISPOSITIONS
        if self.change_disposition:
            dispositions = (("HUP", True), ("INT", False), ("TERM", True))
        self.observation = SignalObservation(frozenset(), dispositions, self.tokens)


@pytest.fixture
def identity():
    return ProcessIdentity(101, 101, 12345, "/bin/coordinator", "a" * 64)


def _coordinator(
    identity,
    *,
    operations=None,
    first_sequence=1,
):
    return CoordinatorSignalHandoff(
        "run-0123456789abcdef",
        identity,
        signal_operations=operations or FakeSignalOperations(),
        first_sequence=first_sequence,
    )


def _supervisor(identity, *, forwarded=None, first_sequence=1):
    forwarded = [] if forwarded is None else forwarded
    return SupervisorSignalHandoff(
        "run-0123456789abcdef",
        identity_validator=lambda value: value == identity,
        forwarder=lambda pgid, name: forwarded.append((pgid, name)),
        first_sequence=first_sequence,
    )


def _send_request(coordinator):
    read_fd, write_fd = os.pipe()
    try:
        request = coordinator.send_ready(
            write_fd,
            blocked=set(MASK),
            dispositions=dict(DISPOSITIONS),
            deadline=time.monotonic() + 0.5,
        )
        os.close(write_fd)
        write_fd = -1
        return request, read_fd
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        if write_fd >= 0:
            os.close(write_fd)


def _accept_request(supervisor, request_read_fd):
    response_read, response_write = os.pipe()
    try:
        acceptance = supervisor.receive_and_accept(
            request_read_fd,
            response_write,
            deadline=time.monotonic() + 0.5,
        )
        os.close(response_write)
        response_write = -1
        return acceptance, response_read
    except BaseException:
        os.close(response_read)
        raise
    finally:
        if response_write >= 0:
            os.close(response_write)


def _round_trip(coordinator, supervisor):
    request, request_read = _send_request(coordinator)
    try:
        acceptance, response_read = _accept_request(supervisor, request_read)
    finally:
        os.close(request_read)
    try:
        coordinator.receive_acceptance(response_read, deadline=time.monotonic() + 0.5)
    finally:
        os.close(response_read)
    return request, acceptance


def _evidence(
    request,
    *,
    nonce=None,
    unblock_index=7,
    first_functional_index=None,
    functional_count=0,
):
    return TraceUnblockEvidence(
        run_nonce=request.run_nonce if nonce is None else nonce,
        identity=request.identity,
        request_sequence=request.sequence,
        request_sha256=request.canonical_sha256,
        unblock_trace_record_index=unblock_index,
        first_functional_trace_record_index=first_functional_index,
        functional_count=functional_count,
    )


def test_actual_pipe_round_trip_uses_two_distinct_role_instances(identity):
    operations = FakeSignalOperations()
    forwarded = []
    coordinator = _coordinator(identity, operations=operations)
    supervisor = _supervisor(identity, forwarded=forwarded)
    supervisor.collect_signal("INT")

    request, acceptance = _round_trip(coordinator, supervisor)

    assert acceptance.request_sha256 == request.canonical_sha256
    assert isinstance(coordinator.snapshot(), CoordinatorSnapshot)
    assert isinstance(supervisor.snapshot(), SupervisorSnapshot)
    assert coordinator.snapshot().role == "COORDINATOR"
    assert supervisor.snapshot().role == "SUPERVISOR"
    assert coordinator.snapshot().acceptance_validated
    assert coordinator.snapshot().unblock_count == 1
    assert supervisor.snapshot().acceptance_count == 1
    assert supervisor.snapshot().forward_count == 1
    assert forwarded == [(identity.pgid, "INT")]
    assert operations.unblock_calls == 1
    assert not hasattr(supervisor, "_sent_request")
    assert not hasattr(coordinator, "_expected_acceptance")


def test_supervisor_build_acceptance_is_pure_and_cannot_authorize(identity):
    coordinator = _coordinator(identity)
    supervisor = _supervisor(identity)
    request, request_read = _send_request(coordinator)
    os.close(request_read)
    before = supervisor.snapshot()

    acceptance = supervisor.build_acceptance(request)

    assert acceptance.request_sha256 == request.canonical_sha256
    assert supervisor.snapshot() == before
    assert supervisor.snapshot().acceptance_count == 0
    assert not hasattr(coordinator, "finalize_ready")
    assert hasattr(supervisor, "finalize_ready")


def test_supervisor_authorizes_only_after_actual_complete_frame_write(identity):
    coordinator = _coordinator(identity)
    forwarded = []
    supervisor = _supervisor(identity, forwarded=forwarded)
    supervisor.collect_signal("TERM")
    _request, request_read = _send_request(coordinator)
    response_read, response_write = os.pipe()
    os.close(response_read)
    response_read = -1
    try:
        with pytest.raises(SignalHandoffError, match="write"):
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(request_read)
        if response_read >= 0:
            os.close(response_read)
        os.close(response_write)
    snapshot = supervisor.snapshot()
    assert snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == snapshot.forward_count == 0
    assert forwarded == []


def test_coordinator_rejection_does_not_rewrite_supervisor_authorization(identity):
    operations = FakeSignalOperations()
    coordinator = _coordinator(identity, operations=operations)
    supervisor = _supervisor(identity)
    request, request_read = _send_request(coordinator)
    try:
        acceptance, legitimate_response = _accept_request(supervisor, request_read)
    finally:
        os.close(request_read)
    os.close(legitimate_response)
    wrong_read, wrong_write = os.pipe()
    try:
        wrong = acceptance.replaced(run_nonce="wrong")
        write_frame(wrong_write, wrong.as_message(), deadline=time.monotonic() + 0.2)
        os.close(wrong_write)
        wrong_write = -1
        with pytest.raises(SignalHandoffError, match="acceptance"):
            coordinator.receive_acceptance(wrong_read, deadline=time.monotonic() + 0.2)
    finally:
        os.close(wrong_read)
        if wrong_write >= 0:
            os.close(wrong_write)
    assert request.sequence == 1
    assert coordinator.snapshot().terminal_state == "FAILED"
    assert coordinator.snapshot().unblock_count == 0
    assert operations.unblock_calls == 0
    assert supervisor.snapshot().acceptance_count == 1
    assert supervisor.snapshot().terminal_state is None


@pytest.mark.parametrize("fault", ["eof", "malformed", "timeout"])
def test_coordinator_response_channel_faults_remain_blocked_and_failed(identity, fault):
    operations = FakeSignalOperations()
    coordinator = _coordinator(identity, operations=operations)
    _request, request_read = _send_request(coordinator)
    os.close(request_read)
    response_read, response_write = os.pipe()
    try:
        if fault == "eof":
            os.close(response_write)
            response_write = -1
        elif fault == "malformed":
            os.write(response_write, b"\x00\x00\x00\x02[]")
            os.close(response_write)
            response_write = -1
        with pytest.raises(SignalHandoffError):
            coordinator.receive_acceptance(
                response_read, deadline=time.monotonic() + 0.02
            )
    finally:
        os.close(response_read)
        if response_write >= 0:
            os.close(response_write)
    assert coordinator.snapshot().terminal_state == "FAILED"
    assert coordinator.snapshot().unblock_count == 0
    assert operations.unblock_calls == 0


def test_supervisor_malformed_request_never_writes_or_authorizes(identity):
    supervisor = _supervisor(identity)
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    try:
        os.write(request_write, b"\x00\x00\x00\x02[]")
        os.close(request_write)
        request_write = -1
        with pytest.raises(SignalHandoffError, match="read"):
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(request_read)
        os.close(response_read)
        os.close(response_write)
        if request_write >= 0:
            os.close(request_write)
    snapshot = supervisor.snapshot()
    assert snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == snapshot.forward_count == 0


def test_default_coordinator_path_really_unblocks_and_preserves_handlers(identity):
    reviewed = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
    old_handlers = {number: signal.getsignal(number) for number in reviewed}

    def handler(_number, _frame):
        return None

    try:
        for number in reviewed:
            signal.signal(number, handler)
        coordinator = CoordinatorSignalHandoff("nonce", identity)
        supervisor = SupervisorSignalHandoff(
            "nonce",
            identity_validator=lambda _value: True,
            forwarder=lambda _pgid, _name: None,
        )
        _round_trip(coordinator, supervisor)
        current = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        assert reviewed.isdisjoint(current)
        assert all(signal.getsignal(number) is handler for number in reviewed)
        assert coordinator.snapshot().unblock_count == 1
    finally:
        for number, disposition in old_handlers.items():
            signal.signal(number, disposition)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def test_changed_handler_after_unblock_fails_closed(identity):
    operations = FakeSignalOperations(change_disposition=True)
    coordinator = _coordinator(identity, operations=operations)
    supervisor = _supervisor(identity)
    request, request_read = _send_request(coordinator)
    try:
        _acceptance, response_read = _accept_request(supervisor, request_read)
    finally:
        os.close(request_read)
    try:
        with pytest.raises(SignalHandoffError, match="disposition"):
            coordinator.receive_acceptance(
                response_read, deadline=time.monotonic() + 0.2
            )
    finally:
        os.close(response_read)
    assert request.sequence == 1
    assert operations.unblock_calls == 1
    assert coordinator.snapshot().terminal_state == "FAILED"
    assert coordinator.snapshot().unblock_count == 0


def test_replacing_callable_handler_with_another_callable_fails_closed(identity):
    class TokenChangingOperations:
        def __init__(self):
            self.observation = SignalObservation(
                MASK, DISPOSITIONS, ("handler-a", "handler-b", "handler-c")
            )

        def observe(self):
            return self.observation

        def unblock_reviewed(self):
            self.observation = SignalObservation(
                frozenset(),
                DISPOSITIONS,
                ("different-handler", "handler-b", "handler-c"),
            )

    coordinator = _coordinator(identity, operations=TokenChangingOperations())
    supervisor = _supervisor(identity)
    _request, request_read = _send_request(coordinator)
    try:
        _acceptance, response_read = _accept_request(supervisor, request_read)
    finally:
        os.close(request_read)
    try:
        with pytest.raises(SignalHandoffError, match="disposition"):
            coordinator.receive_acceptance(
                response_read, deadline=time.monotonic() + 0.2
            )
    finally:
        os.close(response_read)
    assert coordinator.snapshot().terminal_state == "FAILED"


def test_signal_observation_requires_exact_handler_identity_tokens():
    with pytest.raises(SignalHandoffError, match="handler identities"):
        SignalObservation(MASK, DISPOSITIONS)


def test_unblock_operation_exception_is_normalized_and_terminal(identity):
    class FailingUnblockOperations(FakeSignalOperations):
        def unblock_reviewed(self):
            raise OSError("pthread_sigmask failed")

    operations = FailingUnblockOperations()
    coordinator = _coordinator(identity, operations=operations)
    supervisor = _supervisor(identity)
    _request, request_read = _send_request(coordinator)
    try:
        _acceptance, response_read = _accept_request(supervisor, request_read)
    finally:
        os.close(request_read)
    try:
        with pytest.raises(SignalHandoffError, match="unblock"):
            coordinator.receive_acceptance(
                response_read, deadline=time.monotonic() + 0.2
            )
    finally:
        os.close(response_read)
    assert coordinator.snapshot().terminal_state == "FAILED"
    assert coordinator.snapshot().unblock_count == 0


def test_supervisor_finalizes_zero_and_nonzero_functional_runs(identity):
    seen = []
    for functional_count in (0, 1):
        coordinator = _coordinator(identity)
        supervisor = _supervisor(identity)
        request, _acceptance = _round_trip(coordinator, supervisor)
        if functional_count:
            coordinator.record_functional_progress()
        evidence = _evidence(
            request,
            unblock_index=10,
            first_functional_index=11 if functional_count else None,
            functional_count=functional_count,
        )
        coordinator_before = coordinator.snapshot()
        supervisor.finalize_ready(
            coordinator_before,
            evidence,
            lambda value: seen.append(value) is None,
        )
        assert coordinator.snapshot() == coordinator_before
        assert coordinator.snapshot().state == "LIVE_READY"
        assert coordinator.snapshot().terminal_state is None
        assert supervisor.snapshot().terminal_state == "READY"
    assert seen[0].first_functional_trace_record_index is None
    assert (
        seen[1].unblock_trace_record_index < seen[1].first_functional_trace_record_index
    )


@pytest.mark.parametrize(
    "fault",
    ["coordinator", "binding", "order", "count", "verifier", "missing_verifier"],
)
def test_supervisor_rejects_inconsistent_or_untrusted_terminal_evidence(
    identity, fault
):
    coordinator = _coordinator(identity)
    supervisor = _supervisor(identity)
    request, _acceptance = _round_trip(coordinator, supervisor)
    coordinator.record_functional_progress()
    coordinator_evidence = coordinator.snapshot()
    kwargs = {
        "unblock_index": 7,
        "first_functional_index": 8,
        "functional_count": 1,
    }
    if fault == "coordinator":
        coordinator_evidence = replace(coordinator_evidence, unblock_count=0)
    elif fault == "binding":
        kwargs["nonce"] = "wrong"
    elif fault == "order":
        kwargs["first_functional_index"] = 6
    elif fault == "count":
        kwargs["functional_count"] = 0
        kwargs["first_functional_index"] = None
    evidence = _evidence(request, **kwargs)
    verifier = (
        None if fault == "missing_verifier" else lambda _value: fault != "verifier"
    )

    with pytest.raises(SignalHandoffError):
        supervisor.finalize_ready(coordinator_evidence, evidence, verifier)

    assert coordinator.snapshot().state == "LIVE_READY"
    assert coordinator.snapshot().terminal_state is None
    assert supervisor.snapshot().terminal_state == "FAILED"


def test_supervisor_rejects_later_readiness_without_mutating_authorization(
    identity, monkeypatch
):
    forwarded = []
    supervisor = _supervisor(identity, forwarded=forwarded)
    supervisor.collect_signal("TERM")
    _first_request, first_read = _send_request(_coordinator(identity))
    _second_request, second_read = _send_request(
        _coordinator(identity, first_sequence=2)
    )
    writer_calls = []
    real_write_frame = signal_handoff_module.write_frame

    def count_write(*args, **kwargs):
        writer_calls.append((args, kwargs))
        return real_write_frame(*args, **kwargs)

    monkeypatch.setattr(signal_handoff_module, "write_frame", count_write)
    try:
        _acceptance, first_response_read = _accept_request(supervisor, first_read)
        os.close(first_response_read)
        accepted = supervisor.snapshot()

        with pytest.raises(SignalHandoffError, match="already accepted"):
            _accept_request(supervisor, second_read)
    finally:
        os.close(first_read)
        os.close(second_read)
    assert accepted.acceptance_count == accepted.forward_count == 1
    assert accepted.next_sequence == 2
    assert supervisor.snapshot() == accepted
    assert len(writer_calls) == 1
    assert forwarded == [(identity.pgid, "TERM")]


def test_concurrent_duplicate_requests_authorize_exactly_one_without_loser_mutation(
    identity, monkeypatch
):
    source = _coordinator(identity)
    request, original_read = _send_request(source)
    os.close(original_read)
    forwarded = []
    supervisor = _supervisor(identity, forwarded=forwarded)
    supervisor.collect_signal("INT")
    channels = []
    for _index in range(2):
        request_read, request_write = os.pipe()
        response_read, response_write = os.pipe()
        write_frame(
            request_write,
            request.as_message(),
            deadline=time.monotonic() + 0.2,
        )
        os.close(request_write)
        channels.append((request_read, response_read, response_write))

    writer_calls = []
    real_write_frame = signal_handoff_module.write_frame

    def count_write(*args, **kwargs):
        writer_calls.append((args, kwargs))
        return real_write_frame(*args, **kwargs)

    monkeypatch.setattr(signal_handoff_module, "write_frame", count_write)

    def accept(channel):
        request_read, _response_read, response_write = channel
        try:
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.5,
            )
            return "accepted"
        except SignalHandoffError as error:
            return str(error)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(accept, channels))
    finally:
        for request_read, response_read, response_write in channels:
            os.close(request_read)
            os.close(response_read)
            os.close(response_write)
    assert sorted(outcomes) == ["accepted", "readiness already accepted"]
    snapshot = supervisor.snapshot()
    assert snapshot.state == "READY"
    assert snapshot.terminal_state is None
    assert snapshot.next_sequence == 2
    assert snapshot.acceptance_count == snapshot.forward_count == 1
    assert [event.name for event in snapshot.events] == [
        "signal_latched",
        "ready_request_validated",
        "acceptance_write",
        "signal_forward",
    ]
    assert len(writer_calls) == 1
    assert forwarded == [(identity.pgid, "INT")]


def test_supervisor_trace_verifier_reentry_cannot_be_overwritten_by_ready(identity):
    coordinator = _coordinator(identity)
    supervisor = _supervisor(identity)
    request, _acceptance = _round_trip(coordinator, supervisor)

    def verifier(_evidence):
        supervisor.fail("trace verifier reentry")
        return True

    with pytest.raises(SignalHandoffError):
        supervisor.finalize_ready(
            coordinator.snapshot(),
            _evidence(request),
            verifier,
        )

    snapshot = supervisor.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.events[-1].name == "failed:trace verifier reentry"
    assert all(event.name != "terminal_ready" for event in snapshot.events)
    assert coordinator.snapshot().state == "LIVE_READY"
    assert coordinator.snapshot().terminal_state is None


@pytest.mark.parametrize("reentry_call", [1, 2])
def test_identity_validator_reentry_preserves_acceptance_boundary(
    identity, reentry_call
):
    holder = {}
    calls = 0

    def identity_validator(_identity):
        nonlocal calls
        calls += 1
        if calls == reentry_call:
            holder["supervisor"].fail("identity validator reentry")
        return True

    supervisor = SupervisorSignalHandoff(
        "run-0123456789abcdef",
        identity_validator=identity_validator,
        forwarder=lambda _pgid, _name: None,
    )
    holder["supervisor"] = supervisor
    if reentry_call == 2:
        supervisor.collect_signal("TERM")
    _request, request_read = _send_request(_coordinator(identity))
    response_read, response_write = os.pipe()
    try:
        with pytest.raises(SignalHandoffError):
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(request_read)
        os.close(response_read)
        os.close(response_write)

    snapshot = supervisor.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == reentry_call - 1
    assert snapshot.forward_count == 0
    assert snapshot.next_sequence == reentry_call
    assert snapshot.events[-1].name == "failed:identity validator reentry"
    assert all(event.name != "signal_forward" for event in snapshot.events)


def test_forwarder_reentrant_failure_cannot_commit_forward(identity):
    holder = {}

    def forwarder(_pgid, _name):
        holder["supervisor"].fail("forwarder reentry")
        return None

    supervisor = SupervisorSignalHandoff(
        "run-0123456789abcdef",
        identity_validator=lambda value: value == identity,
        forwarder=forwarder,
    )
    holder["supervisor"] = supervisor
    supervisor.collect_signal("HUP")
    _request, request_read = _send_request(_coordinator(identity))
    response_read, response_write = os.pipe()
    try:
        with pytest.raises(SignalHandoffError):
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(request_read)
        os.close(response_read)
        os.close(response_write)

    snapshot = supervisor.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == 1
    assert snapshot.forward_count == 0
    assert snapshot.next_sequence == 2
    assert snapshot.events[-1].name == "failed:forwarder reentry"
    assert all(event.name != "signal_forward" for event in snapshot.events)


def test_coordinator_writer_reentrant_failure_cannot_commit_request(
    identity, monkeypatch
):
    coordinator = _coordinator(identity)
    real_write_frame = signal_handoff_module.write_frame

    def reentrant_write(*args, **kwargs):
        coordinator.fail("coordinator writer reentry")
        return real_write_frame(*args, **kwargs)

    monkeypatch.setattr(signal_handoff_module, "write_frame", reentrant_write)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(SignalHandoffError):
            coordinator.send_ready(
                write_fd,
                blocked=set(MASK),
                dispositions=dict(DISPOSITIONS),
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(read_fd)
        os.close(write_fd)

    snapshot = coordinator.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.request_sequence is None
    assert snapshot.acceptance_validated is False
    assert snapshot.unblock_count == 0
    assert snapshot.events[-1].name == "failed:coordinator writer reentry"
    assert all(event.name != "ready_request_write" for event in snapshot.events)


def test_completed_response_linearizes_acceptance_before_reentrant_failure(
    identity, monkeypatch
):
    coordinator = _coordinator(identity)
    supervisor = _supervisor(identity)
    _request, request_read = _send_request(coordinator)
    response_read, response_write = os.pipe()
    real_write_frame = signal_handoff_module.write_frame

    def complete_then_fail(*args, **kwargs):
        result = real_write_frame(*args, **kwargs)
        supervisor.fail("failure after response publication")
        return result

    monkeypatch.setattr(signal_handoff_module, "write_frame", complete_then_fail)
    try:
        with pytest.raises(SignalHandoffError):
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
    finally:
        os.close(request_read)
        os.close(response_write)
    try:
        coordinator.receive_acceptance(
            response_read,
            deadline=time.monotonic() + 0.2,
        )
    finally:
        os.close(response_read)

    snapshot = supervisor.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == 1
    assert snapshot.forward_count == 0
    assert snapshot.next_sequence == 2
    assert [event.name for event in snapshot.events][-2:] == [
        "acceptance_write",
        "failed:failure after response publication",
    ]
    assert coordinator.snapshot().state == "LIVE_READY"
    assert coordinator.snapshot().unblock_count == 1


def test_signal_during_response_publication_is_preserved_and_forwarded_once(
    identity, monkeypatch
):
    coordinator = _coordinator(identity)
    forwarded = []
    supervisor = _supervisor(identity, forwarded=forwarded)
    _request, request_read = _send_request(coordinator)
    response_read, response_write = os.pipe()
    real_write_frame = signal_handoff_module.write_frame

    def complete_then_collect_signal(*args, **kwargs):
        result = real_write_frame(*args, **kwargs)
        supervisor.collect_signal("TERM")
        return result

    monkeypatch.setattr(
        signal_handoff_module,
        "write_frame",
        complete_then_collect_signal,
    )
    try:
        supervisor.receive_and_accept(
            request_read,
            response_write,
            deadline=time.monotonic() + 0.2,
        )
    finally:
        os.close(request_read)
        os.close(response_write)
    try:
        coordinator.receive_acceptance(
            response_read,
            deadline=time.monotonic() + 0.2,
        )
    finally:
        os.close(response_read)

    snapshot = supervisor.snapshot()
    assert snapshot.state == "READY"
    assert snapshot.terminal_state is None
    assert snapshot.acceptance_count == snapshot.forward_count == 1
    assert snapshot.pending_signal == "TERM"
    assert forwarded == [(identity.pgid, "TERM")]
    assert [event.name for event in snapshot.events][-3:] == [
        "acceptance_write",
        "signal_latched",
        "signal_forward",
    ]


def test_completed_response_linearizes_before_concurrent_failure(identity, monkeypatch):
    coordinator = _coordinator(identity)
    supervisor = _supervisor(identity)
    _request, request_read = _send_request(coordinator)
    response_read, response_write = os.pipe()
    real_write_frame = signal_handoff_module.write_frame
    response_complete = Event()
    failure_complete = Event()

    def complete_and_allow_failure_attempt(*args, **kwargs):
        result = real_write_frame(*args, **kwargs)
        response_complete.set()
        failure_complete.wait(0.05)
        return result

    def fail_after_complete_response():
        assert response_complete.wait(0.5)
        supervisor.fail("concurrent failure after response publication")
        failure_complete.set()

    monkeypatch.setattr(
        signal_handoff_module,
        "write_frame",
        complete_and_allow_failure_attempt,
    )
    failure_thread = Thread(target=fail_after_complete_response, daemon=True)
    failure_thread.start()
    try:
        try:
            supervisor.receive_and_accept(
                request_read,
                response_write,
                deadline=time.monotonic() + 0.2,
            )
        except SignalHandoffError:
            pass
    finally:
        os.close(request_read)
        os.close(response_write)
    failure_thread.join(0.5)
    assert not failure_thread.is_alive()
    try:
        coordinator.receive_acceptance(
            response_read,
            deadline=time.monotonic() + 0.2,
        )
    finally:
        os.close(response_read)

    snapshot = supervisor.snapshot()
    assert snapshot.state == snapshot.terminal_state == "FAILED"
    assert snapshot.acceptance_count == 1
    assert snapshot.next_sequence == 2
    assert coordinator.snapshot().state == "LIVE_READY"
    assert coordinator.snapshot().unblock_count == 1


def test_terminal_role_states_are_immutable(identity):
    coordinator = _coordinator(identity)
    coordinator.fail("timeout")
    coordinator_before = coordinator.snapshot()
    with pytest.raises(SignalHandoffError, match="terminal"):
        coordinator.record_functional_progress()
    with pytest.raises(SignalHandoffError, match="terminal"):
        coordinator.fail("again")
    assert coordinator.snapshot() == coordinator_before

    supervisor = SupervisorSignalHandoff.not_applicable("nonce")
    supervisor_before = supervisor.snapshot()
    with pytest.raises(SignalHandoffError, match="terminal"):
        supervisor.collect_signal("INT")
    with pytest.raises(SignalHandoffError, match="terminal"):
        supervisor.fail("late")
    assert supervisor.snapshot() == supervisor_before


def test_shared_role_compatibility_facade_cannot_produce_proof():
    with pytest.raises(SignalHandoffError, match="explicit coordinator/supervisor"):
        SignalHandoff("nonce")
