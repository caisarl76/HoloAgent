"""Two-way signal-readiness barrier, pipe, terminal, and race tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import signal
import time

import pytest

from holoagent0_setup.broker import write_frame
from holoagent0_setup.process_identity import ProcessIdentity
from holoagent0_setup.signal_handoff import (
    SignalHandoff,
    SignalHandoffError,
    SignalObservation,
    TraceUnblockEvidence,
)


MASK = frozenset({"HUP", "INT", "TERM"})
DISPOSITIONS = {"HUP": True, "INT": True, "TERM": True}


@pytest.fixture
def identity():
    return ProcessIdentity(101, 101, 12345, "/bin/coordinator", "a" * 64)


@pytest.fixture
def observation():
    return SignalObservation(
        blocked_signals=MASK,
        dispositions=(("HUP", True), ("INT", True), ("TERM", True)),
    )


def _handoff(identity, observation, **kwargs):
    return SignalHandoff(
        "run-0123456789abcdef",
        identity_validator=lambda value: value == identity,
        signal_observer=lambda: observation,
        **kwargs,
    )


@pytest.fixture
def harness(identity, observation):
    forwarded = []
    written = []
    handoff = _handoff(
        identity,
        observation,
        acceptance_writer=written.append,
        forwarder=lambda pgid, signal_name: forwarded.append((pgid, signal_name)),
    )
    return handoff, forwarded, written


def _ready(handoff, identity):
    return handoff.coordinator_ready(
        identity,
        blocked=set(MASK),
        dispositions=dict(DISPOSITIONS),
    )


def _evidence(request, *, index=7):
    return TraceUnblockEvidence(
        run_nonce=request.run_nonce,
        identity=request.identity,
        request_sequence=request.sequence,
        request_sha256=request.canonical_sha256,
        unblocked_signals=("HUP", "INT", "TERM"),
        trace_record_index=index,
    )


def _complete_ready(handoff, identity):
    request = _ready(handoff, identity)
    acceptance = handoff.supervisor_accept(request)
    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked(_evidence(request))
    handoff.record_functional_progress()
    handoff.finalize_ready()
    return request, acceptance


def test_acceptance_bytes_are_required_before_count_forward_unblock(harness, identity):
    handoff, forwarded, written = harness
    request = _ready(handoff, identity)
    handoff.collect_signal("INT")
    assert handoff.state == "PENDING_FORWARD"

    acceptance = handoff.supervisor_accept(request)
    assert acceptance.request_sequence == request.sequence
    assert acceptance.request_sha256 == request.canonical_sha256
    assert len(written) == 1
    assert handoff.acceptance_count == handoff.forward_count == 0
    assert forwarded == []
    assert handoff.terminal_state is None

    handoff.coordinator_validate(acceptance)
    assert handoff.acceptance_count == handoff.forward_count == 1
    assert forwarded == [(identity.pgid, "INT")]
    handoff.coordinator_unblocked(_evidence(request))
    handoff.record_functional_progress()
    assert handoff.terminal_state is None
    handoff.finalize_ready()
    assert handoff.terminal_state == "READY"
    names = [event.name for event in handoff.events]
    assert names.index("handlers_installed") < names.index("ready_request")
    assert names.index("ready_request") < names.index("acceptance_write")
    assert names.index("acceptance_write") < names.index("acceptance_validated")
    assert names.index("acceptance_validated") < names.index("trace_unblock")
    assert names.index("trace_unblock") < names.index("functional")
    assert names.index("functional") < names.index("terminal_ready")


@pytest.mark.parametrize("fault", ["wrong_nonce", "wrong_identity", "wrong_sequence"])
def test_wrong_acceptance_with_pending_signal_keeps_all_counts_zero(
    harness, identity, fault
):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    handoff.collect_signal("TERM")
    acceptance = handoff.supervisor_accept(request)
    if fault == "wrong_nonce":
        acceptance = acceptance.replaced(run_nonce="different")
    elif fault == "wrong_identity":
        acceptance = acceptance.replaced(
            identity=ProcessIdentity(102, 102, 12345, "/bin/coordinator", "a" * 64)
        )
    else:
        acceptance = acceptance.replaced(request_sequence=2)
    with pytest.raises(SignalHandoffError):
        handoff.coordinator_validate(acceptance)
    assert handoff.terminal_state == "FAILED"
    assert handoff.acceptance_count == handoff.forward_count == 0
    assert forwarded == []


@pytest.mark.parametrize("writer_result", [0, 1])
def test_partial_or_zero_acceptance_writer_fails_before_acceptance(
    identity, observation, writer_result
):
    forwarded = []
    handoff = _handoff(
        identity,
        observation,
        acceptance_writer=lambda _acceptance: writer_result,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.collect_signal("TERM")
    with pytest.raises(SignalHandoffError, match="write"):
        handoff.supervisor_accept(request)
    assert handoff.terminal_state == "FAILED"
    assert handoff.acceptance_count == handoff.forward_count == 0
    assert forwarded == []


def test_acceptance_writer_exception_fails_before_acceptance(identity, observation):
    def fail_write(_acceptance):
        raise OSError("closed pipe")

    handoff = _handoff(identity, observation, acceptance_writer=fail_write)
    request = _ready(handoff, identity)
    with pytest.raises(SignalHandoffError, match="write"):
        handoff.supervisor_accept(request)
    assert handoff.terminal_state == "FAILED"
    assert handoff.acceptance_count == handoff.forward_count == 0


def test_real_pipe_entrypoints_bind_exact_written_and_read_acceptance(
    identity, observation
):
    forwarded = []
    handoff = _handoff(
        identity,
        observation,
        forwarder=lambda *args: forwarded.append(args),
    )
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    try:
        request = handoff.coordinator_ready_to_pipe(
            request_write,
            identity,
            blocked=set(MASK),
            dispositions=dict(DISPOSITIONS),
            deadline=time.monotonic() + 0.5,
        )
        os.close(request_write)
        request_write = -1
        handoff.collect_signal("HUP")
        acceptance = handoff.supervisor_accept_from_pipe(
            request_read,
            response_write,
            deadline=time.monotonic() + 0.5,
        )
        assert acceptance.request_sha256 == request.canonical_sha256
        assert handoff.acceptance_count == handoff.forward_count == 0
        os.close(response_write)
        response_write = -1
        handoff.coordinator_validate_from_pipe(
            response_read, deadline=time.monotonic() + 0.5
        )
        assert handoff.acceptance_count == handoff.forward_count == 1
        assert forwarded == [(identity.pgid, "HUP")]
    finally:
        os.close(request_read)
        os.close(response_read)
        if request_write >= 0:
            os.close(request_write)
        if response_write >= 0:
            os.close(response_write)


@pytest.mark.parametrize("fault", ["eof", "partial", "malformed", "timeout", "wrong"])
def test_bad_response_pipe_fails_closed_with_pending_signal(
    identity, observation, fault
):
    forwarded = []
    handoff = _handoff(
        identity,
        observation,
        acceptance_writer=lambda _acceptance: None,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.collect_signal("INT")
    acceptance = handoff.supervisor_accept(request)
    read_fd, write_fd = os.pipe()
    try:
        if fault == "partial":
            os.write(write_fd, b"\x00\x00\x00\x08{}")
            os.close(write_fd)
            write_fd = -1
        elif fault == "malformed":
            os.write(write_fd, b"\x00\x00\x00\x02[]")
            os.close(write_fd)
            write_fd = -1
        elif fault == "eof":
            os.close(write_fd)
            write_fd = -1
        elif fault == "wrong":
            wrong = acceptance.replaced(run_nonce="wrong")
            write_frame(write_fd, wrong.as_message(), deadline=time.monotonic() + 0.2)
            os.close(write_fd)
            write_fd = -1
        with pytest.raises(SignalHandoffError):
            handoff.coordinator_validate_from_pipe(
                read_fd, deadline=time.monotonic() + 0.02
            )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
    assert handoff.terminal_state == "FAILED"
    assert handoff.acceptance_count == handoff.forward_count == 0
    assert forwarded == []


def test_actual_os_mask_and_handlers_are_observed(identity):
    signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    old_handlers = {number: signal.getsignal(number) for number in signals}

    def handler(_number, _frame):
        return None

    try:
        for number in signals:
            signal.signal(number, handler)
        handoff = SignalHandoff(
            "nonce",
            identity_validator=lambda _value: True,
        )
        request = _ready(handoff, identity)
        assert set(request.blocked_signals) == MASK
        assert dict(request.dispositions) == DISPOSITIONS
    finally:
        for number, disposition in old_handlers.items():
            signal.signal(number, disposition)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)


def test_omitted_disposition_proof_and_observation_mismatch_reject(
    identity, observation
):
    handoff = _handoff(identity, observation)
    with pytest.raises(SignalHandoffError, match="disposition"):
        handoff.coordinator_ready(identity, blocked=set(MASK))

    mismatched = SignalObservation(
        blocked_signals=frozenset({"INT", "TERM"}),
        dispositions=observation.dispositions,
    )
    handoff = _handoff(identity, mismatched)
    with pytest.raises(SignalHandoffError, match="observed"):
        _ready(handoff, identity)


def test_public_signal_types_normalize_malformed_unicode_and_observation():
    with pytest.raises(SignalHandoffError):
        SignalHandoff("\ud800")
    with pytest.raises(SignalHandoffError):
        SignalObservation(
            blocked_signals=MASK,
            dispositions=(("HUP", True),),
        )


def test_public_readiness_messages_normalize_broker_protocol_errors(harness, identity):
    handoff, _forwarded, _written = harness
    request = _ready(handoff, identity)
    acceptance = handoff.supervisor_accept(request)
    with pytest.raises(SignalHandoffError):
        request.replaced(sequence=True).as_message()
    with pytest.raises(SignalHandoffError):
        acceptance.replaced(request_sequence=True).as_message()


def test_trace_evidence_must_match_all_immutable_bindings(harness, identity):
    handoff, _forwarded, _written = harness
    request = _ready(handoff, identity)
    acceptance = handoff.supervisor_accept(request)
    handoff.coordinator_validate(acceptance)
    wrong = _evidence(request)
    wrong = TraceUnblockEvidence(
        run_nonce="wrong",
        identity=wrong.identity,
        request_sequence=wrong.request_sequence,
        request_sha256=wrong.request_sha256,
        unblocked_signals=wrong.unblocked_signals,
        trace_record_index=wrong.trace_record_index,
    )
    with pytest.raises(SignalHandoffError, match="evidence"):
        handoff.coordinator_unblocked(wrong)
    assert handoff.terminal_state == "FAILED"
    assert handoff.unblock_count == handoff.functional_count == 0


def test_signal_during_acceptance_write_stays_pending_until_coordinator_validation(
    identity, observation
):
    observations = []
    forwarded = []
    handoff = None

    def write_acceptance(_acceptance):
        handoff.collect_signal("INT")
        observations.append((handoff.state, handoff.forward_count))

    handoff = _handoff(
        identity,
        observation,
        acceptance_writer=write_acceptance,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    acceptance = handoff.supervisor_accept(request)
    assert observations == [("PENDING_FORWARD", 0)]
    assert forwarded == []
    handoff.coordinator_validate(acceptance)
    assert forwarded == [(identity.pgid, "INT")]


def test_first_signal_is_latched_and_forwarded_once_after_validation(
    identity, observation
):
    validations = []
    forwarded = []

    def validate(value):
        validations.append(value)
        return value == identity

    handoff = SignalHandoff(
        "nonce",
        identity_validator=validate,
        signal_observer=lambda: observation,
        acceptance_writer=lambda _value: None,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.collect_signal("HUP")
    handoff.collect_signal("TERM")
    acceptance = handoff.supervisor_accept(request)
    assert forwarded == []
    handoff.coordinator_validate(acceptance)
    handoff.collect_signal("INT")
    assert handoff.pending_signal == "HUP"
    assert forwarded == [(identity.pgid, "HUP")]
    assert len(validations) == 2


def test_concurrent_signal_and_acceptance_have_bounded_counts(harness, identity):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    with ThreadPoolExecutor(max_workers=2) as executor:
        signal_future = executor.submit(handoff.collect_signal, "INT")
        accept_future = executor.submit(handoff.supervisor_accept, request)
        signal_future.result()
        acceptance = accept_future.result()
    assert handoff.acceptance_count == handoff.forward_count == 0
    handoff.coordinator_validate(acceptance)
    assert handoff.acceptance_count == handoff.forward_count == 1
    assert forwarded == [(identity.pgid, "INT")]


def test_failed_timeout_cannot_be_resurrected_by_late_acceptance(harness, identity):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    handoff.collect_signal("TERM")
    acceptance = handoff.supervisor_accept(request)
    handoff.fail("acceptance timeout")
    snapshot = (
        handoff.state,
        handoff.terminal_state,
        handoff.acceptance_count,
        handoff.forward_count,
        handoff.events,
    )
    with pytest.raises(SignalHandoffError, match="terminal"):
        handoff.coordinator_validate(acceptance)
    assert snapshot == (
        handoff.state,
        handoff.terminal_state,
        handoff.acceptance_count,
        handoff.forward_count,
        handoff.events,
    )
    assert forwarded == []


def test_duplicate_acceptance_failure_cannot_resurrect(harness, identity):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    handoff.collect_signal("TERM")
    acceptance = handoff.supervisor_accept(request)
    wrong = acceptance.replaced(run_nonce="wrong")
    with pytest.raises(SignalHandoffError):
        handoff.coordinator_validate(wrong)
    snapshot = (handoff.acceptance_count, handoff.forward_count, handoff.events)
    with pytest.raises(SignalHandoffError, match="terminal"):
        handoff.coordinator_validate(acceptance)
    assert snapshot == (handoff.acceptance_count, handoff.forward_count, handoff.events)
    assert forwarded == []


@pytest.mark.parametrize("terminal", ["FAILED", "READY", "NOT_APPLICABLE"])
def test_terminal_states_are_immutable_for_all_transition_operations(
    identity, observation, terminal
):
    donor = _handoff(identity, observation, acceptance_writer=lambda _value: None)
    request = _ready(donor, identity)
    acceptance = donor.supervisor_accept(request)
    evidence = _evidence(request)

    if terminal == "FAILED":
        handoff = _handoff(identity, observation)
        handoff.fail("timeout")
    elif terminal == "NOT_APPLICABLE":
        handoff = SignalHandoff.not_applicable("nonce")
    else:
        handoff = _handoff(identity, observation, acceptance_writer=lambda _value: None)
        _complete_ready(handoff, identity)

    operations = [
        lambda: handoff.supervisor_accept(request),
        lambda: handoff.coordinator_validate(acceptance),
        lambda: handoff.coordinator_unblocked(evidence),
        handoff.record_functional_progress,
        lambda: handoff.fail("late failure"),
    ]
    for operation in operations:
        before = (
            handoff.state,
            handoff.terminal_state,
            handoff.acceptance_count,
            handoff.forward_count,
            handoff.unblock_count,
            handoff.functional_count,
            handoff.events,
        )
        with pytest.raises(SignalHandoffError, match="terminal"):
            operation()
        after = (
            handoff.state,
            handoff.terminal_state,
            handoff.acceptance_count,
            handoff.forward_count,
            handoff.unblock_count,
            handoff.functional_count,
            handoff.events,
        )
        assert after == before
