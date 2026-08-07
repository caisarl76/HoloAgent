"""Two-way signal-readiness barrier and race tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from holoagent0_setup.process_identity import ProcessIdentity
from holoagent0_setup.signal_handoff import SignalHandoff, SignalHandoffError


@pytest.fixture
def identity():
    return ProcessIdentity(101, 101, 12345, "/bin/coordinator", "a" * 64)


@pytest.fixture
def harness(identity):
    forwarded = []
    written = []
    handoff = SignalHandoff(
        "run-0123456789abcdef",
        identity_validator=lambda value: value == identity,
        acceptance_writer=written.append,
        forwarder=lambda pgid, signal_name: forwarded.append((pgid, signal_name)),
    )
    return handoff, forwarded, written


def _ready(handoff, identity):
    return handoff.coordinator_ready(
        identity,
        blocked={"HUP", "INT", "TERM"},
        dispositions={"HUP": True, "INT": True, "TERM": True},
    )


def test_acceptance_is_required_before_unblock(harness, identity):
    handoff, forwarded, written = harness
    request = _ready(handoff, identity)
    handoff.collect_signal("INT")
    assert handoff.state == "PENDING_FORWARD"
    assert (
        handoff.forward_count == handoff.unblock_count == handoff.functional_count == 0
    )

    acceptance = handoff.supervisor_accept(request)
    assert acceptance.request_sequence == request.sequence
    assert acceptance.request_sha256 == request.canonical_sha256
    assert len(written) == handoff.acceptance_count == 1
    assert forwarded == [(identity.pgid, "INT")]
    assert handoff.state == "READY"
    assert handoff.terminal_state is None
    assert handoff.unblock_count == handoff.functional_count == 0

    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked({"HUP", "INT", "TERM"})
    handoff.record_functional_progress()
    assert handoff.terminal_state == "READY"
    assert (
        handoff.forward_count == handoff.unblock_count == handoff.functional_count == 1
    )
    names = [event.name for event in handoff.events]
    assert names.index("handlers_installed") < names.index("ready_request")
    assert names.index("ready_request") < names.index("acceptance_write")
    assert names.index("acceptance_write") < names.index("acceptance_validated")
    assert names.index("acceptance_validated") < names.index("unblock")
    assert names.index("unblock") < names.index("functional")
    assert any(
        event.name == "ready" and event.state == "READY" for event in handoff.events
    )


@pytest.mark.parametrize(
    "fault", ["missing", "wrong_nonce", "wrong_identity", "wrong_sequence", "duplicate"]
)
def test_rejected_acceptance_never_releases_barrier(harness, identity, fault):
    handoff, _forwarded, _written = harness
    request = _ready(handoff, identity)
    if fault == "missing":
        handoff.fail("acceptance EOF")
    else:
        acceptance = handoff.supervisor_accept(request)
        if fault == "wrong_nonce":
            acceptance = acceptance.replaced(run_nonce="different")
        elif fault == "wrong_identity":
            acceptance = acceptance.replaced(
                identity=ProcessIdentity(102, 102, 12345, "/bin/coordinator", "a" * 64)
            )
        elif fault == "wrong_sequence":
            acceptance = acceptance.replaced(request_sequence=2)
        elif fault == "duplicate":
            handoff.coordinator_validate(acceptance)
        with pytest.raises(SignalHandoffError):
            handoff.coordinator_validate(acceptance)
    assert handoff.unblock_count == 0
    assert handoff.functional_count == 0
    if fault != "duplicate":
        assert handoff.terminal_state == "FAILED"


def test_wrong_ready_nonce_sequence_identity_mask_or_disposition_is_rejected(identity):
    bad_validator = SignalHandoff(
        "expected-nonce", identity_validator=lambda _value: False
    )
    request = bad_validator.coordinator_ready(
        identity,
        blocked={"HUP", "INT", "TERM"},
        dispositions={"HUP": True, "INT": True, "TERM": True},
    )
    with pytest.raises(SignalHandoffError):
        bad_validator.supervisor_accept(request)
    assert bad_validator.acceptance_count == bad_validator.forward_count == 0

    for blocked, dispositions in [
        ({"INT", "TERM"}, {"HUP": True, "INT": True, "TERM": True}),
        ({"HUP", "INT", "TERM"}, {"HUP": True, "INT": False, "TERM": True}),
    ]:
        handoff = SignalHandoff("nonce", identity_validator=lambda _value: True)
        with pytest.raises(SignalHandoffError):
            handoff.coordinator_ready(
                identity, blocked=blocked, dispositions=dispositions
            )
        assert handoff.functional_count == handoff.unblock_count == 0


def test_coordinator_must_lead_its_validated_process_group(identity):
    nonleader = ProcessIdentity(
        identity.pid,
        identity.pgid + 1,
        identity.start_time,
        identity.executable_path,
        identity.executable_sha256,
    )
    handoff = SignalHandoff("nonce", identity_validator=lambda _value: True)
    with pytest.raises(SignalHandoffError, match="leader"):
        _ready(handoff, nonleader)
    assert (
        handoff.acceptance_count == handoff.forward_count == handoff.unblock_count == 0
    )


def test_acceptance_write_failure_keeps_counts_zero_and_never_forwards(identity):
    forwarded = []

    def fail_write(_acceptance):
        raise OSError("closed pipe")

    handoff = SignalHandoff(
        "nonce",
        identity_validator=lambda _value: True,
        acceptance_writer=fail_write,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.collect_signal("TERM")
    with pytest.raises(SignalHandoffError):
        handoff.supervisor_accept(request)
    assert handoff.terminal_state == "FAILED"
    assert handoff.acceptance_count == handoff.forward_count == 0
    assert forwarded == []


def test_duplicate_supervisor_acceptance_is_rejected_before_second_write(
    harness, identity
):
    handoff, _forwarded, written = harness
    request = _ready(handoff, identity)
    handoff.supervisor_accept(request)
    with pytest.raises(SignalHandoffError):
        handoff.supervisor_accept(request)
    assert len(written) == handoff.acceptance_count == 1


def test_signal_during_acceptance_write_stays_pending_until_write_returns(identity):
    observations = []
    forwarded = []
    handoff = None

    def write_acceptance(_acceptance):
        handoff.collect_signal("INT")
        observations.append((handoff.state, handoff.forward_count))

    handoff = SignalHandoff(
        "nonce",
        identity_validator=lambda _value: True,
        acceptance_writer=write_acceptance,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.supervisor_accept(request)
    assert observations == [("PENDING_FORWARD", 0)]
    assert forwarded == [(identity.pgid, "INT")]


def test_signal_before_ready_is_latched_without_progress_or_forward(identity):
    forwarded = []
    handoff = SignalHandoff(
        "nonce",
        identity_validator=lambda _value: True,
        acceptance_writer=lambda _value: None,
        forwarder=lambda *args: forwarded.append(args),
    )
    handoff.collect_signal("TERM")
    assert handoff.state == "PENDING_FORWARD"
    request = _ready(handoff, identity)
    assert handoff.state == "PENDING_FORWARD"
    assert (
        handoff.acceptance_count == handoff.forward_count == handoff.unblock_count == 0
    )
    handoff.supervisor_accept(request)
    assert forwarded == [(identity.pgid, "TERM")]


def test_first_signal_is_latched_and_forwarded_once_after_identity_revalidation(
    identity,
):
    validations = []
    forwarded = []

    def validate(value):
        validations.append(value)
        return value == identity

    handoff = SignalHandoff(
        "nonce",
        identity_validator=validate,
        acceptance_writer=lambda _value: None,
        forwarder=lambda *args: forwarded.append(args),
    )
    request = _ready(handoff, identity)
    handoff.collect_signal("HUP")
    handoff.collect_signal("TERM")
    acceptance = handoff.supervisor_accept(request)
    handoff.collect_signal("INT")
    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked({"HUP", "INT", "TERM"})
    assert handoff.pending_signal == "HUP"
    assert forwarded == [(identity.pgid, "HUP")]
    assert len(validations) == 2  # request acceptance and immediately before forward


def test_signal_after_ready_forwards_immediately_once(harness, identity):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    acceptance = handoff.supervisor_accept(request)
    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked({"HUP", "INT", "TERM"})
    handoff.collect_signal("TERM")
    handoff.collect_signal("TERM")
    assert forwarded == [(identity.pgid, "TERM")]


def test_concurrent_signal_and_acceptance_have_deterministic_bounded_counts(
    harness, identity
):
    handoff, forwarded, _written = harness
    request = _ready(handoff, identity)
    with ThreadPoolExecutor(max_workers=2) as executor:
        signal_future = executor.submit(handoff.collect_signal, "INT")
        accept_future = executor.submit(handoff.supervisor_accept, request)
        signal_future.result()
        acceptance = accept_future.result()
    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked({"HUP", "INT", "TERM"})
    assert handoff.acceptance_count == handoff.forward_count == 1
    assert forwarded == [(identity.pgid, "INT")]


def test_not_applicable_and_fail_closed_transitions(identity):
    handoff = SignalHandoff.not_applicable("nonce")
    assert handoff.terminal_state == "NOT_APPLICABLE"
    assert handoff.acceptance_count == handoff.forward_count == 0
    with pytest.raises(SignalHandoffError):
        _ready(handoff, identity)

    handoff = SignalHandoff("nonce", identity_validator=lambda _value: True)
    with pytest.raises(SignalHandoffError):
        handoff.record_functional_progress()
    assert handoff.terminal_state == "FAILED"
