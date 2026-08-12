"""Task 8 traced coordinator ordering and isolation contracts."""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import threading

import pytest

import holoagent0_setup.coordinator as coordinator_module
from holoagent0_setup.constants import OFFLINE_GATE_ORDER
from holoagent0_setup.contract import ContractSet
from holoagent0_setup.cyclone_policy import CONFIG_ROLES, EXPECTED_CONFIG_SHA256
from holoagent0_setup.atomic_io import canonical_json_bytes
from holoagent0_setup.broker import (
    BrokerProtocolError,
    MessageType,
    read_frame,
    write_frame,
)
from holoagent0_setup.coordinator import (
    ActionChildReport,
    CoordinatorCleanupHandlers,
    CoordinatorLedgerAdapter,
    CoordinatorEnvironment,
    CoordinatorError,
    CoordinatorInterrupted,
    DDSMarkerHandle,
    HostObservation,
    HostObservationArtifactSink,
    HostObservationOutcome,
    HostObservationWriterAdapter,
    HandoffMarkerEmission,
    LinuxDDSMarker,
    LinuxHandoffMarker,
    LinuxHostInspectionRuntime,
    LinuxHostObserver,
    LinuxMotionPreflightScanner,
    LinuxNamespaceAuthority,
    LoopbackNamespaceProof,
    MotionPreflight,
    ParticipantRegistration,
    ParticipantRegistrationRelay,
    SemanticFixtureOutcome,
    TrustedHostInspection,
    Task4SignalBarrier,
    Task3LedgerClient,
    Task4OwnershipClient,
    TracedCoordinator,
)
from holoagent0_setup.ledger import LedgerCandidate, LedgerStore
from holoagent0_setup.evidence import AppendOnlyJournal, write_host_observer_artifact
from holoagent0_setup.process_identity import ProcessIdentity
from holoagent0_setup.signal_handoff import (
    CoordinatorSignalHandoff,
    SignalObservation,
    SupervisorSignalHandoff,
)
from holoagent0_setup.supervisor import (
    OwnedProcessController,
    SupervisorError,
    SupervisorLedgerBroker,
    SupervisorOwnershipBroker,
)


PACKAGE_ROOT = Path(__file__).parents[1]
NONCE = "a" * 64


class _OwnershipProcessOperations:
    """Identity-stable pidfd adapter for ownership broker protocol tests."""

    def open_pidfd(self, identity):
        return identity.pid + 10_000

    def identity_matches(self, _identity):
        return True

    def group_identity_matches(self, _identity):
        return True

    def is_alive(self, _pidfd):
        return True

    def send_signal(self, *_args):
        return None

    def send_group_signal(self, *_args):
        return None

    def send_retained_group_signal(self, *_args):
        return None

    def wait_dead(self, *_args):
        return False

    def wait_group_gone(self, *_args):
        return False

    def reap(self, *_args):
        return False

    def prove_owned_absent(self, *_args):
        return False

    def close_pidfd(self, _pidfd):
        return None


def _ownership_controller():
    return OwnedProcessController(_OwnershipProcessOperations())


class FakeBarrier:
    def __init__(self, events, *, accepted=True):
        self.events = events
        self.accepted = accepted
        self.functional_count = 0

    def emit_readiness_begin(self):
        self.events.append("readiness_begin")
        return HandoffMarkerEmission("READINESS_BEGIN", NONCE[:12], _identity())

    def complete_two_way_acceptance(self):
        self.events.append("signal_ready")
        if not self.accepted:
            raise CoordinatorError("SIGNAL_READY_ACCEPTED was not validated")
        self.events.append("signal_ready_accepted")

    def record_functional_progress(self):
        if not self.accepted:
            raise AssertionError("functional progress escaped failed barrier")
        self.functional_count += 1
        self.events.append("functional_progress")

    def emit_functional_begin(self):
        self.events.append("functional_begin")
        return HandoffMarkerEmission("FUNCTIONAL_BEGIN", NONCE[:12], _identity())

    def restore_handoff_marker(self):
        return None


class FakeLedger:
    def __init__(self, events):
        self.events = events
        self.sealed = False

    def pass_preflight(self):
        self.events.append("gate3_pass")

    def open_dds_window(self):
        self.events.append("dds_open")

    def accept_host_preexisting(self, observation):
        observation.validate()
        if observation.preexisting_openclaw:
            self.events.append("gate4_fail")
            raise CoordinatorError("pre-existing OpenClaw state was observed")
        self.events.append("gate4_pass")

    def close_dds_window(self):
        self.events.append("dds_closed")

    def accept_action_gates(self, gates):
        self.events.append("action_gates")

    def finalize_postflight(self, *, inner, host_pre, host_post):
        self.events.append("gate24_pass")

    def seal(self):
        self.events.append("ledger_seal")
        self.sealed = True

    def finalize_failure(self, *, cleanup_complete):
        self.events.append(("failure_finalize", cleanup_complete))
        self.sealed = True

    def finalize_interruption(self):
        self.events.append("interruption_suffix")
        self.events.append("gate24_pass")


class FakeObserver:
    def __init__(self, events):
        self.events = events
        self.outcomes = {}

    def capture(self, phase):
        self.events.append(f"host_{phase}")
        observation = _host_observation(phase=phase)
        self.outcomes[phase] = HostObservationOutcome.observed(observation)
        return observation

    def validate_capture(self, observation):
        observation.validate()

    def close(self):
        pass

    def set_not_run(self, *, cause_gate, reason):
        for phase in ("pre", "post"):
            if (
                self.outcomes.get(phase, None) is None
                or self.outcomes[phase].state != "OBSERVED"
            ):
                self.outcomes[phase] = HostObservationOutcome.not_run(
                    phase=phase, cause_gate=cause_gate, reason=reason
                )


class FakeHostObservationWriter:
    def __init__(self, events):
        self.events = events
        self.outcomes = []

    def persist(self, outcome):
        outcome.validate()
        self.events.append(f"host_{outcome.phase}_persisted")
        self.outcomes.append(outcome)
        return (outcome.phase, len(self.outcomes))

    @property
    def receipts(self):
        if [outcome.phase for outcome in self.outcomes] != ["pre", "post"]:
            raise CoordinatorError("host observation receipts are incomplete")
        return ("pre", 1), ("post", 2)

    @property
    def persisted_phases(self):
        return frozenset(outcome.phase for outcome in self.outcomes)


class FakeHostInspectionRuntime:
    def __init__(self, inspection=None):
        self.inspection = inspection or _trusted_inspection()

    def inspect(self):
        return self.inspection


class FakePreflightScanner:
    def __init__(self, observation=None):
        self.observation = observation or MotionPreflight.clean()

    def scan(self):
        return self.observation


class FakeDDSMarker:
    def __init__(self, events):
        self.events = events

    def begin(self):
        self.events.append("marker_begin")
        return DDSMarkerHandle(original_name="coordinator", begin_name="H0B" + "a" * 12)

    def end(self, handle):
        assert type(handle) is DDSMarkerHandle
        self.events.append("marker_end")


class FailingEndMarker(FakeDDSMarker):
    def end(self, handle):
        super().end(handle)
        raise CoordinatorError("injected END failure")


class FakeOwnershipJournal:
    def __init__(self, events):
        self.events = events
        self.records = []

    def append_identity(self, identity):
        self.events.append("ownership_record")
        self.records.append(identity)

    def append_participant(self, identity, **binding):
        self.records.append((identity, binding))
        return {"type": "PARTICIPANT_ACCEPTED"}


class FakeCleanupRuntime:
    def __init__(
        self,
        events,
        *,
        cleanup_complete=True,
        cleanup_error=None,
        absence_complete=True,
    ):
        self.events = events
        self.cleanup_complete = cleanup_complete
        self.cleanup_error = cleanup_error
        self.absence_complete = absence_complete
        self.cleaned = []
        self.restore_count = 0

    def install(self):
        self.events.append("cleanup_handlers")

    def acquire(self, identity):
        self.events.append("lease_acquire")
        return FakeOwnedLease(identity)

    def exec_after_ownership_ack(self, lease, ownership_client, exec_action):
        self.events.append("lease_authorize")
        ownership_client.append_identity(lease.identity)
        return exec_action()

    def cleanup(self, identities):
        self.cleaned.append(tuple(identities))
        self.events.append("owned_cleanup")
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return self.cleanup_complete

    def verify_absent(self, identities):
        self.cleaned.append(tuple(identities))
        self.events.append("owned_absence_verified")
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return self.absence_complete

    def restore(self):
        self.restore_count += 1


class FakeActionChild:
    def __init__(self, events, report):
        self.events = events
        self.report = report

    def prepare_ownership(self):
        self.events.append("child_prepare")
        return (
            ProcessIdentity(
                pid=201,
                pgid=201,
                start_time=10,
                executable_path="/bin/child",
                executable_sha256="a" * 64,
            ),
        )

    def run(self, environment, semantic_window, participant_relay):
        self.events.append("child_before_semantic")

        def semantic_action():
            for index in range(4):
                participant_relay.register(
                    ParticipantRegistration(
                        replace(
                            _identity(),
                            pid=300 + index,
                            pgid=300 + index,
                            start_time=20 + index,
                        ),
                        index,
                        CONFIG_ROLES[index],
                        EXPECTED_CONFIG_SHA256[index],
                    )
                )
            self.events.append("child_semantic")
            return self.report.semantic_fixture

        observed = semantic_window(semantic_action)
        assert observed == self.report.semantic_fixture
        self.events.append("child_after_semantic")
        return self.report


class FakeNamespaceAuthority:
    def __init__(self, proof):
        self.proof = proof
        self.aborted = []

    def begin(self, identity, *, host_inode):
        assert identity == _identity()
        assert host_inode == 123
        return identity

    def finish(self, handle):
        assert handle == _identity()
        return self.proof

    def abort(self, handle):
        self.aborted.append(handle)


def _environment(**changes):
    values = {
        "START_G1_PUBVEL": "0",
        "G1_DRY_RUN": "1",
        "ALLOW_G1_MOTION": "0",
        "ROS_DOMAIN_ID": "77",
        "ROS_LOCALHOST_ONLY": "1",
        "ROS2CLI_DISABLE_DAEMON": "1",
        "RMW_IMPLEMENTATION": "rmw_cyclonedds_cpp",
    }
    values.update(changes)
    return CoordinatorEnvironment.from_mapping(values)


def _report(*, proof=None):
    semantic_fixture = SemanticFixtureOutcome(
        gate={"id": "semantic.fixture_query"},
        cleanup_complete=True,
        participant_count=0,
        socket_count=0,
    )
    return ActionChildReport(
        gates=tuple({"id": gate_id} for gate_id in OFFLINE_GATE_ORDER[4:23]),
        semantic_fixture=semantic_fixture,
        namespace_proof=proof or LoopbackNamespaceProof.valid_fixture(),
        cleanup_complete=True,
        participant_count=0,
        socket_count=0,
        owned_identity=_identity(),
    )


def _coordinator(events, *, barrier=None, report=None, cleanup=None):
    action_report = report or _report()
    return TracedCoordinator(
        signal_barrier=barrier or FakeBarrier(events),
        ledger=FakeLedger(events),
        host_observer=FakeObserver(events),
        host_observation_writer=FakeHostObservationWriter(events),
        action_child=FakeActionChild(events, action_report),
        ownership_journal=FakeOwnershipJournal(events),
        environment=_environment(),
        motion_preflight_scanner=FakePreflightScanner(),
        cleanup_runtime=cleanup or FakeCleanupRuntime(events),
        namespace_authority=FakeNamespaceAuthority(action_report.namespace_proof),
        dds_marker=FakeDDSMarker(events),
    )


def test_two_way_signal_barrier_precedes_every_functional_operation():
    events = []
    coordinator = _coordinator(events)
    result = coordinator.execute()
    assert events == [
        "readiness_begin",
        "cleanup_handlers",
        "signal_ready",
        "signal_ready_accepted",
        "functional_begin",
        "functional_progress",
        "gate3_pass",
        "host_pre",
        "host_pre_persisted",
        "gate4_pass",
        "child_prepare",
        "lease_acquire",
        "lease_authorize",
        "ownership_record",
        "child_before_semantic",
        "dds_open",
        "marker_begin",
        "child_semantic",
        "marker_end",
        "dds_closed",
        "child_after_semantic",
        "owned_absence_verified",
        "action_gates",
        "host_post",
        "host_post_persisted",
        "gate24_pass",
        "ledger_seal",
    ]
    assert result.sealed
    assert result.postflight_passed


def test_canonical_json_codec_prewarm_is_exact_and_precedes_handler_anchor(
    monkeypatch,
):
    events = []
    original = coordinator_module.canonical_json_bytes
    original_broker_prewarm = coordinator_module.prewarm_broker_codec

    def observed_encoder(value):
        if value == {"signals": ["HUP", "INT", "TERM"], "state": "READY"}:
            events.append("canonical_json_prewarm")
        return original(value)

    monkeypatch.setattr(coordinator_module, "canonical_json_bytes", observed_encoder)
    monkeypatch.setattr(
        coordinator_module,
        "prewarm_broker_codec",
        lambda: (events.append("broker_codec_prewarm"), original_broker_prewarm())[1],
    )
    coordinator = _coordinator(events)
    coordinator.cleanup_runtime.install = lambda: events.append("cleanup_install")

    coordinator.execute()

    assert events[:5] == [
        "canonical_json_prewarm",
        "broker_codec_prewarm",
        "readiness_begin",
        "cleanup_install",
        "signal_ready",
    ]


def test_canonical_json_codec_prewarm_failure_stops_before_cleanup_install(
    monkeypatch,
):
    events = []
    coordinator = _coordinator(events)
    coordinator.cleanup_runtime.install = lambda: events.append("cleanup_install")
    monkeypatch.setattr(
        coordinator_module,
        "canonical_json_bytes",
        lambda _value: b'{"state":"WRONG"}',
    )

    with pytest.raises(CoordinatorError, match="canonical JSON prewarm"):
        coordinator.execute()

    assert "cleanup_install" not in events
    assert "signal_ready" not in events


def test_action_child_gate_authority_excludes_host_owned_gate_four():
    report = _report()
    assert tuple(gate["id"] for gate in report.gates) == OFFLINE_GATE_ORDER[4:23]

    stolen = replace(
        report,
        gates=tuple({"id": gate_id} for gate_id in OFFLINE_GATE_ORDER[3:23]),
    )
    with pytest.raises(CoordinatorError, match="action-child gate order"):
        stolen.validate()


def test_semantic_dds_window_covers_only_semantic_fixture_callback():
    events = []
    _coordinator(events).execute()
    assert events.index("child_before_semantic") < events.index("dds_open")
    assert events.index("marker_begin") < events.index("child_semantic")
    assert events.index("child_semantic") < events.index("marker_end")
    assert events.index("dds_closed") < events.index("child_after_semantic")


def test_host_observations_are_persisted_before_their_gate_transitions():
    events = []
    coordinator = _coordinator(events)
    coordinator.execute()
    assert events.index("host_pre_persisted") < events.index("gate4_pass")
    assert events.index("host_post_persisted") < events.index("gate24_pass")
    assert [item.phase for item in coordinator.host_observation_writer.outcomes] == [
        "pre",
        "post",
    ]


def test_clean_interruption_commits_two_host_observer_receipts_even_before_pre():
    events = []
    coordinator = _coordinator(events)
    coordinator.motion_preflight_scanner.scan = lambda: (_ for _ in ()).throw(
        CoordinatorInterrupted("coordinator interrupted by TERM")
    )

    coordinator.execute()

    assert [item.state for item in coordinator.host_observation_writer.outcomes] == [
        "NOT_RUN",
        "NOT_RUN",
    ]
    assert coordinator.host_observation_writer.receipts == (
        ("pre", 1),
        ("post", 2),
    )


def test_failure_before_host_pre_commits_closed_not_run_observer_artifacts():
    events = []
    coordinator = _coordinator(events)
    coordinator.environment = _environment(START_G1_PUBVEL="1")

    with pytest.raises(CoordinatorError, match="environment"):
        coordinator.execute()

    assert [item.phase for item in coordinator.host_observation_writer.outcomes] == [
        "pre",
        "post",
    ]
    assert all(
        item.state == "NOT_RUN" for item in coordinator.host_observation_writer.outcomes
    )


def test_preexisting_openclaw_is_host_owned_gate_four_and_blocks_child():
    events = []
    coordinator = _coordinator(events)
    active = _host_observation(
        phase="pre", service_inventory=("202:20:EXEC:" + "b" * 64,)
    )
    coordinator.host_observer.capture = lambda _phase: active

    with pytest.raises(CoordinatorError, match="pre-existing OpenClaw"):
        coordinator.execute()

    assert "gate4_fail" in events
    assert "child_prepare" not in events
    assert events.index("host_pre_persisted") < events.index("gate4_fail")


def test_openclaw_appearing_during_action_fails_postflight_after_persistence():
    events = []
    coordinator = _coordinator(events)
    observations = iter(
        (
            _host_observation(phase="pre"),
            _host_observation(
                phase="post", service_inventory=("202:20:EXEC:" + "b" * 64,)
            ),
        )
    )
    coordinator.host_observer.capture = lambda _phase: next(observations)

    with pytest.raises(CoordinatorError, match="OpenClaw appeared"):
        coordinator.execute()

    assert events.index("host_post_persisted") < events.index(
        ("failure_finalize", True)
    )
    assert "gate24_pass" not in events


def test_host_observation_writer_adapter_rejects_untrusted_sink_and_persists():
    class Receipt:
        def __init__(self, phase):
            self.relative_path = f"host_observer_{phase}.json"
            self.closed = False

        def close(self):
            self.closed = True

    class Sink:
        def __init__(self):
            self.items = []
            self.receipts = []

        def write_host_observer_artifact(self, outcome):
            self.items.append(outcome)
            receipt = Receipt(outcome.phase)
            self.receipts.append(receipt)
            return receipt

    with pytest.raises(CoordinatorError, match="writer"):
        HostObservationWriterAdapter(object())
    sink = Sink()
    writer = HostObservationWriterAdapter(sink)
    outcome = HostObservationOutcome.observed(_host_observation(phase="pre"))
    writer.persist(outcome)
    assert sink.items == [outcome]
    assert sink.receipts[0].closed is True


def test_host_artifact_sink_maps_trusted_inspection_and_returns_real_receipts(
    tmp_path,
):
    sink = HostObservationArtifactSink(
        run_root=tmp_path,
        artifact_writer=write_host_observer_artifact,
    )
    writer = HostObservationWriterAdapter(sink)
    pre = HostObservationOutcome.observed(_host_observation(phase="pre"))
    post = HostObservationOutcome.observed(_host_observation(phase="post"))

    writer.persist(pre)
    writer.persist(post)

    value = json.loads((tmp_path / "host_observer_pre.json").read_text())
    assert value["trusted_inspection"] == {
        "gateway_status_command": list(
            pre.observation.inspection.gateway_status_command
        ),
        "gateway_status_exit": 0,
        "gateway_status_sha256": pre.observation.inspection.gateway_status_sha256,
        "gateway_status_state": "INACTIVE",
        "service_definitions": [],
        "listener_command": list(pre.observation.inspection.listener_command),
        "listener_inventory": [],
    }
    assert writer.persisted_phases == frozenset({"pre", "post"})


def test_rejected_acceptance_causes_zero_unblock_and_zero_progression():
    events = []
    barrier = FakeBarrier(events, accepted=False)
    coordinator = _coordinator(events, barrier=barrier)
    with pytest.raises(CoordinatorError, match="SIGNAL_READY_ACCEPTED"):
        coordinator.execute()
    assert events == [
        "readiness_begin",
        "cleanup_handlers",
        "signal_ready",
        "host_pre_persisted",
        "host_post_persisted",
        ("failure_finalize", True),
    ]
    assert barrier.functional_count == 0


@pytest.mark.parametrize(
    "key,value",
    [
        ("START_G1_PUBVEL", "1"),
        ("G1_DRY_RUN", "0"),
        ("ALLOW_G1_MOTION", "1"),
        ("ROS_DOMAIN_ID", "0"),
        ("ROS_LOCALHOST_ONLY", "0"),
        ("ROS2CLI_DISABLE_DAEMON", "0"),
        ("RMW_IMPLEMENTATION", "rmw_fastrtps_cpp"),
    ],
)
def test_environment_posture_fails_closed_after_authorized_functional_boundary(
    key, value
):
    events = []
    coordinator = _coordinator(events)
    coordinator.environment = _environment(**{key: value})
    with pytest.raises(CoordinatorError, match="environment"):
        coordinator.execute()
    assert events == [
        "readiness_begin",
        "cleanup_handlers",
        "signal_ready",
        "signal_ready_accepted",
        "functional_begin",
        "functional_progress",
        "host_pre_persisted",
        "host_post_persisted",
        ("failure_finalize", True),
    ]


@pytest.mark.parametrize(
    "name", ["g1_pubvel_node", "g1_pubmove_node", "g1_pubcmd_node"]
)
def test_motion_executable_is_rejected_before_signal_handoff(name):
    events = []
    coordinator = _coordinator(events)
    coordinator.motion_preflight_scanner = FakePreflightScanner(
        MotionPreflight(
            observed_processes=(name,), ros_participants=(), physical_endpoints=()
        )
    )
    with pytest.raises(CoordinatorError, match="control process"):
        coordinator.execute()
    assert events == [
        "readiness_begin",
        "cleanup_handlers",
        "signal_ready",
        "signal_ready_accepted",
        "functional_begin",
        "functional_progress",
        "host_pre_persisted",
        "host_post_persisted",
        ("failure_finalize", True),
    ]


def test_coordinator_rejects_motion_preflight_self_assertion():
    events = []
    with pytest.raises(CoordinatorError, match="scanner"):
        coordinator = _coordinator(events)
        coordinator.motion_preflight_scanner = MotionPreflight.clean()
        coordinator.execute()


def test_dds_window_never_authorizes_action_before_open_and_begin():
    events = []
    _coordinator(events).execute()
    assert events.index("dds_open") < events.index("marker_begin")
    assert events.index("marker_begin") < events.index("child_semantic")
    assert events.index("child_semantic") < events.index("marker_end")
    assert events.index("marker_end") < events.index("dds_closed")
    assert events.index("dds_closed") < events.index("child_after_semantic")
    assert events.index("child_after_semantic") < events.index("owned_absence_verified")
    assert events.index("dds_closed") < events.index("ledger_seal")


def test_dependency_failure_after_begin_still_ends_and_closes_dds_window():
    events = []
    coordinator = _coordinator(events)
    coordinator.action_child.run = lambda _environment, semantic_window, _relay: (
        semantic_window(lambda: (_ for _ in ()).throw(RuntimeError("child exploded")))
    )

    with pytest.raises(CoordinatorError, match="dependency failed closed"):
        coordinator.execute()

    assert events.index("owned_cleanup") < events.index("marker_end")
    assert events.index("marker_end") < events.index("dds_closed")
    assert events.index("dds_closed") < events.index(("failure_finalize", True))


def test_failed_end_is_not_retried_and_cannot_close_or_seal():
    events = []
    coordinator = _coordinator(events)
    coordinator.dds_marker = FailingEndMarker(events)

    with pytest.raises(CoordinatorError, match="finalization was incomplete"):
        coordinator.execute()

    assert events.count("marker_end") == 1
    assert "dds_closed" not in events
    assert "ledger_seal" not in events


def test_failed_begin_cannot_publish_closed_without_an_end_marker():
    events = []
    coordinator = _coordinator(events)
    coordinator.dds_marker.begin = lambda: (_ for _ in ()).throw(
        CoordinatorError("BEGIN failed")
    )

    with pytest.raises(CoordinatorError, match="finalization was incomplete"):
        coordinator.execute()

    assert "child_semantic" not in events
    assert "marker_end" not in events
    assert "dds_closed" not in events


def test_clean_interruption_closes_window_and_seals_nonfailure_postflight():
    events = []
    coordinator = _coordinator(events)
    coordinator.action_child.run = lambda _environment, semantic_window, _relay: (
        semantic_window(
            lambda: (_ for _ in ()).throw(
                CoordinatorInterrupted("coordinator interrupted by TERM")
            )
        )
    )

    result = coordinator.execute()

    assert result.interrupted_signal == "TERM"
    assert result.postflight_passed is True
    assert events.index("owned_cleanup") < events.index("marker_end")
    assert events.index("marker_end") < events.index("dds_closed")
    assert events.index("dds_closed") < events.index("interruption_suffix")
    assert "gate24_pass" in events
    assert not any(
        isinstance(event, tuple) and event[0] == "failure_finalize" for event in events
    )


@pytest.mark.parametrize(
    "phase",
    ("before_gate3", "before_host_pre", "after_host_pre", "during_action"),
)
def test_clean_interruption_preserves_interrupted_result_at_each_phase(phase):
    events = []
    coordinator = _coordinator(events)
    if phase == "before_gate3":
        coordinator.ledger.pass_preflight = lambda: (_ for _ in ()).throw(
            CoordinatorInterrupted("coordinator interrupted by INT")
        )
    elif phase == "before_host_pre":
        coordinator.host_observer.capture = lambda _phase: (_ for _ in ()).throw(
            CoordinatorInterrupted("coordinator interrupted by INT")
        )
    elif phase == "after_host_pre":
        original_prepare = coordinator.action_child.prepare_ownership

        def interrupt_after_pre():
            original_prepare()
            raise CoordinatorInterrupted("coordinator interrupted by INT")

        coordinator.action_child.prepare_ownership = interrupt_after_pre
    else:
        coordinator.action_child.run = lambda _environment, _semantic_window, _relay: (
            _ for _ in ()
        ).throw(CoordinatorInterrupted("coordinator interrupted by INT"))

    result = coordinator.execute()

    assert result.sealed is True
    assert result.postflight_passed is True
    assert result.interrupted_signal == "INT"
    assert coordinator.host_observation_writer.receipts == (
        ("pre", 1),
        ("post", 2),
    )
    assert "interruption_suffix" in events
    assert ("failure_finalize", True) not in events
    if phase in {"before_gate3", "before_host_pre"}:
        assert coordinator.host_observer.outcomes["pre"].state == "NOT_RUN"
        assert coordinator.host_observer.outcomes["post"].state == "NOT_RUN"
    else:
        assert coordinator.host_observer.outcomes["pre"].state == "OBSERVED"
        assert coordinator.host_observer.outcomes["post"].state == "OBSERVED"


class FakePrctlOperations:
    def __init__(self, events, *, pid=42, name="coordinator"):
        self.events = events
        self.pid = pid
        self.name = name

    def current_pid(self):
        return self.pid

    def get_name(self):
        self.events.append(("get_name", self.name))
        return self.name

    def set_name(self, value):
        self.events.append(("set_name", value))
        self.name = value


class CorruptBeginReadbackOperations(FakePrctlOperations):
    def __init__(self, events):
        super().__init__(events)
        self.corrupt_next_read = False

    def get_name(self):
        if self.corrupt_next_read:
            self.corrupt_next_read = False
            self.events.append(("get_name", "corrupt"))
            return "corrupt"
        return super().get_name()

    def set_name(self, value):
        super().set_name(value)
        if value.startswith("H0B"):
            self.corrupt_next_read = True


class CorruptEndReadbackOperations(FakePrctlOperations):
    def __init__(self, events):
        super().__init__(events)
        self.corrupt_next_read = False

    def get_name(self):
        if self.corrupt_next_read:
            self.corrupt_next_read = False
            self.events.append(("get_name", "corrupt"))
            return "corrupt"
        return super().get_name()

    def set_name(self, value):
        super().set_name(value)
        if value.startswith("H0E"):
            self.corrupt_next_read = True


class InterruptingPrctlOperations(FakePrctlOperations):
    def __init__(self, events, *, interrupt_prefix):
        super().__init__(events)
        self.interrupt_prefix = interrupt_prefix
        self.interrupted = False

    def set_name(self, value):
        super().set_name(value)
        if not self.interrupted and value.startswith(self.interrupt_prefix):
            self.interrupted = True
            raise CoordinatorInterrupted("coordinator interrupted by TERM")


def test_linux_handoff_marker_emits_bound_phases_and_restores_reviewed_name():
    events = []
    operations = FakePrctlOperations(events)
    identity = replace(_identity(), pid=42)
    validations = []
    marker = LinuxHandoffMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: (
            validations.append(observed) is None or observed == identity
        ),
        operations=operations,
    )

    marker.emit_readiness_begin()
    marker.emit_functional_begin()

    assert operations.name == "coordinator"
    assert [event for event in events if event[0] == "set_name"] == [
        ("set_name", "H0R" + "a" * 12),
        ("set_name", "H0F" + "a" * 12),
        ("set_name", "coordinator"),
    ]
    assert validations == [identity]


def test_linux_handoff_marker_rejects_reorder_duplicate_and_identity_spoof():
    identity = replace(_identity(), pid=42)
    marker = LinuxHandoffMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=FakePrctlOperations([]),
    )
    with pytest.raises(CoordinatorError, match="out of order"):
        marker.emit_functional_begin()
    marker.emit_readiness_begin()
    with pytest.raises(CoordinatorError, match="out of order"):
        marker.emit_readiness_begin()

    spoofed = LinuxHandoffMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda _observed: False,
        operations=FakePrctlOperations([]),
    )
    with pytest.raises(CoordinatorError, match="identity"):
        spoofed.emit_readiness_begin()


def test_linux_handoff_marker_restores_without_false_functional_marker_on_failure():
    events = []
    operations = FakePrctlOperations(events)
    identity = replace(_identity(), pid=42)
    marker = LinuxHandoffMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    marker.emit_readiness_begin()
    marker.restore_after_failure()

    assert operations.name == "coordinator"
    assert [event for event in events if event[0] == "set_name"] == [
        ("set_name", "H0R" + "a" * 12),
        ("set_name", "coordinator"),
    ]
    assert not any(event == ("set_name", "H0F" + "a" * 12) for event in events)


def test_handoff_marker_restore_failure_overrides_success_fail_closed():
    events = []
    coordinator = _coordinator(events)
    coordinator.signal_barrier.restore_handoff_marker = lambda: (_ for _ in ()).throw(
        CoordinatorError("injected marker restore failure")
    )

    with pytest.raises(CoordinatorError, match="handoff marker restore failed"):
        coordinator.execute()

    assert "ledger_seal" in events


def test_linux_dds_marker_emits_exact_nonce_bound_names_and_restores():
    events = []
    operations = FakePrctlOperations(events)
    identity = replace(_identity(), pid=42)
    marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    handle = marker.begin()
    marker.end(handle)

    assert operations.name == "coordinator"
    assert [event for event in events if event[0] == "set_name"] == [
        ("set_name", "H0B" + "a" * 12),
        ("set_name", "H0E" + "a" * 12),
        ("set_name", "coordinator"),
    ]


def test_linux_dds_marker_restores_reviewed_name_when_begin_readback_fails():
    events = []
    operations = CorruptBeginReadbackOperations(events)
    identity = replace(_identity(), pid=42)
    marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    with pytest.raises(CoordinatorError, match="BEGIN"):
        marker.begin()

    assert operations.name == "coordinator"
    assert ("set_name", "coordinator") in events[-2:]


def test_linux_dds_marker_restores_reviewed_name_when_end_readback_fails():
    events = []
    operations = CorruptEndReadbackOperations(events)
    identity = replace(_identity(), pid=42)
    marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )
    handle = marker.begin()

    with pytest.raises(CoordinatorError, match="END"):
        marker.end(handle)

    assert operations.name == "coordinator"
    assert ("set_name", "coordinator") in events[-2:]


def test_linux_dds_marker_rejects_unreviewed_original_process_name():
    operations = FakePrctlOperations([], name="unexpected")
    identity = replace(_identity(), pid=42)
    marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    with pytest.raises(CoordinatorError, match="reviewed process name"):
        marker.begin()


@pytest.mark.parametrize("interrupt_prefix", ("H0B", "H0E"))
def test_linux_dds_marker_completes_end_and_restore_across_signal_race(
    interrupt_prefix,
):
    events = []
    operations = InterruptingPrctlOperations(events, interrupt_prefix=interrupt_prefix)
    identity = replace(_identity(), pid=42)
    marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    if interrupt_prefix == "H0B":
        with pytest.raises(CoordinatorInterrupted):
            marker.begin()
    else:
        handle = marker.begin()
        with pytest.raises(CoordinatorInterrupted):
            marker.end(handle)

    assert marker.begin_emitted is True
    assert marker.end_completed is True
    assert operations.name == "coordinator"
    assert [value for operation, value in events if operation == "set_name"] == [
        "H0B" + "a" * 12,
        "H0E" + "a" * 12,
        "coordinator",
    ]


def test_coordinator_closes_ledger_after_internal_begin_signal_race():
    events = []
    coordinator = _coordinator(events)
    operations = InterruptingPrctlOperations(events, interrupt_prefix="H0B")
    identity = replace(_identity(), pid=42)
    coordinator.dds_marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    result = coordinator.execute()

    assert result.interrupted_signal == "TERM"
    assert events.index("dds_open") < events.index("dds_closed")
    assert "child_run" not in events
    assert "ledger_seal" in events


def test_coordinator_closes_ledger_after_internal_end_signal_race():
    events = []
    coordinator = _coordinator(events)
    operations = InterruptingPrctlOperations(events, interrupt_prefix="H0E")
    identity = replace(_identity(), pid=42)
    coordinator.dds_marker = LinuxDDSMarker(
        NONCE,
        identity,
        reviewed_process_name="coordinator",
        identity_validator=lambda observed: observed == identity,
        operations=operations,
    )

    result = coordinator.execute()

    assert result.interrupted_signal == "TERM"
    assert events.index("child_semantic") < events.index("dds_closed")
    assert events.index("owned_cleanup") < events.index("dds_closed")
    assert "ledger_seal" in events


def test_host_observation_outcome_rejects_fabricated_not_run_cause():
    outcome = HostObservationOutcome.not_run(
        phase="post", cause_gate="semantic.fixture_query", reason="OK"
    )
    with pytest.raises(CoordinatorError, match="NOT_RUN"):
        outcome.validate()


def test_host_observation_outcome_accepts_only_closed_evidence_lane_shapes():
    observed = HostObservationOutcome.observed(_host_observation(phase="pre"))
    missing = HostObservationOutcome.not_run(
        phase="post",
        cause_gate="safety.workstation_postflight",
        reason="POSTFLIGHT_FAILED",
    )
    observed.validate()
    missing.validate()
    assert observed.observation is not None
    assert missing.observation is None


def test_linux_motion_preflight_scanner_reads_proc_and_trusted_inputs(tmp_path):
    proc_root = tmp_path / "proc"
    pid_root = proc_root / "12"
    pid_root.mkdir(parents=True)
    (pid_root / "comm").write_text("g1_pubvel_node\n", encoding="utf-8")
    (pid_root / "exe").symlink_to("/opt/unitree/g1_pubvel_node")
    scanner = LinuxMotionPreflightScanner(
        proc_root=proc_root,
        ros_participant_scanner=lambda: (),
        physical_endpoint_scanner=lambda: (),
    )

    with pytest.raises(CoordinatorError, match="control process"):
        scanner.scan()


def test_unexpected_ros_participant_or_physical_unitree_endpoint_is_rejected():
    with pytest.raises(CoordinatorError, match="ROS participant"):
        MotionPreflight(
            observed_processes=(), ros_participants=("/unknown",), physical_endpoints=()
        ).validate()
    with pytest.raises(CoordinatorError, match="physical Unitree"):
        MotionPreflight(
            observed_processes=(),
            ros_participants=(),
            physical_endpoints=("192.168.123.161:8082",),
        ).validate()


def test_ownership_identity_is_journaled_before_child_start():
    events = []
    coordinator = _coordinator(events)
    coordinator.execute()
    assert events.index("ownership_record") < events.index("child_before_semantic")
    assert len(coordinator.ownership_journal.records) == 5
    assert isinstance(coordinator.ownership_journal.records[0], ProcessIdentity)


@dataclass
class FakeOwnedLease:
    identity: ProcessIdentity
    consumed: bool = False


def test_success_uses_retained_lease_absence_verification_without_signaling():
    events = []
    cleanup = FakeCleanupRuntime(events)
    coordinator = _coordinator(events, cleanup=cleanup)

    coordinator.execute()

    assert events.index("lease_acquire") < events.index("ownership_record")
    assert events.index("lease_authorize") < events.index("child_before_semantic")
    assert events.count("owned_absence_verified") == 1
    assert "owned_cleanup" not in events


def test_live_child_rejected_by_absence_check_then_cleaned_through_same_lease():
    events = []
    cleanup = FakeCleanupRuntime(events, absence_complete=False)
    coordinator = _coordinator(events, cleanup=cleanup)

    with pytest.raises(CoordinatorError, match="absence"):
        coordinator.execute()

    assert events.index("owned_absence_verified") < events.index("owned_cleanup")
    assert cleanup.cleaned[0][0] is cleanup.cleaned[1][0]


def test_incomplete_ownership_identity_prevents_child_start():
    events = []
    coordinator = _coordinator(events)
    coordinator.action_child.prepare_ownership = lambda: (
        {"pid": 201, "pgid": 201, "start_time": 10},
    )

    with pytest.raises(CoordinatorError, match="ownership identity"):
        coordinator.execute()

    assert "child_run" not in events


@pytest.mark.parametrize(
    "proof",
    [
        LoopbackNamespaceProof(
            host_inode=123,
            before_inode=1,
            after_inode=2,
            interfaces=("lo",),
            addresses=("127.0.0.1/8",),
            routes=("local 127.0.0.0/8",),
        ),
        LoopbackNamespaceProof(
            host_inode=123,
            before_inode=1,
            after_inode=1,
            interfaces=("lo", "eth0"),
            addresses=("127.0.0.1/8",),
            routes=("local 127.0.0.0/8",),
        ),
        LoopbackNamespaceProof(
            host_inode=123,
            before_inode=1,
            after_inode=1,
            interfaces=("lo",),
            addresses=("127.0.0.1/8", "10.0.0.2/24"),
            routes=("local 127.0.0.0/8",),
        ),
    ],
)
def test_action_child_requires_stable_loopback_only_namespace(proof):
    events = []
    coordinator = _coordinator(events, report=_report(proof=proof))
    with pytest.raises(CoordinatorError, match="loopback|namespace"):
        coordinator.execute()
    assert "gate24_pass" not in events
    assert "ledger_seal" not in events


def test_child_cleanup_must_be_complete_before_post_observer_and_seal():
    events = []
    gates = _report().gates
    report = ActionChildReport(
        gates=gates,
        semantic_fixture=_report().semantic_fixture,
        namespace_proof=LoopbackNamespaceProof.valid_fixture(),
        cleanup_complete=False,
        participant_count=1,
        socket_count=1,
        owned_identity=_identity(),
    )
    coordinator = _coordinator(events, report=report)
    with pytest.raises(CoordinatorError, match="cleanup"):
        coordinator.execute()
    assert "host_post" not in events
    assert "ledger_seal" not in events
    assert events.index("owned_cleanup") < events.index(("failure_finalize", True))


def test_host_observer_rejects_internet_family_operations():
    observation = _host_observation(internet_socket_attempts=1)
    with pytest.raises(CoordinatorError, match="host-namespace internet"):
        observation.validate()


def test_host_namespace_must_remain_stable_across_action():
    events = []
    coordinator = _coordinator(events)
    observations = iter(
        (
            _host_observation(phase="pre"),
            _host_observation(network_namespace_inode=124, phase="post"),
        )
    )
    coordinator.host_observer.capture = lambda _phase: next(observations)

    with pytest.raises(CoordinatorError, match="host network namespace changed"):
        coordinator.execute()

    assert "ledger_seal" not in events


def test_dependency_failure_after_ownership_runs_cleanup_before_failure_seal():
    events = []
    cleanup = FakeCleanupRuntime(events)
    coordinator = _coordinator(events, cleanup=cleanup)

    def fail_after_ownership(_environment, _semantic_window):
        events.append("child_run_failed")
        raise RuntimeError("injected child failure")

    coordinator.action_child.run = fail_after_ownership
    with pytest.raises(CoordinatorError, match="dependency failed closed"):
        coordinator.execute()
    assert len(cleanup.cleaned) == 1
    assert events.index("owned_cleanup") < events.index(("failure_finalize", True))
    assert coordinator.ledger.sealed


def test_cleanup_failure_is_the_reported_coordinator_failure():
    events = []
    cleanup = FakeCleanupRuntime(events, cleanup_complete=False)
    report = ActionChildReport(
        gates=_report().gates,
        semantic_fixture=_report().semantic_fixture,
        namespace_proof=LoopbackNamespaceProof.valid_fixture(),
        cleanup_complete=False,
        participant_count=1,
        socket_count=1,
        owned_identity=_identity(),
    )
    coordinator = _coordinator(events, report=report, cleanup=cleanup)
    with pytest.raises(CoordinatorError, match="owned-child cleanup failed"):
        coordinator.execute()
    assert events.index("marker_end") < events.index("dds_closed")
    assert events.index("dds_closed") < events.index("owned_cleanup")
    assert coordinator.ledger.sealed


def test_cleanup_exception_still_seals_failed_postflight():
    events = []
    cleanup = FakeCleanupRuntime(events, cleanup_error=RuntimeError("cleanup exploded"))
    coordinator = _coordinator(events, cleanup=cleanup)
    coordinator.action_child.run = lambda _environment, _semantic_window, _relay: (
        _ for _ in ()
    ).throw(RuntimeError("child exploded"))

    with pytest.raises(CoordinatorError, match="owned-child cleanup failed"):
        coordinator.execute()

    assert "marker_end" not in events
    assert "dds_closed" not in events
    assert coordinator.ledger.sealed


def test_namespace_close_failure_does_not_skip_owned_child_cleanup():
    events = []
    cleanup = FakeCleanupRuntime(events)
    coordinator = _coordinator(events, cleanup=cleanup)
    coordinator.action_child.run = lambda _environment, _semantic_window, _relay: (
        _ for _ in ()
    ).throw(RuntimeError("child exploded"))
    coordinator.namespace_authority.abort = lambda _handle: (_ for _ in ()).throw(
        RuntimeError("namespace close exploded")
    )

    with pytest.raises(CoordinatorError, match="owned-child cleanup failed"):
        coordinator.execute()

    assert len(cleanup.cleaned) == 1
    assert ("failure_finalize", False) in events


def test_terminal_cleanup_handlers_are_not_restored_after_pass_or_failure():
    pass_events = []
    pass_cleanup = FakeCleanupRuntime(pass_events)
    _coordinator(pass_events, cleanup=pass_cleanup).execute()
    assert pass_cleanup.restore_count == 0

    fail_events = []
    fail_cleanup = FakeCleanupRuntime(fail_events)
    coordinator = _coordinator(fail_events, cleanup=fail_cleanup)
    coordinator.action_child.run = lambda _environment, _semantic_window, _relay: (
        _ for _ in ()
    ).throw(RuntimeError("child exploded"))
    with pytest.raises(CoordinatorError):
        coordinator.execute()
    assert fail_cleanup.restore_count == 0


def test_cleanup_handler_installs_while_blocked_and_records_reviewed_signal():
    reviewed = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
    handlers = CoordinatorCleanupHandlers(FakeCleanupRuntime([]))
    previous_handlers = {number: signal.getsignal(number) for number in reviewed}
    try:
        handlers.install()
        with pytest.raises(CoordinatorError, match="interrupted by TERM"):
            handlers._handle(signal.SIGTERM, None)
        assert handlers.first_signal == "TERM"
    finally:
        handlers.restore()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        assert all(
            signal.getsignal(number) == value
            for number, value in previous_handlers.items()
        )


def test_cleanup_handler_latches_first_signal_and_ignores_repeats_during_cleanup():
    reviewed = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
    handlers = CoordinatorCleanupHandlers(FakeCleanupRuntime([]))
    try:
        handlers.install()
        with pytest.raises(CoordinatorInterrupted, match="TERM"):
            handlers._handle(signal.SIGTERM, None)
        handlers._handle(signal.SIGINT, None)
        handlers._handle(signal.SIGHUP, None)
        assert handlers.first_signal == "TERM"
    finally:
        handlers.restore()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_repeated_signal_during_owned_cleanup_yields_one_interrupted_outcome():
    class Controller(FakeCleanupRuntime):
        def cleanup(self, leases):
            self.events.append("owned_cleanup_started")
            handlers._handle(signal.SIGINT, None)
            self.events.append("owned_cleanup_finished")
            return True

    reviewed = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
    events = []
    controller = Controller(events)
    handlers = CoordinatorCleanupHandlers(controller)
    coordinator = _coordinator(events, cleanup=handlers)
    coordinator.action_child.run = lambda _environment, _semantic_window, _relay: (
        handlers._handle(signal.SIGTERM, None)
    )
    try:
        result = coordinator.execute()
        assert result.interrupted_signal == "TERM"
        assert handlers.first_signal == "TERM"
        assert events.count("owned_cleanup_started") == 1
        assert events.count("owned_cleanup_finished") == 1
        assert events.count("interruption_suffix") == 1
    finally:
        handlers.restore()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_cleanup_handlers_retain_and_verify_owned_lease_without_signaling():
    reviewed = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, reviewed)
    runtime = FakeCleanupRuntime([])
    handlers = CoordinatorCleanupHandlers(runtime)
    try:
        handlers.install()
        lease = handlers.acquire(_identity())
        assert lease.identity == _identity()
        assert handlers.verify_absent((lease,)) is True
        assert runtime.events == ["lease_acquire", "owned_absence_verified"]
    finally:
        handlers.restore()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_empty_or_wrong_action_gate_set_is_rejected():
    empty = ActionChildReport(
        gates=(),
        semantic_fixture=_report().semantic_fixture,
        namespace_proof=LoopbackNamespaceProof.valid_fixture(),
        cleanup_complete=True,
        participant_count=0,
        socket_count=0,
        owned_identity=_identity(),
    )
    with pytest.raises(CoordinatorError, match="action-child gate order"):
        empty.validate()

    wrong = ActionChildReport(
        gates=({"id": OFFLINE_GATE_ORDER[4]},),
        semantic_fixture=_report().semantic_fixture,
        namespace_proof=LoopbackNamespaceProof.valid_fixture(),
        cleanup_complete=True,
        participant_count=0,
        socket_count=0,
        owned_identity=_identity(),
    )
    with pytest.raises(CoordinatorError, match="action-child gate order"):
        wrong.validate()


def test_action_namespace_must_be_distinct_from_observed_host_namespace():
    events = []
    proof = LoopbackNamespaceProof(
        host_inode=123,
        before_inode=123,
        after_inode=123,
        interfaces=("lo",),
        addresses=("127.0.0.1/8",),
        routes=("local 127.0.0.0/8",),
    )
    coordinator = _coordinator(events, report=_report(proof=proof))
    with pytest.raises(CoordinatorError, match="not isolated from host"):
        coordinator.execute()
    assert "gate24_pass" not in events


def _write_fake_loopback_proc(proc_root, identity):
    pid_root = proc_root / str(identity.pid)
    (pid_root / "ns").mkdir(parents=True)
    (pid_root / "net").mkdir()
    (pid_root / "ns" / "net").write_bytes(b"retained namespace identity")
    (pid_root / "net" / "dev").write_text(
        "Inter-| Receive | Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|bytes\n"
        "    lo: 0 0 0 0 0 0 0 0 0\n",
        encoding="ascii",
    )
    (pid_root / "net" / "route").write_text(
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n",
        encoding="ascii",
    )
    (pid_root / "net" / "fib_trie").write_text(
        "Main:\n  +-- 127.0.0.0/8\n     |-- 127.0.0.1\n        /32 host LOCAL\n",
        encoding="ascii",
    )
    (pid_root / "net" / "if_inet6").write_bytes(b"")
    return pid_root


def test_linux_namespace_authority_retains_and_revalidates_exact_loopback_proof(
    tmp_path,
):
    identity = _identity()
    pid_root = _write_fake_loopback_proc(tmp_path / "proc", identity)
    namespace_inode = os.stat(pid_root / "ns" / "net").st_ino
    authority = LinuxNamespaceAuthority(
        proc_root=tmp_path / "proc",
        identity_validator=lambda observed: observed == identity,
    )
    handle = authority.begin(identity, host_inode=namespace_inode + 1)
    assert os.get_inheritable(handle.fd) is False
    assert os.fstat(handle.fd).st_ino == namespace_inode

    proof = authority.finish(handle)

    assert proof == LoopbackNamespaceProof(
        before_inode=namespace_inode,
        after_inode=namespace_inode,
        interfaces=("lo",),
        addresses=("127.0.0.1/8",),
        routes=("local 127.0.0.0/8",),
        host_inode=namespace_inode + 1,
    )
    with pytest.raises(OSError):
        os.fstat(handle.fd)


def test_linux_namespace_authority_rejects_post_action_interface_change(tmp_path):
    identity = _identity()
    pid_root = _write_fake_loopback_proc(tmp_path / "proc", identity)
    namespace_inode = os.stat(pid_root / "ns" / "net").st_ino
    authority = LinuxNamespaceAuthority(
        proc_root=tmp_path / "proc", identity_validator=lambda _identity: True
    )
    handle = authority.begin(identity, host_inode=namespace_inode + 1)
    (pid_root / "net" / "dev").write_text(
        "Inter-| Receive | Transmit\n"
        " face |bytes packets errs drop fifo frame compressed multicast|bytes\n"
        "    lo: 0 0 0 0 0 0 0 0 0\n"
        "  eth0: 0 0 0 0 0 0 0 0 0\n",
        encoding="ascii",
    )

    with pytest.raises(CoordinatorError, match="loopback|changed"):
        authority.finish(handle)

    with pytest.raises(OSError):
        os.fstat(handle.fd)


def test_coordinator_rejects_child_namespace_claim_different_from_trusted_capture():
    events = []
    report = _report()
    coordinator = _coordinator(events, report=report)
    coordinator.namespace_authority.proof = LoopbackNamespaceProof(
        before_inode=2,
        after_inode=2,
        interfaces=("lo",),
        addresses=("127.0.0.1/8",),
        routes=("local 127.0.0.0/8",),
        host_inode=123,
    )

    with pytest.raises(CoordinatorError, match="trusted namespace capture"):
        coordinator.execute()

    assert "action_gates" not in events


def _write_fake_host_proc(proc_root, observer_identity):
    observer_root = _write_fake_loopback_proc(proc_root, observer_identity)
    self_link = proc_root / "self"
    if not self_link.exists() and not self_link.is_symlink():
        self_link.symlink_to(str(observer_identity.pid))
    stat_fields = ["S", "0", str(observer_identity.pgid), str(observer_identity.pid)]
    stat_fields.extend(["0"] * 15)
    stat_fields.append(str(observer_identity.start_time))
    (observer_root / "stat").write_text(
        f"{observer_identity.pid} (observer) " + " ".join(stat_fields) + "\n",
        encoding="ascii",
    )
    (observer_root / "exe").symlink_to(observer_identity.executable_path)
    (observer_root / "cmdline").write_bytes(b"observer\0--no-probe\0")
    (observer_root / "net" / "tcp").write_text(
        "  sl  local_address rem_address   st\n   0: 0100007F:76A5 00000000:0000 0A\n",
        encoding="ascii",
    )
    (observer_root / "net" / "tcp6").write_text(
        "  sl  local_address rem_address   st\n", encoding="ascii"
    )
    other = proc_root / "202"
    other.mkdir()
    other_fields = ["S", "0", "202", "202"] + ["0"] * 15 + ["20"]
    (other / "stat").write_text(
        "202 (openclaw) " + " ".join(other_fields) + "\n", encoding="ascii"
    )
    (other / "exe").symlink_to("/opt/openclaw/bin/openclaw")
    (other / "cmdline").write_bytes(b"openclaw\0gateway\0status\0--no-probe\0")
    kernel = proc_root / "203"
    kernel.mkdir()
    kernel_fields = ["S", "0", "203", "203"] + ["0"] * 15 + ["30"]
    (kernel / "stat").write_text(
        "203 (kworker/0:1) " + " ".join(kernel_fields) + "\n", encoding="ascii"
    )
    return observer_root


def test_linux_host_observer_binds_inventory_listener_and_namespace_evidence(
    tmp_path, monkeypatch
):
    identity = _identity()
    observer_root = _write_fake_host_proc(tmp_path / "proc", identity)
    monkeypatch.setattr(os, "getpid", lambda: identity.pid)
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root: self == identity,
    )
    observer = LinuxHostObserver(
        identity,
        proc_root=tmp_path / "proc",
        identity_validator=lambda observed: observed == identity,
        inspection_runtime=FakeHostInspectionRuntime(),
    )

    pre = observer.capture("pre")
    observer.validate_capture(pre)
    assert pre.process_count == 3
    assert pre.service_count == 1
    assert pre.listener_count == 0
    assert pre.network_namespace_inode == os.stat(observer_root / "ns" / "net").st_ino

    with pytest.raises(CoordinatorError, match="host observation authority"):
        observer.validate_capture(replace(pre, process_inventory=()))
    with pytest.raises(CoordinatorError, match="host observation authority"):
        observer.validate_capture(
            replace(pre, network_namespace_inode=pre.network_namespace_inode + 1)
        )
    with pytest.raises(CoordinatorError, match="host observation authority"):
        observer.validate_capture(
            replace(
                pre,
                observer_identity=ProcessIdentity(
                    pid=202,
                    pgid=202,
                    start_time=20,
                    executable_path="/opt/openclaw/bin/openclaw",
                    executable_sha256="b" * 64,
                ),
            )
        )

    post = observer.capture("post")
    observer.validate_capture(post)
    assert pre.process_inventory == post.process_inventory
    observer.close()


def test_linux_host_observer_rejects_pid_reuse_between_pre_and_post(
    tmp_path, monkeypatch
):
    identity = _identity()
    _write_fake_host_proc(tmp_path / "proc", identity)
    monkeypatch.setattr(os, "getpid", lambda: identity.pid)
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root: self == identity,
    )
    observer = LinuxHostObserver(
        identity,
        proc_root=tmp_path / "proc",
        identity_validator=lambda observed: observed == identity,
        inspection_runtime=FakeHostInspectionRuntime(),
    )
    observer.capture("pre")
    other = tmp_path / "proc" / "202" / "stat"
    reused_fields = ["S", "0", "202", "202"] + ["0"] * 15 + ["21"]
    other.write_text(
        "202 (openclaw) " + " ".join(reused_fields) + "\n", encoding="ascii"
    )

    with pytest.raises(CoordinatorError, match="PID reuse"):
        observer.capture("post")

    observer.close()


def test_linux_host_observer_rejects_pid_reuse_during_one_capture(
    tmp_path, monkeypatch
):
    identity = _identity()
    _write_fake_host_proc(tmp_path / "proc", identity)
    monkeypatch.setattr(os, "getpid", lambda: identity.pid)
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root: self == identity,
    )
    other_stat = tmp_path / "proc" / "202" / "stat"
    real_readlink = os.readlink

    def readlink_after_reuse(path):
        if Path(path) == tmp_path / "proc" / "202" / "exe":
            reused_fields = ["S", "0", "202", "202"] + ["0"] * 15 + ["21"]
            other_stat.write_text(
                "202 (openclaw) " + " ".join(reused_fields) + "\n",
                encoding="ascii",
            )
        return real_readlink(path)

    monkeypatch.setattr(os, "readlink", readlink_after_reuse)
    observer = LinuxHostObserver(
        identity,
        proc_root=tmp_path / "proc",
        identity_validator=lambda observed: observed == identity,
        inspection_runtime=FakeHostInspectionRuntime(),
    )

    with pytest.raises(CoordinatorError, match="identity changed"):
        observer.capture("pre")

    observer.close()


def test_linux_host_observer_represents_protected_executable_deterministically(
    tmp_path, monkeypatch
):
    identity = _identity()
    _write_fake_host_proc(tmp_path / "proc", identity)
    monkeypatch.setattr(os, "getpid", lambda: identity.pid)
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root: self == identity,
    )
    real_readlink = os.readlink

    def protected_readlink(path):
        if Path(path) == tmp_path / "proc" / "202" / "exe":
            raise PermissionError("protected by hidepid")
        return real_readlink(path)

    monkeypatch.setattr(os, "readlink", protected_readlink)
    observer = LinuxHostObserver(
        identity,
        proc_root=tmp_path / "proc",
        identity_validator=lambda observed: observed == identity,
        inspection_runtime=FakeHostInspectionRuntime(),
    )

    pre = observer.capture("pre")
    post = observer.capture("post")

    assert pre.process_inventory == post.process_inventory
    assert any(":UNREADABLE_EXE:" in entry for entry in pre.process_inventory)
    assert pre.service_count == 1
    observer.close()


def test_linux_host_inspection_runtime_uses_exact_no_probe_and_ss_commands(tmp_path):
    openclaw = tmp_path / "openclaw"
    ss = tmp_path / "ss"
    openclaw.write_bytes(b"openclaw")
    ss.write_bytes(b"ss")
    service_root = tmp_path / "services"
    service_root.mkdir()
    commands = []

    def runner(argv):
        commands.append(tuple(argv))
        if argv[0] == str(openclaw):
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=b'{"service":{"loaded":false},"gateway":{"running":false}}',
                stderr=b"",
            )
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    runtime = LinuxHostInspectionRuntime(
        openclaw_cli=openclaw,
        openclaw_cli_sha256=hashlib.sha256(openclaw.read_bytes()).hexdigest(),
        ss_executable=ss,
        ss_executable_sha256=hashlib.sha256(ss.read_bytes()).hexdigest(),
        service_roots=(service_root,),
        command_runner=runner,
    )
    inspection = runtime.inspect()

    assert commands == [
        (
            str(openclaw),
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        ),
        (str(ss), "-H", "-ltnp"),
    ]
    assert inspection.gateway_status_state == "INACTIVE"
    assert inspection.preexisting_openclaw is False


def test_linux_host_inspection_detects_service_or_matching_listener(tmp_path):
    openclaw = tmp_path / "openclaw"
    ss = tmp_path / "ss"
    openclaw.write_bytes(b"openclaw")
    ss.write_bytes(b"ss")
    service_root = tmp_path / "services"
    service_root.mkdir()
    (service_root / "openclaw-gateway.service").write_text(
        "[Service]\nExecStart=/opt/openclaw\n", encoding="utf-8"
    )

    def runner(argv):
        if argv[0] == str(openclaw):
            return subprocess.CompletedProcess(
                argv, 0, stdout=b'{"running":false}', stderr=b""
            )
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=b'LISTEN 0 128 127.0.0.1:18789 0.0.0.0:* users:(("openclaw",pid=9,fd=3))\n',
            stderr=b"",
        )

    inspection = LinuxHostInspectionRuntime(
        openclaw_cli=openclaw,
        openclaw_cli_sha256=hashlib.sha256(openclaw.read_bytes()).hexdigest(),
        ss_executable=ss,
        ss_executable_sha256=hashlib.sha256(ss.read_bytes()).hexdigest(),
        service_roots=(service_root,),
        command_runner=runner,
    ).inspect()

    assert inspection.preexisting_openclaw is True
    assert len(inspection.service_definitions) == 1
    assert inspection.listener_inventory[0].startswith("LISTEN ")


def test_reviewed_policy_treats_openclaw_service_definition_as_preexisting(tmp_path):
    openclaw = tmp_path / "openclaw"
    ss = tmp_path / "ss"
    openclaw.write_bytes(b"openclaw")
    ss.write_bytes(b"ss")
    service_root = tmp_path / "services"
    service_root.mkdir()
    (service_root / "openclaw-gateway.service").write_text(
        "[Service]\nExecStart=/opt/openclaw\n", encoding="utf-8"
    )

    def runner(argv):
        stdout = (
            b'{"loaded":false,"running":false}' if argv[0] == str(openclaw) else b""
        )
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr=b"")

    inspection = LinuxHostInspectionRuntime(
        openclaw_cli=openclaw,
        openclaw_cli_sha256=hashlib.sha256(openclaw.read_bytes()).hexdigest(),
        ss_executable=ss,
        ss_executable_sha256=hashlib.sha256(ss.read_bytes()).hexdigest(),
        service_roots=(service_root,),
        command_runner=runner,
    ).inspect()

    assert inspection.service_definitions
    assert inspection.preexisting_openclaw is True


def test_service_definition_blocks_gate_four_after_fixed_artifact_before_child(
    tmp_path,
):
    events = []
    coordinator = _coordinator(events)
    inspection = replace(
        _trusted_inspection(),
        service_definitions=(
            "/etc/systemd/user/openclaw-gateway.service:0644:" + "a" * 64,
        ),
    )
    observation = _host_observation(phase="pre", inspection=inspection)
    coordinator.host_observer.capture = lambda _phase: observation
    coordinator.host_observation_writer = HostObservationWriterAdapter(
        HostObservationArtifactSink(
            run_root=tmp_path,
            artifact_writer=write_host_observer_artifact,
        )
    )

    with pytest.raises(CoordinatorError, match="pre-existing OpenClaw"):
        coordinator.execute()

    assert (tmp_path / "host_observer_pre.json").is_file()
    assert "child_prepare" not in events


def test_linux_host_observer_rejects_claimed_other_pid_before_inspection(
    tmp_path, monkeypatch
):
    identity = _identity()
    _write_fake_host_proc(tmp_path / "proc", identity)
    runtime = FakeHostInspectionRuntime()
    calls = []
    runtime.inspect = lambda: calls.append("inspect") or _trusted_inspection()
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root: self == identity,
    )
    monkeypatch.setattr(os, "getpid", lambda: identity.pid + 1)
    observer = LinuxHostObserver(
        identity,
        proc_root=tmp_path / "proc",
        identity_validator=lambda _observed: True,
        inspection_runtime=runtime,
    )

    with pytest.raises(CoordinatorError, match="current PID"):
        observer.capture("pre")
    assert calls == []


def test_linux_host_observer_rejects_self_namespace_mismatch_before_inspection(
    tmp_path, monkeypatch
):
    identity = _identity()
    proc_root = tmp_path / "proc"
    _write_fake_host_proc(proc_root, identity)
    self_root = proc_root / "self"
    self_root.unlink()
    self_root.mkdir()
    (self_root / "ns").mkdir()
    (self_root / "ns" / "net").write_bytes(b"different network namespace")
    runtime = FakeHostInspectionRuntime()
    calls = []
    runtime.inspect = lambda: calls.append("inspect") or _trusted_inspection()
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, observed_root: self == identity and observed_root == proc_root,
    )
    monkeypatch.setattr(os, "getpid", lambda: identity.pid)
    observer = LinuxHostObserver(
        identity,
        proc_root=proc_root,
        identity_validator=lambda _observed: True,
        inspection_runtime=runtime,
    )

    with pytest.raises(CoordinatorError, match="current network namespace"):
        observer.capture("pre")
    assert calls == []


def test_linux_host_inspection_rejects_unpinned_executable_bytes(tmp_path):
    openclaw = tmp_path / "openclaw"
    ss = tmp_path / "ss"
    openclaw.write_bytes(b"openclaw")
    ss.write_bytes(b"ss")
    service_root = tmp_path / "services"
    service_root.mkdir()

    with pytest.raises(CoordinatorError, match="digest"):
        LinuxHostInspectionRuntime(
            openclaw_cli=openclaw,
            openclaw_cli_sha256="0" * 64,
            ss_executable=ss,
            ss_executable_sha256=hashlib.sha256(ss.read_bytes()).hexdigest(),
            service_roots=(service_root,),
            command_runner=lambda _argv: None,
        )


def test_linux_host_inspection_rejects_ambiguous_inactivity_status(tmp_path):
    openclaw = tmp_path / "openclaw"
    ss = tmp_path / "ss"
    openclaw.write_bytes(b"openclaw")
    ss.write_bytes(b"ss")
    service_root = tmp_path / "services"
    service_root.mkdir()

    def runner(argv):
        if argv[0] == str(openclaw):
            return subprocess.CompletedProcess(argv, 0, stdout=b"{}", stderr=b"")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    runtime = LinuxHostInspectionRuntime(
        openclaw_cli=openclaw,
        openclaw_cli_sha256=hashlib.sha256(openclaw.read_bytes()).hexdigest(),
        ss_executable=ss,
        ss_executable_sha256=hashlib.sha256(ss.read_bytes()).hexdigest(),
        service_roots=(service_root,),
        command_runner=runner,
    )
    with pytest.raises(CoordinatorError, match="ambiguous"):
        runtime.inspect()


class _SignalOperations:
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


def _identity():
    return ProcessIdentity(
        pid=201,
        pgid=201,
        start_time=10,
        executable_path="/bin/child",
        executable_sha256="a" * 64,
    )


def _host_observation(
    *,
    network_namespace_inode=123,
    internet_socket_attempts=0,
    identity=None,
    phase="pre",
    service_inventory=(),
    inspection=None,
):
    return HostObservation.build(
        observer_identity=identity or _identity(),
        network_namespace_inode=network_namespace_inode,
        process_inventory=(),
        service_inventory=service_inventory,
        listener_inventory=(),
        inspection=inspection or _trusted_inspection(),
        internet_socket_attempts=internet_socket_attempts,
        phase=phase,
    )


def _trusted_inspection():
    status = b'{"running":false}'
    return TrustedHostInspection(
        gateway_status_command=(
            "/opt/openclaw/bin/openclaw",
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        ),
        gateway_status_exit=0,
        gateway_status_sha256=hashlib.sha256(status).hexdigest(),
        gateway_status_state="INACTIVE",
        service_definitions=(),
        listener_command=("/usr/bin/ss", "-H", "-ltnp"),
        listener_inventory=(),
    )


def test_task4_signal_barrier_uses_real_bound_pipe_protocol():
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    operations = _SignalOperations()
    coordinator_handoff = CoordinatorSignalHandoff(
        NONCE, _identity(), signal_operations=operations
    )
    supervisor_handoff = SupervisorSignalHandoff(
        NONCE,
        forwarder=lambda _pgid, _signal_name: None,
        identity_validator=lambda identity: identity == _identity(),
    )
    errors = []

    def accept():
        try:
            supervisor_handoff.receive_and_accept(request_read, response_write)
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)
        finally:
            os.close(response_write)

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        barrier = Task4SignalBarrier(
            coordinator_handoff,
            request_write_fd=request_write,
            acceptance_read_fd=response_read,
            blocked_signals=frozenset({"HUP", "INT", "TERM"}),
            dispositions={"HUP": True, "INT": True, "TERM": True},
            handoff_marker=LinuxHandoffMarker(
                NONCE,
                _identity(),
                reviewed_process_name="coordinator",
                identity_validator=lambda observed: observed == _identity(),
                operations=FakePrctlOperations([], pid=_identity().pid),
            ),
        )
        barrier.emit_readiness_begin()
        barrier.complete_two_way_acceptance()
        barrier.emit_functional_begin()
        barrier.record_functional_progress()
    finally:
        thread.join(timeout=2)
        os.close(request_read)
    assert not thread.is_alive()
    assert errors == []
    assert coordinator_handoff.snapshot().unblock_count == 1
    assert coordinator_handoff.snapshot().functional_count == 1
    assert supervisor_handoff.snapshot().acceptance_count == 1
    with pytest.raises(OSError):
        os.fstat(request_write)
    with pytest.raises(OSError):
        os.fstat(response_read)


def test_pending_signal_at_os_unblock_preserves_interruption_cleanup_path():
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    events = []

    class InterruptAtUnblock(_SignalOperations):
        def unblock_reviewed(self):
            self.blocked = False
            raise CoordinatorInterrupted("coordinator interrupted by TERM")

    handoff = CoordinatorSignalHandoff(
        NONCE, _identity(), signal_operations=InterruptAtUnblock()
    )
    supervisor = SupervisorSignalHandoff(
        NONCE,
        forwarder=lambda _pgid, _signal_name: None,
        identity_validator=lambda identity: identity == _identity(),
    )
    errors = []

    def accept():
        try:
            supervisor.receive_and_accept(request_read, response_write)
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)
        finally:
            os.close(response_write)

    thread = threading.Thread(target=accept)
    thread.start()
    barrier = Task4SignalBarrier(
        handoff,
        request_write_fd=request_write,
        acceptance_read_fd=response_read,
        blocked_signals=frozenset({"HUP", "INT", "TERM"}),
        dispositions={"HUP": True, "INT": True, "TERM": True},
        handoff_marker=LinuxHandoffMarker(
            NONCE,
            _identity(),
            reviewed_process_name="coordinator",
            identity_validator=lambda observed: observed == _identity(),
            operations=FakePrctlOperations(events, pid=_identity().pid),
        ),
    )
    coordinator = _coordinator(events, barrier=barrier)
    try:
        result = coordinator.execute()
    finally:
        thread.join(timeout=2)
        os.close(request_read)

    assert not thread.is_alive()
    assert errors == []
    assert result.interrupted_signal == "TERM"
    assert handoff.snapshot().acceptance_validated is True
    assert handoff.snapshot().unblock_count == 1
    assert handoff.snapshot().functional_count == 0
    assert "functional_begin" not in events
    assert "action_gates" not in events
    with pytest.raises(OSError):
        os.fstat(request_write)
    with pytest.raises(OSError):
        os.fstat(response_read)


def _candidate(store, gates, *, sealed=False):
    return LedgerCandidate(
        generation=store.head.generation + 1,
        previous_generation=store.head.generation,
        previous_digest=store.head.digest,
        run_id=store.run_id,
        ledger_nonce=store.run_nonce,
        gates=gates,
        sealed=sealed,
        semantic_dds_window=store.current["semantic_dds_window"],
    )


def _pass_bootstrap_gates(store):
    gates = copy.deepcopy(store.current["gates"])
    gates[0].update(status="PASS", reason="OK")
    store.append(_candidate(store, gates))
    gates = copy.deepcopy(store.current["gates"])
    gates[1].update(status="PASS", reason="OK")
    store.append(_candidate(store, gates))


def test_coordinator_candidates_are_persisted_only_by_supervisor_broker(tmp_path):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    errors = []
    try:
        _pass_bootstrap_gates(store)
        broker = SupervisorLedgerBroker(
            store,
            candidate_read_fd=candidate_read,
            acceptance_write_fd=acceptance_write,
        )

        def serve():
            try:
                broker.serve_until_sealed()
            except BaseException as error:  # pragma: no cover - asserted below
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        client = Task3LedgerClient(
            candidate_write_fd=candidate_write,
            acceptance_read_fd=acceptance_read,
            initial_document=store.current,
            initial_digest=store.head.digest,
        )
        adapter = CoordinatorLedgerAdapter(client)
        adapter.pass_preflight()
        adapter.accept_host_preexisting(_host_observation(phase="pre"))
        adapter.open_dds_window()
        adapter.close_dds_window()
        action_gates = copy.deepcopy(client.current["gates"][4:23])
        for gate in action_gates:
            gate.update(status="PASS", reason="OK")
        adapter.accept_action_gates(tuple(action_gates))
        report = ActionChildReport(
            gates=tuple(action_gates),
            semantic_fixture=SemanticFixtureOutcome(
                gate=copy.deepcopy(action_gates[13]),
                cleanup_complete=True,
                participant_count=0,
                socket_count=0,
            ),
            namespace_proof=LoopbackNamespaceProof.valid_fixture(),
            cleanup_complete=True,
            participant_count=0,
            socket_count=0,
            owned_identity=_identity(),
        )
        adapter.finalize_postflight(
            inner=report,
            host_pre=_host_observation(phase="pre"),
            host_post=_host_observation(phase="post"),
        )
        adapter.seal()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []
        assert adapter.sealed
        assert store.head.sealed
        assert store.current["semantic_dds_window"] == "CLOSED"
        assert store.current["gates"][2]["status"] == "PASS"
        assert all(gate["status"] == "PASS" for gate in store.current["gates"][3:24])
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_real_ledger_adapter_seals_clean_interruption_suffix(tmp_path):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    errors = []
    try:
        _pass_bootstrap_gates(store)
        broker = SupervisorLedgerBroker(
            store,
            candidate_read_fd=candidate_read,
            acceptance_write_fd=acceptance_write,
        )

        def serve():
            try:
                broker.serve_until_sealed()
            except BaseException as error:  # pragma: no cover - asserted below
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        adapter = CoordinatorLedgerAdapter(
            Task3LedgerClient(
                candidate_write_fd=candidate_write,
                acceptance_read_fd=acceptance_read,
                initial_document=store.current,
                initial_digest=store.head.digest,
            )
        )
        adapter.pass_preflight()
        adapter.open_dds_window()
        adapter.close_dds_window()
        adapter.finalize_interruption()
        adapter.seal()
        thread.join(timeout=2)

        assert not thread.is_alive()
        assert errors == []
        assert store.current["semantic_dds_window"] == "CLOSED"
        assert all(
            gate["status"] == "NOT_RUN" and gate["reason"] == "INTERRUPTED_BEFORE_GATE"
            for gate in store.current["gates"][3:23]
        )
        assert store.current["gates"][23]["status"] == "PASS"
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_real_ledger_adapter_seals_a_failed_postflight(tmp_path):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    errors = []
    try:
        _pass_bootstrap_gates(store)
        broker = SupervisorLedgerBroker(
            store,
            candidate_read_fd=candidate_read,
            acceptance_write_fd=acceptance_write,
        )

        def serve():
            try:
                broker.serve_once()
            except BaseException as error:  # pragma: no cover - asserted below
                errors.append(error)

        thread = threading.Thread(target=serve)
        thread.start()
        adapter = CoordinatorLedgerAdapter(
            Task3LedgerClient(
                candidate_write_fd=candidate_write,
                acceptance_read_fd=acceptance_read,
                initial_document=store.current,
                initial_digest=store.head.digest,
            )
        )
        adapter.finalize_failure(cleanup_complete=False)
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []
        assert store.head.sealed
        assert store.current["gates"][23]["id"] == "safety.workstation_postflight"
        assert store.current["gates"][23]["status"] == "FAIL"
        assert store.current["gates"][23]["reason"] == "POSTFLIGHT_FAILED"
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_coordinator_broker_clients_force_cloexec_on_every_owned_pipe(tmp_path):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    ledger_acceptance_read, ledger_acceptance_write = os.pipe()
    record_read, record_write = os.pipe()
    ownership_acceptance_read, ownership_acceptance_write = os.pipe()
    owned = (
        candidate_write,
        ledger_acceptance_read,
        record_write,
        ownership_acceptance_read,
    )
    try:
        for fd in owned:
            os.set_inheritable(fd, True)
        Task3LedgerClient(
            candidate_write_fd=candidate_write,
            acceptance_read_fd=ledger_acceptance_read,
            initial_document=store.current,
            initial_digest=store.head.digest,
        )
        Task4OwnershipClient(
            run_nonce=NONCE,
            record_write_fd=record_write,
            acceptance_read_fd=ownership_acceptance_read,
        )
        assert all(fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC for fd in owned)
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            ledger_acceptance_read,
            ledger_acceptance_write,
            record_read,
            record_write,
            ownership_acceptance_read,
            ownership_acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_ledger_client_rejects_missing_ack_without_advancing(tmp_path):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    os.close(acceptance_write)
    try:
        client = Task3LedgerClient(
            candidate_write_fd=candidate_write,
            acceptance_read_fd=acceptance_read,
            initial_document=store.current,
            initial_digest=store.head.digest,
        )
        with pytest.raises(CoordinatorError, match="ledger broker exchange"):
            client.submit(copy.deepcopy(client.current["gates"]), sealed=False)
        assert client.head.generation == 0
    finally:
        for fd in (candidate_read, candidate_write, acceptance_read):
            os.close(fd)
        store.close()


def test_ledger_broker_replays_ack_without_reinstalling_after_lost_ack(
    tmp_path, monkeypatch
):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    try:
        _pass_bootstrap_gates(store)
        gates = copy.deepcopy(store.current["gates"])
        gates[2].update(status="PASS", reason="OK")
        candidate = _candidate(store, gates).as_json()
        message = {
            "type": MessageType.LEDGER_CANDIDATE.value,
            "run_nonce": NONCE,
            "sequence": 1,
            "generation": candidate["generation"],
            "previous_generation": candidate["previous_generation"],
            "previous_digest": candidate["previous_digest"],
            "candidate": candidate,
        }
        write_frame(
            candidate_write, message, ledger_validator=lambda value: value == candidate
        )
        write_frame(
            candidate_write, message, ledger_validator=lambda value: value == candidate
        )
        broker = SupervisorLedgerBroker(
            store,
            candidate_read_fd=candidate_read,
            acceptance_write_fd=acceptance_write,
        )
        from holoagent0_setup import supervisor as supervisor_module

        real_write = supervisor_module.write_frame
        writes = 0

        def lose_first_ack(*args, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 1:
                raise BrokerProtocolError("injected lost ACK")
            return real_write(*args, **kwargs)

        monkeypatch.setattr(supervisor_module, "write_frame", lose_first_ack)
        with pytest.raises(SupervisorError, match="acknowledgement write failed"):
            broker.serve_once()
        installed_generation = store.head.generation
        broker.serve_once()
        accepted = read_frame(acceptance_read)
        assert accepted["generation"] == installed_generation
        assert store.head.generation == installed_generation
        assert writes == 2
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_ownership_broker_replays_ack_without_duplicate_journal_record(
    tmp_path, monkeypatch
):
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD"},
    )
    message = {
        "type": MessageType.OWNERSHIP_RECORD.value,
        "run_nonce": NONCE,
        "sequence": 1,
        "identity": _identity().as_dict(),
        "role": "action_child",
    }
    try:
        write_frame(record_write, message)
        write_frame(record_write, message)
        broker = SupervisorOwnershipBroker(
            journal,
            run_nonce=NONCE,
            record_read_fd=record_read,
            acceptance_write_fd=acceptance_write,
            owned_process_controller=_ownership_controller(),
        )
        from holoagent0_setup import supervisor as supervisor_module

        real_write = supervisor_module.write_frame
        writes = 0

        def lose_first_ack(*args, **kwargs):
            nonlocal writes
            writes += 1
            if writes == 1:
                raise BrokerProtocolError("injected lost ACK")
            return real_write(*args, **kwargs)

        monkeypatch.setattr(supervisor_module, "write_frame", lose_first_ack)
        with pytest.raises(SupervisorError, match="durably accepted"):
            broker.serve_once()
        broker.serve_once()
        accepted = read_frame(acceptance_read)
        assert (
            accepted["request_sha256"]
            == hashlib.sha256(canonical_json_bytes(message)).hexdigest()
        )
        assert journal.seal().record_count == 1
        assert writes == 2
    finally:
        for fd in (record_read, record_write, acceptance_read, acceptance_write):
            os.close(fd)


def test_ledger_client_retries_exact_request_after_unbound_ack(tmp_path, monkeypatch):
    store = LedgerStore.create(
        tmp_path / "ledger", ContractSet(PACKAGE_ROOT), NONCE, run_id="run-1"
    )
    candidate_read, candidate_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    _pass_bootstrap_gates(store)
    broker = SupervisorLedgerBroker(
        store,
        candidate_read_fd=candidate_read,
        acceptance_write_fd=acceptance_write,
    )
    errors = []
    from holoagent0_setup import supervisor as supervisor_module

    real_write = supervisor_module.write_frame
    writes = 0

    def publish_wrong_first_ack(fd, message, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 1:
            wrong = dict(message)
            wrong["request_sha256"] = "b" * 64
            real_write(fd, wrong, **kwargs)
            raise BrokerProtocolError("injected lost binding")
        return real_write(fd, message, **kwargs)

    monkeypatch.setattr(supervisor_module, "write_frame", publish_wrong_first_ack)

    def serve():
        try:
            broker.serve_acknowledged()
        except SupervisorError as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = Task3LedgerClient(
            candidate_write_fd=candidate_write,
            acceptance_read_fd=acceptance_read,
            initial_document=store.current,
            initial_digest=store.head.digest,
        )
        CoordinatorLedgerAdapter(client).pass_preflight()
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert client.head.generation == 3
        assert store.head.generation == 3
        assert errors == []
    finally:
        for fd in (
            candidate_read,
            candidate_write,
            acceptance_read,
            acceptance_write,
        ):
            os.close(fd)
        store.close()


def test_ownership_client_retries_exact_request_after_unbound_ack(
    tmp_path, monkeypatch
):
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD"},
    )
    broker = SupervisorOwnershipBroker(
        journal,
        run_nonce=NONCE,
        record_read_fd=record_read,
        acceptance_write_fd=acceptance_write,
        owned_process_controller=_ownership_controller(),
    )
    errors = []
    from holoagent0_setup import supervisor as supervisor_module

    real_write = supervisor_module.write_frame
    writes = 0

    def publish_wrong_first_ack(fd, message, **kwargs):
        nonlocal writes
        writes += 1
        if writes == 1:
            wrong = dict(message)
            wrong["request_sha256"] = "b" * 64
            real_write(fd, wrong, **kwargs)
            raise BrokerProtocolError("injected lost binding")
        return real_write(fd, message, **kwargs)

    monkeypatch.setattr(supervisor_module, "write_frame", publish_wrong_first_ack)

    def serve():
        try:
            broker.serve_acknowledged()
        except SupervisorError as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = Task4OwnershipClient(
            run_nonce=NONCE,
            record_write_fd=record_write,
            acceptance_read_fd=acceptance_read,
        )
        client.append_identity(_identity())
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert journal.seal().record_count == 1
        assert errors == []
    finally:
        for fd in (record_read, record_write, acceptance_read, acceptance_write):
            os.close(fd)


def test_ownership_identity_is_durable_before_pipe_ack(tmp_path):
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD"},
    )
    broker = SupervisorOwnershipBroker(
        journal,
        run_nonce=NONCE,
        record_read_fd=record_read,
        acceptance_write_fd=acceptance_write,
        owned_process_controller=_ownership_controller(),
    )
    errors = []

    def serve():
        try:
            broker.serve_once()
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        client = Task4OwnershipClient(
            run_nonce=NONCE,
            record_write_fd=record_write,
            acceptance_read_fd=acceptance_read,
        )
        client.append_identity(_identity())
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert errors == []
        bound = journal.seal()
        assert bound.record_count == 1
        assert (
            b'"kind":"OWNERSHIP_RECORD"' in (tmp_path / "ownership.ndjson").read_bytes()
        )
    finally:
        for fd in (record_read, record_write, acceptance_read, acceptance_write):
            os.close(fd)


def test_participant_registration_client_requires_exact_order_and_completion():
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    client = Task4OwnershipClient(
        run_nonce=NONCE,
        record_write_fd=record_write,
        acceptance_read_fd=acceptance_read,
    )
    try:
        with pytest.raises(CoordinatorError, match="action-child"):
            client.append_participant(
                _identity(),
                participant_index=0,
                role=CONFIG_ROLES[0],
                config_digest=EXPECTED_CONFIG_SHA256[0],
            )
        with pytest.raises(CoordinatorError, match="incomplete"):
            client.require_participant_registration_complete()
    finally:
        for fd in (record_read, record_write, acceptance_read, acceptance_write):
            os.close(fd)


def test_participant_registration_client_rejects_duplicate_and_late_records(
    monkeypatch,
):
    record_read, record_write = os.pipe()
    acceptance_read, acceptance_write = os.pipe()
    client = Task4OwnershipClient(
        run_nonce=NONCE,
        record_write_fd=record_write,
        acceptance_read_fd=acceptance_read,
    )
    accepted = []

    def accept_locally(message):
        accepted.append(message)
        return {
            "type": (
                "OWNERSHIP_ACCEPTED"
                if message["type"] == "OWNERSHIP_RECORD"
                else "PARTICIPANT_ACCEPTED"
            ),
            "run_nonce": NONCE,
            "sequence": message["sequence"],
            "request_sha256": hashlib.sha256(canonical_json_bytes(message)).hexdigest(),
        }

    monkeypatch.setattr(client, "_exchange", accept_locally)
    try:
        client.append_identity(_identity())
        with pytest.raises(CoordinatorError, match="order"):
            client.append_participant(
                replace(_identity(), pid=203, pgid=203),
                participant_index=1,
                role=CONFIG_ROLES[1],
                config_digest=EXPECTED_CONFIG_SHA256[1],
            )
        for index in range(4):
            client.append_participant(
                replace(
                    _identity(),
                    pid=300 + index,
                    pgid=300 + index,
                    start_time=20 + index,
                ),
                participant_index=index,
                role=CONFIG_ROLES[index],
                config_digest=EXPECTED_CONFIG_SHA256[index],
            )
        client.require_participant_registration_complete()
        with pytest.raises(CoordinatorError, match="complete"):
            client.append_participant(
                replace(_identity(), pid=399, pgid=399),
                participant_index=0,
                role=CONFIG_ROLES[0],
                config_digest=EXPECTED_CONFIG_SHA256[0],
            )
        assert [message["sequence"] for message in accepted] == [1, 2, 3, 4, 5]
    finally:
        for fd in (record_read, record_write, acceptance_read, acceptance_write):
            os.close(fd)


def test_participant_relay_is_a_closed_window_over_existing_ownership_client():
    records = []

    class Client:
        def append_participant(self, identity, **binding):
            records.append((identity, binding))
            return {"type": "PARTICIPANT_ACCEPTED"}

    relay = ParticipantRegistrationRelay(Client())
    relay.open()
    for index in range(4):
        relay.register(
            ParticipantRegistration(
                replace(
                    _identity(),
                    pid=400 + index,
                    pgid=400 + index,
                    start_time=30 + index,
                ),
                index,
                CONFIG_ROLES[index],
                EXPECTED_CONFIG_SHA256[index],
            )
        )
    relay.close_complete()
    assert [binding["participant_index"] for _identity, binding in records] == [
        0,
        1,
        2,
        3,
    ]
    with pytest.raises(CoordinatorError, match="closed"):
        relay.register(
            ParticipantRegistration(
                replace(_identity(), pid=499, pgid=499),
                0,
                CONFIG_ROLES[0],
                EXPECTED_CONFIG_SHA256[0],
            )
        )


def test_participant_relay_refuses_missing_registration_at_window_close():
    class Client:
        def append_participant(self, *_args, **_kwargs):
            return None

    relay = ParticipantRegistrationRelay(Client())
    relay.open()
    with pytest.raises(CoordinatorError, match="incomplete"):
        relay.close_complete()


def test_participant_relay_bridges_existing_child_ipc_only_after_supervisor_ack():
    child_ready_read, child_ready_write = os.pipe()
    child_accept_read, child_accept_write = os.pipe()
    identity = replace(_identity(), pid=450, pgid=450, start_time=45)
    child_message = {
        "type": "PARTICIPANT_RECORD",
        "run_nonce": NONCE,
        "sequence": 2,
        "identity": identity.as_dict(),
        "role": CONFIG_ROLES[0],
        "participant_index": 0,
        "config_digest": EXPECTED_CONFIG_SHA256[0],
    }
    request_sha256 = hashlib.sha256(canonical_json_bytes(child_message)).hexdigest()
    events = []

    class Client:
        def append_participant(self, observed, **binding):
            events.append("supervisor_ack")
            assert observed == identity
            assert binding["participant_index"] == 0
            return {
                "type": "PARTICIPANT_ACCEPTED",
                "run_nonce": NONCE,
                "sequence": 2,
                "request_sha256": request_sha256,
            }

    try:
        write_frame(child_ready_write, child_message)
        relay = ParticipantRegistrationRelay(Client())
        relay.open()
        relay.receive_child_ready(
            child_ready_read,
            child_accept_write,
            run_nonce=NONCE,
        )
        events.append("child_acceptance_observed")
        assert read_frame(child_accept_read) == {
            "type": "PARTICIPANT_ACCEPTED",
            "run_nonce": NONCE,
            "sequence": 2,
            "request_sha256": request_sha256,
        }
        assert events == ["supervisor_ack", "child_acceptance_observed"]
    finally:
        for fd in (
            child_ready_read,
            child_ready_write,
            child_accept_read,
            child_accept_write,
        ):
            os.close(fd)
