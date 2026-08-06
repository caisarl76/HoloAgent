from pathlib import Path
import json

import pytest

from holoagent0_setup.contract import ContractSet
from holoagent0_setup.result_policy import ResultPolicy, ResultPolicyError


CONTRACT_ROOT = Path(__file__).parents[1]
GATE_POLICY = json.loads(
    (CONTRACT_ROOT / "policies/holoagent0-gate-policy-v1.json").read_text()
)


def gate(gate_id, status="PASS", reason="OK"):
    return {"id": gate_id, "status": status, "reason": reason}


def finalized_gates(mode, *overrides):
    profile = GATE_POLICY["profiles"][mode]
    override_by_id = {item["id"]: item for item in overrides}
    gates = []
    for gate_id in profile["gate_order"]:
        if gate_id in override_by_id:
            gates.append(override_by_id[gate_id])
        elif gate_id == "semantic.natural_language_parser":
            gates.append(gate(gate_id, "SKIPPED", "POLICY_DISABLED"))
        else:
            gates.append(gate(gate_id))
    blocking_indexes = [
        index
        for index, item in enumerate(gates)
        if item["status"] == "FAIL"
        and profile["roles"][item["id"]] in {"required", "required_qualification"}
    ]
    if blocking_indexes:
        first = blocking_indexes[0]
        for index in range(first + 1, len(gates)):
            gate_id = gates[index]["id"]
            if (
                profile["roles"][gate_id] != "finalizer"
                and gate_id not in override_by_id
            ):
                gates[index] = gate(gate_id, "NOT_RUN", "EARLIER_BLOCKING_GATE")
    return gates


@pytest.fixture(scope="module")
def policy():
    return ResultPolicy(ContractSet(CONTRACT_ROOT))


def test_safety_finalizer_beats_functional_failure_and_interrupt(policy):
    decision = policy.decide(
        mode="pc2_camera",
        gates=finalized_gates(
            "pc2_camera",
            gate("pc2.camera_rate", "FAIL", "RATE_BELOW_THRESHOLD"),
            gate("pc2.camera_cleanup", "FAIL", "CLEANUP_INCOMPLETE"),
        ),
        signal="TERM",
    )
    assert (decision.label, decision.status, decision.exit_code, decision.primary) == (
        "FAIL_SAFETY",
        "FAIL",
        30,
        "pc2.camera_cleanup",
    )
    assert decision.blocking_gates == ("pc2.camera_rate", "pc2.camera_cleanup")


def test_harness_beats_interrupt_but_safety_beats_harness(policy):
    harness = policy.decide(
        "workstation_offline",
        finalized_gates(
            "workstation_offline",
            gate("offline.trace_integrity", "FAIL", "TRACE_INCOMPLETE"),
        ),
        signal="INT",
    )
    assert (harness.label, harness.exit_class, harness.exit_code) == (
        "FAIL_HARNESS",
        "HARNESS_FAILURE",
        40,
    )
    safety = policy.decide(
        "workstation_offline",
        finalized_gates(
            "workstation_offline",
            gate("offline.trace_integrity", "FAIL", "TRACE_INCOMPLETE"),
            gate("offline.network_policy", "FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
        ),
        signal="HUP",
    )
    assert (safety.label, safety.primary, safety.exit_code) == (
        "FAIL_SAFETY",
        "offline.network_policy",
        30,
    )


@pytest.mark.parametrize(
    ("signal", "exit_class", "exit_code"),
    [("HUP", "HUP", 129), ("INT", "INT", 130), ("TERM", "TERM", 143)],
)
def test_clean_interrupt_has_fixed_tuple(policy, signal, exit_class, exit_code):
    gates = finalized_gates("pc2_inventory")
    gates[12] = gate("pc2.imu_rate", "NOT_RUN", "INTERRUPTED_BEFORE_GATE")
    decision = policy.decide("pc2_inventory", gates, signal=signal)
    assert (
        decision.label,
        decision.status,
        decision.exit_class,
        decision.exit_code,
    ) == (
        "INTERRUPTED",
        "INTERRUPTED",
        exit_class,
        exit_code,
    )


def test_signal_without_interrupted_gate_marker_is_rejected(policy):
    with pytest.raises(ResultPolicyError, match="interruption marker"):
        policy.decide("pc2_inventory", finalized_gates("pc2_inventory"), signal="TERM")


def test_policy_driven_tie_breaking_and_qualification(policy):
    decision = policy.decide(
        "workstation_offline",
        finalized_gates(
            "workstation_offline",
            gate("safety.workstation_postflight", "FAIL", "POSTFLIGHT_FAILED"),
            gate("offline.network_policy", "FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
        ),
    )
    assert decision.primary == "safety.workstation_postflight"
    assert decision.blocking_gates == (
        "safety.workstation_postflight",
        "offline.network_policy",
    )

    qualified = policy.decide(
        "workstation_offline",
        finalized_gates(
            "workstation_offline",
            gate("chatbot.credentials", "QUALIFIED", "CREDENTIALS_MISSING"),
            gate("chatbot.audio_hardware", "QUALIFIED", "AUDIO_HARDWARE_MISSING"),
        ),
    )
    assert (qualified.label, qualified.status, qualified.exit_code) == (
        "READY_CREDENTIALS_AND_AUDIO_REQUIRED",
        "QUALIFIED",
        10,
    )
    assert qualified.qualifications == (
        "chatbot.credentials",
        "chatbot.audio_hardware",
    )


def test_diagnostic_failure_does_not_block_pass(policy):
    decision = policy.decide(
        "pc2_inventory",
        finalized_gates(
            "pc2_inventory", gate("pc2.lidar_sample", "FAIL", "TOPIC_NO_SAMPLE")
        ),
    )
    assert (decision.label, decision.status, decision.exit_code, decision.primary) == (
        "PASS_PC2_SENSOR_INVENTORY",
        "PASS",
        0,
        None,
    )


def test_wrong_mode_unknown_gate_and_invalid_outcomes_fail_closed(policy):
    with pytest.raises(ResultPolicyError, match="exact ordered profile gate set"):
        policy.decide(
            "pc2_camera", [gate("mujoco.stage4", "FAIL", "STAGE_CHILD_FAILED")]
        )
    with pytest.raises(ResultPolicyError, match="unknown mode"):
        policy.decide("not-a-mode", [])
    with pytest.raises(ResultPolicyError, match="invalid status/reason"):
        bad = finalized_gates("pc2_camera", gate("pc2.camera_rate", "FAIL", "OK"))
        policy.decide("pc2_camera", bad)


def test_harness_failure_is_used_when_safety_decision_is_impossible(policy):
    decision = policy.decide(
        "workstation_offline",
        finalized_gates(
            "workstation_offline",
            gate("offline.evidence_binding", "FAIL", "EVIDENCE_BINDING_MISMATCH"),
        ),
        safety_decision_possible=False,
    )
    assert (decision.label, decision.exit_code, decision.primary) == (
        "FAIL_HARNESS",
        40,
        "offline.evidence_binding",
    )


def test_profile_result_policy_rejects_not_run_finalizer(policy):
    with pytest.raises(ResultPolicyError, match="mandatory finalizer"):
        policy.decide(
            "workstation_offline",
            finalized_gates(
                "workstation_offline",
                gate(
                    "safety.workstation_postflight",
                    "NOT_RUN",
                    "EARLIER_BLOCKING_GATE",
                ),
            ),
        )


def test_policy_tables_are_snapshotted_from_mutable_contract():
    contract = ContractSet(CONTRACT_ROOT)
    policy = ResultPolicy(contract)
    contract.policies["holoagent0-gate-policy-v1"]["failure_outcomes"]["pc2_camera"][
        "pc2.camera_rate"
    ] = "FAIL_SOURCE"
    decision = policy.decide(
        "pc2_camera",
        finalized_gates(
            "pc2_camera", gate("pc2.camera_rate", "FAIL", "RATE_BELOW_THRESHOLD")
        ),
    )
    assert decision.label == "FAIL_PC2_CAMERA"


@pytest.mark.parametrize("mode", tuple(GATE_POLICY["profiles"]))
def test_authoritative_decision_rejects_missing_gate_set(policy, mode):
    with pytest.raises(ResultPolicyError, match="exact ordered profile gate set"):
        policy.decide(mode, [])


def test_authoritative_decision_requires_terminal_finalizers(policy):
    gates = finalized_gates("pc2_camera")
    cleanup = next(item for item in gates if item["id"] == "pc2.camera_cleanup")
    cleanup.update(status="SKIPPED", reason="NO_OWNED_CAMERA")
    postflight = next(item for item in gates if item["id"] == "safety.pc2_postflight")
    postflight.update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    with pytest.raises(ResultPolicyError, match="mandatory finalizer"):
        policy.decide("pc2_camera", gates, signal="TERM")


def test_bootstrap_finalizer_failure_can_classify_not_run_action_skeleton(policy):
    gates = finalized_gates("workstation_offline")
    for item in gates[:23]:
        item.update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    postflight = next(
        item for item in gates if item["id"] == "safety.workstation_postflight"
    )
    postflight.update(status="FAIL", reason="POSTFLIGHT_FAILED")
    decision = policy.decide("workstation_offline", gates)
    assert (decision.label, decision.primary, decision.exit_code) == (
        "FAIL_SAFETY",
        "safety.workstation_postflight",
        30,
    )


@pytest.mark.parametrize(
    ("mode", "gates", "signal", "safety_decision_possible"),
    [
        ([], [], None, True),
        (None, [], None, True),
        ("pc2_inventory", None, None, True),
        ("pc2_inventory", [None], None, True),
        ("pc2_inventory", [], [], True),
        ("pc2_inventory", [], None, "yes"),
        ("pc2_inventory", [], None, 1),
    ],
)
def test_decision_rejects_malformed_runtime_inputs_with_policy_error(
    policy, mode, gates, signal, safety_decision_possible
):
    with pytest.raises(ResultPolicyError):
        policy.decide(
            mode,
            gates,
            signal=signal,
            safety_decision_possible=safety_decision_possible,
        )
