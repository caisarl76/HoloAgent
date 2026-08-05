import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from holoagent0_setup.contract import ContractError, ContractLoadError, ContractSet


PACKAGE_ROOT = Path(__file__).parents[1]
CONTRACT_ROOT = PACKAGE_ROOT
SHA256 = "a" * 64


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


PROFILE_GATES = {
    "workstation_offline": (
        ("source.repository", "required"),
        ("runtime.workstation", "required"),
        ("safety.workstation_preflight", "required"),
        ("openclaw.preexisting", "required"),
        ("openclaw.version_pin", "required"),
        ("openclaw.registry_integrity", "required"),
        ("openclaw.config_pin", "required"),
        ("openclaw.config_validate", "required"),
        ("openclaw.doctor_lint", "required"),
        ("skills.registry", "required"),
        ("skills.dry_run", "required"),
        ("agentos.plan_schema", "required"),
        ("agentos.offline_execution", "required"),
        ("agentos.network_attempts", "required"),
        ("source.semantic_blobs", "required"),
        ("semantic.asset_lock", "required"),
        ("semantic.fixture_graph", "required"),
        ("semantic.fixture_query", "required"),
        ("semantic.natural_language_parser", "diagnostic"),
        ("chatbot.dependencies", "required"),
        ("chatbot.configuration", "required"),
        ("chatbot.credentials", "qualification"),
        ("chatbot.audio_hardware", "qualification"),
        ("safety.workstation_postflight", "finalizer"),
        ("offline.trace_integrity", "finalizer"),
        ("offline.network_policy", "finalizer"),
        ("offline.evidence_binding", "finalizer"),
    ),
    "workstation_mujoco": (
        ("source.repository", "required"),
        ("runtime.workstation", "required"),
        ("safety.workstation_preflight", "required"),
        ("offline.reference", "required"),
        ("mujoco.stage1", "required"),
        ("mujoco.stage2", "required"),
        ("mujoco.stage3", "required_qualification"),
        ("mujoco.stage4", "required"),
        ("safety.workstation_postflight", "finalizer"),
    ),
    "pc2_inventory": (
        ("source.repository", "required"),
        ("source.pc2_script", "required"),
        ("runtime.pc2", "required"),
        ("safety.pc2_preflight", "required"),
        ("pc2.inventory", "required"),
        ("pc2.camera_inventory", "required"),
        ("pc2.lidar_advertisement", "diagnostic"),
        ("pc2.lidar_sample", "diagnostic"),
        ("pc2.lidar_rate", "diagnostic"),
        ("pc2.lidar_schema", "diagnostic"),
        ("pc2.imu_advertisement", "diagnostic"),
        ("pc2.imu_sample", "diagnostic"),
        ("pc2.imu_rate", "diagnostic"),
        ("safety.pc2_runtime_monitor", "finalizer"),
        ("safety.pc2_postflight", "finalizer"),
    ),
    "pc2_camera": (
        ("source.repository", "required"),
        ("source.pc2_script", "required"),
        ("runtime.pc2", "required"),
        ("safety.pc2_preflight", "required"),
        ("pc2.inventory", "required"),
        ("pc2.camera_inventory", "required"),
        ("pc2.camera_sample", "required"),
        ("pc2.camera_rate", "required"),
        ("pc2.lidar_advertisement", "diagnostic"),
        ("pc2.lidar_sample", "diagnostic"),
        ("pc2.lidar_rate", "diagnostic"),
        ("pc2.lidar_schema", "diagnostic"),
        ("pc2.imu_advertisement", "diagnostic"),
        ("pc2.imu_sample", "diagnostic"),
        ("pc2.imu_rate", "diagnostic"),
        ("pc2.camera_cleanup", "finalizer"),
        ("safety.pc2_runtime_monitor", "finalizer"),
        ("safety.pc2_postflight", "finalizer"),
    ),
    "pc2_full_streams": (
        ("source.repository", "required"),
        ("source.pc2_script", "required"),
        ("runtime.pc2", "required"),
        ("safety.pc2_preflight", "required"),
        ("pc2.inventory", "required"),
        ("pc2.camera_inventory", "required"),
        ("pc2.camera_sample", "required"),
        ("pc2.camera_rate", "required"),
        ("pc2.lidar_advertisement", "required"),
        ("pc2.lidar_sample", "required"),
        ("pc2.lidar_rate", "required"),
        ("pc2.lidar_schema", "required"),
        ("pc2.imu_advertisement", "required"),
        ("pc2.imu_sample", "required"),
        ("pc2.imu_rate", "required"),
        ("pc2.camera_cleanup", "finalizer"),
        ("safety.pc2_runtime_monitor", "finalizer"),
        ("safety.pc2_postflight", "finalizer"),
    ),
}

PASS_LABELS = {
    "workstation_offline": "PASS_HOLOAGENT0_OFFLINE",
    "workstation_mujoco": "PASS_HOLOAGENT0_MUJOCO",
    "pc2_inventory": "PASS_PC2_SENSOR_INVENTORY",
    "pc2_camera": "PASS_PC2_CAMERA_ONLY",
    "pc2_full_streams": "PASS_PC2_SENSOR_STREAMS",
}


def _gate(gate_id: str, role: str) -> dict[str, object]:
    status = "SKIPPED" if gate_id == "semantic.natural_language_parser" else "PASS"
    reason = "POLICY_DISABLED" if status == "SKIPPED" else "OK"
    return {
        "id": gate_id,
        "status": status,
        "role": role,
        "reason": reason,
        "measurements": [],
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


def make_pass_result(mode: str) -> dict[str, object]:
    invocation_role = "parent" if mode == "workstation_mujoco" else "standalone"
    value: dict[str, object] = {
        "schema_version": "holoagent0.result.v1",
        "run_id": "run-001",
        "mode": mode,
        "label": PASS_LABELS[mode],
        "status": "PASS",
        "exit_class": "PASS",
        "process_exit_code": 0,
        "started_at": "2026-08-05T00:00:00Z",
        "ended_at": "2026-08-05T00:00:01Z",
        "duration_monotonic_seconds": 1.0,
        "hostname": "test-host",
        "architecture": "x86_64",
        "source_commit": "b" * 40,
        "source_manifest_sha256": SHA256,
        "configuration_sha256": SHA256,
        "redacted_environment": {},
        "prohibited_commands": [],
        "result_schema_sha256": _digest(
            CONTRACT_ROOT / "schemas/holoagent0-result-v1.schema.json"
        ),
        "gate_policy_sha256": _digest(
            CONTRACT_ROOT / "policies/holoagent0-gate-policy-v1.json"
        ),
        "reason_code_policy_sha256": _digest(
            CONTRACT_ROOT / "policies/holoagent0-reason-codes-v1.json"
        ),
        "invocation_role": invocation_role,
        "parent_run_id": None,
        "lineage_nonce": None,
        "gates": [_gate(gate_id, role) for gate_id, role in PROFILE_GATES[mode]],
        "primary_blocking_gate": None,
        "blocking_gates": [],
        "qualifications": [],
    }
    if mode.startswith("workstation_"):
        value.update(
            {
                "agentos_plan_schema_sha256": _digest(
                    CONTRACT_ROOT / "schemas/agentos-plan-v1.schema.json"
                ),
                "graph_sha256": SHA256,
                "dataset_sha256": SHA256,
                "checkpoint_sha256": SHA256,
                "openclaw_provisioning_schema_sha256": _digest(
                    CONTRACT_ROOT / "schemas/openclaw-provisioning-v1.schema.json"
                ),
                "offline_ledger_schema_sha256": _digest(
                    CONTRACT_ROOT / "schemas/holoagent0-offline-ledger-v1.schema.json"
                ),
                "trace_tool_policy_sha256": _digest(
                    CONTRACT_ROOT / "policies/holoagent0-trace-tool-v1.json"
                ),
                "trace_tool_policy_schema_sha256": _digest(
                    CONTRACT_ROOT
                    / "schemas/holoagent0-trace-tool-policy-v1.schema.json"
                ),
                "trace_parser_fixture_manifest_sha256": SHA256,
                "cyclonedds_config_set_sha256": SHA256,
            }
        )
    else:
        value["script_sha256"] = SHA256
    if mode == "workstation_offline":
        artifact = {"relative_path": "evidence/item.json", "sha256": SHA256, "size": 1}
        value["offline_evidence_bundle_sha256"] = SHA256
        value["offline_evidence"] = {
            "trace": copy.deepcopy(artifact),
            "bootstrap_report": copy.deepcopy(artifact),
            "ledger_chain_manifest": copy.deepcopy(artifact),
            "ownership_journal": copy.deepcopy(artifact),
            "violation_journal": copy.deepcopy(artifact),
            "host_observer_pre": copy.deepcopy(artifact),
            "host_observer_post": copy.deepcopy(artifact),
            "semantic_dds_window": "NOT_ENTERED",
            "dds_begin_record_index": None,
            "dds_end_record_index": None,
            "marker_token": "holoagent0-dds-window-v1",
            "bundle_sha256": SHA256,
        }
    elif mode == "workstation_mujoco":
        value["offline_reference_evidence_bundle_sha256"] = SHA256
    else:
        value["pc2_evidence"] = {
            "action_window_started_at": "2026-08-05T00:00:00Z",
            "action_window_ended_at": "2026-08-05T00:00:01Z",
            "monitor_samples": [
                {
                    "timestamp": "2026-08-05T00:00:00Z",
                    "state": "EXACT_MATCH",
                    "observed_matches": [],
                }
            ],
            "owned_processes": [],
        }
        if mode in {"pc2_camera", "pc2_full_streams"}:
            value["pc2_evidence"]["owned_processes"] = [
                {
                    "pid": 100,
                    "pgid": 100,
                    "start_time_ticks": 1,
                    "executable": "/usr/bin/camera",
                }
            ]
    return value


@pytest.fixture(scope="module")
def contract(tmp_path_factory: pytest.TempPathFactory) -> ContractSet:
    global CONTRACT_ROOT
    root = tmp_path_factory.mktemp("reviewed-contract")
    shutil.copytree(PACKAGE_ROOT / "schemas", root / "schemas")
    shutil.copytree(PACKAGE_ROOT / "policies", root / "policies")
    policy_path = root / "policies/holoagent0-trace-tool-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    row = policy["rows"][0]
    row["build"].update(
        recipe_sha256="1" * 64,
        container_image_digest="sha256:" + "2" * 64,
        review_state="REVIEWED",
    )
    row["runtime"].update(
        elf_size=1,
        elf_sha256="3" * 64,
        version_output_sha256="4" * 64,
        review_state="REVIEWED",
    )
    row["parser"].update(sha256="5" * 64, review_state="REVIEWED")
    row["argv"].update(canonical_sha256="6" * 64, review_state="REVIEWED")
    row["fixtures"].update(manifest_sha256="7" * 64, review_state="REVIEWED")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    CONTRACT_ROOT = root
    return ContractSet(root)


@pytest.fixture
def offline_pass_result() -> dict[str, object]:
    return make_pass_result("workstation_offline")


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_each_profile_passes_its_closed_contract(contract: ContractSet, mode: str):
    decision = contract.validate_result(make_pass_result(mode))
    assert decision.ok, decision.errors
    assert decision.code == "OK"


def test_wrong_mode_label_is_rejected(contract, offline_pass_result):
    offline_pass_result["label"] = "FAIL_PC2_STREAMS"
    assert (
        contract.validate_result(offline_pass_result).code == "EVIDENCE_SCHEMA_INVALID"
    )


def test_unknown_reason_is_rejected(contract, offline_pass_result):
    offline_pass_result["gates"][0]["reason"] = "LOCAL_REASON"
    assert (
        contract.validate_result(offline_pass_result).code == "EVIDENCE_SCHEMA_INVALID"
    )


def test_trace_tool_policy_has_one_exact_row(contract):
    row = contract.trace_tool_rows()
    assert len(row) == 1
    assert row[0]["version"] == "6.6"
    assert row[0]["source"]["size"] == 2420364
    assert row[0]["source"]["sha256"] == (
        "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
    )


def test_policy_artifacts_have_versioned_ids_and_closed_roots(contract: ContractSet):
    assert {name: policy["$id"] for name, policy in contract.policies.items()} == {
        "holoagent0-gate-policy-v1": "holoagent0.gate-policy.v1",
        "holoagent0-reason-codes-v1": "holoagent0.reason-codes.v1",
        "holoagent0-trace-tool-v1": "holoagent0.trace-tool-policy.v1",
    }
    assert all(
        policy["additionalProperties"] is False for policy in contract.policies.values()
    )


@pytest.mark.parametrize(
    ("mode", "field"),
    (
        ("workstation_offline", "offline_evidence"),
        ("workstation_offline", "offline_evidence_bundle_sha256"),
        ("workstation_mujoco", "offline_reference_evidence_bundle_sha256"),
        ("pc2_inventory", "pc2_evidence"),
        ("pc2_camera", "pc2_evidence"),
        ("pc2_full_streams", "pc2_evidence"),
    ),
)
def test_mode_specific_evidence_is_required(
    contract: ContractSet, mode: str, field: str
):
    value = make_pass_result(mode)
    value.pop(field)
    assert not contract.validate_result(value).ok


def test_offline_bundle_digest_must_bind_the_descriptor_set(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["bundle_sha256"] = "b" * 64
    assert not contract.validate_result(value).ok


def test_pc2_rejects_workstation_only_digest_fields(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value["trace_tool_policy_sha256"] = SHA256
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_later_action_gate_cannot_pass_after_a_block(contract: ContractSet, mode: str):
    value = make_pass_result(mode)
    first_gate = value["gates"][0]
    first_gate.update(status="FAIL", reason="SOURCE_MISMATCH")
    value.update(
        label="FAIL_SOURCE",
        status="FAIL",
        exit_class="GATE_FAILURE",
        process_exit_code=20,
        primary_blocking_gate="source.repository",
        blocking_gates=["source.repository"],
    )
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize(
    ("reason", "top_status"),
    (("EARLIER_BLOCKING_GATE", "PASS"), ("INTERRUPTED_BEFORE_GATE", "PASS")),
)
def test_not_run_requires_its_claimed_control_flow_context(
    contract: ContractSet, reason: str, top_status: str
):
    value = make_pass_result("pc2_inventory")
    value["gates"][6].update(status="NOT_RUN", reason=reason)
    value["status"] = top_status
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_each_profile_accepts_a_closed_source_failure(contract: ContractSet, mode: str):
    value = make_pass_result(mode)
    value["gates"][0].update(status="FAIL", reason="SOURCE_MISMATCH")
    for gate in value["gates"][1:]:
        if gate["role"] != "finalizer":
            gate.update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    value.update(
        label="FAIL_SOURCE",
        status="FAIL",
        exit_class="GATE_FAILURE",
        process_exit_code=20,
        primary_blocking_gate="source.repository",
        blocking_gates=["source.repository"],
    )
    decision = contract.validate_result(value)
    assert decision.ok, decision.errors


@pytest.mark.parametrize(
    ("mode", "gate_id", "reason", "label"),
    (
        (
            "workstation_offline",
            "chatbot.credentials",
            "CREDENTIALS_MISSING",
            "READY_CREDENTIALS_REQUIRED",
        ),
        (
            "workstation_mujoco",
            "mujoco.stage3",
            "ESTIMATOR_THRESHOLD_FAILED",
            "READY_MUJOCO_STAGE4_ESTIMATOR_FAILED",
        ),
    ),
)
def test_closed_qualification_outcomes_are_accepted(
    contract: ContractSet, mode: str, gate_id: str, reason: str, label: str
):
    value = make_pass_result(mode)
    gate = next(gate for gate in value["gates"] if gate["id"] == gate_id)
    gate.update(status="QUALIFIED", reason=reason)
    value.update(
        label=label,
        status="QUALIFIED",
        exit_class="QUALIFIED",
        process_exit_code=10,
        qualifications=[gate_id],
    )
    decision = contract.validate_result(value)
    assert decision.ok, decision.errors


def test_diagnostic_failure_does_not_block_inventory_pass(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    advertisement = next(
        gate for gate in value["gates"] if gate["id"] == "pc2.lidar_advertisement"
    )
    advertisement.update(status="FAIL", reason="TOPIC_NOT_ADVERTISED")
    for gate_id in ("pc2.lidar_sample", "pc2.lidar_rate", "pc2.lidar_schema"):
        gate = next(gate for gate in value["gates"] if gate["id"] == gate_id)
        gate.update(status="SKIPPED", reason="DEPENDENCY_NOT_AVAILABLE")
    decision = contract.validate_result(value)
    assert decision.ok, decision.errors


def _copy_contract(tmp_path: Path) -> Path:
    root = tmp_path / "contract"
    shutil.copytree(PACKAGE_ROOT / "schemas", root / "schemas")
    shutil.copytree(PACKAGE_ROOT / "policies", root / "policies")
    return root


def test_schema_invalid_unhashable_status_returns_a_decision(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value["gates"][0]["status"] = []
    decision = contract.validate_result(value)
    assert not decision.ok
    assert decision.code == "EVIDENCE_SCHEMA_INVALID"


def test_required_full_stream_gate_cannot_use_diagnostic_skip(contract: ContractSet):
    value = make_pass_result("pc2_full_streams")
    gate = next(g for g in value["gates"] if g["id"] == "pc2.lidar_sample")
    gate.update(status="SKIPPED", reason="DEPENDENCY_NOT_AVAILABLE")
    assert not contract.validate_result(value).ok


def test_network_policy_cannot_skip_when_trace_integrity_passes(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    gate = next(g for g in value["gates"] if g["id"] == "offline.network_policy")
    gate.update(status="SKIPPED", reason="DEPENDENCY_NOT_AVAILABLE")
    assert not contract.validate_result(value).ok


def test_result_digests_are_bound_to_loaded_contract_files(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["gate_policy_sha256"] = SHA256
    assert not contract.validate_result(value).ok


def test_non_finite_measurement_is_not_json_evidence(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value["duration_monotonic_seconds"] = float("nan")
    assert not contract.validate_result(value).ok


def test_public_policy_mutation_does_not_change_validation(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value["gates"][0]["reason"] = "DIGEST_MISMATCH"
    contract.policies["holoagent0-reason-codes-v1"]["gate_status_reasons"][
        "source.repository"
    ]["PASS"].append("DIGEST_MISMATCH")
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize(
    "target",
    (
        "policy_extra",
        "schema_keyword",
        "schema_shape",
        "additional_schema",
        "non_json_number",
        "precedence",
        "tuple_shape",
        "outcome_shape",
        "harness_shape",
    ),
)
def test_contract_metadata_tampering_fails_closed(tmp_path: Path, target: str):
    root = _copy_contract(tmp_path)
    if target in {
        "schema_keyword",
        "schema_shape",
        "additional_schema",
        "non_json_number",
    }:
        path = root / (
            "schemas/holoagent0-result-v1.schema.json"
            if target != "schema_shape"
            else "schemas/agentos-plan-v1.schema.json"
        )
        value = json.loads(path.read_text(encoding="utf-8"))
        if target == "schema_keyword":
            value["minProperties"] = 999
        elif target == "schema_shape":
            value["required"] = "not-a-list"
        elif target == "additional_schema":
            value["additionalProperties"] = {}
        else:
            value["minimum"] = float("nan")
    else:
        path = root / "policies/holoagent0-gate-policy-v1.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        if target == "policy_extra":
            value["rogue_unreviewed_rule"] = True
        elif target == "precedence":
            value["precedence"] = list(reversed(value["precedence"]))
        elif target == "tuple_shape":
            value["label_tuples"][0]["labels"] = 1
        elif target == "outcome_shape":
            value["non_failure_outcomes"]["pc2_inventory"] = []
        else:
            value["harness_gates"] = 1
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ContractLoadError):
        ContractSet(root)


def test_interrupted_result_requires_an_interrupted_gate_marker(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value.update(
        label="INTERRUPTED",
        status="INTERRUPTED",
        exit_class="INT",
        process_exit_code=130,
    )
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize("mutation", ("null_window", "empty_samples"))
def test_pc2_pass_requires_complete_action_window_evidence(
    contract: ContractSet, mutation: str
):
    value = make_pass_result("pc2_inventory")
    if mutation == "null_window":
        value["pc2_evidence"]["action_window_started_at"] = None
    else:
        value["pc2_evidence"]["monitor_samples"] = []
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_result_timestamps_cannot_be_reversed(contract: ContractSet, mode: str):
    value = make_pass_result(mode)
    value["started_at"] = "2026-08-05T00:00:02Z"
    assert not contract.validate_result(value).ok


def test_agentos_plan_semantics_are_closed(contract: ContractSet):
    plan = {
        "schema_version": "holoagent.agentos.plan.v1",
        "mode": "single_robot",
        "description": "test",
        "nodes": [
            {
                "id": "first",
                "robot_id": 11,
                "skill": "navigation",
                "target": "stop",
                "depends_on": [],
            },
            {
                "id": "second",
                "robot_id": 11,
                "skill": "arm",
                "target": "high_five",
                "depends_on": ["first"],
            },
        ],
    }
    assert contract.validate_document("agentos-plan-v1", plan).ok
    plan["nodes"][1]["id"] = "first"
    assert not contract.validate_document("agentos-plan-v1", plan).ok
    plan["nodes"][1]["id"] = "second"
    plan["nodes"][1]["depends_on"] = ["missing"]
    assert not contract.validate_document("agentos-plan-v1", plan).ok


def test_generic_dispatch_cannot_bypass_result_policy(contract: ContractSet):
    value = make_pass_result("pc2_inventory")
    value["gates"][0]["reason"] = "DIGEST_MISMATCH"
    assert not contract.validate_document("holoagent0-result-v1", value).ok


def test_agentos_schema_digest_is_bound_when_reported(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["agentos_plan_schema_sha256"] = SHA256
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize(
    ("mode", "field"),
    (
        ("workstation_offline", "agentos_plan_schema_sha256"),
        ("workstation_mujoco", "checkpoint_sha256"),
        ("pc2_inventory", "script_sha256"),
    ),
)
def test_relevant_mode_digest_is_required(contract: ContractSet, mode: str, field: str):
    value = make_pass_result(mode)
    value.pop(field)
    assert not contract.validate_result(value).ok


def test_pending_trace_authorization_cannot_claim_readiness(contract: ContractSet):
    pending = ContractSet(PACKAGE_ROOT)
    decision = pending.validate_result(make_pass_result("workstation_offline"))
    assert not decision.ok
    assert any("not reviewed for readiness" in error for error in decision.errors)


def test_offline_ledger_uses_closed_reason_contexts(contract: ContractSet):
    gates = [
        _gate(gate_id, role) for gate_id, role in PROFILE_GATES["workstation_offline"]
    ]
    gates[0]["reason"] = "ARBITRARY_BUT_LENGTH_OK"
    ledger = {
        "schema_version": "holoagent0.offline-ledger.v1",
        "run_id": "run-001",
        "ledger_nonce": "c" * 64,
        "generation": 0,
        "previous_generation": None,
        "previous_digest": None,
        "sealed": False,
        "semantic_dds_window": "NOT_ENTERED",
        "gates": gates,
    }
    assert not contract.validate_document("holoagent0-offline-ledger-v1", ledger).ok


@pytest.mark.parametrize(
    "mutation",
    (
        "control_violation",
        "reversed_window",
        "monitor_skip",
        "cleanup_skip",
        "camera_observation",
        "missing_owned_camera",
    ),
)
def test_pc2_cross_field_state_machine_rejects_contradictions(
    contract: ContractSet, mutation: str
):
    mode = (
        "pc2_camera"
        if mutation in {"cleanup_skip", "camera_observation", "missing_owned_camera"}
        else "pc2_inventory"
    )
    value = make_pass_result(mode)
    if mutation == "control_violation":
        value["pc2_evidence"]["monitor_samples"][0]["state"] = "CONTROL_VIOLATION"
    elif mutation == "reversed_window":
        value["pc2_evidence"]["action_window_started_at"] = "2026-08-05T00:00:02Z"
    elif mutation == "monitor_skip":
        gate = next(
            g for g in value["gates"] if g["id"] == "safety.pc2_runtime_monitor"
        )
        gate.update(status="SKIPPED", reason="MONITOR_NOT_STARTED")
    elif mutation == "cleanup_skip":
        gate = next(g for g in value["gates"] if g["id"] == "pc2.camera_cleanup")
        gate.update(status="SKIPPED", reason="NO_OWNED_CAMERA")
    elif mutation == "camera_observation":
        value["pc2_evidence"]["monitor_samples"][0]["state"] = "OBSERVATION_ONLY"
    else:
        value["pc2_evidence"]["owned_processes"] = []
    assert not contract.validate_result(value).ok


def test_closed_dds_window_requires_ordered_marker_indices(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["semantic_dds_window"] = "CLOSED"
    assert not contract.validate_result(value).ok


def test_openclaw_schema_contains_exact_reviewed_pins(contract: ContractSet):
    definitions = contract.schemas["openclaw-provisioning-v1"]["$defs"]
    pins = definitions["pins"]["properties"]
    assert pins["package_version"]["const"] == "2026.7.1-2"
    assert pins["node_version"]["const"] == "24.15.0"
    assert pins["installer_sha256"]["const"] == (
        "21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1"
    )
    assert definitions["dist"]["properties"]["integrity"]["const"].startswith(
        "sha512-ycF3yPcb"
    )


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_profile_rejects_another_modes_pass_label(contract: ContractSet, mode: str):
    value = make_pass_result(mode)
    value["label"] = PASS_LABELS[
        "pc2_inventory" if mode != "pc2_inventory" else "pc2_camera"
    ]
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize(
    ("status", "exit_class", "process_exit_code"),
    (("PASS", "QUALIFIED", 0), ("QUALIFIED", "PASS", 10), ("FAIL", "PASS", 20)),
)
def test_invalid_top_level_status_exit_tuple_is_rejected(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    status: str,
    exit_class: str,
    process_exit_code: int,
):
    offline_pass_result.update(
        status=status,
        exit_class=exit_class,
        process_exit_code=process_exit_code,
    )
    assert not contract.validate_result(offline_pass_result).ok


@pytest.mark.parametrize(
    "mutation", ("unknown", "duplicate", "out_of_order", "missing")
)
def test_invalid_gate_catalog_or_order_is_rejected(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    mutation: str,
):
    gates = offline_pass_result["gates"]
    if mutation == "unknown":
        gates[0]["id"] = "local.gate"
    elif mutation == "duplicate":
        gates[1] = copy.deepcopy(gates[0])
    elif mutation == "out_of_order":
        gates[0], gates[1] = gates[1], gates[0]
    else:
        gates.pop()
    assert not contract.validate_result(offline_pass_result).ok


def test_wrong_gate_role_is_rejected(contract: ContractSet, offline_pass_result):
    offline_pass_result["gates"][0]["role"] = "diagnostic"
    assert not contract.validate_result(offline_pass_result).ok


@pytest.mark.parametrize(
    ("gate_id", "status", "reason"),
    (
        ("source.repository", "QUALIFIED", "OK"),
        ("chatbot.credentials", "FAIL", "CREDENTIALS_MISSING"),
        ("semantic.natural_language_parser", "SKIPPED", "NO_OWNED_CAMERA"),
        ("offline.trace_integrity", "SKIPPED", "DEPENDENCY_NOT_AVAILABLE"),
    ),
)
def test_invalid_status_or_reason_context_is_rejected(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    gate_id: str,
    status: str,
    reason: str,
):
    gate = next(gate for gate in offline_pass_result["gates"] if gate["id"] == gate_id)
    gate.update(status=status, reason=reason)
    assert not contract.validate_result(offline_pass_result).ok


def test_qualification_selectors_must_match_qualified_gates(
    contract: ContractSet, offline_pass_result: dict[str, object]
):
    credentials = next(
        gate
        for gate in offline_pass_result["gates"]
        if gate["id"] == "chatbot.credentials"
    )
    credentials.update(status="QUALIFIED", reason="CREDENTIALS_MISSING")
    offline_pass_result.update(
        label="READY_CREDENTIALS_REQUIRED",
        status="QUALIFIED",
        exit_class="QUALIFIED",
        process_exit_code=10,
        qualifications=["chatbot.audio_hardware"],
    )
    assert not contract.validate_result(offline_pass_result).ok


def test_blocking_selectors_must_match_failures_and_precedence(contract: ContractSet):
    value = make_pass_result("pc2_camera")
    camera_rate = next(g for g in value["gates"] if g["id"] == "pc2.camera_rate")
    camera_rate.update(status="FAIL", reason="RATE_BELOW_THRESHOLD")
    cleanup = next(g for g in value["gates"] if g["id"] == "pc2.camera_cleanup")
    cleanup.update(status="FAIL", reason="CLEANUP_INCOMPLETE")
    value.update(
        label="FAIL_SAFETY",
        status="FAIL",
        exit_class="SAFETY_FAILURE",
        process_exit_code=30,
        blocking_gates=["pc2.camera_rate", "pc2.camera_cleanup"],
        primary_blocking_gate="pc2.camera_rate",
    )
    assert not contract.validate_result(value).ok


@pytest.mark.parametrize(
    ("role", "parent_run_id", "lineage_nonce"),
    (
        ("child", None, "c" * 64),
        ("child", "parent-001", None),
        ("standalone", "parent-001", None),
        ("standalone", None, "c" * 64),
    ),
)
def test_child_lineage_nullability_is_closed(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    role: str,
    parent_run_id: str | None,
    lineage_nonce: str | None,
):
    offline_pass_result.update(
        invocation_role=role,
        parent_run_id=parent_run_id,
        lineage_nonce=lineage_nonce,
    )
    assert not contract.validate_result(offline_pass_result).ok


@pytest.mark.parametrize(
    ("gate_id", "wrong_reason"),
    (
        ("safety.workstation_preflight", "PROHIBITED_IO_URING"),
        ("offline.network_policy", "TRACE_INCOMPLETE"),
        ("offline.trace_integrity", "EVIDENCE_BINDING_MISMATCH"),
        ("offline.evidence_binding", "LEDGER_CHAIN_INVALID"),
        ("safety.workstation_postflight", "INHERITED_SOCKET_FD"),
    ),
)
def test_supervisor_reason_codes_are_rejected_cross_gate(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    gate_id: str,
    wrong_reason: str,
):
    gate = next(g for g in offline_pass_result["gates"] if g["id"] == gate_id)
    gate.update(status="FAIL", reason=wrong_reason)
    assert not contract.validate_result(offline_pass_result).ok


@pytest.mark.parametrize("location", ("top", "gate"))
def test_result_schema_rejects_additional_properties(
    contract: ContractSet,
    offline_pass_result: dict[str, object],
    location: str,
):
    if location == "top":
        offline_pass_result["local_extension"] = True
    else:
        offline_pass_result["gates"][0]["local_extension"] = True
    assert not contract.validate_result(offline_pass_result).ok


def test_require_valid_result_raises_dedicated_error(
    contract: ContractSet, offline_pass_result: dict[str, object]
):
    offline_pass_result["mode"] = "local"
    with pytest.raises(ContractError) as error:
        contract.require_valid_result(offline_pass_result)
    assert error.value.decision.code == "EVIDENCE_SCHEMA_INVALID"


def test_all_schema_object_nodes_are_closed(contract: ContractSet):
    def check(node: object, path: str = "$") -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, path
            for key, child in node.items():
                check(child, f"{path}.{key}")
        elif isinstance(node, list):
            for index, child in enumerate(node):
                check(child, f"{path}[{index}]")

    for name, schema in contract.schemas.items():
        check(schema, name)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("version",), "6.7"),
        (("source", "size"), 1),
        (("source", "sha256"), "0" * 64),
        (("argv", "environment", "LC_ALL"), "en_US.UTF-8"),
        (("argv", "options", 0), "-f"),
        (("argv", "raw_syscalls", 0), "recvfrom"),
        (("runtime", "review_state"), "REVIEWED"),
    ),
)
def test_trace_policy_pin_mutations_fail_closed(
    tmp_path: Path, path: tuple[str | int, ...], replacement: object
):
    root = _copy_contract(tmp_path)
    policy_path = root / "policies/holoagent0-trace-tool-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    target = policy["rows"][0]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    with pytest.raises(ContractLoadError, match="trace tool policy"):
        ContractSet(root)
