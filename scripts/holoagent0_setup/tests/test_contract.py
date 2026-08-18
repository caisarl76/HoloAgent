import copy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from holoagent0_setup.contract import ContractError, ContractLoadError, ContractSet
from holoagent0_setup.atomic_io import canonical_json_bytes
from holoagent0_setup.result_policy import ResultPolicy, ResultPolicyError


PACKAGE_ROOT = Path(__file__).parents[1]
CONTRACT_ROOT = PACKAGE_ROOT
SHA256 = "a" * 64
GIT_SHA = "b" * 40
FSRVLN_SCHEMA_IDS = {
    "fsrvln-environment-v1": "holoagent0.fsrvln.environment.v1",
    "fsrvln-source-verification-v1": "holoagent0.fsrvln.source-verification.v1",
    "fsrvln-asset-verification-v1": "holoagent0.fsrvln.asset-verification.v1",
    "fsrvln-query-result-v1": "holoagent0.fsrvln.query-result.v1",
    "fsrvln-handover-result-v1": "holoagent0.fsrvln.handover-result.v1",
}
EVIDENCE_IDENTITY = {
    "pid": 801,
    "pgid": 801,
    "start_time": 8010,
    "executable_path": "/bin/true",
    "executable_sha256": f"{801:064x}",
}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_identity(path: str) -> dict[str, object]:
    return {"path": path, "device": 1, "inode": 2, "mode": 16877}


def _fsrvln_stage(schema_version: str) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "status": "PASS",
        "reason": "OK",
        "started_at": "2026-08-18T00:00:00Z",
        "finished_at": "2026-08-18T00:00:01Z",
    }


def _fsrvln_documents() -> dict[str, dict[str, object]]:
    environment = {
        **_fsrvln_stage(FSRVLN_SCHEMA_IDS["fsrvln-environment-v1"]),
        "os_release": "Linux-6.8.0",
        "machine_architecture": "x86_64",
        "python": {"executable": "/usr/bin/python3.10", "version": "3.10.12"},
        "accelerator": {
            "label": "CPU",
            "torch_cuda_build": None,
            "cuda_available": False,
        },
        "imports": [
            {
                "name": "pytorch",
                "module": "torch",
                "status": "PASS",
                "version": "2.7.1",
                "origin": "/opt/python/torch/__init__.py",
                "reason": "OK",
            }
        ],
        "graph_module_origin": "/checkout/fsr_vln/memory/hmsg/graph/graph.py",
    }
    source = {
        **_fsrvln_stage(FSRVLN_SCHEMA_IDS["fsrvln-source-verification-v1"]),
        "repository_root": _path_identity("/checkout"),
        "checkout_commit": GIT_SHA,
        "source_lock_commit": "c" * 40,
        "verified_count": 73,
        "provenance": [{"commit": GIT_SHA, "count": 73}],
    }
    asset = {
        **_fsrvln_stage(FSRVLN_SCHEMA_IDS["fsrvln-asset-verification-v1"]),
        "data_root": _path_identity("/data"),
        "asset_lock_sha256": SHA256,
        "assets": [
            {
                "role": "graph",
                "path": "/data/fsr_vln/graph",
                "device": 1,
                "inode": 3,
                "file_count": 4,
                "byte_count": 5,
                "sha256": "d" * 64,
            }
        ],
    }
    query = {
        **_fsrvln_stage(FSRVLN_SCHEMA_IDS["fsrvln-query-result-v1"]),
        "query_sha256": "e" * 64,
        "execution_count": 1,
        "result": {
            "graph_counts": {"floors": 1, "rooms": 3, "objects": 497},
            "graph_identity": "icra_ic4f/graph_20260629211448",
            "floor_id": "0",
            "room": {"id": "0_0", "name": "Pantry"},
            "object": {"id": "0_0_81", "name": "counter"},
            "frame_id": "map",
            "position": [-21.5, -15.6, -0.2],
            "orientation": [0.0, 0.0, 0.0, 1.0],
            "structured_query_sha256": "e" * 64,
            "graph_root_sha256": "f" * 64,
            "dataset_root_sha256": "1" * 64,
            "checkpoint_sha256": "2" * 64,
            "room_name_mapping_sha256": "3" * 64,
        },
    }
    evidence_names = (
        "environment.json",
        "source-verification.json",
        "asset-verification.json",
        "query-result.json",
    )
    terminal = {
        **_fsrvln_stage(FSRVLN_SCHEMA_IDS["fsrvln-handover-result-v1"]),
        "accepted_implementation_commit": GIT_SHA,
        "repository_root": _path_identity("/checkout"),
        "data_root": _path_identity("/data"),
        "run_directory": _path_identity("/run"),
        "cpu_gpu_label": "CPU",
        "evidence_files": [
            {"name": name, "sha256": f"{index:064x}", "size": index}
            for index, name in enumerate(evidence_names, start=1)
        ],
        "bundle_sha256": "4" * 64,
        "first_blocking_reason": None,
        "terminal_filename": "handover-result.json",
    }
    return {
        "fsrvln-environment-v1": environment,
        "fsrvln-source-verification-v1": source,
        "fsrvln-asset-verification-v1": asset,
        "fsrvln-query-result-v1": query,
        "fsrvln-handover-result-v1": terminal,
    }


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


def _bootstrap_descriptor(artifact: dict[str, object]) -> dict[str, object]:
    ready_request = {
        "type": "SIGNAL_READY",
        "run_nonce": "c" * 64,
        "sequence": 1,
        "identity": copy.deepcopy(EVIDENCE_IDENTITY),
        "blocked_signals": ["HUP", "INT", "TERM"],
        "dispositions": {"HUP": True, "INT": True, "TERM": True},
    }
    ready_sha256 = hashlib.sha256(canonical_json_bytes(ready_request)).hexdigest()
    accepted_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                "type": "SIGNAL_READY_ACCEPTED",
                "run_nonce": "c" * 64,
                "identity": copy.deepcopy(EVIDENCE_IDENTITY),
                "request_sequence": 1,
                "request_sha256": ready_sha256,
            }
        )
    ).hexdigest()
    return {
        **copy.deepcopy(artifact),
        "terminal_launch_state": "COORDINATOR_LAUNCH_COMMITTED",
        "coordinator_launch_committed": True,
        "first_signal": None,
        "handoff": {
            "event_sequence": [
                {"sequence": 0, "state": "AWAITING_READY"},
                {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
                {"sequence": 2, "state": "READY"},
            ],
            "terminal_state": "READY",
            "signal_ready_identity": copy.deepcopy(EVIDENCE_IDENTITY),
            "signal_ready_sequence": 1,
            "signal_ready_sha256": ready_sha256,
            "signal_ready_accepted_sequence": 1,
            "signal_ready_accepted_sha256": accepted_sha256,
            "inherited_mask": ["HUP", "INT", "TERM"],
            "unblocked_mask": ["HUP", "INT", "TERM"],
            "pending_signal": None,
            "acceptance_count": 1,
            "forward_target_pgid": None,
            "forward_count": 0,
            "unblock_trace_record_index": 0,
            "first_functional_trace_record_index": 1,
        },
        "toolchain": {
            "expected": [{"name": "strace_version", "value": "6.6"}],
            "observed": [{"name": "strace_version", "value": "6.6"}],
        },
        "initial_fd_manifest": [],
        "final_fd_manifest": [],
        "sanitation_actions": [],
        "rebinding_actions": [],
        "live_fixture_passed": True,
    }


def _host_descriptor(artifact: dict[str, object]) -> dict[str, object]:
    return {
        **copy.deepcopy(artifact),
        "state": "OBSERVED",
        "collector_identity": copy.deepcopy(EVIDENCE_IDENTITY),
        "network_namespace_inode": 81,
        "process_count": 1,
        "service_count": 0,
        "listener_count": 0,
        "internet_socket_attempt_count": 0,
        "observation_sha256": SHA256,
        "trusted_inspection": {
            "gateway_status_command": [
                "/opt/openclaw/bin/openclaw",
                "gateway",
                "status",
                "--deep",
                "--no-probe",
                "--json",
            ],
            "gateway_status_exit": 0,
            "gateway_status_sha256": SHA256,
            "gateway_status_state": "INACTIVE",
            "service_definitions": [],
            "listener_command": ["/usr/bin/ss", "-H", "-ltnp"],
            "listener_inventory": [],
        },
        "cause_gate": None,
        "reason": None,
    }


def _refresh_offline_bundle(
    value: dict[str, object], *, refresh_ledger_state: bool = True
) -> None:
    if refresh_ledger_state:
        value["offline_evidence"]["ledger_chain_manifest"][
            "accepted_action_state_sha256"
        ] = hashlib.sha256(
            canonical_json_bytes(
                {
                    "gates": value["gates"][:24],
                    "semantic_dds_window": value["offline_evidence"][
                        "semantic_dds_window"
                    ],
                }
            )
        ).hexdigest()
    descriptor_tree = copy.deepcopy(value["offline_evidence"])
    descriptor_tree.pop("bundle_sha256", None)
    bundle_sha256 = hashlib.sha256(canonical_json_bytes(descriptor_tree)).hexdigest()
    value["offline_evidence"]["bundle_sha256"] = bundle_sha256
    value["offline_evidence_bundle_sha256"] = bundle_sha256


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
            "trace": {
                **copy.deepcopy(artifact),
                "trace_state": "FULL",
                "serialized_record_count": 3,
                "tracee_count": 2,
                "tracer_identity": copy.deepcopy(EVIDENCE_IDENTITY),
                "normalizer_identity": copy.deepcopy(EVIDENCE_IDENTITY),
                "tracer_exit_code": 0,
                "normalizer_exit_code": 0,
                "tool_policy_row_sha256": SHA256,
                "compatibility_fixture_passed": True,
                "not_started_reason": None,
            },
            "bootstrap_report": _bootstrap_descriptor(artifact),
            "ledger_chain_manifest": {
                **copy.deepcopy(artifact),
                "accepted_generation": 1,
                "accepted_sha256": SHA256,
                "immutable_generation_count": 2,
                "accepted_action_state_sha256": SHA256,
            },
            "ownership_journal": {
                **copy.deepcopy(artifact),
                "record_count": 0,
                "head_record_sha256": None,
            },
            "violation_journal": {
                **copy.deepcopy(artifact),
                "violation_count": 0,
                "head_record_sha256": None,
            },
            "host_observer_pre": _host_descriptor(artifact),
            "host_observer_post": _host_descriptor(artifact),
            "semantic_dds_window": "CLOSED",
            "dds_begin_record_index": 0,
            "dds_end_record_index": 2,
            "marker_token": "holoagent0-dds-window-v1",
            "bundle_sha256": SHA256,
        }
        value["offline_evidence"]["ledger_chain_manifest"][
            "accepted_action_state_sha256"
        ] = hashlib.sha256(
            canonical_json_bytes(
                {
                    "gates": value["gates"][:24],
                    "semantic_dds_window": value["offline_evidence"][
                        "semantic_dds_window"
                    ],
                }
            )
        ).hexdigest()
        _refresh_offline_bundle(value)
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


def test_fsrvln_schema_inventory_has_exact_registered_ids(contract: ContractSet):
    assert {
        name: contract.schemas[name]["$id"] for name in FSRVLN_SCHEMA_IDS
    } == FSRVLN_SCHEMA_IDS


@pytest.mark.parametrize("schema_name", tuple(FSRVLN_SCHEMA_IDS))
def test_fsrvln_minimal_documents_validate(contract: ContractSet, schema_name: str):
    decision = contract.validate_document(schema_name, _fsrvln_documents()[schema_name])
    assert decision.ok, decision.errors


@pytest.mark.parametrize("schema_name", tuple(FSRVLN_SCHEMA_IDS))
def test_fsrvln_schemas_reject_unknown_top_level_fields(
    contract: ContractSet, schema_name: str
):
    document = _fsrvln_documents()[schema_name]
    document["local_extension"] = True

    decision = contract.validate_document(schema_name, document)

    assert decision.code == "EVIDENCE_SCHEMA_INVALID"
    assert not decision.ok


@pytest.mark.parametrize(
    ("schema_name", "nested_path", "field"),
    (
        ("fsrvln-environment-v1", ("python",), "executable"),
        ("fsrvln-source-verification-v1", ("repository_root",), "inode"),
        ("fsrvln-asset-verification-v1", ("assets", 0), "file_count"),
        ("fsrvln-query-result-v1", ("result", "room"), "name"),
        ("fsrvln-handover-result-v1", ("evidence_files", 0), "sha256"),
    ),
)
def test_fsrvln_schemas_require_nested_fields(
    contract: ContractSet,
    schema_name: str,
    nested_path: tuple[str | int, ...],
    field: str,
):
    document = _fsrvln_documents()[schema_name]
    target = document
    for part in nested_path:
        target = target[part]
    target.pop(field)

    decision = contract.validate_document(schema_name, document)

    assert decision.code == "EVIDENCE_SCHEMA_INVALID"
    assert not decision.ok


@pytest.mark.parametrize(
    ("schema_name", "nested_path", "field", "replacement"),
    (
        ("fsrvln-environment-v1", ("accelerator",), "cuda_available", "false"),
        ("fsrvln-source-verification-v1", ("provenance", 0), "count", 1.5),
        ("fsrvln-asset-verification-v1", ("assets", 0), "byte_count", -1),
        ("fsrvln-query-result-v1", ("result", "object"), "id", 81),
        ("fsrvln-handover-result-v1", ("run_directory",), "device", -1),
    ),
)
def test_fsrvln_schemas_reject_nested_type_and_range_mutations(
    contract: ContractSet,
    schema_name: str,
    nested_path: tuple[str | int, ...],
    field: str,
    replacement: object,
):
    document = _fsrvln_documents()[schema_name]
    target = document
    for part in nested_path:
        target = target[part]
    target[field] = replacement

    decision = contract.validate_document(schema_name, document)

    assert decision.code == "EVIDENCE_SCHEMA_INVALID"
    assert not decision.ok


@pytest.mark.parametrize(
    "mutation",
    ("missing", "extra", "out_of_order", "wrong_name", "terminal_name"),
)
def test_fsrvln_terminal_requires_exact_evidence_filenames_and_order(
    contract: ContractSet, mutation: str
):
    document = _fsrvln_documents()["fsrvln-handover-result-v1"]
    if mutation == "missing":
        document["evidence_files"].pop()
    elif mutation == "extra":
        document["evidence_files"].append(
            {"name": "extra.json", "sha256": SHA256, "size": 1}
        )
    elif mutation == "out_of_order":
        document["evidence_files"][0], document["evidence_files"][1] = (
            document["evidence_files"][1],
            document["evidence_files"][0],
        )
    elif mutation == "wrong_name":
        document["evidence_files"][0]["name"] = "local-environment.json"
    else:
        document["terminal_filename"] = "result.json"

    assert not contract.validate_document("fsrvln-handover-result-v1", document).ok


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("position", [0.0, 0.0]),
        ("position", [0.0, 0.0, 0.0, 0.0]),
        ("position", [0.0, float("inf"), 0.0]),
        ("orientation", [0.0, 0.0, 1.0]),
        ("orientation", [0.0, 0.0, 0.0, 1.0, 0.0]),
        ("orientation", [0.0, 0.0, float("nan"), 1.0]),
    ),
)
def test_fsrvln_query_vectors_have_exact_finite_cardinality(
    contract: ContractSet, field: str, replacement: list[float]
):
    document = _fsrvln_documents()["fsrvln-query-result-v1"]
    document["result"][field] = replacement

    assert not contract.validate_document("fsrvln-query-result-v1", document).ok


@pytest.mark.parametrize(
    ("schema_name", "field"),
    (
        ("fsrvln-environment-v1", "os_release"),
        ("fsrvln-environment-v1", "machine_architecture"),
        ("fsrvln-environment-v1", "python"),
        ("fsrvln-environment-v1", "accelerator"),
        ("fsrvln-environment-v1", "imports"),
        ("fsrvln-environment-v1", "graph_module_origin"),
        ("fsrvln-source-verification-v1", "checkout_commit"),
        ("fsrvln-source-verification-v1", "source_lock_commit"),
        ("fsrvln-source-verification-v1", "verified_count"),
        ("fsrvln-source-verification-v1", "provenance"),
        ("fsrvln-asset-verification-v1", "asset_lock_sha256"),
        ("fsrvln-asset-verification-v1", "assets"),
        ("fsrvln-query-result-v1", "result"),
    ),
)
def test_fsrvln_pass_requires_concrete_observations(
    contract: ContractSet, schema_name: str, field: str
):
    document = _fsrvln_documents()[schema_name]
    document[field] = None

    assert not contract.validate_document(schema_name, document).ok


@pytest.mark.parametrize(
    ("field", "replacement"), (("execution_count", 0), ("result", None))
)
def test_fsrvln_query_pass_requires_one_execution_and_result(
    contract: ContractSet, field: str, replacement: object
):
    document = _fsrvln_documents()["fsrvln-query-result-v1"]
    document[field] = replacement

    assert not contract.validate_document("fsrvln-query-result-v1", document).ok


@pytest.mark.parametrize("schema_name", tuple(FSRVLN_SCHEMA_IDS)[:-1])
def test_fsrvln_not_run_requires_absent_observations(
    contract: ContractSet, schema_name: str
):
    document = _fsrvln_documents()[schema_name]
    document["status"] = "NOT_RUN"

    assert not contract.validate_document(schema_name, document).ok


@pytest.mark.parametrize(
    ("schema_name", "null_fields", "updates"),
    (
        (
            "fsrvln-environment-v1",
            (
                "os_release",
                "machine_architecture",
                "python",
                "accelerator",
                "imports",
                "graph_module_origin",
            ),
            {},
        ),
        (
            "fsrvln-source-verification-v1",
            (
                "checkout_commit",
                "source_lock_commit",
                "verified_count",
                "provenance",
            ),
            {},
        ),
        (
            "fsrvln-asset-verification-v1",
            ("asset_lock_sha256", "assets"),
            {},
        ),
        (
            "fsrvln-query-result-v1",
            ("result",),
            {"execution_count": 0},
        ),
    ),
)
def test_fsrvln_not_run_accepts_explicit_null_observations(
    contract: ContractSet,
    schema_name: str,
    null_fields: tuple[str, ...],
    updates: dict[str, object],
):
    document = _fsrvln_documents()[schema_name]
    document["status"] = "NOT_RUN"
    document.update(updates)
    for field in null_fields:
        document[field] = None

    decision = contract.validate_document(schema_name, document)

    assert decision.ok, decision.errors


def test_fsrvln_terminal_does_not_accept_not_run(contract: ContractSet):
    terminal = _fsrvln_documents()["fsrvln-handover-result-v1"]
    terminal["status"] = "NOT_RUN"
    assert not contract.validate_document("fsrvln-handover-result-v1", terminal).ok


@pytest.mark.parametrize(
    ("schema_name", "path"),
    (
        ("fsrvln-source-verification-v1", ("checkout_commit",)),
        ("fsrvln-asset-verification-v1", ("asset_lock_sha256",)),
        ("fsrvln-query-result-v1", ("query_sha256",)),
        ("fsrvln-handover-result-v1", ("bundle_sha256",)),
    ),
)
@pytest.mark.parametrize("suffix", ("\n", "0"))
def test_fsrvln_digests_and_git_shas_reject_trailing_characters(
    contract: ContractSet,
    schema_name: str,
    path: tuple[str, ...],
    suffix: str,
):
    document = _fsrvln_documents()[schema_name]
    target = document
    for field in path[:-1]:
        target = target[field]
    target[path[-1]] += suffix

    assert not contract.validate_document(schema_name, document).ok


def test_fsrvln_digest_definitions_have_explicit_exact_lengths(contract: ContractSet):
    for name, schema in contract.schemas.items():
        if not name.startswith("fsrvln-"):
            continue
        for definition_name, definition in schema.get("$defs", {}).items():
            if definition_name == "sha256":
                assert definition["minLength"] == 64
                assert definition["maxLength"] == 64
            elif definition_name == "gitSha":
                assert definition["minLength"] == 40
                assert definition["maxLength"] == 40


@pytest.mark.parametrize(
    "timestamp",
    (
        "2026-08-18Z",
        "2026-08-18T00Z",
        "2026-08-18T00:00Z",
        "2026-08-18T00:00:00+00:00",
        "2026-08-18T00:00:00Z\n",
        "2026-02-30T00:00:00Z",
        "2026-08-18T24:00:00Z",
    ),
)
def test_fsrvln_timestamps_require_strict_utc_rfc3339_seconds(
    contract: ContractSet, timestamp: str
):
    document = _fsrvln_documents()["fsrvln-environment-v1"]
    document["started_at"] = timestamp

    assert not contract.validate_document("fsrvln-environment-v1", document).ok


@pytest.mark.parametrize(
    "timestamp", ("2026-08-18T00:00:00Z", "2026-08-18T00:00:00.123456Z")
)
def test_fsrvln_timestamps_accept_whole_or_fractional_utc_seconds(
    contract: ContractSet, timestamp: str
):
    document = _fsrvln_documents()["fsrvln-environment-v1"]
    document["started_at"] = timestamp

    decision = contract.validate_document("fsrvln-environment-v1", document)

    assert decision.ok, decision.errors


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


def test_offline_evidence_rejects_generic_record_count_and_invalid_trace_branch(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["bootstrap_report"]["record_count"] = 0
    assert not contract.validate_result(value).ok

    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["trace"]["tracer_exit_code"] = None
    _refresh_offline_bundle(value)
    assert not contract.validate_result(value).ok


def test_offline_evidence_cross_field_and_bundle_bindings_are_enforced(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["ledger_chain_manifest"]["immutable_generation_count"] = 7
    assert not contract.validate_result(value).ok

    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["host_observer_post"]["network_namespace_inode"] = 82
    assert not contract.validate_result(value).ok

    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["bootstrap_report"]["size"] = 2
    assert not contract.validate_result(value).ok


def test_offline_finalizer_gates_are_bound_to_evidence_state(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["violation_journal"]["violation_count"] = 1
    value["offline_evidence"]["violation_journal"]["head_record_sha256"] = SHA256
    _refresh_offline_bundle(value)
    decision = contract.validate_result(value)
    assert not decision.ok
    assert any("network_policy" in error for error in decision.errors)

    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["trace"]["tracer_exit_code"] = 42
    _refresh_offline_bundle(value)
    decision = contract.validate_result(value)
    assert not decision.ok
    assert any("trace_integrity" in error for error in decision.errors)


def test_truthful_started_trace_integrity_failure_is_schema_valid(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    trace = next(
        gate for gate in value["gates"] if gate["id"] == "offline.trace_integrity"
    )
    trace.update(status="FAIL", reason="TRACE_INCOMPLETE")
    network = next(
        gate for gate in value["gates"] if gate["id"] == "offline.network_policy"
    )
    network.update(status="SKIPPED", reason="DEPENDENCY_NOT_AVAILABLE")
    decision = ResultPolicy(contract).decide("workstation_offline", value["gates"])
    value.update(
        label=decision.label,
        status=decision.status,
        exit_class=decision.exit_class,
        process_exit_code=decision.exit_code,
        primary_blocking_gate=decision.primary,
        blocking_gates=list(decision.blocking_gates),
        qualifications=list(decision.qualifications),
    )
    _refresh_offline_bundle(value)

    validation = contract.validate_result(value)
    assert validation.ok, validation.errors


def test_signal_acceptance_sequence_must_bind_the_ready_request(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["bootstrap_report"]["handoff"][
        "signal_ready_accepted_sequence"
    ] = 999
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)
    assert not decision.ok
    assert any("handoff" in error or "sequence" in error for error in decision.errors)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("gateway_status_command", ["/bin/false", "--json"]),
        ("gateway_status_exit", 1),
        ("gateway_status_state", "ACTIVE"),
        ("service_definitions", ["z", "a"]),
        ("listener_command", ["/usr/bin/ss", "-ltn"]),
        ("listener_inventory", ["unexpected"]),
    ],
)
def test_result_contract_semantically_binds_trusted_host_inspection(
    contract: ContractSet, field, replacement
):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["host_observer_pre"]["trusted_inspection"][field] = (
        replacement
    )
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert not decision.ok
    assert any(
        "inspection" in error or "listener" in error for error in decision.errors
    )


def test_ready_handoff_allows_immediate_post_unblock_interruption(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    handoff = value["offline_evidence"]["bootstrap_report"]["handoff"]
    handoff.update(
        pending_signal="TERM",
        forward_target_pgid=EVIDENCE_IDENTITY["pgid"],
        forward_count=1,
        first_functional_trace_record_index=None,
    )
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert decision.ok, decision.errors


def test_ready_handoff_allows_bound_preacceptance_pending_forward(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    handoff = value["offline_evidence"]["bootstrap_report"]["handoff"]
    handoff.update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
            {"sequence": 2, "state": "PENDING_FORWARD"},
            {"sequence": 3, "state": "READY"},
        ],
        pending_signal="TERM",
        forward_target_pgid=EVIDENCE_IDENTITY["pgid"],
        forward_count=1,
        first_functional_trace_record_index=None,
    )
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert decision.ok, decision.errors


def test_ready_handoff_rejects_noncanonical_event_order(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    handoff = value["offline_evidence"]["bootstrap_report"]["handoff"]
    handoff["event_sequence"] = [
        {"sequence": 0, "state": "AWAITING_ACCEPTANCE"},
        {"sequence": 1, "state": "AWAITING_READY"},
        {"sequence": 2, "state": "READY"},
    ]
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert not decision.ok
    assert any("handoff" in error or "event" in error for error in decision.errors)


def test_failed_unaccepted_handoff_rejects_partial_ready_request(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    handoff = value["offline_evidence"]["bootstrap_report"]["handoff"]
    handoff.update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        signal_ready_sequence=None,
        signal_ready_sha256=None,
        signal_ready_accepted_sequence=None,
        signal_ready_accepted_sha256=None,
        unblocked_mask=[],
        acceptance_count=0,
        unblock_trace_record_index=None,
        first_functional_trace_record_index=None,
    )
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert not decision.ok
    assert any("handoff" in error or "request" in error for error in decision.errors)


def test_failed_accepted_handoff_requires_bound_unblock_and_forward_facts(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    handoff = value["offline_evidence"]["bootstrap_report"]["handoff"]
    handoff.update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
            {"sequence": 2, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        pending_signal="TERM",
        forward_target_pgid=999,
        forward_count=1,
        first_functional_trace_record_index=None,
    )
    _refresh_offline_bundle(value)

    decision = contract.validate_result(value)

    assert not decision.ok
    assert any("handoff" in error or "forward" in error for error in decision.errors)


def test_contract_exposes_closed_network_violation_reason_set(contract: ContractSet):
    reasons = contract.allowed_gate_reasons("offline.network_policy", "FAIL")

    assert "UNEXPECTED_NETWORK_ATTEMPT" in reasons
    assert "PROHIBITED_FD_TRANSFER" in reasons
    assert "OK" not in reasons
    with pytest.raises(ContractLoadError, match="closed policy"):
        contract.allowed_gate_reasons("offline.network_policy", "NOT_RUN")


def test_result_action_gates_are_bound_to_the_accepted_ledger_state(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    accepted_state = {
        "gates": value["gates"][:24],
        "semantic_dds_window": value["offline_evidence"]["semantic_dds_window"],
    }
    value["offline_evidence"]["ledger_chain_manifest"][
        "accepted_action_state_sha256"
    ] = hashlib.sha256(canonical_json_bytes(accepted_state)).hexdigest()
    _refresh_offline_bundle(value)
    assert contract.validate_result(value).ok

    value["gates"][0]["log_paths"] = ["tampered-after-ledger.log"]
    _refresh_offline_bundle(value, refresh_ledger_state=False)
    decision = contract.validate_result(value)
    assert not decision.ok
    assert any("ledger" in error or "accepted" in error for error in decision.errors)


def test_preflight_pass_then_post_observer_failure_is_truthfully_representable(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    postflight = next(
        gate for gate in value["gates"] if gate["id"] == "safety.workstation_postflight"
    )
    postflight.update(status="FAIL", reason="POSTFLIGHT_FAILED")
    value["offline_evidence"]["host_observer_post"].update(
        state="NOT_RUN",
        collector_identity=None,
        network_namespace_inode=None,
        process_count=0,
        service_count=0,
        listener_count=0,
        internet_socket_attempt_count=0,
        trusted_inspection=None,
        cause_gate="safety.workstation_postflight",
        reason="POSTFLIGHT_FAILED",
    )
    decision = ResultPolicy(contract).decide("workstation_offline", value["gates"])
    value.update(
        label=decision.label,
        status=decision.status,
        exit_class=decision.exit_class,
        process_exit_code=decision.exit_code,
        primary_blocking_gate=decision.primary,
        blocking_gates=list(decision.blocking_gates),
        qualifications=list(decision.qualifications),
    )
    value["offline_evidence"]["ledger_chain_manifest"][
        "accepted_action_state_sha256"
    ] = hashlib.sha256(
        canonical_json_bytes(
            {
                "gates": value["gates"][:24],
                "semantic_dds_window": value["offline_evidence"]["semantic_dds_window"],
            }
        )
    ).hexdigest()
    _refresh_offline_bundle(value)

    validation = contract.validate_result(value)
    assert validation.ok, validation.errors


def test_bootstrap_trace_observer_and_dds_states_are_cross_bound(
    contract: ContractSet,
):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["bootstrap_report"]["terminal_launch_state"] = (
        "NOT_STARTED_BOOTSTRAP_FAILURE"
    )
    value["offline_evidence"]["bootstrap_report"]["coordinator_launch_committed"] = (
        False
    )
    _refresh_offline_bundle(value)
    assert not contract.validate_result(value).ok

    value = make_pass_result("workstation_offline")
    value["offline_evidence"]["trace"]["trace_state"] = "FINALIZER_ONLY"
    _refresh_offline_bundle(value)
    decision = contract.validate_result(value)
    assert not decision.ok
    assert any(
        "FINALIZER_ONLY" in error or "semantic_dds_window" in error
        for error in decision.errors
    )


def test_semantic_query_pass_requires_closed_dds_window(contract: ContractSet):
    value = make_pass_result("workstation_offline")
    value["offline_evidence"].update(
        semantic_dds_window="NOT_ENTERED",
        dds_begin_record_index=None,
        dds_end_record_index=None,
    )
    _refresh_offline_bundle(value)
    decision = contract.validate_result(value)
    assert not decision.ok
    assert any("semantic.fixture_query" in error for error in decision.errors)


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


def test_interruption_marker_must_form_an_exact_remaining_action_suffix(
    contract: ContractSet,
):
    value = make_pass_result("pc2_inventory")
    value["gates"][4].update(status="FAIL", reason="TOOL_RUNTIME_ERROR")
    for gate in value["gates"][5:-2]:
        gate.update(status="NOT_RUN", reason="INTERRUPTED_BEFORE_GATE")
    value["gates"][7]["reason"] = "EARLIER_BLOCKING_GATE"
    value.update(
        label="INTERRUPTED",
        status="INTERRUPTED",
        exit_class="TERM",
        process_exit_code=143,
        blocking_gates=["pc2.inventory"],
    )

    assert not contract.validate_result(value).ok


def test_interruption_cannot_follow_an_earlier_blocked_not_run_segment(
    contract: ContractSet,
):
    value = make_pass_result("pc2_inventory")
    value["gates"][4].update(status="FAIL", reason="TOOL_RUNTIME_ERROR")
    value["gates"][5].update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    for gate in value["gates"][6:-2]:
        gate.update(status="NOT_RUN", reason="INTERRUPTED_BEFORE_GATE")
    value.update(
        label="INTERRUPTED",
        status="INTERRUPTED",
        exit_class="TERM",
        process_exit_code=143,
        blocking_gates=["pc2.inventory"],
    )

    with pytest.raises(ResultPolicyError, match="exact action interruption marker"):
        ResultPolicy(contract).decide("pc2_inventory", value["gates"], signal="TERM")
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
    if mode == "workstation_offline":
        value["offline_evidence"].update(
            semantic_dds_window="NOT_ENTERED",
            dds_begin_record_index=None,
            dds_end_record_index=None,
        )
        for field in ("host_observer_pre", "host_observer_post"):
            value["offline_evidence"][field].update(
                state="NOT_RUN",
                collector_identity=None,
                network_namespace_inode=None,
                process_count=0,
                service_count=0,
                listener_count=0,
                internet_socket_attempt_count=0,
                trusted_inspection=None,
                cause_gate="safety.workstation_preflight",
                reason="EARLIER_BLOCKING_GATE",
            )
        _refresh_offline_bundle(value)
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
    if mode == "workstation_offline":
        _refresh_offline_bundle(value)
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
    value["offline_evidence"]["dds_end_record_index"] = 0
    _refresh_offline_bundle(value)
    assert not contract.validate_result(value).ok


def test_openclaw_schema_contains_exact_reviewed_pins(contract: ContractSet):
    definitions = contract.schemas["openclaw-provisioning-v1"]["$defs"]
    pins = definitions["pins"]["properties"]
    assert pins["package_version"]["const"] == "2026.7.1-2"
    assert pins["node_version"]["const"] == "24.15.0"
    assert pins["configuration_template_git_blob"]["const"] == (
        "28a976724026d615fd21a79d701f8987b28a4f98"
    )
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


def test_result_policy_interruption_precedence_materializes_valid_contract_result(
    contract: ContractSet,
):
    value = make_pass_result("pc2_inventory")
    failed = next(gate for gate in value["gates"] if gate["id"] == "pc2.inventory")
    failed.update(status="FAIL", reason="TOOL_RUNTIME_ERROR")
    failure_index = value["gates"].index(failed)
    for gate in value["gates"][failure_index + 1 : -2]:
        gate.update(status="NOT_RUN", reason="INTERRUPTED_BEFORE_GATE")

    decision = ResultPolicy(contract).decide(
        "pc2_inventory", value["gates"], signal="TERM"
    )
    value.update(
        label=decision.label,
        status=decision.status,
        exit_class=decision.exit_class,
        process_exit_code=decision.exit_code,
        primary_blocking_gate=decision.primary,
        blocking_gates=list(decision.blocking_gates),
        qualifications=list(decision.qualifications),
    )

    validation = contract.validate_result(value)
    assert validation.ok, validation.errors

    functional_over_interrupt = copy.deepcopy(value)
    functional_over_interrupt.update(
        label="FAIL_PC2_INVENTORY",
        status="FAIL",
        exit_class="GATE_FAILURE",
        process_exit_code=20,
        primary_blocking_gate="pc2.inventory",
    )
    assert not contract.validate_result(functional_over_interrupt).ok


@pytest.mark.parametrize(
    ("winning_gate", "reason", "expected_label"),
    [
        ("offline.network_policy", "UNEXPECTED_NETWORK_ATTEMPT", "FAIL_SAFETY"),
        ("offline.trace_integrity", "TRACE_INCOMPLETE", "FAIL_HARNESS"),
    ],
)
def test_failure_precedence_over_interruption_materializes_valid_contract_result(
    contract: ContractSet,
    winning_gate: str,
    reason: str,
    expected_label: str,
):
    value = make_pass_result("workstation_offline")
    for gate in value["gates"][1:23]:
        gate.update(status="NOT_RUN", reason="INTERRUPTED_BEFORE_GATE")
    blocker = next(gate for gate in value["gates"] if gate["id"] == winning_gate)
    blocker.update(status="FAIL", reason=reason)
    if winning_gate == "offline.network_policy":
        value["offline_evidence"]["violation_journal"].update(
            violation_count=1, head_record_sha256=SHA256
        )
    else:
        value["offline_evidence"]["trace"].update(
            tracer_exit_code=1, compatibility_fixture_passed=False
        )
        network = next(
            gate for gate in value["gates"] if gate["id"] == "offline.network_policy"
        )
        network.update(status="SKIPPED", reason="DEPENDENCY_NOT_AVAILABLE")
    for field in ("host_observer_pre", "host_observer_post"):
        value["offline_evidence"][field].update(
            state="NOT_RUN",
            collector_identity=None,
            network_namespace_inode=None,
            process_count=0,
            service_count=0,
            listener_count=0,
            internet_socket_attempt_count=0,
            trusted_inspection=None,
            cause_gate="safety.workstation_preflight",
            reason="INTERRUPTED_BEFORE_GATE",
        )
    _refresh_offline_bundle(value)

    decision = ResultPolicy(contract).decide(
        "workstation_offline", value["gates"], signal="TERM"
    )
    assert decision.label == expected_label
    value.update(
        label=decision.label,
        status=decision.status,
        exit_class=decision.exit_class,
        process_exit_code=decision.exit_code,
        primary_blocking_gate=decision.primary,
        blocking_gates=list(decision.blocking_gates),
        qualifications=list(decision.qualifications),
    )

    validation = contract.validate_result(value)
    assert validation.ok, validation.errors


@pytest.mark.parametrize("mode", tuple(PROFILE_GATES))
def test_safety_override_still_rejects_a_mixed_not_run_interruption_suffix(
    contract: ContractSet, mode: str
):
    value = make_pass_result(mode)
    roles = dict(PROFILE_GATES[mode])
    action_gates = [gate for gate in value["gates"] if roles[gate["id"]] != "finalizer"]
    action_gates[0].update(status="FAIL", reason="SOURCE_MISMATCH")
    for gate in action_gates[1:]:
        gate.update(status="NOT_RUN", reason="INTERRUPTED_BEFORE_GATE")
    safety_gate_id = (
        "safety.pc2_postflight"
        if mode.startswith("pc2_")
        else "safety.workstation_postflight"
    )
    safety_gate = next(gate for gate in value["gates"] if gate["id"] == safety_gate_id)
    safety_gate.update(status="FAIL", reason="POSTFLIGHT_FAILED")

    decision = ResultPolicy(contract).decide(mode, value["gates"], signal="TERM")
    assert decision.label == "FAIL_SAFETY"
    action_gates[1]["reason"] = "EARLIER_BLOCKING_GATE"
    with pytest.raises(ResultPolicyError, match="exact action interruption marker"):
        ResultPolicy(contract).decide(mode, value["gates"], signal="TERM")
    value.update(
        label=decision.label,
        status=decision.status,
        exit_class=decision.exit_class,
        process_exit_code=decision.exit_code,
        primary_blocking_gate=decision.primary,
        blocking_gates=list(decision.blocking_gates),
        qualifications=list(decision.qualifications),
    )

    assert not contract.validate_result(value).ok
