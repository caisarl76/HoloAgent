from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess

from agentic_robot.agentOS.sandbox_test import long_horizon_text_runner

from holoagent0_setup.agentos_gate import run_agentos_gates


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas/agentos-plan-v1.schema.json"
)


def _write_plan(tmp_path: Path, **changes: object) -> Path:
    value: dict[str, object] = {
        "schema_version": "holoagent.agentos.plan.v1",
        "mode": "single_robot",
        "description": "visit one waypoint",
        "nodes": [
            {
                "id": "r11_nav_p1",
                "robot_id": 11,
                "skill": "navigation",
                "target": "one_point_1",
                "depends_on": [],
            }
        ],
    }
    value.update(changes)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _statuses(result):
    return [(gate["id"], gate["status"], gate["reason"]) for gate in result.gates]


def test_agentos_gate_passes_exact_three_gate_contract(tmp_path):
    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        ("agentos.offline_execution", "PASS", "OK"),
        ("agentos.network_attempts", "PASS", "OK"),
    ]
    assert all(gate["role"] == "required" for gate in result.gates)
    assert all(gate["child_command_exit_code"] is None for gate in result.gates)
    assert result.exit_code == 0


def test_agentos_gate_fails_schema_and_marks_later_gates_not_run(tmp_path):
    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path, unexpected=True),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "FAIL", "PLAN_INVALID"),
        (
            "agentos.offline_execution",
            "NOT_RUN",
            "EARLIER_BLOCKING_GATE",
        ),
        ("agentos.network_attempts", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1


def test_agentos_gate_maps_runner_error_without_leaking_exception(tmp_path):
    def failed_runner(*_args, **_kwargs):
        raise RuntimeError("credential-shaped secret must not enter evidence")

    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
        offline_runner=failed_runner,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        ("agentos.offline_execution", "FAIL", "TOOL_RUNTIME_ERROR"),
        ("agentos.network_attempts", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1
    assert "credential-shaped" not in repr(result)


def test_agentos_gate_maps_observed_side_effects_fail_closed(tmp_path):
    class SideEffectResult:
        status = "FAIL"
        exit_code = 3
        side_effect_attempts = ("subprocess.Popen",)

    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
        offline_runner=lambda *_args, **_kwargs: SideEffectResult(),
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        (
            "agentos.offline_execution",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
        ("agentos.network_attempts", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1


def test_agentos_gate_rejects_network_attempts_at_network_gate(tmp_path):
    class NetworkResult:
        status = "PASS"
        exit_code = 0
        side_effect_attempts = ()
        network_attempts = ("socket.connect",)

    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
        offline_runner=lambda *_args, **_kwargs: NetworkResult(),
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        ("agentos.offline_execution", "PASS", "OK"),
        (
            "agentos.network_attempts",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
    ]
    assert result.exit_code == 1


def test_agentos_gate_uses_production_audit_observation(monkeypatch, tmp_path):
    def attempted_network(_self):
        long_horizon_text_runner.socket.socket(
            long_horizon_text_runner.socket.AF_INET,
            long_horizon_text_runner.socket.SOCK_DGRAM,
        )

    monkeypatch.setattr(
        long_horizon_text_runner.LongHorizonTextRunner,
        "_run_offline_guarded",
        attempted_network,
    )
    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        (
            "agentos.offline_execution",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
        (
            "agentos.network_attempts",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
    ]
    assert result.exit_code == 1


def test_agentos_gate_audits_injected_runner_instead_of_trusting_result(tmp_path):
    class DishonestResult:
        status = "PASS"
        exit_code = 0
        side_effect_attempts = ()
        network_attempts = ()

    cached_popen = subprocess.Popen

    def spawning_runner(*_args, **_kwargs):
        cached_popen(["/bin/true"])
        return DishonestResult()

    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
        offline_runner=spawning_runner,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        (
            "agentos.offline_execution",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
        ("agentos.network_attempts", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1


def test_agentos_gate_audits_cached_socket_constructor(tmp_path):
    class DishonestResult:
        status = "PASS"
        exit_code = 0
        side_effect_attempts = ()
        network_attempts = ()

    cached_socket = socket.socket

    def socket_runner(*_args, **_kwargs):
        cached_socket(socket.AF_INET, socket.SOCK_DGRAM).close()
        return DishonestResult()

    result = run_agentos_gates(
        plan_file=_write_plan(tmp_path),
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
        offline_runner=socket_runner,
    )

    assert _statuses(result) == [
        ("agentos.plan_schema", "PASS", "OK"),
        (
            "agentos.offline_execution",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
        (
            "agentos.network_attempts",
            "FAIL",
            "OFFLINE_SIDE_EFFECT_ATTEMPT",
        ),
    ]
    assert result.exit_code == 1
