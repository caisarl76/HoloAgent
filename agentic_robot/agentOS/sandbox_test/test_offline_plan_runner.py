from __future__ import annotations

import builtins
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import ModuleType

import pytest
import yaml


SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "scripts/holoagent0_setup/schemas/agentos-plan-v1.schema.json"
)


def _plan(**changes: object) -> dict[str, object]:
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
    return value


def _write_plan(tmp_path: Path, value: object | None = None) -> Path:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(_plan() if value is None else value), encoding="utf-8")
    return path


def _runner_module():
    return importlib.import_module("long_horizon_text_runner")


def test_offline_module_import_does_not_import_live_dependencies(monkeypatch):
    for name in ("long_horizon_text_runner", "openai", "requests"):
        monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__
    attempted: list[str] = []

    def guarded_import(name, *args, **kwargs):
        if name.split(".", 1)[0] in {"openai", "requests"}:
            attempted.append(name)
            raise AssertionError(f"live dependency imported: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    _runner_module()

    assert attempted == []


def test_offline_plan_produces_expected_artifacts_without_side_effects(
    monkeypatch, tmp_path
):
    runner_module = _runner_module()
    plan_path = _write_plan(tmp_path)
    attempts: list[str] = []

    def reject(kind: str):
        def rejected(*_args, **_kwargs):
            attempts.append(kind)
            raise AssertionError(f"offline side effect attempted: {kind}")

        return rejected

    monkeypatch.setattr(socket.socket, "connect", reject("socket.connect"))
    monkeypatch.setattr(socket, "create_connection", reject("socket.create_connection"))
    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, reject(f"subprocess.{name}"))
    monkeypatch.setattr(os, "system", reject("os.system"))
    for name in ("fork", "forkpty"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, reject(f"os.{name}"))
    for name in dir(os):
        if name.startswith(("exec", "spawn")) and callable(getattr(os, name)):
            monkeypatch.setattr(os, name, reject(f"os.{name}"))
    monkeypatch.setattr(
        multiprocessing.Process, "start", reject("multiprocessing.Process.start")
    )

    real_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        root = name.split(".", 1)[0]
        if root in {
            "openai",
            "requests",
            "rclpy",
            "rosidl_runtime_py",
            "std_msgs",
            "geometry_msgs",
        }:
            attempts.append(f"import:{name}")
            raise AssertionError(f"offline import attempted: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    result = runner_module.run_offline_plan(
        plan_path,
        mode="single_robot",
        output_root=tmp_path / "output",
        schema_path=SCHEMA_PATH,
    )

    assert result.status == "PASS"
    assert result.exit_code == 0
    assert attempts == []
    assert result.plan_path.is_file()
    assert result.validation_path.is_file()
    assert result.execution_path.is_file()
    plan_artifact = yaml.safe_load(result.plan_path.read_text(encoding="utf-8"))
    validation = yaml.safe_load(result.validation_path.read_text(encoding="utf-8"))
    execution = yaml.safe_load(result.execution_path.read_text(encoding="utf-8"))
    assert plan_artifact["dag"] == {
        "description": "visit one waypoint",
        "nodes": _plan()["nodes"],
    }
    assert validation["status"] == "passed"
    assert execution["status"] == "skipped"
    assert execution["executed_nodes"] == []


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda value: value.update(extra=True), "Additional properties"),
        (
            lambda value: value["nodes"][0].update(extra=True),
            "Additional properties",
        ),
        (
            lambda value: value.update(schema_version="wrong"),
            "holoagent.agentos.plan.v1",
        ),
        (lambda value: value.update(mode="wrong"), "single_robot"),
        (lambda value: value.update(description=""), "non-empty"),
        (lambda value: value.update(nodes=[]), "at least one node"),
        (lambda value: value["nodes"][0].update(robot_id=17), "robot_id"),
        (lambda value: value["nodes"][0].update(id="bad id"), "node ID"),
        (
            lambda value: value["nodes"][0].update(
                skill="navigation", target="high_five"
            ),
            "navigation target",
        ),
        (
            lambda value: value["nodes"][0].update(depends_on=["missing_node"]),
            "unknown dependency",
        ),
    ],
)
def test_load_plan_file_rejects_closed_schema_violations(tmp_path, mutate, message):
    runner_module = _runner_module()
    value = _plan()
    mutate(value)

    with pytest.raises(runner_module.PlanValidationError, match=message):
        runner_module.load_plan_file(_write_plan(tmp_path, value), SCHEMA_PATH)


def test_load_plan_file_rejects_duplicate_ids_and_cycles(tmp_path):
    runner_module = _runner_module()
    duplicate = _plan(
        nodes=[
            _plan()["nodes"][0],
            _plan()["nodes"][0],
        ]
    )
    with pytest.raises(runner_module.PlanValidationError, match="unique"):
        runner_module.load_plan_file(_write_plan(tmp_path, duplicate), SCHEMA_PATH)

    cyclic = _plan(
        nodes=[
            {
                **_plan()["nodes"][0],
                "id": "first",
                "depends_on": ["second"],
            },
            {
                **_plan()["nodes"][0],
                "id": "second",
                "depends_on": ["first"],
            },
        ]
    )
    with pytest.raises(runner_module.PlanValidationError, match="cycle"):
        runner_module.load_plan_file(_write_plan(tmp_path, cyclic), SCHEMA_PATH)


def test_load_plan_file_rejects_non_utf8_and_oversize(tmp_path):
    runner_module = _runner_module()
    plan_path = tmp_path / "plan.json"
    plan_path.write_bytes(b"\xff")
    with pytest.raises(runner_module.PlanValidationError, match="UTF-8"):
        runner_module.load_plan_file(plan_path, SCHEMA_PATH)

    plan_path.write_bytes(b" " * 65_537)
    with pytest.raises(runner_module.PlanValidationError, match="65536-byte"):
        runner_module.load_plan_file(plan_path, SCHEMA_PATH)


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": []},
        {
            "nodes": [
                {
                    **_plan()["nodes"][0],
                    "skill": [],
                }
            ]
        },
    ],
)
def test_load_plan_file_normalizes_unhashable_types(tmp_path, changes):
    runner_module = _runner_module()
    with pytest.raises(runner_module.PlanValidationError):
        runner_module.load_plan_file(
            _write_plan(tmp_path, _plan(**changes)), SCHEMA_PATH
        )


def test_load_plan_file_rejects_same_id_schema_drift(tmp_path):
    runner_module = _runner_module()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["description"] = "unreviewed drift"
    changed_schema = tmp_path / "schema.json"
    changed_schema.write_text(json.dumps(schema), encoding="utf-8")

    with pytest.raises(runner_module.PlanValidationError, match="digest"):
        runner_module.load_plan_file(_write_plan(tmp_path), changed_schema)


@pytest.mark.parametrize("method_name", ["connect_ex", "sendto"])
def test_production_guard_blocks_and_records_socket_paths(method_name):
    runner_module = _runner_module()
    guard = runner_module.OfflineSideEffectGuard()
    socket_type = socket.socket
    with guard, pytest.raises(runner_module.OfflineSideEffectAttempt):
        method = getattr(socket_type, method_name)
        if method_name == "sendto":
            method(object(), b"x", ("127.0.0.1", 9))
        else:
            method(object(), ("127.0.0.1", 9))

    assert guard.network_attempts == [f"socket.socket.{method_name}"]


def test_production_guard_blocks_socket_creation():
    runner_module = _runner_module()
    guard = runner_module.OfflineSideEffectGuard()
    with guard, pytest.raises(runner_module.OfflineSideEffectAttempt):
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    assert guard.network_attempts == ["socket.socket"]


def test_production_guard_blocks_process_and_preloaded_ros_publisher(monkeypatch):
    runner_module = _runner_module()
    process_guard = runner_module.OfflineSideEffectGuard()
    with process_guard, pytest.raises(runner_module.OfflineSideEffectAttempt):
        subprocess.Popen(["/bin/true"])
    assert process_guard.process_attempts == ["subprocess.Popen"]

    publisher_module = ModuleType("rclpy.publisher")

    class Publisher:
        def publish(self, _message):
            raise AssertionError("unpatched ROS publication")

    publisher_module.Publisher = Publisher
    monkeypatch.setitem(sys.modules, "rclpy.publisher", publisher_module)
    ros_guard = runner_module.OfflineSideEffectGuard()
    with ros_guard, pytest.raises(runner_module.OfflineSideEffectAttempt):
        Publisher().publish(object())
    assert ros_guard.ros_publication_attempts == ["rclpy.publisher.Publisher.publish"]


def test_offline_mode_requires_plan_mode_to_match_cli(tmp_path):
    runner_module = _runner_module()
    plan_path = _write_plan(tmp_path, _plan(mode="multi_robot"))
    with pytest.raises(runner_module.PlanValidationError, match="does not match"):
        runner_module.run_offline_plan(
            plan_path,
            mode="single_robot",
            output_root=tmp_path / "output",
            schema_path=SCHEMA_PATH,
        )


@pytest.mark.parametrize(
    "argv",
    [
        ["--mode", "single_robot", "--plan-file", "plan.json"],
        [
            "--mode",
            "single_robot",
            "--dry-run",
            "--plan-file",
            "plan.json",
            "--instruction",
            "move",
        ],
        ["--mode", "single_robot", "--dry-run"],
    ],
)
def test_cli_rejects_invalid_plan_and_text_argument_combinations(argv):
    parser = _runner_module().build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(argv)


def test_cli_accepts_offline_plan_without_instruction():
    args = (
        _runner_module()
        .build_arg_parser()
        .parse_args(
            [
                "--mode",
                "single_robot",
                "--dry-run",
                "--plan-file",
                "plan.json",
            ]
        )
    )
    assert args.plan_file == "plan.json"
    assert args.instruction is None
