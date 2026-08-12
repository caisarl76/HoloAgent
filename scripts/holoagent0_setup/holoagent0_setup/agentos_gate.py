"""Deterministic gate adapter for AgentOS offline plan execution."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import sys
from typing import Callable


def _load_agentos_runner():
    try:
        from agentic_robot.agentOS.sandbox_test import long_horizon_text_runner

        return long_horizon_text_runner
    except ModuleNotFoundError as error:
        if error.name not in {"agentic_robot", "agentic_robot.agentOS"}:
            raise
    module_name = "holoagent0_agentos_offline_runner"
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    runner_path = (
        Path(__file__).resolve().parents[3]
        / "agentic_robot/agentOS/sandbox_test/long_horizon_text_runner.py"
    )
    specification = importlib.util.spec_from_file_location(module_name, runner_path)
    if specification is None or specification.loader is None:
        raise RuntimeError("AgentOS offline runner import is unavailable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_RUNNER = _load_agentos_runner()
DEFAULT_PLAN_SCHEMA = _RUNNER.DEFAULT_PLAN_SCHEMA
OfflineSideEffectAttempt = _RUNNER.OfflineSideEffectAttempt
OfflineSideEffectGuard = _RUNNER.OfflineSideEffectGuard
PlanValidationError = _RUNNER.PlanValidationError
load_plan_file = _RUNNER.load_plan_file
run_offline_plan = _RUNNER.run_offline_plan


@dataclass(frozen=True)
class AgentOSGateResult:
    """The exact ordered AgentOS gate subset returned to the coordinator."""

    gates: tuple[dict[str, object], ...]
    exit_code: int


def _gate(gate_id: str, status: str, reason: str) -> dict[str, object]:
    return {
        "id": gate_id,
        "status": status,
        "role": "required",
        "reason": reason,
        "measurements": [],
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


def _not_run(gate_id: str) -> dict[str, object]:
    return _gate(gate_id, "NOT_RUN", "EARLIER_BLOCKING_GATE")


def run_agentos_gates(
    *,
    plan_file: Path,
    mode: str,
    output_root: Path,
    schema_path: Path = DEFAULT_PLAN_SCHEMA,
    offline_runner: Callable[..., object] = run_offline_plan,
) -> AgentOSGateResult:
    """Validate and execute AgentOS without exposing exception text as evidence."""

    try:
        plan = load_plan_file(plan_file, schema_path)
        if plan["mode"] != mode:
            raise PlanValidationError("plan mode does not match requested mode")
    except (PlanValidationError, OSError, TypeError, ValueError):
        return AgentOSGateResult(
            gates=(
                _gate("agentos.plan_schema", "FAIL", "PLAN_INVALID"),
                _not_run("agentos.offline_execution"),
                _not_run("agentos.network_attempts"),
            ),
            exit_code=1,
        )

    plan_gate = _gate("agentos.plan_schema", "PASS", "OK")
    audit = OfflineSideEffectGuard()
    try:
        if offline_runner is run_offline_plan:
            result = offline_runner(
                plan_file,
                mode=mode,
                output_root=output_root,
                schema_path=schema_path,
            )
        else:
            with audit:
                result = offline_runner(
                    plan_file,
                    mode=mode,
                    output_root=output_root,
                    schema_path=schema_path,
                )
    except OfflineSideEffectAttempt:
        network_gate = (
            _gate(
                "agentos.network_attempts",
                "FAIL",
                "OFFLINE_SIDE_EFFECT_ATTEMPT",
            )
            if audit.network_attempts
            else _not_run("agentos.network_attempts")
        )
        return AgentOSGateResult(
            gates=(
                plan_gate,
                _gate(
                    "agentos.offline_execution",
                    "FAIL",
                    "OFFLINE_SIDE_EFFECT_ATTEMPT",
                ),
                network_gate,
            ),
            exit_code=1,
        )
    except Exception:
        return AgentOSGateResult(
            gates=(
                plan_gate,
                _gate("agentos.offline_execution", "FAIL", "TOOL_RUNTIME_ERROR"),
                _not_run("agentos.network_attempts"),
            ),
            exit_code=1,
        )

    side_effect_attempts = (
        *audit.process_attempts,
        *audit.ros_publication_attempts,
        *tuple(getattr(result, "side_effect_attempts", ())),
    )
    network_attempts = (
        *audit.network_attempts,
        *tuple(getattr(result, "network_attempts", ())),
    )
    if side_effect_attempts:
        network_gate = (
            _gate(
                "agentos.network_attempts",
                "FAIL",
                "OFFLINE_SIDE_EFFECT_ATTEMPT",
            )
            if network_attempts
            else _not_run("agentos.network_attempts")
        )
        return AgentOSGateResult(
            gates=(
                plan_gate,
                _gate(
                    "agentos.offline_execution",
                    "FAIL",
                    "OFFLINE_SIDE_EFFECT_ATTEMPT",
                ),
                network_gate,
            ),
            exit_code=1,
        )
    result_passed = (
        getattr(result, "status", None) == "PASS"
        and getattr(result, "exit_code", None) == 0
    )
    if network_attempts:
        return AgentOSGateResult(
            gates=(
                plan_gate,
                _gate(
                    "agentos.offline_execution",
                    "PASS" if result_passed else "FAIL",
                    "OK" if result_passed else "OFFLINE_SIDE_EFFECT_ATTEMPT",
                ),
                _gate(
                    "agentos.network_attempts",
                    "FAIL",
                    "OFFLINE_SIDE_EFFECT_ATTEMPT",
                ),
            ),
            exit_code=1,
        )
    if not result_passed:
        return AgentOSGateResult(
            gates=(
                plan_gate,
                _gate("agentos.offline_execution", "FAIL", "TOOL_RUNTIME_ERROR"),
                _not_run("agentos.network_attempts"),
            ),
            exit_code=1,
        )

    execution_gate = _gate("agentos.offline_execution", "PASS", "OK")
    network_gate = _gate("agentos.network_attempts", "PASS", "OK")
    exit_code = 0
    return AgentOSGateResult(
        gates=(plan_gate, execution_gate, network_gate), exit_code=exit_code
    )
