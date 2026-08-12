#!/usr/bin/env python3
"""
纯文本长指令 DAG 执行器。

目标：
- 使用 LLM 将长指令拆解为单机/多机 DAG
- 在真实物理执行前，先进行虚拟执行验证流程顺序
- 将规划、验证、执行监控结果写入监控文件
"""

from __future__ import annotations

import argparse
import builtins
from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import json
import multiprocessing
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set
from unittest.mock import patch

import yaml


DEFAULT_OUTPUT_ROOT = Path(
    "/workspace/D-Robotics/agentic_robot_system/agentic_robot/agentOS/long_horizon_instruction_test/output"
)
DEFAULT_PLAN_SCHEMA = (
    Path(__file__).resolve().parents[3]
    / "scripts/holoagent0_setup/schemas/agentos-plan-v1.schema.json"
)
DEFAULT_PLAN_SCHEMA_SHA256 = (
    "4b6845a66fb6037b7b17b5e66ba97f2e0ea7767b1a976328d1d5001f50fec66a"
)


class PlanValidationError(ValueError):
    """An offline AgentOS plan does not satisfy the reviewed contract."""


class OfflineSideEffectAttempt(RuntimeError):
    """A prohibited offline network, process, or ROS action was attempted."""


@dataclass(frozen=True)
class OfflinePlanResult:
    status: str
    exit_code: int
    session_dir: Path
    plan_path: Path
    validation_path: Path
    execution_path: Path
    network_attempts: tuple[str, ...] = ()
    process_attempts: tuple[str, ...] = ()
    ros_publication_attempts: tuple[str, ...] = ()

    @property
    def side_effect_attempts(self) -> tuple[str, ...]:
        return (*self.process_attempts, *self.ros_publication_attempts)


class OfflineSideEffectGuard:
    """Block and record reviewed Python side-effect entry points."""

    _NETWORK_SOCKET_METHODS = (
        "connect",
        "connect_ex",
        "send",
        "sendall",
        "sendto",
        "sendmsg",
        "sendfile",
    )
    _NETWORK_MODULE_FUNCTIONS = (
        "create_connection",
        "getaddrinfo",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
    )
    _SUBPROCESS_FUNCTIONS = (
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
    )
    _ROS_ROOTS = frozenset(
        {
            "rclpy",
            "rosidl_runtime_py",
            "std_msgs",
            "geometry_msgs",
        }
    )
    _ROS_METHODS = (
        ("rclpy.publisher", "Publisher", "publish"),
        ("rclpy.node", "Node", "create_publisher"),
    )
    _AUDIT_NETWORK_EVENTS = frozenset(
        {
            "socket.__new__",
            "socket.bind",
            "socket.connect",
            "socket.sendmsg",
            "socket.sendto",
            "socket.getaddrinfo",
            "socket.gethostbyaddr",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.gethostname",
        }
    )
    _AUDIT_PROCESS_EVENTS = frozenset(
        {
            "os.exec",
            "os.fork",
            "os.forkpty",
            "os.posix_spawn",
            "os.spawn",
            "os.system",
            "subprocess.Popen",
        }
    )
    _active_audit_guard: "OfflineSideEffectGuard | None" = None
    _audit_hook_installed = False

    def __init__(self) -> None:
        self.network_attempts: list[str] = []
        self.process_attempts: list[str] = []
        self.ros_publication_attempts: list[str] = []
        self._stack: ExitStack | None = None

    def __enter__(self) -> "OfflineSideEffectGuard":
        if self._stack is not None:
            raise RuntimeError("offline side-effect guard is already active")
        stack = ExitStack()
        self._stack = stack
        try:
            if type(self)._active_audit_guard is not None:
                raise RuntimeError("offline side-effect guard is already active")
            if not type(self)._audit_hook_installed:
                sys.addaudithook(type(self)._audit_hook)
                type(self)._audit_hook_installed = True
            type(self)._active_audit_guard = self
            for name in self._NETWORK_SOCKET_METHODS:
                if hasattr(socket.socket, name):
                    stack.enter_context(
                        patch.object(
                            socket.socket,
                            name,
                            self._blocked("network", f"socket.socket.{name}"),
                        )
                    )
            stack.enter_context(
                patch.object(
                    socket,
                    "socket",
                    self._blocked("network", "socket.socket"),
                )
            )
            for name in self._NETWORK_MODULE_FUNCTIONS:
                if hasattr(socket, name):
                    stack.enter_context(
                        patch.object(
                            socket,
                            name,
                            self._blocked("network", f"socket.{name}"),
                        )
                    )
            for name in self._SUBPROCESS_FUNCTIONS:
                stack.enter_context(
                    patch.object(
                        subprocess,
                        name,
                        self._blocked("process", f"subprocess.{name}"),
                    )
                )
            for name in dir(os):
                if name in {"fork", "forkpty", "system"} or name.startswith(
                    ("exec", "spawn", "posix_spawn")
                ):
                    candidate = getattr(os, name)
                    if callable(candidate):
                        stack.enter_context(
                            patch.object(
                                os,
                                name,
                                self._blocked("process", f"os.{name}"),
                            )
                        )
            stack.enter_context(
                patch.object(
                    multiprocessing.Process,
                    "start",
                    self._blocked("process", "multiprocessing.Process.start"),
                )
            )
            current_import = builtins.__import__

            def guarded_import(name, *args, **kwargs):
                if name.split(".", 1)[0] in self._ROS_ROOTS:
                    return self._reject("ros", f"import:{name}")
                return current_import(name, *args, **kwargs)

            stack.enter_context(patch.object(builtins, "__import__", guarded_import))
            for module_name, owner_name, method_name in self._ROS_METHODS:
                module = sys.modules.get(module_name)
                owner = None if module is None else getattr(module, owner_name, None)
                if owner is not None and hasattr(owner, method_name):
                    stack.enter_context(
                        patch.object(
                            owner,
                            method_name,
                            self._blocked(
                                "ros", f"{module_name}.{owner_name}.{method_name}"
                            ),
                        )
                    )
        except BaseException:
            if type(self)._active_audit_guard is self:
                type(self)._active_audit_guard = None
            stack.close()
            self._stack = None
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        stack = self._stack
        if stack is None:
            raise RuntimeError("offline side-effect guard is not active")
        self._stack = None
        try:
            stack.close()
        finally:
            if type(self)._active_audit_guard is self:
                type(self)._active_audit_guard = None

    @classmethod
    def _audit_hook(cls, event: str, _arguments: tuple[object, ...]) -> None:
        guard = cls._active_audit_guard
        if guard is None:
            return
        if event in cls._AUDIT_NETWORK_EVENTS:
            guard._reject("network", f"audit:{event}")
        if event in cls._AUDIT_PROCESS_EVENTS:
            guard._reject("process", f"audit:{event}")

    def _blocked(self, category: str, operation: str):
        def blocked(*_args, **_kwargs):
            return self._reject(category, operation)

        return blocked

    def _reject(self, category: str, operation: str):
        inventory = {
            "network": self.network_attempts,
            "process": self.process_attempts,
            "ros": self.ros_publication_attempts,
        }.get(category)
        if inventory is None:
            raise RuntimeError("offline side-effect category is invalid")
        inventory.append(operation)
        raise OfflineSideEffectAttempt(operation)


def _validate_plan_schema(schema: object, value: object) -> dict[str, object]:
    if not isinstance(schema, dict) or schema.get("$id") != (
        "holoagent.agentos.plan.v1"
    ):
        raise PlanValidationError("plan schema identifier is not approved")
    if not isinstance(value, dict):
        raise PlanValidationError("plan must be an object")
    top_keys = {"schema_version", "mode", "description", "nodes"}
    missing = top_keys - value.keys()
    unexpected = value.keys() - top_keys
    if missing:
        raise PlanValidationError(f"required property is missing: {sorted(missing)[0]}")
    if unexpected:
        raise PlanValidationError(
            f"Additional properties are not allowed: {sorted(unexpected)[0]}"
        )
    if value["schema_version"] != "holoagent.agentos.plan.v1":
        raise PlanValidationError("schema_version must be holoagent.agentos.plan.v1")
    if not isinstance(value["mode"], str) or value["mode"] not in {
        "single_robot",
        "multi_robot",
    }:
        raise PlanValidationError("mode must be single_robot or multi_robot")
    description = value["description"]
    if not isinstance(description, str) or not 1 <= len(description) <= 512:
        raise PlanValidationError(
            "description must be non-empty and at most 512 characters"
        )
    nodes = value["nodes"]
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 64:
        raise PlanValidationError("nodes must contain at least one node and at most 64")

    node_keys = {"id", "robot_id", "skill", "target", "depends_on"}
    navigation_targets = {
        "one_point_1",
        "one_point_2",
        "one_point_3",
        "one_point_4",
        "stop",
    }
    arm_targets = {
        "release_arm",
        "turn_back_wave",
        "blow_kiss_with_both_hands",
        "blow_kiss_with_left_hand",
        "blow_kiss_with_right_hand",
        "both_hands_up",
        "clamp",
        "high_five",
        "hug",
        "make_heart_with_both_hands",
        "make_heart_with_right_hand",
        "refuse",
        "right_hand_up",
        "ultraman_ray",
        "wave_under_head",
        "wave_above_head",
        "shake_hand",
        "one_point_1_waypoint_1",
        "box_left_hand_win",
        "box_right_hand_win",
        "box_both_hand_win",
        "right_hand_on_heart",
        "both_hands_up_deviate_right",
        "forward_push",
    }
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise PlanValidationError(f"node {index} must be an object")
        missing = node_keys - node.keys()
        unexpected = node.keys() - node_keys
        if missing:
            raise PlanValidationError(
                f"node {index} required property is missing: {sorted(missing)[0]}"
            )
        if unexpected:
            raise PlanValidationError(
                f"Additional properties are not allowed in node {index}: "
                f"{sorted(unexpected)[0]}"
            )
        node_id = node["id"]
        if (
            not isinstance(node_id, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", node_id) is None
        ):
            raise PlanValidationError(f"node {index} node ID is invalid")
        robot_id = node["robot_id"]
        if type(robot_id) is not int or robot_id not in {11, 12, 13, 14, 15, 16}:
            raise PlanValidationError(f"node {index} robot_id is not approved")
        skill = node["skill"]
        target = node["target"]
        if not isinstance(skill, str) or skill not in {"navigation", "arm"}:
            raise PlanValidationError(f"node {index} skill is not approved")
        if not isinstance(target, str) or (
            skill == "navigation" and target not in navigation_targets
        ):
            raise PlanValidationError(f"node {index} navigation target is not approved")
        if skill == "arm" and target not in arm_targets:
            raise PlanValidationError(f"node {index} arm target is not approved")
        dependencies = node["depends_on"]
        if not isinstance(dependencies, list) or len(dependencies) > 64:
            raise PlanValidationError(f"node {index} dependencies are not bounded")
        if any(
            not isinstance(dependency, str)
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", dependency) is None
            for dependency in dependencies
        ):
            raise PlanValidationError(f"node {index} dependency ID is invalid")
        if len(set(dependencies)) != len(dependencies):
            raise PlanValidationError(f"node {index} dependencies must be unique")
    return value


def _has_graph_cycle(nodes: list[dict[str, object]]) -> bool:
    graph = {str(node["id"]): tuple(node["depends_on"]) for node in nodes}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> bool:
        if node_id in visiting:
            return True
        if node_id in visited:
            return False
        visiting.add(node_id)
        if any(visit(str(dependency)) for dependency in graph[node_id]):
            return True
        visiting.remove(node_id)
        visited.add(node_id)
        return False

    return any(visit(node_id) for node_id in graph)


def load_plan_file(
    path: Path, schema_path: Path = DEFAULT_PLAN_SCHEMA, max_bytes: int = 65_536
) -> dict[str, object]:
    """Load a bounded, closed AgentOS offline plan without live dependencies."""

    if type(max_bytes) is not int or max_bytes != 65_536:
        raise PlanValidationError("plan byte limit must be exactly 65536")
    try:
        raw = Path(path).read_bytes()
    except OSError as error:
        raise PlanValidationError("plan file could not be read") from error
    if len(raw) > max_bytes:
        raise PlanValidationError("plan exceeds 65536-byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise PlanValidationError("plan must be valid UTF-8") from error
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as error:
        raise PlanValidationError("plan must be valid JSON") from error

    try:
        schema_bytes = Path(schema_path).read_bytes()
        if hashlib.sha256(schema_bytes).hexdigest() != DEFAULT_PLAN_SCHEMA_SHA256:
            raise PlanValidationError("plan schema digest is not approved")
        schema = json.loads(schema_bytes.decode("utf-8", errors="strict"))
    except PlanValidationError:
        raise
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as error:
        raise PlanValidationError("plan schema could not be validated") from error
    value = _validate_plan_schema(schema, value)

    nodes = value["nodes"]
    if not isinstance(nodes, list):
        raise PlanValidationError("nodes must be an array")
    node_ids = [str(node["id"]) for node in nodes]
    if len(set(node_ids)) != len(node_ids):
        raise PlanValidationError("node IDs must be unique")
    known_ids = set(node_ids)
    for node in nodes:
        for dependency in node["depends_on"]:
            if dependency not in known_ids:
                raise PlanValidationError(f"unknown dependency for node {node['id']}")
    if _has_graph_cycle(nodes):
        raise PlanValidationError("plan dependency graph contains a cycle")
    if value["mode"] == "single_robot":
        robot_ids = {node["robot_id"] for node in nodes}
        if len(robot_ids) != 1:
            raise PlanValidationError("single_robot plan must use exactly one robot")
    return value


SINGLE_ROBOT_TEST_CASES = [
    {
        "name": "single_robot_long_instruction",
        "instruction": "11机器先去点位1，到了以后高挥手打招呼，然后去点位2和用户击掌，最后回到点位3并挥手再见",
        "expected_dag": {
            "description": "11 机器串行执行导航、挥手、导航、击掌、导航、挥手再见",
            "nodes": [
                {
                    "id": "r11_nav_p1",
                    "robot_id": 11,
                    "skill": "navigation",
                    "target": "one_point_1",
                    "depends_on": [],
                },
                {
                    "id": "r11_wave_greet",
                    "robot_id": 11,
                    "skill": "arm",
                    "target": "wave_above_head",
                    "depends_on": ["r11_nav_p1"],
                },
                {
                    "id": "r11_nav_p2",
                    "robot_id": 11,
                    "skill": "navigation",
                    "target": "one_point_2",
                    "depends_on": ["r11_wave_greet"],
                },
                {
                    "id": "r11_high_five",
                    "robot_id": 11,
                    "skill": "arm",
                    "target": "high_five",
                    "depends_on": ["r11_nav_p2"],
                },
                {
                    "id": "r11_nav_p3",
                    "robot_id": 11,
                    "skill": "navigation",
                    "target": "one_point_3",
                    "depends_on": ["r11_high_five"],
                },
                {
                    "id": "r11_wave_bye",
                    "robot_id": 11,
                    "skill": "arm",
                    "target": "wave_under_head",
                    "depends_on": ["r11_nav_p3"],
                },
            ],
        },
    }
]

MULTI_ROBOT_TEST_CASES = [
    {
        "name": "multi_robot_long_instruction",
        "instruction": "11机器和12机器同时去点位1，11机器到达后高挥手打招呼，12机器到达后和用户击掌，全部完成后同时挥手再见，然后回到点位2",
        "expected_dag": {
            "description": "11/12 并行到点位1；11 到达后挥手；12 到达后击掌；全部完成后并行挥手再见；最后并行回点位2",
            "nodes": [
                {
                    "id": "r11_nav_p1",
                    "robot_id": 11,
                    "skill": "navigation",
                    "target": "one_point_1",
                    "depends_on": [],
                },
                {
                    "id": "r12_nav_p1",
                    "robot_id": 12,
                    "skill": "navigation",
                    "target": "one_point_1",
                    "depends_on": [],
                },
                {
                    "id": "r11_wave_greet",
                    "robot_id": 11,
                    "skill": "arm",
                    "target": "wave_above_head",
                    "depends_on": ["r11_nav_p1"],
                },
                {
                    "id": "r12_high_five",
                    "robot_id": 12,
                    "skill": "arm",
                    "target": "high_five",
                    "depends_on": ["r12_nav_p1"],
                },
                {
                    "id": "r11_wave_bye",
                    "robot_id": 11,
                    "skill": "arm",
                    "target": "wave_under_head",
                    "depends_on": ["r11_wave_greet", "r12_high_five"],
                },
                {
                    "id": "r12_wave_bye",
                    "robot_id": 12,
                    "skill": "arm",
                    "target": "wave_under_head",
                    "depends_on": ["r11_wave_greet", "r12_high_five"],
                },
                {
                    "id": "r11_nav_p2",
                    "robot_id": 11,
                    "skill": "navigation",
                    "target": "one_point_2",
                    "depends_on": ["r11_wave_bye", "r12_wave_bye"],
                },
                {
                    "id": "r12_nav_p2",
                    "robot_id": 12,
                    "skill": "navigation",
                    "target": "one_point_2",
                    "depends_on": ["r11_wave_bye", "r12_wave_bye"],
                },
            ],
        },
    }
]


class LongHorizonTextRunner:
    _HTTP_TIMEOUT_SEC = 10.0
    _CONTROL_CENTER_TIMEOUT_SEC = 5.0
    _NAV_WAIT_TIMEOUT_SEC = 120.0
    _ARM_SKILL_WAIT_SEC = 8.0
    _DAG_EXECUTOR_MAX_WORKERS = 8

    def __init__(
        self,
        mode: str,
        dry_run: bool = False,
        output_root: Optional[Path] = None,
        *,
        plan_file: Path | None = None,
        schema_path: Path = DEFAULT_PLAN_SCHEMA,
    ) -> None:
        self.mode = mode
        self.dry_run = dry_run
        self.plan_file = Path(plan_file) if plan_file is not None else None
        self.schema_path = Path(schema_path)
        if self.plan_file is not None and not self.dry_run:
            raise PlanValidationError("offline plan-file mode requires dry-run")
        self.output_root = output_root or DEFAULT_OUTPUT_ROOT
        self.output_root.mkdir(parents=True, exist_ok=True)

        self.session_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = self.output_root / f"{self.mode}_{self.session_datetime}"
        self.session_dir.mkdir(parents=True, exist_ok=True)

        self.monitor_path = self.session_dir / "monitor.yaml"
        self.plan_path = self.session_dir / "dag_plan.yaml"
        self.virtual_validation_path = self.session_dir / "virtual_validation.yaml"
        self.execution_path = self.session_dir / "execution_result.yaml"

        self.robot_urls = {
            11: os.getenv("ROBOT_11_URL", "http://192.168.124.101:8000"),
            12: os.getenv("ROBOT_12_URL", "http://192.168.124.102:8000"),
            13: os.getenv("ROBOT_13_URL", "http://192.168.124.103:8000"),
            14: os.getenv("ROBOT_14_URL", "http://192.168.124.104:8000"),
            15: os.getenv("ROBOT_15_URL", "http://192.168.124.105:8000"),
            16: os.getenv("ROBOT_16_URL", "http://192.168.124.106:8000"),
        }
        self.control_center_url = os.getenv(
            "MULTI_ROBOT_CONTROL_CENTER_URL", "http://127.0.0.1:8080"
        ).rstrip("/")

        self.supported_navigation_targets = {
            "one_point_1",
            "one_point_2",
            "one_point_3",
            "one_point_4",
            "stop",
        }
        self.supported_arm_targets = {
            "release_arm",
            "turn_back_wave",
            "blow_kiss_with_both_hands",
            "blow_kiss_with_left_hand",
            "blow_kiss_with_right_hand",
            "both_hands_up",
            "clamp",
            "high_five",
            "hug",
            "make_heart_with_both_hands",
            "make_heart_with_right_hand",
            "refuse",
            "right_hand_up",
            "ultraman_ray",
            "wave_under_head",
            "wave_above_head",
            "shake_hand",
            "one_point_1_waypoint_1",
            "box_left_hand_win",
            "box_right_hand_win",
            "box_both_hand_win",
            "right_hand_on_heart",
            "both_hands_up_deviate_right",
            "forward_push",
        }

        self.client = None
        self.gpt_model = None
        if self.plan_file is None:
            self.client, self.gpt_model = self._build_llm_client()
        self.monitor = {
            "session_datetime": self.session_datetime,
            "session_dir": str(self.session_dir),
            "mode": self.mode,
            "dry_run": self.dry_run,
            "created_at": datetime.now().isoformat(),
            "status": "initialized",
            "validation_conclusion": "pending",
            "execution_conclusion": "pending",
            "events": [],
            "subtasks": [],
            "artifacts": {
                "dag_plan": str(self.plan_path),
                "virtual_validation": str(self.virtual_validation_path),
                "execution_result": str(self.execution_path),
            },
        }
        self._write_yaml(self.monitor_path, self.monitor)

    def _build_llm_client(self):
        from openai import AzureOpenAI, OpenAI

        gpt_provider = os.getenv("GPT_PROVIDER", "azure").strip().lower()
        gpt_api_key = (
            os.getenv("AZURE_OPENAI_API_KEY")
            if gpt_provider == "azure"
            else os.getenv("OPENAI_API_KEY")
        )
        if not gpt_api_key:
            raise RuntimeError(
                "未配置 GPT API Key，请设置 AZURE_OPENAI_API_KEY 或 OPENAI_API_KEY"
            )

        if gpt_provider == "azure":
            azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
            if not azure_endpoint:
                raise RuntimeError(
                    "未配置 Azure Endpoint，请设置 AZURE_OPENAI_ENDPOINT"
                )
            azure_api_version = os.getenv(
                "AZURE_OPENAI_API_VERSION", "2024-02-15-preview"
            )
            gpt_model = os.getenv(
                "AZURE_OPENAI_DEPLOYMENT",
                os.getenv("AZURE_OPENAI_MODEL", "gpt-4o"),
            )
            client = AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=gpt_api_key,
                api_version=azure_api_version,
            )
            return client, gpt_model

        gpt_model = os.getenv("OPENAI_MODEL", "gpt-4o")
        client = OpenAI(
            api_key=gpt_api_key, base_url=os.getenv("OPENAI_BASE_URL") or None
        )
        return client, gpt_model

    def _write_yaml(self, path: Path, data: dict) -> None:
        path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8"
        )

    def _append_event(self, event_type: str, payload: dict) -> None:
        self.monitor["events"].append(
            {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "payload": payload,
            }
        )
        self._write_yaml(self.monitor_path, self.monitor)

    def _update_monitor(self, **updates) -> None:
        self.monitor.update(updates)
        self._write_yaml(self.monitor_path, self.monitor)

    def _record_subtask_update(self, record: dict) -> None:
        subtasks = self.monitor.setdefault("subtasks", [])
        node_id = record["node_id"]
        for index, existing in enumerate(subtasks):
            if existing.get("node_id") == node_id:
                subtasks[index] = {**existing, **record}
                break
        else:
            subtasks.append(record)
        self._write_yaml(self.monitor_path, self.monitor)

    def _build_system_prompt(self) -> str:
        mode_rule = (
            "当前任务模式是 single_robot，只允许规划单个 robot_id 的串行多任务 DAG。"
            if self.mode == "single_robot"
            else "当前任务模式是 multi_robot，允许规划多个 robot_id 的并发协作 DAG。"
        )
        return f"""
你是一个机器人长指令任务规划器。你的职责是把用户自然语言长指令转换为一个可执行 DAG(JSON)。
你只能输出合法 JSON，不要输出 markdown，不要输出解释，不要输出代码块。

输出 JSON 格式固定为：
{{
  "description": "任务描述",
  "nodes": [
    {{
      "id": "r11_nav_p1",
      "robot_id": 11,
      "skill": "navigation",
      "target": "one_point_1",
      "depends_on": []
    }}
  ]
}}

字段约束：
- id: 字符串，必须唯一
- robot_id: 整数，必须是 11/12/13/14/15/16 之一
- skill: 只能是 "navigation" 或 "arm"
- target:
  - skill="navigation" 时只能是 {sorted(self.supported_navigation_targets)}
  - skill="arm" 时只能是 {sorted(self.supported_arm_targets)}
- depends_on: 字符串数组，没有依赖时必须输出 []
- “同时”表示并行，不要互相依赖
- “然后”“之后”“完成后”“到达后”表示建立依赖
- 不要凭空增加用户未提及的动作
- 如果无法可靠映射，输出 {{"description": "unrecognized", "nodes": []}}
- {mode_rule}

单机长指令样例：
{json.dumps(SINGLE_ROBOT_TEST_CASES, ensure_ascii=False, indent=2)}

多机长指令样例：
{json.dumps(MULTI_ROBOT_TEST_CASES, ensure_ascii=False, indent=2)}
"""

    def analyze_instruction(self, instruction: str) -> Optional[dict]:
        if self.client is None or self.gpt_model is None:
            raise RuntimeError("live text planning is unavailable in plan-file mode")
        self._append_event("instruction_received", {"instruction": instruction})
        try:
            response = self.client.responses.create(
                model=self.gpt_model,
                input=[
                    {"role": "system", "content": self._build_system_prompt()},
                    {"role": "user", "content": instruction},
                ],
            )
            content = ""
            if hasattr(response, "output_text") and response.output_text:
                content = response.output_text.strip()
            elif hasattr(response, "output") and response.output:
                for item in response.output:
                    if getattr(item, "type", "") != "message":
                        continue
                    for part in getattr(item, "content", []):
                        text_value = getattr(part, "text", None)
                        if text_value:
                            content += text_value

            if not content:
                self._append_event(
                    "dag_generation_failed", {"reason": "empty_response"}
                )
                return None

            dag = json.loads(content)
            normalized = self._validate_and_normalize_dag(dag)
            self._write_yaml(
                self.plan_path,
                {
                    "instruction": instruction,
                    "recorded_at": datetime.now().isoformat(),
                    "dag": normalized,
                },
            )
            self._append_event(
                "dag_generated",
                {
                    "node_count": len(normalized.get("nodes", [])) if normalized else 0,
                    "description": normalized.get("description", "")
                    if normalized
                    else "",
                },
            )
            return normalized
        except Exception as exc:
            self._append_event("dag_generation_failed", {"reason": str(exc)})
            return None

    def _validate_and_normalize_dag(self, dag: dict) -> Optional[dict]:
        if not isinstance(dag, dict):
            return None

        description = str(dag.get("description", "")).strip()
        nodes = dag.get("nodes", [])
        if not isinstance(nodes, list):
            return None

        normalized_nodes = []
        node_ids: Set[str] = set()
        robot_ids = set()

        for node in nodes:
            if not isinstance(node, dict):
                return None

            node_id = str(node.get("id", "")).strip()
            if not node_id or node_id in node_ids:
                return None

            try:
                robot_id = int(node.get("robot_id"))
            except Exception:
                return None

            skill = str(node.get("skill", "")).strip()
            target = str(node.get("target", "")).strip()
            depends_on = node.get("depends_on", [])

            if robot_id not in self.robot_urls:
                return None
            if skill not in {"navigation", "arm"}:
                return None
            if (
                skill == "navigation"
                and target not in self.supported_navigation_targets
            ):
                return None
            if skill == "arm" and target not in self.supported_arm_targets:
                return None
            if not isinstance(depends_on, list):
                return None

            normalized_nodes.append(
                {
                    "id": node_id,
                    "robot_id": robot_id,
                    "skill": skill,
                    "target": target,
                    "depends_on": [
                        str(dep).strip() for dep in depends_on if str(dep).strip()
                    ],
                }
            )
            node_ids.add(node_id)
            robot_ids.add(robot_id)

        if self.mode == "single_robot" and len(robot_ids) > 1:
            return None

        for node in normalized_nodes:
            for dep in node["depends_on"]:
                if dep not in node_ids:
                    return None

        if normalized_nodes and self._has_cycle(normalized_nodes):
            return None

        return {
            "description": description or f"{self.mode}_dag",
            "nodes": normalized_nodes,
        }

    def _has_cycle(self, nodes: List[dict]) -> bool:
        graph = {node["id"]: list(node["depends_on"]) for node in nodes}
        visiting = set()
        visited = set()

        def dfs(node_id: str) -> bool:
            if node_id in visiting:
                return True
            if node_id in visited:
                return False
            visiting.add(node_id)
            for dep in graph.get(node_id, []):
                if dfs(dep):
                    return True
            visiting.remove(node_id)
            visited.add(node_id)
            return False

        return any(dfs(node_id) for node_id in graph)

    def _build_dependency_closure(self, nodes: List[dict]) -> dict[str, Set[str]]:
        graph = {node["id"]: list(node["depends_on"]) for node in nodes}
        closure_cache: dict[str, Set[str]] = {}

        def collect_dependencies(node_id: str) -> Set[str]:
            if node_id in closure_cache:
                return closure_cache[node_id]

            dependencies: Set[str] = set()
            for dep in graph.get(node_id, []):
                dependencies.add(dep)
                dependencies.update(collect_dependencies(dep))

            closure_cache[node_id] = dependencies
            return dependencies

        for node_id in graph:
            collect_dependencies(node_id)

        return closure_cache

    def virtual_validate(self, dag: Optional[dict]) -> bool:
        result = {
            "recorded_at": datetime.now().isoformat(),
            "status": "passed",
            "conclusion": "虚拟执行验证通过：流程顺序正确，可进入真实执行阶段",
            "checks": [],
            "virtual_execution_trace": [],
        }

        if not dag or not dag.get("nodes"):
            result["status"] = "failed"
            result["conclusion"] = "虚拟执行验证失败：DAG 为空或无法识别，禁止真实执行"
            result["checks"].append(
                {
                    "name": "dag_non_empty",
                    "passed": False,
                    "reason": "DAG 为空或无法识别",
                }
            )
            self._write_yaml(self.virtual_validation_path, result)
            self._update_monitor(
                status="validation_failed", validation_conclusion=result["conclusion"]
            )
            return False

        nodes = dag["nodes"]
        node_map = {node["id"]: node for node in nodes}
        dependency_closure = self._build_dependency_closure(nodes)
        pending = set(node_map.keys())
        completed = set()
        step_index = 0

        for node in nodes:
            missing_deps = [dep for dep in node["depends_on"] if dep not in node_map]
            passed = not missing_deps
            result["checks"].append(
                {
                    "name": f"deps_exist::{node['id']}",
                    "passed": passed,
                    "missing_dependencies": missing_deps,
                }
            )
            if not passed:
                result["status"] = "failed"

        for node in nodes:
            conflicts = [
                other["id"]
                for other in nodes
                if other["id"] != node["id"]
                and other["robot_id"] == node["robot_id"]
                and node["id"] not in dependency_closure.get(other["id"], set())
                and other["id"] not in dependency_closure.get(node["id"], set())
            ]
            passed = not conflicts
            result["checks"].append(
                {
                    "name": f"single_robot_serialization::{node['id']}",
                    "passed": passed,
                    "conflicting_nodes": conflicts,
                }
            )
            if not passed:
                result["status"] = "failed"

        while pending and result["status"] == "passed":
            ready_nodes = [
                node_map[node_id]
                for node_id in sorted(pending)
                if all(dep in completed for dep in node_map[node_id]["depends_on"])
            ]
            if not ready_nodes:
                result["status"] = "failed"
                result["conclusion"] = (
                    "虚拟执行验证失败：存在无法推进的依赖阻塞，禁止真实执行"
                )
                result["checks"].append(
                    {
                        "name": "topology_progress",
                        "passed": False,
                        "reason": f"剩余节点无法推进: {sorted(pending)}",
                    }
                )
                break

            step_index += 1
            result["virtual_execution_trace"].append(
                {
                    "step": step_index,
                    "parallel_nodes": [
                        {
                            "id": node["id"],
                            "robot_id": node["robot_id"],
                            "skill": node["skill"],
                            "target": node["target"],
                        }
                        for node in ready_nodes
                    ],
                }
            )
            for node in ready_nodes:
                pending.remove(node["id"])
                completed.add(node["id"])

        if result["status"] != "passed" and result["conclusion"].startswith(
            "虚拟执行验证通过"
        ):
            result["conclusion"] = (
                "虚拟执行验证失败：存在依赖或串行约束问题，禁止真实执行"
            )

        self._write_yaml(self.virtual_validation_path, result)
        self._update_monitor(
            status="validated" if result["status"] == "passed" else "validation_failed",
            validation_conclusion=result["conclusion"],
        )
        self._append_event(
            "virtual_validation_completed",
            {"status": result["status"], "conclusion": result["conclusion"]},
        )
        return result["status"] == "passed"

    def execute(self, dag: Optional[dict]) -> bool:
        if self.dry_run:
            result = {
                "recorded_at": datetime.now().isoformat(),
                "status": "skipped",
                "conclusion": "当前为 dry-run，仅完成虚拟执行验证，未触发真实物理执行",
                "executed_nodes": [],
            }
            self._write_yaml(self.execution_path, result)
            self._update_monitor(
                status="dry_run_completed", execution_conclusion=result["conclusion"]
            )
            self._append_event("physical_execution_skipped", result)
            return True

        if not dag or not dag.get("nodes"):
            result = {
                "recorded_at": datetime.now().isoformat(),
                "status": "failed",
                "conclusion": "真实执行失败：DAG 为空",
                "executed_nodes": [],
            }
            self._write_yaml(self.execution_path, result)
            self._update_monitor(
                status="execution_failed", execution_conclusion=result["conclusion"]
            )
            return False

        nodes = dag["nodes"]
        node_map = {node["id"]: node for node in nodes}
        pending = set(node_map.keys())
        completed = set()
        failed = set()
        execution_trace = []

        with ThreadPoolExecutor(max_workers=self._DAG_EXECUTOR_MAX_WORKERS) as executor:
            while pending:
                ready_nodes = [
                    node_map[node_id]
                    for node_id in sorted(pending)
                    if all(dep in completed for dep in node_map[node_id]["depends_on"])
                ]
                if not ready_nodes:
                    break

                future_to_node_id = {
                    executor.submit(self._execute_single_node, node): node["id"]
                    for node in ready_nodes
                }
                for node in ready_nodes:
                    pending.remove(node["id"])

                for future, node_id in future_to_node_id.items():
                    success = future.result()
                    execution_trace.append({"node_id": node_id, "success": success})
                    if success:
                        completed.add(node_id)
                    else:
                        failed.add(node_id)

                if failed:
                    break

        success = not failed and not pending
        conclusion = (
            "真实执行完成：所有 DAG 节点已按验证后的顺序执行成功"
            if success
            else f"真实执行失败：失败节点={sorted(failed)}，剩余节点={sorted(pending)}"
        )
        result = {
            "recorded_at": datetime.now().isoformat(),
            "status": "passed" if success else "failed",
            "conclusion": conclusion,
            "completed_nodes": sorted(completed),
            "failed_nodes": sorted(failed),
            "remaining_nodes": sorted(pending),
            "execution_trace": execution_trace,
        }
        self._write_yaml(self.execution_path, result)
        self._update_monitor(
            status="completed" if success else "execution_failed",
            execution_conclusion=conclusion,
        )
        self._append_event(
            "physical_execution_completed",
            {"status": result["status"], "conclusion": conclusion},
        )
        return success

    def _execute_single_node(self, node: dict) -> bool:
        robot_id = node["robot_id"]
        skill = node["skill"]
        target = node["target"]
        started_at = datetime.now().isoformat()
        started_monotonic = time.time()

        self._record_subtask_update(
            {
                "node_id": node["id"],
                "robot_id": robot_id,
                "skill": skill,
                "target": target,
                "status": "running",
                "started_at": started_at,
            }
        )
        self._append_event(
            "node_execution_started",
            {
                "node_id": node["id"],
                "robot_id": robot_id,
                "skill": skill,
                "target": target,
                "started_at": started_at,
            },
        )

        if skill == "navigation":
            ok = self._call_robot_navigation(robot_id, target)
        elif skill == "arm":
            ok = self._call_robot_arm(robot_id, target)
        else:
            ok = False

        finished_at = datetime.now().isoformat()
        duration_sec = round(time.time() - started_monotonic, 3)
        status = "passed" if ok else "failed"
        self._record_subtask_update(
            {
                "node_id": node["id"],
                "robot_id": robot_id,
                "skill": skill,
                "target": target,
                "status": status,
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_sec": duration_sec,
            }
        )
        self._append_event(
            "node_execution_finished",
            {
                "node_id": node["id"],
                "robot_id": robot_id,
                "skill": skill,
                "target": target,
                "success": ok,
                "finished_at": finished_at,
                "duration_sec": duration_sec,
            },
        )
        print(
            f"[subtask] node={node['id']} robot={robot_id} skill={skill} "
            f"target={target} status={status} duration_sec={duration_sec}"
        )
        return ok

    def _call_robot_navigation(self, robot_id: int, target: str) -> bool:
        self._append_event(
            "navigation_trigger_requested",
            {"robot_id": robot_id, "target": target},
        )
        self._reset_control_center_reached_state([robot_id])
        url = f"{self.control_center_url}/trigger/{target}?robot_id={robot_id}"
        if not self._post_json(url):
            self._append_event(
                "navigation_trigger_failed",
                {"robot_id": robot_id, "target": target},
            )
            return False
        self._append_event(
            "navigation_trigger_accepted",
            {"robot_id": robot_id, "target": target},
        )
        return self._wait_for_robot_navigation_completion(robot_id, target)

    def _call_robot_arm(self, robot_id: int, target: str) -> bool:
        self._append_event(
            "arm_trigger_requested",
            {"robot_id": robot_id, "target": target},
        )
        url = f"{self.robot_urls[robot_id]}/api/arm/{target}"
        ok = self._post_json(url)
        if ok:
            self._append_event(
                "arm_trigger_accepted",
                {
                    "robot_id": robot_id,
                    "target": target,
                    "wait_sec": self._ARM_SKILL_WAIT_SEC,
                },
            )
            time.sleep(self._ARM_SKILL_WAIT_SEC)
            self._append_event(
                "arm_wait_completed",
                {
                    "robot_id": robot_id,
                    "target": target,
                    "wait_sec": self._ARM_SKILL_WAIT_SEC,
                },
            )
        else:
            self._append_event(
                "arm_trigger_failed",
                {"robot_id": robot_id, "target": target},
            )
        return ok

    def _post_json(self, url: str, payload: Optional[dict] = None) -> bool:
        import requests

        try:
            response = requests.post(url, json=payload, timeout=self._HTTP_TIMEOUT_SEC)
            return response.ok
        except Exception:
            return False

    def _reset_control_center_reached_state(self, robot_ids: List[int]) -> None:
        import requests

        try:
            requests.post(
                f"{self.control_center_url}/reset_reached",
                json={"robot_ids": robot_ids},
                timeout=self._CONTROL_CENTER_TIMEOUT_SEC,
            )
        except Exception:
            pass

    def _wait_for_robot_navigation_completion(self, robot_id: int, target: str) -> bool:
        import requests

        wait_started_at = datetime.now().isoformat()
        self._append_event(
            "navigation_wait_started",
            {"robot_id": robot_id, "target": target, "started_at": wait_started_at},
        )
        deadline = time.time() + self._NAV_WAIT_TIMEOUT_SEC
        while time.time() < deadline:
            try:
                response = requests.get(
                    f"{self.control_center_url}/robot_reached/{robot_id}",
                    params={"target": target},
                    timeout=self._CONTROL_CENTER_TIMEOUT_SEC,
                )
                if response.ok and response.json().get("reached"):
                    self._append_event(
                        "navigation_wait_completed",
                        {
                            "robot_id": robot_id,
                            "target": target,
                            "finished_at": datetime.now().isoformat(),
                            "completion_source": "nav_finish",
                        },
                    )
                    return True
            except Exception:
                pass
            time.sleep(0.5)

        self._append_event(
            "navigation_wait_timeout",
            {
                "robot_id": robot_id,
                "target": target,
                "finished_at": datetime.now().isoformat(),
                "timeout_sec": self._NAV_WAIT_TIMEOUT_SEC,
            },
        )
        return False

    def run_offline(self) -> OfflinePlanResult:
        guard = OfflineSideEffectGuard()
        try:
            with guard:
                result = self._run_offline_guarded()
        except OfflineSideEffectAttempt:
            return OfflinePlanResult(
                status="FAIL",
                exit_code=3,
                session_dir=self.session_dir,
                plan_path=self.plan_path,
                validation_path=self.virtual_validation_path,
                execution_path=self.execution_path,
                network_attempts=tuple(guard.network_attempts),
                process_attempts=tuple(guard.process_attempts),
                ros_publication_attempts=tuple(guard.ros_publication_attempts),
            )
        return OfflinePlanResult(
            status=result.status,
            exit_code=result.exit_code,
            session_dir=result.session_dir,
            plan_path=result.plan_path,
            validation_path=result.validation_path,
            execution_path=result.execution_path,
            network_attempts=tuple(guard.network_attempts),
            process_attempts=tuple(guard.process_attempts),
            ros_publication_attempts=tuple(guard.ros_publication_attempts),
        )

    def _run_offline_guarded(self) -> OfflinePlanResult:
        if self.plan_file is None:
            raise PlanValidationError("offline execution requires a plan file")
        plan = load_plan_file(self.plan_file, self.schema_path)
        if plan["mode"] != self.mode:
            raise PlanValidationError("plan mode does not match CLI mode")
        dag = {
            "description": plan["description"],
            "nodes": plan["nodes"],
        }
        self._update_monitor(status="planning")
        self._write_yaml(
            self.plan_path,
            {
                "instruction": None,
                "recorded_at": datetime.now().isoformat(),
                "source": "offline_plan_file",
                "schema_version": plan["schema_version"],
                "mode": plan["mode"],
                "dag": dag,
            },
        )
        self._append_event(
            "offline_plan_loaded",
            {
                "schema_version": plan["schema_version"],
                "node_count": len(plan["nodes"]),
            },
        )
        validation_ok = self.virtual_validate(dag)
        if not validation_ok:
            self._update_monitor(
                execution_conclusion="虚拟执行验证未通过，真实执行被阻止",
            )
            exit_code = 2
            status = "FAIL"
        else:
            execution_ok = self.execute(dag)
            exit_code = 0 if execution_ok else 3
            status = "PASS" if execution_ok else "FAIL"
        return OfflinePlanResult(
            status=status,
            exit_code=exit_code,
            session_dir=self.session_dir,
            plan_path=self.plan_path,
            validation_path=self.virtual_validation_path,
            execution_path=self.execution_path,
        )

    def run(self, instruction: str | None = None) -> int:
        if self.plan_file is not None:
            if instruction is not None:
                raise PlanValidationError(
                    "plan-file mode rejects live text-planning arguments"
                )
            return self.run_offline().exit_code
        if instruction is None:
            raise ValueError("live text planning requires an instruction")
        self._update_monitor(status="planning")
        dag = self.analyze_instruction(instruction)
        if not dag:
            self._update_monitor(
                status="planning_failed",
                validation_conclusion="DAG 规划失败，无法进入虚拟执行验证",
                execution_conclusion="未执行",
            )
            return 1

        validation_ok = self.virtual_validate(dag)
        if not validation_ok:
            self._update_monitor(
                execution_conclusion="虚拟执行验证未通过，真实执行被阻止",
            )
            return 2

        execution_ok = self.execute(dag)
        return 0 if execution_ok else 3


class _RunnerArgumentParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)
        if parsed.plan_file is not None and not parsed.dry_run:
            self.error("--plan-file requires --dry-run")
        return parsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = _RunnerArgumentParser(description="纯文本长指令 DAG 执行器")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--instruction", help="纯文本长指令")
    input_group.add_argument("--plan-file", help="schema-validated offline DAG JSON")
    parser.add_argument(
        "--mode", choices=["single_robot", "multi_robot"], required=True
    )
    parser.add_argument("--dry-run", action="store_true", help="仅做规划和虚拟执行验证")
    parser.add_argument("--output-root", default=str(DEFAULT_OUTPUT_ROOT))
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    runner = LongHorizonTextRunner(
        mode=args.mode,
        dry_run=args.dry_run,
        output_root=Path(args.output_root),
        plan_file=Path(args.plan_file) if args.plan_file is not None else None,
    )
    return runner.run(args.instruction)


def run_offline_plan(
    plan_file: Path,
    *,
    mode: str,
    output_root: Path,
    schema_path: Path = DEFAULT_PLAN_SCHEMA,
) -> OfflinePlanResult:
    """Run the deterministic, dry-run-only AgentOS plan boundary."""

    return LongHorizonTextRunner(
        mode=mode,
        dry_run=True,
        output_root=output_root,
        plan_file=plan_file,
        schema_path=schema_path,
    ).run_offline()


if __name__ == "__main__":
    raise SystemExit(main())
