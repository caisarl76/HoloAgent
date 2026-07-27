from __future__ import annotations

import pytest

from holoagent_mujoco.preflight import PreflightError
from holoagent_mujoco.stage4_result import (
    EXPECTED_ACTION_TYPES,
    EXPECTED_NODES,
    EXPECTED_SERVICE_TYPES,
    EXPECTED_TOPIC_TYPES,
    parse_stage4_processes,
    validate_empty_graph,
    validate_evaluator_status,
    validate_stage4_graph,
)


def _snapshot() -> str:
    sections = ["=== NODES ===", *EXPECTED_NODES, "=== TOPICS ==="]
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_TOPIC_TYPES.items())
    sections.append("=== SERVICES ===")
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_SERVICE_TYPES.items())
    sections.append("=== ACTIONS ===")
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_ACTION_TYPES.items())
    return "\n".join(sections) + "\n"


def test_stage4_graph_is_exact_and_identical_from_host_and_container():
    graph = validate_stage4_graph(_snapshot(), _snapshot())
    assert graph["nodes"] == list(EXPECTED_NODES)
    assert graph["topics"] == EXPECTED_TOPIC_TYPES


def test_stage4_graph_rejects_physical_motion_participant():
    altered = _snapshot().replace("=== TOPICS ===", "/g1_pubvel_node\n=== TOPICS ===")
    with pytest.raises(PreflightError, match="unexpected Stage 4 nodes"):
        validate_stage4_graph(altered, altered)


def test_stage4_process_parser_tracks_only_exact_simulation_components():
    output = """
12 /opt/ros/humble/lib/nav2_controller/controller_server --ros-args
13 /tmp/build/install/holoagent_mujoco/lib/holoagent_mujoco/stage4_eval --config x
14 /usr/bin/python3 unrelated.py
"""
    assert [item["pid"] for item in parse_stage4_processes(output)] == [12, 13]


def test_stage4_evaluator_exit_status_preserves_pass_or_failure():
    validate_evaluator_status({"status": "PASS"}, 0)
    validate_evaluator_status({"status": "FAIL"}, 1)
    with pytest.raises(PreflightError, match="exit one"):
        validate_evaluator_status({"status": "FAIL"}, 0)


def test_postflight_graph_allows_only_ros_cli_builtin_topics():
    snapshot = """=== NODES ===
=== TOPICS ===
/parameter_events [rcl_interfaces/msg/ParameterEvent]
/rosout [rcl_interfaces/msg/Log]
=== SERVICES ===
=== ACTIONS ===
"""
    graph = validate_empty_graph(snapshot, snapshot)
    assert graph["nodes"] == []

    altered = snapshot.replace(
        "=== SERVICES ===", "/cmd_vel [geometry_msgs/msg/Twist]\n=== SERVICES ==="
    )
    with pytest.raises(PreflightError, match="not empty"):
        validate_empty_graph(altered, altered)
