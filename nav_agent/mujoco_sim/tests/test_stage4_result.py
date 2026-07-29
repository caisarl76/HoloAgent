from __future__ import annotations

import pytest

from holoagent_mujoco.preflight import PreflightError
from holoagent_mujoco.stage4_result import (
    EXPECTED_ACTION_TYPES,
    EXPECTED_NODES,
    EXPECTED_SERVICE_TYPES,
    EXPECTED_TOPIC_TYPES,
    parse_stage4_processes,
    validate_clock_subscriptions,
    validate_empty_graph,
    validate_endpoint_ownership,
    validate_evaluator_status,
    validate_nav2_versions,
    validate_stage4_graph,
)


def _snapshot() -> str:
    sections = [
        "=== NODES ===",
        *EXPECTED_NODES,
        "/transform_listener_impl_000000000001",
        "/transform_listener_impl_000000000002",
        "=== TOPICS ===",
    ]
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_TOPIC_TYPES.items())
    sections.append("=== SERVICES ===")
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_SERVICE_TYPES.items())
    sections.append("=== ACTIONS ===")
    sections.extend(f"{name} [{kind}]" for name, kind in EXPECTED_ACTION_TYPES.items())
    return "\n".join(sections) + "\n"


def test_stage4_graph_is_exact_and_identical_from_host_and_container():
    graph = validate_stage4_graph(_snapshot(), _snapshot())
    assert graph["node_contract"]["static"] == list(EXPECTED_NODES)
    assert len(graph["node_contract"]["transform_listeners"]) == 2
    assert graph["topics"] == EXPECTED_TOPIC_TYPES


def test_stage4_graph_rejects_physical_motion_participant():
    altered = _snapshot().replace("=== TOPICS ===", "/g1_pubvel_node\n=== TOPICS ===")
    with pytest.raises(PreflightError, match="unexpected Stage 4 nodes"):
        validate_stage4_graph(altered, altered)


def test_stage4_graph_rejects_wrong_transform_listener_count():
    altered = _snapshot().replace("/transform_listener_impl_000000000002\n", "")
    with pytest.raises(PreflightError, match="transform_listeners"):
        validate_stage4_graph(altered, altered)


def test_stage4_graph_rejects_duplicate_node_rows():
    altered = _snapshot().replace(
        "=== TOPICS ===", "/controller_server\n=== TOPICS ==="
    )
    with pytest.raises(PreflightError, match="duplicate Stage 4 nodes"):
        validate_stage4_graph(altered, altered)


def test_stage4_process_parser_tracks_only_exact_simulation_components():
    output = """
12 /opt/ros/humble/lib/nav2_controller/controller_server --ros-args
13 /tmp/build/install/holoagent_mujoco/lib/holoagent_mujoco/stage4_eval --config x
14 /usr/bin/python3 unrelated.py
"""
    assert [item["pid"] for item in parse_stage4_processes(output)] == [12, 13]


def test_stage4_endpoint_ownership_is_exact_and_serializable():
    evidence = validate_endpoint_ownership(
        publishers={"/controller_server"},
        subscribers={"/holoagent_mujoco_bridge", "/holoagent_stage4_eval"},
        expected_publishers={"/controller_server"},
        expected_subscribers={
            "/holoagent_mujoco_bridge",
            "/holoagent_stage4_eval",
        },
        topic="/cmd_vel",
    )
    assert evidence == {
        "topic": "/cmd_vel",
        "publishers": ["/controller_server"],
        "subscribers": [
            "/holoagent_mujoco_bridge",
            "/holoagent_stage4_eval",
        ],
        "publisher_count": 1,
        "subscriber_count": 2,
    }

    with pytest.raises(PreflightError, match="ownership mismatch"):
        validate_endpoint_ownership(
            publishers=set(),
            subscribers={"/holoagent_stage4_eval"},
            expected_publishers={"/holoagent_mujoco_bridge"},
            expected_subscribers={"/holoagent_stage4_eval"},
            topic="/holoagent_sim/collision_count",
        )


def test_bt_helper_clock_subscriptions_are_live_sim_time_evidence():
    required = {
        "/bt_navigator_navigate_to_pose_rclcpp_node",
        "/bt_navigator_navigate_through_poses_rclcpp_node",
    }
    evidence = validate_clock_subscriptions(
        subscribers={*required, "/holoagent_stage4_eval"},
        required_nodes=required,
    )
    assert evidence == {
        "required_nodes": sorted(required),
        "subscribers": sorted({*required, "/holoagent_stage4_eval"}),
    }

    with pytest.raises(PreflightError, match="clock subscriptions"):
        validate_clock_subscriptions(
            subscribers={"/bt_navigator_navigate_to_pose_rclcpp_node"},
            required_nodes=required,
        )


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


def test_nav2_version_gate_rejects_the_incompatible_diagnostic_library(tmp_path):
    evidence = tmp_path / "versions.txt"
    evidence.write_text(
        """ros-humble-navigation2=1.1.20-build
ros-humble-nav2-bringup=1.1.20-build
ros-humble-nav2-controller=1.1.20-build
ros-humble-nav2-lifecycle-manager=1.1.20-build
ros-humble-nav2-map-server=1.1.20-build
ros-humble-nav2-planner=1.1.20-build
ros-humble-diagnostic-updater=4.0.7-build
""",
        encoding="utf-8",
    )
    assert validate_nav2_versions(evidence)["ros-humble-diagnostic-updater"].startswith(
        "4.0.7-"
    )

    evidence.write_text(
        evidence.read_text(encoding="utf-8").replace("4.0.7-", "4.0.6-"),
        encoding="utf-8",
    )
    with pytest.raises(PreflightError, match="unexpected Nav2 package versions"):
        validate_nav2_versions(evidence)
