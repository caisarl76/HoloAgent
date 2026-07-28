from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from holoagent_mujoco.preflight import (
    PARAMETER_SERVICE_TYPES,
    PreflightError,
    assert_no_forbidden_source,
    merge_postflight_result,
    scan_forbidden_processes,
    validate_isolation_environment,
)
from holoagent_mujoco.stage2_result import (
    _container_pid_alive,
    _docker_inspect,
    _parse_snapshot,
    _pid_alive,
    _typed_lines,
    _write_json,
    collect_source_provenance,
    validate_container_contract,
)
from holoagent_mujoco.stage4_config import load_stage4_config


EXPECTED_NODES = (
    "/bt_navigator",
    "/bt_navigator_navigate_through_poses_rclcpp_node",
    "/bt_navigator_navigate_to_pose_rclcpp_node",
    "/controller_server",
    "/global_costmap/global_costmap",
    "/holoagent_mujoco_bridge",
    "/holoagent_stage4_eval",
    "/lifecycle_manager_stage4",
    "/local_costmap/local_costmap",
    "/map_server",
    "/planner_server",
    "/sim_fixture",
)

# This allowlist is intentionally explicit. The first isolated runtime capture is
# expected to expose any distribution-specific Nav2 endpoints before approval.
EXPECTED_TOPIC_TYPES = {
    "/behavior_tree_log": "nav2_msgs/msg/BehaviorTreeLog",
    "/bond": "bond/msg/Status",
    "/bt_navigator/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/camera/color/camera_info": "sensor_msgs/msg/CameraInfo",
    "/camera/color/image_raw": "sensor_msgs/msg/Image",
    "/clock": "rosgraph_msgs/msg/Clock",
    "/cmd_vel": "geometry_msgs/msg/Twist",
    "/controller_server/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/cost_cloud": "sensor_msgs/msg/PointCloud2",
    "/diagnostics": "diagnostic_msgs/msg/DiagnosticArray",
    "/evaluation": "dwb_msgs/msg/LocalPlanEvaluation",
    "/global_costmap/costmap": "nav_msgs/msg/OccupancyGrid",
    "/global_costmap/costmap_raw": "nav2_msgs/msg/Costmap",
    "/global_costmap/costmap_updates": "map_msgs/msg/OccupancyGridUpdate",
    "/global_costmap/footprint": "geometry_msgs/msg/Polygon",
    "/global_costmap/global_costmap/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/global_costmap/published_footprint": "geometry_msgs/msg/PolygonStamped",
    "/goal_pose": "geometry_msgs/msg/PoseStamped",
    "/holoagent_sim/applied_cmd_vel": "geometry_msgs/msg/Twist",
    "/holoagent_sim/collision_count": "std_msgs/msg/UInt32",
    "/holoagent_sim/contact_count": "std_msgs/msg/UInt32",
    "/livox/imu": "sensor_msgs/msg/Imu",
    "/local_costmap/costmap": "nav_msgs/msg/OccupancyGrid",
    "/local_costmap/costmap_raw": "nav2_msgs/msg/Costmap",
    "/local_costmap/costmap_updates": "map_msgs/msg/OccupancyGridUpdate",
    "/local_costmap/footprint": "geometry_msgs/msg/Polygon",
    "/local_costmap/local_costmap/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/local_costmap/published_footprint": "geometry_msgs/msg/PolygonStamped",
    "/local_plan": "nav_msgs/msg/Path",
    "/map": "nav_msgs/msg/OccupancyGrid",
    "/map_server/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/marker": "visualization_msgs/msg/MarkerArray",
    "/object_pose": "geometry_msgs/msg/PoseStamped",
    "/odom": "nav_msgs/msg/Odometry",
    "/parameter_events": "rcl_interfaces/msg/ParameterEvent",
    "/plan": "nav_msgs/msg/Path",
    "/planner_server/transition_event": "lifecycle_msgs/msg/TransitionEvent",
    "/received_global_plan": "nav_msgs/msg/Path",
    "/robot_odom": "nav_msgs/msg/Odometry",
    "/rosout": "rcl_interfaces/msg/Log",
    "/sim_fixture/query": "std_msgs/msg/String",
    "/speed_limit": "nav2_msgs/msg/SpeedLimit",
    "/tf": "tf2_msgs/msg/TFMessage",
    "/tf_static": "tf2_msgs/msg/TFMessage",
    "/transformed_global_plan": "nav_msgs/msg/Path",
}

EXPECTED_SERVICE_TYPES = {
    f"{node}/{name}": kind
    for node in EXPECTED_NODES
    for name, kind in PARAMETER_SERVICE_TYPES.items()
}
EXPECTED_SERVICE_TYPES.update(
    {
        "/bt_navigator/change_state": "lifecycle_msgs/srv/ChangeState",
        "/bt_navigator/get_state": "lifecycle_msgs/srv/GetState",
        "/bt_navigator/get_available_states": "lifecycle_msgs/srv/GetAvailableStates",
        "/bt_navigator/get_available_transitions": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/bt_navigator/get_transition_graph": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/controller_server/change_state": "lifecycle_msgs/srv/ChangeState",
        "/controller_server/get_state": "lifecycle_msgs/srv/GetState",
        "/controller_server/get_available_states": "lifecycle_msgs/srv/GetAvailableStates",
        "/controller_server/get_available_transitions": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/controller_server/get_transition_graph": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/map_server/change_state": "lifecycle_msgs/srv/ChangeState",
        "/map_server/get_state": "lifecycle_msgs/srv/GetState",
        "/map_server/get_available_states": "lifecycle_msgs/srv/GetAvailableStates",
        "/map_server/get_available_transitions": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/map_server/get_transition_graph": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/map_server/load_map": "nav2_msgs/srv/LoadMap",
        "/map_server/map": "nav_msgs/srv/GetMap",
        "/planner_server/change_state": "lifecycle_msgs/srv/ChangeState",
        "/planner_server/get_state": "lifecycle_msgs/srv/GetState",
        "/planner_server/get_available_states": "lifecycle_msgs/srv/GetAvailableStates",
        "/planner_server/get_available_transitions": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/planner_server/get_transition_graph": "lifecycle_msgs/srv/GetAvailableTransitions",
        "/is_path_valid": "nav2_msgs/srv/IsPathValid",
        "/lifecycle_manager_stage4/is_active": "std_srvs/srv/Trigger",
        "/lifecycle_manager_stage4/manage_nodes": "nav2_msgs/srv/ManageLifecycleNodes",
        "/global_costmap/clear_around_global_costmap": "nav2_msgs/srv/ClearCostmapAroundRobot",
        "/global_costmap/clear_entirely_global_costmap": "nav2_msgs/srv/ClearEntireCostmap",
        "/global_costmap/clear_except_global_costmap": "nav2_msgs/srv/ClearCostmapExceptRegion",
        "/global_costmap/get_costmap": "nav2_msgs/srv/GetCostmap",
        "/local_costmap/clear_around_local_costmap": "nav2_msgs/srv/ClearCostmapAroundRobot",
        "/local_costmap/clear_entirely_local_costmap": "nav2_msgs/srv/ClearEntireCostmap",
        "/local_costmap/clear_except_local_costmap": "nav2_msgs/srv/ClearCostmapExceptRegion",
        "/local_costmap/get_costmap": "nav2_msgs/srv/GetCostmap",
    }
)

for costmap in ("/global_costmap/global_costmap", "/local_costmap/local_costmap"):
    EXPECTED_SERVICE_TYPES.update(
        {
            f"{costmap}/change_state": "lifecycle_msgs/srv/ChangeState",
            f"{costmap}/get_state": "lifecycle_msgs/srv/GetState",
            f"{costmap}/get_available_states": "lifecycle_msgs/srv/GetAvailableStates",
            f"{costmap}/get_available_transitions": "lifecycle_msgs/srv/GetAvailableTransitions",
            f"{costmap}/get_transition_graph": "lifecycle_msgs/srv/GetAvailableTransitions",
        }
    )

EXPECTED_ACTION_TYPES = {
    "/compute_path_through_poses": "nav2_msgs/action/ComputePathThroughPoses",
    "/compute_path_to_pose": "nav2_msgs/action/ComputePathToPose",
    "/follow_path": "nav2_msgs/action/FollowPath",
    "/navigate_to_pose": "nav2_msgs/action/NavigateToPose",
    "/navigate_through_poses": "nav2_msgs/action/NavigateThroughPoses",
}

NAV2_PACKAGE_PREFIXES = {
    "ros-humble-navigation2": "1.1.20-",
    "ros-humble-nav2-bringup": "1.1.20-",
    "ros-humble-nav2-controller": "1.1.20-",
    "ros-humble-nav2-lifecycle-manager": "1.1.20-",
    "ros-humble-nav2-map-server": "1.1.20-",
    "ros-humble-nav2-planner": "1.1.20-",
    "ros-humble-diagnostic-updater": "4.0.7-",
}
NAV2_PACKAGES = tuple(NAV2_PACKAGE_PREFIXES)
TRANSFORM_LISTENER_PATTERN = re.compile(r"^/transform_listener_impl_[0-9a-f]{12}$")


def validate_stage4_node_names(nodes: set[str]) -> dict[str, list[str]]:
    generated = sorted(
        name for name in nodes if TRANSFORM_LISTENER_PATTERN.fullmatch(name)
    )
    static = sorted(nodes - set(generated))
    missing = sorted(set(EXPECTED_NODES) - set(static))
    unexpected = sorted(set(static) - set(EXPECTED_NODES))
    if missing or unexpected or len(generated) != 2:
        raise PreflightError(
            "unexpected Stage 4 nodes: "
            f"missing={missing}, unexpected={unexpected}, "
            f"transform_listeners={generated}"
        )
    return {"static": static, "transform_listeners": generated}


def validate_endpoint_ownership(
    *,
    publishers: set[str],
    subscribers: set[str],
    expected_publishers: set[str],
    expected_subscribers: set[str],
    topic: str,
) -> dict[str, Any]:
    if publishers != expected_publishers or subscribers != expected_subscribers:
        raise PreflightError(
            f"Stage 4 endpoint ownership mismatch for {topic}: "
            f"publishers={sorted(publishers)}, subscribers={sorted(subscribers)}"
        )
    return {
        "topic": topic,
        "publishers": sorted(publishers),
        "subscribers": sorted(subscribers),
        "publisher_count": len(publishers),
        "subscriber_count": len(subscribers),
    }


def _require_exact(
    actual: dict[str, str], expected: dict[str, str], *, label: str
) -> None:
    if actual == expected:
        return
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    wrong = {
        name: {"expected": expected[name], "actual": actual[name]}
        for name in sorted(set(actual) & set(expected))
        if actual[name] != expected[name]
    }
    raise PreflightError(
        f"Stage 4 {label} allowlist mismatch: missing={missing}, "
        f"unexpected={unexpected}, wrong_types={wrong}"
    )


def validate_stage4_graph(host: str, container: str) -> dict[str, Any]:
    if host != container:
        raise PreflightError("host and container Stage 4 graphs differ")
    sections = _parse_snapshot(host)
    if len(sections["nodes"]) != len(set(sections["nodes"])):
        raise PreflightError("duplicate Stage 4 nodes are forbidden")
    nodes = set(sections["nodes"])
    node_contract = validate_stage4_node_names(nodes)
    topics = _typed_lines(sections["topics"])
    services = _typed_lines(sections["services"])
    actions = _typed_lines(sections["actions"])
    _require_exact(topics, EXPECTED_TOPIC_TYPES, label="topic")
    _require_exact(services, EXPECTED_SERVICE_TYPES, label="service")
    _require_exact(actions, EXPECTED_ACTION_TYPES, label="action")
    return {
        "nodes": sorted(nodes),
        "node_contract": node_contract,
        "topics": topics,
        "services": services,
        "actions": actions,
    }


def validate_empty_graph(host: str, container: str) -> dict[str, list[str]]:
    if host != container:
        raise PreflightError("host and container postflight graphs differ")
    sections = _parse_snapshot(host)
    cli_topics = {
        "/parameter_events": "rcl_interfaces/msg/ParameterEvent",
        "/rosout": "rcl_interfaces/msg/Log",
    }
    unexpected = {
        "nodes": sections["nodes"],
        "topics": (
            sections["topics"] if _typed_lines(sections["topics"]) != cli_topics else []
        ),
        "services": sections["services"],
        "actions": sections["actions"],
    }
    populated = {name: values for name, values in unexpected.items() if values}
    if populated:
        raise PreflightError(f"Stage 4 postflight graph is not empty: {populated}")
    return sections


def parse_stage4_processes(output: str) -> list[dict[str, Any]]:
    exact_tokens = (
        "/nav2_map_server/map_server",
        "/nav2_planner/planner_server",
        "/nav2_controller/controller_server",
        "/nav2_bt_navigator/bt_navigator",
        "/nav2_lifecycle_manager/lifecycle_manager",
        "/holoagent_mujoco/stage4_fixture",
        "/holoagent_mujoco/stage4_eval",
        "ros2 launch holoagent_mujoco stage4_nav2.launch.py",
    )
    found = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        if any(token in parts[1] for token in exact_tokens):
            found.append({"pid": int(parts[0]), "command": parts[1]})
    return found


def _container_stage4_processes(container: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["docker", "exec", container, "ps", "-eo", "pid=,args="],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise PreflightError("cannot inspect Stage 4 container processes")
    return parse_stage4_processes(result.stdout)


def validate_nav2_versions(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    try:
        versions = json.loads(text)
    except json.JSONDecodeError:
        versions = {}
        for line in text.splitlines():
            parts = line.strip().split("=", 1)
            if len(parts) != 2 or not all(parts):
                raise PreflightError("invalid Nav2 package version evidence")
            versions[parts[0]] = parts[1]
    if not isinstance(versions, dict):
        raise PreflightError("Nav2 package version evidence must be an object")
    if set(versions) != set(NAV2_PACKAGES):
        raise PreflightError("Nav2 package version evidence is incomplete")
    if any(
        not str(versions[name]).startswith(prefix)
        for name, prefix in NAV2_PACKAGE_PREFIXES.items()
    ):
        raise PreflightError(f"unexpected Nav2 package versions: {versions}")
    return {name: str(versions[name]) for name in NAV2_PACKAGES}


def validate_evaluator_status(result: dict[str, Any], exit_status: int | None) -> None:
    if result.get("status") == "PASS" and exit_status != 0:
        raise PreflightError("passing Stage 4 evaluator must exit zero")
    if result.get("status") == "FAIL" and exit_status != 1:
        raise PreflightError("failed Stage 4 evaluator must exit one")
    if result.get("status") not in {"PASS", "FAIL"}:
        raise PreflightError("invalid Stage 4 evaluator status")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 4 preflight/finalizer")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--workspace-source", type=Path, required=True)
    parser.add_argument("--nav2-versions", type=Path)
    parser.add_argument("--graph-host", type=Path)
    parser.add_argument("--graph-container", type=Path)
    parser.add_argument("--postflight", action="store_true")
    parser.add_argument("--host-pid", action="append", type=int, default=[])
    parser.add_argument("--container-pid", action="append", type=int, default=[])
    parser.add_argument("--evaluator-exit-status", type=int)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--final-result-file", type=Path)
    args = parser.parse_args(argv)
    run_dir = args.run_dir.resolve()
    try:
        config = load_stage4_config(args.config)
        validate_isolation_environment(os.environ, config.bridge)
        container = validate_container_contract(
            _docker_inspect(args.container),
            expected_name=args.container,
            expected_source=args.workspace_source,
        )
        forbidden = scan_forbidden_processes()
        if forbidden:
            raise PreflightError(f"physical motion processes are running: {forbidden}")
        if args.postflight:
            alive_host = [pid for pid in args.host_pid if _pid_alive(pid)]
            alive_container = [
                pid
                for pid in args.container_pid
                if _container_pid_alive(args.container, pid)
            ]
            remnants = _container_stage4_processes(args.container)
            if alive_host or alive_container or remnants:
                raise PreflightError(
                    "Stage 4 cleanup incomplete: "
                    f"host={alive_host}, container={alive_container}, remnants={remnants}"
                )
            if args.graph_host is None or args.graph_container is None:
                raise PreflightError("Stage 4 postflight graph snapshots are required")
            validate_empty_graph(
                args.graph_host.read_text(encoding="utf-8"),
                args.graph_container.read_text(encoding="utf-8"),
            )
            if args.result_file is None or args.final_result_file is None:
                raise PreflightError("Stage 4 postflight result paths are required")
            pending = json.loads(args.result_file.read_text(encoding="utf-8"))
            validate_evaluator_status(pending, args.evaluator_exit_status)
            result = {
                "status": "PASS",
                "gate": "postflight",
                "container": container,
                "provenance": collect_source_provenance(
                    args.workspace_source, container
                ),
                "host_pids": args.host_pid,
                "container_pids": args.container_pid,
                "forbidden_processes": forbidden,
                "graph_empty": True,
            }
            _write_json(run_dir / "postflight.json", result)
            merge_postflight_result(
                args.result_file, result, final_path=args.final_result_file
            )
        elif args.graph_host is not None and args.graph_container is not None:
            graph = validate_stage4_graph(
                args.graph_host.read_text(encoding="utf-8"),
                args.graph_container.read_text(encoding="utf-8"),
            )
            result = {"status": "PASS", "gate": "graph", "graph": graph}
            _write_json(run_dir / "graph_preflight.json", result)
        else:
            if run_dir.exists():
                raise PreflightError("run directory already exists")
            run_dir.mkdir()
            (run_dir / "ros_logs").mkdir()
            if args.nav2_versions is None:
                raise PreflightError("Nav2 package version evidence is required")
            versions = validate_nav2_versions(args.nav2_versions)
            assert_no_forbidden_source(Path(__file__).parent)
            remnants = _container_stage4_processes(args.container)
            if remnants:
                raise PreflightError(f"stale Stage 4 container processes: {remnants}")
            result = {
                "status": "PASS",
                "gate": "initial_preflight",
                "container": container,
                "nav2_versions": versions,
                "forbidden_processes": forbidden,
            }
            _write_json(run_dir / "preflight.json", result)
    except Exception as exc:
        result = {
            "status": "FAIL",
            "error": str(exc),
            "exception_type": type(exc).__name__,
        }
        if run_dir.is_dir():
            _write_json(run_dir / "stage4_result_error.json", result)
        print(str(exc))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
