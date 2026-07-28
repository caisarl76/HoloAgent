from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from holoagent_mujoco.config import load_config
from holoagent_mujoco.preflight import (
    PARAMETER_SERVICE_TYPES,
    PreflightError,
    merge_postflight_result,
    scan_forbidden_processes,
    validate_isolation_environment,
)
from holoagent_mujoco.stage2_result import (
    _container_pid_alive,
    _container_stage_processes,
    _docker_inspect,
    _parse_snapshot,
    _pid_alive,
    _typed_lines,
    _write_json,
    collect_source_provenance,
    validate_container_contract,
)
from holoagent_mujoco.stage2_result_topics import STAGE2_TOPIC_TYPES


EXPECTED_NODES = (
    "/holoagent_livox_converter",
    "/holoagent_mujoco_bridge",
    "/holoagent_stage3_eval",
    "/laserMapping",
)

FASTLIVO_TOPICS = {
    "/LIVO2/imu_propagate": "nav_msgs/msg/Odometry",
    "/Laser_map": "sensor_msgs/msg/PointCloud2",
    "/aft_mapped_to_init": "nav_msgs/msg/Odometry",
    "/camera_pose": "geometry_msgs/msg/PoseStamped",
    "/cloud_effected": "sensor_msgs/msg/PointCloud2",
    "/cloud_registered": "sensor_msgs/msg/PointCloud2",
    "/cloud_visual_sub_map_before": "sensor_msgs/msg/PointCloud2",
    "/depth_img": "sensor_msgs/msg/Image",
    "/depth_img/compressed": "sensor_msgs/msg/CompressedImage",
    "/depth_img/compressedDepth": "sensor_msgs/msg/CompressedImage",
    "/depth_img/theora": "theora_image_transport/msg/Packet",
    "/dyn_obj": "sensor_msgs/msg/PointCloud2",
    "/dyn_obj_dbg_hist": "sensor_msgs/msg/PointCloud2",
    "/dyn_obj_removed": "sensor_msgs/msg/PointCloud2",
    "/icp_loop_closure_corrected_cloud": "sensor_msgs/msg/PointCloud2",
    "/icp_loop_closure_history_cloud": "sensor_msgs/msg/PointCloud2",
    "/local_cloud_registered": "sensor_msgs/msg/PointCloud2",
    "/loop_closure_constraints": "visualization_msgs/msg/MarkerArray",
    "/mavros/vision_pose/pose": "geometry_msgs/msg/PoseStamped",
    "/overlay_img": "sensor_msgs/msg/Image",
    "/overlay_img/compressed": "sensor_msgs/msg/CompressedImage",
    "/overlay_img/compressedDepth": "sensor_msgs/msg/CompressedImage",
    "/overlay_img/theora": "theora_image_transport/msg/Packet",
    "/path": "nav_msgs/msg/Path",
    "/planner_normal": "visualization_msgs/msg/Marker",
    "/planes": "visualization_msgs/msg/MarkerArray",
    "/rgb_img": "sensor_msgs/msg/Image",
    "/rgb_img/compressed": "sensor_msgs/msg/CompressedImage",
    "/rgb_img/compressedDepth": "sensor_msgs/msg/CompressedImage",
    "/rgb_img/theora": "theora_image_transport/msg/Packet",
    "/robot_odom_convert": "nav_msgs/msg/Odometry",
    "/stage3/unused_robot_odom": "nav_msgs/msg/Odometry",
    "/undistort_cloud": "sensor_msgs/msg/PointCloud2",
    "/visualization_marker": "visualization_msgs/msg/MarkerArray",
    "/voxels": "visualization_msgs/msg/MarkerArray",
}
STAGE3_TOPIC_TYPES = {**STAGE2_TOPIC_TYPES, **FASTLIVO_TOPICS}


def validate_stage3_graph(host: str, container: str) -> dict[str, Any]:
    if host != container:
        raise PreflightError("host and container Stage 3 graphs differ")
    sections = _parse_snapshot(host)
    if tuple(sorted(sections["nodes"])) != EXPECTED_NODES:
        raise PreflightError(f"unexpected Stage 3 nodes: {sections['nodes']}")
    topics = _typed_lines(sections["topics"])
    if topics != STAGE3_TOPIC_TYPES:
        missing = sorted(set(STAGE3_TOPIC_TYPES) - set(topics))
        unexpected = sorted(set(topics) - set(STAGE3_TOPIC_TYPES))
        wrong = sorted(
            name
            for name in set(topics) & set(STAGE3_TOPIC_TYPES)
            if topics[name] != STAGE3_TOPIC_TYPES[name]
        )
        raise PreflightError(
            f"Stage 3 topic allowlist mismatch: missing={missing}, "
            f"unexpected={unexpected}, wrong_types={wrong}"
        )
    services = _typed_lines(sections["services"])
    expected_services = {
        f"{node}/{name}": kind
        for node in EXPECTED_NODES
        for name, kind in PARAMETER_SERVICE_TYPES.items()
    }
    expected_services["/fast_livo/save_map"] = "fast_livo/srv/SaveMap"
    if services != expected_services:
        raise PreflightError("Stage 3 service allowlist mismatch")
    if sections["actions"]:
        raise PreflightError("Stage 3 action endpoints are forbidden")
    return {
        "nodes": list(EXPECTED_NODES),
        "topics": topics,
        "services": services,
        "actions": [],
    }


def validate_evaluator_status(result: dict[str, Any], exit_status: int | None) -> None:
    if result.get("status") == "PASS" and exit_status != 0:
        raise PreflightError("passing Stage 3 evaluator must exit zero")
    if result.get("status") == "FAIL" and exit_status != 1:
        raise PreflightError("failed Stage 3 evaluator must exit one")
    if result.get("status") not in {"PASS", "FAIL"}:
        raise PreflightError("invalid Stage 3 evaluator status")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 3 graph gate/finalizer")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--workspace-source", type=Path, required=True)
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
        config = load_config(args.config)
        validate_isolation_environment(os.environ, config)
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
            remnants = _container_stage_processes(args.container)
            if alive_host or alive_container or remnants:
                raise PreflightError(
                    "Stage 3 cleanup incomplete: "
                    f"host={alive_host}, container={alive_container}, remnants={remnants}"
                )
            if args.result_file is None or args.final_result_file is None:
                raise PreflightError("Stage 3 postflight result paths are required")
            pending = json.loads(args.result_file.read_text(encoding="utf-8"))
            validate_evaluator_status(pending, args.evaluator_exit_status)
            build_manifest_path = run_dir / "stage3_build_manifest.json"
            build_provenance = json.loads(
                build_manifest_path.read_text(encoding="utf-8")
            )
            binary = build_provenance.get("binary", {})
            if (
                build_provenance.get("kind") != "holoagent_stage3_clean_build"
                or not isinstance(binary, dict)
                or len(str(binary.get("sha256", ""))) != 64
            ):
                raise PreflightError("Stage 3 clean-build manifest is invalid")
            result = {
                "status": "PASS",
                "gate": "postflight",
                "container": container,
                "provenance": collect_source_provenance(
                    args.workspace_source, container
                ),
                "build_provenance": build_provenance,
                "host_pids": args.host_pid,
                "container_pids": args.container_pid,
                "forbidden_processes": forbidden,
            }
            _write_json(run_dir / "postflight.json", result)
            merge_postflight_result(
                args.result_file, result, final_path=args.final_result_file
            )
        else:
            if args.graph_host is None or args.graph_container is None:
                raise PreflightError("Stage 3 graph snapshots are required")
            graph = validate_stage3_graph(
                args.graph_host.read_text(encoding="utf-8"),
                args.graph_container.read_text(encoding="utf-8"),
            )
            result = {"status": "PASS", "gate": "graph", "graph": graph}
            _write_json(run_dir / "graph_preflight.json", result)
    except Exception as exc:
        result = {
            "status": "FAIL",
            "error": str(exc),
            "exception_type": type(exc).__name__,
        }
        if run_dir.is_dir():
            _write_json(run_dir / "stage3_result_error.json", result)
        print(str(exc))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
