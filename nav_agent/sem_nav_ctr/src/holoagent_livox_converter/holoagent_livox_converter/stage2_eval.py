from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Any

from livox_ros_driver2.msg import CustomMsg
import numpy as np
import rclpy
from rcl_interfaces.srv import GetParameters
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import qos_profile_sensor_data
from rosgraph_msgs.msg import Clock
from sensor_msgs.msg import Image, Imu, PointCloud2
import yaml

from holoagent_livox_converter.converter_core import (
    ConversionOptions,
    decode_pointcloud,
)
from holoagent_livox_converter.stage2_collector import Stage2Collector
from holoagent_livox_converter.stage2_metrics import Stage2Limits, evaluate_stage2
from holoagent_mujoco.config import Stage1Config, file_sha256, load_config


EXPECTED_NODES = {
    "/holoagent_mujoco_bridge",
    "/holoagent_livox_converter",
    "/holoagent_stage2_eval",
}
EXPECTED_TOPICS = {
    "/clock": "rosgraph_msgs/msg/Clock",
    "/cmd_vel": "geometry_msgs/msg/Twist",
    "/robot_odom": "nav_msgs/msg/Odometry",
    "/livox/imu": "sensor_msgs/msg/Imu",
    "/livox/lidar": "livox_ros_driver2/msg/CustomMsg",
    "/camera/color/image_raw": "sensor_msgs/msg/Image",
    "/camera/color/camera_info": "sensor_msgs/msg/CameraInfo",
    "/holoagent_sim/applied_cmd_vel": "geometry_msgs/msg/Twist",
    "/holoagent_sim/contact_count": "std_msgs/msg/UInt32",
    "/holoagent_sim/lidar_points": "sensor_msgs/msg/PointCloud2",
    "/tf": "tf2_msgs/msg/TFMessage",
    "/tf_static": "tf2_msgs/msg/TFMessage",
    "/parameter_events": "rcl_interfaces/msg/ParameterEvent",
    "/rosout": "rcl_interfaces/msg/Log",
}


def validate_calibration_evidence(
    config: Stage1Config, calibration_path: Path, metadata_path: Path
) -> bool:
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        document = yaml.safe_load(calibration_path.read_text(encoding="utf-8"))
        parameters = document["/**"]["ros__parameters"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError, yaml.YAMLError):
        return False
    return (
        metadata.get("kind") == "holoagent_sim_calibration"
        and metadata.get("config_sha256") == file_sha256(calibration_path)
        and metadata.get("source_config_sha256") == file_sha256(config.source_path)
        and metadata.get("forbidden_real_rig_source") is False
        and metadata.get("lidar_points_per_scan") == config.lidar.configured_points
        and metadata.get("lidar_min_finite_points")
        == config.lidar.min_finite_points
        and parameters.get("use_sim_time") is True
        and parameters.get("common", {}).get("img_en") == 0
        and parameters.get("common", {}).get("lid_topic") == "/livox/lidar"
        and parameters.get("common", {}).get("imu_topic") == "/livox/imu"
        and parameters.get("wheel", {}).get("enable_wheel_odom") is False
    )


class Stage2Evaluator(Node):
    def __init__(
        self,
        config: Stage1Config,
        *,
        calibration_path: Path,
        metadata_path: Path,
        ready_file: Path,
        approval_file: Path,
    ) -> None:
        super().__init__(
            "holoagent_stage2_eval",
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
            automatically_declare_parameters_from_overrides=True,
        )
        self.config = config
        self.calibration_path = calibration_path.resolve()
        self.metadata_path = metadata_path.resolve()
        self.ready_file = ready_file.resolve()
        self.approval_file = approval_file.resolve()
        self.collector: Stage2Collector | None = None
        self.current_clock_ns: int | None = None
        self.graph_evidence: dict[str, Any] = {}
        self.active_gate = "graph"
        self._wall_deadline = time.monotonic() + (
            config.thresholds.wall_time_multiplier
            * (config.thresholds.warmup_sec + config.thresholds.rate_window_sec)
            + config.thresholds.startup_allowance_sec
        )
        self._raw_options = ConversionOptions(
            acquisition_mode=config.lidar.acquisition_mode,
            scan_period_ns=round(config.lidar.scan_period_sec * 1_000_000_000),
            min_finite_points=config.lidar.min_finite_points,
            noise_std_m=0.0,
            dropout_probability=0.0,
            random_seed=config.lidar.random_seed,
            reflectivity_override=None,
            tag_override=None,
            line_override=None,
        )

        self.create_subscription(Clock, "/clock", self._clock, qos_profile_sensor_data)
        self.create_subscription(Imu, "/livox/imu", self._imu, qos_profile_sensor_data)
        self.create_subscription(
            Image,
            "/camera/color/image_raw",
            self._camera,
            qos_profile_sensor_data,
        )
        self.create_subscription(
            PointCloud2,
            "/holoagent_sim/lidar_points",
            self._raw_lidar,
            qos_profile_sensor_data,
        )
        self.create_subscription(
            CustomMsg, "/livox/lidar", self._custom_lidar, qos_profile_sensor_data
        )
        self._parameter_clients = {
            "bridge": self.create_client(
                GetParameters, "/holoagent_mujoco_bridge/get_parameters"
            ),
            "converter": self.create_client(
                GetParameters, "/holoagent_livox_converter/get_parameters"
            ),
        }

    def run(self) -> dict[str, object]:
        self._wait_for_clock_and_graph()
        self._write_ready_and_wait_for_approval()
        self._wait_for_exact_graph()
        uses_sim_time = {
            "bridge": self._remote_bool_parameter("bridge", "use_sim_time"),
            "converter": self._remote_bool_parameter("converter", "use_sim_time"),
            "eval": bool(self.get_parameter("use_sim_time").value),
        }
        calibration_match = validate_calibration_evidence(
            self.config, self.calibration_path, self.metadata_path
        )
        self.collector = Stage2Collector(
            warmup_sec=self.config.thresholds.warmup_sec,
            rate_window_sec=self.config.thresholds.rate_window_sec,
        )
        while not self.collector.done:
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.02)
        observations = self.collector.observations(
            use_sim_time=uses_sim_time,
            graph_approved=True,
            calibration_match=calibration_match,
        )
        return evaluate_stage2(observations, _limits(self.config))

    def _wait_for_clock_and_graph(self) -> None:
        while self.current_clock_ns is None:
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)
        self._wait_for_exact_graph()

    def _wait_for_exact_graph(self) -> None:
        deadline = min(self._wall_deadline, time.monotonic() + 8.0)
        reason = "graph did not converge"
        while time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.05)
            valid, reason = self._graph_contract()
            if valid:
                return
        raise RuntimeError(reason)

    def _graph_contract(self) -> tuple[bool, str]:
        nodes = {
            f"{namespace.rstrip('/')}/{name}".replace("//", "/")
            for name, namespace in self.get_node_names_and_namespaces()
        }
        topics = {
            name: types for name, types in self.get_topic_names_and_types()
        }
        services = {
            name: types for name, types in self.get_service_names_and_types()
        }
        self.graph_evidence = {
            "nodes": sorted(nodes),
            "topics": {name: sorted(types) for name, types in sorted(topics.items())},
            "services": {
                name: sorted(types) for name, types in sorted(services.items())
            },
        }
        if nodes != EXPECTED_NODES:
            return False, f"unexpected ROS nodes: {sorted(nodes)}"
        observed_topics = {
            name: types[0] for name, types in topics.items() if len(types) == 1
        }
        if observed_topics != EXPECTED_TOPICS:
            return False, "topic/type allowlist mismatch"
        parameter_suffixes = {
            "describe_parameters",
            "get_parameter_types",
            "get_parameters",
            "list_parameters",
            "set_parameters",
            "set_parameters_atomically",
        }
        expected_services = {
            f"{node}/{suffix}" for node in EXPECTED_NODES for suffix in parameter_suffixes
        }
        if set(services) != expected_services:
            return False, "service allowlist mismatch"
        ownership = {
            "/cmd_vel": (set(), {"/holoagent_mujoco_bridge"}),
            "/holoagent_sim/lidar_points": (
                {"/holoagent_mujoco_bridge"},
                {"/holoagent_livox_converter", "/holoagent_stage2_eval"},
            ),
            "/livox/lidar": (
                {"/holoagent_livox_converter"},
                {"/holoagent_stage2_eval"},
            ),
        }
        for topic, (expected_publishers, expected_subscribers) in ownership.items():
            publishers = {
                _endpoint_name(endpoint)
                for endpoint in self.get_publishers_info_by_topic(topic)
            }
            subscribers = {
                _endpoint_name(endpoint)
                for endpoint in self.get_subscriptions_info_by_topic(topic)
            }
            if publishers != expected_publishers or subscribers != expected_subscribers:
                return False, f"endpoint ownership mismatch for {topic}"
        return True, "ok"

    def _write_ready_and_wait_for_approval(self) -> None:
        if self.ready_file.exists() or self.approval_file.exists():
            raise RuntimeError("graph approval artifacts must not pre-exist")
        payload = {
            "status": "READY_NO_MOTION",
            "clock_ns": self.current_clock_ns,
            "graph": self.graph_evidence,
        }
        self.ready_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        expected = file_sha256(self.ready_file)
        while not self.approval_file.is_file():
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)
        if self.approval_file.read_text(encoding="utf-8").strip() != expected:
            raise RuntimeError("external graph approval digest mismatch")

    def _remote_bool_parameter(self, client_name: str, parameter: str) -> bool:
        client = self._parameter_clients[client_name]
        if not client.wait_for_service(timeout_sec=2.0):
            return False
        request = GetParameters.Request()
        request.names = [parameter]
        future = client.call_async(request)
        deadline = min(self._wall_deadline, time.monotonic() + 2.0)
        while not future.done() and time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.02)
        if not future.done() or future.exception() is not None:
            return False
        values = future.result().values
        return len(values) == 1 and bool(values[0].bool_value)

    def _clock(self, message: Clock) -> None:
        stamp = _stamp_ns(message.clock)
        self.current_clock_ns = stamp
        if self.collector is not None:
            self.collector.record_clock(stamp, wall_time=time.monotonic())

    def _imu(self, message: Imu) -> None:
        if self.collector is not None:
            self.collector.record_imu(_stamp_ns(message.header.stamp))

    def _camera(self, message: Image) -> None:
        if self.collector is not None:
            self.collector.record_camera(_stamp_ns(message.header.stamp))

    def _raw_lidar(self, message: PointCloud2) -> None:
        if self.collector is None:
            return
        try:
            cloud = decode_pointcloud(message, self._raw_options)
            if cloud.frame_id != self.config.frames.lidar:
                raise ValueError("raw lidar frame mismatch")
            self.collector.record_raw_lidar(cloud.timebase, cloud.point_num)
        except Exception as exc:
            self.collector.add_error(f"raw lidar: {exc}")

    def _custom_lidar(self, message: CustomMsg) -> None:
        if self.collector is None:
            return
        try:
            stamp = _stamp_ns(message.header.stamp)
            if message.header.frame_id != self.config.frames.lidar:
                raise ValueError("custom lidar frame mismatch")
            if int(message.timebase) != stamp:
                raise ValueError("CustomMsg timebase differs from header stamp")
            if int(message.point_num) != len(message.points):
                raise ValueError("CustomMsg point_num differs from points length")
            xyz = np.asarray(
                [(point.x, point.y, point.z) for point in message.points],
                dtype=np.float32,
            )
            if xyz.shape != (len(message.points), 3) or not np.isfinite(xyz).all():
                raise ValueError("CustomMsg coordinates are not finite")
            offsets = np.asarray(
                [point.offset_time for point in message.points], dtype=np.uint32
            )
            self.collector.record_custom_lidar(stamp, len(message.points), offsets)
        except Exception as exc:
            self.collector.add_error(f"custom lidar: {exc}")

    def _check_deadline(self) -> None:
        if time.monotonic() > self._wall_deadline:
            raise TimeoutError("Stage 2 wall-time limit exceeded")


def _stamp_ns(stamp: Any) -> int:
    seconds = int(stamp.sec)
    nanoseconds = int(stamp.nanosec)
    if seconds < 0 or not 0 <= nanoseconds < 1_000_000_000:
        raise ValueError("invalid ROS timestamp")
    return seconds * 1_000_000_000 + nanoseconds


def _endpoint_name(endpoint: Any) -> str:
    return f"{endpoint.node_namespace.rstrip('/')}/{endpoint.node_name}".replace(
        "//", "/"
    )


def _limits(config: Stage1Config) -> Stage2Limits:
    thresholds = config.thresholds
    return Stage2Limits(
        rate_window_sec=thresholds.rate_window_sec,
        clock_min_hz=thresholds.clock_min_hz,
        min_realtime_factor=thresholds.min_realtime_factor,
        imu_min_hz=thresholds.imu_min_hz,
        imu_max_hz=thresholds.imu_max_hz,
        camera_min_hz=thresholds.camera_min_hz,
        camera_max_hz=thresholds.camera_max_hz,
        lidar_min_hz=thresholds.lidar_min_hz,
        lidar_max_hz=thresholds.lidar_max_hz,
        min_finite_points=config.lidar.min_finite_points,
        acquisition_mode=config.lidar.acquisition_mode,
        scan_period_ns=round(config.lidar.scan_period_sec * 1_000_000_000),
    )


def _failure(gate: str, error: Exception) -> dict[str, object]:
    return {
        "stage": 2,
        "status": "FAIL",
        "label": None,
        "qualified_pass": None,
        "first_failing_gate": gate,
        "motion_enabled": False,
        "simulated_motion": False,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": {gate: False},
        "metrics": {"error": str(error), "exception_type": type(error).__name__},
    }


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Stage 2 synthetic Livox")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--calibration-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    node: Stage2Evaluator | None = None
    initialized = False
    result: dict[str, object]
    try:
        config = load_config(arguments.config)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = Stage2Evaluator(
            config,
            calibration_path=arguments.calibration,
            metadata_path=arguments.calibration_metadata,
            ready_file=arguments.ready_file,
            approval_file=arguments.approval_file,
        )
        result = node.run()
        result["graph"] = node.graph_evidence
        result["config_sha256"] = file_sha256(arguments.config)
        result["calibration_sha256"] = file_sha256(arguments.calibration)
    except Exception as exc:
        result = _failure(node.active_gate if node is not None else "graph", exc)
    finally:
        if node is not None:
            node.destroy_node()
        if initialized and rclpy.ok():
            rclpy.shutdown()
    _write_json(arguments.output.resolve(), result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
