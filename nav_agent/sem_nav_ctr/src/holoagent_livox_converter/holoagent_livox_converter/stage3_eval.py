from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import time
from typing import Any

from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
import rclpy
from rcl_interfaces.srv import GetParameters
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import qos_profile_sensor_data
from rosgraph_msgs.msg import Clock

from holoagent_livox_converter.stage2_eval import (
    EvalConfig,
    _endpoint_name,
    _stamp_ns,
    load_eval_config,
    validate_calibration_evidence,
)
from holoagent_livox_converter.stage3_metrics import (
    PoseSample,
    Stage3Limits,
    evaluate_stage3,
)
from holoagent_mujoco.config import file_sha256


EXPECTED_NODES = {
    "/holoagent_livox_converter",
    "/holoagent_mujoco_bridge",
    "/holoagent_stage3_eval",
    "/laserMapping",
}


def stage3_command(elapsed_sec: float) -> tuple[float, float, float]:
    if elapsed_sec < 0.0 or elapsed_sec >= 30.0:
        return (0.0, 0.0, 0.0)
    if elapsed_sec < 2.0:
        return (0.0, 0.0, 0.0)
    if elapsed_sec < 10.0:
        return (0.10, 0.0, 0.0)
    if elapsed_sec < 16.0:
        return (0.0, 0.0, 0.15)
    if elapsed_sec < 24.0:
        return (0.10, 0.0, 0.0)
    return (0.0, 0.0, -0.15)


class Stage3Evaluator(Node):
    def __init__(
        self,
        config: EvalConfig,
        *,
        calibration_path: Path,
        metadata_path: Path,
        ready_file: Path,
        approval_file: Path,
    ) -> None:
        super().__init__(
            "holoagent_stage3_eval",
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
            automatically_declare_parameters_from_overrides=True,
        )
        self.config = config
        self.calibration_path = calibration_path.resolve()
        self.metadata_path = metadata_path.resolve()
        self.ready_file = ready_file.resolve()
        self.approval_file = approval_file.resolve()
        self.current_clock_ns: int | None = None
        self.collect_start_ns: int | None = None
        self.collect_end_ns: int | None = None
        self.ground_truth: list[PoseSample] = []
        self.estimates: list[PoseSample] = []
        self.message_errors: list[str] = []
        self.graph_evidence: dict[str, Any] = {}
        self.active_gate = "graph"
        self._wall_deadline = time.monotonic() + 4.0 * 34.0 + 30.0

        self._command = self.create_publisher(Twist, "/cmd_vel", 10)
        self.create_subscription(
            Clock, "/clock", self._clock_callback, qos_profile_sensor_data
        )
        self.create_subscription(
            Odometry, "/robot_odom", self._ground_truth_callback, 20
        )
        self.create_subscription(
            Odometry, "/aft_mapped_to_init", self._estimate_callback, 20
        )
        self._parameter_clients = {
            "bridge": self.create_client(
                GetParameters, "/holoagent_mujoco_bridge/get_parameters"
            ),
            "converter": self.create_client(
                GetParameters, "/holoagent_livox_converter/get_parameters"
            ),
            "fast_livo": self.create_client(
                GetParameters, "/laserMapping/get_parameters"
            ),
        }

    def run(self) -> dict[str, object]:
        self._wait_for_clock()
        self._wait_for_exact_graph()
        self._write_ready_and_wait_for_approval()
        self._wait_for_exact_graph()
        uses_sim_time = {
            name: self._remote_bool_parameter(name, "use_sim_time")
            for name in self._parameter_clients
        }
        uses_sim_time["eval"] = bool(self.get_parameter("use_sim_time").value)
        calibration_match = validate_calibration_evidence(
            self.config, self.calibration_path, self.metadata_path
        )
        perfect_odom_isolated = self._perfect_odom_isolated()

        self.collect_start_ns = int(self.current_clock_ns)
        self.collect_end_ns = self.collect_start_ns + 30_000_000_000
        last_publish = -math.inf
        while self.current_clock_ns < self.collect_end_ns:
            self._check_deadline()
            now = time.monotonic()
            if now - last_publish >= 0.02:
                elapsed = (self.current_clock_ns - self.collect_start_ns) / 1e9
                self._publish_command(stage3_command(elapsed))
                last_publish = now
            rclpy.spin_once(self, timeout_sec=0.01)
        self._publish_command((0.0, 0.0, 0.0))
        result = evaluate_stage3(
            tuple(self.ground_truth),
            tuple(self.estimates),
            limits=Stage3Limits(),
            graph_approved=True,
            use_sim_time=uses_sim_time,
            calibration_match=calibration_match,
            perfect_odom_isolated=perfect_odom_isolated,
            message_errors=tuple(self.message_errors),
        )
        result["graph"] = self.graph_evidence
        return result

    def publish_zero(self) -> None:
        self._publish_command((0.0, 0.0, 0.0))

    def _wait_for_clock(self) -> None:
        while self.current_clock_ns is None:
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)

    def _wait_for_exact_graph(self) -> None:
        deadline = min(self._wall_deadline, time.monotonic() + 15.0)
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
            name: sorted(types) for name, types in self.get_topic_names_and_types()
        }
        self.graph_evidence = {"nodes": sorted(nodes), "topics": topics}
        if nodes != EXPECTED_NODES:
            return False, f"unexpected ROS nodes: {sorted(nodes)}"
        required = {
            "/clock": "rosgraph_msgs/msg/Clock",
            "/cmd_vel": "geometry_msgs/msg/Twist",
            "/robot_odom": "nav_msgs/msg/Odometry",
            "/stage3/unused_robot_odom": "nav_msgs/msg/Odometry",
            "/livox/imu": "sensor_msgs/msg/Imu",
            "/livox/lidar": "livox_ros_driver2/msg/CustomMsg",
            "/aft_mapped_to_init": "nav_msgs/msg/Odometry",
        }
        if any(topics.get(name) != [kind] for name, kind in required.items()):
            return False, "required Stage 3 topic/type mismatch"
        publishers = {
            _endpoint_name(item) for item in self.get_publishers_info_by_topic("/cmd_vel")
        }
        subscribers = {
            _endpoint_name(item)
            for item in self.get_subscriptions_info_by_topic("/cmd_vel")
        }
        if publishers != {"/holoagent_stage3_eval"} or subscribers != {
            "/holoagent_mujoco_bridge"
        }:
            return False, "Stage 3 command ownership mismatch"
        return True, "ok"

    def _perfect_odom_isolated(self) -> bool:
        real_subscribers = {
            _endpoint_name(item)
            for item in self.get_subscriptions_info_by_topic("/robot_odom")
        }
        isolated_subscribers = {
            _endpoint_name(item)
            for item in self.get_subscriptions_info_by_topic(
                "/stage3/unused_robot_odom"
            )
        }
        return real_subscribers == {"/holoagent_stage3_eval"} and isolated_subscribers == {
            "/laserMapping"
        }

    def _write_ready_and_wait_for_approval(self) -> None:
        if self.ready_file.exists() or self.approval_file.exists():
            raise RuntimeError("graph approval artifacts must not pre-exist")
        self.ready_file.write_text(
            json.dumps(
                {
                    "status": "READY_SIM_MOTION_DISABLED",
                    "clock_ns": self.current_clock_ns,
                    "graph": self.graph_evidence,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
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

    def _clock_callback(self, message: Clock) -> None:
        self.current_clock_ns = _stamp_ns(message.clock)

    def _ground_truth_callback(self, message: Odometry) -> None:
        if self.collect_start_ns is None or self.collect_end_ns is None:
            return
        self._record_pose(message, self.ground_truth, "ground truth")

    def _estimate_callback(self, message: Odometry) -> None:
        if self.collect_start_ns is None or self.collect_end_ns is None:
            return
        self._record_pose(message, self.estimates, "estimate")

    def _record_pose(
        self, message: Odometry, destination: list[PoseSample], label: str
    ) -> None:
        try:
            stamp = _stamp_ns(message.header.stamp)
            if not self.collect_start_ns <= stamp <= self.collect_end_ns:
                return
            position = message.pose.pose.position
            orientation = message.pose.pose.orientation
            norm = math.sqrt(
                orientation.w**2
                + orientation.x**2
                + orientation.y**2
                + orientation.z**2
            )
            values = (
                position.x,
                position.y,
                position.z,
                orientation.w,
                orientation.x,
                orientation.y,
                orientation.z,
            )
            if not all(math.isfinite(float(value)) for value in values) or not math.isclose(
                norm, 1.0, abs_tol=1e-3
            ):
                raise ValueError("non-finite pose or non-unit quaternion")
            yaw = math.atan2(
                2.0 * (orientation.w * orientation.z + orientation.x * orientation.y),
                1.0 - 2.0 * (orientation.y**2 + orientation.z**2),
            )
            destination.append(
                PoseSample(stamp, position.x, position.y, position.z, yaw)
            )
        except Exception as exc:
            self.message_errors.append(f"{label}: {exc}")

    def _publish_command(self, values: tuple[float, float, float]) -> None:
        message = Twist()
        message.linear.x, message.linear.y, message.angular.z = values
        self._command.publish(message)

    def _check_deadline(self) -> None:
        if time.monotonic() > self._wall_deadline:
            raise TimeoutError("Stage 3 wall-time limit exceeded")


def _failure(error: Exception, gate: str = "graph") -> dict[str, object]:
    return {
        "stage": 3,
        "status": "FAIL",
        "label": "FAIL_ESTIMATOR",
        "qualified_pass": None,
        "first_failing_gate": gate,
        "motion_enabled": False,
        "simulated_motion": False,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": {gate: False},
        "metrics": {"error": str(error), "exception_type": type(error).__name__},
    }


def _write_json(path: Path, result: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Stage 3 FastLIVO LIO")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--calibration-metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    node: Stage3Evaluator | None = None
    initialized = False
    try:
        config = load_eval_config(arguments.config)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = Stage3Evaluator(
            config,
            calibration_path=arguments.calibration,
            metadata_path=arguments.calibration_metadata,
            ready_file=arguments.ready_file,
            approval_file=arguments.approval_file,
        )
        result = node.run()
        result["config_sha256"] = file_sha256(arguments.config)
        result["calibration_sha256"] = file_sha256(arguments.calibration)
    except Exception as exc:
        result = _failure(exc, node.active_gate if node is not None else "graph")
    finally:
        if node is not None:
            try:
                node.publish_zero()
            except Exception:
                pass
            node.destroy_node()
        if initialized and rclpy.ok():
            rclpy.shutdown()
    _write_json(arguments.output.resolve(), result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
