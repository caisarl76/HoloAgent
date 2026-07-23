from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import time
from typing import Any, Iterable

from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry
import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from rcl_interfaces.srv import GetParameters
from rosgraph_msgs.msg import Clock
from sensor_msgs.msg import CameraInfo, Image, Imu
from std_msgs.msg import UInt32
from tf2_msgs.msg import TFMessage

from holoagent_mujoco.command import CommandLimits, VelocityCommand
from holoagent_mujoco.config import Stage1Config, file_sha256, load_config
from holoagent_mujoco.ros_messages import twist_message


GATE_ORDER = (
    "graph",
    "clock",
    "rtf",
    "imu_rate",
    "odom_rate",
    "camera_rate",
    "stationary_drift",
    "command_clamp",
    "bounded_motion",
    "timeout_zero",
    "stopped_speed",
    "message_finite",
)


@dataclass(frozen=True)
class OdomSample:
    sim_time: float
    x: float
    y: float
    speed: float
    quaternion_wxyz: tuple[float, float, float, float]


@dataclass(frozen=True)
class AppliedCommandSample:
    sim_time: float
    command: VelocityCommand


def strictly_monotonic(values: Iterable[float]) -> bool:
    previous = None
    found = False
    for raw in values:
        value = float(raw)
        if not math.isfinite(value) or (previous is not None and value <= previous):
            return False
        previous = value
        found = True
    return found


def simulated_rate(timestamps: Iterable[float], *, start: float, end: float) -> float:
    if not math.isfinite(start) or not math.isfinite(end) or end <= start:
        raise ValueError("rate window end must be after start")
    count = sum(1 for stamp in timestamps if start <= float(stamp) < end)
    return count / (end - start)


def realtime_factor(
    clock_samples: Iterable[tuple[float, float]], *, warmup_sec: float
) -> float:
    samples = list(clock_samples)
    if len(samples) < 2 or warmup_sec < 0.0:
        return 0.0
    threshold = samples[0][0] + warmup_sec
    start = next((sample for sample in samples if sample[0] >= threshold), None)
    if start is None:
        return 0.0
    end = samples[-1]
    wall_delta = end[1] - start[1]
    sim_delta = end[0] - start[0]
    if wall_delta <= 0.0 or sim_delta <= 0.0:
        return 0.0
    return sim_delta / wall_delta


def stationary_drift(samples: Iterable[OdomSample]) -> float:
    values = list(samples)
    if len(values) < 2:
        return math.inf
    origin = values[0]
    return max(math.hypot(sample.x - origin.x, sample.y - origin.y) for sample in values)


def horizontal_displacement(samples: Iterable[OdomSample]) -> float:
    values = list(samples)
    if len(values) < 2:
        return 0.0
    return math.hypot(values[-1].x - values[0].x, values[-1].y - values[0].y)


def clamp_gate(
    samples: Iterable[AppliedCommandSample],
    limits: CommandLimits,
    *,
    require_positive_probe: bool,
) -> bool:
    values = list(samples)
    if not values:
        return False
    tolerance = 1e-5
    within_bounds = all(
        math.isfinite(sample.command.x)
        and math.isfinite(sample.command.y)
        and math.isfinite(sample.command.yaw)
        and abs(sample.command.x) <= limits.max_linear_x + tolerance
        and abs(sample.command.y) <= limits.max_linear_y + tolerance
        and abs(sample.command.yaw) <= limits.max_yaw_rate + tolerance
        for sample in values
    )
    if not within_bounds or not require_positive_probe:
        return within_bounds
    return any(
        math.isclose(sample.command.x, limits.max_linear_x, abs_tol=tolerance)
        and math.isclose(sample.command.y, limits.max_linear_y, abs_tol=tolerance)
        and math.isclose(sample.command.yaw, limits.max_yaw_rate, abs_tol=tolerance)
        for sample in values
    )


def timeout_latency(
    samples: Iterable[AppliedCommandSample], *, silence_start: float
) -> float:
    for sample in samples:
        if sample.sim_time >= silence_start and sample.command.is_zero:
            return sample.sim_time - silence_start
    return math.inf


def max_speed_in_window(
    samples: Iterable[OdomSample], *, start: float, duration: float
) -> float:
    speeds = [
        sample.speed
        for sample in samples
        if start <= sample.sim_time <= start + duration
    ]
    return max(speeds, default=math.inf)


def quaternion_samples_finite(samples: Iterable[OdomSample]) -> bool:
    values = list(samples)
    return bool(values) and all(
        all(math.isfinite(component) for component in sample.quaternion_wxyz)
        for sample in values
    )


def build_result(gates: dict[str, bool], metrics: dict[str, Any]) -> dict[str, Any]:
    first_failure = next(
        (name for name in GATE_ORDER if not bool(gates.get(name, False))), None
    )
    passed = first_failure is None
    return {
        "status": "PASS" if passed else "FAIL",
        "label": "PASS_SIM_ODOM" if passed else None,
        "first_failing_gate": first_failure,
        "gates": {name: bool(gates.get(name, False)) for name in GATE_ORDER},
        "metrics": metrics,
    }


class Stage1Evaluator(Node):
    def __init__(self, config: Stage1Config) -> None:
        super().__init__(
            "holoagent_stage1_eval",
            parameter_overrides=[
                Parameter("use_sim_time", Parameter.Type.BOOL, True)
            ],
            automatically_declare_parameters_from_overrides=True,
        )
        self.config = config
        self.current_sim_time: float | None = None
        self.clock_samples: list[tuple[float, float]] = []
        self.imu_times: list[float] = []
        self.odom_samples: list[OdomSample] = []
        self.image_times: list[float] = []
        self.camera_info_times: list[float] = []
        self.applied_commands: list[AppliedCommandSample] = []
        self.contact_samples: list[tuple[float, int]] = []
        self.tf_messages = 0
        self.static_tf_messages = 0
        self.graph_evidence: dict[str, Any] = {}
        self._wall_deadline = math.inf

        sensor_qos = QoSProfile(
            history=HistoryPolicy.KEEP_LAST,
            depth=20,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            durability=DurabilityPolicy.VOLATILE,
        )
        clock_qos = QoSProfile(
            history=HistoryPolicy.KEEP_LAST,
            depth=20,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            durability=DurabilityPolicy.VOLATILE,
        )
        reliable_qos = QoSProfile(depth=20)
        transient_qos = QoSProfile(
            history=HistoryPolicy.KEEP_LAST,
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._command_publisher = self.create_publisher(
            Twist, "/cmd_vel", reliable_qos
        )
        self.create_subscription(Clock, "/clock", self._clock_callback, clock_qos)
        self.create_subscription(
            Odometry, "/robot_odom", self._odom_callback, reliable_qos
        )
        self.create_subscription(Imu, "/livox/imu", self._imu_callback, sensor_qos)
        self.create_subscription(
            Image, "/camera/color/image_raw", self._image_callback, sensor_qos
        )
        self.create_subscription(
            CameraInfo,
            "/camera/color/camera_info",
            self._camera_info_callback,
            sensor_qos,
        )
        self.create_subscription(
            Twist,
            "/holoagent_sim/applied_cmd_vel",
            self._applied_callback,
            reliable_qos,
        )
        self.create_subscription(
            UInt32,
            "/holoagent_sim/contact_count",
            self._contact_callback,
            sensor_qos,
        )
        self.create_subscription(TFMessage, "/tf", self._tf_callback, reliable_qos)
        self.create_subscription(
            TFMessage, "/tf_static", self._static_tf_callback, transient_qos
        )

    def run(self) -> dict[str, Any]:
        thresholds = self.config.thresholds
        planned_duration = (
            thresholds.warmup_sec
            + thresholds.rate_window_sec
            + 0.5
            + 1.0
            + thresholds.motion_duration_sec
            + thresholds.timeout_zero_sec
            + thresholds.stopped_hold_sec
        )
        self._wall_deadline = (
            time.monotonic()
            + thresholds.wall_time_multiplier * planned_duration
            + thresholds.startup_allowance_sec
        )
        self._wait_for_first_clock()
        graph_ok, graph_reason = self._wait_for_graph_contract()
        if not graph_ok:
            self.publish_zero()
            return build_result(
                {"graph": False},
                {
                    "graph_reason": graph_reason,
                    "graph": self.graph_evidence,
                },
            )
        start = float(self.current_sim_time)

        self._wait_sim(start + thresholds.warmup_sec, VelocityCommand.zero())
        rate_start = float(self.current_sim_time)
        self._wait_sim(
            rate_start + thresholds.rate_window_sec, VelocityCommand.zero()
        )
        rate_end = rate_start + thresholds.rate_window_sec

        clamp_start = float(self.current_sim_time)
        clamp_probe = VelocityCommand(10.0, 10.0, 10.0)
        self._wait_sim(clamp_start + 0.5, clamp_probe)
        clamp_end = clamp_start + 0.5

        recovery_start = float(self.current_sim_time)
        self._wait_sim(recovery_start + 1.0, VelocityCommand.zero())

        motion_start = float(self.current_sim_time)
        self._wait_sim(
            motion_start + thresholds.motion_duration_sec,
            VelocityCommand(thresholds.motion_speed_mps, 0.0, 0.0),
        )
        motion_end = motion_start + thresholds.motion_duration_sec

        silence_start = float(self.current_sim_time)
        silence_duration = thresholds.timeout_zero_sec + thresholds.stopped_hold_sec
        self._wait_sim(silence_start + silence_duration, None)
        self.publish_zero()

        limits = CommandLimits(
            self.config.command.max_linear_x,
            self.config.command.max_linear_y,
            self.config.command.max_yaw_rate,
            self.config.command.timeout_sim_sec,
        )
        rate_metrics = {
            "clock_hz": simulated_rate(
                [sample[0] for sample in self.clock_samples],
                start=rate_start,
                end=rate_end,
            ),
            "imu_hz": simulated_rate(
                self.imu_times, start=rate_start, end=rate_end
            ),
            "odom_hz": simulated_rate(
                [sample.sim_time for sample in self.odom_samples],
                start=rate_start,
                end=rate_end,
            ),
            "camera_hz": simulated_rate(
                self.image_times, start=rate_start, end=rate_end
            ),
            "camera_info_hz": simulated_rate(
                self.camera_info_times, start=rate_start, end=rate_end
            ),
        }
        stationary_samples = _odom_window(
            self.odom_samples,
            rate_start,
            rate_start + thresholds.stationary_duration_sec,
        )
        motion_samples = _odom_window(self.odom_samples, motion_start, motion_end)
        clamp_samples = [
            sample
            for sample in self.applied_commands
            if clamp_start <= sample.sim_time <= clamp_end
        ]
        latency = timeout_latency(
            self.applied_commands, silence_start=silence_start
        )
        stopped_start = silence_start + latency
        stopped_speed = max_speed_in_window(
            self.odom_samples, start=stopped_start, duration=thresholds.stopped_hold_sec
        )
        drift = stationary_drift(stationary_samples)
        displacement = horizontal_displacement(motion_samples)
        rtf = realtime_factor(
            self.clock_samples, warmup_sec=thresholds.warmup_sec
        )
        max_contacts = max((count for _, count in self.contact_samples), default=0)
        metrics = {
            **rate_metrics,
            "realtime_factor": rtf,
            "stationary_drift_m": drift,
            "motion_displacement_m": displacement,
            "timeout_latency_sec": latency,
            "post_timeout_max_speed_mps": stopped_speed,
            "max_contact_count": max_contacts,
            "tf_messages": self.tf_messages,
            "static_tf_messages": self.static_tf_messages,
            "graph_reason": graph_reason,
            "graph": self.graph_evidence,
        }
        all_applied_in_bounds = clamp_gate(
            self.applied_commands, limits, require_positive_probe=False
        )
        gates = {
            "graph": graph_ok,
            "clock": strictly_monotonic(sample[0] for sample in self.clock_samples)
            and rate_metrics["clock_hz"] >= thresholds.clock_min_hz,
            "rtf": rtf >= thresholds.min_realtime_factor,
            "imu_rate": thresholds.imu_min_hz
            <= rate_metrics["imu_hz"]
            <= thresholds.imu_max_hz,
            "odom_rate": thresholds.odom_min_hz
            <= rate_metrics["odom_hz"]
            <= thresholds.odom_max_hz,
            "camera_rate": thresholds.camera_min_hz
            <= rate_metrics["camera_hz"]
            <= thresholds.camera_max_hz
            and thresholds.camera_min_hz
            <= rate_metrics["camera_info_hz"]
            <= thresholds.camera_max_hz,
            "stationary_drift": drift <= thresholds.max_stationary_drift_m,
            "command_clamp": all_applied_in_bounds
            and clamp_gate(clamp_samples, limits, require_positive_probe=True),
            "bounded_motion": thresholds.motion_min_displacement_m
            <= displacement
            <= thresholds.motion_max_displacement_m,
            "timeout_zero": latency <= thresholds.timeout_zero_sec,
            "stopped_speed": stopped_speed <= thresholds.stopped_speed_mps,
            "message_finite": quaternion_samples_finite(self.odom_samples)
            and self.tf_messages > 0
            and self.static_tf_messages > 0,
        }
        return build_result(gates, metrics)

    def publish_zero(self) -> None:
        self._command_publisher.publish(twist_message(VelocityCommand.zero()))

    def _wait_for_first_clock(self) -> None:
        while self.current_sim_time is None:
            self._check_wall_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)

    def _wait_sim(
        self, target_sim_time: float, command: VelocityCommand | None
    ) -> None:
        last_publish = -math.inf
        while self.current_sim_time is None or self.current_sim_time < target_sim_time:
            self._check_wall_deadline()
            now = time.monotonic()
            if command is not None and now - last_publish >= 0.02:
                self._command_publisher.publish(twist_message(command))
                last_publish = now
            rclpy.spin_once(self, timeout_sec=0.01)

    def _check_wall_deadline(self) -> None:
        if time.monotonic() > self._wall_deadline:
            raise TimeoutError("Stage 1 wall-time limit exceeded")

    def _wait_for_graph_contract(self) -> tuple[bool, str]:
        deadline = min(self._wall_deadline, time.monotonic() + 5.0)
        reason = "ROS graph did not converge"
        while time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.05)
            valid, reason = self._graph_contract_once()
            if valid:
                sim_time_ok = self._bridge_uses_sim_time()
                if sim_time_ok:
                    return True, "ok"
                reason = "bridge use_sim_time is not true"
        return False, reason

    def _graph_contract_once(self) -> tuple[bool, str]:
        nodes = sorted(
            _qualified_name(name, namespace)
            for name, namespace in self.get_node_names_and_namespaces()
        )
        topics = {
            name: sorted(types) for name, types in self.get_topic_names_and_types()
        }
        self.graph_evidence = {"nodes": nodes, "topics": topics}
        allowed_nodes = {
            "/holoagent_mujoco_bridge",
            "/holoagent_stage1_eval",
        }
        if set(nodes) != allowed_nodes:
            return False, f"unexpected nodes: {nodes}"
        forbidden_node_tokens = (
            "nav2",
            "controller_server",
            "planner_server",
            "bt_navigator",
        )
        if any(token in name for token in forbidden_node_tokens for name in nodes):
            return False, "navigation node discovered"
        if "/object_pose" in topics:
            return False, "/object_pose is forbidden in Stage 1"
        if any("/_action/" in name for name in topics):
            return False, "action endpoint discovered in Stage 1"
        required = {
            "/clock": "rosgraph_msgs/msg/Clock",
            "/cmd_vel": "geometry_msgs/msg/Twist",
            "/robot_odom": "nav_msgs/msg/Odometry",
            "/livox/imu": "sensor_msgs/msg/Imu",
            "/camera/color/image_raw": "sensor_msgs/msg/Image",
            "/camera/color/camera_info": "sensor_msgs/msg/CameraInfo",
            "/holoagent_sim/applied_cmd_vel": "geometry_msgs/msg/Twist",
            "/holoagent_sim/contact_count": "std_msgs/msg/UInt32",
            "/tf": "tf2_msgs/msg/TFMessage",
            "/tf_static": "tf2_msgs/msg/TFMessage",
        }
        for topic, expected_type in required.items():
            if topics.get(topic) != [expected_type]:
                return False, f"{topic} type mismatch: {topics.get(topic)}"
        if len(self.get_subscriptions_info_by_topic("/cmd_vel")) != 1:
            return False, "/cmd_vel must have exactly one subscriber"
        for topic in required:
            if topic == "/cmd_vel":
                continue
            if len(self.get_publishers_info_by_topic(topic)) != 1:
                return False, f"{topic} must have exactly one publisher"
        if not bool(self.get_parameter("use_sim_time").value):
            return False, "evaluator use_sim_time is not true"
        return True, "ok"

    def _bridge_uses_sim_time(self) -> bool:
        client = self.create_client(
            GetParameters, "/holoagent_mujoco_bridge/get_parameters"
        )
        if not client.wait_for_service(timeout_sec=1.0):
            return False
        request = GetParameters.Request()
        request.names = ["use_sim_time"]
        future = client.call_async(request)
        deadline = time.monotonic() + 2.0
        while not future.done() and time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.02)
        if not future.done() or future.exception() is not None:
            return False
        values = future.result().values
        return len(values) == 1 and bool(values[0].bool_value)

    def _clock_callback(self, message: Clock) -> None:
        value = _stamp_seconds(message.clock)
        self.current_sim_time = value
        self.clock_samples.append((value, time.monotonic()))

    def _odom_callback(self, message: Odometry) -> None:
        stamp = _stamp_seconds(message.header.stamp)
        linear = message.twist.twist.linear
        orientation = message.pose.pose.orientation
        self.odom_samples.append(
            OdomSample(
                stamp,
                float(message.pose.pose.position.x),
                float(message.pose.pose.position.y),
                math.hypot(float(linear.x), float(linear.y)),
                (
                    float(orientation.w),
                    float(orientation.x),
                    float(orientation.y),
                    float(orientation.z),
                ),
            )
        )

    def _imu_callback(self, message: Imu) -> None:
        self.imu_times.append(_stamp_seconds(message.header.stamp))

    def _image_callback(self, message: Image) -> None:
        self.image_times.append(_stamp_seconds(message.header.stamp))

    def _camera_info_callback(self, message: CameraInfo) -> None:
        self.camera_info_times.append(_stamp_seconds(message.header.stamp))

    def _applied_callback(self, message: Twist) -> None:
        if self.current_sim_time is None:
            return
        self.applied_commands.append(
            AppliedCommandSample(
                self.current_sim_time,
                VelocityCommand(
                    float(message.linear.x),
                    float(message.linear.y),
                    float(message.angular.z),
                ),
            )
        )

    def _contact_callback(self, message: UInt32) -> None:
        if self.current_sim_time is not None:
            self.contact_samples.append((self.current_sim_time, int(message.data)))

    def _tf_callback(self, message: TFMessage) -> None:
        self.tf_messages += len(message.transforms)

    def _static_tf_callback(self, message: TFMessage) -> None:
        self.static_tf_messages += len(message.transforms)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the Stage 1 MuJoCo contract")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    node = None
    initialized = False
    result: dict[str, Any]
    try:
        config = load_config(arguments.config)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = Stage1Evaluator(config)
        result = node.run()
        result["config_path"] = str(arguments.config.resolve())
        result["config_sha256"] = file_sha256(arguments.config)
    except Exception as exc:
        result = build_result({"graph": False}, {"error": str(exc)})
        result["exception_type"] = type(exc).__name__
    finally:
        if node is not None:
            node.publish_zero()
            for _ in range(3):
                rclpy.spin_once(node, timeout_sec=0.02)
            node.destroy_node()
        if initialized and rclpy.ok():
            rclpy.shutdown()
    _write_json(arguments.output, result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


def _stamp_seconds(stamp: Any) -> float:
    return float(stamp.sec) + float(stamp.nanosec) / 1_000_000_000.0


def _odom_window(
    samples: Iterable[OdomSample], start: float, end: float
) -> list[OdomSample]:
    return [sample for sample in samples if start <= sample.sim_time <= end]


def _qualified_name(name: str, namespace: str) -> str:
    prefix = namespace.rstrip("/")
    return f"{prefix}/{name}" if prefix else f"/{name}"


def _write_json(path: Path, result: dict[str, Any]) -> None:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)


if __name__ == "__main__":
    raise SystemExit(main())
