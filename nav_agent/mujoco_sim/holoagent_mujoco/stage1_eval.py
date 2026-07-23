from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re
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
    "stop_settle",
    "stopped_speed",
    "message_finite",
)

REQUIRED_TOPICS = {
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

AUXILIARY_TOPICS = {
    "/parameter_events": "rcl_interfaces/msg/ParameterEvent",
    "/rosout": "rcl_interfaces/msg/Log",
}

PARAMETER_SERVICE_TYPES = {
    "describe_parameters": "rcl_interfaces/srv/DescribeParameters",
    "get_parameter_types": "rcl_interfaces/srv/GetParameterTypes",
    "get_parameters": "rcl_interfaces/srv/GetParameters",
    "list_parameters": "rcl_interfaces/srv/ListParameters",
    "set_parameters": "rcl_interfaces/srv/SetParameters",
    "set_parameters_atomically": "rcl_interfaces/srv/SetParametersAtomically",
}


@dataclass(frozen=True)
class OdomSample:
    sim_time: float
    x: float
    y: float
    speed: float
    quaternion_wxyz: tuple[float, float, float, float]
    frame_id: str = ""
    child_frame_id: str = ""


@dataclass(frozen=True)
class AppliedCommandSample:
    sim_time: float
    command: VelocityCommand


@dataclass(frozen=True)
class ImuContractSample:
    sim_time: float
    frame_id: str
    quaternion_wxyz: tuple[float, float, float, float]
    angular_velocity: tuple[float, float, float]
    linear_acceleration: tuple[float, float, float]


@dataclass(frozen=True)
class ImageContractSample:
    sim_time: float
    frame_id: str
    width: int
    height: int
    encoding: str
    step: int
    data_length: int


@dataclass(frozen=True)
class CameraInfoContractSample:
    sim_time: float
    frame_id: str
    width: int
    height: int
    k: tuple[float, ...]
    p: tuple[float, ...]


@dataclass(frozen=True)
class TransformContractSample:
    sim_time: float
    parent: str
    child: str
    translation: tuple[float, float, float]
    quaternion_wxyz: tuple[float, float, float, float]
    is_static: bool


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


def forward_motion(samples: Iterable[OdomSample]) -> tuple[float, float]:
    values = list(samples)
    if len(values) < 2:
        return (0.0, 0.0)
    yaw = _yaw_from_wxyz(values[0].quaternion_wxyz)
    delta_x = values[-1].x - values[0].x
    delta_y = values[-1].y - values[0].y
    forward = delta_x * math.cos(yaw) + delta_y * math.sin(yaw)
    lateral = -delta_x * math.sin(yaw) + delta_y * math.cos(yaw)
    return (forward, lateral)


def yaw_change_degrees(samples: Iterable[OdomSample]) -> float:
    values = list(samples)
    if len(values) < 2:
        return math.inf
    start = _yaw_from_wxyz(values[0].quaternion_wxyz)
    end = _yaw_from_wxyz(values[-1].quaternion_wxyz)
    difference = math.atan2(math.sin(end - start), math.cos(end - start))
    return abs(math.degrees(difference))


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


def stable_stop_window(
    samples: Iterable[OdomSample],
    *,
    start: float,
    max_settle: float,
    hold: float,
    speed_limit: float,
) -> tuple[float, float]:
    values = sorted(
        (
            sample
            for sample in samples
            if start <= sample.sim_time <= start + max_settle + hold
        ),
        key=lambda sample: sample.sim_time,
    )
    for candidate in values:
        if candidate.sim_time > start + max_settle:
            break
        end = candidate.sim_time + hold
        window = [
            sample
            for sample in values
            if candidate.sim_time <= sample.sim_time <= end
        ]
        if not window or window[-1].sim_time < end - 1e-6:
            continue
        maximum = max(sample.speed for sample in window)
        if maximum <= speed_limit:
            return candidate.sim_time - start, maximum
    return math.inf, math.inf


def quaternion_samples_finite(samples: Iterable[OdomSample]) -> bool:
    values = list(samples)
    return bool(values) and all(
        all(math.isfinite(component) for component in sample.quaternion_wxyz)
        for sample in values
    )


def message_contract_errors(
    config: Stage1Config,
    odometry: Iterable[OdomSample],
    imu: Iterable[ImuContractSample],
    images: Iterable[ImageContractSample],
    camera_info: Iterable[CameraInfoContractSample],
    transforms: Iterable[TransformContractSample],
) -> list[str]:
    errors: list[str] = []
    odom_samples = list(odometry)
    imu_samples = list(imu)
    image_samples = list(images)
    info_samples = list(camera_info)
    transform_samples = list(transforms)

    if not odom_samples or any(
        sample.frame_id != config.frames.odom
        or sample.child_frame_id != config.frames.base
        or not _finite_values((sample.x, sample.y, sample.speed))
        or not _valid_quaternion(sample.quaternion_wxyz)
        for sample in odom_samples
    ):
        errors.append("odometry frames or numeric fields are invalid")

    if not imu_samples or any(
        sample.frame_id != config.frames.imu
        or not _valid_quaternion(sample.quaternion_wxyz)
        or not _finite_values(sample.angular_velocity)
        or not _finite_values(sample.linear_acceleration)
        for sample in imu_samples
    ):
        errors.append("IMU frame or numeric fields are invalid")

    if not image_samples or any(
        sample.frame_id != config.frames.camera
        or sample.width != config.camera.width
        or sample.height != config.camera.height
        or sample.encoding != "rgb8"
        or sample.step != config.camera.width * 3
        or sample.data_length != config.camera.height * sample.step
        for sample in image_samples
    ):
        errors.append("image frame, shape, encoding, or stride is invalid")

    expected_k = (
        config.camera.fx,
        0.0,
        config.camera.cx,
        0.0,
        config.camera.fy,
        config.camera.cy,
        0.0,
        0.0,
        1.0,
    )
    expected_p = (
        config.camera.fx,
        0.0,
        config.camera.cx,
        0.0,
        0.0,
        config.camera.fy,
        config.camera.cy,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
    )
    if not info_samples or any(
        sample.frame_id != config.frames.camera
        or sample.width != config.camera.width
        or sample.height != config.camera.height
        or not _tuple_close(sample.k, expected_k)
        or not _tuple_close(sample.p, expected_p)
        for sample in info_samples
    ):
        errors.append("camera info frame, dimensions, or matrices are invalid")
    image_times = [round(sample.sim_time, 9) for sample in image_samples]
    info_times = [round(sample.sim_time, 9) for sample in info_samples]
    if image_times != info_times:
        errors.append("camera image and info timestamps differ")

    required_tf = {
        (config.frames.map, config.frames.odom, True),
        (config.frames.odom, config.frames.base, False),
        (config.frames.base, config.frames.imu, False),
        (config.frames.base, config.frames.camera, False),
    }
    observed_tf = {
        (sample.parent, sample.child, sample.is_static)
        for sample in transform_samples
    }
    if not required_tf.issubset(observed_tf) or any(
        not _finite_values(sample.translation)
        or not _valid_quaternion(sample.quaternion_wxyz)
        for sample in transform_samples
    ):
        errors.append("TF frame pairs or numeric fields are invalid")
    return errors


def build_result(gates: dict[str, bool], metrics: dict[str, Any]) -> dict[str, Any]:
    first_failure = next(
        (name for name in GATE_ORDER if not bool(gates.get(name, False))), None
    )
    passed = first_failure is None
    return {
        "stage": 1,
        "status": "PASS" if passed else "FAIL",
        "label": "PASS_SIM_ODOM" if passed else None,
        "qualified_pass": "PASS_SIM_ODOM" if passed else None,
        "first_failing_gate": first_failure,
        "motion_enabled": False,
        "simulated_motion": True,
        "physical_motion": False,
        "gates": {name: bool(gates.get(name, False)) for name in GATE_ORDER},
        "metrics": metrics,
    }


def build_failure_result(
    failed_gate: str, metrics: dict[str, Any], *, phase: str
) -> dict[str, Any]:
    if failed_gate not in GATE_ORDER:
        raise ValueError(f"unknown Stage 1 gate: {failed_gate}")
    gates: dict[str, bool] = {}
    for name in GATE_ORDER:
        gates[name] = name != failed_gate
        if name == failed_gate:
            break
    result = build_result(gates, metrics)
    result["failure_phase"] = phase
    return result


class Stage1Evaluator(Node):
    def __init__(
        self,
        config: Stage1Config,
        *,
        ready_file: Path | None = None,
        approval_file: Path | None = None,
    ) -> None:
        super().__init__(
            "holoagent_stage1_eval",
            parameter_overrides=[
                Parameter("use_sim_time", Parameter.Type.BOOL, True)
            ],
            automatically_declare_parameters_from_overrides=True,
        )
        self.config = config
        self.ready_file = ready_file
        self.approval_file = approval_file
        self.current_sim_time: float | None = None
        self.clock_samples: list[tuple[float, float]] = []
        self.imu_times: list[float] = []
        self.odom_samples: list[OdomSample] = []
        self.image_times: list[float] = []
        self.camera_info_times: list[float] = []
        self.imu_contract_samples: list[ImuContractSample] = []
        self.image_contract_samples: list[ImageContractSample] = []
        self.camera_info_contract_samples: list[CameraInfoContractSample] = []
        self.transform_contract_samples: list[TransformContractSample] = []
        self.applied_commands: list[AppliedCommandSample] = []
        self.contact_samples: list[tuple[float, int]] = []
        self.tf_messages = 0
        self.static_tf_messages = 0
        self.graph_evidence: dict[str, Any] = {}
        self.active_gate = "graph"
        self.phase = "graph"
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
            + thresholds.stop_settle_sec
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
        self.active_gate = "clock"
        self.phase = "warmup"
        start = float(self.current_sim_time)

        self._wait_sim(start + thresholds.warmup_sec, VelocityCommand.zero())
        rate_start = float(self.current_sim_time)
        self.phase = "rate_window"
        self._wait_sim(
            rate_start + thresholds.rate_window_sec, VelocityCommand.zero()
        )
        rate_end = rate_start + thresholds.rate_window_sec
        self.active_gate = "graph"
        self.phase = "motion_approval"
        self._wait_for_external_motion_approval()
        self._assert_motion_graph()

        clamp_start = float(self.current_sim_time)
        self.active_gate = "command_clamp"
        self.phase = "clamp_probe"
        clamp_probe = VelocityCommand(10.0, 10.0, 10.0)
        self._wait_sim(clamp_start + 0.5, clamp_probe)
        clamp_end = clamp_start + 0.5

        recovery_start = float(self.current_sim_time)
        self.phase = "zero_recovery"
        self._wait_sim(recovery_start + 1.0, VelocityCommand.zero())

        motion_start = float(self.current_sim_time)
        self.active_gate = "bounded_motion"
        self.phase = "motion"
        self._wait_sim(
            motion_start + thresholds.motion_duration_sec,
            VelocityCommand(thresholds.motion_speed_mps, 0.0, 0.0),
        )
        motion_end = motion_start + thresholds.motion_duration_sec

        silence_start = float(self.current_sim_time)
        self.active_gate = "timeout_zero"
        self.phase = "timeout"
        silence_duration = (
            thresholds.timeout_zero_sec
            + thresholds.stop_settle_sec
            + thresholds.stopped_hold_sec
        )
        self._wait_sim(silence_start + silence_duration, None)
        self.publish_zero()
        self.phase = "metrics"

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
        stop_settle_latency, stopped_speed = stable_stop_window(
            self.odom_samples,
            start=stopped_start,
            max_settle=thresholds.stop_settle_sec,
            hold=thresholds.stopped_hold_sec,
            speed_limit=thresholds.stopped_speed_mps,
        )
        drift = stationary_drift(stationary_samples)
        forward_displacement, lateral_displacement = forward_motion(motion_samples)
        yaw_error_degrees = yaw_change_degrees(motion_samples)
        rtf = realtime_factor(
            self.clock_samples, warmup_sec=thresholds.warmup_sec
        )
        max_contacts = max((count for _, count in self.contact_samples), default=0)
        metrics = {
            **rate_metrics,
            "realtime_factor": rtf,
            "stationary_drift_m": drift,
            "motion_forward_displacement_m": forward_displacement,
            "motion_lateral_displacement_m": lateral_displacement,
            "motion_yaw_error_deg": yaw_error_degrees,
            "timeout_latency_sec": latency,
            "stop_settle_latency_sec": stop_settle_latency,
            "stopped_hold_max_speed_mps": stopped_speed,
            "max_contact_count": max_contacts,
            "tf_messages": self.tf_messages,
            "static_tf_messages": self.static_tf_messages,
            "graph_reason": graph_reason,
            "graph": self.graph_evidence,
        }
        all_applied_in_bounds = clamp_gate(
            self.applied_commands, limits, require_positive_probe=False
        )
        contract_errors = message_contract_errors(
            self.config,
            self.odom_samples,
            self.imu_contract_samples,
            self.image_contract_samples,
            self.camera_info_contract_samples,
            self.transform_contract_samples,
        )
        metrics["message_contract_errors"] = contract_errors
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
            <= forward_displacement
            <= thresholds.motion_max_displacement_m
            and abs(lateral_displacement) <= thresholds.motion_max_lateral_m
            and yaw_error_degrees <= thresholds.motion_max_yaw_error_deg,
            "timeout_zero": latency <= thresholds.timeout_zero_sec,
            "stop_settle": stop_settle_latency <= thresholds.stop_settle_sec,
            "stopped_speed": stopped_speed <= thresholds.stopped_speed_mps,
            "message_finite": not contract_errors,
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
        last_graph_check = -math.inf
        while self.current_sim_time is None or self.current_sim_time < target_sim_time:
            self._check_wall_deadline()
            now = time.monotonic()
            if motion_graph_guard_required(command) and now - last_graph_check >= 0.1:
                self._assert_motion_graph(check_remote_parameter=False)
                last_graph_check = now
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

    def _wait_for_external_motion_approval(self) -> None:
        if self.ready_file is None or self.approval_file is None:
            raise RuntimeError("external graph approval paths are required")
        ready = self.ready_file.expanduser().resolve()
        approval = self.approval_file.expanduser().resolve()
        if ready.exists() or approval.exists():
            raise RuntimeError("graph approval artifacts must not pre-exist")
        ready.write_text(
            json.dumps(
                {
                    "status": "READY_MOTION_DISABLED",
                    "sim_time": self.current_sim_time,
                    "graph": self.graph_evidence,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        expected_approval = file_sha256(ready)
        while True:
            self._check_wall_deadline()
            self._assert_motion_graph(
                check_remote_parameter=False,
                allow_cli_verifiers=True,
            )
            if approval.is_file():
                supplied = approval.read_text(encoding="utf-8").strip()
                if supplied != expected_approval:
                    raise RuntimeError("external graph approval digest mismatch")
                self._wait_for_cli_verifier_departure()
                return
            rclpy.spin_once(self, timeout_sec=0.05)

    def _wait_for_cli_verifier_departure(self) -> None:
        deadline = time.monotonic() + 5.0
        last_reason = "ROS CLI verifier did not leave the graph"
        while time.monotonic() < deadline:
            self._check_wall_deadline()
            valid, last_reason = self._graph_contract_once()
            if valid:
                return
            permissive_valid, permissive_reason = self._graph_contract_once(
                allow_cli_verifiers=True
            )
            if not permissive_valid:
                self.active_gate = "graph"
                self.phase = "motion_graph_guard"
                self.publish_zero()
                raise RuntimeError(
                    f"motion graph guard failed: {permissive_reason}"
                )
            rclpy.spin_once(self, timeout_sec=0.05)
        self.active_gate = "graph"
        self.phase = "motion_graph_guard"
        self.publish_zero()
        raise RuntimeError(
            f"motion graph guard failed after verifier departure timeout: {last_reason}"
        )

    def _assert_motion_graph(
        self,
        *,
        check_remote_parameter: bool = True,
        allow_cli_verifiers: bool = False,
    ) -> None:
        valid, reason = self._graph_contract_once(
            allow_cli_verifiers=allow_cli_verifiers
        )
        if not valid or (check_remote_parameter and not self._bridge_uses_sim_time()):
            self.active_gate = "graph"
            self.phase = "motion_graph_guard"
            self.publish_zero()
            detail = reason if not valid else "bridge use_sim_time is not true"
            raise RuntimeError(f"motion graph guard failed: {detail}")

    def _graph_contract_once(
        self, *, allow_cli_verifiers: bool = False
    ) -> tuple[bool, str]:
        nodes = sorted(
            _qualified_name(name, namespace)
            for name, namespace in self.get_node_names_and_namespaces()
        )
        topics = {
            name: sorted(types) for name, types in self.get_topic_names_and_types()
        }
        services = {
            name: sorted(types) for name, types in self.get_service_names_and_types()
        }
        action_endpoints = sorted(name for name in topics if "/_action/" in name)
        self.graph_evidence = {
            "nodes": nodes,
            "topics": topics,
            "services": services,
            "actions": action_endpoints,
            "endpoints": {},
        }
        allowed_nodes = {"/holoagent_mujoco_bridge", "/holoagent_stage1_eval"}
        node_error = node_contract_error(
            nodes, allow_cli_verifiers=allow_cli_verifiers
        )
        if node_error is not None:
            return False, node_error
        forbidden_node_tokens = (
            "nav2",
            "controller_server",
            "planner_server",
            "bt_navigator",
        )
        if any(token in name for token in forbidden_node_tokens for name in nodes):
            return False, "navigation node discovered"
        topic_error = topic_contract_error(topics)
        if topic_error is not None:
            return False, topic_error
        service_error = service_contract_error(services, tuple(sorted(allowed_nodes)))
        if service_error is not None:
            return False, service_error
        endpoint_evidence: dict[str, dict[str, list[str]]] = {}
        for topic in REQUIRED_TOPICS:
            publishers = _endpoint_node_names(
                self.get_publishers_info_by_topic(topic)
            )
            subscriptions = _endpoint_node_names(
                self.get_subscriptions_info_by_topic(topic)
            )
            endpoint_evidence[topic] = {
                "publishers": publishers,
                "subscriptions": subscriptions,
            }
            expected_publisher = (
                ["/holoagent_stage1_eval"]
                if topic == "/cmd_vel"
                else ["/holoagent_mujoco_bridge"]
            )
            expected_subscription = (
                ["/holoagent_mujoco_bridge"]
                if topic == "/cmd_vel"
                else [
                    "/holoagent_mujoco_bridge",
                    "/holoagent_stage1_eval",
                    "/holoagent_stage1_eval",
                ]
                if topic == "/clock"
                else ["/holoagent_stage1_eval"]
            )
            if publishers != expected_publisher:
                return False, f"{topic} publisher ownership mismatch: {publishers}"
            if subscriptions != expected_subscription:
                return False, (
                    f"{topic} subscriber ownership mismatch: {subscriptions}"
                )
        self.graph_evidence = {
            "nodes": nodes,
            "topics": topics,
            "services": services,
            "actions": action_endpoints,
            "endpoints": endpoint_evidence,
        }
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
                message.header.frame_id,
                message.child_frame_id,
            )
        )

    def _imu_callback(self, message: Imu) -> None:
        stamp = _stamp_seconds(message.header.stamp)
        self.imu_times.append(stamp)
        self.imu_contract_samples.append(
            ImuContractSample(
                stamp,
                message.header.frame_id,
                (
                    float(message.orientation.w),
                    float(message.orientation.x),
                    float(message.orientation.y),
                    float(message.orientation.z),
                ),
                (
                    float(message.angular_velocity.x),
                    float(message.angular_velocity.y),
                    float(message.angular_velocity.z),
                ),
                (
                    float(message.linear_acceleration.x),
                    float(message.linear_acceleration.y),
                    float(message.linear_acceleration.z),
                ),
            )
        )

    def _image_callback(self, message: Image) -> None:
        stamp = _stamp_seconds(message.header.stamp)
        self.image_times.append(stamp)
        self.image_contract_samples.append(
            ImageContractSample(
                stamp,
                message.header.frame_id,
                int(message.width),
                int(message.height),
                message.encoding,
                int(message.step),
                len(message.data),
            )
        )

    def _camera_info_callback(self, message: CameraInfo) -> None:
        stamp = _stamp_seconds(message.header.stamp)
        self.camera_info_times.append(stamp)
        self.camera_info_contract_samples.append(
            CameraInfoContractSample(
                stamp,
                message.header.frame_id,
                int(message.width),
                int(message.height),
                tuple(float(value) for value in message.k),
                tuple(float(value) for value in message.p),
            )
        )

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
        self._record_transforms(message, is_static=False)

    def _static_tf_callback(self, message: TFMessage) -> None:
        self.static_tf_messages += len(message.transforms)
        self._record_transforms(message, is_static=True)

    def _record_transforms(self, message: TFMessage, *, is_static: bool) -> None:
        for transform in message.transforms:
            translation = transform.transform.translation
            rotation = transform.transform.rotation
            self.transform_contract_samples.append(
                TransformContractSample(
                    _stamp_seconds(transform.header.stamp),
                    transform.header.frame_id,
                    transform.child_frame_id,
                    (
                        float(translation.x),
                        float(translation.y),
                        float(translation.z),
                    ),
                    (
                        float(rotation.w),
                        float(rotation.x),
                        float(rotation.y),
                        float(rotation.z),
                    ),
                    is_static,
                )
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the Stage 1 MuJoCo contract")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    node = None
    initialized = False
    config = None
    result: dict[str, Any]
    try:
        config = load_config(arguments.config)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = Stage1Evaluator(
            config,
            ready_file=arguments.ready_file,
            approval_file=arguments.approval_file,
        )
        result = node.run()
        result["config_path"] = str(arguments.config.resolve())
        result["config_sha256"] = file_sha256(arguments.config)
        _enrich_result(result, config, arguments.output)
    except Exception as exc:
        gate = node.active_gate if node is not None else "graph"
        phase = node.phase if node is not None else "startup"
        result = build_failure_result(
            gate,
            {"error": str(exc)},
            phase=phase,
        )
        result["exception_type"] = type(exc).__name__
        if config is not None:
            _enrich_result(result, config, arguments.output)
    finally:
        if node is not None:
            try:
                node.publish_zero()
            except Exception:
                pass
            if rclpy.ok():
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


def _yaw_from_wxyz(quaternion: tuple[float, float, float, float]) -> float:
    w, x, y, z = quaternion
    return math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def _finite_values(values: Iterable[float]) -> bool:
    return all(math.isfinite(float(value)) for value in values)


def _valid_quaternion(values: tuple[float, float, float, float]) -> bool:
    if not _finite_values(values):
        return False
    norm = math.sqrt(sum(float(value) ** 2 for value in values))
    return math.isclose(norm, 1.0, abs_tol=1e-3)


def _tuple_close(left: tuple[float, ...], right: tuple[float, ...]) -> bool:
    return len(left) == len(right) and all(
        math.isfinite(float(value)) and math.isclose(value, expected, abs_tol=1e-9)
        for value, expected in zip(left, right)
    )


def _odom_window(
    samples: Iterable[OdomSample], start: float, end: float
) -> list[OdomSample]:
    return [sample for sample in samples if start <= sample.sim_time <= end]


def _qualified_name(name: str, namespace: str) -> str:
    prefix = namespace.rstrip("/")
    return f"{prefix}/{name}" if prefix else f"/{name}"


def _endpoint_node_names(endpoint_info: Iterable[Any]) -> list[str]:
    return sorted(
        _qualified_name(endpoint.node_name, endpoint.node_namespace)
        for endpoint in endpoint_info
    )


def motion_graph_guard_required(command: VelocityCommand | None) -> bool:
    """Keep guarding while a prior non-zero command can be timing out."""
    return command is None or not command.is_zero


def node_contract_error(
    nodes: list[str], *, allow_cli_verifiers: bool = False
) -> str | None:
    expected = ["/holoagent_mujoco_bridge", "/holoagent_stage1_eval"]
    observed = list(nodes)
    if allow_cli_verifiers:
        observed = [
            name
            for name in observed
            if not (
                re.fullmatch(r"/_ros2cli_[0-9]+", name)
                or re.fullmatch(r"/_ros2cli_daemon_77_[0-9a-f]{32}", name)
            )
        ]
    if observed != expected:
        return f"unexpected nodes: {nodes}"
    return None


def topic_contract_error(topics: dict[str, list[str]]) -> str | None:
    allowed = {**REQUIRED_TOPICS, **AUXILIARY_TOPICS}
    unexpected = sorted(set(topics) - set(allowed))
    if unexpected:
        return f"unexpected topic endpoint: {unexpected[0]}"
    for topic, expected_type in allowed.items():
        observed = topics.get(topic)
        if observed != [expected_type]:
            return f"{topic} type mismatch: {observed}"
    return None


def service_contract_error(
    services: dict[str, list[str]], nodes: tuple[str, ...]
) -> str | None:
    expected = {
        f"{node}/{name}": [service_type]
        for node in nodes
        for name, service_type in PARAMETER_SERVICE_TYPES.items()
    }
    if services != expected:
        return (
            "service contract mismatch: "
            f"expected={sorted(expected)}, got={sorted(services)}"
        )
    return None


def _write_json(path: Path, result: dict[str, Any]) -> None:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)


def _enrich_result(
    result: dict[str, Any], config: Stage1Config, output_path: Path
) -> None:
    run_directory = output_path.expanduser().resolve().parent
    result["isolation"] = {
        "ros_domain_id": config.runtime.ros_domain_id,
        "ros_localhost_only": config.runtime.ros_localhost_only,
        "rmw_implementation": config.runtime.rmw_implementation,
    }
    result["backend_artifacts"] = {
        name: {"path": str(path), "sha256": digest}
        for (name, digest), path in zip(
            config.backend.expected_sha256,
            (
                config.backend.balance_policy,
                config.backend.config_yaml,
                config.backend.runner,
                config.backend.walk_policy,
                config.backend.xml,
            ),
        )
    }
    result["evidence"] = {
        name: str(run_directory / filename)
        for name, filename in {
            "preflight": "preflight.json",
            "graph_preflight": "graph_preflight.json",
            "host_graph": "host_graph.txt",
            "container_graph": "container_graph.txt",
            "bridge_log": "bridge.log",
            "evaluator_log": "evaluator.log",
            "postflight": "postflight.json",
        }.items()
    }


if __name__ == "__main__":
    raise SystemExit(main())
