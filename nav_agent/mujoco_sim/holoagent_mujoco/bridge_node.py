from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys
import time
from typing import Callable

from geometry_msgs.msg import Twist
import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import DurabilityPolicy, HistoryPolicy, QoSProfile, ReliabilityPolicy
from rosgraph_msgs.msg import Clock
from nav_msgs.msg import Odometry
from sensor_msgs.msg import CameraInfo, Image, Imu
from std_msgs.msg import UInt32
from tf2_ros import StaticTransformBroadcaster, TransformBroadcaster

from holoagent_mujoco.backend import BackendError, MujocoBackend, create_backend
from holoagent_mujoco.command import CommandLimits, CommandSafety
from holoagent_mujoco.config import Stage1Config, load_config
from holoagent_mujoco.ros_messages import (
    camera_info_message,
    clock_message,
    image_message,
    imu_message,
    odometry_message,
    static_sensor_transforms,
    transform_message,
    twist_message,
)
from holoagent_mujoco.scene import generate_scene


class SimRateScheduler:
    """Integer accumulator scheduler keyed only to physics steps."""

    def __init__(self, physics_hz: int, stream_hz: dict[str, int]) -> None:
        if physics_hz <= 0:
            raise ValueError("physics_hz must be positive")
        for name, rate in stream_hz.items():
            if rate <= 0:
                raise ValueError(f"{name} rate must be positive")
            if rate > physics_hz:
                raise ValueError(f"{name} rate cannot exceed physics_hz")
        self._physics_hz = physics_hz
        self._rates = dict(stream_hz)
        self._accumulators = {name: 0 for name in stream_hz}

    def tick(self) -> frozenset[str]:
        due = set()
        for name, rate in self._rates.items():
            self._accumulators[name] += rate
            if self._accumulators[name] >= self._physics_hz:
                self._accumulators[name] -= self._physics_hz
                due.add(name)
        return frozenset(due)


def run_fail_closed_loop(
    iteration: Callable[[], None],
    force_zero: Callable[[], None],
    keep_running: Callable[[], bool],
) -> None:
    try:
        while keep_running():
            iteration()
    finally:
        force_zero()


class HoloAgentMujocoBridge(Node):
    def __init__(self, config: Stage1Config, backend: MujocoBackend) -> None:
        super().__init__(
            "holoagent_mujoco_bridge",
            parameter_overrides=[
                Parameter("use_sim_time", Parameter.Type.BOOL, True)
            ],
            automatically_declare_parameters_from_overrides=True,
        )
        if not self.get_parameter("use_sim_time").value:
            raise BackendError("bridge must use simulated time")
        self.config = config
        self.backend = backend
        self.safety = CommandSafety(
            CommandLimits(
                config.command.max_linear_x,
                config.command.max_linear_y,
                config.command.max_yaw_rate,
                config.command.timeout_sim_sec,
            )
        )
        self.scheduler = SimRateScheduler(
            config.rates.physics_hz,
            {
                "imu": config.rates.imu_hz,
                "odom": config.rates.odom_hz,
                "camera": config.rates.camera_hz,
            },
        )
        self._sim_time = float(backend.data.time)
        clock_qos = QoSProfile(
            history=HistoryPolicy.KEEP_LAST,
            depth=1,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            durability=DurabilityPolicy.VOLATILE,
        )
        sensor_qos = QoSProfile(
            history=HistoryPolicy.KEEP_LAST,
            depth=5,
            reliability=ReliabilityPolicy.BEST_EFFORT,
            durability=DurabilityPolicy.VOLATILE,
        )
        reliable_qos = QoSProfile(depth=10)
        self._clock_publisher = self.create_publisher(Clock, "/clock", clock_qos)
        self._odom_publisher = self.create_publisher(
            Odometry, "/robot_odom", reliable_qos
        )
        self._imu_publisher = self.create_publisher(Imu, "/livox/imu", sensor_qos)
        self._image_publisher = self.create_publisher(
            Image, "/camera/color/image_raw", sensor_qos
        )
        self._camera_info_publisher = self.create_publisher(
            CameraInfo, "/camera/color/camera_info", sensor_qos
        )
        self._applied_publisher = self.create_publisher(
            Twist, "/holoagent_sim/applied_cmd_vel", reliable_qos
        )
        self._contact_publisher = self.create_publisher(
            UInt32, "/holoagent_sim/contact_count", sensor_qos
        )
        self._tf_broadcaster = TransformBroadcaster(self)
        self._static_tf_broadcaster = StaticTransformBroadcaster(self)
        self._command_subscription = self.create_subscription(
            Twist, "/cmd_vel", self._command_callback, reliable_qos
        )
        self._static_tf_broadcaster.sendTransform(
            static_sensor_transforms(self._sim_time, config.frames, config.camera)
        )

    @property
    def sim_time(self) -> float:
        return self._sim_time

    def step_once(self) -> None:
        command = self.safety.current(sim_time=self._sim_time)
        self.backend.set_command(command)
        snapshot = self.backend.step()
        self._sim_time = snapshot.sim_time
        self._clock_publisher.publish(clock_message(snapshot.sim_time))
        self._applied_publisher.publish(twist_message(snapshot.applied_command))
        contact_message = UInt32()
        contact_message.data = snapshot.contact_count
        self._contact_publisher.publish(contact_message)

        due = self.scheduler.tick()
        if "imu" in due:
            self._imu_publisher.publish(imu_message(snapshot, self.config.frames))
        if "odom" in due:
            self._odom_publisher.publish(
                odometry_message(snapshot, self.config.frames)
            )
            self._tf_broadcaster.sendTransform(
                transform_message(snapshot, self.config.frames)
            )
        if "camera" in due:
            image = self.backend.render_rgb(
                camera=self.config.camera.name,
                width=self.config.camera.width,
                height=self.config.camera.height,
            )
            self._image_publisher.publish(
                image_message(image, snapshot.sim_time, self.config.frames)
            )
            self._camera_info_publisher.publish(
                camera_info_message(
                    snapshot.sim_time, self.config.frames, self.config.camera
                )
            )

    def force_zero(self) -> None:
        command = self.safety.shutdown()
        try:
            self.backend.set_command(command)
        except BackendError:
            pass
        self._applied_publisher.publish(twist_message(command))

    def _command_callback(self, message: Twist) -> None:
        command = self.safety.accept(
            message.linear.x,
            message.linear.y,
            message.angular.z,
            sim_time=self._sim_time,
        )
        self.backend.set_command(command)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HoloAgent Stage 1 MuJoCo bridge")
    parser.add_argument("--config", type=Path, default=_default_config_path())
    parser.add_argument("--duration-sim", type=float, default=None)
    arguments, ros_arguments = parser.parse_known_args(argv)
    if arguments.duration_sim is not None and (
        not math.isfinite(arguments.duration_sim) or arguments.duration_sim <= 0.0
    ):
        parser.error("--duration-sim must be a positive finite value")

    backend = None
    node = None
    initialized = False
    try:
        config = load_config(arguments.config)
        scene = generate_scene(
            config.backend.xml,
            config.runtime.directory,
            config.scene,
            config.camera,
        )
        backend = create_backend(config, scene.path)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = HoloAgentMujocoBridge(config, backend)
        start_sim_time = node.sim_time
        start_wall_time = time.monotonic()

        def keep_running() -> bool:
            if not rclpy.ok():
                return False
            if arguments.duration_sim is None:
                return True
            return node.sim_time - start_sim_time < arguments.duration_sim

        def iteration() -> None:
            rclpy.spin_once(node, timeout_sec=0.0)
            node.step_once()
            target_wall_time = start_wall_time + (node.sim_time - start_sim_time)
            remaining = target_wall_time - time.monotonic()
            if remaining > 0.0:
                time.sleep(remaining)

        run_fail_closed_loop(iteration, node.force_zero, keep_running)
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Stage 1 bridge failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if node is not None:
            try:
                node.force_zero()
            finally:
                node.destroy_node()
        if backend is not None:
            backend.close()
        if initialized and rclpy.ok():
            rclpy.shutdown()


def _default_config_path() -> Path:
    try:
        from ament_index_python.packages import get_package_share_directory

        return Path(get_package_share_directory("holoagent_mujoco")) / "config" / "stage1.yaml"
    except (ImportError, LookupError):
        return Path(__file__).parents[1] / "config" / "stage1.yaml"


if __name__ == "__main__":
    raise SystemExit(main())
