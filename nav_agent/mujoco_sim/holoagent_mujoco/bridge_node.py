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
from sensor_msgs.msg import CameraInfo, Image, Imu, PointCloud2
from std_msgs.msg import UInt32
from tf2_ros import StaticTransformBroadcaster, TransformBroadcaster

from holoagent_mujoco.backend import (
    BackendError,
    BackendSnapshot,
    MujocoBackend,
    create_backend,
)
from holoagent_mujoco.command import CommandLimits, CommandSafety
from holoagent_mujoco.config import Stage1Config, load_config
from holoagent_mujoco.lidar import LidarPose, PoseHistory, SyntheticLidar
from holoagent_mujoco.ros_messages import (
    camera_info_message,
    clock_message,
    image_message,
    imu_message,
    odometry_message,
    pointcloud_message,
    sensor_transforms,
    static_map_transform,
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


def fast_livo_sensor_qos() -> QoSProfile:
    """Offer reliable sensor delivery for FastLIVO's reliable subscriptions."""
    return QoSProfile(
        history=HistoryPolicy.KEEP_LAST,
        depth=5,
        reliability=ReliabilityPolicy.RELIABLE,
        durability=DurabilityPolicy.VOLATILE,
    )


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
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
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
        stream_rates = {
            "imu": config.rates.imu_hz,
            "odom": config.rates.odom_hz,
            "camera": config.rates.camera_hz,
        }
        if config.lidar.enabled:
            stream_rates["lidar"] = config.rates.lidar_hz
        self.scheduler = SimRateScheduler(config.rates.physics_hz, stream_rates)
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
        livo_sensor_qos = fast_livo_sensor_qos()
        reliable_qos = QoSProfile(depth=10)
        self._clock_publisher = self.create_publisher(Clock, "/clock", clock_qos)
        self._odom_publisher = self.create_publisher(
            Odometry, "/robot_odom", reliable_qos
        )
        self._imu_publisher = self.create_publisher(Imu, "/livox/imu", livo_sensor_qos)
        self._image_publisher = self.create_publisher(
            Image, "/camera/color/image_raw", livo_sensor_qos
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
        self._collision_publisher = None
        if config.scene.publish_collision_count:
            self._collision_publisher = self.create_publisher(
                UInt32, "/holoagent_sim/collision_count", sensor_qos
            )
        self._lidar_publisher = None
        self._lidar_sensor = None
        self._lidar_history = None
        if config.lidar.enabled:
            self._lidar_publisher = self.create_publisher(
                PointCloud2, "/holoagent_sim/lidar_points", sensor_qos
            )
            self._lidar_sensor = SyntheticLidar(config.lidar)
            self._lidar_history = PoseHistory(config.lidar.scan_period_sec)
            self._lidar_history.append(_lidar_pose(backend.snapshot()))
        self._tf_broadcaster = TransformBroadcaster(self)
        self._static_tf_broadcaster = StaticTransformBroadcaster(self)
        self._command_subscription = self.create_subscription(
            Twist, "/cmd_vel", self._command_callback, reliable_qos
        )
        self._static_tf_broadcaster.sendTransform(
            static_map_transform(self._sim_time, config.frames)
        )

    @property
    def sim_time(self) -> float:
        return self._sim_time

    def step_once(self) -> None:
        command = self.safety.current(sim_time=self._sim_time)
        self.backend.set_command(command)
        snapshot = self.backend.step()
        self._sim_time = snapshot.sim_time
        if self._lidar_history is not None:
            self._lidar_history.append(_lidar_pose(snapshot))
        self._clock_publisher.publish(clock_message(snapshot.sim_time))
        self._applied_publisher.publish(twist_message(snapshot.applied_command))
        contact_message = UInt32()
        contact_message.data = snapshot.contact_count
        self._contact_publisher.publish(contact_message)
        if self._collision_publisher is not None:
            collision_message = UInt32()
            collision_message.data = snapshot.scene_collision_count
            self._collision_publisher.publish(collision_message)

        due = self.scheduler.tick()
        if "imu" in due:
            self._imu_publisher.publish(imu_message(snapshot, self.config.frames))
        if "odom" in due:
            self._odom_publisher.publish(odometry_message(snapshot, self.config.frames))
            self._tf_broadcaster.sendTransform(
                [
                    transform_message(snapshot, self.config.frames),
                    *sensor_transforms(
                        snapshot,
                        self.config.frames,
                        include_lidar=self.config.lidar.enabled,
                    ),
                ]
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
        if "lidar" in due:
            if (
                self._lidar_sensor is None
                or self._lidar_history is None
                or self._lidar_publisher is None
            ):
                raise BackendError("lidar scheduler fired while lidar is disabled")
            scan = self._lidar_sensor.acquire(
                _lidar_pose(snapshot),
                self._lidar_history,
                self.backend.raycast_static,
            )
            self._lidar_publisher.publish(pointcloud_message(scan, self.config.frames))

    def force_zero(self) -> None:
        command = self.safety.shutdown()
        try:
            self.backend.set_command(command)
        except BackendError:
            pass
        if rclpy.ok():
            try:
                self._applied_publisher.publish(twist_message(command))
            except Exception:
                # The internal controller is already zero; ROS may have shut down
                # between the context check and this best-effort final publication.
                pass

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
            config.lidar,
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
        if initialized and not rclpy.ok():
            return 0
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

        return (
            Path(get_package_share_directory("holoagent_mujoco"))
            / "config"
            / "stage1.yaml"
        )
    except (ImportError, LookupError):
        return Path(__file__).parents[1] / "config" / "stage1.yaml"


def _lidar_pose(snapshot: BackendSnapshot) -> LidarPose:
    return LidarPose(
        sim_time=snapshot.sim_time,
        position_world=snapshot.lidar_position_world,
        quaternion_world_wxyz=snapshot.lidar_quaternion_world_wxyz,
    )


if __name__ == "__main__":
    raise SystemExit(main())
