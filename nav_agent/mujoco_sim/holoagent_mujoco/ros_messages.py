from __future__ import annotations

import math

from builtin_interfaces.msg import Time
from geometry_msgs.msg import TransformStamped, Twist
from nav_msgs.msg import Odometry
import numpy as np
from rosgraph_msgs.msg import Clock
from sensor_msgs.msg import CameraInfo, Image, Imu

from holoagent_mujoco.backend import BackendSnapshot
from holoagent_mujoco.command import VelocityCommand
from holoagent_mujoco.config import CameraConfig, FrameConfig


def time_message(sim_time: float) -> Time:
    value = float(sim_time)
    if not math.isfinite(value) or value < 0.0:
        raise ValueError("simulated time must be non-negative finite")
    seconds = math.floor(value)
    nanoseconds = round((value - seconds) * 1_000_000_000)
    if nanoseconds >= 1_000_000_000:
        seconds += 1
        nanoseconds -= 1_000_000_000
    message = Time()
    message.sec = int(seconds)
    message.nanosec = int(nanoseconds)
    return message


def clock_message(sim_time: float) -> Clock:
    message = Clock()
    message.clock = time_message(sim_time)
    return message


def odometry_message(snapshot: BackendSnapshot, frames: FrameConfig) -> Odometry:
    message = Odometry()
    message.header.stamp = time_message(snapshot.sim_time)
    message.header.frame_id = frames.odom
    message.child_frame_id = frames.base
    _set_xyz(message.pose.pose.position, snapshot.base_position)
    _set_ros_quaternion(
        message.pose.pose.orientation, snapshot.base_quaternion_wxyz
    )
    _set_xyz(message.twist.twist.linear, snapshot.base_linear_velocity)
    _set_xyz(message.twist.twist.angular, snapshot.base_angular_velocity)
    return message


def transform_message(
    snapshot: BackendSnapshot, frames: FrameConfig
) -> TransformStamped:
    message = TransformStamped()
    message.header.stamp = time_message(snapshot.sim_time)
    message.header.frame_id = frames.odom
    message.child_frame_id = frames.base
    _set_xyz(message.transform.translation, snapshot.base_position)
    _set_ros_quaternion(
        message.transform.rotation, snapshot.base_quaternion_wxyz
    )
    return message


def imu_message(snapshot: BackendSnapshot, frames: FrameConfig) -> Imu:
    message = Imu()
    message.header.stamp = time_message(snapshot.sim_time)
    message.header.frame_id = frames.imu
    _set_ros_quaternion(message.orientation, snapshot.imu_quaternion_wxyz)
    _set_xyz(message.angular_velocity, snapshot.imu_angular_velocity)
    _set_xyz(message.linear_acceleration, snapshot.imu_linear_acceleration)
    return message


def image_message(rgb: np.ndarray, sim_time: float, frames: FrameConfig) -> Image:
    array = np.asarray(rgb)
    if array.ndim != 3 or array.shape[2] != 3 or array.dtype != np.uint8:
        raise ValueError("RGB image must be an HxWx3 uint8 array")
    if not array.flags.c_contiguous:
        array = np.ascontiguousarray(array)
    message = Image()
    message.header.stamp = time_message(sim_time)
    message.header.frame_id = frames.camera
    message.height = int(array.shape[0])
    message.width = int(array.shape[1])
    message.encoding = "rgb8"
    message.is_bigendian = 0
    message.step = int(array.shape[1] * 3)
    message.data = array.tobytes()
    return message


def camera_info_message(
    sim_time: float, frames: FrameConfig, camera: CameraConfig
) -> CameraInfo:
    message = CameraInfo()
    message.header.stamp = time_message(sim_time)
    message.header.frame_id = frames.camera
    message.height = camera.height
    message.width = camera.width
    message.distortion_model = "plumb_bob"
    message.d = [0.0, 0.0, 0.0, 0.0, 0.0]
    message.k = [
        camera.fx,
        0.0,
        camera.cx,
        0.0,
        camera.fy,
        camera.cy,
        0.0,
        0.0,
        1.0,
    ]
    message.r = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    message.p = [
        camera.fx,
        0.0,
        camera.cx,
        0.0,
        0.0,
        camera.fy,
        camera.cy,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
    ]
    return message


def sensor_transforms(
    snapshot: BackendSnapshot, frames: FrameConfig
) -> list[TransformStamped]:
    stamp = time_message(snapshot.sim_time)
    imu = TransformStamped()
    imu.header.stamp = stamp
    imu.header.frame_id = frames.base
    imu.child_frame_id = frames.imu
    _set_xyz(imu.transform.translation, snapshot.imu_position_in_base)
    _set_ros_quaternion(
        imu.transform.rotation, snapshot.imu_quaternion_in_base_wxyz
    )

    camera_transform = TransformStamped()
    camera_transform.header.stamp = stamp
    camera_transform.header.frame_id = frames.base
    camera_transform.child_frame_id = frames.camera
    _set_xyz(camera_transform.transform.translation, snapshot.camera_position_in_base)
    _set_ros_quaternion(
        camera_transform.transform.rotation,
        snapshot.camera_quaternion_in_base_wxyz,
    )
    return [imu, camera_transform]


def static_map_transform(sim_time: float, frames: FrameConfig) -> TransformStamped:
    message = TransformStamped()
    message.header.stamp = time_message(sim_time)
    message.header.frame_id = frames.map
    message.child_frame_id = frames.odom
    message.transform.rotation.w = 1.0
    return message


def twist_message(command: VelocityCommand) -> Twist:
    message = Twist()
    message.linear.x = float(command.x)
    message.linear.y = float(command.y)
    message.angular.z = float(command.yaw)
    return message


def _set_xyz(message, values: tuple[float, float, float]) -> None:
    message.x = float(values[0])
    message.y = float(values[1])
    message.z = float(values[2])


def _set_ros_quaternion(message, wxyz: tuple[float, float, float, float]) -> None:
    message.w = float(wxyz[0])
    message.x = float(wxyz[1])
    message.y = float(wxyz[2])
    message.z = float(wxyz[3])


def _quaternion_from_xyaxes(
    xyaxes: tuple[float, float, float, float, float, float]
) -> tuple[float, float, float, float]:
    x_axis = np.asarray(xyaxes[:3], dtype=np.float64)
    y_axis = np.asarray(xyaxes[3:], dtype=np.float64)
    x_axis /= np.linalg.norm(x_axis)
    y_axis -= x_axis * np.dot(x_axis, y_axis)
    y_axis /= np.linalg.norm(y_axis)
    z_axis = np.cross(x_axis, y_axis)
    matrix = np.column_stack((x_axis, y_axis, z_axis))
    return _matrix_to_wxyz(matrix)


def _matrix_to_wxyz(matrix: np.ndarray) -> tuple[float, float, float, float]:
    trace = float(np.trace(matrix))
    if trace > 0.0:
        scale = math.sqrt(trace + 1.0) * 2.0
        quaternion = (
            0.25 * scale,
            (matrix[2, 1] - matrix[1, 2]) / scale,
            (matrix[0, 2] - matrix[2, 0]) / scale,
            (matrix[1, 0] - matrix[0, 1]) / scale,
        )
    else:
        diagonal = np.diag(matrix)
        index = int(np.argmax(diagonal))
        if index == 0:
            scale = math.sqrt(1.0 + matrix[0, 0] - matrix[1, 1] - matrix[2, 2]) * 2.0
            quaternion = (
                (matrix[2, 1] - matrix[1, 2]) / scale,
                0.25 * scale,
                (matrix[0, 1] + matrix[1, 0]) / scale,
                (matrix[0, 2] + matrix[2, 0]) / scale,
            )
        elif index == 1:
            scale = math.sqrt(1.0 + matrix[1, 1] - matrix[0, 0] - matrix[2, 2]) * 2.0
            quaternion = (
                (matrix[0, 2] - matrix[2, 0]) / scale,
                (matrix[0, 1] + matrix[1, 0]) / scale,
                0.25 * scale,
                (matrix[1, 2] + matrix[2, 1]) / scale,
            )
        else:
            scale = math.sqrt(1.0 + matrix[2, 2] - matrix[0, 0] - matrix[1, 1]) * 2.0
            quaternion = (
                (matrix[1, 0] - matrix[0, 1]) / scale,
                (matrix[0, 2] + matrix[2, 0]) / scale,
                (matrix[1, 2] + matrix[2, 1]) / scale,
                0.25 * scale,
            )
    norm = math.sqrt(sum(value * value for value in quaternion))
    return tuple(value / norm for value in quaternion)
