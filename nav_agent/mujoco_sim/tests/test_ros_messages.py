from __future__ import annotations

import numpy as np
import pytest

from holoagent_mujoco.backend import BackendSnapshot
from holoagent_mujoco.command import VelocityCommand
from holoagent_mujoco.config import CameraConfig, FrameConfig
from holoagent_mujoco.ros_messages import (
    camera_info_message,
    clock_message,
    image_message,
    imu_message,
    odometry_message,
    static_sensor_transforms,
    time_message,
    transform_message,
    twist_message,
)


FRAMES = FrameConfig(
    map="sim_map", odom="odom", base="base_link", imu="imu_link", camera="camera_link"
)
CAMERA = CameraConfig(
    name="head_camera",
    width=2,
    height=1,
    fx=240.0,
    fy=241.0,
    cx=1.0,
    cy=0.5,
    mount_pos=(0.18, 0.0, 0.35),
    mount_xyaxes=(0.0, -1.0, 0.0, 0.0, 0.0, 1.0),
)
SNAPSHOT = BackendSnapshot(
    sim_time=1.25,
    base_position=(1.0, 2.0, 0.8),
    base_quaternion_wxyz=(0.5, 0.1, 0.2, 0.3),
    base_linear_velocity=(0.4, 0.5, 0.6),
    base_angular_velocity=(0.7, 0.8, 0.9),
    imu_angular_velocity=(1.0, 1.1, 1.2),
    imu_linear_acceleration=(2.0, 2.1, 2.2),
    applied_command=VelocityCommand(0.1, 0.0, -0.2),
    contact_count=4,
)


def test_timestamp_rounding_normalizes_nanoseconds():
    stamp = time_message(1.9999999996)

    assert stamp.sec == 2
    assert stamp.nanosec == 0
    with pytest.raises(ValueError, match="non-negative finite"):
        time_message(float("nan"))
    with pytest.raises(ValueError, match="non-negative finite"):
        time_message(-0.1)


def test_clock_uses_mujoco_simulated_time():
    message = clock_message(1.25)

    assert message.clock.sec == 1
    assert message.clock.nanosec == 250_000_000


def test_odometry_and_transform_map_wxyz_to_ros_xyzw():
    odom = odometry_message(SNAPSHOT, FRAMES)
    transform = transform_message(SNAPSHOT, FRAMES)

    assert odom.header.frame_id == "odom"
    assert odom.child_frame_id == "base_link"
    assert (odom.pose.pose.position.x, odom.pose.pose.position.y) == (1.0, 2.0)
    assert (
        odom.pose.pose.orientation.x,
        odom.pose.pose.orientation.y,
        odom.pose.pose.orientation.z,
        odom.pose.pose.orientation.w,
    ) == (0.1, 0.2, 0.3, 0.5)
    assert odom.twist.twist.linear.x == 0.4
    assert odom.twist.twist.angular.z == 0.9
    assert transform.header.frame_id == "odom"
    assert transform.child_frame_id == "base_link"
    assert transform.transform.rotation.w == 0.5


def test_imu_uses_declared_frame_and_snapshot_values():
    message = imu_message(SNAPSHOT, FRAMES)

    assert message.header.frame_id == "imu_link"
    assert message.header.stamp.sec == 1
    assert message.orientation.w == 0.5
    assert message.angular_velocity.y == 1.1
    assert message.linear_acceleration.z == 2.2
    assert message.orientation_covariance[0] == -1.0


def test_rgb_image_encoding_stride_and_camera_matrix():
    rgb = np.array([[[1, 2, 3], [4, 5, 6]]], dtype=np.uint8)

    image = image_message(rgb, SNAPSHOT.sim_time, FRAMES)
    info = camera_info_message(SNAPSHOT.sim_time, FRAMES, CAMERA)

    assert image.header.frame_id == "camera_link"
    assert image.encoding == "rgb8"
    assert image.height == 1 and image.width == 2
    assert image.step == 6
    assert bytes(image.data) == bytes([1, 2, 3, 4, 5, 6])
    assert info.header == image.header
    assert list(info.k) == [240.0, 0.0, 1.0, 0.0, 241.0, 0.5, 0.0, 0.0, 1.0]
    assert list(info.p) == [
        240.0, 0.0, 1.0, 0.0,
        0.0, 241.0, 0.5, 0.0,
        0.0, 0.0, 1.0, 0.0,
    ]


def test_static_sensor_frames_and_applied_twist():
    transforms = static_sensor_transforms(0.0, FRAMES, CAMERA)
    by_child = {transform.child_frame_id: transform for transform in transforms}

    assert set(by_child) == {"imu_link", "camera_link"}
    assert by_child["imu_link"].header.frame_id == "base_link"
    assert by_child["camera_link"].transform.translation.x == 0.18
    rotation = by_child["camera_link"].transform.rotation
    assert (rotation.x, rotation.y, rotation.z, rotation.w) == pytest.approx(
        (0.5, -0.5, -0.5, 0.5)
    )

    twist = twist_message(SNAPSHOT.applied_command)
    assert twist.linear.x == 0.1
    assert twist.linear.y == 0.0
    assert twist.angular.z == -0.2
