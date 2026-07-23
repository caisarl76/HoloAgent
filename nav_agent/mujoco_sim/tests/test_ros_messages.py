from __future__ import annotations

import struct

import numpy as np
import pytest
from sensor_msgs.msg import PointField

from holoagent_mujoco.backend import BackendSnapshot
from holoagent_mujoco.command import VelocityCommand
from holoagent_mujoco.config import CameraConfig, FrameConfig
from holoagent_mujoco.lidar import LidarScan
from holoagent_mujoco.ros_messages import (
    camera_info_message,
    clock_message,
    image_message,
    imu_message,
    odometry_message,
    pointcloud_message,
    sensor_transforms,
    static_map_transform,
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
    imu_quaternion_wxyz=(0.7, 0.1, 0.2, 0.3),
    imu_position_in_base=(0.01, 0.02, 0.03),
    imu_quaternion_in_base_wxyz=(0.8, 0.0, 0.6, 0.0),
    camera_position_in_base=(0.18, 0.0, 0.35),
    camera_quaternion_in_base_wxyz=(0.5, 0.5, -0.5, -0.5),
    applied_command=VelocityCommand(0.1, 0.0, -0.2),
    contact_count=4,
    lidar_position_in_base=(0.04, 0.0, 0.30),
    lidar_quaternion_in_base_wxyz=(1.0, 0.0, 0.0, 0.0),
    lidar_position_world=(1.04, 2.0, 1.1),
    lidar_quaternion_world_wxyz=(1.0, 0.0, 0.0, 0.0),
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
    assert message.orientation.w == 0.7
    assert message.angular_velocity.y == 1.1
    assert message.linear_acceleration.z == 2.2
    assert message.orientation_covariance[0] >= 0.0


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
        240.0,
        0.0,
        1.0,
        0.0,
        0.0,
        241.0,
        0.5,
        0.0,
        0.0,
        0.0,
        1.0,
        0.0,
    ]


def test_lidar_scan_serializes_to_deterministic_little_endian_pointcloud():
    scan = LidarScan(
        timebase=1.25,
        points=np.array([[1.0, 2.0, 3.0], [-1.0, 0.5, 4.0]], dtype=np.float32),
        reflectivity=np.array([100, 101], dtype=np.uint8),
        tags=np.array([0, 2], dtype=np.uint8),
        lines=np.array([1, 5], dtype=np.uint8),
        offset_time=np.array([0, 99_000_000], dtype=np.uint32),
        configured_points=3072,
    )

    message = pointcloud_message(scan, FRAMES)

    assert message.header.stamp.sec == 1
    assert message.header.stamp.nanosec == 250_000_000
    assert message.header.frame_id == "livox_frame"
    assert message.height == 1
    assert message.width == 2
    assert message.point_step == 20
    assert message.row_step == 40
    assert message.is_bigendian is False
    assert message.is_dense is True
    assert [(field.name, field.offset, field.datatype) for field in message.fields] == [
        ("x", 0, PointField.FLOAT32),
        ("y", 4, PointField.FLOAT32),
        ("z", 8, PointField.FLOAT32),
        ("intensity", 12, PointField.UINT8),
        ("tag", 13, PointField.UINT8),
        ("line", 14, PointField.UINT8),
        ("offset_time", 16, PointField.UINT32),
    ]
    assert struct.unpack_from("<fffBBBxI", bytes(message.data), 0) == pytest.approx(
        (1.0, 2.0, 3.0, 100, 0, 1, 0)
    )
    assert struct.unpack_from("<fffBBBxI", bytes(message.data), 20) == pytest.approx(
        (-1.0, 0.5, 4.0, 101, 2, 5, 99_000_000)
    )


def test_dynamic_sensor_frames_and_static_map_contract():
    transforms = sensor_transforms(SNAPSHOT, FRAMES)
    by_child = {transform.child_frame_id: transform for transform in transforms}

    assert set(by_child) == {"imu_link", "camera_link", "livox_frame"}
    assert by_child["imu_link"].header.frame_id == "base_link"
    assert by_child["imu_link"].transform.translation.x == 0.01
    assert by_child["camera_link"].transform.translation.x == 0.18
    assert by_child["livox_frame"].transform.translation.x == 0.04
    rotation = by_child["camera_link"].transform.rotation
    assert (rotation.x, rotation.y, rotation.z, rotation.w) == pytest.approx(
        (0.5, -0.5, -0.5, 0.5)
    )

    fixed = static_map_transform(0.0, FRAMES)
    assert fixed.header.frame_id == "sim_map"
    assert fixed.child_frame_id == "odom"
    assert fixed.transform.rotation.w == 1.0

    twist = twist_message(SNAPSHOT.applied_command)
    assert twist.linear.x == 0.1
    assert twist.linear.y == 0.0
    assert twist.angular.z == -0.2
