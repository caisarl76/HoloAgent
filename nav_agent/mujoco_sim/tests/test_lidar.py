from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from holoagent_mujoco.config import load_mapping
from holoagent_mujoco.lidar import (
    LidarError,
    LidarPose,
    PoseHistory,
    SyntheticLidar,
    acquisition_offsets,
    build_pattern,
)
from test_config import valid_mapping


def lidar_config():
    return load_mapping(valid_mapping()).lidar


def test_ray_pattern_has_six_normalized_lines_and_3072_points():
    pattern = build_pattern(
        scan_lines=6,
        azimuth_samples=512,
        vertical_fov_deg=(-15.0, 15.0),
    )

    assert pattern.directions.shape == (3072, 3)
    assert pattern.lines.shape == (3072,)
    assert pattern.lines.dtype == np.uint8
    assert pattern.lines.min() == 0
    assert pattern.lines.max() == 5
    assert np.linalg.norm(pattern.directions, axis=1) == pytest.approx(1.0)


def test_offsets_match_actual_acquisition_mode():
    snapshot = acquisition_offsets("snapshot", 3072, 0.1)
    rolling = acquisition_offsets("rolling", 3072, 0.1)

    assert snapshot.dtype == np.uint32
    assert np.array_equal(snapshot, np.zeros(3072, dtype=np.uint32))
    assert rolling.dtype == np.uint32
    assert rolling[0] == 0
    assert np.all(np.diff(rolling.astype(np.int64)) >= 0)
    assert rolling[-1] < 100_000_000
    with pytest.raises(LidarError, match="acquisition mode"):
        acquisition_offsets("invented", 10, 0.1)


def test_snapshot_scan_uses_one_measured_pose_and_zero_offsets():
    config = lidar_config()
    sensor = SyntheticLidar(config)
    pose = LidarPose(2.0, (1.0, 2.0, 1.2), (1.0, 0.0, 0.0, 0.0))
    captured = {}

    def raycast(origins, directions):
        captured["origins"] = origins.copy()
        captured["directions"] = directions.copy()
        return np.full(len(origins), 4.0)

    scan = sensor.acquire(pose, PoseHistory(config.scan_period_sec), raycast)

    assert scan.timebase == pytest.approx(2.0)
    assert scan.points.shape == (3072, 3)
    assert scan.points.dtype == np.float32
    assert np.array_equal(scan.offset_time, np.zeros(3072, dtype=np.uint32))
    assert np.all(captured["origins"] == np.array([1.0, 2.0, 1.2]))
    assert np.isfinite(scan.points).all()
    assert scan.lines.min() == 0 and scan.lines.max() == 5


def test_rolling_scan_samples_measured_pose_history_over_scan_period():
    config = replace(lidar_config(), acquisition_mode="rolling")
    sensor = SyntheticLidar(config)
    history = PoseHistory(config.scan_period_sec)
    history.append(LidarPose(0.9, (0.0, 0.0, 1.0), (1.0, 0.0, 0.0, 0.0)))
    current = LidarPose(1.0, (0.1, 0.0, 1.0), (1.0, 0.0, 0.0, 0.0))
    history.append(current)
    captured = {}

    def raycast(origins, directions):
        captured["origins"] = origins.copy()
        return np.full(len(origins), 3.0)

    scan = sensor.acquire(current, history, raycast)

    assert scan.timebase == pytest.approx(0.9)
    assert scan.offset_time[0] == 0
    assert scan.offset_time[-1] < 100_000_000
    assert captured["origins"][0, 0] == pytest.approx(0.0)
    assert captured["origins"][-1, 0] < 0.1
    assert captured["origins"][-1, 0] > 0.099


def test_rolling_scan_rejects_insufficient_pose_history():
    config = replace(lidar_config(), acquisition_mode="rolling")
    sensor = SyntheticLidar(config)
    current = LidarPose(1.0, (0.1, 0.0, 1.0), (1.0, 0.0, 0.0, 0.0))
    history = PoseHistory(config.scan_period_sec)
    history.append(current)

    with pytest.raises(LidarError, match="pose history"):
        sensor.acquire(
            current, history, lambda origins, directions: np.ones(len(origins))
        )


def test_noise_and_dropout_are_deterministic_and_density_is_fail_closed():
    pose = LidarPose(1.0, (0.0, 0.0, 1.0), (1.0, 0.0, 0.0, 0.0))
    base = lidar_config()
    noisy = replace(base, noise_std_m=0.01, dropout_probability=0.05)

    first = SyntheticLidar(noisy).acquire(
        pose,
        PoseHistory(noisy.scan_period_sec),
        lambda origins, directions: np.full(len(origins), 4.0),
    )
    second = SyntheticLidar(noisy).acquire(
        pose,
        PoseHistory(noisy.scan_period_sec),
        lambda origins, directions: np.full(len(origins), 4.0),
    )
    assert np.array_equal(first.points, second.points)
    assert len(first.points) >= noisy.min_finite_points

    with pytest.raises(LidarError, match="finite points"):
        SyntheticLidar(base).acquire(
            pose,
            PoseHistory(base.scan_period_sec),
            lambda origins, directions: np.where(
                np.arange(len(origins)) < 2499, 4.0, -1.0
            ),
        )


@pytest.mark.parametrize("distance", [float("nan"), float("inf"), -1.0, 0.05, 21.0])
def test_invalid_or_out_of_range_returns_are_dropped(distance):
    config = lidar_config()
    distances = np.full(config.configured_points, 4.0)
    distances[0] = distance
    scan = SyntheticLidar(config).acquire(
        LidarPose(1.0, (0.0, 0.0, 1.0), (1.0, 0.0, 0.0, 0.0)),
        PoseHistory(config.scan_period_sec),
        lambda origins, directions: distances,
    )

    assert len(scan.points) == config.configured_points - 1
    assert np.isfinite(scan.points).all()
