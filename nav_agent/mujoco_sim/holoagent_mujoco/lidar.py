from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Callable

import numpy as np

from holoagent_mujoco.config import LidarConfig


class LidarError(RuntimeError):
    """Raised when a synthetic scan violates its acquisition contract."""


@dataclass(frozen=True)
class LidarPattern:
    directions: np.ndarray
    lines: np.ndarray


@dataclass(frozen=True)
class LidarPose:
    sim_time: float
    position_world: tuple[float, float, float]
    quaternion_world_wxyz: tuple[float, float, float, float]


@dataclass(frozen=True)
class LidarScan:
    timebase: float
    points: np.ndarray
    reflectivity: np.ndarray
    tags: np.ndarray
    lines: np.ndarray
    offset_time: np.ndarray
    configured_points: int


def build_pattern(
    *,
    scan_lines: int,
    azimuth_samples: int,
    vertical_fov_deg: tuple[float, float],
) -> LidarPattern:
    if scan_lines <= 0 or scan_lines > 255 or azimuth_samples <= 0:
        raise LidarError("scan dimensions must be positive and lines fit uint8")
    lower, upper = (float(value) for value in vertical_fov_deg)
    if not (-90.0 < lower < upper < 90.0):
        raise LidarError("vertical field of view is invalid")
    elevations = np.deg2rad(np.linspace(lower, upper, scan_lines))
    azimuths = np.linspace(-math.pi, math.pi, azimuth_samples, endpoint=False)
    azimuth_grid, elevation_grid = np.meshgrid(azimuths, elevations, indexing="ij")
    cosine = np.cos(elevation_grid)
    directions = np.column_stack(
        (
            (cosine * np.cos(azimuth_grid)).reshape(-1),
            (cosine * np.sin(azimuth_grid)).reshape(-1),
            np.sin(elevation_grid).reshape(-1),
        )
    ).astype(np.float64)
    directions /= np.linalg.norm(directions, axis=1, keepdims=True)
    lines = np.tile(np.arange(scan_lines, dtype=np.uint8), azimuth_samples)
    directions.setflags(write=False)
    lines.setflags(write=False)
    return LidarPattern(directions=directions, lines=lines)


def acquisition_offsets(mode: str, count: int, scan_period_sec: float) -> np.ndarray:
    if count <= 0 or not math.isfinite(scan_period_sec) or scan_period_sec <= 0.0:
        raise LidarError("point count and scan period must be positive")
    if mode == "snapshot":
        return np.zeros(count, dtype=np.uint32)
    if mode != "rolling":
        raise LidarError(f"unsupported acquisition mode: {mode}")
    period_ns = round(scan_period_sec * 1_000_000_000)
    if period_ns <= 0 or period_ns > np.iinfo(np.uint32).max:
        raise LidarError("scan period does not fit uint32 nanoseconds")
    return ((np.arange(count, dtype=np.uint64) * period_ns) // count).astype(np.uint32)


class PoseHistory:
    def __init__(self, scan_period_sec: float) -> None:
        if not math.isfinite(scan_period_sec) or scan_period_sec <= 0.0:
            raise LidarError("pose history period must be positive")
        self.scan_period_sec = float(scan_period_sec)
        self._poses: list[LidarPose] = []

    def append(self, pose: LidarPose) -> None:
        _validate_pose(pose)
        if self._poses and pose.sim_time <= self._poses[-1].sim_time:
            raise LidarError("pose history must be strictly monotonic")
        self._poses.append(pose)
        cutoff = pose.sim_time - self.scan_period_sec - 1e-9
        while len(self._poses) > 2 and self._poses[1].sim_time < cutoff:
            self._poses.pop(0)

    def sample(self, times: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        requested = np.asarray(times, dtype=np.float64)
        if (
            requested.ndim != 1
            or requested.size == 0
            or not np.isfinite(requested).all()
        ):
            raise LidarError("sample times must be a finite vector")
        if (
            len(self._poses) < 2
            or requested[0] < self._poses[0].sim_time - 1e-9
            or requested[-1] > self._poses[-1].sim_time + 1e-9
        ):
            raise LidarError("pose history does not span the rolling scan period")
        pose_times = np.asarray([pose.sim_time for pose in self._poses])
        origins = np.empty((len(requested), 3), dtype=np.float64)
        rotations = np.empty((len(requested), 3, 3), dtype=np.float64)
        for index, sample_time in enumerate(requested):
            upper = int(np.searchsorted(pose_times, sample_time, side="right"))
            upper = min(max(upper, 1), len(self._poses) - 1)
            before = self._poses[upper - 1]
            after = self._poses[upper]
            span = after.sim_time - before.sim_time
            fraction = min(max((sample_time - before.sim_time) / span, 0.0), 1.0)
            origins[index] = (
                np.asarray(before.position_world) * (1.0 - fraction)
                + np.asarray(after.position_world) * fraction
            )
            quaternion = _slerp(
                np.asarray(before.quaternion_world_wxyz),
                np.asarray(after.quaternion_world_wxyz),
                fraction,
            )
            rotations[index] = _quaternion_matrix(quaternion)
        return origins, rotations


class SyntheticLidar:
    def __init__(self, config: LidarConfig) -> None:
        self.config = config
        self.pattern = build_pattern(
            scan_lines=config.scan_lines,
            azimuth_samples=config.azimuth_samples,
            vertical_fov_deg=config.vertical_fov_deg,
        )
        self._scan_index = 0

    def acquire(
        self,
        current_pose: LidarPose,
        pose_history: PoseHistory,
        raycast: Callable[[np.ndarray, np.ndarray], np.ndarray],
    ) -> LidarScan:
        _validate_pose(current_pose)
        count = len(self.pattern.directions)
        offsets = acquisition_offsets(
            self.config.acquisition_mode, count, self.config.scan_period_sec
        )
        if self.config.acquisition_mode == "snapshot":
            timebase = current_pose.sim_time
            origins = np.repeat(
                np.asarray(current_pose.position_world, dtype=np.float64)[None, :],
                count,
                axis=0,
            )
            rotation = _quaternion_matrix(current_pose.quaternion_world_wxyz)
            rotations = np.repeat(rotation[None, :, :], count, axis=0)
        else:
            timebase = current_pose.sim_time - self.config.scan_period_sec
            sample_times = timebase + offsets.astype(np.float64) / 1_000_000_000
            origins, rotations = pose_history.sample(sample_times)

        world_directions = np.einsum("nij,nj->ni", rotations, self.pattern.directions)
        distances = np.asarray(raycast(origins, world_directions), dtype=np.float64)
        if distances.shape != (count,):
            raise LidarError("ray caster returned the wrong distance vector")

        generator = np.random.default_rng(self.config.random_seed + self._scan_index)
        self._scan_index += 1
        if self.config.noise_std_m > 0.0:
            distances = distances + generator.normal(
                0.0, self.config.noise_std_m, count
            )
        retained = generator.random(count) >= self.config.dropout_probability
        retained &= np.isfinite(distances)
        retained &= distances >= self.config.min_range_m
        retained &= distances <= self.config.max_range_m
        valid_count = int(np.count_nonzero(retained))
        if valid_count < self.config.min_finite_points:
            raise LidarError(
                "scan contains too few finite points: "
                f"{valid_count} < {self.config.min_finite_points}"
            )

        points = (self.pattern.directions[retained] * distances[retained, None]).astype(
            np.float32
        )
        reflectivity = np.full(valid_count, self.config.reflectivity, dtype=np.uint8)
        tags = np.full(valid_count, self.config.tag, dtype=np.uint8)
        lines = self.pattern.lines[retained].copy()
        valid_offsets = offsets[retained].copy()
        for array in (points, reflectivity, tags, lines, valid_offsets):
            array.setflags(write=False)
        return LidarScan(
            timebase=timebase,
            points=points,
            reflectivity=reflectivity,
            tags=tags,
            lines=lines,
            offset_time=valid_offsets,
            configured_points=count,
        )


def _validate_pose(pose: LidarPose) -> None:
    values = (
        pose.sim_time,
        *pose.position_world,
        *pose.quaternion_world_wxyz,
    )
    if pose.sim_time < 0.0 or not all(math.isfinite(float(value)) for value in values):
        raise LidarError("lidar pose must be finite and non-negative")
    quaternion = np.asarray(pose.quaternion_world_wxyz, dtype=np.float64)
    if quaternion.shape != (4,) or not math.isclose(
        float(np.linalg.norm(quaternion)), 1.0, abs_tol=1e-6
    ):
        raise LidarError("lidar pose quaternion must have unit length")


def _slerp(first: np.ndarray, second: np.ndarray, fraction: float) -> np.ndarray:
    first = first / np.linalg.norm(first)
    second = second / np.linalg.norm(second)
    dot = float(np.dot(first, second))
    if dot < 0.0:
        second = -second
        dot = -dot
    if dot > 0.9995:
        result = first + fraction * (second - first)
        return result / np.linalg.norm(result)
    angle = math.acos(min(max(dot, -1.0), 1.0))
    sine = math.sin(angle)
    return (
        math.sin((1.0 - fraction) * angle) / sine * first
        + math.sin(fraction * angle) / sine * second
    )


def _quaternion_matrix(quaternion: tuple[float, ...] | np.ndarray) -> np.ndarray:
    q = np.asarray(quaternion, dtype=np.float64)
    q = q / np.linalg.norm(q)
    w, x, y, z = q
    return np.array(
        [
            [1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)],
            [2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)],
            [2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)],
        ],
        dtype=np.float64,
    )
