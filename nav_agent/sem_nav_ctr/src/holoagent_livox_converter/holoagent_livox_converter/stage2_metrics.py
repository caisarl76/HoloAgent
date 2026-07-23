from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Mapping

import numpy as np


@dataclass(frozen=True)
class Stage2Limits:
    rate_window_sec: float
    clock_min_hz: float
    min_realtime_factor: float
    imu_min_hz: float
    imu_max_hz: float
    camera_min_hz: float
    camera_max_hz: float
    lidar_min_hz: float
    lidar_max_hz: float
    min_finite_points: int
    acquisition_mode: str
    scan_period_ns: int


@dataclass(frozen=True)
class Stage2Observations:
    clock_stamps_ns: tuple[int, ...]
    imu_stamps_ns: tuple[int, ...]
    camera_stamps_ns: tuple[int, ...]
    raw_lidar_stamps_ns: tuple[int, ...]
    custom_lidar_stamps_ns: tuple[int, ...]
    raw_point_counts: tuple[int, ...]
    custom_point_counts: tuple[int, ...]
    custom_offsets: tuple[np.ndarray, ...]
    wall_duration_sec: float
    use_sim_time: Mapping[str, bool]
    graph_approved: bool
    calibration_match: bool
    message_errors: tuple[str, ...]


def evaluate_stage2(
    observations: Stage2Observations, limits: Stage2Limits
) -> dict[str, object]:
    duration = limits.rate_window_sec
    rates = {
        "clock_hz": len(observations.clock_stamps_ns) / duration,
        "imu_hz": len(observations.imu_stamps_ns) / duration,
        "camera_hz": len(observations.camera_stamps_ns) / duration,
        "raw_lidar_hz": len(observations.raw_lidar_stamps_ns) / duration,
        "custom_lidar_hz": len(observations.custom_lidar_stamps_ns) / duration,
    }
    realtime_factor = (
        duration / observations.wall_duration_sec
        if math.isfinite(observations.wall_duration_sec)
        and observations.wall_duration_sec > 0.0
        else 0.0
    )
    all_point_counts = observations.raw_point_counts + observations.custom_point_counts
    min_points = min(all_point_counts, default=0)
    mean_points = (
        sum(all_point_counts) / len(all_point_counts) if all_point_counts else 0.0
    )
    paired_count = min(
        len(observations.raw_lidar_stamps_ns),
        len(observations.custom_lidar_stamps_ns),
    )
    max_lidar_skew = max(
        (
            abs(
                observations.raw_lidar_stamps_ns[index]
                - observations.custom_lidar_stamps_ns[index]
            )
            for index in range(paired_count)
        ),
        default=0,
    )

    graph = bool(observations.graph_approved)
    use_sim_time = bool(observations.use_sim_time) and all(
        observations.use_sim_time.values()
    )
    calibration = bool(observations.calibration_match)
    clock = _strictly_monotonic(observations.clock_stamps_ns) and (
        rates["clock_hz"] >= limits.clock_min_hz
    )
    rtf = realtime_factor >= limits.min_realtime_factor
    imu_rate = limits.imu_min_hz <= rates["imu_hz"] <= limits.imu_max_hz
    camera_rate = (
        limits.camera_min_hz <= rates["camera_hz"] <= limits.camera_max_hz
    )
    raw_lidar_rate = (
        limits.lidar_min_hz <= rates["raw_lidar_hz"] <= limits.lidar_max_hz
    )
    custom_lidar_rate = (
        limits.lidar_min_hz <= rates["custom_lidar_hz"] <= limits.lidar_max_hz
    )
    lidar_density = bool(all_point_counts) and all(
        count >= limits.min_finite_points for count in all_point_counts
    )
    point_count = (
        len(observations.raw_point_counts) == len(observations.custom_point_counts)
        and observations.raw_point_counts == observations.custom_point_counts
        and len(observations.custom_point_counts) == len(observations.custom_offsets)
    )
    offset_contract = _offsets_valid(observations.custom_offsets, limits)
    shared_clock = _shared_clock_valid(observations)
    message_finite = not observations.message_errors

    gates = {
        "graph": graph,
        "use_sim_time": use_sim_time,
        "calibration": calibration,
        "clock": clock,
        "rtf": rtf,
        "imu_rate": imu_rate,
        "camera_rate": camera_rate,
        "raw_lidar_rate": raw_lidar_rate,
        "custom_lidar_rate": custom_lidar_rate,
        "lidar_density": lidar_density,
        "point_count": point_count,
        "offset_contract": offset_contract,
        "shared_clock": shared_clock,
        "message_finite": message_finite,
    }
    first_failure = next((name for name, passed in gates.items() if not passed), None)
    passed = first_failure is None
    return {
        "stage": 2,
        "status": "PASS" if passed else "FAIL",
        "label": "PASS_SYNTHETIC_LIVOX" if passed else None,
        "qualified_pass": "PASS_SYNTHETIC_LIVOX" if passed else None,
        "first_failing_gate": first_failure,
        "motion_enabled": False,
        "simulated_motion": False,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": gates,
        "metrics": {
            **rates,
            "realtime_factor": realtime_factor,
            "min_points_per_scan": min_points,
            "mean_points_per_scan": mean_points,
            "raw_scan_count": len(observations.raw_point_counts),
            "custom_scan_count": len(observations.custom_point_counts),
            "max_lidar_timestamp_skew_ns": max_lidar_skew,
            "message_contract_errors": list(observations.message_errors),
            "use_sim_time": dict(observations.use_sim_time),
        },
    }


def _strictly_monotonic(values: tuple[int, ...]) -> bool:
    return bool(values) and all(
        current > previous for previous, current in zip(values, values[1:])
    )


def _offsets_valid(
    collections: tuple[np.ndarray, ...], limits: Stage2Limits
) -> bool:
    if not collections:
        return False
    for offsets in collections:
        values = np.asarray(offsets)
        if values.ndim != 1 or values.dtype != np.uint32 or values.size == 0:
            return False
        if limits.acquisition_mode == "snapshot":
            if np.any(values != 0):
                return False
        elif limits.acquisition_mode == "rolling":
            if np.any(np.diff(values.astype(np.int64)) < 0):
                return False
            if int(values[-1]) > limits.scan_period_ns:
                return False
        else:
            return False
    return True


def _shared_clock_valid(observations: Stage2Observations) -> bool:
    clock = set(observations.clock_stamps_ns)
    streams = (
        observations.imu_stamps_ns,
        observations.camera_stamps_ns,
        observations.raw_lidar_stamps_ns,
        observations.custom_lidar_stamps_ns,
    )
    return bool(clock) and all(
        _strictly_monotonic(stream) and set(stream).issubset(clock)
        for stream in streams
    )
