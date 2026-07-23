from __future__ import annotations

from dataclasses import replace

import numpy as np

from holoagent_livox_converter.stage2_metrics import (
    Stage2Limits,
    Stage2Observations,
    evaluate_stage2,
)


LIMITS = Stage2Limits(
    rate_window_sec=10.0,
    clock_min_hz=50.0,
    min_realtime_factor=0.25,
    imu_min_hz=180.0,
    imu_max_hz=220.0,
    camera_min_hz=12.0,
    camera_max_hz=18.0,
    lidar_min_hz=8.0,
    lidar_max_hz=12.0,
    min_finite_points=2500,
    acquisition_mode="snapshot",
    scan_period_ns=100_000_000,
)


def passing_observations() -> Stage2Observations:
    base = 2_000_000_000
    clock = tuple(base + index * 5_000_000 for index in range(2000))
    imu = tuple(base + index * 5_000_000 for index in range(2000))
    camera = tuple(base + index * 65_000_000 for index in range(150))
    lidar = tuple(base + index * 100_000_000 for index in range(100))
    return Stage2Observations(
        clock_stamps_ns=clock,
        imu_stamps_ns=imu,
        camera_stamps_ns=camera,
        raw_lidar_stamps_ns=lidar,
        custom_lidar_stamps_ns=lidar,
        raw_point_counts=(3072,) * 100,
        custom_point_counts=(3072,) * 100,
        custom_offsets=tuple(np.zeros(3072, dtype=np.uint32) for _ in range(100)),
        wall_duration_sec=9.8,
        use_sim_time={
            "/holoagent_mujoco_bridge": True,
            "/holoagent_livox_converter": True,
            "/holoagent_stage2_eval": True,
        },
        graph_approved=True,
        calibration_match=True,
        message_errors=(),
    )


def test_passing_observations_produce_qualified_stage2_result():
    result = evaluate_stage2(passing_observations(), LIMITS)

    assert result["status"] == "PASS"
    assert result["qualified_pass"] == "PASS_SYNTHETIC_LIVOX"
    assert result["first_failing_gate"] is None
    assert all(result["gates"].values())
    assert result["motion_enabled"] is False
    assert result["simulated_motion"] is False
    assert result["physical_motion"] is False
    assert result["metrics"]["clock_hz"] == 200.0
    assert result["metrics"]["imu_hz"] == 200.0
    assert result["metrics"]["camera_hz"] == 15.0
    assert result["metrics"]["raw_lidar_hz"] == 10.0
    assert result["metrics"]["custom_lidar_hz"] == 10.0
    assert result["metrics"]["min_points_per_scan"] == 3072
    assert result["metrics"]["max_lidar_timestamp_skew_ns"] == 0


def test_under_density_scan_is_the_first_failing_gate():
    observations = replace(
        passing_observations(),
        custom_point_counts=(2499,) + (3072,) * 99,
    )

    result = evaluate_stage2(observations, LIMITS)

    assert result["status"] == "FAIL"
    assert result["qualified_pass"] is None
    assert result["first_failing_gate"] == "lidar_density"
    assert result["gates"]["lidar_density"] is False


def test_fabricated_snapshot_offset_fails_offset_contract():
    bad = np.zeros(3072, dtype=np.uint32)
    bad[-1] = 1
    observations = replace(
        passing_observations(),
        custom_offsets=(bad,) + passing_observations().custom_offsets[1:],
    )

    result = evaluate_stage2(observations, LIMITS)

    assert result["first_failing_gate"] == "offset_contract"
    assert result["gates"]["offset_contract"] is False


def test_sensor_timestamp_absent_from_clock_fails_shared_clock_gate():
    observations = passing_observations()
    bad_stamps = (observations.imu_stamps_ns[0] + 1,) + observations.imu_stamps_ns[1:]

    result = evaluate_stage2(
        replace(observations, imu_stamps_ns=bad_stamps), LIMITS
    )

    assert result["first_failing_gate"] == "shared_clock"
    assert result["gates"]["shared_clock"] is False


def test_graph_use_sim_time_calibration_and_message_errors_fail_closed():
    base = passing_observations()
    cases = (
        (replace(base, graph_approved=False), "graph"),
        (
            replace(
                base,
                use_sim_time={**base.use_sim_time, "/holoagent_livox_converter": False},
            ),
            "use_sim_time",
        ),
        (replace(base, calibration_match=False), "calibration"),
        (replace(base, message_errors=("nonfinite custom point",)), "message_finite"),
    )

    for observations, expected_gate in cases:
        result = evaluate_stage2(observations, LIMITS)
        assert result["first_failing_gate"] == expected_gate
        assert result["gates"][expected_gate] is False


def test_rolling_offsets_are_monotonic_and_bounded():
    offsets = tuple(
        np.linspace(0, 99_000_000, 3072, dtype=np.uint32) for _ in range(100)
    )
    result = evaluate_stage2(
        replace(passing_observations(), custom_offsets=offsets),
        replace(LIMITS, acquisition_mode="rolling"),
    )
    assert result["gates"]["offset_contract"] is True

    bad = offsets[0].copy()
    bad[100] = bad[99] - 1
    result = evaluate_stage2(
        replace(
            passing_observations(),
            custom_offsets=(bad,) + offsets[1:],
        ),
        replace(LIMITS, acquisition_mode="rolling"),
    )
    assert result["gates"]["offset_contract"] is False
