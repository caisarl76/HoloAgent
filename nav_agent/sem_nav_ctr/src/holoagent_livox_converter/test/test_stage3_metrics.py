from __future__ import annotations

import math

from holoagent_livox_converter.stage3_metrics import (
    PoseSample,
    Stage3Limits,
    evaluate_stage3,
)


def _truth() -> tuple[PoseSample, ...]:
    samples = []
    for index in range(301):
        fraction = index / 300
        samples.append(
            PoseSample(
                index * 100_000_000,
                fraction,
                0.2 * math.sin(fraction * math.pi),
                0.0,
                fraction * math.radians(45),
            )
        )
    return tuple(samples)


def _sensor_pass() -> dict[str, object]:
    return {
        "status": "PASS",
        "label": "PASS_SYNTHETIC_LIVOX",
        "gates": {"imu_rate": True, "lidar_density": True},
        "metrics": {"imu_hz": 200.0, "custom_lidar_hz": 10.0},
    }


def test_first_pose_alignment_removes_only_rigid_frame_offset():
    truth = _truth()
    rotation = math.radians(-30)
    cosine, sine = math.cos(rotation), math.sin(rotation)
    estimates = tuple(
        PoseSample(
            sample.stamp_ns,
            4.0 + cosine * sample.x - sine * sample.y,
            -3.0 + sine * sample.x + cosine * sample.y,
            1.2 + sample.z,
            sample.yaw + rotation,
        )
        for sample in truth
    )
    result = evaluate_stage3(
        truth,
        estimates,
        limits=Stage3Limits(),
        graph_approved=True,
        use_sim_time={"bridge": True, "converter": True, "fast_livo": True, "eval": True},
        calibration_match=True,
        perfect_odom_isolated=True,
        sensor_contract=_sensor_pass(),
    )
    assert result["status"] == "PASS"
    assert result["qualified_pass"] == "PASS_LIO_ONLY"
    assert result["metrics"]["translation_rmse_m"] < 1e-9
    assert result["metrics"]["yaw_rmse_deg"] < 1e-9


def test_drifting_estimator_records_fail_estimator_without_overclaim():
    truth = _truth()
    estimates = tuple(
        PoseSample(sample.stamp_ns, sample.x * 3.0, sample.y, sample.z, sample.yaw)
        for sample in truth
    )
    result = evaluate_stage3(
        truth,
        estimates,
        limits=Stage3Limits(),
        graph_approved=True,
        use_sim_time={"all": True},
        calibration_match=True,
        perfect_odom_isolated=True,
        sensor_contract=_sensor_pass(),
    )
    assert result["status"] == "FAIL"
    assert result["label"] == "FAIL_ESTIMATOR"
    assert result["qualified_pass"] is None
    assert result["first_failing_gate"] in {"translation_rmse", "translation_max"}


def test_perfect_odometry_isolation_is_a_hard_gate():
    truth = _truth()
    result = evaluate_stage3(
        truth,
        truth,
        limits=Stage3Limits(),
        graph_approved=True,
        use_sim_time={"all": True},
        calibration_match=True,
        perfect_odom_isolated=False,
        sensor_contract=_sensor_pass(),
    )
    assert result["first_failing_gate"] == "perfect_odom_isolated"


def test_stage2_sensor_contract_is_a_hard_gate_during_stage3():
    truth = _truth()
    sensor_failure = {
        "status": "FAIL",
        "label": None,
        "first_failing_gate": "lidar_density",
        "gates": {"lidar_density": False},
        "metrics": {"min_points_per_scan": 0},
    }

    result = evaluate_stage3(
        truth,
        truth,
        limits=Stage3Limits(),
        graph_approved=True,
        use_sim_time={"all": True},
        calibration_match=True,
        perfect_odom_isolated=True,
        sensor_contract=sensor_failure,
    )

    assert result["status"] == "FAIL"
    assert result["first_failing_gate"] == "sensor_contract"
    assert result["gates"]["sensor_contract"] is False
    assert result["metrics"]["sensor_contract"] == sensor_failure
