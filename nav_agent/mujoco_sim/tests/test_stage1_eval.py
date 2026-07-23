from __future__ import annotations

import json

import pytest

from holoagent_mujoco.command import CommandLimits, VelocityCommand
from holoagent_mujoco.stage1_eval import (
    AppliedCommandSample,
    OdomSample,
    build_result,
    clamp_gate,
    horizontal_displacement,
    max_speed_in_window,
    quaternion_samples_finite,
    realtime_factor,
    simulated_rate,
    stationary_drift,
    strictly_monotonic,
    timeout_latency,
)


def test_clock_must_be_strictly_monotonic():
    assert strictly_monotonic([0.005, 0.010, 0.015])
    assert not strictly_monotonic([0.005, 0.010, 0.010])
    assert not strictly_monotonic([0.005, float("nan")])


def test_topic_rate_is_measured_in_simulated_time():
    timestamps = [2.0 + index / 200.0 for index in range(2000)]

    assert simulated_rate(timestamps, start=2.0, end=12.0) == pytest.approx(200.0)
    with pytest.raises(ValueError, match="end"):
        simulated_rate(timestamps, start=2.0, end=2.0)


def test_realtime_factor_excludes_warmup():
    samples = [(0.0, 10.0), (2.0, 14.0), (12.0, 34.0)]

    assert realtime_factor(samples, warmup_sec=2.0) == pytest.approx(0.5)


def test_stationary_drift_and_bounded_motion_displacement():
    stationary = [
        OdomSample(2.0, 1.0, 2.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(7.0, 1.03, 2.04, 0.01, (1.0, 0.0, 0.0, 0.0)),
    ]
    motion = [
        OdomSample(10.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(12.0, 0.2, 0.0, 0.1, (1.0, 0.0, 0.0, 0.0)),
    ]

    assert stationary_drift(stationary) == pytest.approx(0.05)
    assert horizontal_displacement(motion) == pytest.approx(0.2)


def test_command_clamps_require_bounds_and_observed_probe():
    limits = CommandLimits(0.22, 0.0, 0.30, 0.50)
    samples = [
        AppliedCommandSample(1.0, VelocityCommand(0.22, 0.0, 0.30)),
        AppliedCommandSample(1.1, VelocityCommand(-0.22, 0.0, -0.30)),
    ]

    assert clamp_gate(samples, limits, require_positive_probe=True)
    assert not clamp_gate(
        [AppliedCommandSample(1.0, VelocityCommand(0.1, 0.0, 0.1))],
        limits,
        require_positive_probe=True,
    )
    assert not clamp_gate(
        [AppliedCommandSample(1.0, VelocityCommand(0.1, 0.01, 0.0))],
        limits,
        require_positive_probe=False,
    )


def test_timeout_latency_and_post_timeout_speed_window():
    commands = [
        AppliedCommandSample(5.0, VelocityCommand(0.1, 0.0, 0.0)),
        AppliedCommandSample(5.4, VelocityCommand(0.1, 0.0, 0.0)),
        AppliedCommandSample(5.95, VelocityCommand.zero()),
    ]
    odometry = [
        OdomSample(5.95, 0.0, 0.0, 0.02, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(6.50, 0.0, 0.0, 0.025, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(7.00, 0.0, 0.0, 0.01, (1.0, 0.0, 0.0, 0.0)),
    ]

    assert timeout_latency(commands, silence_start=5.4) == pytest.approx(0.55)
    assert max_speed_in_window(odometry, start=5.95, duration=1.0) == pytest.approx(
        0.025
    )


def test_quaternion_finiteness_rejects_nan():
    good = [OdomSample(0.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0))]
    bad = [OdomSample(0.0, 0.0, 0.0, 0.0, (float("nan"), 0.0, 0.0, 0.0))]

    assert quaternion_samples_finite(good)
    assert not quaternion_samples_finite(bad)


def test_first_failing_gate_uses_declared_order():
    gates = {
        "graph": True,
        "clock": True,
        "rtf": False,
        "imu_rate": False,
    }

    result = build_result(gates, {"rtf": 0.1})

    assert result["status"] == "FAIL"
    assert result["first_failing_gate"] == "rtf"
    assert result["label"] is None


def test_qualified_pass_result_is_json_serializable():
    gates = {
        "graph": True,
        "clock": True,
        "rtf": True,
        "imu_rate": True,
        "odom_rate": True,
        "camera_rate": True,
        "stationary_drift": True,
        "command_clamp": True,
        "bounded_motion": True,
        "timeout_zero": True,
        "stopped_speed": True,
        "message_finite": True,
    }

    result = build_result(gates, {"rtf": 0.8})

    assert result["status"] == "PASS"
    assert result["label"] == "PASS_SIM_ODOM"
    assert result["first_failing_gate"] is None
    assert json.loads(json.dumps(result))["metrics"]["rtf"] == 0.8
