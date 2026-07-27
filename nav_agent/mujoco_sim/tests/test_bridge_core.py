from __future__ import annotations

import pytest
from rclpy.qos import ReliabilityPolicy

from holoagent_mujoco.bridge_node import (
    SimRateScheduler,
    fast_livo_sensor_qos,
    run_fail_closed_loop,
)


def test_integer_accumulator_scheduler_hits_exact_stage1_rates():
    scheduler = SimRateScheduler(
        physics_hz=200,
        stream_hz={"imu": 200, "odom": 50, "camera": 15},
    )
    counts = {"clock": 0, "imu": 0, "odom": 0, "camera": 0}
    due_times = {"imu": [], "odom": [], "camera": []}

    for step in range(1, 201):
        due = scheduler.tick()
        counts["clock"] += 1
        for stream in due:
            counts[stream] += 1
            due_times[stream].append(step / 200.0)

    assert counts == {"clock": 200, "imu": 200, "odom": 50, "camera": 15}
    assert due_times["imu"][0] == pytest.approx(0.005)
    assert due_times["odom"][0] == pytest.approx(0.020)
    assert due_times["camera"][-1] == pytest.approx(1.0)


def test_scheduler_rejects_impossible_rates():
    with pytest.raises(ValueError, match="cannot exceed"):
        SimRateScheduler(physics_hz=200, stream_hz={"camera": 201})
    with pytest.raises(ValueError, match="positive"):
        SimRateScheduler(physics_hz=200, stream_hz={"camera": 0})


def test_stage2_scheduler_emits_exact_lidar_rate_without_changing_stage1_rates():
    scheduler = SimRateScheduler(
        physics_hz=200,
        stream_hz={"imu": 200, "odom": 50, "camera": 15, "lidar": 10},
    )
    counts = {"imu": 0, "odom": 0, "camera": 0, "lidar": 0}

    for _ in range(200):
        for stream in scheduler.tick():
            counts[stream] += 1

    assert counts == {"imu": 200, "odom": 50, "camera": 15, "lidar": 10}


def test_fast_livo_sensor_qos_offers_reliable_delivery():
    assert fast_livo_sensor_qos().reliability == ReliabilityPolicy.RELIABLE


def test_loop_forces_final_zero_after_iteration_exception():
    events = []

    def iteration():
        events.append("step")
        raise RuntimeError("policy failed")

    with pytest.raises(RuntimeError, match="policy failed"):
        run_fail_closed_loop(iteration, lambda: events.append("zero"), lambda: True)

    assert events == ["step", "zero"]


def test_loop_forces_final_zero_after_normal_completion():
    events = []
    remaining = iter([True, True, False])

    run_fail_closed_loop(
        lambda: events.append("step"),
        lambda: events.append("zero"),
        lambda: next(remaining),
    )

    assert events == ["step", "step", "zero"]
