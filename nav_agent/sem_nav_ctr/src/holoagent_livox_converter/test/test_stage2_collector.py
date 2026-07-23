from __future__ import annotations

import numpy as np
import pytest

from holoagent_livox_converter.stage2_collector import Stage2Collector


def test_collector_uses_simulated_warmup_and_exact_rate_window():
    collector = Stage2Collector(warmup_sec=2.0, rate_window_sec=10.0)

    for index in range(2402):
        stamp = index * 5_000_000
        collector.record_clock(stamp, wall_time=100.0 + index * 0.0049)
        collector.record_imu(stamp)
        if index % 20 == 0:
            collector.record_raw_lidar(stamp, 3072)
            collector.record_custom_lidar(
                stamp, 3072, np.zeros(3072, dtype=np.uint32)
            )
        if index % 13 == 0:
            collector.record_camera(stamp)

    assert collector.done is True
    observations = collector.observations(
        use_sim_time={"bridge": True, "converter": True, "eval": True},
        graph_approved=True,
        calibration_match=True,
    )
    assert len(observations.clock_stamps_ns) == 2000
    assert len(observations.imu_stamps_ns) == 2000
    assert len(observations.raw_lidar_stamps_ns) == 100
    assert len(observations.custom_lidar_stamps_ns) == 100
    assert 153 <= len(observations.camera_stamps_ns) <= 154
    assert observations.wall_duration_sec == pytest.approx(9.7951, abs=0.01)


def test_collector_rejects_nonmonotonic_clock_and_records_message_errors():
    collector = Stage2Collector(warmup_sec=0.1, rate_window_sec=1.0)
    collector.record_clock(100_000_000, wall_time=1.0)

    collector.record_clock(100_000_000, wall_time=1.1)
    collector.add_error("bad custom point")

    assert collector.message_errors == [
        "clock is not strictly monotonic",
        "bad custom point",
    ]


def test_sensor_samples_outside_window_are_not_counted():
    collector = Stage2Collector(warmup_sec=1.0, rate_window_sec=2.0)
    collector.record_clock(0, wall_time=0.0)
    collector.record_imu(500_000_000)
    collector.record_camera(3_500_000_000)

    observations = collector.observations(
        use_sim_time={}, graph_approved=False, calibration_match=False
    )
    assert observations.imu_stamps_ns == ()
    assert observations.camera_stamps_ns == ()
