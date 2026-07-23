from __future__ import annotations

from collections.abc import Mapping
import math

import numpy as np

from .stage2_metrics import Stage2Observations


class Stage2Collector:
    """Collect a fixed simulated-time window for the Stage 2 gates."""

    def __init__(self, *, warmup_sec: float, rate_window_sec: float) -> None:
        if not math.isfinite(warmup_sec) or warmup_sec < 0.0:
            raise ValueError("warmup_sec must be finite and non-negative")
        if not math.isfinite(rate_window_sec) or rate_window_sec <= 0.0:
            raise ValueError("rate_window_sec must be finite and positive")

        self._warmup_ns = round(warmup_sec * 1_000_000_000)
        self._window_duration_ns = round(rate_window_sec * 1_000_000_000)
        self._epoch_ns: int | None = None
        self._window_start_ns: int | None = None
        self._window_end_ns: int | None = None
        self._last_clock_ns: int | None = None
        self._last_wall_time: float | None = None
        self._window_wall_start: float | None = None
        self._window_wall_end: float | None = None
        self._done = False

        self._clock_stamps_ns: list[int] = []
        self._imu_stamps_ns: list[int] = []
        self._camera_stamps_ns: list[int] = []
        self._raw_lidar_stamps_ns: list[int] = []
        self._custom_lidar_stamps_ns: list[int] = []
        self._raw_point_counts: list[int] = []
        self._custom_point_counts: list[int] = []
        self._custom_offsets: list[np.ndarray] = []
        self._message_errors: list[str] = []

    @property
    def done(self) -> bool:
        return self._done

    @property
    def message_errors(self) -> list[str]:
        return list(self._message_errors)

    def record_clock(self, stamp_ns: int, *, wall_time: float) -> None:
        stamp_ns = int(stamp_ns)
        wall_time = float(wall_time)
        if self._last_clock_ns is not None and stamp_ns <= self._last_clock_ns:
            self.add_error("clock is not strictly monotonic")
            return

        if self._epoch_ns is None:
            self._epoch_ns = stamp_ns
            self._window_start_ns = stamp_ns + self._warmup_ns
            self._window_end_ns = self._window_start_ns + self._window_duration_ns

        self._last_clock_ns = stamp_ns
        if self._in_window(stamp_ns):
            if self._window_wall_start is None:
                self._window_wall_start = wall_time
            self._clock_stamps_ns.append(stamp_ns)
            self._last_wall_time = wall_time
        elif self._window_end_ns is not None and stamp_ns >= self._window_end_ns:
            self._done = True
            self._window_wall_end = self._last_wall_time

    def record_imu(self, stamp_ns: int) -> None:
        if self._in_window(stamp_ns):
            self._imu_stamps_ns.append(int(stamp_ns))

    def record_camera(self, stamp_ns: int) -> None:
        if self._in_window(stamp_ns):
            self._camera_stamps_ns.append(int(stamp_ns))

    def record_raw_lidar(self, stamp_ns: int, point_count: int) -> None:
        if self._in_window(stamp_ns):
            self._raw_lidar_stamps_ns.append(int(stamp_ns))
            self._raw_point_counts.append(int(point_count))

    def record_custom_lidar(
        self, stamp_ns: int, point_count: int, offsets: np.ndarray
    ) -> None:
        if self._in_window(stamp_ns):
            self._custom_lidar_stamps_ns.append(int(stamp_ns))
            self._custom_point_counts.append(int(point_count))
            self._custom_offsets.append(np.asarray(offsets, dtype=np.uint32).copy())

    def add_error(self, error: str) -> None:
        self._message_errors.append(str(error))

    def observations(
        self,
        *,
        use_sim_time: Mapping[str, bool],
        graph_approved: bool,
        calibration_match: bool,
    ) -> Stage2Observations:
        wall_end = self._window_wall_end
        if wall_end is None:
            wall_end = self._last_wall_time
        wall_duration = (
            wall_end - self._window_wall_start
            if wall_end is not None and self._window_wall_start is not None
            else 0.0
        )
        return Stage2Observations(
            clock_stamps_ns=tuple(self._clock_stamps_ns),
            imu_stamps_ns=tuple(self._imu_stamps_ns),
            camera_stamps_ns=tuple(self._camera_stamps_ns),
            raw_lidar_stamps_ns=tuple(self._raw_lidar_stamps_ns),
            custom_lidar_stamps_ns=tuple(self._custom_lidar_stamps_ns),
            raw_point_counts=tuple(self._raw_point_counts),
            custom_point_counts=tuple(self._custom_point_counts),
            custom_offsets=tuple(self._custom_offsets),
            wall_duration_sec=wall_duration,
            use_sim_time=dict(use_sim_time),
            graph_approved=bool(graph_approved),
            calibration_match=bool(calibration_match),
            message_errors=tuple(self._message_errors),
        )

    def _in_window(self, stamp_ns: int) -> bool:
        return (
            self._window_start_ns is not None
            and self._window_end_ns is not None
            and self._window_start_ns <= int(stamp_ns) < self._window_end_ns
        )
