from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class CommandLimits:
    max_linear_x: float
    max_linear_y: float
    max_yaw_rate: float
    timeout_sim_sec: float

    def __post_init__(self) -> None:
        values = (
            self.max_linear_x,
            self.max_linear_y,
            self.max_yaw_rate,
            self.timeout_sim_sec,
        )
        if not all(math.isfinite(value) for value in values):
            raise ValueError("command limits must be finite")
        if self.max_linear_x <= 0.0:
            raise ValueError("max_linear_x must be positive")
        if self.max_linear_y < 0.0:
            raise ValueError("max_linear_y cannot be negative")
        if self.max_yaw_rate <= 0.0:
            raise ValueError("max_yaw_rate must be positive")
        if self.timeout_sim_sec <= 0.0:
            raise ValueError("timeout_sim_sec must be positive")


@dataclass(frozen=True)
class VelocityCommand:
    x: float
    y: float
    yaw: float

    @classmethod
    def zero(cls) -> VelocityCommand:
        return cls(0.0, 0.0, 0.0)

    @property
    def is_zero(self) -> bool:
        return self == self.zero()


class CommandSafety:
    """Fail-closed velocity state driven exclusively by simulated time."""

    def __init__(self, limits: CommandLimits) -> None:
        self._limits = limits
        self._command = VelocityCommand.zero()
        self._last_valid_time: float | None = None
        self._shutdown = False

    def accept(
        self, linear_x: float, linear_y: float, yaw_rate: float, *, sim_time: float
    ) -> VelocityCommand:
        if self._shutdown:
            return self._fail_closed()
        values = (linear_x, linear_y, yaw_rate, sim_time)
        if not all(_is_finite_number(value) for value in values):
            return self._fail_closed()

        time_value = float(sim_time)
        if self._last_valid_time is not None and time_value < self._last_valid_time:
            return self._fail_closed()

        self._command = VelocityCommand(
            x=_clamp(float(linear_x), self._limits.max_linear_x),
            y=_clamp(float(linear_y), self._limits.max_linear_y),
            yaw=_clamp(float(yaw_rate), self._limits.max_yaw_rate),
        )
        self._last_valid_time = time_value
        return self._command

    def current(self, *, sim_time: float) -> VelocityCommand:
        if self._shutdown or not _is_finite_number(sim_time):
            return self._fail_closed()
        if self._last_valid_time is None:
            return self._command

        age = float(sim_time) - self._last_valid_time
        if age < 0.0 or age >= self._limits.timeout_sim_sec:
            return self._fail_closed()
        return self._command

    def shutdown(self) -> VelocityCommand:
        self._shutdown = True
        return self._fail_closed()

    def _fail_closed(self) -> VelocityCommand:
        self._command = VelocityCommand.zero()
        self._last_valid_time = None
        return self._command


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def _clamp(value: float, limit: float) -> float:
    if limit == 0.0:
        return 0.0
    return max(-limit, min(limit, value))
