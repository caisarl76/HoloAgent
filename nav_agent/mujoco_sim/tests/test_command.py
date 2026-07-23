from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from holoagent_mujoco.command import CommandLimits, CommandSafety, VelocityCommand


LIMITS = CommandLimits(
    max_linear_x=0.22,
    max_linear_y=0.0,
    max_yaw_rate=0.30,
    timeout_sim_sec=0.50,
)


def test_command_clamps_and_disables_lateral_motion():
    safety = CommandSafety(LIMITS)

    accepted = safety.accept(1.0, 1.0, -1.0, sim_time=2.0)

    assert accepted == VelocityCommand(0.22, 0.0, -0.30)
    assert safety.current(sim_time=2.1) == accepted


def test_negative_linear_command_is_clamped_symmetrically():
    safety = CommandSafety(LIMITS)

    assert safety.accept(-1.0, -1.0, 1.0, sim_time=0.0) == VelocityCommand(
        -0.22, 0.0, 0.30
    )


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), float("-inf")])
def test_invalid_component_immediately_replaces_state_with_zero(invalid):
    safety = CommandSafety(LIMITS)
    safety.accept(0.1, 0.0, 0.1, sim_time=1.0)

    assert safety.accept(invalid, 0.0, 0.0, sim_time=1.1).is_zero
    assert safety.current(sim_time=1.2).is_zero


def test_invalid_sim_time_fails_closed():
    safety = CommandSafety(LIMITS)
    safety.accept(0.1, 0.0, 0.0, sim_time=1.0)

    assert safety.accept(0.1, 0.0, 0.0, sim_time=float("nan")).is_zero
    assert safety.current(sim_time=1.1).is_zero


def test_exact_timeout_boundary_returns_zero():
    safety = CommandSafety(LIMITS)
    safety.accept(0.1, 0.0, 0.0, sim_time=1.0)

    assert safety.current(sim_time=1.499999).x == pytest.approx(0.1)
    assert safety.current(sim_time=1.50).is_zero


def test_backward_simulated_time_returns_zero_and_clears_state():
    safety = CommandSafety(LIMITS)
    safety.accept(0.1, 0.0, 0.0, sim_time=2.0)

    assert safety.current(sim_time=1.9).is_zero
    assert safety.current(sim_time=2.1).is_zero


def test_shutdown_is_latched_and_accept_cannot_rearm_it():
    safety = CommandSafety(LIMITS)
    safety.accept(0.1, 0.0, 0.0, sim_time=1.0)

    assert safety.shutdown().is_zero
    assert safety.accept(0.1, 0.0, 0.0, sim_time=1.1).is_zero
    assert safety.current(sim_time=1.2).is_zero


def test_returned_commands_and_limits_are_immutable():
    safety = CommandSafety(LIMITS)
    command = safety.accept(0.1, 0.0, 0.0, sim_time=1.0)

    with pytest.raises(FrozenInstanceError):
        command.x = 1.0
    with pytest.raises(FrozenInstanceError):
        LIMITS.max_linear_x = 1.0


def test_velocity_command_zero_property_is_exact():
    assert VelocityCommand.zero().is_zero
    assert not VelocityCommand(1e-12, 0.0, 0.0).is_zero
