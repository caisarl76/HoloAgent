from __future__ import annotations

from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Pose2D:
    x: float
    y: float
    yaw: float


@dataclass(frozen=True)
class VelocitySample:
    stamp_ns: int
    x: float
    y: float
    yaw: float


@dataclass(frozen=True)
class Stage4Limits:
    position_tolerance_m: float = 0.35
    yaw_tolerance_deg: float = 15.0
    max_linear_x: float = 0.22
    max_linear_y: float = 0.0
    max_yaw_rate: float = 0.30
    timeout_zero_sec: float = 0.60
    stop_settle_sec: float = 2.0
    stopped_hold_sec: float = 1.0
    min_realtime_factor: float = 0.25


def evaluate_stage4(
    *,
    expected_fixture: Pose2D,
    observed_fixture: Pose2D | None,
    final_pose: Pose2D | None,
    commands: tuple[VelocitySample, ...],
    path_pose_count: int,
    action_succeeded: bool,
    max_scene_collision_count: int,
    zero_latency_sec: float,
    settle_latency_sec: float,
    stopped_hold_sec: float,
    simulated_duration_sec: float,
    wall_duration_sec: float,
    graph_approved: bool,
    map_approved: bool,
    all_use_sim_time: bool,
    limits: Stage4Limits,
) -> dict[str, object]:
    poses = tuple(
        pose for pose in (expected_fixture, observed_fixture, final_pose) if pose
    )
    finite = all(
        math.isfinite(value) for pose in poses for value in (pose.x, pose.y, pose.yaw)
    ) and all(
        sample.stamp_ns >= 0
        and all(math.isfinite(value) for value in (sample.x, sample.y, sample.yaw))
        for sample in commands
    )
    monotonic = all(
        current.stamp_ns > previous.stamp_ns
        for previous, current in zip(commands, commands[1:])
    )
    command_bounds = (
        bool(commands)
        and finite
        and monotonic
        and all(
            abs(sample.x) <= limits.max_linear_x + 1e-9
            and abs(sample.y) <= limits.max_linear_y + 1e-9
            and abs(sample.yaw) <= limits.max_yaw_rate + 1e-9
            for sample in commands
        )
    )
    commanded_motion = any(
        abs(sample.x) > 1e-4 or abs(sample.y) > 1e-4 or abs(sample.yaw) > 1e-4
        for sample in commands
    )
    fixture_position_error, fixture_yaw_error = _pose_error(
        expected_fixture, observed_fixture
    )
    position_error, yaw_error = _pose_error(expected_fixture, final_pose)
    realtime_factor = (
        simulated_duration_sec / wall_duration_sec if wall_duration_sec > 0.0 else 0.0
    )
    gates = {
        "graph": bool(graph_approved),
        "map": bool(map_approved),
        "use_sim_time": bool(all_use_sim_time),
        "message_finite": finite and monotonic,
        "sim_fixture": fixture_position_error <= 1e-6 and fixture_yaw_error <= 1e-6,
        "path": path_pose_count >= 2,
        "command_bounds": command_bounds and commanded_motion,
        "collision_free": max_scene_collision_count == 0,
        "action_succeeded": bool(action_succeeded),
        "goal_position": position_error <= limits.position_tolerance_m,
        "goal_yaw": yaw_error <= limits.yaw_tolerance_deg,
        "timeout_zero": zero_latency_sec <= limits.timeout_zero_sec,
        "settled_stop": settle_latency_sec <= limits.stop_settle_sec
        and stopped_hold_sec >= limits.stopped_hold_sec,
        "realtime_factor": realtime_factor >= limits.min_realtime_factor,
    }
    first_failure = next((name for name, passed in gates.items() if not passed), None)
    passed = first_failure is None
    return {
        "stage": 4,
        "status": "PASS" if passed else "FAIL",
        "label": "PASS_SIM_SEMANTIC_PLUMBING" if passed else "FAIL_NAVIGATION",
        "qualified_pass": "PASS_SIM_SEMANTIC_PLUMBING" if passed else None,
        "first_failing_gate": first_failure,
        "motion_enabled": False,
        "simulated_motion": commanded_motion,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": gates,
        "metrics": {
            "fixture_position_error_m": fixture_position_error,
            "fixture_yaw_error_deg": fixture_yaw_error,
            "position_error_m": position_error,
            "yaw_error_deg": yaw_error,
            "path_pose_count": int(path_pose_count),
            "command_samples": len(commands),
            "max_abs_cmd_x": max((abs(sample.x) for sample in commands), default=0.0),
            "max_abs_cmd_y": max((abs(sample.y) for sample in commands), default=0.0),
            "max_abs_cmd_yaw": max(
                (abs(sample.yaw) for sample in commands), default=0.0
            ),
            "max_scene_collision_count": int(max_scene_collision_count),
            "zero_latency_sec": zero_latency_sec,
            "settle_latency_sec": settle_latency_sec,
            "stopped_hold_sec": stopped_hold_sec,
            "simulated_duration_sec": simulated_duration_sec,
            "wall_duration_sec": wall_duration_sec,
            "realtime_factor": realtime_factor,
        },
    }


def _pose_error(expected: Pose2D, observed: Pose2D | None) -> tuple[float, float]:
    if observed is None:
        return math.inf, math.inf
    return (
        math.hypot(observed.x - expected.x, observed.y - expected.y),
        math.degrees(abs(_wrap(observed.yaw - expected.yaw))),
    )


def _wrap(angle: float) -> float:
    return math.atan2(math.sin(angle), math.cos(angle))
