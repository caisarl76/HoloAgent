from __future__ import annotations

import math

from holoagent_mujoco.stage4_metrics import (
    Pose2D,
    Stage4Limits,
    VelocitySample,
    evaluate_stage4,
)


def _passing_result():
    return evaluate_stage4(
        expected_fixture=Pose2D(1.25, 0.0, 0.0),
        observed_fixture=Pose2D(1.25, 0.0, 0.0),
        final_pose=Pose2D(1.08, 0.02, math.radians(5.0)),
        commands=(
            VelocitySample(1_000_000_000, 0.10, 0.0, 0.0),
            VelocitySample(2_000_000_000, 0.0, 0.0, 0.0),
        ),
        path_pose_count=20,
        action_succeeded=True,
        max_scene_collision_count=0,
        zero_latency_sec=0.2,
        settle_latency_sec=0.8,
        stopped_hold_sec=1.1,
        simulated_duration_sec=20.0,
        wall_duration_sec=30.0,
        graph_approved=True,
        map_approved=True,
        all_use_sim_time=True,
        limits=Stage4Limits(),
    )


def test_stage4_metrics_issue_only_qualified_sim_semantic_pass():
    result = _passing_result()
    assert result["status"] == "PASS"
    assert result["label"] == "PASS_SIM_SEMANTIC_PLUMBING"
    assert result["qualified_pass"] == "PASS_SIM_SEMANTIC_PLUMBING"
    assert result["physical_motion"] is False
    assert result["metrics"]["position_error_m"] < 0.35
    assert result["metrics"]["yaw_error_deg"] < 15.0


def test_collision_or_lateral_command_fails_without_overclaim():
    kwargs = dict(
        expected_fixture=Pose2D(1.25, 0.0, 0.0),
        observed_fixture=Pose2D(1.25, 0.0, 0.0),
        final_pose=Pose2D(1.25, 0.0, 0.0),
        commands=(VelocitySample(1, 0.10, 0.01, 0.0),),
        path_pose_count=2,
        action_succeeded=True,
        max_scene_collision_count=1,
        zero_latency_sec=0.1,
        settle_latency_sec=0.1,
        stopped_hold_sec=1.0,
        simulated_duration_sec=10.0,
        wall_duration_sec=10.0,
        graph_approved=True,
        map_approved=True,
        all_use_sim_time=True,
        limits=Stage4Limits(),
    )
    result = evaluate_stage4(**kwargs)
    assert result["status"] == "FAIL"
    assert result["qualified_pass"] is None
    assert result["first_failing_gate"] == "command_bounds"
    assert result["gates"]["collision_free"] is False


def test_headerless_commands_may_share_a_clock_tick_but_never_reverse_time():
    kwargs = {
        "expected_fixture": Pose2D(1.25, 0.0, 0.0),
        "observed_fixture": Pose2D(1.25, 0.0, 0.0),
        "final_pose": Pose2D(1.25, 0.0, 0.0),
        "path_pose_count": 2,
        "action_succeeded": True,
        "max_scene_collision_count": 0,
        "zero_latency_sec": 0.1,
        "settle_latency_sec": 0.1,
        "stopped_hold_sec": 1.0,
        "simulated_duration_sec": 1.0,
        "wall_duration_sec": 1.0,
        "graph_approved": True,
        "map_approved": True,
        "all_use_sim_time": True,
        "limits": Stage4Limits(),
    }
    shared_tick = evaluate_stage4(
        **kwargs,
        commands=(
            VelocitySample(1_000, 0.1, 0.0, 0.0),
            VelocitySample(1_000, 0.1, 0.0, 0.0),
        ),
    )
    assert shared_tick["gates"]["message_finite"] is True

    reversed_time = evaluate_stage4(
        **kwargs,
        commands=(
            VelocitySample(1_001, 0.1, 0.0, 0.0),
            VelocitySample(1_000, 0.1, 0.0, 0.0),
        ),
    )
    assert reversed_time["gates"]["message_finite"] is False
