from pathlib import Path

from holoagent_mujoco.config import load_config
from holoagent_mujoco.stage4_nav import validate_nav2_parameters


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_nav2_parameters_are_ground_truth_and_nonholonomic():
    bridge = load_config(PACKAGE_ROOT / "config" / "stage4.yaml")
    evidence = validate_nav2_parameters(
        PACKAGE_ROOT / "config" / "stage4_nav2.yaml",
        bridge=bridge,
        inflation_radius_m=0.45,
    )

    assert evidence["global_frame"] == "sim_map"
    assert evidence["odom_topic"] == "/robot_odom"
    assert evidence["controller_plugin"] == "dwb_core::DWBLocalPlanner"
    assert evidence["navigators"] == ["navigate_to_pose", "navigate_through_poses"]
    assert evidence["bt_plugin_libs"] == [
        "nav2_compute_path_to_pose_action_bt_node",
        "nav2_compute_path_through_poses_action_bt_node",
        "nav2_follow_path_action_bt_node",
        "nav2_pipeline_sequence_bt_node",
    ]
    assert evidence["lateral_velocity_range"] == [0.0, 0.0]
    assert evidence["vy_samples"] == 1
    assert evidence["max_vel_x"] <= bridge.command.max_linear_x
    assert evidence["max_vel_theta"] <= bridge.command.max_yaw_rate
    assert evidence["all_use_sim_time"] is True
