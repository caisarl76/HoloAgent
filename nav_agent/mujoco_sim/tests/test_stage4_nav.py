from pathlib import Path

import pytest

from holoagent_mujoco.config import load_config
from holoagent_mujoco.stage4_activate import (
    Stage4ActivationError,
    validate_pre_activation_contract,
)
from holoagent_mujoco.stage4_nav import validate_nav2_parameters
from holoagent_mujoco.stage4_prepare import prepare_stage4


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


def test_pre_activation_contract_checks_live_map_and_sim_time_before_startup(tmp_path):
    config = PACKAGE_ROOT / "config" / "stage4.yaml"
    prepare_stage4(config, tmp_path)
    live = {
        name: {"use_sim_time": True}
        for name in (
            "map_server",
            "planner_server",
            "controller_server",
            "bt_navigator",
            "global_costmap/global_costmap",
            "local_costmap/local_costmap",
            "lifecycle_manager_stage4",
        )
    }
    live["map_server"]["yaml_filename"] = str(tmp_path / "sim_map.yaml")

    evidence = validate_pre_activation_contract(
        config_path=config,
        manifest_path=tmp_path / "stage4_manifest.json",
        live_parameters=live,
    )

    assert evidence["status"] == "PRE_ACTIVATION_APPROVED"
    assert evidence["map"]["yaml_path"] == str((tmp_path / "sim_map.yaml").resolve())
    assert all(item["use_sim_time"] for item in evidence["live_parameters"].values())

    live["controller_server"]["use_sim_time"] = False
    with pytest.raises(Stage4ActivationError, match="use_sim_time"):
        validate_pre_activation_contract(
            config_path=config,
            manifest_path=tmp_path / "stage4_manifest.json",
            live_parameters=live,
        )
