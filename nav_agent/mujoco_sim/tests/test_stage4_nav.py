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
    assert evidence["lateral_velocity_range"] == [0.0, 0.0]
    assert evidence["vy_samples"] == 1
    assert evidence["max_vel_x"] <= bridge.command.max_linear_x
    assert evidence["max_vel_theta"] <= bridge.command.max_yaw_rate
    assert evidence["all_use_sim_time"] is True
