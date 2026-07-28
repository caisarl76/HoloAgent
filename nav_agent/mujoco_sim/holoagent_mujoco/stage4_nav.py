from __future__ import annotations

import math
from pathlib import Path

import yaml

from holoagent_mujoco.config import Stage1Config


class Nav2ContractError(ValueError):
    """Raised when Nav2 can command outside the Stage 4 bridge contract."""


def validate_nav2_parameters(
    path: Path, *, bridge: Stage1Config, inflation_radius_m: float
) -> dict[str, object]:
    source = Path(path).expanduser().resolve()
    document = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not document:
        raise Nav2ContractError("Nav2 parameter root must be a mapping")
    parameters = {}
    for node, section in document.items():
        if not isinstance(section, dict):
            raise Nav2ContractError(f"{node} has no ros__parameters")
        candidate = section.get("ros__parameters")
        if candidate is None and isinstance(section.get(node), dict):
            candidate = section[node].get("ros__parameters")
        if not isinstance(candidate, dict):
            raise Nav2ContractError(f"{node} has no ros__parameters")
        parameters[node] = candidate
    if not all(values.get("use_sim_time") is True for values in parameters.values()):
        raise Nav2ContractError("every Nav2 node must set use_sim_time=true")

    controller = parameters["controller_server"]
    plugin = controller["FollowPath"]
    for name in ("min_vel_y", "max_vel_y", "acc_lim_y", "decel_lim_y"):
        if float(plugin.get(name, math.nan)) != 0.0:
            raise Nav2ContractError(
                "DWB lateral velocity and acceleration must be zero"
            )
    if int(plugin.get("vy_samples", -1)) != 1:
        raise Nav2ContractError("DWB must have one zero-only lateral sample")
    if plugin.get("plugin") != "dwb_core::DWBLocalPlanner":
        raise Nav2ContractError("Stage 4 requires the DWB non-holonomic controller")
    max_x = float(plugin["max_vel_x"])
    max_theta = float(plugin["max_vel_theta"])
    if max_x > bridge.command.max_linear_x or max_theta > bridge.command.max_yaw_rate:
        raise Nav2ContractError("Nav2 velocity exceeds the bridge command envelope")

    bt = parameters["bt_navigator"]
    if bt.get("navigators") != ["navigate_to_pose"]:
        raise Nav2ContractError("Stage 4 must enable only NavigateToPose")
    if bt.get("navigate_to_pose", {}).get("plugin") != (
        "nav2_bt_navigator/NavigateToPoseNavigator"
    ):
        raise Nav2ContractError("Stage 4 NavigateToPose plugin mismatch")
    if bt.get("global_frame") != bridge.frames.map:
        raise Nav2ContractError("BT global frame must match sim_map")
    if bt.get("robot_base_frame") != bridge.frames.base:
        raise Nav2ContractError("BT base frame mismatch")
    if bt.get("odom_topic") != "/robot_odom":
        raise Nav2ContractError("Stage 4 must use simulator ground-truth odometry")
    for name in ("global_costmap", "local_costmap"):
        costmap = parameters[name]
        for dimension in ("width", "height"):
            if dimension in costmap and not isinstance(costmap[dimension], int):
                raise Nav2ContractError(
                    f"{name} {dimension} must use Nav2's integer parameter type"
                )
        if costmap.get("plugins") != ["static_layer", "inflation_layer"]:
            raise Nav2ContractError(f"{name} must use only static and inflation layers")
        inflation = float(costmap["inflation_layer"]["inflation_radius"])
        if not math.isclose(inflation, inflation_radius_m, abs_tol=1e-12):
            raise Nav2ContractError(f"{name} inflation radius mismatch")
        if "scan" in str(costmap).lower() or "obstacle" in str(costmap).lower():
            raise Nav2ContractError(f"{name} must not depend on scan data")
    if parameters["global_costmap"].get("global_frame") != bridge.frames.map:
        raise Nav2ContractError("global costmap frame must be sim_map")
    if parameters["local_costmap"].get("global_frame") != bridge.frames.odom:
        raise Nav2ContractError("local costmap frame must be odom")
    return {
        "global_frame": bt["global_frame"],
        "odom_topic": bt["odom_topic"],
        "controller_plugin": plugin["plugin"],
        "navigators": bt["navigators"],
        "lateral_velocity_range": [plugin["min_vel_y"], plugin["max_vel_y"]],
        "vy_samples": plugin["vy_samples"],
        "max_vel_x": max_x,
        "max_vel_theta": max_theta,
        "inflation_radius_m": inflation_radius_m,
        "all_use_sim_time": True,
    }
