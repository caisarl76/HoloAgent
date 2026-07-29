from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
LAUNCH = PACKAGE_ROOT / "launch" / "stage4_nav2.launch.py"
RUNNER = PACKAGE_ROOT / "scripts" / "run_stage4.sh"
THROUGH_POSES_TREE = (
    PACKAGE_ROOT / "behavior_trees" / "stage4_navigate_through_poses.xml"
)
EVALUATOR = PACKAGE_ROOT / "holoagent_mujoco" / "stage4_eval.py"
ACTIVATOR = PACKAGE_ROOT / "holoagent_mujoco" / "stage4_activate.py"


def test_stage4_launch_is_minimal_nav2_without_localization_or_robot_drivers():
    text = LAUNCH.read_text(encoding="utf-8")
    for package in (
        "nav2_map_server",
        "nav2_planner",
        "nav2_controller",
        "nav2_bt_navigator",
        "nav2_lifecycle_manager",
    ):
        assert f'package="{package}"' in text
    assert "yaml_filename" in text
    assert "ParameterValue(map_yaml, value_type=str)" in text
    assert 'default_value="false"' in text
    assert "amcl" not in text.lower()
    assert "slam" not in text.lower()
    assert "unitree" not in text.lower()
    assert "g1_" not in text.lower()


def test_package_installs_stage4_launch_and_behavior_tree():
    setup = (PACKAGE_ROOT / "setup.py").read_text(encoding="utf-8")
    assert 'glob("launch/*.launch.py")' in setup
    assert 'glob("behavior_trees/*.xml")' in setup
    tree = THROUGH_POSES_TREE.read_text(encoding="utf-8")
    assert "ComputePathThroughPoses" in tree
    assert "FollowPath" in tree
    assert "RecoveryNode" not in tree


def test_stage4_runner_is_fail_closed_before_query_motion():
    text = RUNNER.read_text(encoding="utf-8")
    assert "ROS_LOCALHOST_ONLY=1" in text
    assert "ROS2CLI_DISABLE_DAEMON=1" in text
    assert "RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" in text
    assert "LC_ALL=C" in text
    assert "stage4_prepare" in text
    assert "stage4_result" in text
    assert "stage4_graph_ready.json" in text
    assert "stage4_graph_approved.sha256" in text
    assert text.index("--graph-host") < text.index("stage4_graph_approved.sha256")
    assert "autostart:=false" in text
    assert "stage4_activate" in text
    assert "stage4_activation.json" in text
    assert "--activation ${container_run_dir}/stage4_activation.json" in text
    assert text.index("stage4_activate") < text.index("stage4_eval")
    assert "ros2 action list -t" in text
    assert "ros2 daemon stop" in text
    assert text.count("stop_cli_daemons") >= 3
    assert "recover_container_pids" in text
    assert text.index("recover_container_pids") < text.index(
        'stop_container_pid "${evaluator_container_pid}"'
    )
    assert "result.pending.json" in text
    assert "result.json" in text


def test_stage4_runner_has_no_physical_transport_or_broad_cleanup():
    text = RUNNER.read_text(encoding="utf-8").lower()
    assert "unitree" not in text
    assert "g1_pub" not in text
    assert "ssh " not in text
    assert "pkill" not in text
    assert "killall" not in text


def test_stage4_evaluator_queries_helper_clocks_and_times_only_approved_motion():
    text = EVALUATOR.read_text(encoding="utf-8")
    assert '"bt_navigator_navigate_to_pose_rclcpp_node"' in text
    assert '"bt_navigator_navigate_through_poses_rclcpp_node"' in text
    assert 'values["configured/bt_navigator_navigate_to_pose_rclcpp_node"] = True' not in text
    assert "measurement_wall_start = time.monotonic()" in text
    assert "wall_duration_sec=time.monotonic() - measurement_wall_start" in text


def test_stage4_activation_configures_before_live_costmap_validation():
    text = ACTIVATOR.read_text(encoding="utf-8")

    assert "TRANSITION_CONFIGURE" in text
    assert "ManageLifecycleNodes.Request.RESUME" in text
    assert "ManageLifecycleNodes.Request.STARTUP" not in text
    assert text.index("node.configure_managed_nodes()") < text.index(
        "node.read_live_parameters()"
    )
    assert text.index("validate_pre_activation_contract(") < text.index(
        "node.activate_managed_nodes()"
    )
