from __future__ import annotations

import json
from pathlib import Path

import pytest

from holoagent_mujoco.config import load_config
from holoagent_mujoco.preflight import (
    PreflightError,
    assert_evaluator_exit_status,
    assert_no_forbidden_source,
    create_run_directory,
    graph_lists_match,
    graph_snapshots_match,
    graph_snapshot_command,
    merge_postflight_result,
    scan_forbidden_processes,
    validate_container_inspect,
    validate_isolation_environment,
    validate_runtime_imports,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONFIG = load_config(PACKAGE_ROOT / "config" / "stage1.yaml")


def safe_environment() -> dict[str, str]:
    return {
        "ROS_DOMAIN_ID": "77",
        "ROS_LOCALHOST_ONLY": "1",
        "ROS2CLI_DISABLE_DAEMON": "1",
        "RMW_IMPLEMENTATION": "rmw_cyclonedds_cpp",
        "MUJOCO_GL": "egl",
        "PYTHONPATH": ":".join(
            [
                str(PACKAGE_ROOT),
                *(str(path) for path in CONFIG.runtime.extra_python_paths),
            ]
        ),
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ROS_DOMAIN_ID", "0"),
        ("ROS_LOCALHOST_ONLY", "0"),
        ("ROS2CLI_DISABLE_DAEMON", "0"),
        ("RMW_IMPLEMENTATION", "rmw_fastrtps_cpp"),
        ("MUJOCO_GL", "glfw"),
    ],
)
def test_wrong_isolation_environment_is_rejected(key, value):
    environment = safe_environment()
    environment[key] = value

    with pytest.raises(PreflightError, match=key):
        validate_isolation_environment(environment, CONFIG)


def test_missing_runtime_python_overlay_is_rejected():
    environment = safe_environment()
    environment["PYTHONPATH"] = str(PACKAGE_ROOT)

    with pytest.raises(PreflightError, match="PYTHONPATH"):
        validate_isolation_environment(environment, CONFIG)


@pytest.mark.parametrize("key", ["PC2_HOST", "ROBOT_IP", "UNITREE_INTERFACE"])
def test_physical_interface_environment_is_rejected(key):
    environment = safe_environment()
    environment[key] = "192.0.2.10"

    with pytest.raises(PreflightError, match="physical-interface"):
        validate_isolation_environment(environment, CONFIG)


def test_runtime_import_probe_uses_configured_interpreter_and_modules():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()

    evidence = validate_runtime_imports(CONFIG, safe_environment(), runner=runner)

    assert calls[0][0][0] == str(CONFIG.runtime.python)
    assert "onnxruntime" in calls[0][0][-1]
    assert "rclpy.init" in calls[0][0][-1]
    assert "get_rmw_implementation_identifier" in calls[0][0][-1]
    assert evidence["stdout"] == "ok"


def test_failed_runtime_import_probe_is_a_hard_failure():
    def runner(command, **kwargs):
        return type(
            "Result", (), {"returncode": 1, "stdout": "", "stderr": "missing module"}
        )()

    with pytest.raises(PreflightError, match="runtime import probe"):
        validate_runtime_imports(CONFIG, safe_environment(), runner=runner)


def test_source_boundary_rejects_forbidden_transport_import(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    (package / "safe.py").write_text("import math\n", encoding="utf-8")
    assert_no_forbidden_source(package)
    forbidden = "unitree" + "_sdk2py"
    (package / "unsafe.py").write_text(f"import {forbidden}\n", encoding="utf-8")

    with pytest.raises(PreflightError, match="forbidden transport"):
        assert_no_forbidden_source(package)


def test_process_scan_reports_only_forbidden_motion_executables(tmp_path):
    proc = tmp_path / "proc"
    (proc / "100").mkdir(parents=True)
    (proc / "100" / "cmdline").write_bytes(b"python\x00worker.py\x00")
    (proc / "200").mkdir()
    (proc / "200" / "cmdline").write_bytes(b"/opt/ros/g1_pubvel_node\x00")

    assert scan_forbidden_processes(proc) == [
        {"pid": 200, "executable": "g1_pubvel_node"}
    ]


def test_run_directory_creation_fails_if_path_exists(tmp_path):
    run = tmp_path / "run"
    created = create_run_directory(run)
    assert created == run.resolve() and created.is_dir()

    with pytest.raises(PreflightError, match="already exists"):
        create_run_directory(run)


def test_container_must_be_running_with_host_network_and_ipc():
    valid = [
        {
            "Name": "/holoagent_running",
            "State": {"Running": True},
            "HostConfig": {"NetworkMode": "host", "IpcMode": "host"},
        }
    ]
    evidence = validate_container_inspect(json.dumps(valid), "holoagent_running")
    assert evidence["network_mode"] == "host"

    invalid = valid.copy()
    invalid[0] = {**valid[0], "HostConfig": {"NetworkMode": "host", "IpcMode": ""}}
    with pytest.raises(PreflightError, match="IPC"):
        validate_container_inspect(json.dumps(invalid), "holoagent_running")


def test_host_and_container_graphs_must_match_expected_bridge_only():
    host = "/holoagent_mujoco_bridge\n"
    container = "/holoagent_mujoco_bridge\n"
    assert graph_lists_match(host, container) == ["/holoagent_mujoco_bridge"]

    with pytest.raises(PreflightError, match="differ"):
        graph_lists_match(host, "/unexpected\n")


def test_graph_snapshot_cli_disables_ros2_daemon_per_command():
    command = graph_snapshot_command(
        ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval")
    )

    assert "ros2 node list --no-daemon" in command
    assert "ros2 topic list --no-daemon -t" in command
    assert "ros2 service list --no-daemon -t" in command
    assert "ros2 node info --no-daemon /holoagent_mujoco_bridge" in command
    assert "ros2 node info --no-daemon /holoagent_stage1_eval" in command
    assert "ros2 action list" not in command


def test_complete_active_graph_snapshot_requires_two_expected_nodes():
    topic_lines = [
        "/camera/color/camera_info [sensor_msgs/msg/CameraInfo]",
        "/camera/color/image_raw [sensor_msgs/msg/Image]",
        "/clock [rosgraph_msgs/msg/Clock]",
        "/cmd_vel [geometry_msgs/msg/Twist]",
        "/holoagent_sim/applied_cmd_vel [geometry_msgs/msg/Twist]",
        "/holoagent_sim/contact_count [std_msgs/msg/UInt32]",
        "/livox/imu [sensor_msgs/msg/Imu]",
        "/parameter_events [rcl_interfaces/msg/ParameterEvent]",
        "/robot_odom [nav_msgs/msg/Odometry]",
        "/rosout [rcl_interfaces/msg/Log]",
        "/tf [tf2_msgs/msg/TFMessage]",
        "/tf_static [tf2_msgs/msg/TFMessage]",
    ]
    service_types = {
        "describe_parameters": "rcl_interfaces/srv/DescribeParameters",
        "get_parameter_types": "rcl_interfaces/srv/GetParameterTypes",
        "get_parameters": "rcl_interfaces/srv/GetParameters",
        "list_parameters": "rcl_interfaces/srv/ListParameters",
        "set_parameters": "rcl_interfaces/srv/SetParameters",
        "set_parameters_atomically": "rcl_interfaces/srv/SetParametersAtomically",
    }
    service_lines = [
        f"{node}/{service} [{service_type}]"
        for node in ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval")
        for service, service_type in service_types.items()
    ]
    bridge_publishers = [
        line.split(maxsplit=1)[0]
        for line in topic_lines
        if line.split(maxsplit=1)[0]
        not in {"/cmd_vel", "/parameter_events", "/rosout"}
    ] + ["/parameter_events", "/rosout"]
    evaluator_subscribers = [
        topic
        for topic in bridge_publishers
        if topic not in {"/parameter_events", "/rosout"}
    ]
    endpoint_lines = [
        "/holoagent_mujoco_bridge",
        "  Subscribers:",
        "    /clock: rosgraph_msgs/msg/Clock",
        "    /cmd_vel: geometry_msgs/msg/Twist",
        "  Publishers:",
        *(f"    {topic}: type" for topic in bridge_publishers),
        "  Service Servers:",
        *(f"    /holoagent_mujoco_bridge/{name}: type" for name in service_types),
        "  Service Clients:",
        "  Action Servers:",
        "  Action Clients:",
        "/holoagent_stage1_eval",
        "  Subscribers:",
        *(f"    {topic}: type" for topic in evaluator_subscribers),
        "  Publishers:",
        "    /cmd_vel: geometry_msgs/msg/Twist",
        "    /parameter_events: rcl_interfaces/msg/ParameterEvent",
        "    /rosout: rcl_interfaces/msg/Log",
        "  Service Servers:",
        *(f"    /holoagent_stage1_eval/{name}: type" for name in service_types),
        "  Service Clients:",
        "    /holoagent_mujoco_bridge/get_parameters: type",
        "  Action Servers:",
        "  Action Clients:",
    ]
    snapshot = "\n".join(
        [
            "=== NODES ===",
            "/holoagent_mujoco_bridge",
            "/holoagent_stage1_eval",
            "=== TOPICS ===",
            *topic_lines,
            "=== SERVICES ===",
            *service_lines,
            "=== ACTIONS ===",
            "=== ENDPOINTS ===",
            *endpoint_lines,
            "",
        ]
    )

    assert graph_snapshots_match(
        snapshot,
        snapshot,
        ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval"),
    ) == ["/holoagent_mujoco_bridge", "/holoagent_stage1_eval"]

    with pytest.raises(PreflightError, match="snapshots differ"):
        graph_snapshots_match(
            snapshot,
            snapshot.replace("/clock", "/wrong"),
            ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval"),
        )

    unexpected = snapshot.replace(
        "=== SERVICES ===",
        "/unexpected [std_msgs/msg/String]\n=== SERVICES ===",
    )
    with pytest.raises(PreflightError, match="unexpected topic"):
        graph_snapshots_match(
            unexpected,
            unexpected,
            ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval"),
        )


def test_failed_postflight_invalidates_evaluator_pass(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "status": "PASS",
                "label": "PASS_SIM_ODOM",
                "qualified_pass": "PASS_SIM_ODOM",
                "first_failing_gate": None,
                "metrics": {},
            }
        ),
        encoding="utf-8",
    )

    merge_postflight_result(
        result_path,
        {"status": "FAIL", "gate": "postflight", "error": "child alive"},
    )

    merged = json.loads(result_path.read_text(encoding="utf-8"))
    assert merged["status"] == "FAIL"
    assert merged["label"] is None
    assert merged["qualified_pass"] is None
    assert merged["first_failing_gate"] == "postflight"
    assert merged["postflight_pass"] is False
    assert merged["metrics"]["postflight_error"] == "child alive"


def test_failed_postflight_preserves_earlier_graph_failure(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(
        json.dumps(
            {
                "status": "FAIL",
                "label": None,
                "qualified_pass": None,
                "first_failing_gate": "graph",
                "metrics": {"error": "unexpected node"},
            }
        ),
        encoding="utf-8",
    )

    merge_postflight_result(
        result_path,
        {"status": "FAIL", "gate": "postflight", "error": "exit 1"},
    )

    merged = json.loads(result_path.read_text(encoding="utf-8"))
    assert merged["first_failing_gate"] == "graph"
    assert merged["metrics"]["postflight_error"] == "exit 1"


def test_nonzero_evaluator_exit_status_blocks_postflight_promotion():
    assert_evaluator_exit_status(0)

    with pytest.raises(PreflightError, match="evaluator exit status 124"):
        assert_evaluator_exit_status(124)


def test_postflight_atomically_promotes_pending_result(tmp_path):
    pending = tmp_path / "result.pending.json"
    final = tmp_path / "result.json"
    pending.write_text(
        json.dumps(
            {
                "status": "PASS",
                "label": "PASS_SIM_ODOM",
                "qualified_pass": "PASS_SIM_ODOM",
                "first_failing_gate": None,
                "metrics": {},
            }
        ),
        encoding="utf-8",
    )
    assert not final.exists()

    merge_postflight_result(
        pending,
        {"status": "PASS", "gate": "postflight"},
        final_path=final,
    )

    promoted = json.loads(final.read_text(encoding="utf-8"))
    assert promoted["status"] == "PASS"
    assert promoted["postflight_pass"] is True
    assert json.loads(pending.read_text(encoding="utf-8"))["status"] == "PASS"
