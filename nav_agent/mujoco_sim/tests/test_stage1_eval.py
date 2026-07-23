from __future__ import annotations

import json

import pytest

from holoagent_mujoco.command import CommandLimits, VelocityCommand
from holoagent_mujoco.stage1_eval import (
    AppliedCommandSample,
    CameraInfoContractSample,
    ImageContractSample,
    ImuContractSample,
    OdomSample,
    TransformContractSample,
    build_result,
    build_failure_result,
    clamp_gate,
    forward_motion,
    max_speed_in_window,
    message_contract_errors,
    motion_graph_guard_required,
    node_contract_error,
    quaternion_samples_finite,
    realtime_factor,
    service_contract_error,
    simulated_rate,
    stable_stop_window,
    stationary_drift,
    strictly_monotonic,
    timeout_latency,
    topic_contract_error,
)
from holoagent_mujoco.stage1_eval import Stage1Evaluator
from holoagent_mujoco.config import load_config
from pathlib import Path


def test_clock_must_be_strictly_monotonic():
    assert strictly_monotonic([0.005, 0.010, 0.015])
    assert not strictly_monotonic([0.005, 0.010, 0.010])
    assert not strictly_monotonic([0.005, float("nan")])


def test_topic_rate_is_measured_in_simulated_time():
    timestamps = [2.0 + index / 200.0 for index in range(2000)]

    assert simulated_rate(timestamps, start=2.0, end=12.0) == pytest.approx(200.0)
    with pytest.raises(ValueError, match="end"):
        simulated_rate(timestamps, start=2.0, end=2.0)


def test_realtime_factor_excludes_warmup():
    samples = [(0.0, 10.0), (2.0, 14.0), (12.0, 34.0)]

    assert realtime_factor(samples, warmup_sec=2.0) == pytest.approx(0.5)


def test_stationary_drift_and_bounded_motion_displacement():
    stationary = [
        OdomSample(2.0, 1.0, 2.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(7.0, 1.03, 2.04, 0.01, (1.0, 0.0, 0.0, 0.0)),
    ]
    motion = [
        OdomSample(10.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(12.0, 0.2, 0.0, 0.1, (1.0, 0.0, 0.0, 0.0)),
    ]

    assert stationary_drift(stationary) == pytest.approx(0.05)
    assert forward_motion(motion) == pytest.approx((0.2, 0.0))


def test_forward_motion_rejects_backward_and_reports_lateral_displacement():
    backward = [
        OdomSample(0.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(1.0, -0.2, 0.0, 0.1, (1.0, 0.0, 0.0, 0.0)),
    ]
    sideways = [
        OdomSample(0.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(1.0, 0.0, 0.2, 0.1, (1.0, 0.0, 0.0, 0.0)),
    ]

    assert forward_motion(backward)[0] < 0.0
    assert forward_motion(sideways) == pytest.approx((0.0, 0.2))


def test_command_clamps_require_bounds_and_observed_probe():
    limits = CommandLimits(0.22, 0.0, 0.30, 0.50)
    samples = [
        AppliedCommandSample(1.0, VelocityCommand(0.22, 0.0, 0.30)),
        AppliedCommandSample(1.1, VelocityCommand(-0.22, 0.0, -0.30)),
    ]

    assert clamp_gate(samples, limits, require_positive_probe=True)
    assert not clamp_gate(
        [AppliedCommandSample(1.0, VelocityCommand(0.1, 0.0, 0.1))],
        limits,
        require_positive_probe=True,
    )
    assert not clamp_gate(
        [AppliedCommandSample(1.0, VelocityCommand(0.1, 0.01, 0.0))],
        limits,
        require_positive_probe=False,
    )


def test_timeout_latency_and_post_timeout_speed_window():
    commands = [
        AppliedCommandSample(5.0, VelocityCommand(0.1, 0.0, 0.0)),
        AppliedCommandSample(5.4, VelocityCommand(0.1, 0.0, 0.0)),
        AppliedCommandSample(5.95, VelocityCommand.zero()),
    ]
    odometry = [
        OdomSample(5.95, 0.0, 0.0, 0.02, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(6.50, 0.0, 0.0, 0.025, (1.0, 0.0, 0.0, 0.0)),
        OdomSample(7.00, 0.0, 0.0, 0.01, (1.0, 0.0, 0.0, 0.0)),
    ]

    assert timeout_latency(commands, silence_start=5.4) == pytest.approx(0.55)
    assert max_speed_in_window(odometry, start=5.95, duration=1.0) == pytest.approx(
        0.025
    )


def test_stable_stop_requires_settling_then_full_hold_window():
    odometry = [
        OdomSample(
            index / 10.0,
            0.0,
            0.0,
            speed,
            (1.0, 0.0, 0.0, 0.0),
        )
        for index, speed in enumerate(
            [0.17, 0.09, 0.04, 0.02, 0.035, 0.025] + [0.01] * 16
        )
    ]

    settle, hold_max = stable_stop_window(
        odometry,
        start=0.0,
        max_settle=1.0,
        hold=1.0,
        speed_limit=0.03,
    )

    assert settle == pytest.approx(0.5)
    assert hold_max == pytest.approx(0.025)


def test_quaternion_finiteness_rejects_nan():
    good = [OdomSample(0.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0))]
    bad = [OdomSample(0.0, 0.0, 0.0, 0.0, (float("nan"), 0.0, 0.0, 0.0))]

    assert quaternion_samples_finite(good)
    assert not quaternion_samples_finite(bad)


def test_first_failing_gate_uses_declared_order():
    gates = {
        "graph": True,
        "clock": True,
        "rtf": False,
        "imu_rate": False,
    }

    result = build_result(gates, {"rtf": 0.1})

    assert result["status"] == "FAIL"
    assert result["first_failing_gate"] == "rtf"
    assert result["label"] is None


def test_runtime_failure_preserves_actual_gate_and_phase():
    result = build_failure_result(
        "bounded_motion", {"error": "bridge stopped"}, phase="motion"
    )

    assert result["first_failing_gate"] == "bounded_motion"
    assert result["failure_phase"] == "motion"
    assert result["gates"]["graph"] is True
    assert result["gates"]["command_clamp"] is True


def test_qualified_pass_result_is_json_serializable():
    gates = {
        "graph": True,
        "clock": True,
        "rtf": True,
        "imu_rate": True,
        "odom_rate": True,
        "camera_rate": True,
        "stationary_drift": True,
        "command_clamp": True,
        "bounded_motion": True,
        "timeout_zero": True,
        "stop_settle": True,
        "stopped_speed": True,
        "message_finite": True,
    }

    result = build_result(gates, {"rtf": 0.8})

    assert result["status"] == "PASS"
    assert result["label"] == "PASS_SIM_ODOM"
    assert result["qualified_pass"] == "PASS_SIM_ODOM"
    assert result["stage"] == 1
    assert result["physical_motion"] is False
    assert result["motion_enabled"] is False
    assert result["simulated_motion"] is True
    assert result["first_failing_gate"] is None
    assert json.loads(json.dumps(result))["metrics"]["rtf"] == 0.8


def test_failed_graph_gate_returns_before_any_phase_command():
    config = load_config(Path(__file__).parents[1] / "config" / "stage1.yaml")

    class FakeEvaluator:
        def __init__(self):
            self.config = config
            self.current_sim_time = 0.0
            self.graph_evidence = {"nodes": ["/unexpected"]}
            self.phase_commands = []
            self.zero_count = 0

        def _wait_for_first_clock(self):
            pass

        def _wait_for_graph_contract(self):
            return False, "unexpected node"

        def _wait_sim(self, target, command):
            self.phase_commands.append(command)

        def publish_zero(self):
            self.zero_count += 1

    evaluator = FakeEvaluator()

    result = Stage1Evaluator.run(evaluator)

    assert result["first_failing_gate"] == "graph"
    assert evaluator.phase_commands == []
    assert evaluator.zero_count == 1


def test_motion_graph_guard_fails_closed_on_stale_graph():
    class FakeEvaluator:
        zero_count = 0
        active_gate = "bounded_motion"
        phase = "motion"

        def _graph_contract_once(self, **kwargs):
            return False, "unexpected endpoint"

        def _bridge_uses_sim_time(self):
            return True

        def publish_zero(self):
            self.zero_count += 1

    evaluator = FakeEvaluator()

    with pytest.raises(RuntimeError, match="motion graph guard"):
        Stage1Evaluator._assert_motion_graph(evaluator)

    assert evaluator.zero_count == 1
    assert evaluator.active_gate == "graph"
    assert evaluator.phase == "motion_graph_guard"


def test_graph_guard_remains_active_while_command_times_out():
    assert motion_graph_guard_required(None)
    assert motion_graph_guard_required(VelocityCommand(0.1, 0.0, 0.0))
    assert not motion_graph_guard_required(VelocityCommand.zero())


def test_only_preapproval_ros2cli_verifier_nodes_are_temporarily_allowed():
    core = ["/holoagent_mujoco_bridge", "/holoagent_stage1_eval"]
    with_cli = ["/_ros2cli_56531", *core]
    with_daemon = [
        "/_ros2cli_daemon_77_fadfcf5940a749328af955cc162a4265",
        *core,
    ]

    assert node_contract_error(core) is None
    assert node_contract_error(with_cli) is not None
    assert node_contract_error(with_cli, allow_cli_verifiers=True) is None
    assert node_contract_error(with_daemon, allow_cli_verifiers=True) is None
    assert (
        node_contract_error(
            ["/untrusted_cli", *core], allow_cli_verifiers=True
        )
        is not None
    )


def test_motion_approval_waits_for_cli_verifier_departure(monkeypatch):
    calls = []

    class FakeEvaluator:
        active_gate = "graph"
        phase = "motion_approval"

        def _check_wall_deadline(self):
            pass

        def _graph_contract_once(self, *, allow_cli_verifiers=False):
            calls.append(allow_cli_verifiers)
            if calls == [False]:
                return False, "unexpected verifier"
            if allow_cli_verifiers:
                return True, "ok"
            return True, "ok"

        def publish_zero(self):
            raise AssertionError("valid verifier departure must not force a failure")

    monkeypatch.setattr(
        "holoagent_mujoco.stage1_eval.rclpy.spin_once",
        lambda node, timeout_sec: None,
    )

    Stage1Evaluator._wait_for_cli_verifier_departure(FakeEvaluator())

    assert calls == [False, True, False]


def test_topic_contract_rejects_additional_ordinary_endpoint():
    topics = {
        "/clock": ["rosgraph_msgs/msg/Clock"],
        "/cmd_vel": ["geometry_msgs/msg/Twist"],
        "/robot_odom": ["nav_msgs/msg/Odometry"],
        "/livox/imu": ["sensor_msgs/msg/Imu"],
        "/camera/color/image_raw": ["sensor_msgs/msg/Image"],
        "/camera/color/camera_info": ["sensor_msgs/msg/CameraInfo"],
        "/holoagent_sim/applied_cmd_vel": ["geometry_msgs/msg/Twist"],
        "/holoagent_sim/contact_count": ["std_msgs/msg/UInt32"],
        "/tf": ["tf2_msgs/msg/TFMessage"],
        "/tf_static": ["tf2_msgs/msg/TFMessage"],
        "/parameter_events": ["rcl_interfaces/msg/ParameterEvent"],
        "/rosout": ["rcl_interfaces/msg/Log"],
    }
    assert topic_contract_error(topics) is None

    topics["/unexpected"] = ["std_msgs/msg/String"]

    assert topic_contract_error(topics) == "unexpected topic endpoint: /unexpected"


def test_service_contract_requires_exact_parameter_endpoints_and_types():
    nodes = ("/holoagent_mujoco_bridge", "/holoagent_stage1_eval")
    types = {
        "describe_parameters": "rcl_interfaces/srv/DescribeParameters",
        "get_parameter_types": "rcl_interfaces/srv/GetParameterTypes",
        "get_parameters": "rcl_interfaces/srv/GetParameters",
        "list_parameters": "rcl_interfaces/srv/ListParameters",
        "set_parameters": "rcl_interfaces/srv/SetParameters",
        "set_parameters_atomically": "rcl_interfaces/srv/SetParametersAtomically",
    }
    services = {
        f"{node}/{name}": [service_type]
        for node in nodes
        for name, service_type in types.items()
    }
    assert service_contract_error(services, nodes) is None

    del services["/holoagent_stage1_eval/get_parameters"]

    assert "service contract mismatch" in service_contract_error(services, nodes)


def test_full_message_contract_accepts_expected_frames_and_metadata():
    config = load_config(Path(__file__).parents[1] / "config" / "stage1.yaml")
    odom = [
        OdomSample(
            1.0,
            0.0,
            0.0,
            0.0,
            (1.0, 0.0, 0.0, 0.0),
            "odom",
            "base_link",
        )
    ]
    imu = [
        ImuContractSample(
            1.0,
            "imu_link",
            (1.0, 0.0, 0.0, 0.0),
            (0.0, 0.0, 0.0),
            (0.0, 0.0, 9.81),
        )
    ]
    images = [
        ImageContractSample(1.0, "camera_link", 320, 240, "rgb8", 960, 230400)
    ]
    info = [
        CameraInfoContractSample(
            1.0,
            "camera_link",
            320,
            240,
            (240.0, 0.0, 160.0, 0.0, 240.0, 120.0, 0.0, 0.0, 1.0),
            (
                240.0,
                0.0,
                160.0,
                0.0,
                0.0,
                240.0,
                120.0,
                0.0,
                0.0,
                0.0,
                1.0,
                0.0,
            ),
        )
    ]
    transforms = [
        TransformContractSample(0.0, "sim_map", "odom", (0.0, 0.0, 0.0), (1.0, 0.0, 0.0, 0.0), True),
        TransformContractSample(1.0, "odom", "base_link", (0.0, 0.0, 0.8), (1.0, 0.0, 0.0, 0.0), False),
        TransformContractSample(1.0, "base_link", "imu_link", (0.0, 0.0, 0.2), (1.0, 0.0, 0.0, 0.0), False),
        TransformContractSample(1.0, "base_link", "camera_link", (0.2, 0.0, 0.3), (1.0, 0.0, 0.0, 0.0), False),
    ]

    assert message_contract_errors(config, odom, imu, images, info, transforms) == []


def test_message_contract_rejects_wrong_frame_nan_and_malformed_image():
    config = load_config(Path(__file__).parents[1] / "config" / "stage1.yaml")
    odom = [
        OdomSample(1.0, 0.0, 0.0, 0.0, (1.0, 0.0, 0.0, 0.0), "map", "base_link")
    ]
    imu = [
        ImuContractSample(
            1.0,
            "wrong_imu",
            (1.0, 0.0, 0.0, 0.0),
            (float("nan"), 0.0, 0.0),
            (0.0, 0.0, 9.81),
        )
    ]
    images = [ImageContractSample(1.0, "camera_link", 1, 1, "bgr8", 3, 2)]

    errors = message_contract_errors(config, odom, imu, images, [], [])

    assert any("odometry frames" in error for error in errors)
    assert any("IMU" in error for error in errors)
    assert any("image" in error for error in errors)
    assert any("camera info" in error for error in errors)
    assert any("TF" in error for error in errors)
