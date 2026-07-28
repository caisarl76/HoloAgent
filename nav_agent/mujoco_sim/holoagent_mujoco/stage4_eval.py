from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import time
from typing import Any

from action_msgs.msg import GoalStatus
from geometry_msgs.msg import PoseStamped, Twist
from nav2_msgs.action import NavigateToPose
from nav_msgs.msg import Odometry, Path as NavPath
import rclpy
from rcl_interfaces.msg import ParameterType
from rcl_interfaces.srv import GetParameters
from rclpy.action import ActionClient
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import (
    DurabilityPolicy,
    QoSProfile,
    ReliabilityPolicy,
    qos_profile_sensor_data,
)
from rosgraph_msgs.msg import Clock
from std_msgs.msg import String, UInt32

from holoagent_mujoco.config import file_sha256
from holoagent_mujoco.stage4_config import Stage4Config, load_stage4_config
from holoagent_mujoco.stage4_map import verify_loaded_map
from holoagent_mujoco.stage4_metrics import (
    Pose2D,
    Stage4Limits,
    VelocitySample,
    evaluate_stage4,
)
from holoagent_mujoco.stage4_nav import validate_nav2_parameters
from holoagent_mujoco.stage4_result import (
    validate_endpoint_ownership,
    validate_stage4_node_names,
)


def _endpoint_name(endpoint: Any) -> str:
    namespace = str(endpoint.node_namespace).rstrip("/")
    return f"{namespace}/{endpoint.node_name}".replace("//", "/")


class Stage4Evaluator(Node):
    def __init__(
        self,
        config: Stage4Config,
        *,
        manifest_path: Path,
        activation_path: Path,
        ready_file: Path,
        approval_file: Path,
    ) -> None:
        super().__init__(
            "holoagent_stage4_eval",
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
            automatically_declare_parameters_from_overrides=True,
        )
        self.config = config
        self.manifest_path = manifest_path.resolve()
        self.activation_path = activation_path.resolve()
        self.ready_file = ready_file.resolve()
        self.approval_file = approval_file.resolve()
        self.current_clock_ns: int | None = None
        self.latest_pose: Pose2D | None = None
        self.latest_speed_mps = math.inf
        self.observed_fixture: Pose2D | None = None
        self.observed_fixture_frame = ""
        self.path_pose_count = 0
        self.commands: list[VelocitySample] = []
        self.applied_commands: list[VelocitySample] = []
        self.max_scene_collision_count = 0
        self.collision_stamps_ns: list[int] = []
        self.graph_evidence: dict[str, Any] = {}
        self.all_use_sim_time = False
        self.activation_evidence: dict[str, Any] = {}
        self.active_gate = "graph"
        wall_limit = (
            config.gates.wall_time_multiplier * config.gates.goal_timeout_sim_sec
            + config.gates.startup_allowance_sec
        )
        self._wall_deadline = time.monotonic() + wall_limit
        reliable = QoSProfile(depth=20, reliability=ReliabilityPolicy.RELIABLE)
        latched = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._query = self.create_publisher(String, config.query_topic, reliable)
        self.create_subscription(
            PoseStamped, config.output_topic, self._fixture_callback, latched
        )
        self.create_subscription(
            Clock, "/clock", self._clock_callback, qos_profile_sensor_data
        )
        self.create_subscription(Odometry, "/robot_odom", self._odom_callback, reliable)
        self.create_subscription(NavPath, "/plan", self._path_callback, reliable)
        self.create_subscription(Twist, "/cmd_vel", self._command_callback, reliable)
        self.create_subscription(
            Twist,
            "/holoagent_sim/applied_cmd_vel",
            self._applied_callback,
            reliable,
        )
        self.create_subscription(
            UInt32,
            "/holoagent_sim/collision_count",
            self._collision_callback,
            qos_profile_sensor_data,
        )
        self._navigate = ActionClient(self, NavigateToPose, "navigate_to_pose")
        self._parameter_clients = {
            name: self.create_client(GetParameters, f"/{name}/get_parameters")
            for name in (
                "map_server",
                "planner_server",
                "controller_server",
                "bt_navigator",
                "bt_navigator_navigate_to_pose_rclcpp_node",
                "bt_navigator_navigate_through_poses_rclcpp_node",
                "global_costmap/global_costmap",
                "local_costmap/local_costmap",
                "lifecycle_manager_stage4",
                "sim_fixture",
                "holoagent_mujoco_bridge",
            )
        }

    def run(self) -> dict[str, object]:
        self._wait_for_clock()
        self._wait_for_exact_graph()
        manifest = self._validate_assets_and_runtime_parameters()
        self._write_ready_and_wait_for_approval(manifest)
        self._wait_for_exact_graph()
        measurement_wall_start = time.monotonic()
        collect_start_ns = int(self.current_clock_ns)
        expected = next(iter(self.config.fixtures.values()))
        self.active_gate = "sim_fixture"
        self._publish_query_until_fixture(expected.query, timeout_sim_sec=3.0)
        self._validate_observed_fixture(expected)

        self.active_gate = "navigation"
        if not self._navigate.wait_for_server(timeout_sec=10.0):
            raise RuntimeError("navigate_to_pose action server is unavailable")
        goal = NavigateToPose.Goal()
        goal.pose = PoseStamped()
        goal.pose.header.frame_id = self.config.map.frame_id
        goal.pose.header.stamp = self.get_clock().now().to_msg()
        goal.pose.pose.position.x = expected.x
        goal.pose.pose.position.y = expected.y
        goal.pose.pose.orientation.z = math.sin(expected.yaw / 2.0)
        goal.pose.pose.orientation.w = math.cos(expected.yaw / 2.0)
        send_future = self._navigate.send_goal_async(goal)
        self._spin_until_future(send_future, wall_timeout_sec=10.0)
        goal_handle = send_future.result()
        if goal_handle is None or not goal_handle.accepted:
            raise RuntimeError("Nav2 rejected the sim_fixture goal")
        result_future = goal_handle.get_result_async()
        goal_deadline_ns = collect_start_ns + int(
            self.config.gates.goal_timeout_sim_sec * 1e9
        )
        while not result_future.done() and self.current_clock_ns < goal_deadline_ns:
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.02)
        action_succeeded = bool(
            result_future.done()
            and result_future.result() is not None
            and result_future.result().status == GoalStatus.STATUS_SUCCEEDED
        )
        action_done_ns = int(self.current_clock_ns)
        self.active_gate = "stop"
        stop = self._observe_stop(action_done_ns)
        final_pose = self.latest_pose
        simulated_duration = (int(self.current_clock_ns) - collect_start_ns) / 1e9
        collision_sample_count = sum(
            collect_start_ns <= stamp <= int(self.current_clock_ns)
            for stamp in self.collision_stamps_ns
        )
        result = evaluate_stage4(
            expected_fixture=Pose2D(expected.x, expected.y, expected.yaw),
            observed_fixture=self.observed_fixture,
            final_pose=final_pose,
            commands=tuple(self.commands),
            path_pose_count=self.path_pose_count,
            action_succeeded=action_succeeded,
            max_scene_collision_count=self.max_scene_collision_count,
            collision_sample_count=collision_sample_count,
            zero_latency_sec=stop["zero_latency_sec"],
            settle_latency_sec=stop["settle_latency_sec"],
            stopped_hold_sec=stop["stopped_hold_sec"],
            simulated_duration_sec=simulated_duration,
            wall_duration_sec=time.monotonic() - measurement_wall_start,
            graph_approved=True,
            map_approved=True,
            all_use_sim_time=self.all_use_sim_time,
            limits=Stage4Limits(
                position_tolerance_m=self.config.gates.position_tolerance_m,
                yaw_tolerance_deg=self.config.gates.yaw_tolerance_deg,
                max_linear_x=self.config.bridge.command.max_linear_x,
                max_linear_y=self.config.bridge.command.max_linear_y,
                max_yaw_rate=self.config.bridge.command.max_yaw_rate,
                timeout_zero_sec=self.config.gates.timeout_zero_sec,
                stop_settle_sec=self.config.gates.stop_settle_sec,
                stopped_hold_sec=self.config.gates.stopped_hold_sec,
                min_realtime_factor=self.config.gates.min_realtime_factor,
            ),
        )
        result["graph"] = self.graph_evidence
        result["map_manifest"] = manifest
        result["pre_activation"] = self.activation_evidence
        result["sim_fixture"] = {
            "query": expected.query,
            "frame_id": self.observed_fixture_frame,
            "pose": [expected.x, expected.y, expected.yaw],
        }
        return result

    def _wait_for_clock(self) -> None:
        while self.current_clock_ns is None:
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)

    def _wait_for_exact_graph(self) -> None:
        deadline = min(self._wall_deadline, time.monotonic() + 30.0)
        reason = "Stage 4 graph did not converge"
        while time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.05)
            valid, reason = self._graph_contract()
            if valid:
                return
        raise RuntimeError(reason)

    def _graph_contract(self) -> tuple[bool, str]:
        nodes = {
            f"{namespace.rstrip('/')}/{name}".replace("//", "/")
            for name, namespace in self.get_node_names_and_namespaces()
        }
        topics = {
            name: sorted(types) for name, types in self.get_topic_names_and_types()
        }
        self.graph_evidence = {"nodes": sorted(nodes), "topics": topics}
        try:
            node_contract = validate_stage4_node_names(nodes)
        except Exception as exc:
            return False, str(exc)
        self.graph_evidence["node_contract"] = node_contract
        required = {
            "/clock": "rosgraph_msgs/msg/Clock",
            "/cmd_vel": "geometry_msgs/msg/Twist",
            "/robot_odom": "nav_msgs/msg/Odometry",
            "/map": "nav_msgs/msg/OccupancyGrid",
            "/plan": "nav_msgs/msg/Path",
            "/sim_fixture/query": "std_msgs/msg/String",
            "/object_pose": "geometry_msgs/msg/PoseStamped",
            "/holoagent_sim/collision_count": "std_msgs/msg/UInt32",
        }
        if any(topics.get(name) != [kind] for name, kind in required.items()):
            return False, "required Stage 4 topic/type mismatch"
        endpoint_contracts = {}
        for topic, expected_publishers, expected_subscribers in (
            (
                "/cmd_vel",
                {"/controller_server"},
                {"/holoagent_mujoco_bridge", "/holoagent_stage4_eval"},
            ),
            (
                "/holoagent_sim/collision_count",
                {"/holoagent_mujoco_bridge"},
                {"/holoagent_stage4_eval"},
            ),
        ):
            publishers = {
                _endpoint_name(item)
                for item in self.get_publishers_info_by_topic(topic)
            }
            subscribers = {
                _endpoint_name(item)
                for item in self.get_subscriptions_info_by_topic(topic)
            }
            try:
                endpoint_contracts[topic] = validate_endpoint_ownership(
                    publishers=publishers,
                    subscribers=subscribers,
                    expected_publishers=expected_publishers,
                    expected_subscribers=expected_subscribers,
                    topic=topic,
                )
            except Exception as exc:
                return False, str(exc)
        self.graph_evidence["endpoint_ownership"] = endpoint_contracts
        return True, "ok"

    def _validate_assets_and_runtime_parameters(self) -> dict[str, object]:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        activation = json.loads(self.activation_path.read_text(encoding="utf-8"))
        if (
            activation.get("status") != "PRE_ACTIVATION_APPROVED"
            or activation.get("lifecycle_active") is not True
            or activation.get("manifest_sha256") != file_sha256(self.manifest_path)
        ):
            raise RuntimeError("Stage 4 pre-activation evidence is invalid")
        self.activation_evidence = {
            **activation,
            "evidence_path": str(self.activation_path),
            "evidence_sha256": file_sha256(self.activation_path),
        }
        map_evidence = manifest.get("map", {})
        loaded_path = Path(self._remote_parameter("map_server", "yaml_filename"))
        verify_loaded_map(
            loaded_path,
            expected_yaml_path=Path(map_evidence["yaml_path"]),
            expected_yaml_sha256=str(map_evidence["yaml_sha256"]),
            expected_pgm_sha256=str(map_evidence["pgm_sha256"]),
            prohibited_real_map_paths=self.config.map.prohibited_real_map_paths,
        )
        runtime_params = Path(manifest["nav2"]["runtime_params_path"])
        if file_sha256(runtime_params) != manifest["nav2"]["runtime_params_sha256"]:
            raise RuntimeError("Stage 4 runtime Nav2 parameter digest mismatch")
        if (
            file_sha256(self.config.behavior_tree)
            != manifest["nav2"]["behavior_tree_sha256"]
        ):
            raise RuntimeError("Stage 4 NavigateToPose tree digest mismatch")
        if (
            file_sha256(self.config.behavior_tree_through_poses)
            != manifest["nav2"]["behavior_tree_through_poses_sha256"]
        ):
            raise RuntimeError("Stage 4 NavigateThroughPoses tree digest mismatch")
        validate_nav2_parameters(
            runtime_params,
            bridge=self.config.bridge,
            inflation_radius_m=self.config.map.inflation_radius_m,
        )
        self.all_use_sim_time = self._all_nodes_use_sim_time()
        if not self.all_use_sim_time:
            raise RuntimeError("one or more Stage 4 nodes do not use simulated time")
        if manifest.get("config_sha256") != file_sha256(self.config.source_path):
            raise RuntimeError("Stage 4 manifest config digest mismatch")
        return manifest

    def _write_ready_and_wait_for_approval(self, manifest: dict[str, object]) -> None:
        if self.ready_file.exists() or self.approval_file.exists():
            raise RuntimeError("Stage 4 graph approval artifacts must not pre-exist")
        self.ready_file.write_text(
            json.dumps(
                {
                    "status": "READY_SIM_NAVIGATION_DISABLED",
                    "clock_ns": self.current_clock_ns,
                    "graph": self.graph_evidence,
                    "map_manifest_sha256": file_sha256(self.manifest_path),
                    "map": manifest["map"],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        expected = file_sha256(self.ready_file)
        while not self.approval_file.is_file():
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.05)
        if self.approval_file.read_text(encoding="utf-8").strip() != expected:
            raise RuntimeError("external Stage 4 graph approval digest mismatch")

    def _publish_query_until_fixture(
        self, query: str, *, timeout_sim_sec: float
    ) -> None:
        deadline = int(self.current_clock_ns + timeout_sim_sec * 1e9)
        last_publish_ns = -(10**18)
        message = String(data=query)
        while self.observed_fixture is None and self.current_clock_ns < deadline:
            if self.current_clock_ns - last_publish_ns >= 200_000_000:
                self._query.publish(message)
                last_publish_ns = self.current_clock_ns
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.02)
        if self.observed_fixture is None:
            raise RuntimeError("sim_fixture did not publish /object_pose")

    def _validate_observed_fixture(self, expected: Any) -> None:
        if self.observed_fixture_frame != self.config.map.frame_id:
            raise RuntimeError("sim_fixture pose frame is not sim_map")
        observed = self.observed_fixture
        if observed is None or any(
            abs(value) > 1e-6
            for value in (
                observed.x - expected.x,
                observed.y - expected.y,
                _wrap(observed.yaw - expected.yaw),
            )
        ):
            raise RuntimeError("sim_fixture pose differs from the prevalidated fixture")

    def _observe_stop(self, action_done_ns: int) -> dict[str, float]:
        deadline = action_done_ns + int(
            (
                self.config.gates.timeout_zero_sec
                + self.config.gates.stop_settle_sec
                + self.config.gates.stopped_hold_sec
                + 1.0
            )
            * 1e9
        )
        stopped_since: int | None = None
        while self.current_clock_ns < deadline:
            if self.latest_speed_mps <= self.config.gates.stopped_speed_mps:
                if stopped_since is None:
                    stopped_since = int(self.current_clock_ns)
                if (
                    self.current_clock_ns - stopped_since
                    >= self.config.gates.stopped_hold_sec * 1e9
                ):
                    break
            else:
                stopped_since = None
            self._check_deadline()
            rclpy.spin_once(self, timeout_sec=0.02)
        nonzero = [
            sample
            for sample in self.applied_commands
            if abs(sample.x) > 1e-4 or abs(sample.y) > 1e-4 or abs(sample.yaw) > 1e-4
        ]
        last_nonzero_ns = nonzero[-1].stamp_ns if nonzero else action_done_ns
        first_zero = next(
            (
                sample
                for sample in self.applied_commands
                if sample.stamp_ns > last_nonzero_ns
                and abs(sample.x) <= 1e-4
                and abs(sample.y) <= 1e-4
                and abs(sample.yaw) <= 1e-4
            ),
            None,
        )
        zero_latency = (
            (first_zero.stamp_ns - last_nonzero_ns) / 1e9
            if first_zero is not None
            else math.inf
        )
        settle_latency = (
            (stopped_since - action_done_ns) / 1e9
            if stopped_since is not None
            else math.inf
        )
        hold = (
            (int(self.current_clock_ns) - stopped_since) / 1e9
            if stopped_since is not None
            else 0.0
        )
        return {
            "zero_latency_sec": zero_latency,
            "settle_latency_sec": max(0.0, settle_latency),
            "stopped_hold_sec": hold,
        }

    def _all_nodes_use_sim_time(self) -> bool:
        values = {
            name: bool(self._remote_parameter(name, "use_sim_time"))
            for name in self._parameter_clients
        }
        values["eval"] = bool(self.get_parameter("use_sim_time").value)
        values["inherited/transform_listener_nodes"] = bool(
            values["global_costmap/global_costmap"]
            and values["local_costmap/local_costmap"]
        )
        self.graph_evidence["use_sim_time"] = values
        return all(values.values())

    def _remote_parameter(self, client_name: str, parameter: str) -> Any:
        client = self._parameter_clients[client_name]
        if not client.wait_for_service(timeout_sec=3.0):
            raise RuntimeError(f"{client_name} parameter service is unavailable")
        request = GetParameters.Request(names=[parameter])
        future = client.call_async(request)
        try:
            self._spin_until_future(future, wall_timeout_sec=3.0)
        except RuntimeError as exc:
            raise RuntimeError(
                f"{client_name}.{parameter} query did not complete"
            ) from exc
        response = future.result()
        if response is None or len(response.values) != 1:
            raise RuntimeError(f"{client_name}.{parameter} is unavailable")
        value = response.values[0]
        if value.type == ParameterType.PARAMETER_BOOL:
            return bool(value.bool_value)
        if value.type == ParameterType.PARAMETER_STRING:
            return str(value.string_value)
        raise RuntimeError(f"{client_name}.{parameter} has an unexpected type")

    def _spin_until_future(self, future: Any, *, wall_timeout_sec: float) -> None:
        deadline = min(self._wall_deadline, time.monotonic() + wall_timeout_sec)
        while not future.done() and time.monotonic() < deadline:
            rclpy.spin_once(self, timeout_sec=0.02)
        if not future.done() or future.exception() is not None:
            raise RuntimeError("ROS operation did not complete")

    def _clock_callback(self, message: Clock) -> None:
        self.current_clock_ns = _stamp_ns(message.clock)

    def _fixture_callback(self, message: PoseStamped) -> None:
        self.observed_fixture = _pose2d(message.pose)
        self.observed_fixture_frame = message.header.frame_id

    def _odom_callback(self, message: Odometry) -> None:
        self.latest_pose = _pose2d(message.pose.pose)
        velocity = message.twist.twist.linear
        self.latest_speed_mps = math.hypot(velocity.x, velocity.y)

    def _path_callback(self, message: NavPath) -> None:
        self.path_pose_count = max(self.path_pose_count, len(message.poses))

    def _command_callback(self, message: Twist) -> None:
        if self.current_clock_ns is not None:
            self.commands.append(_velocity_sample(self.current_clock_ns, message))

    def _applied_callback(self, message: Twist) -> None:
        if self.current_clock_ns is not None:
            self.applied_commands.append(
                _velocity_sample(self.current_clock_ns, message)
            )

    def _collision_callback(self, message: UInt32) -> None:
        self.max_scene_collision_count = max(
            self.max_scene_collision_count, int(message.data)
        )
        if self.current_clock_ns is not None:
            self.collision_stamps_ns.append(int(self.current_clock_ns))

    def _check_deadline(self) -> None:
        if time.monotonic() > self._wall_deadline:
            raise TimeoutError("Stage 4 wall-time limit exceeded")


def _stamp_ns(stamp: Any) -> int:
    return int(stamp.sec) * 1_000_000_000 + int(stamp.nanosec)


def _pose2d(pose: Any) -> Pose2D:
    orientation = pose.orientation
    values = (
        pose.position.x,
        pose.position.y,
        orientation.x,
        orientation.y,
        orientation.z,
        orientation.w,
    )
    if not all(math.isfinite(float(value)) for value in values):
        raise ValueError("pose contains non-finite values")
    norm = math.sqrt(
        orientation.x**2 + orientation.y**2 + orientation.z**2 + orientation.w**2
    )
    if not math.isclose(norm, 1.0, abs_tol=1e-3):
        raise ValueError("pose quaternion is not unit length")
    yaw = math.atan2(
        2.0 * (orientation.w * orientation.z + orientation.x * orientation.y),
        1.0 - 2.0 * (orientation.y**2 + orientation.z**2),
    )
    return Pose2D(float(pose.position.x), float(pose.position.y), yaw)


def _velocity_sample(stamp_ns: int, message: Twist) -> VelocitySample:
    return VelocitySample(
        int(stamp_ns),
        float(message.linear.x),
        float(message.linear.y),
        float(message.angular.z),
    )


def _wrap(angle: float) -> float:
    return math.atan2(math.sin(angle), math.cos(angle))


def _failure(error: Exception, gate: str) -> dict[str, object]:
    return {
        "stage": 4,
        "status": "FAIL",
        "label": "FAIL_NAVIGATION",
        "qualified_pass": None,
        "first_failing_gate": gate,
        "motion_enabled": False,
        "simulated_motion": False,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": {gate: False},
        "metrics": {"error": str(error), "exception_type": type(error).__name__},
    }


def _write_json(path: Path, result: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate Stage 4 semantic Nav2 plumbing"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--activation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--approval-file", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    node: Stage4Evaluator | None = None
    initialized = False
    try:
        config = load_stage4_config(arguments.config, validate_bridge_artifacts=False)
        rclpy.init(args=ros_arguments)
        initialized = True
        node = Stage4Evaluator(
            config,
            manifest_path=arguments.manifest,
            activation_path=arguments.activation,
            ready_file=arguments.ready_file,
            approval_file=arguments.approval_file,
        )
        result = node.run()
        result["config_sha256"] = file_sha256(arguments.config)
    except Exception as exc:
        result = _failure(exc, node.active_gate if node is not None else "startup")
        if node is not None:
            observed_motion = any(
                abs(sample.x) > 1e-4 or abs(sample.y) > 1e-4 or abs(sample.yaw) > 1e-4
                for sample in (*node.commands, *node.applied_commands)
            )
            result["simulated_motion"] = observed_motion
            result["metrics"].update(
                {
                    "command_samples": len(node.commands),
                    "applied_command_samples": len(node.applied_commands),
                    "path_pose_count": node.path_pose_count,
                    "max_scene_collision_count": node.max_scene_collision_count,
                    "collision_sample_count": len(node.collision_stamps_ns),
                }
            )
    finally:
        if node is not None:
            node.destroy_node()
        if initialized and rclpy.ok():
            rclpy.shutdown()
    _write_json(arguments.output.resolve(), result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
