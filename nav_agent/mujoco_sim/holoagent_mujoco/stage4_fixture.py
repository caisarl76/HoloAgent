from __future__ import annotations

import argparse
from collections.abc import Mapping
import math
from pathlib import Path

from builtin_interfaces.msg import Time
from geometry_msgs.msg import PoseStamped
import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
from std_msgs.msg import String

from holoagent_mujoco.stage4_map import FixturePose


def normalize_query(query: str) -> str:
    return " ".join(str(query).strip().lower().split())


def resolve_fixture(query: str, fixtures: Mapping[str, FixturePose]) -> FixturePose:
    normalized = normalize_query(query)
    normalized_fixtures = {
        normalize_query(name): pose for name, pose in fixtures.items()
    }
    try:
        return normalized_fixtures[normalized]
    except KeyError as exc:
        raise KeyError(f"query {query!r} is not in sim_fixture") from exc


def fixture_pose_message(pose: FixturePose, stamp: Time) -> PoseStamped:
    message = PoseStamped()
    message.header.stamp = stamp
    message.header.frame_id = "sim_map"
    message.pose.position.x = pose.x
    message.pose.position.y = pose.y
    message.pose.orientation.z = math.sin(pose.yaw / 2.0)
    message.pose.orientation.w = math.cos(pose.yaw / 2.0)
    return message


class Stage4FixtureNode(Node):
    def __init__(self, config_path: Path) -> None:
        from holoagent_mujoco.stage4_config import load_stage4_config

        super().__init__(
            "sim_fixture",
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
            automatically_declare_parameters_from_overrides=True,
        )
        if not self.get_parameter("use_sim_time").value:
            raise RuntimeError("sim_fixture must use simulated time")
        self.config = load_stage4_config(config_path, validate_bridge_artifacts=False)
        reliable = QoSProfile(depth=10, reliability=ReliabilityPolicy.RELIABLE)
        latched = QoSProfile(
            depth=1,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
        self._publisher = self.create_publisher(
            PoseStamped, self.config.output_topic, latched
        )
        self._subscription = self.create_subscription(
            String, self.config.query_topic, self._query_callback, reliable
        )

    def _query_callback(self, message: String) -> None:
        try:
            pose = resolve_fixture(message.data, self.config.fixtures)
        except KeyError as exc:
            self.get_logger().error(str(exc))
            return
        self._publisher.publish(
            fixture_pose_message(pose, self.get_clock().now().to_msg())
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 4 simulation-only fixture")
    parser.add_argument("--config", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    rclpy.init(args=ros_arguments)
    node = Stage4FixtureNode(arguments.config)
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
