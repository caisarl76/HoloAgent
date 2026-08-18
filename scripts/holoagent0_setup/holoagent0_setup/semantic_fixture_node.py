"""Import-safe ROS fixture adapter for the exact offline semantic query."""

from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import time
from typing import Callable, Sequence

from .semantic_gate import (
    HMSGRetrievalAdapter,
    SemanticFixtureResult,
    SemanticGateError,
    StructuredQuery,
    evaluate_semantic_fixture,
    load_real_hmsg_adapter,
    validate_fixture_runtime_environment,
    verify_cyclone_roles,
)
from .source_gate import HandoverPaths


QUERY_TOPIC = "/holoagent0/semantic_fixture_query"
RESULT_TOPIC = "/object_pose"
NODE_NAME = "holoagent0_semantic_fixture"


class SemanticFixtureController:
    """Pure one-query/one-result controller used by the ROS shell."""

    def __init__(
        self,
        adapter: HMSGRetrievalAdapter,
        publish: Callable[[SemanticFixtureResult], None],
    ) -> None:
        self._adapter = adapter
        self._publish = publish
        self._handled = False

    def handle(self, payload: str) -> SemanticFixtureResult:
        if self._handled:
            raise SemanticGateError(
                "SEMANTIC_CARDINALITY_MISMATCH",
                "fixture cardinality requires exactly one structured query",
            )
        query = StructuredQuery.from_json(payload)
        self._handled = True
        result = evaluate_semantic_fixture(self._adapter, query)
        if result.query_text != query.text:
            raise SemanticGateError(
                "SEMANTIC_FIXTURE_MISMATCH", "result is not bound to the request"
            )
        self._publish(result)
        return result


def build_ros_node(adapter: HMSGRetrievalAdapter):
    """Build the ROS shell; all ROS imports remain behind this explicit call."""
    try:
        import rclpy  # noqa: F401
        from geometry_msgs.msg import PoseStamped
        from rclpy.node import Node
        from std_msgs.msg import String
    except ImportError as error:
        raise SemanticGateError("SEMANTIC_ROS_UNAVAILABLE", str(error)) from error

    class SemanticFixtureNode(Node):
        def __init__(self) -> None:
            super().__init__(NODE_NAME)
            self._publisher = self.create_publisher(PoseStamped, RESULT_TOPIC, 1)
            self._controller = SemanticFixtureController(adapter, self._publish_result)
            self._subscription = self.create_subscription(
                String, QUERY_TOPIC, self._receive_query, 1
            )
            self.fixture_complete = False
            self.fixture_error: SemanticGateError | None = None

        def _receive_query(self, message) -> None:
            try:
                self._controller.handle(message.data)
            except SemanticGateError as error:
                self.fixture_error = error
                self.get_logger().error(str(error))
            finally:
                self.fixture_complete = True

        def _publish_result(self, result: SemanticFixtureResult) -> None:
            message = PoseStamped()
            message.header.stamp = self.get_clock().now().to_msg()
            message.header.frame_id = result.frame_id
            (
                message.pose.position.x,
                message.pose.position.y,
                message.pose.position.z,
            ) = result.position
            (
                message.pose.orientation.x,
                message.pose.orientation.y,
                message.pose.orientation.z,
                message.pose.orientation.w,
            ) = result.orientation
            self._publisher.publish(message)

    return SemanticFixtureNode()


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run only when explicitly invoked by the coordinator-owned lifecycle."""
    arguments = _parse_arguments(argv)
    if (
        not math.isfinite(arguments.timeout_seconds)
        or arguments.timeout_seconds <= 0.0
        or arguments.timeout_seconds > 60.0
    ):
        raise SemanticGateError(
            "SEMANTIC_CARDINALITY_MISMATCH", "timeout must be in (0, 60] seconds"
        )
    paths = HandoverPaths.from_roots(
        arguments.repository_root,
        arguments.data_root,
    )
    cyclone = verify_cyclone_roles(paths.repository_root, paths.asset_lock)
    validate_fixture_runtime_environment(cyclone, os.environ)
    adapter = load_real_hmsg_adapter(paths, arguments.run_directory)
    try:
        import rclpy
    except ImportError as error:
        raise SemanticGateError("SEMANTIC_ROS_UNAVAILABLE", str(error)) from error
    node = None
    initialized = False
    try:
        rclpy.init(args=[])
        initialized = True
        node = build_ros_node(adapter)
        deadline = time.monotonic() + arguments.timeout_seconds
        while rclpy.ok() and not node.fixture_complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                raise SemanticGateError(
                    "SEMANTIC_CARDINALITY_MISMATCH",
                    "fixture did not receive exactly one query before timeout",
                )
            rclpy.spin_once(node, timeout_sec=min(0.1, remaining))
        if node.fixture_error is not None:
            raise node.fixture_error
        if not node.fixture_complete:
            raise SemanticGateError(
                "SEMANTIC_CARDINALITY_MISMATCH",
                "ROS context stopped before the fixture completed",
            )
    finally:
        try:
            if node is not None:
                node.destroy_node()
        finally:
            if initialized and rclpy.ok():
                rclpy.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
