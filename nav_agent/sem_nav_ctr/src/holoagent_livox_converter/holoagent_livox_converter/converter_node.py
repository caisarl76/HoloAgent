from __future__ import annotations

from livox_ros_driver2.msg import CustomMsg, CustomPoint
import rclpy
from rclpy.node import Node
from rclpy.parameter import Parameter
from rclpy.qos import qos_profile_sensor_data
from sensor_msgs.msg import PointCloud2

from holoagent_livox_converter.converter_core import (
    ConversionOptions,
    decode_pointcloud,
)


class LivoxConverterNode(Node):
    def __init__(self) -> None:
        super().__init__(
            "holoagent_livox_converter",
            parameter_overrides=[Parameter("use_sim_time", Parameter.Type.BOOL, True)],
            automatically_declare_parameters_from_overrides=True,
        )
        if not self.get_parameter("use_sim_time").value:
            raise RuntimeError("Livox converter must use simulated time")
        for name, default in (
            ("input_topic", "/holoagent_sim/lidar_points"),
            ("output_topic", "/livox/lidar"),
            ("acquisition_mode", "snapshot"),
            ("scan_period_ns", 100_000_000),
            ("min_finite_points", 2500),
            ("noise_std_m", 0.0),
            ("dropout_probability", 0.0),
            ("random_seed", 7),
            ("reflectivity_override", -1),
            ("tag_override", -1),
            ("line_override", -1),
        ):
            _declare_parameter_once(self, name, default)
        self._options = ConversionOptions(
            acquisition_mode=str(self.get_parameter("acquisition_mode").value),
            scan_period_ns=int(self.get_parameter("scan_period_ns").value),
            min_finite_points=int(self.get_parameter("min_finite_points").value),
            noise_std_m=float(self.get_parameter("noise_std_m").value),
            dropout_probability=float(self.get_parameter("dropout_probability").value),
            random_seed=int(self.get_parameter("random_seed").value),
            reflectivity_override=_optional_uint8(
                self.get_parameter("reflectivity_override").value
            ),
            tag_override=_optional_uint8(self.get_parameter("tag_override").value),
            line_override=_optional_uint8(self.get_parameter("line_override").value),
        )
        self._publisher = self.create_publisher(
            CustomMsg,
            str(self.get_parameter("output_topic").value),
            qos_profile_sensor_data,
        )
        self._subscription = self.create_subscription(
            PointCloud2,
            str(self.get_parameter("input_topic").value),
            self._convert,
            qos_profile_sensor_data,
        )

    def _convert(self, message: PointCloud2) -> None:
        cloud = decode_pointcloud(message, self._options)
        output = CustomMsg()
        output.header = message.header
        output.timebase = cloud.timebase
        output.point_num = cloud.point_num
        output.lidar_id = 0
        output.rsvd = [0, 0, 0]
        points = []
        for index in range(cloud.point_num):
            point = CustomPoint()
            point.offset_time = int(cloud.offset_time[index])
            point.x = float(cloud.xyz[index, 0])
            point.y = float(cloud.xyz[index, 1])
            point.z = float(cloud.xyz[index, 2])
            point.reflectivity = int(cloud.reflectivity[index])
            point.tag = int(cloud.tags[index])
            point.line = int(cloud.lines[index])
            points.append(point)
        output.points = points
        self._publisher.publish(output)


def _optional_uint8(value) -> int | None:
    parsed = int(value)
    return None if parsed < 0 else parsed


def _declare_parameter_once(node, name: str, default) -> None:
    if not node.has_parameter(name):
        node.declare_parameter(name, default)


def main(args: list[str] | None = None) -> None:
    rclpy.init(args=args)
    node = LivoxConverterNode()
    try:
        rclpy.spin(node)
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == "__main__":
    main()
