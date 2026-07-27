from rclpy.qos import ReliabilityPolicy

from holoagent_livox_converter.converter_node import (
    _declare_parameter_once,
    fast_livo_output_qos,
)


class FakeNode:
    def __init__(self, declared: set[str]) -> None:
        self.declared = set(declared)
        self.calls: list[tuple[str, object]] = []

    def has_parameter(self, name: str) -> bool:
        return name in self.declared

    def declare_parameter(self, name: str, default) -> None:
        self.calls.append((name, default))
        self.declared.add(name)


def test_parameter_override_is_not_declared_twice():
    node = FakeNode({"acquisition_mode"})

    _declare_parameter_once(node, "acquisition_mode", "snapshot")
    _declare_parameter_once(node, "min_finite_points", 2500)

    assert node.calls == [("min_finite_points", 2500)]


def test_fast_livo_output_qos_offers_reliable_delivery():
    assert fast_livo_output_qos().reliability == ReliabilityPolicy.RELIABLE
