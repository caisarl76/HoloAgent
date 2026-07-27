from __future__ import annotations

import pytest

from holoagent_mujoco.preflight import PARAMETER_SERVICE_TYPES, PreflightError
from holoagent_mujoco.stage3_result import (
    EXPECTED_NODES,
    STAGE3_TOPIC_TYPES,
    validate_evaluator_status,
    validate_stage3_graph,
)


def _snapshot() -> str:
    lines = ["=== NODES ===", *EXPECTED_NODES, "=== TOPICS ==="]
    lines.extend(f"{name} [{kind}]" for name, kind in STAGE3_TOPIC_TYPES.items())
    lines.append("=== SERVICES ===")
    lines.extend(
        f"{node}/{name} [{kind}]"
        for node in EXPECTED_NODES
        for name, kind in PARAMETER_SERVICE_TYPES.items()
    )
    lines.extend(["/fast_livo/save_map [fast_livo/srv/SaveMap]", "=== ACTIONS ==="])
    return "\n".join(lines) + "\n"


def test_stage3_graph_is_exact_and_host_container_identical():
    result = validate_stage3_graph(_snapshot(), _snapshot())
    assert result["nodes"] == list(EXPECTED_NODES)
    assert result["topics"] == STAGE3_TOPIC_TYPES


def test_stage3_graph_includes_observed_image_transport_endpoints():
    for image_topic in ("/depth_img", "/overlay_img", "/rgb_img"):
        assert STAGE3_TOPIC_TYPES[f"{image_topic}/compressed"] == (
            "sensor_msgs/msg/CompressedImage"
        )
        assert STAGE3_TOPIC_TYPES[f"{image_topic}/compressedDepth"] == (
            "sensor_msgs/msg/CompressedImage"
        )
        assert STAGE3_TOPIC_TYPES[f"{image_topic}/theora"] == (
            "theora_image_transport/msg/Packet"
        )


def test_stage3_graph_rejects_an_unexpected_motion_participant():
    altered = _snapshot().replace("=== TOPICS ===", "/g1_pubvel_node\n=== TOPICS ===")
    with pytest.raises(PreflightError, match="unexpected Stage 3 nodes"):
        validate_stage3_graph(altered, altered)


def test_failed_estimator_exit_one_is_preserved_for_nonblocking_stage4():
    validate_evaluator_status({"status": "FAIL", "label": "FAIL_ESTIMATOR"}, 1)
    with pytest.raises(PreflightError, match="exit one"):
        validate_evaluator_status({"status": "FAIL"}, 0)
