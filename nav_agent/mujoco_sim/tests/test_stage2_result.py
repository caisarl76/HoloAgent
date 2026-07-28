from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from holoagent_mujoco.preflight import PARAMETER_SERVICE_TYPES, PreflightError
from holoagent_mujoco.stage2_result import (
    EXPECTED_NODES,
    collect_source_provenance,
    parse_container_stage_processes,
    validate_container_contract,
    validate_graph_parity,
)
from holoagent_mujoco.stage2_result_topics import STAGE2_TOPIC_TYPES


def _container(source: Path) -> str:
    return json.dumps(
        [
            {
                "Name": "/holoagent-stages234",
                "Id": "container-id",
                "Image": "sha256:image-id",
                "State": {"Running": True},
                "HostConfig": {
                    "NetworkMode": "host",
                    "IpcMode": "host",
                    "Privileged": False,
                    "Devices": [],
                },
                "Mounts": [
                    {
                        "Type": "bind",
                        "Source": str(source),
                        "Destination": "/workspace/HoloAgent",
                        "RW": True,
                    }
                ],
                "Config": {
                    "Env": [
                        "ROS_DOMAIN_ID=77",
                        "ROS_LOCALHOST_ONLY=1",
                        "ROS2CLI_DISABLE_DAEMON=1",
                    ]
                },
            }
        ]
    )


def test_container_contract_requires_exact_worktree_and_no_devices(tmp_path):
    result = validate_container_contract(
        _container(tmp_path),
        expected_name="holoagent-stages234",
        expected_source=tmp_path,
    )
    assert result["workspace_source"] == str(tmp_path.resolve())
    assert result["devices"] == []
    assert result["privileged"] is False


def test_container_contract_rejects_wrong_mount(tmp_path):
    with pytest.raises(PreflightError, match="workspace bind"):
        validate_container_contract(
            _container(tmp_path / "other"),
            expected_name="holoagent-stages234",
            expected_source=tmp_path,
        )


def _snapshot() -> str:
    lines = ["=== NODES ===", *EXPECTED_NODES, "=== TOPICS ==="]
    lines.extend(f"{name} [{kind}]" for name, kind in STAGE2_TOPIC_TYPES.items())
    lines.append("=== SERVICES ===")
    lines.extend(
        f"{node}/{name} [{kind}]"
        for node in EXPECTED_NODES
        for name, kind in PARAMETER_SERVICE_TYPES.items()
    )
    lines.append("=== ACTIONS ===")
    return "\n".join(lines) + "\n"


def test_graph_parity_requires_exact_nodes_topics_services_and_no_actions():
    snapshot = _snapshot()
    result = validate_graph_parity(snapshot, snapshot)
    assert result["nodes"] == list(EXPECTED_NODES)
    assert result["topics"] == STAGE2_TOPIC_TYPES
    assert result["actions"] == []


def test_graph_parity_rejects_host_container_difference():
    with pytest.raises(PreflightError, match="differ"):
        validate_graph_parity(_snapshot(), _snapshot() + "/foreign\n")


def test_container_process_parser_finds_wrappers_and_direct_nodes():
    output = """\
1224 /usr/bin/python3 /opt/ros/humble/bin/ros2 run holoagent_livox_converter livox_converter
1363 /usr/bin/python3 /tmp/run/install/holoagent_livox_converter/lib/holoagent_livox_converter/livox_converter
1400 /bin/sleep infinity
"""
    assert [item["pid"] for item in parse_container_stage_processes(output)] == [
        1224,
        1363,
    ]


def test_source_provenance_records_commit_tree_cleanliness_and_container(tmp_path):
    responses = {
        ("rev-parse", "HEAD"): "a" * 40 + "\n",
        ("rev-parse", "HEAD^{tree}"): "b" * 40 + "\n",
        ("status", "--porcelain", "--untracked-files=no"): "",
    }

    def runner(command, **kwargs):
        key = tuple(command[3:])
        return subprocess.CompletedProcess(command, 0, responses[key], "")

    evidence = collect_source_provenance(
        tmp_path,
        {
            "id": "container-id",
            "image_id": "sha256:image-id",
            "workspace_source": str(tmp_path),
        },
        runner=runner,
    )

    assert evidence == {
        "source_commit": "a" * 40,
        "source_tree": "b" * 40,
        "tracked_worktree_dirty": False,
        "tracked_diff_sha256": None,
        "workspace_source": str(tmp_path.resolve()),
        "container_id": "container-id",
        "container_image_id": "sha256:image-id",
    }
