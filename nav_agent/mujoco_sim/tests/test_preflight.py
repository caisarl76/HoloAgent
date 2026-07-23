from __future__ import annotations

import json
from pathlib import Path

import pytest

from holoagent_mujoco.config import load_config
from holoagent_mujoco.preflight import (
    PreflightError,
    assert_no_forbidden_source,
    create_run_directory,
    graph_lists_match,
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

