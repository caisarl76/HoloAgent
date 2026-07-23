from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
from typing import Any, Callable, Mapping

from holoagent_mujoco.config import Stage1Config, file_sha256, load_config


class PreflightError(RuntimeError):
    """Raised when Stage 1 isolation or runtime checks fail."""


Runner = Callable[..., Any]


def validate_isolation_environment(
    environment: Mapping[str, str], config: Stage1Config
) -> dict[str, str]:
    expected = {
        "ROS_DOMAIN_ID": str(config.runtime.ros_domain_id),
        "ROS_LOCALHOST_ONLY": "1" if config.runtime.ros_localhost_only else "0",
        "ROS2CLI_DISABLE_DAEMON": "1",
        "RMW_IMPLEMENTATION": config.runtime.rmw_implementation,
        "MUJOCO_GL": config.runtime.mujoco_gl,
    }
    for key, value in expected.items():
        if environment.get(key) != value:
            raise PreflightError(f"{key} must equal {value}")

    python_paths = {
        str(Path(value).expanduser().resolve())
        for value in environment.get("PYTHONPATH", "").split(os.pathsep)
        if value
    }
    required_paths = {
        str(path.resolve()) for path in config.runtime.extra_python_paths
    }
    if not required_paths.issubset(python_paths):
        missing = sorted(required_paths - python_paths)
        raise PreflightError(f"PYTHONPATH is missing required overlays: {missing}")

    forbidden_keys = {
        "PC2_HOST",
        "PC2_IP",
        "ROBOT_IP",
        "ROBOT_HOST",
        "UNITREE_INTERFACE",
        "UNITREE_IP",
        "G1_INTERFACE",
    }
    active_forbidden = sorted(
        key for key in forbidden_keys if str(environment.get(key, "")).strip()
    )
    if active_forbidden:
        raise PreflightError(
            f"physical-interface environment is forbidden: {active_forbidden}"
        )
    return expected


def validate_runtime_imports(
    config: Stage1Config,
    environment: Mapping[str, str],
    *,
    runner: Runner = subprocess.run,
) -> dict[str, Any]:
    probe = (
        "import json, mujoco, numpy, onnxruntime, rclpy, torch, yaml; "
        "print(json.dumps({'mujoco': mujoco.__version__, "
        "'numpy': numpy.__version__, 'onnxruntime': onnxruntime.__version__, "
        "'rclpy': rclpy.__file__, 'torch': torch.__version__}, sort_keys=True))"
    )
    result = runner(
        [str(config.runtime.python), "-c", probe],
        env=dict(environment),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise PreflightError(
            f"runtime import probe failed: {result.stderr.strip()}"
        )
    return {"stdout": result.stdout.strip(), "stderr": result.stderr.strip()}


def assert_no_forbidden_source(package: Path) -> None:
    root = Path(package).resolve()
    forbidden = ("unitree" + "_sdk2", "unitree" + "_sdk2py")
    violations = []
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if any(token in text for token in forbidden):
            violations.append(str(path.relative_to(root)))
    if violations:
        raise PreflightError(f"forbidden transport import in source: {violations}")


def scan_forbidden_processes(proc_root: Path = Path("/proc")) -> list[dict[str, Any]]:
    forbidden = {"g1_pubvel_node", "g1_pubmove_node", "g1_pubcmd_node"}
    found = []
    for directory in Path(proc_root).iterdir():
        if not directory.name.isdigit():
            continue
        try:
            command = (directory / "cmdline").read_bytes().split(b"\0", 1)[0]
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        executable = Path(command.decode("utf-8", errors="replace")).name
        if executable in forbidden:
            found.append({"pid": int(directory.name), "executable": executable})
    return sorted(found, key=lambda item: item["pid"])


def create_run_directory(path: Path) -> Path:
    destination = Path(path).expanduser().resolve()
    try:
        destination.mkdir(parents=False, exist_ok=False)
    except FileExistsError as exc:
        raise PreflightError(f"run directory already exists: {destination}") from exc
    except FileNotFoundError as exc:
        raise PreflightError(f"run directory parent does not exist: {destination.parent}") from exc
    return destination


def validate_container_inspect(payload: str, expected_name: str) -> dict[str, Any]:
    try:
        documents = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PreflightError("docker inspect returned invalid JSON") from exc
    if not isinstance(documents, list) or len(documents) != 1:
        raise PreflightError("docker inspect must return exactly one container")
    document = documents[0]
    actual_name = str(document.get("Name", "")).lstrip("/")
    if actual_name != expected_name:
        raise PreflightError(
            f"container name mismatch: expected {expected_name}, got {actual_name}"
        )
    if not bool(document.get("State", {}).get("Running")):
        raise PreflightError(f"container is not running: {expected_name}")
    host_config = document.get("HostConfig", {})
    network_mode = host_config.get("NetworkMode")
    ipc_mode = host_config.get("IpcMode")
    if network_mode != "host":
        raise PreflightError("container network mode must be host")
    if ipc_mode != "host":
        raise PreflightError("container IPC mode must be host")
    return {
        "name": actual_name,
        "running": True,
        "network_mode": network_mode,
        "ipc_mode": ipc_mode,
    }


def inspect_container(
    name: str, *, runner: Runner = subprocess.run
) -> dict[str, Any]:
    result = runner(
        ["docker", "inspect", name],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise PreflightError(f"docker inspect failed: {result.stderr.strip()}")
    return validate_container_inspect(result.stdout, name)


def graph_lists_match(host_output: str, container_output: str) -> list[str]:
    host = sorted(line.strip() for line in host_output.splitlines() if line.strip())
    container = sorted(
        line.strip() for line in container_output.splitlines() if line.strip()
    )
    if host != container:
        raise PreflightError(
            f"host and container ROS graphs differ: host={host}, container={container}"
        )
    expected = ["/holoagent_mujoco_bridge"]
    if host != expected:
        raise PreflightError(f"bridge-only graph expected, got: {host}")
    return host


def graph_snapshots_match(
    host_output: str,
    container_output: str,
    expected_nodes: tuple[str, ...],
) -> list[str]:
    host_lines = [line.rstrip() for line in host_output.splitlines() if line.strip()]
    container_lines = [
        line.rstrip() for line in container_output.splitlines() if line.strip()
    ]
    if host_lines != container_lines:
        raise PreflightError("host and container complete ROS graph snapshots differ")
    try:
        start = host_lines.index("=== NODES ===") + 1
        end = host_lines.index("=== TOPICS ===")
    except ValueError as exc:
        raise PreflightError("complete graph snapshot markers are missing") from exc
    nodes = sorted(host_lines[start:end])
    expected = sorted(expected_nodes)
    if nodes != expected:
        raise PreflightError(f"expected active nodes {expected}, got {nodes}")
    for marker in ("=== SERVICES ===", "=== ACTIONS ===", "=== ENDPOINTS ==="):
        if marker not in host_lines:
            raise PreflightError(f"complete graph snapshot missing {marker}")
    return nodes


def capture_graph_parity(
    container: str,
    environment: Mapping[str, str],
    *,
    runner: Runner = subprocess.run,
    timeout_sec: float = 10.0,
    expected_nodes: tuple[str, ...] = ("/holoagent_mujoco_bridge",),
) -> dict[str, Any]:
    docker_environment = [
        "--env",
        f"ROS_DOMAIN_ID={environment['ROS_DOMAIN_ID']}",
        "--env",
        f"ROS_LOCALHOST_ONLY={environment['ROS_LOCALHOST_ONLY']}",
        "--env",
        f"ROS2CLI_DISABLE_DAEMON={environment['ROS2CLI_DISABLE_DAEMON']}",
        "--env",
        f"RMW_IMPLEMENTATION={environment['RMW_IMPLEMENTATION']}",
    ]
    deadline = time.monotonic() + timeout_sec
    endpoint_commands = " && ".join(
        f"ros2 node info {shlex.quote(node)}" for node in expected_nodes
    )
    graph_command = (
        "printf '=== NODES ===\\n' && ros2 node list && "
        "printf '=== TOPICS ===\\n' && ros2 topic list -t && "
        "printf '=== SERVICES ===\\n' && ros2 service list -t && "
        "printf '=== ACTIONS ===\\n' && ros2 action list -t && "
        f"printf '=== ENDPOINTS ===\\n' && {endpoint_commands}"
    )
    last_error = "graph discovery did not run"
    while time.monotonic() < deadline:
        host = runner(
            ["bash", "-lc", "source /opt/ros/humble/setup.bash && " + graph_command],
            env=dict(environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        guest = runner(
            [
                "docker",
                "exec",
                *docker_environment,
                container,
                "bash",
                "-lc",
                "source /opt/ros/humble/setup.bash && "
                "ros2 pkg prefix rmw_cyclonedds_cpp >/dev/null && "
                + graph_command,
            ],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        if host.returncode == 0 and guest.returncode == 0:
            try:
                nodes = graph_snapshots_match(
                    host.stdout, guest.stdout, expected_nodes
                )
                return {
                    "nodes": nodes,
                    "host_output": host.stdout,
                    "container_output": guest.stdout,
                }
            except PreflightError as exc:
                last_error = str(exc)
        else:
            last_error = (
                f"host rc={host.returncode} stderr={host.stderr.strip()}; "
                f"container rc={guest.returncode} stderr={guest.stderr.strip()}"
            )
        time.sleep(0.2)
    raise PreflightError(f"graph parity check failed: {last_error}")


def artifact_evidence(config: Stage1Config) -> dict[str, dict[str, str]]:
    paths = {
        "runner": config.backend.runner,
        "config_yaml": config.backend.config_yaml,
        "xml": config.backend.xml,
        "balance_policy": config.backend.balance_policy,
        "walk_policy": config.backend.walk_policy,
    }
    expected = dict(config.backend.expected_sha256)
    return {
        name: {
            "path": str(path),
            "expected_sha256": expected.get(name, "unpinned"),
            "actual_sha256": file_sha256(path),
        }
        for name, path in paths.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Stage 1 preflight")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--container", default="holoagent_running")
    parser.add_argument("--graph-only", action="store_true")
    parser.add_argument("--postflight", action="store_true")
    parser.add_argument("--expected-node", action="append", default=[])
    parser.add_argument("--bridge-pid", type=int)
    parser.add_argument("--evaluator-pid", type=int)
    arguments = parser.parse_args(argv)
    run_dir = arguments.run_dir.expanduser().resolve()
    result: dict[str, Any]
    try:
        if arguments.graph_only or arguments.postflight:
            if not run_dir.is_dir():
                raise PreflightError(f"run directory does not exist: {run_dir}")
        else:
            create_run_directory(run_dir)
        config = load_config(arguments.config)
        isolation = validate_isolation_environment(os.environ, config)
        if arguments.postflight:
            processes = scan_forbidden_processes()
            if processes:
                raise PreflightError(
                    f"physical motion executables are running: {processes}"
                )
            pids = {
                "bridge": arguments.bridge_pid,
                "evaluator": arguments.evaluator_pid,
            }
            alive = {
                name: pid
                for name, pid in pids.items()
                if pid is not None and Path(f"/proc/{pid}").exists()
            }
            if alive:
                raise PreflightError(f"Stage 1 child PIDs remain alive: {alive}")
            result = {
                "status": "PASS",
                "gate": "postflight",
                "isolation": isolation,
                "child_pids": pids,
                "forbidden_processes": processes,
            }
            _write_json(run_dir / "postflight.json", result)
        elif arguments.graph_only:
            container = inspect_container(arguments.container)
            processes = scan_forbidden_processes()
            if processes:
                raise PreflightError(
                    f"physical motion executables are running: {processes}"
                )
            expected_nodes = tuple(
                arguments.expected_node
                or ["/holoagent_mujoco_bridge"]
            )
            graph = capture_graph_parity(
                arguments.container,
                os.environ,
                expected_nodes=expected_nodes,
            )
            (run_dir / "host_graph.txt").write_text(
                graph["host_output"], encoding="utf-8"
            )
            (run_dir / "container_graph.txt").write_text(
                graph["container_output"], encoding="utf-8"
            )
            result = {
                "status": "PASS",
                "gate": "graph_parity",
                "isolation": isolation,
                "container": container,
                "nodes": graph["nodes"],
                "forbidden_processes": processes,
            }
            _write_json(run_dir / "graph_preflight.json", result)
        else:
            container = inspect_container(arguments.container)
            runtime = validate_runtime_imports(config, os.environ)
            assert_no_forbidden_source(Path(__file__).parent)
            processes = scan_forbidden_processes()
            if processes:
                raise PreflightError(
                    f"physical motion executables are running: {processes}"
                )
            result = {
                "status": "PASS",
                "gate": "initial_preflight",
                "isolation": isolation,
                "container": container,
                "runtime": runtime,
                "forbidden_processes": processes,
                "artifacts": artifact_evidence(config),
            }
            _write_json(run_dir / "preflight.json", result)
            _write_json(run_dir / "artifact_digests.json", result["artifacts"])
    except Exception as exc:
        result = {
            "status": "FAIL",
            "gate": (
                "postflight"
                if arguments.postflight
                else "graph_parity"
                if arguments.graph_only
                else "initial_preflight"
            ),
            "error": str(exc),
            "exception_type": type(exc).__name__,
        }
        if run_dir.is_dir():
            name = (
                "postflight.json"
                if arguments.postflight
                else "graph_preflight.json"
                if arguments.graph_only
                else "preflight.json"
            )
            _write_json(run_dir / name, result)
        print(json.dumps(result, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
