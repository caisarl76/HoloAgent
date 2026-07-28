from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from holoagent_mujoco.config import load_config
from holoagent_mujoco.preflight import (
    PARAMETER_SERVICE_TYPES,
    PreflightError,
    assert_evaluator_exit_status,
    assert_no_forbidden_source,
    merge_postflight_result,
    scan_forbidden_processes,
    validate_isolation_environment,
)
from holoagent_mujoco.stage2_result_topics import STAGE2_TOPIC_TYPES


EXPECTED_NODES = (
    "/holoagent_livox_converter",
    "/holoagent_mujoco_bridge",
    "/holoagent_stage2_eval",
)


def collect_source_provenance(
    workspace_source: Path,
    container: dict[str, Any],
    *,
    runner: Any = subprocess.run,
) -> dict[str, Any]:
    workspace = Path(workspace_source).expanduser().resolve()

    def git(*arguments: str) -> str:
        result = runner(
            ["git", "-C", str(workspace), *arguments],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if result.returncode != 0:
            raise PreflightError(
                f"cannot collect source provenance ({' '.join(arguments)}): "
                f"{result.stderr.strip()}"
            )
        return result.stdout

    commit = git("rev-parse", "HEAD").strip()
    tree = git("rev-parse", "HEAD^{tree}").strip()
    if not all(
        len(value) == 40 and all(character in "0123456789abcdef" for character in value)
        for value in (commit, tree)
    ):
        raise PreflightError("source commit/tree provenance is malformed")
    status = git("status", "--porcelain", "--untracked-files=no")
    dirty = bool(status.strip())
    diff_sha256 = None
    if dirty:
        diff = git("diff", "--binary", "--no-ext-diff", "HEAD", "--")
        diff_sha256 = hashlib.sha256(diff.encode("utf-8")).hexdigest()
    return {
        "source_commit": commit,
        "source_tree": tree,
        "tracked_worktree_dirty": dirty,
        "tracked_diff_sha256": diff_sha256,
        "workspace_source": str(workspace),
        "container_id": container.get("id"),
        "container_image_id": container.get("image_id"),
    }


def validate_container_contract(
    payload: str, *, expected_name: str, expected_source: Path
) -> dict[str, Any]:
    try:
        documents = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PreflightError("docker inspect returned invalid JSON") from exc
    if not isinstance(documents, list) or len(documents) != 1:
        raise PreflightError("docker inspect must return one container")
    document = documents[0]
    if str(document.get("Name", "")).lstrip("/") != expected_name:
        raise PreflightError("container name mismatch")
    if not document.get("State", {}).get("Running"):
        raise PreflightError("container is not running")
    host = document.get("HostConfig", {})
    if host.get("NetworkMode") != "host" or host.get("IpcMode") != "host":
        raise PreflightError("container must use host network and IPC")
    if host.get("Privileged") or host.get("Devices"):
        raise PreflightError("privileged mode and host devices are forbidden")
    mounts = document.get("Mounts", [])
    workspace = [
        mount
        for mount in mounts
        if mount.get("Destination") == "/workspace/HoloAgent"
    ]
    if len(workspace) != 1:
        raise PreflightError("exactly one workspace bind is required")
    mount = workspace[0]
    if (
        mount.get("Type") != "bind"
        or Path(str(mount.get("Source", ""))).resolve() != expected_source.resolve()
        or not mount.get("RW")
    ):
        raise PreflightError("workspace bind source or mode mismatch")
    environment = {
        item.split("=", 1)[0]: item.split("=", 1)[1]
        for item in document.get("Config", {}).get("Env", [])
        if "=" in item
    }
    required_environment = {
        "ROS_DOMAIN_ID": "77",
        "ROS_LOCALHOST_ONLY": "1",
        "ROS2CLI_DISABLE_DAEMON": "1",
    }
    if any(environment.get(key) != value for key, value in required_environment.items()):
        raise PreflightError("container DDS environment mismatch")
    return {
        "name": expected_name,
        "id": document.get("Id"),
        "image_id": document.get("Image"),
        "workspace_source": str(expected_source.resolve()),
        "network_mode": "host",
        "ipc_mode": "host",
        "privileged": False,
        "devices": [],
    }


def validate_graph_parity(host: str, container: str) -> dict[str, Any]:
    if host != container:
        raise PreflightError("host and container graph snapshots differ")
    sections = _parse_snapshot(host)
    if tuple(sorted(sections["nodes"])) != EXPECTED_NODES:
        raise PreflightError(f"unexpected nodes: {sections['nodes']}")
    topics = _typed_lines(sections["topics"])
    if topics != STAGE2_TOPIC_TYPES:
        raise PreflightError("topic/type allowlist mismatch")
    services = _typed_lines(sections["services"])
    expected_services = {
        f"{node}/{name}": service_type
        for node in EXPECTED_NODES
        for name, service_type in PARAMETER_SERVICE_TYPES.items()
    }
    if services != expected_services:
        raise PreflightError("service allowlist mismatch")
    if sections["actions"]:
        raise PreflightError("action endpoints are forbidden in Stage 2")
    return {
        "nodes": list(EXPECTED_NODES),
        "topics": topics,
        "services": services,
        "actions": [],
    }


def _parse_snapshot(text: str) -> dict[str, list[str]]:
    markers = {
        "=== NODES ===": "nodes",
        "=== TOPICS ===": "topics",
        "=== SERVICES ===": "services",
        "=== ACTIONS ===": "actions",
    }
    sections = {name: [] for name in markers.values()}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line in markers:
            current = markers[line]
        elif line and current is not None:
            sections[current].append(line)
    if current != "actions":
        raise PreflightError("graph snapshot markers are incomplete")
    return sections


def _typed_lines(lines: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not parts[1].startswith("[") or not parts[1].endswith("]"):
            raise PreflightError(f"invalid typed graph line: {line}")
        result[parts[0]] = parts[1][1:-1]
    return result


def _docker_inspect(container: str) -> str:
    result = subprocess.run(
        ["docker", "inspect", container],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise PreflightError(f"docker inspect failed: {result.stderr.strip()}")
    return result.stdout


def _pid_alive(pid: int | None) -> bool:
    return bool(pid and Path(f"/proc/{pid}").exists())


def _container_pid_alive(container: str, pid: int | None) -> bool:
    if not pid:
        return False
    result = subprocess.run(
        ["docker", "exec", container, "kill", "-0", str(pid)],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    return result.returncode == 0


def parse_container_stage_processes(output: str) -> list[dict[str, Any]]:
    found = []
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        command = parts[1]
        if any(
            token in command
            for token in (
                "/holoagent_livox_converter/livox_converter",
                "/holoagent_livox_converter/stage2_eval",
                "/holoagent_livox_converter/stage3_eval",
                "/fast_livo/fastlivo_mapping",
                "ros2 run holoagent_livox_converter livox_converter",
                "ros2 run holoagent_livox_converter stage2_eval",
                "ros2 run holoagent_livox_converter stage3_eval",
                "ros2 run fast_livo fastlivo_mapping",
            )
        ):
            found.append({"pid": int(parts[0]), "command": command})
    return found


def _container_stage_processes(container: str) -> list[dict[str, Any]]:
    result = subprocess.run(
        ["docker", "exec", container, "ps", "-eo", "pid=,args="],
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise PreflightError("cannot inspect container process table")
    return parse_container_stage_processes(result.stdout)


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stage 2 preflight/finalizer")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--workspace-source", type=Path, required=True)
    parser.add_argument("--graph-host", type=Path)
    parser.add_argument("--graph-container", type=Path)
    parser.add_argument("--postflight", action="store_true")
    parser.add_argument("--host-pid", action="append", type=int, default=[])
    parser.add_argument("--container-pid", action="append", type=int, default=[])
    parser.add_argument("--evaluator-exit-status", type=int)
    parser.add_argument("--result-file", type=Path)
    parser.add_argument("--final-result-file", type=Path)
    args = parser.parse_args(argv)
    run_dir = args.run_dir.resolve()
    try:
        config = load_config(args.config)
        validate_isolation_environment(os.environ, config)
        if not config.lidar.enabled:
            raise PreflightError("Stage 2 requires lidar.enabled=true")
        container = validate_container_contract(
            _docker_inspect(args.container),
            expected_name=args.container,
            expected_source=args.workspace_source,
        )
        forbidden = scan_forbidden_processes()
        if forbidden:
            raise PreflightError(f"physical motion processes are running: {forbidden}")
        if args.postflight:
            alive_host = [pid for pid in args.host_pid if _pid_alive(pid)]
            alive_container = [
                pid
                for pid in args.container_pid
                if _container_pid_alive(args.container, pid)
            ]
            if alive_host or alive_container:
                raise PreflightError(
                    f"Stage 2 PIDs remain alive: host={alive_host}, container={alive_container}"
                )
            remnants = _container_stage_processes(args.container)
            if remnants:
                raise PreflightError(f"Stage 2 container processes remain: {remnants}")
            assert_evaluator_exit_status(args.evaluator_exit_status)
            if args.result_file is None or args.final_result_file is None:
                raise PreflightError("postflight result paths are required")
            result = {
                "status": "PASS",
                "gate": "postflight",
                "container": container,
                "provenance": collect_source_provenance(
                    args.workspace_source, container
                ),
                "host_pids": args.host_pid,
                "container_pids": args.container_pid,
                "forbidden_processes": forbidden,
            }
            _write_json(run_dir / "postflight.json", result)
            merge_postflight_result(
                args.result_file, result, final_path=args.final_result_file
            )
        elif args.graph_host and args.graph_container:
            graph = validate_graph_parity(
                args.graph_host.read_text(encoding="utf-8"),
                args.graph_container.read_text(encoding="utf-8"),
            )
            result = {"status": "PASS", "gate": "graph", "graph": graph}
            _write_json(run_dir / "graph_preflight.json", result)
        else:
            if run_dir.exists():
                raise PreflightError("run directory already exists")
            run_dir.mkdir()
            (run_dir / "ros_logs").mkdir()
            assert_no_forbidden_source(Path(__file__).parent)
            remnants = _container_stage_processes(args.container)
            if remnants:
                raise PreflightError(f"stale Stage 2 container processes: {remnants}")
            result = {
                "status": "PASS",
                "gate": "initial_preflight",
                "container": container,
                "forbidden_processes": forbidden,
            }
            _write_json(run_dir / "preflight.json", result)
    except Exception as exc:
        if run_dir.is_dir():
            result = {
                "status": "FAIL",
                "error": str(exc),
                "exception_type": type(exc).__name__,
            }
            _write_json(run_dir / "stage2_result_error.json", result)
        print(str(exc))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
