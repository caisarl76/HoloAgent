from __future__ import annotations

from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage2.sh"


def test_stage2_launcher_has_valid_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)], text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_stage2_launcher_is_localhost_only_and_uses_dedicated_container():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "export ROS_DOMAIN_ID=77" in text
    assert "export ROS_LOCALHOST_ONLY=1" in text
    assert "export ROS2CLI_DISABLE_DAEMON=1" in text
    assert "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" in text
    assert "holoagent-stages234" in text
    assert "--workspace-source" in text


def test_stage2_launcher_records_exact_host_and_container_pids():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "bridge_pid=$!" in text
    assert "converter_host_pid=$!" in text
    assert "evaluator_host_pid=$!" in text
    assert "converter.container.pid" in text
    assert "evaluator.container.pid" in text
    assert "for signal in INT TERM KILL" in text
    assert 'kill -"${signal}" "${pid}"' in text
    assert "pkill" not in text
    assert "killall" not in text
    assert "jobs -p" not in text
    assert "exec ${build_root}/install/holoagent_livox_converter/lib/" in text
    assert "exec ros2 run" not in text


def test_stage2_launcher_graph_gates_measurement_and_promotes_atomically():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    ready = next(index for index, line in enumerate(lines) if "graph_ready.json" in line)
    graph = next(index for index, line in enumerate(lines) if "graph-host" in line)
    approval = next(
        index for index, line in enumerate(lines) if "graph_approved.sha256" in line
    )
    text = "\n".join(lines)
    assert ready < graph
    assert "result.pending.json" in text
    assert "result.json" in text
    assert "--postflight" in text
    assert "--evaluator-exit-status" in text
    assert approval < graph  # path declaration precedes external graph gate
    assert "ros2 action list -t | sort" in text
    assert "ros2 daemon stop" in text
    assert text.count("stop_cli_daemons") >= 3
    assert text.rindex("stop_cli_daemons") < text.index("ready_digest=")


def test_stage2_launcher_contains_no_robot_or_remote_target():
    text = SCRIPT.read_text(encoding="utf-8").lower()
    assert "ssh " not in text
    assert "pc2" not in text
    assert "g1_pubvel_node" not in text
    assert "g1_pubmove_node" not in text
    assert "g1_pubcmd_node" not in text
