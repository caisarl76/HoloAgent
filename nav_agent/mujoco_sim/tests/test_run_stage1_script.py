from __future__ import annotations

from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage1.sh"


def test_launcher_has_valid_bash_syntax():
    result = subprocess.run(
        ["bash", "-n", str(SCRIPT)], text=True, capture_output=True, check=False
    )

    assert result.returncode == 0, result.stderr


def test_launcher_exports_exact_dds_isolation_contract():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "export ROS_DOMAIN_ID=77" in text
    assert "export ROS_LOCALHOST_ONLY=1" in text
    assert "export ROS2CLI_DISABLE_DAEMON=1" in text
    assert "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" in text
    assert "export MUJOCO_GL=egl" in text


def test_cleanup_targets_only_recorded_bridge_pid():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "bridge_pid=$!" in text
    assert 'kill -INT "${bridge_pid}"' in text
    assert "pkill" not in text
    assert "killall" not in text
    assert "jobs -p" not in text


def test_launcher_gates_graph_before_evaluator_can_publish_motion():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    graph_line = next(index for index, line in enumerate(lines) if "--graph-only" in line)
    evaluator_line = next(index for index, line in enumerate(lines) if "stage1_eval" in line)

    assert graph_line < evaluator_line


def test_launcher_contains_no_physical_robot_or_pc2_target():
    text = SCRIPT.read_text(encoding="utf-8").lower()

    assert "ssh " not in text
    assert "pc2" not in text
    assert "g1_pubvel_node" not in text
    assert "g1_pubmove_node" not in text
    assert "g1_pubcmd_node" not in text
