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

    assert "source /opt/ros/humble/setup.bash" in text
    assert "set +u\nsource /opt/ros/humble/setup.bash\nset -u" in text
    assert "export ROS_DOMAIN_ID=77" in text
    assert "export ROS_LOCALHOST_ONLY=1" in text
    assert "export ROS2CLI_DISABLE_DAEMON=1" in text
    assert "export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" in text
    assert "export MUJOCO_GL=egl" in text
    assert "HOLOAGENT_STAGE1_RMW_OVERLAY" in text
    assert 'export ROS_LOG_DIR="${run_dir}/ros_logs"' in text
    assert 'lib/x86_64-linux-gnu' in text


def test_cleanup_targets_only_recorded_bridge_pid():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "bridge_pid=$!" in text
    assert "evaluator_pid=$!" in text
    assert 'stop_recorded_pid "${bridge_pid}"' in text
    assert 'stop_recorded_pid "${evaluator_pid}"' in text
    assert 'kill -INT "${pid}"' in text
    assert "pkill" not in text
    assert "killall" not in text
    assert "jobs -p" not in text


def test_launcher_gates_graph_before_evaluator_can_publish_motion():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    ready_line = next(index for index, line in enumerate(lines) if "ready_file=" in line)
    graph_line = next(index for index, line in enumerate(lines) if "--graph-only" in line)
    approval_line = next(
        index for index, line in enumerate(lines) if '"${ready_digest}" >' in line
    )

    assert ready_line < graph_line < approval_line


def test_launcher_records_bounded_postflight_cleanup_evidence():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "for _attempt in {1..150}" in text
    assert "--postflight" in text
    assert "--result-file" in text
    assert "--final-result-file" in text
    assert '--evaluator-exit-status "${evaluation_status}"' in text
    assert 'result.pending.json' in text
    assert '"${run_dir}/postflight.log"' in text
    assert "postflight_status=$?" in text
    assert "if [[ ${postflight_status} -ne 0 ]]" in text
    assert 'postflight.log" 2>&1 || true' not in text


def test_launcher_contains_no_physical_robot_or_pc2_target():
    text = SCRIPT.read_text(encoding="utf-8").lower()

    assert "ssh " not in text
    assert "pc2" not in text
    assert "g1_pubvel_node" not in text
    assert "g1_pubmove_node" not in text
    assert "g1_pubcmd_node" not in text
