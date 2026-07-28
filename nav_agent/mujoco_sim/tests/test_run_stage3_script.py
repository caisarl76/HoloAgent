from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_stage3.sh"


def test_stage3_launcher_syntax_and_isolation():
    result = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    text = SCRIPT.read_text(encoding="utf-8")
    assert "export ROS_DOMAIN_ID=77" in text
    assert "export ROS_LOCALHOST_ONLY=1" in text
    assert "RMW_IMPLEMENTATION=rmw_cyclonedds_cpp" in text
    assert "holoagent-stages234" in text


def test_stage3_graph_serialization_uses_the_same_c_locale_on_both_sides():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "export LC_ALL=C" in text
    assert "--env LC_ALL=C" in text
    assert "ros2 action list -t | sort" in text


def test_stage3_launcher_isolates_perfect_odom_and_gates_before_motion():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "-r /robot_odom:=/stage3/unused_robot_odom" in text
    assert "stage3_graph_ready.json" in text
    assert "stage3_graph_approved.sha256" in text
    assert "graph_preflight.log" in text
    assert "result.pending.json" in text and "result.json" in text


def test_stage3_launcher_builds_fastlivo_from_a_unique_clean_source_overlay():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "holoagent-stage3-build-20260724" not in text
    assert 'stage3_build_root="/tmp/holoagent-stage3-build-${run_id}"' in text
    assert 'stage3_source_root="/tmp/holoagent-stage3-source-${run_id}"' in text
    assert "cp -a ${container_root}/agentic_robot/core/src/fast_livo" in text
    assert "patch -p1 --batch --forward" in text
    assert "--packages-select vikit_common vikit_ros" in text
    assert "--packages-select fast_livo" in text
    assert "holoagent_mujoco.stage3_build" in text
    assert "stage3_build_manifest.json" in text


def test_stage3_cleanup_uses_only_recorded_exact_pids():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "fastlivo.container.pid" in text
    assert "evaluator.container.pid" in text
    assert 'kill -"${signal}" "${pid}"' in text
    assert "pkill" not in text
    assert "killall" not in text
    assert "jobs -p" not in text


def test_stage3_launcher_has_no_physical_or_remote_target():
    text = SCRIPT.read_text(encoding="utf-8").lower()
    assert "ssh " not in text
    assert "pc2" not in text
    assert "g1_pubvel_node" not in text
    assert "g1_pubmove_node" not in text
    assert "g1_pubcmd_node" not in text
