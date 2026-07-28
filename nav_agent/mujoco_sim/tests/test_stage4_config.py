from pathlib import Path

from holoagent_mujoco.stage4_config import load_stage4_config


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_stage4_config_is_explicit_sim_fixture_and_sim_map_contract():
    config = load_stage4_config(PACKAGE_ROOT / "config" / "stage4.yaml")

    assert config.bridge.frames.map == config.map.frame_id == "sim_map"
    assert config.map.resolution_m == 0.05
    assert config.map.inflation_radius_m == 0.45
    assert config.query_topic == "/sim_fixture/query"
    assert config.output_topic == "/object_pose"
    assert tuple(config.fixtures) == ("go to the blue chair",)
    assert config.fixtures["go to the blue chair"].x == 1.25
    assert config.nav2_params.name == "stage4_nav2.yaml"
    assert config.behavior_tree.name == "stage4_navigate_to_pose.xml"
    assert (
        config.behavior_tree_through_poses.name == "stage4_navigate_through_poses.xml"
    )
    assert all(path.is_absolute() for path in config.map.prohibited_real_map_paths)
    assert config.gates.goal_timeout_sim_sec == 90.0
