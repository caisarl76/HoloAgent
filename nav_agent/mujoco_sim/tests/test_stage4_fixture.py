import pytest
from builtin_interfaces.msg import Time

from holoagent_mujoco.stage4_fixture import (
    fixture_pose_message,
    normalize_query,
    resolve_fixture,
)
from holoagent_mujoco.stage4_map import FixturePose


FIXTURES = {"go to the blue chair": FixturePose("go to the blue chair", 1.25, 0.0, 0.0)}


def test_fixture_query_is_fixed_normalized_and_sim_map_only():
    assert normalize_query("  Go   TO the BLUE chair  ") == "go to the blue chair"
    pose = resolve_fixture("  Go TO the blue chair ", FIXTURES)
    assert pose == FIXTURES["go to the blue chair"]

    with pytest.raises(KeyError, match="not in sim_fixture"):
        resolve_fixture("go to a real building object", FIXTURES)


def test_fixture_pose_message_is_finite_and_in_sim_map():
    message = fixture_pose_message(FIXTURES["go to the blue chair"], Time(sec=3))
    assert message.header.frame_id == "sim_map"
    assert message.header.stamp.sec == 3
    assert message.pose.position.x == 1.25
    assert message.pose.orientation.w == 1.0
