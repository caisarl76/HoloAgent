from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from holoagent_mujoco.config import SceneConfig
from holoagent_mujoco.stage4_map import (
    FixturePose,
    MapContractError,
    generate_sim_map,
    validate_fixture_pose,
    verify_loaded_map,
)
from holoagent_mujoco.stage4_prepare import prepare_stage4


SCENE = SceneConfig(half_extent=4.0, wall_height=2.5, wall_thickness=0.10)


def test_sim_map_is_deterministic_005m_grid_from_known_scene(tmp_path):
    first = generate_sim_map(SCENE, tmp_path / "first", resolution_m=0.05)
    second = generate_sim_map(SCENE, tmp_path / "second", resolution_m=0.05)

    assert first.frame_id == "sim_map"
    assert first.width == first.height == 160
    assert first.origin_xy == (-4.0, -4.0)
    assert first.pgm_sha256 == second.pgm_sha256
    assert first.yaml_sha256 == second.yaml_sha256
    assert first.pgm_path.read_bytes() == second.pgm_path.read_bytes()
    assert first.yaml_path.read_bytes() == second.yaml_path.read_bytes()
    assert first.is_occupied(-2.5, 2.5)
    assert first.is_occupied(2.5, -2.5)
    assert not first.is_occupied(0.0, 0.0)


def test_fixture_must_be_inside_free_space_with_inflation_clearance(tmp_path):
    grid = generate_sim_map(SCENE, tmp_path, resolution_m=0.05)

    pose = FixturePose("go to the blue chair", 1.25, 0.0, 0.0)
    evidence = validate_fixture_pose(grid, pose, clearance_m=0.45)
    assert evidence["frame_id"] == "sim_map"
    assert evidence["clearance_m"] >= 0.45

    with pytest.raises(MapContractError, match="occupied"):
        validate_fixture_pose(
            grid,
            FixturePose("inside obstacle", -2.5, 2.5, 0.0),
            clearance_m=0.45,
        )
    with pytest.raises(MapContractError, match="clearance"):
        validate_fixture_pose(
            grid,
            FixturePose("too close", -2.0, 2.5, 0.0),
            clearance_m=0.45,
        )
    with pytest.raises(MapContractError, match="bounds"):
        validate_fixture_pose(
            grid,
            FixturePose("outside", 4.1, 0.0, 0.0),
            clearance_m=0.45,
        )


def test_loaded_map_is_allowlisted_by_exact_path_and_both_digests(tmp_path):
    grid = generate_sim_map(SCENE, tmp_path / "sim", resolution_m=0.05)
    verified = verify_loaded_map(
        grid.yaml_path,
        expected_yaml_path=grid.yaml_path,
        expected_yaml_sha256=grid.yaml_sha256,
        expected_pgm_sha256=grid.pgm_sha256,
        prohibited_real_map_paths=(
            Path("/mnt/data/jihun/HoloAgent/maps/fastlio_map.yaml"),
        ),
    )
    assert verified["yaml_sha256"] == grid.yaml_sha256
    assert verified["pgm_sha256"] == grid.pgm_sha256

    alternate = tmp_path / "fastlio_map.yaml"
    alternate.write_bytes(grid.yaml_path.read_bytes())
    with pytest.raises(MapContractError, match="exact generated sim_map path"):
        verify_loaded_map(
            alternate,
            expected_yaml_path=grid.yaml_path,
            expected_yaml_sha256=grid.yaml_sha256,
            expected_pgm_sha256=grid.pgm_sha256,
            prohibited_real_map_paths=(alternate,),
        )


def test_stage4_preparation_writes_a_self_consistent_manifest(tmp_path):
    config = Path(__file__).resolve().parents[1] / "config" / "stage4.yaml"
    evidence = prepare_stage4(config, tmp_path)

    assert evidence["map"]["source"] == "known_mujoco_scene_geometry"
    assert evidence["map"]["frame_id"] == "sim_map"
    assert evidence["fixtures"][0]["query"] == "go to the blue chair"
    assert evidence["nav2"]["all_use_sim_time"] is True
    assert (tmp_path / "stage4_manifest.json").is_file()


def test_stage4_manifest_can_name_the_bind_mounted_runtime_map(tmp_path):
    config = Path(__file__).resolve().parents[1] / "config" / "stage4.yaml"
    runtime_dir = Path("/workspace/HoloAgent/outputs/mujoco_holoagent/test-run")

    evidence = prepare_stage4(config, tmp_path, runtime_output_dir=runtime_dir)

    assert evidence["map"]["yaml_path"] == str(runtime_dir / "sim_map.yaml")
    assert evidence["map"]["pgm_path"] == str(runtime_dir / "sim_map.pgm")
    assert (tmp_path / "sim_map.yaml").is_file()
    runtime_params = yaml.safe_load(
        (tmp_path / "stage4_nav2_runtime.yaml").read_text(encoding="utf-8")
    )
    assert runtime_params["map_server"]["ros__parameters"]["yaml_filename"] == str(
        runtime_dir / "sim_map.yaml"
    )
    assert evidence["nav2"]["runtime_params_path"] == str(
        runtime_dir / "stage4_nav2_runtime.yaml"
    )
