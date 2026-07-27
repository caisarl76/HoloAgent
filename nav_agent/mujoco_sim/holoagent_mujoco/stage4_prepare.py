from __future__ import annotations

import argparse
import json
from pathlib import Path

from holoagent_mujoco.config import file_sha256
from holoagent_mujoco.stage4_config import load_stage4_config
from holoagent_mujoco.stage4_map import (
    generate_sim_map,
    validate_fixture_pose,
    verify_loaded_map,
)
from holoagent_mujoco.stage4_nav import validate_nav2_parameters


def prepare_stage4(
    config_path: Path,
    output_dir: Path,
    *,
    runtime_output_dir: Path | None = None,
) -> dict[str, object]:
    config = load_stage4_config(config_path)
    destination = Path(output_dir).expanduser().resolve()
    grid = generate_sim_map(
        config.bridge.scene,
        destination,
        resolution_m=config.map.resolution_m,
        frame_id=config.map.frame_id,
    )
    fixtures = [
        validate_fixture_pose(grid, pose, clearance_m=config.map.inflation_radius_m)
        for pose in config.fixtures.values()
    ]
    nav2 = validate_nav2_parameters(
        config.nav2_params,
        bridge=config.bridge,
        inflation_radius_m=config.map.inflation_radius_m,
    )
    loaded = verify_loaded_map(
        grid.yaml_path,
        expected_yaml_path=grid.yaml_path,
        expected_yaml_sha256=grid.yaml_sha256,
        expected_pgm_sha256=grid.pgm_sha256,
        prohibited_real_map_paths=config.map.prohibited_real_map_paths,
    )
    if runtime_output_dir is not None:
        runtime_destination = Path(runtime_output_dir).expanduser()
        if not runtime_destination.is_absolute():
            raise ValueError("runtime output directory must be absolute")
        loaded = {
            **loaded,
            "yaml_path": str(runtime_destination / grid.yaml_path.name),
            "pgm_path": str(runtime_destination / grid.pgm_path.name),
        }
    evidence = {
        "stage": 4,
        "config_path": str(config.source_path),
        "config_sha256": file_sha256(config.source_path),
        "map": {
            "source": "known_mujoco_scene_geometry",
            "frame_id": grid.frame_id,
            "resolution_m": grid.resolution_m,
            "size": [grid.width, grid.height],
            "origin_xy": list(grid.origin_xy),
            **loaded,
            "prohibited_real_map_paths": [
                str(path) for path in config.map.prohibited_real_map_paths
            ],
        },
        "fixtures": fixtures,
        "nav2": {
            **nav2,
            "params_path": str(config.nav2_params),
            "params_sha256": file_sha256(config.nav2_params),
            "behavior_tree_path": str(config.behavior_tree),
            "behavior_tree_sha256": file_sha256(config.behavior_tree),
        },
    }
    _write_json(destination / "stage4_manifest.json", evidence)
    return evidence


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare deterministic Stage 4 assets")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runtime-output-dir", type=Path)
    arguments = parser.parse_args(argv)
    evidence = prepare_stage4(
        arguments.config,
        arguments.output_dir,
        runtime_output_dir=arguments.runtime_output_dir,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
