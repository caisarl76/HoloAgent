from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Iterable

import numpy as np
import yaml

from holoagent_mujoco.config import SceneConfig, file_sha256


class MapContractError(ValueError):
    """Raised when a Stage 4 map or fixture violates the sim_map contract."""


@dataclass(frozen=True)
class FixturePose:
    query: str
    x: float
    y: float
    yaw: float


@dataclass(frozen=True)
class GeneratedSimMap:
    yaml_path: Path
    pgm_path: Path
    yaml_sha256: str
    pgm_sha256: str
    frame_id: str
    resolution_m: float
    width: int
    height: int
    origin_xy: tuple[float, float]
    occupancy: np.ndarray

    def world_to_cell(self, x: float, y: float) -> tuple[int, int] | None:
        if not math.isfinite(x) or not math.isfinite(y):
            return None
        column = math.floor((x - self.origin_xy[0]) / self.resolution_m)
        row = math.floor((y - self.origin_xy[1]) / self.resolution_m)
        if not (0 <= column < self.width and 0 <= row < self.height):
            return None
        return int(column), int(row)

    def is_occupied(self, x: float, y: float) -> bool:
        cell = self.world_to_cell(x, y)
        if cell is None:
            return True
        column, row = cell
        return bool(self.occupancy[row, column])


def generate_sim_map(
    scene: SceneConfig,
    output_dir: Path,
    *,
    resolution_m: float,
    frame_id: str = "sim_map",
) -> GeneratedSimMap:
    if frame_id != "sim_map":
        raise MapContractError("Stage 4 map frame must be sim_map")
    if not math.isfinite(resolution_m) or resolution_m <= 0.0:
        raise MapContractError("map resolution must be positive and finite")
    cells = 2.0 * scene.half_extent / resolution_m
    if not math.isclose(cells, round(cells), abs_tol=1e-9):
        raise MapContractError("scene extent must divide exactly into map cells")
    width = height = int(round(cells))
    origin = (-scene.half_extent, -scene.half_extent)
    x_centers = origin[0] + (np.arange(width) + 0.5) * resolution_m
    y_centers = origin[1] + (np.arange(height) + 0.5) * resolution_m
    x_grid, y_grid = np.meshgrid(x_centers, y_centers)
    occupied = np.zeros((height, width), dtype=bool)
    occupied[[0, -1], :] = True
    occupied[:, [0, -1]] = True
    for center_x, center_y in ((-2.5, 2.5), (2.5, -2.5)):
        occupied |= (np.abs(x_grid - center_x) <= 0.35) & (
            np.abs(y_grid - center_y) <= 0.35
        )

    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    pgm_path = destination / "sim_map.pgm"
    yaml_path = destination / "sim_map.yaml"
    image = np.where(np.flipud(occupied), 0, 255).astype(np.uint8)
    pgm_path.write_bytes(
        f"P5\n{width} {height}\n255\n".encode("ascii") + image.tobytes()
    )
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "image": pgm_path.name,
                "mode": "trinary",
                "resolution": float(resolution_m),
                "origin": [float(origin[0]), float(origin[1]), 0.0],
                "negate": 0,
                "occupied_thresh": 0.65,
                "free_thresh": 0.196,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return GeneratedSimMap(
        yaml_path=yaml_path,
        pgm_path=pgm_path,
        yaml_sha256=file_sha256(yaml_path),
        pgm_sha256=file_sha256(pgm_path),
        frame_id=frame_id,
        resolution_m=resolution_m,
        width=width,
        height=height,
        origin_xy=origin,
        occupancy=occupied,
    )


def validate_fixture_pose(
    grid: GeneratedSimMap, pose: FixturePose, *, clearance_m: float
) -> dict[str, object]:
    if not all(math.isfinite(value) for value in (pose.x, pose.y, pose.yaw)):
        raise MapContractError("fixture pose must be finite")
    if not math.isfinite(clearance_m) or clearance_m <= 0.0:
        raise MapContractError("fixture clearance must be positive and finite")
    cell = grid.world_to_cell(pose.x, pose.y)
    if cell is None:
        raise MapContractError(f"fixture {pose.query!r} is outside sim_map bounds")
    if grid.is_occupied(pose.x, pose.y):
        raise MapContractError(f"fixture {pose.query!r} is occupied")
    rows, columns = np.nonzero(grid.occupancy)
    occupied_x = grid.origin_xy[0] + (columns + 0.5) * grid.resolution_m
    occupied_y = grid.origin_xy[1] + (rows + 0.5) * grid.resolution_m
    clearance = float(np.min(np.hypot(occupied_x - pose.x, occupied_y - pose.y)))
    if clearance + 1e-12 < clearance_m:
        raise MapContractError(
            f"fixture {pose.query!r} clearance {clearance:.3f} m is below "
            f"{clearance_m:.3f} m"
        )
    return {
        "query": pose.query,
        "frame_id": grid.frame_id,
        "pose": [pose.x, pose.y, pose.yaw],
        "cell": list(cell),
        "clearance_m": clearance,
        "required_clearance_m": clearance_m,
    }


def verify_loaded_map(
    loaded_yaml_path: Path,
    *,
    expected_yaml_path: Path,
    expected_yaml_sha256: str,
    expected_pgm_sha256: str,
    prohibited_real_map_paths: Iterable[Path] = (),
) -> dict[str, str]:
    loaded = Path(loaded_yaml_path).expanduser().resolve()
    expected = Path(expected_yaml_path).expanduser().resolve()
    prohibited = {
        Path(path).expanduser().resolve() for path in prohibited_real_map_paths
    }
    if loaded in prohibited or loaded != expected:
        raise MapContractError("Nav2 must load the exact generated sim_map path")
    if not loaded.is_file() or file_sha256(loaded) != expected_yaml_sha256:
        raise MapContractError("loaded sim_map YAML digest mismatch")
    document = yaml.safe_load(loaded.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("image") != "sim_map.pgm":
        raise MapContractError("sim_map YAML must reference sim_map.pgm")
    pgm = (loaded.parent / str(document["image"])).resolve()
    if pgm.parent != loaded.parent or not pgm.is_file():
        raise MapContractError("sim_map image path escapes its evidence directory")
    if file_sha256(pgm) != expected_pgm_sha256:
        raise MapContractError("loaded sim_map PGM digest mismatch")
    return {
        "yaml_path": str(loaded),
        "yaml_sha256": expected_yaml_sha256,
        "pgm_path": str(pgm),
        "pgm_sha256": expected_pgm_sha256,
    }


def write_map_manifest(
    grid: GeneratedSimMap,
    fixtures: Iterable[dict[str, object]],
    output_path: Path,
) -> None:
    payload = {
        "source": "known_mujoco_scene_geometry",
        "frame_id": grid.frame_id,
        "resolution_m": grid.resolution_m,
        "size": [grid.width, grid.height],
        "origin_xy": list(grid.origin_xy),
        "yaml_path": str(grid.yaml_path),
        "yaml_sha256": grid.yaml_sha256,
        "pgm_path": str(grid.pgm_path),
        "pgm_sha256": grid.pgm_sha256,
        "fixtures": list(fixtures),
    }
    destination = Path(output_path).resolve()
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)
