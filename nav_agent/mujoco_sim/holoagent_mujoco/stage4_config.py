from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any, Mapping

import yaml

from holoagent_mujoco.config import Stage1Config, load_config
from holoagent_mujoco.stage4_fixture import normalize_query
from holoagent_mujoco.stage4_map import FixturePose


class Stage4ConfigError(ValueError):
    """Raised when the simulator-native navigation contract is incomplete."""


@dataclass(frozen=True)
class Stage4MapSettings:
    frame_id: str
    resolution_m: float
    robot_radius_m: float
    inflation_radius_m: float
    prohibited_real_map_paths: tuple[Path, ...]


@dataclass(frozen=True)
class Stage4Gates:
    goal_timeout_sim_sec: float
    position_tolerance_m: float
    yaw_tolerance_deg: float
    timeout_zero_sec: float
    stop_settle_sec: float
    stopped_speed_mps: float
    stopped_hold_sec: float
    min_realtime_factor: float
    wall_time_multiplier: float
    startup_allowance_sec: float


@dataclass(frozen=True)
class Stage4Config:
    source_path: Path
    bridge: Stage1Config
    map: Stage4MapSettings
    query_topic: str
    output_topic: str
    fixtures: dict[str, FixturePose]
    nav2_params: Path
    behavior_tree: Path
    gates: Stage4Gates


def load_stage4_config(path: Path) -> Stage4Config:
    source = Path(path).expanduser().resolve()
    bridge = load_config(source)
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or not isinstance(raw.get("stage4"), Mapping):
        raise Stage4ConfigError("stage4 configuration section is required")
    stage4 = raw["stage4"]
    map_raw = _mapping(stage4, "map")
    frame_id = _string(map_raw, "frame_id")
    if frame_id != bridge.frames.map or frame_id != "sim_map":
        raise Stage4ConfigError("Stage 4 map frame must be sim_map")
    resolution = _positive(map_raw, "resolution_m")
    if not math.isclose(resolution, 0.05, abs_tol=1e-12):
        raise Stage4ConfigError("Stage 4 map resolution must be 0.05 m")
    robot_radius = _positive(map_raw, "robot_radius_m")
    inflation_radius = _positive(map_raw, "inflation_radius_m")
    if inflation_radius < robot_radius:
        raise Stage4ConfigError("inflation radius must cover the robot radius")
    prohibited_values = map_raw.get("prohibited_real_map_paths")
    if not isinstance(prohibited_values, list) or not prohibited_values:
        raise Stage4ConfigError("at least one prohibited real map path is required")
    prohibited_paths = tuple(
        Path(str(value)).expanduser() for value in prohibited_values
    )
    if any(not path.is_absolute() for path in prohibited_paths):
        raise Stage4ConfigError("prohibited real map paths must be absolute")

    fixture_raw = _mapping(stage4, "sim_fixture")
    query_topic = _topic(fixture_raw, "query_topic")
    output_topic = _topic(fixture_raw, "output_topic")
    if query_topic != "/sim_fixture/query" or output_topic != "/object_pose":
        raise Stage4ConfigError("sim_fixture topics must use the approved names")
    fixtures_raw = _mapping(fixture_raw, "fixtures")
    fixtures = {}
    for query, values in fixtures_raw.items():
        normalized = normalize_query(str(query))
        if not normalized or normalized in fixtures:
            raise Stage4ConfigError("sim_fixture queries must be unique and nonempty")
        if not isinstance(values, list) or len(values) != 3:
            raise Stage4ConfigError(f"fixture {query!r} must contain x, y, yaw")
        pose_values = tuple(float(value) for value in values)
        if not all(math.isfinite(value) for value in pose_values):
            raise Stage4ConfigError(f"fixture {query!r} must be finite")
        fixtures[normalized] = FixturePose(normalized, *pose_values)
    if not fixtures:
        raise Stage4ConfigError("at least one sim_fixture pose is required")

    navigation = _mapping(stage4, "navigation")
    repo_root = source.parents[3]
    nav2_params = _repo_file(repo_root, navigation, "params_file")
    behavior_tree = _repo_file(repo_root, navigation, "behavior_tree")
    gates_raw = _mapping(stage4, "gates")
    gate_names = (
        "goal_timeout_sim_sec",
        "position_tolerance_m",
        "yaw_tolerance_deg",
        "timeout_zero_sec",
        "stop_settle_sec",
        "stopped_speed_mps",
        "stopped_hold_sec",
        "min_realtime_factor",
        "wall_time_multiplier",
        "startup_allowance_sec",
    )
    gates = Stage4Gates(**{name: _positive(gates_raw, name) for name in gate_names})
    return Stage4Config(
        source_path=source,
        bridge=bridge,
        map=Stage4MapSettings(
            frame_id=frame_id,
            resolution_m=resolution,
            robot_radius_m=robot_radius,
            inflation_radius_m=inflation_radius,
            prohibited_real_map_paths=prohibited_paths,
        ),
        query_topic=query_topic,
        output_topic=output_topic,
        fixtures=fixtures,
        nav2_params=nav2_params,
        behavior_tree=behavior_tree,
        gates=gates,
    )


def _mapping(parent: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = parent.get(key)
    if not isinstance(value, Mapping):
        raise Stage4ConfigError(f"stage4.{key} must be a mapping")
    return value


def _string(parent: Mapping[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value.strip():
        raise Stage4ConfigError(f"{key} must be a nonempty string")
    return value.strip()


def _topic(parent: Mapping[str, Any], key: str) -> str:
    value = _string(parent, key)
    if not value.startswith("/") or "//" in value:
        raise Stage4ConfigError(f"{key} must be an absolute ROS topic")
    return value


def _positive(parent: Mapping[str, Any], key: str) -> float:
    try:
        value = float(parent.get(key))
    except (TypeError, ValueError) as exc:
        raise Stage4ConfigError(f"{key} must be finite and positive") from exc
    if not math.isfinite(value) or value <= 0.0:
        raise Stage4ConfigError(f"{key} must be finite and positive")
    return value


def _repo_file(repo_root: Path, parent: Mapping[str, Any], key: str) -> Path:
    value = Path(_string(parent, key))
    if value.is_absolute():
        raise Stage4ConfigError(f"{key} must be repository-relative")
    resolved = (repo_root / value).resolve()
    if repo_root.resolve() not in resolved.parents or not resolved.is_file():
        raise Stage4ConfigError(f"{key} does not resolve inside the repository")
    return resolved
