from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
from typing import Any, Mapping

import yaml


class ConfigError(ValueError):
    """Raised when Stage 1 configuration is unsafe or incomplete."""


@dataclass(frozen=True)
class RuntimeConfig:
    python: Path
    extra_python_paths: tuple[Path, ...]
    directory: Path
    ros_domain_id: int
    ros_localhost_only: bool
    rmw_implementation: str
    mujoco_gl: str


@dataclass(frozen=True)
class BackendConfig:
    root: Path
    runner: Path
    config_yaml: Path
    xml: Path
    balance_policy: Path
    walk_policy: Path
    onnx_providers: tuple[str, ...]
    expected_sha256: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RateConfig:
    physics_hz: int
    imu_hz: int
    odom_hz: int
    camera_hz: int


@dataclass(frozen=True)
class FrameConfig:
    map: str
    odom: str
    base: str
    imu: str
    camera: str


@dataclass(frozen=True)
class CommandConfig:
    max_linear_x: float
    max_linear_y: float
    max_yaw_rate: float
    timeout_sim_sec: float


@dataclass(frozen=True)
class CameraConfig:
    name: str
    width: int
    height: int
    fx: float
    fy: float
    cx: float
    cy: float
    mount_pos: tuple[float, float, float]
    mount_xyaxes: tuple[float, float, float, float, float, float]


@dataclass(frozen=True)
class SceneConfig:
    half_extent: float
    wall_height: float
    wall_thickness: float


@dataclass(frozen=True)
class ThresholdConfig:
    warmup_sec: float
    rate_window_sec: float
    clock_min_hz: float
    min_realtime_factor: float
    imu_min_hz: float
    imu_max_hz: float
    odom_min_hz: float
    odom_max_hz: float
    camera_min_hz: float
    camera_max_hz: float
    stationary_duration_sec: float
    max_stationary_drift_m: float
    motion_speed_mps: float
    motion_duration_sec: float
    motion_min_displacement_m: float
    motion_max_displacement_m: float
    timeout_zero_sec: float
    stopped_speed_mps: float
    stopped_hold_sec: float
    wall_time_multiplier: float
    startup_allowance_sec: float


@dataclass(frozen=True)
class Stage1Config:
    runtime: RuntimeConfig
    backend: BackendConfig
    rates: RateConfig
    frames: FrameConfig
    command: CommandConfig
    camera: CameraConfig
    scene: SceneConfig
    thresholds: ThresholdConfig
    source_path: Path | None = None


def load_config(path: str | Path) -> Stage1Config:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise ConfigError(f"config does not exist: {source}")
    with source.open("r", encoding="utf-8") as stream:
        raw = yaml.safe_load(stream)
    if not isinstance(raw, Mapping):
        raise ConfigError("config root must be a mapping")
    cfg = load_mapping(raw)
    return Stage1Config(**{**cfg.__dict__, "source_path": source})


def load_mapping(raw: Mapping[str, Any]) -> Stage1Config:
    runtime_raw = _mapping(raw, "runtime")
    backend_raw = _mapping(raw, "backend")
    rates_raw = _mapping(raw, "rates")
    frames_raw = _mapping(raw, "frames")
    command_raw = _mapping(raw, "command")
    camera_raw = _mapping(raw, "camera")
    scene_raw = _mapping(raw, "scene")
    threshold_raw = _mapping(raw, "thresholds")

    runtime = RuntimeConfig(
        python=_path(runtime_raw, "python", "runtime.python", file=True, executable=True),
        extra_python_paths=tuple(
            _absolute_path(value, f"runtime.extra_python_paths[{index}]", directory=True)
            for index, value in enumerate(_list(runtime_raw, "extra_python_paths"))
        ),
        directory=_absolute_path(runtime_raw.get("directory"), "runtime.directory"),
        ros_domain_id=_integer(runtime_raw, "ros_domain_id", "runtime.ros_domain_id"),
        ros_localhost_only=_boolean(
            runtime_raw, "ros_localhost_only", "runtime.ros_localhost_only"
        ),
        rmw_implementation=_nonempty_string(
            runtime_raw, "rmw_implementation", "runtime.rmw_implementation"
        ),
        mujoco_gl=_nonempty_string(runtime_raw, "mujoco_gl", "runtime.mujoco_gl"),
    )
    if runtime.ros_domain_id != 77:
        raise ConfigError("runtime.ros_domain_id must be 77")
    if not runtime.ros_localhost_only:
        raise ConfigError("runtime.ros_localhost_only must be true")
    if runtime.rmw_implementation != "rmw_cyclonedds_cpp":
        raise ConfigError("runtime.rmw_implementation must be rmw_cyclonedds_cpp")

    digest_raw = backend_raw.get("expected_sha256", {})
    if not isinstance(digest_raw, Mapping):
        raise ConfigError("backend.expected_sha256 must be a mapping")
    expected_sha256 = tuple(
        sorted((str(key), _sha256_text(value, f"backend.expected_sha256.{key}")) for key, value in digest_raw.items())
    )
    backend = BackendConfig(
        root=_path(backend_raw, "root", "backend.root", directory=True),
        runner=_path(backend_raw, "runner", "backend.runner", file=True),
        config_yaml=_path(backend_raw, "config_yaml", "backend.config_yaml", file=True),
        xml=_path(backend_raw, "xml", "backend.xml", file=True),
        balance_policy=_path(
            backend_raw, "balance_policy", "backend.balance_policy", file=True
        ),
        walk_policy=_path(backend_raw, "walk_policy", "backend.walk_policy", file=True),
        onnx_providers=tuple(
            _nonempty_value(value, f"backend.onnx_providers[{index}]")
            for index, value in enumerate(_list(backend_raw, "onnx_providers"))
        ),
        expected_sha256=expected_sha256,
    )
    if backend.onnx_providers != ("CPUExecutionProvider",):
        raise ConfigError("backend.onnx_providers must contain only CPUExecutionProvider")
    _verify_digest_pins(backend)

    rates = RateConfig(
        physics_hz=_positive_integer(rates_raw, "physics_hz", "rates.physics_hz"),
        imu_hz=_positive_integer(rates_raw, "imu_hz", "rates.imu_hz"),
        odom_hz=_positive_integer(rates_raw, "odom_hz", "rates.odom_hz"),
        camera_hz=_positive_integer(rates_raw, "camera_hz", "rates.camera_hz"),
    )
    for name in ("imu_hz", "odom_hz", "camera_hz"):
        if getattr(rates, name) > rates.physics_hz:
            raise ConfigError(f"rates.{name} cannot exceed rates.physics_hz")

    frame_values = {
        name: _nonempty_string(frames_raw, name, f"frames.{name}")
        for name in ("map", "odom", "base", "imu", "camera")
    }
    if len(set(frame_values.values())) != len(frame_values):
        raise ConfigError("frames must be distinct")
    frames = FrameConfig(**frame_values)

    command = CommandConfig(
        max_linear_x=_positive_float(command_raw, "max_linear_x", "command.max_linear_x"),
        max_linear_y=_finite_float(command_raw, "max_linear_y", "command.max_linear_y"),
        max_yaw_rate=_positive_float(command_raw, "max_yaw_rate", "command.max_yaw_rate"),
        timeout_sim_sec=_positive_float(
            command_raw, "timeout_sim_sec", "command.timeout_sim_sec"
        ),
    )
    if command.max_linear_y != 0.0:
        raise ConfigError("command.max_linear_y must be zero")

    camera = CameraConfig(
        name=_nonempty_string(camera_raw, "name", "camera.name"),
        width=_positive_integer(camera_raw, "width", "camera.width"),
        height=_positive_integer(camera_raw, "height", "camera.height"),
        fx=_positive_float(camera_raw, "fx", "camera.fx"),
        fy=_positive_float(camera_raw, "fy", "camera.fy"),
        cx=_finite_float(camera_raw, "cx", "camera.cx"),
        cy=_finite_float(camera_raw, "cy", "camera.cy"),
        mount_pos=_float_tuple(camera_raw, "mount_pos", "camera.mount_pos", 3),
        mount_xyaxes=_float_tuple(camera_raw, "mount_xyaxes", "camera.mount_xyaxes", 6),
    )
    if not (0.0 <= camera.cx <= camera.width and 0.0 <= camera.cy <= camera.height):
        raise ConfigError("camera principal point must lie inside the image")

    scene = SceneConfig(
        half_extent=_positive_float(scene_raw, "half_extent", "scene.half_extent"),
        wall_height=_positive_float(scene_raw, "wall_height", "scene.wall_height"),
        wall_thickness=_positive_float(
            scene_raw, "wall_thickness", "scene.wall_thickness"
        ),
    )

    threshold_names = (
        "warmup_sec",
        "rate_window_sec",
        "clock_min_hz",
        "min_realtime_factor",
        "imu_min_hz",
        "imu_max_hz",
        "odom_min_hz",
        "odom_max_hz",
        "camera_min_hz",
        "camera_max_hz",
        "stationary_duration_sec",
        "max_stationary_drift_m",
        "motion_speed_mps",
        "motion_duration_sec",
        "motion_min_displacement_m",
        "motion_max_displacement_m",
        "timeout_zero_sec",
        "stopped_speed_mps",
        "stopped_hold_sec",
        "wall_time_multiplier",
        "startup_allowance_sec",
    )
    thresholds = ThresholdConfig(
        **{
            name: _positive_float(threshold_raw, name, f"thresholds.{name}")
            for name in threshold_names
        }
    )
    for minimum, maximum in (
        (thresholds.imu_min_hz, thresholds.imu_max_hz),
        (thresholds.odom_min_hz, thresholds.odom_max_hz),
        (thresholds.camera_min_hz, thresholds.camera_max_hz),
        (thresholds.motion_min_displacement_m, thresholds.motion_max_displacement_m),
    ):
        if minimum > maximum:
            raise ConfigError("threshold minimum cannot exceed maximum")

    return Stage1Config(
        runtime=runtime,
        backend=backend,
        rates=rates,
        frames=frames,
        command=command,
        camera=camera,
        scene=scene,
        thresholds=thresholds,
    )


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _verify_digest_pins(backend: BackendConfig) -> None:
    paths = {
        "runner": backend.runner,
        "config_yaml": backend.config_yaml,
        "xml": backend.xml,
        "balance_policy": backend.balance_policy,
        "walk_policy": backend.walk_policy,
    }
    for name, expected in backend.expected_sha256:
        if name not in paths:
            raise ConfigError(f"backend.expected_sha256 has unknown key: {name}")
        actual = file_sha256(paths[name])
        if actual != expected:
            raise ConfigError(
                f"backend.{name} SHA-256 mismatch: expected {expected}, got {actual}"
            )


def _mapping(parent: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = parent.get(key)
    if not isinstance(value, Mapping):
        raise ConfigError(f"{key} must be a mapping")
    return value


def _list(parent: Mapping[str, Any], key: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{key} must be a non-empty list")
    return value


def _path(
    parent: Mapping[str, Any],
    key: str,
    label: str,
    *,
    file: bool = False,
    directory: bool = False,
    executable: bool = False,
) -> Path:
    return _absolute_path(
        parent.get(key), label, file=file, directory=directory, executable=executable
    )


def _absolute_path(
    value: Any,
    label: str,
    *,
    file: bool = False,
    directory: bool = False,
    executable: bool = False,
) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a non-empty path")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ConfigError(f"{label} must be absolute")
    if file and not path.is_file():
        raise ConfigError(f"{label} does not exist: {path}")
    if directory and not path.is_dir():
        raise ConfigError(f"{label} does not exist: {path}")
    if executable and not os.access(path, os.X_OK):
        raise ConfigError(f"{label} is not executable: {path}")
    return path


def _boolean(parent: Mapping[str, Any], key: str, label: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        raise ConfigError(f"{label} must be boolean")
    return value


def _integer(parent: Mapping[str, Any], key: str, label: str) -> int:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    return value


def _positive_integer(parent: Mapping[str, Any], key: str, label: str) -> int:
    value = _integer(parent, key, label)
    if value <= 0:
        raise ConfigError(f"{label} must be positive")
    return value


def _finite_float(parent: Mapping[str, Any], key: str, label: str) -> float:
    value = parent.get(key)
    if isinstance(value, bool):
        raise ConfigError(f"{label} must be finite")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{label} must be finite") from exc
    if not math.isfinite(result):
        raise ConfigError(f"{label} must be finite")
    return result


def _positive_float(parent: Mapping[str, Any], key: str, label: str) -> float:
    value = _finite_float(parent, key, label)
    if value <= 0.0:
        raise ConfigError(f"{label} must be positive")
    return value


def _float_tuple(
    parent: Mapping[str, Any], key: str, label: str, length: int
) -> tuple[float, ...]:
    value = parent.get(key)
    if not isinstance(value, list) or len(value) != length:
        raise ConfigError(f"{label} must contain {length} values")
    result = tuple(float(item) for item in value)
    if not all(math.isfinite(item) for item in result):
        raise ConfigError(f"{label} must contain only finite values")
    return result


def _nonempty_string(parent: Mapping[str, Any], key: str, label: str) -> str:
    return _nonempty_value(parent.get(key), label)


def _nonempty_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a non-empty string")
    return value.strip()


def _sha256_text(value: Any, label: str) -> str:
    text = _nonempty_value(value, label).lower()
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ConfigError(f"{label} must be a SHA-256 hex digest")
    return text

