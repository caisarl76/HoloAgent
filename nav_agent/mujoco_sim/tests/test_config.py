from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from holoagent_mujoco.config import ConfigError, load_config, load_mapping


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CHECKED_CONFIG = PACKAGE_ROOT / "config" / "stage1.yaml"
CHECKED_STAGE2_CONFIG = PACKAGE_ROOT / "config" / "stage2.yaml"
GR00T_ROOT = Path("/home/jihun/work/GR00T-WholeBodyControl")
G1_ROOT = GR00T_ROOT / "decoupled_wbc" / "sim2mujoco"
G1_CONFIG = G1_ROOT / "resources" / "robots" / "g1"


def valid_mapping() -> dict:
    return {
        "runtime": {
            "python": str(GR00T_ROOT / ".venv_sim" / "bin" / "python"),
            "extra_python_paths": [
                str(
                    GR00T_ROOT
                    / ".venv_data_collection"
                    / "lib"
                    / "python3.10"
                    / "site-packages"
                )
            ],
            "directory": "/tmp/holoagent_mujoco_stage1",
            "ros_domain_id": 77,
            "ros_localhost_only": True,
            "rmw_implementation": "rmw_cyclonedds_cpp",
            "mujoco_gl": "egl",
        },
        "backend": {
            "root": str(G1_ROOT),
            "runner": str(G1_ROOT / "scripts" / "run_mujoco_gear_wbc.py"),
            "config_yaml": str(G1_CONFIG / "g1_gear_wbc.yaml"),
            "xml": str(G1_CONFIG / "g1_gear_wbc.xml"),
            "balance_policy": str(
                G1_CONFIG / "policy" / "GR00T-WholeBodyControl-Balance.onnx"
            ),
            "walk_policy": str(
                G1_CONFIG / "policy" / "GR00T-WholeBodyControl-Walk.onnx"
            ),
            "onnx_providers": ["CPUExecutionProvider"],
            "expected_sha256": {
                "runner": "b78dfb546ee250116b3853f96a12f82174aca248808da33caf199ec8e42f82fd",
                "config_yaml": "31226a224ca8450e89d9ce17d5cb31c052192a9cbfedc8d145f1cb95627ac7a2",
                "xml": "3b0b5a1c8299fda85cf328cc2a8df53ccc765ce37f20030175295049947b1a19",
                "balance_policy": "f645da599d4ca3d29ed273c8f4712620bb680d34977469ca3aeabe5bb9631c18",
                "walk_policy": "7c82255b6905ffcc4468fa7f8ddcf7b70db168cf1042107ccab887cb6a8e5407",
            },
        },
        "rates": {
            "physics_hz": 200,
            "imu_hz": 200,
            "odom_hz": 50,
            "camera_hz": 15,
            "lidar_hz": 10,
        },
        "frames": {
            "map": "sim_map",
            "odom": "odom",
            "base": "base_link",
            "imu": "imu_link",
            "camera": "camera_link",
            "lidar": "livox_frame",
        },
        "command": {
            "max_linear_x": 0.22,
            "max_linear_y": 0.0,
            "max_yaw_rate": 0.30,
            "timeout_sim_sec": 0.50,
        },
        "camera": {
            "name": "head_camera",
            "width": 320,
            "height": 240,
            "fx": 240.0,
            "fy": 240.0,
            "cx": 160.0,
            "cy": 120.0,
            "mount_pos": [0.18, 0.0, 0.35],
            "mount_xyaxes": [0.0, -1.0, 0.0, 0.0, 0.0, 1.0],
        },
        "lidar": {
            "enabled": True,
            "name": "lidar_in_torso",
            "acquisition_mode": "snapshot",
            "scan_lines": 6,
            "azimuth_samples": 512,
            "vertical_fov_deg": [-15.0, 15.0],
            "min_range_m": 0.10,
            "max_range_m": 20.0,
            "scan_period_sec": 0.10,
            "noise_std_m": 0.0,
            "dropout_probability": 0.0,
            "reflectivity": 100,
            "tag": 0,
            "random_seed": 7,
            "mount_pos": [-0.03959, -0.00224, 0.14792],
            "mount_quat_wxyz": [1.0, 0.0, 0.0, 0.0],
            "min_finite_points": 2500,
        },
        "scene": {
            "half_extent": 4.0,
            "wall_height": 2.5,
            "wall_thickness": 0.10,
        },
        "thresholds": {
            "warmup_sec": 2.0,
            "rate_window_sec": 10.0,
            "clock_min_hz": 50.0,
            "min_realtime_factor": 0.25,
            "imu_min_hz": 180.0,
            "imu_max_hz": 220.0,
            "odom_min_hz": 40.0,
            "odom_max_hz": 60.0,
            "camera_min_hz": 12.0,
            "camera_max_hz": 18.0,
            "lidar_min_hz": 8.0,
            "lidar_max_hz": 12.0,
            "stationary_duration_sec": 5.0,
            "max_stationary_drift_m": 0.05,
            "motion_speed_mps": 0.10,
            "motion_duration_sec": 2.0,
            "motion_min_displacement_m": 0.08,
            "motion_max_displacement_m": 0.30,
            "motion_max_lateral_m": 0.05,
            "motion_max_yaw_error_deg": 10.0,
            "timeout_zero_sec": 0.60,
            "stop_settle_sec": 2.0,
            "stopped_speed_mps": 0.03,
            "stopped_hold_sec": 1.0,
            "wall_time_multiplier": 4.0,
            "startup_allowance_sec": 30.0,
        },
    }


def test_checked_in_config_is_stage1_safe():
    cfg = load_config(CHECKED_CONFIG)

    assert cfg.runtime.ros_domain_id == 77
    assert cfg.runtime.ros_localhost_only is True
    assert cfg.runtime.rmw_implementation == "rmw_cyclonedds_cpp"
    assert cfg.command.max_linear_y == 0.0
    assert cfg.command.timeout_sim_sec == 0.50
    assert cfg.rates.physics_hz == 200
    assert cfg.rates.imu_hz == 200
    assert cfg.rates.odom_hz == 50
    assert cfg.rates.camera_hz == 15
    assert cfg.rates.lidar_hz == 10
    assert cfg.frames.lidar == "livox_frame"
    assert cfg.lidar.acquisition_mode == "snapshot"
    assert cfg.lidar.enabled is False
    assert cfg.lidar.scan_lines == 6
    assert cfg.lidar.azimuth_samples == 512
    assert cfg.lidar.configured_points == 3072
    assert cfg.lidar.min_finite_points == 2500
    assert cfg.lidar.scan_period_sec == pytest.approx(0.1)
    assert cfg.lidar.noise_std_m == 0.0
    assert cfg.lidar.dropout_probability == 0.0
    assert cfg.backend.runner.name == "run_mujoco_gear_wbc.py"
    assert cfg.backend.balance_policy.is_file()
    assert cfg.backend.walk_policy.is_file()


def test_checked_in_stage2_config_explicitly_enables_lidar():
    cfg = load_config(CHECKED_STAGE2_CONFIG)

    assert cfg.lidar.enabled is True
    assert cfg.lidar.configured_points == 3072
    assert cfg.lidar.min_finite_points == 2500


def test_camera_rate_need_not_divide_physics_rate():
    cfg = load_mapping(valid_mapping())

    assert cfg.rates.camera_hz == 15


def test_relative_runtime_path_is_rejected():
    raw = valid_mapping()
    raw["runtime"]["python"] = ".venv_sim/bin/python"

    with pytest.raises(ConfigError, match="runtime.python.*absolute"):
        load_mapping(raw)


def test_missing_policy_fails_before_ros_start(tmp_path):
    raw = valid_mapping()
    raw["backend"]["walk_policy"] = str(tmp_path / "missing.onnx")

    with pytest.raises(ConfigError, match="backend.walk_policy.*does not exist"):
        load_mapping(raw)


def test_nonexecuting_contract_parser_keeps_pins_without_local_artifacts(tmp_path):
    raw = valid_mapping()
    raw["runtime"]["python"] = str(tmp_path / "not-executed-python")
    raw["runtime"]["extra_python_paths"] = [str(tmp_path / "not-imported")]
    raw["backend"]["root"] = str(tmp_path / "not-instantiated")
    for name in ("runner", "config_yaml", "xml", "balance_policy", "walk_policy"):
        raw["backend"][name] = str(tmp_path / name)

    cfg = load_mapping(raw, validate_runtime_artifacts=False)

    assert cfg.runtime.python == tmp_path / "not-executed-python"
    assert dict(cfg.backend.expected_sha256) == raw["backend"]["expected_sha256"]

    raw["backend"]["expected_sha256"]["runner"] = "0" * 64
    with pytest.raises(ConfigError, match="approved artifact manifest"):
        load_mapping(raw, validate_runtime_artifacts=False)


def test_backend_digest_manifest_must_be_complete():
    raw = valid_mapping()
    del raw["backend"]["expected_sha256"]["runner"]

    with pytest.raises(ConfigError, match="exactly.*runner"):
        load_mapping(raw)


def test_backend_digest_manifest_rejects_unknown_keys():
    raw = valid_mapping()
    raw["backend"]["expected_sha256"]["other"] = "0" * 64

    with pytest.raises(ConfigError, match="exactly.*other"):
        load_mapping(raw)


def test_backend_digest_manifest_rejects_unapproved_pin():
    raw = valid_mapping()
    raw["backend"]["expected_sha256"]["runner"] = "0" * 64

    with pytest.raises(ConfigError, match="approved artifact manifest"):
        load_mapping(raw)


@pytest.mark.parametrize(
    ("section", "key", "value", "message"),
    [
        ("rates", "camera_hz", 201, "camera_hz.*physics_hz"),
        ("rates", "odom_hz", 0, "odom_hz.*positive"),
        ("command", "max_linear_y", 0.01, "max_linear_y.*zero"),
        ("command", "max_yaw_rate", float("nan"), "max_yaw_rate.*finite"),
        ("runtime", "ros_domain_id", 78, "ros_domain_id.*77"),
        ("runtime", "ros_localhost_only", False, "ros_localhost_only.*true"),
    ],
)
def test_unsafe_numeric_or_isolation_value_is_rejected(section, key, value, message):
    raw = deepcopy(valid_mapping())
    raw[section][key] = value

    with pytest.raises(ConfigError, match=message):
        load_mapping(raw)


def test_frames_must_be_nonempty_and_distinct():
    raw = valid_mapping()
    raw["frames"]["imu"] = "base_link"

    with pytest.raises(ConfigError, match="frames.*distinct"):
        load_mapping(raw)


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("acquisition_mode", "fabricated", "acquisition_mode"),
        ("scan_lines", 256, "scan_lines"),
        ("azimuth_samples", 0, "azimuth_samples.*positive"),
        ("min_range_m", float("nan"), "min_range_m.*finite"),
        ("max_range_m", 0.1, "max_range_m.*greater"),
        ("scan_period_sec", 0.2, "scan_period_sec.*lidar_hz"),
        ("noise_std_m", -0.01, "noise_std_m.*non-negative"),
        ("dropout_probability", 1.1, "dropout_probability"),
        ("reflectivity", 256, "reflectivity"),
        ("tag", -1, "tag"),
        ("min_finite_points", 3073, "min_finite_points"),
    ],
)
def test_invalid_lidar_contract_is_rejected(key, value, message):
    raw = valid_mapping()
    raw["lidar"][key] = value

    with pytest.raises(ConfigError, match=message):
        load_mapping(raw)


def test_lidar_mount_quaternion_must_be_unit_length():
    raw = valid_mapping()
    raw["lidar"]["mount_quat_wxyz"] = [2.0, 0.0, 0.0, 0.0]

    with pytest.raises(ConfigError, match="mount_quat_wxyz.*unit"):
        load_mapping(raw)


def test_lidar_density_gate_cannot_be_too_weak():
    raw = valid_mapping()
    raw["lidar"]["min_finite_points"] = 2499

    with pytest.raises(ConfigError, match="min_finite_points.*2500"):
        load_mapping(raw)
