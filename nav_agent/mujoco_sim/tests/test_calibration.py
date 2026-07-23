from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from holoagent_mujoco.calibration import generate_fastlivo_config
from holoagent_mujoco.config import load_config


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PACKAGE_ROOT / "config" / "stage1.yaml"


def test_generated_fastlivo_config_is_sim_only_and_matches_mounts(tmp_path):
    config = load_config(CONFIG_PATH)

    generated = generate_fastlivo_config(config, tmp_path)

    document = yaml.safe_load(generated.config_path.read_text(encoding="utf-8"))
    params = document["/**"]["ros__parameters"]
    assert params["common"] == {
        "img_topic": "/camera/color/image_raw",
        "lid_topic": "/livox/lidar",
        "imu_topic": "/livox/imu",
        "img_en": 0,
        "lidar_en": 1,
        "ros_driver_bug_fix": False,
        "map_save_path": str(tmp_path / "fastlivo_map"),
        "enable_zupt": False,
    }
    assert params["wheel"]["enable_wheel_odom"] is False
    assert params["preprocess"]["scan_line"] == 6
    assert params["preprocess"]["scan_rate"] == 10
    assert params["preprocess"]["blind"] == pytest.approx(0.10)
    assert params["preprocess"]["max_range"] == pytest.approx(20.0)
    assert params["extrin_calib"]["extrinsic_R"] == pytest.approx(
        [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    )
    assert params["extrin_calib"]["extrinsic_T"] == pytest.approx([0.0, 0.0, 0.0])
    assert params["extrin_calib"]["Rcl"] == pytest.approx(
        [0.0, -1.0, 0.0, 0.0, 0.0, -1.0, 1.0, 0.0, 0.0]
    )
    assert params["extrin_calib"]["Pcl"] == pytest.approx([0.00224, 0.20208, -0.21959])
    assert params["camera"] == {
        "model": "Pinhole",
        "width": 320,
        "height": 240,
        "scale": 1.0,
        "fx": 240.0,
        "fy": 240.0,
        "cx": 160.0,
        "cy": 120.0,
        "d0": 0.0,
        "d1": 0.0,
        "d2": 0.0,
        "d3": 0.0,
    }


def test_calibration_metadata_binds_output_to_config_source(tmp_path):
    config = load_config(CONFIG_PATH)

    generated = generate_fastlivo_config(config, tmp_path)

    metadata = json.loads(generated.metadata_path.read_text(encoding="utf-8"))
    assert (
        generated.config_sha256
        == hashlib.sha256(generated.config_path.read_bytes()).hexdigest()
    )
    assert metadata["kind"] == "holoagent_sim_calibration"
    assert metadata["config_sha256"] == generated.config_sha256
    assert metadata["source_sha256"] == generated.source_sha256
    assert metadata["source_config_path"] == str(CONFIG_PATH.resolve())
    assert metadata["forbidden_real_rig_source"] is False


def test_calibration_refuses_nonempty_destination_files(tmp_path):
    config = load_config(CONFIG_PATH)
    target = tmp_path / "fastlivo_sim.yaml"
    target.write_text("user-owned\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        generate_fastlivo_config(config, tmp_path)

    assert target.read_text(encoding="utf-8") == "user-owned\n"
