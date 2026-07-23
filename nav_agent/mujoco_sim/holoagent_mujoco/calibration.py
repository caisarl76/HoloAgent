from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
import xml.etree.ElementTree as ET

import numpy as np
import yaml

from holoagent_mujoco.config import Stage1Config, file_sha256, load_config


@dataclass(frozen=True)
class GeneratedCalibration:
    config_path: Path
    metadata_path: Path
    config_sha256: str
    source_sha256: str


def generate_fastlivo_config(
    config: Stage1Config, destination: str | Path
) -> GeneratedCalibration:
    output_dir = Path(destination).expanduser().resolve()
    config_path = output_dir / "fastlivo_sim.yaml"
    metadata_path = output_dir / "fastlivo_sim_calibration.json"
    for path in (config_path, metadata_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite calibration output: {path}")

    extrinsics = _derive_extrinsics(config)
    document = {
        "/**": {
            "ros__parameters": {
                "use_sim_time": True,
                "common": {
                    "img_topic": "/camera/color/image_raw",
                    "lid_topic": "/livox/lidar",
                    "imu_topic": "/livox/imu",
                    "img_en": 0,
                    "lidar_en": 1,
                    "ros_driver_bug_fix": False,
                    "map_save_path": str(output_dir / "fastlivo_map"),
                    "enable_zupt": False,
                },
                "extrin_calib": extrinsics,
                "wheel": {"enable_wheel_odom": False},
                "time_offset": {
                    "imu_time_offset": 0.0,
                    "img_time_offset": 0.0,
                    "exposure_time_init": 0.0,
                    "lidar_time_offset": 0.0,
                },
                "preprocess": {
                    "point_filter_num": 1,
                    "filter_size_surf": 0.20,
                    "lidar_type": 1,
                    "scan_line": config.lidar.scan_lines,
                    "scan_rate": config.rates.lidar_hz,
                    "blind": config.lidar.min_range_m,
                    "max_range": config.lidar.max_range_m,
                    "feature_extract_enabled": False,
                    "img_filter_en": False,
                    "img_filter_fre": 1,
                },
                "camera": {
                    "model": "Pinhole",
                    "width": config.camera.width,
                    "height": config.camera.height,
                    "scale": 1.0,
                    "fx": config.camera.fx,
                    "fy": config.camera.fy,
                    "cx": config.camera.cx,
                    "cy": config.camera.cy,
                    "d0": 0.0,
                    "d1": 0.0,
                    "d2": 0.0,
                    "d3": 0.0,
                },
                "vio": {
                    "max_iterations": 3,
                    "outlier_threshold": 1000,
                    "img_point_cov": 100,
                    "patch_size": 8,
                    "patch_pyrimid_level": 4,
                    "normal_en": True,
                    "raycast_en": False,
                    "inverse_composition_en": False,
                    "exposure_estimate_en": False,
                    "inv_expo_cov": 0.1,
                },
                "imu": {
                    "imu_en": True,
                    "imu_int_frame": 50,
                    "acc_cov": 0.02,
                    "gyr_cov": 0.02,
                    "b_acc_cov": 0.0001,
                    "b_gyr_cov": 0.0001,
                },
                "lio": {
                    "max_iterations": 5,
                    "dept_err": 0.02,
                    "beam_err": 0.05,
                    "min_eigen_value": 0.005,
                    "voxel_size": 0.3,
                    "max_layer": 2,
                    "max_points_num": 50,
                    "layer_init_num": [5, 5, 5, 5, 5],
                    "max_voxel_num": 20000,
                },
                "local_map": {
                    "map_sliding_en": False,
                    "half_map_size": 100,
                    "sliding_thresh": 8.0,
                },
                "uav": {"imu_rate_odom": False, "gravity_align_en": True},
                "publish": {
                    "dense_map_en": False,
                    "pub_effect_point_en": False,
                    "pub_plane_en": False,
                    "pub_scan_num": 1,
                    "pub_rgb_cloud_en": False,
                    "blind_rgb_points": 0.1,
                    "rgb_cloud_interval": 4,
                    "depth_en": False,
                    "viz_timer_ms": 50,
                },
                "evo": {"seq_name": "holoagent_sim", "pose_output_en": False},
                "pcd_save": {
                    "pcd_save_en": False,
                    "colmap_output_en": False,
                    "interval": -1,
                    "filter_size_pcd": 0.04,
                },
                "loop": {"loop_closure_enable_flag": False},
                "mapping": {
                    "keyframeAddingDistThreshold": 0.5,
                    "keyframeAddingAngleThreshold": 0.10,
                    "enable_gtsam": False,
                },
            }
        }
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    yaml_text = yaml.safe_dump(document, sort_keys=False)
    _atomic_write(config_path, yaml_text)
    config_sha256 = file_sha256(config_path)
    source_sha256 = _source_digest(config)
    metadata = {
        "kind": "holoagent_sim_calibration",
        "config_sha256": config_sha256,
        "source_sha256": source_sha256,
        "source_config_path": str(config.source_path) if config.source_path else None,
        "source_config_sha256": (
            file_sha256(config.source_path) if config.source_path else None
        ),
        "forbidden_real_rig_source": False,
        "lidar_points_per_scan": config.lidar.configured_points,
        "lidar_min_finite_points": config.lidar.min_finite_points,
    }
    _atomic_write(metadata_path, json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return GeneratedCalibration(
        config_path=config_path,
        metadata_path=metadata_path,
        config_sha256=config_sha256,
        source_sha256=source_sha256,
    )


def _derive_extrinsics(config: Stage1Config) -> dict[str, list[float]]:
    root = ET.parse(config.backend.xml).getroot()
    imu_site = root.find(".//site[@name='imu_in_torso']")
    if imu_site is None:
        raise ValueError("pinned MuJoCo model has no imu_in_torso site")
    imu_position = _xml_vector(imu_site, "pos", 3)
    imu_rotation = _quaternion_matrix(_xml_vector(imu_site, "quat", 4, (1, 0, 0, 0)))
    lidar_position = np.asarray(config.lidar.mount_pos, dtype=np.float64)
    lidar_rotation = _quaternion_matrix(config.lidar.mount_quat_wxyz)
    camera_position = np.asarray(config.camera.mount_pos, dtype=np.float64)
    camera_rotation = _xyaxes_matrix(config.camera.mount_xyaxes)
    camera_optical_rotation = camera_rotation @ np.diag([1.0, -1.0, -1.0])

    lidar_to_imu_rotation = imu_rotation.T @ lidar_rotation
    lidar_to_imu_position = imu_rotation.T @ (lidar_position - imu_position)
    lidar_to_camera_rotation = camera_optical_rotation.T @ lidar_rotation
    lidar_to_camera_position = camera_optical_rotation.T @ (
        lidar_position - camera_position
    )
    return {
        "extrinsic_T": _flat(lidar_to_imu_position),
        "extrinsic_R": _flat(lidar_to_imu_rotation),
        "Rcl": _flat(lidar_to_camera_rotation),
        "Pcl": _flat(lidar_to_camera_position),
    }


def _source_digest(config: Stage1Config) -> str:
    payload = {
        "backend_xml_sha256": file_sha256(config.backend.xml),
        "camera": config.camera.__dict__,
        "lidar": config.lidar.__dict__,
        "rates": config.rates.__dict__,
        "frames": config.frames.__dict__,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _xml_vector(
    element: ET.Element,
    attribute: str,
    length: int,
    default: tuple[float, ...] | None = None,
) -> np.ndarray:
    raw = element.attrib.get(attribute)
    if raw is None:
        if default is None:
            raise ValueError(f"MuJoCo element lacks {attribute}")
        values = default
    else:
        values = tuple(float(item) for item in raw.split())
    array = np.asarray(values, dtype=np.float64)
    if array.shape != (length,) or not np.isfinite(array).all():
        raise ValueError(f"MuJoCo {attribute} must contain {length} finite values")
    return array


def _quaternion_matrix(quaternion: tuple[float, ...] | np.ndarray) -> np.ndarray:
    q = np.asarray(quaternion, dtype=np.float64)
    q = q / np.linalg.norm(q)
    w, x, y, z = q
    return np.array(
        [
            [1 - 2 * (y * y + z * z), 2 * (x * y - z * w), 2 * (x * z + y * w)],
            [2 * (x * y + z * w), 1 - 2 * (x * x + z * z), 2 * (y * z - x * w)],
            [2 * (x * z - y * w), 2 * (y * z + x * w), 1 - 2 * (x * x + y * y)],
        ]
    )


def _xyaxes_matrix(values: tuple[float, ...]) -> np.ndarray:
    axes = np.asarray(values, dtype=np.float64).reshape(2, 3)
    x_axis = axes[0] / np.linalg.norm(axes[0])
    y_axis = axes[1] - x_axis * float(np.dot(x_axis, axes[1]))
    y_axis = y_axis / np.linalg.norm(y_axis)
    z_axis = np.cross(x_axis, y_axis)
    return np.column_stack((x_axis, y_axis, z_axis))


def _flat(values: np.ndarray) -> list[float]:
    return [float(value) for value in np.asarray(values).reshape(-1)]


def _atomic_write(path: Path, text: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate sim-only FastLIVO calibration"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    generated = generate_fastlivo_config(
        load_config(arguments.config), arguments.output_dir
    )
    print(generated.config_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
