from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from holoagent_mujoco.config import CameraConfig, LidarConfig, SceneConfig
from holoagent_mujoco.scene import GeneratedSceneError, generate_scene


SCENE = SceneConfig(half_extent=4.0, wall_height=2.5, wall_thickness=0.10)
CAMERA = CameraConfig(
    name="head_camera",
    width=320,
    height=240,
    fx=240.0,
    fy=240.0,
    cx=160.0,
    cy=120.0,
    mount_pos=(0.18, 0.0, 0.35),
    mount_xyaxes=(0.0, -1.0, 0.0, 0.0, 0.0, 1.0),
)
LIDAR = LidarConfig(
    enabled=True,
    name="lidar_in_torso",
    acquisition_mode="snapshot",
    scan_lines=6,
    azimuth_samples=512,
    vertical_fov_deg=(-15.0, 15.0),
    min_range_m=0.1,
    max_range_m=20.0,
    scan_period_sec=0.1,
    noise_std_m=0.0,
    dropout_probability=0.0,
    reflectivity=100,
    tag=0,
    random_seed=7,
    mount_pos=(-0.03959, -0.00224, 0.14792),
    mount_quat_wxyz=(1.0, 0.0, 0.0, 0.0),
    min_finite_points=2500,
)


def _write_base_xml(root: Path) -> Path:
    meshes = root / "meshes"
    meshes.mkdir(parents=True)
    path = root / "base.xml"
    path.write_text(
        """<mujoco model="fixture">
  <compiler angle="radian" meshdir="meshes"/>
  <asset>
    <texture name="groundplane" type="2d" builtin="checker" width="8" height="8"/>
    <material name="groundplane" texture="groundplane"/>
  </asset>
  <worldbody>
    <body name="pelvis">
      <body name="torso_link"><geom name="torso" type="sphere" size="0.1"/></body>
    </body>
    <geom name="floor" type="plane" size="0 0 0.05" material="groundplane"/>
  </worldbody>
</mujoco>
""",
        encoding="utf-8",
    )
    return path


def test_scene_generation_is_deterministic_and_preserves_floor(tmp_path):
    base = _write_base_xml(tmp_path / "source")
    runtime = tmp_path / "runtime"

    first = generate_scene(base, runtime, SCENE, CAMERA)
    first_bytes = first.path.read_bytes()
    second = generate_scene(base, runtime, SCENE, CAMERA)

    assert second.path.read_bytes() == first_bytes
    assert second.sha256 == first.sha256
    assert first.path.parent == runtime

    root = ET.parse(first.path).getroot()
    compiler = root.find("compiler")
    assert compiler is not None
    assert Path(compiler.attrib["meshdir"]).is_absolute()
    assert Path(compiler.attrib["meshdir"]) == base.parent / "meshes"

    texture = root.find("./asset/texture[@name='groundplane']")
    floor = root.find("./worldbody/geom[@name='floor']")
    assert texture is not None and texture.attrib["builtin"] == "checker"
    assert floor is not None and floor.attrib["material"] == "groundplane"


def test_camera_is_attached_to_torso_with_configured_mount(tmp_path):
    generated = generate_scene(
        _write_base_xml(tmp_path / "source"), tmp_path / "runtime", SCENE, CAMERA
    )
    root = ET.parse(generated.path).getroot()

    torso = root.find(".//body[@name='torso_link']")
    assert torso is not None
    camera = torso.find("camera[@name='head_camera']")
    assert camera is not None
    assert camera.attrib["pos"] == "0.18 0 0.35"
    assert camera.attrib["xyaxes"] == "0 -1 0 0 0 1"
    assert float(camera.attrib["fovy"]) == pytest.approx(53.130102, abs=1e-6)


def test_static_indoor_geometry_has_stable_names_and_bounds(tmp_path):
    generated = generate_scene(
        _write_base_xml(tmp_path / "source"), tmp_path / "runtime", SCENE, CAMERA
    )
    root = ET.parse(generated.path).getroot()

    expected_names = {
        "sim_wall_north",
        "sim_wall_south",
        "sim_wall_east",
        "sim_wall_west",
        "sim_corner_northwest",
        "sim_corner_southeast",
        "sim_lidar_floor",
        "sim_lidar_ceiling",
    }
    geoms = {
        geom.attrib["name"]: geom
        for geom in root.findall("./worldbody/geom")
        if geom.attrib.get("name", "").startswith("sim_")
    }
    assert set(geoms) == expected_names
    assert all(geom.attrib["type"] == "box" for geom in geoms.values())
    # Direct children of worldbody are fixed to the world in MJCF.
    assert all(geom in list(root.find("worldbody")) for geom in geoms.values())


def test_generated_scene_adds_exact_lidar_site_and_dedicated_ray_group(tmp_path):
    generated = generate_scene(
        _write_base_xml(tmp_path / "source"),
        tmp_path / "runtime",
        SCENE,
        CAMERA,
        LIDAR,
    )

    root = ET.parse(generated.path).getroot()
    site = root.find(".//body[@name='torso_link']/site[@name='lidar_in_torso']")
    assert site is not None
    assert site.attrib["pos"] == "-0.03959 -0.00224 0.14792"
    assert site.attrib["quat"] == "1 0 0 0"
    generated_geoms = root.findall(".//geom[@group='3']")
    assert len(generated_geoms) == 8
    assert {geom.attrib["name"] for geom in generated_geoms} == {
        "sim_wall_north",
        "sim_wall_south",
        "sim_wall_east",
        "sim_wall_west",
        "sim_corner_northwest",
        "sim_corner_southeast",
        "sim_lidar_floor",
        "sim_lidar_ceiling",
    }
    ray_surfaces = {
        geom.attrib["name"]: geom
        for geom in generated_geoms
        if geom.attrib["name"].startswith("sim_lidar_")
    }
    assert all(geom.attrib["contype"] == "0" for geom in ray_surfaces.values())
    assert all(geom.attrib["conaffinity"] == "0" for geom in ray_surfaces.values())


def test_generated_scene_contains_no_external_include_plugin_or_unitree_sdk(tmp_path):
    generated = generate_scene(
        _write_base_xml(tmp_path / "source"), tmp_path / "runtime", SCENE, CAMERA
    )
    text = generated.path.read_text(encoding="utf-8").lower()

    assert "<include" not in text
    assert "<plugin" not in text
    assert "unitree_sdk" not in text
    assert "network" not in text


def test_refuses_to_overwrite_a_non_generated_file(tmp_path):
    base = _write_base_xml(tmp_path / "source")
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    output = runtime / "holoagent_stage1_scene.xml"
    output.write_text("user-owned", encoding="utf-8")

    with pytest.raises(GeneratedSceneError, match="refusing to overwrite"):
        generate_scene(base, runtime, SCENE, CAMERA)

    assert output.read_text(encoding="utf-8") == "user-owned"


def test_missing_torso_fails_without_writing_output(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    base = source / "base.xml"
    base.write_text("<mujoco><worldbody/></mujoco>", encoding="utf-8")
    runtime = tmp_path / "runtime"

    with pytest.raises(GeneratedSceneError, match="torso_link"):
        generate_scene(base, runtime, SCENE, CAMERA)

    assert not (runtime / "holoagent_stage1_scene.xml").exists()
