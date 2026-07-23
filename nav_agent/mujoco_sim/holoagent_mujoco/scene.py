from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
import xml.etree.ElementTree as ET

from holoagent_mujoco.config import CameraConfig, LidarConfig, SceneConfig, file_sha256


GENERATED_MARKER = "holoagent_mujoco_generated_v1"
OUTPUT_NAME = "holoagent_stage1_scene.xml"


class GeneratedSceneError(RuntimeError):
    """Raised when a safe, deterministic scene cannot be generated."""


@dataclass(frozen=True)
class GeneratedScene:
    path: Path
    sha256: str


def generate_scene(
    base_xml: Path,
    runtime_dir: Path,
    scene: SceneConfig,
    camera: CameraConfig,
    lidar: LidarConfig | None = None,
) -> GeneratedScene:
    """Generate the bounded Stage 1 scene without modifying the pinned model."""
    source = Path(base_xml).expanduser().resolve()
    destination_dir = Path(runtime_dir).expanduser()
    destination = destination_dir / OUTPUT_NAME

    if not source.is_file():
        raise GeneratedSceneError(f"base XML does not exist: {source}")
    if destination.exists() and not _is_generated(destination):
        raise GeneratedSceneError(
            f"refusing to overwrite non-generated file: {destination}"
        )

    try:
        tree = ET.parse(source)
    except (ET.ParseError, OSError) as exc:
        raise GeneratedSceneError(f"cannot parse base XML: {source}") from exc
    root = tree.getroot()
    if root.tag != "mujoco":
        raise GeneratedSceneError("base XML root must be <mujoco>")

    torso = root.find(".//body[@name='torso_link']")
    if torso is None:
        raise GeneratedSceneError("base XML has no torso_link body")
    if root.find(f".//camera[@name='{camera.name}']") is not None:
        raise GeneratedSceneError(f"base XML already has camera named {camera.name}")

    compiler = root.find("compiler")
    if compiler is None:
        compiler = ET.Element("compiler")
        root.insert(0, compiler)
    _make_asset_directory_absolute(compiler, "meshdir", source.parent)
    _make_asset_directory_absolute(compiler, "texturedir", source.parent)

    fovy_degrees = math.degrees(2.0 * math.atan(camera.height / (2.0 * camera.fy)))
    ET.SubElement(
        torso,
        "camera",
        {
            "name": camera.name,
            "mode": "fixed",
            "pos": _numbers(camera.mount_pos),
            "xyaxes": _numbers(camera.mount_xyaxes),
            "fovy": _number(fovy_degrees),
        },
    )
    if lidar is not None:
        if root.find(f".//site[@name='{lidar.name}']") is not None:
            raise GeneratedSceneError(f"base XML already has site named {lidar.name}")
        ET.SubElement(
            torso,
            "site",
            {
                "name": lidar.name,
                "size": "0.01",
                "pos": _numbers(lidar.mount_pos),
                "quat": _numbers(lidar.mount_quat_wxyz),
            },
        )

    worldbody = root.find("worldbody")
    if worldbody is None:
        raise GeneratedSceneError("base XML has no worldbody")
    _add_indoor_geometry(worldbody, scene)
    root.insert(0, ET.Comment(f" {GENERATED_MARKER} "))
    ET.indent(tree, space="  ")

    destination_dir.mkdir(parents=True, exist_ok=True)
    tree.write(destination, encoding="utf-8", xml_declaration=True)
    return GeneratedScene(path=destination, sha256=file_sha256(destination))


def _is_generated(path: Path) -> bool:
    try:
        return GENERATED_MARKER.encode() in path.read_bytes()[:512]
    except OSError:
        return False


def _make_asset_directory_absolute(
    compiler: ET.Element, attribute: str, source_dir: Path
) -> None:
    configured = compiler.attrib.get(attribute)
    if configured is None:
        return
    configured_path = Path(configured).expanduser()
    if not configured_path.is_absolute():
        configured_path = (source_dir / configured_path).resolve()
    compiler.set(attribute, str(configured_path))


def _add_indoor_geometry(worldbody: ET.Element, scene: SceneConfig) -> None:
    half = scene.half_extent
    half_thickness = scene.wall_thickness / 2.0
    half_height = scene.wall_height / 2.0
    wall_center = half + half_thickness
    attributes = {
        "type": "box",
        "group": "3",
        "rgba": "0.62 0.67 0.72 1",
        "friction": "0.8 0.1 0.1",
    }
    walls = (
        (
            "sim_wall_north",
            (0.0, wall_center, half_height),
            (half, half_thickness, half_height),
        ),
        (
            "sim_wall_south",
            (0.0, -wall_center, half_height),
            (half, half_thickness, half_height),
        ),
        (
            "sim_wall_east",
            (wall_center, 0.0, half_height),
            (half_thickness, half, half_height),
        ),
        (
            "sim_wall_west",
            (-wall_center, 0.0, half_height),
            (half_thickness, half, half_height),
        ),
        (
            "sim_corner_northwest",
            (-2.5, 2.5, 0.6),
            (0.35, 0.35, 0.6),
        ),
        (
            "sim_corner_southeast",
            (2.5, -2.5, 0.6),
            (0.35, 0.35, 0.6),
        ),
    )
    for name, position, size in walls:
        if worldbody.find(f"geom[@name='{name}']") is not None:
            raise GeneratedSceneError(f"base XML already has generated geom: {name}")
        ET.SubElement(
            worldbody,
            "geom",
            {
                **attributes,
                "name": name,
                "pos": _numbers(position),
                "size": _numbers(size),
            },
        )


def _numbers(values: tuple[float, ...]) -> str:
    return " ".join(_number(value) for value in values)


def _number(value: float) -> str:
    return f"{value:.9g}"
