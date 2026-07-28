from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

import pytest

from holoagent_mujoco.stage3_build import (
    Stage3BuildError,
    create_stage3_build_manifest,
    directory_sha256,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_ROOT.parents[1]
SOURCE = REPO_ROOT / "agentic_robot" / "core" / "src" / "fast_livo"
PATCH = PACKAGE_ROOT / "overlays" / "fast_livo_generated_interface.patch"


def test_fastlivo_overlay_applies_without_modifying_pinned_source(tmp_path):
    source_cmake = SOURCE / "CMakeLists.txt"
    original = source_cmake.read_bytes()
    assert hashlib.sha1(b"blob " + str(len(original)).encode() + b"\0" + original).hexdigest() == (
        "4c5b6d2ac1c40740f791cdbd15196073866701f8"
    )
    overlay = tmp_path / "fast_livo"
    subprocess.run(["cp", "-a", str(SOURCE), str(overlay)], check=True)

    result = subprocess.run(
        ["patch", "-p1", "-i", str(PATCH)],
        cwd=overlay,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    patched = (overlay / "CMakeLists.txt").read_text(encoding="utf-8")
    assert "add_dependencies(laser_mapping ${PROJECT_NAME}__rosidl_generator_cpp)" in patched
    assert source_cmake.read_bytes() == original


def test_stage3_build_manifest_binds_sources_cache_homes_binary_and_toolchain(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    vikit = workspace / "agentic_robot/thirdparty/src/rpg_vikit-ros2"
    fastlivo = workspace / "agentic_robot/core/src/fast_livo"
    package = workspace / "nav_agent/mujoco_sim"
    for path in (vikit / "vikit_common", vikit / "vikit_ros", fastlivo, package / "overlays"):
        path.mkdir(parents=True)
        (path / "source.txt").write_text(str(path), encoding="utf-8")
    patch = package / "overlays/fast_livo_generated_interface.patch"
    patch.write_text("patch", encoding="utf-8")

    source_overlay = tmp_path / "source"
    overlay_fastlivo = source_overlay / "fast_livo"
    overlay_fastlivo.mkdir(parents=True)
    (overlay_fastlivo / "CMakeLists.txt").write_text(
        "add_dependencies(laser_mapping ${PROJECT_NAME}__rosidl_generator_cpp)\n",
        encoding="utf-8",
    )
    build_root = tmp_path / "build"
    cache_homes = {
        build_root / "vikit/build/vikit_common/CMakeCache.txt": vikit
        / "vikit_common",
        build_root / "vikit/build/vikit_ros/CMakeCache.txt": vikit / "vikit_ros",
        build_root / "fastlivo/build/fast_livo/CMakeCache.txt": overlay_fastlivo,
    }
    for cache, home in cache_homes.items():
        cache.parent.mkdir(parents=True)
        cache.write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={home}\n", encoding="utf-8")
    binary = build_root / "fastlivo/install/fast_livo/lib/fast_livo/fastlivo_mapping"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"binary")
    binary.chmod(0o755)
    build_log = tmp_path / "build.log"
    build_log.write_text("clean build", encoding="utf-8")

    def runner(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, f"{command[0]} version\n", "")

    evidence = create_stage3_build_manifest(
        workspace=workspace,
        build_root=build_root,
        source_overlay=source_overlay,
        build_log=build_log,
        runner=runner,
    )

    assert evidence["binary"]["sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert evidence["source_trees"]["fast_livo"]["sha256"] == directory_sha256(
        fastlivo
    )
    assert evidence["cmake_home_directories"]["fast_livo"] == str(
        overlay_fastlivo.resolve()
    )
    assert evidence["toolchain"]["cxx"] == "c++ version"

    (build_root / "fastlivo/build/fast_livo/CMakeCache.txt").write_text(
        "CMAKE_HOME_DIRECTORY:INTERNAL=/stale/source\n", encoding="utf-8"
    )
    with pytest.raises(Stage3BuildError, match="CMake source mismatch"):
        create_stage3_build_manifest(
            workspace=workspace,
            build_root=build_root,
            source_overlay=source_overlay,
            build_log=build_log,
            runner=runner,
        )
