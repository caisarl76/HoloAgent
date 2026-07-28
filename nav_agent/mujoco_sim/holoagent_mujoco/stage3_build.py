from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Callable

from holoagent_mujoco.config import file_sha256


class Stage3BuildError(RuntimeError):
    """Raised when a Stage 3 binary cannot be tied to the current source tree."""


Runner = Callable[..., Any]


def directory_sha256(path: Path) -> str:
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise Stage3BuildError(f"source directory does not exist: {root}")
    digest = hashlib.sha256()
    files = sorted(candidate for candidate in root.rglob("*") if candidate.is_file())
    if not files:
        raise Stage3BuildError(f"source directory is empty: {root}")
    for candidate in files:
        relative = candidate.relative_to(root).as_posix().encode("utf-8")
        payload = candidate.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _cmake_home(cache: Path, expected: Path) -> str:
    source = Path(cache).resolve()
    if not source.is_file():
        raise Stage3BuildError(f"CMake cache is missing: {source}")
    prefix = "CMAKE_HOME_DIRECTORY:INTERNAL="
    homes = [
        line.removeprefix(prefix).strip()
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.startswith(prefix)
    ]
    expected_path = Path(expected).resolve()
    if len(homes) != 1 or Path(homes[0]).resolve() != expected_path:
        raise Stage3BuildError(
            f"CMake source mismatch for {source}: expected {expected_path}, got {homes}"
        )
    return str(expected_path)


def _tool_version(name: str, command: list[str], runner: Runner) -> str:
    result = runner(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise Stage3BuildError(f"cannot identify Stage 3 toolchain component {name}")
    lines = (result.stdout or result.stderr).strip().splitlines()
    if not lines:
        raise Stage3BuildError(f"empty Stage 3 toolchain version for {name}")
    return lines[0]


def create_stage3_build_manifest(
    *,
    workspace: Path,
    build_root: Path,
    source_overlay: Path,
    build_log: Path,
    runner: Runner = subprocess.run,
) -> dict[str, object]:
    workspace = Path(workspace).expanduser().resolve()
    build_root = Path(build_root).expanduser().resolve()
    source_overlay = Path(source_overlay).expanduser().resolve()
    build_log = Path(build_log).expanduser().resolve()
    sources = {
        "vikit_common": workspace
        / "agentic_robot/thirdparty/src/rpg_vikit-ros2/vikit_common",
        "vikit_ros": workspace
        / "agentic_robot/thirdparty/src/rpg_vikit-ros2/vikit_ros",
        "fast_livo": workspace / "agentic_robot/core/src/fast_livo",
    }
    patch = (
        workspace / "nav_agent/mujoco_sim/overlays/fast_livo_generated_interface.patch"
    )
    overlay_fastlivo = source_overlay / "fast_livo"
    patched_cmake = overlay_fastlivo / "CMakeLists.txt"
    if not patch.is_file() or not patched_cmake.is_file():
        raise Stage3BuildError("Stage 3 patch or patched source overlay is missing")
    dependency = "add_dependencies(laser_mapping ${PROJECT_NAME}__rosidl_generator_cpp)"
    if dependency not in patched_cmake.read_text(encoding="utf-8"):
        raise Stage3BuildError("FastLIVO generated-interface patch is absent")

    cache_homes = {
        "vikit_common": _cmake_home(
            build_root / "vikit/build/vikit_common/CMakeCache.txt",
            sources["vikit_common"],
        ),
        "vikit_ros": _cmake_home(
            build_root / "vikit/build/vikit_ros/CMakeCache.txt",
            sources["vikit_ros"],
        ),
        "fast_livo": _cmake_home(
            build_root / "fastlivo/build/fast_livo/CMakeCache.txt",
            overlay_fastlivo,
        ),
    }
    binary = build_root / "fastlivo/install/fast_livo/lib/fast_livo/fastlivo_mapping"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise Stage3BuildError(
            f"FastLIVO binary is missing or not executable: {binary}"
        )
    if not build_log.is_file():
        raise Stage3BuildError(f"Stage 3 build log is missing: {build_log}")

    return {
        "kind": "holoagent_stage3_clean_build",
        "workspace": str(workspace),
        "build_root": str(build_root),
        "source_overlay": str(source_overlay),
        "source_trees": {
            name: {"path": str(path), "sha256": directory_sha256(path)}
            for name, path in sources.items()
        },
        "patch": {"path": str(patch), "sha256": file_sha256(patch)},
        "cmake_home_directories": cache_homes,
        "binary": {"path": str(binary), "sha256": file_sha256(binary)},
        "build_log": {
            "path": str(build_log),
            "sha256": file_sha256(build_log),
        },
        "toolchain": {
            "cxx": _tool_version("cxx", ["c++", "--version"], runner),
            "cmake": _tool_version("cmake", ["cmake", "--version"], runner),
            "python": _tool_version("python", ["python3", "--version"], runner),
            "colcon": _tool_version("colcon", ["colcon", "--help"], runner),
        },
        "build_commands": [
            "colcon build --packages-select vikit_common vikit_ros",
            "copy FastLIVO source and apply fast_livo_generated_interface.patch",
            "colcon build --packages-select fast_livo",
        ],
    }


def _write_json(path: Path, value: object) -> None:
    destination = Path(path).expanduser().resolve()
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record a clean Stage 3 build")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--source-overlay", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    evidence = create_stage3_build_manifest(
        workspace=arguments.workspace,
        build_root=arguments.build_root,
        source_overlay=arguments.source_overlay,
        build_log=arguments.build_log,
    )
    _write_json(arguments.output, evidence)
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
