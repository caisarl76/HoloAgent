from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess


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
