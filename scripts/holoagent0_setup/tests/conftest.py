"""Shared test helpers for the HoloAgent0 setup package."""

import os
from pathlib import Path
import sys


def manifest_test_paths(manifest_path: Path) -> tuple[Path, ...]:
    """Return existing test paths declared by a non-empty manifest."""
    relative_paths = tuple(
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not relative_paths:
        raise ValueError("test manifest must list at least one test path")

    manifest_parent = manifest_path.parent
    if (
        manifest_parent.name == "holoagent0_setup"
        and manifest_parent.parent.name == "scripts"
    ):
        path_root = manifest_parent.parent.parent
    else:
        path_root = manifest_parent

    test_paths = tuple(path_root / relative_path for relative_path in relative_paths)
    missing_paths = tuple(path for path in test_paths if not path.is_file())
    if missing_paths:
        missing = ", ".join(str(path) for path in missing_paths)
        raise FileNotFoundError(f"test manifest lists missing files: {missing}")
    return test_paths


def main() -> int:
    """Validate one manifest, then run pytest against only its listed tests."""
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} MANIFEST", file=sys.stderr)
        return 2

    try:
        test_paths = manifest_test_paths(Path(sys.argv[1]).resolve())
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    os.execv(
        sys.executable,
        [sys.executable, "-m", "pytest", "-q", *(str(path) for path in test_paths)],
    )


if __name__ == "__main__":
    raise SystemExit(main())
