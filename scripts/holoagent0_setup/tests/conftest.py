"""Shared test helpers for the HoloAgent0 setup package."""

import os
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def manifest_test_paths(manifest_path: Path) -> tuple[Path, ...]:
    """Return existing test paths declared by a non-empty manifest."""
    relative_paths = tuple(
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if not relative_paths:
        raise ValueError("test manifest must list at least one test path")

    test_paths = []
    missing_paths = []
    for entry in relative_paths:
        entry_path = Path(entry)
        if entry_path.is_absolute():
            raise ValueError(
                "test manifest paths must be relative to the repository root"
            )
        if ".." in entry_path.parts:
            raise ValueError("test manifest paths must not contain parent traversal")

        unresolved_path = REPOSITORY_ROOT / entry_path
        try:
            test_path = unresolved_path.resolve(strict=True)
        except FileNotFoundError:
            missing_paths.append(unresolved_path)
            continue
        try:
            test_path.relative_to(REPOSITORY_ROOT)
        except ValueError as error:
            raise ValueError(
                f"test manifest path resolves outside the repository root: {entry}"
            ) from error
        if not test_path.is_file():
            missing_paths.append(unresolved_path)
            continue
        test_paths.append(test_path)

    if missing_paths:
        missing = ", ".join(str(path) for path in missing_paths)
        raise FileNotFoundError(f"test manifest lists missing files: {missing}")
    return tuple(test_paths)


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

    pytest_environment = os.environ.copy()
    pytest_environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    pytest_environment.pop("PYTEST_ADDOPTS", None)
    pytest_environment.pop("PYTEST_PLUGINS", None)
    os.execve(
        sys.executable,
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-c",
            os.devnull,
            *(str(path) for path in test_paths),
        ],
        pytest_environment,
    )


if __name__ == "__main__":
    raise SystemExit(main())
