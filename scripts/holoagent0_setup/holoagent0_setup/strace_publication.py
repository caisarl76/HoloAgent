"""Race-safe publication helpers for the pinned strace provisioner."""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
from pathlib import Path
import stat
from typing import Mapping

from .atomic_io import atomic_write_json_no_replace


_RENAME_NOREPLACE = 1


class PublicationError(RuntimeError):
    """The reviewed strace artifact could not be published safely."""


def publish_candidate_evidence(
    destination: Path, evidence: Mapping[str, object]
) -> None:
    """Publish canonical candidate evidence without replacing any path."""

    atomic_write_json_no_replace(Path(destination), evidence, mode=0o600)


def publish_install_directory(staged: Path, destination: Path) -> None:
    """Atomically publish a same-parent directory with no-replace semantics."""

    staged = Path(staged)
    destination = Path(destination)
    if not staged.is_absolute() or not destination.is_absolute():
        raise PublicationError("install paths must be absolute")
    if ".." in staged.parts or ".." in destination.parts:
        raise PublicationError("install paths must not contain parent traversal")
    if staged.parent != destination.parent:
        raise PublicationError(
            "staged install and destination must use the same parent"
        )
    try:
        lexical_parent = Path(os.path.abspath(staged.parent))
        resolved_parent = staged.parent.resolve(strict=True)
    except OSError as error:
        raise PublicationError("install parent is unavailable") from error
    if lexical_parent != resolved_parent:
        raise PublicationError("install parent must not traverse a symlink")
    if not staged.name or not destination.name:
        raise PublicationError("install paths require safe final names")

    directory_fd = -1
    staged_fd = -1
    try:
        directory_fd = os.open(
            resolved_parent,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        parent_stat = os.fstat(directory_fd)
        _require_parent_path_identity(resolved_parent, parent_stat)
        staged_fd = os.open(
            staged.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        staged_stat = os.fstat(staged_fd)
        if not stat.S_ISDIR(staged_stat.st_mode):
            raise PublicationError("staged install is not a directory")

        _rename_no_replace(directory_fd, staged.name, destination.name)
        os.fsync(directory_fd)

        final_parent_stat = os.fstat(directory_fd)
        if (final_parent_stat.st_dev, final_parent_stat.st_ino) != (
            parent_stat.st_dev,
            parent_stat.st_ino,
        ):
            raise PublicationError("install parent identity changed during publication")
        _require_parent_path_identity(resolved_parent, final_parent_stat)
        installed_stat = os.stat(
            destination.name, dir_fd=directory_fd, follow_symlinks=False
        )
        retained_stat = os.fstat(staged_fd)
        if not stat.S_ISDIR(installed_stat.st_mode) or (
            installed_stat.st_dev,
            installed_stat.st_ino,
        ) != (retained_stat.st_dev, retained_stat.st_ino):
            raise PublicationError("published install identity changed")
    except FileExistsError:
        raise
    except PublicationError:
        raise
    except OSError as error:
        raise PublicationError(f"install publication failed: {error}") from error
    finally:
        if staged_fd >= 0:
            os.close(staged_fd)
        if directory_fd >= 0:
            os.close(directory_fd)


def _require_parent_path_identity(path: Path, retained_stat: os.stat_result) -> None:
    try:
        path_stat = os.stat(path, follow_symlinks=False)
    except OSError as error:
        raise PublicationError("install parent path became unavailable") from error
    if not stat.S_ISDIR(path_stat.st_mode) or (
        path_stat.st_dev,
        path_stat.st_ino,
    ) != (retained_stat.st_dev, retained_stat.st_ino):
        raise PublicationError("install parent path identity changed")


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise PublicationError("renameat2 is unavailable on this reviewed platform")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    raise OSError(error_number, os.strerror(error_number), destination)


def _candidate_evidence(arguments: argparse.Namespace) -> dict[str, object]:
    return {
        "schema_version": "holoagent0.strace-candidate-evidence.v1",
        "measurement_kind": "CANDIDATE_MEASUREMENT",
        "recipe_sha256": arguments.recipe_sha256,
        "container_image_digest": arguments.container_image_digest,
        "elf_size": arguments.elf_size,
        "elf_sha256": arguments.elf_sha256,
        "version_output_sha256": arguments.version_output_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    candidate = subparsers.add_parser("candidate")
    candidate.add_argument("destination", type=Path)
    candidate.add_argument("recipe_sha256")
    candidate.add_argument("container_image_digest")
    candidate.add_argument("elf_size", type=int)
    candidate.add_argument("elf_sha256")
    candidate.add_argument("version_output_sha256")
    install = subparsers.add_parser("install")
    install.add_argument("staged", type=Path)
    install.add_argument("destination", type=Path)
    arguments = parser.parse_args(argv)

    if arguments.command == "candidate":
        publish_candidate_evidence(
            arguments.destination, _candidate_evidence(arguments)
        )
    else:
        publish_install_directory(arguments.staged, arguments.destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
