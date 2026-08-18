"""Build and atomically publish closed FSR-VLN Stage A handover evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from importlib import import_module, metadata
import inspect
import json
import math
import os
from pathlib import Path
import platform
import stat
import sys
from typing import Mapping

from .atomic_io import (
    ArtifactDescriptor,
    AtomicIOError,
    AtomicPublicationAmbiguity,
    atomic_write_json_no_replace,
    canonical_json_bytes,
    read_json_secure,
)
from .contract import ContractError, ContractSet
from .semantic_gate import (
    CHECKPOINT_SHA256,
    DATASET_ROOT_SHA256,
    EXPECTED_SEMANTIC,
    GRAPH_ROOT_SHA256,
    GraphCounts,
    ROOM_NAME_MAPPING_SHA256,
    SemanticFixtureResult,
    STRUCTURED_QUERY_SHA256,
    import_root_hmsg_runtime,
)
from .source_gate import (
    HandoverPaths,
    PathIdentity,
    SourceVerification,
    VerifiedAssetLock,
)


ENVIRONMENT_FILE = "environment.json"
SOURCE_FILE = "source-verification.json"
ASSET_FILE = "asset-verification.json"
QUERY_FILE = "query-result.json"
RESULT_FILE = "handover-result.json"
EVIDENCE_ORDER = (ENVIRONMENT_FILE, SOURCE_FILE, ASSET_FILE, QUERY_FILE)
BLOCKING_ORDER = (SOURCE_FILE, ENVIRONMENT_FILE, ASSET_FILE, QUERY_FILE)

REQUIRED_IMPORTS = (
    ("pytorch", "torch"),
    ("open3d", "open3d"),
    ("openclip", "open_clip"),
    ("numpy", "numpy"),
    ("omegaconf", "omegaconf"),
    ("faiss", "faiss"),
    ("opencv", "cv2"),
    ("networkx", "networkx"),
    ("pyvista", "pyvista"),
    ("scikit-fmm", "skfmm"),
    ("oss2", "oss2"),
    ("segment-anything", "segment_anything"),
)

_DISTRIBUTION_CANDIDATES = {
    "pytorch": ("torch",),
    "open3d": ("open3d",),
    "openclip": ("open-clip-torch",),
    "numpy": ("numpy",),
    "omegaconf": ("omegaconf",),
    "faiss": ("faiss-cpu", "faiss-gpu", "faiss"),
    "opencv": (
        "opencv-python",
        "opencv-python-headless",
        "opencv-contrib-python",
        "opencv-contrib-python-headless",
    ),
    "networkx": ("networkx",),
    "pyvista": ("pyvista",),
    "scikit-fmm": ("scikit-fmm",),
    "oss2": ("oss2",),
    "segment-anything": ("segment-anything",),
}

_STAGE_SCHEMAS = {
    ENVIRONMENT_FILE: "fsrvln-environment-v1",
    SOURCE_FILE: "fsrvln-source-verification-v1",
    ASSET_FILE: "fsrvln-asset-verification-v1",
    QUERY_FILE: "fsrvln-query-result-v1",
}
_MISSING = object()


@dataclass(frozen=True)
class PublicationFailure:
    """One failed validation, write, authority, or terminal publication attempt."""

    filename: str
    phase: str
    error: Exception


class EvidencePublicationError(RuntimeError):
    """One or more evidence artifacts could not be published unambiguously."""

    def __init__(self, failures: tuple[PublicationFailure, ...]) -> None:
        if not failures:
            raise ValueError("publication failure set must not be empty")
        self.failures = failures
        detail = "; ".join(
            f"{failure.filename}/{failure.phase}: {failure.error}"
            for failure in failures
        )
        super().__init__(detail)


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _stage_header(
    schema_version: str,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "status": status,
        "reason": reason,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def _optional_object(value: Mapping[str, object] | None) -> dict[str, object] | None:
    return None if value is None else dict(value)


def _optional_rows(
    value: list[dict[str, object]] | tuple[dict[str, object], ...] | None,
) -> list[dict[str, object]] | None:
    return None if value is None else [dict(row) for row in value]


def build_environment_document(
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
    os_release: str | None = None,
    machine_architecture: str | None = None,
    python: Mapping[str, object] | None = None,
    accelerator: Mapping[str, object] | None = None,
    imports: list[dict[str, object]] | tuple[dict[str, object], ...] | None = None,
    graph_module_origin: str | None = None,
) -> dict[str, object]:
    """Build one environment stage document with explicit null observations."""

    if status == "NOT_RUN":
        os_release = None
        machine_architecture = None
        python = None
        accelerator = None
        imports = None
        graph_module_origin = None
    return {
        **_stage_header(
            "holoagent0.fsrvln.environment.v1",
            status,
            reason,
            started_at,
            finished_at,
        ),
        "os_release": os_release,
        "machine_architecture": machine_architecture,
        "python": _optional_object(python),
        "accelerator": _optional_object(accelerator),
        "imports": _optional_rows(imports),
        "graph_module_origin": graph_module_origin,
    }


def _module_origin(module: object) -> str | None:
    specification = getattr(module, "__spec__", None)
    specification_origin = getattr(specification, "origin", None)
    if type(specification_origin) is str and specification_origin:
        return specification_origin
    file_origin = getattr(module, "__file__", None)
    return file_origin if type(file_origin) is str and file_origin else None


def _module_version(display_name: str, module: object) -> str | None:
    try:
        inspect.getattr_static(module, "__version__")
    except AttributeError:
        direct = _MISSING
    else:
        direct = getattr(module, "__version__")
    if direct is not _MISSING:
        if type(direct) is not str or not direct:
            raise ValueError("module __version__ must be nonempty text when exposed")
        return direct
    for candidate in _DISTRIBUTION_CANDIDATES[display_name]:
        try:
            observed = metadata.version(candidate)
        except metadata.PackageNotFoundError:
            continue
        if type(observed) is not str or not observed:
            raise ValueError(f"distribution {candidate} returned an invalid version")
        return observed
    return None


def _failed_import_row(
    display_name: str, module_name: str, reason: str
) -> dict[str, object]:
    return {
        "name": display_name,
        "module": module_name,
        "status": "FAIL",
        "version": None,
        "origin": None,
        "reason": reason,
    }


def _replace_import_failure(
    rows: list[dict[str, object]], module_name: str, reason: str
) -> None:
    for index, row in enumerate(rows):
        if row["module"] == module_name:
            failed = dict(row)
            failed.update(status="FAIL", reason=reason)
            rows[index] = failed
            return
    raise RuntimeError(f"required import row is absent: {module_name}")


def qualify_environment(paths: HandoverPaths) -> dict[str, object]:
    """Import the closed dependency list and prove the root-level Graph origin."""

    started_at = _utc_timestamp()
    rows: list[dict[str, object]] = []
    imported: dict[str, object] = {}
    failures: list[str] = []
    for display_name, module_name in REQUIRED_IMPORTS:
        try:
            module = import_module(module_name)
        except ModuleNotFoundError as error:
            if error.name == module_name:
                reason = f"IMPORT_MISSING: {module_name}"
            else:
                reason = f"IMPORT_FAILED: {module_name}: ModuleNotFoundError: {error}"
            rows.append(_failed_import_row(display_name, module_name, reason))
            failures.append(reason)
            continue
        except Exception as error:
            reason = f"IMPORT_FAILED: {module_name}: {type(error).__name__}: {error}"
            rows.append(_failed_import_row(display_name, module_name, reason))
            failures.append(reason)
            continue

        try:
            observed_name = getattr(module, "__name__", None)
            if observed_name != module_name:
                raise ValueError(f"expected {module_name}, got {observed_name!r}")
            version = _module_version(display_name, module)
            origin = _module_origin(module)
        except Exception as error:
            prefix = (
                "IMPORT_IDENTITY_MISMATCH"
                if isinstance(error, ValueError)
                and str(error).startswith(f"expected {module_name},")
                else "IMPORT_OBSERVATION_FAILED"
            )
            reason = f"{prefix}: {module_name}: {type(error).__name__}: {error}"
            rows.append(_failed_import_row(display_name, module_name, reason))
            failures.append(reason)
            continue
        else:
            imported[module_name] = module
            rows.append(
                {
                    "name": display_name,
                    "module": module_name,
                    "status": "PASS",
                    "version": version,
                    "origin": origin,
                    "reason": "OK",
                }
            )

    accelerator: dict[str, object] | None = None
    torch_module = imported.get("torch")
    if torch_module is not None:
        try:
            version_namespace = getattr(torch_module, "version")
            cuda_build = getattr(version_namespace, "cuda")
            if cuda_build is not None and (
                type(cuda_build) is not str or not cuda_build
            ):
                raise ValueError("torch.version.cuda must be text or null")
            cuda_available = getattr(getattr(torch_module, "cuda"), "is_available")()
            if type(cuda_available) is not bool:
                raise ValueError("torch.cuda.is_available() must return bool")
            accelerator = {
                "label": "GPU" if cuda_available else "CPU",
                "torch_cuda_build": cuda_build,
                "cuda_available": cuda_available,
            }
            if cuda_available and cuda_build is None:
                reason = "CUDA_BUILD_MISSING: torch reports CUDA available"
                _replace_import_failure(rows, "torch", reason)
                failures.append(reason)
        except Exception as error:
            reason = f"CUDA_QUALIFICATION_FAILED: {type(error).__name__}: {error}"
            _replace_import_failure(rows, "torch", reason)
            failures.append(reason)
            accelerator = None

    graph_module_origin: str | None = None
    try:
        _graph_module, _omega_conf, observed_origin = import_root_hmsg_runtime(paths)
        expected_origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
        if observed_origin != expected_origin:
            raise ValueError(f"expected {expected_origin}, got {observed_origin}")
        graph_module_origin = str(observed_origin)
    except Exception as error:
        reason = f"GRAPH_MODULE_ORIGIN_FAILED: {type(error).__name__}: {error}"
        failures.append(reason)

    try:
        os_release: str | None = platform.platform()
    except Exception as error:
        os_release = None
        failures.append(f"PLATFORM_OBSERVATION_FAILED: {type(error).__name__}: {error}")
    try:
        machine_architecture: str | None = platform.machine()
    except Exception as error:
        machine_architecture = None
        failures.append(f"MACHINE_OBSERVATION_FAILED: {type(error).__name__}: {error}")

    finished_at = _utc_timestamp()
    return build_environment_document(
        status="FAIL" if failures else "PASS",
        reason=failures[0] if failures else "OK",
        started_at=started_at,
        finished_at=finished_at,
        os_release=os_release,
        machine_architecture=machine_architecture,
        python={"executable": sys.executable, "version": sys.version},
        accelerator=accelerator,
        imports=rows,
        graph_module_origin=graph_module_origin,
    )


def path_identity_document(identity: PathIdentity) -> dict[str, object]:
    """Serialize one retained path identity without resolving or restating it."""

    if not isinstance(identity, PathIdentity):
        raise TypeError("a PathIdentity instance is required")
    return {
        "path": str(identity.path),
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


def _retained_identity(paths: HandoverPaths, role: str) -> PathIdentity:
    roles = (
        "repository_root",
        "data_root",
        "graph",
        "dataset",
        "checkpoint",
        "asset_lock",
    )
    if not isinstance(paths, HandoverPaths) or role not in roles:
        raise TypeError("a retained HandoverPaths role is required")
    if len(paths.identities) != len(roles):
        raise ValueError("handover path identities are incomplete")
    identity = paths.identities[roles.index(role)]
    if identity.path != getattr(paths, role):
        raise ValueError(f"handover identity does not match role: {role}")
    return identity


def build_source_document(
    paths: HandoverPaths,
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
    checkout_commit: str | None = None,
    verification: SourceVerification | None = None,
) -> dict[str, object]:
    """Build source verification evidence from exact retained observations."""

    if status == "NOT_RUN":
        checkout_commit = None
        verification = None
    return {
        **_stage_header(
            "holoagent0.fsrvln.source-verification.v1",
            status,
            reason,
            started_at,
            finished_at,
        ),
        "repository_root": path_identity_document(
            _retained_identity(paths, "repository_root")
        ),
        "checkout_commit": checkout_commit,
        "source_lock_commit": None if verification is None else verification.commit,
        "verified_count": (
            None if verification is None else verification.verified_count
        ),
        "provenance": (
            None
            if verification is None
            else [
                {"commit": commit, "count": count}
                for commit, count in verification.provenance
            ]
        ),
    }


def build_asset_document(
    paths: HandoverPaths,
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
    asset_lock_sha256: str | None = None,
    verification: VerifiedAssetLock | None = None,
) -> dict[str, object]:
    """Build asset evidence from retained identities and verified manifests."""

    if status == "NOT_RUN":
        asset_lock_sha256 = None
        verification = None
    assets: list[dict[str, object]] | None = None
    if verification is not None:
        specifications = tuple(verification.lock.assets)
        manifests = tuple(verification.manifests)
        expected_roles = ("graph", "dataset", "checkpoint")
        if (
            len(specifications) != len(expected_roles)
            or len(manifests) != len(expected_roles)
            or tuple(specification.role for specification in specifications)
            != expected_roles
        ):
            raise ValueError("verified asset roles are incomplete or out of order")
        assets = []
        for role, manifest in zip(expected_roles, manifests):
            identity = _retained_identity(paths, role)
            assets.append(
                {
                    "role": role,
                    "path": str(identity.path),
                    "device": identity.device,
                    "inode": identity.inode,
                    "file_count": manifest.file_count,
                    "byte_count": manifest.byte_count,
                    "sha256": manifest.sha256,
                }
            )
    return {
        **_stage_header(
            "holoagent0.fsrvln.asset-verification.v1",
            status,
            reason,
            started_at,
            finished_at,
        ),
        "data_root": path_identity_document(_retained_identity(paths, "data_root")),
        "asset_lock_sha256": asset_lock_sha256,
        "assets": assets,
    }


def _query_result_document(
    graph_counts: GraphCounts, result: SemanticFixtureResult
) -> dict[str, object]:
    return {
        "graph_counts": {
            "floors": graph_counts.floors,
            "rooms": graph_counts.rooms,
            "objects": graph_counts.objects,
        },
        "graph_identity": result.graph_identity,
        "floor_id": result.floor_id,
        "room": {"id": result.room_id, "name": result.room_name},
        "object": {"id": result.object_id, "name": result.object_name},
        "frame_id": result.frame_id,
        "position": list(result.position),
        "orientation": list(result.orientation),
        "structured_query_sha256": result.structured_query_sha256,
        "graph_root_sha256": result.graph_root_sha256,
        "dataset_root_sha256": result.dataset_root_sha256,
        "checkpoint_sha256": result.checkpoint_sha256,
        "room_name_mapping_sha256": result.room_name_mapping_sha256,
    }


def build_query_document(
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
    query_sha256: str,
    graph_counts: GraphCounts | None = None,
    result: SemanticFixtureResult | None = None,
    execution_count: int | None = None,
) -> dict[str, object]:
    """Build fixed-query evidence with exact once/not-run execution semantics."""

    if status == "PASS":
        execution_count = 1
    elif status == "NOT_RUN":
        execution_count = 0
        graph_counts = None
        result = None
    elif execution_count is None:
        execution_count = 0
    result_document = (
        _query_result_document(graph_counts, result)
        if graph_counts is not None and result is not None
        else None
    )
    return {
        **_stage_header(
            "holoagent0.fsrvln.query-result.v1",
            status,
            reason,
            started_at,
            finished_at,
        ),
        "query_sha256": query_sha256,
        "execution_count": execution_count,
        "result": result_document,
    }


def validate_and_publish_stage(
    contract: ContractSet,
    schema_name: str,
    run_directory: Path,
    filename: str,
    document: dict[str, object],
    *,
    parent_fd: int | None = None,
    expected_parent_identity: tuple[int, int] | None = None,
) -> ArtifactDescriptor:
    """Validate one stage and atomically install its canonical JSON once."""

    contract.require_valid_document(schema_name, document)
    return atomic_write_json_no_replace(
        run_directory / filename,
        document,
        relative_to=run_directory,
        parent_fd=parent_fd,
        expected_parent_identity=expected_parent_identity,
    )


def _require_descriptor_matches(
    descriptor: ArtifactDescriptor, filename: str, document: dict[str, object]
) -> None:
    payload = canonical_json_bytes(document)
    if (
        descriptor.relative_path != filename
        or descriptor.sha256 != hashlib.sha256(payload).hexdigest()
        or descriptor.size != len(payload)
    ):
        raise AtomicIOError(f"atomic descriptor differs from canonical {filename}")


class _RunDirectoryAuthority:
    """One retained no-follow directory descriptor for the complete publication."""

    def __init__(self, path: Path, identity: PathIdentity, descriptor: int) -> None:
        self.path = path
        self.identity = identity
        self._descriptor = descriptor

    @classmethod
    def retain(
        cls, run_directory: Path, identity: PathIdentity
    ) -> "_RunDirectoryAuthority":
        if not isinstance(identity, PathIdentity):
            raise AtomicIOError("run directory identity is not retained")
        try:
            raw = os.fspath(run_directory)
        except TypeError as error:
            raise AtomicIOError("run directory is not path-like") from error
        if type(raw) is not str:
            raise AtomicIOError("run directory path must be text")
        path = Path(raw)
        if (
            not path.is_absolute()
            or raw != os.path.normpath(raw)
            or raw != path.as_posix()
            or identity.path != path
        ):
            raise AtomicIOError("run directory path differs from retained identity")

        flags = (
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path.anchor, flags)
        try:
            for component in path.parts[1:]:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            authority = cls(path, identity, descriptor)
            authority.revalidate()
            return authority
        except BaseException:
            os.close(descriptor)
            raise

    @property
    def descriptor(self) -> int:
        if self._descriptor < 0:
            raise AtomicIOError("run directory authority is closed")
        return self._descriptor

    @property
    def parent_identity(self) -> tuple[int, int]:
        return self.identity.device, self.identity.inode

    def revalidate(self) -> None:
        retained = os.fstat(self.descriptor)
        try:
            lexical = os.stat(self.path, follow_symlinks=False)
            resolved = self.path.resolve(strict=True)
        except OSError as error:
            raise AtomicIOError(
                "run directory lexical binding is unavailable"
            ) from error
        expected = (self.identity.device, self.identity.inode, self.identity.mode)
        if (
            not stat.S_ISDIR(retained.st_mode)
            or retained.st_uid != os.getuid()
            or (retained.st_dev, retained.st_ino, retained.st_mode) != expected
            or (lexical.st_dev, lexical.st_ino, lexical.st_mode) != expected
            or resolved != self.path
        ):
            raise AtomicIOError("run directory lexical binding changed")

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def _replay_published_document(
    contract: ContractSet,
    authority: _RunDirectoryAuthority,
    schema_name: str,
    filename: str,
    expected_document: dict[str, object],
    expected_descriptor: ArtifactDescriptor,
) -> ArtifactDescriptor:
    authority.revalidate()
    value, replayed_descriptor = read_json_secure(
        authority.path / filename,
        expected_mode=0o600,
        relative_to=authority.path,
        directory_fd=authority.descriptor,
    )
    authority.revalidate()
    if type(value) is not dict or value != expected_document:
        raise AtomicIOError(f"replayed {filename} differs from expected document")
    contract.require_valid_document(schema_name, value)
    _require_descriptor_matches(replayed_descriptor, filename, expected_document)
    if replayed_descriptor != expected_descriptor:
        raise AtomicIOError(f"replayed {filename} differs from publication proof")
    return replayed_descriptor


def _require_reserved_names_absent(authority: _RunDirectoryAuthority) -> None:
    authority.revalidate()
    collisions: list[str] = []
    for filename in (*EVIDENCE_ORDER, RESULT_FILE):
        try:
            os.stat(
                filename,
                dir_fd=authority.descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AtomicIOError(
                f"reserved artifact name could not be inspected: {filename}"
            ) from error
        collisions.append(filename)
    authority.revalidate()
    if collisions:
        raise EvidencePublicationError(
            tuple(
                PublicationFailure(
                    filename,
                    "reserved_name_collision",
                    FileExistsError(f"reserved artifact name exists: {filename}"),
                )
                for filename in collisions
            )
        )


def _semantic_failure(detail: str) -> EvidencePublicationError:
    return EvidencePublicationError(
        (
            PublicationFailure(
                ENVIRONMENT_FILE,
                "cross_document_validation",
                ValueError(detail),
            ),
        )
    )


def _environment_runtime_label(document: Mapping[str, object]) -> str | None:
    status = document.get("status")
    rows = document.get("imports")
    accelerator = document.get("accelerator")
    if status == "NOT_RUN":
        if rows is not None or accelerator is not None:
            raise _semantic_failure(
                "NOT_RUN environment must contain null imports and accelerator"
            )
        return None
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_IMPORTS):
        raise _semantic_failure("environment must contain all 12 required imports")
    observed_order = tuple(
        (row.get("name"), row.get("module")) if isinstance(row, dict) else (None, None)
        for row in rows
    )
    if observed_order != REQUIRED_IMPORTS:
        raise _semantic_failure("environment required imports are out of order")
    row_statuses = tuple(
        row.get("status") if isinstance(row, dict) else None for row in rows
    )
    if any(row_status not in {"PASS", "FAIL"} for row_status in row_statuses):
        raise _semantic_failure("environment import row status is invalid")
    if status == "PASS" and any(row_status != "PASS" for row_status in row_statuses):
        raise _semantic_failure("environment PASS requires every import row to PASS")

    if accelerator is None:
        if status == "PASS":
            raise _semantic_failure(
                "environment PASS requires accelerator observations"
            )
        return None
    if not isinstance(accelerator, dict):
        raise _semantic_failure("accelerator evidence must be an object or null")
    cuda_available = accelerator.get("cuda_available")
    cuda_build = accelerator.get("torch_cuda_build")
    label = accelerator.get("label")
    if type(cuda_available) is not bool:
        raise _semantic_failure("CUDA availability must be boolean")
    expected_label = "GPU" if cuda_available else "CPU"
    if label != expected_label:
        raise _semantic_failure("accelerator label disagrees with CUDA availability")
    if cuda_build is not None and (type(cuda_build) is not str or not cuda_build):
        raise _semantic_failure("PyTorch CUDA build must be nonempty text or null")
    if status == "PASS" and cuda_available and cuda_build is None:
        raise _semantic_failure("CUDA availability requires a PyTorch CUDA build")
    return expected_label


def _require_repository_binding(
    environment: Mapping[str, object],
    source: Mapping[str, object],
    authoritative_repository_root: PathIdentity,
) -> None:
    expected_identity = path_identity_document(authoritative_repository_root)
    recorded_identity = source.get("repository_root")
    if type(recorded_identity) is not dict or recorded_identity != expected_identity:
        raise _semantic_failure(
            "source repository identity disagrees with authoritative repository identity"
        )
    if environment.get("status") != "PASS":
        return
    repository_path = expected_identity["path"]
    graph_origin = environment.get("graph_module_origin")
    if type(graph_origin) is not str:
        raise _semantic_failure(
            "environment PASS graph module origin requires an authoritative source root"
        )
    root = Path(repository_path)
    origin = Path(graph_origin)
    if (
        not root.is_absolute()
        or str(root) != repository_path
        or ".." in root.parts
        or not origin.is_absolute()
        or str(origin) != graph_origin
        or ".." in origin.parts
    ):
        raise _semantic_failure(
            "environment PASS graph module origin must be an exact absolute path"
        )
    expected = root / "fsr_vln/memory/hmsg/graph/graph.py"
    if origin != expected or graph_origin != str(expected):
        raise _semantic_failure(
            "environment PASS graph module origin disagrees with source root"
        )


def _require_pass_stage_bindings(
    source: Mapping[str, object],
    asset: Mapping[str, object],
    query: Mapping[str, object],
    *,
    accepted_implementation_commit: str | None,
    authoritative_data_root: PathIdentity,
) -> None:
    if source.get("status") == "PASS" and accepted_implementation_commit != source.get(
        "checkout_commit"
    ):
        raise _semantic_failure(
            "accepted implementation commit disagrees with source checkout"
        )

    asset_rows: list[dict[str, object]] | None = None
    if asset.get("status") == "PASS":
        if asset.get("data_root") != path_identity_document(authoritative_data_root):
            raise _semantic_failure(
                "asset data root disagrees with authoritative data root"
            )
        observed_rows = asset.get("assets")
        if type(observed_rows) is not list or len(observed_rows) != 3:
            raise _semantic_failure("asset PASS requires exactly three asset rows")
        if any(type(row) is not dict for row in observed_rows):
            raise _semantic_failure("asset PASS rows must be exact objects")
        asset_rows = observed_rows
        if tuple(row.get("role") for row in asset_rows) != (
            "graph",
            "dataset",
            "checkpoint",
        ):
            raise _semantic_failure(
                "asset PASS roles must be graph, dataset, checkpoint in order"
            )
        expected_asset_digests = (
            GRAPH_ROOT_SHA256,
            DATASET_ROOT_SHA256,
            CHECKPOINT_SHA256,
        )
        if tuple(row.get("sha256") for row in asset_rows) != expected_asset_digests:
            raise _semantic_failure("asset PASS digests differ from pinned assets")

    if query.get("status") != "PASS":
        return
    result = query.get("result")
    if query.get("execution_count") != 1 or type(result) is not dict:
        raise _semantic_failure(
            "query PASS requires one execution and a semantic result"
        )
    if (
        query.get("query_sha256") != STRUCTURED_QUERY_SHA256
        or result.get("structured_query_sha256") != STRUCTURED_QUERY_SHA256
    ):
        raise _semantic_failure("query digest differs from the pinned structured query")

    semantic_digests = (
        result.get("graph_root_sha256"),
        result.get("dataset_root_sha256"),
        result.get("checkpoint_sha256"),
        result.get("room_name_mapping_sha256"),
    )
    expected_semantic_digests = (
        GRAPH_ROOT_SHA256,
        DATASET_ROOT_SHA256,
        CHECKPOINT_SHA256,
        ROOM_NAME_MAPPING_SHA256,
    )
    if semantic_digests != expected_semantic_digests:
        raise _semantic_failure("semantic result digests differ from pinned fixtures")
    if (
        asset_rows is not None
        and tuple(row.get("sha256") for row in asset_rows) != semantic_digests[:3]
    ):
        raise _semantic_failure("semantic result digests disagree with asset evidence")

    if result.get("graph_counts") != {
        "floors": 1,
        "rooms": 3,
        "objects": 497,
    }:
        raise _semantic_failure("semantic graph counts differ from the pinned fixture")
    expected = EXPECTED_SEMANTIC
    observed_identity = (
        result.get("graph_identity"),
        result.get("floor_id"),
        result.get("room"),
        result.get("object"),
        result.get("frame_id"),
    )
    expected_identity = (
        expected.graph_identity,
        expected.floor_id,
        {"id": expected.room_id, "name": expected.room_name},
        {"id": expected.object_id, "name": expected.object_name},
        expected.frame_id,
    )
    if observed_identity != expected_identity:
        raise _semantic_failure("semantic identities differ from the pinned fixture")

    position = result.get("position")
    if (
        type(position) is not list
        or len(position) != len(expected.position)
        or any(type(value) not in {int, float} for value in position)
        or any(
            not math.isclose(
                actual,
                expected_value,
                rel_tol=0.0,
                abs_tol=1e-6,
            )
            for actual, expected_value in zip(position, expected.position)
        )
    ):
        raise _semantic_failure("semantic position differs from the pinned fixture")
    if result.get("orientation") != list(expected.orientation):
        raise _semantic_failure("semantic orientation differs from the pinned fixture")


def sha256_retained_asset_lock(paths: HandoverPaths) -> str:
    """Hash the retained asset-lock inode twice through a no-follow descriptor."""

    paths.revalidate()
    identity = _retained_identity(paths, "asset_lock")
    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(identity.path.anchor, directory_flags)
    try:
        for index, component in enumerate(identity.path.parts[1:]):
            final = index == len(identity.path.parts[1:]) - 1
            flags = (
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                if final
                else directory_flags
            )
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or (
            before.st_dev,
            before.st_ino,
            before.st_mode,
        ) != (identity.device, identity.inode, identity.mode):
            raise AtomicIOError("retained asset lock identity changed")
        observed: list[tuple[int, str]] = []
        for _pass_index in range(2):
            os.lseek(descriptor, 0, os.SEEK_SET)
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            observed.append((size, digest.hexdigest()))
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if (
            tuple(getattr(before, field) for field in stable_fields)
            != tuple(getattr(after, field) for field in stable_fields)
            or observed[0] != observed[1]
            or observed[0][0] != before.st_size
        ):
            raise AtomicIOError("retained asset lock changed while hashing")
    except AtomicIOError:
        raise
    except OSError as error:
        raise AtomicIOError("retained asset lock could not be hashed") from error
    finally:
        os.close(descriptor)
    paths.revalidate()
    return observed[0][1]


def _require_authoritative_pass_documents(
    documents: Mapping[str, dict[str, object]],
    paths: HandoverPaths,
    *,
    accepted_implementation_commit: str | None,
    source_verification: SourceVerification | None,
    asset_verification: VerifiedAssetLock | None,
    graph_counts: GraphCounts | None,
    semantic_result: SemanticFixtureResult | None,
) -> None:
    if not isinstance(paths, HandoverPaths):
        raise _semantic_failure("publisher requires authoritative HandoverPaths")
    paths.revalidate()

    source = documents[SOURCE_FILE]
    if source.get("status") == "PASS":
        if not isinstance(source_verification, SourceVerification):
            raise _semantic_failure("source PASS requires SourceVerification")
        expected_source = build_source_document(
            paths,
            status="PASS",
            reason=source["reason"],
            started_at=source["started_at"],
            finished_at=source["finished_at"],
            checkout_commit=accepted_implementation_commit,
            verification=source_verification,
        )
        if source != expected_source:
            raise _semantic_failure(
                "source PASS differs from authoritative source observations"
            )

    asset = documents[ASSET_FILE]
    if asset.get("status") == "PASS":
        if not isinstance(asset_verification, VerifiedAssetLock):
            raise _semantic_failure("asset PASS requires VerifiedAssetLock")
        expected_asset = build_asset_document(
            paths,
            status="PASS",
            reason=asset["reason"],
            started_at=asset["started_at"],
            finished_at=asset["finished_at"],
            asset_lock_sha256=sha256_retained_asset_lock(paths),
            verification=asset_verification,
        )
        if asset != expected_asset:
            raise _semantic_failure(
                "asset PASS differs from authoritative asset observations"
            )

    query = documents[QUERY_FILE]
    if query.get("status") == "PASS":
        if not isinstance(graph_counts, GraphCounts) or not isinstance(
            semantic_result, SemanticFixtureResult
        ):
            raise _semantic_failure(
                "query PASS requires GraphCounts and SemanticFixtureResult"
            )
        expected_query = build_query_document(
            status="PASS",
            reason=query["reason"],
            started_at=query["started_at"],
            finished_at=query["finished_at"],
            query_sha256=STRUCTURED_QUERY_SHA256,
            graph_counts=graph_counts,
            result=semantic_result,
        )
        if query != expected_query:
            raise _semantic_failure(
                "query PASS differs from authoritative semantic observations"
            )
    paths.revalidate()


def _read_authoritative_file(
    authority: _RunDirectoryAuthority,
    filename: str,
    expected: bytes,
    proof: ArtifactDescriptor,
) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            filename,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=authority.descriptor,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino, before.st_size)
            != (proof.device, proof.inode, proof.size)
        ):
            raise AtomicIOError("ambiguous terminal identity differs from proof")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, len(expected) - observed + 1))
            if not chunk:
                break
            observed += len(chunk)
            if observed > len(expected):
                raise AtomicIOError("ambiguous terminal exceeds expected bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        path_stat = os.stat(
            filename, dir_fd=authority.descriptor, follow_symlinks=False
        )
        payload = b"".join(chunks)
        if (
            payload != expected
            or hashlib.sha256(payload).hexdigest() != proof.sha256
            or (after.st_dev, after.st_ino, after.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
            or (path_stat.st_dev, path_stat.st_ino, path_stat.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise AtomicIOError("ambiguous terminal bytes differ from proof")
    except AtomicIOError:
        raise
    except OSError as error:
        raise AtomicIOError("ambiguous terminal proof is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remove_authoritative_terminal(
    authority: _RunDirectoryAuthority,
) -> Exception | None:
    try:
        observed = os.stat(
            RESULT_FILE,
            dir_fd=authority.descriptor,
            follow_symlinks=False,
        )
        if stat.S_ISDIR(observed.st_mode):
            os.rmdir(RESULT_FILE, dir_fd=authority.descriptor)
        else:
            os.unlink(RESULT_FILE, dir_fd=authority.descriptor)
        os.fsync(authority.descriptor)
    except FileNotFoundError:
        return None
    except OSError as error:
        return error
    try:
        os.stat(RESULT_FILE, dir_fd=authority.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        return error
    return AtomicIOError("authoritative terminal filename still exists")


def _cleanup_terminal_after_exception(
    authority: _RunDirectoryAuthority,
    terminal: dict[str, object],
    proof: ArtifactDescriptor | None,
) -> str:
    """Remove every retained terminal name, quarantining only exact evidence."""

    binding_error: Exception | None = None
    try:
        authority.revalidate()
    except Exception as error:
        binding_error = error
    try:
        os.stat(
            RESULT_FILE,
            dir_fd=authority.descriptor,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        try:
            authority.revalidate()
        except Exception:
            return "ABSENT_BINDING_CHANGED"
        return "ABSENT"
    except OSError as error:
        raise AtomicIOError("authoritative terminal could not be inspected") from error

    observed_proof: ArtifactDescriptor | None = None
    try:
        if binding_error is not None:
            raise AtomicIOError(
                "run directory lexical binding changed"
            ) from binding_error
        value, observed_proof = read_json_secure(
            authority.path / RESULT_FILE,
            relative_to=authority.path,
            directory_fd=authority.descriptor,
        )
        if value != terminal:
            raise AtomicIOError("authoritative terminal content is not expected")
        if proof is not None and observed_proof != proof:
            raise AtomicIOError("authoritative terminal differs from publication proof")
    except Exception:
        removal_error = _remove_authoritative_terminal(authority)
        if removal_error is not None:
            raise AtomicIOError(
                "unverified authoritative terminal could not be removed"
            ) from removal_error
        try:
            authority.revalidate()
        except Exception:
            return "REMOVED_BINDING_CHANGED"
        return "REMOVED"

    if observed_proof is None:
        raise AtomicIOError("authoritative terminal proof is absent")
    _quarantine_ambiguous_terminal(authority, observed_proof, terminal)
    return "QUARANTINED"


def _quarantine_ambiguous_terminal(
    authority: _RunDirectoryAuthority,
    proof: ArtifactDescriptor,
    terminal: dict[str, object],
) -> None:
    expected = canonical_json_bytes(terminal)
    quarantine = f".{RESULT_FILE}.quarantine-{proof.sha256}"
    try:
        authority.revalidate()
        if proof.relative_path != RESULT_FILE:
            raise AtomicIOError("ambiguous terminal proof has the wrong path")
        _read_authoritative_file(authority, RESULT_FILE, expected, proof)
        os.link(
            RESULT_FILE,
            quarantine,
            src_dir_fd=authority.descriptor,
            dst_dir_fd=authority.descriptor,
            follow_symlinks=False,
        )
        os.fsync(authority.descriptor)
        _read_authoritative_file(authority, quarantine, expected, proof)
        removal_error = _remove_authoritative_terminal(authority)
        if removal_error is not None:
            raise removal_error
        _read_authoritative_file(authority, quarantine, expected, proof)
        authority.revalidate()
    except Exception as error:
        removal_error = _remove_authoritative_terminal(authority)
        if removal_error is not None:
            raise AtomicIOError(
                "terminal quarantine and authoritative removal both failed"
            ) from removal_error
        raise AtomicIOError("terminal quarantine could not be proven") from error


def build_handover_result_document(
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
    accepted_implementation_commit: str | None,
    repository_root: PathIdentity,
    data_root: PathIdentity,
    run_directory: PathIdentity,
    cpu_gpu_label: str | None,
    evidence_files: list[dict[str, object]],
    bundle_sha256: str,
    first_blocking_reason: str | None,
) -> dict[str, object]:
    """Build the terminal record from the already-published descriptor rows."""

    return {
        **_stage_header(
            "holoagent0.fsrvln.handover-result.v1",
            status,
            reason,
            started_at,
            finished_at,
        ),
        "accepted_implementation_commit": accepted_implementation_commit,
        "repository_root": path_identity_document(repository_root),
        "data_root": path_identity_document(data_root),
        "run_directory": path_identity_document(run_directory),
        "cpu_gpu_label": cpu_gpu_label,
        "evidence_files": [dict(row) for row in evidence_files],
        "bundle_sha256": bundle_sha256,
        "first_blocking_reason": first_blocking_reason,
        "terminal_filename": RESULT_FILE,
    }


def _snapshot_stage_documents(
    stage_documents: Mapping[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    if set(stage_documents) != set(EVIDENCE_ORDER):
        raise EvidencePublicationError(
            (
                PublicationFailure(
                    RESULT_FILE,
                    "input_validation",
                    ValueError(
                        "stage documents must use the exact evidence filename set"
                    ),
                ),
            )
        )
    snapshots: dict[str, dict[str, object]] = {}
    for filename in EVIDENCE_ORDER:
        document = stage_documents[filename]
        if type(document) is not dict:
            raise EvidencePublicationError(
                (
                    PublicationFailure(
                        filename,
                        "input_validation",
                        TypeError("stage document must be an exact dict"),
                    ),
                )
            )
        value = json.loads(canonical_json_bytes(document))
        if type(value) is not dict:
            raise EvidencePublicationError(
                (
                    PublicationFailure(
                        filename,
                        "input_validation",
                        TypeError("stage snapshot must be an exact dict"),
                    ),
                )
            )
        snapshots[filename] = value
    return snapshots


def publish_handover_evidence(
    contract: ContractSet,
    run_directory: Path,
    stage_documents: Mapping[str, dict[str, object]],
    *,
    paths: HandoverPaths,
    source_verification: SourceVerification | None,
    asset_verification: VerifiedAssetLock | None,
    graph_counts: GraphCounts | None,
    semantic_result: SemanticFixtureResult | None,
    accepted_implementation_commit: str | None,
    run_directory_identity: PathIdentity,
    cpu_gpu_label: str | None,
    started_at: str,
    finished_at: str,
) -> ArtifactDescriptor:
    """Publish all four stage files and then their digest-bound terminal record."""

    documents = _snapshot_stage_documents(stage_documents)
    repository_root = _retained_identity(paths, "repository_root")
    data_root = _retained_identity(paths, "data_root")
    _require_repository_binding(
        documents[ENVIRONMENT_FILE],
        documents[SOURCE_FILE],
        repository_root,
    )
    _require_authoritative_pass_documents(
        documents,
        paths,
        accepted_implementation_commit=accepted_implementation_commit,
        source_verification=source_verification,
        asset_verification=asset_verification,
        graph_counts=graph_counts,
        semantic_result=semantic_result,
    )
    derived_cpu_gpu_label = _environment_runtime_label(documents[ENVIRONMENT_FILE])
    if cpu_gpu_label != derived_cpu_gpu_label:
        raise _semantic_failure(
            "terminal CPU/GPU label disagrees with environment evidence"
        )
    _require_pass_stage_bindings(
        documents[SOURCE_FILE],
        documents[ASSET_FILE],
        documents[QUERY_FILE],
        accepted_implementation_commit=accepted_implementation_commit,
        authoritative_data_root=data_root,
    )

    authority = _RunDirectoryAuthority.retain(
        Path(run_directory), run_directory_identity
    )
    try:
        _require_reserved_names_absent(authority)
        descriptors: dict[str, ArtifactDescriptor] = {}
        failures: list[PublicationFailure] = []
        for filename in EVIDENCE_ORDER:
            document = documents[filename]
            attempt_errors: list[Exception] = []
            try:
                authority.revalidate()
            except Exception as error:
                attempt_errors.append(error)
            descriptor: ArtifactDescriptor | None = None
            try:
                descriptor = validate_and_publish_stage(
                    contract,
                    _STAGE_SCHEMAS[filename],
                    authority.path,
                    filename,
                    document,
                    parent_fd=authority.descriptor,
                    expected_parent_identity=authority.parent_identity,
                )
                _require_descriptor_matches(descriptor, filename, document)
            except Exception as error:
                attempt_errors.append(error)
            try:
                authority.revalidate()
            except Exception as error:
                attempt_errors.append(error)
            if attempt_errors:
                phase = (
                    "validation"
                    if any(isinstance(error, ContractError) for error in attempt_errors)
                    else "write_or_authority"
                )
                combined = RuntimeError(
                    "; ".join(
                        f"{type(error).__name__}: {error}" for error in attempt_errors
                    )
                )
                failures.append(PublicationFailure(filename, phase, combined))
            elif descriptor is not None:
                descriptors[filename] = descriptor

        if failures or tuple(descriptors) != EVIDENCE_ORDER:
            if not failures:
                failures.append(
                    PublicationFailure(
                        RESULT_FILE,
                        "descriptor_closure",
                        AtomicIOError("stage descriptor set is incomplete"),
                    )
                )
            raise EvidencePublicationError(tuple(failures))

        replayed_descriptors: dict[str, ArtifactDescriptor] = {}
        replay_failures: list[PublicationFailure] = []
        for filename in EVIDENCE_ORDER:
            try:
                replayed_descriptors[filename] = _replay_published_document(
                    contract,
                    authority,
                    _STAGE_SCHEMAS[filename],
                    filename,
                    documents[filename],
                    descriptors[filename],
                )
            except Exception as error:
                replay_failures.append(
                    PublicationFailure(filename, "stage_replay", error)
                )
        if replay_failures or tuple(replayed_descriptors) != EVIDENCE_ORDER:
            if not replay_failures:
                replay_failures.append(
                    PublicationFailure(
                        RESULT_FILE,
                        "stage_replay",
                        AtomicIOError("replayed stage descriptor set is incomplete"),
                    )
                )
            raise EvidencePublicationError(tuple(replay_failures))
        descriptors = replayed_descriptors

        evidence_files = [
            {
                "name": filename,
                "sha256": descriptors[filename].sha256,
                "size": descriptors[filename].size,
            }
            for filename in EVIDENCE_ORDER
        ]
        first_blocking_reason = next(
            (
                documents[filename]["reason"]
                for filename in BLOCKING_ORDER
                if documents[filename]["status"] != "PASS"
            ),
            None,
        )
        status = "PASS" if first_blocking_reason is None else "FAIL"
        reason = "OK" if first_blocking_reason is None else first_blocking_reason
        bundle_sha256 = hashlib.sha256(canonical_json_bytes(evidence_files)).hexdigest()
        terminal = build_handover_result_document(
            status=status,
            reason=reason,
            started_at=started_at,
            finished_at=finished_at,
            accepted_implementation_commit=accepted_implementation_commit,
            repository_root=repository_root,
            data_root=data_root,
            run_directory=authority.identity,
            cpu_gpu_label=derived_cpu_gpu_label,
            evidence_files=evidence_files,
            bundle_sha256=bundle_sha256,
            first_blocking_reason=first_blocking_reason,
        )
        terminal_descriptor: ArtifactDescriptor | None = None
        try:
            authority.revalidate()
            terminal_descriptor = validate_and_publish_stage(
                contract,
                "fsrvln-handover-result-v1",
                authority.path,
                RESULT_FILE,
                terminal,
                parent_fd=authority.descriptor,
                expected_parent_identity=authority.parent_identity,
            )
            _require_descriptor_matches(terminal_descriptor, RESULT_FILE, terminal)
            post_terminal_descriptors = {
                filename: _replay_published_document(
                    contract,
                    authority,
                    _STAGE_SCHEMAS[filename],
                    filename,
                    documents[filename],
                    descriptors[filename],
                )
                for filename in EVIDENCE_ORDER
            }
            replayed_terminal_descriptor = _replay_published_document(
                contract,
                authority,
                "fsrvln-handover-result-v1",
                RESULT_FILE,
                terminal,
                terminal_descriptor,
            )
            post_terminal_rows = [
                {
                    "name": filename,
                    "sha256": post_terminal_descriptors[filename].sha256,
                    "size": post_terminal_descriptors[filename].size,
                }
                for filename in EVIDENCE_ORDER
            ]
            post_terminal_bundle = hashlib.sha256(
                canonical_json_bytes(post_terminal_rows)
            ).hexdigest()
            if (
                terminal["evidence_files"] != post_terminal_rows
                or terminal["bundle_sha256"] != post_terminal_bundle
                or replayed_terminal_descriptor != terminal_descriptor
            ):
                raise AtomicIOError(
                    "terminal content differs from replayed evidence bundle"
                )
            authority.revalidate()
        except AtomicPublicationAmbiguity as error:
            cleanup_error: Exception | None = None
            cleanup_result: str | None = None
            try:
                cleanup_result = _cleanup_terminal_after_exception(
                    authority,
                    terminal,
                    error.expected_artifact,
                )
            except Exception as observed:
                cleanup_error = observed
            detail = RuntimeError(
                f"{error}; cleanup="
                f"{cleanup_result if cleanup_error is None else cleanup_error}"
            )
            raise EvidencePublicationError(
                (PublicationFailure(RESULT_FILE, "ambiguous_terminal", detail),)
            ) from error
        except Exception as error:
            cleanup_error: Exception | None = None
            try:
                _cleanup_terminal_after_exception(
                    authority,
                    terminal,
                    terminal_descriptor,
                )
            except Exception as observed:
                cleanup_error = observed
            detail = (
                error
                if cleanup_error is None
                else RuntimeError(f"{error}; cleanup={cleanup_error}")
            )
            raise EvidencePublicationError(
                (PublicationFailure(RESULT_FILE, "terminal", detail),)
            ) from error
        if terminal_descriptor is None:
            raise EvidencePublicationError(
                (
                    PublicationFailure(
                        RESULT_FILE,
                        "terminal",
                        AtomicIOError("terminal descriptor is absent"),
                    ),
                )
            )
        return terminal_descriptor
    finally:
        authority.close()


publish_evidence_bundle = publish_handover_evidence
