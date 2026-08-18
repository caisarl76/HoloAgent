"""Build and atomically publish closed FSR-VLN Stage A handover evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from importlib import import_module, metadata
from pathlib import Path
import platform
import sys
from typing import Mapping

from .atomic_io import (
    ArtifactDescriptor,
    AtomicIOError,
    atomic_write_json_no_replace,
    canonical_json_bytes,
)
from .contract import ContractSet
from .semantic_gate import (
    GraphCounts,
    SemanticFixtureResult,
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
    direct = getattr(module, "__version__", None)
    if type(direct) is str and direct:
        return direct
    for candidate in _DISTRIBUTION_CANDIDATES[display_name]:
        try:
            observed = metadata.version(candidate)
        except Exception:
            continue
        if type(observed) is str and observed:
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

        observed_name = getattr(module, "__name__", None)
        if observed_name != module_name:
            reason = (
                "IMPORT_IDENTITY_MISMATCH: "
                f"expected {module_name}, got {observed_name!r}"
            )
            rows.append(_failed_import_row(display_name, module_name, reason))
            failures.append(reason)
            continue
        imported[module_name] = module
        rows.append(
            {
                "name": display_name,
                "module": module_name,
                "status": "PASS",
                "version": _module_version(display_name, module),
                "origin": _module_origin(module),
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
) -> ArtifactDescriptor:
    """Validate one stage and atomically install its canonical JSON once."""

    contract.require_valid_document(schema_name, document)
    return atomic_write_json_no_replace(
        run_directory / filename,
        document,
        relative_to=run_directory,
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


def publish_handover_evidence(
    contract: ContractSet,
    run_directory: Path,
    stage_documents: Mapping[str, dict[str, object]],
    *,
    accepted_implementation_commit: str | None,
    repository_root: PathIdentity,
    data_root: PathIdentity,
    run_directory_identity: PathIdentity,
    cpu_gpu_label: str | None,
    started_at: str,
    finished_at: str,
) -> ArtifactDescriptor:
    """Publish all four stage files and then their digest-bound terminal record."""

    if set(stage_documents) != set(EVIDENCE_ORDER):
        raise ValueError("stage documents must use the exact evidence filename set")
    descriptors: list[ArtifactDescriptor] = []
    for filename in EVIDENCE_ORDER:
        document = stage_documents[filename]
        if type(document) is not dict:
            raise TypeError(f"stage document must be an exact dict: {filename}")
        descriptor = validate_and_publish_stage(
            contract,
            _STAGE_SCHEMAS[filename],
            run_directory,
            filename,
            document,
        )
        _require_descriptor_matches(descriptor, filename, document)
        descriptors.append(descriptor)

    evidence_files = [
        {"name": filename, "sha256": descriptor.sha256, "size": descriptor.size}
        for filename, descriptor in zip(EVIDENCE_ORDER, descriptors)
    ]
    first_blocking_reason = next(
        (
            stage_documents[filename]["reason"]
            for filename in EVIDENCE_ORDER
            if stage_documents[filename]["status"] != "PASS"
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
        run_directory=run_directory_identity,
        cpu_gpu_label=cpu_gpu_label,
        evidence_files=evidence_files,
        bundle_sha256=bundle_sha256,
        first_blocking_reason=first_blocking_reason,
    )
    terminal_descriptor = validate_and_publish_stage(
        contract,
        "fsrvln-handover-result-v1",
        run_directory,
        RESULT_FILE,
        terminal,
    )
    _require_descriptor_matches(terminal_descriptor, RESULT_FILE, terminal)
    return terminal_descriptor


publish_evidence_bundle = publish_handover_evidence
