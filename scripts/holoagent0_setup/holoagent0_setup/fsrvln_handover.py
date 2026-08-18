"""Verify the fixed FSR-VLN Stage A handover without ROS or robot control."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Sequence

from .atomic_io import AtomicIOError
from .contract import ContractError, ContractSet
from .handover_evidence import (
    ASSET_FILE,
    ENVIRONMENT_FILE,
    EvidencePublicationError,
    QUERY_FILE,
    REQUIRED_IMPORTS,
    SOURCE_FILE,
    build_asset_document,
    build_environment_document,
    build_query_document,
    build_source_document,
    publish_handover_evidence,
    qualify_environment,
    sha256_retained_asset_lock,
)
from .semantic_gate import (
    EXPECTED_SEMANTIC,
    STRUCTURED_QUERY_SHA256,
    GraphCounts,
    SemanticFixtureResult,
    SemanticGateError,
    evaluate_semantic_fixture,
    load_real_hmsg_adapter,
)
from .source_gate import (
    AssetGateError,
    HandoverPaths,
    SourceGateError,
    SourceVerification,
    VerifiedAssetLock,
    load_source_lock,
    prepare_handover_run_directory,
    verify_asset_lock,
    verify_checkout_identity,
    verify_manifest_git_objects,
    verify_source_worktree,
)


FORBIDDEN_MODULE_PREFIXES = (
    "rclpy",
    "nav2",
    "agentos",
    "agentic_robot",
    "unitree",
    "unitree_sdk2py",
)

_ANTICIPATED_ERRORS = (
    SourceGateError,
    AssetGateError,
    SemanticGateError,
    ContractError,
    AtomicIOError,
    EvidencePublicationError,
    OSError,
)


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fixed Stage A verifier and return 0 only for terminal PASS."""

    arguments = _parse_arguments(argv)
    initially_loaded = frozenset(sys.modules)
    try:
        paths = HandoverPaths.from_roots(arguments.repository_root, arguments.data_root)
        paths.revalidate()
        run_identity = prepare_handover_run_directory(arguments.run_directory, paths)
    except (AssetGateError, OSError):
        return 2

    started_at = _utc_timestamp()
    source_status = "NOT_RUN"
    environment_status = "NOT_RUN"
    asset_status = "NOT_RUN"
    query_status = "NOT_RUN"
    blocker: str | None = None
    checkout_commit: str | None = None
    source_verification: SourceVerification | None = None
    environment_observation: dict[str, object] | None = None
    asset_verification: VerifiedAssetLock | None = None
    asset_lock_sha256: str | None = None
    graph_counts: GraphCounts | None = None
    semantic_result: SemanticFixtureResult | None = None
    query_execution_count = 0

    source_lock_path = (
        paths.repository_root
        / "scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json"
    )
    try:
        paths.revalidate()
        source_lock = load_source_lock(source_lock_path)
        checkout_commit = verify_checkout_identity(paths.repository_root, source_lock)
        git_verification = verify_manifest_git_objects(
            paths.repository_root, source_lock
        )
        worktree_verification = verify_source_worktree(
            paths.repository_root, source_lock
        )
        if git_verification != worktree_verification:
            raise SourceGateError(
                "SOURCE_VERIFICATION_MISMATCH",
                "Git-object and worktree verification results differ",
            )
        source_verification = git_verification
        source_status = "PASS"
    except _ANTICIPATED_ERRORS as error:
        blocker = _stable_reason(error)
        source_status = "FAIL"

    if blocker is None:
        try:
            environment_observation = qualify_environment(paths)
            environment_status = _stage_status(environment_observation)
            if environment_status == "FAIL":
                blocker = _document_reason(environment_observation)
        except _ANTICIPATED_ERRORS as error:
            blocker = _stable_reason(error)
            environment_status = "FAIL"
            environment_observation = _failed_environment_observation(
                blocker, started_at
            )

    if blocker is None:
        try:
            paths.revalidate()
            asset_verification = verify_asset_lock(paths)
            asset_lock_sha256 = sha256_retained_asset_lock(paths)
            asset_status = "PASS"
        except _ANTICIPATED_ERRORS as error:
            blocker = _stable_reason(error)
            asset_status = "FAIL"

    if blocker is None:
        adapter = None
        try:
            adapter = load_real_hmsg_adapter(paths, arguments.run_directory)
            try:
                query_execution_count = 1
                semantic_result = evaluate_semantic_fixture(
                    adapter, EXPECTED_SEMANTIC.query
                )
                graph_counts = adapter.graph_counts()
            finally:
                adapter.close()
            forbidden = _new_forbidden_module(initially_loaded)
            if forbidden is not None:
                blocker = f"FORBIDDEN_RUNTIME_MODULE: {forbidden}"
                query_status = "FAIL"
            else:
                query_status = "PASS"
        except _ANTICIPATED_ERRORS as error:
            blocker = _stable_reason(error)
            query_status = "FAIL"

    finished_at = _utc_timestamp()
    source_reason = _stage_reason(source_status, blocker)
    environment_reason = _stage_reason(environment_status, blocker)
    asset_reason = _stage_reason(asset_status, blocker)
    query_reason = _stage_reason(query_status, blocker)

    environment_document = _build_environment_evidence(
        environment_observation,
        status=environment_status,
        reason=environment_reason,
        started_at=started_at,
        finished_at=finished_at,
    )
    source_document = build_source_document(
        paths,
        status=source_status,
        reason=source_reason,
        started_at=started_at,
        finished_at=finished_at,
        checkout_commit=checkout_commit,
        verification=source_verification if source_status == "PASS" else None,
    )
    asset_document = build_asset_document(
        paths,
        status=asset_status,
        reason=asset_reason,
        started_at=started_at,
        finished_at=finished_at,
        asset_lock_sha256=asset_lock_sha256,
        verification=asset_verification,
    )
    query_document = build_query_document(
        status=query_status,
        reason=query_reason,
        started_at=started_at,
        finished_at=finished_at,
        query_sha256=STRUCTURED_QUERY_SHA256,
        graph_counts=graph_counts,
        result=semantic_result,
        execution_count=query_execution_count,
    )
    documents = {
        ENVIRONMENT_FILE: environment_document,
        SOURCE_FILE: source_document,
        ASSET_FILE: asset_document,
        QUERY_FILE: query_document,
    }
    accelerator = environment_document.get("accelerator")
    cpu_gpu_label = accelerator.get("label") if isinstance(accelerator, dict) else None
    try:
        contract = ContractSet(paths.repository_root / "scripts/holoagent0_setup")
        publish_handover_evidence(
            contract,
            arguments.run_directory,
            documents,
            paths=paths,
            source_verification=source_verification,
            asset_verification=asset_verification,
            graph_counts=graph_counts,
            semantic_result=semantic_result,
            accepted_implementation_commit=checkout_commit,
            run_directory_identity=run_identity,
            cpu_gpu_label=cpu_gpu_label,
            started_at=started_at,
            finished_at=finished_at,
        )
    except _ANTICIPATED_ERRORS:
        return 1
    return 0 if blocker is None else 1


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _stable_reason(error: BaseException) -> str:
    reason = getattr(error, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    if isinstance(error, ContractError):
        return error.decision.code
    if isinstance(error, EvidencePublicationError):
        return "EVIDENCE_PUBLICATION_FAILED"
    if isinstance(error, OSError):
        return f"IO_ERROR: {type(error).__name__}"
    return f"{type(error).__name__.upper()}_FAILED"


def _stage_status(document: dict[str, object]) -> str:
    status = document.get("status")
    if status not in {"PASS", "FAIL"}:
        raise TypeError("environment evidence status must be PASS or FAIL")
    return status


def _document_reason(document: dict[str, object]) -> str:
    reason = document.get("reason")
    if not isinstance(reason, str) or not reason:
        raise TypeError("environment evidence reason must be nonempty text")
    return reason


def _stage_reason(status: str, blocker: str | None) -> str:
    if status == "PASS":
        return "OK"
    if blocker is None:
        raise AssertionError("a non-PASS stage requires one blocker")
    return blocker


def _failed_environment_observation(reason: str, started_at: str) -> dict[str, object]:
    return {
        "status": "FAIL",
        "reason": reason,
        "started_at": started_at,
        "finished_at": _utc_timestamp(),
        "os_release": None,
        "machine_architecture": None,
        "python": None,
        "accelerator": None,
        "imports": [
            {
                "name": display_name,
                "module": module_name,
                "status": "FAIL",
                "version": None,
                "origin": None,
                "reason": reason,
            }
            for display_name, module_name in REQUIRED_IMPORTS
        ],
        "graph_module_origin": None,
    }


def _build_environment_evidence(
    observation: dict[str, object] | None,
    *,
    status: str,
    reason: str,
    started_at: str,
    finished_at: str,
) -> dict[str, object]:
    if observation is None or status == "NOT_RUN":
        return build_environment_document(
            status="NOT_RUN",
            reason=reason,
            started_at=started_at,
            finished_at=finished_at,
        )
    return build_environment_document(
        status=status,
        reason=reason,
        started_at=str(observation.get("started_at", started_at)),
        finished_at=str(observation.get("finished_at", finished_at)),
        os_release=observation.get("os_release"),
        machine_architecture=observation.get("machine_architecture"),
        python=observation.get("python"),
        accelerator=observation.get("accelerator"),
        imports=observation.get("imports"),
        graph_module_origin=observation.get("graph_module_origin"),
    )


def _new_forbidden_module(initially_loaded: frozenset[str]) -> str | None:
    forbidden = sorted(
        name
        for name in sys.modules.keys() - initially_loaded
        if name.startswith(FORBIDDEN_MODULE_PREFIXES)
    )
    return forbidden[0] if forbidden else None


if __name__ == "__main__":
    raise SystemExit(main())
