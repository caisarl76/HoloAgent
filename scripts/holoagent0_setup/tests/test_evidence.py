"""Immutable Task 8 evidence-bundle and redaction contracts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import hashlib
import copy
import base64
from types import MappingProxyType

import pytest

import holoagent0_setup.evidence as evidence_module
from holoagent0_setup.evidence import (
    AppendOnlyJournal,
    ArtifactBindingError,
    ArtifactRequirement,
    EvidenceContext,
    EvidenceBinder,
    TracePolicyReplayEvidence,
    TraceRuntimeEvidence,
    redact_environment,
    redact_value,
    write_host_observer_artifact,
)
from holoagent0_setup.cyclone_policy import CONFIG_ROLES, EXPECTED_CONFIG_SHA256
from holoagent0_setup.atomic_io import canonical_json_bytes
from holoagent0_setup.contract import ContractSet
from holoagent0_setup.ledger import LedgerCandidate, LedgerStore
from holoagent0_setup.process_identity import ProcessIdentity


REQUIRED_ARTIFACTS = (
    "trace",
    "bootstrap_report",
    "ledger_chain_manifest",
    "ownership_journal",
    "violation_journal",
    "host_observer_pre",
    "host_observer_post",
)
PACKAGE_ROOT = Path(__file__).parents[1]
RUN_NONCE = "a" * 64
SHA256 = "b" * 64


def _closed_file(path: Path, payload: bytes = b"{}") -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)


def _git_blob_sha1(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def _requirements(root: Path) -> dict[str, ArtifactRequirement]:
    requirements = {}
    for name in REQUIRED_ARTIFACTS:
        suffix = (
            ".ndjson"
            if name in {"trace", "ownership_journal", "violation_journal"}
            else ".json"
        )
        path = root / f"{name}{suffix}"
        payload = b"" if suffix == ".ndjson" else b"{}"
        _closed_file(path, payload)
        requirements[name] = ArtifactRequirement(path, expected_mode=0o400)
    return requirements


def _identity(pid: int) -> ProcessIdentity:
    return ProcessIdentity(pid, pid, pid * 10, "/bin/true", f"{pid:064x}")


def _trusted_inspection(listeners=()) -> dict[str, object]:
    return {
        "gateway_status_command": [
            "/opt/openclaw/bin/openclaw",
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        ],
        "gateway_status_exit": 0,
        "gateway_status_sha256": hashlib.sha256(b'{"running":false}').hexdigest(),
        "gateway_status_state": "INACTIVE",
        "service_definitions": [],
        "listener_command": ["/usr/bin/ss", "-H", "-ltnp"],
        "listener_inventory": list(listeners),
    }


def _bootstrap_report(trace_state: str) -> dict[str, object]:
    active = trace_state == "FULL"
    ready_identity = _identity(601).as_dict()
    ready_request = {
        "type": "SIGNAL_READY",
        "run_nonce": RUN_NONCE,
        "sequence": 1,
        "identity": ready_identity,
        "blocked_signals": ["HUP", "INT", "TERM"],
        "dispositions": {"HUP": True, "INT": True, "TERM": True},
    }
    ready_sha256 = hashlib.sha256(canonical_json_bytes(ready_request)).hexdigest()
    accepted = {
        "type": "SIGNAL_READY_ACCEPTED",
        "run_nonce": RUN_NONCE,
        "identity": ready_identity,
        "request_sequence": 1,
        "request_sha256": ready_sha256,
    }
    accepted_sha256 = hashlib.sha256(canonical_json_bytes(accepted)).hexdigest()
    return {
        "schema_version": "holoagent0.bootstrap-report.v1",
        "terminal_launch_state": (
            "COORDINATOR_LAUNCH_COMMITTED"
            if active
            else "NOT_STARTED_BOOTSTRAP_FAILURE"
        ),
        "coordinator_launch_committed": active,
        "first_signal": None,
        "handoff": {
            "event_sequence": (
                [
                    {"sequence": 0, "state": "AWAITING_READY"},
                    {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
                    {"sequence": 2, "state": "READY"},
                ]
                if active
                else []
            ),
            "terminal_state": "READY" if active else "NOT_APPLICABLE",
            "signal_ready_identity": ready_identity if active else None,
            "signal_ready_sequence": 1 if active else None,
            "signal_ready_sha256": ready_sha256 if active else None,
            "signal_ready_accepted_sequence": 1 if active else None,
            "signal_ready_accepted_sha256": accepted_sha256 if active else None,
            "inherited_mask": ["HUP", "INT", "TERM"],
            "unblocked_mask": ["HUP", "INT", "TERM"] if active else [],
            "pending_signal": None,
            "acceptance_count": 1 if active else 0,
            "forward_target_pgid": None,
            "forward_count": 0,
            "unblock_trace_record_index": 0 if active else None,
            "first_functional_trace_record_index": 1 if active else None,
        },
        "toolchain": {
            "expected": {"strace_version": "6.6"},
            "observed": {"strace_version": "6.6"},
        },
        "initial_fd_manifest": [],
        "final_fd_manifest": [],
        "sanitation_actions": [],
        "rebinding_actions": [],
        "live_fixture_passed": active,
    }


def _trace_runtime(state: str = "NOT_STARTED") -> TraceRuntimeEvidence:
    if state == "NOT_STARTED":
        return TraceRuntimeEvidence(
            trace_state=state,
            tracer_identity=None,
            normalizer_identity=None,
            tracer_exit_code=None,
            normalizer_exit_code=None,
            tool_policy_row_sha256=None,
            compatibility_fixture_passed=None,
            not_started_reason="TRACE_NOT_STARTED",
        )
    return TraceRuntimeEvidence(
        trace_state=state,
        tracer_identity=_identity(501),
        normalizer_identity=_identity(502),
        tracer_exit_code=0,
        normalizer_exit_code=0,
        tool_policy_row_sha256=SHA256,
        compatibility_fixture_passed=True,
        not_started_reason=None,
    )


def _trace_policy_replay() -> TracePolicyReplayEvidence:
    return TracePolicyReplayEvidence(
        coordinator_pid=601,
        participants={
            100 + index: {
                "index": index,
                "config_digest": EXPECTED_CONFIG_SHA256[index],
            }
            for index in range(4)
        },
        namespace_loopback_only=True,
        initial_fd_manifest={601: []},
    )


def _finalizer_trace_policy_replay() -> TracePolicyReplayEvidence:
    return TracePolicyReplayEvidence(
        coordinator_pid=601,
        participants={},
        namespace_loopback_only=True,
        initial_fd_manifest={601: []},
    )


def test_trace_policy_replay_participants_match_the_trace_role(tmp_path):
    contract = ContractSet(PACKAGE_ROOT)
    common = {
        "ledger_contract": contract,
        "expected_run_id": "run-1",
        "expected_ledger_nonce": RUN_NONCE,
        "marker_token": "0123456789ab",
        "expected_host_observer_identity": _identity(801),
    }

    EvidenceContext(
        trace=_trace_runtime("FINALIZER_ONLY"),
        trace_policy_replay=_finalizer_trace_policy_replay(),
        **common,
    )
    with pytest.raises(ArtifactBindingError, match="participant|FULL"):
        EvidenceContext(
            trace=_trace_runtime("FULL"),
            trace_policy_replay=_finalizer_trace_policy_replay(),
            **common,
        )


def _seal_recovery_ledger(
    root: Path, contract: ContractSet, *, window: str
) -> tuple[int, str]:
    store = LedgerStore.create(root / "ledger", contract, RUN_NONCE, run_id="run-1")
    if window == "CLOSED":
        store.append(
            LedgerCandidate(
                generation=1,
                previous_generation=0,
                previous_digest=store.head.digest,
                run_id="run-1",
                ledger_nonce=RUN_NONCE,
                gates=store.current["gates"],
                semantic_dds_window="OPEN",
            )
        )
        store.append(
            LedgerCandidate(
                generation=2,
                previous_generation=1,
                previous_digest=store.head.digest,
                run_id="run-1",
                ledger_nonce=RUN_NONCE,
                gates=store.current["gates"],
                semantic_dds_window="CLOSED",
            )
        )
    gates = copy.deepcopy(store.current["gates"])
    gates[23].update(status="FAIL", reason="POSTFLIGHT_FAILED")
    head = store.seal(
        LedgerCandidate(
            generation=store.head.generation + 1,
            previous_generation=store.head.generation,
            previous_digest=store.head.digest,
            run_id="run-1",
            ledger_nonce=RUN_NONCE,
            gates=gates,
            sealed=True,
            semantic_dds_window=window,
        )
    )
    store.close()
    return head.generation, head.digest


def _write_chain_manifest(root: Path, accepted_generation: int, accepted_sha: str):
    generations = []
    for generation in range(accepted_generation + 1):
        path = root / "ledger" / f"generation-{generation:06d}.json"
        value = json.loads(path.read_text())
        generations.append(
            {
                "generation": generation,
                "relative_path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size": path.stat().st_size,
                "previous_generation": value["previous_generation"],
                "previous_digest": value["previous_digest"],
                "sealed": value["sealed"],
            }
        )
    manifest = {
        "schema_version": "holoagent0.ledger-chain-manifest.v1",
        "accepted_generation": accepted_generation,
        "accepted_sha256": accepted_sha,
        "generation_count": accepted_generation + 1,
        "generations": generations,
    }
    _closed_file(root / "ledger_chain_manifest.json", canonical_json_bytes(manifest))


def _write_trace(root: Path, state: str) -> None:
    if state == "NOT_STARTED":
        _closed_file(root / "trace.ndjson", b"")
        return
    records = [
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 0,
            "entry_index": 0,
            "exit_index": 0,
            "syscall": "rt_sigprocmask",
            "result": {"value": 0},
        },
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 1,
            "entry_index": 1,
            "exit_index": 1,
            "syscall": "prctl",
            "marker": {"phase": "BEGIN", "token": "0123456789ab"},
            "result": {"value": 0},
        },
        {
            "kind": "exit",
            "pid": 100,
            "record_index": 2,
            "entry_index": 2,
            "exit_index": 2,
            "exit_code": 0,
        },
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 3,
            "entry_index": 3,
            "exit_index": 3,
            "syscall": "prctl",
            "marker": {"phase": "END", "token": "0123456789ab"},
            "result": {"value": 0},
        },
    ]
    _closed_file(
        root / "trace.ndjson",
        b"".join(canonical_json_bytes(record) + b"\n" for record in records),
    )


def _write_policy_violation_trace(root: Path) -> None:
    records = [
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 0,
            "entry_index": 0,
            "exit_index": 0,
            "syscall": "rt_sigprocmask",
            "result": {"value": 0},
        },
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 1,
            "entry_index": 1,
            "exit_index": 1,
            "syscall": "prctl",
            "marker": {"phase": "BEGIN", "token": "0123456789ab"},
            "result": {"value": 0},
        },
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 2,
            "entry_index": 2,
            "exit_index": 2,
            "syscall": "io_uring_setup",
            "result": {"value": -1, "errno": "EPERM"},
        },
        {
            "kind": "syscall",
            "pid": 601,
            "record_index": 3,
            "entry_index": 3,
            "exit_index": 3,
            "syscall": "prctl",
            "marker": {"phase": "END", "token": "0123456789ab"},
            "result": {"value": 0},
        },
    ]
    _closed_file(
        root / "trace.ndjson",
        b"".join(canonical_json_bytes(record) + b"\n" for record in records),
    )


def _valid_evidence_inputs(
    root: Path,
    *,
    trace_state: str = "NOT_STARTED",
    secret_sentinels=(),
    log_paths=(),
    tracked_paths=(),
    tracked_symlinks=(),
):
    contract = ContractSet(PACKAGE_ROOT)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_trace(root, trace_state)
    _closed_file(
        root / "bootstrap_report.json",
        canonical_json_bytes(_bootstrap_report(trace_state)),
    )
    window = "CLOSED" if trace_state == "FULL" else "NOT_ENTERED"
    generation, digest = _seal_recovery_ledger(root, contract, window=window)
    _write_chain_manifest(root, generation, digest)
    ownership = AppendOnlyJournal.create(
        root / "ownership_journal.ndjson",
        relative_to=root,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    if trace_state == "FULL":
        action = _identity(701)
        messages = [
            {
                "type": "OWNERSHIP_RECORD",
                "run_nonce": RUN_NONCE,
                "sequence": 1,
                "identity": action.as_dict(),
                "role": "action_child",
            }
        ]
        messages.extend(
            {
                "type": "PARTICIPANT_RECORD",
                "run_nonce": RUN_NONCE,
                "sequence": index + 2,
                "identity": _identity(100 + index).as_dict(),
                "role": CONFIG_ROLES[index],
                "participant_index": index,
                "config_digest": EXPECTED_CONFIG_SHA256[index],
            }
            for index in range(4)
        )
        for message in messages:
            payload = {
                "identity": message["identity"],
                "role": message["role"],
                "request_sha256": hashlib.sha256(
                    canonical_json_bytes(message)
                ).hexdigest(),
            }
            if message["type"] == "PARTICIPANT_RECORD":
                payload.update(
                    participant_index=message["participant_index"],
                    config_digest=message["config_digest"],
                )
            ownership.append(message["type"], payload)
    ownership.seal()
    AppendOnlyJournal.create(
        root / "violation_journal.ndjson",
        relative_to=root,
        allowed_kinds={
            "TRACE_VIOLATION_RECORD",
            "SUPERVISOR_VIOLATION_RECORD",
        },
    ).seal()
    pre_receipt = write_host_observer_artifact(
        root / "host_observer_pre.json",
        relative_to=root,
        state="OBSERVED",
        collector_identity=_identity(801),
        network_namespace_inode=81,
        observed_processes=("pid=1 exe=/usr/bin/observer",),
        observed_services=(),
        observed_listeners=(),
        internet_socket_attempts=(),
        trusted_inspection=_trusted_inspection(),
    )
    post_receipt = write_host_observer_artifact(
        root / "host_observer_post.json",
        relative_to=root,
        state="OBSERVED",
        collector_identity=_identity(801),
        network_namespace_inode=81,
        observed_processes=("pid=1 exe=/usr/bin/observer",),
        observed_services=(),
        observed_listeners=(),
        internet_socket_attempts=(),
        trusted_inspection=_trusted_inspection(),
    )
    requirements = {
        name: ArtifactRequirement(
            root
            / (
                f"{name}.ndjson"
                if name in {"trace", "ownership_journal", "violation_journal"}
                else f"{name}.json"
            ),
            expected_mode=0o400,
        )
        for name in REQUIRED_ARTIFACTS
    }
    if not tracked_paths:
        tracked_root = root.parent / f"{root.name}-tracked-root"
        tracked_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _closed_file(tracked_root / "tracked.txt", b"safe")
        tracked_paths = (tracked_root,)
    # Coordinator-side receipts do not cross into the supervisor.  Binding
    # independently reopens both fixed paths after the traced tree exits.
    pre_receipt.close()
    post_receipt.close()
    context = EvidenceContext(
        trace=_trace_runtime(trace_state),
        trace_policy_replay=(
            _trace_policy_replay() if trace_state != "NOT_STARTED" else None
        ),
        ledger_contract=contract,
        expected_run_id="run-1",
        expected_ledger_nonce=RUN_NONCE,
        marker_token="0123456789ab",
        expected_host_observer_identity=_identity(801),
        log_paths=tuple(log_paths),
        tracked_paths=tuple(tracked_paths),
        tracked_symlinks=tuple(tracked_symlinks),
        publication_paths=(root / "result.json", root / "emergency.txt"),
    )
    return requirements, context, secret_sentinels


def test_append_only_journal_is_hash_chained_fsynced_and_sealed(tmp_path, monkeypatch):
    fsync_calls: list[int] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        fsync_calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    journal = AppendOnlyJournal.create(
        tmp_path / "ownership.ndjson", relative_to=tmp_path
    )
    first = journal.append("OWNERSHIP_RECORD", {"pid": 101, "pgid": 101})
    second = journal.append("OWNERSHIP_RECORD", {"pid": 102, "pgid": 102})
    artifact = journal.seal()

    records = [
        json.loads(line)
        for line in (tmp_path / "ownership.ndjson").read_text().splitlines()
    ]
    assert [record["index"] for record in records] == [0, 1]
    assert records[0]["previous_digest"] is None
    assert records[1]["previous_digest"] == first.record_sha256
    assert second.previous_digest == first.record_sha256
    assert artifact.record_count == 2
    assert artifact.relative_path == "ownership.ndjson"
    assert (tmp_path / "ownership.ndjson").stat().st_mode & 0o777 == 0o400
    assert len(fsync_calls) >= 3
    with pytest.raises(ArtifactBindingError, match="sealed"):
        journal.append("OWNERSHIP_RECORD", {"pid": 103, "pgid": 103})


def test_journal_seal_rejects_same_length_external_rewrite(tmp_path):
    path = tmp_path / "ownership.ndjson"
    journal = AppendOnlyJournal.create(path, relative_to=tmp_path)
    journal.append("OWNERSHIP_RECORD", {"pid": 101, "pgid": 101})
    rewrite_fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.pwrite(rewrite_fd, b"X", 0)
        os.fsync(rewrite_fd)
    finally:
        os.close(rewrite_fd)

    with pytest.raises(ArtifactBindingError, match="changed|digest|chain"):
        journal.seal()


def test_journal_rejects_replay_gap_unknown_kind_and_secret(tmp_path):
    journal = AppendOnlyJournal.create(
        tmp_path / "violations.ndjson",
        relative_to=tmp_path,
        allowed_kinds={"TRACE_VIOLATION_RECORD"},
        secret_sentinels={"never-persist-this"},
    )
    journal.append("TRACE_VIOLATION_RECORD", {"reason": "UNEXPECTED_NETWORK_ATTEMPT"})
    with pytest.raises(ArtifactBindingError, match="kind"):
        journal.append("OWNERSHIP_RECORD", {"pid": 1})
    with pytest.raises(ArtifactBindingError, match="secret"):
        journal.append("TRACE_VIOLATION_RECORD", {"value": "never-persist-this"})
    assert "never-persist-this" not in (tmp_path / "violations.ndjson").read_text()


def test_bundle_binds_exact_artifacts_counts_and_retained_descriptors(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)

    assert tuple(bundle.artifacts) == REQUIRED_ARTIFACTS
    assert bundle.artifacts["trace"].record_count == 4
    assert len(bundle.bundle_sha256) == 64
    assert bundle.as_result_artifacts()["trace"] == {
        "relative_path": "trace.ndjson",
        "sha256": bundle.artifacts["trace"].sha256,
        "size": bundle.artifacts["trace"].size,
        "trace_state": "FULL",
        "serialized_record_count": 4,
        "tracee_count": 2,
        "tracer_identity": _identity(501).as_dict(),
        "normalizer_identity": _identity(502).as_dict(),
        "tracer_exit_code": 0,
        "normalizer_exit_code": 0,
        "tool_policy_row_sha256": SHA256,
        "compatibility_fixture_passed": True,
        "not_started_reason": None,
    }
    assert "record_count" not in bundle.as_result_artifacts()["bootstrap_report"]
    assert bundle.as_result_artifacts()["ownership_journal"]["record_count"] == 5
    assert bundle.as_result_artifacts()["violation_journal"]["violation_count"] == 0
    ledger_descriptor = bundle.as_result_artifacts()["ledger_chain_manifest"]
    assert ledger_descriptor["accepted_generation"] == 3
    assert ledger_descriptor["immutable_generation_count"] == 4
    assert bundle.semantic_dds_window == "CLOSED"
    assert bundle.dds_begin_record_index == 1
    assert bundle.dds_end_record_index == 3
    result_evidence = bundle.as_result_evidence()
    assert result_evidence["bundle_sha256"] == bundle.bundle_sha256
    assert isinstance(bundle.artifacts, MappingProxyType)
    assert (
        bundle.bundle_sha256
        == hashlib.sha256(
            canonical_json_bytes(
                {
                    **bundle.as_result_artifacts(),
                    "semantic_dds_window": "CLOSED",
                    "dds_begin_record_index": 1,
                    "dds_end_record_index": 3,
                    "marker_token": "0123456789ab",
                }
            )
        ).hexdigest()
    )
    with pytest.raises(TypeError):
        bundle.artifacts["trace"] = bundle.artifacts["trace"]
    binder.revalidate(bundle)
    assert binder.retained_fd_count == len(REQUIRED_ARTIFACTS) + 5
    freeze = binder.freeze_for_publication(bundle)
    assert binder.revalidate_for_publication(bundle, freeze) == result_evidence
    binder.close()
    assert binder.retained_fd_count == 0


def test_binding_rejects_secret_sentinel_in_any_artifact(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    target = tmp_path / "trace.ndjson"
    _closed_file(target, b'{"value":"never-persist-this"}\n')
    binder = EvidenceBinder(
        tmp_path,
        context=context,
        secret_sentinels={"never-persist-this"},
    )

    with pytest.raises(ArtifactBindingError, match="secret"):
        binder.bind(requirements)


@pytest.mark.parametrize("mutation", ["content", "replace", "mode"])
def test_revalidation_fails_on_mutation_replacement_or_mode_change(tmp_path, mutation):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    target = tmp_path / "trace.ndjson"
    if mutation == "content":
        target.chmod(0o600)
        target.write_bytes(b"changed")
        target.chmod(0o400)
    elif mutation == "replace":
        target.unlink()
        _closed_file(target, b"replacement")
    else:
        target.chmod(0o600)
    with pytest.raises(ArtifactBindingError, match="changed"):
        binder.revalidate(bundle)
    binder.close()


def test_binding_rejects_symlink_escape_and_incomplete_inventory(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    _closed_file(outside, b"{}")
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    (tmp_path / "trace.ndjson").unlink()
    (tmp_path / "trace.ndjson").symlink_to(outside)
    binder = EvidenceBinder(tmp_path, context=context)
    with pytest.raises(ArtifactBindingError, match="symlink|escape"):
        binder.bind(requirements)

    requirements, context, _ = _valid_evidence_inputs(tmp_path / "closed")
    requirements.pop("host_observer_post")
    with pytest.raises(ArtifactBindingError, match="inventory"):
        EvidenceBinder(tmp_path / "closed", context=context).bind(requirements)


def test_host_observer_not_run_is_a_real_closed_artifact(tmp_path):
    artifact = write_host_observer_artifact(
        tmp_path / "host-pre.json",
        relative_to=tmp_path,
        state="NOT_RUN",
        cause_gate="safety.workstation_preflight",
        reason="INTERRUPTED_BEFORE_GATE",
    )
    value = json.loads((tmp_path / "host-pre.json").read_text())
    assert value == {
        "state": "NOT_RUN",
        "collector_identity": None,
        "network_namespace_inode": None,
        "observed_processes": [],
        "observed_services": [],
        "observed_listeners": [],
        "internet_socket_attempts": [],
        "trusted_inspection": None,
        "cause_gate": "safety.workstation_preflight",
        "reason": "INTERRUPTED_BEFORE_GATE",
    }
    assert artifact.record_count == 0
    assert (tmp_path / "host-pre.json").stat().st_mode & 0o777 == 0o400


def test_redaction_records_only_presence_and_rejects_secret_sentinel():
    environment = {
        "OPENAI_API_KEY": "never-persist-this",
        "AZURE_OPENAI_ENDPOINT": "https://secret.invalid",
        "HTTPS_PROXY": "http://user:password@proxy.invalid",
        "ROS_DOMAIN_ID": "77",
        "ROS_LOCALHOST_ONLY": "1",
        "SAFE_NAME": "visible",
    }
    redacted = redact_environment(environment, network_namespace="net:[123]")
    assert redacted == {
        "network_namespace": "net:[123]",
        "ros_domain_id": 77,
        "ros_localhost_only": True,
        "credential_variables_present": ["AZURE_OPENAI_ENDPOINT", "OPENAI_API_KEY"],
        "proxy_variables_present": ["HTTPS_PROXY"],
    }
    rendered = json.dumps(redact_value(environment, {"never-persist-this"}))
    assert "never-persist-this" not in rendered
    assert "password" not in rendered


def test_binding_replays_ledger_chain_and_requires_sealed_accepted_head(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    manifest_path = tmp_path / "ledger_chain_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["accepted_generation"] = 0
    manifest["accepted_sha256"] = manifest["generations"][0]["sha256"]
    _closed_file(manifest_path, canonical_json_bytes(manifest))

    with pytest.raises(ArtifactBindingError, match="ledger|accepted|sealed"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_binding_rejects_broken_journal_hash_chain(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "ownership_journal.ndjson"
    record = {
        "index": 0,
        "kind": "OWNERSHIP_RECORD",
        "previous_digest": None,
        "payload": {"identity": _identity(701).as_dict()},
        "record_sha256": "f" * 64,
    }
    _closed_file(path, canonical_json_bytes(record) + b"\n")

    with pytest.raises(ArtifactBindingError, match="journal.*digest|hash chain"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_binding_rejects_blank_or_noncanonical_ndjson_records(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    _closed_file(tmp_path / "trace.ndjson", b"{}\n\n")

    with pytest.raises(ArtifactBindingError, match="NDJSON|record"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_semantic_secret_scan_rejects_json_escaped_value(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    _closed_file(
        tmp_path / "bootstrap_report.json",
        b'{"value":"never-persist-\\u0074his"}',
    )

    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            tmp_path,
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)


@pytest.mark.parametrize("target_kind", ["log", "tracked"])
def test_secret_scan_covers_logs_and_explicit_tracked_files(tmp_path, target_kind):
    log = tmp_path / "runner.log"
    tracked = tmp_path / "tracked.json"
    _closed_file(log, b"safe")
    _closed_file(tracked, b"{}")
    if target_kind == "log":
        _closed_file(log, b"never-persist-this")
    else:
        _closed_file(tracked, b'{"v":"never-persist-\\u0074his"}')
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run",
        log_paths=(log,),
        tracked_paths=(tracked,),
    )

    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            tmp_path / "run",
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)


def test_secret_scan_accepts_binary_tracked_file_without_sentinel(tmp_path):
    tracked = tmp_path / "tracked.bin"
    _closed_file(tracked, b"\x89PNG\r\n\x1a\n\xff\x00safe")
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run", tracked_paths=(tracked,)
    )

    binder = EvidenceBinder(
        tmp_path / "run",
        context=context,
        secret_sentinels={"never-persist-this"},
    )
    binder.bind(requirements)
    binder.close()


def test_secret_scan_rejects_raw_sentinel_in_binary_tracked_file(tmp_path):
    tracked = tmp_path / "tracked.bin"
    _closed_file(tracked, b"\xff\x00never-persist-this\x80")
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run", tracked_paths=(tracked,)
    )

    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            tmp_path / "run",
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)


def test_tracked_symlink_is_verified_through_publication(tmp_path):
    target = "../../reviewed/checkpoints"
    tracked_symlink = tmp_path / "tracked-checkpoints"
    tracked_symlink.symlink_to(target)
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run",
        tracked_symlinks=((tracked_symlink, _git_blob_sha1(target.encode("utf-8"))),),
    )
    binder = EvidenceBinder(tmp_path / "run", context=context)

    bundle = binder.bind(requirements)
    binder.revalidate(bundle)
    freeze = binder.freeze_for_publication(bundle)

    assert binder.revalidate_for_publication(bundle, freeze)
    binder.close()


def test_tracked_symlink_revalidation_rejects_inode_substitution(tmp_path):
    target = "../../reviewed/checkpoints"
    tracked_symlink = tmp_path / "tracked-checkpoints"
    replacement = tmp_path / "replacement-checkpoints"
    tracked_symlink.symlink_to(target)
    replacement.symlink_to(target)
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run",
        tracked_symlinks=((tracked_symlink, _git_blob_sha1(target.encode("utf-8"))),),
    )
    binder = EvidenceBinder(tmp_path / "run", context=context)
    bundle = binder.bind(requirements)
    os.replace(replacement, tracked_symlink)

    with pytest.raises(ArtifactBindingError, match="tracked symlink"):
        binder.revalidate(bundle)
    binder.close()


def test_tracked_symlink_rejects_encoded_secret_target(tmp_path):
    target = base64.b64encode(b"never-persist-this").decode("ascii")
    tracked_symlink = tmp_path / "tracked-checkpoints"
    tracked_symlink.symlink_to(target)
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run",
        tracked_symlinks=((tracked_symlink, _git_blob_sha1(target.encode("utf-8"))),),
    )

    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            tmp_path / "run",
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)


def test_snapshot_inventory_hash_is_deterministic_beyond_json_collection_bound():
    rows = [
        {"name": f"tracked-{index:04d}", "sha256": "a" * 64, "size": index}
        for index in range(1_025)
    ]

    first = evidence_module._snapshot_rows_sha256(rows)
    assert first == evidence_module._snapshot_rows_sha256(copy.deepcopy(rows))
    rows[-1]["size"] += 1
    assert evidence_module._snapshot_rows_sha256(rows) != first


def test_trace_metadata_and_marker_contract_fail_closed(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    wrong_context = EvidenceContext(
        trace=TraceRuntimeEvidence(
            trace_state="NOT_STARTED",
            tracer_identity=_identity(501),
            normalizer_identity=None,
            tracer_exit_code=None,
            normalizer_exit_code=None,
            tool_policy_row_sha256=None,
            compatibility_fixture_passed=None,
            not_started_reason="TRACE_NOT_STARTED",
        ),
        ledger_contract=context.ledger_contract,
        expected_run_id="run-1",
        expected_ledger_nonce=RUN_NONCE,
        marker_token="0123456789ab",
        expected_host_observer_identity=_identity(801),
    )
    with pytest.raises(ArtifactBindingError, match="NOT_STARTED|trace"):
        EvidenceBinder(tmp_path, context=wrong_context).bind(requirements)

    records = [
        json.loads(line)
        for line in (tmp_path / "trace.ndjson").read_text().splitlines()
    ]
    records[3]["marker"]["token"] = "ffffffffffff"
    _closed_file(
        tmp_path / "trace.ndjson",
        b"".join(canonical_json_bytes(record) + b"\n" for record in records),
    )
    with pytest.raises(ArtifactBindingError, match="marker"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_host_observer_descriptor_is_derived_and_semantically_validated(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    bad = {
        "state": "NOT_RUN",
        "collector_identity": _identity(801).as_dict(),
        "network_namespace_inode": 81,
        "observed_processes": ["pid=1"],
        "observed_services": [],
        "observed_listeners": [],
        "internet_socket_attempts": [],
        "trusted_inspection": None,
        "cause_gate": "safety.workstation_preflight",
        "reason": "INTERRUPTED_BEFORE_GATE",
    }
    _closed_file(tmp_path / "host_observer_post.json", canonical_json_bytes(bad))
    with pytest.raises(ArtifactBindingError, match="observer"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("gateway_status_command", ["/bin/false", "--json"]),
        ("gateway_status_exit", 1),
        ("gateway_status_sha256", "not-a-digest"),
        ("gateway_status_state", "UNKNOWN"),
        ("service_definitions", ["z", "a"]),
        ("listener_command", ["/usr/bin/ss", "-ltn"]),
        ("listener_inventory", ["unexpected-listener"]),
    ],
)
def test_host_observer_rejects_unbound_trusted_inspection_fields(
    tmp_path, field, replacement
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "host_observer_pre.json"
    value = json.loads(path.read_text())
    value["trusted_inspection"][field] = replacement
    _closed_file(path, canonical_json_bytes(value))

    with pytest.raises(ArtifactBindingError, match="inspection|listener|observer"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_host_observer_result_preserves_exact_trusted_inspection(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    descriptor = bundle.as_result_artifacts()["host_observer_pre"]
    assert descriptor["trusted_inspection"] == _trusted_inspection()
    assert (
        descriptor["observation_sha256"]
        == hashlib.sha256(
            canonical_json_bytes(
                {
                    "state": "OBSERVED",
                    "collector_identity": _identity(801).as_dict(),
                    "network_namespace_inode": 81,
                    "observed_processes": ["pid=1 exe=/usr/bin/observer"],
                    "observed_services": [],
                    "observed_listeners": [],
                    "internet_socket_attempts": [],
                    "trusted_inspection": _trusted_inspection(),
                    "cause_gate": None,
                    "reason": None,
                }
            )
        ).hexdigest()
    )


def test_observed_writer_requires_trusted_inspection_and_not_run_forbids_it(tmp_path):
    with pytest.raises(ArtifactBindingError, match="trusted inspection"):
        write_host_observer_artifact(
            tmp_path / "observed.json",
            relative_to=tmp_path,
            state="OBSERVED",
            collector_identity=_identity(801),
            network_namespace_inode=81,
        )

    with pytest.raises(ArtifactBindingError, match="NOT_RUN|zero observations"):
        write_host_observer_artifact(
            tmp_path / "not-run.json",
            relative_to=tmp_path,
            state="NOT_RUN",
            cause_gate="safety.workstation_preflight",
            reason="EARLIER_BLOCKING_GATE",
            trusted_inspection=_trusted_inspection(),
        )


def test_host_observer_preserves_reviewed_long_ss_listener_line(tmp_path):
    listener = "LISTEN " + "x" * 5000
    receipt = write_host_observer_artifact(
        tmp_path / "observed.json",
        relative_to=tmp_path,
        state="OBSERVED",
        collector_identity=_identity(801),
        network_namespace_inode=81,
        observed_listeners=(listener,),
        trusted_inspection=_trusted_inspection((listener,)),
    )

    assert json.loads((tmp_path / "observed.json").read_text())["trusted_inspection"][
        "listener_inventory"
    ] == [listener]
    receipt.close()


def test_publication_freeze_rejects_stale_token_and_last_moment_mutation(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    first = binder.freeze_for_publication(bundle)
    second = binder.freeze_for_publication(bundle)
    with pytest.raises(ArtifactBindingError, match="token"):
        binder.revalidate_for_publication(bundle, first)

    target = tmp_path / "bootstrap_report.json"
    target.chmod(0o600)
    target.write_bytes(b'{"mutated":true}')
    target.chmod(0o400)
    with pytest.raises(ArtifactBindingError, match="changed"):
        binder.revalidate_for_publication(bundle, second)
    binder.close()


def test_support_artifact_path_replacement_is_rejected_before_freeze(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    target = tmp_path / "ledger/generation-000000.json"
    payload = target.read_bytes()
    target.unlink()
    _closed_file(target, payload)

    with pytest.raises(ArtifactBindingError, match="support artifact changed"):
        binder.freeze_for_publication(bundle)
    binder.close()


def test_ownership_journal_accepts_only_broker_bound_production_payload(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "ownership_journal.ndjson"
    path.unlink()
    identity = _identity(701)
    request = {
        "type": "OWNERSHIP_RECORD",
        "run_nonce": RUN_NONCE,
        "sequence": 1,
        "identity": identity.as_dict(),
        "role": "action_child",
    }
    request_sha256 = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    journal.append(
        "OWNERSHIP_RECORD",
        {
            "identity": identity.as_dict(),
            "role": "action_child",
            "request_sha256": request_sha256,
        },
    )
    journal.seal()
    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)
    assert bundle.as_result_artifacts()["ownership_journal"]["record_count"] == 1

    for field, replacement in (("role", "observer"), ("request_sha256", "f" * 64)):
        case = tmp_path.parent / f"{tmp_path.name}-{field}"
        case_requirements, case_context, _ = _valid_evidence_inputs(case)
        case_path = case / "ownership_journal.ndjson"
        case_path.unlink()
        bad_payload = {
            "identity": identity.as_dict(),
            "role": "action_child",
            "request_sha256": request_sha256,
        }
        bad_payload[field] = replacement
        bad = AppendOnlyJournal.create(
            case_path, relative_to=case, allowed_kinds={"OWNERSHIP_RECORD"}
        )
        bad.append("OWNERSHIP_RECORD", bad_payload)
        bad.seal()
        with pytest.raises(ArtifactBindingError, match="ownership"):
            EvidenceBinder(case, context=case_context).bind(case_requirements)


def test_full_ownership_evidence_reconstructs_exact_participant_authority(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "ownership_journal.ndjson"
    path.unlink()
    action = _identity(701)
    identities = [_identity(100 + index) for index in range(4)]
    messages = [
        {
            "type": "OWNERSHIP_RECORD",
            "run_nonce": RUN_NONCE,
            "sequence": 1,
            "identity": action.as_dict(),
            "role": "action_child",
        }
    ]
    messages.extend(
        {
            "type": "PARTICIPANT_RECORD",
            "run_nonce": RUN_NONCE,
            "sequence": index + 2,
            "identity": identity.as_dict(),
            "role": CONFIG_ROLES[index],
            "participant_index": index,
            "config_digest": EXPECTED_CONFIG_SHA256[index],
        }
        for index, identity in enumerate(identities)
    )
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    for message in messages:
        payload = {
            "identity": message["identity"],
            "role": message["role"],
            "request_sha256": hashlib.sha256(canonical_json_bytes(message)).hexdigest(),
        }
        if message["type"] == "PARTICIPANT_RECORD":
            payload.update(
                participant_index=message["participant_index"],
                config_digest=message["config_digest"],
            )
        journal.append(message["type"], payload)
    journal.seal()

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)
    assert bundle.as_result_artifacts()["ownership_journal"]["record_count"] == 5


@pytest.mark.parametrize("defect", ["missing", "duplicate", "late", "digest"])
def test_participant_ownership_evidence_fails_closed(tmp_path, defect):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "ownership_journal.ndjson"
    path.unlink()
    action = _identity(701)
    messages = [
        {
            "type": "OWNERSHIP_RECORD",
            "run_nonce": RUN_NONCE,
            "sequence": 1,
            "identity": action.as_dict(),
            "role": "action_child",
        }
    ]
    for index in range(4):
        messages.append(
            {
                "type": "PARTICIPANT_RECORD",
                "run_nonce": RUN_NONCE,
                "sequence": index + 2,
                "identity": _identity(100 + index).as_dict(),
                "role": CONFIG_ROLES[index],
                "participant_index": index,
                "config_digest": EXPECTED_CONFIG_SHA256[index],
            }
        )
    if defect == "missing":
        messages.pop()
    elif defect == "duplicate":
        messages[2]["identity"] = messages[1]["identity"]
    elif defect == "late":
        messages[1], messages[2] = messages[2], messages[1]
    else:
        messages[2]["config_digest"] = "f" * 64
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={"OWNERSHIP_RECORD", "PARTICIPANT_RECORD"},
    )
    for message in messages:
        payload = {
            "identity": message["identity"],
            "role": message["role"],
            "request_sha256": hashlib.sha256(canonical_json_bytes(message)).hexdigest(),
        }
        if message["type"] == "PARTICIPANT_RECORD":
            payload.update(
                participant_index=message["participant_index"],
                config_digest=message["config_digest"],
            )
        journal.append(message["type"], payload)
    journal.seal()
    with pytest.raises(ArtifactBindingError, match="ownership|participant"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_ledger_replay_rejects_schema_valid_gate_regression(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    generation_paths = [
        tmp_path / f"ledger/generation-{index:06d}.json" for index in range(4)
    ]
    documents = [json.loads(path.read_text()) for path in generation_paths]
    documents[1]["gates"][0].update(status="PASS", reason="OK")
    documents[2]["gates"][0].update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    previous = None
    digests = []
    for index, (path, document) in enumerate(zip(generation_paths, documents)):
        document["previous_digest"] = previous
        _closed_file(path, canonical_json_bytes(document))
        previous = hashlib.sha256(path.read_bytes()).hexdigest()
        digests.append(previous)
    manifest = json.loads((tmp_path / "ledger_chain_manifest.json").read_text())
    for index, entry in enumerate(manifest["generations"]):
        entry["sha256"] = digests[index]
        entry["size"] = generation_paths[index].stat().st_size
        entry["previous_digest"] = None if index == 0 else digests[index - 1]
    manifest["accepted_sha256"] = digests[-1]
    _closed_file(
        tmp_path / "ledger_chain_manifest.json", canonical_json_bytes(manifest)
    )

    with pytest.raises(ArtifactBindingError, match="ledger.*transition|monotonic"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_bootstrap_report_is_closed_and_semantically_derived(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    _closed_file(tmp_path / "bootstrap_report.json", b"{}")
    with pytest.raises(ArtifactBindingError, match="bootstrap"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)

    requirements, context, _ = _valid_evidence_inputs(tmp_path / "valid")
    bundle = EvidenceBinder(tmp_path / "valid", context=context).bind(requirements)
    report = bundle.as_result_artifacts()["bootstrap_report"]
    assert report["terminal_launch_state"] == "NOT_STARTED_BOOTSTRAP_FAILURE"
    assert report["coordinator_launch_committed"] is False
    assert report["handoff"]["terminal_state"] == "NOT_APPLICABLE"


def test_not_started_bootstrap_preserves_nullable_mismatched_tool_observations(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["toolchain"]["observed"] = {
        "strace_version": None,
        "parser_sha256": "f" * 64,
    }
    report["toolchain"]["expected"] = {
        "strace_version": "6.6",
        "parser_sha256": "e" * 64,
    }
    _closed_file(path, canonical_json_bytes(report))

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert bundle.as_result_artifacts()["bootstrap_report"]["toolchain"] == {
        "expected": [
            {"name": "parser_sha256", "value": "e" * 64},
            {"name": "strace_version", "value": "6.6"},
        ],
        "observed": [
            {"name": "parser_sha256", "value": "f" * 64},
            {"name": "strace_version", "value": None},
        ],
    }


def test_committed_bootstrap_can_truthfully_end_with_failed_signal_handoff(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"].update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        signal_ready_identity=None,
        signal_ready_sequence=None,
        signal_ready_sha256=None,
        signal_ready_accepted_sequence=None,
        signal_ready_accepted_sha256=None,
        unblocked_mask=[],
        acceptance_count=0,
        forward_target_pgid=None,
        forward_count=0,
        unblock_trace_record_index=None,
        first_functional_trace_record_index=None,
    )
    _closed_file(path, canonical_json_bytes(report))

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert (
        bundle.as_result_artifacts()["bootstrap_report"]["handoff"]["terminal_state"]
        == "FAILED"
    )


def test_ready_handoff_digests_and_trace_order_are_bound_to_the_run(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"]["signal_ready_sha256"] = "f" * 64
    _closed_file(path, canonical_json_bytes(report))
    with pytest.raises(ArtifactBindingError, match="handoff|request.*digest"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)

    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "order", trace_state="FULL"
    )
    path = tmp_path / "order/bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"]["unblock_trace_record_index"] = 2
    report["handoff"]["first_functional_trace_record_index"] = 1
    _closed_file(path, canonical_json_bytes(report))
    with pytest.raises(ArtifactBindingError, match="trace.*order|functional"):
        EvidenceBinder(tmp_path / "order", context=context).bind(requirements)


def test_ready_handoff_can_be_interrupted_immediately_after_unblock(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"]["pending_signal"] = "TERM"
    report["handoff"]["forward_target_pgid"] = 601
    report["handoff"]["forward_count"] = 1
    report["handoff"]["first_functional_trace_record_index"] = None
    report["handoff"]["event_sequence"] = [
        {"sequence": 0, "state": "AWAITING_READY"},
        {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
        {"sequence": 2, "state": "PENDING_FORWARD"},
        {"sequence": 3, "state": "READY"},
    ]
    _closed_file(path, canonical_json_bytes(report))

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    handoff = bundle.as_result_artifacts()["bootstrap_report"]["handoff"]
    assert handoff["acceptance_count"] == 1
    assert handoff["unblock_trace_record_index"] == 0
    assert handoff["first_functional_trace_record_index"] is None


def test_not_applicable_handoff_requires_an_empty_event_history(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"]["event_sequence"] = [{"sequence": 0, "state": "NOT_APPLICABLE"}]
    _closed_file(path, canonical_json_bytes(report))

    with pytest.raises(ArtifactBindingError, match="non-applicable|activity|history"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_ready_handoff_cannot_omit_functional_progress_without_pending_signal(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"]["first_functional_trace_record_index"] = None
    _closed_file(path, canonical_json_bytes(report))

    with pytest.raises(ArtifactBindingError, match="handoff|incomplete|functional"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_failed_accepted_handoff_recomputes_request_and_acceptance_digests(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"].update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
            {"sequence": 2, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        first_functional_trace_record_index=None,
    )
    report["handoff"]["signal_ready_accepted_sha256"] = "f" * 64
    _closed_file(path, canonical_json_bytes(report))

    with pytest.raises(ArtifactBindingError, match="handoff|acceptance|digest"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_failed_unaccepted_handoff_recomputes_any_observed_ready_request(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"].update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "AWAITING_ACCEPTANCE"},
            {"sequence": 2, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        signal_ready_sha256="f" * 64,
        signal_ready_accepted_sequence=None,
        signal_ready_accepted_sha256=None,
        unblocked_mask=[],
        acceptance_count=0,
        unblock_trace_record_index=None,
        first_functional_trace_record_index=None,
    )
    _closed_file(path, canonical_json_bytes(report))

    with pytest.raises(ArtifactBindingError, match="handoff|request|digest"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_failed_unaccepted_handoff_rejects_partial_ready_identity(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "bootstrap_report.json"
    report = json.loads(path.read_text())
    report["handoff"].update(
        event_sequence=[
            {"sequence": 0, "state": "AWAITING_READY"},
            {"sequence": 1, "state": "FAILED"},
        ],
        terminal_state="FAILED",
        signal_ready_sequence=None,
        signal_ready_sha256=None,
        signal_ready_accepted_sequence=None,
        signal_ready_accepted_sha256=None,
        unblocked_mask=[],
        acceptance_count=0,
        unblock_trace_record_index=None,
        first_functional_trace_record_index=None,
    )
    _closed_file(path, canonical_json_bytes(report))

    with pytest.raises(ArtifactBindingError, match="handoff|identity|request"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_violation_journal_rejects_wrong_reason_for_matching_trace_record(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    _write_policy_violation_trace(tmp_path)
    path = tmp_path / "violation_journal.ndjson"
    path.unlink()
    journal = AppendOnlyJournal.create(
        path, relative_to=tmp_path, allowed_kinds={"TRACE_VIOLATION_RECORD"}
    )
    payload = {
        "reason": "UNEXPECTED_NETWORK_ATTEMPT",
        "record_index": 2,
        "pid": 601,
        "operation": "io_uring_setup",
    }
    journal.append("TRACE_VIOLATION_RECORD", payload)
    journal.seal()

    with pytest.raises(ArtifactBindingError, match="violation|reason|trace|payload"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_violation_journal_accepts_exact_closed_trace_correlated_payload(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    _write_policy_violation_trace(tmp_path)
    path = tmp_path / "violation_journal.ndjson"
    path.unlink()
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={
            "TRACE_VIOLATION_RECORD",
            "SUPERVISOR_VIOLATION_RECORD",
        },
    )
    journal.append(
        "TRACE_VIOLATION_RECORD",
        {
            "reason": "PROHIBITED_IO_URING",
            "record_index": 2,
            "pid": 601,
            "operation": "io_uring_setup",
        },
    )
    journal.seal()

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert bundle.as_result_artifacts()["violation_journal"]["violation_count"] == 1


def test_violation_journal_accepts_supervisor_audit_before_trace(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path, trace_state="NOT_STARTED"
    )
    path = tmp_path / "violation_journal.ndjson"
    path.unlink()
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={
            "TRACE_VIOLATION_RECORD",
            "SUPERVISOR_VIOLATION_RECORD",
        },
    )
    journal.append(
        "SUPERVISOR_VIOLATION_RECORD",
        {
            "reason": "UNEXPECTED_NETWORK_ATTEMPT",
            "event_sequence": 0,
            "pid": 501,
            "operation": "socket",
        },
    )
    journal.seal()

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert bundle.as_result_artifacts()["violation_journal"]["violation_count"] == 1


def test_violation_journal_rejects_supervisor_record_with_fake_trace_index(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "violation_journal.ndjson"
    path.unlink()
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={"SUPERVISOR_VIOLATION_RECORD"},
    )
    journal.append(
        "SUPERVISOR_VIOLATION_RECORD",
        {
            "reason": "UNEXPECTED_NETWORK_ATTEMPT",
            "event_sequence": 0,
            "record_index": 0,
            "pid": 501,
            "operation": "socket",
        },
    )
    journal.seal()

    with pytest.raises(ArtifactBindingError, match="violation|payload"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_violation_journal_requires_contiguous_supervisor_event_sequence(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "violation_journal.ndjson"
    path.unlink()
    journal = AppendOnlyJournal.create(
        path,
        relative_to=tmp_path,
        allowed_kinds={"SUPERVISOR_VIOLATION_RECORD"},
    )
    journal.append(
        "SUPERVISOR_VIOLATION_RECORD",
        {
            "reason": "UNEXPECTED_NETWORK_ATTEMPT",
            "event_sequence": 1,
            "pid": 501,
            "operation": "socket",
        },
    )
    journal.seal()

    with pytest.raises(ArtifactBindingError, match="sequence|violation"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_violation_journal_cannot_omit_a_replayed_policy_violation(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    _write_policy_violation_trace(tmp_path)

    with pytest.raises(ArtifactBindingError, match="violation|replay|journal"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_postflight_failure_can_leave_post_observer_not_run_after_preflight_passes(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    (tmp_path / "host_observer_post.json").unlink()
    write_host_observer_artifact(
        tmp_path / "host_observer_post.json",
        relative_to=tmp_path,
        state="NOT_RUN",
        cause_gate="safety.workstation_postflight",
        reason="POSTFLIGHT_FAILED",
    )

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    post = bundle.as_result_artifacts()["host_observer_post"]
    assert post["state"] == "NOT_RUN"
    assert post["cause_gate"] == "safety.workstation_postflight"
    assert post["reason"] == "POSTFLIGHT_FAILED"


def test_bundle_binds_the_exact_accepted_ledger_action_state(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    ledger = bundle.as_result_artifacts()["ledger_chain_manifest"]
    accepted = json.loads(
        (
            tmp_path / f"ledger/generation-{ledger['accepted_generation']:06d}.json"
        ).read_text()
    )
    expected = hashlib.sha256(
        canonical_json_bytes(
            {
                "gates": accepted["gates"][:24],
                "semantic_dds_window": accepted["semantic_dds_window"],
            }
        )
    ).hexdigest()
    assert ledger["accepted_action_state_sha256"] == expected


def test_publication_freeze_rejects_new_log_created_after_binding(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(
        tmp_path,
        context=context,
        secret_sentinels={"never-persist-this"},
    )
    bundle = binder.bind(requirements)
    _closed_file(tmp_path / "late.log", b"never-persist-this")

    with pytest.raises(ArtifactBindingError, match="inventory|secret|added"):
        binder.freeze_for_publication(bundle)


def test_publication_freeze_rejects_any_unexpected_late_file(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    _closed_file(tmp_path / "late-safe.txt", b"safe")

    with pytest.raises(ArtifactBindingError, match="inventory|added"):
        binder.freeze_for_publication(bundle)


def test_publication_inventory_allows_only_configured_atomic_result_temporary(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    freeze = binder.freeze_for_publication(bundle)
    temporary = tmp_path / f".result.json.tmp-{os.getpid()}-fixture"
    temporary.write_bytes(b"{}")
    temporary.chmod(0o600)
    binder.register_publication_temporary(bundle, freeze, temporary)

    assert (
        binder.revalidate_for_publication(bundle, freeze) == bundle.as_result_evidence()
    )

    _closed_file(tmp_path / ".other.json.tmp-1-bypass", b"{}")
    with pytest.raises(ArtifactBindingError, match="inventory"):
        binder.revalidate_for_publication(bundle, freeze)


def test_publication_inventory_rejects_unregistered_result_temporary(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    freeze = binder.freeze_for_publication(bundle)
    temporary = tmp_path / f".result.json.tmp-{os.getpid()}-unregistered"
    temporary.write_bytes(b"{}")
    temporary.chmod(0o600)

    with pytest.raises(ArtifactBindingError, match="inventory|registered"):
        binder.revalidate_for_publication(bundle, freeze)


def test_publication_registration_rejects_wrong_mode_and_unconfigured_prefix(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    freeze = binder.freeze_for_publication(bundle)
    wrong = tmp_path / ".unconfigured.json.tmp-exact"
    wrong.write_bytes(b"{}")
    wrong.chmod(0o600)

    with pytest.raises(ArtifactBindingError, match="publication|configured"):
        binder.register_publication_temporary(bundle, freeze, wrong)

    wrong.unlink()
    wrong_mode = tmp_path / ".result.json.tmp-exact"
    _closed_file(wrong_mode, b"{}")
    with pytest.raises(ArtifactBindingError, match="mode|publication"):
        binder.register_publication_temporary(bundle, freeze, wrong_mode)


def test_publication_freeze_binds_every_preexisting_run_file_content(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    extra = tmp_path / "extra.txt"
    extra.write_bytes(b"pre-existing support")
    extra.chmod(0o400)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)

    extra.chmod(0o600)
    extra.write_bytes(b"same-name mutation")
    extra.chmod(0o400)

    with pytest.raises(ArtifactBindingError, match="support|inventory|changed"):
        binder.freeze_for_publication(bundle)


def test_publication_freeze_binds_every_preexisting_secret_root_file(tmp_path):
    tracked = tmp_path / "tracked"
    tracked.mkdir(mode=0o700)
    extra = tracked / "extra.txt"
    _closed_file(extra, b"pre-existing secret-root support")
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run", tracked_paths=(tracked,)
    )
    binder = EvidenceBinder(tmp_path / "run", context=context)
    bundle = binder.bind(requirements)

    extra.chmod(0o600)
    extra.write_bytes(b"same-name mutation")
    extra.chmod(0o400)

    with pytest.raises(ArtifactBindingError, match="support|secret|changed"):
        binder.freeze_for_publication(bundle)


def test_publication_freeze_does_not_chmod_external_tracked_directories(tmp_path):
    tracked = tmp_path / "tracked"
    tracked.mkdir(mode=0o700)
    _closed_file(tracked / "extra.txt", b"tracked support")
    requirements, context, _ = _valid_evidence_inputs(
        tmp_path / "run", tracked_paths=(tracked,)
    )
    binder = EvidenceBinder(tmp_path / "run", context=context)
    bundle = binder.bind(requirements)

    binder.freeze_for_publication(bundle)

    assert tracked.stat().st_mode & 0o777 == 0o700


def test_publication_freeze_requires_all_evidence_writer_identities_absent(
    tmp_path, monkeypatch
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    monkeypatch.setattr(
        ProcessIdentity, "matches_proc", lambda self, proc_root=Path("/proc"): True
    )

    with pytest.raises(ArtifactBindingError, match="writer|live|identity"):
        binder.freeze_for_publication(bundle)


def test_publication_freeze_checks_ownership_journal_writer_identity(
    tmp_path, monkeypatch
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    path = tmp_path / "ownership_journal.ndjson"
    path.unlink()
    identity = _identity(701)
    request = {
        "type": "OWNERSHIP_RECORD",
        "run_nonce": RUN_NONCE,
        "sequence": 1,
        "identity": identity.as_dict(),
        "role": "action_child",
    }
    journal = AppendOnlyJournal.create(
        path, relative_to=tmp_path, allowed_kinds={"OWNERSHIP_RECORD"}
    )
    journal.append(
        "OWNERSHIP_RECORD",
        {
            "identity": identity.as_dict(),
            "role": "action_child",
            "request_sha256": hashlib.sha256(canonical_json_bytes(request)).hexdigest(),
        },
    )
    journal.seal()
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)
    monkeypatch.setattr(
        ProcessIdentity,
        "matches_proc",
        lambda self, proc_root=Path("/proc"): self.pid == 701,
    )

    with pytest.raises(ArtifactBindingError, match="writer|live|identity"):
        binder.freeze_for_publication(bundle)


def test_publication_freeze_leaves_evidence_subdirectories_read_only_after_close(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    binder = EvidenceBinder(tmp_path, context=context)
    bundle = binder.bind(requirements)

    binder.freeze_for_publication(bundle)
    binder.close()

    assert (tmp_path / "ledger").stat().st_mode & 0o777 == 0o500
    assert (tmp_path / "ledger/generation-000000.json").stat().st_mode & 0o777 == 0o400


def test_artifact_open_never_traverses_a_swappable_absolute_ancestor(
    tmp_path, monkeypatch
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    original = tmp_path / "artifacts"
    outside = tmp_path.parent / f"{tmp_path.name}-outside-artifacts"
    original.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    trace = tmp_path / "trace.ndjson"
    nested_trace = original / "trace.ndjson"
    trace.rename(nested_trace)
    os.link(nested_trace, outside / "trace.ndjson")
    requirements["trace"] = ArtifactRequirement(nested_trace, expected_mode=0o400)
    real_open = os.open
    traversed_swappable_ancestor = False

    def racing_open(path, flags, *args, **kwargs):
        nonlocal traversed_swappable_ancestor
        if Path(path) == nested_trace and "dir_fd" not in kwargs:
            traversed_swappable_ancestor = True
            saved = tmp_path / "artifacts.saved"
            original.rename(saved)
            original.symlink_to(outside, target_is_directory=True)
            try:
                return real_open(path, flags, *args, **kwargs)
            finally:
                original.unlink()
                saved.rename(original)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", racing_open)
    EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert traversed_swappable_ancestor is False


def test_host_observer_requires_trusted_identity_and_observed_inventory(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    value = json.loads((tmp_path / "host_observer_pre.json").read_text())
    value["collector_identity"] = _identity(999).as_dict()
    _closed_file(tmp_path / "host_observer_pre.json", canonical_json_bytes(value))
    with pytest.raises(ArtifactBindingError, match="observer.*identity"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)

    requirements, context, _ = _valid_evidence_inputs(tmp_path / "attempt")
    value = json.loads((tmp_path / "attempt/host_observer_pre.json").read_text())
    value["internet_socket_attempts"] = ["connect(203.0.113.1:443)"]
    _closed_file(
        tmp_path / "attempt/host_observer_pre.json", canonical_json_bytes(value)
    )
    with pytest.raises(ArtifactBindingError, match="observer.*socket"):
        EvidenceBinder(tmp_path / "attempt", context=context).bind(requirements)


def test_full_bind_independently_reopens_observers_after_receipts_are_discarded(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")

    bundle = EvidenceBinder(tmp_path, context=context).bind(requirements)

    assert bundle.as_result_artifacts()["host_observer_pre"]["trusted_inspection"]
    assert bundle.as_result_artifacts()["host_observer_post"]["trusted_inspection"]


def test_full_bind_rejects_tampered_observer_without_receipt_or_metadata_authority(
    tmp_path,
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "host_observer_pre.json"
    value = json.loads(path.read_text())
    value["trusted_inspection"]["listener_inventory"] = ["caller-claimed-listener"]
    _closed_file(path, canonical_json_bytes(value))

    with pytest.raises(ArtifactBindingError, match="inspection|listener|observer"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


def test_host_observer_requirements_must_use_fixed_run_root_paths(tmp_path):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    alternate = tmp_path / "alternate-pre.json"
    alternate.write_bytes((tmp_path / "host_observer_pre.json").read_bytes())
    alternate.chmod(0o400)
    requirements["host_observer_pre"] = ArtifactRequirement(
        alternate, expected_mode=0o400
    )

    with pytest.raises(ArtifactBindingError, match="fixed|path|observer"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


@pytest.mark.parametrize("claimed_field", ["sha256", "size", "process_count"])
def test_host_observer_caller_metadata_cannot_override_derived_descriptor(
    tmp_path, claimed_field
):
    requirements, context, _ = _valid_evidence_inputs(tmp_path, trace_state="FULL")
    path = tmp_path / "host_observer_pre.json"
    value = json.loads(path.read_text())
    value[claimed_field] = 999 if claimed_field != "sha256" else "f" * 64
    _closed_file(path, canonical_json_bytes(value))

    with pytest.raises(ArtifactBindingError, match="observer.*closed|artifact"):
        EvidenceBinder(tmp_path, context=context).bind(requirements)


@pytest.mark.parametrize(
    "encoded",
    [
        'prefix {"v":"never-persist-\\u0074his"} suffix',
        "never-persist-%74his",
        base64.b64encode(b"never-persist-this").decode(),
        b"never-persist-this".hex(),
    ],
)
def test_secret_scan_rejects_transformed_sentinels(tmp_path, encoded):
    requirements, context, _ = _valid_evidence_inputs(tmp_path)
    log = tmp_path / "unlisted-runner.log"
    _closed_file(log, encoded.encode())
    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            tmp_path,
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)


def test_tracked_root_is_recursively_enumerated(tmp_path):
    run = tmp_path / "run"
    tracked = tmp_path / "tracked"
    nested = tracked / "nested"
    nested.mkdir(mode=0o700, parents=True)
    _closed_file(nested / "config.txt", b"never-persist-this")
    requirements, context, _ = _valid_evidence_inputs(run, tracked_paths=(tracked,))
    with pytest.raises(ArtifactBindingError, match="secret"):
        EvidenceBinder(
            run,
            context=context,
            secret_sentinels={"never-persist-this"},
        ).bind(requirements)
