import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import threading

import pytest

import holoagent0_setup.atomic_io as atomic_io
from holoagent0_setup.atomic_io import (
    atomic_write_json_no_replace,
    canonical_json_bytes,
)
from holoagent0_setup.contract import ContractSet
from holoagent0_setup.ledger import LedgerCandidate, LedgerChainError, LedgerStore
import holoagent0_setup.ledger as ledger_module


PACKAGE_ROOT = Path(__file__).parents[1]
NONCE = "a" * 64


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    root = tmp_path_factory.mktemp("ledger-contract")
    shutil.copytree(PACKAGE_ROOT / "schemas", root / "schemas")
    shutil.copytree(PACKAGE_ROOT / "policies", root / "policies")
    policy_path = root / "policies/holoagent0-trace-tool-v1.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    row = policy["rows"][0]
    row["build"].update(
        recipe_sha256="1" * 64,
        container_image_digest="sha256:" + "2" * 64,
        review_state="REVIEWED",
    )
    row["runtime"].update(
        elf_size=1,
        elf_sha256="3" * 64,
        version_output_sha256="4" * 64,
        review_state="REVIEWED",
    )
    row["parser"].update(sha256="5" * 64, review_state="REVIEWED")
    row["argv"].update(canonical_sha256="6" * 64, review_state="REVIEWED")
    row["fixtures"].update(manifest_sha256="7" * 64, review_state="REVIEWED")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return ContractSet(root)


def pass_gate(store, gate_id):
    gates = copy.deepcopy(store.current["gates"])
    gate = next(item for item in gates if item["id"] == gate_id)
    gate.update(status="PASS", reason="OK")
    return gates


def interrupted_postflight_gates(store):
    gates = copy.deepcopy(store.current["gates"])
    for gate in gates[:23]:
        if gate["status"] == "NOT_RUN":
            gate["reason"] = "INTERRUPTED_BEFORE_GATE"
    gates[23].update(status="PASS", reason="OK")
    return gates


def recovery_postflight_gates(store, reason="POSTFLIGHT_FAILED"):
    gates = copy.deepcopy(store.current["gates"])
    gates[23].update(status="FAIL", reason=reason)
    return gates


def candidate(
    store,
    gates,
    *,
    generation=None,
    previous_generation=None,
    previous_digest=None,
    sealed=False,
    window="NOT_ENTERED",
):
    return LedgerCandidate(
        generation=store.head.generation + 1 if generation is None else generation,
        previous_generation=store.head.generation
        if previous_generation is None
        else previous_generation,
        previous_digest=store.head.digest
        if previous_digest is None
        else previous_digest,
        run_id="run-1",
        ledger_nonce=NONCE,
        gates=gates,
        sealed=sealed,
        semantic_dds_window=window,
    )


def test_generation_zero_is_immutable_schema_valid_and_described(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    assert store.head.generation == 0
    assert not store.head.sealed
    assert store.current["previous_generation"] is None
    assert all(gate["status"] == "NOT_RUN" for gate in store.current["gates"])
    assert all(
        gate["reason"] == "EARLIER_BLOCKING_GATE" for gate in store.current["gates"]
    )
    path = tmp_path / "ledger/generation-000000.json"
    assert path.stat().st_mode & 0o777 == 0o400
    assert contract.validate_document("holoagent0-offline-ledger-v1", store.current).ok


def test_successor_requires_exact_acknowledged_generation_and_digest(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    first = store.append(candidate(store, pass_gate(store, "source.repository")))
    assert first.generation == 1
    assert all(gate["status"] == "NOT_RUN" for gate in store.current["gates"][23:])

    with pytest.raises(LedgerChainError, match="repeated generation"):
        store.append(candidate(store, store.current["gates"], generation=1))
    with pytest.raises(LedgerChainError, match="generation gap"):
        store.append(candidate(store, store.current["gates"], generation=3))
    with pytest.raises(LedgerChainError, match="stale predecessor generation"):
        store.append(candidate(store, store.current["gates"], previous_generation=0))
    with pytest.raises(LedgerChainError, match="stale predecessor digest"):
        store.append(candidate(store, store.current["gates"], previous_digest="b" * 64))
    assert store.head == first


def test_replay_fork_nonce_and_non_monotonic_transition_are_rejected(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    store.append(candidate(store, pass_gate(store, "source.repository")))

    reverted = copy.deepcopy(store.current["gates"])
    reverted[0].update(status="NOT_RUN", reason="EARLIER_BLOCKING_GATE")
    with pytest.raises(LedgerChainError, match="non-monotonic"):
        store.append(candidate(store, reverted))
    wrong_nonce = candidate(store, store.current["gates"])
    wrong_nonce = LedgerCandidate(**{**wrong_nonce.__dict__, "ledger_nonce": "c" * 64})
    with pytest.raises(LedgerChainError, match="nonce"):
        store.append(wrong_nonce)

    old_head = store.head
    fork = candidate(store, pass_gate(store, "runtime.workstation"))
    store.append(fork)
    with pytest.raises(LedgerChainError, match="repeated generation"):
        store.append(fork)
    assert store.head.generation == old_head.generation + 1


def test_noop_generation_is_rejected_as_replay(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    with pytest.raises(LedgerChainError, match="no state transition"):
        store.append(candidate(store, store.current["gates"]))


def test_action_gate_cannot_advance_out_of_profile_order(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    with pytest.raises(LedgerChainError, match="out of profile order"):
        store.append(candidate(store, pass_gate(store, "runtime.workstation")))


def test_blocking_failure_prevents_later_action_progression(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    failed = copy.deepcopy(store.current["gates"])
    failed[0].update(status="FAIL", reason="SOURCE_MISMATCH")
    store.append(candidate(store, failed))
    later = copy.deepcopy(store.current["gates"])
    later[1].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="earlier blocking failure"):
        store.append(candidate(store, later))


def test_new_blocking_failure_stops_same_generation_progression(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = copy.deepcopy(store.current["gates"])
    gates[0].update(status="FAIL", reason="SOURCE_MISMATCH")
    gates[1].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="same generation"):
        store.append(candidate(store, gates))


def test_supervisor_finalizers_cannot_be_written_to_working_ledger(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = copy.deepcopy(store.current["gates"])
    gates[24].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="supervisor-owned"):
        store.append(candidate(store, gates))


def test_gate24_can_only_transition_in_sealed_generation(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = interrupted_postflight_gates(store)
    with pytest.raises(LedgerChainError, match="gate 24.*sealed"):
        store.append(candidate(store, gates))


def test_interruption_reason_transition_requires_exact_remaining_action_suffix(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    store.append(candidate(store, pass_gate(store, "source.repository")))
    suffix = copy.deepcopy(store.current["gates"])
    for gate in suffix[1:23]:
        gate["reason"] = "INTERRUPTED_BEFORE_GATE"
    store.append(candidate(store, suffix))
    assert all(
        gate["reason"] == "INTERRUPTED_BEFORE_GATE"
        for gate in store.current["gates"][1:23]
    )
    resumed = copy.deepcopy(store.current["gates"])
    resumed[1].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="interrupted action gate"):
        store.append(candidate(store, resumed))

    store2 = LedgerStore.create(tmp_path / "ledger2", contract, NONCE, run_id="run-1")
    partial = copy.deepcopy(store2.current["gates"])
    partial[1]["reason"] = "INTERRUPTED_BEFORE_GATE"
    with pytest.raises(LedgerChainError, match="interruption suffix"):
        store2.append(candidate(store2, partial))


def test_acknowledged_block_cannot_transition_only_a_later_interruption_suffix(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    failed = copy.deepcopy(store.current["gates"])
    failed[0].update(status="FAIL", reason="SOURCE_MISMATCH")
    store.append(candidate(store, failed))

    mixed = copy.deepcopy(store.current["gates"])
    for gate in mixed[2:23]:
        gate["reason"] = "INTERRUPTED_BEFORE_GATE"
    with pytest.raises(LedgerChainError, match="exact interruption suffix"):
        store.append(candidate(store, mixed))

    exact = copy.deepcopy(store.current["gates"])
    for gate in exact[1:23]:
        gate["reason"] = "INTERRUPTED_BEFORE_GATE"
    store.append(candidate(store, exact))
    assert all(
        gate["reason"] == "INTERRUPTED_BEFORE_GATE"
        for gate in store.current["gates"][1:23]
    )


def test_dds_window_requires_open_before_closed(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    with pytest.raises(LedgerChainError, match="DDS window"):
        store.append(
            candidate(
                store,
                pass_gate(store, "source.repository"),
                window="CLOSED",
            )
        )
    store.append(candidate(store, store.current["gates"], window="OPEN"))
    store.append(candidate(store, pass_gate(store, "source.repository"), window="OPEN"))
    store.append(candidate(store, store.current["gates"], window="CLOSED"))
    assert store.current["semantic_dds_window"] == "CLOSED"


def test_seal_requires_terminal_postflight_closed_window_and_blocks_append(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = interrupted_postflight_gates(store)
    with pytest.raises(LedgerChainError, match="DDS window"):
        store.seal(candidate(store, gates, sealed=True, window="OPEN"))

    store.append(candidate(store, store.current["gates"], window="OPEN"))
    store.append(candidate(store, store.current["gates"], window="CLOSED"))
    gates = interrupted_postflight_gates(store)
    head = store.seal(candidate(store, gates, sealed=True, window="CLOSED"))
    assert head.sealed
    assert (tmp_path / "ledger/generation-000003.json").stat().st_mode & 0o777 == 0o400
    with pytest.raises(LedgerChainError, match="sealed"):
        store.append(candidate(store, store.current["gates"]))


def test_sealed_generation_rejects_not_run_coordinator_finalizer(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    with pytest.raises(LedgerChainError, match="transition gate 24"):
        store.seal(candidate(store, store.current["gates"], sealed=True))


def test_sealed_generation_rejects_unjustified_action_skeleton(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = pass_gate(store, "safety.workstation_postflight")
    with pytest.raises(LedgerChainError, match="sealed action state"):
        store.seal(candidate(store, gates, sealed=True))


def test_supervisor_can_seal_exact_genesis_recovery_failure(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    head = store.seal(candidate(store, recovery_postflight_gates(store), sealed=True))
    assert head.sealed


def test_supervisor_can_seal_exact_mid_run_recovery_failure(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    store.append(candidate(store, pass_gate(store, "source.repository")))
    head = store.seal(candidate(store, recovery_postflight_gates(store), sealed=True))
    assert head.sealed


def test_supervisor_recovery_rejects_wrong_reason_and_inconsistent_suffix(
    tmp_path, contract
):
    wrong = LedgerStore.create(tmp_path / "wrong", contract, NONCE, run_id="run-1")
    with pytest.raises(LedgerChainError, match="sealed action state"):
        wrong.seal(
            candidate(
                wrong,
                recovery_postflight_gates(wrong, "CLEANUP_INCOMPLETE"),
                sealed=True,
            )
        )

    inconsistent = LedgerStore.create(
        tmp_path / "inconsistent", contract, NONCE, run_id="run-1"
    )
    gates = recovery_postflight_gates(inconsistent)
    gates[1]["reason"] = "INTERRUPTED_BEFORE_GATE"
    with pytest.raises(LedgerChainError, match="unacknowledged action progress"):
        inconsistent.seal(candidate(inconsistent, gates, sealed=True))


def test_supervisor_recovery_rejects_unacknowledged_genesis_action_progress(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    gates = recovery_postflight_gates(store)
    gates[0].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="unacknowledged action progress"):
        store.seal(candidate(store, gates, sealed=True))


def test_supervisor_recovery_rejects_unacknowledged_mid_run_action_progress(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    store.append(candidate(store, pass_gate(store, "source.repository")))
    gates = recovery_postflight_gates(store)
    gates[1].update(status="PASS", reason="OK")
    with pytest.raises(LedgerChainError, match="unacknowledged action progress"):
        store.seal(candidate(store, gates, sealed=True))


def test_supervisor_recovery_may_close_an_acknowledged_open_dds_window(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    store.append(candidate(store, store.current["gates"], window="OPEN"))
    head = store.seal(
        candidate(
            store,
            recovery_postflight_gates(store),
            sealed=True,
            window="CLOSED",
        )
    )
    assert head.sealed


def test_candidate_schema_failure_and_existing_generation_do_not_advance_head(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    malformed = copy.deepcopy(store.current["gates"])
    malformed[0].update(status="FAIL", reason="LOCAL_REASON")
    before = store.head
    with pytest.raises(LedgerChainError, match="schema"):
        store.append(candidate(store, malformed))
    assert store.head == before

    existing = tmp_path / "ledger/generation-000001.json"
    existing.write_text("attacker", encoding="utf-8")
    with pytest.raises(LedgerChainError, match="already exists"):
        store.append(candidate(store, pass_gate(store, "source.repository")))
    assert store.head == before
    assert existing.read_text(encoding="utf-8") == "attacker"


def test_preexisting_byte_identical_generation_is_never_reconciled(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    successor = candidate(store, pass_gate(store, "source.repository"))
    atomic_write_json_no_replace(
        tmp_path / "ledger/generation-000001.json",
        successor.as_json(),
        mode=0o400,
    )

    with pytest.raises(LedgerChainError, match="already exists"):
        store.append(successor)
    assert store.head.generation == 0


def test_generation_file_mutation_attempt_fails_for_unprivileged_writer(
    tmp_path, contract
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    path = tmp_path / "ledger/generation-000000.json"
    assert path.stat().st_mode & 0o222 == 0
    original = hashlib.sha256(path.read_bytes()).hexdigest()
    assert original == store.head.digest

    path.chmod(0o600)
    path.write_bytes(b"{}")
    with pytest.raises(LedgerChainError, match="immutable generation changed"):
        store.append(candidate(store, store.current["gates"]))


def test_current_generation_is_returned_as_a_defensive_copy(tmp_path, contract):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    exposed = store.current
    exposed["gates"][0]["status"] = "PASS"
    assert store.current["gates"][0]["status"] == "NOT_RUN"


def test_post_install_error_is_securely_reconciled_without_occupied_generation_wedge(
    tmp_path, contract, monkeypatch
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    successor = candidate(store, pass_gate(store, "source.repository"))
    real_install = ledger_module.atomic_write_json_no_replace

    def install_then_report_error(*args, **kwargs):
        descriptor = real_install(*args, **kwargs)
        raise atomic_io.AtomicPublicationAmbiguity(
            "injected post-install durability error", descriptor
        )

    monkeypatch.setattr(
        ledger_module, "atomic_write_json_no_replace", install_then_report_error
    )
    head = store.append(successor)

    assert head.generation == 1
    assert store.current["gates"][0]["status"] == "PASS"
    assert (tmp_path / "ledger/generation-000001.json").exists()


def test_transient_post_install_verification_uses_only_pending_publication(
    tmp_path, contract, monkeypatch
):
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    exact = candidate(store, pass_gate(store, "source.repository"))
    real_verify = store._verify_immutable_chain
    fail_once = True

    def transient_verify(descriptors=None):
        nonlocal fail_once
        if descriptors is not None and fail_once:
            fail_once = False
            raise LedgerChainError("injected post-install chain verification failure")
        return real_verify(descriptors)

    monkeypatch.setattr(store, "_verify_immutable_chain", transient_verify)
    with pytest.raises(LedgerChainError, match="injected post-install"):
        store.append(exact)
    assert store.head.generation == 0

    wrong_gates = copy.deepcopy(exact.gates)
    wrong_gates[1].update(status="PASS", reason="OK")
    wrong = candidate(store, wrong_gates)
    with pytest.raises(LedgerChainError, match="already exists|pending publication"):
        store.append(wrong)
    assert store.head.generation == 0

    head = store.append(exact)
    assert head.generation == 1


def test_generation_zero_reconciles_only_this_calls_publication_ambiguity(
    tmp_path, contract, monkeypatch
):
    real_install = ledger_module.atomic_write_json_no_replace

    def install_then_report_error(*args, **kwargs):
        descriptor = real_install(*args, **kwargs)
        raise atomic_io.AtomicPublicationAmbiguity(
            "injected generation-zero publication ambiguity", descriptor
        )

    monkeypatch.setattr(
        ledger_module, "atomic_write_json_no_replace", install_then_report_error
    )
    store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")

    assert store.head.generation == 0
    assert store.current["generation"] == 0


def test_create_initializes_unpublished_staging_before_final_root(
    tmp_path, contract, monkeypatch
):
    root = tmp_path / "ledger"
    real_validate = contract.validate_document
    observed: dict[str, object] = {}

    def observe_staging(name, value):
        observed["final_exists"] = root.exists()
        observed["staging"] = tuple(tmp_path.glob(".ledger.staging-*"))
        return real_validate(name, value)

    monkeypatch.setattr(contract, "validate_document", observe_staging)
    store = LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert observed["final_exists"] is False
    assert len(observed["staging"]) == 1
    assert store.root == root
    assert root.is_dir()


def test_create_is_umask_independent(tmp_path, contract):
    previous_umask = os.umask(0o777)
    try:
        store = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    finally:
        os.umask(previous_umask)

    assert (tmp_path / "ledger").stat().st_mode & 0o777 == 0o700
    assert store.head.generation == 0


def test_append_serializes_head_current_and_descriptor_publication(tmp_path, contract):
    head_published = threading.Event()
    second_started = threading.Event()
    second_postinstall = threading.Event()
    release_first = threading.Event()

    class PausingLedgerStore(LedgerStore):
        @property
        def head(self):
            return self._test_head

        @head.setter
        def head(self, value):
            self._test_head = value
            if getattr(self, "pause_publication", False) and value.generation == 1:
                head_published.set()
                assert second_started.wait(timeout=2)
                assert release_first.wait(timeout=2)

        def _verify_immutable_chain(self, descriptors=None):
            if (
                threading.current_thread().name == "ledger-second"
                and descriptors is not None
            ):
                second_postinstall.set()
                assert release_first.wait(timeout=2)
            return super()._verify_immutable_chain(descriptors)

    store = PausingLedgerStore.create(
        tmp_path / "ledger", contract, NONCE, run_id="run-1"
    )
    store.pause_publication = True
    first_candidate = candidate(store, pass_gate(store, "source.repository"))
    second_gates = copy.deepcopy(first_candidate.gates)
    second_gates[1].update(status="PASS", reason="OK")
    second_candidate = LedgerCandidate(
        generation=2,
        previous_generation=1,
        previous_digest=hashlib.sha256(
            canonical_json_bytes(first_candidate.as_json())
        ).hexdigest(),
        run_id="run-1",
        ledger_nonce=NONCE,
        gates=second_gates,
    )
    failures: list[BaseException] = []

    def append_first():
        try:
            store.append(first_candidate)
        except BaseException as error:  # pragma: no cover - asserted below
            failures.append(error)

    first = threading.Thread(target=append_first)
    first.start()
    assert head_published.wait(timeout=2)

    def append_second():
        second_started.set()
        try:
            store.append(second_candidate)
        except BaseException as error:  # pragma: no cover - asserted below
            failures.append(error)

    second = threading.Thread(target=append_second, name="ledger-second")
    second.start()
    assert second_started.wait(timeout=2)
    second_postinstall.wait(timeout=0.2)
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive() and not second.is_alive()
    assert failures == []
    assert store.head.generation == 2
    assert store.current["gates"][1]["status"] == "PASS"


def test_create_rejects_symlink_ancestor_without_mutating_its_target(
    tmp_path, contract
):
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(outside, target_is_directory=True)

    with pytest.raises(LedgerChainError, match="directory creation"):
        LedgerStore.create(alias / "ledger", contract, NONCE, run_id="run-1")

    assert not (outside / "ledger").exists()


def test_create_closes_retained_root_fd_when_genesis_validation_fails(
    tmp_path, contract, monkeypatch
):
    real_validate = contract.validate_document

    def reject_genesis(name, value):
        decision = real_validate(name, value)
        return type(decision)(False, decision.code, ("injected invalid genesis",))

    monkeypatch.setattr(contract, "validate_document", reject_genesis)
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(LedgerChainError, match="generation zero schema invalid"):
        LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    after = set(os.listdir("/proc/self/fd"))

    assert after == before
    monkeypatch.setattr(contract, "validate_document", real_validate)
    retry = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    assert retry.head.generation == 0


def test_create_failure_leaves_final_root_unpublished_and_retryable(
    tmp_path, contract, monkeypatch
):
    real_validate = contract.validate_document

    def reject_genesis(name, value):
        decision = real_validate(name, value)
        return type(decision)(False, decision.code, ("injected invalid genesis",))

    root = tmp_path / "new-parent/ledger"
    monkeypatch.setattr(contract, "validate_document", reject_genesis)
    with pytest.raises(LedgerChainError, match="generation zero schema invalid"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")
    assert not root.exists()
    assert tuple((tmp_path / "new-parent").glob(".ledger.staging-*"))

    monkeypatch.setattr(contract, "validate_document", real_validate)
    retry = LedgerStore.create(root, contract, NONCE, run_id="run-1")
    assert retry.head.generation == 0


def test_prepublication_failure_never_uses_path_rmdir_cleanup(
    tmp_path, contract, monkeypatch
):
    real_validate = contract.validate_document
    root = tmp_path / "ledger"

    def reject_genesis(name, value):
        decision = real_validate(name, value)
        return type(decision)(False, decision.code, ("injected invalid genesis",))

    monkeypatch.setattr(contract, "validate_document", reject_genesis)
    monkeypatch.setattr(
        os,
        "rmdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("path rmdir is forbidden")
        ),
    )
    with pytest.raises(LedgerChainError, match="generation zero schema invalid"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert not root.exists()


def test_create_cleanup_never_removes_a_replacement_directory(
    tmp_path, contract, monkeypatch
):
    real_validate = contract.validate_document
    root = tmp_path / "ledger"

    def publish_competing_root_then_reject(name, value):
        root.mkdir(mode=0o700)
        decision = real_validate(name, value)
        return type(decision)(False, decision.code, ("injected invalid genesis",))

    monkeypatch.setattr(
        contract, "validate_document", publish_competing_root_then_reject
    )
    with pytest.raises(LedgerChainError, match="generation zero schema invalid"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert root.is_dir()


def test_staging_publication_is_atomic_no_replace(tmp_path, contract, monkeypatch):
    root = tmp_path / "ledger"
    real_publish = ledger_module._publish_directory_no_replace

    def race_competing_root(parent_fd, staging_name, final_name, lexical_parent):
        os.mkdir(final_name, mode=0o700, dir_fd=parent_fd)
        return real_publish(parent_fd, staging_name, final_name, lexical_parent)

    monkeypatch.setattr(
        ledger_module, "_publish_directory_no_replace", race_competing_root
    )
    with pytest.raises(LedgerChainError, match="generation zero install failed"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert root.is_dir()
    assert list(root.iterdir()) == []


def test_create_rejects_parent_replacement_before_staging_publish(
    tmp_path, contract, monkeypatch
):
    parent = tmp_path / "parent"
    displaced = tmp_path / "displaced-parent"
    parent.mkdir()
    root = parent / "ledger"
    real_publish = ledger_module._publish_directory_no_replace

    def replace_parent_then_publish(*args):
        parent.rename(displaced)
        parent.mkdir()
        return real_publish(*args)

    monkeypatch.setattr(
        ledger_module, "_publish_directory_no_replace", replace_parent_then_publish
    )
    with pytest.raises(LedgerChainError, match="parent|generation zero install failed"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert not root.exists()


def test_create_rejects_parent_replacement_after_staging_publish(
    tmp_path, contract, monkeypatch
):
    parent = tmp_path / "parent"
    displaced = tmp_path / "displaced-parent"
    parent.mkdir()
    root = parent / "ledger"
    real_require_parent = ledger_module._require_lexical_directory_identity
    checks = 0

    def replace_parent_before_postrename_check(path, retained_fd):
        nonlocal checks
        checks += 1
        if checks == 2:
            parent.rename(displaced)
            parent.mkdir()
        return real_require_parent(path, retained_fd)

    monkeypatch.setattr(
        ledger_module,
        "_require_lexical_directory_identity",
        replace_parent_before_postrename_check,
    )
    with pytest.raises(LedgerChainError, match="parent|generation zero install failed"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert checks >= 2
    assert not root.exists()


def test_create_rejects_final_path_replacement_after_first_observation(
    tmp_path, contract, monkeypatch
):
    root = tmp_path / "ledger"
    displaced_name = ".displaced-ledger"
    real_stat = os.stat
    replaced = False

    def observe_then_replace(path, *args, **kwargs):
        nonlocal replaced
        observed = real_stat(path, *args, **kwargs)
        if (
            not replaced
            and path == root.name
            and kwargs.get("dir_fd") is not None
            and kwargs.get("follow_symlinks") is False
        ):
            replaced = True
            parent_fd = kwargs["dir_fd"]
            os.rename(
                root.name,
                displaced_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.mkdir(root.name, mode=0o700, dir_fd=parent_fd)
        return observed

    monkeypatch.setattr(ledger_module.os, "stat", observe_then_replace)
    with pytest.raises(
        LedgerChainError, match="root identity|generation zero install failed"
    ):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert replaced
    assert root.is_dir()
    assert list(root.iterdir()) == []


def test_create_reopens_requested_root_after_last_parent_identity_check(
    tmp_path, contract, monkeypatch
):
    parent = tmp_path / "parent"
    displaced = tmp_path / "displaced-parent"
    parent.mkdir()
    root = parent / "ledger"
    real_require_parent = ledger_module._require_lexical_directory_identity
    checks = 0

    def replace_parent_after_last_check(path, retained_fd):
        nonlocal checks
        result = real_require_parent(path, retained_fd)
        checks += 1
        if checks == 4:
            parent.rename(displaced)
            parent.mkdir()
        return result

    monkeypatch.setattr(
        ledger_module,
        "_require_lexical_directory_identity",
        replace_parent_after_last_check,
    )
    with pytest.raises(LedgerChainError, match="root|generation zero install failed"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert checks == 4
    assert not root.exists()


def test_create_reconciles_transient_parent_fsync_after_publication(
    tmp_path, contract, monkeypatch
):
    root = tmp_path / "ledger"
    real_fsync = os.fsync
    failed = False

    def fail_once_when_final_root_is_visible(fd):
        nonlocal failed
        try:
            observed = os.stat(root.name, dir_fd=fd, follow_symlinks=False)
        except (FileNotFoundError, NotADirectoryError):
            return real_fsync(fd)
        if not failed and observed.st_ino == root.stat(follow_symlinks=False).st_ino:
            failed = True
            raise OSError("injected transient parent fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(ledger_module.os, "fsync", fail_once_when_final_root_is_visible)
    store = LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert failed
    assert store.head.generation == 0
    assert root.is_dir()


def test_create_reconciles_transient_postpublication_identity_failure(
    tmp_path, contract, monkeypatch
):
    root = tmp_path / "ledger"
    real_require_root = ledger_module._require_published_root_identity
    checks = 0

    def fail_first_identity_check(*args, **kwargs):
        nonlocal checks
        checks += 1
        if checks == 1:
            raise OSError("injected transient published-root identity failure")
        return real_require_root(*args, **kwargs)

    monkeypatch.setattr(
        ledger_module, "_require_published_root_identity", fail_first_identity_check
    )
    store = LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert checks >= 2
    assert store.head.generation == 0
    assert root.is_dir()


def test_create_persistent_postpublication_identity_failure_fails_closed(
    tmp_path, contract, monkeypatch
):
    root = tmp_path / "ledger"
    checks = 0

    def fail_every_identity_check(*_args, **_kwargs):
        nonlocal checks
        checks += 1
        raise OSError("injected persistent published-root identity failure")

    monkeypatch.setattr(
        ledger_module, "_require_published_root_identity", fail_every_identity_check
    )
    with pytest.raises(LedgerChainError, match="generation zero install failed"):
        LedgerStore.create(root, contract, NONCE, run_id="run-1")

    assert checks >= 1
    assert root.is_dir()


@pytest.mark.parametrize("operation", ["chmod", "fsync"])
def test_create_closes_new_directory_fd_when_secure_creation_fails(
    tmp_path, contract, monkeypatch, operation
):
    real_operation = getattr(os, operation)

    def fail(*_args, **_kwargs):
        raise OSError(f"injected {operation} failure")

    monkeypatch.setattr(os, operation, fail)
    before = set(os.listdir("/proc/self/fd"))
    with pytest.raises(LedgerChainError, match="directory creation"):
        LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    after = set(os.listdir("/proc/self/fd"))

    assert after == before
    monkeypatch.setattr(os, operation, real_operation)
    retry = LedgerStore.create(tmp_path / "ledger", contract, NONCE, run_id="run-1")
    assert retry.head.generation == 0
