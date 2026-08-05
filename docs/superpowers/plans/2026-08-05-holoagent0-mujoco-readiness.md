# HoloAgent-0 MuJoCo Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `workstation_mujoco`, which runs a fresh validated offline child followed by existing MuJoCo Stages 1–4 and emits only the approved pass, qualification, or failure result.

**Architecture:** Reuse the evidence contracts and atomic result engine delivered by Plan 1. A parent runner creates and validates the offline child lineage, invokes each existing stage script without trusting shell exit alone, normalizes child evidence, applies the exact Stage 3 qualification predicate, and makes workstation postflight outrank functional outcomes. Stage scripts remain independently executable and are not hardened beyond their approved existing cleanup contract in this milestone.

**Tech Stack:** Python 3.10, pytest, Bash, ROS 2 Humble, MuJoCo 3.8.1, existing `holoagent_mujoco` package, Plan 1 JSON schemas and policies.

**Dependencies:** Complete Plan 1 first. Preserve the existing Stage 1–4 implementation and its tracked tests.

---

## File map

- `scripts/holoagent0_setup/holoagent0_setup/lineage_request.py`: create, canonically bind, and single-use-claim the offline child request.
- `scripts/holoagent0_setup/holoagent0_setup/offline_reference.py`: validate child lineage, freshness, labels, gates, and digests.
- `scripts/holoagent0_setup/holoagent0_setup/stage_adapter.py`: read one stage result and separate process exit, evaluator outcome, and postflight safety.
- `scripts/holoagent0_setup/holoagent0_setup/mujoco_decision.py`: closed Stage 3 qualification and top-level result mapping.
- `scripts/holoagent0_setup/holoagent0_setup/mujoco_runner.py`: sequential child orchestration and mandatory postflight.
- `scripts/holoagent0_setup/run_workstation_mujoco.sh`: public wrapper with localhost-only DDS.
- `scripts/holoagent0_setup/tests/test_lineage_request.py`, `test_offline_reference.py`, `test_stage_adapter.py`, `test_mujoco_decision.py`, `test_mujoco_runner.py`: focused contract tests.
- `docs/holoagent0/workstation-mujoco-runbook.md`: execution and evidence inspection.

### Task 1: Offline child lineage and reference acceptance

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/lineage_request.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/offline_reference.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/invocation.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/offline_cli.py`
- Modify: `scripts/holoagent0_setup/schemas/holoagent0-result-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/holoagent0-lineage-request-v1.schema.json`
- Test: `scripts/holoagent0_setup/tests/test_lineage_request.py`
- Test: `scripts/holoagent0_setup/tests/test_offline_reference.py`

- [ ] **Step 1: Write establishment, single-use, and reference-rejection tests**

```python
def test_parent_creates_canonical_mode_0600_request(parent_run):
    request = create_lineage_request(parent_run.request_fields)
    assert request.path.parent == parent_run.path.resolve()
    assert stat.S_IMODE(request.path.stat().st_mode) == 0o600
    assert request.path.read_bytes() == rfc8785(request.value)


@pytest.mark.parametrize("mutation", [
    "replay", "symlink", "outside_parent", "mode_0640", "wrong_owner",
    "noncanonical", "wrong_parent", "wrong_nonce", "wrong_child_mode",
    "source_digest", "config_digest", "asset_digest", "policy_digest",
])
def test_child_rejects_lineage_request_before_gate_one(
    child_cli, lineage_request, mutation
):
    completed = child_cli(mutate_request(lineage_request, mutation))
    assert completed.functional_gate_calls == []
    assert completed.gates[0].status == "NOT_RUN"


@pytest.mark.parametrize("mutation", [
    "stale", "failed_label", "blocking_gate", "wrong_parent",
    "wrong_nonce", "request_digest", "source_digest", "asset_digest",
    "policy_digest", "provisioning_digest", "evidence_bundle_digest",
])
def test_offline_reference_rejects_mismatch(valid_child, parent_context, mutation):
    child = mutate(valid_child, mutation)
    decision = validate_offline_reference(child, parent_context)
    assert decision.status == "FAIL"
    assert decision.reason in {"DIGEST_MISMATCH", "STAGE_EVIDENCE_INVALID"}
```

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_lineage_request.py scripts/holoagent0_setup/tests/test_offline_reference.py`

Expected: FAIL because the request protocol and `offline_reference` are absent.

- [ ] **Step 3: Implement request establishment, child claim, and exact acceptance**

```python
@dataclass(frozen=True)
class ParentContext:
    run_id: str
    lineage_nonce: str
    source_commit: str
    started_monotonic_ns: int
    required_digests: Mapping[str, str]
    lineage_request_sha256: str


@dataclass(frozen=True)
class LineageRequest:
    schema: Literal["holoagent0.lineage-request.v1"]
    parent_run_id: str
    lineage_nonce: str
    child_mode: Literal["workstation_offline"]
    expected_digests: Mapping[str, str]


@dataclass(frozen=True)
class OfflineReferenceDecision:
    status: Literal["PASS", "FAIL"]
    reason: str
    child_run_id: str | None
    child_bundle_sha256: str | None
```

The MuJoCo parent generates exactly 32 random bytes as 64 lowercase hex, builds a closed `holoagent0.lineage-request.v1` object containing only schema/version, parent run ID, nonce, child mode, and the complete expected schema/policy/source/config/asset digest map, serializes it as RFC 8785 canonical JSON, and atomically installs `offline-lineage-request-v1.json` with `O_EXCL`, owner UID, mode `0600`, file and parent-directory `fsync`, and no symlink or path escape. It records the canonical request SHA-256 and passes the absolute request path to the child only as `--lineage-request PATH`; it never passes independent parent/nonce values that could disagree with the request.

Extend the Plan 1 invocation and CLI so `--lineage-request` is the sole way to select `invocation_role="child"`. Before `source.repository` or any other gate can transition from `NOT_RUN`, the child opens the file with `O_NOFOLLOW`, requires a regular current-UID mode-`0600` file directly inside the declared parent run directory, validates the closed schema/canonical bytes/64-hex nonce/child mode/digest set, and atomically claims it by a no-replace rename to `offline-lineage-request-v1.claimed.json`. Missing, already-claimed, replayed, replaced, noncanonical, wrong-owner, over-permissive, symlinked, escaped, or digest-mismatched requests fail closed with zero functional-gate progression. The child derives and records `parent_run_id`, `lineage_nonce`, `lineage_request_sha256`, `invocation_role="child"`, and expected digests from the claimed request. Standalone invocation rejects `--lineage-request` companions and records null lineage fields.

Require a fresh schema-valid child; allowed offline pass/qualification label and exit; no blocking failed gate; exact parent ID, nonce, and canonical request digest on the child; child start/end within the parent window; and equality of every source, config, graph, dataset, checkpoint, provisioning, schema, policy, Cyclone, trace-tool, and evidence-bundle digest named in the approved design. The parent hashes the closed child result and computes `lineage_binding_sha256` over RFC 8785 canonical JSON containing exactly `parent_run_id`, `child_run_id`, `lineage_nonce`, and `child_result_sha256`; any extra/missing field, alternate serialization, request replay, or path substitution fails `offline.reference`.

- [ ] **Step 4: Run valid and adversarial establishment/reference tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_lineage_request.py scripts/holoagent0_setup/tests/test_offline_reference.py scripts/holoagent0_setup/tests/test_offline_cli.py`

Expected: PASS; request creation is canonical and mode `0600`, one request can be claimed exactly once before gate 1, and only the exactly bound child result is accepted.

- [ ] **Step 5: Commit reference validation**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/lineage_request.py scripts/holoagent0_setup/holoagent0_setup/offline_reference.py scripts/holoagent0_setup/holoagent0_setup/invocation.py scripts/holoagent0_setup/holoagent0_setup/offline_cli.py scripts/holoagent0_setup/schemas/holoagent0-result-v1.schema.json scripts/holoagent0_setup/schemas/holoagent0-lineage-request-v1.schema.json scripts/holoagent0_setup/tests/test_lineage_request.py scripts/holoagent0_setup/tests/test_offline_reference.py scripts/holoagent0_setup/tests/test_offline_cli.py
git commit -m "feat: validate offline child lineage"
```

### Task 2: Stage result adapter and postflight safety override

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/stage_adapter.py`
- Test: `scripts/holoagent0_setup/tests/test_stage_adapter.py`

- [ ] **Step 1: Write tests that distrust process exit alone**

```python
def test_zero_exit_with_missing_postflight_is_safety_failure(tmp_path):
    write_stage_result(tmp_path, label="PASS_SIM_ODOM", postflight_pass=None)
    decision = read_stage_result(stage=1, process_exit=0, run_dir=tmp_path)
    assert decision.safety_failed
    assert decision.reason == "STAGE_POSTFLIGHT_FAILED"


def test_nonzero_estimator_result_is_preserved_for_stage3(tmp_path):
    write_stage_result(tmp_path, label="FAIL_ESTIMATOR", postflight_pass=True)
    decision = read_stage_result(stage=3, process_exit=20, run_dir=tmp_path)
    assert decision.label == "FAIL_ESTIMATOR"
    assert not decision.safety_failed
```

- [ ] **Step 2: Run and verify the adapter is missing**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_stage_adapter.py`

Expected: FAIL because the adapter does not exist.

- [ ] **Step 3: Implement strict stage evidence parsing**

```python
@dataclass(frozen=True)
class StageDecision:
    stage: int
    process_exit: int
    label: str
    evidence_valid: bool
    postflight_pass: bool
    safety_failed: bool
    gates: Mapping[str, bool]
    result_path: Path
```

Require one final `result.json`, no pending-only artifact, finite measurements, expected stage label enum, stage-specific schema, and `postflight_pass: true`. A false/missing postflight always maps to parent `FAIL_SAFETY`/30 and leaves later stages `NOT_RUN`, even when the evaluator already returned nonzero.

- [ ] **Step 4: Run stage adapter tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_stage_adapter.py`

Expected: PASS for exits 0/10/20 and all missing/malformed/postflight cases.

- [ ] **Step 5: Commit the stage adapter**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/stage_adapter.py scripts/holoagent0_setup/tests/test_stage_adapter.py
git commit -m "feat: normalize mujoco stage evidence"
```

### Task 3: Exact Stage 3 qualification predicate

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/mujoco_decision.py`
- Test: `scripts/holoagent0_setup/tests/test_mujoco_decision.py`

- [ ] **Step 1: Write pass, qualified, and blocking matrix tests**

```python
PREREQUISITES = (
    "graph", "use_sim_time", "calibration", "sensor_contract",
    "perfect_odom_isolated", "message_finite", "excitation",
)
ESTIMATOR_GATES = (
    "estimate_stream", "translation_rmse", "translation_max", "yaw_rmse",
)


def test_estimator_only_failure_is_qualified():
    gates = {name: True for name in PREREQUISITES + ESTIMATOR_GATES}
    gates["translation_rmse"] = False
    decision = classify_stage3("FAIL_ESTIMATOR", gates)
    assert decision.status == "QUALIFIED"


@pytest.mark.parametrize("gate", PREREQUISITES)
def test_prerequisite_failure_blocks_stage4(gate):
    gates = {name: True for name in PREREQUISITES + ESTIMATOR_GATES}
    gates[gate] = False
    decision = classify_stage3("FAIL_ESTIMATOR", gates)
    assert decision.status == "FAIL"
    assert not decision.run_stage4
```

- [ ] **Step 2: Run and verify decision module absence**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_decision.py`

Expected: FAIL because Stage 3 classification is missing.

- [ ] **Step 3: Implement the closed predicate**

```python
@dataclass(frozen=True)
class Stage3Decision:
    status: Literal["PASS", "QUALIFIED", "FAIL"]
    run_stage4: bool
    reason: str


def classify_stage3(label: str, gates: Mapping[str, bool]) -> Stage3Decision:
    expected = set(PREREQUISITES + ESTIMATOR_GATES)
    if set(gates) != expected:
        return Stage3Decision("FAIL", False, "STAGE_EVIDENCE_INVALID")
    prereq_ok = all(gates.get(name) is True for name in PREREQUISITES)
    failed = {name for name in ESTIMATOR_GATES if gates.get(name) is not True}
    if label == "PASS_LIO_ONLY" and prereq_ok and not failed:
        return Stage3Decision("PASS", True, "OK")
    if label == "FAIL_ESTIMATOR" and prereq_ok and failed:
        return Stage3Decision("QUALIFIED", True, "ESTIMATOR_THRESHOLD_FAILED")
    return Stage3Decision("FAIL", False, "STAGE_CHILD_FAILED")
```

Reject missing/extra gates, malformed evidence, another failure label, or any prerequisite failure. Qualification never becomes a MuJoCo pass.

- [ ] **Step 4: Run the full decision matrix**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_decision.py`

Expected: PASS for every individual and combined estimator failure and every prerequisite failure.

- [ ] **Step 5: Commit Stage 3 classification**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/mujoco_decision.py scripts/holoagent0_setup/tests/test_mujoco_decision.py
git commit -m "feat: classify stage3 estimator qualification"
```

### Task 4: Sequential MuJoCo parent runner

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/mujoco_runner.py`
- Create: `scripts/holoagent0_setup/run_workstation_mujoco.sh`
- Test: `scripts/holoagent0_setup/tests/test_mujoco_runner.py`

- [ ] **Step 1: Write fake-child sequencing tests**

```python
def test_qualified_stage3_runs_independent_stage4(fake_children):
    fake_children.stage3(label="FAIL_ESTIMATOR", estimator_only=True)
    result = fake_children.run_parent()
    assert fake_children.calls == ["offline", "stage1", "stage2", "stage3", "stage4"]
    assert result.label == "READY_MUJOCO_STAGE4_ESTIMATOR_FAILED"
    assert result.exit_code == 10


def test_stage3_prerequisite_failure_marks_stage4_not_run(fake_children):
    fake_children.stage3(label="FAIL_ESTIMATOR", prerequisite="calibration")
    result = fake_children.run_parent()
    assert fake_children.calls == ["offline", "stage1", "stage2", "stage3"]
    assert result.gate("mujoco.stage4").status == "NOT_RUN"
```

- [ ] **Step 2: Run and verify runner absence**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_runner.py`

Expected: FAIL because the parent runner is absent.

- [ ] **Step 3: Implement exact command and cleanup orchestration**

```python
STAGE_COMMANDS = {
    1: ("bash", "nav_agent/mujoco_sim/scripts/run_stage1.sh"),
    2: ("bash", "nav_agent/mujoco_sim/scripts/run_stage2.sh"),
    3: ("bash", "nav_agent/mujoco_sim/scripts/run_stage3.sh"),
    4: ("bash", "nav_agent/mujoco_sim/scripts/run_stage4.sh"),
}


class MujocoRunner:
    def run(self) -> int:
        request = self.create_fresh_offline_request()
        child = self.run_fresh_offline_child(
            argv=(
                "bash", "scripts/holoagent0_setup/run_workstation_offline.sh",
                "--output-root", str(self.offline_child_root),
                "--run-id", self.allocate_child_run_id(),
                "--lineage-request", str(request.path),
            ),
            expected_request_sha256=request.sha256,
        )
        self.require_offline_reference(child, request)
        for stage in (1, 2, 3, 4):
            if self.should_run(stage):
                self.run_stage(stage)
        return self.finalize_authoritative_result()
```

`run_fresh_offline_child()` accepts only the fully constructed argv tuple and expected canonical request digest shown above; it does not accept a pre-existing result or independent lineage fields. It verifies the request is still the parent's unclaimed mode-`0600` file immediately before spawn, records the child PID/start time, requires the `.claimed.json` transition, resolves the one explicitly allocated child result path, and hashes/validates that result before Stage 1. A nonzero child exit is interpreted only through its schema-valid result; missing claim/result, request mutation/replay, wrong path, wrong permission, lineage mismatch, or reference rejection leaves Stages 1–4 `NOT_RUN`.

Set `ROS_DOMAIN_ID=77`, `ROS_LOCALHOST_ONLY=1`, `ROS2CLI_DISABLE_DAEMON=1`, exact Cyclone RMW, `MUJOCO_GL=egl`, and a new output directory. Never invoke Unitree SDK or PC2. Capture all child exits without `set -e` short-circuiting, validate results, mark later stages deterministically, and always execute parent workstation postflight.

- [ ] **Step 4: Run sequencing and signal tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_runner.py`

Expected: PASS for request creation/claim, replay/path/permission rejection before Stage 1, offline result rejection, every stage failure, qualified Stage 3, parent HUP/INT/TERM, and postflight override.

- [ ] **Step 5: Commit the parent runner**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/mujoco_runner.py scripts/holoagent0_setup/run_workstation_mujoco.sh scripts/holoagent0_setup/tests/test_mujoco_runner.py
git commit -m "feat: add consolidated mujoco readiness runner"
```

### Task 5: Result mapping and existing Stage 1–4 regression manifest

**Files:**
- Modify: `scripts/holoagent0_setup/test-manifest-v1.txt`
- Test: `scripts/holoagent0_setup/tests/test_mujoco_result_mapping.py`
- Test: `scripts/holoagent0_setup/tests/test_mujoco_manifest.py`

- [ ] **Step 1: Write top-level mapping tests**

```python
def test_all_stage_passes_are_required_for_pass(parent_result):
    result = parent_result(stage_labels=(
        "PASS_SIM_ODOM", "PASS_SYNTHETIC_LIVOX", "PASS_LIO_ONLY",
        "PASS_SIM_SEMANTIC_PLUMBING",
    ))
    assert (result.label, result.status, result.exit_code) == (
        "PASS_HOLOAGENT0_MUJOCO", "PASS", 0)


def test_estimator_qualification_cannot_map_to_pass(parent_result):
    result = parent_result(stage3="QUALIFIED", stage4="PASS")
    assert result.label == "READY_MUJOCO_STAGE4_ESTIMATOR_FAILED"
    assert result.exit_code == 10
```

- [ ] **Step 2: Run mapping and manifest tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_result_mapping.py scripts/holoagent0_setup/tests/test_mujoco_manifest.py`

Expected: FAIL until mappings and exact Stage test paths are registered.

- [ ] **Step 3: Register the existing tests and closed mappings**

Add every current `nav_agent/mujoco_sim/tests/test_*.py` and `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test/test_*.py` to the manifest. Require each path to exist, at least one test to collect, and zero failures. Map safety first, then harness, interruption, functional failure, allowed Stage 3 qualification, and pass.

- [ ] **Step 4: Run the tracked MuJoCo regression set**

Run: `PYTHONPATH=nav_agent/mujoco_sim:nav_agent/sem_nav_ctr/src/holoagent_livox_converter:scripts/holoagent0_setup python3 -m pytest -q nav_agent/mujoco_sim/tests nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test scripts/holoagent0_setup/tests/test_mujoco_result_mapping.py scripts/holoagent0_setup/tests/test_mujoco_manifest.py`

Expected: at least one test collected and zero failures; no test-count equality is asserted.

- [ ] **Step 5: Commit mappings and manifest**

```bash
git add scripts/holoagent0_setup/test-manifest-v1.txt scripts/holoagent0_setup/tests/test_mujoco_result_mapping.py scripts/holoagent0_setup/tests/test_mujoco_manifest.py
git commit -m "test: pin mujoco readiness regression selection"
```

### Task 6: Runtime runbook and acceptance evidence

**Files:**
- Modify: `nav_agent/mujoco_sim/README.md`
- Create: `docs/holoagent0/workstation-mujoco-runbook.md`
- Test: `scripts/holoagent0_setup/tests/test_mujoco_runbook.py`

- [ ] **Step 1: Write runbook safety tests**

```python
def test_runbook_is_simulation_only(runbook):
    assert "run_workstation_mujoco.sh" in runbook
    assert "ROS_LOCALHOST_ONLY=1" in runbook
    assert "g1_pubvel_node" not in runbook
    assert "unitree_sdk2" not in runbook
```

- [ ] **Step 2: Run and verify documentation test fails**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_mujoco_runbook.py`

Expected: FAIL because the runbook is absent.

- [ ] **Step 3: Document execution and result inspection**

```bash
bash scripts/holoagent0_setup/run_workstation_mujoco.sh --output-root outputs/holoagent0_setup
jq '{label,status,exit_class,primary_blocking_gate,qualifications}' outputs/holoagent0_setup/*/result.json
```

Document how to view MuJoCo motion, `/clock`, sensor rates, DDS graph, Stage 3 estimator metrics, Stage 4 Nav2 path, offline child lineage, and parent postflight. Explain that the qualified estimator label is not a mapping pass and that no physical motion was commissioned.

- [ ] **Step 4: Run full static and regression verification**

Run: `PYTHONPATH=nav_agent/mujoco_sim:nav_agent/sem_nav_ctr/src/holoagent_livox_converter:scripts/holoagent0_setup python3 -m pytest -q nav_agent/mujoco_sim/tests nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test scripts/holoagent0_setup/tests/test_offline_reference.py scripts/holoagent0_setup/tests/test_stage_adapter.py scripts/holoagent0_setup/tests/test_mujoco_decision.py scripts/holoagent0_setup/tests/test_mujoco_runner.py scripts/holoagent0_setup/tests/test_mujoco_result_mapping.py scripts/holoagent0_setup/tests/test_mujoco_manifest.py scripts/holoagent0_setup/tests/test_mujoco_runbook.py && git diff --check`

Expected: zero failures and no diff-check output.

- [ ] **Step 5: Commit the MuJoCo runbook**

```bash
git add nav_agent/mujoco_sim/README.md docs/holoagent0/workstation-mujoco-runbook.md scripts/holoagent0_setup/tests/test_mujoco_runbook.py
git commit -m "docs: add consolidated mujoco readiness runbook"
```

## Plan 2 completion gate

Accept `PASS_HOLOAGENT0_MUJOCO` only from a fresh parent run whose offline child reference validates, Stages 1–4 all pass, and every child and parent postflight passes. Preserve `READY_MUJOCO_STAGE4_ESTIMATOR_FAILED` only for the exact estimator predicate with independent Stage 4 success. Do not start PC2 actions as part of this plan.
