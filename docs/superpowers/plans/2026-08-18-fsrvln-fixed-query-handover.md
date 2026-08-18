# FSR-VLN Fixed-Query Handover Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a portable, observation-only Stage A handover that verifies one immutable source closure, three transferred assets under one caller-owned data root, the actual Python runtime, and the pinned pantry-counter query with a digest-bound PASS/FAIL evidence bundle.

**Architecture:** Work in the existing feature worktree after merging `main`. Keep `source_gate.py` authoritative for immutable source/data paths and content verification, keep `semantic_gate.py` authoritative for the real root-level HMSG adapter and fixed result, add a small evidence layer backed by tracked closed schemas, and expose one thin non-ROS CLI that runs those gates in a fixed order. Source and assets are read-only; only a new or explicitly empty run directory may be written.

**Tech Stack:** Python 3.10-compatible standard library, pytest, existing `holoagent0_setup` canonical/atomic JSON and contract utilities, Git plumbing, root-level FSR-VLN/HMSG, PyTorch, Open3D, OpenCLIP, OmegaConf, FAISS, OpenCV, NetworkX, PyVista, scikit-fmm, OSS2, and Segment Anything.

---

## Working Rules and Fixed Values

- Perform Tasks 1–10 in `/home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup`, not in the dirty main worktree.
- Preserve all unrelated changes in `/home/jihun/work/HoloAgent`; never clean, reset, or stage them.
- Use test-first order for every behavior change: write the failing test, run it and confirm the intended failure, implement the minimum change, rerun, then commit.
- Do not install an environment, download an asset, edit a lock to accommodate a mismatch, or use `git clone --recursive`.
- The Stage A source tree is only `repository_root/fsr_vln`; `agentic_robot/fsr_vln` is not an allowed fallback.
- Source baseline commit: `ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8`.
- Reviewed README override commit: `d862782b3661e2f2cf155d6e006f11c27063a6b0`.
- Revised source closure: 73 paths total, comprising 72 baseline entries and one reviewed README override.
- Revised path-set SHA-256: `968b39b7a16021b65e4d0adbcc33528007d42c7d4c52aee03f9c70c563ad50dc`.
- Release tag: `holoagent0-fsrvln-handover-v1`.
- Focused test command used below:

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider
```

## Task 1: Bring the Approved Design onto the Feature Lineage

**Files:**

- Verify: `docs/superpowers/specs/2026-08-18-fsrvln-portable-workstation-handover-design.md`
- Verify: `docs/superpowers/plans/2026-08-18-fsrvln-fixed-query-handover.md`
- Verify: `docs/FSR_VLN_HOLOAGENT_HANDOVER.md`

- [ ] **Step 1: Confirm the feature worktree is clean and still contains the reviewed baseline**

```bash
cd /home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup
git status --short
git merge-base --is-ancestor ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8 HEAD
```

Expected: `git status --short` prints nothing and `merge-base` exits 0. Stop if the worktree is dirty; inspect and preserve the owner’s changes before continuing.

- [ ] **Step 2: Merge main without rebasing the reviewed feature lineage**

```bash
git merge --no-ff main -m "merge: bring approved FSR-VLN handover design to feature"
```

Expected: one merge commit. Resolve only conflicts in the three handover/design files named above; do not alter unrelated code.

- [ ] **Step 3: Verify both sides of the required history are ancestors**

```bash
git merge-base --is-ancestor ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8 HEAD
git merge-base --is-ancestor 807e93c HEAD
test -f docs/superpowers/specs/2026-08-18-fsrvln-portable-workstation-handover-design.md
test -f docs/superpowers/plans/2026-08-18-fsrvln-fixed-query-handover.md
```

Expected: every command exits 0.

## Task 2: Rebase the Source Lock onto Reachable Provenance

**Files:**

- Modify: `scripts/holoagent0_setup/tests/test_source_gate.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/source_gate.py`
- Modify: `scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json`
- Modify: `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`
- Delete: `fsr_vln/checkpoints`

- [ ] **Step 1: Write the failing reachable-provenance and 73-path tests**

Change `_approved_paths()` to parse `Restore the exact 73-path` and replace the current source-lock assertions with:

```python
def test_source_lock_is_exact_sorted_approved_73_path_set():
    lock = load_source_lock(SOURCE_LOCK)
    expected = _approved_paths()

    assert lock.commit == SOURCE_COMMIT == (
        "ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8"
    )
    assert len(lock.entries) == 73
    assert "fsr_vln/checkpoints" not in {entry.path for entry in lock.entries}
    assert tuple(entry.path for entry in lock.entries) == expected
    assert lock.path_set_sha256 == (
        "968b39b7a16021b65e4d0adbcc33528007d42c7d4c52aee03f9c70c563ad50dc"
    )


def test_source_lock_matches_reachable_git_tree_without_restoring_anything():
    result = verify_manifest_git_objects(REPOSITORY_ROOT, SOURCE_LOCK)

    assert result.commit == SOURCE_COMMIT
    assert result.verified_count == 73
    assert result.provenance == (
        ("ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8", 72),
        ("d862782b3661e2f2cf155d6e006f11c27063a6b0", 1),
    )
```

Also add a test that uses `/usr/bin/git merge-base --is-ancestor` to prove both provenance commits are reachable from `HEAD`.

- [ ] **Step 2: Run the focused source test and confirm the old lock fails**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py
```

Expected: failures show the old `f164095…` commit, 74-entry count, old path-set digest, and tracked checkpoint symlink.

- [ ] **Step 3: Update the lock, constants, and superseded design section mechanically**

Apply these exact changes:

```python
SOURCE_COMMIT = "ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8"
APPROVED_PATH_COUNT = 73
APPROVED_PATH_SET_SHA256 = (
    "968b39b7a16021b65e4d0adbcc33528007d42c7d4c52aee03f9c70c563ad50dc"
)
```

In `semantic-source-manifest-v1.json`, set `commit` to `ca5ee3…`, delete only the `fsr_vln/checkpoints` entry, set the exact revised path-set digest, and leave all retained modes/blob OIDs plus the README override unchanged. In the July design, change the section to 73 paths, remove `fsr_vln/checkpoints` from the list, document 72 baseline entries plus one override, and remove the instruction to verify that host-specific symlink.

Delete the tracked link only after proving its exact target:

```bash
git ls-files --stage -- fsr_vln/checkpoints
git cat-file -p dd9ed2846596bfad50a8d2619dcaa54f68f7a32a
git rm fsr_vln/checkpoints
```

Expected before deletion: mode `120000` and target `/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/`.

- [ ] **Step 4: Verify the revised digest and retained blob identities**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py -k 'source_lock or manifest_git or worktree'
git diff --check
```

Expected: selected tests pass; 73 paths are verified; provenance is `(ca5ee3…, 72)` and `(d862782…, 1)`; no whitespace errors.

- [ ] **Step 5: Commit the source authority change**

```bash
git add scripts/holoagent0_setup/tests/test_source_gate.py \
  scripts/holoagent0_setup/holoagent0_setup/source_gate.py \
  scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json \
  docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md
git commit -m "fix: make FSR-VLN source provenance portable"
```

## Task 3: Replace Literal Asset Paths with an Immutable Two-Root Contract

**Files:**

- Modify: `scripts/holoagent0_setup/tests/test_source_gate.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/source_gate.py`

- [ ] **Step 1: Write failing derivation, alias, overlap, and identity tests**

Add tests for one valid temporary repository/data layout and for each rejection below:

```python
paths = HandoverPaths.from_roots(repository_root, data_root)
assert paths.graph == (
    data_root
    / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
)
assert paths.dataset == data_root / "fsr_vln/rgbd_datasets/icra_ic4f"
assert paths.checkpoint == (
    data_root / "fsr_vln/checkpoints/open_clip_pytorch_model.bin"
)
assert paths.asset_lock == (
    repository_root / "scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json"
)
```

The negative matrix must cover relative roots, `..` spellings, repository/data overlap in either direction, symlink aliases at every retained root or role path, missing roles, non-directory roots, a non-regular checkpoint, and inode/device replacement between construction and `revalidate()`.

Add run-directory tests covering a newly created directory, an explicitly empty existing directory, a non-empty directory, a relative path, a symlink component, and overlap with either authority root.

Replace the host-bound `test_generated_asset_lock_exactly_matches_the_three_approved_roots` with portable synthetic inventory tests plus the real CLI acceptance in Task 9. No default pytest test may depend on Jihun’s literal asset paths or silently skip because those paths are absent.

- [ ] **Step 2: Run the new path tests and confirm imports/API are absent**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py -k 'handover_paths or run_directory'
```

Expected: collection or assertion failures because `HandoverPaths` and the run-directory validator do not exist.

- [ ] **Step 3: Implement the immutable path objects and remove host literals**

Replace `APPROVED_ASSET_ROOTS` and `_validated_asset_roots()` with frozen objects shaped as follows:

```python
@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    mode: int


@dataclass(frozen=True)
class HandoverPaths:
    repository_root: Path
    data_root: Path
    graph: Path
    dataset: Path
    checkpoint: Path
    asset_lock: Path
    identities: tuple[PathIdentity, ...]

    @classmethod
    def from_roots(cls, repository_root: Path, data_root: Path) -> "HandoverPaths":
        """Derive the only accepted Stage A roles and snapshot their identities."""

    def revalidate(self) -> None:
        """Fail if any retained path, type, device, inode, or no-alias rule changed."""
```

Use `lstat`, strict resolution, `S_ISDIR`/`S_ISREG`, and explicit ancestor checks. Require `candidate == candidate.resolve(strict=True)` for both input roots and every derived retained role so an intermediate symlink cannot disguise an alias. Do not accept individual role paths, environment variables, search results, or defaults.

Add `prepare_handover_run_directory(path, paths) -> PathIdentity`. It may create one absent final directory under an existing no-symlink parent, or accept one existing empty real directory. Open it with `O_DIRECTORY | O_NOFOLLOW`, record device/inode, and reject any overlap with repository/data/asset paths.

Change the verifier APIs to:

```python
def measure_approved_asset_roots(paths: HandoverPaths) -> dict[str, AssetManifest]:
    paths.revalidate()
    return {
        "graph": canonical_asset_manifest(paths.graph),
        "dataset": canonical_asset_manifest(paths.dataset),
        "checkpoint": canonical_asset_manifest(paths.checkpoint),
    }


def verify_asset_lock(paths: HandoverPaths) -> tuple[AssetManifest, ...]:
    paths.revalidate()
    lock = load_asset_lock(paths.asset_lock)
    roots = {"graph": paths.graph, "dataset": paths.dataset, "checkpoint": paths.checkpoint}
    return tuple(verify_asset_inventory(roots[item.role], item) for item in lock.assets)
```

- [ ] **Step 4: Run all source-gate tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py
```

Expected: every source-gate unit test passes without external assets. Synthetic path/inventory coverage remains mandatory; complete multi-gigabyte remeasurement is performed by the real CLI in Task 9 rather than a host-bound pytest case.

- [ ] **Step 5: Commit the portable path authority**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/source_gate.py \
  scripts/holoagent0_setup/tests/test_source_gate.py
git commit -m "feat: derive FSR-VLN assets from two immutable roots"
```

## Task 4: Make the Real HMSG Adapter Consume the Path Contract

**Files:**

- Modify: `scripts/holoagent0_setup/tests/test_semantic_gate.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/semantic_gate.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/semantic_fixture_node.py`

- [ ] **Step 1: Write failing adapter tests for the new API and exact origin**

Replace `APPROVED_ASSET_ROOTS` usage with a constructed `HandoverPaths`. Add tests that monkeypatch the graph import and assert:

```python
adapter = load_real_hmsg_adapter(paths, run_directory)

assert imported_origin == (
    paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
)
assert configured_graph == paths.graph
assert configured_checkpoint == paths.checkpoint
assert configured_save_path == run_directory
```

Add failures for a module originating in `agentic_robot/fsr_vln`, path identity drift immediately before load, a run directory overlapping an asset, and an asset mismatch. Preserve the existing exact one-query/one-result and `1e-6` pose tests.

- [ ] **Step 2: Run the semantic subset and confirm the old signature fails**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_semantic_gate.py \
  -k 'real_hmsg or configuration or semantic_fixture'
```

Expected: failures reference the obsolete four-argument adapter and literal asset-root mapping.

- [ ] **Step 3: Refactor the real adapter without changing retrieval semantics**

Use this public signature:

```python
def load_real_hmsg_adapter(
    paths: HandoverPaths,
    run_directory: Path,
) -> RealHMSGRetrievalAdapter:
```

Call `paths.revalidate()` immediately before source/import validation and again before asset traversal. Verify `paths.asset_lock`, pass only `paths.graph` and `paths.checkpoint` into `hmsg_query_configuration`, require the graph module’s resolved origin to equal `paths.repository_root/fsr_vln/memory/hmsg/graph/graph.py`, and retain the current `Graph.load_graph`, room-name mapping, structured lookup, axis transform, and numeric tolerances.

Update the legacy ROS fixture parser to accept `--repository-root`, `--data-root`, `--run-directory`, and `--timeout-seconds`; remove `--asset-lock`, `--graph-root`, `--dataset-root`, and `--checkpoint-path`. Construct `HandoverPaths` once. This keeps the old fixture compatible without making ROS part of the new acceptance CLI.

- [ ] **Step 4: Run source and semantic suites together**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py \
  scripts/holoagent0_setup/tests/test_semantic_gate.py
```

Expected: all non-real-asset tests pass and the semantic result remains floor `0`, room `0_0 Pantry`, object `0_0_81 counter`, frame `map`, identity orientation, and the exact accepted position within `1e-6`.

- [ ] **Step 5: Commit the adapter refactor**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/semantic_gate.py \
  scripts/holoagent0_setup/holoagent0_setup/semantic_fixture_node.py \
  scripts/holoagent0_setup/tests/test_semantic_gate.py
git commit -m "refactor: bind HMSG loading to portable handover paths"
```

## Task 5: Add Five Closed Evidence Schemas

**Files:**

- Create: `scripts/holoagent0_setup/schemas/fsrvln-environment-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/fsrvln-source-verification-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/fsrvln-asset-verification-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/fsrvln-query-result-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/fsrvln-handover-result-v1.schema.json`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/contract.py`
- Modify: `scripts/holoagent0_setup/tests/test_contract.py`

- [ ] **Step 1: Write failing contract-inventory and mutation tests**

Extend `test_contract.py` to require the five schema keys and IDs:

```python
FSRVLN_SCHEMA_IDS = {
    "fsrvln-environment-v1": "holoagent0.fsrvln.environment.v1",
    "fsrvln-source-verification-v1": "holoagent0.fsrvln.source-verification.v1",
    "fsrvln-asset-verification-v1": "holoagent0.fsrvln.asset-verification.v1",
    "fsrvln-query-result-v1": "holoagent0.fsrvln.query-result.v1",
    "fsrvln-handover-result-v1": "holoagent0.fsrvln.handover-result.v1",
}
```

For one minimal valid document per schema, assert `ContractSet.validate_document(name, document).ok`. For every schema, add an unknown top-level property and assert `EVIDENCE_SCHEMA_INVALID`. Also mutate one required nested field and its type so closure is tested below the top level.

- [ ] **Step 2: Run the new contract tests and confirm the schema inventory fails**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_contract.py -k fsrvln
```

Expected: failures report unknown/missing tracked schemas.

- [ ] **Step 3: Add the schemas and register their exact IDs**

Every object, including nested objects and array items, must declare `additionalProperties: false`; every property is required, using `null` explicitly where a failed stage has no observation. Use these exact document shapes:

| File | Required payload beyond `schema_version`, `status`, `reason`, `started_at`, `finished_at` |
| --- | --- |
| environment | `os_release`, `machine_architecture`, `python` (`executable`, `version`), `accelerator` (`label`, `torch_cuda_build`, `cuda_available`), `imports[]` (`name`, `module`, `status`, `version`, `origin`, `reason`), `graph_module_origin` |
| source verification | `repository_root` path identity, `checkout_commit`, `source_lock_commit`, `verified_count`, `provenance[]` (`commit`, `count`) |
| asset verification | `data_root` path identity, `asset_lock_sha256`, `assets[]` (`role`, `path`, `device`, `inode`, `file_count`, `byte_count`, `sha256`) |
| query result | `query_sha256`, `execution_count`, `result` containing graph counts, floor/room/object identities, frame, position, orientation, and the five bound digests |
| handover result | `accepted_implementation_commit`, repository/data/run identities, `cpu_gpu_label`, `evidence_files[]` (`name`, `sha256`, `size`), `bundle_sha256`, `first_blocking_reason` |

Use `status` enum `PASS`, `FAIL`, or `NOT_RUN` in stage records and only `PASS` or `FAIL` in the terminal record. Use UTC RFC 3339 timestamps, lowercase 64-character SHA-256 strings, 40-character lowercase Git SHAs, nonnegative counts, and exactly three position/four orientation finite numbers. Require `environment.json`, `source-verification.json`, `asset-verification.json`, and `query-result.json` as the four literal `evidence_files` rows, plus a separate literal `terminal_filename: handover-result.json`. Compute `bundle_sha256` over the four ordered descriptor rows, avoiding a self-digest cycle.

Add the schema names to `_SCHEMA_FILES` and IDs to `_EXPECTED_SCHEMA_IDS`; reuse the existing limited Draft 2020-12 validator rather than adding a runtime dependency.

- [ ] **Step 4: Run the complete contract suite**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_contract.py
```

Expected: all contract tests pass, including closed schema-directory inventory checks.

- [ ] **Step 5: Commit the evidence contract**

```bash
git add scripts/holoagent0_setup/schemas/fsrvln-*-v1.schema.json \
  scripts/holoagent0_setup/holoagent0_setup/contract.py \
  scripts/holoagent0_setup/tests/test_contract.py
git commit -m "feat: define closed FSR-VLN handover evidence"
```

## Task 6: Build Runtime Qualification and Atomic Evidence Publication

**Files:**

- Create: `scripts/holoagent0_setup/holoagent0_setup/handover_evidence.py`
- Create: `scripts/holoagent0_setup/tests/test_fsrvln_handover.py`

- [ ] **Step 1: Write failing runtime inventory and evidence tests**

Define the exact required import rows in the test:

```python
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
```

Tests must prove: all rows are attempted in order; a missing import yields an explicit FAIL reason; versions may be null only when the imported module/distribution exposes none; CUDA label agrees with `torch.cuda.is_available()`; graph origin must equal the root-level file; no environment variable supplies a path; every document validates before write; writes use canonical JSON and no-replace atomic publication; the terminal record is published last; its four evidence descriptors and bundle digest match bytes on disk; and a second publication cannot overwrite a prior run.

- [ ] **Step 2: Run the new tests and confirm the module is absent**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py \
  -k 'environment or evidence'
```

Expected: import/collection failure for `holoagent0_setup.handover_evidence`.

- [ ] **Step 3: Implement qualification and document builders**

In `handover_evidence.py`, add:

```python
ENVIRONMENT_FILE = "environment.json"
SOURCE_FILE = "source-verification.json"
ASSET_FILE = "asset-verification.json"
QUERY_FILE = "query-result.json"
RESULT_FILE = "handover-result.json"
EVIDENCE_ORDER = (ENVIRONMENT_FILE, SOURCE_FILE, ASSET_FILE, QUERY_FILE)


def qualify_environment(paths: HandoverPaths) -> dict[str, object]:
    """Import the closed dependency list and prove the root-level Graph origin."""


def validate_and_publish_stage(
    contract: ContractSet,
    schema_name: str,
    run_directory: Path,
    filename: str,
    document: dict[str, object],
) -> ArtifactDescriptor:
    contract.require_valid_document(schema_name, document)
    return atomic_write_json_no_replace(
        run_directory / filename,
        document,
        relative_to=run_directory,
    )
```

Add `ContractSet.require_valid_document()` as the symmetric raising wrapper around `validate_document()`. For versions, prefer an exact module `__version__`, then reviewed `importlib.metadata.version()` distribution candidates, otherwise record null. Record `platform.platform()`, `platform.machine()`, `sys.executable`, `sys.version`, PyTorch CUDA build/availability, and CPU/GPU label.

Import the graph using the same isolated root-level insertion used by `semantic_gate.py`, return its exact resolved origin, and share that helper so the environment gate and adapter cannot disagree. Never inspect `.env` or record the entire process environment.

Implement builders for PASS/FAIL/NOT_RUN stage documents. Always attempt to publish all four stage files, using null observations for unrun stages after the first blocker, then publish the terminal file last. Compute descriptors from the canonical bytes returned by the atomic I/O layer, and compute the bundle digest from the four ordered descriptor rows.

- [ ] **Step 4: Run the evidence and contract tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_contract.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py \
  -k 'environment or evidence or fsrvln'
```

Expected: all selected tests pass and every emitted JSON file round-trips to the exact canonical bytes.

- [ ] **Step 5: Commit runtime qualification and evidence publication**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/handover_evidence.py \
  scripts/holoagent0_setup/holoagent0_setup/contract.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py
git commit -m "feat: qualify FSR-VLN runtime and publish evidence"
```

## Task 7: Add the Single Non-ROS Acceptance CLI

**Files:**

- Create: `scripts/holoagent0_setup/holoagent0_setup/fsrvln_handover.py`
- Modify: `scripts/holoagent0_setup/tests/test_fsrvln_handover.py`

- [ ] **Step 1: Write failing CLI orchestration tests**

Use injected/monkeypatched gates to assert this exact successful call order:

```python
assert calls == [
    "paths",
    "run_directory",
    "checkout_identity",
    "source_git_objects",
    "source_worktree",
    "environment",
    "asset_inventory",
    "graph_load",
    "query_once",
    "environment_evidence",
    "source_evidence",
    "asset_evidence",
    "query_evidence",
    "terminal_evidence",
]
assert query_execution_count == 1
```

Test only these public arguments: `--repository-root`, `--data-root`, and `--run-directory`. Assert relative/aliased/overlapping roots fail before semantic work; once a safe run directory has been prepared, a stage exception stops later operational gates but still produces all five evidence files with one first blocking reason; PASS exits 0; FAIL exits 1; argparse misuse exits 2; and `handover-result.json` is never PASS if a stage record is FAIL/NOT_RUN. Invalid roots or an unsafe run directory fail with no writes because no trustworthy evidence location exists yet.

In a fresh subprocess, assert importing the CLI or running `--help` does not add any module whose name starts with `rclpy`, `nav2`, the AgentOS package, or a robot-control package. The historical Graph transitively imports the OpenAI client module through `llm_utils.py`; therefore test that `create_llm_client`, `create_chat_completion`, and every natural-language parser seam are never called rather than incorrectly requiring the library to be absent from `sys.modules`.

- [ ] **Step 2: Run CLI tests and confirm the entry point is missing**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py -k cli
```

Expected: import/entry-point failures for `holoagent0_setup.fsrvln_handover`.

- [ ] **Step 3: Implement the thin fail-closed CLI**

Expose exactly:

```python
def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--run-directory", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fixed Stage A verifier and return 0 only for terminal PASS."""
```

The operational pipeline must:

1. construct/revalidate `HandoverPaths` and prepare the run directory;
2. resolve `HEAD`, verify the source-lock commit is reachable, then call `verify_manifest_git_objects` and `verify_source_worktree`;
3. qualify imports and exact Graph origin before reading assets;
4. call `verify_asset_lock(paths)` for the complete inventories;
5. call `load_real_hmsg_adapter(paths, run_directory)`;
6. call `evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)` exactly once;
7. build/validate the query result including graph counts and all bound digests; and
8. publish the five files atomically, with the terminal result last.

Catch only anticipated source/asset/semantic/contract/I/O errors at the top-level acceptance boundary. Convert the first error into a stable reason and terminal FAIL; do not repair, search, download, retry the query, switch source trees, or mask programmer exceptions. Check the fresh process module set before terminal PASS and fail if ROS, Nav2, AgentOS, or robot-control modules entered the execution path. Bind the result to the structured-query digest and record `external_llm_parser` as bypassed; never invoke an LLM client or natural-language parser.

- [ ] **Step 4: Run CLI, source, semantic, and evidence tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py \
  scripts/holoagent0_setup/tests/test_semantic_gate.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py
```

Expected: all non-real-asset tests pass; CLI tests prove one query, terminal-last publication, exit-code behavior, and forbidden-module absence.

- [ ] **Step 5: Commit the CLI**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/fsrvln_handover.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py
git commit -m "feat: add non-ROS FSR-VLN handover verifier"
```

## Task 8: Close the Test Manifest and Rewrite the Operator Handover

**Files:**

- Modify: `scripts/holoagent0_setup/tests/test_constants.py`
- Modify: `scripts/holoagent0_setup/test-manifest-v1.txt`
- Modify: `docs/FSR_VLN_HOLOAGENT_HANDOVER.md`
- Modify: `scripts/holoagent0_setup/tests/test_fsrvln_handover.py`

- [ ] **Step 1: Write the failing tracked-manifest equality test**

Add a helper that runs the reviewed `/usr/bin/git` with the existing minimal environment and compare the manifest with the exact tracked set:

```python
tracked = subprocess.run(
    [
        "/usr/bin/git",
        "ls-files",
        "--",
        "scripts/holoagent0_setup/tests/test_*.py",
    ],
    cwd=REPOSITORY_ROOT,
    env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
    capture_output=True,
    text=True,
    timeout=10,
    check=True,
).stdout.splitlines()
listed = [
    str(path.relative_to(REPOSITORY_ROOT))
    for path in manifest_test_paths(PACKAGE_ROOT / "test-manifest-v1.txt")
]
assert listed == sorted(tracked, key=os.fsencode)
```

This must fail on the currently omitted `test_offline_cli.py` and the new `test_fsrvln_handover.py`.

- [ ] **Step 2: Add a documentation command-contract test**

Require the handover’s Stage A section to contain the literal module entry point and all three allowed flags, the exact tag, source implementation SHA field, graph/dataset/checkpoint relative paths and digests, expected room/object/pose, five evidence filenames, `--no-recurse-submodules`, and explicit `NOT QUALIFIED BY THIS HANDOVER` language for Stage B. Assert it does not call either environment YAML authoritative, instruct `--recursive`, expose individual role flags, say `agentic_robot/fsr_vln` is Stage A, or retain a legacy reference to a file that does not exist.

- [ ] **Step 3: Run the tests and confirm manifest/docs failures**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_constants.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py \
  -k 'manifest or documentation'
```

Expected: the manifest equality and new runbook assertions fail.

- [ ] **Step 4: Make the manifest exact and rewrite the Stage A runbook**

Sort `test-manifest-v1.txt` bytewise and include every tracked `tests/test_*.py`, especially:

```text
scripts/holoagent0_setup/tests/test_fsrvln_handover.py
scripts/holoagent0_setup/tests/test_offline_cli.py
```

Rewrite the top of `docs/FSR_VLN_HOLOAGENT_HANDOVER.md` into this operator order:

1. signed release/source identity and no-submodule clone/detach verification;
2. exact source and three asset roles under one absolute `data_root`;
3. transfer/custody constraints and 10 GB free-space requirement, without prescribing a transfer tool;
4. teammate-owned environment qualification and dependency list;
5. the one literal CLI command;
6. expected result and five evidence files;
7. owner sign-off fields and second-copy confirmation;
8. failure interpretation; and
9. historical results plus Stage B as explicitly unqualified background.

Do not invent an incoming owner, transfer date, data root, or PASS. Before actual sign-off, label the record `UNSIGNED — acceptance not yet performed`; this is a state, not a placeholder. Preserve useful historical results only below the authoritative Stage A runbook and clearly label old `f164095…`, 74-path, ROS, and Jihun-host paths as superseded history.

Remove absent legacy file references rather than carrying them into the rewritten handover. A replacement is allowed only when the referenced file exists and is the correct authority for the surrounding statement.

- [ ] **Step 5: Run the documentation and manifest tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_constants.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py \
  -k 'manifest or documentation'
git diff --check
```

Expected: selected tests pass; manifest equals the tracked test set; no whitespace errors.

- [ ] **Step 6: Commit the closed manifest and runbook**

```bash
git add scripts/holoagent0_setup/test-manifest-v1.txt \
  scripts/holoagent0_setup/tests/test_constants.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py \
  docs/FSR_VLN_HOLOAGENT_HANDOVER.md
git commit -m "docs: publish FSR-VLN Stage A handover runbook"
```

## Task 9: Freeze the Implementation and Qualify the Real Handover

**Files:**

- Modify before the freeze if defects are found: only the files already listed in Tasks 2–8
- Verify after the freeze: every file changed in Tasks 1–8
- Do not modify after the freeze: any repository file, including the handover
- Do not commit: the external data root or run-directory evidence

- [ ] **Step 1: Run the complete tracked test manifest**

```bash
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 scripts/holoagent0_setup/tests/conftest.py \
  scripts/holoagent0_setup/test-manifest-v1.txt
```

Expected: zero failures and no deselected tracked test files. If a failure exposes a defect, add the narrowest regression test, fix it, rerun the affected file, then rerun the manifest and commit that focused fix before continuing.

- [ ] **Step 2: Freeze and capture the candidate implementation commit**

```bash
WORKTREE_STATUS="$(git status --short)"
printf '%s' "$WORKTREE_STATUS"
test -z "$WORKTREE_STATUS"
IMPLEMENTATION_SHA="$(git rev-parse HEAD)"
printf '%s\n' "$IMPLEMENTATION_SHA"
printf '%s\n' "$IMPLEMENTATION_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
git merge-base --is-ancestor ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8 "$IMPLEMENTATION_SHA"
git merge-base --is-ancestor d862782b3661e2f2cf155d6e006f11c27063a6b0 "$IMPLEMENTATION_SHA"
```

Expected: the worktree is clean, one literal 40-character candidate SHA is printed, and both provenance commits are reachable. Copy that exact printed value into the acceptance record outside the repository. Every later `IMPLEMENTATION_SHA` assignment must use that captured literal; do not recalculate it from a branch that could move.

This successful check starts the acceptance freeze. Do not edit, stage, commit, merge, or otherwise change any repository file until the clean-clone qualification, Jihun run, and incoming-owner run below have all completed against this exact SHA. If any code, lock, test, or runbook implementation defect is found, invalidate all evidence for this candidate, make and commit the focused fix, then restart Task 9 at Step 1 with a new candidate SHA and repeat every acceptance run.

- [ ] **Step 3: Have the asset custodian prepare the unified external data root**

This is an explicit owner-operation checkpoint, not an automated repository step. The custodian chooses the safe copy/resume tool, stages without destructive deletion, inspects collisions, promotes the complete copy, retains Jihun’s originals, and reports the final absolute `data_root`. For the current workstation qualification, the intended root is:

```text
/mnt/data/jihun/HoloAgent
```

Before continuing, these exact derived paths must exist as real, non-aliased entries:

```text
/mnt/data/jihun/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448
/mnt/data/jihun/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f
/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/open_clip_pytorch_model.bin
```

Do not create repository symlinks. Do not proceed if transfer permission/license confirmation or the required second-copy plan is unresolved.

- [ ] **Step 4: Qualify a clean detached clone and run Jihun’s real comparison**

Replace the quoted instruction value below with the exact literal SHA captured in Step 2 before running the block.

```bash
IMPLEMENTATION_SHA='<paste the exact 40-character SHA printed in Step 2>'
printf '%s\n' "$IMPLEMENTATION_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
CLEAN_PARENT="$(mktemp -d /tmp/fsrvln-clean-clone.XXXXXX)"
CLEAN_REPOSITORY="$CLEAN_PARENT/HoloAgent"
FSRVLN_DATA=/mnt/data/jihun/HoloAgent
FSRVLN_RUN="$(mktemp -d /tmp/fsrvln-handover-jihun.XXXXXX)"

git clone --no-recurse-submodules --no-local \
  /home/jihun/work/HoloAgent "$CLEAN_REPOSITORY"
git -C "$CLEAN_REPOSITORY" checkout --detach "$IMPLEMENTATION_SHA"
test "$(git -C "$CLEAN_REPOSITORY" rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
git -C "$CLEAN_REPOSITORY" merge-base --is-ancestor \
  ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8 HEAD
git -C "$CLEAN_REPOSITORY" submodule status

PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH="$CLEAN_REPOSITORY/scripts/holoagent0_setup" \
/usr/bin/python3.10 "$CLEAN_REPOSITORY/scripts/holoagent0_setup/tests/conftest.py" \
  "$CLEAN_REPOSITORY/scripts/holoagent0_setup/test-manifest-v1.txt"

MPLCONFIGDIR="$FSRVLN_RUN/.matplotlib" \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH="$CLEAN_REPOSITORY/scripts/holoagent0_setup" \
/home/jihun/anaconda3/envs/fsrvln/bin/python -m holoagent0_setup.fsrvln_handover \
  --repository-root "$CLEAN_REPOSITORY" \
  --data-root "$FSRVLN_DATA" \
  --run-directory "$FSRVLN_RUN"

/home/jihun/anaconda3/envs/fsrvln/bin/python - \
  "$FSRVLN_RUN" "$IMPLEMENTATION_SHA" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
implementation_sha = sys.argv[2]
names = (
    "environment.json",
    "source-verification.json",
    "asset-verification.json",
    "query-result.json",
    "handover-result.json",
)
assert tuple(path.name for path in sorted(root.glob("*.json"))) == tuple(sorted(names))
documents = {name: json.loads((root / name).read_text()) for name in names}
assert documents["source-verification.json"]["checkout_commit"] == implementation_sha
terminal = documents["handover-result.json"]
assert terminal["accepted_implementation_commit"] == implementation_sha
assert terminal["status"] == "PASS"
query = documents["query-result.json"]
assert query["execution_count"] == 1
assert query["result"]["room"] == {"id": "0_0", "name": "Pantry"}
assert query["result"]["object"] == {"id": "0_0_81", "name": "counter"}
assert query["result"]["position"] == [
    -21.526786203133774,
    -15.671372634872082,
    -0.27579107548158116,
]
print(implementation_sha)
print(terminal["bundle_sha256"])
PY

test "$(git -C "$CLEAN_REPOSITORY" rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
test -z "$(git -C "$CLEAN_REPOSITORY" status --short)"
```

Expected: the exact candidate is detached in a clean non-recursive clone, the complete manifest passes there, and the CLI exits 0 after reading all 6,590 locked asset files and the 1.71 GB checkpoint. No ROS/LLM/robot process starts. The five canonical evidence files record the exact candidate SHA, fixed query result, terminal PASS, and printed bundle digest.

- [ ] **Step 5: Repeat the real run from the exact candidate on the incoming owner’s machine**

The incoming owner must replace all five quoted instruction values below. `IMPLEMENTATION_SHA` is the exact literal captured in Step 2, not the current tip of a branch. `REPOSITORY_SOURCE` is an authorized URL, Git bundle, or repository path that already contains that exact candidate; obtaining it must not change the frozen candidate.

```bash
IMPLEMENTATION_SHA='<paste the exact 40-character SHA printed in Step 2>'
REPOSITORY_SOURCE='<authorized source containing the exact candidate>'
REPOSITORY_URL='https://github.com/caisarl76/HoloAgent.git'
PYTHON='<incoming owner qualified Python executable>'
DATA_ROOT='<incoming owner absolute transferred data root>'
printf '%s\n' "$IMPLEMENTATION_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
CLONE_PARENT="$(mktemp -d /tmp/fsrvln-owner-clone.XXXXXX)"
OWNER_REPOSITORY="$CLONE_PARENT/HoloAgent"
RUN_DIRECTORY="$(mktemp -d /tmp/fsrvln-handover-owner.XXXXXX)"

git clone --no-recurse-submodules "$REPOSITORY_SOURCE" "$OWNER_REPOSITORY"
git -C "$OWNER_REPOSITORY" checkout --detach "$IMPLEMENTATION_SHA"
test "$(git -C "$OWNER_REPOSITORY" rev-parse HEAD)" = "$IMPLEMENTATION_SHA"

MPLCONFIGDIR="$RUN_DIRECTORY/.matplotlib" \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH="$OWNER_REPOSITORY/scripts/holoagent0_setup" \
"$PYTHON" -m holoagent0_setup.fsrvln_handover \
  --repository-root "$OWNER_REPOSITORY" \
  --data-root "$DATA_ROOT" \
  --run-directory "$RUN_DIRECTORY"

"$PYTHON" - "$RUN_DIRECTORY" "$IMPLEMENTATION_SHA" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
implementation_sha = sys.argv[2]
source = json.loads((root / "source-verification.json").read_text())
terminal = json.loads((root / "handover-result.json").read_text())
assert source["checkout_commit"] == implementation_sha
assert terminal["accepted_implementation_commit"] == implementation_sha
assert terminal["status"] == "PASS"
print(implementation_sha)
print(terminal["bundle_sha256"])
PY

test "$(git -C "$OWNER_REPOSITORY" rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
test -z "$(git -C "$OWNER_REPOSITORY" status --short)"
```

Acceptance requires this second exit-0 bundle to record the exact candidate SHA and to match the lock’s graph, dataset, checkpoint, structured-query, and room-mapping digests. Preserve outside the repository the actual incoming owner, transfer/acceptance dates, repository URL, exact data root, environment summary, graph-module origin, evidence-bundle location/digest, PASS state, and second-copy confirmation.

If the incoming-owner run is unavailable, stop here. The manifest, clean-clone qualification, and Jihun comparison do not authorize a signed release on the teammate’s behalf.

- [ ] **Step 6: Confirm the frozen candidate and acceptance gate**

Return to the feature worktree and replace the quoted instruction value with the same Step 2 literal:

```bash
cd /home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup
IMPLEMENTATION_SHA='<paste the exact 40-character SHA printed in Step 2>'
printf '%s\n' "$IMPLEMENTATION_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
test "$(git rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
test -z "$(git status --short)"
```

Expected: the feature worktree is still clean at the frozen candidate. Independently compare the clean-clone, Jihun, and incoming-owner evidence with the captured SHA and lock. Do not edit the handover until the complete manifest, clean-clone qualification, Jihun real run, and incoming-owner real run are all PASS for this same candidate.

## Task 10: Record Acceptance and Publish the Immutable Release

**Files:**

- Modify once: `docs/FSR_VLN_HOLOAGENT_HANDOVER.md`
- Verify: every file changed in Tasks 1–9

- [ ] **Step 1: Add the factual sign-off after the acceptance gate**

Return to the clean feature worktree and replace the quoted instruction value with the exact Task 9 candidate:

```bash
cd /home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup
IMPLEMENTATION_SHA='<paste the accepted 40-character SHA from Task 9>'
printf '%s\n' "$IMPLEMENTATION_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
test "$(git rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
test -z "$(git status --short)"
```

Only after that check and all four Task 9 gates pass, edit `docs/FSR_VLN_HOLOAGENT_HANDOVER.md` once. Replace `UNSIGNED — acceptance not yet performed` with the factual sign-off, write the accepted implementation commit as the literal `IMPLEMENTATION_SHA`, and record the clean-clone facts plus both real evidence-bundle digests and custody confirmation. Do not include assets, evidence bundles, credentials, environment dumps, or placeholders.

This release edit may change factual sign-off and verification metadata only. A code, lock, test, command, or instructional runbook correction is an implementation change: abandon the candidate, make a new implementation commit, and repeat all of Task 9 before creating any release commit.

- [ ] **Step 2: Create the single documentation-only release commit**

Replace the quoted instruction value with the same literal used in Step 1:

```bash
IMPLEMENTATION_SHA='<paste the accepted 40-character SHA from Task 9>'
test "$(git rev-parse HEAD)" = "$IMPLEMENTATION_SHA"
git add docs/FSR_VLN_HOLOAGENT_HANDOVER.md
test "$(git diff --cached --name-only)" = 'docs/FSR_VLN_HOLOAGENT_HANDOVER.md'
test "$(git status --short)" = 'M  docs/FSR_VLN_HOLOAGENT_HANDOVER.md'
git diff --cached --check
git diff --cached -- docs/FSR_VLN_HOLOAGENT_HANDOVER.md
git commit -m "docs: bind FSR-VLN handover release identity"
DOCS_RELEASE_SHA="$(git rev-parse HEAD)"
test "$(git rev-parse HEAD^)" = "$IMPLEMENTATION_SHA"
git merge-base --is-ancestor "$IMPLEMENTATION_SHA" "$DOCS_RELEASE_SHA"
test -z "$(git status --short)"
```

Expected: exactly one documentation-only commit contains the factual sign-off and literal accepted implementation SHA. The docs release commit is the tag target, but it is not the reproduction identity; its direct parent, `IMPLEMENTATION_SHA`, remains the accepted implementation commit.

- [ ] **Step 3: Create and locally verify the annotated tag**

```bash
git show-ref --verify --quiet refs/tags/holoagent0-fsrvln-handover-v1
```

Expected before creation: exit 1. If it exists, stop and inspect; do not move or overwrite a published tag.

```bash
DOCUMENTED_SHA="$(sed -n 's/^Accepted implementation commit: `\([0-9a-f]\{40\}\)`$/\1/p' docs/FSR_VLN_HOLOAGENT_HANDOVER.md)"
DOCS_RELEASE_SHA="$(git rev-parse HEAD)"
test "$DOCUMENTED_SHA" = "$(git rev-parse HEAD^)"
git tag -a holoagent0-fsrvln-handover-v1 \
  -m "FSR-VLN fixed-query workstation handover v1"
test "$(git rev-parse holoagent0-fsrvln-handover-v1^{commit})" = "$DOCS_RELEASE_SHA"
git merge-base --is-ancestor "$DOCUMENTED_SHA" \
  holoagent0-fsrvln-handover-v1^{commit}
git show holoagent0-fsrvln-handover-v1 --no-patch --decorate=full
```

Expected: the annotated tag points to the single docs-only release commit, and the documented implementation SHA is that commit’s direct parent and ancestor.

- [ ] **Step 4: Test discovery by tag and detachment at the documented SHA**

```bash
TAG_PARENT="$(mktemp -d /tmp/fsrvln-tag-clone.XXXXXX)"
git clone --no-recurse-submodules --branch holoagent0-fsrvln-handover-v1 \
  --single-branch \
  /home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup \
  "$TAG_PARENT/HoloAgent"
cd "$TAG_PARENT/HoloAgent"
DOCUMENTED_SHA="$(sed -n 's/^Accepted implementation commit: `\([0-9a-f]\{40\}\)`$/\1/p' docs/FSR_VLN_HOLOAGENT_HANDOVER.md)"
printf '%s\n' "$DOCUMENTED_SHA" | /usr/bin/grep -Eq '^[0-9a-f]{40}$'
git merge-base --is-ancestor "$DOCUMENTED_SHA" HEAD
git checkout --detach "$DOCUMENTED_SHA"
test "$(git rev-parse HEAD)" = "$DOCUMENTED_SHA"
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py \
  scripts/holoagent0_setup/tests/test_semantic_gate.py \
  scripts/holoagent0_setup/tests/test_fsrvln_handover.py
```

Expected: the implementation SHA is discoverable from the tag and is the exact detached reproduction identity; focused tests pass there.

- [ ] **Step 5: Obtain explicit approval before external publication**

Present the implementation SHA, docs release SHA, annotated tag target, full test-manifest result, clean-clone result, Jihun comparison evidence digest, incoming-owner acceptance evidence digest, and `git status --short`. Ask the repository owner to approve pushing the feature/release commits and the new tag. Do not push without that approval.

After approval, use the already configured repository remote and push the reviewed branch followed by the single tag. Never force-push and never use `--tags`:

```bash
git push origin feat/holoagent0-workstation-pc2-setup
git push origin refs/tags/holoagent0-fsrvln-handover-v1
```

Expected: `origin` has first been reconfirmed as `https://github.com/caisarl76/HoloAgent.git`; both pushes succeed without rewriting any remote ref.

## Final Verification Checklist

- [ ] `git status --short` is clean in the feature worktree.
- [ ] The complete tracked test manifest reports zero failures, including `test_offline_cli.py` and `test_fsrvln_handover.py`.
- [ ] The exact 73-path source closure verifies from reachable Git objects in a clean clone.
- [ ] No tracked `fsr_vln/checkpoints` host symlink remains.
- [ ] Correct assets pass under the incoming owner’s non-Jihun absolute data root; aliases, overlaps, missing/extra/changed content, and role substitution fail.
- [ ] The exact root-level HMSG Graph module is recorded and `agentic_robot/fsr_vln` is not imported for Stage A.
- [ ] The fixed query executes once and returns one floor, three rooms, 497 objects, `0_0 Pantry`, `0_0_81 counter`, frame `map`, identity orientation, and the accepted position within `1e-6` per coordinate.
- [ ] No ROS, Nav2, AgentOS, external LLM call/parser, or robot-control process participates; the transitive but unused OpenAI import is recorded as a historical Graph limitation.
- [ ] All five evidence files are canonical, schema-valid, digest-bound, and terminal PASS is written last.
- [ ] The clean clone and both real acceptance bundles record the same frozen implementation SHA before the factual handover release edit.
- [ ] The handover records factual owners, dates, paths, environment, module origin, implementation SHA, evidence digest, PASS, and second-copy custody confirmation with no placeholders.
- [ ] The annotated tag is only a discovery pointer; the documented 40-character implementation commit is reachable and is the detached reproduction identity.
- [ ] Stage B graph rebuilding, maintained `agentic_robot/fsr_vln`, public artifact equivalence, Nav2 alignment, and robot execution remain explicitly unqualified.
