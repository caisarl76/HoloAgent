# FSR-VLN and HoloAgent Handover

**Status date:** 2026-08-14
**Outgoing owner:** Jihun
**Incoming owner:** TBD
**Scope:** FSR-VLN semantic mapping/retrieval and its HoloAgent/NavAgent integration

## Executive Summary

FSR-VLN is usable in this workspace as a precomputed HMSG semantic retriever.
The strongest completed evidence is an observation-only query against the real
`icra_ic4f` graph:

```text
Query:    Take me to the counter in the pantry
Floor:    0
Room:     0_0 Pantry
Object:   0_0_81 counter
Frame:    map
Position: (-21.526786203133774,
           -15.671372634872082,
           -0.27579107548158116)
```

This result exercises the real HMSG room/object retrieval and scene-graph to
`map` coordinate transform. The external natural-language parser is bypassed
in the deterministic offline fixture. It does **not** prove paper-level VLN
accuracy, Nav2 goal completion, map alignment, or physical robot behavior.

The workspace also contains earlier multi-query results covering four scenes.
Those outputs prove that queries completed and returned objects, but they do
not contain ground-truth correctness, trajectory, SPL, or navigation-success
metrics.

## Current Readiness

| Capability | Status | Evidence boundary |
| --- | --- | --- |
| Tracked FSR-VLN source and Python API | Available | `agentic_robot/fsr_vln/` |
| Precomputed HMSG semantic retrieval | Reproduced | Four local scenes and fixed Stage 0 query |
| Exact `icra_ic4f` source/asset lock | Implemented | 74 source paths; graph, dataset, and checkpoint manifests |
| Static and interactive visualization | Available | PNG and PLY per retrieved candidate |
| Deterministic external-language parsing | Not complete | Offline fixture bypasses the networked parser |
| Raw RGB-D to repeatable HMSG rebuild | Not proven | Mapping code and local graph artifacts exist |
| Paper quantitative result reproduction | Not proven | No ground-truth or trajectory metrics in result files |
| Full `workstation_offline` acceptance | Not complete | Task 13 runner and Task 14 runbook are not present |
| FSR-VLN pose sent through aligned Nav2 map | Not proven | Real HMSG and simulation map are deliberately separated |
| Physical G1 reproduction | Not attempted by this evidence | Stage 0 had motion and Nav2 disabled |

## What the Reproduced Result Contains

### 1. Batch query summary

`fsr_vln/outputs/holoagent_repro_summary.json` is the compact authoritative
summary of the retained query outputs. It contains:

- 84 primary `auto_region_slow_reasoning` queries across:
  - `icra_ic3f`: 22 queries;
  - `icra_ic4f`: 15 queries;
  - `icra_ic7f`: 24 queries;
  - `icra_sh3f`: 23 queries.
- Weighted latency averages for total time, fast matching, object checking,
  VLM rethinking, and LLM parsing.
- Two additional `icra_ic4f` comparison modes:
  - 15 `auto_region_fast_match` queries;
  - 15 `human_assign_slow_reasoning` queries.
- Warnings that:
  - directories ending in `slow_reasonin` are typo runs and must be ignored;
  - the fast-match code path produced valid rows but zero aggregate timing
    fields;
  - these artifacts cover FSR-VLN/NavAgent setup, not full AgentOS behavior.

The six non-typo runs contain 114 query rows. Every retained row has at least
one returned room and object. This is an execution-completeness observation,
not a correctness score.

### 2. Per-run `all_results.json`

Each mode directory contains `all_results.json`. Its top-level fields are:

```text
average_total_time
average_objectIncheck_time
average_vlm_rethinking_time
average_re_matching_time
average_fastmatching_time
average_llm_parse_time
results
```

Each `results` row contains:

```text
query
time_seconds
floor_id
rooms[]  -> room_id, name
objects[] -> object_id
```

The file records what was returned and how long it took. It does not record
whether the returned object is ground-truth correct.

### 3. Visual result bundle

`fsr_vln/outputs/fsrvln_eval_visual_report.html` is a static gallery. The
machine-readable source is
`fsr_vln/outputs/fsrvln_eval_visual_summary.json`.

For each query, its result directory can contain:

- `scene_0.png` through `scene_4.png`: static views of the top five candidates;
- `scene_0.ply` through `scene_4.ply`: interactive point clouds;
- `query_time_consumer.json`: per-stage timing;
- optional VLM comparison/refinement images.

`scene_0` is the top-ranked candidate, not camera view zero. For the verified
counter query, `scene_0` corresponds to object `0_0_81`. The red sphere marks
the retrieved object center in HMSG scene-graph coordinates. The result JSON
contains the separately transformed `map` coordinate.

The retained visualization is **not** an overlay on the Nav2 occupancy map.
Do not place this pose on a different map until an explicit frame-alignment
transform has been measured and validated.

### 4. Reproduction archive

`fsr_vln/outputs/fsr_vln_repro_results.tar.gz` is approximately 1 GB and
contains 926 result entries. It packages the four canonical slow-reasoning
output trees and their compact summary. It does not contain source code,
datasets, or model checkpoints, so it is an output archive rather than a
self-contained reproduction package.

### 5. Stage 0 semantic recovery evidence

`outputs/mujoco_holoagent/20260722T084234Z/` is the durable evidence directory
for the observation-only ROS query. Important files are:

- `result.json`: authoritative PASS result and qualification;
- `query-flow.log`: query publication and captured `/object_pose`;
- `object-pose.yaml`: captured pose;
- `blob-verification.tsv`: source verification;
- `final-verification.txt`: source, checkpoint, process, and no-motion checks;
- `graph-before-query.txt` and `graph-after-query.txt`: ROS graph observations;
- `goal-publisher.log`: full semantic-node runtime log.

The result is `PASS_SEMANTIC_RECOVERY`. It records:

- source commit `f164095abb0045a69c0b8eb23683063be3deaa38`;
- 74 manifest entries and zero blob mismatches;
- one floor, three rooms, and 497 objects in the selected graph;
- `ROS_DOMAIN_ID=77` and localhost-only DDS;
- `motion_enabled=false` and `nav2_started=false`;
- a finite `map`-frame pose for the fixed query.

It also records a crucial limitation: the ICRA parser called the configured
chat-completion API even when `NAV_AGENT_USE_GPT=0`. That flag disables
slow-reasoning retrieval, not language parsing.

### 6. New pinned offline fixture

The feature worktree
`.worktrees/holoagent0-workstation-pc2-setup` contains the newer deterministic
fixture implementation:

```text
scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json
scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json
scripts/holoagent0_setup/holoagent0_setup/source_gate.py
scripts/holoagent0_setup/holoagent0_setup/semantic_gate.py
scripts/holoagent0_setup/holoagent0_setup/semantic_fixture_node.py
```

The lock pins:

| Asset | Count/size | SHA-256 |
| --- | --- | --- |
| `icra_ic4f/graph_20260629211448` | 1,229 files | `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050` |
| `rgbd_datasets/icra_ic4f` | 5,360 files | `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913` |
| `open_clip_pytorch_model.bin` | 1,710,631,365 bytes | `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b` |

The focused source/semantic tests passed on 2026-08-14: 50 passed. A direct
real-graph rerun also selected room `0_0`, object `0_0_81`, and the exact pinned
pose. The full offline CLI and authoritative `PASS_HOLOAGENT0_OFFLINE` result
are still pending.

## Module Boundaries

### FSR-VLN mapping path

```text
G1 RGB-D sequence
  -> OVO semantic instance mapping
  -> floor/room/object/view segmentation
  -> HMSG graph
  -> semantic retrieval and visualization
```

The maintained tracked implementation is under `agentic_robot/fsr_vln/`.
Its primary mapping entrypoint is `run_holoagent_mapping.py`; the reusable
retrieval interface is `api.py::FsrVlnClient`.

### HoloAgent navigation path

```text
structured semantic command on /chat_loc_pub
  -> semantic_goal_node
  -> FsrVlnClient / HMSG lookup
  -> geometry_msgs/PoseStamped on /object_pose
  -> nav_executor_node
  -> Nav2 only after map/frame and safety validation
```

The tracked implementation is under
`agentic_robot/core/src/navigation/semantic_goal/`. Its current ROS input is a
comma-separated `floor, room, object` string; it is not an unrestricted
natural-language interface.

### Legacy recovered NavAgent path

The untracked `nav_agent/` tree contains the older integration used by Stage 0.
It loads `fsr_vln/memory/hmsg/graph/Graph` directly, accepts text on
`/chat_loc_pub`, and publishes `/object_pose`. This path may invoke an external
LLM parser.

There are therefore two integration paths. The incoming owner should not make
changes in both without first deciding which path is authoritative.

## Workspace and Asset Warnings

1. `fsr_vln/`, `nav_agent/`, and `outputs/` are untracked local trees on main.
   A clean clone does not reproduce the demonstrated workspace.
2. `fsr_vln/checkpoints` and `fsr_vln/rgbd_datasets` are symlinks into
   `/mnt/data/jihun/HoloAgent/fsr_vln/`.
3. The asset verifier intentionally requires the literal approved roots:
   - graph under `/home/jihun/work/HoloAgent/fsr_vln/...`;
   - dataset and checkpoint under `/mnt/data/jihun/HoloAgent/fsr_vln/...`.
   Passing the workspace symlink spellings fails closed.
4. The main worktree contains unrelated modifications and generated build
   trees. Preserve them and do not use destructive Git cleanup commands.
5. `.env` is untracked and may contain credentials. Never include it in logs,
   archives, commits, or handover messages.
6. The `fsrvln` Conda environment currently reports CUDA unavailable and falls
   back to CPU. Loading and querying the 1.71 GB CLIP checkpoint can take time.
7. The public Docker tag documented by NavAgent is `latest`, and no relevant
   local container/image was present during the 2026-08-14 audit. Pin an image
   digest before treating Docker setup as reproducible.

## Safe Verification Commands

### Open the visual report

```bash
xdg-open /home/jihun/work/HoloAgent/fsr_vln/outputs/fsrvln_eval_visual_report.html
```

### Open the verified counter render

```bash
xdg-open "/home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/fsrvln_result_online_auto_region_slow_reasoning/Take me to the counter in the pantry/scene_0.png"
```

### Open the verified result interactively

```bash
cd "/home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/fsrvln_result_online_auto_region_slow_reasoning/Take me to the counter in the pantry"

/home/jihun/anaconda3/envs/fsrvln/bin/python -c \
"import open3d as o3d; p=o3d.io.read_point_cloud('scene_0.ply'); o3d.visualization.draw_geometries([p], window_name='FSR-VLN: counter in pantry')"
```

### Re-run source and semantic contract tests

```bash
cd /home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup

PYTHONDONTWRITEBYTECODE=1 \
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
PYTHONPATH=scripts/holoagent0_setup \
/usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_source_gate.py \
  scripts/holoagent0_setup/tests/test_semantic_gate.py
```

Expected: 50 tests pass. This includes full asset-manifest remeasurement and
may read several gigabytes.

### Re-run the deterministic real-graph query

```bash
mkdir -p /tmp/fsrvln-fixture-run /tmp/fsrvln-matplotlib

MPLCONFIGDIR=/tmp/fsrvln-matplotlib \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH="/home/jihun/work/HoloAgent/.worktrees/holoagent0-workstation-pc2-setup/scripts/holoagent0_setup" \
/home/jihun/anaconda3/envs/fsrvln/bin/python - <<'PY'
import json
from pathlib import Path

from holoagent0_setup.semantic_gate import (
    EXPECTED_SEMANTIC,
    evaluate_semantic_fixture,
    load_real_hmsg_adapter,
)
from holoagent0_setup.source_gate import APPROVED_ASSET_ROOTS

repo = Path("/home/jihun/work/HoloAgent")
setup = repo / ".worktrees/holoagent0-workstation-pc2-setup/scripts/holoagent0_setup"

adapter = load_real_hmsg_adapter(
    repository_root=repo,
    asset_source=setup / "locks/icra_ic4f-assets-v1.json",
    asset_roots=APPROVED_ASSET_ROOTS,
    run_directory=Path("/tmp/fsrvln-fixture-run"),
)
result = evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)
print(json.dumps(result.to_document(), indent=2))
PY
```

This command is read-only with respect to source/assets and writes only under
`/tmp`. It does not initialize ROS, Nav2, AgentOS, or robot control.

## Known Limitations and Risks

- **No accuracy claim:** nonempty top-k outputs do not establish correct
  retrieval.
- **No paper reproduction claim:** the retained results lack benchmark ground
  truth and paper-table comparison.
- **Parser dependence:** historical free-text runs depend on an external
  chat-completion service; provider/model behavior can change.
- **Fixture scope:** the deterministic fixture begins after parsing with fixed
  room/object fields.
- **Code divergence:** tracked `agentic_robot/fsr_vln/` and untracked
  `fsr_vln/` are not identical.
- **Map alignment:** the HMSG `map` frame must not be assumed identical to a
  Nav2 or MuJoCo map with the same frame name.
- **No robot evidence:** do not interpret static query evidence as authority to
  start `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node`.
- **Incomplete offline integration:** absence of the Task 13 runner means no
  current end-to-end offline gate order, evidence bundle, or final pass label.

## Decisions to Preserve

1. Keep the real `icra_ic4f` query observation-only until map alignment is
   independently validated.
2. Keep natural-language parsing separate from deterministic HMSG retrieval.
3. Preserve exact source and asset digests; never regenerate and automatically
   bless a changed lock.
4. Treat `scene_0` as the top-ranked candidate and `scene_1..4` as alternative
   candidates, not multiple views of one object.
5. Keep all robot-motion flags disabled during workstation and semantic tests.

## Recommended Continuation Plan

- [ ] **P0 — Incoming owner, due TBD:** Decide and document the authoritative
  FSR-VLN implementation: tracked `agentic_robot/fsr_vln/` or recovered
  `fsr_vln/`. Define a migration plan for the other tree.
- [ ] **P0 — Incoming owner, due TBD:** Finish Task 13 offline CLI integration
  and Task 14 runtime acceptance; produce the first schema-valid authoritative
  `PASS_HOLOAGENT0_OFFLINE` or explicit failure artifact.
- [ ] **P0 — Incoming owner, due TBD:** Make the exact source closure and asset
  acquisition reproducible from a clean clone without relying on undocumented
  untracked workspace state.
- [ ] **P1 — Incoming owner, due TBD:** Add ground-truth annotations and
  correctness metrics for retained queries. Report retrieval accuracy separately
  from latency.
- [ ] **P1 — Incoming owner, due TBD:** Pin the LLM provider, model, request
  schema, and cached parser fixtures, or provide a deterministic local parser.
- [ ] **P1 — Incoming owner, due TBD:** Validate a transform between the HMSG
  graph and the intended Nav2 map before creating an overlay or forwarding
  `/object_pose` to Nav2.
- [ ] **P2 — Incoming owner, due TBD:** Rebuild at least one HMSG from raw RGB-D
  using the tracked OVO mapping path and compare graph structure and retrieval
  quality against the pinned graph.
- [ ] **P2 — Incoming owner, due TBD:** Pin the Docker image by immutable digest
  and document an offline dependency/cache strategy.

## Open Questions

1. Which code tree should own production retrieval after the feature branch is
   merged?
2. What ground truth defines a correct target: object instance, semantic class,
   navigable approach point, or successful robot arrival?
3. Is the intended next milestone semantic retrieval evaluation, simulator
   navigation, or real-building map alignment?
4. Which parser/provider is allowed for reproducible online slow reasoning?
5. Where will the large datasets/checkpoints be distributed and versioned for
   the incoming teammate?

## Primary References

- `README.md`
- `agentic_robot/fsr_vln/README.md`
- `agentic_robot/fsr_vln/api.py`
- `agentic_robot/core/src/navigation/README.md`
- `nav_agent/DEPLOY_UNITREE_G1.md`
- `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`
- `docs/superpowers/plans/2026-07-22-holoagent-stage0-recovery.md`
- `.worktrees/holoagent0-workstation-pc2-setup/docs/superpowers/specs/2026-07-29-holoagent0-workstation-pc2-setup-design.md`
- `.worktrees/holoagent0-workstation-pc2-setup/docs/superpowers/plans/2026-08-05-holoagent0-workstation-offline.md`
