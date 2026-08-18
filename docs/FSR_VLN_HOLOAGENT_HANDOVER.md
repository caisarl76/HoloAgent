# FSR-VLN Stage A Handover

This is the operator contract for transferring and qualifying the fixed-query
FSR-VLN Stage A runtime on another workstation. It qualifies one detached
source revision, three content-locked assets, one teammate-managed Python
environment, and one observation-only query. It does not install software,
choose a transfer tool, call an external LLM, start ROS, or authorize motion.

Acceptance state: **UNSIGNED — acceptance not yet performed**

## 1. Release and Source Identity

- Repository: `https://github.com/caisarl76/HoloAgent.git`
- Release tag: `holoagent0-fsrvln-handover-v1`
- Stage A source authority: `repository_root/fsr_vln`
- Required graph-module origin:
  `repository_root/fsr_vln/memory/hmsg/graph/graph.py`
- Source lock:
  `scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json`

Accepted implementation commit: UNSIGNED — acceptance not yet performed

The accepted identity is the full 40-character implementation commit recorded
above after owner acceptance. A branch or tag name alone is not sufficient.
Until this record is signed with that commit, the commands below describe the
acceptance procedure but do not assert a completed acceptance.

Clone without submodules, fetch the release tag without recursing into
submodules, inspect the annotated tag, verify the recorded implementation
commit is an ancestor of the release, then detach at that exact commit:

```bash
REPOSITORY_URL='https://github.com/caisarl76/HoloAgent.git'
REPOSITORY_ROOT='<replace with an absolute checkout path>'
ACCEPTED_IMPLEMENTATION_COMMIT='<replace with the signed 40-character commit>'
git clone --no-recurse-submodules "$REPOSITORY_URL" "$REPOSITORY_ROOT"
git -C "$REPOSITORY_ROOT" fetch --no-recurse-submodules origin tag holoagent0-fsrvln-handover-v1
git -C "$REPOSITORY_ROOT" show --no-patch holoagent0-fsrvln-handover-v1
git -C "$REPOSITORY_ROOT" merge-base --is-ancestor "$ACCEPTED_IMPLEMENTATION_COMMIT" holoagent0-fsrvln-handover-v1
git -C "$REPOSITORY_ROOT" checkout --detach "$ACCEPTED_IMPLEMENTATION_COMMIT"
test "$(git -C "$REPOSITORY_ROOT" rev-parse --verify HEAD)" = "$ACCEPTED_IMPLEMENTATION_COMMIT"
```

The final `rev-parse` value must equal the accepted implementation commit
byte-for-byte. Do not continue from a branch tip, a different tag target, or a
clone made with submodule recursion.

## 2. Roots and Locked Assets

Choose one absolute, normalized, teammate-controlled `data_root` outside the
repository. Do not put either root inside the other and do not use a symlink
alias. The CLI accepts only `repository_root` and `data_root`; it derives every
asset role internally.

| Role | Path | Locked size | Canonical SHA-256 |
| --- | --- | ---: | --- |
| Source | `repository_root/fsr_vln` | 73 reviewed paths | source manifest above |
| Graph | `data_root/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448` | 1,229 files; 150,066,065 bytes | `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050` |
| Dataset | `data_root/fsr_vln/rgbd_datasets/icra_ic4f` | 5,360 files; 2,391,476,669 bytes | `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913` |
| Checkpoint | `data_root/fsr_vln/checkpoints/open_clip_pytorch_model.bin` | 1 file; 1,710,631,365 bytes | `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b` |

The complete per-file asset lock at
`scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json` is authoritative;
aggregate counts and root digests are only summaries.

## 3. Transfer and Custody

The custodian chooses and operates a reviewed transfer method; this handover
does not prescribe a transfer tool. The known outgoing sources are:

```text
graph:      jihun@jihun-Z590-AORUS-ELITE:/home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448
dataset:    jihun@jihun-Z590-AORUS-ELITE:/mnt/data/jihun/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f
checkpoint: jihun@jihun-Z590-AORUS-ELITE:/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/open_clip_pytorch_model.bin
```

Before transfer, both owners must confirm that internal transfer is permitted
by the applicable source, dataset, and checkpoint licenses. Reserve at least 10 GB
of free space for the assets and staging, excluding the Python environment and
optional visualizations.

Transfer into a new sibling staging location. Do not use destructive deletion
against the source or an existing destination. Inspect destination collisions
before copying, use only a verified resume mode after interruption, and promote
the completed staging copy on the same filesystem when atomic rename is
available. Run the verifier against the final paths. Keep Jihun's originals
unchanged until PASS and custody sign-off, and retain a second verified asset
copy before repurposing the outgoing workstation or its data disk. Never
transfer credentials, `.env`, unrelated logs, build trees, or generated output.

## 4. Teammate-Owned Environment Qualification

The incoming owner chooses the environment manager and installation procedure.
Neither environment YAML is an acceptance authority:
`fsr_vln/environment.yaml` and `agentic_robot/fsr_vln/environment.yaml` are
historical inputs only. Environment acceptance comes from observed imports,
origins, versions, asset verification, and the fixed-query result.

Before loading assets, the verifier attempts and records every required import:

| Distribution | Import module |
| --- | --- |
| PyTorch | `torch` |
| Open3D | `open3d` |
| OpenCLIP | `open_clip` |
| NumPy | `numpy` |
| OmegaConf | `omegaconf` |
| FAISS | `faiss` |
| OpenCV | `cv2` |
| NetworkX | `networkx` |
| PyVista | `pyvista` |
| scikit-fmm | `skfmm` |
| OSS2 | `oss2` |
| Segment Anything | `segment_anything` |

It also records the OS, architecture, Python executable and version, PyTorch
version, CUDA build and availability, CPU/GPU label, and exact root-level HMSG
module origin. Missing or mis-originated dependencies fail qualification. No API
token, `.env`, OSS credential, chat-completion credential, ROS installation, or
robot SDK is required.

## 5. Run the One Acceptance Command

Choose a new absolute `run_directory` outside both roots. It must not exist, or
must be an explicitly empty owner-controlled directory. From the detached
checkout, run exactly this CLI with its three accepted flags:

```bash
REPOSITORY_ROOT='<replace with the absolute detached checkout path>'
DATA_ROOT='<replace with the absolute transferred data root>'
RUN_DIRECTORY='<replace with a new absolute evidence directory>'
PYTHONPATH="$REPOSITORY_ROOT/scripts/holoagent0_setup" \
python -m holoagent0_setup.fsrvln_handover \
  --repository-root "$REPOSITORY_ROOT" \
  --data-root "$DATA_ROOT" \
  --run-directory "$RUN_DIRECTORY"
```

Do not add separate asset-role arguments or environment-variable fallbacks. The
verifier checks the checkout and source lock, qualifies the environment,
verifies the full asset inventory, loads the real root-level HMSG graph, and
executes `Take me to the counter in the pantry` exactly once without a network
parser.

## 6. Expected Outcome and Evidence

The accepted observation is:

- Graph counts: 1 floor, 3 rooms, 497 objects
- Floor: `0`
- Room: `0_0` (`Pantry`)
- Object: `0_0_81` (`counter`)
- Frame: `map`
- Position:
  `(-21.526786203133774, -15.671372634872082, -0.27579107548158116)`
- Position absolute tolerance: `1e-6` per coordinate
- Orientation: `(0.0, 0.0, 0.0, 1.0)`

The structured-query, graph, dataset, checkpoint, and room-name-mapping digests
must match the reviewed locks. A qualifying run exits zero only after atomically
publishing these five closed-schema canonical JSON files, with the terminal file
published last:

1. `environment.json`
2. `source-verification.json`
3. `asset-verification.json`
4. `query-result.json`
5. `handover-result.json`

Optional PNG or PLY visualization is not acceptance evidence and is not a Nav2
occupancy-map overlay.

## 7. Owner Sign-Off Record

Record facts only after both real acceptance runs complete. Do not fill this
section with an assumed owner, date, path, digest, result, or environment.

- Sign-off state: **UNSIGNED — acceptance not yet performed**
- Outgoing owner: Jihun
- Incoming owner: not recorded — acceptance not yet performed
- Transfer date: not recorded — acceptance not yet performed
- Acceptance date: not recorded — acceptance not yet performed
- Accepted absolute `data_root`: not recorded — acceptance not yet performed
- Environment summary and graph-module origin: not recorded — acceptance not yet performed
- Evidence-bundle location and digest: not recorded — acceptance not yet performed
- Final acceptance result: not recorded — acceptance not yet performed
- Second verified asset copy: not recorded — acceptance not yet performed

The accepted implementation commit remains the unsigned state at the top until
the acceptance record is factual. The second-copy confirmation must identify a
verified copy independent of the outgoing workstation slated for repurposing.

## 8. Failure Interpretation

- Exit `0` means all stages and the terminal evidence policy passed. It is not a
  paper-level accuracy, navigation, mapping, or robot qualification.
- Exit `1` means an anticipated source, dependency, asset, graph, query, or
  evidence failure after the safe run directory was established. Inspect the
  first blocking reason and all five evidence files; diagnostic files are not
  acceptance.
- Exit `2` means command syntax or root/run-directory validation failed before
  a safe evidence directory existed. Correct the invocation or ownership/path
  condition; do not weaken a lock.
- The verifier never repairs, searches for, downloads, or substitutes content.
  A failed transfer does not authorize editing the lock, and a failed import
  does not authorize changing the Stage A source tree.

## 9. Stage B Boundary

Raw RGB-D to OVO to HMSG rebuilding, free-text parsing, Nav2 frame alignment,
MuJoCo, PC2, and physical-robot execution are **NOT QUALIFIED BY THIS
HANDOVER**. In particular, `agentic_robot/fsr_vln/` is a Stage B candidate and
is **NOT QUALIFIED BY THIS HANDOVER** as the Stage A runtime. Stage B requires a
separate design that selects and pins its maintained source, mapping models,
raw-data layout, rebuild procedure, and comparison criteria.

## Superseded Historical Evidence

Everything below is comparison context, not Stage A authority or acceptance.
The fixed-query runbook and locks above supersede the older host-bound paths,
commands, source counts, and ROS result.

### Recovered source history

The July Stage 0 record used unreachable stash commit
`f164095abb0045a69c0b8eb23683063be3deaa38`, a 74-path source closure, and a
host-specific tracked checkpoint symlink. The current lock instead anchors the
same retained blobs at reachable commit
`ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8`, removes the asset-location symlink,
and retains the reviewed `nav_agent/README.md` override from
`d862782b3661e2f2cf155d6e006f11c27063a6b0`. See the current source manifest and
`docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md` for the
explicit supersession record.

### Jihun-host ROS observation

The 2026-07-22 observation on Jihun's host used ROS, `ROS_DOMAIN_ID=77`, a
recovered NavAgent path, and Jihun-specific source and output locations. It
returned pantry object `0_0_81` with a finite map-frame pose while motion and
Nav2 were disabled. That result was useful recovery evidence, but its ROS graph,
74-path identity, host paths, and `PASS_SEMANTIC_RECOVERY` label are superseded
for this handover. They do not qualify a transferred workstation.

### Historical batch outputs

Earlier retained runs covered 114 query rows across `icra_ic3f`, `icra_ic4f`,
`icra_ic7f`, and `icra_sh3f`. They demonstrate completed retrieval calls and
latency observations, but contain no ground-truth correctness, trajectory, SPL,
or navigation-success metric. They are not a substitute for the five-file
Stage A evidence bundle.

Authoritative implementation context is in
`docs/superpowers/specs/2026-08-18-fsrvln-portable-workstation-handover-design.md`
and the two reviewed lock files under `scripts/holoagent0_setup/locks/`.
