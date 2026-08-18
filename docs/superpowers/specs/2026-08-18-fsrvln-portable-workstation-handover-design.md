# FSR-VLN Fixed-Query Asset and Runtime Handover Design

**Date:** 2026-08-18

**Status:** Approved scope; implementation pending

**Primary handover:** `docs/FSR_VLN_HOLOAGENT_HANDOVER.md`

## Problem

The current handover records a reproduced FSR-VLN result, but it mixes historical
workspace details, two different FSR-VLN source trees, host-specific asset paths,
and broader workstation commissioning work. That makes it difficult for an
incoming owner to determine which code and assets produced the accepted result.

The incoming owner can transfer the assets from Jihun's workstation and manage
their own Python environment. The repository therefore does not need to automate
those mechanics. It must instead provide an unambiguous identity contract and a
single observation-only command that proves the transferred source, assets, and
runtime can reproduce the accepted fixed query.

## Decision Summary

The handover is an outcome-based acceptance contract, not a general workstation
bootstrap guide.

- The incoming owner chooses the transfer tool and environment manager.
- The repository pins the source closure, asset inventories, fixed query,
  expected result, and acceptance evidence.
- Stage A uses the recovered root-level `fsr_vln/` implementation because that
  is the implementation loaded by the existing deterministic fixture.
- `agentic_robot/fsr_vln/` is not installed or imported for Stage A.
- All non-Git assets live beneath one teammate-controlled `data_root` outside
  the repository.
- One non-ROS CLI verifies source and assets, records the runtime, executes the
  fixed query, and emits a machine-readable PASS or FAIL result.

## Goals

1. Give the incoming owner one authoritative Stage A source tree and source
   identity.
2. Accept transferred assets at any reviewed absolute data root while preserving
   exact content identity.
3. Qualify an incoming-owner-managed environment by observed imports, module
   origins, versions, and query behavior.
4. Reproduce `Take me to the counter in the pantry` from the pinned graph without
   an external LLM, ROS, Nav2, AgentOS, or robot control.
5. Produce a compact evidence bundle that both owners can use for handover
   sign-off.
6. Keep raw RGB-D-to-HMSG rebuilding and navigation commissioning explicitly
   outside Stage A.

## Non-Goals

- The repository does not install Conda, create a Python environment, choose an
  environment manager, or promise one-command dependency installation.
- The repository does not prescribe `rsync` over another safe transfer tool.
- The handover does not qualify `agentic_robot/fsr_vln/` as the Stage A runtime.
- The handover does not claim paper-level retrieval accuracy or navigation
  success.
- The handover does not rebuild an HMSG graph, align a Nav2 map, initialize ROS,
  or enable robot motion.
- The handover does not make the public dataset archive authoritative. Public
  artifact publication and equivalence testing remain follow-up work.
- The handover does not automatically regenerate or approve a changed source or
  asset lock.

## Ownership Boundary

### Incoming owner

The incoming owner is responsible for:

- selecting and operating the transfer method;
- providing sufficient storage and a writable staging location;
- creating and maintaining a Python environment;
- obtaining any required internal access without copying credentials into the
  repository or evidence bundle; and
- retaining the accepted assets after handover.

### Repository

The repository is responsible for:

- identifying the exact source payload;
- defining the only accepted asset roles and paths;
- verifying the complete per-file asset inventory;
- proving which Python modules were imported;
- executing the fixed query without network parsing or motion-capable systems;
- emitting deterministic acceptance evidence; and
- failing closed on any mismatch.

## Source and Release Authority

The source repository is `https://github.com/caisarl76/HoloAgent.git`. The
official `https://github.com/HorizonRobotics/HoloAgent.git` remains the upstream
remote, but Stage A never requires push access to either remote.

Implementation proceeds on `feat/holoagent0-workstation-pc2-setup`. Because the
primary handover and this design currently exist on `main`, implementation first
merges `main` into that feature branch. It does not rebase away the reviewed
feature lineage.

The current source lock names the unreachable stash commit
`f164095abb0045a69c0b8eb23683063be3deaa38`. The same 73 non-README baseline
entries have identical Git blob identities at the reachable feature commit
`ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8`. The implementation updates source
provenance to that reachable commit while preserving every approved baseline
blob identity. The existing reviewed `nav_agent/README.md` override remains
bound to `d862782b3661e2f2cf155d6e006f11c27063a6b0`.

The host-specific tracked symlink `fsr_vln/checkpoints` is removed from the
Stage A source closure and from the accepted release. Its target is an asset
location, not executable source authority. Removing it changes only the reviewed
path-set digest and count; it must not change any retained source blob identity.

The release process creates:

1. an accepted implementation commit containing the code, locks, tests, and
   commands used for Stage A;
2. a documentation-only release commit that records the accepted
   implementation commit's full 40-character SHA; and
3. annotated tag `holoagent0-fsrvln-handover-v1` on the documentation release
   commit.

The tag is a discovery aid. The full implementation commit SHA in the handover
is the reproduction identity. The handover tells the teammate to fetch the tag,
verify that the recorded implementation commit is its ancestor, and detach at
the recorded implementation commit. A branch name or tag name alone is not an
accepted identity.

Stage A clones do not use `--recursive`. The only configured submodule uses an
SSH URL and is not part of the Stage A source closure.

## Authoritative Stage A Runtime

Stage A executes the recovered root-level tree:

```text
repository_root/fsr_vln
```

The acceptance CLI inserts that directory for the duration of the fixture and
requires the loaded graph module to resolve exactly to:

```text
repository_root/fsr_vln/memory/hmsg/graph/graph.py
```

It does not install or import `repository_root/agentic_robot/fsr_vln`. The
maintained `agentic_robot/fsr_vln/` API and the RGB-D mapping entry point remain
Stage B candidates until a separate design selects and qualifies them.

## Data Root and Asset Identity

The acceptance CLI takes two mandatory absolute inputs:

- `repository_root`: the detached accepted implementation checkout;
- `data_root`: a teammate-controlled directory outside `repository_root`.

It derives all roles internally:

```text
graph      = data_root/fsr_vln/scene_graphs_opensource/horizon/
             icra_ic4f/graph_20260629211448
dataset    = data_root/fsr_vln/rgbd_datasets/icra_ic4f
checkpoint = data_root/fsr_vln/checkpoints/open_clip_pytorch_model.bin
asset_lock = repository_root/scripts/holoagent0_setup/locks/
             icra_ic4f-assets-v1.json
```

The caller cannot supply individual graph, dataset, checkpoint, or lock paths.
The implementation uses one immutable path object derived from the two roots.
There is no environment-variable fallback, filesystem search, newest-file
selection, or role substitution.

Both roots must:

- be absolute, normalized paths;
- exist before verification;
- be directories;
- equal their strict resolved paths, thereby rejecting symlink aliases;
- remain identity-stable while opened and measured; and
- be disjoint, with `data_root` neither inside nor above `repository_root`.

The run directory must be absolute, writable, outside both roots, and must not
pre-exist unless it is an explicitly empty owner-controlled directory. Path
components used as retained authorities are opened without following symlinks.

The locked asset identities remain:

| Role | Count/size | Canonical SHA-256 |
| --- | ---: | --- |
| Graph | 1,229 files; 150,066,065 bytes | `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050` |
| Dataset | 5,360 files; 2,391,476,669 bytes | `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913` |
| Checkpoint | 1 file; 1,710,631,365 bytes | `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b` |

The complete per-file lock, including file type, mode, byte size, digest, and
reviewed internal symlink target, is authoritative. Aggregate counts and root
digests are summaries, not substitutes.

## Transfer and Custody Contract

The authoritative initial source is `jihun@jihun-Z590-AORUS-ELITE` at:

```text
graph:      /home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/
            horizon/icra_ic4f/graph_20260629211448
dataset:    /mnt/data/jihun/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f
checkpoint: /mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/
            open_clip_pytorch_model.bin
```

The teammate may use `rsync`, removable storage, or another reviewed method. The
handover records the sources and destinations but does not make one transfer
command authoritative.

Operational requirements are:

- transfer into a new sibling staging location;
- do not use destructive deletion against the source or an existing destination;
- inspect destination collisions before copying;
- resume an interrupted transfer only with the selected tool's verified resume
  mode;
- optionally measure the staged copy with the same inventory algorithm;
- promote on the same filesystem when atomic rename is available, then run the
  mandatory verifier against the final derived paths;
- keep Jihun's originals unchanged until the incoming owner signs off; and
- retain a second verified copy before the outgoing workstation or its data disk
  is repurposed.

The three assets total 4,252,174,099 bytes. The teammate reserves at least 10 GB
of free space for assets and staging, excluding the Python environment and
optional retained visualizations.

The outgoing and incoming owners confirm that internal transfer is permitted by
the applicable source, dataset, and checkpoint licenses. Secrets, `.env`, logs,
build trees, and unrelated outputs are never transferred as part of this
contract.

## Environment Qualification

The environment manager and installation steps are teammate-owned. Neither
`fsr_vln/environment.yaml` nor `agentic_robot/fsr_vln/environment.yaml` is called
an authoritative lock by this handover.

The historical successful environment is recorded only as a comparison point:

```text
Python 3.9.23
PyTorch 2.4.1+cu118
Open3D 0.18.0
CUDA unavailable; CPU execution
```

Before asset loading, the acceptance CLI records:

- operating-system release and machine architecture;
- Python executable and version;
- PyTorch, CUDA build, CUDA availability, Open3D, OpenCLIP, NumPy, OmegaConf,
  FAISS, OpenCV, NetworkX, PyVista, scikit-fmm, OSS2, and Segment Anything import
  status and version when exposed; and
- the resolved origin of the root-level HMSG graph module.

Missing imports or a graph-module origin outside the accepted root-level tree
fail qualification. The incoming environment may differ from the historical
versions, but it is accepted only if the complete asset verification and fixed
query pass. CPU and GPU runs are labeled and are not compared for performance.

No API token, `.env`, OSS credential, external chat-completion credential, ROS
installation, or robot SDK is required for Stage A.

## Single Acceptance Command

The handover exposes one non-ROS module entry point:

```text
PYTHONPATH=<repository_root>/scripts/holoagent0_setup \
python -m holoagent0_setup.fsrvln_handover \
  --repository-root <repository_root> \
  --data-root <data_root> \
  --run-directory <new_absolute_run_directory>
```

The CLI performs these steps in order:

1. verify the checkout identity and reachable source provenance;
2. verify the current locked source files without modifying them;
3. capture the environment, required imports, and exact module origins;
4. derive and verify all asset roles and complete inventories;
5. load the real root-level HMSG graph;
6. execute the pinned structured form of
   `Take me to the counter in the pantry` exactly once;
7. compare the result with the accepted identity and pose tolerance; and
8. atomically write the evidence bundle and terminal result.

The CLI does not import `rclpy`, initialize ROS, start Nav2 or AgentOS, call an
external LLM, or launch a robot-control process.

## Expected Result

Acceptance requires:

- graph counts: one floor, three rooms, and 497 objects;
- floor: `0`;
- room: `0_0`, `Pantry`;
- object: `0_0_81`, `counter`;
- frame: `map`;
- position:
  `(-21.526786203133774, -15.671372634872082, -0.27579107548158116)`,
  with absolute tolerance `1e-6` per coordinate;
- orientation: `(0.0, 0.0, 0.0, 1.0)`;
- the pinned structured-query, graph, dataset, checkpoint, and room-name-mapping
  digests; and
- no network parser or motion-capable subsystem in the execution path.

The retained PNG and PLY may be opened after acceptance, but visualization is
optional and is not a Nav2 occupancy-map overlay.

## Evidence and Sign-Off

The run directory contains at least:

```text
environment.json
source-verification.json
asset-verification.json
query-result.json
handover-result.json
```

Every document uses a closed schema and canonical JSON. `handover-result.json`
records the terminal `PASS` or `FAIL`, the accepted implementation commit, input
root identities, evidence-file digests, CPU/GPU label, start and finish times,
and the first blocking reason on failure.

The handover sign-off records:

- outgoing owner and incoming owner;
- transfer and acceptance dates;
- repository URL, release tag, and full accepted implementation commit;
- the three asset root digests;
- environment summary and module origin;
- evidence-bundle location and digest;
- final PASS or FAIL; and
- custody confirmation that a second verified asset copy exists.

## Failure Handling

- Any source, asset, module-origin, graph-count, object, pose, or evidence mismatch
  produces FAIL and a nonzero exit status.
- The verifier never repairs, searches for, downloads, or substitutes content.
- A failed transfer does not authorize editing the lock.
- A failed environment import is diagnosed in the teammate-owned environment;
  it does not authorize switching to `agentic_robot/fsr_vln` silently.
- Partial evidence is retained as diagnostic output but cannot be labeled PASS.
- Jihun's source assets remain unchanged until PASS and custody sign-off.

## Stage B and Later Work

The handover may summarize the intended RGB-D to OVO to HMSG flow, but it labels
it `NOT QUALIFIED BY THIS HANDOVER`. Stage B requires a separate design that
chooses the maintained source tree, pins Segment Anything 2 and all mapping
models, defines raw-data layout, performs a clean rebuild, and compares graph
structure and retrieval behavior.

Nav2 frame alignment, MuJoCo, PC2, and physical robot execution remain separate
commissioning projects.

## Implementation Scope

Implementation updates the feature branch in this order:

1. Merge `main` into `feat/holoagent0-workstation-pc2-setup` so the primary
   handover and this design share the release lineage.
2. Update `scripts/holoagent0_setup/holoagent0_setup/source_gate.py`,
   `scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json`, and the
   superseded 74-path section of
   `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md` to use
   reachable source provenance, remove the host checkpoint symlink from the
   closure, and introduce the immutable two-root path contract.
3. Update `semantic_gate.py` to consume the derived path object and enforce the
   root-level HMSG module origin.
4. Add
   `scripts/holoagent0_setup/holoagent0_setup/fsrvln_handover.py` as the one
   non-ROS acceptance CLI and add closed evidence schemas.
5. Update `test_source_gate.py` and `test_semantic_gate.py`; add
   `test_fsrvln_handover.py` with clean-clone, alternate-root, dependency,
   evidence, and fixed-query coverage.
6. Make `test-manifest-v1.txt` equal the complete tracked `tests/test_*.py` set,
   including the currently omitted `test_offline_cli.py`, and test that equality.
7. Rewrite the top of `docs/FSR_VLN_HOLOAGENT_HANDOVER.md` as the concise Stage A
   runbook while retaining historical results as clearly labeled background.
8. Run the focused tests, complete tracked manifest, clean-tag clone test, and
   real transferred-asset query under a teammate-managed environment.
9. Create the accepted implementation commit, record its full SHA in a
   documentation-only release commit, create the annotated release tag, and
   publish both commits and the tag.

## Acceptance Criteria

The handover implementation is complete only when all of the following are true:

1. A clone fetching the documented release tag can detach at the literal
   implementation SHA and resolve every commit and blob required by the source
   verifier without another local ref.
2. The accepted CLI imports the root-level HMSG graph from the exact expected
   file and never imports `agentic_robot/fsr_vln` for Stage A.
3. A teammate-managed environment either passes the import qualification or
   fails with an explicit missing dependency or wrong-origin reason.
4. Correct assets pass under a non-Jihun absolute `data_root`; relative roots,
   aliases, overlaps, role substitution, missing files, extra files, and changed
   content fail.
5. The fixed query returns the accepted graph counts, node identities,
   orientation, and pose within `1e-6` absolute tolerance per coordinate.
6. The execution initializes no ROS, Nav2, AgentOS, external LLM, or robot-control
   component.
7. The evidence bundle is complete, schema-valid, digest-bound, and records a
   terminal PASS before owner sign-off.
8. The tracked test manifest contains exactly every tracked
   `scripts/holoagent0_setup/tests/test_*.py` file, and the complete manifest
   reports zero failures.
9. The handover includes no placeholder commit, owner, path, digest, or status
   in its signed-off record.
10. Stage B, public artifact equivalence, map alignment, Nav2, and robot execution
    remain explicitly unqualified.
