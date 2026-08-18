# Portable FSR-VLN Workstation Handover Design

**Date:** 2026-08-18

**Status:** Approved design; implementation pending written-spec review

**Primary document:** `docs/FSR_VLN_HOLOAGENT_HANDOVER.md`

## Problem

The current handover explains the reproduced FSR-VLN result and how to rerun it
on Jihun's workstation. It does not let a teammate start from a clean
workstation because it lacks a validated environment bootstrap and complete
asset-acquisition procedure. The current semantic asset gate also requires
literal paths under `/home/jihun` and `/mnt/data/jihun`, so otherwise valid
copies fail before content verification.

The verified query used the existing `fsrvln` Conda environment, which currently
reports Python 3.9.23, PyTorch 2.4.1+cu118, Open3D 0.18.0, and CPU fallback. The
tracked `agentic_robot/fsr_vln/environment.yaml` instead declares Python
3.10.19, PyTorch 2.5.0+cu121, and Open3D 0.19.0. Therefore, the tracked
environment must pass a clean-environment reproduction before the handover may
call it authoritative.

## Goals

1. Make native Conda the authoritative workstation reproduction path.
2. Let a teammate choose their own absolute repository and data roots without
   weakening source or asset identity checks.
3. Provide complete acquisition commands for the pinned graph, RGB-D dataset,
   and checkpoint.
4. Reproduce the exact fixed query from transferred pinned assets before any
   mapping, ROS, Nav2, or robot work.
5. Clearly separate the accepted query-reproduction path from the not-yet-
   accepted RGB-D-to-HMSG rebuild path.

## Non-Goals

- Docker is not an authoritative setup path. The published `latest` image is
  not accepted until it is pinned by immutable digest and independently tested.
- This change does not claim paper-level retrieval accuracy or navigation
  success.
- This change does not commission Nav2, MuJoCo motion, PC2, or physical robot
  execution.
- This change does not automatically regenerate or approve a changed graph,
  dataset, checkpoint, source manifest, or environment lock.
- This change does not make external LLM parsing part of the deterministic
  fixture.

## Chosen Approach

The existing handover remains the single entry point. It gains two early
sections:

1. `Clean Workstation Environment Setup`
2. `Dataset, Graph, and Checkpoint Acquisition`

The setup is command-driven but not hidden behind a new bootstrap script. This
keeps each network, filesystem, and environment mutation visible to the
teammate. A future bootstrap script may automate the reviewed commands, but it
must not become the first portable reproduction authority.

## Repository and Version Authority

The guide uses the fork `https://github.com/caisarl76/HoloAgent.git`. The
portable asset-root implementation is developed and reviewed on
`feat/holoagent0-workstation-pc2-setup`. After its tests pass, that exact commit
is tagged `holoagent0-fsrvln-workstation-repro-v1`. The handover tells the
teammate to fetch tags and detach at that tag. Moving branch names and an
unpinned `main` checkout are not sufficient reproduction identities.

The original `https://github.com/HorizonRobotics/HoloAgent.git` remains the
canonical upstream remote. The handover includes the expected `origin` and
`upstream` URLs but never asks the teammate to push to upstream.

## Clean Workstation Environment Setup

### Platform contract

The authoritative path is Linux x86-64 on Ubuntu 20.04 or newer with:

- Git and Git LFS;
- `rsync`, `curl`, `unzip`, and SHA-256 tooling;
- Conda or Miniforge;
- enough storage for the environment and at least 7 GB of reproduction assets
  and transfer staging;
- optional NVIDIA GPU and a driver compatible with the tracked CUDA-enabled
  PyTorch build.

GPU availability is not required for the fixed observation-only query. A CPU
pass is valid but must be labeled as CPU and must not be used for performance
comparison.

### Environment creation contract

The handover will provide literal commands to:

1. clone the fork recursively;
2. add and verify the official upstream remote;
3. fetch and detach at `holoagent0-fsrvln-workstation-repro-v1`;
4. create a new Conda environment from
   `agentic_robot/fsr_vln/environment.yaml`;
5. activate `holoagent_semantic_mapping`;
6. install `agentic_robot/fsr_vln` in editable mode;
7. print and record Python, PyTorch, CUDA availability, Open3D, OpenCLIP,
   NumPy, and OmegaConf versions;
8. run import-only and source-contract smoke tests before assets are loaded.

The environment validation must use a newly created environment. Reusing
Jihun's existing `fsrvln` environment is evidence about the historical result,
not evidence that the clean setup works. If clean creation or the fixed query
fails, the tracked environment definition is corrected and reviewed before the
handover is updated. The guide must not tell the teammate to apply ad hoc
unrecorded `pip install` fixes.

No `.env`, API token, or external chat-completion credential is needed for the
deterministic fixed query. Online slow reasoning is documented separately and
is not part of this acceptance path.

## Portable Asset Root Contract

The literal Jihun-specific roots are replaced by one explicit configuration
object derived from two mandatory absolute inputs:

- `repository_root`: the detached HoloAgent checkout;
- `data_root`: a teammate-controlled data directory outside the Git index.

The role paths are derived without search or fallback:

```text
graph      = repository_root/fsr_vln/scene_graphs_opensource/horizon/
             icra_ic4f/graph_20260629211448
dataset    = data_root/fsr_vln/rgbd_datasets/icra_ic4f
checkpoint = data_root/fsr_vln/checkpoints/open_clip_pytorch_model.bin
```

Both inputs must exist, be absolute, and resolve successfully before asset
measurement. The implementation rejects relative paths, missing roots,
unexpected role names, post-resolution path changes, and asset paths that do
not equal the paths derived above. It does not search the filesystem and does
not select the newest graph.

Portability changes location authority only. The following identity checks
remain mandatory:

| Role | Count/size | Canonical SHA-256 |
| --- | ---: | --- |
| Graph | 1,229 files; 150,066,065 bytes | `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050` |
| Dataset | 5,360 files; 2,391,476,669 bytes | `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913` |
| Checkpoint | 1 file; 1,710,631,365 bytes | `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b` |

The existing per-file asset manifest remains authoritative. A canonical-root
digest alone is not a substitute for the complete inventory comparison.

## Dataset, Graph, and Checkpoint Acquisition

### Authoritative immediate transfer

The immediate reproduction source is
`jihun@jihun-Z590-AORUS-ELITE`. The teammate must be on a LAN or VPN where that
hostname resolves and must have SSH read access authorized by the outgoing
owner.

The handover provides three explicit `rsync` commands. Each copies into a new
or reviewed destination without `--delete`:

- graph source:
  `/home/jihun/work/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448/`;
- dataset source:
  `/mnt/data/jihun/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f/`;
- checkpoint source:
  `/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/open_clip_pytorch_model.bin`.

Interrupted transfers may be resumed. A received asset is not usable until the
portable verifier confirms the complete locked inventory. The guide never asks
the teammate to copy `.env`, historical logs, build trees, or unrelated output
directories.

### Public dataset archive

The public
`HorizonRobotics/fsrvln_datasets` repository is an optional RGB-D acquisition
source. The guide pins repository revision
`3ae09a4d99a1afa0307fe32abc25d0a3b75cb1df` and downloads only
`icra_ic4f.zip` from:

```text
https://huggingface.co/datasets/HorizonRobotics/fsrvln_datasets/resolve/3ae09a4d99a1afa0307fe32abc25d0a3b75cb1df/icra_ic4f.zip
```

The server reports 2,313,731,566 bytes and linked object identifier
`cd6c3f4fd2d925ede5c7f1a3219457bd11936065fc354dfb3e783cde5746609c`.

Before the public archive is documented as equivalent to the internally
transferred dataset, implementation must independently download it, compute its
SHA-256, inspect extraction paths, and prove that the normalized extracted
dataset matches the existing 5,360-file lock. Until that test passes, the guide
labels the public archive as an optional source that is not the authoritative
exact-reproduction transfer.

No public source has yet been accepted for the exact pinned graph or
checkpoint. The guide uses internal transfer for those assets and records
public artifact publication as follow-up work, not as an invented URL.

## Staged Reproduction

### Stage A: accepted fixed-query reproduction

After environment and asset verification, the teammate runs the deterministic
query `Take me to the counter in the pantry`. Acceptance requires:

- floor `0`;
- room `0_0`, `Pantry`;
- object `0_0_81`, `counter`;
- frame `map`;
- position
  `(-21.526786203133774, -15.671372634872082, -0.27579107548158116)`;
- no ROS initialization, Nav2 start, AgentOS action, external LLM request, or
  robot-control process;
- a clean asset-verification result using the configured roots.

The guide then shows how to open the retained PNG and PLY visualization. The
visualization is not described as a Nav2 occupancy-map overlay.

### Stage B: separately qualified map rebuild

The handover describes the intended RGB-D to OVO to HMSG flow and points to the
tracked mapping entry point, but labels it `NOT YET REPRODUCED FROM CLEAN
SETUP`. It does not instruct the teammate to treat a newly generated graph as a
substitute for the pinned Stage A graph.

Stage B becomes accepted only after Segment Anything 2 and every mapping model
are pinned, the raw-data layout is documented, one clean rebuild completes, and
graph structure and retrieval behavior are compared with the pinned graph.

## Failure Handling and Safety

- A checksum, file-count, byte-count, per-file inventory, or semantic-result
  mismatch stops the procedure. The teammate must not update a lock to make a
  failed transfer pass.
- Insufficient storage, unavailable SSH access, missing Conda packages, and an
  unavailable public archive are reported as setup blockers rather than worked
  around with unreviewed assets.
- Transfer commands do not use destructive deletion flags.
- Secrets remain outside Git, command transcripts, evidence archives, and the
  handover.
- All setup and query commands retain motion-disabled, observation-only
  boundaries.

## Implementation Scope

The portability implementation updates the existing feature worktree before
the handover claims clean-workstation support:

1. amend the workstation setup design and offline implementation plan to
   replace literal host roots with the two-root contract;
2. replace `APPROVED_ASSET_ROOTS` constant use with an explicit derivation and
   validation API;
3. thread the root configuration through semantic fixture invocation without
   environment-variable fallback;
4. add adversarial tests for relative roots, missing roots, role substitution,
   symlink/path aliasing, and correct assets at alternate absolute roots;
5. create and validate a fresh Conda environment;
6. verify the internal-transfer command structure; independently validate the
   public archive or keep it explicitly outside exact-reproduction authority;
7. add the two approved sections to the handover;
8. rerun the focused source/semantic suite and the complete tracked manifest;
9. tag the accepted feature commit and publish the handover update.

## Acceptance Criteria

The documentation change is complete only when all of the following are true:

1. A fresh Conda environment can be created from the tracked definition without
   undocumented commands.
2. The portable gate accepts correctly transferred assets under a non-Jihun
   absolute data root.
3. The gate continues to reject wrong content, wrong role mappings, relative
   roots, and unapproved aliases.
4. The internal transfer commands name all three exact source assets and never
   include secrets or unrelated workspace data.
5. The fixed query returns the exact accepted object and pose.
6. The handover clearly marks the public dataset archive's validated or
   unvalidated status.
7. The handover clearly marks full HMSG rebuilding, Nav2, and robot execution
   as outside Stage A acceptance.
8. Documentation formatting, command tests, focused tests, and the tracked test
   manifest report zero failures.
