# HoloAgent Stage 0 Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the approved 21-path semantic-navigation recovery manifest from its pinned Git snapshot and prove, without starting Nav2 or a motion publisher, that one fixed HMSG text query emits a finite `/object_pose`.

**Architecture:** The recovery source is immutable commit `f164095abb0045a69c0b8eb23683063be3deaa38`. Its first-parent diff is the executable manifest. Recovery runs directly in the approved target workspace because the required FSR-VLN datasets are untracked local assets that a clean worktree would omit; existing paths cause a fail-closed stop, and GNU tar's keep-old-files mode prevents a check/write race from overwriting them. Compilation and runtime checks run in the existing bind-mounted HoloAgent container with isolated `/tmp` build outputs and dry-run motion flags.

**Tech Stack:** Git object database, Bash, GNU tar, Docker, ROS 2 Humble, colcon, Python 3, FSR-VLN/HMSG.

---

## File Responsibilities

- Restore: the exact 21 paths listed in `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`.
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/` evidence files; these are generated results, not source changes.
- Do not modify: existing tracked source outside this plan, local scene graphs/datasets, Nav2 configuration, FastLIVO configuration, or Unitree sources.

## Execution Context Exception

The standard implementation workflow prefers a Git worktree. This recovery is
an approved exception: `fsr_vln/` and `nav_agent/` are untracked local working
trees containing the datasets, configs, and build state that Stage 0 must
repair and validate. A clean worktree would neither contain those assets nor
repair the target workspace. The user explicitly approved execution on the
current `main` workspace. Exact-path restore, keep-old-files extraction, pinned
blob verification, `/tmp` build outputs, and no-motion runtime isolation bound
the risk.

### Task 1: Pin and Validate the Recovery Manifest

**Files:**
- Read: `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`
- Read: Git commit `f164095abb0045a69c0b8eb23683063be3deaa38`
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/manifest.txt`

- [ ] **Step 1: Allocate a unique evidence directory**

Run:

```bash
stage0_run_id="$(date -u +%Y%m%dT%H%M%SZ)"
stage0_evidence_dir="outputs/mujoco_holoagent/$stage0_run_id"
mkdir -p "$stage0_evidence_dir"
test -d "$stage0_evidence_dir"
```

Expected: a new, empty run directory under `outputs/mujoco_holoagent/`.

- [ ] **Step 2: Assert the durable branch still resolves to the approved object**

Run:

```bash
stage0_source=f164095abb0045a69c0b8eb23683063be3deaa38
test "$(git rev-parse stash-backup-20260722)" = "$stage0_source"
```

Expected: exit 0 and no output.

- [ ] **Step 3: Derive the manifest from the immutable commit**

Run:

```bash
git diff-tree --no-commit-id --name-only -r \
  "$stage0_source^1" "$stage0_source"
```

Expected: the exact 21 paths in the approved design, with no extra path.

- [ ] **Step 4: Assert the manifest count and approved roots**

Run:

```bash
mapfile -t stage0_paths < <(
  git diff-tree --no-commit-id --name-only -r \
    "$stage0_source^1" "$stage0_source"
)
test "${#stage0_paths[@]}" -eq 21
for stage0_path in "${stage0_paths[@]}"; do
  case "$stage0_path" in
    fsr_vln/*|nav_agent/README.md|nav_agent/scripts/*|nav_agent/sem_nav_ctr/src/*) ;;
    *) printf 'Unexpected recovery path: %s\n' "$stage0_path" >&2; exit 1 ;;
  esac
done
```

Expected: exit 0 and no output.

### Task 2: Restore Without Overwriting Workspace State

**Files:**
- Restore: the 21 paths held in `stage0_paths`
- Preserve: every path not held in `stage0_paths`

- [ ] **Step 1: Prove every target is absent immediately before recovery**

Run:

```bash
for stage0_path in "${stage0_paths[@]}"; do
  if [[ -e "$stage0_path" || -L "$stage0_path" ]]; then
    printf 'Refusing to overwrite: %s\n' "$stage0_path" >&2
    exit 1
  fi
done
```

Expected: exit 0 and no output. Any listed path causes a hard stop.

- [ ] **Step 2: Extract only the approved objects with keep-old-files protection**

Run from `/home/jihun/work/HoloAgent`:

```bash
test "$(pwd -P)" = /home/jihun/work/HoloAgent
git archive --format=tar "$stage0_source" -- "${stage0_paths[@]}" |
  tar --extract --keep-old-files --directory=/home/jihun/work/HoloAgent
```

Expected: exit 0. GNU tar refuses rather than overwrites if a target appears
between the preflight and extraction.

- [ ] **Step 3: Assert exactly the approved paths appeared**

Run:

```bash
for stage0_path in "${stage0_paths[@]}"; do
  [[ -e "$stage0_path" || -L "$stage0_path" ]] || {
    printf 'Recovery path still absent: %s\n' "$stage0_path" >&2
    exit 1
  }
done
```

Expected: exit 0 and no output.

### Task 3: Verify Git Objects, Assets, and Motion Exclusion

**Files:**
- Read: all restored paths
- Read: `/mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/`
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/blob-verification.tsv`

- [ ] **Step 1: Compare every restored file or symlink with its pinned blob**

Run:

```bash
for stage0_path in "${stage0_paths[@]}"; do
  stage0_tree_line="$(git ls-tree "$stage0_source" -- "$stage0_path")"
  stage0_mode="$(awk '{print $1}' <<<"$stage0_tree_line")"
  stage0_expected_blob="$(awk '{print $3}' <<<"$stage0_tree_line")"
  if [[ -L "$stage0_path" ]]; then
    test "$stage0_mode" = 120000
    stage0_actual_blob="$(printf '%s' "$(readlink "$stage0_path")" | git hash-object --stdin)"
  else
    [[ "$stage0_mode" = 100644 || "$stage0_mode" = 100755 ]]
    stage0_actual_blob="$(git hash-object "$stage0_path")"
  fi
  test "$stage0_actual_blob" = "$stage0_expected_blob" || {
    printf 'Blob mismatch: %s\n' "$stage0_path" >&2
    exit 1
  }
done
```

Expected: all 21 comparisons exit 0.

- [ ] **Step 2: Verify the recovered checkpoint symlink and model assets**

Run:

```bash
test "$(readlink fsr_vln/checkpoints)" = \
  /mnt/data/jihun/HoloAgent/fsr_vln/checkpoints/
test -s fsr_vln/checkpoints/open_clip_pytorch_model.bin
test -s fsr_vln/checkpoints/sam_vit_h_4b8939.pth
```

Expected: exit 0 and no output.

- [ ] **Step 3: Verify safe flags and absence of motion executables before ROS startup**

Run:

```bash
test "$(sed -n 's/^START_G1_PUBVEL=//p' nav_agent/config/g1_deploy.env)" = 0
test "$(sed -n 's/^G1_DRY_RUN=//p' nav_agent/config/g1_deploy.env)" = 1
test "$(sed -n 's/^ALLOW_G1_MOTION=//p' nav_agent/config/g1_deploy.env)" = 0
if pgrep -af '[g]1_pubvel_node|[g]1_pubmove_node|[g]1_pubcmd_node'; then
  exit 1
fi
```

Expected: exit 0; `pgrep` prints no matching process.

### Task 4: Build and Smoke-Test in the Existing Container

**Files:**
- Read/build: `nav_agent/sem_nav_ctr/src/`
- Create inside container: unique `/tmp/navagent_stage0_*` build, install, and log directories
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/container-build-smoke.log`

- [ ] **Step 1: Verify the container bind mount and transport modes**

Run:

```bash
docker inspect --format \
  '{{.HostConfig.NetworkMode}} {{.HostConfig.IpcMode}} {{range .Mounts}}{{if eq .Destination "/workspace/HoloAgent"}}{{.Source}}{{end}}{{end}}' \
  holoagent-navagent
```

Expected:

```text
host host /home/jihun/work/HoloAgent
```

- [ ] **Step 2: Allocate clean build paths and run setup plus smoke checks**

Run with `stage0_run_id` set to the evidence directory basename:

```bash
NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
SEM_NAV_BUILD_BASE="/tmp/navagent_stage0_${stage0_run_id}_build" \
SEM_NAV_INSTALL_BASE="/tmp/navagent_stage0_${stage0_run_id}_install" \
SEM_NAV_LOG_BASE="/tmp/navagent_stage0_${stage0_run_id}_log" \
SEM_NAV_SETUP="/tmp/navagent_stage0_${stage0_run_id}_install/setup.bash" \
INSTALL_GOAL_PUBLISHER_DEPS=0 \
START_G1_PUBVEL=0 \
G1_DRY_RUN=1 \
ALLOW_G1_MOTION=0 \
RUN_SETUP=1 \
RUN_SMOKE=0 \
RUN_READINESS=0 \
bash nav_agent/scripts/run_navagent_container_checks.sh
```

Expected: all three packages build, imports succeed, executable discovery finds
`topic_chat_loc_pub`, `goal_pose_publisher`, and `g1_getvel_node`, and
`g1_pubvel_node` is absent because `BUILD_MODE=dryrun`.

- [ ] **Step 3: Verify the dry-run install contains no Unitree motion executable**

Run:

```bash
docker exec \
  -e ROS_DOMAIN_ID=77 \
  -e ROS_LOCALHOST_ONLY=1 \
  holoagent-navagent /bin/bash -lc \
  "source /opt/ros/humble/setup.bash && source /tmp/navagent_stage0_${stage0_run_id}_install/setup.bash && ! ros2 pkg executables g1_move | grep -Fq g1_pubvel_node"
```

Expected: exit 0 and no output.

### Task 5: Run the Observation-Only Semantic Query

**Files:**
- Read: `fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448/`
- Read: restored `goal_pose_publisher.py` and HMSG modules
- Create at runtime: query log, ROS graph snapshots, and `/object_pose` capture

- [ ] **Step 1: Start only the semantic goal publisher on isolated local DDS**

Run:

```bash
docker exec holoagent-navagent /bin/bash -lc \
  "tmux new-session -d -s holoagent_stage0_goal_${stage0_run_id} \
  'export ROS_DOMAIN_ID=77 ROS_LOCALHOST_ONLY=1 START_G1_PUBVEL=0 G1_DRY_RUN=1 ALLOW_G1_MOTION=0; \
   export FSRVLN_MEMORY_PATH=/workspace/HoloAgent/fsr_vln/memory FSRVLN_ROOT_PATH=/workspace/HoloAgent/fsr_vln; \
   export PYTHONPATH=/workspace/HoloAgent/fsr_vln/memory:/workspace/HoloAgent/fsr_vln; \
   export MPLCONFIGDIR=/tmp/matplotlib-cache NAV_AGENT_SCENE=icra_ic4f NAV_AGENT_ROOM_NAME_METHOD=label; \
   export NAV_AGENT_ROOM_TYPES=Hallway,Pantry,Office NAV_AGENT_QUERY_METHOD=icra NAV_AGENT_USE_GPT=0; \
   export NAV_AGENT_GRAPH_PATH=/workspace/HoloAgent/fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448; \
   export NAV_AGENT_DATASET_PATH=/workspace/HoloAgent/fsr_vln/rgbd_datasets/icra_ic4f; \
   export NAV_AGENT_CLIP_CHECKPOINT=/workspace/HoloAgent/fsr_vln/checkpoints/open_clip_pytorch_model.bin; \
   source /opt/ros/humble/setup.bash; \
   source /tmp/navagent_stage0_${stage0_run_id}_install/setup.bash; \
   ros2 run goal_publisher goal_pose_publisher'"
```

Expected: the named tmux session stays alive and eventually exposes
`/object_pose` and `/chat_loc_pub`.

- [ ] **Step 2: Assert the pre-query graph has no Nav2 or motion endpoint**

Run in the container with the same ROS domain and localhost-only settings:

```bash
ros2 node list
ros2 topic info /object_pose --verbose
ros2 topic list
```

Expected: only the goal publisher (plus ROS CLI helper nodes while commands
run), `/object_pose` has one publisher and zero persistent subscribers, and
`/cmd_vel` is absent.

- [ ] **Step 3: Publish the fixed query and capture one pose**

Run in the container:

```bash
TEST_QUERY='Take me to the counter in the pantry' \
CHECK_CMD_VEL=0 \
REQUIRE_DRY_RUN=1 \
START_G1_PUBVEL=0 \
G1_DRY_RUN=1 \
ALLOW_G1_MOTION=0 \
ROS_DOMAIN_ID=77 \
ROS_LOCALHOST_ONLY=1 \
SEM_NAV_SETUP="/tmp/navagent_stage0_${stage0_run_id}_install/setup.bash" \
bash /workspace/HoloAgent/nav_agent/scripts/validate_navagent_query_flow.sh
```

Expected: one `geometry_msgs/msg/PoseStamped` on `/object_pose`, with
`header.frame_id: map`, finite position values, and a unit identity quaternion.
No `/cmd_vel` check runs.

- [ ] **Step 4: Stop the exact semantic session**

Run:

```bash
docker exec holoagent-navagent tmux kill-session \
  -t "holoagent_stage0_goal_${stage0_run_id}"
```

Expected: exit 0. No broad process-kill command is used.

### Task 6: Write and Verify Stage 0 Evidence

**Files:**
- Create: `outputs/mujoco_holoagent/<run-id>/manifest.txt`
- Create: `outputs/mujoco_holoagent/<run-id>/blob-verification.tsv`
- Create: `outputs/mujoco_holoagent/<run-id>/container-build-smoke.log`
- Create: `outputs/mujoco_holoagent/<run-id>/graph-before-query.txt`
- Create: `outputs/mujoco_holoagent/<run-id>/object-pose.yaml`
- Create: `outputs/mujoco_holoagent/<run-id>/result.json`

- [ ] **Step 1: Record immutable inputs and gate outputs**

`result.json` must include:

```json
{
  "stage": 0,
  "status": "PASS",
  "qualified_pass": "PASS_SEMANTIC_RECOVERY",
  "source_commit": "f164095abb0045a69c0b8eb23683063be3deaa38",
  "manifest_count": 21,
  "motion_enabled": false,
  "nav2_started": false,
  "query": "Take me to the counter in the pantry",
  "object_pose_frame": "map",
  "first_failing_gate": null
}
```

The generated file may add timestamps, full pose values, blob IDs, container
image ID, and log filenames, but it must not omit or weaken these fields.

- [ ] **Step 2: Re-run final invariants after cleanup**

Run:

```bash
test "$(git rev-parse stash-backup-20260722)" = "$stage0_source"
test "${#stage0_paths[@]}" -eq 21
if pgrep -af '[g]1_pubvel_node|[g]1_pubmove_node|[g]1_pubcmd_node'; then
  exit 1
fi
docker exec holoagent-navagent /bin/bash -lc \
  "! pgrep -af '[g]1_pubvel_node|[g]1_pubmove_node|[g]1_pubcmd_node|[g]oal_pose_publisher'"
git diff --check
```

Expected: exit 0; no motion or Stage 0 query process remains.

- [ ] **Step 3: Commit only the execution plan if source recovery paths remain intentionally ignored**

Run:

```bash
git status --short
git add docs/superpowers/plans/2026-07-22-holoagent-stage0-recovery.md
git diff --cached --check
git commit -m "docs: plan HoloAgent Stage 0 recovery"
```

Expected: the commit contains only the plan. Recovered third-party/local
workspace paths and generated evidence remain outside the tracked source diff.
