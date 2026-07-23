# HoloAgent Stage 2 Synthetic Livox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the verified Stage 1 bridge with deterministic MuJoCo lidar, convert its standard point cloud to the installed Livox `CustomMsg`, and produce a bounded `PASS_SYNTHETIC_LIVOX` result without any physical transport path.

**Architecture:** The host bridge owns MuJoCo time, pose history, and static-world ray casting and publishes `/holoagent_sim/lidar_points`. A container-only ROS package converts that `PointCloud2` to `/livox/lidar`, preserving acquisition timing. A container evaluator validates raw and converted scans, timestamps, rates, point density, calibration provenance, graph parity, and cleanup. Snapshot mode is the required gate; rolling mode is unit- and integration-contract tested but never fabricates offsets.

**Tech Stack:** Python 3.10, MuJoCo 3.8, ROS 2 Humble, `sensor_msgs/PointCloud2`, `livox_ros_driver2/CustomMsg`, CycloneDDS, Docker, pytest, colcon.

---

## File responsibilities

- `nav_agent/mujoco_sim/holoagent_mujoco/lidar.py`: ray pattern, pose interpolation, acquisition offsets, scan validation.
- `nav_agent/mujoco_sim/holoagent_mujoco/backend.py`: finite static-geometry `mj_ray` adapter and lidar pose snapshots.
- `nav_agent/mujoco_sim/holoagent_mujoco/ros_messages.py`: deterministic PointCloud2 serialization.
- `nav_agent/mujoco_sim/holoagent_mujoco/calibration.py`: sim-only FastLIVO calibration generation and digest.
- `nav_agent/mujoco_sim/holoagent_mujoco/bridge_node.py`: scheduled 10 Hz raw lidar publisher.
- `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/`: container converter, evaluator, and pure conversion rules.
- `nav_agent/mujoco_sim/scripts/run_stage2.sh`: exact-process orchestration and atomic evidence finalization.

### Task 1: Reconcile the approved Stage 0 source closure

**Files:**
- Restore: the exact 74 paths in `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`
- Test: Git tree/blob checks against `f164095abb0045a69c0b8eb23683063be3deaa38`

- [ ] **Step 1: Prove the continuation branch starts from Stage 1**

Run:

```bash
test "$(git merge-base HEAD 7692aae)" = "$(git rev-parse 7692aae)"
test "$(git rev-parse stash-backup-20260722)" = f164095abb0045a69c0b8eb23683063be3deaa38
```

Expected: both commands exit zero.

- [ ] **Step 2: Derive and validate the build-driven manifest**

```bash
source_commit=f164095abb0045a69c0b8eb23683063be3deaa38
mapfile -t restore_paths < <(git ls-tree -r --name-only "$source_commit" -- \
  nav_agent/sem_nav_ctr/src fsr_vln/memory fsr_vln/perception fsr_vln/config \
  fsr_vln/setup.py fsr_vln/environment.yaml fsr_vln/checkpoints \
  nav_agent/README.md nav_agent/scripts/run_nav.sh \
  nav_agent/scripts/run_sem_nav.sh nav_agent/scripts/run_sensors.sh | sort -u)
test "${#restore_paths[@]}" -eq 74
for path in "${restore_paths[@]}"; do test ! -e "$path" && test ! -L "$path"; done
```

Expected: exactly 74 absent targets; any collision stops the restore.

- [ ] **Step 3: Restore without overwriting and verify every blob**

```bash
git archive --format=tar "$source_commit" -- "${restore_paths[@]}" | \
  tar --extract --keep-old-files --directory="$PWD"
for path in "${restore_paths[@]}"; do
  expected="$(git ls-tree "$source_commit" -- "$path" | awk '{print $3}')"
  if test -L "$path"; then
    actual="$(printf %s "$(readlink "$path")" | git hash-object --stdin)"
  else
    actual="$(git hash-object "$path")"
  fi
  test "$actual" = "$expected"
done
```

Expected: all restored objects match the immutable snapshot. Commit the 74 paths as one recovery commit so the continuation branch is reproducible.

### Task 2: Define the lidar and calibration configuration contract

**Files:**
- Modify: `nav_agent/mujoco_sim/holoagent_mujoco/config.py`
- Modify: `nav_agent/mujoco_sim/config/stage1.yaml`
- Modify: `nav_agent/mujoco_sim/setup.py`
- Test: `nav_agent/mujoco_sim/tests/test_config.py`
- Test: `nav_agent/mujoco_sim/tests/test_calibration.py`

- [ ] **Step 1: Write failing configuration tests**

Add assertions for this immutable contract:

```python
assert cfg.rates.lidar_hz == 10
assert cfg.frames.lidar == "livox_frame"
assert cfg.lidar.acquisition_mode == "snapshot"
assert cfg.lidar.scan_lines == 6
assert cfg.lidar.azimuth_samples == 512
assert cfg.lidar.configured_points == 3072
assert cfg.lidar.min_finite_points == 2500
assert cfg.lidar.scan_period_sec == pytest.approx(0.1)
assert cfg.lidar.noise_std_m == 0.0
assert cfg.lidar.dropout_probability == 0.0
```

Tests must reject relative paths, unknown acquisition modes, non-finite ranges, a maximum range no greater than the minimum, offsets beyond `uint32` nanoseconds, line counts above 255, point counts below the density gate, and lidar rates inconsistent with the scan period.

- [ ] **Step 2: Run RED**

```bash
PYTHONPATH="$PWD/nav_agent/mujoco_sim" \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_config.py \
  nav_agent/mujoco_sim/tests/test_calibration.py
```

Expected: failures because lidar configuration and calibration generation do not exist.

- [ ] **Step 3: Implement frozen lidar configuration**

Add `LidarConfig` with `name`, `acquisition_mode`, `scan_lines`, `azimuth_samples`, vertical field of view, min/max range, scan period, noise, dropout, reflectivity, tag, mount position/orientation, and minimum finite points. Extend rates, frames, thresholds, package data, and YAML. Preserve every Stage 1 default and safety check.

- [ ] **Step 4: Implement calibration generation**

`generate_fastlivo_config(config, destination)` must derive lidar-to-IMU and lidar-to-camera transforms from the same mount configuration used by scene generation, set the exact topics/rates/intrinsics, force `common.img_en: 0` for the required Stage 3 gate, force `wheel.enable_wheel_odom: false`, and write a source/config digest alongside the YAML. It must never read a real-rig calibration file.

- [ ] **Step 5: Run GREEN and commit**

Run the two test files and commit only configuration/calibration changes.

### Task 3: Implement deterministic MuJoCo lidar acquisition

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/lidar.py`
- Modify: `nav_agent/mujoco_sim/holoagent_mujoco/scene.py`
- Modify: `nav_agent/mujoco_sim/holoagent_mujoco/backend.py`
- Test: `nav_agent/mujoco_sim/tests/test_lidar.py`
- Test: `nav_agent/mujoco_sim/tests/test_scene.py`
- Test: `nav_agent/mujoco_sim/tests/test_backend.py`

- [ ] **Step 1: Write failing ray-pattern and timing tests**

Tests must prove:

```python
pattern = build_pattern(scan_lines=6, azimuth_samples=512, vertical_fov_deg=(-15, 15))
assert pattern.directions.shape == (3072, 3)
assert pattern.lines.min() == 0 and pattern.lines.max() == 5
assert np.linalg.norm(pattern.directions, axis=1) == pytest.approx(1.0)

snapshot = acquisition_offsets("snapshot", 3072, 0.1)
assert np.array_equal(snapshot, np.zeros(3072, dtype=np.uint32))
rolling = acquisition_offsets("rolling", 3072, 0.1)
assert np.all(np.diff(rolling.astype(np.int64)) >= 0)
assert rolling[-1] <= 100_000_000
```

Also test deterministic dropout/noise seeds, finite/range filtering, interpolation across the actual pose-history interval, and rejection when rolling pose history does not span one scan period.

- [ ] **Step 2: Run RED**

Expected: import failure for `holoagent_mujoco.lidar`.

- [ ] **Step 3: Add the exact lidar site and static-world ray adapter**

Scene generation adds a uniquely named lidar site to `torso_link`. Backend initialization resolves it, records world and base-relative pose, and exposes a batched loop around `mujoco.mj_ray` with the robot body excluded. Negative/non-finite ranges are discarded; static walls/corners remain hittable. Any MuJoCo error produces no partial scan and drives the command output to zero.

- [ ] **Step 4: Implement snapshot and rolling scans**

Snapshot mode ray-casts all directions from one measured MuJoCo pose and assigns zero offsets. Rolling mode interpolates the stored measured lidar poses over the preceding configured scan period and ray-casts each group from its sampled pose; its offsets are the actual sample times relative to scan start. Both modes return immutable arrays and deterministic metadata.

- [ ] **Step 5: Run GREEN and commit**

Run the three targeted test files, then the complete Stage 1 suite to prove compatibility.

### Task 4: Publish the raw PointCloud2 contract

**Files:**
- Modify: `nav_agent/mujoco_sim/holoagent_mujoco/ros_messages.py`
- Modify: `nav_agent/mujoco_sim/holoagent_mujoco/bridge_node.py`
- Test: `nav_agent/mujoco_sim/tests/test_ros_messages.py`
- Test: `nav_agent/mujoco_sim/tests/test_bridge_core.py`

- [ ] **Step 1: Write failing serialization and scheduler tests**

The raw cloud must contain little-endian fields `x`, `y`, `z`, `intensity`, `line`, and `offset_time`; `width` equals the finite point count, `height=1`, `is_dense=true`, `frame_id=livox_frame`, and timestamp equals scan timebase. The 200 Hz scheduler must emit exactly 10 lidar scans per simulated second without changing Stage 1 rates.

- [ ] **Step 2: Run RED**

Expected: missing `pointcloud_message` and missing lidar scheduler entry.

- [ ] **Step 3: Implement publication**

Add a best-effort `/holoagent_sim/lidar_points` publisher. Generate the scan only when lidar is due, publish nothing on an invalid/under-density scan, and fail the bridge closed so a starving sensor cannot be mistaken for valid data.

- [ ] **Step 4: Run GREEN and commit**

Run message, bridge, lidar, and all Stage 1 tests.

### Task 5: Build the container Livox converter

**Files:**
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/package.xml`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/setup.py`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/setup.cfg`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/resource/holoagent_livox_converter`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/holoagent_livox_converter/__init__.py`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/holoagent_livox_converter/converter_core.py`
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/holoagent_livox_converter/converter_node.py`
- Test: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test/test_converter_core.py`

- [ ] **Step 1: Write failing pure conversion tests**

Tests must assert `timebase = stamp.sec * 1_000_000_000 + stamp.nanosec`, `point_num == len(points)`, finite XYZ, uint8 reflectivity/tag/line, exact snapshot zeros, monotonic rolling offsets bounded by the scan period, deterministic configured noise/dropout, and rejection of a malformed PointCloud2 layout or fewer than 2,500 finite points.

- [ ] **Step 2: Run RED in the ROS overlay**

```bash
PYTHONPATH="$PWD/nav_agent/sem_nav_ctr/src/holoagent_livox_converter" \
  /usr/bin/python3 -m pytest -q \
  nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test
```

Expected: missing converter module.

- [ ] **Step 3: Implement the pure converter and ROS node**

The node is named `/holoagent_livox_converter`, declares `use_sim_time=true`, subscribes to `/holoagent_sim/lidar_points`, and publishes `livox_ros_driver2/msg/CustomMsg` on `/livox/lidar` using sensor-data QoS. It uses raw per-point metadata and never invents acquisition offsets.

- [ ] **Step 4: Build only the new package in a clean `/tmp` workspace**

Source `/opt/ros/humble`, `agentic_robot/thirdparty/install/setup.bash`, and `agentic_robot/core/install/setup.bash`, then run `colcon build --packages-select holoagent_livox_converter` with unique build/install/log directories. Confirm Python can import `CustomMsg` and discover the converter executable.

- [ ] **Step 5: Run GREEN and commit**

Commit converter source and tests only.

### Task 6: Implement Stage 2 evaluation and fail-closed orchestration

**Files:**
- Create: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/holoagent_livox_converter/stage2_eval.py`
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/stage2_result.py`
- Create: `nav_agent/mujoco_sim/scripts/run_stage2.sh`
- Test: `nav_agent/sem_nav_ctr/src/holoagent_livox_converter/test/test_stage2_eval.py`
- Test: `nav_agent/mujoco_sim/tests/test_stage2_result.py`
- Test: `nav_agent/mujoco_sim/tests/test_run_stage2_script.py`

- [ ] **Step 1: Write failing gate and launcher tests**

Required gates are: clock monotonic/rate, real-time factor, lidar 8–12 Hz, IMU 180–220 Hz, camera 12–18 Hz, at least 2,500 finite points in every accepted scan, exact point counts, snapshot-zero or rolling-monotonic offsets, timestamps from the same simulated clock, sim-only calibration digest, exact localhost graph, `use_sim_time=true`, no physical process/import, exact-PID cleanup, and final zero command.

- [ ] **Step 2: Run RED**

Expected: evaluator and launcher do not exist.

- [ ] **Step 3: Implement atomic evidence lifecycle**

The evaluator writes `result.pending.json`. Postflight promotes it atomically to `result.json` only when evaluator exit is zero, bridge/converter/evaluator exact PIDs are gone, graph and isolation checks passed, and no motion endpoint remains. Passing output uses:

```json
{
  "stage": 2,
  "status": "PASS",
  "qualified_pass": "PASS_SYNTHETIC_LIVOX",
  "motion_enabled": false,
  "simulated_motion": false,
  "physical_motion": false,
  "first_failing_gate": null
}
```

- [ ] **Step 4: Implement the dedicated container boundary**

The launcher requires a dedicated container bound read-only/read-write as needed to this continuation worktree, with host network and IPC, domain 77, localhost-only CycloneDDS, and no PC2 address/device. It records the container image ID and mount source, sources the two explicit ROS overlays, builds the converter in `/tmp`, generates sim calibration, and graph-gates bridge/converter/evaluator before the bounded rate window. No generic `pkill` is permitted.

- [ ] **Step 5: Run GREEN and commit**

Run all Stage 2 and Stage 1 tests, shell syntax checks, Ruff, py_compile, clean colcon builds, and `git diff --check`.

### Task 7: Run the bounded Stage 2 integration

**Files:**
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/`

- [ ] **Step 1: Obtain explicit approval and launch headless MuJoCo**

Run `run_stage2.sh` only after operator approval. The script starts no real-robot process and keeps all DDS discovery on localhost.

- [ ] **Step 2: Inspect the first failure or passing evidence**

If a gate fails, preserve the run directory, report `first_failing_gate`, fix with TDD, and rerun. Do not weaken density, timing, graph, or cleanup gates to manufacture a pass.

- [ ] **Step 3: Verify the authoritative result**

Require `PASS_SYNTHETIC_LIVOX`, all gates true, finite metrics, matching host/container graphs, matching calibration digests, and passing postflight. Record exact scan rate, minimum/mean point count, offsets, timestamp skew, and real-time factor.

### Task 8: Review and handoff

- [ ] Run the complete test/build/static suite again.
- [ ] Review the source and evidence against every Stage 2 design clause.
- [ ] Commit the final reviewed implementation without generated evidence.
- [ ] Update `.omx/notepad.md` with the authoritative result directory and preserve Stage 3/4 dependency semantics.
