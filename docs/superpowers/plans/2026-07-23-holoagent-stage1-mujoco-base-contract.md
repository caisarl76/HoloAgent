# HoloAgent Stage 1 MuJoCo Base Contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a localhost-isolated ROS 2 bridge that accepts bounded `/cmd_vel`, drives only the configured MuJoCo G1, publishes clock/pose/IMU/camera contracts, and produces objective `PASS_SIM_ODOM` evidence without importing Unitree SDK code.

**Architecture:** A new `holoagent_mujoco` ament-Python package owns pure configuration, command safety, scene generation, a Unitree-SDK-free adapter around GR00T's direct `run_mujoco_gear_wbc.py`, ROS message conversion, a deterministic stepping node, and a bounded evaluator. The runtime uses `/home/jihun/work/GR00T-WholeBodyControl/.venv_sim`, adds the already-installed Python 3.10 `onnxruntime` site-packages directory explicitly, and overrides the stale upstream `ft92.onnx`/`ft109.onnx` YAML entries with the release Balance/Walk policies. The bridge is the sole `/clock` authority and never imports `gear_sonic.utils.mujoco_sim.base_sim`, `unitree_sdk2`, or `unitree_sdk2py`.

**Tech Stack:** Python 3.10, ROS 2 Humble/rclpy, MuJoCo 3.8.1, NumPy, PyYAML, ONNX Runtime 1.23.2 CPU provider, PyTorch 2.6, pytest, ament_python, Bash.

---

## Backend Resolution and Non-Negotiable Constraints

- Use `/home/jihun/work/GR00T-WholeBodyControl/decoupled_wbc/sim2mujoco/scripts/run_mujoco_gear_wbc.py`, SHA-256 `b78dfb546ee250116b3853f96a12f82174aca248808da33caf199ec8e42f82fd`.
- Do not use `run_mujoco_gear_wbc_gait.py`: it creates 95 features × 6 history frames while both release policies require a 516-wide input.
- Use explicit Balance and Walk policies whose ONNX contracts are `[batch, 516] -> [batch, 15]`.
- Load ONNX Runtime from `/home/jihun/work/GR00T-WholeBodyControl/.venv_data_collection/lib/python3.10/site-packages`; do not install into or modify `.venv_sim`.
- Override policy inference to `CPUExecutionProvider`; do not inherit the runner's hard-coded `cuda:0` tensor creation.
- Generate the camera/test-scene XML under `/tmp`; set the MJCF mesh directory to the absolute configured mesh directory before writing it.
- Never import GR00T's `gear_sonic.utils.mujoco_sim.base_sim`, because it imports and initializes Unitree SDK transport.
- Every process exports `ROS_DOMAIN_ID=77`, `ROS_LOCALHOST_ONLY=1`, `ROS2CLI_DISABLE_DAEMON=1`, and uses `rmw_cyclonedds_cpp`.
- No PC2 address, Unitree network interface, `unitree_sdk2`, or physical motion executable is permitted in package code, config, environment, graph, or evidence.

## File Responsibilities

- `nav_agent/mujoco_sim/holoagent_mujoco/config.py`: immutable dataclasses, YAML loading, path/type/rate/frame validation, file digests.
- `nav_agent/mujoco_sim/holoagent_mujoco/command.py`: finite command validation, clamps, simulated-time timeout, fail-closed zero state.
- `nav_agent/mujoco_sim/holoagent_mujoco/scene.py`: temporary indoor MJCF generation and camera mounting.
- `nav_agent/mujoco_sim/holoagent_mujoco/backend.py`: configurable direct-runner adapter, policy overlay, deterministic MuJoCo stepping and snapshots.
- `nav_agent/mujoco_sim/holoagent_mujoco/ros_messages.py`: ROS message construction and quaternion/frame conversions.
- `nav_agent/mujoco_sim/holoagent_mujoco/bridge_node.py`: `/cmd_vel` subscriber, deterministic loop, `/clock`, TF, odometry, IMU, camera, camera-info, and applied-command publishers.
- `nav_agent/mujoco_sim/holoagent_mujoco/stage1_eval.py`: graph/use-sim-time/rate/motion/clamp/timeout evaluation and result JSON.
- `nav_agent/mujoco_sim/holoagent_mujoco/preflight.py`: environment, asset digest, import-graph, DDS and process checks before ROS startup.
- `nav_agent/mujoco_sim/config/stage1.yaml`: exact workstation backend paths, frames, rates, camera mount, command limits, and immutable thresholds.
- `nav_agent/mujoco_sim/scripts/run_stage1.sh`: exact-PID orchestration, wall-time bound, evidence capture, and idempotent cleanup.
- `nav_agent/mujoco_sim/tests/`: pure unit/contract tests; each production behavior is introduced only after its test fails correctly.

### Task 1: Package Skeleton and Fail-Closed Configuration

**Files:**
- Create: `nav_agent/mujoco_sim/package.xml`
- Create: `nav_agent/mujoco_sim/setup.py`
- Create: `nav_agent/mujoco_sim/setup.cfg`
- Create: `nav_agent/mujoco_sim/resource/holoagent_mujoco`
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/__init__.py`
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/config.py`
- Create: `nav_agent/mujoco_sim/config/stage1.yaml`
- Test: `nav_agent/mujoco_sim/tests/test_config.py`

- [ ] **Step 1: Write failing configuration tests**

Tests must prove the checked-in configuration loads; all required interpreter, runner, XML, YAML, policy, and extra-Python paths exist; rates are positive and no greater than the 200 Hz physics rate; `linear_y` is exactly zero; timeout is 0.50 simulated seconds; frames are distinct and non-empty; and missing/relative/non-finite/invalid values fail before ROS imports. Non-divisor rates such as the required 15 Hz camera use an accumulator scheduler rather than rounded step intervals.

```python
def test_checked_in_config_is_stage1_safe():
    cfg = load_config(CONFIG)
    assert cfg.runtime.ros_domain_id == 77
    assert cfg.runtime.ros_localhost_only is True
    assert cfg.command.max_linear_y == 0.0
    assert cfg.command.timeout_sim_sec == 0.50
    assert cfg.rates.imu_hz == 200
    assert cfg.rates.odom_hz == 50
    assert cfg.rates.camera_hz == 15

def test_missing_policy_fails_before_ros_start(tmp_path):
    raw = valid_raw_config()
    raw["backend"]["walk_policy"] = str(tmp_path / "missing.onnx")
    with pytest.raises(ConfigError, match="walk_policy"):
        load_mapping(raw)
```

- [ ] **Step 2: Run the tests and verify RED**

```bash
cd nav_agent/mujoco_sim
PYTHONPATH="$PWD" /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q tests/test_config.py
```

Expected: collection fails because `holoagent_mujoco.config` does not exist.

- [ ] **Step 3: Implement immutable configuration and package metadata**

The YAML must explicitly name `.venv_sim`, the direct runner, upstream G1 config/XML, release Balance/Walk policies, the ONNX Runtime site-packages overlay, `MUJOCO_GL=egl`, rates, frames, command limits, and every quantitative Stage 1 gate. `load_config()` resolves and validates every path and returns frozen dataclasses; no default may silently substitute a workstation path.

- [ ] **Step 4: Verify GREEN and package build**

```bash
PYTHONPATH="$PWD/nav_agent/mujoco_sim" \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_config.py
colcon build --base-paths nav_agent/mujoco_sim \
  --build-base /tmp/holoagent_stage1_build \
  --install-base /tmp/holoagent_stage1_install \
  --log-base /tmp/holoagent_stage1_log
```

Expected: configuration tests pass and one ament-Python package builds.

- [ ] **Step 5: Commit**

```bash
git add nav_agent/mujoco_sim
git commit -m "feat(sim): add validated Stage 1 configuration"
```

### Task 2: Simulated-Time Command Safety

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/command.py`
- Test: `nav_agent/mujoco_sim/tests/test_command.py`

- [ ] **Step 1: Write failing command tests**

Cover accepted commands, x/y/yaw clamps, disabled lateral motion, NaN/Inf fail-closed behavior, backward simulated time, exact timeout boundary, shutdown zero, and returned immutable values.

```python
def test_command_clamps_and_disables_lateral_motion():
    safety = CommandSafety(CommandLimits(0.22, 0.0, 0.30, 0.50))
    assert safety.accept(1.0, 1.0, -1.0, sim_time=2.0) == VelocityCommand(0.22, 0.0, -0.30)

def test_invalid_or_stale_command_returns_zero():
    safety = CommandSafety(CommandLimits(0.22, 0.0, 0.30, 0.50))
    safety.accept(0.1, 0.0, 0.0, sim_time=1.0)
    assert safety.accept(float("nan"), 0.0, 0.0, sim_time=1.1).is_zero
    assert safety.current(sim_time=1.61).is_zero
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_command.py
```

- [ ] **Step 3: Implement the minimal pure state machine**

`accept()` stores only validated clamped values. Invalid input immediately replaces state with zero. `current()` returns zero when `sim_time - last_valid_time >= timeout_sim_sec`, when simulated time goes backward, or after `shutdown()`.

- [ ] **Step 4: Verify GREEN and commit**

```bash
git add nav_agent/mujoco_sim/holoagent_mujoco/command.py \
  nav_agent/mujoco_sim/tests/test_command.py
git commit -m "feat(sim): enforce fail-closed velocity commands"
```

### Task 3: Temporary Indoor Scene and Camera Contract

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/scene.py`
- Test: `nav_agent/mujoco_sim/tests/test_scene.py`

- [ ] **Step 1: Write failing XML transformation tests**

Use a minimal fixture MJCF. Assert absolute meshdir rewriting, one named camera attached to `torso_link`, checker/textured floor retention, static wall/corner geoms, no network/Unitree element, deterministic bytes, and refusal to overwrite a non-generated file.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_scene.py
```

- [ ] **Step 3: Implement deterministic scene generation**

Implement `generate_scene(base_xml: Path, runtime_dir: Path, scene: SceneConfig) -> GeneratedScene`. Generate under the configured `/tmp/holoagent_mujoco_stage1` runtime directory. Preserve robot assets, use absolute meshdir, add a fixed `head_camera`, and add bounded floor/wall/corner geometry with stable names. Return the path plus SHA-256.

- [ ] **Step 4: Verify the real generated scene loads headlessly**

```bash
MUJOCO_GL=egl PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_sim/bin/python -c \
  "from pathlib import Path; import mujoco; from holoagent_mujoco.config import load_config; from holoagent_mujoco.scene import generate_scene; c=load_config(Path('nav_agent/mujoco_sim/config/stage1.yaml')); s=generate_scene(c.backend.xml, c.runtime.directory, c.scene); m=mujoco.MjModel.from_xml_path(str(s.path)); assert m.ncam == 1 and m.nsensor == 4; print(s.sha256)"
```

Expected: MuJoCo loads the generated scene; camera and four IMU sensors resolve.

- [ ] **Step 5: Commit**

```bash
git add nav_agent/mujoco_sim/holoagent_mujoco/scene.py \
  nav_agent/mujoco_sim/tests/test_scene.py
git commit -m "feat(sim): generate deterministic indoor G1 scene"
```

### Task 4: Unitree-SDK-Free GR00T Controller Adapter

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/backend.py`
- Test: `nav_agent/mujoco_sim/tests/test_backend.py`
- Test: `nav_agent/mujoco_sim/tests/test_import_boundary.py`

- [ ] **Step 1: Write failing adapter tests with fake runner/model**

Cover module loading from the configured direct runner, keyboard suppression, explicit XML/policy overrides, CPU ONNX provider, shape/finite command checks, balance-vs-walk selection, policy decimation, PD torque clipping, monotonic `data.time`, snapshot fields, zero-on-close, and no imports whose names start with `unitree_sdk2` or `unitree_sdk2py`.

```python
def test_source_has_no_unitree_sdk_imports():
    package = Path(__file__).parents[1] / "holoagent_mujoco"
    text = "\n".join(path.read_text() for path in package.glob("*.py"))
    assert "unitree_sdk2" not in text
    assert "unitree_sdk2py" not in text
```

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_backend.py \
  nav_agent/mujoco_sim/tests/test_import_boundary.py
```

- [ ] **Step 3: Implement the adapter**

Load `run_mujoco_gear_wbc.py` with `importlib.util.spec_from_file_location`. Subclass its controller only to suppress keyboard input, override XML/Balance/Walk policy paths, and replace ONNX inference with CPU-provider output tensors. Implement one deterministic physics step locally, including the runner's balance/walk threshold, without invoking its viewer loop.

- [ ] **Step 4: Run a bounded backend smoke**

Instantiate the real backend, issue zero, step 20 times, assert `data.time` advances by 0.1 seconds, snapshot values are finite, and close. This is not the long Stage 1 loop.

- [ ] **Step 5: Verify GREEN and commit**

```bash
git add nav_agent/mujoco_sim/holoagent_mujoco/backend.py \
  nav_agent/mujoco_sim/tests/test_backend.py \
  nav_agent/mujoco_sim/tests/test_import_boundary.py
git commit -m "feat(sim): adapt the direct GR00T MuJoCo controller"
```

### Task 5: ROS Messages and Deterministic Bridge Loop

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/ros_messages.py`
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/bridge_node.py`
- Test: `nav_agent/mujoco_sim/tests/test_ros_messages.py`
- Test: `nav_agent/mujoco_sim/tests/test_bridge_core.py`

- [ ] **Step 1: Write failing conversion/scheduler tests**

Test MuJoCo `wxyz` to ROS `xyzw`, timestamp normalization, odometry pose/twist, IMU fields, image encoding/stride, camera matrix, TF frame IDs, exact 200/50/15 Hz simulated-time scheduling, and final zero on loop exceptions.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_ros_messages.py \
  nav_agent/mujoco_sim/tests/test_bridge_core.py
```

- [ ] **Step 3: Implement message builders and bridge node**

The node declares `use_sim_time=true`, subscribes only to `/cmd_vel`, publishes `/clock` every physics step, `/robot_odom`, `/tf`, `/tf_static`, `/livox/imu`, `/camera/color/image_raw`, `/camera/color/camera_info`, and `/holoagent_sim/applied_cmd_vel`. The main loop performs non-blocking ROS spinning, computes the simulated-time-safe command, steps exactly once, publishes due streams, measures wall time, and rate-limits without using ROS timers. Any callback, render, policy, or physics exception commands zero and exits nonzero.

- [ ] **Step 4: Verify GREEN and ROS package imports**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_ros_messages.py \
  nav_agent/mujoco_sim/tests/test_bridge_core.py
```

- [ ] **Step 5: Commit**

```bash
git add nav_agent/mujoco_sim/holoagent_mujoco/ros_messages.py \
  nav_agent/mujoco_sim/holoagent_mujoco/bridge_node.py \
  nav_agent/mujoco_sim/tests/test_ros_messages.py \
  nav_agent/mujoco_sim/tests/test_bridge_core.py
git commit -m "feat(sim): publish the Stage 1 ROS contract"
```

### Task 6: Machine-Readable Stage 1 Evaluator

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/stage1_eval.py`
- Test: `nav_agent/mujoco_sim/tests/test_stage1_eval.py`

- [ ] **Step 1: Write failing metric and phase tests**

Use synthetic samples to test strict clock monotonicity, rates in simulated time, RTF after warm-up, stationary drift, bounded motion displacement, applied-command clamps, timeout latency, one-second post-timeout speed, quaternion finiteness, first-failing-gate ordering, and qualified-pass JSON.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_stage1_eval.py
```

- [ ] **Step 3: Implement the evaluator**

Before non-zero commands, require exactly the allowlisted bridge/evaluator nodes, required topic types/endpoints, no `/object_pose`, no Nav2 node/action, no physical motion executable, and `use_sim_time=true` on both active nodes. Then run: 2 s warm-up, 10 s stationary/rate window, bounded clamp probe, 1 s zero recovery, 2 s at 0.10 m/s, command silence for timeout, and 1 s stopped-speed observation. Enforce wall limit `4 * planned_sim_duration + 30` seconds. Record MuJoCo contact counts as diagnostic evidence without treating expected foot-floor contacts as Stage 1 collisions.

- [ ] **Step 4: Verify GREEN and commit**

```bash
git add nav_agent/mujoco_sim/holoagent_mujoco/stage1_eval.py \
  nav_agent/mujoco_sim/tests/test_stage1_eval.py
git commit -m "feat(sim): evaluate quantitative Stage 1 gates"
```

### Task 7: Preflight, Orchestration, and Documentation

**Files:**
- Create: `nav_agent/mujoco_sim/holoagent_mujoco/preflight.py`
- Create: `nav_agent/mujoco_sim/scripts/run_stage1.sh`
- Create: `nav_agent/mujoco_sim/README.md`
- Test: `nav_agent/mujoco_sim/tests/test_preflight.py`
- Test: `nav_agent/mujoco_sim/tests/test_run_stage1_script.py`

- [ ] **Step 1: Write failing safety/orchestration tests**

Test rejection of wrong domain/localhost/RMW, missing runtime modules/assets, unexpected digests when pins are enabled, forbidden SDK modules or physical-interface settings, unsafe process names, existing run directory, non-finite thresholds, and cleanup that targets only recorded PIDs.

- [ ] **Step 2: Verify RED**

```bash
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_preflight.py \
  nav_agent/mujoco_sim/tests/test_run_stage1_script.py
```

- [ ] **Step 3: Implement fail-closed launcher**

The script exports the exact isolation environment and merged Python path, allocates a unique evidence directory, runs preflight, starts only the bridge by exact PID, runs the evaluator foreground, sends SIGINT only to that PID in an idempotent trap, verifies it stopped, and writes `result.json`, logs, config/digests, host/container graph snapshots, and first-failing-gate evidence. Preflight also requires the existing HoloAgent container to use host networking/IPC, verifies its CycloneDDS RMW, and confirms the same localhost-only graph is visible from host and container before a non-zero command. The script never uses broad `pkill`, `killall`, or globs for cleanup.

- [ ] **Step 4: Verify GREEN, shell syntax, and docs**

```bash
bash -n nav_agent/mujoco_sim/scripts/run_stage1.sh
PYTHONPATH=nav_agent/mujoco_sim \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests/test_preflight.py \
  nav_agent/mujoco_sim/tests/test_run_stage1_script.py
```

- [ ] **Step 5: Commit**

```bash
git add nav_agent/mujoco_sim
git commit -m "feat(sim): orchestrate isolated Stage 1 evaluation"
```

### Task 8: Full Verification and Bounded Headless Evaluation

**Files:**
- Read: all Stage 1 source/config/tests
- Create at runtime: `outputs/mujoco_holoagent/<run-id>/`

- [ ] **Step 1: Run all unit tests and static checks**

```bash
PYTHONPATH=/home/jihun/work/GR00T-WholeBodyControl/.venv_data_collection/lib/python3.10/site-packages:$PWD/nav_agent/mujoco_sim:/opt/ros/humble/local/lib/python3.10/dist-packages:/opt/ros/humble/lib/python3.10/site-packages \
  /home/jihun/work/GR00T-WholeBodyControl/.venv_teleop/bin/python \
  -m pytest -q nav_agent/mujoco_sim/tests
python3 -m py_compile nav_agent/mujoco_sim/holoagent_mujoco/*.py
git diff --check
```

Expected: all tests pass, compilation succeeds, and no whitespace errors exist.

- [ ] **Step 2: Build into clean `/tmp` paths**

```bash
colcon build --base-paths nav_agent/mujoco_sim \
  --build-base /tmp/holoagent_stage1_verify_build \
  --install-base /tmp/holoagent_stage1_verify_install \
  --log-base /tmp/holoagent_stage1_verify_log
```

- [ ] **Step 3: Run the bounded headless loop with explicit approval**

```bash
ROS_DOMAIN_ID=77 ROS_LOCALHOST_ONLY=1 ROS2CLI_DISABLE_DAEMON=1 \
RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
bash nav_agent/mujoco_sim/scripts/run_stage1.sh \
  nav_agent/mujoco_sim/config/stage1.yaml
```

Expected required gates:

- strict `/clock`, at least 50 samples/simulated second;
- mean RTF at least 0.25 after warm-up;
- IMU 180–220 Hz, odom 40–60 Hz, camera 12–18 Hz;
- stationary drift at most 0.05 m over 5 simulated seconds;
- 0.08–0.30 m forward displacement for 0.10 m/s over 2 simulated seconds;
- applied `abs(x)<=0.22`, `y==0`, `abs(yaw)<=0.30`;
- zero command within 0.60 simulated seconds and speed below 0.03 m/s for the following second;
- no unexpected graph endpoints, Nav2, physical motion processes, PC2 address, or Unitree SDK imports.

- [ ] **Step 4: Validate evidence and cleanup**

`result.json` must contain `stage: 1`, `status: PASS`, `qualified_pass: PASS_SIM_ODOM`, `motion_enabled: false`, `simulated_motion: true`, `first_failing_gate: null`, numeric metrics, config/backend digests, isolation settings, graph snapshots, and exact log paths. Verify the bridge PID is gone and no G1 physical motion executable exists.

- [ ] **Step 5: Final commit**

```bash
git add nav_agent/mujoco_sim
git commit -m "test(sim): verify the Stage 1 MuJoCo base contract"
```

## Self-Review Checklist

- Every Stage 1 design requirement maps to a task.
- Raw simulated lidar and Livox conversion are deliberately deferred to Stage 2.
- The real HMSG/map and semantic query path are absent from Stage 1.
- All rates and timeouts use simulated time; only the RTF and watchdog use wall time.
- Every non-zero command is preceded by the DDS graph allowlist gate.
- No restored Stage 0 blob or neighboring GR00T/DualMap file is edited.
- No placeholder, silent path substitution, physical interface, or broad process kill is present.
