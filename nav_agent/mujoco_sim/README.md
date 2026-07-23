# HoloAgent Stage 1 MuJoCo Base Contract

This package validates the G1 navigation base contract in MuJoCo before any
real-robot execution. It accepts a conservative `/cmd_vel`, drives only the
pinned direct GR00T MuJoCo controller, and publishes simulated clock, odometry,
TF, torso IMU, head-camera image/info, applied command, and contact diagnostics.

The Stage 1 result is intentionally qualified as `PASS_SIM_ODOM`. Perfect
MuJoCo odometry proves ROS wiring, timing, command safety, and bounded simulated
motion; it does not prove localization quality or transfer to hardware.

## Safety boundary

Every process must use:

```text
ROS_DOMAIN_ID=77
ROS_LOCALHOST_ONLY=1
ROS2CLI_DISABLE_DAEMON=1
RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
MUJOCO_GL=egl
```

Preflight fails if those values differ, if physical-interface environment
variables or motion executables are present, if a pinned asset changes, or if
the configured runtime cannot import MuJoCo, ROS, PyTorch, and CPU ONNX Runtime.
The existing `holoagent_running` container must be running with host networking
and host IPC. The host and container must both provide `rmw_cyclonedds_cpp`.
Before any non-zero command is approved, the complete two-node ROS graph must
be byte-for-byte equivalent from the host and container views and match the
exact Stage 1 topic, service, action, and endpoint allowlists.

The preferred host prerequisite is the system package
`ros-humble-rmw-cyclonedds-cpp`. For a non-root verification environment, set
`HOLOAGENT_STAGE1_RMW_OVERLAY` to a directory containing packages extracted
under `opt/ros/humble`; the launcher validates the RMW library and adds both
ROS library directories explicitly. Preflight creates a localhost-only probe
participant and verifies the selected RMW before MuJoCo starts. ROS logs are
kept inside the run evidence directory.

The bridge adapter imports only the configured direct GR00T runner. It disables
keyboard input, overrides stale policy paths with the checked release policies,
forces `CPUExecutionProvider`, rejects transport modules loaded at import or
controller-construction time, and never enters the upstream viewer loop. The
five accepted artifact digests are immutable constants in the package; editing
the YAML digest manifest cannot authorize different runner or policy content.

## Run

The launcher is bounded by the evaluator's simulated-time phase plan and wall
deadline. It records the exact bridge and evaluator PIDs and signals only those
PIDs during cleanup.

```bash
bash nav_agent/mujoco_sim/scripts/run_stage1.sh \
  nav_agent/mujoco_sim/config/stage1.yaml
```

Evidence is written to a new UTC-named directory under
`outputs/mujoco_holoagent/`. The directory includes validated config, artifact
digests, preflight results, host/container graph snapshots, bridge/evaluator
logs, the exact bridge PID, and `result.json`. A passing result contains:

```json
{"status": "PASS", "label": "PASS_SIM_ODOM", "motion_enabled": false,
 "simulated_motion": true, "postflight_pass": true,
 "first_failing_gate": null}
```

The evaluator runs a 2 s warm-up, 10 s stationary/rate window, clamp probe,
zero recovery, 2 s bounded motion at 0.10 m/s, command silence, and a one-second
post-settle speed hold. Zero command must arrive within 0.60 simulated seconds;
the base then has at most 2.0 simulated seconds to settle below 0.03 m/s and
must remain below that limit for a full second. Thresholds are versioned in
`config/stage1.yaml`.
Contact counts are diagnostic only; expected foot-floor contacts are not treated
as Stage 1 collisions. A failed cleanup/postflight invalidates an evaluator
pass and rewrites the final result to `FAIL` with `first_failing_gate` set to
`postflight`.

The evaluator first writes `result.pending.json`. Only successful postflight
atomically creates the authoritative `result.json`; an interrupted run cannot
leave an authoritative PASS behind.

Stages 2–4 remain separate work: synthetic Livox, LIO/LIVO, and simulator-native
semantic Nav2 validation must not be inferred from a Stage 1 pass.
