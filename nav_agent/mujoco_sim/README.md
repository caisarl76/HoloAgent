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
and host IPC. Before the evaluator starts, the bridge-only ROS graph must be
byte-for-byte equivalent from the host and container views.

The bridge adapter imports only the configured direct GR00T runner. It disables
keyboard input, overrides stale policy paths with the checked release policies,
forces `CPUExecutionProvider`, and never enters the upstream viewer loop.

## Run

The launcher is bounded by the evaluator's simulated-time phase plan and wall
deadline. It records only the bridge PID and signals only that PID during
cleanup.

```bash
bash nav_agent/mujoco_sim/scripts/run_stage1.sh \
  nav_agent/mujoco_sim/config/stage1.yaml
```

Evidence is written to a new UTC-named directory under
`outputs/mujoco_holoagent/`. The directory includes validated config, artifact
digests, preflight results, host/container graph snapshots, bridge/evaluator
logs, the exact bridge PID, and `result.json`. A passing result contains:

```json
{"status": "PASS", "label": "PASS_SIM_ODOM", "first_failing_gate": null}
```

The evaluator runs a 2 s warm-up, 10 s stationary/rate window, clamp probe,
zero recovery, 2 s bounded motion at 0.10 m/s, command silence, and a one-second
post-timeout speed observation. Thresholds are versioned in `config/stage1.yaml`.
Contact counts are diagnostic only; expected foot-floor contacts are not treated
as Stage 1 collisions.

Stages 2–4 remain separate work: synthetic Livox, LIO/LIVO, and simulator-native
semantic Nav2 validation must not be inferred from a Stage 1 pass.
