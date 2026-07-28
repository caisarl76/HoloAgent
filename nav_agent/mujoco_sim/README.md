# HoloAgent MuJoCo-First Navigation Commissioning

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

## Commissioning stages

Each label is deliberately narrow:

| Stage | Required result | What it establishes |
|---|---|---|
| 1 | `PASS_SIM_ODOM` | base command, clock, odometry, sensor-rate, and stop contracts |
| 2 | `PASS_SYNTHETIC_LIVOX` | deterministic raw and Livox-format lidar contracts |
| 3 | `PASS_LIO_ONLY` or recorded `FAIL_ESTIMATOR` | FastLIVO quality against MuJoCo truth; failure does not block Stage 4 |
| 4 | `PASS_SIM_SEMANTIC_PLUMBING` | fixed phrase → `sim_fixture` → Nav2 → bounded MuJoCo motion |

Stage 4 uses a deterministic `sim_map` generated from the known MuJoCo room.
It prohibits the real-building map by exact path and validates the generated
YAML and PGM hashes before approval. The fixed `sim_fixture` pose is checked
against inflated free space. This proves frame-consistent HoloAgent navigation
plumbing, not FSR-VLN semantic accuracy in the synthetic scene.

Run later stages only in the dedicated no-device container described by the
commissioning design:

```bash
bash nav_agent/mujoco_sim/scripts/run_stage2.sh
bash nav_agent/mujoco_sim/scripts/run_stage3.sh
bash nav_agent/mujoco_sim/scripts/run_stage4.sh
```

Stage 3's estimator result must be retained even when it fails. Stage 4 is
allowed to continue with simulator ground-truth localization because its map
and navigation gate do not consume Stage 3 output.

## View results

Set a run directory explicitly so failed exploratory runs are not confused
with the authoritative result:

```bash
stage4_run=outputs/mujoco_holoagent/20260728T035826Z
```

Show the qualified label, every gate, and motion metrics:

```bash
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print("status:",r["status"]); print("label:",r["label"]); print("postflight:",r["postflight_pass"]); print("gates:"); [print(f"  {k}: {v}") for k,v in r["gates"].items()]; print("metrics:"); [print(f"  {k}: {v}") for k,v in r["metrics"].items()]' "$stage4_run/result.json"
```

The Stage 4 motion evidence is numeric and headless. Inspect the planned path
size, final error, command envelope, collision count, and stop behavior with:

```bash
python3 -c 'import json,sys; m=json.load(open(sys.argv[1]))["metrics"]; keys=("path_pose_count","position_error_m","yaw_error_deg","max_abs_cmd_x","max_abs_cmd_y","max_abs_cmd_yaw","max_scene_collision_count","zero_latency_sec","settle_latency_sec"); [print(f"{k}: {m[k]}") for k in keys]' "$stage4_run/result.json"
rg 'Received a goal|Reached the goal|Goal succeeded' "$stage4_run/nav2.log"
```

Open the exact simulator occupancy map on a graphical workstation:

```bash
xdg-open "$stage4_run/sim_map.pgm"
```

Inspect DDS parity and the approved graph:

```bash
diff -u "$stage4_run/host_graph.txt" "$stage4_run/container_graph.txt"
sed -n '1,220p' "$stage4_run/host_graph.txt"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(json.dumps(r["graph"]["node_contract"],indent=2)); print(json.dumps(r["graph"]["use_sim_time"],indent=2))' "$stage4_run/stage4_graph_ready.json"
```

After shutdown, both postflight graph files may contain only the ROS CLI's
built-in `/parameter_events` and `/rosout` topics; no nodes, services, or
actions may remain:

```bash
cat "$stage4_run/postflight_host_graph.txt"
cat "$stage4_run/postflight_container_graph.txt"
```

For Stage 2 sensor rates and point density:

```bash
stage2_run=outputs/mujoco_holoagent/20260724T055647Z
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["label"]); print(json.dumps(r["metrics"],indent=2,sort_keys=True))' "$stage2_run/result.json"
```

For the Stage 3 estimator error and its qualified or failed label:

```bash
stage3_run=outputs/mujoco_holoagent/20260727T023738Z
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["status"],r["label"],r["first_failing_gate"]); print(json.dumps(r["metrics"],indent=2,sort_keys=True))' "$stage3_run/result.json"
```

## HoloAgent-0 workstation scope

The repository-level HoloAgent-0 stack combines Embodied AgentOS, 3D spatial
memory, embodied skills, and FSR-VLN. For navigation, FSR-VLN/HMSG retrieves a
semantic target and publishes `/object_pose`; Nav2 and the robot adapter execute
the goal. Stage 0 validates the restored semantic query path. Stages 1–4 then
validate the simulator command, sensor, estimator, and navigation layers. See
`docs/user_guide/Intruduction.md` and `nav_agent/README.md` for the wider stack.

## PC2 no-motion handoff

`PASS_SIM_SEMANTIC_PLUMBING` authorizes preparation checks only. It does not
authorize a real G1 command. On PC2, keep the motion bridge disabled and use a
separate commissioning domain:

```bash
source robots/unitree/install_pc2/setup.bash
export ROS_DOMAIN_ID=78

pgrep -x g1_pubvel_node
pgrep -x g1_pubmove_node
pgrep -x g1_pubcmd_node
ip -brief link show enP8p1s0
```

All three `pgrep` commands must produce no output. Linkage and architecture
checks are read-only; apply them to the PC2-installed executables before any
launch:

```bash
file robots/unitree/install_pc2/g1_move/lib/g1_move/g1_pubvel_node
ldd robots/unitree/install_pc2/g1_move/lib/g1_move/g1_pubvel_node
```

Verify topic names and rates by subscribing only:

```bash
ros2 topic list -t
ros2 topic hz --window 20 /livox/lidar
ros2 topic hz --window 200 /livox/imu
ros2 topic hz --window 30 /camera/color/image_raw
```

Preview the semantic stack with every motion switch off:

```bash
START_G1_PUBVEL=0 \
G1_DRY_RUN=1 \
ALLOW_G1_MOTION=0 \
PRINT_SEM_NAV_COMMANDS=1 \
bash nav_agent/scripts/run_sem_nav.sh
```

Do not start `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node` during
this handoff. Physical movement requires a later explicit operator approval,
an available emergency stop, and a separate robot-mode readiness check.
