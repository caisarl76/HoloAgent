# HoloAgent MuJoCo-First Commissioning Design

## Context

HoloAgent-0 must be commissioned on the workstation and prepared for a later
Unitree G1 PC2 handoff. Real-robot execution is intentionally deferred until
the same command, navigation, and safety paths pass in MuJoCo.

The current workstation already has:

- the HoloAgent repository and `holoagent-navagent:deps` Docker image;
- FSR-VLN data and an `icra_ic4f` HMSG graph;
- the Nav2 map that is byte-identical to PC2's active real-building map;
- an established G1 MuJoCo runtime at
  `/home/jihun/work/GR00T-WholeBodyControl/.venv_sim`;
- a working G1 simulation controller in the neighboring GR00T/DualMap
  workspaces.

PC2 already has ROS 2 Humble, the Unitree SDK, live G1 sensor topics, and clean
ARM64 `g1_move`/`g1_arm` builds under `robots/unitree/install_pc2`. Those
binaries must not be started during this simulation phase.

The workstation recovery source originally lived only in mutable `stash@{0}`.
Its portable baseline is pinned to reachable commit
`ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8`. The stash diff lists 21 modified
paths, but the build-and-smoke closure contains 73 paths because stash diff is
not the same thing as the complete snapshot tree. The other 52 dependencies
were unchanged relative to the stash parent and therefore absent from
`git stash show`, even though the release commit removed them.

## Goals

1. Restore and verify the HoloAgent semantic command-to-pose path.
2. Drive a simulated Unitree G1 with Nav2 `/cmd_vel` commands.
3. Publish the ROS 2 topics expected by the HoloAgent navigation stack.
4. Validate semantic-query and simulator-navigation plumbing in explicitly
   frame-consistent gates, without claiming that the real-building HMSG is a
   semantic map of the simulated scene.
5. Evaluate FastLIVO against MuJoCo ground truth without making full visual
   convergence a prerequisite for the navigation-loop test.
6. Produce objective pass/fail evidence before preparing a no-motion PC2
   handoff.

## Non-Goals

- Sending `LocoClient.Move()` or arm commands to the physical G1.
- Starting `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node` on PC2.
- Treating perfect simulator odometry as proof that FastLIVO works.
- Treating a simulation-only semantic fixture as proof of FSR-VLN spatial
  accuracy.
- Rebuilding OVO/FSR-VLN maps for the simulated scene during this milestone.
- Copying GR00T controller policies or robot assets into this repository.

## Selected Architecture

The implementation will use a repository-local HoloAgent adapter with the
existing GR00T MuJoCo runtime as a configured backend. Every simulation
process uses all three of these settings:

```text
ROS_DOMAIN_ID=77
ROS_LOCALHOST_ONLY=1
use_sim_time=true
```

The host and container must use the same installed RMW implementation. The
container must use host networking and host IPC so localhost-only DDS and
shared-memory transport work across the boundary.

```text
HoloAgent container (domain 77, localhost-only DDS, simulated time)
  Stage 0: real FSR-VLN/HMSG query (real-building frame; observed only)
  Stage 4: sim semantic fixture + Nav2 (sim_map frame)
  FastLIVO + PointCloud2-to-Livox converter
        |                         ^
        | /cmd_vel                | ROS sensor topics
        v                         |
Host MuJoCo adapter (domain 77, localhost-only DDS, simulated time)
  GR00T G1 controller + MuJoCo model
        |
        +-- /clock
        +-- /tf, /tf_static
        +-- /robot_odom
        +-- /livox/imu
        +-- /camera/color/image_raw + /camera/color/camera_info
        +-- /holoagent_sim/lidar_points (PointCloud2)
                                      |
                                      v
HoloAgent container converter
  PointCloud2 -> livox_ros_driver2/msg/CustomMsg -> /livox/lidar
```

The host adapter uses the existing `.venv_sim`, which can import both MuJoCo
and the system ROS 2 Python packages. The host does not currently have the
generated `livox_ros_driver2` Python messages, so a small converter runs in the
HoloAgent container where those message types are installed. This avoids
copying container binaries onto the host or adding MuJoCo to the large Docker
image.

The adapter will not import or call `unitree_sdk2`. The physical robot's
control interface is absent from the simulation data path.

## Frame and Map Contract

The `icra_ic4f` HMSG graph and the current PC2 Nav2 occupancy map describe a
real building. The initial MuJoCo scene has different geometry. Their
coordinates must never be composed.

Stage 0 therefore runs the restored real HMSG query path in observation-only
mode and records its `/object_pose`; no Nav2 goal subscriber or velocity
publisher is active. Stage 4 uses a `sim_map` occupancy grid generated from the
known MuJoCo scene geometry. A simulation-only semantic fixture maps a fixed
set of test phrases to prevalidated free-space poses in `sim_map`. Its node,
configuration, and result metadata are named `sim_fixture` so evidence cannot
be mistaken for real FSR-VLN spatial validation.

This selects the simulator-map-plus-mocked-poses strategy. The occupancy grid
is derived from known scene geometry rather than Stage 3 estimator output so a
sensor-estimation failure cannot block the independent navigation-loop test.
Stage 3 output may be compared with `sim_map`, but it is never substituted
without an explicit alignment check.

The real-building map is prohibited from the Stage 4 process graph. The
orchestrator verifies the loaded map path and SHA-256 digest before Nav2
activation. A future true semantic simulation test would require a new HMSG
whose poses are explicitly aligned to `sim_map`; it is outside this milestone.

## Components

### 1. Semantic Source Recovery

Restore the exact 73-path, build-driven manifest with closed mixed
provenance: 72 baseline entries use reachable commit
`ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8`; the one documentation-only
`nav_agent/README.md` uses reviewed commit
`d862782b3661e2f2cf155d6e006f11c27063a6b0` and blob
`291eea5e1969497760c5c48c62a4a04623a09eb6` with Git mode `100644` so its
later MuJoCo/PC2 handoff links are preserved. No other override is permitted:

```text
fsr_vln/config/semantic_scene_reconstruction_hm3d.yaml
fsr_vln/config/semantic_scene_reconstruction_ic3f.yaml
fsr_vln/config/semantic_scene_reconstruction_ic4f.yaml
fsr_vln/config/semantic_scene_reconstruction_ic7f.yaml
fsr_vln/config/semantic_scene_reconstruction_scannet.yaml
fsr_vln/config/semantic_scene_reconstruction_sh3f.yaml
fsr_vln/config/visualize_graph.yaml
fsr_vln/config/visualize_query_graph_icra_hm3d_bench.yaml
fsr_vln/config/visualize_query_graph_icra_ic3f.yaml
fsr_vln/config/visualize_query_graph_icra_ic4f.yaml
fsr_vln/config/visualize_query_graph_icra_ic7f.yaml
fsr_vln/config/visualize_query_graph_icra_sh3f.yaml
fsr_vln/environment.yaml
fsr_vln/memory/hmsg/data/__init__.py
fsr_vln/memory/hmsg/dataloader/generic.py
fsr_vln/memory/hmsg/dataloader/hm3dsem.py
fsr_vln/memory/hmsg/dataloader/horizon.py
fsr_vln/memory/hmsg/dataloader/__init__.py
fsr_vln/memory/hmsg/dataloader/iphone.py
fsr_vln/memory/hmsg/dataloader/replica.py
fsr_vln/memory/hmsg/dataloader/scannet.py
fsr_vln/memory/hmsg/eval/hm3dsem_evaluator.py
fsr_vln/memory/hmsg/eval/__init__.py
fsr_vln/memory/hmsg/graph/floor.py
fsr_vln/memory/hmsg/graph/graph.py
fsr_vln/memory/hmsg/graph/__init__.py
fsr_vln/memory/hmsg/graph/navigation_graph.py
fsr_vln/memory/hmsg/graph/object.py
fsr_vln/memory/hmsg/graph/room.py
fsr_vln/memory/hmsg/graph/view.py
fsr_vln/memory/hmsg/__init__.py
fsr_vln/memory/hmsg/labels/class_id_colors.json
fsr_vln/memory/hmsg/labels/final_label.csv
fsr_vln/memory/hmsg/labels/HM3D_CountsOfObjectTypes.csv
fsr_vln/memory/hmsg/labels/imagenet21k.csv
fsr_vln/memory/hmsg/labels/__init__.py
fsr_vln/memory/hmsg/labels/label_constants.py
fsr_vln/memory/hmsg/labels/scannet200.csv
fsr_vln/memory/hmsg/labels/scannet20.csv
fsr_vln/memory/hmsg/utils/clip_utils.py
fsr_vln/memory/hmsg/utils/constants.py
fsr_vln/memory/hmsg/utils/eval_utils.py
fsr_vln/memory/hmsg/utils/graph_utils.py
fsr_vln/memory/hmsg/utils/__init__.py
fsr_vln/memory/hmsg/utils/label_feats.py
fsr_vln/memory/hmsg/utils/llm_utils.py
fsr_vln/memory/hmsg/utils/long_query_eval_utils.py
fsr_vln/memory/hmsg/utils/metric.py
fsr_vln/memory/hmsg/utils/sam_utils.py
fsr_vln/perception/models/__init__.py
fsr_vln/perception/models/sam_clip_feats_extractor.py
fsr_vln/setup.py
nav_agent/README.md
nav_agent/scripts/run_nav.sh
nav_agent/scripts/run_sem_nav.sh
nav_agent/scripts/run_sensors.sh
nav_agent/sem_nav_ctr/src/chat_loc_python/chat_loc_python/drobotc_g1.py
nav_agent/sem_nav_ctr/src/chat_loc_python/chat_loc_python/__init__.py
nav_agent/sem_nav_ctr/src/chat_loc_python/chat_loc_python/node_chat_loc_class.py
nav_agent/sem_nav_ctr/src/chat_loc_python/package.xml
nav_agent/sem_nav_ctr/src/chat_loc_python/setup.cfg
nav_agent/sem_nav_ctr/src/chat_loc_python/setup.py
nav_agent/sem_nav_ctr/src/g1_move/CMakeLists.txt
nav_agent/sem_nav_ctr/src/g1_move/package.xml
nav_agent/sem_nav_ctr/src/g1_move/src/getvel.cpp
nav_agent/sem_nav_ctr/src/g1_move/src/pubvel.cpp
nav_agent/sem_nav_ctr/src/goal_publisher/config/visualize_query_graph_demo.yaml
nav_agent/sem_nav_ctr/src/goal_publisher/goal_publisher/goal_pose_publisher.py
nav_agent/sem_nav_ctr/src/goal_publisher/goal_publisher/__init__.py
nav_agent/sem_nav_ctr/src/goal_publisher/package.xml
nav_agent/sem_nav_ctr/src/goal_publisher/resource/goal_publisher
nav_agent/sem_nav_ctr/src/goal_publisher/setup.cfg
nav_agent/sem_nav_ctr/src/goal_publisher/setup.py
```

This is deliberately not a restore of every path missing from the snapshot.
It contains the ROS semantic workspace plus the FSR-VLN modules/configuration
required by its build, import smoke test, and fixed query. Pre-release trees
such as `nav_agent/humble_localization_nav2/` remain excluded. If a build or
smoke gate identifies another dependency, add only that evidenced dependency
to this manifest and verify it against the same pin.

Recovery fails rather than overwriting a path that has appeared since review.
Each restored regular file or symlink must match its pinned Git blob. Rebuild
into `/tmp/navagent_sem_nav_*` and rerun the container smoke test. Unlisted
outputs, generated configs, logs, and unrelated dirty-worktree changes remain
untouched.

Restored files are never edited to accommodate the workstation. In particular,
`chat_loc_python/setup.py` contains a robot-specific build-script interpreter.
If that value becomes active in the container build, generate a documented
copy under the isolated `/tmp` build overlay, patch only the overlay, record
its diff, and re-verify the restored working-tree blob after the build.

### 2. MuJoCo G1 Bridge

Add a ROS 2 Python package under `nav_agent/mujoco_sim` with:

- validated YAML configuration;
- a GR00T G1 controller backend loaded from configurable paths;
- a `/cmd_vel` subscriber;
- finite-value validation and conservative command clamps;
- deterministic stepping and `/clock` publication from MuJoCo model time;
- odometry, TF, IMU, camera, and raw simulated lidar publishers;
- headless operation by default;
- an optional viewer flag for operator inspection.

Default command limits are:

```text
linear x:       +/-0.22 m/s
linear y:         0.00 m/s (disabled)
yaw rate:       +/-0.30 rad/s
command timeout:   0.50 simulated seconds, then force zero
```

The bridge starts stationary and returns to zero on timeout, shutdown, invalid
input, or simulation error. MuJoCo model time is the only ROS clock authority.
All queryable consuming nodes, including Nav2 and FastLIVO, must report
`use_sim_time=true` before activation. Nav2 Humble's internal BT client nodes do
not service their advertised parameter APIs, so they are verified by their live
`/clock` subscription endpoints plus the pinned runtime configuration instead.
The orchestrator records the real-time factor so slow policy inference changes
wall-clock duration without changing controller semantics.

Default publication rates are IMU 200 Hz, odometry 50 Hz, camera 15 Hz, and
lidar 10 Hz in simulated time.

### 3. Livox Message Converter

Add a ROS 2 Python node to the semantic simulation workspace. It consumes a
standard `sensor_msgs/msg/PointCloud2` and emits
`livox_ros_driver2/msg/CustomMsg` with:

- a consistent `timebase`;
- `point_num` matching the actual point array;
- finite XYZ coordinates;
- configurable reflectivity, line, tag, scan period, noise, and dropout;
- per-point `offset_time` values that reflect actual acquisition time.

Two explicit acquisition modes are supported. `snapshot` ray-casts every
point at one MuJoCo time and sets every offset to zero. `rolling` advances the
sampling pose across the configured scan period and emits monotonic offsets
for those actual sample times. Fabricated non-zero offsets are forbidden.

The first implementation may use deterministic MuJoCo range rays. It must not
claim sensor fidelity beyond the configured model.

### 4. Test Scene and Sensor Configuration

Use the existing GR00T G1 model/controller through configuration variables:

- `HOLOAGENT_MUJOCO_PYTHON`
- `HOLOAGENT_G1_SIM_ROOT`
- `HOLOAGENT_G1_CONFIG_DIR`
- `HOLOAGENT_MUJOCO_SCENE`

Configuration validation fails before ROS startup when a required interpreter,
controller, model, or policy asset is missing. No workstation-specific path is
silently substituted.

The initial scene is a textured, static indoor world with non-degenerate planar
and corner geometry. Its purpose is deterministic navigation and sensor-contract
validation, not photorealistic reconstruction of `icra_ic4f`.

A sim-specific FastLIVO YAML is generated from the same scene/sensor mounting
configuration used by the bridge. It contains the exact lidar-to-IMU transform,
lidar-to-camera `Rcl`/`Pcl`, camera intrinsics and image dimensions, topic names,
and simulated sensor rates. Existing real-rig calibration values are forbidden
in a simulation run. The generated values and their source digest are stored
with the evidence.

### 5. Simulation Navigation Configuration

Stage 4 loads only the simulator-native occupancy grid and the `sim_fixture`
phrase-to-pose mapping. Every fixture pose is checked against the occupancy
grid, inflation radius, and world bounds before Nav2 starts.

The Nav2 controller is configured for non-holonomic motion. Preflight requires
`min_vel_y=0.0`, `max_vel_y=0.0`, no lateral-velocity samples, and a differential
or otherwise non-holonomic motion model. A controller configuration capable of
commanding lateral motion is a hard failure rather than something the adapter
silently clamps.

ROS 2 Humble does not service the embedded global/local costmap parameter
requests until their parent planner/controller lifecycle nodes are configured.
Stage 4 therefore configures—but does not activate—the four managed Nav2 nodes,
live-queries the map path and `use_sim_time` from every top-level and costmap
node, validates the pinned map/runtime digests, and only then asks the lifecycle
manager to `RESUME` the configured stack. The semantic evaluator is not started
until that activation evidence has been written, so no navigation command can
precede the live contract check.

### 6. Orchestration and Isolation

Provide scripts that:

1. validate dependencies, safety flags, map/frame contracts, and RMW parity;
2. export `ROS_DOMAIN_ID=77` and `ROS_LOCALHOST_ONLY=1` for every host and
   container process;
3. assert that the container uses host networking and host IPC;
4. start the host bridge headlessly;
5. start the container converter and selected HoloAgent components;
6. verify the discovered ROS graph against a stage-specific allowlist from
   both host and container before publishing any non-zero command;
7. run bounded checks with explicit simulated-time and wall-time limits;
8. stop all simulator sessions and publish a final zero velocity.

The graph check records node names, publishers, subscribers, services, and
actions. Any unexpected node or motion-command endpoint fails closed. Local
process-name checks for `g1_pubvel_node`, `g1_pubmove_node`, and
`g1_pubcmd_node` remain as defense in depth, but they are not the isolation
boundary.

Simulation configuration contains no PC2 address, physical control interface,
or Unitree channel. PC2 is not contacted during these stages. Localhost-only
DDS makes PC2's ROS domain irrelevant even if it also uses domain 77.

## Quantitative Default Gates

Thresholds live in a versioned evaluation YAML and are copied into each run
directory. Changing one creates a distinct run configuration; it must not be
edited after a run.

| Gate | Default pass threshold |
|---|---|
| Clock | strictly monotonic; at least 50 updates/simulated second |
| Mean real-time factor | at least 0.25 after a 2 s warm-up |
| IMU rate | 180-220 Hz over 10 simulated seconds |
| Odometry rate | 40-60 Hz over 10 simulated seconds |
| Camera rate | 12-18 Hz over 10 simulated seconds |
| Lidar rate | 8-12 Hz over 10 simulated seconds |
| Lidar density | 3,072 configured rays and at least 2,500 finite points in every accepted scan |
| Stationary drift | at most 0.05 m over 5 simulated seconds |
| Bounded motion | 0.08-0.30 m forward displacement for 0.10 m/s over 2 simulated seconds |
| Command clamps | `abs(x)<=0.22`, `y==0`, `abs(yaw)<=0.30` |
| Timeout stop | zero command within 0.60 simulated seconds; settle below 0.03 m/s within 2.0 s, then remain below 0.03 m/s for 1 s |
| LIO estimate | translation RMSE at most 0.50 m, maximum error at most 1.50 m, yaw RMSE at most 10 degrees over 30 simulated seconds |
| Nav2 goal | position error at most 0.35 m and yaw error at most 15 degrees within 90 simulated seconds, with no collision |

Each bounded test also has a wall-time limit equal to four times its simulated
duration plus a 30-second startup allowance. Falling below the real-time-factor
gate fails with a performance reason rather than appearing as a navigation
timeout.

## Evaluation Stages

### Stage 0: Software and Semantic Recovery

- The durable recovery branch resolves to the pinned commit.
- All 73 restored paths match their saved Git blobs: 72 from
  `ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8` and only
  `nav_agent/README.md` from
  `d862782b3661e2f2cf155d6e006f11c27063a6b0`.
- Skill registry validation passes.
- Semantic workspace builds cleanly in `/tmp`.
- Container import/executable smoke checks pass.
- A fixed text-query fixture produces an expected finite `/object_pose` in the
  real HMSG `map` frame while no Nav2 goal consumer or motion publisher exists.

This validates the FSR-VLN/HMSG query interface only. It does not validate the
pose against the MuJoCo scene or its occupancy map.

### Stage 1: MuJoCo Base Contract

- The headless G1 simulation passes the clock, real-time-factor, rate,
  stationary-drift, motion, clamp, and timeout thresholds.
- `/clock`, TF, `/robot_odom`, IMU, camera, and camera-info topics have the
  expected types and frames.
- Every active node reports `use_sim_time=true`.
- A bounded `/cmd_vel` command moves only the simulated G1.

This stage may use perfect `/robot_odom`; its result is labeled
`PASS_SIM_ODOM`, not a localization pass.

### Stage 2: Synthetic Livox Contract

- `/livox/lidar` uses `livox_ros_driver2/msg/CustomMsg`.
- Lidar, IMU, and camera timestamps advance from the same simulated clock.
- `snapshot` scans contain only zero offsets, or `rolling` scans contain
  monotonic offsets bounded by the configured scan period.
- Point counts, finite-coordinate checks, and topic-rate gates pass.
- Each accepted scan contains at least 2,500 finite points from the configured
  3,072-ray pattern; an under-density scan is a hard failure rather than a
  silently starved FastLIVO input.
- The generated sim extrinsics/intrinsics match the bridge configuration.

### Stage 3: Estimator Evaluation

Stage 3 is an evaluation branch, not a prerequisite for Stage 4.

The required estimator gate is LIO-only with `common.img_en: 0`, a mode already
supported by the repository's FastLIVO implementation. It must consume the
synthetic lidar and IMU without perfect odometry masking the estimator and meet
the numeric LIO error threshold. If mapping/finalization is exercised, its
artifacts must include non-empty `mapping.txt`, `cloudGlobal.pcd`,
`keyframe_cloud/*.pcd`, and `keyframe_pose.txt`.

Full LIVO with `common.img_en: 1` is a promotion test using the textured scene
and sim-specific camera calibration. If it converges and meets the same error
gate, record `PASS_FULL_LIVO`. If LIO passes but photometric alignment does not,
record `PASS_LIO_ONLY` plus the first LIVO failure; this does not block Stage 4.
If even LIO fails, record `FAIL_ESTIMATOR` and continue only with Stage 4's
explicit simulator-ground-truth localization path.

### Stage 4: Frame-Consistent HoloAgent Navigation Plumbing

- Nav2 loads the verified simulator-native occupancy map in `sim_map`.
- The simulation-only semantic fixture converts a fixed text query to a
  prevalidated free-space `/object_pose` in `sim_map`.
- Nav2 accepts the goal and produces a path and bounded `/cmd_vel`.
- The simulated G1 meets the numeric goal and collision gates.
- Timeout and stop commands meet the stop gate.
- DDS graph evidence contains only allowlisted localhost simulation nodes and
  endpoints.
- Real Unitree motion executables and `unitree_sdk2` remain absent from the
  process/import graph.

The result is labeled `PASS_SIM_SEMANTIC_PLUMBING`. It does not claim that the
real `icra_ic4f` semantic poses are correct in simulation.

## Stage Dependencies

Stage 0 is required for restored HoloAgent software, Stage 1 for motion, and
Stage 2 for the Livox contract. Stage 3 evaluates localization independently.
Stage 4 requires Stages 0-2 but intentionally does not require Stage 3, because
it may use simulator-ground-truth localization and the simulator-native map.

## Error Handling and Evidence

Every stage is bounded and writes a machine-readable result under
`outputs/mujoco_holoagent/<run-id>/`. Results include:

- configuration, map/sensor digests, and relevant commit IDs;
- isolation environment, RMW implementation, container network/IPC mode, and
  ROS graph snapshots from host and container;
- `use_sim_time` values and observed topic rates;
- simulator start/end pose, real-time factor, and collision count;
- maximum commanded velocities and stop latency;
- estimator RMSE and maximum error when applicable;
- pass/fail status, qualified pass label, and first failing gate;
- logs needed to reproduce the failure.

A dependent stage does not run after a required dependency fails. Optional
promotion failures are recorded without erasing a lower qualified pass.
Cleanup is idempotent and must not use broad process-kill patterns.

## PC2 Handoff

After Stage 4 passes, PC2 preparation remains no-motion:

- source `robots/unitree/install_pc2/setup.bash`;
- verify ARM64 executable linkage and the `enP8p1s0` Unitree interface;
- verify sensor topic mappings;
- configure the robot bridge without starting motion executables;
- repeat network/topic checks on a separate commissioning ROS domain.

Physical G1 movement requires a later explicit operator authorization, an
available emergency stop, and a separate strict readiness run.
