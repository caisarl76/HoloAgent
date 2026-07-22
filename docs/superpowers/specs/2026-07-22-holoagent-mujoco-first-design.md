# HoloAgent MuJoCo-First Commissioning Design

## Context

HoloAgent-0 must be commissioned on the workstation and prepared for a later
Unitree G1 PC2 handoff. Real-robot execution is intentionally deferred until
the same command, navigation, and safety paths pass in MuJoCo.

The current workstation already has:

- the HoloAgent repository and `holoagent-navagent:deps` Docker image;
- FSR-VLN data and an `icra_ic4f` HMSG graph;
- the Nav2 map that is byte-identical to PC2's active map;
- an established G1 MuJoCo runtime at
  `/home/jihun/work/GR00T-WholeBodyControl/.venv_sim`;
- a working G1 simulation controller in the neighboring GR00T/DualMap
  workspaces.

PC2 already has ROS 2 Humble, the Unitree SDK, live G1 sensor topics, and clean
ARM64 `g1_move`/`g1_arm` builds under `robots/unitree/install_pc2`. Those
binaries must not be started during this simulation phase.

The workstation semantic-navigation source tree is incomplete: 19 regular
source/config files disappeared while build artifacts remained. The exact
files are preserved in `stash@{0}` and will be restored before simulation.

## Goals

1. Restore and verify the HoloAgent semantic command-to-pose path.
2. Drive a simulated Unitree G1 with Nav2 `/cmd_vel` commands.
3. Publish the ROS 2 topics expected by the HoloAgent navigation stack.
4. Validate semantic navigation, localization, path planning, and velocity
   generation without contacting G1 PC2.
5. Produce objective pass/fail evidence before preparing a no-motion PC2
   handoff.

## Non-Goals

- Sending `LocoClient.Move()` or arm commands to the physical G1.
- Starting `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node` on PC2.
- Treating perfect simulator odometry as proof that FastLIVO works.
- Rebuilding OVO/FSR-VLN maps from a real robot dataset during the first
  simulator milestone.
- Copying GR00T controller policies or robot assets into this repository.

## Selected Architecture

The implementation will use a repository-local HoloAgent adapter with the
existing GR00T MuJoCo runtime as a configured backend.

```text
HoloAgent container (ROS_DOMAIN_ID=77)
  AgentOS / semantic query / Nav2 / FastLIVO
        |                         ^
        | /cmd_vel                | ROS sensor topics
        v                         |
Host MuJoCo adapter (ROS_DOMAIN_ID=77)
  GR00T G1 controller + MuJoCo model
        |
        +-- /clock
        +-- /tf, /tf_static
        +-- /robot_odom
        +-- /livox/imu
        +-- /camera/color/image_raw + camera_info
        +-- /holoagent_sim/lidar_points (PointCloud2)
                                      |
                                      v
HoloAgent container converter
  PointCloud2 -> livox_ros_driver2/msg/CustomMsg
        |
        +-- /livox/lidar
```

The host adapter uses the existing `.venv_sim`, which can import both MuJoCo
and the system ROS 2 Python packages. The host does not currently have the
generated `livox_ros_driver2` Python messages, so a small converter runs in the
HoloAgent container where those message types are already installed. This
avoids copying container binaries onto the host or adding MuJoCo to the large
Docker image.

The adapter will not import or call `unitree_sdk2`. The physical robot's
control interface is therefore absent from the simulation data path.

## Components

### 1. Semantic Source Recovery

Restore only the missing files under `nav_agent/sem_nav_ctr/src` from
`stash@{0}`. Existing deployment scripts, generated configs, logs, and later
changes remain untouched. Verify the restored source against the stash blob
IDs, rebuild into `/tmp/navagent_sem_nav_*`, and rerun the container smoke
test.

### 2. MuJoCo G1 Bridge

Add a ROS 2 Python package under `nav_agent/mujoco_sim` with:

- validated YAML configuration;
- a GR00T G1 controller backend loaded from configurable paths;
- a `/cmd_vel` subscriber;
- finite-value validation and conservative command clamps;
- deterministic stepping and `/clock` publication;
- odometry, TF, IMU, camera, and raw simulated lidar publishers;
- headless operation by default;
- an optional viewer flag for operator inspection.

Default command limits are:

```text
linear x:  +/-0.22 m/s
linear y:   0.00 m/s (disabled initially)
yaw rate:  +/-0.30 rad/s
command timeout: 0.5 s, then force zero
```

The bridge must start with a stationary command and return to zero on timeout,
shutdown, invalid input, or simulation error.

### 3. Livox Message Converter

Add a ROS 2 Python node to the semantic simulation workspace. It consumes a
standard `sensor_msgs/msg/PointCloud2` and emits
`livox_ros_driver2/msg/CustomMsg` with:

- a consistent `timebase`;
- `point_num` matching the actual point array;
- non-zero, monotonic per-point `offset_time` values;
- finite XYZ coordinates;
- configurable reflectivity, line, tag, scan period, noise, and dropout.

The first implementation may use deterministic MuJoCo range rays. It must not
claim sensor fidelity beyond the configured model.

### 4. Test Scene and Configuration

Use the existing GR00T G1 model/controller through configuration variables:

- `HOLOAGENT_MUJOCO_PYTHON`
- `HOLOAGENT_G1_SIM_ROOT`
- `HOLOAGENT_G1_CONFIG_DIR`
- `HOLOAGENT_MUJOCO_SCENE`

Configuration validation fails before ROS startup when a required interpreter,
controller, model, or policy asset is missing. No workstation-specific path is
silently substituted.

The initial scene is a small static indoor world. Its purpose is deterministic
navigation and sensor-contract validation, not photorealistic reconstruction
of `icra_ic4f`.

### 5. Orchestration

Provide scripts that:

1. validate dependencies and safety flags;
2. start the host bridge headlessly on `ROS_DOMAIN_ID=77`;
3. start the container-side converter and HoloAgent components on the same
   domain;
4. run bounded checks with explicit timeouts;
5. stop all simulator sessions and publish a final zero velocity.

The scripts refuse to start when any real-motion flag is enabled or when a
local process named `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node` is
running. Simulation orchestration never connects to PC2; PC2 checks are a
separate, read-only handoff stage.

## Evaluation Stages

### Stage 0: Software and Semantic Recovery

- Restored files match their saved Git blobs.
- Skill registry validation passes.
- Semantic workspace builds cleanly.
- Container import/executable smoke checks pass.
- A text query produces one expected `/object_pose` with no motion publisher.

### Stage 1: MuJoCo Base Contract

- The headless G1 simulation remains stable for a bounded run.
- `/clock`, TF, `/robot_odom`, IMU, and camera topics have the expected types.
- A bounded `/cmd_vel` command moves only the simulated G1.
- The robot stops within the command-timeout window.

This stage may use perfect `/robot_odom`, but its result is labeled as a Nav2
integration check rather than a localization check.

### Stage 2: Synthetic Livox Contract

- `/livox/lidar` uses `livox_ros_driver2/msg/CustomMsg`.
- Lidar, IMU, and camera timestamps advance consistently.
- Lidar points contain valid, non-constant offsets.
- Topic rate checks pass for a bounded interval.

### Stage 3: FastLIVO Mapping and Relocalization

- FastLIVO consumes synthetic sensors without perfect odometry masking the
  estimator.
- Offline mapping produces `mapping.txt`, `cloudGlobal.pcd`, and non-empty
  `keyframe_cloud/*.pcd`.
- Finalization produces a valid `keyframe_pose.txt`.
- Relocalization starts from the generated prior and remains bounded against
  MuJoCo ground truth.

### Stage 4: Full HoloAgent Navigation Loop

- A semantic query produces `/object_pose`.
- Nav2 accepts the goal and produces a path and bounded `/cmd_vel`.
- The simulated G1 approaches the goal within configured tolerance.
- Timeout and stop commands halt the simulated robot.
- Real Unitree motion executables remain absent from the process graph.

## Error Handling and Evidence

Every stage is bounded by a timeout and writes a machine-readable result under
`outputs/mujoco_holoagent/<run-id>/`. Results include:

- configuration and relevant commit IDs;
- command and topic contract checks;
- simulator start/end pose;
- maximum commanded velocities;
- estimator error when applicable;
- pass/fail status and the first failing gate;
- logs needed to reproduce the failure.

A later stage does not run after an earlier required gate fails. Cleanup is
idempotent and must not use broad process-kill patterns.

## PC2 Handoff

After Stage 4 passes, PC2 preparation remains no-motion:

- source `robots/unitree/install_pc2/setup.bash`;
- verify ARM64 executable linkage and the `enP8p1s0` Unitree interface;
- verify sensor topic mappings;
- configure the robot bridge without starting motion executables;
- repeat network/topic checks on a separate commissioning ROS domain.

Physical G1 movement requires a later explicit operator authorization, an
available emergency stop, and a separate strict readiness run.
