# HoloAgent-0 Workstation and PC2 Fail-Closed Setup Design

## Decision

HoloAgent-0 will be commissioned in two deliberately separate planes:

1. The workstation is the HoloAgent control and validation plane. AgentOS,
   OpenClaw, HoloAgent skills, OVO/FSR-VLN, chatbot configuration, Nav2, and
   MuJoCo run here. MuJoCo is the only motion backend.
2. Unitree G1 PC2 is a sensor-only plane during this milestone. It may expose
   camera, lidar, and IMU data and produce diagnostic evidence, but it must not
   run AgentOS, an HTTP-to-ROS control bridge, Nav2, or any Unitree motion
   executable.

The user approved this architecture on 2026-07-29 after the MuJoCo Stage 1-4
validation and the read-only workstation/PC2 audit.

## Current Evidence

The implementation branch starts from commit
`2368a78f6568a2293b27f4a290c2c33d1de4a099`, which contains the Stage 1-4
MuJoCo work. Its baseline test suite reports 196 passing tests.

The existing evidence establishes:

- Stage 2 passed the sensor/topic/graph contract.
- Stage 3 passed its sensor, build, and graph gates, but correctly reported a
  qualified estimator failure rather than overstating LIO accuracy.
- Stage 4 passed all 14 semantic-plumbing and navigation gates.
- PC2 is an ARM64 ROS 2 Humble machine with the Unitree C++ overlay and a
  connected Intel RealSense D435i.
- PC2 advertises native `/utlidar/cloud_livox_mid360` as
  `sensor_msgs/msg/PointCloud2` and `/utlidar/imu_livox_mid360` as
  `sensor_msgs/msg/Imu`, but neither produced a sample during two bounded
  passive checks.
- PC2 does not currently publish `/livox/lidar`, `/livox/imu`, or
  `/camera/color/image_raw`.
- PC2 has `realsense2_camera`, but it does not have the repository's FastLIVO,
  Nav2, services, Livox driver, ZED wrapper, or chatbot overlays installed.
- Exact process-name checks found no `g1_pubvel_node`, `g1_pubmove_node`, or
  `g1_pubcmd_node` process before or after the PC2 audits.

Two repository paths are explicitly unsafe for physical deployment in their
current form:

- `agentic_robot/agentOS/run_dameon/run_g1_background_daemon.py` starts the
  `ctl` group by default, and `robots/unitree/scripts/run_ctl.sh` starts the
  Unitree arm and base executables.
- `agentic_robot/services/src/robot_bridge` binds HTTP to `0.0.0.0`, performs
  no authentication or authorization, and translates requests directly into
  navigation and arm ROS messages.

Neither path is part of this setup.

## HoloAgent-0 Feature Coverage

The repository introduction identifies four HoloAgent-0 capabilities. This
design makes their setup status explicit:

| Capability | Workstation setup and proof | PC2 role |
| --- | --- | --- |
| OVO-accelerated FSR-VLN semantic mapping | Validate imports, pinned assets, OVO configuration, HMSG graph, and an observation-only semantic query | None during this milestone |
| Doubao chatbot speech interaction | Create an isolated Python 3.10 environment, install declared dependencies, validate device/configuration without printing secrets, and provide a bounded configuration smoke test | D435i is unrelated; audio hardware/API execution remains a separately reported external gate |
| AgentOS Harness adapted to OpenClaw | Install OpenClaw in a user-local prefix, keep its gateway loopback-only, validate the HoloAgent skill registry, and run deterministic offline DAG planning | None |
| Skill/Blueprint isolation and background triggering | Validate all five repository skills, exercise every motion-capable helper only with `--dry-run`, and prove the daemon/control groups are absent | Sensor-only preflight; no skills or daemon |

The setup report must distinguish `PASS`, `FAIL`, and qualified readiness such
as `READY_CONFIG_REQUIRED`. Missing Doubao credentials cannot be reported as a
functional speech pass, and inactive PC2 lidar cannot be reported as a sensor
stream pass.

## Goals

1. Make HoloAgent-0 reproducibly installable and auditable on the workstation.
2. Add a deterministic AgentOS dry-run that does not require an LLM client or
   make a network request.
3. Validate the restored OVO/FSR-VLN semantic source and HMSG query path without
   composing real-building coordinates with the MuJoCo map.
4. Validate chatbot dependencies and configuration without exposing secrets or
   requiring a live speech/API call for the offline gate.
5. Re-run the validated MuJoCo motion, sensor, DDS, and semantic-navigation
   gates from one fail-closed readiness workflow.
6. Bring up and measure PC2 sensors without starting any motion or control
   process.
7. Store machine-readable, timestamped evidence and identify the first failing
   gate.

## Non-Goals

- Enabling physical base or arm motion.
- Starting any Unitree SDK motion client on PC2.
- Running `run_g1_background_daemon.py`, `run_ctl.sh`, `robot_bridge`, or
  `multi_robot_ctl` on PC2.
- Exposing OpenClaw or robot HTTP services beyond loopback.
- Treating Stage 3's degraded LIO result as estimator proof.
- Treating the Stage 4 semantic fixture as proof of FSR-VLN spatial accuracy.
- Converting PC2's native Mid360 `PointCloud2` to Livox `CustomMsg` before a
  real sample establishes its fields and timing semantics.
- Copying workstation x86_64 binaries, Python environments, or Docker layers to
  ARM64 PC2.

## Architecture

```text
Workstation (control and validation plane)
  OpenClaw CLI + loopback-only gateway
        |
        v
  AgentOS deterministic plan / HoloAgent skill registry
        |
        +-- dry-run HTTP descriptions only
        +-- observation-only FSR-VLN/HMSG query
        v
  MuJoCo Stage 1-4 orchestration
    ROS_DOMAIN_ID=77
    ROS_LOCALHOST_ONLY=1
    use_sim_time=true
        |
        +-- /cmd_vel -> simulated G1 only
        +-- simulated lidar/IMU/camera/clock/TF
        +-- timestamped evidence

PC2 (sensor-only plane)
  exact motion-process denylist
        |
        +-- D435i / realsense2_camera
        +-- native Mid360 topic discovery and passive capture
        +-- topic type/rate/field evidence
        v
  no AgentOS, no HTTP bridge, no Nav2, no Unitree motion executable
```

No ROS command graph crosses from the workstation to PC2 in this milestone.
Workstation simulation remains localhost-only. PC2 sensor commands are invoked
through a bounded SSH session that runs only an allowlisted sensor/readiness
script and repeats the exact motion-process check before and after every
operation.

## Components

### 1. Deterministic AgentOS Planning

`agentic_robot/agentOS/sandbox_test/long_horizon_text_runner.py` gains a
`--plan-file` input for an already materialized DAG. When `--plan-file` is
provided:

- the constructor does not instantiate `OpenAI` or `AzureOpenAI`;
- no API key or endpoint is required;
- the plan is parsed and passed through the existing normalization and virtual
  validation logic;
- `--dry-run` remains mandatory for the offline readiness gate;
- no HTTP request, ROS publish, or subprocess is permitted;
- the existing monitor, DAG, validation, and execution-result artifacts remain
  the output contract.

The normal text-to-LLM planning path remains available and unchanged. The CLI
rejects `--plan-file` without `--dry-run` so a stored plan cannot become an
unreviewed execution shortcut.

### 2. HoloAgent-0 Readiness Runner

A focused Python runner under `scripts/holoagent0_setup/` coordinates checks
and writes `outputs/holoagent0_setup/YYYYMMDDTHHMMSSZ/result.json`. It has no ROS
publisher and no Unitree SDK import. Each check is an argv array executed
without a shell; command output is bounded and secret values are redacted.

The workstation gates are:

1. repository commit and expected paths;
2. Python 3.10, ROS 2 Humble, MuJoCo, Docker image, and architecture checks;
3. OpenClaw version, doctor result, configuration presence, gateway bind, and
   authentication posture;
4. HoloAgent skill layout validation and dry-run helper checks;
5. deterministic AgentOS plan-file validation with networking unavailable;
6. OVO/FSR-VLN imports, configuration, data/checkpoint paths, HMSG graph counts,
   and observation-only fixed query;
7. chatbot dependency, audio-device, and redacted credential-name checks;
8. Stage 1, Stage 2, Stage 3, and Stage 4 evidence validation.

The runner accepts `--check-only` and `--run-mujoco`. `--check-only` never
starts a service. `--run-mujoco` delegates only to the existing Stage 1-4
scripts after rechecking localhost DDS and the motion-process denylist.

### 3. OpenClaw Installation and Isolation

OpenClaw is installed without root in its official user-local prefix. The
setup records the CLI version and installer source URL but not credentials.
The supported workstation Node version is checked before installation.

The gateway contract is:

- loopback bind only;
- authentication configured before any gateway start;
- no LAN or wildcard bind;
- no automatic startup during installation;
- `openclaw doctor` must complete before skill registration;
- the gateway is stopped at the end of a smoke run.

The offline AgentOS gate does not depend on the gateway. A missing OpenClaw
installation fails the OpenClaw gate without affecting the already validated
MuJoCo result labels.

### 4. OVO/FSR-VLN Validation

The readiness workflow uses the restored build-driven source set and existing
`icra_ic4f` data. It validates:

- OVO module and configuration imports;
- FSR-VLN HMSG graph modules and query utilities;
- checkpoint and dataset paths;
- non-empty floor, room, object, and view collections;
- one fixed text query producing exactly one finite `/object_pose` observation.

The query runs without Nav2, `/cmd_vel`, or a physical control subscriber.
Its coordinates remain in the real-building map frame and are never submitted
to the MuJoCo `sim_map` navigation stack.

### 5. Chatbot Environment and Configuration

The chatbot environment uses Python 3.10 and the dependencies declared in
`agentic_robot/chatbot/g1/pyproject.toml`. Setup produces a redacted report of:

- importability of `aiohttp`, `loguru`, `pyaudio`, `pydub`, and `websockets`;
- presence of an input and output audio device;
- presence, but never the value, of required provider configuration variables;
- successful parsing of the robot's JSON configuration;
- bounded startup in an explicit configuration-check mode that opens neither
  a microphone stream nor a network connection.

When credentials are absent, the gate returns `READY_CONFIG_REQUIRED` with the
missing variable names. A live Doubao speech/API pass is recorded only after
credentials are supplied and the user separately authorizes the external API
and audio test.

### 6. PC2 Sensor-Only Preflight

A Bash script under `robots/unitree/scripts/` is safe to copy to and run on
PC2. It uses `set -euo pipefail`, contains no `ros2 topic pub`, Unitree SDK
command, FIFO creation, tmux command, or Docker invocation, and performs:

1. exact `pgrep -ax` checks for the three prohibited motion executables;
2. architecture, ROS distribution, network-interface, disk, and memory checks;
3. D435i USB and `/dev/video*` inventory;
4. ROS package presence checks;
5. bounded native lidar/IMU topic type, publisher, sample, and rate checks;
6. bounded camera topic type, sample, dimensions, encoding, and rate checks;
7. a repeated exact motion-process check before exit.

PC2 sensor launch is a separate, explicit `--start-realsense` action. It starts
only `realsense2_camera` in a dedicated process group, records its PID, verifies
the resulting topic contract, and stops that process group before the script
returns. It never persists a service or tmux session.

The native Mid360 check is passive. If no sample arrives, the result is
`FAIL_LIDAR_INACTIVE`; the workflow does not activate Unitree SLAM, publish an
API request, or install a second driver automatically. Once a sample is
captured, its `PointField` schema, `point_step`, frame, timestamps, density, and
rate become the input to a separately reviewed compatibility design.

### 7. Evidence Model

Every run writes a result with:

- schema version and run label;
- UTC start/end timestamps and wall duration;
- source commit and relevant file/configuration SHA-256 digests;
- hostname, architecture, Python/ROS/MuJoCo/OpenClaw versions;
- safety environment values without secrets;
- ordered gates containing status, measurements, thresholds, and bounded log
  file paths;
- exact first failing gate;
- before/after motion-process checks;
- an explicit list of commands that were prohibited.

Allowed top-level labels are:

- `PASS_HOLOAGENT0_OFFLINE`
- `PASS_HOLOAGENT0_MUJOCO`
- `READY_CONFIG_REQUIRED`
- `PASS_PC2_SENSOR_INVENTORY`
- `PASS_PC2_CAMERA_ONLY`
- `PASS_PC2_SENSOR_STREAMS`
- `FAIL_OPENCLAW_VERSION`, `FAIL_AGENTOS_PLAN`, or another concrete
  `FAIL_` label derived from the first failing gate

`PASS_PC2_SENSOR_STREAMS` requires both camera and lidar/IMU samples. A topic
advertisement without messages is insufficient.

## Safety Contract

The following invariants are hard failures:

1. Workstation simulation processes do not all have `ROS_DOMAIN_ID=77` and
   `ROS_LOCALHOST_ONLY=1`.
2. Any Stage 1-4 graph contains an unexpected participant or a physical
   Unitree control endpoint.
3. Any exact motion-process check finds `g1_pubvel_node`, `g1_pubmove_node`, or
   `g1_pubcmd_node` on either machine.
4. `START_G1_PUBVEL` is not `0`, `G1_DRY_RUN` is not `1`, or
   `ALLOW_G1_MOTION` is not `0` in a workstation setup command.
5. A PC2 command contains `run_ctl.sh`, `run_g1_background_daemon.py`,
   `robot_bridge`, `multi_robot_ctl`, `ros2 topic pub`, or a Unitree SDK
   executable.
6. OpenClaw attempts a non-loopback bind or starts without authentication.
7. A dry-run AgentOS or skill helper attempts network, ROS publish, subprocess,
   or physical execution.
8. A secret value appears in stdout, logs, JSON evidence, or a Git-tracked
   file.

On failure, the orchestrator stops only processes it started, terminates the
simulator with a final zero command, stops the OpenClaw smoke gateway, records
the first failure, and exits non-zero. It never tries a less isolated fallback.

## Testing Strategy

Implementation follows test-driven development.

### Unit tests

- AgentOS plan-file parsing, mutual constraints, validation, and proof that the
  LLM client factory is not called.
- Evidence schema, ordered gate evaluation, first-failure selection, redaction,
  timeout behavior, and command denylisting.
- OpenClaw configuration inspection without gateway startup.
- OVO/FSR-VLN and chatbot check classification.
- PC2 preflight script static denylist and exact process matching.

### Integration tests

- Run deterministic AgentOS with networking removed and verify the expected
  artifacts and zero outgoing requests.
- Run the workstation check-only workflow in the unprivileged, network-disabled
  dependency container.
- Re-run the 196 MuJoCo unit tests.
- Re-run Stages 1-4 with localhost DDS and validate their result schemas.
- Run PC2 inventory and camera-only probes over SSH while checking prohibited
  processes before and after.

### Adversarial tests

- Reject malformed plans, unsupported skills/targets, duplicate node IDs,
  cyclic dependencies, and plan-file execution without `--dry-run`.
- Reject command arguments containing a prohibited executable even when the
  process list is otherwise clean.
- Reject wildcard gateway binds and unredacted credential-shaped values.
- Reject topic advertisement as a rate/sample pass.
- Kill or timeout each started child and verify cleanup is limited to recorded
  PIDs/process groups.

## Rollout and Acceptance Gates

### Phase A: Workstation offline setup

Acceptance requires skill validation, deterministic AgentOS artifacts, OVO and
HMSG checks, chatbot dependency/configuration classification, OpenClaw doctor,
and zero network/ROS/motion side effects. The result is
`PASS_HOLOAGENT0_OFFLINE` or `READY_CONFIG_REQUIRED` when only external
credentials/audio authorization remain.

### Phase B: Workstation MuJoCo setup

Acceptance requires fresh Stage 1 and Stage 2 passes, an honestly classified
Stage 3 result, and a fresh Stage 4 pass. The result is
`PASS_HOLOAGENT0_MUJOCO`. A Stage 3 estimator failure cannot be rewritten as a
pass and cannot poison Stage 4's simulator-native map.

### Phase C: PC2 sensor-only setup

Acceptance first requires `PASS_PC2_SENSOR_INVENTORY`. A bounded D435i launch
may then produce `PASS_PC2_CAMERA_ONLY`. Full `PASS_PC2_SENSOR_STREAMS` remains
unmet until native Mid360 lidar and IMU samples are captured and measured.
Every phase repeats the exact no-motion process checks.

### Phase D: Handoff

The handoff documents exact commands, evidence paths, installed versions,
qualified results, remaining credentials/hardware gates, and prohibited
commands. It explicitly states that physical motion is not commissioned.

## Implementation Plan Decomposition

This umbrella design will be implemented through three independently testable
plans, in order:

1. Workstation HoloAgent-0 offline readiness and deterministic AgentOS.
2. Workstation MuJoCo integration and consolidated evidence.
3. PC2 sensor-only preflight, bounded D435i launch, and handoff documentation.

The first plan can pass without PC2 availability. The second reuses the
validated Stage 1-4 implementation rather than rewriting it. The third cannot
claim full sensor streams until PC2 produces real Mid360 samples.
