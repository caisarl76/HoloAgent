# HoloAgent-0 Workstation and PC2 Fail-Closed Setup Design

## Decision

HoloAgent-0 is commissioned in two deliberately separate planes:

1. The workstation is the control and validation plane. AgentOS, OpenClaw,
   HoloAgent skills, OVO/FSR-VLN, chatbot configuration, Nav2, and MuJoCo run
   here. MuJoCo is the only motion backend in this milestone.
2. Unitree G1 PC2 is a sensor-only observation plane. The approved automation
   may inventory or sample camera, lidar, and IMU data, but it does not start
   AgentOS, an HTTP-to-ROS control bridge, Nav2, or a Unitree SDK motion client.

No physical base or arm motion is commissioned by this work.

This revision resolves the review findings from 2026-07-30 by making qualified
Stage 3 continuation explicit, separating the PC2 profiles, defining owned
process cleanup and continuous observation, pinning OpenClaw, closing the
AgentOS offline import/schema boundary, pinning the semantic closure and
assets, and replacing ad hoc result labels with a versioned evidence schema.

## Verified Baseline

The implementation branch starts from commit
`2368a78f6568a2293b27f4a290c2c33d1de4a099`, which contains the validated
MuJoCo Stage 1-4 work. The current pinned MuJoCo test selection passes; the
historical count of 196 tests is context only and is not an acceptance gate.

The existing evidence establishes:

- Stage 2 passed the synthetic sensor, topic, density, and DDS graph contract.
- Stage 3 passed its build, sensor, calibration, graph, clock, and isolation
  prerequisites but returned `FAIL_ESTIMATOR` on estimator metrics.
- Stage 4 passed all semantic-plumbing and navigation gates using a
  simulator-native map and simulator-native semantic fixtures.
- PC2 is an ARM64 ROS 2 Humble host with the Unitree C++ overlay and a connected
  Intel RealSense D435i.
- PC2 advertises native `/utlidar/cloud_livox_mid360` as
  `sensor_msgs/msg/PointCloud2` and `/utlidar/imu_livox_mid360` as
  `sensor_msgs/msg/Imu`, but neither produced a sample during two bounded
  passive checks.
- PC2 has `realsense2_camera`; it does not have this repository's FastLIVO,
  Nav2, services, Livox driver, ZED wrapper, or chatbot overlays installed.
- Point-in-time checks did not observe `g1_pubvel_node`, `g1_pubmove_node`, or
  `g1_pubcmd_node`. That is an observation, not proof that no external actor
  could launch another Unitree SDK client between checks.

Two repository paths are explicitly prohibited on PC2:

- `agentic_robot/agentOS/run_dameon/run_g1_background_daemon.py` starts the
  `ctl` group by default, and `robots/unitree/scripts/run_ctl.sh` starts the
  Unitree arm and base executables.
- `agentic_robot/services/src/robot_bridge` binds HTTP to `0.0.0.0`, has no
  authentication or authorization, and translates requests into navigation
  and arm ROS messages.

Neither path is part of this setup.

## Security Claim and Trust Boundary

The workstation motion-safety boundary is enforceable DDS isolation:
`ROS_DOMAIN_ID=77`, `ROS_LOCALHOST_ONLY=1`, a graph allowlist, and the absence
of the Unitree SDK from the MuJoCo import graph. Process-name checks are only
defense in depth.

PC2 must join its native sensor DDS graph to observe the Mid360 topics, so the
setup cannot prove that an unrelated privileged actor never ran a motion
client. Its narrower, auditable claim is:

> The approved automation invoked only hashed, allowlisted sensor/readiness
> commands, and its continuous `/proc` monitor did not observe a prohibited or
> Unitree-SDK-linked executable during the recorded action window.

The result must use exactly that wording or a stricter claim supported by a
future enforceable sandbox. It must never shorten the claim to "PC2 ran no
motion executable."

## HoloAgent-0 Feature Coverage

| Capability | Workstation proof | PC2 role |
| --- | --- | --- |
| OVO-accelerated FSR-VLN semantic mapping | Verify the pinned 74-blob source closure, pinned graph/dataset/checkpoint manifests, imports, exact graph identity, and a deterministic observation-only semantic fixture | None |
| Doubao chatbot speech interaction | Build an isolated Python 3.10 environment and distinguish dependency, configuration, credential, and audio-hardware outcomes | D435i is unrelated; a live audio/API test is separately authorized |
| AgentOS Harness adapted to OpenClaw | Install exact pinned OpenClaw and Node artifacts without starting a service, run read-only lint, validate skills, and execute a schema-validated offline DAG | None |
| Skill/Blueprint isolation and background triggering | Validate all five skills, exercise motion-capable helpers only with `--dry-run`, and prove daemon/control groups are absent | Hashed sensor-only action and continuous process observation |

## Goals

1. Make HoloAgent-0 reproducibly installable and auditable on the workstation.
2. Add deterministic AgentOS dry-run planning with no LLM dependency import or
   network attempt in the offline path.
3. Validate the restored OVO/FSR-VLN source and exact HMSG fixture without
   composing real-building coordinates with the MuJoCo map.
4. Validate chatbot dependencies and configuration without exposing secrets or
   requiring a live speech/API call for the offline profile.
5. Consolidate the validated MuJoCo motion, sensor, DDS, estimator, and
   semantic-navigation results without relabeling degraded estimation as pass.
6. Inventory and measure PC2 sensors through explicit profiles without starting
   any control process.
7. Produce atomic, schema-valid, timestamped evidence with deterministic label
   and exit-code precedence.

## Non-Goals

- Enabling physical base or arm motion.
- Starting a Unitree SDK motion client on PC2.
- Running `run_g1_background_daemon.py`, `run_ctl.sh`, `robot_bridge`, or
  `multi_robot_ctl` on PC2.
- Proving the absence of processes started by unrelated PC2 users outside the
  continuously observed action window.
- Exposing OpenClaw or robot HTTP services beyond loopback.
- Treating Stage 3's estimator-metric failure as LIO proof or as a MuJoCo pass.
- Treating the HMSG fixture or Stage 4 semantic fixture as proof of FSR-VLN
  spatial accuracy.
- Calling the live natural-language semantic parser during an offline profile.
- Converting native Mid360 `PointCloud2` to Livox `CustomMsg` before a real
  sample establishes its fields and timing semantics.
- Copying workstation x86_64 binaries, Python environments, or Docker layers to
  ARM64 PC2.

## Architecture

```text
Workstation (control and validation plane)
  pinned OpenClaw CLI; no persistent gateway
        |
        v
  schema-validated AgentOS plan + HoloAgent skill registry
        |
        +-- dry-run HTTP descriptions only
        +-- deterministic structured HMSG fixture
        v
  MuJoCo Stage 1-4 orchestration
    ROS_DOMAIN_ID=77
    ROS_LOCALHOST_ONLY=1
    use_sim_time=true
        |
        +-- /cmd_vel -> simulated G1 only
        +-- simulated lidar/IMU/camera/clock/TF
        +-- schema-valid atomic evidence

PC2 (sensor-only observation plane)
  hashed allowlisted command + continuous /proc monitor
        |
        +-- inventory profile
        +-- bounded D435i camera profile
        +-- passive full-streams profile
        v
  no command publisher, AgentOS, HTTP bridge, Nav2, or automation-owned
  Unitree SDK process
```

No ROS command graph crosses from the workstation to PC2. Workstation
simulation is localhost-only. PC2 operations run through one bounded SSH action
whose exact script digest is recorded before execution.

## Components

### 1. Deterministic AgentOS Planning

`agentic_robot/agentOS/sandbox_test/long_horizon_text_runner.py` gains a
`--plan-file` input for an already materialized DAG. The offline path must not
import a live-client dependency as a side effect:

- `OpenAI` and `AzureOpenAI` are imported only inside the live LLM client
  factory;
- `requests` is imported only inside the live HTTP execution path;
- the constructor does not instantiate a client when `--plan-file` is used;
- `--plan-file` requires `--dry-run` and rejects text-planning arguments;
- no API key or endpoint is required;
- no HTTP request, socket connect, ROS publish, or subprocess is permitted;
- the existing monitor, DAG, validation, and execution-result artifacts remain
  the output contract.

Plans are UTF-8 JSON, at most 65,536 bytes, and validate against tracked
`scripts/holoagent0_setup/schemas/agentos-plan-v1.schema.json`. The schema has:

- top-level required keys `schema_version`, `mode`, `description`, and `nodes`;
- `schema_version` fixed to `holoagent.agentos.plan.v1`;
- `mode` restricted to `single_robot` or `multi_robot` and required to match
  the CLI mode;
- `description` length 1-512;
- 1-64 nodes;
- node keys exactly `id`, `robot_id`, `skill`, `target`, and `depends_on`;
- node IDs matching `^[A-Za-z][A-Za-z0-9_-]{0,63}$` and unique;
- `robot_id` restricted to `11`, `12`, `13`, `14`, `15`, or `16`;
- `skill` restricted to `navigation` or `arm`;
- navigation targets restricted to `one_point_1`, `one_point_2`,
  `one_point_3`, `one_point_4`, or `stop`;
- arm targets restricted to `release_arm`, `turn_back_wave`,
  `blow_kiss_with_both_hands`, `blow_kiss_with_left_hand`,
  `blow_kiss_with_right_hand`, `both_hands_up`, `clamp`, `high_five`, `hug`,
  `make_heart_with_both_hands`, `make_heart_with_right_hand`, `refuse`,
  `right_hand_up`, `ultraman_ray`, `wave_under_head`, `wave_above_head`,
  `shake_hand`, `one_point_1_waypoint_1`, `box_left_hand_win`,
  `box_right_hand_win`, `box_both_hand_win`, `right_hand_on_heart`,
  `both_hands_up_deviate_right`, or `forward_push`;
- `depends_on` unique, bounded to 64 entries, and referencing existing IDs;
- `additionalProperties: false` at every object level.

The normal text-to-LLM path remains available but is not used by an offline
profile. Unit tests inject transport spies for `socket.connect`,
`socket.create_connection`, `requests`, and the OpenAI client factories. The
integration gate also runs the offline process under
`strace -f -e trace=connect,sendto,sendmsg` and requires an empty syscall trace.
Blocking the network is defense in depth; zero attempted transport syscalls is
the actual gate.

### 2. HoloAgent-0 Readiness Runner

A focused Python runner under `scripts/holoagent0_setup/` coordinates checks
and writes `outputs/holoagent0_setup/YYYYMMDDTHHMMSSZ/result.json`. It has no
ROS publisher and no Unitree SDK import. Each child command is an argv array
executed without a shell; stdout/stderr are bounded and credential-shaped
values are redacted before storage.

It exposes explicit modes rather than a single ambiguous workflow:

- `workstation_offline`
- `workstation_mujoco`
- `pc2_inventory`
- `pc2_camera`
- `pc2_full_streams`

`workstation_offline` never starts a service and makes zero network attempts.
OpenClaw provisioning is a separate explicit action. `workstation_mujoco`
delegates only to the existing Stage 1-4 scripts after rechecking localhost DDS
and the graph allowlist.

### 3. OpenClaw Installation and Lifecycle Isolation

OpenClaw provisioning is reproducible and fail-closed. These pins are part of
the reviewed design as of 2026-07-30:

| Artifact | Pin |
| --- | --- |
| Installer | `https://openclaw.ai/install-cli.sh` |
| Installer SHA-256 | `21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1` |
| OpenClaw package | `openclaw@2026.7.1-2` |
| npm integrity | `sha512-ycF3yPcbjN6bUPeaUx6Mh6vze1hQWoD3CT/wWcmD7a8xaHHHRUaAlaq+lFxMHf1ssEgODVAwjlzYqp2twkYZ7g==` |
| Embedded Node | `24.15.0`, Linux x64 |
| Node tarball SHA-256 | `472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6` |

Before downloading or modifying anything, provisioning checks all of the
following:

- `openclaw gateway status --deep --json` when a CLI exists;
- user and system service definitions for `openclaw-gateway*`;
- running process executable paths and command lines;
- actual listening sockets from `ss -H -ltnp`, including the default port and
  sockets owned by an OpenClaw process.

If a loaded service, running gateway, or matching listener already exists, the
action returns `FAIL_OPENCLAW` without installation, refresh, restart, or state
mutation. If the target prefix already contains the exact pinned CLI and no
gateway/service/listener exists, provisioning treats it as immutable input and
verifies it. A mismatched existing CLI also fails without automatic upgrade.

The installer is downloaded to a fresh temporary directory, verified against
the exact SHA-256, then invoked with the equivalent of:

```text
--prefix ~/.openclaw --version 2026.7.1-2 --node-version 24.15.0
--no-onboard --json
```

An upstream digest or integrity change requires a reviewed pin update; the
runner never accepts `latest`. Installation does not start or refresh a
gateway. The automated health gate is the documented read-only
`openclaw doctor --lint --json`, with exit 0 required. The official installer
and doctor behavior are defined at
<https://docs.openclaw.ai/install/installer> and
<https://docs.openclaw.ai/cli/doctor>.

An optional gateway smoke test is a separate explicitly authorized action. It
uses an unused port, loopback bind, authentication, and an owned session. It
records PID, PGID, executable, and `/proc/<pid>/stat` start time; proves the
actual socket is bound only to `127.0.0.1` or `::1` with `ss`; checks
`openclaw gateway status --deep --require-rpc --json`; and cleans up through
the same identity-safe trap contract used for PC2. Configuration alone is not
socket evidence. Gateway status behavior is documented at
<https://docs.openclaw.ai/cli/gateway>.

### 4. Pinned OVO/FSR-VLN Validation

The source gate reuses immutable semantic recovery commit
`f164095abb0045a69c0b8eb23683063be3deaa38` and the exact build-driven 74-path
manifest from `2026-07-22-holoagent-mujoco-first-design.md`. Every tracked path
must match its blob at that commit. The rule remains build-driven: it does not
restore every file missing from the old snapshot.

The implementation also adds a tracked Stage 0 verifier. The clean feature
branch must not depend on the main worktree's untracked
`nav_agent/scripts/validate_navagent_query_flow.sh`.

Large assets are pinned in tracked
`scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json`. The lock contains:

- logical roots for graph, RGB-D dataset, and CLIP checkpoint;
- each file's relative POSIX path, byte size, and SHA-256;
- a canonical root digest computed over bytewise-sorted manifest lines of
  `<sha256><two spaces><relative-path>\n`;
- symlink targets, with any target escaping an approved asset root rejected;
- the graph identity `icra_ic4f/graph_20260629211448`;
- the expected graph counts: 1 floor, 3 rooms, and 497 objects.

The approved values measured on 2026-07-30 are:

| Asset | Files/bytes | Pinned digest |
| --- | --- | --- |
| `scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448` | 1,229 files | canonical root SHA-256 `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050` |
| `rgbd_datasets/icra_ic4f` | 5,360 files | canonical root SHA-256 `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913` |
| `checkpoints/open_clip_pytorch_model.bin` | 1,710,631,365 bytes | file SHA-256 `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b` |

The implementation commits those exact values to the lock. Subsequent runs
only compare against it; they never regenerate or bless changed digests
automatically.

The required offline semantic fixture is versioned and exact:

| Field | Expected value |
| --- | --- |
| Source text | `Take me to the counter in the pantry` |
| Parsed room query | `Pantry` |
| Parsed object query | `counter` |
| Graph | `icra_ic4f/graph_20260629211448` and its locked digest |
| Expected room | ID `0_0`, name `Pantry` |
| Expected object | ID `0_0_81`, name `counter` |
| Expected frame | `map` |
| Expected position | `(-21.526786203133774, -15.671372634872082, -0.27579107548158116)` m, absolute tolerance `1e-6` m per axis |
| Expected orientation | identity quaternion, norm tolerance `1e-9` |

The fixture bypasses only the external LLM parser: a tracked structured query
containing the source text and parsed room/object fields enters the same HMSG
room/object retrieval and coordinate-transform logic. An observation-only ROS
node subscribes once on `/holoagent0/semantic_fixture_query` and publishes one
`geometry_msgs/msg/PoseStamped` on `/object_pose`. Before capture, the graph
must show exactly one fixture-query subscriber, exactly one object-pose
publisher, zero persistent object-pose subscribers, no Nav2 nodes, and no
`/cmd_vel`. The capture adds one temporary subscriber and must receive exactly
one pose.

The existing natural-language parser is known to call an external
chat-completion API even when `NAV_AGENT_USE_GPT=0`; room label generation may
also call externally. Therefore `semantic.natural_language_parser` is an
optional, separately authorized networked diagnostic and is `SKIPPED` in the
offline profile. It cannot affect `PASS_HOLOAGENT0_OFFLINE`.

The real-building pose is never sent to the MuJoCo `sim_map` stack. Stage 4
continues to use only its prevalidated simulator-native fixture.

### 5. Chatbot Environment and Classification

The chatbot environment uses Python 3.10 and the dependencies declared in
`agentic_robot/chatbot/g1/pyproject.toml`. The offline checks record:

- importability of `aiohttp`, `loguru`, `pyaudio`, `pydub`, and `websockets`;
- successful parsing of the robot JSON configuration;
- audio input and output device inventory without opening a stream;
- presence, never value, of required provider variable names;
- bounded configuration-check startup with no microphone or network action.

Dependency/import or JSON-configuration failure is blocking
`FAIL_CHATBOT`. External readiness is classified separately:

| Credentials | Input/output audio hardware | Offline result when all other gates pass |
| --- | --- | --- |
| Present | Present | `PASS_HOLOAGENT0_OFFLINE` |
| Missing | Present | `READY_CREDENTIALS_REQUIRED` |
| Present | Missing | `READY_AUDIO_HARDWARE_REQUIRED` |
| Missing | Missing | `READY_CREDENTIALS_AND_AUDIO_REQUIRED` |

These qualified labels exit 10 and never claim live speech functionality. A
live Doubao speech/API result requires credentials and separate user approval.

### 6. Stage 3 Qualified Continuation

The consolidated MuJoCo runner does not treat every nonzero Stage 3 child exit
as an immediate shell abort. It captures the exit code, validates Stage 3's
`result.json`, and applies this decision:

1. `PASS_LIO_ONLY` with every gate true is a required pass.
2. `FAIL_ESTIMATOR` is eligible for qualified continuation only when
   `graph`, `use_sim_time`, `calibration`, `sensor_contract`,
   `perfect_odom_isolated`, `message_finite`, and `excitation` are all true,
   and only one or more of `estimate_stream`, `translation_rmse`,
   `translation_max`, or `yaw_rmse` failed.
3. Missing/malformed evidence, a different label, or failure of any prerequisite
   is blocking and Stage 4 is `NOT_RUN`.

For case 2, Stage 4 may run because it uses a known-geometry simulator map and
does not consume the Stage 3 estimate. If Stage 4 passes, the top-level result
is `READY_MUJOCO_STAGE4_ESTIMATOR_FAILED`, status `QUALIFIED`, exit 10. It is
never `PASS_HOLOAGENT0_MUJOCO`. `PASS_HOLOAGENT0_MUJOCO` requires fresh Stage
1, 2, 3, and 4 passes.

### 7. PC2 Sensor-Only Action and Owned Cleanup

A Bash script under `robots/unitree/scripts/` is safe to copy to PC2. It uses
`set -Eeuo pipefail`, contains no publisher, FIFO, tmux, Docker, daemon, or
Unitree SDK command, and accepts exactly one profile:
`inventory`, `camera`, or `full-streams`.

Before a sensor action, the script:

1. verifies its own local and remote SHA-256 against the reviewed digest;
2. inventories executable files under the Unitree repository and overlays;
3. uses ELF dynamic-section inspection to find executables linked to Unitree
   SDK, DDS, or known control libraries, recording canonical path and SHA-256;
4. scans `/proc/*/exe`, `/proc/*/cmdline`, and `/proc/*/maps` for those paths,
   hashes, libraries, the three known G1 executables, and prohibited scripts;
5. starts a continuous monitor before any sensor launch or sample action.

The monitor samples at 20 Hz through cleanup, records monotonic timestamps and
every match, and causes a safety failure if it exits early or observes a match.
Because `/proc` inspection has race limits, evidence says "not observed during
the window," not "impossible."

The script installs `EXIT`, `INT`, `TERM`, and `HUP` traps before starting any
child. Every owned child records PID, PGID, canonical executable, SHA-256, and
the process start-time field from `/proc/<pid>/stat`. A sensor child starts in a
new session with PGID equal to PID. Cleanup sends a signal to its process group
only if PID, PGID, start time, and executable still match the recorded values;
otherwise it records an ownership mismatch and does not kill the reused PID.
Cleanup performs a bounded TERM/wait/KILL sequence, then runs the final `/proc`
denylist scan inside the `EXIT` trap. When postflight passes, signal traps
preserve exits 129 for HUP, 130 for INT, and 143 for TERM. A trap-observed
safety failure upgrades any prior outcome to exit 30. The evidence finalizer
also runs in the trap, so an early `set -e` failure cannot bypass postflight.

`camera` starts only the resolved `realsense2_camera` launch executable in its
owned session, validates the topic, and cleans it up. `inventory` starts no
sensor. `full-streams` may start the same camera action but only observes the
already advertised native Mid360 topics; it does not activate Unitree SLAM or
install another driver.

The measurement thresholds, after a 5 s warmup, are:

- D435i color: `sensor_msgs/msg/Image`, at least 100 samples over 10 s and at
  least 15.0 Hz, finite monotonic stamps, nonzero dimensions, supported
  encoding;
- native Mid360 lidar: `sensor_msgs/msg/PointCloud2`, at least 80 samples over
  10 s and at least 8.0 Hz, finite monotonic stamps, nonzero width and
  point-step, and a recorded `PointField` schema;
- native Mid360 IMU: `sensor_msgs/msg/Imu`, at least 1,000 samples over 10 s and
  at least 100.0 Hz, finite monotonic stamps and finite vectors/covariances.

These first thresholds are locked configuration values. Changing them requires
review and is not an automatic response to a failed PC2 run.

## Versioned Evidence Contract

Every mode validates against tracked
`scripts/holoagent0_setup/schemas/holoagent0-result-v1.schema.json`, JSON Schema
Draft 2020-12, schema ID `holoagent0.result.v1`. The result requires:

- schema version, mode, fixed top-level label, top-level status, and exit class;
- UTC start/end timestamps, monotonic duration, hostname, architecture, and
  source commit;
- relevant command, configuration, script, graph, dataset, and checkpoint
  SHA-256 digests;
- redacted environment posture and exact prohibited-command inventory;
- every gate for the selected mode in fixed order, including gates not run;
- gate ID, status, required/diagnostic role, fixed reason code, measurements,
  thresholds, bounded log paths, and nullable child command exit code;
- nullable `first_blocking_gate` and an ordered `qualifications` array;
- PC2 action-window timestamps, monitor samples, observed matches, and owned
  process identities when applicable.

Gate status is one of `PASS`, `FAIL`, `QUALIFIED`, `SKIPPED`, or `NOT_RUN`:

- `SKIPPED` means policy explicitly permits a diagnostic not to execute.
- `NOT_RUN` means an earlier blocking failure or interruption prevented it.
- Every later gate is materialized as `NOT_RUN`; it is never omitted.
- A diagnostic failure is recorded but cannot become a blocking failure.

Top-level exit codes are fixed:

| Exit code | Exit class | Meaning |
| --- | --- | --- |
| 0 | `PASS` | Every required gate passed and no qualification remains |
| 10 | `QUALIFIED` | Required plumbing passed but an explicitly allowed external or estimator qualification remains |
| 20 | `GATE_FAILURE` | A required functional gate failed |
| 30 | `SAFETY_FAILURE` | A safety/preflight/postflight invariant failed |
| 40 | `HARNESS_FAILURE` | Evidence/schema/tooling could not make a trustworthy decision |
| 129 | `HUP` | Interrupted by HUP after trap finalization |
| 130 | `INT` | Interrupted by INT after trap finalization |
| 143 | `TERM` | Interrupted by TERM after trap finalization |

Allowed top-level labels are a closed enum:

- passes: `PASS_HOLOAGENT0_OFFLINE`, `PASS_HOLOAGENT0_MUJOCO`,
  `PASS_PC2_SENSOR_INVENTORY`, `PASS_PC2_CAMERA_ONLY`,
  `PASS_PC2_SENSOR_STREAMS`;
- qualifications: `READY_CREDENTIALS_REQUIRED`,
  `READY_AUDIO_HARDWARE_REQUIRED`,
  `READY_CREDENTIALS_AND_AUDIO_REQUIRED`,
  `READY_MUJOCO_STAGE4_ESTIMATOR_FAILED`;
- failures: `FAIL_SOURCE`, `FAIL_RUNTIME`, `FAIL_OPENCLAW`, `FAIL_AGENTOS`,
  `FAIL_SEMANTIC`, `FAIL_CHATBOT`, `FAIL_MUJOCO`,
  `FAIL_PC2_INVENTORY`, `FAIL_PC2_CAMERA`, `FAIL_PC2_STREAMS`,
  `FAIL_SAFETY`, `FAIL_HARNESS`, and `INTERRUPTED`.

No dynamically constructed `FAIL_*` label is allowed. `first_blocking_gate`
supplies the precise fixed gate ID.

### Fixed Gate Catalog

The result schema contains this closed gate-ID enum; implementations cannot add
run-specific IDs:

| Domain | Fixed gate IDs |
| --- | --- |
| Source/runtime | `source.repository`, `source.semantic_blobs`, `source.pc2_script`, `runtime.workstation`, `runtime.pc2`, `offline.reference` |
| Safety | `safety.workstation_preflight`, `safety.workstation_postflight`, `safety.pc2_preflight`, `safety.pc2_runtime_monitor`, `safety.pc2_postflight` |
| OpenClaw | `openclaw.preexisting`, `openclaw.version_pin`, `openclaw.doctor_lint` |
| Skills | `skills.registry`, `skills.dry_run` |
| AgentOS | `agentos.plan_schema`, `agentos.offline_execution`, `agentos.network_attempts` |
| Semantic | `semantic.asset_lock`, `semantic.fixture_graph`, `semantic.fixture_query`, `semantic.natural_language_parser` |
| Chatbot | `chatbot.dependencies`, `chatbot.configuration`, `chatbot.credentials`, `chatbot.audio_hardware` |
| MuJoCo | `mujoco.stage1`, `mujoco.stage2`, `mujoco.stage3`, `mujoco.stage4` |
| PC2 inventory/camera | `pc2.inventory`, `pc2.camera_inventory`, `pc2.camera_sample`, `pc2.camera_rate`, `pc2.camera_cleanup` |
| PC2 lidar | `pc2.lidar_advertisement`, `pc2.lidar_sample`, `pc2.lidar_rate`, `pc2.lidar_schema` |
| PC2 IMU | `pc2.imu_advertisement`, `pc2.imu_sample`, `pc2.imu_rate` |

### Required-Gate Decision Table

`R` is required, `D` is diagnostic, and `-` is policy `NOT_RUN` or `SKIPPED`.
The schema contains the complete fixed gate-ID enum; this table defines the
profile decision boundary.

| Exact gate IDs | workstation offline | workstation MuJoCo | PC2 inventory | PC2 camera | PC2 full streams |
| --- | --- | --- | --- | --- | --- |
| `source.repository` | R | R | R | R | R |
| `source.pc2_script` | - | - | R | R | R |
| `runtime.workstation` | R | R | - | - | - |
| `runtime.pc2` | - | - | R | R | R |
| `safety.workstation_preflight`, `safety.workstation_postflight` | R | R | - | - | - |
| `safety.pc2_preflight`, `safety.pc2_runtime_monitor`, `safety.pc2_postflight` | - | - | R | R | R |
| `offline.reference` | - | R | - | - | - |
| `openclaw.preexisting`, `openclaw.version_pin`, `openclaw.doctor_lint` | R | D through offline result reference | - | - | - |
| `skills.registry`, `skills.dry_run` | R | D through offline result reference | - | - | - |
| `agentos.plan_schema`, `agentos.offline_execution`, `agentos.network_attempts` | R | D through offline result reference | - | - | - |
| `source.semantic_blobs`, `semantic.asset_lock`, `semantic.fixture_graph`, `semantic.fixture_query` | R | D through offline result reference | - | - | - |
| `semantic.natural_language_parser` | D, default SKIPPED | - | - | - | - |
| `chatbot.dependencies`, `chatbot.configuration` | R | D through offline result reference | - | - | - |
| `chatbot.credentials`, `chatbot.audio_hardware` | qualification | D through offline result reference | - | - | - |
| `mujoco.stage1`, `mujoco.stage2`, `mujoco.stage3`, `mujoco.stage4` | - | R, subject to Stage 3 qualified rule | - | - | - |
| `pc2.inventory`, `pc2.camera_inventory` | - | - | R | R | R |
| `pc2.camera_sample`, `pc2.camera_rate`, `pc2.camera_cleanup` | - | - | - | R | R |
| `pc2.lidar_advertisement`, `pc2.lidar_sample`, `pc2.lidar_rate`, `pc2.lidar_schema` | - | - | D | D | R |
| `pc2.imu_advertisement`, `pc2.imu_sample`, `pc2.imu_rate` | - | - | D | D | R |

Thus an inactive Mid360 is diagnostic in `pc2_inventory` and `pc2_camera` and
cannot block their pass labels. It is blocking only in `pc2_full_streams`,
which returns `FAIL_PC2_STREAMS` rather than a free-form
`FAIL_LIDAR_INACTIVE` label; the fixed lidar gate ID and reason code carry that
detail.

### Label Precedence

The runner evaluates labels in this fixed order:

1. any safety failure, including a trap-owned postflight failure;
2. interruption when postflight passes;
3. evidence/schema/harness failure;
4. first required functional failure in profile gate order, mapped to its fixed
   domain failure label;
5. allowed qualification, including the combined audio/credential table and
   Stage 3 qualified result;
6. profile pass.

Diagnostic failures never outrank a pass or qualification. An offline
qualification and a MuJoCo result are separate mode results and are not merged
into an invented combined label.

The result is written atomically in its new, non-reused run directory: write a
same-directory temporary file, flush and `fsync` it, `os.replace` to
`result.json`, then `fsync` the directory. A partial result is never accepted.
If final schema validation fails, the process writes a bounded emergency text
record and exits 40 without publishing a JSON result that claims readiness.

## Safety Contract

The following are hard failures:

1. Workstation simulation processes do not all use `ROS_DOMAIN_ID=77` and
   `ROS_LOCALHOST_ONLY=1`.
2. A Stage 1-4 graph contains an unexpected participant or physical Unitree
   control endpoint.
3. A workstation motion-process defense-in-depth scan finds a prohibited G1
   executable.
4. `START_G1_PUBVEL` is not `0`, `G1_DRY_RUN` is not `1`, or
   `ALLOW_G1_MOTION` is not `0` in a workstation setup command.
5. A PC2 command is outside the hashed allowlist or contains a publisher,
   control script, HTTP bridge, Nav2 launch, tmux/FIFO/daemon action, or Unitree
   SDK executable.
6. The PC2 continuous monitor stops early or observes a prohibited/SDK-linked
   process during the action window.
7. A cleanup target does not match its recorded PID, PGID, start time, and
   executable identity.
8. OpenClaw provisioning finds a pre-existing gateway/service/listener, a pin
   mismatch, or any automatic service start.
9. An OpenClaw smoke gateway binds outside loopback or lacks authentication.
10. An offline AgentOS or skill helper attempts network, ROS publish,
    subprocess, or physical execution.
11. A secret value appears in stdout, logs, evidence, or a Git-tracked file.

On failure, an orchestrator stops only identity-matched processes it started,
terminates MuJoCo with a final zero command, runs trap-owned postflight, marks
remaining gates `NOT_RUN`, records the first blocking gate, and exits according
to the fixed table. It never tries a less isolated fallback.

## Testing Strategy

Implementation follows test-driven development.

### Unit tests

- AgentOS plan schema, size limit, unknown-field rejection, CLI mutual
  constraints, DAG validation, and proof that live dependency factories/imports
  are not reached.
- Evidence JSON Schema, closed label/gate enums, mode table, status/exit-code
  consistency, precedence, atomic writes, redaction, and interruption states.
- Stage 3 pass, qualified continuation, prerequisite failure, malformed result,
  and Stage 4 `NOT_RUN` behavior.
- OpenClaw pins, pre-existing lifecycle detection, read-only doctor argv, socket
  ownership, and refusal to mutate/upgrade.
- Semantic 74-blob verification, canonical asset manifests, exact fixture
  identity/pose, and parser `SKIPPED` behavior.
- Chatbot dependency failure and all four credential/audio classifications.
- PC2 static command allowlist, ELF inventory parsing, `/proc` observations,
  PID-reuse defense, signal/early-error trap cleanup, and profile gate roles.

### Integration tests

- Run AgentOS offline with transport spies and syscall tracing; require zero
  transport attempts and the expected artifacts.
- Run workstation offline checks in a network-disabled unprivileged container.
- Verify exact OpenClaw/Node artifacts and `doctor --lint --json` without a
  gateway process or listener.
- Run the structured HMSG fixture and assert graph, object, room, pose, frame,
  and ROS endpoint counts.
- Re-run the tracked MuJoCo test manifest and require every selected test to
  exist, at least one test to be collected, and zero failures. No test-count
  equality is used.
- Re-run Stages 1-4 under localhost DDS and validate both Stage 3 decision
  branches and consolidated evidence.
- Run PC2 inventory and camera profiles while the continuous monitor remains
  active through trap cleanup.

The pinned test selection lives at
`scripts/holoagent0_setup/test-manifest-v1.txt`. It lists exact test files for
the readiness, AgentOS, semantic, PC2, and MuJoCo suites. Adding tests updates
the reviewed manifest; acceptance is zero failures, not "196 tests."

### Adversarial tests

- Reject oversized/malformed plans, unknown keys, unsupported skills/targets,
  duplicate IDs, missing dependencies, cycles, and plan execution without
  `--dry-run`.
- Make an import-time network client raise and prove offline AgentOS still
  starts because that dependency is lazy-loaded.
- Simulate a nonzero Stage 3 script with valid qualifying evidence and with each
  prerequisite failure; only the former reaches Stage 4.
- Reject changed semantic blobs/assets, an alternate graph with the same
  counts, the wrong object, and a second `/object_pose`.
- Reject wildcard gateway binds, an existing service/listener, installer hash
  drift, and unredacted credential-shaped values.
- Launch or race a fake SDK-linked executable during the PC2 sensor window and
  require the monitor/trap result to fail safely.
- Reuse a recorded PID with a different start time and prove cleanup does not
  signal it.
- Interrupt each PC2 phase with HUP, INT, and TERM and verify identity-safe
  cleanup, final monitoring, atomic evidence, and the correct exit code.

## Rollout and Acceptance

### Phase A: Workstation provisioning and offline profile

Provision exact OpenClaw artifacts only after pre-existing lifecycle checks.
Then run `workstation_offline` with networking disabled. Required source,
runtime, skill, AgentOS, semantic, chatbot dependency/configuration, OpenClaw
lint, and safety gates must pass. Credentials/audio produce only the fixed
qualified labels in their decision table.

### Phase B: Workstation MuJoCo profile

Require a fresh, schema-valid offline reference and fresh Stages 1-4. The result
is `PASS_HOLOAGENT0_MUJOCO` only if all four stages pass. A qualifying estimator
failure may continue to independent Stage 4 and yields only
`READY_MUJOCO_STAGE4_ESTIMATOR_FAILED` with exit 10. Any Stage 3 prerequisite
failure stops the workflow and marks Stage 4 `NOT_RUN`.

### Phase C: PC2 sensor-only profiles

Run `pc2_inventory` first. Inactive lidar/IMU is diagnostic, so the observed
PC2 can still reach `PASS_PC2_SENSOR_INVENTORY`. An explicit bounded D435i
action may then reach `PASS_PC2_CAMERA_ONLY`; inactive lidar/IMU remains
diagnostic. `PASS_PC2_SENSOR_STREAMS` requires the camera, native lidar, and
native IMU required gates and quantitative thresholds. Each action runs the
continuous monitor and trap-owned postflight.

### Phase D: Handoff

The handoff records exact commands, evidence paths, installed pins, qualified
results, remaining credential/audio/lidar gates, and the narrow PC2 observation
claim. It explicitly states that physical motion is not commissioned.

## Implementation Plan Decomposition

After this design is approved, it is implemented through three independently
testable plans, in order:

1. Workstation HoloAgent-0 provisioning, offline readiness, deterministic
   AgentOS, pinned semantic fixture, and evidence schema.
2. Workstation MuJoCo consolidation with explicit Stage 3 qualification.
3. PC2 inventory, bounded D435i action, full-stream diagnostics, continuous
   process observation, and handoff.

The first plan can pass without PC2 availability. The second reuses the
validated Stage 1-4 implementation. The third cannot claim full sensor streams
until PC2 produces native Mid360 lidar and IMU samples that satisfy the pinned
thresholds.
