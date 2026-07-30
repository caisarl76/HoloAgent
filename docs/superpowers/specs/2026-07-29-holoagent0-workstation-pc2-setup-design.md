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
> commands; its continuous monitor did not observe a control-specific
> signature during the recorded action window. It independently matched the
> observed process inventory and aggregate ROS graph against their reviewed
> allowlists. It makes no PID-to-DDS-participant or PID-to-ROS-node ownership
> claim.

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
profile. The zero-side-effect proof has three independent guards:

1. Unit tests inject failing spies for `socket.connect`,
   `socket.create_connection`, `requests`, OpenAI client factories,
   `subprocess.Popen/run/call/check_call/check_output`, `os.system`, all
   available `os.exec*`, `os.spawn*`, `os.fork`, and
   `multiprocessing.Process.start`.
2. A Python audit hook fails and records any socket, subprocess, fork, exec, or
   spawn event. An import guard fails and records any attempted import of
   `rclpy`, `rosidl_runtime_py`, `std_msgs`, or `geometry_msgs`; fake `rclpy`
   publisher/node objects also raise if reached in unit tests.
3. The integration process runs under `strace`. The transport trace
   (`connect`, `sendto`, `sendmsg`) must be empty. The process trace may contain
   only the one initial `execve` of the resolved approved Python interpreter;
   it must contain no subsequent `execve`, `execveat`, `fork`, `vfork`,
   `clone`, or `clone3`. ROS graph snapshots in an isolated, daemon-disabled
   domain must be identical before and after the run, excluding the bounded
   snapshot CLI helper itself.

Blocking the network and removing ROS configuration are defense in depth; zero
attempted transport, process-spawn, and ROS-publication side effects is the
actual gate.

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

- `openclaw gateway status --deep --no-probe --json` when a CLI exists;
- user and system service definitions for `openclaw-gateway*`;
- running process executable paths and command lines;
- actual listening sockets from `ss -H -ltnp`, including the default port and
  sockets owned by an OpenClaw process.

`--no-probe` is mandatory for every lifecycle-status call in provisioning and
in `workstation_offline`; these paths must not perform an RPC or connectivity
probe. Service discovery and `ss` are local state inspection. Only the
separately authorized optional loopback smoke test may use a probing status
command.

If a loaded service, running gateway, or matching listener already exists, the
action returns `FAIL_OPENCLAW` without installation, refresh, restart, or state
mutation. If the target prefix already contains the exact pinned CLI and no
gateway/service/listener exists, provisioning treats it as immutable input and
verifies it. A mismatched existing CLI also fails without automatic upgrade.

Before invoking the installer, the networked provisioning action fetches the
exact registry version document
`https://registry.npmjs.org/openclaw/2026.7.1-2` and requires all of:

- `version` is exactly `2026.7.1-2`;
- `dist.integrity` exactly equals the pinned npm integrity string above;
- `dist.tarball` is exactly
  `https://registry.npmjs.org/openclaw/-/openclaw-2026.7.1-2.tgz`.

It then downloads that exact tarball into the fresh temporary directory and
independently computes its SRI SHA-512 value; the computed value must equal
both the registry `dist.integrity` value and the reviewed pin. Any mismatch
returns `FAIL_OPENCLAW` before the installer is executed. The registry response
SHA-256, tarball URL, computed SRI value, and tarball SHA-256 are evidence, not
installer inputs that may float.

The installer is downloaded to a fresh temporary directory, verified against
the exact SHA-256, then invoked with the equivalent of:

```text
--prefix ~/.openclaw --version 2026.7.1-2 --node-version 24.15.0
--no-onboard --json
```

An upstream digest or integrity change requires a reviewed pin update; the
runner never accepts `latest`. Installation does not start or refresh a
gateway.

Provisioning atomically writes a schema-valid
`openclaw-provisioning-v1.json` in its unique provisioning run directory. It
records the installer, registry-response, package-tarball, Node-tarball,
installed CLI, target-prefix manifest, and configuration-template digests. It
contains no token or credential. A later `workstation_offline` run does not
query the registry: `openclaw.registry_integrity` verifies this immutable
provisioning record, the installed prefix manifest, and all reviewed pins. A
missing, malformed, or mismatched record is blocking.

After installation, provisioning creates a dedicated configuration only when
`~/.openclaw-holoagent0` does not already exist. Any pre-existing non-identical
file or directory fails without mutation. The tracked template
`scripts/holoagent0_setup/config/openclaw-local-v1.json` has exactly this
security-relevant content:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  }
}
```

The provisioner records the tracked template's Git blob and SHA-256, copies it
atomically to `~/.openclaw-holoagent0/openclaw.json` with mode `0600`, and uses
`OPENCLAW_CONFIG_PATH=$HOME/.openclaw-holoagent0/openclaw.json` and
`OPENCLAW_STATE_DIR=$HOME/.openclaw-holoagent0/state`. An identical existing
directory is reusable only when its permissions, file set, template digest, and
absence of service/listener state all match; extra or changed state fails
without mutation. The provisioner generates an ephemeral token of at least 32
random bytes for validation and optional smoke-test environments; the token is
never persisted, printed, or hashed into evidence.

With that environment set, the required non-service checks are exact:

1. `openclaw config validate --json` exits 0 and reports a valid active schema.
2. `openclaw doctor --lint --only core/doctor/gateway-config --severity-min warning --json`
   exits 0, reports `checksRun: 1`, and has an empty `findings` array.
3. `openclaw doctor --lint --severity-min error --json` exits 0, reports at
   least one check run, and has no error finding. Warning/info findings below
   the selected threshold are not acceptance failures.
4. The service/process/socket preflight is repeated and proves that configuring
   and linting did not start a gateway or listener.

The commands use the documented read-only lint posture; no `doctor --fix`,
onboarding, or service command is allowed. The official configuration and
doctor behavior are defined at
<https://docs.openclaw.ai/install/installer> and
<https://docs.openclaw.ai/cli/doctor>, with configuration fields defined at
<https://docs.openclaw.ai/gateway/configuration-reference>.

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

For every reused Stage 1-4 script, the consolidated runner treats the child exit
code as one input rather than the final classification. After the child exits,
it requires a final result with `postflight_pass: true`. A false or missing
postflight value is `FAIL_SAFETY`, exit 30, even when the evaluator already
returned nonzero; later stages are `NOT_RUN`. This supplies safety-first result
precedence above the existing scripts' shell exit-code selection without
claiming that their internal cleanup implementation changed.

The stronger PID/PGID/start-time/executable ownership contract below applies
only to newly implemented PC2 actions and the optional OpenClaw smoke gateway.
The reused Stage 1-4 scripts retain their already validated PID/container
cleanup in this milestone. Hardening all four stage scripts against PID reuse is
separate future work and is not an acceptance claim of this design.

### 7. PC2 Sensor-Only Action and Owned Cleanup

A Bash script under `robots/unitree/scripts/` is safe to copy to PC2. It uses
`set -Eeuo pipefail`, contains no publisher, FIFO, tmux, Docker, daemon, or
Unitree SDK command, and accepts exactly one profile:
`inventory`, `camera`, or `full-streams`.

Before a sensor action, the script:

1. verifies its own local and remote SHA-256 against the reviewed digest;
2. inventories executable files under the Unitree repository and overlays and
   classifies them as reviewed control, reviewed sensor, or unknown;
3. records ELF dependencies as evidence, but treats generic ROS/DDS libraries
   such as CycloneDDS, Fast DDS, and `rmw_*` as neutral because both legitimate
   sensor and control processes use them;
4. loads tracked
   `robots/unitree/config/pc2_sensor_process_allowlist_v1.json`, whose entries
   require hostname, canonical executable path and SHA-256, owner UID, exact or
   anchored argv pattern, parent executable or systemd unit, and permitted
   dynamic-library identities;
5. separately loads tracked
   `robots/unitree/config/pc2_sensor_graph_allowlist_v1.json`, whose entries
   define each profile's exact aggregate ROS node names/namespaces,
   publishers, subscribers, services, actions, interface types, and required
   QoS constraints;
6. scans `/proc/*/exe`, `/proc/*/cmdline`, and `/proc/*/maps` for process-plane
   control signatures and independently compares the aggregate ROS graph with
   the graph-plane allowlist;
7. starts a continuous monitor before any sensor launch or sample action.

Linux `/proc` identity and the ROS 2 graph do not establish which PID owns a
DDS participant, ROS node, or endpoint. This design therefore makes no such
correlation claim. The process and graph checks are independent conjunctive
gates: both must pass, and evidence records separate allowlist digests,
observations, and `process_allowlist_pass`/`graph_allowlist_pass` decisions.

A control-specific signature is one of:

- an executable path/hash in the reviewed control denylist, including the
  three G1 command binaries;
- a prohibited control script or HTTP bridge path/argv;
- on the process plane, a Unitree SDK/control-library dependency together with
  a control argv or executable signature;
- on the graph plane, any known control endpoint, including a `/cmd_vel`
  subscription or Unitree arm/base command service/action, or any node/topic/
  service/action outside the profile's aggregate graph allowlist.

DDS linkage alone is neutral on the process plane because legitimate sensor
and control processes both use it. Conversely, naming a process "sensor" is
insufficient: every observed candidate process must match all reviewed process
fields, and the independently observed aggregate graph must exactly satisfy
the selected profile's graph policy. The owned D435i process entry is derived
from the resolved installed package version, executable hash, exact launch
argv, parent identity, and owned PGID; its expected nodes and camera-only
endpoints live only in the separate graph allowlist. A pre-existing native
Mid360 process and the aggregate graph each need reviewed host-specific entries
before `camera` or `full-streams`; `inventory` may collect unknown observations
for review but cannot bless or write either allowlist automatically. In
`inventory`, an unknown SDK-linked process with no control-specific signature
is diagnostic reason `UNCLASSIFIED_SENSOR_CANDIDATE`; in `camera` or
`full-streams`, an unapproved process or graph is a safety preflight failure.

The `/proc` monitor samples at 20 Hz through cleanup. The ROS graph guard runs
before the action, after each sensor becomes ready, at 1 Hz during the bounded
measurement window, and during postflight. Both record monotonic timestamps and
every classification change. A safety failure occurs if either monitor exits
early, observes a control signature, sees the process set diverge from its
process allowlist, or sees the aggregate graph diverge from its graph
allowlist. Because `/proc` inspection and graph sampling have race limits,
evidence says "not observed during the window," not "impossible," and never
attributes a graph endpoint to a PID.

The script installs `EXIT`, `INT`, `TERM`, and `HUP` traps before starting any
child. Every owned child records PID, PGID, canonical executable, SHA-256, and
the process start-time field from `/proc/<pid>/stat`. A sensor child starts in a
new session with PGID equal to PID. Cleanup sends a signal to its process group
only if PID, PGID, start time, and executable still match the recorded values;
otherwise it records an ownership mismatch and does not kill the reused PID.
Cleanup performs a bounded TERM/wait/KILL sequence, then runs the final `/proc`
denylist scan inside the `EXIT` trap. When postflight and final evidence-schema
validation pass, signal traps preserve exits 129 for HUP, 130 for INT, and 143
for TERM. A trap-observed safety failure upgrades any prior outcome to exit 30;
otherwise an invalid final result exits 40. The evidence finalizer also runs in
the trap, so an early `set -e` failure cannot bypass postflight.

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
Draft 2020-12, schema ID `holoagent0.result.v1`. Two additional tracked,
closed policy artifacts are authoritative:

- `scripts/holoagent0_setup/policies/holoagent0-gate-policy-v1.json` defines
  exact profile membership and order, gate roles, finalizer classes, label/
  exit mappings, and same-precedence tie breaking;
- `scripts/holoagent0_setup/policies/holoagent0-reason-codes-v1.json` defines
  the allowed reason-code enum and the allowed reason codes for each
  gate/status pair.

Both policy files have versioned schema IDs, `additionalProperties: false`,
and reviewed SHA-256 digests. An unknown gate, status, reason code, or invalid
gate/status/reason combination is an evidence-schema failure; implementations
cannot improvise a reason string. The result requires:

- schema version, mode, fixed top-level label, top-level status, and exit class;
- UTC start/end timestamps, monotonic duration, hostname, architecture, and
  source commit;
- relevant command, configuration, script, graph, dataset, and checkpoint
  SHA-256 digests;
- redacted environment posture and exact prohibited-command inventory;
- every gate for the selected mode in fixed order, including gates not run;
- gate ID, status, role from `required`, `diagnostic`, `qualification`, or
  `finalizer`, fixed reason code, measurements, thresholds, bounded log paths,
  and nullable child command exit code;
- nullable `primary_blocking_gate`, an ordered `blocking_gates` array, and an
  ordered `qualifications` array;
- result-schema, gate-policy, and reason-code-policy digests;
- `invocation_role` from `standalone`, `parent`, or `child`; a child additionally
  requires non-null `parent_run_id` and `lineage_nonce`, while those fields are
  null for every non-child result;
- PC2 action-window timestamps, monitor samples, observed matches, and owned
  process identities when applicable.

Gate status is one of `PASS`, `FAIL`, `QUALIFIED`, `SKIPPED`, or `NOT_RUN`:

- `SKIPPED` means a reached diagnostic is policy-disabled or a reached
  conditional gate has no nonblocking prerequisite.
- `NOT_RUN` means an earlier blocking failure or interruption prevented a
  sequenced action gate from running.
- Later action gates become `NOT_RUN`; mandatory finalizers still execute and
  record their terminal state.
- A diagnostic failure is recorded but cannot become a blocking failure.

The v1 reason-code policy is a closed enum containing:

- normal/control flow: `OK`, `EARLIER_BLOCKING_GATE`,
  `INTERRUPTED_BEFORE_GATE`, `POLICY_DISABLED`,
  `DEPENDENCY_NOT_AVAILABLE`, `NO_OWNED_CAMERA`, and
  `MONITOR_NOT_STARTED`;
- source/runtime/evidence: `SOURCE_MISMATCH`, `RUNTIME_MISMATCH`,
  `DIGEST_MISMATCH`, `EVIDENCE_SCHEMA_INVALID`, `TOOL_RUNTIME_ERROR`, and
  `ATOMIC_WRITE_FAILED`;
- safety/process/graph: `UNEXPECTED_CONTROL_PROCESS`,
  `PROCESS_ALLOWLIST_MISMATCH`, `GRAPH_ALLOWLIST_MISMATCH`,
  `MONITOR_EXITED`, `OWNERSHIP_MISMATCH`, `CLEANUP_INCOMPLETE`,
  `UNEXPECTED_DDS_PARTICIPANT`, `UNEXPECTED_ROS_ENDPOINT`, and
  `POSTFLIGHT_FAILED`;
- OpenClaw: `PREEXISTING_OPENCLAW`, `INSTALLER_PIN_MISMATCH`,
  `REGISTRY_INTEGRITY_MISMATCH`, `OPENCLAW_VERSION_MISMATCH`,
  `OPENCLAW_CONFIG_MISMATCH`, `OPENCLAW_CONFIG_INVALID`, and
  `OPENCLAW_LINT_FINDING`;
- AgentOS/semantic/chatbot: `PLAN_INVALID`,
  `OFFLINE_SIDE_EFFECT_ATTEMPT`, `SEMANTIC_BLOB_MISMATCH`,
  `SEMANTIC_ASSET_MISMATCH`, `SEMANTIC_FIXTURE_MISMATCH`,
  `CHATBOT_DEPENDENCY_MISSING`, `CHATBOT_CONFIG_INVALID`,
  `CREDENTIALS_MISSING`, and `AUDIO_HARDWARE_MISSING`;
- sensors/stages: `TOPIC_NOT_ADVERTISED`, `TOPIC_NO_SAMPLE`,
  `RATE_BELOW_THRESHOLD`, `MESSAGE_SCHEMA_MISMATCH`,
  `UNCLASSIFIED_SENSOR_CANDIDATE`, `STAGE_CHILD_FAILED`,
  `STAGE_EVIDENCE_INVALID`, `ESTIMATOR_THRESHOLD_FAILED`, and
  `STAGE_POSTFLIGHT_FAILED`.

`PASS` uses `OK`. Each non-pass gate/status pair maps to one of the listed
codes in the policy file. Adding a code or changing a mapping requires review
of the policy artifact and its digest.

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

No dynamically constructed `FAIL_*` label is allowed.
`primary_blocking_gate` supplies the precedence-winning fixed gate ID;
`blocking_gates` preserves every blocking gate in observation/evaluation time
order.

### Fixed Gate Catalog

The result schema contains this closed gate-ID enum; implementations cannot add
run-specific IDs:

| Domain | Fixed gate IDs |
| --- | --- |
| Source/runtime | `source.repository`, `source.semantic_blobs`, `source.pc2_script`, `runtime.workstation`, `runtime.pc2`, `offline.reference` |
| Safety | `safety.workstation_preflight`, `safety.workstation_postflight`, `safety.pc2_preflight`, `safety.pc2_runtime_monitor`, `safety.pc2_postflight` |
| OpenClaw | `openclaw.preexisting`, `openclaw.version_pin`, `openclaw.registry_integrity`, `openclaw.config_pin`, `openclaw.config_validate`, `openclaw.doctor_lint` |
| Skills | `skills.registry`, `skills.dry_run` |
| AgentOS | `agentos.plan_schema`, `agentos.offline_execution`, `agentos.network_attempts` |
| Semantic | `semantic.asset_lock`, `semantic.fixture_graph`, `semantic.fixture_query`, `semantic.natural_language_parser` |
| Chatbot | `chatbot.dependencies`, `chatbot.configuration`, `chatbot.credentials`, `chatbot.audio_hardware` |
| MuJoCo | `mujoco.stage1`, `mujoco.stage2`, `mujoco.stage3`, `mujoco.stage4` |
| PC2 inventory/camera | `pc2.inventory`, `pc2.camera_inventory`, `pc2.camera_sample`, `pc2.camera_rate`, `pc2.camera_cleanup` |
| PC2 lidar | `pc2.lidar_advertisement`, `pc2.lidar_sample`, `pc2.lidar_rate`, `pc2.lidar_schema` |
| PC2 IMU | `pc2.imu_advertisement`, `pc2.imu_sample`, `pc2.imu_rate` |

### Required-Gate Decision Table

`R` is required, `D` is diagnostic, `Q` is a qualification gate, `F` is a
mandatory finalizer, and `-` means the gate is not a member of that profile and
is absent from its result. The schema contains the complete fixed gate-ID enum;
this table defines the profile decision boundary.

| Exact gate IDs | workstation offline | workstation MuJoCo | PC2 inventory | PC2 camera | PC2 full streams |
| --- | --- | --- | --- | --- | --- |
| `source.repository` | R | R | R | R | R |
| `source.pc2_script` | - | - | R | R | R |
| `runtime.workstation` | R | R | - | - | - |
| `runtime.pc2` | - | - | R | R | R |
| `safety.workstation_preflight` | R | R | - | - | - |
| `safety.workstation_postflight` | F | F | - | - | - |
| `safety.pc2_preflight` | - | - | R | R | R |
| `safety.pc2_runtime_monitor`, `safety.pc2_postflight` | - | - | F | F | F |
| `offline.reference` | - | R | - | - | - |
| `openclaw.preexisting`, `openclaw.version_pin`, `openclaw.registry_integrity`, `openclaw.config_pin`, `openclaw.config_validate`, `openclaw.doctor_lint` | R | - (covered by `offline.reference`) | - | - | - |
| `skills.registry`, `skills.dry_run` | R | - (covered by `offline.reference`) | - | - | - |
| `agentos.plan_schema`, `agentos.offline_execution`, `agentos.network_attempts` | R | - (covered by `offline.reference`) | - | - | - |
| `source.semantic_blobs`, `semantic.asset_lock`, `semantic.fixture_graph`, `semantic.fixture_query` | R | - (covered by `offline.reference`) | - | - | - |
| `semantic.natural_language_parser` | D, default SKIPPED | - | - | - | - |
| `chatbot.dependencies`, `chatbot.configuration` | R | - (covered by `offline.reference`) | - | - | - |
| `chatbot.credentials`, `chatbot.audio_hardware` | Q | - (covered by `offline.reference`) | - | - | - |
| `mujoco.stage1`, `mujoco.stage2`, `mujoco.stage3`, `mujoco.stage4` | - | R, subject to Stage 3 qualified rule | - | - | - |
| `pc2.inventory`, `pc2.camera_inventory` | - | - | R | R | R |
| `pc2.camera_sample`, `pc2.camera_rate` | - | - | - | R | R |
| `pc2.camera_cleanup` | - | - | - | F | F |
| `pc2.lidar_advertisement`, `pc2.lidar_sample`, `pc2.lidar_rate`, `pc2.lidar_schema` | - | - | D | D | R |
| `pc2.imu_advertisement`, `pc2.imu_sample`, `pc2.imu_rate` | - | - | D | D | R |

Thus an inactive Mid360 is diagnostic in `pc2_inventory` and `pc2_camera` and
cannot block their pass labels. It is blocking only in `pc2_full_streams`,
which returns `FAIL_PC2_STREAMS` rather than a free-form
`FAIL_LIDAR_INACTIVE` label; the fixed lidar gate ID and reason code carry that
detail.

### `offline.reference` Acceptance

`workstation_mujoco` does not accept an arbitrary result path. It runs
`workstation_offline` as an immediately preceding child of the same parent run
and binds the two results explicitly. Before launching the child, the parent
generates 32 random bytes and encodes them as a 64-character lowercase-hex
`lineage_nonce`. It atomically writes a mode-`0600` lineage request in the
parent run directory containing the parent run ID, nonce, expected policy/
schema/source/config/asset digests, and child mode. The request path is passed
as an argv value; the nonce is unique audit data, not a credential.

The child validates the request before any gate and atomically records
`invocation_role: "child"`, its own run ID, the exact `parent_run_id`, the
exact `lineage_nonce`, and the request's expected digests. The parent records
the child result's SHA-256 and run ID and computes
`lineage_binding_sha256` over RFC 8785 canonical JSON containing exactly
`parent_run_id`, `child_run_id`, `lineage_nonce`, and `child_result_sha256`.
A standalone offline result records `invocation_role: "standalone"` and null
parent/nonce fields and therefore cannot satisfy this gate.

`offline.reference` passes only when all of these are true:

- the child result validates against the exact result-schema digest recorded by
  the parent;
- its label is `PASS_HOLOAGENT0_OFFLINE`, `READY_CREDENTIALS_REQUIRED`,
  `READY_AUDIO_HARDWARE_REQUIRED`, or
  `READY_CREDENTIALS_AND_AUDIO_REQUIRED`;
- its status is respectively `PASS` or `QUALIFIED`, and its process exit is
  respectively 0 or 10;
- `primary_blocking_gate` is null, `blocking_gates` is empty, every required
  offline gate is `PASS`, and no gate has blocking status `FAIL`;
- its only qualifications, if any, are the credential/audio gates represented
  by its allowed top-level label;
- its source commit, 74-blob manifest digest, asset-lock digest, graph/dataset/
  checkpoint digests, AgentOS plan-schema digest, OpenClaw configuration
  template digest, OpenClaw provisioning-record digest, evidence-schema digest,
  gate-policy digest, and reason-code-policy digest exactly match the parent
  run;
- the child-side parent run ID and nonce exactly match the request, the child
  result digest matches the parent observation, and the recomputed canonical
  lineage binding matches `lineage_binding_sha256`;
- it completed after the parent preflight and before Stage 1 began.

An externally supplied or older offline result can be inspected as a
diagnostic, but cannot satisfy `offline.reference` or permit a MuJoCo pass.

### Total Gate Order and Terminal-State Rules

Each profile result contains its exact ordered sequence below. Initialization
materializes every member as `NOT_RUN`; evaluation replaces statuses in order.
Gates not in the selected sequence are absent, not `SKIPPED`.

`workstation_offline` order:

1. `source.repository`
2. `runtime.workstation`
3. `safety.workstation_preflight`
4. `openclaw.preexisting`
5. `openclaw.version_pin`
6. `openclaw.registry_integrity`
7. `openclaw.config_pin`
8. `openclaw.config_validate`
9. `openclaw.doctor_lint`
10. `skills.registry`
11. `skills.dry_run`
12. `agentos.plan_schema`
13. `agentos.offline_execution`
14. `agentos.network_attempts`
15. `source.semantic_blobs`
16. `semantic.asset_lock`
17. `semantic.fixture_graph`
18. `semantic.fixture_query`
19. `semantic.natural_language_parser`
20. `chatbot.dependencies`
21. `chatbot.configuration`
22. `chatbot.credentials`
23. `chatbot.audio_hardware`
24. `safety.workstation_postflight` (mandatory finalizer)

`workstation_mujoco` order:

1. `source.repository`
2. `runtime.workstation`
3. `safety.workstation_preflight`
4. `offline.reference`
5. `mujoco.stage1`
6. `mujoco.stage2`
7. `mujoco.stage3`
8. `mujoco.stage4`
9. `safety.workstation_postflight` (mandatory finalizer)

All PC2 profiles begin with this prefix:

1. `source.repository`
2. `source.pc2_script`
3. `runtime.pc2`
4. `safety.pc2_preflight`
5. `pc2.inventory`
6. `pc2.camera_inventory`

`pc2_inventory` then evaluates, in order,
`pc2.lidar_advertisement`, `pc2.lidar_sample`, `pc2.lidar_rate`,
`pc2.lidar_schema`, `pc2.imu_advertisement`, `pc2.imu_sample`,
`pc2.imu_rate`, `safety.pc2_runtime_monitor`, and
`safety.pc2_postflight`.

`pc2_camera` and `pc2_full_streams` continue after the prefix with
`pc2.camera_sample`, `pc2.camera_rate`, `pc2.lidar_advertisement`,
`pc2.lidar_sample`, `pc2.lidar_rate`, `pc2.lidar_schema`,
`pc2.imu_advertisement`, `pc2.imu_sample`, `pc2.imu_rate`,
`pc2.camera_cleanup`, `safety.pc2_runtime_monitor`, and
`safety.pc2_postflight`. The lidar/IMU gates are diagnostic in `pc2_camera` and
required in `pc2_full_streams` as defined above.

Status transitions are deterministic:

- A reached required or diagnostic gate that executes is `PASS` or `FAIL`.
- A reached qualification gate is `PASS` or `QUALIFIED`.
- `SKIPPED` is used only for a reached policy-disabled diagnostic (the offline
  natural-language parser) or a conditional gate whose nonblocking prerequisite
  is absent. In a diagnostic PC2 chain, a missing advertisement makes sample,
  rate, and schema gates `SKIPPED`; an advertised topic with no sample records a
  diagnostic sample `FAIL` and makes its rate/schema gates `SKIPPED`. The same
  missing required advertisement or sample in `pc2_full_streams` is blocking
  and leaves later action gates `NOT_RUN`. The IMU chain follows the same rule
  without a schema gate.
- `NOT_RUN` is used for a sequenced action gate bypassed after an earlier
  blocking failure or interruption.
- Mandatory finalizers always run after a block or signal. A camera cleanup is
  `SKIPPED` with fixed reason `NO_OWNED_CAMERA` if no camera child was created;
  otherwise it is `PASS` or `FAIL`. Safety postflight is always `PASS` or
  `FAIL`. The runtime-monitor finalizer is `SKIPPED` with fixed reason
  `MONITOR_NOT_STARTED` only when preflight failed before it could start.

Finalizer failure mappings are closed and safety-first:

| Finalizer | `FAIL` condition | Fixed result mapping |
| --- | --- | --- |
| `pc2.camera_cleanup` | an owned camera PID/PGID/start-time/executable identity mismatch, bounded TERM/wait/KILL exhaustion, or inability to prove that the owned process group terminated | `FAIL_SAFETY`, exit 30 |
| `safety.pc2_runtime_monitor` | monitor exit, an observed process/control signature, process-allowlist divergence, aggregate graph-allowlist divergence, or an incomplete terminal sample | `FAIL_SAFETY`, exit 30 |
| `safety.pc2_postflight` | final denylist/process/graph checks fail or cannot establish the required safety state | `FAIL_SAFETY`, exit 30 |
| `safety.workstation_postflight` | localhost-DDS/graph/process checks fail, or a reused Stage 1-4 result has false/missing postflight proof | `FAIL_SAFETY`, exit 30 |

The optional OpenClaw smoke action uses the same rule: an owned gateway cleanup
identity mismatch or incomplete termination is `FAIL_SAFETY`, exit 30. These
are never remapped to a functional failure. A serializer, schema-validator, or
atomic-writer defect is `FAIL_HARNESS`, exit 40 only when no safety finalizer
has failed; lack of trustworthy final safety evidence itself is the relevant
safety finalizer failure, not a harness escape hatch.

### Label Precedence

The runner evaluates labels in this fixed order:

1. any safety failure, including camera cleanup, runtime-monitor, and
   trap-owned postflight failure;
2. evidence/schema/harness failure when every applicable safety finalizer
   passed or was validly skipped;
3. interruption only when every applicable safety finalizer passed or was
   validly skipped and final schema validation passed;
4. first required functional failure in profile gate order, mapped to its fixed
   domain failure label;
5. allowed qualification, including the combined audio/credential table and
   Stage 3 qualified result;
6. profile pass.

Diagnostic failures never outrank a pass or qualification. An offline
qualification and a MuJoCo result are separate mode results and are not merged
into an invented combined label.

`blocking_gates` retains all blocking gate IDs in the order their failures were
observed/evaluated. `primary_blocking_gate` is not necessarily its first item:
it is the gate in the highest-precedence class above; ties within one class use
the profile's total gate order. For example, if `pc2.camera_rate` fails first
and `pc2.camera_cleanup` later fails, `blocking_gates` contains both in that
observation order, but `primary_blocking_gate` is `pc2.camera_cleanup`, the
label is `FAIL_SAFETY`, and the exit is 30. Thus the primary blocker always
names the gate that determined the reported label/exit when that decision is
gate-attributable.

The result is written atomically in its new, non-reused run directory: write a
same-directory temporary file, flush and `fsync` it, `os.replace` to
`result.json`, then `fsync` the directory. A partial result is never accepted.
If final schema validation fails and no safety finalizer failed, the process
writes a bounded emergency text record and exits 40 without publishing a JSON
result that claims readiness. If any safety finalizer failed as well, the
emergency record names both the safety gate(s) and the schema defect, suppresses
the invalid JSON readiness result, and exits 30; safety outranks schema failure.
On HUP, INT, or TERM, the trap first marks unfinished action gates `NOT_RUN`,
runs all finalizers, builds the `INTERRUPTED` result, and validates it. A safety
failure therefore exits 30; otherwise a schema failure exits 40; only a
schema-valid, postflight-safe interruption preserves exit 129, 130, or 143.

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
6. The PC2 continuous monitor stops early, observes a control-specific
   signature, or observes process-allowlist or aggregate-graph-allowlist
   divergence during the action window. Generic DDS linkage alone is neutral,
   and the result does not attribute graph endpoints to PIDs.
7. A PC2 or optional OpenClaw cleanup target does not match its recorded PID,
   PGID, start time, and executable identity.
8. OpenClaw provisioning finds a pre-existing gateway/service/listener, a pin
   mismatch, or any automatic service start.
9. An OpenClaw smoke gateway binds outside loopback or lacks authentication.
10. An offline AgentOS or skill helper attempts network, ROS publish,
    subprocess, or physical execution.
11. A secret value appears in stdout, logs, evidence, or a Git-tracked file.

On PC2 and in an optional OpenClaw smoke action, the orchestrator stops only
identity-matched processes it started. Reused Stage 1-4 scripts own their
existing PID/container cleanup; the consolidated runner waits for its direct
stage-script child, requires the stage's final postflight evidence, and applies
safety-first classification independently of that child's exit code. All
orchestrators run their scoped postflight, mark remaining action gates
`NOT_RUN`, record all blocking gates and the precedence-winning primary gate,
and exit according to the fixed table. They never try a less isolated fallback.

## Testing Strategy

Implementation follows test-driven development.

### Unit tests

- AgentOS plan schema, size limit, unknown-field rejection, CLI mutual
  constraints, DAG validation, and failing network/process/ROS guards proving
  that live dependency factories/imports and side-effect surfaces are not
  reached.
- Evidence JSON Schema, closed label/gate enums, mode table, status/exit-code
  consistency, exact per-profile ordering, `SKIPPED`/`NOT_RUN` transitions,
  atomic writes, redaction, and safety/schema/interruption precedence.
- Stage 3 pass, qualified continuation, prerequisite failure, malformed result,
  Stage 4 `NOT_RUN` behavior, and postflight safety overriding every evaluator
  exit code.
- `offline.reference` allowed labels/exits, required-gate closure, child-side
  parent ID/nonce binding, canonical lineage digest, parent/child timing, and
  every source/config/asset/policy/provisioning digest mismatch.
- OpenClaw pins, pre-existing lifecycle detection, exact minimal configuration,
  registry `dist.integrity` comparison before installer execution, downloaded
  package SRI verification, schema validation, focused/full lint thresholds,
  socket ownership, and refusal to mutate/upgrade.
- Semantic 74-blob verification, canonical asset manifests, exact fixture
  identity/pose, and parser `SKIPPED` behavior.
- Chatbot dependency failure and all four credential/audio classifications.
- PC2 static command allowlist, neutral DDS classification, process-plane
  control signatures, independent process and aggregate-graph allowlist
  matching, absence of PID-to-node attribution, `/proc` observations, PID-reuse
  defense, signal/early-error trap cleanup, and profile gate roles.

### Integration tests

- Run AgentOS offline with transport/process/ROS spies, an audit hook, syscall
  tracing, and graph snapshots; require zero transport, child-process, and ROS
  publication attempts and the expected artifacts.
- Run workstation offline checks in a network-disabled unprivileged container.
- Verify exact OpenClaw/Node artifacts, the pinned local configuration,
  `config validate`, both exact lint commands, and the absence of a gateway
  process/service/listener.
- Run the structured HMSG fixture and assert graph, object, room, pose, frame,
  and ROS endpoint counts.
- Re-run the tracked MuJoCo test manifest and require every selected test to
  exist, at least one test to be collected, and zero failures. No test-count
  equality is used.
- Re-run Stages 1-4 under localhost DDS and validate both Stage 3 decision
  branches, the exact offline child reference, postflight-over-exit precedence,
  and consolidated evidence.
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
  drift, registry `dist.integrity` drift, a package tarball whose computed SRI
  differs from the registry/pin, and unredacted credential-shaped values. Prove
  no installer child is created for either integrity mismatch.
- Show that a DDS-linked camera process is neutral; then launch or race a fake
  control-signature process during the PC2 window and require failure. Change
  one path/hash/UID/argv/parent field in the process allowlist or one independent
  aggregate ROS-graph field and require the corresponding monitor plane to fail
  safely. Verify that evidence never claims a PID owns a ROS node.
- Reuse a recorded PID with a different start time and prove cleanup does not
  signal it.
- Interrupt each PC2 phase with HUP, INT, and TERM and verify identity-safe
  cleanup, final monitoring, atomic evidence, and the correct exit code. Inject
  an invalid result during interruption and require exit 40 when all safety
  finalizers pass, but exit 30 when a safety finalizer also fails. Combine an
  earlier functional failure with a later camera-cleanup failure and require
  `pc2.camera_cleanup` as the primary blocker while preserving both IDs in
  `blocking_gates`.

## Rollout and Acceptance

### Phase A: Workstation provisioning and offline profile

Provision exact OpenClaw artifacts and the pinned minimal configuration only
after pre-existing lifecycle checks. Validate the configuration and exact lint
contracts without starting a gateway. Then run `workstation_offline` with
networking disabled. Required source, runtime, skill, AgentOS, semantic, chatbot
dependency/configuration, OpenClaw, and safety gates must pass.
Credentials/audio produce only the fixed qualified labels in their decision
table.

### Phase B: Workstation MuJoCo profile

Run the offline child inside the same parent and require the full
`offline.reference` acceptance contract above, then run fresh Stages 1-4. The
result is `PASS_HOLOAGENT0_MUJOCO` only if all four stages and every stage
postflight pass. A qualifying estimator failure may continue to independent
Stage 4 and yields only
`READY_MUJOCO_STAGE4_ESTIMATOR_FAILED` with exit 10. Any Stage 3 prerequisite
failure stops the workflow and marks Stage 4 `NOT_RUN`.

### Phase C: PC2 sensor-only profiles

Run `pc2_inventory` first. Inactive lidar/IMU is diagnostic, so the observed
PC2 can still reach `PASS_PC2_SENSOR_INVENTORY`. An explicit bounded D435i
action may then reach `PASS_PC2_CAMERA_ONLY` only after every pre-existing
sensor process is covered by the reviewed process allowlist and the aggregate
ROS graph matches the reviewed camera-profile graph allowlist; inactive lidar/
IMU remains diagnostic. `PASS_PC2_SENSOR_STREAMS` requires the corresponding
independent process and full-stream graph closure plus camera, native lidar,
and native IMU required gates and quantitative thresholds. Each action runs
the continuous monitor and trap-owned postflight and makes no PID-to-node
ownership claim.

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
