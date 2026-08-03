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
> signature during the recorded action window. It independently compared the
> observed process inventory and aggregate ROS graph with their reviewed
> allowlists. Inventory-only unknown, non-control observations were retained as
> triage diagnostics; camera and full-stream profiles required exact allowlist
> closure. It makes no PID-to-DDS-participant or PID-to-ROS-node ownership claim.

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

Those three guards cover the AgentOS execution boundary. The broader
`workstation_offline` contract is zero **unapproved or external** network
traffic, not zero IP syscalls. The required ROS semantic endpoint fixture uses
DDS, and ROS 2 derives UDP discovery and communication ports from the domain
ID. `ROS_LOCALHOST_ONLY=1` confines discovery scope but does not remove those
IP sockets. This behavior is documented at
<https://docs.ros.org/en/lyrical/Concepts/Intermediate/About-Domain-ID.html>.

An external evidence supervisor owns three mandatory finalizers over the complete
`workstation_offline` runner and every descendant:
`offline.trace_integrity`, `offline.network_policy`, and
`offline.evidence_binding`. It starts the runner as
the trace root under resolved strace 6.6 or newer with
`--kill-on-exit -f -yy -ttt -T -s 256` and one serialized, append-only trace.
The exact binary path, version, SHA-256, and successful `--kill-on-exit` probe
are runtime evidence. The trace captures `socket`, `socketpair`, `accept`,
`accept4`, `getsockopt`, `setsockopt`, `connect`, `bind`, `listen`, `sendto`,
`recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`, `recvmmsg`, `prctl`, `unshare`,
`setns`, `close_range`, `fcntl`, `clone`, `clone3`, `fork`, `vfork`, `execve`,
`execveat`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `ptrace`,
`exit`, and `exit_group`. `-ttt` timestamps are retained as diagnostic realtime
values, but policy does not correlate userspace clocks or compare timestamps
from separate trace files. The single trace's record order and the marker
protocol below are the authorization boundary. Quiet modes that suppress
process exit/signal records are prohibited. General `read`/`write` syscalls are
intentionally not traced so raw application data cannot bypass evidence
redaction.

Before `strace` starts, the supervisor enumerates every candidate inherited FD
through `/proc/self/fd`, `fstat`, and socket `SO_DOMAIN`/`SO_TYPE`/
`SO_PROTOCOL` probes. Stdin is `/dev/null`; stdout/stderr are owned non-socket
pipes or regular files; and the only additional tracee descriptors are exact
anonymous pipes for ledger and ownership-journal requests/acknowledgements.
Any socket—including a socket placed in fd 0, 1, or 2—or unknown descriptor in
the pass set fails `safety.workstation_preflight` with
`INHERITED_SOCKET_FD`. The spawn uses close-on-exec defaults and an explicit
pass list. A traced native launcher repeats the classification, places each
allowed FD at its reviewed number, applies `close_range(...,
CLOSE_RANGE_UNSHARE)` to everything else, and proves the final set before the
coordinator starts. Coordinator broker-pipe FDs are marked close-on-exec before
any functional child; newly created child IPC is pipe-only. No profile process
inherits or receives an internet or Unix-domain socket.

The same native launcher installs an inherited seccomp filter before the
coordinator executes. It denies `io_uring_setup`, `io_uring_enter`, and
`io_uring_register`; denies `ptrace`; returns `ENOSYS` for `clone3` so reviewed
libraries fall back to inspectable `clone`; and rejects `clone` when
`CLONE_UNTRACED` is set. The three io_uring syscalls remain in the strace filter
so any denied attempt is evidence. Any io_uring attempt, `CLONE_UNTRACED`
attempt, `ptrace` attempt, or `SCM_RIGHTS` control message decoded in `sendmsg`,
`recvmsg`, `sendmmsg`, or `recvmmsg` fails `offline.network_policy` with
respectively `PROHIBITED_IO_URING`, `UNTRACED_CHILD_ATTEMPT`,
`TRACE_BYPASS_ATTEMPT`, or `PROHIBITED_FD_TRANSFER`. This is necessary because
Unix-domain ancillary data can transfer an already open descriptor and
io_uring can perform socket I/O without the ordinary socket syscalls listed
above. The upstream contracts are
<https://man7.org/linux/man-pages/man7/unix.7.html> and
<https://man7.org/linux/man-pages/man2/io_uring_enter.2.html>.

The supervisor tails the trace while it is written. Each fully decoded
prohibited operation is immediately persisted and `fsync`ed in a
supervisor-owned, append-only violation journal with trace record index, PID,
operation, and reason code. Final parsing independently replays the closed
trace against that journal. A later truncation, parser defect, marker defect,
or tracer death can make `offline.trace_integrity` fail, but cannot erase an
already established `offline.network_policy` failure. Structural validity and
policy compliance are separate decisions.

The traced runner is a host-namespace coordinator. It performs the functional
gates, obtains the isolated child's bounded gate ledger, runs
`safety.workstation_postflight`, atomically seals a provisional ledger, and
exits. Only after the traced process tree and `strace` have closed does the
supervisor evaluate trace integrity, then network policy, then evidence
binding; compute the winning outcome; atomically write the authoritative
`result.json`; and return the authoritative process exit. The coordinator
never writes a readiness result or chooses the final exit.

The supervisor itself performs no functional or action gate; its only profile
gates are the three finalizers it owns, and it needs no IP socket. From process
start, a Python audit hook rejects and records any internet-family socket
construction. After spawning `strace` and the runner, the supervisor installs
a non-inherited seccomp filter on itself that denies new
`AF_INET`/`AF_INET6` sockets; failure to install that filter is
`offline.trace_integrity: FAIL`. The trace tool and traced runner do not inherit
this supervisor-only filter, so the semantic DDS allowance remains usable and
observable.

The coordinator begins in the host network namespace and records its namespace
inode. Before creating the isolated child, it runs the traced, non-networking
host observer used by `openclaw.preexisting`: exact `--no-probe` lifecycle
status, service/process inspection, and `ss -H -ltnp`. The observer may use
only `AF_UNIX` and `AF_NETLINK`; any host-namespace internet-family socket is a
network-policy failure. This is the authoritative pre-existing listener check.

The coordinator then creates one action child in a new user/network namespace
whose only interface and route are loopback. All gates after
`openclaw.preexisting` and before workstation postflight run in that child.
The namespace inode, interface flags, addresses, and routes are recorded before
and after the action. When the child finishes its internal process/DDS cleanup,
it sends its bounded ledger and namespace postflight proof to the coordinator
over length-bounded anonymous pipes created for that child, closes them, and
exits. No Unix-domain socket IPC is used. The coordinator reruns the same host
observer, combines the inner and host observations into
`safety.workstation_postflight`, and only then seals the provisional ledger.
Thus host listeners are checked from the host namespace both before and after
the isolated action; no `setns` return path or private-namespace `ss` result is
treated as host evidence.

Inside the action namespace, `ROS_DOMAIN_ID=77`, `ROS_LOCALHOST_ONLY=1`,
`ROS2CLI_DISABLE_DAEMON=1`, and `RMW_IMPLEMENTATION=rmw_cyclonedds_cpp` are
mandatory. Four tracked Cyclone DDS files are the only allowed
`CYCLONEDDS_URI` values:

- `scripts/holoagent0_setup/config/cyclonedds-offline-p0.xml` for the fixture;
- `scripts/holoagent0_setup/config/cyclonedds-offline-p1.xml` for the query
  publisher;
- `scripts/holoagent0_setup/config/cyclonedds-offline-p2.xml` for the result
  subscriber;
- `scripts/holoagent0_setup/config/cyclonedds-offline-p3.xml` for the bounded
  graph inspector.

Each URI is an absolute `file:` URI to the corresponding tracked file. The
four XML files differ only in fixed `Discovery/ParticipantIndex` value `0`,
`1`, `2`, or `3`. Each explicitly pins domain `77`; interface `lo` with
autodetection disabled, presence required, `multicast=true`, and
`allow_multicast=spdp`; `General/Transport=udp`; global
`AllowMulticast=spdp`; multicast loopback enabled; multicast TTL `1`;
redundant networking disabled; numeric SPDP/default multicast address
`239.255.0.1`; `Peers/AddLocalhost=false` with no static peers;
`Compatibility/ManySocketsMode=false`; `Internal/MonitorPort=-1`; and DDSI
port constants base `7400`, domain gain `250`, participant gain `2`, and
offsets `0`, `1`, `10`, and `11`. No TCP, raw-Ethernet, IPv6, automatic
participant index, or per-domain-participant socket mode is permitted.
`source.repository` verifies all four file blobs. The gate policy pins a
reviewed digest of the ordered repository-relative path/digest/role/index set.
Each result records that set plus each resolved absolute URI. Every URI must
resolve back to its tracked file without a symlink/content mismatch. Any unset,
inline, alternate, mutable, or digest-
mismatched `CYCLONEDDS_URI` fails before a ROS import.

With those fixed settings, the only permitted internet-family operations are
UDP4 DDS operations during the trace-visible `semantic.fixture_query` window,
issued by those four participant PIDs. The only multicast destination is SPDP
at 239.255.0.1:26650; port 26651 is computed by the pinned DDSI constants but
is not authorized because ASM/SSM data multicast is disabled. The allowed
unicast pairs are 26660/26661, 26662/26663, 26664/26665, and 26666/26667.
`ManySocketsMode=false` prohibits the additional kernel-selected per-domain-
participant ports. Loopback/wildcard binds and the configured DDS multicast
destination are allowed only because the namespace has no non-loopback
interface or route.

The supervisor gives the coordinator a 64-hex run nonce in the initialized
ledger. After the action child reports namespace/config validation and
immediately before the coordinator authorizes it to spawn the first
participant, the exact coordinator PID calls
`prctl(PR_SET_NAME, "H0B<token>")`, where `<token>` is the first 12 nonce hex
characters. After the child reports that every recorded participant has
exited, been reaped, and its sockets are absent, the coordinator calls
`prctl(PR_SET_NAME, "H0E<token>")` and then restores its reviewed process name.
Both marker syscalls, all participant clone/exec/exit events, and every network
syscall appear in the same serialized trace. The parser accepts markers only
from the recorded coordinator PID and only when their token matches the full
ledger nonce. A permitted syscall's entry and completion must both lie between
the matching marker records and belong to one of the four recorded participant
PIDs. The marker protocol is conditional: no BEGIN marker is valid only when
the last accepted ledger generation has `semantic_dds_window: NOT_ENTERED` and
the trace contains no fixture-participant lifecycle. A fully decoded IP event
in that branch is an `offline.network_policy` violation, not by itself a trace-
integrity defect. The coordinator atomically records `OPEN`, emits BEGIN,
authorizes the child, then after cleanup emits END and atomically records
`CLOSED`, in that order. Once BEGIN appears, one matching END is mandatory even
on handled interruption. A marker/ledger-state disagreement or a missing,
duplicated, reordered, spoofed, or incomplete marker sequence fails trace
integrity. Because an invalid marker sequence supplies no authorization, any
fully decoded IP operation associated with it also fails network policy.

TCP, DNS, any host-namespace IP operation, an IP operation outside the marked
semantic-fixture interval or participant set, a UDP endpoint outside that DDS
port policy, or any non-loopback route or interface fails
`offline.network_policy` with
`UNEXPECTED_NETWORK_ATTEMPT`. Every allowed DDS syscall is retained in evidence
with PID, serialized record index, diagnostic timestamp, address, port, and
marker nonce. A truncated trace, an unclosed traced PID or syscall, ptrace loss,
marker failure, parser failure, or incomplete descendant coverage fails
`offline.trace_integrity` as `FAIL_HARNESS`. Network policy is still evaluated
over every complete record and the violation journal: it is `FAIL` whenever a
prohibited operation was established, even if trace integrity also fails; it
is `PASS` only when trace integrity passes and no violation exists; and it is
`SKIPPED` with `DEPENDENCY_NOT_AVAILABLE` only when trace integrity fails and
no violation can be proved. When both gates fail, `offline.network_policy` is
the precedence-winning safety blocker and `offline.trace_integrity` remains in
`blocking_gates` as the harness defect.

The supervisor installs `HUP`, `INT`, and `TERM` handlers before launch and
records the first signal. It launches `strace` in a tracer process group, while
the tracee command starts the coordinator through `setsid`, making the
coordinator PID its distinct session and PGID. The supervisor records and
validates both PID/PGID/start-time/executable identities; the tracer never joins
the coordinator group. Immediately after spawn, the supervisor opens a pidfd
for the exact tracer identity and continuously polls it alongside the trace
tail; losing the pidfd, receiving an unexpected tracer exit, or observing a
tracer identity change stops all profile progression.

`--kill-on-exit` is mandatory and is verified to apply Linux
`PTRACE_O_EXITKILL`, which sends SIGKILL to tracees if their tracer exits; see
<https://man7.org/linux/man-pages/man2/ptrace.2.html>. Normal `clone` descendants
inherit tracing, `CLONE_UNTRACED` is denied, and `clone3` is forced through the
reviewed fallback, so no authorized child may survive by escaping ptrace. If
the tracer exits while any tracee is live, the supervisor waits a bounded
interval for kernel EXITKILL, then uses the append-only ownership journal to
identity-check and kill any remainder. It marks `offline.trace_integrity: FAIL`
with `TRACER_EXITED` and `safety.workstation_postflight: FAIL` with
`POSTFLIGHT_FAILED`; safety wins. If the tracer exits unexpectedly only after
all tracees ended, the accepted ledger is sealed, postflight passed, and the
ownership journal proves no live child, the outcome is trace-integrity
`FAIL_HARNESS` unless an earlier violation journal entry already requires
`FAIL_SAFETY`. Unexpected tracer exit never permits a functional gate or tracee
to continue.

If the coordinator is live, the supervisor forwards the signal exactly once
only to the coordinator PGID, leaving `strace` alive. The
coordinator trap propagates cleanup to any separately owned child groups using
their recorded identities. Every owned child identity is also streamed before
exec to a supervisor-owned append-only ownership journal. If the coordinator
cannot run its trap, the supervisor uses that journal for the same bounded,
identity-checked child-group cleanup; an incomplete journal or cleanup is
`safety.workstation_postflight: FAIL`. A bounded wait is followed by identity-
checked TERM and KILL only when needed. Repeated signals are recorded but do
not bypass finalization.

Before launch, the supervisor materializes the schema-valid ordered gate
skeleton as immutable `ledger/generation-000000.json` with every gate
`NOT_RUN`, generation `0`, null `previous_generation`/`previous_digest`,
`sealed: false`, and a run nonce. It computes that file's SHA-256 and sends the
coordinator an acknowledgement containing generation and digest over the
reviewed non-socket broker pipe.

For every update, the coordinator sends a candidate containing exactly
`generation = previous_generation + 1` and the last supervisor-acknowledged
generation/digest. The supervisor validates schema, nonce, chain link, and
allowed gate transition; writes a same-directory temporary file; flushes and
`fsync`s it; installs `ledger/generation-%06d.json` with no-replace semantics;
and `fsync`s the directory before acknowledging the new SHA-256. Generation
files are never overwritten, renamed, or deleted, and the coordinator cannot
advance until it receives the acknowledgement. A repeated generation, stale
digest, gap, fork, replay, non-monotonic gate transition, or unacknowledged
candidate fails `safety.workstation_postflight` with `LEDGER_CHAIN_INVALID`.
The final generation may set `sealed: true` only with the same nonce and a
terminal workstation postflight value.

If the coordinator is killed, exits without a valid seal, or cannot establish
the inner and host postflight observations, the supervisor starts from the last
acknowledged generation (falling back to generation `0`) and persists one
supervisor-authored successor that sets later action gates to `NOT_RUN` and
`safety.workstation_postflight: FAIL` with `POSTFLIGHT_FAILED`. That generation
is the accepted ledger head. The failure wins over trace/harness failure or
interruption. After the runner and trace close, the supervisor always evaluates
its three finalizers and applies safety-over-harness-over-interruption
precedence. Only a schema-valid result with workstation postflight, trace
integrity, network policy, and evidence binding satisfied preserves exit 129,
130, or 143.

### 2. HoloAgent-0 Readiness Runner

A focused Python command under `scripts/holoagent0_setup/` coordinates checks
and targets `outputs/holoagent0_setup/YYYYMMDDTHHMMSSZ/`. In
`workstation_offline`, its external supervisor alone writes authoritative
`result.json`; the traced coordinator writes only the provisional ledger
generations described above. In every other mode, the mode runner writes
authoritative `result.json` after its finalizers. Neither component has a ROS
publisher or Unitree SDK import. Each child command is an argv array executed
without a shell; stdout/stderr are bounded and credential-shaped values are
redacted before storage.

It exposes explicit modes rather than a single ambiguous workflow:

- `workstation_offline`
- `workstation_mujoco`
- `pc2_inventory`
- `pc2_camera`
- `pc2_full_streams`

`workstation_offline` never starts a service or permits external network
traffic. Its sole IP allowance is the traced, namespace-confined DDS loopback
traffic required by `semantic.fixture_query`.
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
installer inputs that may float. The verified tarball remains at a resolved
absolute path until the installer and installed-payload verification complete.

The installer is downloaded to a fresh temporary directory, verified against
the exact SHA-256, then invoked with the verified local package as its npm
package spec:

```text
--prefix ~/.openclaw
--version file:/absolute/path/to/verified/openclaw-2026.7.1-2.tgz
--node-version 24.15.0
--no-onboard --json
```

The pinned installer passes that value to npm as
`openclaw@file:/absolute/path/...tgz`; it must not be invoked with the registry
version string, a tag, or `latest`. Thus npm's OpenClaw package input is the
already verified artifact rather than a second registry resolution. The
installer output and installed `package.json` must still report version
`2026.7.1-2`. An upstream digest or integrity change requires a reviewed pin
update. Installation does not start or refresh a gateway.

Before accepting the prefix, provisioning builds two canonical OpenClaw
payload manifests. The expected manifest comes from the verified tarball after
stripping its single `package/` prefix; the actual manifest comes from the
installed `lib/node_modules/openclaw` package. Tar validation rejects absolute
or parent-traversing paths, duplicate normalized paths, device/FIFO entries,
escaping symlinks, and any type other than directory, regular file, or safe
relative symlink. Each manifest is RFC 8785 canonical JSON sorted by normalized
UTF-8 path and records entry type, regular-file SHA-256, relative symlink
target, and executable bit. Every expected path must match exactly, including
`package.json`; any extra actual path outside the top-level `node_modules/`
dependency subtree is rejected. The dependency subtree is recorded separately
in the prefix manifest and is not misrepresented as tarball payload.

The expected and actual payload-manifest SHA-256 values must be identical, and
the generated CLI launcher must resolve to the verified payload's declared bin
entry. A mismatch returns `FAIL_OPENCLAW`, never marks the fresh prefix usable,
and never creates configuration. For a prefix created by this run, it moves
only that provisioner-owned prefix to the evidence directory as quarantined
input; a pre-existing prefix fails verification without being moved,
overwritten, or removed. This post-install comparison is defense in depth; the
local `file:` package spec is the primary byte-binding control.

Provisioning evidence validates against tracked JSON Schema Draft 2020-12 file
`scripts/holoagent0_setup/schemas/openclaw-provisioning-v1.schema.json`, schema
ID `holoagent0.openclaw.provisioning.v1`. The schema has
`additionalProperties: false` at every object, status enum `PASS` or `FAIL`,
and a reason-code enum limited to `OK`, `PREEXISTING_OPENCLAW`,
`INSTALLER_PIN_MISMATCH`, `REGISTRY_INTEGRITY_MISMATCH`,
`INSTALLED_PAYLOAD_MISMATCH`, `OPENCLAW_VERSION_MISMATCH`,
`OPENCLAW_CONFIG_MISMATCH`, `OPENCLAW_CONFIG_INVALID`,
`OPENCLAW_LINT_FINDING`, `TOOL_RUNTIME_ERROR`, or `ATOMIC_WRITE_FAILED`. It
requires `PASS` with `OK` and `FAIL` with a non-`OK` code through closed
conditional branches. It also requires schema version and SHA-256, run/
timestamp/host/architecture, all reviewed pins, registry-response digest and
exact `dist` fields, package
tarball SHA-256/SRI, expected and actual payload-manifest digests and match
decision, installer/Node/CLI identities, target-prefix manifest, configuration
template digest, and before/after service/process/socket observations.

The provisioner resolves and records the tracked provisioning-schema digest
before network or mutation. After the installation, configuration, lint, and
lifecycle-postflight steps below, it validates the final record against that
exact schema and atomically writes `openclaw-provisioning-v1.json` in its
unique provisioning run directory. It contains no token or credential. A later
`workstation_offline` run does not query the registry:
`openclaw.registry_integrity` requires a successful record, validates it
against the recorded schema digest, requires that digest to equal the current
tracked schema, and rechecks the installed payload and target-prefix manifests
against the record and reviewed pins. A missing, malformed, failed, stale-
schema, or mismatched record is blocking.

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

This gate is the sole offline IP exception. The coordinator emits the exact
nonce-bearing BEGIN/END `prctl` records and journals the four ROS process
identities plus their role-specific Cyclone configuration digests. Its DDS
window includes only the query publisher, result subscriber, fixture node, and
bounded graph inspector. All must exit, be reaped, and close their DDS sockets
before the END marker. Their UDP activity must satisfy the namespace, PID,
marker-order, configuration, and fixed-port allowance in
`offline.network_policy`; diagnostic monotonic start/end timestamps remain in
the result but are not the authorization clock. Passing the semantic result
alone cannot bless additional traffic.

In `workstation_offline`, safety preflight and postflight must not create a ROS
participant. Preflight uses process, namespace, and socket inspection; the
semantic gate performs the one bounded ROS graph proof inside its allowed
window; postflight verifies those recorded PIDs and DDS sockets are gone using
`/proc` and local socket state. The MuJoCo profile may use its separate
localhost-DDS graph checks because it is not governed by the offline network
policy.

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

`mujoco.stage3` has the explicit gate role `required_qualification`, not the
ordinary `required` role. That role is qualification-capable but remains
blocking on every failure outside the single estimator predicate below. Its
only valid terminal statuses are:

- `PASS` when the Stage 3 required pass contract holds;
- `QUALIFIED` only for the exact estimator-only failure in case 2 below; or
- blocking `FAIL` for malformed evidence, failed prerequisites, or any other
  label/failure combination.

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
correlation claim. The process and graph checks are always run independently,
and each records its allowlist digest, observations, and a policy state from
the closed enum `EXACT_MATCH`, `TRIAGE_UNKNOWN`, or `CONTROL_VIOLATION`.
`camera` and `full-streams` require `EXACT_MATCH` on both planes. `inventory`
is observation-only and also accepts `TRIAGE_UNKNOWN`; no profile accepts
`CONTROL_VIOLATION`.

A control-specific signature is one of:

- an executable path/hash in the reviewed control denylist, including the
  three G1 command binaries;
- a prohibited control script or HTTP bridge path/argv;
- on the process plane, a Unitree SDK/control-library dependency together with
  a control argv or executable signature;
- on the graph plane, any known control endpoint, including a `/cmd_vel`
  subscription or Unitree arm/base command service/action.

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
`inventory`, an unknown SDK-linked process or non-control graph addition yields
`TRIAGE_UNKNOWN`; `pc2.inventory` remains nonblocking and retains a diagnostic
candidate record with reason `UNCLASSIFIED_SENSOR_CANDIDATE`, exact observed
identity/endpoint fields, and timestamps. A process or endpoint with a known
control signature is `CONTROL_VIOLATION` and a safety failure in every profile.
In `camera` or `full-streams`, any unapproved process or aggregate-graph
divergence is a safety preflight failure even when it has no known control
signature.

The `/proc` monitor samples at 20 Hz through cleanup. The ROS graph guard runs
before the action, after each sensor becomes ready, at 1 Hz during the bounded
measurement window, and during postflight. Both record monotonic timestamps and
every classification change. A safety failure occurs if either monitor exits
early or observes `CONTROL_VIOLATION`. In `camera` and `full-streams`, any
transition away from `EXACT_MATCH` is also a safety failure. In `inventory`, a
transition between `EXACT_MATCH` and `TRIAGE_UNKNOWN` updates the diagnostic
record but does not become a safety failure. Because `/proc` inspection and
graph sampling have race limits, evidence says "not observed during the
window," not "impossible," and never attributes a graph endpoint to a PID.

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
Draft 2020-12, schema ID `holoagent0.result.v1`. Offline working-ledger
generations separately validate against tracked, closed
`scripts/holoagent0_setup/schemas/holoagent0-offline-ledger-v1.schema.json`,
schema ID `holoagent0.offline-ledger.v1`. It fixes run ID/nonce, nonnegative
generation, nullable `previous_generation` and 64-hex `previous_digest`, boolean
`sealed`, the exact ordered offline gate array and gate fields, and
`semantic_dds_window` from `NOT_ENTERED`, `OPEN`, or `CLOSED`. Generation 0
requires both previous fields null; later generations require both non-null.
The supervisor broker enforces exact increment and digest continuity across
immutable schema-valid files. The schema permits `sealed: true` only with terminal
`safety.workstation_postflight` and a DDS-window state other than `OPEN`;
`additionalProperties: false` applies at every object level. Two additional
tracked, closed policy artifacts are authoritative:

- `scripts/holoagent0_setup/policies/holoagent0-gate-policy-v1.json` defines
  exact profile membership and order, gate roles, finalizer classes, the
  top-level status enum, exact label/status/exit-class/process-exit tuples, and
  closed per-mode winner/qualification-to-label mappings, and same-precedence
  tie breaking;
- `scripts/holoagent0_setup/policies/holoagent0-reason-codes-v1.json` defines
  the allowed reason-code enum and the allowed reason codes for each
  gate/status pair.

Both policy files have versioned schema IDs, `additionalProperties: false`,
and reviewed SHA-256 digests. An unknown gate, status, reason code, or invalid
gate/status/reason combination is an evidence-schema failure; implementations
cannot improvise a reason string. The result requires:

- schema version, mode, fixed top-level label, top-level status, exit class,
  and process exit code;
- UTC start/end timestamps, monotonic duration, hostname, architecture, and
  source commit;
- relevant command, configuration, script, graph, dataset, and checkpoint
  SHA-256 digests;
- redacted environment posture and exact prohibited-command inventory;
- every gate for the selected mode in fixed order, including gates not run;
- gate ID, status, role from `required`, `diagnostic`, `qualification`,
  `required_qualification`, or `finalizer`, fixed reason code, measurements,
  thresholds, bounded log paths, and nullable child command exit code;
- nullable `primary_blocking_gate`, an ordered `blocking_gates` array, and an
  ordered `qualifications` array;
- result-schema, applicable provisioning- and offline-ledger-schema,
  gate-policy, and reason-code-policy digests;
- `invocation_role` from `standalone`, `parent`, or `child`; a child additionally
  requires non-null `parent_run_id` and `lineage_nonce`, while those fields are
  null for every non-child result;
- PC2 action-window timestamps, monitor samples, observed matches, and owned
  process identities when applicable.

`openclaw_provisioning_schema_sha256` is required for
`workstation_offline` and `workstation_mujoco` results and absent from PC2
results. In the MuJoCo parent it must equal the referenced offline child's
value as well as the current tracked schema digest.
`offline_ledger_schema_sha256` has the same workstation presence and
parent/child equality rule.
`cyclonedds_config_set_sha256`, computed over canonical JSON containing the
four ordered repository-relative path/SHA-256/role/participant-index records,
follows the same presence and parent/child equality rule. Each offline result
additionally records the four individual file digests and resolved absolute
`file:` URIs.

Every `workstation_offline` result also contains a closed `offline_evidence`
object whose artifact descriptors are computed only after writers close and
files/directories are `fsync`ed:

- trace relative path, SHA-256, byte size, serialized record count, tracee
  count, tracer identity, and tracer exit status;
- accepted ledger generation and SHA-256, immutable generation count, and the
  SHA-256/byte size of a canonical chain manifest listing every generation's
  relative path, digest, size, predecessor, and sealed state;
- ownership-journal relative path, SHA-256, byte size, and record count;
- violation-journal relative path, SHA-256, byte size, and violation count;
- separate pre/post host-observer relative paths, SHA-256 values, byte sizes,
  host network-namespace inodes, and process/service/listener counts; and
- nullable DDS BEGIN/END serialized trace record indices plus the marker token;
  both are null only for the valid `NOT_ENTERED` branch.

`offline_evidence_bundle_sha256` is the SHA-256 of RFC 8785 canonical JSON over
those descriptors. After all writers close, the supervisor opens every artifact
with `O_RDONLY|O_NOFOLLOW`, verifies its regular-file type, owner, mode, device,
and inode, and retains those exact file descriptors through final result
publication. It computes every size, count, digest, ledger predecessor, and
marker index from the retained descriptors, freezes the artifact subtree
against tracee writes while leaving the supervisor-owned result path writable,
then repeats `fstat` and digest verification immediately
before the atomic `result.json` rename. The independently derived descriptor
set, not coordinator-supplied metadata, is the value serialized in the result.

`offline.evidence_binding` is the supervisor-owned finalizer for that operation.
It is `PASS` only when one stable descriptor snapshot binds the closed trace,
the accepted immutable ledger chain, the ownership and violation journals, and
both host-observer artifacts through the bundle digest. Any missing artifact,
path escape, symlink, type/owner/mode mismatch, chain-manifest mismatch,
count/index disagreement, digest drift, inode replacement, or failure to retain
and revalidate the descriptors is `FAIL` with
`EVIDENCE_BINDING_MISMATCH`. If a stable post-failure snapshot can still be
formed, the result binds that snapshot and honestly records the finalizer
failure; otherwise the supervisor writes only the bounded emergency record.
The failure maps to `FAIL_HARNESS` unless it prevents a safety decision or
attempts to conceal an already journaled policy violation, in which case the
relevant safety gate remains primary. A `workstation_mujoco` parent records
`offline_reference_evidence_bundle_sha256` and requires it to equal the fresh
offline child's bundle digest.

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
  `DIGEST_MISMATCH`, `EVIDENCE_SCHEMA_INVALID`, `TRACE_INCOMPLETE`,
  `TRACER_EXITED`, `EVIDENCE_BINDING_MISMATCH`, `TOOL_RUNTIME_ERROR`, and
  `ATOMIC_WRITE_FAILED`;
- safety/process/graph: `UNEXPECTED_CONTROL_PROCESS`,
  `PROCESS_ALLOWLIST_MISMATCH`, `GRAPH_ALLOWLIST_MISMATCH`,
  `MONITOR_EXITED`, `OWNERSHIP_MISMATCH`, `CLEANUP_INCOMPLETE`,
  `UNEXPECTED_DDS_PARTICIPANT`, `UNEXPECTED_ROS_ENDPOINT`,
  `POSTFLIGHT_FAILED`, `INHERITED_SOCKET_FD`, `PROHIBITED_FD_TRANSFER`,
  `PROHIBITED_IO_URING`, `UNTRACED_CHILD_ATTEMPT`,
  `TRACE_BYPASS_ATTEMPT`, and `LEDGER_CHAIN_INVALID`;
- OpenClaw: `PREEXISTING_OPENCLAW`, `INSTALLER_PIN_MISMATCH`,
  `REGISTRY_INTEGRITY_MISMATCH`, `INSTALLED_PAYLOAD_MISMATCH`,
  `OPENCLAW_VERSION_MISMATCH`, `OPENCLAW_CONFIG_MISMATCH`,
  `OPENCLAW_CONFIG_INVALID`, and `OPENCLAW_LINT_FINDING`;
- AgentOS/semantic/chatbot: `PLAN_INVALID`,
  `OFFLINE_SIDE_EFFECT_ATTEMPT`, `UNEXPECTED_NETWORK_ATTEMPT`,
  `SEMANTIC_BLOB_MISMATCH`, `SEMANTIC_ASSET_MISMATCH`,
  `SEMANTIC_FIXTURE_MISMATCH`,
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

For the new supervisor boundary, the closed mapping permits
`INHERITED_SOCKET_FD` only on failed `safety.workstation_preflight`;
`UNEXPECTED_NETWORK_ATTEMPT`, `PROHIBITED_FD_TRANSFER`,
`PROHIBITED_IO_URING`, `UNTRACED_CHILD_ATTEMPT`, or
`TRACE_BYPASS_ATTEMPT` only on failed `offline.network_policy`;
`TRACE_INCOMPLETE` or `TRACER_EXITED` only on failed
`offline.trace_integrity`; `EVIDENCE_BINDING_MISMATCH` only on failed
`offline.evidence_binding`; and `LEDGER_CHAIN_INVALID` only on failed
`safety.workstation_postflight`. Tests reject every cross-gate use.

`UNCLASSIFIED_SENSOR_CANDIDATE` is additionally allowed only on nested
inventory candidate records whose policy state is `TRIAGE_UNKNOWN`; it is not
the reason for a passing gate. An observation-only inventory gate that contains
such records remains `PASS` with gate reason `OK`. The reason-code policy
closes this nested context as well as gate/status contexts.

Top-level `status` is a separate closed enum: `PASS`, `QUALIFIED`, `FAIL`, or
`INTERRUPTED`. It must not reuse the gate-status enum.

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

The gate policy and result schema allow only these exact top-level tuples:

| Exact label set | Top-level status | Exit class | Process exit |
| --- | --- | --- | --- |
| `PASS_HOLOAGENT0_OFFLINE`, `PASS_HOLOAGENT0_MUJOCO`, `PASS_PC2_SENSOR_INVENTORY`, `PASS_PC2_CAMERA_ONLY`, `PASS_PC2_SENSOR_STREAMS` | `PASS` | `PASS` | 0 |
| `READY_CREDENTIALS_REQUIRED`, `READY_AUDIO_HARDWARE_REQUIRED`, `READY_CREDENTIALS_AND_AUDIO_REQUIRED`, `READY_MUJOCO_STAGE4_ESTIMATOR_FAILED` | `QUALIFIED` | `QUALIFIED` | 10 |
| `FAIL_SOURCE`, `FAIL_RUNTIME`, `FAIL_OPENCLAW`, `FAIL_AGENTOS`, `FAIL_SEMANTIC`, `FAIL_CHATBOT`, `FAIL_MUJOCO`, `FAIL_PC2_INVENTORY`, `FAIL_PC2_CAMERA`, `FAIL_PC2_STREAMS` | `FAIL` | `GATE_FAILURE` | 20 |
| `FAIL_SAFETY` | `FAIL` | `SAFETY_FAILURE` | 30 |
| `FAIL_HARNESS` | `FAIL` | `HARNESS_FAILURE` | 40 |
| `INTERRUPTED` after HUP | `INTERRUPTED` | `HUP` | 129 |
| `INTERRUPTED` after INT | `INTERRUPTED` | `INT` | 130 |
| `INTERRUPTED` after TERM | `INTERRUPTED` | `TERM` | 143 |

The result schema encodes these tuples with closed conditional branches and
`additionalProperties: false`; no label may appear with another status, exit
class, or process exit. A safety or harness failure observed during signal
finalization uses its higher-precedence `FAIL_*` tuple, not `INTERRUPTED`.

### Authoritative Mode-to-Outcome Mapping

Tuple validity is necessary but not sufficient. The gate policy contains a
closed lookup from `(mode, primary_blocking_gate)` to failure label and from
`(mode, exact qualification-gate set)` to qualification/pass label. The result
schema requires the reported label to equal that lookup. A label from another
profile or domain is invalid even if its status and exit tuple are otherwise
valid. The selected primary gate must be a member of that mode, appear in
`blocking_gates`, and have blocking `FAIL`; the qualification set must exactly
equal the result's `QUALIFIED` gates. The policy validator rejects missing,
extra, diagnostic, or wrong-mode selectors.

When there is no blocking gate and no interruption, these are the only
mappings:

| Mode | Exact qualification condition after every required/finalizer gate passes | Required label |
| --- | --- | --- |
| `workstation_offline` | none | `PASS_HOLOAGENT0_OFFLINE` |
| `workstation_offline` | only `chatbot.credentials` | `READY_CREDENTIALS_REQUIRED` |
| `workstation_offline` | only `chatbot.audio_hardware` | `READY_AUDIO_HARDWARE_REQUIRED` |
| `workstation_offline` | exactly `chatbot.credentials` and `chatbot.audio_hardware` | `READY_CREDENTIALS_AND_AUDIO_REQUIRED` |
| `workstation_mujoco` | none | `PASS_HOLOAGENT0_MUJOCO` |
| `workstation_mujoco` | only the allowed `mujoco.stage3` estimator qualification, with Stage 4 passed | `READY_MUJOCO_STAGE4_ESTIMATOR_FAILED` |
| `pc2_inventory` | none; diagnostic lidar/IMU failures do not create qualifications | `PASS_PC2_SENSOR_INVENTORY` |
| `pc2_camera` | none; diagnostic lidar/IMU failures do not create qualifications | `PASS_PC2_CAMERA_ONLY` |
| `pc2_full_streams` | none | `PASS_PC2_SENSOR_STREAMS` |

An offline child's credential/audio qualification remains in that child result
and does not create a new combined qualification in its MuJoCo parent.
When interruption wins precedence, every mode uses only `INTERRUPTED` with the
matching HUP/INT/TERM tuple defined above.

When a gate wins precedence, these are the only failure mappings:

| Mode | Precedence-winning fixed gate(s) | Required label |
| --- | --- | --- |
| any profile containing the gate | `source.repository`, `source.semantic_blobs`, or `source.pc2_script` | `FAIL_SOURCE` |
| any profile containing the gate | `runtime.workstation` or `runtime.pc2` | `FAIL_RUNTIME` |
| any profile containing the gate | any `safety.*` gate, `pc2.camera_cleanup`, or `offline.network_policy` | `FAIL_SAFETY` |
| `workstation_offline` | `offline.trace_integrity` or `offline.evidence_binding` | `FAIL_HARNESS` |
| `workstation_offline` | any `openclaw.*` gate | `FAIL_OPENCLAW` |
| `workstation_offline` | `skills.registry`, `skills.dry_run`, or any `agentos.*` gate | `FAIL_AGENTOS` |
| `workstation_offline` | `semantic.asset_lock`, `semantic.fixture_graph`, or `semantic.fixture_query` | `FAIL_SEMANTIC` |
| `workstation_offline` | `chatbot.dependencies` or `chatbot.configuration` | `FAIL_CHATBOT` |
| `workstation_mujoco` | `offline.reference` or any `mujoco.*` gate in blocking `FAIL` state | `FAIL_MUJOCO` |
| `pc2_inventory` | `pc2.inventory` or `pc2.camera_inventory` | `FAIL_PC2_INVENTORY` |
| `pc2_camera` | `pc2.inventory`, `pc2.camera_inventory`, `pc2.camera_sample`, or `pc2.camera_rate` | `FAIL_PC2_CAMERA` |
| `pc2_full_streams` | any required `pc2.*` functional lidar/IMU/inventory/camera gate other than `pc2.camera_cleanup` | `FAIL_PC2_STREAMS` |

Diagnostic and nonblocking qualification gates cannot become
`primary_blocking_gate`. A `required_qualification` gate can select its mapped
failure label only when it ends in blocking `FAIL`; for Stage 3 that means the
closed estimator-only qualification predicate did not match. Evidence
serialization, schema-validation, or atomic-write failure that prevents a
trustworthy JSON result produces only the bounded emergency record and exit 40;
it cannot use a tuple-valid but unmapped `FAIL_HARNESS` JSON result. Consequently,
`FAIL_HARNESS` is schema-valid only for `workstation_offline` with
`offline.trace_integrity` or `offline.evidence_binding` as its primary blocker.

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
| Offline profile | `offline.trace_integrity`, `offline.network_policy`, `offline.evidence_binding` |
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

`R` is required, `D` is diagnostic, `Q` is a nonblocking qualification gate,
`RQ` is required but qualification-capable under a closed predicate, `F` is a
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
| `offline.trace_integrity`, `offline.network_policy`, `offline.evidence_binding` | F | - (covered by `offline.reference`) | - | - | - |
| `openclaw.preexisting`, `openclaw.version_pin`, `openclaw.registry_integrity`, `openclaw.config_pin`, `openclaw.config_validate`, `openclaw.doctor_lint` | R | - (covered by `offline.reference`) | - | - | - |
| `skills.registry`, `skills.dry_run` | R | - (covered by `offline.reference`) | - | - | - |
| `agentos.plan_schema`, `agentos.offline_execution`, `agentos.network_attempts` | R | - (covered by `offline.reference`) | - | - | - |
| `source.semantic_blobs`, `semantic.asset_lock`, `semantic.fixture_graph`, `semantic.fixture_query` | R | - (covered by `offline.reference`) | - | - | - |
| `semantic.natural_language_parser` | D, default SKIPPED | - | - | - | - |
| `chatbot.dependencies`, `chatbot.configuration` | R | - (covered by `offline.reference`) | - | - | - |
| `chatbot.credentials`, `chatbot.audio_hardware` | Q | - (covered by `offline.reference`) | - | - | - |
| `mujoco.stage1`, `mujoco.stage2`, `mujoco.stage4` | - | R | - | - | - |
| `mujoco.stage3` | - | RQ | - | - | - |
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
  offline gate is `PASS`, `safety.workstation_postflight`,
  `offline.trace_integrity`, `offline.network_policy`, and
  `offline.evidence_binding` are all `PASS`, and no gate has blocking status
  `FAIL`;
- its only qualifications, if any, are the credential/audio gates represented
  by its allowed top-level label;
- its source commit, 74-blob manifest digest, asset-lock digest, graph/dataset/
  checkpoint digests, AgentOS plan-schema digest, OpenClaw configuration
  template digest, OpenClaw provisioning-record and provisioning-schema
  digests, Cyclone DDS configuration-set digest and member digests,
  evidence- and offline-ledger-schema digests, gate-policy digest, and
  reason-code-policy digest exactly match the parent run;
- every child `offline_evidence` artifact still exists under the child run
  directory, independently recomputes to its recorded type/owner/mode,
  size/count/digest/marker values, the accepted ledger generation is the sealed
  head of the verified immutable hash chain, and the recomputed descriptor
  bundle equals both `offline_evidence_bundle_sha256` and the parent's
  `offline_reference_evidence_bundle_sha256`;
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
24. `safety.workstation_postflight` (coordinator-owned mandatory finalizer;
    supervisor-synthesized on a missing/unsealed ledger)
25. `offline.trace_integrity` (supervisor-owned mandatory finalizer)
26. `offline.network_policy` (supervisor-owned mandatory finalizer)
27. `offline.evidence_binding` (supervisor-owned mandatory finalizer)

On a normal or trap-handled path, gate 24 completes and is sealed into the
provisional ledger before the traced coordinator exits. If that seal is
missing, the supervisor first performs identity-safe cleanup and synthesizes
gate 24 `FAIL` from its initialized skeleton. Only after gate 24 has that
terminal coordinator-written or supervisor-synthesized value and the trace is
closed does the supervisor evaluate gates 25-27 in order. No authoritative
label, JSON result, or process exit is selected before that sequence completes.
The initial host observer supplies gate 4; the isolated action child supplies
gates 5-23 and its inner cleanup proof; and the host coordinator combines the child
proof with the final host observer to decide gate 24 on the normal path. A
missing or unsealed provisional ledger is never a shortcut past gate 24.

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
- A reached `required_qualification` gate is `PASS`, `QUALIFIED` only when its
  closed qualification predicate matches, or blocking `FAIL` otherwise.
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
  `MONITOR_NOT_STARTED` only when preflight failed before it could start. The
  trace-integrity finalizer is always `PASS` or `FAIL`; it is never `SKIPPED`
  or `NOT_RUN`, even after an earlier functional failure or signal. The network-
  policy finalizer is `FAIL` whenever a complete decoded record or violation-
  journal entry proves a prohibited operation, regardless of trace-integrity
  status. It is `PASS` only after trace integrity passes with no violation, or
  `SKIPPED` with `DEPENDENCY_NOT_AVAILABLE` when integrity fails and no
  violation is provable. The evidence-binding finalizer is always `PASS` or
  `FAIL`; it is never `SKIPPED` or `NOT_RUN`, and it runs after both other
  supervisor finalizers so their accepted inputs and decisions are included in
  the bound result.

Finalizer failure mappings are closed and precedence-aware:

| Finalizer | `FAIL` condition | Fixed result mapping |
| --- | --- | --- |
| `offline.trace_integrity` | truncated/unclosed trace coverage, missing or invalid marker protocol, tracer loss, unclosed PID/syscall, or trace-parser/tool failure; reason `TRACE_INCOMPLETE` or `TRACER_EXITED` | `FAIL_HARNESS`, exit 40 unless a safety gate also fails |
| `offline.network_policy` | any host-namespace IP operation; any isolated-child IP operation outside the exact marker/config/PID/port-bounded semantic DDS allowance; or any prohibited fd-transfer, io_uring, untraced-child, or ptrace attempt, even when trace integrity later fails | `FAIL_SAFETY`, exit 30, with the fixed gate/reason mapping |
| `offline.evidence_binding` | any missing, mutable, substituted, path-escaped, digest/count/index-inconsistent, or otherwise unbindable trace, accepted-ledger, chain-manifest, ownership-journal, violation-journal, or host-observer artifact; reason `EVIDENCE_BINDING_MISMATCH` | `FAIL_HARNESS`, exit 40 unless a safety gate also fails or the defect conceals a proved safety violation |
| `pc2.camera_cleanup` | an owned camera PID/PGID/start-time/executable identity mismatch, bounded TERM/wait/KILL exhaustion, or inability to prove that the owned process group terminated | `FAIL_SAFETY`, exit 30 |
| `safety.pc2_runtime_monitor` | monitor exit, `CONTROL_VIOLATION` in any profile, a transition away from `EXACT_MATCH` in camera/full-stream profiles, or an incomplete terminal sample | `FAIL_SAFETY`, exit 30 |
| `safety.pc2_postflight` | final control-signature checks fail in any profile, exact process/graph closure fails in camera/full-stream profiles, or the required profile-specific safety state cannot be established | `FAIL_SAFETY`, exit 30 |
| `safety.workstation_postflight` | offline recorded-PID/socket teardown fails; either host observer is unavailable or inconsistent; the provisional ledger is missing, invalid, unsealed, or has the wrong nonce; MuJoCo localhost-DDS/graph/process checks fail; or a reused Stage 1-4 result has false/missing postflight proof | `FAIL_SAFETY`, exit 30 |

The optional OpenClaw smoke action uses the same rule: an owned gateway cleanup
identity mismatch or incomplete termination is `FAIL_SAFETY`, exit 30. These
are never remapped to a functional failure. A serializer, schema-validator, or
atomic-writer defect is `FAIL_HARNESS`, exit 40 only when no safety-class
finalizer has failed. Failure to prove owned-process cleanup or the terminal
process/graph safety state is safety-class; inability to complete the passive
offline syscall trace is the explicitly mapped harness-class exception above.

### Label Precedence

The authoritative result owner—the trace supervisor for
`workstation_offline`, and the mode runner otherwise—evaluates labels in this
fixed order:

1. any safety failure, including an unexpected offline network operation,
   camera cleanup, runtime-monitor, and trap-owned postflight failure;
2. evidence/schema/harness failure when no safety-class failure was observed;
3. interruption only when every applicable mandatory finalizer passed or was
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

The authoritative result owner writes the result atomically in its new,
non-reused run directory: write a same-directory temporary file, flush and
`fsync` it, `os.replace` to `result.json`, then `fsync` the directory. A partial
result is never accepted. For `workstation_offline`, the traced coordinator can
write only schema-validated provisional gate-ledger generations; the supervisor
alone writes `result.json` and returns the command's exit.

If final schema validation fails and no safety-class finalizer failed, the
process writes a bounded emergency text record and exits 40 without publishing
a JSON result that claims readiness. If any safety-class finalizer failed as
well, the emergency record names both the safety gate(s) and the schema defect,
suppresses the invalid JSON readiness result, and exits 30; safety outranks
schema failure.

On HUP, INT, or TERM in `workstation_offline`, the supervisor follows the
identity-checked forwarding and bounded-wait contract above; when able, the
coordinator marks unfinished action gates `NOT_RUN`, executes postflight, seals
the provisional ledger, and exits. If it cannot, the supervisor applies the
missing-ledger safety rule. The supervisor then closes the trace, executes its
finalizers, builds the authoritative result, and validates it. Other modes
perform the analogous sequence in their owned traps. A safety failure exits 30;
otherwise a harness/schema failure exits 40; only a schema-valid interruption
with every applicable finalizer passed or validly skipped preserves exit 129,
130, or 143.

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
   divergence during a camera/full-stream action. Inventory-only
   `TRIAGE_UNKNOWN` remains diagnostic; `CONTROL_VIOLATION` fails every
   profile. Generic DDS linkage alone is neutral, and the result does not
   attribute graph endpoints to PIDs.
7. A PC2 or optional OpenClaw cleanup target does not match its recorded PID,
   PGID, start time, and executable identity.
8. OpenClaw provisioning finds a pre-existing gateway/service/listener, a pin
   mismatch, or any automatic service start.
9. An OpenClaw smoke gateway binds outside loopback or lacks authentication.
10. An offline AgentOS or skill helper attempts network, ROS publish,
    subprocess, or physical execution.
11. The offline namespace exposes a non-loopback interface/route, or any
    process in the complete `workstation_offline` tree performs an IP operation
    outside the exact semantic-fixture DDS allowance. A complete prohibited
    operation is a safety violation even when a separate trace defect is also
    present.
12. The offline tracee inherits an unapproved or socket FD, transfers an FD with
    `SCM_RIGHTS`, attempts an io_uring operation, requests an untraced clone, or
    invokes `ptrace`.
13. The tracer loses identity or exits while a tracee is live, and kernel
    exit-kill plus ownership-journal cleanup cannot prove that every tracee and
    owned child stopped. Unexpected tracer exit after proved teardown remains a
    harness failure, not a silent continuation.
14. Complete trace coverage, the acknowledged immutable ledger chain, or the
    final evidence-artifact binding cannot be established. These remain
    structural harness failures unless the specific finalizer rules establish a
    safety failure; they do not erase an independently proved policy violation.
15. A secret value appears in stdout, logs, evidence, or a Git-tracked file.

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
- Evidence and offline-ledger JSON Schemas, closed
  label/gate/top-level-status enums, immutable ledger nonce/generation/seal
  transitions, acknowledged predecessor-digest continuity and replay/gap/fork
  rejection,
  every exact label/status/exit-class/process-exit tuple, rejection of every
  cross-product mismatch, authoritative `(mode, primary gate/qualification
  set)` label lookup, mode table, exact per-profile ordering,
  `SKIPPED`/`NOT_RUN` transitions, atomic writes, redaction, and
  safety/schema/interruption precedence. Every label is tested in its allowed
  and wrong-mode cases.
- Offline trace parsing, structural-integrity versus policy classification,
  violation-journal replay, complete descendant closure, domain-77 DDS port
  calculation, four pinned Cyclone config/path/digest/role mappings,
  `ManySocketsMode=false`, trace-visible marker parsing, semantic-fixture
  never-entered/entered marker branches, PID/record-order scoping, host/private
  namespace-interface/route validation, supervisor audit/seccomp enforcement,
  inherited-FD classification and close-range sanitization, `SCM_RIGHTS`,
  io_uring/ptrace/`CLONE_UNTRACED` denial, postflight-before-trace ordering,
  tracer/runner process-group separation, tracer pidfd liveness and
  `PTRACE_O_EXITKILL`, missing-ledger synthesis, artifact descriptor/bundle
  recomputation, and supervisor signal/exit precedence.
- Stage 3 `required_qualification` role, pass, exact qualified continuation,
  prerequisite failure, malformed result, Stage 4 `NOT_RUN` behavior, and
  postflight safety overriding every evaluator exit code.
- `offline.reference` allowed labels/exits, required-gate closure, child-side
  parent ID/nonce binding, canonical lineage digest, parent/child timing, and
  every source/config/asset/policy/provisioning digest mismatch.
- OpenClaw pins, pre-existing lifecycle detection, exact minimal configuration,
  registry `dist.integrity` comparison before installer execution, downloaded
  package SRI verification, exact local `file:` installer argv, canonical
  expected/installed payload matching, provisioning-schema closure/digest,
  focused/full lint thresholds, socket ownership, and refusal to mutate/upgrade.
- Semantic 74-blob verification, canonical asset manifests, exact fixture
  identity/pose, and parser `SKIPPED` behavior.
- Chatbot dependency failure and all four credential/audio classifications.
- PC2 static command allowlist, neutral DDS classification, process-plane
  control signatures, independent process and aggregate-graph allowlist
  matching, inventory-only `TRIAGE_UNKNOWN`, exact camera/full-stream closure,
  absence of PID-to-node attribution, `/proc` observations, PID-reuse defense,
  signal/early-error trap cleanup, and profile gate roles.

### Integration tests

- Run AgentOS offline with transport/process/ROS spies, an audit hook, syscall
  tracing, and graph snapshots; require zero transport, child-process, and ROS
  publication attempts and the expected artifacts.
- Run the complete workstation offline action and every descendant under the
  specified single serialized syscall trace. Require host-namespace OpenClaw
  listener observations before and after the isolated child, an unprivileged
  action namespace containing only loopback, `offline.trace_integrity: PASS`,
  `offline.network_policy: PASS`, exact marker-bounded allowance of the
  semantic fixture's DDS UDP4 operations through the four pinned Cyclone
  configurations, and zero other IP operations.
- Require strace 6.6 or newer, a passing `--kill-on-exit` capability probe,
  exact sanitized inherited descriptors, continuous tracer pidfd liveness,
  and verified kernel exit-kill of tracees if the tracer is terminated. After
  closure, independently recompute and match the trace, accepted ledger chain,
  ownership/violation journals, host observations, marker indices, and
  `offline_evidence_bundle_sha256` recorded in `result.json`.
- Verify exact OpenClaw/Node artifacts, the pinned local configuration,
  successful provisioning-schema validation, identical expected/installed
  payload manifests, `config validate`, both exact lint commands, and the
  absence of a gateway process/service/listener.
- Run the structured HMSG fixture and assert graph, object, room, pose, frame,
  and ROS endpoint counts, then match every resulting DDS syscall to the exact
  participant PID, BEGIN/END marker order, configuration digest, and fixed
  domain-77 port allowance.
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
  no installer child is created for either integrity mismatch. Change the
  registry response after verification and prove the installer still receives
  only the verified local `file:` package; alter one installed payload byte or
  add an unexpected payload path and require quarantine plus
  `INSTALLED_PAYLOAD_MISMATCH`.
- From a descendant outside the semantic gate, attempt TCP, UDP/DNS, and
  loopback traffic and require `offline.network_policy: FAIL`. During the gate,
  vary PID, marker position, protocol, destination, Cyclone config digest,
  participant index, socket mode, and DDS port independently and require
  failure; the exact namespace-confined DDS trace must pass. Attempt any host-
  namespace IP operation from either observer and require failure. Truncate the
  trace, remove/duplicate/reorder a marker, split a syscall across a marker, or
  simulate an unclosed PID with no complete prohibited operation and require
  `offline.trace_integrity: FAIL`, `offline.network_policy: SKIPPED`, and
  `FAIL_HARNESS`. First persist a complete unauthorized IP event and then
  truncate the trace or corrupt a later marker; require both finalizers to
  `FAIL`, preserve the violation journal, select `offline.network_policy` as
  the primary blocker, and return `FAIL_SAFETY`/30. Separately block before
  `semantic.fixture_query` and require no markers, no IP events, and
  `offline.trace_integrity: PASS` so an honest earlier functional failure is
  not remapped to a harness failure.
- Give the supervisor an inherited connected TCP or UDP socket in an ordinary
  FD and separately in fd 0, 1, or 2; attempt payload `write` without creating
  another socket and require preflight `INHERITED_SOCKET_FD` safety failure.
  Attempt to receive an already connected socket over `SCM_RIGHTS` and use it,
  and require `PROHIBITED_FD_TRANSFER` even though general `write` is not
  traced. Submit a socket operation through io_uring, including an SQPOLL case,
  and attempt `CLONE_UNTRACED` and `ptrace`; require the inherited seccomp
  policy to deny each operation, trace the attempt, journal it, and select the
  corresponding network-policy safety reason.
- Send HUP, INT, and TERM during early, semantic, postflight, and trace-close
  phases. Require distinct tracer/coordinator process groups, one identity-
  checked forward only to the coordinator PGID, coordinator postflight before
  trace closure, all three supervisor finalizers afterward, one authoritative
  result, and the precedence-defined exit. Kill the tracer before coordinator
  setup, while a descendant is live, and after all tracees exit; prove pidfd
  detection, kernel exit-kill, journal-based remainder cleanup, no continued
  profile progression, and the specified safety-versus-harness outcome. Kill
  the coordinator before it can seal the ledger; submit a stale predecessor,
  repeated generation, gap, fork, replay, and unacknowledged successor; and
  require synthesized `safety.workstation_postflight: FAIL`,
  `LEDGER_CHAIN_INVALID` where applicable, `FAIL_SAFETY`, and exit 30 even when
  tracing also fails.
- Replace or mutate the closed trace, any ledger generation or chain manifest,
  either journal, or either host-observer artifact between descriptor passes;
  alter recorded sizes/counts, accepted generation, or marker indices; and
  require `offline.evidence_binding: FAIL` with
  `EVIDENCE_BINDING_MISMATCH`. If a violation-journal mutation would conceal a
  previously persisted policy violation, require safety precedence. A stable
  untampered bundle must recompute from the child result and again during
  `offline.reference` acceptance.
- For every mode, pair each valid failure/qualification tuple with a label from
  another mode or domain and require schema rejection—for example, a
  workstation OpenClaw failure labeled `FAIL_PC2_STREAMS`, a PC2 lidar failure
  labeled `FAIL_OPENCLAW`, and a PC2 result using a workstation qualification.
- Show that a DDS-linked camera process is neutral; then launch or race a fake
  control-signature process during the PC2 window and require failure. Change
  one path/hash/UID/argv/parent field in the process allowlist or one independent
  aggregate ROS-graph field and require the corresponding monitor plane to fail
  safely in camera/full-stream profiles. Apply the same non-control changes in
  inventory and require `TRIAGE_UNKNOWN` diagnostic records without a safety
  failure; a known control signature must still fail inventory. Verify that
  evidence never claims a PID owns a ROS node.
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
a traced host coordinator, host listener observers before and after the action,
an isolated loopback-only action namespace, four digest-pinned Cyclone
configurations, and complete-process-tree tracing. Required source, runtime,
skill, AgentOS, semantic, chatbot dependency/configuration, OpenClaw, safety,
`offline.trace_integrity`, `offline.network_policy`, and
`offline.evidence_binding` gates must pass. Only the exact marker-bounded
semantic-fixture DDS allowance may contain IP operations.
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
   AgentOS, pinned semantic fixture, full-process-tree network tracing, and the
   result/provisioning evidence schemas and policies.
2. Workstation MuJoCo consolidation with explicit Stage 3 qualification.
3. PC2 inventory, bounded D435i action, full-stream diagnostics, continuous
   process observation, and handoff.

The first plan can pass without PC2 availability. The second reuses the
validated Stage 1-4 implementation. The third cannot claim full sensor streams
until PC2 produces native Mid360 lidar and IMU samples that satisfy the pinned
thresholds.
