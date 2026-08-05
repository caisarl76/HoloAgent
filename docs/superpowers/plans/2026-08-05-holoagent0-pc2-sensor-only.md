# HoloAgent-0 PC2 Sensor-Only Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build observation-only PC2 inventory, bounded D435i camera, and full-stream sensor profiles with continuous control-process monitoring, identity-safe cleanup, and no physical motion command.

**Architecture:** A stdlib-only Python package under `robots/unitree/holoagent0_pc2/` performs independent process-plane and aggregate ROS-graph checks; a small Bash wrapper owns traps and exact profile selection. Reviewed JSON allowlists are immutable inputs. The PC2 result consumes copied Plan 1 schema/policy data but imports no Plan 1 Python package, so the manifest is a closed runtime bundle. The copyable action contains no workstation provisioning, MuJoCo, Unitree command publisher, tmux, FIFO, Docker, daemon, or SDK control path.

**Tech Stack:** Python 3.10 standard library, pytest for workstation tests, Bash, Linux `/proc`, ELF metadata tools, ROS 2 Humble CLI/introspection, RealSense ROS, Livox ROS, copied Plan 1 JSON schemas and policies.

**Dependencies:** Complete Plan 1 contract/result work first. Run `inventory` before proposing host-specific allowlist entries. PC2 execution requires separate explicit action authorization; writing and testing this plan on the workstation does not authorize remote execution.

---

## File map

- `robots/unitree/holoagent0_pc2/allowlist.py`: closed process/graph policy loading.
- `robots/unitree/holoagent0_pc2/process_scan.py`: executable, argv, UID, parent, maps, and control-signature inventory.
- `robots/unitree/holoagent0_pc2/graph_scan.py`: independent aggregate ROS graph snapshot and QoS checks.
- `robots/unitree/holoagent0_pc2/monitor.py`: continuous two-plane sampling and append-only observations.
- `robots/unitree/holoagent0_pc2/camera.py`: owned D435i process group, bounded sampling, and cleanup identity.
- `robots/unitree/holoagent0_pc2/topics.py`: lidar/IMU/camera advertisement, sample, rate, and schema measurements.
- `robots/unitree/holoagent0_pc2/result.py`: fixed gate order, profile roles, finalizers, and atomic evidence.
- `robots/unitree/holoagent0_pc2/cli.py`: exact `inventory`, `camera`, or `full-streams` action.
- `robots/unitree/scripts/run_holoagent0_sensor_check.sh`: copyable fail-closed wrapper and traps.
- `robots/unitree/config/pc2_sensor_process_allowlist_v1.json`: host-specific process identities.
- `robots/unitree/config/pc2_sensor_graph_allowlist_v1.json`: exact aggregate graph per profile.
- `robots/unitree/config/pc2_sensor_allowlist_v1.schema.json`: closed allowlist schema.
- `robots/unitree/config/pc2_sensor_copy_manifest_v1.json`: exact copied runtime closure; the reviewed manifest digest is verified out of band and the manifest lists every other runtime file.
- `robots/unitree/tests/`: workstation fixtures plus subprocess/adversarial tests.

### Task 1: Closed PC2 allowlist schemas and profile roles

**Files:**
- Create: `robots/unitree/holoagent0_pc2/__init__.py`
- Create: `robots/unitree/holoagent0_pc2/allowlist.py`
- Create: `robots/unitree/config/pc2_sensor_allowlist_v1.schema.json`
- Create: `robots/unitree/config/pc2_sensor_process_allowlist_v1.json`
- Create: `robots/unitree/config/pc2_sensor_graph_allowlist_v1.json`
- Test: `robots/unitree/tests/test_pc2_allowlist.py`

- [ ] **Step 1: Write closed-schema and role tests**

```python
def test_camera_requires_exact_process_and_graph_match(policies):
    assert policies.profile("camera").process_requirement == "EXACT_MATCH"
    assert policies.profile("camera").graph_requirement == "EXACT_MATCH"


def test_inventory_allows_unknown_noncontrol_only(policies):
    assert policies.profile("inventory").accepted_states == {
        "EXACT_MATCH", "TRIAGE_UNKNOWN"
    }
    assert "CONTROL_VIOLATION" not in policies.profile("inventory").accepted_states
```

- [ ] **Step 2: Run and verify allowlist modules are absent**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_allowlist.py`

Expected: FAIL because schemas and loader do not exist.

- [ ] **Step 3: Implement closed policy models**

```python
@dataclass(frozen=True)
class ProcessRule:
    hostname: str
    executable_path: str
    executable_sha256: str
    uid: int
    argv_pattern: str
    parent_executable: str | None
    systemd_unit: str | None
    permitted_library_sha256: tuple[str, ...]


@dataclass(frozen=True)
class ProfilePolicy:
    name: Literal["inventory", "camera", "full-streams"]
    process_requirement: str
    graph_requirement: str
    accepted_states: frozenset[str]
```

Set `additionalProperties: false`, anchored argv regexes, literal host/path/hash/UID/parent/service fields, exact graph endpoint/type/QoS records, and reviewed control signatures. Leave host-specific unknown sensor entries unblessed until inventory evidence is reviewed.

- [ ] **Step 4: Run schema, wrong-field, and cross-profile tests**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_allowlist.py`

Expected: PASS; unknown fields and control signatures are rejected in every profile.

- [ ] **Step 5: Commit PC2 policy inputs**

```bash
git add robots/unitree/holoagent0_pc2 robots/unitree/config/pc2_sensor_allowlist_v1.schema.json robots/unitree/config/pc2_sensor_process_allowlist_v1.json robots/unitree/config/pc2_sensor_graph_allowlist_v1.json robots/unitree/tests/test_pc2_allowlist.py
git commit -m "feat: add closed pc2 sensor allowlists"
```

### Task 2: Process-plane inventory and control denylist

**Files:**
- Create: `robots/unitree/holoagent0_pc2/process_scan.py`
- Create: `robots/unitree/config/pc2_control_signatures_v1.json`
- Test: `robots/unitree/tests/test_pc2_process_scan.py`
- Create: `robots/unitree/tests/fixtures/proc/dds-sensor.json`
- Create: `robots/unitree/tests/fixtures/proc/g1-pubvel.json`
- Create: `robots/unitree/tests/fixtures/proc/unknown-sdk-sensor.json`
- Create: `robots/unitree/tests/fixtures/proc/pid-reuse.json`

- [ ] **Step 1: Write `/proc` fixture tests**

```python
def test_dds_library_alone_is_neutral(proc_fixture, scanner):
    proc_fixture.add_process(exe="/opt/ros/camera", maps=["librmw_cyclonedds_cpp.so"])
    result = scanner.scan(proc_fixture.root)
    assert result.state != "CONTROL_VIOLATION"


@pytest.mark.parametrize("name", ["g1_pubvel_node", "g1_pubmove_node", "g1_pubcmd_node"])
def test_known_command_binary_is_control_violation(proc_fixture, scanner, name):
    proc_fixture.add_process(exe=f"/repo/install/g1_move/lib/g1_move/{name}")
    assert scanner.scan(proc_fixture.root).state == "CONTROL_VIOLATION"
```

- [ ] **Step 2: Run and verify scanner absence**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_process_scan.py`

Expected: FAIL because process scanning is absent.

- [ ] **Step 3: Implement independent process classification**

```python
@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pgid: int
    start_time: int
    uid: int
    exe: str
    exe_sha256: str
    argv: tuple[str, ...]
    parent_exe: str | None
    libraries: tuple[str, ...]


def classify_process(identity: ProcessIdentity, policy: ProcessPolicy) -> str:
    if policy.matches_control(identity):
        return "CONTROL_VIOLATION"
    if policy.matches_sensor(identity):
        return "EXACT_MATCH"
    return "TRIAGE_UNKNOWN"
```

Inventory executable files under the Unitree repository and overlays, ELF dependencies, `/proc/*/exe`, `cmdline`, `maps`, UID, parent, PGID, and start time. Parse dynamic sections with `readelf -d`/`objdump -p`; never use `ldd` on an untrusted candidate. Generic DDS linkage stays neutral; an SDK/control library becomes a violation only with a reviewed control argv/executable signature. The scanner makes no PID-to-ROS-node claim.

- [ ] **Step 4: Run process fixtures and live read-only smoke test**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_process_scan.py`

Expected: PASS, including PID reuse, unreadable `/proc` entry, disappearing process, neutral DDS, unknown sensor, and known control cases.

- [ ] **Step 5: Commit process scanning**

```bash
git add robots/unitree/holoagent0_pc2/process_scan.py robots/unitree/config/pc2_control_signatures_v1.json robots/unitree/tests
git commit -m "feat: add pc2 process-plane scanner"
```

### Task 3: Independent aggregate ROS graph scanner

**Files:**
- Create: `robots/unitree/holoagent0_pc2/graph_scan.py`
- Test: `robots/unitree/tests/test_pc2_graph_scan.py`
- Create: `robots/unitree/tests/fixtures/graphs/inventory-unknown.json`
- Create: `robots/unitree/tests/fixtures/graphs/camera-exact.json`
- Create: `robots/unitree/tests/fixtures/graphs/camera-extra.json`
- Create: `robots/unitree/tests/fixtures/graphs/cmd-vel-control.json`

- [ ] **Step 1: Write exact-closure tests**

```python
def test_cmd_vel_subscription_is_control_violation(graph_scanner):
    graph = graph_fixture(subscriptions=[("/cmd_vel", "geometry_msgs/msg/Twist")])
    assert graph_scanner.classify("inventory", graph).state == "CONTROL_VIOLATION"


def test_camera_extra_endpoint_breaks_exact_closure(graph_scanner):
    graph = approved_camera_graph().with_publisher("/unexpected", "std_msgs/msg/String")
    assert graph_scanner.classify("camera", graph).state == "TRIAGE_UNKNOWN"
```

- [ ] **Step 2: Run and verify graph scanner absence**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_graph_scan.py`

Expected: FAIL because aggregate graph normalization is absent.

- [ ] **Step 3: Implement normalized graph snapshots**

```python
@dataclass(frozen=True)
class Endpoint:
    node: str
    namespace: str
    direction: Literal["publisher", "subscriber", "service", "action"]
    name: str
    interface_type: str
    qos: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class GraphSnapshot:
    nodes: tuple[tuple[str, str], ...]
    endpoints: tuple[Endpoint, ...]
```

Run with `ROS2CLI_DISABLE_DAEMON=1`. Normalize sorted node/endpoint/service/action/type/QoS data. Compare the aggregate snapshot independently with the selected profile policy. Any control endpoint is `CONTROL_VIOLATION`; camera/full-stream profiles require exact closure; inventory records non-control divergence as `TRIAGE_UNKNOWN`.

- [ ] **Step 4: Run graph fixtures**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_graph_scan.py`

Expected: PASS with no evidence field claiming a PID owns an endpoint.

- [ ] **Step 5: Commit graph scanning**

```bash
git add robots/unitree/holoagent0_pc2/graph_scan.py robots/unitree/tests/test_pc2_graph_scan.py robots/unitree/tests/fixtures/graphs
git commit -m "feat: add pc2 aggregate graph scanner"
```

### Task 4: Continuous two-plane monitor

**Files:**
- Create: `robots/unitree/holoagent0_pc2/monitor.py`
- Test: `robots/unitree/tests/test_pc2_monitor.py`

- [ ] **Step 1: Write race-window and monitor-death tests**

```python
def test_transient_control_process_is_not_missed(monitor, proc_source):
    monitor.start()
    proc_source.flash_control_process(samples=1)
    result = monitor.stop_and_finalize()
    assert result.state == "CONTROL_VIOLATION"


def test_monitor_exit_is_safety_failure(runner):
    result = runner.run(profile="camera", fault="MONITOR_EXITED")
    assert result.primary_blocking_gate == "safety.pc2_runtime_monitor"
    assert result.exit_code == 30
```

- [ ] **Step 2: Run and verify monitor absence**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_monitor.py`

Expected: FAIL because monitor ownership and append-only samples are missing.

- [ ] **Step 3: Implement continuous sampling**

```python
class SafetyMonitor:
    def start(self) -> MonitorIdentity:
        return self._spawn_owned_sampler()

    def assert_live(self) -> None:
        if not self._identity.matches_proc():
            raise SafetyViolation("MONITOR_EXITED")

    def stop_and_finalize(self) -> MonitorResult:
        return self._seal_last_sample_after_owned_cleanup()
```

Start before any sensor launch/sample action. Sample `/proc` at 20 Hz and the aggregate ROS graph before action, after readiness, at 1 Hz throughout measurement, and during postflight. Write canonical append-only records atomically, require monitor identity throughout cleanup, and seal a terminal sample. Inventory accepts `TRIAGE_UNKNOWN`; camera/full-stream fail on any transition away from `EXACT_MATCH`; every profile fails on `CONTROL_VIOLATION`.

- [ ] **Step 4: Run monitor timing and signal tests**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_monitor.py`

Expected: PASS for transient/raced control processes, graph divergence, monitor exit, and terminal-sample absence.

- [ ] **Step 5: Commit runtime monitoring**

```bash
git add robots/unitree/holoagent0_pc2/monitor.py robots/unitree/tests/test_pc2_monitor.py
git commit -m "feat: continuously monitor pc2 sensor safety"
```

### Task 5: Owned D435i action and sensor measurements

**Files:**
- Create: `robots/unitree/holoagent0_pc2/camera.py`
- Create: `robots/unitree/holoagent0_pc2/topics.py`
- Test: `robots/unitree/tests/test_pc2_camera.py`
- Test: `robots/unitree/tests/test_pc2_topics.py`

- [ ] **Step 1: Write ownership, cleanup, and profile-role tests**

```python
def test_camera_cleanup_rejects_pid_reuse(camera_action):
    owned = camera_action.start()
    camera_action.proc.replace_start_time(owned.pid)
    result = camera_action.cleanup()
    assert result.reason == "OWNERSHIP_MISMATCH"


def test_inactive_lidar_is_diagnostic_for_camera(topic_result):
    gates = classify_topics("camera", topic_result(lidar_sample=None))
    assert gates["pc2.lidar_sample"].role == "diagnostic"
    assert gates["pc2.lidar_sample"].status == "FAIL"
```

- [ ] **Step 2: Run and verify camera/topic modules are absent**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_camera.py robots/unitree/tests/test_pc2_topics.py`

Expected: FAIL because owned camera and topic classifiers are missing.

- [ ] **Step 3: Implement bounded action and measurements**

```python
@dataclass(frozen=True)
class OwnedProcess:
    pid: int
    pgid: int
    start_time: int
    executable: str
    executable_sha256: str


@dataclass(frozen=True)
class TopicMeasurement:
    advertised: bool
    samples: int
    rate_hz: float | None
    finite: bool | None
    schema_ok: bool | None
```

Launch only the exact reviewed RealSense command in a new session/PGID after both allowlists pass. Record identity before action. After 5 s warmup, require D435i color to produce at least 100 samples/10 s and 15.0 Hz with finite monotonic stamps, nonzero dimensions, and supported encoding; Mid360 `PointCloud2` to produce at least 80 samples/10 s and 8.0 Hz with finite monotonic stamps, nonzero width/point-step, and recorded `PointField` schema; and Mid360 IMU to produce at least 1,000 samples/10 s and 100.0 Hz with finite stamps, vectors, and covariances. Camera/full-stream camera gates are required; lidar/IMU are diagnostic in camera and required in full-stream. Cleanup only a matching identity through bounded TERM/wait/KILL and always re-run process/graph final checks.

- [ ] **Step 4: Run ownership, rates, schema, and cleanup tests**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_camera.py robots/unitree/tests/test_pc2_topics.py`

Expected: PASS for absent hardware, no sample, low rate, malformed schema, PID reuse, signal escalation, and no-owned-camera cleanup.

- [ ] **Step 5: Commit camera and topic gates**

```bash
git add robots/unitree/holoagent0_pc2/camera.py robots/unitree/holoagent0_pc2/topics.py robots/unitree/tests/test_pc2_camera.py robots/unitree/tests/test_pc2_topics.py
git commit -m "feat: add bounded pc2 camera and topic gates"
```

### Task 6: PC2 result engine and trap-owned finalizers

**Files:**
- Create: `robots/unitree/holoagent0_pc2/result.py`
- Create: `robots/unitree/holoagent0_pc2/cli.py`
- Create: `robots/unitree/scripts/run_holoagent0_sensor_check.sh`
- Create: `robots/unitree/config/pc2_sensor_copy_manifest_v1.json`
- Test: `robots/unitree/tests/test_pc2_result.py`
- Test: `robots/unitree/tests/test_pc2_cli.py`

- [ ] **Step 1: Write total-order and interruption tests**

```python
def test_cleanup_failure_wins_over_camera_rate(result_builder):
    result = result_builder.camera(
        functional_failure="pc2.camera_rate",
        cleanup_failure="pc2.camera_cleanup",
    )
    assert result.blocking_gates == ["pc2.camera_rate", "pc2.camera_cleanup"]
    assert result.primary_blocking_gate == "pc2.camera_cleanup"
    assert result.label == "FAIL_SAFETY"


@pytest.mark.parametrize("signal,code", [("HUP", 129), ("INT", 130), ("TERM", 143)])
def test_signal_exit_survives_only_after_finalizers(runner, signal, code):
    result = runner.interrupt(signal, finalizers="PASS")
    assert result.label == "INTERRUPTED"
    assert result.exit_code == code
```

- [ ] **Step 2: Run and verify result/CLI absence**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_result.py robots/unitree/tests/test_pc2_cli.py`

Expected: FAIL because PC2 result and wrapper are absent.

- [ ] **Step 3: Implement exact profiles and traps**

```bash
#!/usr/bin/env bash
set -Eeuo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
bundle_root="$(cd -- "${script_dir}/../../.." && pwd -P)"
profile="${1:?profile must be inventory, camera, or full-streams}"
case "${profile}" in inventory|camera|full-streams) ;; *) exit 40 ;; esac
shift
output_root=""
while (($#)); do
  case "$1" in
    --output-root) (($# >= 2)) || exit 40; output_root="$2"; shift 2 ;;
    *) exit 40 ;;
  esac
done
[[ -n "${output_root}" ]] || exit 40
mkdir -p -- "${output_root}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-${BASHPID}"
run_dir="${output_root%/}/${run_id}"
(umask 077 && mkdir -- "${run_dir}") || exit 40
export PYTHONNOUSERSITE=1
export PYTHONPATH="${bundle_root}/robots/unitree"
child_pid=""
received_signal=""
finalize() {
  prior_exit="$?"
  trap - EXIT HUP INT TERM
  set +e
  python3 -m holoagent0_pc2.cli finalize \
    --bundle-root "${bundle_root}" --run-dir "${run_dir}" \
    --child-pid "${child_pid}" \
    --signal "${received_signal}" --prior-exit "${prior_exit}"
  final_exit="$?"
  exit "${final_exit}"
}
trap finalize EXIT
trap 'received_signal=HUP; exit 129' HUP
trap 'received_signal=INT; exit 130' INT
trap 'received_signal=TERM; exit 143' TERM
python3 -m holoagent0_pc2.cli run "${profile}" \
  --bundle-root "${bundle_root}" --run-dir "${run_dir}" &
child_pid="$!"
set +e
wait "${child_pid}"
child_exit="$?"
set -e
exit "${child_exit}"
```

The shell excerpt is normative for argument ownership, bundle-root discovery, run-directory creation, and module search; implementation may factor parsing helpers but must preserve that observable contract. The sole operator-facing CLI is `run_holoagent0_sensor_check.sh PROFILE --output-root DIR`. `HOLOAGENT0_RUN_DIR`, caller `PYTHONPATH`, and caller working directory are neither required nor trusted. The wrapper derives `bundle_root` from its resolved script location, resets `PYTHONPATH` to the copied `robots/unitree` root, creates one mode-`0700` run directory beneath `--output-root`, and passes that exact path to internal `python3 -m holoagent0_pc2.cli run/finalize` subcommands. Do not forward `${@:2}` after the parser consumes arguments; the final implementation passes only the closed arguments it constructed.

Before action, the wrapper verifies its own SHA-256 and every copied policy/package file against `pc2_sensor_copy_manifest_v1.json`; a local/remote mismatch fails before monitor or sensor startup. The manifest itself is not self-hashed: its reviewed SHA-256 is compared before transfer and again on PC2, then the verified manifest authenticates every listed payload file. The Python `run` command starts in an owned PGID and writes its PID/PGID/start-time/executable identity before action; `finalize` validates that identity rather than trusting the PID argument alone. The idempotent finalizer stops owned camera, seals monitor, runs final independent scans, validates schema, writes atomically, and applies safety → harness → interruption → functional → pass precedence.

- [ ] **Step 4: Run shell syntax and finalizer tests**

Run: `bash -n robots/unitree/scripts/run_holoagent0_sensor_check.sh && PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_result.py robots/unitree/tests/test_pc2_cli.py`

Expected: PASS for all three profiles, early errors, each signal phase, double traps, invalid JSON, and combined functional/finalizer failures.

- [ ] **Step 5: Commit the PC2 runner**

```bash
git add robots/unitree/holoagent0_pc2/result.py robots/unitree/holoagent0_pc2/cli.py robots/unitree/scripts/run_holoagent0_sensor_check.sh robots/unitree/config/pc2_sensor_copy_manifest_v1.json robots/unitree/tests/test_pc2_result.py robots/unitree/tests/test_pc2_cli.py
git commit -m "feat: add pc2 sensor-only profile runner"
```

### Task 7: Static no-motion proof and adversarial profile integration

**Files:**
- Create: `robots/unitree/tests/test_pc2_no_motion_static.py`
- Create: `robots/unitree/tests/test_pc2_integration.py`
- Create: `robots/unitree/tests/test_pc2_adversarial.py`

- [ ] **Step 1: Write source/import/command denylist tests**

```python
PROHIBITED = (
    "g1_pubvel_node", "g1_pubmove_node", "g1_pubcmd_node",
    "run_ctl.sh", "run_armctl.sh", "run_velctl.sh", "robot_bridge",
    "mkfifo", "tmux", "docker", "unitree_sdk2", "nav2",
)


def test_pc2_action_has_no_motion_path(action_sources):
    text = "\n".join(path.read_text() for path in action_sources)
    for token in PROHIBITED:
        assert token not in text
```

- [ ] **Step 2: Run and verify any unsafe reference fails**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_no_motion_static.py robots/unitree/tests/test_pc2_integration.py robots/unitree/tests/test_pc2_adversarial.py`

Expected: FAIL until all fixtures and action source boundaries are registered.

- [ ] **Step 3: Add fake ROS/process integration harnesses**

Exercise inventory with inactive lidar/IMU and unknown non-control sensor; camera exact closure with owned D435i; full-stream required lidar/IMU; a one-sample raced control process; extra graph endpoint; monitor death; camera cleanup failure; PID reuse; HUP/INT/TERM at every phase; invalid result plus safety failure; and final process/graph divergence. Assert labels, exits, all gate statuses, finalizer precedence, and no PID-to-node attribution.

- [ ] **Step 4: Run the complete workstation PC2 test set**

Run: `bash -n robots/unitree/scripts/run_holoagent0_sensor_check.sh && PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests && git diff --check`

Expected: at least one test collected, zero failures, and no diff-check output.

- [ ] **Step 5: Commit adversarial coverage**

```bash
git add robots/unitree/tests
git commit -m "test: cover pc2 sensor-only safety boundary"
```

### Task 8: PC2 copy manifest, execution runbook, and handoff

**Files:**
- Modify: `robots/unitree/config/pc2_sensor_copy_manifest_v1.json`
- Create: `docs/holoagent0/pc2-sensor-only-runbook.md`
- Create: `docs/holoagent0/handoff-template.md`
- Test: `robots/unitree/tests/test_pc2_runbook.py`

- [ ] **Step 1: Write copy-manifest and runbook tests**

```python
def test_copy_manifest_is_closed_and_hashed(copy_manifest):
    assert copy_manifest["schema"] == "holoagent0.pc2-copy-manifest.v1"
    assert tuple(item["path"] for item in copy_manifest["files"]) == PC2_RUNTIME_PATHS
    assert all(len(item["sha256"]) == 64 for item in copy_manifest["files"])


def test_manifest_only_bundle_runs_inventory_from_neutral_cwd(
    tmp_path, copy_manifest, fake_ros_path
):
    bundle = copy_manifest_and_only_its_payloads(tmp_path / "bundle", copy_manifest)
    neutral = tmp_path / "neutral"
    neutral.mkdir()
    completed = subprocess.run(
        [bundle / "robots/unitree/scripts/run_holoagent0_sensor_check.sh",
         "inventory", "--output-root", tmp_path / "evidence"],
        cwd=neutral,
        env=minimal_pc2_env(PATH=fake_ros_path),
        text=True,
        capture_output=True,
    )
    result = load_single_result(tmp_path / "evidence")
    assert result["mode"] == "pc2_inventory"
    assert validates_against_copied_contract(result, bundle)
    assert "ModuleNotFoundError" not in completed.stderr


def test_runbook_starts_inventory_only(runbook):
    assert runbook.index(" inventory ") < runbook.index(" camera ")
    assert "run_ctl.sh" not in runbook
```

- [ ] **Step 2: Run and verify runbook absence**

Run: `PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests/test_pc2_runbook.py`

Expected: FAIL because the closed manifest smoke test and runbook are absent.

- [ ] **Step 3: Document the authorized sequence and evidence**

Define `PC2_RUNTIME_PATHS` as this exact sorted closure, with no globbing or directory entries:

```text
robots/unitree/config/pc2_control_signatures_v1.json
robots/unitree/config/pc2_sensor_allowlist_v1.schema.json
robots/unitree/config/pc2_sensor_graph_allowlist_v1.json
robots/unitree/config/pc2_sensor_process_allowlist_v1.json
robots/unitree/holoagent0_pc2/__init__.py
robots/unitree/holoagent0_pc2/allowlist.py
robots/unitree/holoagent0_pc2/camera.py
robots/unitree/holoagent0_pc2/cli.py
robots/unitree/holoagent0_pc2/graph_scan.py
robots/unitree/holoagent0_pc2/monitor.py
robots/unitree/holoagent0_pc2/process_scan.py
robots/unitree/holoagent0_pc2/result.py
robots/unitree/holoagent0_pc2/topics.py
robots/unitree/scripts/run_holoagent0_sensor_check.sh
scripts/holoagent0_setup/policies/holoagent0-gate-policy-v1.json
scripts/holoagent0_setup/policies/holoagent0-reason-codes-v1.json
scripts/holoagent0_setup/schemas/holoagent0-result-v1.schema.json
```

`pc2_sensor_copy_manifest_v1.json` contains one regular-file SHA-256 record for every path above and no other payload path; its path set must equal `PC2_RUNTIME_PATHS` exactly. The PC2 package must use only Python 3.10 standard-library imports plus ROS subprocesses, and it loads the three copied Plan 1 contract files as data. It must not import `holoagent0_setup`, depend on the repository working directory, preserve caller `PYTHONPATH`, or search outside `bundle_root`. An import-graph test enforces that closure, while the subprocess smoke test copies only the manifest plus its listed payloads, runs the published inventory command from a neutral directory with fake ROS commands on `PATH`, and requires a contract-valid `pc2_inventory` result rather than merely a successful `--help` import.

The runbook must first compare the reviewed manifest SHA-256 locally and remotely, verify every listed payload SHA-256, run `inventory` through the one public wrapper CLI, stop for review of every `TRIAGE_UNKNOWN`, and require updated reviewed allowlists before camera/full-stream profiles. Include exact commands for result validation and evidence retrieval, but do not include SSH credentials, PC2 mutation outside the copied action, or any motion command.

```bash
bash robots/unitree/scripts/run_holoagent0_sensor_check.sh inventory --output-root ./holoagent0-evidence
jq '{label,status,primary_blocking_gate,blocking_gates}' ./holoagent0-evidence/*/result.json
```

The handoff template records commit, script/config hashes, hostname, profile, evidence path, qualifications, inactive hardware, and the exact claim “no Unitree control process was observed during the bounded sensor action.” It states that physical motion is not commissioned.

- [ ] **Step 4: Run final PC2 static verification**

Run: `bash -n robots/unitree/scripts/run_holoagent0_sensor_check.sh && PYTHONPATH=robots/unitree python3 -m pytest -q robots/unitree/tests && git diff --check`

Expected: zero failures and no diff-check output.

- [ ] **Step 5: Commit runbook and handoff**

```bash
git add robots/unitree/config/pc2_sensor_copy_manifest_v1.json docs/holoagent0/pc2-sensor-only-runbook.md docs/holoagent0/handoff-template.md robots/unitree/tests/test_pc2_runbook.py
git commit -m "docs: add pc2 sensor-only handoff"
```

## Plan 3 completion gate

Workstation tests may complete without PC2. A remote `PASS_PC2_SENSOR_INVENTORY` requires the reviewed copy manifest and continuous observation but may classify inactive lidar/IMU diagnostically. Do not run `camera` until inventory observations are reviewed and both allowlists close exactly. Do not claim `PASS_PC2_SENSOR_STREAMS` until native Mid360 lidar and IMU produce samples and rates satisfying every required gate. No result from this plan commissions physical motion.
