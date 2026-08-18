# HoloAgent-0 Workstation Offline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the approved `workstation_offline` core and a fail-closed public
Task 13 checkpoint: deterministic offline gates, pinned assets, supervisor-only
evidence, and a production CLI that cannot launch while the reviewed live trace
runtime remains unavailable.

**Architecture:** A small Python package under `scripts/holoagent0_setup/` owns closed schemas, policies, immutable ledgers, result classification, trace normalization, and the supervisor/coordinator split. Native launch helpers establish the inherited-FD, signal, seccomp, ptrace, and namespace boundaries before Python functional gates run. The supervisor alone publishes `result.json`; the traced coordinator can only submit hash-chained ledger generations over reviewed anonymous pipes.

**Tech Stack:** Python 3.10, pytest, JSON Schema Draft 2020-12, Bash, C17/Linux syscalls, strace 6.6, Linux user/network namespaces, seccomp, ROS 2 Humble, CycloneDDS, OpenClaw 2026.7.1-2, SHA-256/SHA-512.

**Dependency:** Begin from the approved design lineage through `6557b1f` and the
one-shot run-root/wrapper hardening committed with this plan amendment. This
plan produces the shared result/policy package later consumed by separately
approved live-runtime, MuJoCo, and PC2 plans.

---

## File map

Create these focused units:

- `scripts/holoagent0_setup/holoagent0_setup/contract.py`: load and validate closed schemas/policies.
- `scripts/holoagent0_setup/holoagent0_setup/invocation.py`: immutable mode/run/output arguments shared by every runner.
- `scripts/holoagent0_setup/holoagent0_setup/atomic_io.py`: no-follow reads, durable atomic writes, and digest descriptors.
- `scripts/holoagent0_setup/holoagent0_setup/result_policy.py`: gate transitions, precedence, mode-to-label mapping, and final tuple validation.
- `scripts/holoagent0_setup/holoagent0_setup/ledger.py`: immutable acknowledged ledger generations.
- `scripts/holoagent0_setup/holoagent0_setup/broker.py`: bounded request/response framing, including the two-way signal-readiness barrier.
- `scripts/holoagent0_setup/holoagent0_setup/trace_normalizer.py`: pinned strace grammar to canonical payload-free NDJSON.
- `scripts/holoagent0_setup/holoagent0_setup/trace_policy.py`: FD provenance, marker validation, and network-policy decisions.
- `scripts/holoagent0_setup/holoagent0_setup/process_identity.py`: PID/PGID/start-time/executable/pidfd identity checks.
- `scripts/holoagent0_setup/holoagent0_setup/evidence.py`: stable descriptor snapshots and bundle digest.
- `scripts/holoagent0_setup/holoagent0_setup/supervisor.py`: bootstrap, tracer ownership, signal collection, finalizers, and authoritative exit.
- `scripts/holoagent0_setup/holoagent0_setup/coordinator.py`: host observers, isolated action child, gate execution, and provisional ledger sealing.
- `scripts/holoagent0_setup/holoagent0_setup/agentos_gate.py`, `openclaw_gate.py`, `semantic_gate.py`, `chatbot_gate.py`, `skills_gate.py`: functional gate adapters.
- `scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py`: fixed pending-runtime production composition and the closed internal factory protocol.
- `scripts/holoagent0_setup/holoagent0_setup/offline_cli.py`: the public `workstation_offline` command.
- `scripts/holoagent0_setup/run_workstation_offline.sh`: neutral-working-directory public wrapper with fixed Python and motion-deny environment.
- `scripts/holoagent0_setup/native/tracee_launcher.c`: final FD layout, process group/session setup, prctl markers, and coordinator exec.
- `scripts/holoagent0_setup/native/finalizer_only.c`: sanitized trace root for bootstrap finalization.
- `scripts/holoagent0_setup/native/seccomp_policy.c`: deny the exact io_uring, `pidfd_getfd`, ptrace, and untraced-clone bypasses while leaving message syscalls traceable.
- `scripts/holoagent0_setup/tests/`: unit, integration, fixture, and adversarial tests mirroring the approved gate catalog.

### Task 1: Package skeleton and deterministic test entrypoint

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/__init__.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/constants.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/invocation.py`
- Create: `scripts/holoagent0_setup/tests/conftest.py`
- Create: `scripts/holoagent0_setup/tests/test_constants.py`
- Create: `scripts/holoagent0_setup/test-manifest-v1.txt`
- Create: `scripts/holoagent0_setup/README.md`

- [ ] **Step 1: Write the failing package-contract test**

```python
# scripts/holoagent0_setup/tests/test_constants.py
from holoagent0_setup.constants import OFFLINE_GATE_ORDER, PROFILE_MODES


def test_offline_gate_order_is_closed() -> None:
    assert PROFILE_MODES == (
        "workstation_offline", "workstation_mujoco",
        "pc2_inventory", "pc2_camera", "pc2_full_streams",
    )
    assert len(OFFLINE_GATE_ORDER) == 27
    assert OFFLINE_GATE_ORDER[:4] == (
        "source.repository", "runtime.workstation",
        "safety.workstation_preflight", "openclaw.preexisting",
    )
    assert OFFLINE_GATE_ORDER[-4:] == (
        "safety.workstation_postflight", "offline.trace_integrity",
        "offline.network_policy", "offline.evidence_binding",
    )
```

- [ ] **Step 2: Run the focused test and verify collection fails**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_constants.py`

Expected: FAIL during import because `holoagent0_setup.constants` does not exist.

- [ ] **Step 3: Add immutable constants and a manifest runner**

```python
# scripts/holoagent0_setup/holoagent0_setup/constants.py
PROFILE_MODES = (
    "workstation_offline", "workstation_mujoco",
    "pc2_inventory", "pc2_camera", "pc2_full_streams",
)
OFFLINE_GATE_ORDER = (
    "source.repository", "runtime.workstation", "safety.workstation_preflight",
    "openclaw.preexisting", "openclaw.version_pin",
    "openclaw.registry_integrity", "openclaw.config_pin",
    "openclaw.config_validate", "openclaw.doctor_lint", "skills.registry",
    "skills.dry_run", "agentos.plan_schema", "agentos.offline_execution",
    "agentos.network_attempts", "source.semantic_blobs", "semantic.asset_lock",
    "semantic.fixture_graph", "semantic.fixture_query",
    "semantic.natural_language_parser", "chatbot.dependencies",
    "chatbot.configuration", "chatbot.credentials", "chatbot.audio_hardware",
    "safety.workstation_postflight", "offline.trace_integrity",
    "offline.network_policy", "offline.evidence_binding",
)


@dataclass(frozen=True)
class OfflineInvocation:
    mode: Literal["workstation_offline"]
    output_root: Path
    run_id: str
    invocation_role: Literal["standalone", "child"]
    parent_run_id: str | None
    lineage_nonce: str | None

    @property
    def result_path(self) -> Path:
        return self.output_root / self.run_id / "result.json"
```

Put every tracked test path, one per line, in `test-manifest-v1.txt`; the runner must reject missing entries and zero collected tests rather than compare a historical test count.

- [ ] **Step 4: Run the focused test and manifest smoke check**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_constants.py`

Expected: PASS.

- [ ] **Step 5: Commit the package skeleton**

```bash
git add scripts/holoagent0_setup
git commit -m "test: scaffold holoagent0 offline package"
```

### Task 2: Closed schemas, policy files, and contract loader

**Files:**
- Create: `scripts/holoagent0_setup/schemas/holoagent0-result-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/holoagent0-offline-ledger-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/holoagent0-trace-tool-policy-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/openclaw-provisioning-v1.schema.json`
- Create: `scripts/holoagent0_setup/schemas/agentos-plan-v1.schema.json`
- Create: `scripts/holoagent0_setup/policies/holoagent0-gate-policy-v1.json`
- Create: `scripts/holoagent0_setup/policies/holoagent0-reason-codes-v1.json`
- Create: `scripts/holoagent0_setup/policies/holoagent0-trace-tool-v1.json`
- Create: `scripts/holoagent0_setup/holoagent0_setup/contract.py`
- Test: `scripts/holoagent0_setup/tests/test_contract.py`

- [ ] **Step 1: Write adversarial schema and policy tests**

```python
def test_wrong_mode_label_is_rejected(contract, offline_pass_result):
    offline_pass_result["label"] = "FAIL_PC2_STREAMS"
    assert contract.validate_result(offline_pass_result).code == "EVIDENCE_SCHEMA_INVALID"


def test_unknown_reason_is_rejected(contract, offline_pass_result):
    offline_pass_result["gates"][0]["reason"] = "LOCAL_REASON"
    assert contract.validate_result(offline_pass_result).code == "EVIDENCE_SCHEMA_INVALID"


def test_trace_tool_policy_has_one_exact_row(contract):
    row = contract.trace_tool_rows()
    assert len(row) == 1
    assert row[0]["version"] == "6.6"
    assert row[0]["source"]["size"] == 2420364
    assert row[0]["source"]["sha256"] == "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
```

- [ ] **Step 2: Run tests and verify missing contract files fail**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_contract.py`

Expected: FAIL because schemas, policies, and `ContractSet` are absent.

- [ ] **Step 3: Implement the closed loader and validators**

```python
@dataclass(frozen=True)
class ValidationDecision:
    ok: bool
    code: str
    errors: tuple[str, ...] = ()


class ContractSet:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)
        self.schemas = _load_closed_json(self.root / "schemas")
        self.policies = _load_closed_json(self.root / "policies")

    def validate_result(self, value: Mapping[str, object]) -> ValidationDecision:
        schema_errors = tuple(_schema_errors(self.schemas["holoagent0-result-v1"], value))
        policy_errors = tuple(_policy_errors(self.policies, value))
        errors = schema_errors + policy_errors
        return ValidationDecision(not errors, "OK" if not errors else "EVIDENCE_SCHEMA_INVALID", errors)
```

Encode all gate IDs, roles, statuses, reason-code contexts, label/status/exit tuples, per-mode failure selectors, qualification sets, interruption tuples, and `additionalProperties: false` branches from the approved design. Record literal reviewed digests; never learn them from a run.

- [ ] **Step 4: Run positive and wrong-mode tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_contract.py`

Expected: PASS, including every cross-mode adversarial fixture.

- [ ] **Step 5: Commit schemas and policies**

```bash
git add scripts/holoagent0_setup/schemas scripts/holoagent0_setup/policies scripts/holoagent0_setup/holoagent0_setup/contract.py scripts/holoagent0_setup/tests/test_contract.py
git commit -m "feat: add closed holoagent0 evidence contracts"
```

### Task 3: Durable atomic I/O, result policy, and immutable ledgers

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/atomic_io.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/result_policy.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/ledger.py`
- Test: `scripts/holoagent0_setup/tests/test_atomic_io.py`
- Test: `scripts/holoagent0_setup/tests/test_result_policy.py`
- Test: `scripts/holoagent0_setup/tests/test_ledger.py`

- [ ] **Step 1: Write red tests for no-replace generations and precedence**

```python
def test_generation_replay_is_rejected(tmp_path, contract):
    ledger = LedgerStore.create(tmp_path / "ledger", contract, run_nonce="n-1")
    first = ledger.append(LedgerCandidate(1, 0, ledger.head.digest, gate_pass("source.repository")))
    with pytest.raises(LedgerChainError, match="repeated generation"):
        ledger.append(LedgerCandidate(1, 0, ledger.genesis.digest, gate_pass("source.repository")))
    assert ledger.head == first


def test_safety_finalizer_beats_functional_and_interrupt(policy):
    decision = policy.decide(mode="pc2_camera", gates=[
        gate_fail("pc2.camera_rate", "RATE_BELOW_THRESHOLD"),
        gate_fail("pc2.camera_cleanup", "CLEANUP_INCOMPLETE"),
    ], signal="TERM")
    assert (decision.label, decision.exit_code, decision.primary) == (
        "FAIL_SAFETY", 30, "pc2.camera_cleanup")
```

- [ ] **Step 2: Run tests and verify failures**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_atomic_io.py scripts/holoagent0_setup/tests/test_result_policy.py scripts/holoagent0_setup/tests/test_ledger.py`

Expected: FAIL because durable write, decision, and ledger APIs are missing.

- [ ] **Step 3: Implement exact public types and durable writes**

```python
@dataclass(frozen=True)
class ArtifactDescriptor:
    relative_path: str
    sha256: str
    size: int
    inode: int
    device: int


def atomic_write_json(path: Path, value: Mapping[str, object], mode: int = 0o600) -> ArtifactDescriptor:
    """Write canonical JSON through a same-directory temp, fsync file/dir, and replace."""


@dataclass(frozen=True)
class LedgerHead:
    generation: int
    digest: str
    sealed: bool


class LedgerStore:
    @classmethod
    def create(cls, root: Path, contract: ContractSet, run_nonce: str) -> "LedgerStore":
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        genesis = build_generation_zero(run_nonce)
        descriptor = atomic_write_json_no_replace(root / "generation-000000.json", genesis)
        return cls(root=root, contract=contract, head=LedgerHead(0, descriptor.sha256, False))

    def append(self, candidate: LedgerCandidate) -> LedgerHead:
        self._validate_successor(candidate)
        path = self.root / f"generation-{candidate.generation:06d}.json"
        descriptor = atomic_write_json_no_replace(path, candidate.as_json())
        self.head = LedgerHead(candidate.generation, descriptor.sha256, candidate.sealed)
        return self.head

    def seal(self, candidate: LedgerCandidate) -> LedgerHead:
        if not candidate.sealed:
            raise LedgerChainError("terminal generation must be sealed")
        return self.append(candidate)
```

Use `O_NOFOLLOW`, regular-file/owner/mode checks, RFC 8785-compatible canonical JSON, no-replace generation installation, file and directory `fsync`, acknowledged predecessor digests, and the fixed safety → harness → interruption → functional → qualification → pass ordering.

- [ ] **Step 4: Run the durability and decision suite**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_atomic_io.py scripts/holoagent0_setup/tests/test_result_policy.py scripts/holoagent0_setup/tests/test_ledger.py`

Expected: PASS, including replay, fork, stale digest, finalizer precedence, and atomic-write fault injection.

- [ ] **Step 5: Commit the evidence core**

```bash
git add scripts/holoagent0_setup/holoagent0_setup scripts/holoagent0_setup/tests
git commit -m "feat: add immutable ledger and result policy"
```

### Task 4: Two-way broker protocol and signal-readiness state machine

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/broker.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/signal_handoff.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/process_identity.py`
- Test: `scripts/holoagent0_setup/tests/test_broker.py`
- Test: `scripts/holoagent0_setup/tests/test_signal_handoff.py`
- Test: `scripts/holoagent0_setup/tests/test_process_identity.py`

- [ ] **Step 1: Write state-machine tests before implementation**

```python
def test_acceptance_is_required_before_unblock(handoff, identity):
    request = handoff.coordinator_ready(identity, blocked={"HUP", "INT", "TERM"})
    handoff.collect_signal("INT")
    assert handoff.state == "PENDING_FORWARD"
    assert handoff.forward_count == 0
    acceptance = handoff.supervisor_accept(request)
    assert acceptance.request_sequence == request.sequence
    handoff.coordinator_validate(acceptance)
    handoff.coordinator_unblocked()
    assert handoff.terminal_state == "READY"
    assert handoff.forward_count == 1


@pytest.mark.parametrize("fault", ["missing", "wrong_nonce", "wrong_identity", "wrong_sequence", "duplicate"])
def test_rejected_acceptance_never_releases_barrier(handoff, identity, fault):
    request = handoff.coordinator_ready(identity, blocked={"HUP", "INT", "TERM"})
    handoff.inject_acceptance_fault(request, fault)
    assert handoff.unblock_count == 0
    assert handoff.functional_count == 0
```

- [ ] **Step 2: Run the tests and verify the missing APIs fail**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_broker.py scripts/holoagent0_setup/tests/test_signal_handoff.py scripts/holoagent0_setup/tests/test_process_identity.py`

Expected: FAIL because broker framing and handoff state do not exist.

- [ ] **Step 3: Implement bounded frames and the closed handoff**

```python
class MessageType(str, Enum):
    SIGNAL_READY = "SIGNAL_READY"
    SIGNAL_READY_ACCEPTED = "SIGNAL_READY_ACCEPTED"
    LEDGER_CANDIDATE = "LEDGER_CANDIDATE"
    LEDGER_ACCEPTED = "LEDGER_ACCEPTED"
    OWNERSHIP_RECORD = "OWNERSHIP_RECORD"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    pgid: int
    start_time: int
    executable_path: str
    executable_sha256: str

    def matches_proc(self, proc_root: Path = Path("/proc")) -> bool:
        return read_process_identity(proc_root, self.pid) == self


@dataclass(frozen=True)
class SignalReadyAccepted:
    run_nonce: str
    identity: ProcessIdentity
    request_sequence: int
    request_sha256: str


def write_frame(fd: int, message: Mapping[str, object]) -> None:
    payload = canonical_json_bytes(message)
    if len(payload) > 4096:
        raise BrokerProtocolError("frame exceeds reviewed bound")
    write_all(fd, len(payload).to_bytes(4, "big") + payload)
```

Keep the coordinator's three signals blocked until the exact acceptance validates. A missing/rejected response, EOF, or deadline leaves it blocked until supervisor cleanup. The supervisor cannot forward `PENDING_FORWARD` until the acceptance write completes; final `READY` additionally requires the trace-proven unblock before any functional operation.

- [ ] **Step 4: Run state, race, and malformed-frame tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_broker.py scripts/holoagent0_setup/tests/test_signal_handoff.py scripts/holoagent0_setup/tests/test_process_identity.py`

Expected: PASS with acceptance/unblock/functional ordering asserted from event indices.

- [ ] **Step 5: Commit the broker barrier**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/broker.py scripts/holoagent0_setup/holoagent0_setup/signal_handoff.py scripts/holoagent0_setup/holoagent0_setup/process_identity.py scripts/holoagent0_setup/tests/test_broker.py scripts/holoagent0_setup/tests/test_signal_handoff.py scripts/holoagent0_setup/tests/test_process_identity.py
git commit -m "feat: add signal readiness acceptance barrier"
```

### Task 5: Pinned strace provisioning and canonical normalizer

**Files:**
- Create: `scripts/holoagent0_setup/provision_strace_6_6.sh`
- Create: `scripts/holoagent0_setup/holoagent0_setup/trace_normalizer.py`
- Create: `scripts/holoagent0_setup/fixtures/strace/manifest-v1.json`
- Create: `scripts/holoagent0_setup/fixtures/strace/generic-io.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/generic-io.expected.ndjson`
- Create: `scripts/holoagent0_setup/fixtures/strace/unfinished-resumed.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/unfinished-resumed.expected.ndjson`
- Create: `scripts/holoagent0_setup/fixtures/strace/socket-addresses.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/socket-addresses.expected.ndjson`
- Create: `scripts/holoagent0_setup/fixtures/strace/ancillary-rights.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/ancillary-rights.expected.ndjson`
- Create: `scripts/holoagent0_setup/fixtures/strace/errors-signals.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/errors-signals.expected.ndjson`
- Create: `scripts/holoagent0_setup/fixtures/strace/abbreviation-reject.input`
- Test: `scripts/holoagent0_setup/tests/test_trace_normalizer.py`
- Test: `scripts/holoagent0_setup/tests/test_strace_provisioner.py`

- [ ] **Step 1: Add failing grammar and payload-redaction fixtures**

```python
def test_write_payload_is_not_persisted(normalize_fixture):
    records = normalize_fixture('123 1700000000.0 write(7, "SECRET_SENTINEL", 15) = 15')
    assert records[0]["syscall"] == "write"
    assert records[0]["length"] == 15
    assert "SECRET_SENTINEL" not in json.dumps(records)


@pytest.mark.parametrize("text", ["...", "<unfinished ...>", "pid ??? socket("])
def test_undecodable_relevant_record_fails(text, normalizer):
    with pytest.raises(TraceDecodeError):
        normalizer.feed(text)
```

- [ ] **Step 2: Run fixture tests and verify failure**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_trace_normalizer.py scripts/holoagent0_setup/tests/test_strace_provisioner.py`

Expected: FAIL because the pinned provisioner and grammar are absent.

- [ ] **Step 3: Implement the exact provisioner and parser**

The provisioner downloads only `strace-6.6.tar.xz`, verifies size `2420364` and SHA-256 `421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c`, builds in the pinned container image/recipe, records the literal ELF/version digests, and refuses to amend the tracked allowlist automatically. The normalizer accepts only the committed 6.6 fixtures, joins unfinished/resumed records, emits serialized record indices, and strips every payload byte before persistence.

The reviewed invocation is exactly `--kill-on-exit -f -yy -ttt -T --no-abbrev --string-limit=1048576 --quiet=none --trace=all` with `LC_ALL=C` and `TZ=UTC`. Apply `--raw` to `read`, `readv`, `pread64`, `preadv`, `preadv2`, `write`, `writev`, `pwrite64`, `pwritev`, `pwritev2`, `sendfile`, `splice`, `vmsplice`, `tee`, and `copy_file_range`; keep address/control-message calls decoded only in transient input. Any argv, parser, fixture, ELF, version-output, ABI, or grammar mismatch is a bootstrap failure with no fallback.

```bash
archive_sha="421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
test "$(stat -c %s "${archive}")" = 2420364
printf '%s  %s\n' "${archive_sha}" "${archive}" | sha256sum --check --status
```

- [ ] **Step 4: Run every committed parser fixture**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_trace_normalizer.py scripts/holoagent0_setup/tests/test_strace_provisioner.py`

Expected: PASS; fixture count is read from the manifest and no payload sentinel appears in generated evidence.

- [ ] **Step 5: Commit the pinned trace toolchain**

```bash
git add scripts/holoagent0_setup/provision_strace_6_6.sh scripts/holoagent0_setup/fixtures scripts/holoagent0_setup/holoagent0_setup/trace_normalizer.py scripts/holoagent0_setup/tests
git commit -m "feat: pin strace parser and provisioning recipe"
```

### Task 6: FD provenance and offline network policy

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/trace_policy.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/cyclone_policy.py`
- Create: `scripts/holoagent0_setup/config/cyclonedds-offline-p0.xml`
- Create: `scripts/holoagent0_setup/config/cyclonedds-offline-p1.xml`
- Create: `scripts/holoagent0_setup/config/cyclonedds-offline-p2.xml`
- Create: `scripts/holoagent0_setup/config/cyclonedds-offline-p3.xml`
- Create: `scripts/holoagent0_setup/fixtures/strace/cyclonedds-0.10.5-runtime-representative.input`
- Create: `scripts/holoagent0_setup/fixtures/strace/cyclonedds-0.10.5-runtime-representative.expected.ndjson`
- Modify: `scripts/holoagent0_setup/fixtures/strace/manifest-v1.json`
- Test: `scripts/holoagent0_setup/tests/test_trace_policy.py`
- Test: `scripts/holoagent0_setup/tests/test_trace_normalizer.py`
- Test: `scripts/holoagent0_setup/tests/test_cyclone_policy.py`

- [ ] **Step 1: Write runtime-derived endpoint, provenance, and thread-authority tests**

```python
RECEIVE_PORTS = {
    0: (26650, 26651, 26660, 26661),
    1: (26650, 26651, 26662, 26663),
    2: (26650, 26651, 26664, 26665),
    3: (26650, 26651, 26666, 26667),
}


def register_tx(policy, records, participant, fd, dynamic_port):
    pid, decision = bind_udp(
        policy, records, participant, fd=fd, local=("127.0.0.1", 0)
    )
    assert decision.status == "PASS"
    for level, option, value, length in (
        ("SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
        ("SOL_IP", "IP_MULTICAST_TTL", 1, 1),
        ("SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
    ):
        assert policy.feed(
            tx_socket_option(pid, fd, level, option, value, length)
        ).status == "PASS"
    decision = policy.feed(
        getsockname(pid, fd, local=("127.0.0.1", dynamic_port))
    )
    assert decision.status == "PASS"
    return pid, fd, dynamic_port


@pytest.mark.parametrize("participant", range(4))
def test_runtime_receive_bind_matrix_includes_both_multicast_ports(participant):
    policy, records = open_dds_window()
    for port in RECEIVE_PORTS[participant]:
        pid, decision = bind_udp(
            policy, records, participant, fd=port, local=("0.0.0.0", port)
        )
        assert decision.status == "PASS"
        if port in {26650, 26651}:
            assert policy.feed(
                add_membership(pid, port, "239.255.0.1", "127.0.0.1")
            ).status == "PASS"


def test_one_tx_fd_carries_spdp_sedp_and_user_data():
    policy, records = open_dds_window()
    pid, fd, _ = register_tx(
        policy, records, participant=0, fd=17, dynamic_port=40000
    )
    destinations = [("239.255.0.1", 26650)] + [
        ("127.0.0.1", port) for port in range(26660, 26668)
    ]
    for destination in destinations:
        assert policy.feed(sendto(pid, fd, destination)).status == "PASS"


def test_inbound_requires_registered_dynamic_source():
    policy, records = open_dds_window()
    _, _, e_j = register_tx(
        policy, records, participant=1, fd=18, dynamic_port=40001
    )
    pid, decision = bind_udp(
        policy, records, participant=0, fd=7, local=("0.0.0.0", 26660)
    )
    assert decision.status == "PASS"
    assert policy.feed(recvfrom(pid, 7, ("127.0.0.1", e_j))).status == "PASS"
    assert policy.feed(
        recvfrom(pid, 7, ("127.0.0.1", 40999))
    ).reason == "UNEXPECTED_NETWORK_ATTEMPT"


def test_worker_tid_requires_clone_thread_and_clone_files():
    policy, records = open_dds_window()
    pid, decision = bind_udp(
        policy, records, participant=0, fd=7, local=("0.0.0.0", 26650)
    )
    assert decision.status == "PASS"
    assert policy.feed(clone(
        pid, child_tid=200, flags=("CLONE_THREAD", "CLONE_FILES")
    )).status == "PASS"
    assert policy.feed(
        add_membership(200, 7, "239.255.0.1", "127.0.0.1")
    ).status == "PASS"


@pytest.mark.parametrize("lifecycle", [
    fork(child_pid=200),
    clone(child_tid=200, flags=("CLONE_FILES",)),
    clone(child_tid=200, flags=("CLONE_THREAD",)),
])
def test_nonthread_or_nonsharing_descendant_has_no_participant_authority(lifecycle):
    policy, records = open_dds_window()
    # FD inheritance still follows Linux, but role authority does not.
    policy.feed(lifecycle)
    assert policy.feed(dds_io_from(200)).reason == "UNEXPECTED_NETWORK_ATTEMPT"
```

Add the closed manifest case
`cyclonedds-0.10.5-runtime-representative.{input,expected.ndjson}`. Its input
is a sanitized, payload-free, deterministic reconstruction of the syscall
structure observed in the live pinned CycloneDDS 0.10.5 run, not byte-for-byte
raw strace. The normalizer test must reproduce the expected NDJSON exactly and
assert both multicast binds/memberships, the fixed receive pair, port-zero bind
plus the exact three post-bind option records and nonzero `getsockname`, worker
TIDs, SPDP destination, unicast destinations, registered inbound source, worker
and root exits, root-owned socket closes, and END only after that cleanup. The
closed normalizer has no wait/reap transition, so reaping is coordinator/ledger
evidence outside this representative trace; do not fabricate a wait record.
The policy replay must accept the entire marker-bounded golden only when no
participant task or tracked participant socket remains live at finalization.

Also cover rejection of a second TX socket for one identity, a duplicate/zero
or unknown `E_i`, an unknown inbound `E_j`, IPv6, non-loopback endpoints,
alternate multicast groups, sends from the `26651` FD, destination `26651`,
and role inheritance through `fork`, `vfork`, or a `clone` missing either
`CLONE_THREAD` or `CLONE_FILES`. Revise every former blanket rejection of
port zero or `26651`; those are now respectively a conditional TX bind and a
receive-bind/membership endpoint.

For each receive-FD class (`26650`, `26651`, fixed meta, and fixed data), prove
that `sendto` and any connected generic write are denied even when their peer
would be valid for the registered TX FD. Parameterize inbound `recvfrom` over
the same four classes: a registered `E_j` passes and an unknown source fails,
including explicit bind, membership, and source validation on `26651`. Exercise
actual inbound and outbound DDS I/O from `fork`, `vfork`, and incomplete-clone
descendants, then from their `CLONE_THREAD|CLONE_FILES` threads, and prove that
no transitive lifecycle edge from an unauthorized descendant re-grants
participant authority. Conversely, valid both-flag edges propagate authority
transitively from a currently authorized root or worker; exit erases that
incarnation's authority, and the same numeric TID remains unauthorized until a
fresh valid edge. Finally, pin `E_i` to its registered open-socket provenance.
A same-value repeated
`getsockname` through the original FD or a proven `dup` alias preserves the
registration without creating a second TX socket. A conflicting repetition
fails without replacing `E_i`, poisons that TX provenance and the run, and
leaves later outbound or receive I/O denied. A post-hoc `getsockname` is one
observed after any attempted outbound, receive, connect, or generic socket I/O
on the port-zero-bound FD
before registration completed; reject it for authority purposes, keep later I/O
denied, and retain the first violation in the journal. Before registration, the
only permitted operations on the TX FD after its port-zero bind are successful
`SOL_IP/IP_MULTICAST_IF=127.0.0.1` length `4`,
`SOL_IP/IP_MULTICAST_TTL=1` length `1`, and
`SOL_IP/IP_MULTICAST_LOOP=1` length `1`, in that order, followed by successful
`getsockname`. They must use the original numeric FD and open-file-description;
an alias is not accepted during registration. Reject a wrong, duplicated,
omitted, or reordered successful option, another option or endpoint operation,
or any socket I/O before registration. A failed syscall for one of the three
reviewed options is neutral/`PASS` for network policy and does not advance
registration: the next successful operation must remain the current expected
stage, and a successful retry followed by the remaining exact sequence may
register. A failed unreviewed option, endpoint, or socket-I/O operation remains
a policy violation.

Parameterize stages 0/1/2 separately. Before injecting a bad level, option,
value/interface, or length, feed and verify the exact valid preceding prefix.
Likewise cover omission, duplication, and reordering at every stage by feeding
the valid prefix and then the operation that exposes that stage; test IDs name
both stage and defect so a failure cannot be mistaken for an earlier ordering
error.

- [ ] **Step 2: Run and verify the amended policy contract is RED**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_trace_policy.py scripts/holoagent0_setup/tests/test_trace_normalizer.py scripts/holoagent0_setup/tests/test_cyclone_policy.py`

Expected at the contract-amendment checkpoint: FAIL because production still
implements the disproven fixed-source-port matrix, lacks dynamic TX endpoint
registration and thread-scoped role authority, and still pins the pre-golden
fixture-manifest digest. This checkpoint commits tests/docs/fixtures only and
does not advance to Task 7.

- [ ] **Step 3: Implement provenance and the exact pinned DDS allowance**

```python
@dataclass(frozen=True)
class PolicyDecision:
    status: Literal["PASS", "FAIL", "SKIPPED"]
    reason: str
    violation_index: int | None


class TracePolicy:
    def feed(self, record: CanonicalRecord) -> PolicyDecision:
        self.provenance.apply(record)
        violation = self.classifier.classify(record, self.provenance, self.markers)
        if violation is not None:
            self.journal.persist(violation)
            return PolicyDecision("FAIL", violation.reason, record.index)
        return PolicyDecision("PASS", "OK", None)

    def finalize(self, trace_integrity_ok: bool) -> PolicyDecision:
        if self.journal.violation_count:
            first = self.journal.first_violation
            return PolicyDecision("FAIL", first.reason, first.record_index)
        if trace_integrity_ok:
            return PolicyDecision("PASS", "OK", None)
        return PolicyDecision("SKIPPED", "DEPENDENCY_NOT_AVAILABLE", None)
```

Track pipe and socket creation, local binds, `getsockname`, connected and
message peers, `dup*`, `fcntl(F_DUPFD*)`, fork/clone table semantics,
thread-group semantics, exec, exit, close/`close_range`, decoded `SCM_RIGHTS`,
and `pidfd_getfd`. Register an exact successful generic `open`/`openat` result
with closed redacted `path` provenance, then resolve the pinned raw-I/O grammar's
numeric FD operand through that table. Known non-socket I/O is neutral. The
canonical policy may defensively accept only exact closed `path`,
nonnegative-inode `pipe`, and nonnegative-inode `character_device` annotations,
but pinned raw records do not carry them. A successful `open`/`openat` with a
nonnegative result but no exact `result.fd` annotation, and any other
unannotated, malformed, or unknown FD provenance, fails trace integrity; an
unknown annotated socket also fails network policy.
Classify TCP/DNS, host-namespace IP, non-loopback routes, any `pidfd_getfd`
acquisition attempt, any decoded `SCM_RIGHTS` transfer, and any UDP operation
outside the exact four identity/config-digest participant roots, their
trace-proven authorized TIDs, marker interval, and direction-specific domain-77
endpoint/provenance matrix. Preserve violation-journal failures even when trace
integrity later fails.

Under the approved pinned CycloneDDS 0.10.5 configuration, the closed UDP4
allowance is:

| Operation | Local FD/bind/source | Peer/source/destination | Additional restriction |
|---|---|---|---|
| Bind multicast receive sockets | wildcard/loopback `:26650` and `:26651` | none | Both binds are required; join `239.255.0.1` on both FDs through loopback |
| Bind fixed unicast receive sockets | wildcard/loopback at that participant's pair | none | p0 `26660/26661`; p1 `26662/26663`; p2 `26664/26665`; p3 `26666/26667` |
| Register transmit socket | exactly one FD bound `127.0.0.1:0` | exact successful `IP_MULTICAST_IF=127.0.0.1`/length 4, `IP_MULTICAST_TTL=1`/length 1, `IP_MULTICAST_LOOP=1`/length 1, then the first successful endpoint observation is `getsockname -> 127.0.0.1:E_i` | All steps use the same numeric FD/open-file-description before any socket I/O; `E_i` is unique and nonzero |
| Outbound DDS | registered TX FD/source `E_i` | `239.255.0.1:26650` or loopback `26660..26667` | The same TX FD carries SPDP and ordinary unicast SEDP/user data |
| Inbound DDS | an approved multicast/fixed receive FD | loopback source at a previously registered `E_j` | Unknown source ports never inherit permission from destination validity |
| Worker-TID DDS operation | FD from the participant's shared table | same endpoint rules | TID role requires lifecycle proof containing both `CLONE_THREAD` and `CLONE_FILES` |

The `26651` socket is receive/join-only: reject sends from that FD and every
destination `:26651`. Fixed receive sockets likewise do not become TX FDs.
Reject a second port-zero TX socket for an identity and zero, duplicate, or
unknown `E_i`. The port-zero bind plus its exact three successful post-bind
options and successful `getsockname` is the only registration path. No other
operation may interpose on that FD. After registration, an exact
same-value `getsockname` on the FD or a proven `dup` alias is permitted and
preserves the original provenance. A conflicting repetition is a TX-provenance
integrity/policy failure: never overwrite `E_i`, poison that FD/run, and reject
later outbound or receive use. "Post-hoc" means after any attempted outbound or
receive I/O before registration completed; reject that observation for
authority, do not register the endpoint, keep every later use denied, and
preserve the earlier violation as authoritative. Also reject unknown inbound
`E_j`, IPv6, non-loopback endpoints, alternate multicast groups, and every
destination outside the table. A wildcard receive bind is permitted only after
the preflight artifact proves the private namespace has exactly `lo` and no
non-loopback interface or route.

Before applying TX interposition, inspect every affected open-file-description
for successful and failed descriptor attempts. Failed `close` uses its input
`fd`; `dup2`/`dup3` include both the source and the implicitly closed target even
on failure; and `close_range` includes the entire selected range on success or
failure, including `CLOSE_RANGE_CLOEXEC`. Poison and journal any incomplete
registration found. Apply descriptor-table and lifecycle closure only for
successful non-CLOEXEC closes; failed operations and CLOEXEC-only ranges remain
open for lifecycle accounting. The only failed TX-setup operations that remain
neutral are the three exact reviewed multicast options described above.

Participant authority is not inherited merely because a descendant has an FD.
A successful lifecycle edge from an authorized task grants authority only when
the clone flags prove both the same thread group and the same FD table through
`CLONE_THREAD|CLONE_FILES`. `fork`, `vfork`, and any `clone` missing
either flag retain only their ordinary FD-provenance semantics; they receive no
participant role. Exit removes the task/TID authority without granting it to a
later PID reuse. Observing the externally journal-validated configured root
spawn immediately activates its lifecycle. Its first successful exec preserves
the root role only before participant/DDS-authority activity and also activates
lifecycle accounting. Ordinary post-fork, pre-exec housekeeping—such as signal
masking, non-socket descriptor close, or process setup—does not consume that
allowance; participant socket activation or authorized worker creation does. A
second successful exec, or an exec after prior participant/DDS activity,
replaces the journal-bound identity: revoke root authority, latch trace
integrity failure, deny later DDS, and prevent a passing final result. A pinned
no-exec lifecycle remains valid. Root exit permanently closes that incarnation
and later numeric PID reuse cannot reauthorize it. A
worker exec or worker-side successful `unshare(CLONE_FILES)`/
`close_range(..., CLOSE_RANGE_UNSHARE)` revokes only that worker's network
authority. A root-side split revokes every live worker for the participant while
the root stays authorized; lifecycle tracking for revoked workers continues
until exit.

This behavior is specific to the approved pinned configuration. CycloneDDS
0.10.5 creates one port-zero transmit connection per selected interface, uses
that connection for multicast and unicast address sets/writes, creates separate
receive sockets on both multicast ports, joins SPDP on both, and adds the TX
connection to its receive waitset. The source anchors are
[`ddsi_udp.c` transmit socket options](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/ddsi_udp.c#L408-L425),
[`ddsi_udp.c` bind/option/port-observation order](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/ddsi_udp.c#L529-L575),
[`q_init.c` transmit creation](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/q_init.c#L1715-L1741),
[`q_addrset.c` connection selection](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/q_addrset.c#L313-L355),
[`q_xmsg.c` connection write](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/q_xmsg.c#L1178-L1201),
[`q_receive.c` receive waitset](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/q_receive.c#L3570-L3630),
and
[`q_init.c` receive creation/join](https://github.com/eclipse-cyclonedds/cyclonedds/blob/0.10.5/src/core/ddsi/src/q_init.c#L650-L738).
State `no outbound user-data multicast` only as an endpoint/configuration
invariant. The payload-free syscall trace cannot determine RTPS payload kind.

The four XML files are byte-pinned by role/index, but the approved 0.10.5
grammar uses
`<NetworkInterface name="lo" autodetermine="false" presence_required="true" multicast="true"/>`,
global `<AllowMulticast>spdp</AllowMulticast>`, and an empty `<Peers/>`.
It does not support per-interface `allow_multicast` or `Peers/AddLocalhost`;
see the pinned
[0.10.5 XSD](https://raw.githubusercontent.com/eclipse-cyclonedds/cyclonedds/0.10.5/etc/cyclonedds.xsd).
Keep domain `77`, `Transport=udp`, multicast loopback, TTL `1`, numeric
SPDP/default multicast address `239.255.0.1`, `ManySocketsMode=false`,
monitor port `-1`, redundant networking disabled, fixed participant indexes,
and DDSI constants base `7400`, gains `250`/`2`, offsets
`0`/`1`/`10`/`11`. Tests reject automatic participant selection,
alternate transport/interface/address/port constants, inline or symlinked
`CYCLONEDDS_URI`, and any digest mismatch before a ROS import.

The runtime-representative golden is identity-bound to CycloneDDS `0.10.5`.
Its 44-record input/expected SHA-256 values are
`55bf3b4a3bd38abd2c097f61ac722d46f480923b9f9ba1325ba4befc04acba5a` and
`571fbf7932295a8476b5c03cf94b39c4a0be6ba05b464e7c93f0c6b08944c41d`.
The expected NDJSON is the target contract and retains the decoded `value` on
all six TX setup-option records. Task 6 production retains those values, so
exact source-to-expected normalization and manifest closure/digests pass
together.
Reaping is coordinator-ledger evidence because the closed normalizer has no
wait/reap transition; the golden must not invent one.
The reviewed Task 6 p0/p1/p2/p3 config hashes are
`103da44a684613ead128dd221cace5455ae8890322f8ef50607ea4aa53283ed1`,
`fed9c399b9cc2139440e359d89231d4c0dabe2ddaac99a256146f45faeb3c9fd`,
`badd1e0472ab796697c7aca008f392f76c30af55e25c4502d04116c34dad19e2`,
and `1fc59441a89e0ac1632b84786f54ec9bfb40470d4498dbed4b18962cdab6993c`;
the set hash is
`2f4b15dfe1ee168425ad0552c45d5434d068e6ff6bab43c45f82d7869dcb5879`.
They pin the corrected 0.10.5 grammar described above. No run learns or amends
any digest.

- [ ] **Step 4: Run provenance, registration-order, lifecycle, marker, endpoint, and thread-authority tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_trace_policy.py scripts/holoagent0_setup/tests/test_trace_normalizer.py scripts/holoagent0_setup/tests/test_cyclone_policy.py`

Expected after Task 6 production implementation: PASS for the one exact
semantic DDS window under the approved pinned configuration and policy
rejection for every other IP path. Until that implementation lands, the
contract-amendment commit intentionally remains RED as specified in Step 2.

- [ ] **Step 5: Commit network policy**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/trace_policy.py scripts/holoagent0_setup/holoagent0_setup/cyclone_policy.py scripts/holoagent0_setup/config scripts/holoagent0_setup/fixtures/strace scripts/holoagent0_setup/tests
git commit -m "feat: enforce offline trace network policy"
```

### Task 7: Native launch boundary and process identity

**Files:**
- Create: `scripts/holoagent0_setup/native/Makefile`
- Create: `scripts/holoagent0_setup/native/.gitignore`
- Create: `scripts/holoagent0_setup/native/tracee_launcher.c`
- Create: `scripts/holoagent0_setup/native/finalizer_only.c`
- Create: `scripts/holoagent0_setup/native/seccomp_policy.c`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/process_identity.py`
- Test: `scripts/holoagent0_setup/tests/test_native_launchers.py`
- Modify: `scripts/holoagent0_setup/tests/test_process_identity.py`

- [ ] **Step 1: Write native capability and PID-reuse tests**

```python
def test_tracee_launcher_rejects_inherited_socket(native_launcher, socket_fd):
    completed = native_launcher(pass_fds=(socket_fd,))
    assert completed.returncode == 30
    assert completed.json["reason"] == "INHERITED_SOCKET_FD"


@pytest.mark.parametrize("syscall", [
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "pidfd_getfd", "ptrace", "clone_untraced",
])
def test_seccomp_denies_only_reviewed_bypasses(native_launcher, syscall):
    assert native_launcher.probe(syscall).denied


def test_clone3_gets_reviewed_fallback_errno(native_launcher):
    assert native_launcher.probe("clone3").errno == errno.ENOSYS


def test_seccomp_leaves_message_syscalls_for_trace_policy(native_launcher):
    completed = native_launcher.probe_unix_message_round_trip(
        control_messages=(), syscalls=("sendmsg", "recvmsg", "sendmmsg", "recvmmsg")
    )
    assert completed.returncode == 0


def test_identity_rejects_reused_pid(proc_fixture):
    expected = proc_fixture.identity()
    proc_fixture.replace_start_time()
    assert not expected.matches_proc()
```

- [ ] **Step 2: Run tests and verify native binaries are absent**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_native_launchers.py scripts/holoagent0_setup/tests/test_process_identity.py`

Expected: FAIL because launchers and identity helpers do not exist.

- [ ] **Step 3: Implement and compile the boundary**

```c
struct process_identity {
    pid_t pid;
    pid_t pgid;
    unsigned long long start_time;
    unsigned char executable_sha256[32];
};

int sanitize_fds(const int *allowed, size_t count);
int install_tracee_seccomp(void);
int emit_marker(const char *phase, const char *nonce);
```

Use `/proc/self/fd`, `fstat`, `SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, explicit FD relocation, `CLOSE_RANGE_UNSHARE`, `PR_SET_NO_NEW_PRIVS`, `setsid`, and `PR_SET_PDEATHSIG`. The inherited tracee seccomp filter denies exactly `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `pidfd_getfd`, and `ptrace`; returns `ENOSYS` for `clone3`; and rejects `clone` only when `CLONE_UNTRACED` is set. It does not deny `sendmsg`, `recvmsg`, `sendmmsg`, or `recvmmsg` wholesale and does not claim to inspect ancillary payloads. Decoded `SCM_RIGHTS` control messages are rejected by Task 6 trace policy as `PROHIBITED_FD_TRANSFER` and durably recorded in the violation journal. The supervisor/coordinator control channel remains reviewed anonymous pipes rather than socket IPC. Keep the supervisor's filter non-inherited. Build into ignored `native/build/` with `-std=c17 -Wall -Wextra -Werror -fPIE -pie`; `.gitignore` contains exactly `/build/`, so no generated ELF is committed.

- [ ] **Step 4: Run native tests and compiler warnings as errors**

Run: `make -C scripts/holoagent0_setup/native clean all && PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_native_launchers.py scripts/holoagent0_setup/tests/test_process_identity.py`

Expected: PASS with no compiler warning and no surviving child.

- [ ] **Step 5: Commit the native boundary**

```bash
git add scripts/holoagent0_setup/native scripts/holoagent0_setup/holoagent0_setup/process_identity.py scripts/holoagent0_setup/tests
git commit -m "feat: add native offline launch boundary"
```

### Task 8: Supervisor, coordinator, immutable evidence bundle

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/evidence.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/supervisor.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/coordinator.py`
- Test: `scripts/holoagent0_setup/tests/test_evidence.py`
- Test: `scripts/holoagent0_setup/tests/test_supervisor.py`
- Test: `scripts/holoagent0_setup/tests/test_coordinator.py`

- [ ] **Step 1: Write bootstrap, signal, tracer-loss, and artifact-binding tests**

```python
def test_precoordinator_signal_uses_finalizer_only(supervisor):
    result = supervisor.run(signal_at="BOOTSTRAP_CLEAN", signal="TERM")
    assert result.trace_state == "FINALIZER_ONLY"
    assert result.gates[0:2] == [passed(), passed()]
    assert all(g.status == "NOT_RUN" for g in result.gates[2:23])
    assert result.exit_code == 143


def test_tracer_loss_with_live_tracee_is_safety(supervisor):
    result = supervisor.run(fault="TRACER_EXITED_WITH_LIVE_TRACEE")
    assert result.primary_blocking_gate == "safety.workstation_postflight"
    assert result.label == "FAIL_SAFETY"
    assert result.exit_code == 30
```

- [ ] **Step 2: Run tests and verify orchestration is missing**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_evidence.py scripts/holoagent0_setup/tests/test_supervisor.py scripts/holoagent0_setup/tests/test_coordinator.py`

Expected: FAIL because supervisor/coordinator/evidence implementations are absent.

- [ ] **Step 3: Implement the authority split**

```python
class EvidenceSupervisor:
    def execute_authoritative(self, invocation: OfflineInvocation) -> int:
        state = self.bootstrap_engine.run(invocation)
        session = self.trace_runtime.launch(state)
        ledger = self.ledger_broker.collect(session)
        result = self.finalizers.evaluate_and_bind(session, ledger)
        self.contract.require_valid_result(result)
        atomic_write_json(invocation.result_path, result.as_json())
        return result.process_exit


class TracedCoordinator:
    def execute(self) -> int:
        self.signal_barrier.complete_two_way_acceptance()
        self.ledger.pass_gate("safety.workstation_preflight")
        self.host_observer.capture("pre")
        self.action_child.run_all_gates()
        self.host_observer.capture("post")
        self.ledger.finalize_workstation_postflight()
        self.ledger.seal()
        return 0
```

Implement the exact bootstrap table, generation-0 creation, synchronous signal collector, launch-commit linearization, two-way readiness barrier, tracer/normalizer pidfds, `PTRACE_O_EXITKILL` verification, append-only ownership/violation journals, host observer before/after, loopback-only user/network namespace, supervisor-synthesized gate 24, gates 25–27 ordering, retained `O_NOFOLLOW` artifact descriptors, and supervisor-only atomic `result.json`.

Workstation preflight also requires `START_G1_PUBVEL=0`, `G1_DRY_RUN=1`, and `ALLOW_G1_MOTION=0`; rejects any observed `g1_pubvel_node`, `g1_pubmove_node`, or `g1_pubcmd_node`; and rejects an unexpected ROS participant or physical Unitree endpoint. Redact credential-shaped values before bounded log persistence and fail if a secret sentinel reaches a log, journal, result, or tracked file.

- [ ] **Step 4: Run fault-injection matrix**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_evidence.py scripts/holoagent0_setup/tests/test_supervisor.py scripts/holoagent0_setup/tests/test_coordinator.py`

Expected: PASS for every bootstrap row, HUP/INT/TERM phase, ledger fault, tracer death, journal replay, evidence mutation, and finalizer-precedence case.

- [ ] **Step 5: Commit the supervisor boundary**

```bash
git add scripts/holoagent0_setup/holoagent0_setup scripts/holoagent0_setup/tests
git commit -m "feat: add offline evidence supervisor"
```

### Task 9: Deterministic AgentOS plan-file mode and zero side effects

**Files:**
- Modify: `agentic_robot/agentOS/sandbox_test/long_horizon_text_runner.py`
- Create: `agentic_robot/agentOS/sandbox_test/test_offline_plan_runner.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/agentos_gate.py`
- Test: `scripts/holoagent0_setup/tests/test_agentos_gate.py`

- [ ] **Step 1: Write plan-file schema and import-side-effect tests**

```python
def test_offline_plan_does_not_import_llm_or_spawn(monkeypatch, plan_file):
    monkeypatch.setitem(sys.modules, "openai", ImportBomb())
    with ProcessAndNetworkSpy() as spy:
        result = run_offline_plan(plan_file)
    assert result.status == "PASS"
    assert spy.network_attempts == []
    assert spy.process_attempts == []
    assert spy.ros_publications == []
```

- [ ] **Step 2: Run and verify top-level OpenAI imports fail the test**

Run: `PYTHONPATH=agentic_robot/agentOS/sandbox_test:scripts/holoagent0_setup python3 -m pytest -q agentic_robot/agentOS/sandbox_test/test_offline_plan_runner.py scripts/holoagent0_setup/tests/test_agentos_gate.py`

Expected: FAIL because `openai` is imported at module load and no plan-file mode exists.

- [ ] **Step 3: Refactor into explicit text and offline paths**

```python
def load_plan_file(path: Path, schema_path: Path, max_bytes: int = 65_536) -> dict[str, object]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise PlanValidationError("plan exceeds 65536-byte limit")
    value = json.loads(raw)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=lambda e: list(e.path))
    if errors:
        raise PlanValidationError("; ".join(error.message for error in errors))
    return value


def build_llm_client_from_env():
    from openai import AzureOpenAI, OpenAI
    return _select_client(AzureOpenAI, OpenAI)
```

Add `--plan-file`, require schema version `holoagent.agentos.plan.v1`, reject unknown keys and oversize files, lazy-load `requests`/OpenAI only in text planning/execution, and prohibit process/network/ROS publication in offline validation. Preserve existing online behavior when `--plan-file` is absent.

Use the approved schema identifier `holoagent.agentos.plan.v1`; top-level keys are exactly `schema_version`, `mode`, `description`, and `nodes`; size is at most 65,536 UTF-8 bytes; description length is 1–512; there are 1–64 nodes; and node keys are exactly `id`, `robot_id`, `skill`, `target`, and `depends_on`. Require unique bounded IDs/dependencies, existing dependency targets, approved robot IDs 11–16, and the existing navigation/arm target enums. `--plan-file` requires `--dry-run` and rejects live text-planning arguments.

- [ ] **Step 4: Run old and new AgentOS tests**

Run: `PYTHONPATH=agentic_robot/agentOS/sandbox_test:scripts/holoagent0_setup python3 -m pytest -q agentic_robot/agentOS/sandbox_test/test_offline_plan_runner.py agentic_robot/agentOS/sandbox_test/test_single_robot_long_instruction.py agentic_robot/agentOS/sandbox_test/test_multi_robot_long_instruction.py scripts/holoagent0_setup/tests/test_agentos_gate.py`

Expected: PASS with injected transport/process/ROS spies recording zero attempts in offline mode.

- [ ] **Step 5: Commit deterministic AgentOS mode**

```bash
git add agentic_robot/agentOS/sandbox_test scripts/holoagent0_setup/holoagent0_setup/agentos_gate.py scripts/holoagent0_setup/tests/test_agentos_gate.py
git commit -m "feat: add deterministic offline AgentOS plans"
```

### Task 10: Pinned OpenClaw provisioning and read-only lifecycle gates

**Files:**
- Create: `scripts/holoagent0_setup/provision_openclaw.sh`
- Create: `scripts/holoagent0_setup/openclaw_install_driver.sh`
- Create: `scripts/holoagent0_setup/config/openclaw-local-v1.json`
- Create: `scripts/holoagent0_setup/holoagent0_setup/openclaw_gate.py`
- Test: `scripts/holoagent0_setup/tests/test_openclaw_provisioning.py`
- Test: `scripts/holoagent0_setup/tests/test_openclaw_gate.py`

- [ ] **Step 1: Write pin, pre-existing listener, and payload-binding tests**

```python
def test_installer_uses_verified_local_tarball(provisioner):
    command = provisioner.installer_command(Path("/verified/openclaw.tgz"))
    assert command[-1] == "openclaw@file:/verified/openclaw.tgz"


def test_preexisting_gateway_refuses_mutation(gate, fake_listener):
    result = gate.preexisting()
    assert result.reason == "PREEXISTING_OPENCLAW"
    assert fake_listener.mutations == []
```

- [ ] **Step 2: Run tests and verify failure**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_openclaw_provisioning.py scripts/holoagent0_setup/tests/test_openclaw_gate.py`

Expected: FAIL because provisioning and lifecycle adapters are missing.

- [ ] **Step 3: Implement exact artifact and configuration flow**

Pin Node, installer digest, `openclaw@2026.7.1-2`, registry `dist.integrity`, tarball SHA-512, installed canonical payload manifest, local prefix, provisioning schema digest, and minimal loopback configuration. Refuse mutation if a service/process/listener exists. Identity-safely read and hash the exact installer and tracked driver, copy each into a write/grow/shrink/seal-locked Linux memfd, execute the sealed driver through `/proc/self/fd/<n>`, and explicitly pass both descriptors to the child. The driver rechecks all installer seals and the digest, sources `/proc/self/fd/<n>` under `OPENCLAW_INSTALL_CLI_SH_NO_RUN=1`, closes the installer FD, and invokes only the argument parser and validated `install_openclaw` subset with the preinstalled verified Node/npm and local `file:` tarball. Because the pinned npm parser treats `/proc/self/fd/<n>` as a directory, the tarball remains a mode-`0400` file in the mode-`0700` owned download directory and is SRI/SHA-256 reverified immediately before launch. Disable npm user/global configuration and place its cache in an owned mode-`0700` directory inside the run. The installer `main`, `install_node`, `ensure_git`, npm-prefix repair, refresh/status, and onboarding paths are forbidden. Use only `openclaw gateway status --deep --no-probe --json`, `config validate`, and the two approved `doctor --lint --json` invocations after install; never start a gateway in the offline profile.

Expose the optional authenticated loopback smoke action as a separate CLI subcommand with PID/PGID/start-time/executable ownership and guaranteed cleanup, but cover it only with fake-listener tests in this plan. A live smoke invocation remains separately authorized and is never called by provisioning or `workstation_offline`.

The literal pins are installer SHA-256 `21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1`, npm integrity `sha512-ycF3yPcbjN6bUPeaUx6Mh6vze1hQWoD3CT/wWcmD7a8xaHHHRUaAlaq+lFxMHf1ssEgODVAwjlzYqp2twkYZ7g==`, embedded Node `24.15.0` Linux x64, and Node tarball SHA-256 `472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6`. The tracked configuration content is exactly:

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {"mode": "token", "token": "${OPENCLAW_GATEWAY_TOKEN}"}
  }
}
```

```bash
test -f "${run_dir}/downloads/registry.json"
test -f "${run_dir}/downloads/openclaw.tgz"
test -f "${run_dir}/downloads/install-cli.sh"
test -f "${run_dir}/downloads/node-v24.15.0-linux-x64.tar.xz"
package_root="$(pwd -P)/scripts/holoagent0_setup"
/usr/bin/python3.10 -I -S -c \
  'import runpy,sys; sys.path.insert(0,sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_module("holoagent0_setup.openclaw_gate",run_name="__main__",alter_sys=True)' \
  "${package_root}" verify-record \
  --record "${run_dir}/openclaw-provisioning-v1.json" \
  --prefix "${openclaw_prefix}" \
  --configuration-root "${openclaw_configuration_root}"
```

The separately authorized provisioner saves those four response artifacts first,
validates their exact pins, then invokes only the sealed tracked driver subset over
the saved mode-`0400` tarball.  This executable verification example is intentionally
offline: it neither queries npm nor runs the upstream installer entry point.

- [ ] **Step 4: Run provisioner dry-run and gate tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_openclaw_provisioning.py scripts/holoagent0_setup/tests/test_openclaw_gate.py`

Expected: PASS, including registry race, pre-existing service, wrong manifest, config severity, and socket-observer cases.

- [ ] **Step 5: Commit OpenClaw isolation**

```bash
git add scripts/holoagent0_setup/provision_openclaw.sh scripts/holoagent0_setup/config/openclaw-local-v1.json scripts/holoagent0_setup/holoagent0_setup/openclaw_gate.py scripts/holoagent0_setup/tests
git commit -m "feat: pin isolated OpenClaw provisioning"
```

### Task 11: Pinned semantic assets and exact ROS fixture

**Files:**
- Create: `scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json`
- Create: `scripts/holoagent0_setup/locks/semantic-source-manifest-v1.json`
- Create: `scripts/holoagent0_setup/holoagent0_setup/source_gate.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/semantic_gate.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/semantic_fixture_node.py`
- Test: `scripts/holoagent0_setup/tests/test_source_gate.py`
- Test: `scripts/holoagent0_setup/tests/test_semantic_gate.py`

- [ ] **Step 1: Write exact blob, asset, and pose tests**

```python
def test_semantic_fixture_is_exact(fixture_result):
    assert fixture_result.query_text == "Take me to the counter in the pantry"
    assert fixture_result.room == ("0_0", "Pantry")
    assert fixture_result.object == ("0_0_81", "counter")
    assert fixture_result.frame_id == "map"
    assert fixture_result.position == pytest.approx(
        (-21.526786203133774, -15.671372634872082, -0.27579107548158116), abs=1e-6)
```

- [ ] **Step 2: Run tests and verify locks/gates are missing**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_source_gate.py scripts/holoagent0_setup/tests/test_semantic_gate.py`

Expected: FAIL because the 74-blob verifier, asset lock, and fixture node are absent.

- [ ] **Step 3: Implement pinned source and semantic checks**

Populate `semantic-source-manifest-v1.json` with the exact 74 sorted paths approved in Component 1 of `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`; the test must compare the tracked manifest path set to that table with no extras or omissions. Verify 73 paths against commit `f164095abb0045a69c0b8eb23683063be3deaa38`. Verify only `nav_agent/README.md` against reviewed commit `d862782b3661e2f2cf155d6e006f11c27063a6b0`, Git mode `100644`, and blob `291eea5e1969497760c5c48c62a4a04623a09eb6`, preserving its later MuJoCo/PC2 handoff links. Reject a missing, additional, or changed override including mode drift, reject a reappeared conflicting path, and never expand the manifest by scanning the old snapshot tree. Record graph/dataset/checkpoint root digests from the approved design. Run the structured query through the real HMSG retrieval/transform code, bypassing only the external LLM parser. Enforce exact publisher/subscriber counts, frame, object, pose, and the four pinned Cyclone participant configurations; bracket DDS with nonce-bearing BEGIN/END markers.

The pinned semantic digests are graph root `6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050`, dataset root `a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913`, and checkpoint file `5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b`. Under the approved pinned CycloneDDS 0.10.5 configuration, the four roles use loopback UDP4, global SPDP-only multicast at `239.255.0.1:26650`, `ManySocketsMode=false`, domain 77, and fixed participant indices 0–3 for fixture, query publisher, result subscriber, and graph inspector. Receive binds include both `26650` and `26651` plus each role's fixed meta/data pair, with the SPDP group joined on both multicast receive FDs. Each participant registers exactly one unique nonzero dynamic TX endpoint `E_i` through `127.0.0.1:0` plus `getsockname`; that FD carries every outbound SPDP and unicast DDS operation. Sends from or to `26651` are prohibited, and inbound source ports must be registered `E_j` values. "No outbound user-data multicast" remains a configuration/endpoint invariant, not a payload classification inferred from the sanitized syscall trace.

```python
EXPECTED_QUERY = SemanticExpectation(
    text="Take me to the counter in the pantry",
    room_id="0_0", room_name="Pantry",
    object_id="0_0_81", object_name="counter",
    frame_id="map",
    position=(-21.526786203133774, -15.671372634872082, -0.27579107548158116),
)
```

- [ ] **Step 4: Run semantic unit tests and a bounded ROS fixture smoke test**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_source_gate.py scripts/holoagent0_setup/tests/test_semantic_gate.py`

Expected: PASS; the fixture publishes exactly one finite `PoseStamped` and no Nav2 or `/cmd_vel` endpoint exists.

- [ ] **Step 5: Commit pinned semantic validation**

```bash
git add scripts/holoagent0_setup/locks scripts/holoagent0_setup/holoagent0_setup/source_gate.py scripts/holoagent0_setup/holoagent0_setup/semantic_gate.py scripts/holoagent0_setup/holoagent0_setup/semantic_fixture_node.py scripts/holoagent0_setup/tests
git commit -m "feat: add pinned semantic fixture gate"
```

### Task 12: Skills and chatbot offline gates

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/skills_gate.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py`
- Create: `scripts/holoagent0_setup/chatbot_child.py`
- Test: `scripts/holoagent0_setup/tests/test_skills_gate.py`
- Test: `scripts/holoagent0_setup/tests/test_chatbot_gate.py`

- [ ] **Step 1: Write pass, failure, and qualification tests**

```python
@pytest.mark.parametrize("credentials,audio,label", [
    (True, True, "PASS_HOLOAGENT0_OFFLINE"),
    (False, True, "READY_CREDENTIALS_REQUIRED"),
    (True, False, "READY_AUDIO_HARDWARE_REQUIRED"),
    (False, False, "READY_CREDENTIALS_AND_AUDIO_REQUIRED"),
])
def test_chatbot_qualification_matrix(classify, credentials, audio, label):
    assert classify(credentials=credentials, audio=audio).label == label
```

- [ ] **Step 2: Run focused tests and verify adapters are missing**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_skills_gate.py scripts/holoagent0_setup/tests/test_chatbot_gate.py`

Expected: FAIL because gate adapters do not exist.

- [ ] **Step 3: Implement observation-only gates**

Call the tracked skill validator/list/dry-run commands without executing robot scripts. For chatbot, import all seven declared Python 3.10 runtime dependencies (`aiohttp`, `loguru`, `numpy`, `openai`, `pyaudio`, `pydub`, and `websockets`), parse robot JSON, require the configured device-name substring on one full-duplex audio device without opening streams, record only credential variable presence, and run bounded configuration startup with process/network/microphone spies. Map missing credentials/audio only through the approved qualification matrix.

```python
def classify_external_readiness(credentials: bool, audio: bool) -> tuple[str, int]:
    return {
        (True, True): ("PASS_HOLOAGENT0_OFFLINE", 0),
        (False, True): ("READY_CREDENTIALS_REQUIRED", 10),
        (True, False): ("READY_AUDIO_HARDWARE_REQUIRED", 10),
        (False, False): ("READY_CREDENTIALS_AND_AUDIO_REQUIRED", 10),
    }[(credentials, audio)]
```

- [ ] **Step 4: Run gate and existing skill validation tests**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_skills_gate.py scripts/holoagent0_setup/tests/test_chatbot_gate.py && python3 agentic_robot/agentOS/holoagent_skills/scripts/validate_skills.py`

Expected: PASS; no skill action, microphone stream, network call, or credential value appears in evidence.

- [ ] **Step 5: Commit skills and chatbot gates**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/skills_gate.py scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py scripts/holoagent0_setup/tests
git commit -m "feat: add offline skills and chatbot gates"
```

- [ ] **Step 6: Write sealed-before-hash skill snapshot tests and verify RED**

Modify `scripts/holoagent0_setup/tests/test_skills_gate.py`. Add a private,
deterministic snapshot hook to test the two exact mutation boundaries. At
`before_seal`, overwrite the memfd with `pwrite`; the changed bytes must receive
the full seal mask but then fail the expected digest, and the runner must not be
called. At `after_seal`, prove the same write is rejected with `EPERM`, then let
the runner execute and observe the original reviewed bytes. Trace helper calls
to prove `F_ADD_SEALS` and complete `F_GET_SEALS` verification both occur before
`_descriptor_sha256`, and preserve the existing success/exception descriptor
closure assertions.

Run:
`PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider scripts/holoagent0_setup/tests/test_skills_gate.py -k 'before_seal or after_seal or sealed_before_hash'`

Expected: FAIL because `_run_command` hashes the memfd before applying and
verifying its seals and has no deterministic mutation boundary.

- [ ] **Step 7: Seal, verify, then hash skill snapshots and commit**

Modify `scripts/holoagent0_setup/holoagent0_setup/skills_gate.py`. Give only the
private `_run_command` helper an optional test hook receiving
`("before_seal" | "after_seal", memfd)`. Keep the stable no-follow repository
read, but do not make its pre-seal digest authoritative. Copy the exact bytes,
run `before_seal`, apply all four required seals, verify the complete observed
mask, hash the now-sealed descriptor against `expected_script_digest`, rewind,
and run `after_seal`. Close the repository descriptor before invoking the
runner; close both descriptors on every failure path. Missing seal support,
hook failure, incomplete seals, or sealed digest mismatch remains blocking.

Run the Step 6 command and the complete skills test file. Expected: PASS.
Refresh the skills/test tracked OIDs and supervisor manifest digest, run the
manifest-authority tests, and commit:

```bash
git commit -m "fix: hash sealed skill snapshots"
```

- [ ] **Step 8: Write chatbot source-authority tests and verify RED**

Modify `scripts/holoagent0_setup/tests/test_chatbot_gate.py`. Require the public
adapter call to supply this exact authority with no defaults:

```python
@dataclass(frozen=True)
class ChatbotSourceAuthority:
    repository_root: Path
    tracked_manifest_sha256: str
```

Add adversarial tests for a relative/unowned root, symlinked traversal,
nonregular or executable manifest/source (the forbidden alternative to Git mode
`100644`), malformed/noncanonical/duplicate or wrong-digest manifest, missing
exact source rows, and wrong sealed Git OIDs. Do not require checkout POSIX
permission bits to equal literal `0644`.
Use deterministic internal seams to replace the manifest and each source
pathname after their retained descriptors open; verification and execution
must continue from the retained original descriptors. Mutate an opened inode
during its stable read and require `ChatbotSourceAuthorityError` with no spawn.
Cover unavailable memfd/seal APIs, failed or incomplete seals, spawn failure,
and repository/snapshot FD closure after every outcome.

Assert the child command is exact pinned Python with argv starting exactly
`("-I", "-B", "/proc/self/fd/<entry-fd>", "<gate-fd>")` and `pass_fds` is
exactly the two sealed snapshots. The parent closes both copies immediately
after the spawn attempt.
Assert there is no import-time `_CHATBOT_CHILD_ENTRY`, no package-path or
`sys.path` fallback, and the child installs the gate module in `sys.modules`
before `SourceFileLoader.exec_module`. Preserve the exact four-key control
document and prove provider values are absent from argv, control, result, and
exceptions.

Run:
`PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider scripts/holoagent0_setup/tests/test_chatbot_gate.py -k 'source_authority or sealed_source or retained_source or source_descriptor'`

Expected: FAIL because the adapter rediscovers a mutable child pathname and
does not accept externally pinned manifest authority.

- [ ] **Step 9: Implement sealed chatbot source authority and commit**

Modify `scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py` and
`scripts/holoagent0_setup/chatbot_child.py`. Add `ChatbotSourceAuthorityError`
and the required dataclass. Open the absolute root once with
`O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`, require effective-UID ownership, and
walk only fixed relative components with `dir_fd` plus `O_NOFOLLOW`. Open the
derived manifest and exact child/gate sources as retained effective-UID-owned,
stable regular non-executable descriptors corresponding to manifest Git mode
`100644`. Verify the manifest's supplied SHA-256, closed canonical grammar, and
unique exact rows from that manifest FD.

Copy both retained sources to `MFD_ALLOW_SEALING | MFD_CLOEXEC` snapshots.
Apply and verify the complete seal mask before hashing each sealed descriptor
as a Git blob and comparing it with its manifest row; rewind both, then close
all repository descriptors. Execute only the sealed entry FD and pass the
sealed gate FD numerically. In the child, load `/proc/self/fd/<gate-fd>` with
`SourceFileLoader`, insert the module into `sys.modules` before `exec_module`,
and remove all pathname import fallback. Pass exactly the two snapshots through
`pass_fds`, close the parent's copies after every spawn attempt, and leave the
control document's four keys unchanged. Authority, path, FD, manifest, OID,
seal, or authority-cleanup failures raise `ChatbotSourceAuthorityError` with no
gate result; functional failures retain their existing closed-result behavior.

Run the Step 8 command and the complete chatbot test file. Expected: PASS.
Refresh child/gate/test tracked OIDs and the manifest digest, run the authority
tests, and commit:

```bash
git commit -m "fix: execute sealed chatbot sources"
```

- [ ] **Step 10: Write unreaped chatbot containment tests and verify RED**

Modify `scripts/holoagent0_setup/tests/test_chatbot_gate.py`. Make
`Popen.poll`, premature `Popen.wait`, and `waitpid` explode. Prove root exit is
observed with `waitid(P_PID, pid, WEXITED | WNOHANG | WNOWAIT)`, a sole matching
root in `Z`/`X` receives no signal, a residual descendant receives `SIGTERM`, a
group that reaches root-only `Z`/`X` during the exact 250 ms grace receives no
`SIGKILL`, and a resistant descendant does receive `SIGKILL`. Assert the root
is reaped exactly once with final `process.wait(timeout=1.0)` and the literal
final `killpg(pgid, 0)` returns `ESRCH` before parsing.

Add pre-bind failure coverage proving only PID-directed `process.kill()` is
used before the single wait. Add `SIGCHLD != SIG_DFL`, `waitid` `ECHILD`,
malformed status, saved-status/returncode disagreement, identity mismatch,
PID/PGID/start-time reuse, and final non-`ESRCH` probes; each must raise
`ChatbotChildContainmentError` with no result and no unrelated group signal.
For `/proc/*/stat` enumeration, ignore only an `ENOENT` entry that vanishes
during the scan and fail closed on every other parse/read ambiguity. Preserve
real fixtures for timeout, residual cleanup, delayed markers, bounded output,
and normal child success.

Run:
`PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider scripts/holoagent0_setup/tests/test_chatbot_gate.py -k 'waitid or unreaped or root_zombie or sigchld or pid_reuse or group_enumeration'`

Expected: FAIL because the current run loop and finalizer call `Popen.poll()`
and reap before cleanup decisions.

- [ ] **Step 11: Implement unreaped identity authority and commit**

Modify `scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py`. Before
spawning, require `signal.getsignal(SIGCHLD) is SIG_DFL`; otherwise raise
`ChatbotChildContainmentError`. Bind PID=PGID/start-time before releasing
control. On initial bind failure, use only `process.kill()` and perform the one
final wait. On all bound paths, replace `poll`/pre-cleanup waits with
`os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)` and enumerate
`/proc` records `(pid, pgrp, state, start_time)` without treating enumeration as
ownership authority.

Treat only the matching root alone in `Z`/`X` as clean. Otherwise revalidate
the unreaped root identity immediately before group `SIGTERM`, observe for
exactly 250 ms without reaping, and send group `SIGKILL` only if the state has
not reached root-only `Z`/`X`; revalidate again first. Then call
`process.wait(timeout=1.0)` exactly once, compare any saved `waitid` status with
`process.returncode`, and require a final `killpg(pgid, 0)` `ESRCH`. Parse only
after all proofs. Containment ambiguity raises `ChatbotChildContainmentError`;
only a proven-clean functional/transport defect returns the closed dependency
failure.

Run the Step 10 command and the complete chatbot test file. Expected: PASS.
Refresh gate/test tracked OIDs and supervisor manifest digest, run the authority
tests, and commit:

```bash
git commit -m "fix: retain chatbot child identity through cleanup"
```

- [ ] **Step 12: Run complete Task 12 and repository verification**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider scripts/holoagent0_setup/tests/test_skills_gate.py scripts/holoagent0_setup/tests/test_chatbot_gate.py
ruff check --no-cache scripts/holoagent0_setup/holoagent0_setup/skills_gate.py scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py scripts/holoagent0_setup/chatbot_child.py scripts/holoagent0_setup/tests/test_skills_gate.py scripts/holoagent0_setup/tests/test_chatbot_gate.py
ruff format --check --no-cache scripts/holoagent0_setup/holoagent0_setup/skills_gate.py scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py scripts/holoagent0_setup/chatbot_child.py scripts/holoagent0_setup/tests/test_skills_gate.py scripts/holoagent0_setup/tests/test_chatbot_gate.py
/usr/bin/python3.10 agentic_robot/agentOS/holoagent_skills/scripts/validate_skills.py
cd scripts/holoagent0_setup
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider tests/test_supervisor.py -k 'tracked_file_manifest or tracked_manifest_pin'
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider $(sed '/^#/d;/^$/d' test-manifest-v1.txt)
```

Expected: all tests pass with only declared skips; `git diff --check` is clean
and `git status --short` is empty.

### Task 13A: Standalone invocation and one-shot run-root authority

**Files:**
- Modify: `scripts/holoagent0_setup/holoagent0_setup/invocation.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/supervisor.py`
- Create: `scripts/holoagent0_setup/tests/test_offline_cli.py`
- Modify: `scripts/holoagent0_setup/tests/test_supervisor.py`
- Modify: `scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt`

- [ ] **Step 1: Write failing invocation and directory-authority tests**

In `test_offline_cli.py`, construct deterministic private sources and require
the exact public grammar and generated identities:

```python
def test_public_parse_generates_closed_standalone_invocation(tmp_path):
    output_root = _owned_output_root(tmp_path)
    invocation = _parse_offline_invocation(
        ["--output-root", str(output_root)],
        sources=_InvocationSources(
            now_utc=lambda: datetime(2026, 8, 18, 1, 2, 3, tzinfo=timezone.utc),
            token_bytes=lambda size: bytes(range(size)),
            cwd=lambda: tmp_path,
            effective_uid=os.geteuid,
        ),
    )
    assert invocation.mode == "workstation_offline"
    assert invocation.run_id == (
        "workstation-offline-20260818T010203Z-000102030405060708090a0b0c0d0e0f"
    )
    assert invocation.invocation_role == "standalone"
    assert invocation.parent_run_id is None
    assert invocation.lineage_nonce is None
    assert invocation.run_root_authority.expected_run_root == (
        output_root / invocation.run_id
    )
```

Parametrize missing, repeated, abbreviated, unknown, positional, `--run-id`,
`--mode`, `--parent-run-id`, `--lineage-nonce`, and `--factory` inputs. Add
symlink-at-every-component, wrong owner/type/mode, group/other-writable parent,
recursive missing parent, changed device/inode, collision, replay, and cleanup
tests. In `test_supervisor.py`, require production bootstrap to call the exact
one-shot authority and prohibit the pathname fallback:

```python
def test_production_bootstrap_creates_run_root_through_retained_authority(
    tmp_path, reviewed_trace_contract, complete_bootstrap_inputs
):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, "run-authority")
    invocation = BootstrapInvocation(
        run_root=output_root / "run-authority",
        run_id="run-authority",
        run_nonce="a" * 64,
        facts=BootstrapFacts.clean(),
        bootstrap_report=complete_bootstrap_inputs,
        run_root_authority=authority,
    )
    state = BootstrapRuntime(
        reviewed_trace_contract,
        require_run_root_authority=True,
    ).run(invocation)
    assert state.run_root == output_root / "run-authority"
    assert stat.S_IMODE(state.run_root.stat().st_mode) == 0o700
    assert authority.consumed is True
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_supervisor.py \
  -k 'offline_invocation or run_root_authority or production_bootstrap_creates_run_root'
```

Expected: collection fails because `_InvocationSources`,
`_parse_offline_invocation`, and `RunRootAuthority` do not exist and
`BootstrapInvocation` has no `run_root_authority` field.

- [ ] **Step 3: Implement the minimal invocation and bootstrap authority**

In `invocation.py`, retain the existing value fields, add an optional authority
for legacy scenario construction, and expose only the closed public parser:

```python
class InvocationError(ValueError):
    """The public invocation or retained path authority is invalid."""


class _ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise InvocationError("invalid offline invocation")


@dataclass(frozen=True)
class _InvocationSources:
    now_utc: Callable[[], datetime]
    token_bytes: Callable[[int], bytes]
    cwd: Callable[[], Path]
    effective_uid: Callable[[], int]


class RunRootAuthority:
    def __init__(
        self,
        *,
        output_root: Path,
        output_root_fd: int,
        output_root_identity: tuple[int, int],
        run_basename: str,
    ) -> None:
        self._output_root = output_root
        self._output_root_fd = output_root_fd
        self._output_root_identity = output_root_identity
        self._run_basename = run_basename
        self._consumed = False

    @classmethod
    def open(cls, output_root: Path, run_basename: str) -> "RunRootAuthority":
        absolute, descriptor, identity = _open_or_create_output_root(output_root)
        return cls(
            output_root=absolute,
            output_root_fd=descriptor,
            output_root_identity=identity,
            run_basename=run_basename,
        )

    def create(self, expected_run_root: Path) -> None:
        if self._consumed or expected_run_root != self.expected_run_root:
            raise InvocationError("run-root authority is invalid or consumed")
        before = os.fstat(self._output_root_fd)
        if (before.st_dev, before.st_ino) != self._output_root_identity:
            raise InvocationError("output-root identity changed")
        try:
            os.mkdir(self._run_basename, 0o700, dir_fd=self._output_root_fd)
            child_fd = os.open(
                self._run_basename,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=self._output_root_fd,
            )
            try:
                child = os.fstat(child_fd)
                bound = os.stat(
                    self._run_basename,
                    dir_fd=self._output_root_fd,
                    follow_symlinks=False,
                )
                if (
                    (child.st_dev, child.st_ino) != (bound.st_dev, bound.st_ino)
                    or child.st_uid != os.geteuid()
                    or not stat.S_ISDIR(child.st_mode)
                    or stat.S_IMODE(child.st_mode) != 0o700
                ):
                    raise InvocationError("created run root is not authoritative")
            finally:
                os.close(child_fd)
        finally:
            self.close()

    def close(self) -> None:
        if not self._consumed:
            os.close(self._output_root_fd)
            self._consumed = True

    @property
    def expected_run_root(self) -> Path:
        return self._output_root / self._run_basename

    @property
    def consumed(self) -> bool:
        return self._consumed


@dataclass(frozen=True)
class OfflineInvocation:
    mode: Literal["workstation_offline"]
    output_root: Path
    run_id: str
    invocation_role: Literal["standalone", "child"]
    parent_run_id: str | None
    lineage_nonce: str | None
    run_root_authority: RunRootAuthority | None = None

    @classmethod
    def parse(cls, argv: Sequence[str] | None = None) -> "OfflineInvocation":
        return _parse_offline_invocation(argv, sources=_SYSTEM_INVOCATION_SOURCES)
```

`_parse_offline_invocation` uses `_ClosedArgumentParser(allow_abbrev=False)`,
an explicit one-occurrence scan for `--output-root`, exactly 16 random bytes
for the run-ID suffix, and `RunRootAuthority.open`. Help may retain argparse's
normal zero-exit behavior, but every invalid form is converted to the fixed
`InvocationError` rather than escaping as exit `2`. The authority validates
the generated basename against the closed run-ID grammar, walks absolute
components with retained `dir_fd` plus `O_NOFOLLOW`, permits creation of only
the final output-root component, records the parent device/inode, and owns that
FD until `create` or `close`. `create` revalidates the parent, calls
`os.mkdir(run_basename, 0o700, dir_fd=output_root_fd)`, opens and verifies the
new directory, compares it with the expected absolute binding, then consumes
the authority. Every exception closes all owned descriptors.

In `supervisor.py`, add
`run_root_authority: RunRootAuthority | None = None` to `BootstrapInvocation`
and `require_run_root_authority: bool = False` to `BootstrapRuntime`. Its
production classmethod sets the flag to `True`. `run()` calls the exact
authority once before ledger creation; only non-production scenario runtimes
retain the existing `Path.mkdir` branch. Update all direct production-runtime
tests to construct a real authority rather than weakening the production flag.

- [ ] **Step 4: Run focused and regression tests and verify GREEN**

Run:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_supervisor.py \
  scripts/holoagent0_setup/tests/test_evidence.py \
  scripts/holoagent0_setup/tests/test_ledger.py
ruff check --no-cache \
  scripts/holoagent0_setup/holoagent0_setup/invocation.py \
  scripts/holoagent0_setup/holoagent0_setup/supervisor.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_supervisor.py
ruff format --check --no-cache \
  scripts/holoagent0_setup/holoagent0_setup/invocation.py \
  scripts/holoagent0_setup/holoagent0_setup/supervisor.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_supervisor.py
```

Expected: all selected tests pass; Ruff reports no error and no reformatting.

- [ ] **Step 5: Refresh tracked authority and commit Task 13A**

Stage the intended files, regenerate each changed Git blob row in
`git-tracked-files-v1.txt`, recompute its SHA-256 in `supervisor.py`, and run the
closed authority selection before committing:

```bash
git add scripts/holoagent0_setup/holoagent0_setup/invocation.py \
  scripts/holoagent0_setup/holoagent0_setup/supervisor.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_supervisor.py \
  scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_supervisor.py -k 'production_tracked'
git diff --cached --check
git commit -m "feat: add offline invocation authority"
```

Expected: the authority tests pass, the staged diff is clean, and the commit
contains no Task 13B/13C file.

### Task 13B: Pending production factory and strict CLI

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py`
- Create: `scripts/holoagent0_setup/holoagent0_setup/offline_cli.py`
- Modify: `scripts/holoagent0_setup/tests/test_offline_cli.py`
- Create: `scripts/holoagent0_setup/tests/test_offline_integration.py`
- Modify: `scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/supervisor.py`

- [ ] **Step 1: Write failing pending-runtime, readback, and factory-isolation tests**

Require a fixed production factory, the current exact pending-runtime outcome,
and validated diagnostic output:

```python
def test_public_pending_runtime_is_authoritative_and_never_launches(
    pending_offline_application, parsed_invocation
):
    completed = pending_offline_application.run(parsed_invocation)
    result = _secure_result(parsed_invocation.result_path)
    assert completed == 40
    assert pending_offline_application.factory.launcher_calls == 0
    assert result["label"] == "FAIL_HARNESS"
    assert result["status"] == "FAIL"
    assert result["process_exit_code"] == 40
    assert result["primary_blocking_gate"] == "offline.trace_integrity"
    assert _gate(result, "offline.trace_integrity") == {
        "id": "offline.trace_integrity",
        "role": "finalizer",
        "status": "FAIL",
        "reason": "TRACE_BOOTSTRAP_FAILED",
    }
    assert _gate(result, "offline.network_policy")["status"] == "SKIPPED"
    assert _gate(result, "offline.network_policy")["reason"] == (
        "DEPENDENCY_NOT_AVAILABLE"
    )
```

Add tests for the two exact output lines, `NONE`, and `UNAVAILABLE`; missing,
symlinked, changing, oversized, noncanonical, wrong-run, wrong-mode,
wrong-gate-order, and wrong-label/status/exit/blocker results; fake selectors in
argv/environment/entry-point metadata; working-directory/path shadowing; and
unexpected launcher/forwarder/identity-validator calls. Every invalid readback
returns `40`, leaves artifacts untouched, and performs no second publication.

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
```

Expected: collection fails because `offline_runtime`, `offline_cli`,
`OfflineApplication`, and `PendingProductionFactory` do not exist.

- [ ] **Step 3: Implement the fixed factory, application, and secure readback**

In `offline_runtime.py`, define the only composition boundary:

```python
class OfflineRuntimeError(RuntimeError):
    """The fixed offline composition could not be constructed safely."""


@dataclass(frozen=True)
class OfflineExecution:
    supervisor: EvidenceSupervisor
    bootstrap_invocation: BootstrapInvocation
    contract: ContractSet


class OfflineRuntimeFactory(Protocol):
    def build(self, invocation: OfflineInvocation) -> OfflineExecution:
        raise NotImplementedError


class PendingProductionFactory:
    def __init__(self, package_root: Path) -> None:
        self._package_root = _retain_tracked_package_root(package_root)
        self.launcher_calls = 0

    def _unexpected_launch(self, specification: object) -> object:
        self.launcher_calls += 1
        raise SupervisorError("pending trace runtime was unexpectedly reached")

    @staticmethod
    def _unexpected_forward(_pgid: int, _signal_name: str) -> object:
        raise SupervisorError("pending coordinator forward was unexpectedly reached")

    @staticmethod
    def _unexpected_identity(_identity: ProcessIdentity) -> bool:
        raise SupervisorError("pending coordinator identity was unexpectedly reached")

    def build(self, invocation: OfflineInvocation) -> OfflineExecution:
        contract = ContractSet(self._package_root)
        facts, report = _collect_pending_bootstrap_inputs(contract)
        bootstrap = BootstrapInvocation(
            run_root=invocation.result_path.parent,
            run_id=invocation.run_id,
            run_nonce=secrets.token_hex(32),
            facts=facts,
            bootstrap_report=report,
            run_root_authority=invocation.run_root_authority,
        )
        supervisor = EvidenceSupervisor.production(
            contract,
            trace_launcher=self._unexpected_launch,
            signal_forwarder=self._unexpected_forward,
            signal_identity_validator=self._unexpected_identity,
            secret_sentinels={"h0-sentinel-" + secrets.token_hex(32)},
        )
        return OfflineExecution(supervisor, bootstrap, contract)
```

`_retain_tracked_package_root` walks the absolute path from `/` through
`O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW` descriptors, requires every component
to remain identity-stable, and returns the canonical package path only when the
final descriptor is an effective-UID-owned directory. It closes every
descriptor on success and failure. `_collect_pending_bootstrap_inputs` loads
the one trace-tool row, enumerates at most 64 numeric `/proc/self/fd` entries in
ascending order, excludes only its own enumeration descriptor, records exact
`fd`/redacted `target`/`cloexec` rows, classifies sockets through
`SO_DOMAIN`/`SO_TYPE`/`SO_PROTOCOL`, and returns `BootstrapFacts` plus this
closed report:

```python
{
    "schema_version": "holoagent0.bootstrap-report.v1",
    "toolchain": {"expected": expected_toolchain, "observed": observed_toolchain},
    "initial_fd_manifest": descriptor_rows,
    "final_fd_manifest": descriptor_rows,
    "sanitation_actions": [],
    "rebinding_actions": [],
    "live_fixture_passed": False,
}
```

The collector accepts only stdin `/dev/null` or a reviewed non-socket
pipe/regular file and stdout/stderr reviewed non-socket pipes/regular files;
every other inherited descriptor makes `inherited_fd_safe=False` without
silently closing it. `PendingProductionFactory` accepts only that retained
package root derived from `offline_runtime.py.__file__`. It loads the tracked
`ContractSet`, generates a separate 32-byte ledger nonce, and passes facts with
`source_ok`, `runtime_ok`, `trace_capability_ok`, and `exitkill_verified`
initially true while `inherited_fd_safe` and `sanitation_ok` reflect the exact
descriptor observation. The existing
`_ProductionBootstrapAdapter` intersects those facts with the pending trace
policy and selects `NOT_STARTED`. Its trace launcher, signal forwarder, and
post-launch identity validator increment private counters and raise
`SupervisorError` if reached. The secret-sentinel set contains one independent
32-byte random value held only in memory.

In `offline_cli.py`, make the internal test seam explicit while keeping public
construction fixed:

```python
class OfflineApplication:
    def __init__(
        self,
        factory: OfflineRuntimeFactory,
        *,
        stdout: TextIO,
    ) -> None:
        self._factory = factory
        self.stdout = stdout

    def run(self, invocation: OfflineInvocation) -> int:
        print(f"evidence_dir={invocation.result_path.parent}", file=self.stdout, flush=True)
        try:
            execution = self._factory.build(invocation)
            exit_code = execution.supervisor.execute_authoritative(
                execution.bootstrap_invocation
            )
            primary = _validated_primary_blocker(execution, invocation, exit_code)
        except (
            OfflineRuntimeError,
            SupervisorError,
            AtomicIOError,
            CanonicalJSONError,
            ContractLoadError,
            ContractError,
        ):
            print(
                "primary_blocking_gate=UNAVAILABLE",
                file=self.stdout,
                flush=True,
            )
            return 40
        print(f"primary_blocking_gate={primary}", file=self.stdout, flush=True)
        return exit_code if primary != "UNAVAILABLE" else 40


def main(argv: Sequence[str] | None = None) -> int:
    try:
        invocation = OfflineInvocation.parse(argv)
        package_root = _tracked_package_root()
        return OfflineApplication(
            PendingProductionFactory(package_root),
            stdout=sys.stdout,
        ).run(invocation)
    except (InvocationError, OfflineRuntimeError):
        print("offline invocation rejected", file=sys.stderr, flush=True)
        return 40
```

`_validated_primary_blocker` calls `read_json_secure` relative to the retained
run root, requires exact mode, canonical bytes, stable identity, result size,
`ContractSet.require_valid_result`, expected run ID/mode, exact
`OFFLINE_GATE_ORDER`, and matching process exit. It returns the fixed gate ID,
`NONE`, or `UNAVAILABLE`; it never writes. `OfflineApplication.run` catches
only the six listed post-invocation exception classes, prints the mandatory
`UNAVAILABLE` line, and returns `40`; public `main` catches only
`InvocationError` and pre-execution `OfflineRuntimeError`, emits the fixed
credential-free diagnostic to stderr, and returns `40`. Each helper wraps its
own raw `OSError` or decode failure into one of those closed classes. Do not
catch `KeyboardInterrupt`, `SystemExit`, or `BaseException`.

- [ ] **Step 4: Run focused, production-pending, and quality checks**

Run:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py \
  scripts/holoagent0_setup/tests/test_supervisor.py \
  -k 'offline or production_factory_current_pending_policy'
ruff check --no-cache \
  scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py \
  scripts/holoagent0_setup/holoagent0_setup/offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
ruff format --check --no-cache \
  scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py \
  scripts/holoagent0_setup/holoagent0_setup/offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
```

Expected: all selected tests pass, the launcher counters remain zero, and Ruff
reports no error or reformatting.

- [ ] **Step 5: Refresh tracked authority and commit Task 13B**

Add both new tests to `test-manifest-v1.txt`, refresh the tracked Git blob rows
and manifest SHA-256, run the manifest-authority selection, then commit:

```bash
git add scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py \
  scripts/holoagent0_setup/holoagent0_setup/offline_cli.py \
  scripts/holoagent0_setup/holoagent0_setup/supervisor.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py \
  scripts/holoagent0_setup/test-manifest-v1.txt \
  scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_supervisor.py -k 'production_tracked'
git diff --cached --check
git commit -m "feat: add pending offline readiness CLI"
```

Expected: the authority tests pass and the commit contains no shell wrapper or
live launcher/action-child implementation.

### Task 13C: Full fake-pipeline proof and public shell wrapper

**Files:**
- Create: `scripts/holoagent0_setup/run_workstation_offline.sh`
- Create: `scripts/holoagent0_setup/tests/offline_fake_runtime.py`
- Modify: `scripts/holoagent0_setup/tests/test_offline_integration.py`
- Modify: `scripts/holoagent0_setup/tests/test_offline_cli.py`
- Modify: `scripts/holoagent0_setup/test-manifest-v1.txt`
- Modify: `scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/supervisor.py`

- [ ] **Step 1: Write failing fake-authority and wrapper tests**

Build a tracked fake factory from the real `EvidenceSupervisor` with injected
bootstrap, trace, broker, finalizer, and result-publisher dependencies. Only
the supervisor invokes the publisher. Require the complete passing tuple:

```python
def test_offline_pass_has_exact_order_and_authority(fake_offline_environment):
    completed = fake_offline_environment.run_application()
    result = completed.validated_result
    assert completed.returncode == 0
    assert result["label"] == "PASS_HOLOAGENT0_OFFLINE"
    assert result["status"] == "PASS"
    assert result["process_exit_code"] == 0
    assert result["primary_blocking_gate"] is None
    assert [gate["id"] for gate in result["gates"]] == list(OFFLINE_GATE_ORDER)
    assert all(gate["status"] == "PASS" for gate in result["gates"][-4:])
    assert result["offline_evidence"]["trace"]["state"] == "FULL"
    assert result["offline_evidence"]["network_policy"]["violations"] == 0
    assert completed.publisher_calls == 1
```

Run the real wrapper from a neutral directory against an owned output root and
require the Task 13B pending tuple, fixed stdout lines, exit `40`, and retained
result. Repeat with hostile `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`,
entry-point metadata, current directory, and factory-shaped environment keys;
the result must remain production-pending. Inspect the executed process tree
and wrapper text to reject any install, download, probe, ROS, gateway,
simulator, Unitree, cleanup, deletion, alternate Python, or shell-evaluated
user command.

- [ ] **Step 2: Run integration tests and verify RED**

Run:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_integration.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  -k 'fake_pipeline or shell_wrapper or neutral_working_directory or hostile_python'
```

Expected: the fake helper and public shell wrapper are missing.

- [ ] **Step 3: Implement the tracked fake and fixed wrapper**

`offline_fake_runtime.py` constructs `EvidenceSupervisor` with exact fake
stages. Its finalizer returns an `AuthoritativeEvaluation` containing a
schema-valid full offline PASS result and terminal proof; its fake publisher
uses `atomic_write_json_no_replace` exactly once. No fake writes before the
supervisor calls `publish`, and the helper is imported only by tests.

Create `run_workstation_offline.sh` as mode `100755`:

```bash
#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -P -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export LC_ALL=C
export TZ=UTC
export PYTHONPATH="${script_dir}"
export PYTHONNOUSERSITE=1
export PYTHONSAFEPATH=1
export PYTHONDONTWRITEBYTECODE=1
export START_G1_PUBVEL=0
export G1_DRY_RUN=1
export ALLOW_G1_MOTION=0
unset PYTHONHOME PYTHONSTARTUP PYTHONINSPECT PYTHONWARNINGS PYTHONBREAKPOINT \
  PYTHONUSERBASE PYTHONPLATLIBDIR PYTHONCASEOK PYTHONEXECUTABLE

exec /usr/bin/python3.10 -P -B -m holoagent0_setup.offline_cli "$@"
```

The wrapper uses only Bash builtins plus the fixed `/usr/bin/dirname`; it does
not source another file, search `PATH`, preserve a caller
`PYTHONPATH`, preserve a caller-controlled Python home/startup/user-base/runtime
layout, evaluate user text, create/delete an evidence path, or run any other
command after `exec`. Provider credential variables remain inherited but are
never copied to argv or diagnostics. The hostile-environment test enumerates
every unset variable above and proves that none can select the fake factory or
shadow the tracked package.

- [ ] **Step 4: Run focused, full-manifest, and static verification**

Run from the repository root:

```bash
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
sed '/^#/d;/^$/d' scripts/holoagent0_setup/test-manifest-v1.txt | \
  xargs env PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 \
  PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 /usr/bin/python3.10 -m pytest -q -p no:cacheprovider
bash -n scripts/holoagent0_setup/run_workstation_offline.sh
ruff check --no-cache scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py \
  scripts/holoagent0_setup/holoagent0_setup/offline_cli.py \
  scripts/holoagent0_setup/holoagent0_setup/invocation.py \
  scripts/holoagent0_setup/tests/offline_fake_runtime.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
ruff format --check --no-cache scripts/holoagent0_setup/holoagent0_setup/offline_runtime.py \
  scripts/holoagent0_setup/holoagent0_setup/offline_cli.py \
  scripts/holoagent0_setup/holoagent0_setup/invocation.py \
  scripts/holoagent0_setup/tests/offline_fake_runtime.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py
```

Expected: the focused and complete tracked selections collect tests and have
zero failures; shell syntax, Ruff, and formatting pass. Declared skips are
reported but not converted to failures. No live network, ROS/DDS, OpenClaw,
audio, simulator, PC2, sensor, Unitree, or robot action is started.

- [ ] **Step 5: Refresh authority, commit Task 13C, and stop at its review gate**

Refresh every new/changed tracked Git blob row and the manifest SHA-256, then
run final authority and cleanliness checks before committing:

```bash
git add scripts/holoagent0_setup/run_workstation_offline.sh \
  scripts/holoagent0_setup/tests/offline_fake_runtime.py \
  scripts/holoagent0_setup/tests/test_offline_cli.py \
  scripts/holoagent0_setup/tests/test_offline_integration.py \
  scripts/holoagent0_setup/test-manifest-v1.txt \
  scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt \
  scripts/holoagent0_setup/holoagent0_setup/supervisor.py
PYTHONPATH=scripts/holoagent0_setup PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/bin/python3.10 -m pytest -q -p no:cacheprovider \
  scripts/holoagent0_setup/tests/test_supervisor.py -k 'production_tracked'
git diff --cached --check
git commit -m "feat: integrate workstation offline runner"
git status --short
```

Expected: authority checks pass, the diff is clean, the final status is empty,
and Task 14 remains unimplemented pending a separate live-runtime review.

## Post-Task 13 live-runtime handoff

Task 13C is the terminal implementation and review boundary of this plan. The
old documentation-only Task 14 was removed because it could not implement the
live authorities assigned to it by the approved design and therefore could
never satisfy the completion gate below.

Live readiness is a separate subsystem and requires a separate reviewed design
amendment and implementation plan after Task 13C. That work must first review
and commit literal reproducible-build and installed-runtime pins for strace
6.6, then implement the concrete tracer/normalizer/coordinator launcher,
production `TracedCoordinator` and action-child factory, broker and handoff FD
assembly, isolated semantic DDS loopback execution, and finally the inspection
runbook. Candidate measurements may be produced only by the already reviewed
provisioner under separate network/Docker authorization; they do not amend the
policy or authorize installation automatically.

Until that separate checkpoint is approved, the public wrapper must retain the
exact Task 13B pending outcome (`FAIL_HARNESS`, exit `40`, zero launcher calls).
No Task 13 worker may provision strace, promote a policy row to `REVIEWED`,
start the live coordinator/action child, create a ROS/DDS participant, launch
OpenClaw, access audio, run MuJoCo, contact PC2, inspect sensors, import the
Unitree SDK, or command robot hardware.

## Plan 1 completion gate

Do not start the MuJoCo plan until the separate live-runtime plan is approved
and one fresh `workstation_offline` run has a schema-valid pass or approved
credential/audio qualification, gates 1–27 in exact order, all four finalizers
satisfied, trace/evidence bundle digests independently recomputed, and no
unapproved network operation. Preserve the run directory and its
commit/config/asset/policy digests for `offline.reference`.
