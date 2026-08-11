# HoloAgent-0 Workstation Offline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the approved `workstation_offline` profile: deterministic AgentOS input, pinned OpenClaw and semantic assets, a fail-closed traced coordinator, and schema-valid evidence with no external or unapproved network activity.

**Architecture:** A small Python package under `scripts/holoagent0_setup/` owns closed schemas, policies, immutable ledgers, result classification, trace normalization, and the supervisor/coordinator split. Native launch helpers establish the inherited-FD, signal, seccomp, ptrace, and namespace boundaries before Python functional gates run. The supervisor alone publishes `result.json`; the traced coordinator can only submit hash-chained ledger generations over reviewed anonymous pipes.

**Tech Stack:** Python 3.10, pytest, JSON Schema Draft 2020-12, Bash, C17/Linux syscalls, strace 6.6, Linux user/network namespaces, seccomp, ROS 2 Humble, CycloneDDS, OpenClaw 2026.7.1-2, SHA-256/SHA-512.

**Dependency:** Begin from approved design commit `2363983`. This plan produces the shared result/policy package consumed by the MuJoCo and PC2 plans.

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
- `scripts/holoagent0_setup/holoagent0_setup/offline_cli.py`: the public `workstation_offline` command.
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
but pinned raw records do not carry them. Unannotated, malformed, or unknown FD
provenance fails trace integrity and an unknown annotated socket also fails
network policy.
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

Before applying TX interposition, inspect every affected open-file-description.
For `dup2`/`dup3`, this includes both the source and the implicitly closed target;
for `close_range`, it includes the entire selected range even when
`CLOSE_RANGE_CLOEXEC` is present. Poison and journal any incomplete registration
found. CLOEXEC-only ranges remain open for lifecycle accounting.

Participant authority is not inherited merely because a descendant has an FD.
A successful lifecycle edge from an authorized task grants authority only when
the clone flags prove both the same thread group and the same FD table through
`CLONE_THREAD|CLONE_FILES`. `fork`, `vfork`, and any `clone` missing
either flag retain only their ordinary FD-provenance semantics; they receive no
participant role. Exit removes the task/TID authority without granting it to a
later PID reuse. The externally journal-validated configured root remains the
root across its first observed spawn/exec lifecycle, but its exit permanently
closes that incarnation and later numeric PID reuse cannot reauthorize it. A
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

Pin Node, installer digest, `openclaw@2026.7.1-2`, registry `dist.integrity`, tarball SHA-512, installed canonical payload manifest, local prefix, provisioning schema digest, and minimal loopback configuration. Refuse mutation if a service/process/listener exists. Use only `openclaw gateway status --deep --no-probe --json`, `config validate`, and the two approved `doctor --lint --json` invocations; never start a gateway in the offline profile.

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
npm view "openclaw@2026.7.1-2" dist.integrity --json
npm pack "openclaw@2026.7.1-2" --pack-destination "${verified_dir}"
PYTHONPATH=scripts/holoagent0_setup python3 -m holoagent0_setup.openclaw_gate \
  verify-sri --tarball "${tarball}" --integrity "${expected_integrity}"
"${verified_installer}" --prefix "${HOME}/.openclaw" \
  --version "file:${tarball}" --node-version 24.15.0 --no-onboard --json
OPENCLAW_CONFIG_PATH="${HOME}/.openclaw-holoagent0/openclaw.json" \
  openclaw config validate --json
OPENCLAW_CONFIG_PATH="${HOME}/.openclaw-holoagent0/openclaw.json" \
  openclaw doctor --lint --only core/doctor/gateway-config \
  --severity-min warning --json
OPENCLAW_CONFIG_PATH="${HOME}/.openclaw-holoagent0/openclaw.json" \
  openclaw doctor --lint --severity-min error --json
```

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

Populate `semantic-source-manifest-v1.json` with the exact 74 sorted paths approved in Component 1 of `docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md`; the test must compare the tracked manifest path set to that table with no extras or omissions. Verify every path against commit `f164095abb0045a69c0b8eb23683063be3deaa38`, reject a reappeared conflicting path, and never expand the manifest by scanning the old snapshot tree. Record graph/dataset/checkpoint root digests from the approved design. Run the structured query through the real HMSG retrieval/transform code, bypassing only the external LLM parser. Enforce exact publisher/subscriber counts, frame, object, pose, and the four pinned Cyclone participant configurations; bracket DDS with nonce-bearing BEGIN/END markers.

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

Call the tracked skill validator/list/dry-run commands without executing robot scripts. For chatbot, import the declared Python 3.10 dependencies, parse robot JSON, enumerate audio devices without opening streams, record only credential variable presence, and run bounded configuration startup with process/network/microphone spies. Map missing credentials/audio only through the approved qualification matrix.

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

### Task 13: Offline CLI and full gate integration

**Files:**
- Create: `scripts/holoagent0_setup/holoagent0_setup/offline_cli.py`
- Modify: `scripts/holoagent0_setup/holoagent0_setup/invocation.py`
- Create: `scripts/holoagent0_setup/run_workstation_offline.sh`
- Test: `scripts/holoagent0_setup/tests/test_offline_cli.py`
- Test: `scripts/holoagent0_setup/tests/test_offline_integration.py`

- [ ] **Step 1: Write an end-to-end fake-toolchain test**

```python
def test_offline_pass_has_exact_order_and_authority(fake_offline_environment):
    completed = fake_offline_environment.run()
    result = json.loads(completed.result_path.read_text())
    assert completed.returncode == 0
    assert result["label"] == "PASS_HOLOAGENT0_OFFLINE"
    assert [g["id"] for g in result["gates"]] == list(OFFLINE_GATE_ORDER)
    assert result["offline_evidence"]["trace"]["state"] == "FULL"
    assert result["offline_evidence"]["network_policy"]["violations"] == 0
```

- [ ] **Step 2: Run integration tests and verify CLI absence**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_offline_cli.py scripts/holoagent0_setup/tests/test_offline_integration.py`

Expected: FAIL because the public runner does not exist.

- [ ] **Step 3: Implement strict CLI wiring**

```python
def main(argv: Sequence[str] | None = None) -> int:
    invocation = OfflineInvocation.parse(argv)
    supervisor = EvidenceSupervisor.from_invocation(invocation)
    return supervisor.execute_authoritative()
```

The shell wrapper sets `LC_ALL=C`, `TZ=UTC`, `START_G1_PUBVEL=0`, `G1_DRY_RUN=1`, `ALLOW_G1_MOTION=0`, reviewed paths only, no ROS participant, and no download command. Require a new run directory, exact pins, read-only host observation, loopback namespace, fixed gate order, all four finalizers, and supervisor-only result publication. Print the evidence directory and first precedence-winning gate; never delete failed runs.

- [ ] **Step 4: Run the complete tracked offline manifest**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q $(sed '/^#/d;/^$/d' scripts/holoagent0_setup/test-manifest-v1.txt)`

Expected: at least one test collected and zero failures.

- [ ] **Step 5: Commit the offline runner**

```bash
git add scripts/holoagent0_setup/holoagent0_setup/offline_cli.py scripts/holoagent0_setup/run_workstation_offline.sh scripts/holoagent0_setup/tests scripts/holoagent0_setup/test-manifest-v1.txt
git commit -m "feat: add workstation offline readiness runner"
```

### Task 14: Runtime acceptance, evidence inspection, and documentation

**Files:**
- Modify: `scripts/holoagent0_setup/README.md`
- Create: `docs/holoagent0/workstation-offline-runbook.md`
- Test: `scripts/holoagent0_setup/tests/test_runbook_commands.py`

- [ ] **Step 1: Add command-validation tests for the runbook**

```python
def test_runbook_uses_no_unpinned_or_motion_command(runbook):
    assert "run_ctl.sh" not in runbook
    assert "g1_pubvel_node" not in runbook
    assert "openclaw gateway start" not in runbook
    assert "run_workstation_offline.sh" in runbook
```

- [ ] **Step 2: Run the runbook test and verify it fails before documentation exists**

Run: `PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q scripts/holoagent0_setup/tests/test_runbook_commands.py`

Expected: FAIL because the runbook is absent.

- [ ] **Step 3: Document provisioning, execution, and inspection commands**

Include exact commands for pinned strace provisioning, OpenClaw provisioning, offline execution, JSON Schema validation, trace/journal digest recomputation, gate/label inspection, qualification interpretation, and safe cleanup. State explicitly that the run does not commission physical motion.

```bash
bash scripts/holoagent0_setup/run_workstation_offline.sh --output-root outputs/holoagent0_setup
jq '{label,status,process_exit,primary_blocking_gate,qualifications}' outputs/holoagent0_setup/*/result.json
```

- [ ] **Step 4: Run static, unit, native, and manifest verification**

Run: `make -C scripts/holoagent0_setup/native clean all && PYTHONPATH=scripts/holoagent0_setup python3 -m pytest -q $(sed '/^#/d;/^$/d' scripts/holoagent0_setup/test-manifest-v1.txt) && git diff --check`

Expected: native build succeeds, at least one test is collected, zero tests fail, and `git diff --check` prints nothing.

- [ ] **Step 5: Commit the runbook**

```bash
git add scripts/holoagent0_setup/README.md docs/holoagent0/workstation-offline-runbook.md scripts/holoagent0_setup/tests/test_runbook_commands.py
git commit -m "docs: add workstation offline readiness runbook"
```

## Plan 1 completion gate

Do not start the MuJoCo plan until one fresh `workstation_offline` run has a schema-valid pass or approved credential/audio qualification, gates 1–27 in exact order, all four finalizers satisfied, trace/evidence bundle digests independently recomputed, and no unapproved network operation. Preserve the run directory and its commit/config/asset/policy digests for `offline.reference`.
