from __future__ import annotations

import copy
import inspect
import itertools
from pathlib import Path

import pytest

from holoagent0_setup.cyclone_policy import EXPECTED_CONFIG_SHA256
from holoagent0_setup.trace_normalizer import normalize_bytes
from holoagent0_setup.trace_policy import TracePolicy


TOKEN = "0123456789ab"
COORDINATOR_PID = 90
PARTICIPANT_PIDS = {index: 100 + index for index in range(4)}
CONFIG_DIGESTS = EXPECTED_CONFIG_SHA256
META_PORTS = {0: 26660, 1: 26662, 2: 26664, 3: 26666}
DATA_PORTS = {0: 26661, 1: 26663, 2: 26665, 3: 26667}
EPHEMERAL_PORTS = {0: 40000, 1: 40001, 2: 40002, 3: 40003}
TX_SETUP_OPTIONS = (
    ("IP_MULTICAST_IF", "127.0.0.1", 4),
    ("IP_MULTICAST_TTL", 1, 1),
    ("IP_MULTICAST_LOOP", 1, 1),
)
TX_STAGE_NAMES = ("if", "ttl", "loop")
TX_INVALID_VALUES = ("0.0.0.0", 2, 0)
FIXTURES = Path(__file__).parents[1] / "fixtures/strace"
RECEIVE_FD_CASES = (
    ("spdp", 26650, ("239.255.0.1", 26650)),
    ("data_multicast", 26651, ("239.255.0.1", 26650)),
    ("fixed_meta", META_PORTS[0], ("127.0.0.1", META_PORTS[1])),
    ("fixed_data", DATA_PORTS[0], ("127.0.0.1", DATA_PORTS[1])),
)


def _launcher_manifest():
    return {
        COORDINATOR_PID: [
            {
                "fd": 0,
                "kind": "character_device",
                "inode": 101,
                "cloexec": False,
            },
            {"fd": 4, "kind": "pipe", "inode": 102, "cloexec": True},
        ]
    }


class RecordingViolationSink:
    def __init__(self):
        self.events = []

    def persist(self, violation):
        self.events.append(violation)


class FailingViolationSink:
    def persist(self, violation):
        del violation
        raise RuntimeError("violation sink unavailable")


class Records:
    def __init__(self):
        self.index = 0

    def make(self, pid, syscall, **fields):
        event_index = self.index
        record = {
            "kind": "syscall",
            "pid": pid,
            "record_index": event_index,
            "entry_index": event_index,
            "exit_index": event_index,
            "syscall": syscall,
            "result": {"value": fields.pop("result", 0)},
        }
        record.update(fields)
        self.index += 1
        return record

    def marker(self, phase, *, pid=COORDINATOR_PID, token=TOKEN, result=0):
        return self.make(
            pid,
            "prctl",
            result=result,
            marker={"phase": phase, "token": token},
        )

    def socket(self, pid, fd, *, domain="AF_INET", protocol="IPPROTO_UDP"):
        return self.make(
            pid,
            "socket",
            result=fd,
            transition={
                "operation": "socket",
                "domain": domain,
                "socket_type": ["SOCK_DGRAM", "SOCK_CLOEXEC"],
                "protocol": protocol,
                "created_fd": {
                    "fd": fd,
                    "provenance": {"kind": "socket", "inode": 10_000 + fd},
                },
            },
        )

    def bind(self, pid, fd, address, port):
        return self.make(
            pid,
            "bind",
            transition={
                "operation": "bind",
                "fd": {"fd": fd},
                "address": {"family": "AF_INET", "ip": address, "port": port},
            },
        )

    def getsockname(self, pid, fd, address, port):
        return self.make(
            pid,
            "getsockname",
            transition={
                "operation": "getsockname",
                "fd": {"fd": fd},
                "address": {"family": "AF_INET", "ip": address, "port": port},
            },
        )

    def membership(self, pid, fd, *, option="IP_ADD_MEMBERSHIP"):
        return self.make(
            pid,
            "setsockopt",
            transition={
                "operation": "setsockopt",
                "fd": {"fd": fd},
                "level": "SOL_IP",
                "option": option,
                "length": 8,
                "membership": {
                    "group": "239.255.0.1",
                    "interface": "127.0.0.1",
                },
            },
        )

    def tx_socket_option(
        self,
        pid,
        fd,
        option,
        value,
        length,
        *,
        level="SOL_IP",
        result=0,
    ):
        return self.make(
            pid,
            "setsockopt",
            result=result,
            transition={
                "operation": "setsockopt",
                "fd": {"fd": fd},
                "level": level,
                "option": option,
                "value": value,
                "length": length,
            },
        )

    def close(self, pid, fd):
        return self.make(
            pid,
            "close",
            transition={"operation": "close", "closed_fd": {"fd": fd}},
        )

    def io(self, pid, syscall, fd, *, address=None, control=None, result=8):
        fields = {"fds": [{"fd": fd}], "lengths": {"count": 8}}
        if address is not None:
            fields["address"] = {
                "family": "AF_INET",
                "ip": address[0],
                "port": address[1],
            }
        if control is not None:
            fields["control"] = control
        return self.make(pid, syscall, result=result, **fields)

    def exit(self, pid, *, exit_code=0):
        event_index = self.index
        self.index += 1
        return {
            "kind": "exit",
            "pid": pid,
            "record_index": event_index,
            "exit_code": exit_code,
        }


def _trace_line(call, *, pid=100, result="0"):
    prefix = f"{pid:<5} 1700000060.000001 "
    padding = " " * max(1, 40 - len(prefix) - len(call))
    return f"{prefix}{call}{padding}= {result} <0.000001>\n".encode()


def make_policy(
    *,
    loopback_only=True,
    participant_digests=None,
    initial_fd_manifest=None,
    violation_sink=None,
):
    participant_digests = participant_digests or CONFIG_DIGESTS
    constructor_arguments = {
        "coordinator_pid": COORDINATOR_PID,
        "marker_token": TOKEN,
        "participants": {
            pid: {"index": index, "config_digest": participant_digests[index]}
            for index, pid in PARTICIPANT_PIDS.items()
        },
        "namespace_loopback_only": loopback_only,
        "initial_fd_manifest": copy.deepcopy(
            _launcher_manifest() if initial_fd_manifest is None else initial_fd_manifest
        ),
    }
    if "violation_sink" in inspect.signature(TracePolicy).parameters:
        constructor_arguments["violation_sink"] = (
            RecordingViolationSink() if violation_sink is None else violation_sink
        )
    return TracePolicy(**constructor_arguments)


def _constructor_arguments(*, include_manifest=True, include_sink=True):
    arguments = {
        "coordinator_pid": COORDINATOR_PID,
        "marker_token": TOKEN,
        "participants": {
            pid: {"index": index, "config_digest": CONFIG_DIGESTS[index]}
            for index, pid in PARTICIPANT_PIDS.items()
        },
        "namespace_loopback_only": True,
    }
    if include_manifest:
        arguments["initial_fd_manifest"] = _launcher_manifest()
    if include_sink and "violation_sink" in inspect.signature(TracePolicy).parameters:
        arguments["violation_sink"] = RecordingViolationSink()
    return arguments


def open_window(policy, records):
    assert policy.feed(records.marker("BEGIN")).status == "PASS"


def outcome(decision):
    return decision.status, decision.reason


def passing_registration():
    return [("PASS", "OK")] * 6


def bound_udp(policy, records, participant, local, *, fd=7):
    pid = PARTICIPANT_PIDS[participant]
    assert policy.feed(records.socket(pid, fd)).status == "PASS"
    return pid, policy.feed(records.bind(pid, fd, *local))


def registered_tx(policy, records, participant, *, fd=17, port=None):
    dynamic_port = EPHEMERAL_PORTS[participant] if port is None else port
    pid, decision = bound_udp(
        policy,
        records,
        participant,
        ("127.0.0.1", 0),
        fd=fd,
    )
    assert decision.status == "PASS"
    for option, value, length in TX_SETUP_OPTIONS:
        decision = policy.feed(records.tx_socket_option(pid, fd, option, value, length))
        assert decision.status == "PASS"
    decision = policy.feed(records.getsockname(pid, fd, "127.0.0.1", dynamic_port))
    assert decision.status == "PASS"
    return pid, fd, dynamic_port


def observe_tx_registration(policy, records, participant, *, fd=17, port=None):
    dynamic_port = EPHEMERAL_PORTS[participant] if port is None else port
    pid = PARTICIPANT_PIDS[participant]
    decisions = (
        policy.feed(records.socket(pid, fd)),
        policy.feed(records.bind(pid, fd, "127.0.0.1", 0)),
        *(
            policy.feed(records.tx_socket_option(pid, fd, option, value, length))
            for option, value, length in TX_SETUP_OPTIONS
        ),
        policy.feed(records.getsockname(pid, fd, "127.0.0.1", dynamic_port)),
    )
    return pid, fd, dynamic_port, decisions


def clone_worker(policy, records, parent_pid, worker_tid):
    return policy.feed(
        records.make(
            parent_pid,
            "clone",
            result=worker_tid,
            transition={
                "operation": "clone",
                "child_pid": worker_tid,
                "fd_table": "shared",
                "flags": [
                    "CLONE_VM",
                    "CLONE_FILES",
                    "CLONE_SIGHAND",
                    "CLONE_THREAD",
                ],
            },
        )
    )


def connected_udp(policy, records, participant=0, *, fd=7):
    pid, fd, _ = registered_tx(policy, records, participant, fd=fd)
    decision = policy.feed(
        records.make(
            pid,
            "connect",
            transition={
                "operation": "connect",
                "fd": {"fd": fd},
                "address": {
                    "family": "AF_INET",
                    "ip": "127.0.0.1",
                    "port": META_PORTS[1],
                },
            },
        )
    )
    assert decision.status == "PASS"
    return pid


@pytest.mark.parametrize("syscall", ["write", "writev", "sendfile", "splice"])
def test_connected_udp_alias_after_end_is_safety_failure(syscall):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, 0, fd=7)
    assert (
        policy.feed(
            records.make(
                pid,
                "connect",
                transition={
                    "operation": "connect",
                    "fd": {"fd": fd},
                    "address": {
                        "family": "AF_INET",
                        "ip": "127.0.0.1",
                        "port": META_PORTS[1],
                    },
                },
            )
        ).status
        == "PASS"
    )
    assert (
        policy.feed(
            records.make(
                pid,
                "dup",
                result=11,
                transition={
                    "operation": "dup",
                    "source_fd": {"fd": fd},
                    "created_fd": {"fd": 11},
                },
            )
        ).status
        == "PASS"
    )
    assert policy.feed(records.marker("END")).status == "PASS"
    decision = policy.feed(records.io(pid, syscall, 11))
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_fd_tables_copy_for_fork_share_for_clone_and_track_close():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    assert decision.status == "PASS"
    policy.feed(
        records.make(
            pid,
            "fork",
            result=200,
            transition={"operation": "fork", "child_pid": 200, "fd_table": "copied"},
        )
    )
    policy.feed(
        records.make(
            pid,
            "clone",
            result=201,
            transition={"operation": "clone", "child_pid": 201, "fd_table": "shared"},
        )
    )
    assert policy.provenance.describe(pid, 7)["domain"] == "AF_INET"
    assert policy.provenance.describe(200, 7)["local"] == (
        "127.0.0.1",
        META_PORTS[0],
    )
    policy.feed(
        records.make(
            201,
            "close",
            transition={"operation": "close", "closed_fd": {"fd": 7}},
        )
    )
    assert policy.provenance.describe(pid, 7) is None
    assert policy.provenance.describe(200, 7) is not None


@pytest.mark.parametrize("local_address", ["0.0.0.0", "127.0.0.1"])
@pytest.mark.parametrize(
    "participant,local_port",
    [
        *((index, 26650) for index in range(4)),
        *((index, 26651) for index in range(4)),
        *((index, port) for index, port in META_PORTS.items()),
        *((index, port) for index, port in DATA_PORTS.items()),
    ],
)
def test_exact_dds_local_bind_matrix_passes(local_address, participant, local_port):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    _, decision = bound_udp(policy, records, participant, (local_address, local_port))
    assert decision.status == "PASS"


def test_runtime_contract_registers_one_dynamic_tx_endpoint_per_participant():
    policy = make_policy()
    records = Records()
    open_window(policy, records)

    pid, fd, port = registered_tx(policy, records, 0)
    assert policy.provenance.describe(pid, fd)["local"] == ("127.0.0.1", port)

    assert policy.feed(records.socket(pid, 18)).status == "PASS"
    second = policy.feed(records.bind(pid, 18, "127.0.0.1", 0))
    assert (second.status, second.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_runtime_contract_dynamic_tx_endpoints_are_globally_unique():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    registered_tx(policy, records, 0)

    pid, decision = bound_udp(policy, records, 1, ("127.0.0.1", 0), fd=18)
    assert decision.status == "PASS"
    for option, value, length in TX_SETUP_OPTIONS:
        assert (
            policy.feed(records.tx_socket_option(pid, 18, option, value, length)).status
            == "PASS"
        )
    duplicate = policy.feed(
        records.getsockname(pid, 18, "127.0.0.1", EPHEMERAL_PORTS[0])
    )
    assert (duplicate.status, duplicate.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_runtime_contract_one_tx_fd_carries_spdp_sedp_and_user_data():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, 0)

    destinations = [("239.255.0.1", 26650)] + [
        ("127.0.0.1", port) for port in range(26660, 26668)
    ]
    for destination in destinations:
        assert (
            policy.feed(records.io(pid, "sendto", fd, address=destination)).status
            == "PASS"
        )


def test_runtime_contract_inbound_accepts_only_registered_dynamic_source():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    _, _, remote_port = registered_tx(policy, records, 1)
    pid, decision = bound_udp(policy, records, 0, ("0.0.0.0", META_PORTS[0]))
    assert decision.status == "PASS"

    assert (
        policy.feed(
            records.io(pid, "recvfrom", 7, address=("127.0.0.1", remote_port))
        ).status
        == "PASS"
    )
    unknown = policy.feed(records.io(pid, "recvfrom", 7, address=("127.0.0.1", 40999)))
    assert (unknown.status, unknown.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_runtime_contract_26651_is_receive_join_only():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("0.0.0.0", 26651))
    assert decision.status == "PASS"
    assert policy.feed(records.membership(pid, 7)).status == "PASS"

    outbound = policy.feed(
        records.io(pid, "sendto", 7, address=("127.0.0.1", META_PORTS[1]))
    )
    assert (outbound.status, outbound.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_runtime_contract_unregistered_ephemeral_tx_cannot_send():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", 0), fd=17)
    assert decision.status == "PASS"

    decision = policy.feed(
        records.io(pid, "sendto", 17, address=("239.255.0.1", 26650))
    )
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_runtime_contract_exact_tx_setup_sequence_registers_dynamic_endpoint():
    policy = make_policy()
    records = Records()
    open_window(policy, records)

    pid, fd, dynamic_port, decisions = observe_tx_registration(
        policy, records, 0, fd=17
    )

    assert [outcome(decision) for decision in decisions] == passing_registration()
    assert policy.provenance.describe(pid, fd)["local"] == (
        "127.0.0.1",
        dynamic_port,
    )


def _start_tx_registration(policy, records, *, fd=17):
    pid = PARTICIPANT_PIDS[0]
    socket_decision = policy.feed(records.socket(pid, fd))
    bind_decision = policy.feed(records.bind(pid, fd, "127.0.0.1", 0))
    return pid, socket_decision, bind_decision


def _feed_tx_options(policy, records, pid, options, *, fd=17, result=0):
    return [
        policy.feed(
            records.tx_socket_option(
                pid,
                fd,
                option,
                value,
                length,
                result=result,
            )
        )
        for option, value, length in options
    ]


@pytest.mark.parametrize(
    ("stage", "field"),
    [
        pytest.param(
            stage,
            field,
            id=f"stage{stage}-{TX_STAGE_NAMES[stage]}-{field}",
        )
        for stage in range(3)
        for field in (
            "level",
            "option",
            "interface" if stage == 0 else "value",
            "length",
        )
    ],
)
def test_runtime_contract_rejects_malformed_tx_option_at_exact_stage(stage, field):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    prefix_decisions = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS[:stage])
    option, value, length = TX_SETUP_OPTIONS[stage]
    level = "SOL_IP"
    if field == "level":
        level = "SOL_SOCKET"
    elif field == "option":
        option = "IP_TOS"
    elif field in {"interface", "value"}:
        value = TX_INVALID_VALUES[stage]
    else:
        length += 1

    rejected = policy.feed(
        records.tx_socket_option(
            pid,
            17,
            option,
            value,
            length,
            level=level,
        )
    )

    assert outcome(socket_decision) == ("PASS", "OK")
    assert [outcome(decision) for decision in prefix_decisions] == [
        ("PASS", "OK")
    ] * stage
    assert outcome(rejected) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize(
    ("stage", "violation"),
    [
        pytest.param(
            stage,
            violation,
            id=f"stage{stage}-{TX_STAGE_NAMES[stage]}-{violation}",
        )
        for stage in range(3)
        for violation in ("omission", "duplicate", "reorder")
    ],
)
def test_runtime_contract_rejects_sequence_violation_at_exact_stage(stage, violation):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    if violation == "duplicate":
        prefix = TX_SETUP_OPTIONS[: stage + 1]
        rejected_option = TX_SETUP_OPTIONS[stage]
    elif violation == "reorder":
        prefix = TX_SETUP_OPTIONS[:stage]
        reordered_stage = (2, 0, 0)[stage]
        rejected_option = TX_SETUP_OPTIONS[reordered_stage]
    else:
        prefix = TX_SETUP_OPTIONS[:stage]
        rejected_option = TX_SETUP_OPTIONS[stage + 1] if stage < 2 else None
    prefix_decisions = _feed_tx_options(policy, records, pid, prefix)
    if rejected_option is None:
        rejected = policy.feed(
            records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
        )
    else:
        rejected = policy.feed(records.tx_socket_option(pid, 17, *rejected_option))

    assert outcome(socket_decision) == ("PASS", "OK")
    assert [outcome(decision) for decision in prefix_decisions] == [
        ("PASS", "OK")
    ] * len(prefix)
    assert outcome(rejected) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize("use_alias", [False, True], ids=["other-fd", "dup-alias"])
def test_runtime_contract_tx_setup_requires_original_numeric_fd(use_alias):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, _, _ = _start_tx_registration(policy, records)
    other_fd = 18
    if use_alias:
        duplicate = policy.feed(
            records.make(
                pid,
                "dup",
                result=other_fd,
                transition={
                    "operation": "dup",
                    "source_fd": {"fd": 17},
                    "created_fd": {"fd": other_fd},
                },
            )
        )
        assert outcome(duplicate) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    else:
        assert policy.feed(records.socket(pid, other_fd)).status == "PASS"

    decision = policy.feed(
        records.tx_socket_option(pid, other_fd, *TX_SETUP_OPTIONS[0])
    )

    assert outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize("operation", ["getsockopt", "getpeername"])
def test_runtime_contract_rejects_unreviewed_control_or_endpoint_interposition(
    operation,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, _, _ = _start_tx_registration(policy, records)
    if operation == "getsockopt":
        transition = {
            "operation": "getsockopt",
            "fd": {"fd": 17},
            "level": "SOL_SOCKET",
            "option": "SO_ERROR",
            "length": 4,
        }
    else:
        transition = {
            "operation": "getpeername",
            "fd": {"fd": 17},
            "address": {
                "family": "AF_INET",
                "ip": "127.0.0.1",
                "port": META_PORTS[1],
            },
        }

    decision = policy.feed(records.make(pid, operation, transition=transition))

    assert outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize("syscall", ["sendto", "recvfrom", "connect", "write"])
def test_runtime_contract_pre_registration_io_poisons_tx_and_cannot_be_cured(
    syscall,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, _, _ = _start_tx_registration(policy, records)
    if syscall == "connect":
        attempted = records.make(
            pid,
            syscall,
            transition={
                "operation": "connect",
                "fd": {"fd": 17},
                "address": {
                    "family": "AF_INET",
                    "ip": "127.0.0.1",
                    "port": META_PORTS[1],
                },
            },
        )
    else:
        address = None
        if syscall == "sendto":
            address = ("239.255.0.1", 26650)
        elif syscall == "recvfrom":
            address = ("127.0.0.1", EPHEMERAL_PORTS[1])
        attempted = records.io(pid, syscall, 17, address=address)
    first_violation = policy.feed(attempted)
    option_decisions = [
        policy.feed(records.tx_socket_option(pid, 17, option, value, length))
        for option, value, length in TX_SETUP_OPTIONS
    ]
    posthoc = policy.feed(records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0]))

    assert outcome(first_violation) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert all(decision.status == "FAIL" for decision in option_decisions)
    assert outcome(posthoc) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert policy.finalize(trace_integrity_ok=True) == first_violation


@pytest.mark.parametrize(
    "stage",
    [
        pytest.param(stage, id=f"stage{stage}-{TX_STAGE_NAMES[stage]}")
        for stage in range(3)
    ],
)
def test_runtime_contract_failed_reviewed_option_is_neutral_but_cannot_advance(
    stage,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    prefix_decisions = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS[:stage])
    failed = policy.feed(
        records.tx_socket_option(
            pid,
            17,
            *TX_SETUP_OPTIONS[stage],
            result=-1,
        )
    )
    if stage < 2:
        advanced = policy.feed(
            records.tx_socket_option(pid, 17, *TX_SETUP_OPTIONS[stage + 1])
        )
    else:
        advanced = policy.feed(
            records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
        )

    assert outcome(socket_decision) == ("PASS", "OK")
    assert [outcome(decision) for decision in prefix_decisions] == [
        ("PASS", "OK")
    ] * stage
    assert outcome(failed) == ("PASS", "OK")
    assert outcome(advanced) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize(
    "stage",
    [
        pytest.param(stage, id=f"stage{stage}-{TX_STAGE_NAMES[stage]}")
        for stage in range(3)
    ],
)
def test_runtime_contract_failed_reviewed_option_retry_can_register(stage):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    prefix_decisions = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS[:stage])
    failed = policy.feed(
        records.tx_socket_option(
            pid,
            17,
            *TX_SETUP_OPTIONS[stage],
            result=-1,
        )
    )
    retry_and_suffix = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS[stage:])
    observed = policy.feed(
        records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
    )
    sent = policy.feed(records.io(pid, "sendto", 17, address=("239.255.0.1", 26650)))

    assert outcome(socket_decision) == ("PASS", "OK")
    assert [outcome(decision) for decision in prefix_decisions] == [
        ("PASS", "OK")
    ] * stage
    assert outcome(failed) == ("PASS", "OK")
    assert [outcome(decision) for decision in retry_and_suffix] == [("PASS", "OK")] * (
        3 - stage
    )
    assert outcome(observed) == ("PASS", "OK")
    assert outcome(sent) == ("PASS", "OK")


def test_runtime_contract_failed_future_reviewed_option_is_neutral_and_no_advance():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    failed_future = policy.feed(
        records.tx_socket_option(
            pid,
            17,
            *TX_SETUP_OPTIONS[1],
            result=-1,
        )
    )
    successful = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS)
    observed = policy.feed(
        records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
    )
    sent = policy.feed(records.io(pid, "sendto", 17, address=("239.255.0.1", 26650)))

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(failed_future) == ("PASS", "OK")
    assert [outcome(decision) for decision in successful] == [("PASS", "OK")] * 3
    assert outcome(observed) == ("PASS", "OK")
    assert outcome(sent) == ("PASS", "OK")


@pytest.mark.parametrize(
    "operation",
    ["unreviewed-option", "endpoint", "socket-io"],
)
def test_runtime_contract_failed_unreviewed_operation_remains_violation(operation):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, _ = _start_tx_registration(policy, records)
    if operation == "unreviewed-option":
        record = records.tx_socket_option(
            pid,
            17,
            "IP_TOS",
            0,
            4,
            result=-1,
        )
    elif operation == "endpoint":
        record = records.make(
            pid,
            "getpeername",
            result=-1,
            transition={
                "operation": "getpeername",
                "fd": {"fd": 17},
                "address": {
                    "family": "AF_INET",
                    "ip": "127.0.0.1",
                    "port": META_PORTS[1],
                },
            },
        )
    else:
        record = records.io(
            pid,
            "sendto",
            17,
            address=("239.255.0.1", 26650),
            result=-1,
        )

    rejected = policy.feed(record)

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(rejected) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_runtime_contract_golden_replays_as_one_authorized_dds_window():
    source = (FIXTURES / "cyclonedds-0.10.5-runtime-representative.input").read_bytes()
    policy = make_policy()

    failures = [
        (record["record_index"], record.get("syscall"), decision)
        for record in normalize_bytes(source)
        if (decision := policy.feed(record)).status != "PASS"
    ]

    assert failures == []
    for pid, fds in ((100, (7, 8, 9, 10, 11)), (101, (21,))):
        assert all(policy.provenance.describe(pid, fd) is None for fd in fds)
    assert policy.finalize(trace_integrity_ok=True).status == "PASS"


@pytest.mark.parametrize(
    "lifecycle",
    ["open-socket", "root-live", "worker-live"],
)
def test_runtime_contract_cannot_finalize_with_live_participant_or_socket(lifecycle):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, bind_decision = bound_udp(policy, records, 0, ("0.0.0.0", META_PORTS[0]))
    assert bind_decision.status == "PASS"
    if lifecycle == "root-live":
        assert policy.feed(records.close(pid, 7)).status == "PASS"
    elif lifecycle == "worker-live":
        assert clone_worker(policy, records, pid, 1100).status == "PASS"
        assert policy.feed(records.close(pid, 7)).status == "PASS"
        assert policy.feed(records.exit(pid)).status == "PASS"
    else:
        assert policy.feed(records.exit(pid)).status == "PASS"
    assert policy.feed(records.marker("END")).status == "PASS"

    assert policy.finalize(trace_integrity_ok=True).status != "PASS"


def test_runtime_contract_complete_trace_visible_lifecycle_can_finalize():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, bind_decision = bound_udp(policy, records, 0, ("0.0.0.0", META_PORTS[0]))
    assert bind_decision.status == "PASS"
    assert clone_worker(policy, records, pid, 1100).status == "PASS"
    assert policy.feed(records.exit(1100)).status == "PASS"
    assert policy.feed(records.close(pid, 7)).status == "PASS"
    assert policy.feed(records.exit(pid)).status == "PASS"
    assert policy.feed(records.marker("END")).status == "PASS"

    assert policy.provenance.describe(pid, 7) is None
    assert policy.finalize(trace_integrity_ok=True).status == "PASS"


@pytest.mark.parametrize(
    "order",
    [
        ("close", "worker-exit", "root-exit", "end"),
        ("worker-exit", "root-exit", "close", "end"),
        ("end", "worker-exit", "close", "root-exit"),
    ],
    ids=["close-before-worker-exit", "root-exit-before-close", "end-before-cleanup"],
)
def test_runtime_contract_rejects_out_of_order_cleanup_before_end(order):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, bind_decision = bound_udp(policy, records, 0, ("0.0.0.0", META_PORTS[0]))
    assert bind_decision.status == "PASS"
    assert clone_worker(policy, records, pid, 1100).status == "PASS"
    actions = {
        "worker-exit": lambda: records.exit(1100),
        "close": lambda: records.close(pid, 7),
        "root-exit": lambda: records.exit(pid),
        "end": lambda: records.marker("END"),
    }

    decisions = [policy.feed(actions[action]()) for action in order]

    assert any(decision.status != "PASS" for decision in decisions) or (
        policy.finalize(trace_integrity_ok=True).status != "PASS"
    )


def test_runtime_contract_truncated_golden_cannot_finalize_as_pass():
    source = (FIXTURES / "cyclonedds-0.10.5-runtime-representative.input").read_bytes()
    records = normalize_bytes(source)
    policy = make_policy()

    for record in records[:-1]:
        policy.feed(record)

    assert policy.finalize(trace_integrity_ok=True).status != "PASS"


def test_runtime_contract_receive_fds_are_never_sendto_sources():
    observed = {}
    for receive_class, local_port, destination in RECEIVE_FD_CASES:
        policy = make_policy()
        records = Records()
        open_window(policy, records)
        pid, bind_decision = bound_udp(
            policy,
            records,
            0,
            ("0.0.0.0", local_port),
        )
        send_decision = policy.feed(records.io(pid, "sendto", 7, address=destination))
        observed[receive_class] = outcome(bind_decision), outcome(send_decision)

    assert observed == {
        receive_class: (
            ("PASS", "OK"),
            ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
        )
        for receive_class, _, _ in RECEIVE_FD_CASES
    }


def test_runtime_contract_receive_fds_are_never_connected_write_sources():
    observed = {}
    for receive_class, local_port, destination in RECEIVE_FD_CASES:
        policy = make_policy()
        records = Records()
        open_window(policy, records)
        pid, bind_decision = bound_udp(
            policy,
            records,
            0,
            ("0.0.0.0", local_port),
        )
        connect_decision = policy.feed(
            records.make(
                pid,
                "connect",
                transition={
                    "operation": "connect",
                    "fd": {"fd": 7},
                    "address": {
                        "family": "AF_INET",
                        "ip": destination[0],
                        "port": destination[1],
                    },
                },
            )
        )
        write_decision = policy.feed(records.io(pid, "write", 7))
        observed[receive_class] = (
            outcome(bind_decision),
            outcome(connect_decision),
            outcome(write_decision),
        )

    assert observed == {
        receive_class: (
            ("PASS", "OK"),
            ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
            ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
        )
        for receive_class, _, _ in RECEIVE_FD_CASES
    }


@pytest.mark.parametrize(
    ("source_kind", "expected_receive"),
    [
        pytest.param("registered", ("PASS", "OK"), id="registered"),
        pytest.param(
            "unknown",
            ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
            id="unknown",
        ),
    ],
)
@pytest.mark.parametrize(
    ("receive_class", "local_port"),
    [(receive_class, local_port) for receive_class, local_port, _ in RECEIVE_FD_CASES],
)
def test_runtime_contract_inbound_source_registry_covers_every_receive_fd_class(
    receive_class,
    local_port,
    source_kind,
    expected_receive,
):
    del receive_class
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    _, _, registered_source, registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    pid, bind_decision = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", local_port),
    )
    membership_decision = None
    if local_port in {26650, 26651}:
        membership_decision = policy.feed(records.membership(pid, 7))
    source_port = registered_source if source_kind == "registered" else 40999
    receive_decision = policy.feed(
        records.io(pid, "recvfrom", 7, address=("127.0.0.1", source_port))
    )

    assert outcome(receive_decision) == expected_receive
    assert [outcome(decision) for decision in registration] == passing_registration()
    assert outcome(bind_decision) == ("PASS", "OK")
    if membership_decision is not None:
        assert outcome(membership_decision) == ("PASS", "OK")


@pytest.mark.parametrize(
    ("syscall", "fd_table", "flags"),
    [
        pytest.param("fork", "copied", None, id="fork"),
        pytest.param("vfork", "copied", None, id="vfork"),
        pytest.param(
            "clone",
            "shared",
            ["CLONE_VM", "CLONE_FILES", "SIGCHLD"],
            id="clone_without_thread",
        ),
        pytest.param(
            "clone",
            "copied",
            ["CLONE_VM", "CLONE_SIGHAND", "CLONE_THREAD"],
            id="clone_without_files",
        ),
    ],
)
def test_runtime_contract_nonthread_descendants_cannot_perform_dds_io(
    syscall,
    fd_table,
    flags,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, tx_fd, _, local_registration = observe_tx_registration(
        policy,
        records,
        0,
        fd=17,
    )
    _, _, remote_source, remote_registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    _, receive_bind = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
        fd=7,
    )
    transition = {
        "operation": syscall,
        "child_pid": 200,
        "fd_table": fd_table,
    }
    if flags is not None:
        transition["flags"] = flags
    lifecycle = policy.feed(
        records.make(pid, syscall, result=200, transition=transition)
    )
    outbound = policy.feed(
        records.io(
            200,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    inbound = policy.feed(
        records.io(
            200,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )

    assert [outcome(decision) for decision in local_registration] == (
        passing_registration()
    )
    assert [outcome(decision) for decision in remote_registration] == (
        passing_registration()
    )
    assert outcome(receive_bind) == ("PASS", "OK")
    assert outcome(lifecycle) == ("PASS", "OK")
    assert outcome(outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(inbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize(
    ("syscall", "fd_table", "flags"),
    [
        pytest.param("fork", "copied", None, id="fork"),
        pytest.param("vfork", "copied", None, id="vfork"),
        pytest.param(
            "clone",
            "shared",
            ["CLONE_VM", "CLONE_FILES", "SIGCHLD"],
            id="clone_without_thread",
        ),
        pytest.param(
            "clone",
            "copied",
            ["CLONE_VM", "CLONE_SIGHAND", "CLONE_THREAD"],
            id="clone_without_files",
        ),
    ],
)
def test_runtime_contract_nonthread_descendant_thread_cannot_regain_authority(
    syscall,
    fd_table,
    flags,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, tx_fd, _, local_registration = observe_tx_registration(
        policy,
        records,
        0,
        fd=17,
    )
    _, _, remote_source, remote_registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    _, receive_bind = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
        fd=7,
    )
    descendant_transition = {
        "operation": syscall,
        "child_pid": 200,
        "fd_table": fd_table,
    }
    if flags is not None:
        descendant_transition["flags"] = flags
    descendant = policy.feed(
        records.make(pid, syscall, result=200, transition=descendant_transition)
    )
    thread = policy.feed(
        records.make(
            200,
            "clone",
            result=201,
            transition={
                "operation": "clone",
                "child_pid": 201,
                "fd_table": "shared",
                "flags": [
                    "CLONE_VM",
                    "CLONE_FILES",
                    "CLONE_SIGHAND",
                    "CLONE_THREAD",
                ],
            },
        )
    )
    outbound = policy.feed(
        records.io(
            201,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    inbound = policy.feed(
        records.io(
            201,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )

    assert [outcome(decision) for decision in local_registration] == (
        passing_registration()
    )
    assert [outcome(decision) for decision in remote_registration] == (
        passing_registration()
    )
    assert outcome(receive_bind) == ("PASS", "OK")
    assert outcome(descendant) == ("PASS", "OK")
    assert outcome(thread) == ("PASS", "OK")
    assert outcome(outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(inbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_runtime_contract_authority_propagates_across_transitive_worker_threads():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _, local_registration = observe_tx_registration(
        policy,
        records,
        0,
        fd=17,
    )
    _, _, remote_source, remote_registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    _, receive_bind = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
        fd=7,
    )
    worker_a = 200
    worker_b = 201
    edge_a = clone_worker(policy, records, root_pid, worker_a)
    edge_b = clone_worker(policy, records, worker_a, worker_b)
    outbound = policy.feed(
        records.io(
            worker_b,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    inbound = policy.feed(
        records.io(
            worker_b,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )

    assert outcome(edge_a) == ("PASS", "OK")
    assert outcome(edge_b) == ("PASS", "OK")
    assert outcome(outbound) == ("PASS", "OK")
    assert outcome(inbound) == ("PASS", "OK")
    assert [outcome(decision) for decision in local_registration] == (
        passing_registration()
    )
    assert [outcome(decision) for decision in remote_registration] == (
        passing_registration()
    )
    assert outcome(receive_bind) == ("PASS", "OK")


def test_runtime_contract_exited_worker_tid_has_no_stale_or_transitive_authority():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _, local_registration = observe_tx_registration(
        policy,
        records,
        0,
        fd=17,
    )
    _, _, remote_source, remote_registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    _, receive_bind = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
        fd=7,
    )
    worker_tid = 200
    initial_edge = clone_worker(policy, records, root_pid, worker_tid)
    initial_outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    initial_inbound = policy.feed(
        records.io(
            worker_tid,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )
    worker_exit = policy.feed(records.exit(worker_tid))
    stale_outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    stale_inbound = policy.feed(
        records.io(
            worker_tid,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )
    nonthread_pid = 300
    nonthread_edge = policy.feed(
        records.make(
            root_pid,
            "fork",
            result=nonthread_pid,
            transition={
                "operation": "fork",
                "child_pid": nonthread_pid,
                "fd_table": "copied",
            },
        )
    )
    invalid_reuse_edge = clone_worker(policy, records, nonthread_pid, worker_tid)
    reused_outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    reused_inbound = policy.feed(
        records.io(
            worker_tid,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )
    final = policy.finalize(trace_integrity_ok=True)

    assert outcome(worker_exit) == ("PASS", "OK")
    assert outcome(stale_outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(stale_inbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(nonthread_edge) == ("PASS", "OK")
    assert outcome(invalid_reuse_edge) == ("PASS", "OK")
    assert outcome(reused_outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(reused_inbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(initial_edge) == ("PASS", "OK")
    assert outcome(initial_outbound) == ("PASS", "OK")
    assert outcome(initial_inbound) == ("PASS", "OK")
    assert [outcome(decision) for decision in local_registration] == (
        passing_registration()
    )
    assert [outcome(decision) for decision in remote_registration] == (
        passing_registration()
    )
    assert outcome(receive_bind) == ("PASS", "OK")
    assert final == stale_outbound


def test_runtime_contract_fresh_root_edge_reauthorizes_reused_worker_tid():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _, local_registration = observe_tx_registration(
        policy,
        records,
        0,
        fd=17,
    )
    _, _, remote_source, remote_registration = observe_tx_registration(
        policy,
        records,
        1,
        fd=18,
    )
    _, receive_bind = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
        fd=7,
    )
    worker_tid = 200
    first_edge = clone_worker(policy, records, root_pid, worker_tid)
    first_outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    worker_exit = policy.feed(records.exit(worker_tid))
    fresh_edge = clone_worker(policy, records, root_pid, worker_tid)
    fresh_outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("127.0.0.1", META_PORTS[1]),
        )
    )
    fresh_inbound = policy.feed(
        records.io(
            worker_tid,
            "recvfrom",
            7,
            address=("127.0.0.1", remote_source),
        )
    )

    assert outcome(first_edge) == ("PASS", "OK")
    assert outcome(first_outbound) == ("PASS", "OK")
    assert outcome(worker_exit) == ("PASS", "OK")
    assert outcome(fresh_edge) == ("PASS", "OK")
    assert outcome(fresh_outbound) == ("PASS", "OK")
    assert outcome(fresh_inbound) == ("PASS", "OK")
    assert [outcome(decision) for decision in local_registration] == (
        passing_registration()
    )
    assert [outcome(decision) for decision in remote_registration] == (
        passing_registration()
    )
    assert outcome(receive_bind) == ("PASS", "OK")


def test_runtime_contract_conflicting_getsockname_preserves_ei_and_poisons_tx():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, original_port, registration = observe_tx_registration(
        policy,
        records,
        0,
    )
    conflict = policy.feed(
        records.getsockname(pid, fd, "127.0.0.1", original_port + 100)
    )
    description = policy.provenance.describe(pid, fd)
    outbound = policy.feed(
        records.io(pid, "sendto", fd, address=("239.255.0.1", 26650))
    )
    final = policy.finalize(trace_integrity_ok=True)

    assert [outcome(decision) for decision in registration] == passing_registration()
    assert outcome(conflict) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert description["local"] == ("127.0.0.1", original_port)
    assert outcome(outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert final == conflict


def test_runtime_contract_same_getsockname_via_dup_preserves_tx_provenance():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, dynamic_port, registration = observe_tx_registration(
        policy,
        records,
        0,
    )
    alias_fd = 18
    duplicate = policy.feed(
        records.make(
            pid,
            "dup",
            result=alias_fd,
            transition={
                "operation": "dup",
                "source_fd": {"fd": fd},
                "created_fd": {"fd": alias_fd},
            },
        )
    )
    repeated_original = policy.feed(
        records.getsockname(pid, fd, "127.0.0.1", dynamic_port)
    )
    repeated_alias = policy.feed(
        records.getsockname(pid, alias_fd, "127.0.0.1", dynamic_port)
    )
    original_description = policy.provenance.describe(pid, fd)
    alias_description = policy.provenance.describe(pid, alias_fd)
    outbound = policy.feed(
        records.io(pid, "sendto", fd, address=("239.255.0.1", 26650))
    )

    assert [outcome(decision) for decision in registration] == passing_registration()
    assert outcome(duplicate) == ("PASS", "OK")
    assert outcome(repeated_original) == ("PASS", "OK")
    assert outcome(repeated_alias) == ("PASS", "OK")
    assert {
        key: value for key, value in original_description.items() if key != "cloexec"
    } == {key: value for key, value in alias_description.items() if key != "cloexec"}
    assert original_description["cloexec"] is True
    assert alias_description["cloexec"] is False
    assert original_description["local"] == ("127.0.0.1", dynamic_port)
    assert original_description["local_conflict"] is False
    assert outcome(outbound) == ("PASS", "OK")


@pytest.mark.parametrize("syscall", ["sendto", "recvfrom"])
def test_runtime_contract_posthoc_getsockname_cannot_cure_prior_io(syscall):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    remote_registration = ()
    remote_source = EPHEMERAL_PORTS[1]
    if syscall == "recvfrom":
        _, _, remote_source, remote_registration = observe_tx_registration(
            policy,
            records,
            1,
            fd=18,
        )
    pid = PARTICIPANT_PIDS[0]
    fd = 17
    socket_decision = policy.feed(records.socket(pid, fd))
    bind_decision = policy.feed(records.bind(pid, fd, "127.0.0.1", 0))
    address = (
        ("239.255.0.1", 26650) if syscall == "sendto" else ("127.0.0.1", remote_source)
    )
    unauthorized = policy.feed(records.io(pid, syscall, fd, address=address))
    posthoc = policy.feed(records.getsockname(pid, fd, "127.0.0.1", EPHEMERAL_PORTS[0]))
    later_io = policy.feed(records.io(pid, syscall, fd, address=address))
    final = policy.finalize(trace_integrity_ok=True)

    if remote_registration:
        assert [outcome(decision) for decision in remote_registration] == (
            passing_registration()
        )
    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(bind_decision) == ("PASS", "OK")
    assert outcome(unauthorized) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(posthoc) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(later_io) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert final == unauthorized


@pytest.mark.parametrize(
    "local_address,participant,local_port",
    [
        ("192.0.2.10", 0, 26650),
        ("::1", 0, 26650),
        ("239.255.0.1", 0, 26650),
        ("127.0.0.1", 0, META_PORTS[1]),
        ("0.0.0.0", 0, 0),
    ],
)
def test_invalid_dds_bind_interface_or_port_is_rejected(
    local_address, participant, local_port
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    _, decision = bound_udp(policy, records, participant, (local_address, local_port))
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


@pytest.mark.parametrize("participant", range(4))
def test_outbound_spdp_matrix_passes(participant):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, participant)
    decision = policy.feed(
        records.io(pid, "sendto", fd, address=("239.255.0.1", 26650))
    )
    assert decision.status == "PASS"


@pytest.mark.parametrize(
    "channel,local_ports,remote_index",
    [
        (channel, ports, remote)
        for channel, ports in (("meta", META_PORTS), ("data", DATA_PORTS))
        for remote in range(4)
    ],
)
@pytest.mark.parametrize("participant", range(4))
def test_outbound_unicast_matrix_passes(
    channel, local_ports, remote_index, participant
):
    del channel
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, participant)
    decision = policy.feed(
        records.io(
            pid,
            "sendto",
            fd,
            address=("127.0.0.1", local_ports[remote_index]),
        )
    )
    assert decision.status == "PASS"


@pytest.mark.parametrize("remote_index", range(4))
@pytest.mark.parametrize("participant", range(4))
def test_inbound_spdp_and_unicast_sources_pass(participant, remote_index):
    for local_port in (
        26650,
        META_PORTS[participant],
        DATA_PORTS[participant],
    ):
        policy = make_policy()
        records = Records()
        open_window(policy, records)
        _, _, remote_port = registered_tx(
            policy, records, remote_index, fd=17 + remote_index
        )
        pid, decision = bound_udp(policy, records, participant, ("0.0.0.0", local_port))
        assert decision.status == "PASS"
        assert (
            policy.feed(
                records.io(
                    pid,
                    "recvfrom",
                    7,
                    address=("127.0.0.1", remote_port),
                )
            ).status
            == "PASS"
        )


@pytest.mark.parametrize(
    "remote",
    [
        ("239.255.0.2", 26650),
        ("239.255.0.1", 26651),
        ("127.0.0.1", 26650),
        ("127.0.0.1", 26651),
        ("127.0.0.1", 26668),
        ("192.0.2.10", META_PORTS[1]),
    ],
)
def test_nonmatrix_dds_destination_is_rejected(remote):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, 0)
    decision = policy.feed(records.io(pid, "sendto", fd, address=remote))
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_ephemeral_tx_requires_loopback_bind_and_nonzero_getsockname():
    for bind_address, observed_address, observed_port in (
        ("0.0.0.0", "127.0.0.1", EPHEMERAL_PORTS[0]),
        ("127.0.0.1", "0.0.0.0", EPHEMERAL_PORTS[0]),
        ("127.0.0.1", "127.0.0.1", 0),
    ):
        policy = make_policy()
        records = Records()
        open_window(policy, records)
        pid, decision = bound_udp(policy, records, 0, (bind_address, 0), fd=17)
        if decision.status == "PASS":
            for option, value, length in TX_SETUP_OPTIONS:
                assert (
                    policy.feed(
                        records.tx_socket_option(pid, 17, option, value, length)
                    ).status
                    == "PASS"
                )
            decision = policy.feed(
                records.getsockname(pid, 17, observed_address, observed_port)
            )
        assert (decision.status, decision.reason) == (
            "FAIL",
            "UNEXPECTED_NETWORK_ATTEMPT",
        )


def test_ordinary_dds_message_passes_but_scm_rights_is_journaled():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, fd, _ = registered_tx(policy, records, 0)
    assert (
        policy.feed(
            records.io(
                pid,
                "sendmsg",
                fd,
                address=("239.255.0.1", 26650),
                control={},
            )
        ).status
        == "PASS"
    )
    transfer = policy.feed(
        records.io(
            pid,
            "sendmsg",
            fd,
            control={"scm_rights": [[{"fd": 12}]]},
        )
    )
    assert (transfer.status, transfer.reason) == ("FAIL", "PROHIBITED_FD_TRANSFER")
    assert policy.journal.first_violation.reason == "PROHIBITED_FD_TRANSFER"


def test_bad_marker_is_trace_integrity_not_a_network_violation():
    policy = make_policy()
    records = Records()
    bad_marker = policy.feed(records.marker("BEGIN", pid=91))
    assert (bad_marker.status, bad_marker.reason) == ("PASS", "OK")
    assert policy.trace_integrity_error == "INVALID_MARKER"
    assert policy.journal.violation_count == 0
    assert policy.finalize(trace_integrity_ok=False).status == "SKIPPED"


def test_pidfd_acquisition_is_a_network_policy_violation():

    policy = make_policy()
    records = Records()
    open_window(policy, records)
    decision = policy.feed(
        records.make(
            PARTICIPANT_PIDS[0],
            "pidfd_getfd",
            result=12,
            transition={
                "operation": "pidfd_getfd",
                "pidfd": {"fd": 9},
                "target_fd": 7,
                "created_fd": {"fd": 12},
            },
        )
    )
    assert (decision.status, decision.reason) == (
        "FAIL",
        "PROHIBITED_FD_ACQUISITION",
    )


def test_first_policy_violation_survives_later_trace_integrity_failure():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, _ = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    violation = policy.feed(records.io(pid, "sendto", 7, address=("203.0.113.10", 443)))
    decision = policy.finalize(trace_integrity_ok=False)
    assert decision == violation
    assert decision.reason == "UNEXPECTED_NETWORK_ATTEMPT"


def test_clean_finalize_passes_or_skips_when_trace_is_unavailable():
    assert make_policy().finalize(trace_integrity_ok=True).status == "PASS"
    decision = make_policy().finalize(trace_integrity_ok=False)
    assert (decision.status, decision.reason) == (
        "SKIPPED",
        "DEPENDENCY_NOT_AVAILABLE",
    )


def test_participant_pid_and_pinned_config_digest_are_exact():
    for mutate in ("pid", "digest"):
        policy = make_policy()
        records = Records()
        if mutate == "digest":
            bad_digests = dict(CONFIG_DIGESTS)
            bad_digests[0] = "f" * 64
            policy = make_policy(participant_digests=bad_digests)
            records = Records()
        open_window(policy, records)
        pid = 999 if mutate == "pid" else PARTICIPANT_PIDS[0]
        decision = policy.feed(records.socket(pid, 7))
        assert decision.status == "FAIL"


@pytest.mark.parametrize(
    "marker",
    [
        {"phase": "BEGIN", "token": "ffffffffffff"},
        {"phase": "END", "token": TOKEN},
    ],
)
def test_invalid_marker_sequence_only_poison_trace_integrity(marker):
    policy = make_policy()
    records = Records()
    decision = policy.feed(records.make(COORDINATOR_PID, "prctl", marker=marker))
    assert (decision.status, decision.reason) == ("PASS", "OK")
    assert policy.trace_integrity_error == "INVALID_MARKER"
    assert policy.journal.violation_count == 0


@pytest.mark.parametrize(
    "domain,protocol",
    [
        ("AF_INET", "IPPROTO_TCP"),
        ("AF_INET6", "IPPROTO_UDP"),
    ],
)
def test_tcp_and_ipv6_are_rejected_even_inside_the_window(domain, protocol):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    decision = policy.feed(
        records.socket(PARTICIPANT_PIDS[0], 7, domain=domain, protocol=protocol)
    )
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


@pytest.mark.parametrize(
    "domain,protocol",
    [
        ("AF_UNIX", 0),
        ("AF_NETLINK", "NETLINK_ROUTE"),
    ],
)
def test_non_ip_observer_sockets_are_neutral(domain, protocol):
    policy = make_policy()
    records = Records()
    decision = policy.feed(
        records.socket(COORDINATOR_PID, 7, domain=domain, protocol=protocol)
    )
    assert decision.status == "PASS"


def test_netlink_observer_bind_and_message_operations_are_neutral():
    policy = make_policy()
    records = Records()
    assert (
        policy.feed(
            records.socket(
                COORDINATOR_PID,
                7,
                domain="AF_NETLINK",
                protocol="NETLINK_ROUTE",
            )
        ).status
        == "PASS"
    )
    address = {"family": "AF_NETLINK", "pid": COORDINATOR_PID, "groups": 0}
    for operation in ("bind", "getsockname"):
        decision = policy.feed(
            records.make(
                COORDINATOR_PID,
                operation,
                transition={
                    "operation": operation,
                    "fd": {"fd": 7},
                    "address": address,
                },
            )
        )
        assert decision.status == "PASS"
    for syscall in ("sendmsg", "recvmsg"):
        decision = policy.feed(
            records.make(
                COORDINATOR_PID,
                syscall,
                result=1,
                fds=[{"fd": 7}],
                lengths={"iov_count": 1},
                flags=[],
            )
        )
        assert decision.status == "PASS"


def test_missing_or_nonmonotonic_marker_indices_fail_closed():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    unindexed = records.socket(PARTICIPANT_PIDS[0], 7)
    unindexed.pop("entry_index")
    unindexed.pop("exit_index")
    assert policy.feed(unindexed).reason == "UNEXPECTED_NETWORK_ATTEMPT"

    policy = make_policy()
    records = Records()
    open_window(policy, records)
    invalid_end = records.marker("END")
    invalid_end["entry_index"] = 0
    assert policy.feed(invalid_end).status == "PASS"
    assert policy.trace_integrity_error == "INVALID_MARKER"
    assert policy.journal.violation_count == 0


def test_exec_unshares_clone_files_table_before_closing_cloexec_entries():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    parent = PARTICIPANT_PIDS[0]
    assert policy.feed(records.socket(parent, 7)).status == "PASS"
    assert (
        policy.feed(
            records.make(
                parent,
                "clone",
                result=200,
                transition={
                    "operation": "clone",
                    "child_pid": 200,
                    "fd_table": "shared",
                    "flags": ["CLONE_VM", "CLONE_FILES", "SIGCHLD"],
                },
            )
        ).status
        == "PASS"
    )
    policy.feed(
        records.make(
            200,
            "execve",
            transition={"operation": "exec", "cloexec_fds": "closed"},
        )
    )
    assert policy.provenance.describe(200, 7) is None
    assert policy.provenance.describe(parent, 7) is not None


@pytest.mark.parametrize(
    "group,interface,expected",
    [
        ("239.255.0.1", "127.0.0.1", "PASS"),
        ("224.0.0.1", "127.0.0.1", "FAIL"),
        ("239.255.0.1", "0.0.0.0", "FAIL"),
        ("239.255.0.1", "192.0.2.10", "FAIL"),
    ],
)
@pytest.mark.parametrize("local_port", [26650, 26651])
@pytest.mark.parametrize("option", ["IP_ADD_MEMBERSHIP", "IP_DROP_MEMBERSHIP"])
def test_multicast_membership_option_is_value_bound(
    option, local_port, group, interface, expected
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("0.0.0.0", local_port))
    assert decision.status == "PASS"
    decision = policy.feed(
        records.make(
            pid,
            "setsockopt",
            transition={
                "operation": "setsockopt",
                "fd": {"fd": 7},
                "level": "SOL_IP",
                "option": option,
                "length": 8,
                "membership": {"group": group, "interface": interface},
            },
        )
    )
    assert decision.status == expected


@pytest.mark.parametrize("local_port", [26650, 26651])
@pytest.mark.parametrize("option", ["IP_ADD_MEMBERSHIP", "IP_DROP_MEMBERSHIP"])
def test_normalizer_retains_only_structural_multicast_membership_values(
    option, local_port
):
    source = _trace_line(
        f"setsockopt(7<UDP:[127.0.0.1:{local_port}]>, SOL_IP, {option}, "
        '{imr_multiaddr=inet_addr("239.255.0.1"), '
        'imr_interface=inet_addr("127.0.0.1")}, 8)'
    )
    (record,) = normalize_bytes(source)
    assert record["transition"] == {
        "operation": "setsockopt",
        "fd": {
            "fd": 7,
            "provenance": {"kind": "socket", "protocol": "UDP"},
        },
        "level": "SOL_IP",
        "option": option,
        "length": 8,
        "membership": {
            "group": "239.255.0.1",
            "interface": "127.0.0.1",
        },
    }


def test_reviewed_launcher_manifest_seeds_descriptor_tables_before_trace():
    policy = make_policy(
        initial_fd_manifest={
            COORDINATOR_PID: [
                {
                    "fd": 0,
                    "kind": "character_device",
                    "inode": 101,
                    "cloexec": False,
                },
                {"fd": 4, "kind": "pipe", "inode": 102, "cloexec": True},
            ]
        }
    )
    records = Records()

    assert policy.provenance.describe(COORDINATOR_PID, 0) == {
        "kind": "character_device",
        "domain": None,
        "socket_type": [],
        "protocol": None,
        "inode": 101,
        "local": None,
        "peer": None,
        "cloexec": False,
        "local_conflict": False,
        "peer_conflict": False,
        "message_peers": (),
    }
    policy.feed(
        records.make(
            COORDINATOR_PID,
            "fork",
            result=PARTICIPANT_PIDS[0],
            transition={
                "operation": "fork",
                "child_pid": PARTICIPANT_PIDS[0],
                "fd_table": "copied",
            },
        )
    )
    policy.feed(
        records.make(
            PARTICIPANT_PIDS[0],
            "execve",
            transition={"operation": "exec", "cloexec_fds": "closed"},
        )
    )
    assert policy.provenance.describe(PARTICIPANT_PIDS[0], 4) is None
    assert policy.provenance.describe(COORDINATOR_PID, 4)["kind"] == "pipe"


@pytest.mark.parametrize(
    "manifest",
    [
        {COORDINATOR_PID: [{"fd": 1, "kind": "socket", "cloexec": False}]},
        {
            COORDINATOR_PID: [
                {"fd": 1, "kind": "pipe", "cloexec": False},
                {"fd": 1, "kind": "pipe", "cloexec": False},
            ]
        },
        {COORDINATOR_PID: [{"fd": 1, "kind": "pipe", "cloexec": False, "x": 1}]},
    ],
)
def test_reviewed_launcher_manifest_rejects_unsafe_or_ambiguous_entries(manifest):
    with pytest.raises(ValueError, match="initial FD manifest"):
        make_policy(initial_fd_manifest=manifest)


def test_meta_and_data_port_sets_are_closed_and_disjoint():
    assert set(META_PORTS.values()) | set(DATA_PORTS.values()) == set(
        range(26660, 26668)
    )
    assert not set(META_PORTS.values()) & set(DATA_PORTS.values())
    assert len(tuple(itertools.product(PARTICIPANT_PIDS, PARTICIPANT_PIDS))) == 16


def test_launcher_manifest_is_mandatory():
    arguments = _constructor_arguments(include_manifest=False)
    with pytest.raises((TypeError, ValueError), match="manifest"):
        TracePolicy(**arguments)


@pytest.mark.parametrize(
    "manifest",
    [
        {999: _launcher_manifest()[COORDINATOR_PID]},
        {
            **_launcher_manifest(),
            999: [{"fd": 8, "kind": "pipe", "inode": 108, "cloexec": True}],
        },
    ],
)
def test_launcher_manifest_is_bound_only_to_the_coordinator(manifest):
    arguments = _constructor_arguments()
    arguments["initial_fd_manifest"] = manifest
    with pytest.raises(ValueError, match="coordinator"):
        TracePolicy(**arguments)


def test_open_marker_without_end_cannot_finalize_as_pass():
    policy = make_policy()
    records = Records()
    open_window(policy, records)

    decision = policy.finalize(trace_integrity_ok=True)

    assert (decision.status, decision.reason) == (
        "SKIPPED",
        "DEPENDENCY_NOT_AVAILABLE",
    )
    assert policy.trace_integrity_error is not None


def test_matching_begin_and_end_can_finalize_as_pass():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    assert policy.feed(records.marker("END")).status == "PASS"

    assert policy.finalize(trace_integrity_ok=True).status == "PASS"


def test_unknown_raw_fd_fails_trace_integrity_without_inventing_network_evidence():
    policy = make_policy()
    records = Records()
    open_window(policy, records)

    decision = policy.feed(records.io(PARTICIPANT_PIDS[0], "write", 77))

    assert (decision.status, decision.reason) == ("PASS", "OK")
    assert policy.trace_integrity_error is not None
    assert policy.finalize(trace_integrity_ok=True).status == "SKIPPED"


def test_annotated_unknown_socket_fails_both_integrity_and_network_policy():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    record = records.io(PARTICIPANT_PIDS[0], "write", 77)
    record["fds"][0]["provenance"] = {"kind": "socket", "inode": 7077}

    decision = policy.feed(record)

    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )
    assert policy.trace_integrity_error is not None


@pytest.mark.parametrize(
    ("operation", "flags"),
    [("dup2", None), ("dup3", [])],
)
def test_dup_from_unknown_source_evicts_stale_target_and_fails_integrity(
    operation, flags
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid = connected_udp(policy, records)
    transition = {
        "operation": operation,
        "source_fd": {"fd": 99},
        "target_fd": {"fd": 7},
        "created_fd": {"fd": 7},
    }
    if flags is not None:
        transition["flags"] = flags

    policy.feed(records.make(pid, operation, result=7, transition=transition))

    assert policy.provenance.describe(pid, 7) is None
    assert policy.trace_integrity_error is not None


def test_runtime_contract_clone_thread_inherits_participant_role_and_fd_authority():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("0.0.0.0", 26650))
    assert decision.status == "PASS"
    thread_pid = 200
    assert (
        policy.feed(
            records.make(
                pid,
                "clone",
                result=thread_pid,
                transition={
                    "operation": "clone",
                    "child_pid": thread_pid,
                    "fd_table": "shared",
                    "flags": [
                        "CLONE_VM",
                        "CLONE_FILES",
                        "CLONE_SIGHAND",
                        "CLONE_THREAD",
                    ],
                },
            )
        ).status
        == "PASS"
    )

    assert policy.feed(records.membership(thread_pid, 7)).status == "PASS"


@pytest.mark.parametrize(
    ("syscall", "transition"),
    [
        (
            "fork",
            {"operation": "fork", "child_pid": 200, "fd_table": "copied"},
        ),
        (
            "clone",
            {
                "operation": "clone",
                "child_pid": 200,
                "fd_table": "shared",
                "flags": ["CLONE_VM", "CLONE_FILES", "SIGCHLD"],
            },
        ),
        (
            "clone",
            {
                "operation": "clone",
                "child_pid": 200,
                "fd_table": "copied",
                "flags": ["CLONE_VM", "CLONE_SIGHAND", "CLONE_THREAD"],
            },
        ),
    ],
)
def test_nonthread_descendants_do_not_inherit_participant_role(syscall, transition):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, bind_decision = bound_udp(policy, records, 0, ("0.0.0.0", 26650))
    assert bind_decision.status == "PASS"
    assert policy.feed(records.make(pid, syscall, result=200, transition=transition))

    decision = policy.feed(records.membership(200, 7))

    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_canonical_exit_removes_pid_descriptor_authority():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid = connected_udp(policy, records)

    assert policy.feed(records.exit(pid)).status == "PASS"

    assert policy.provenance.describe(pid, 7) is None


def test_pid_reuse_after_exit_is_not_authorized_without_registration():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid = connected_udp(policy, records)
    assert policy.feed(records.exit(pid)).status == "PASS"

    decision = policy.feed(records.socket(pid, 11))

    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_violation_sink_is_mandatory():
    arguments = _constructor_arguments(include_sink=False)
    with pytest.raises((TypeError, ValueError), match="violation.*sink|sink"):
        TracePolicy(**arguments)


def test_violation_sink_receives_complete_event_before_feed_returns():
    sink = RecordingViolationSink()
    policy = make_policy(violation_sink=sink)
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    assert decision.status == "PASS"
    record = records.io(pid, "sendto", 7, address=("203.0.113.10", 443))

    decision = policy.feed(record)

    assert decision.reason == "UNEXPECTED_NETWORK_ATTEMPT"
    (event,) = sink.events
    assert (event.record_index, event.pid, event.operation, event.reason) == (
        record["record_index"],
        pid,
        "sendto",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_violation_sink_failure_cannot_return_a_policy_decision():
    policy = make_policy(violation_sink=FailingViolationSink())
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    assert decision.status == "PASS"
    record = records.io(pid, "sendto", 7, address=("203.0.113.10", 443))

    with pytest.raises(Exception, match="violation sink unavailable"):
        policy.feed(record)


@pytest.mark.parametrize(
    ("syscall", "fd"),
    [("read", 0), ("write", 4)],
    ids=["reviewed-character-device", "reviewed-pipe"],
)
def test_reviewed_non_socket_io_does_not_poison_trace_integrity(syscall, fd):
    policy = make_policy()
    records = Records()

    decision = policy.feed(records.io(COORDINATOR_PID, syscall, fd))

    assert outcome(decision) == ("PASS", "OK")
    assert policy.trace_integrity_error is None
    assert policy.finalize(trace_integrity_ok=True).status == "PASS"


def test_new_pipe_provenance_makes_raw_io_neutral():
    policy = make_policy()
    records = Records()
    created = policy.feed(
        records.make(
            COORDINATOR_PID,
            "pipe2",
            transition={
                "operation": "pipe",
                "created_fds": [
                    {
                        "fd": 5,
                        "provenance": {"kind": "pipe", "inode": 105},
                    },
                    {
                        "fd": 6,
                        "provenance": {"kind": "pipe", "inode": 105},
                    },
                ],
                "cloexec": True,
            },
        )
    )

    read_decision = policy.feed(records.io(COORDINATOR_PID, "read", 5))
    write_decision = policy.feed(records.io(COORDINATOR_PID, "write", 6))

    assert outcome(created) == ("PASS", "OK")
    assert outcome(read_decision) == ("PASS", "OK")
    assert outcome(write_decision) == ("PASS", "OK")
    assert policy.provenance.describe(COORDINATOR_PID, 5)["kind"] == "pipe"
    assert policy.provenance.describe(COORDINATOR_PID, 6)["cloexec"] is True
    assert policy.trace_integrity_error is None


@pytest.mark.parametrize(
    "provenance",
    [
        {"kind": "path"},
        {"kind": "pipe", "inode": 105},
        {"kind": "character_device", "inode": 106},
    ],
    ids=["path", "pipe", "character-device"],
)
def test_reviewed_raw_fd_annotation_is_neutral_without_manifest_entry(provenance):
    policy = make_policy()
    records = Records()
    record = records.io(COORDINATOR_PID, "write", 77)
    record["fds"][0]["provenance"] = provenance

    decision = policy.feed(record)

    assert outcome(decision) == ("PASS", "OK")
    assert policy.trace_integrity_error is None


@pytest.mark.parametrize(
    "provenance",
    [
        {"kind": "unknown"},
        {"kind": "path", "inode": 107},
        {"kind": "pipe"},
        {"kind": "character_device", "inode": -1},
    ],
    ids=["unknown-kind", "path-extra-field", "pipe-missing-inode", "negative-inode"],
)
def test_unreviewed_raw_fd_annotation_fails_trace_integrity(provenance):
    policy = make_policy()
    records = Records()
    record = records.io(COORDINATOR_PID, "write", 77)
    record["fds"][0]["provenance"] = provenance

    decision = policy.feed(record)

    assert outcome(decision) == ("PASS", "OK")
    assert policy.trace_integrity_error == "UNKNOWN_FD_PROVENANCE"


def test_normalized_external_path_raw_io_is_neutral_without_manifest_entry():
    source = b"".join(
        [
            _trace_line(
                'openat(AT_FDCWD, "/tmp/TASK6_SECRET", O_WRONLY)',
                pid=COORDINATOR_PID,
                result="77</tmp/TASK6_SECRET>",
            ),
            _trace_line(
                "write(0x4d, 0x7fff0000, 0x4)",
                pid=COORDINATOR_PID,
                result="0x4",
            ),
        ]
    )
    normalized = normalize_bytes(source)
    policy = make_policy()

    decisions = [policy.feed(record) for record in normalized]

    assert normalized[0]["result"]["fd"] == {
        "fd": 77,
        "provenance": {"kind": "path"},
    }
    assert normalized[1]["fds"] == [{"fd": 77}]
    assert [outcome(decision) for decision in decisions] == [
        ("PASS", "OK"),
        ("PASS", "OK"),
    ]
    assert policy.trace_integrity_error is None


@pytest.mark.parametrize(
    "provenance",
    [
        {"kind": "socket", "inode": 7077},
        {"kind": "unknown"},
        {"kind": "path", "unexpected": True},
    ],
    ids=["socket", "unknown-kind", "malformed-path"],
)
def test_generic_fd_creation_with_unreviewed_provenance_fails_integrity(provenance):
    policy = make_policy()
    records = Records()
    created = records.make(COORDINATOR_PID, "openat", result=77)
    created["result"]["fd"] = {"fd": 77, "provenance": provenance}

    decision = policy.feed(created)

    assert outcome(decision) == ("PASS", "OK")
    assert policy.trace_integrity_error == "UNKNOWN_FD_PROVENANCE"


@pytest.mark.parametrize(
    ("syscall", "transition"),
    [
        (
            "unshare",
            {"operation": "unshare_files", "flags": ["CLONE_FILES"]},
        ),
        (
            "close_range",
            {
                "operation": "close_range",
                "first_fd": 100,
                "last_fd": 100,
                "flags": ["CLOSE_RANGE_UNSHARE"],
            },
        ),
    ],
    ids=["unshare", "close-range-unshare"],
)
def test_worker_loses_network_authority_after_fd_table_unshare(syscall, transition):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _ = registered_tx(policy, records, 0)
    worker_tid = 1100
    assert clone_worker(policy, records, root_pid, worker_tid).status == "PASS"

    unshared = policy.feed(records.make(worker_tid, syscall, transition=transition))
    outbound = policy.feed(
        records.io(
            worker_tid,
            "sendto",
            tx_fd,
            address=("239.255.0.1", 26650),
        )
    )

    assert outcome(unshared) == ("PASS", "OK")
    assert outcome(outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


@pytest.mark.parametrize(
    ("syscall", "transition"),
    [
        (
            "unshare",
            {"operation": "unshare_files", "flags": ["CLONE_FILES"]},
        ),
        (
            "close_range",
            {
                "operation": "close_range",
                "first_fd": 100,
                "last_fd": 100,
                "flags": ["CLOSE_RANGE_UNSHARE"],
            },
        ),
    ],
    ids=["unshare", "close-range-unshare"],
)
def test_root_fd_table_split_revokes_every_live_worker(syscall, transition):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _ = registered_tx(policy, records, 0)
    worker_tids = (1100, 1101)
    for worker_tid in worker_tids:
        assert clone_worker(policy, records, root_pid, worker_tid).status == "PASS"

    split = policy.feed(records.make(root_pid, syscall, transition=transition))
    worker_outbound = [
        policy.feed(
            records.io(
                worker_tid,
                "sendto",
                tx_fd,
                address=("239.255.0.1", 26650),
            )
        )
        for worker_tid in worker_tids
    ]
    root_outbound = policy.feed(
        records.io(
            root_pid,
            "sendto",
            tx_fd,
            address=("239.255.0.1", 26650),
        )
    )

    assert outcome(split) == ("PASS", "OK")
    assert [outcome(decision) for decision in worker_outbound] == [
        ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
        ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT"),
    ]
    assert outcome(root_outbound) == ("PASS", "OK")


def test_worker_fd_table_split_revokes_only_that_worker():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, tx_fd, _ = registered_tx(policy, records, 0)
    worker_tids = (1100, 1101)
    for worker_tid in worker_tids:
        assert clone_worker(policy, records, root_pid, worker_tid).status == "PASS"

    split = policy.feed(
        records.make(
            worker_tids[0],
            "unshare",
            transition={"operation": "unshare_files", "flags": ["CLONE_FILES"]},
        )
    )
    revoked = policy.feed(
        records.io(
            worker_tids[0],
            "sendto",
            tx_fd,
            address=("239.255.0.1", 26650),
        )
    )
    retained = policy.feed(
        records.io(
            worker_tids[1],
            "sendto",
            tx_fd,
            address=("239.255.0.1", 26650),
        )
    )

    assert outcome(split) == ("PASS", "OK")
    assert outcome(revoked) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(retained) == ("PASS", "OK")


def test_root_close_range_cleanup_satisfies_participant_lifecycle():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, bind_decision = bound_udp(
        policy,
        records,
        0,
        ("0.0.0.0", META_PORTS[0]),
    )
    assert bind_decision.status == "PASS"

    close_decision = policy.feed(
        records.make(
            root_pid,
            "close_range",
            transition={
                "operation": "close_range",
                "first_fd": 7,
                "last_fd": 7,
                "flags": [],
            },
        )
    )
    root_exit = policy.feed(records.exit(root_pid))
    end = policy.feed(records.marker("END"))

    assert outcome(close_decision) == ("PASS", "OK")
    assert outcome(root_exit) == ("PASS", "OK")
    assert outcome(end) == ("PASS", "OK")
    assert policy.provenance.describe(root_pid, 7) is None
    assert policy.finalize(trace_integrity_ok=True).status == "PASS"


def test_marker_metadata_cannot_suppress_a_decoded_ip_violation():
    policy = make_policy()
    records = Records()
    record = records.socket(PARTICIPANT_PIDS[0], 7)
    record["marker"] = {"phase": "BEGIN", "token": TOKEN}

    decision = policy.feed(record)

    assert outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert policy.trace_integrity_error == "INVALID_MARKER"
    assert policy.journal.first_violation.reason == "UNEXPECTED_NETWORK_ATTEMPT"


def test_repeated_port_zero_bind_poisons_tx_registration():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, first_bind = _start_tx_registration(policy, records)

    repeated_bind = policy.feed(records.bind(pid, 17, "127.0.0.1", 0))
    later = [
        policy.feed(records.tx_socket_option(pid, 17, option, value, length))
        for option, value, length in TX_SETUP_OPTIONS
    ]
    observed = policy.feed(
        records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
    )
    outbound = policy.feed(
        records.io(pid, "sendto", 17, address=("239.255.0.1", 26650))
    )

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(first_bind) == ("PASS", "OK")
    assert outcome(repeated_bind) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert all(
        outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
        for decision in later
    )
    assert outcome(observed) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert outcome(outbound) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_dup_cannot_interpose_during_tx_registration():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, bind_decision = _start_tx_registration(policy, records)

    duplicate = policy.feed(
        records.make(
            pid,
            "dup",
            result=18,
            transition={
                "operation": "dup",
                "source_fd": {"fd": 17},
                "created_fd": {"fd": 18},
            },
        )
    )
    setup = [
        policy.feed(records.tx_socket_option(pid, 17, option, value, length))
        for option, value, length in TX_SETUP_OPTIONS
    ]
    observed = policy.feed(
        records.getsockname(pid, 17, "127.0.0.1", EPHEMERAL_PORTS[0])
    )

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(bind_decision) == ("PASS", "OK")
    assert outcome(duplicate) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert all(
        outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
        for decision in setup
    )
    assert outcome(observed) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_close_range_cloexec_poisons_incomplete_tx_without_lifecycle_close():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, bind_decision = _start_tx_registration(policy, records)

    cloexec = policy.feed(
        records.make(
            pid,
            "close_range",
            transition={
                "operation": "close_range",
                "first_fd": 7,
                "last_fd": 17,
                "flags": ["CLOSE_RANGE_CLOEXEC"],
            },
        )
    )
    later = _feed_tx_options(policy, records, pid, TX_SETUP_OPTIONS)

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(bind_decision) == ("PASS", "OK")
    assert outcome(cloexec) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert policy.provenance.describe(pid, 17)["cloexec"] is True
    assert policy.provenance.describe(pid, 17)["kind"] == "socket"
    assert all(
        outcome(decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
        for decision in later
    )


@pytest.mark.parametrize("operation", ["dup2", "dup3"])
def test_dup_target_interposition_poisons_implicitly_closed_incomplete_tx(operation):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid = PARTICIPANT_PIDS[0]
    assert policy.feed(records.socket(pid, 18, domain="AF_UNIX")).status == "PASS"
    pid, socket_decision, bind_decision = _start_tx_registration(policy, records)
    transition = {
        "operation": operation,
        "source_fd": {"fd": 18},
        "target_fd": {"fd": 17},
        "created_fd": {"fd": 17},
    }
    if operation == "dup3":
        transition["flags"] = []

    duplicate = policy.feed(
        records.make(pid, operation, result=17, transition=transition)
    )

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(bind_decision) == ("PASS", "OK")
    assert outcome(duplicate) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_incomplete_tx_registration_cannot_finalize_as_pass():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, socket_decision, bind_decision = _start_tx_registration(policy, records)

    close_decision = policy.feed(records.close(pid, 17))
    assert policy.feed(records.exit(pid)).status == "PASS"
    assert policy.feed(records.marker("END")).status == "PASS"

    assert outcome(socket_decision) == ("PASS", "OK")
    assert outcome(bind_decision) == ("PASS", "OK")
    assert outcome(close_decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
    assert policy.finalize(trace_integrity_ok=True).status != "PASS"


def _spawn_configured_root(policy, records, participant, *, parent_pid=COORDINATOR_PID):
    return policy.feed(
        records.make(
            parent_pid,
            "fork",
            result=PARTICIPANT_PIDS[participant],
            transition={
                "operation": "fork",
                "child_pid": PARTICIPANT_PIDS[participant],
                "fd_table": "copied",
            },
        )
    )


@pytest.mark.parametrize(
    "parent_pid",
    [COORDINATOR_PID, 999],
    ids=["coordinator-parent", "nonparticipant-launcher-parent"],
)
def test_configured_root_survives_observed_spawn_and_validated_exec_lifecycle(
    parent_pid,
):
    policy = make_policy()
    records = Records()
    open_window(policy, records)

    spawn = _spawn_configured_root(policy, records, 0, parent_pid=parent_pid)
    exec_decision = policy.feed(
        records.make(
            PARTICIPANT_PIDS[0],
            "execve",
            transition={"operation": "exec", "cloexec_fds": "closed"},
        )
    )
    socket_decision = policy.feed(records.socket(PARTICIPANT_PIDS[0], 7))

    assert outcome(spawn) == ("PASS", "OK")
    assert outcome(exec_decision) == ("PASS", "OK")
    assert outcome(socket_decision) == ("PASS", "OK")


@pytest.mark.parametrize(
    "parent_pid",
    [COORDINATOR_PID, 999],
    ids=["coordinator-parent", "nonparticipant-launcher-parent"],
)
def test_exited_configured_root_pid_cannot_be_reauthorized_by_numeric_reuse(parent_pid):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid = PARTICIPANT_PIDS[0]
    assert policy.feed(records.exit(root_pid)).status == "PASS"

    respawn = _spawn_configured_root(policy, records, 0, parent_pid=parent_pid)
    socket_decision = policy.feed(records.socket(root_pid, 7))

    assert outcome(respawn) == ("PASS", "OK")
    assert outcome(socket_decision) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")


def test_successful_worker_exec_revokes_shared_thread_authority():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    root_pid, _, _ = registered_tx(policy, records, 0)
    worker_tid = 1100
    assert clone_worker(policy, records, root_pid, worker_tid).status == "PASS"
    exec_decision = policy.feed(
        records.make(
            worker_tid,
            "execve",
            transition={"operation": "exec", "cloexec_fds": "closed"},
        )
    )
    after_exec = policy.feed(records.socket(worker_tid, 22))

    assert outcome(exec_decision) == ("PASS", "OK")
    assert outcome(after_exec) == ("FAIL", "UNEXPECTED_NETWORK_ATTEMPT")
