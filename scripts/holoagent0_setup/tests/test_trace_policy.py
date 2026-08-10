from __future__ import annotations

import itertools

import pytest

from holoagent0_setup.trace_policy import TracePolicy


TOKEN = "0123456789ab"
COORDINATOR_PID = 90
PARTICIPANT_PIDS = {index: 100 + index for index in range(4)}
CONFIG_DIGESTS = {index: f"{index + 1:064x}" for index in range(4)}
META_PORTS = {0: 26660, 1: 26662, 2: 26664, 3: 26666}
DATA_PORTS = {0: 26661, 1: 26663, 2: 26665, 3: 26667}


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

    def io(self, pid, syscall, fd, *, address=None, control=None):
        fields = {"fds": [{"fd": fd}], "lengths": {"count": 8}}
        if address is not None:
            fields["address"] = {
                "family": "AF_INET",
                "ip": address[0],
                "port": address[1],
            }
        if control is not None:
            fields["control"] = control
        return self.make(pid, syscall, result=8, **fields)


def make_policy(*, loopback_only=True, participant_digests=None):
    participant_digests = participant_digests or CONFIG_DIGESTS
    return TracePolicy(
        coordinator_pid=COORDINATOR_PID,
        marker_token=TOKEN,
        participants={
            pid: {"index": index, "config_digest": participant_digests[index]}
            for index, pid in PARTICIPANT_PIDS.items()
        },
        expected_config_digests=CONFIG_DIGESTS,
        namespace_loopback_only=loopback_only,
    )


def open_window(policy, records):
    assert policy.feed(records.marker("BEGIN")).status == "PASS"


def bound_udp(policy, records, participant, local, *, fd=7):
    pid = PARTICIPANT_PIDS[participant]
    assert policy.feed(records.socket(pid, fd)).status == "PASS"
    return pid, policy.feed(records.bind(pid, fd, *local))


@pytest.mark.parametrize("syscall", ["write", "writev", "sendfile", "splice"])
def test_connected_udp_alias_after_end_is_safety_failure(syscall):
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    assert decision.status == "PASS"
    assert (
        policy.feed(
            records.make(
                pid,
                "connect",
                transition={
                    "operation": "connect",
                    "fd": {"fd": 7},
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
                    "source_fd": {"fd": 7},
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


@pytest.mark.parametrize(
    "local_address,participant,local_port",
    [
        ("192.0.2.10", 0, 26650),
        ("::1", 0, 26650),
        ("239.255.0.1", 0, 26650),
        ("0.0.0.0", 0, 26651),
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
    pid, decision = bound_udp(
        policy, records, participant, ("127.0.0.1", META_PORTS[participant])
    )
    assert decision.status == "PASS"
    decision = policy.feed(records.io(pid, "sendto", 7, address=("239.255.0.1", 26650)))
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
    pid, decision = bound_udp(
        policy, records, participant, ("127.0.0.1", local_ports[participant])
    )
    assert decision.status == "PASS"
    decision = policy.feed(
        records.io(
            pid,
            "sendto",
            7,
            address=("127.0.0.1", local_ports[remote_index]),
        )
    )
    assert decision.status == "PASS"


@pytest.mark.parametrize("remote_index", range(4))
@pytest.mark.parametrize("participant", range(4))
def test_inbound_spdp_and_unicast_sources_pass(participant, remote_index):
    for local_port, remote_port in (
        (26650, META_PORTS[remote_index]),
        (META_PORTS[participant], META_PORTS[remote_index]),
        (DATA_PORTS[participant], DATA_PORTS[remote_index]),
    ):
        policy = make_policy()
        records = Records()
        open_window(policy, records)
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
    "local,remote",
    [
        (("0.0.0.0", META_PORTS[0]), ("239.255.0.1", 26650)),
        (("127.0.0.1", META_PORTS[0]), ("127.0.0.1", DATA_PORTS[1])),
        (("127.0.0.1", DATA_PORTS[0]), ("127.0.0.1", META_PORTS[1])),
        (("127.0.0.1", META_PORTS[0]), ("192.0.2.10", META_PORTS[1])),
        (("127.0.0.1", META_PORTS[0]), ("127.0.0.1", 26651)),
    ],
)
def test_nonmatrix_dds_destination_is_rejected(local, remote):
    policy = make_policy(loopback_only=False if local[0] == "0.0.0.0" else True)
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, local)
    if decision.status == "FAIL":
        assert decision.reason == "UNEXPECTED_NETWORK_ATTEMPT"
        return
    decision = policy.feed(records.io(pid, "sendto", 7, address=remote))
    assert (decision.status, decision.reason) == (
        "FAIL",
        "UNEXPECTED_NETWORK_ATTEMPT",
    )


def test_wildcard_outbound_requires_loopback_only_namespace_proof():
    for loopback_only, expected in ((True, "PASS"), (False, "FAIL")):
        policy = make_policy(loopback_only=loopback_only)
        records = Records()
        open_window(policy, records)
        pid, decision = bound_udp(policy, records, 0, ("0.0.0.0", META_PORTS[0]))
        assert decision.status == "PASS"
        decision = policy.feed(
            records.io(pid, "sendto", 7, address=("127.0.0.1", META_PORTS[1]))
        )
        assert decision.status == expected


def test_ordinary_dds_message_passes_but_scm_rights_is_journaled():
    policy = make_policy()
    records = Records()
    open_window(policy, records)
    pid, decision = bound_udp(policy, records, 0, ("127.0.0.1", META_PORTS[0]))
    assert decision.status == "PASS"
    assert (
        policy.feed(
            records.io(
                pid,
                "sendmsg",
                7,
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
            7,
            control={"scm_rights": [[{"fd": 12}]]},
        )
    )
    assert (transfer.status, transfer.reason) == ("FAIL", "PROHIBITED_FD_TRANSFER")
    assert policy.journal.first_violation.reason == "PROHIBITED_FD_TRANSFER"


def test_pidfd_acquisition_and_bad_marker_identity_fail_closed():
    policy = make_policy()
    records = Records()
    bad_marker = policy.feed(records.marker("BEGIN", pid=91))
    assert (bad_marker.status, bad_marker.reason) == ("FAIL", "INVALID_MARKER")

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


def test_participant_config_digest_and_marker_window_are_exact():
    for mutate in ("pid", "digest", "token", "phase"):
        policy = make_policy()
        records = Records()
        if mutate == "token":
            decision = policy.feed(records.marker("BEGIN", token="ffffffffffff"))
        elif mutate == "phase":
            decision = policy.feed(records.marker("END"))
        else:
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
    assert policy.feed(invalid_end).reason == "INVALID_MARKER"


def test_meta_and_data_port_sets_are_closed_and_disjoint():
    assert set(META_PORTS.values()) | set(DATA_PORTS.values()) == set(
        range(26660, 26668)
    )
    assert not set(META_PORTS.values()) & set(DATA_PORTS.values())
    assert len(tuple(itertools.product(PARTICIPANT_PIDS, PARTICIPANT_PIDS))) == 16
