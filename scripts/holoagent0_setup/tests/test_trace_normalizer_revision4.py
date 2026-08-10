from pathlib import Path

import pytest

from holoagent0_setup.trace_normalizer import (
    TraceDecodeError,
    canonical_ndjson,
    normalize_bytes,
)


ROOT = Path(__file__).parents[1]
TEST_MANIFEST = ROOT / "test-manifest-v1.txt"


def _line(
    call: str,
    result: str = "0",
    *,
    pid: int = 81,
    timestamp: str = "1700000050.000001",
    duration: str = "0.000001",
) -> bytes:
    prefix = f"{pid:<5} {timestamp} "
    padding = " " * max(1, 40 - len(prefix) - len(call))
    return f"{prefix}{call}{padding}= {result} <{duration}>\n".encode()


def test_result_alignment_accepts_pinned_two_and_eight_space_forms():
    source = _line("getpid()", "81") + _line(
        "close(1234567)",
        "-1 EBADF (Bad file descriptor)",
        timestamp="1700000050.000002",
    )
    assert b"getpid()        =" in source
    assert b"close(1234567)  =" in source
    records = normalize_bytes(source)
    assert [record["syscall"] for record in records] == ["getpid", "close"]


@pytest.mark.parametrize(
    "source",
    [
        b"81    1700000050.000001 getpid()       = 81 <0.000001>\n",
        b"81    1700000050.000001 getpid()         = 81 <0.000001>\n",
        b"81    1700000050.000001 getpid()\t= 81 <0.000001>\n",
        b"81    1700000050.000001 close(1234567) = -1 EBADF (Bad file descriptor) <0.000001>\n",
        b"81    1700000050.000001 close(1234567)   = -1 EBADF (Bad file descriptor) <0.000001>\n",
    ],
)
def test_result_alignment_rejects_noncanonical_separators(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_resumed_result_alignment_uses_the_actual_resumed_line_column():
    entry = b"81    1700000050.000001 read(0x3, <unfinished ...>\n"
    prefix = "81    1700000050.000002 "
    resumed_call = "<... read resumed>0x0, 0x1)"
    spaces = " " * max(1, 40 - len(prefix) - len(resumed_call))
    resumed = f"{prefix}{resumed_call}{spaces}= 0x1 <0.000001>\n".encode()
    record = normalize_bytes(entry + resumed)[0]
    assert record["syscall"] == "read"
    assert record["result"] == {"value": 1}
    malformed = resumed.replace((spaces + "=").encode(), (spaces + " =").encode())
    with pytest.raises(TraceDecodeError):
        normalize_bytes(entry + malformed)


@pytest.mark.parametrize(("phase", "prefix"), [("BEGIN", "H0B"), ("END", "H0E")])
def test_prctl_dds_markers_preserve_phase_token_and_ordering_fields(phase, prefix):
    token = "0123456789ab"
    record = normalize_bytes(_line(f'prctl(PR_SET_NAME, "{prefix}{token}"...)'))[0]
    assert record["marker"] == {"phase": phase, "token": token}
    assert {
        key: record[key] for key in ("pid", "entry_index", "exit_index", "result")
    } == {"pid": 81, "entry_index": 0, "exit_index": 0, "result": {"value": 0}}


def test_failed_marker_attempt_remains_visible_but_result_prevents_authorization():
    record = normalize_bytes(
        _line(
            'prctl(PR_SET_NAME, "H0B0123456789ab"...)',
            "-1 EPERM (Operation not permitted)",
        )
    )[0]
    assert record["marker"] == {"phase": "BEGIN", "token": "0123456789ab"}
    assert record["result"]["errno"] == "EPERM"


@pytest.mark.parametrize(
    "name",
    [
        "H0B0123456789a",
        "H0B0123456789abc",
        "H0B0123456789AB",
        "H0X0123456789ab",
        "MARKER_PAYLOAD_SECRET",
    ],
)
def test_nonmarker_prctl_names_are_redacted_and_never_gain_marker_authority(name):
    record = normalize_bytes(_line(f'prctl(PR_SET_NAME, "{name}")'))[0]
    assert "marker" not in record
    rendered = canonical_ndjson([record])
    assert name not in rendered
    assert "PAYLOAD_SECRET" not in rendered


def test_other_prctl_operations_remain_argument_redacted():
    record = normalize_bytes(_line("prctl(PR_SET_DUMPABLE, 1)"))[0]
    assert "marker" not in record
    assert "PR_SET_DUMPABLE" not in canonical_ndjson([record])


def test_netlink_bind_and_getsockname_preserve_safe_sockaddr_fields():
    source = _line(
        "bind(4<NETLINK:[404]>, {sa_family=AF_NETLINK, nl_pid=4321, "
        "nl_groups=00000000}, 12)"
    ) + _line(
        "getsockname(4<NETLINK:[ROUTE:4321]>, {sa_family=AF_NETLINK, "
        "nl_pid=4321, nl_groups=00000001}, [12])",
        timestamp="1700000050.000002",
    )
    records = normalize_bytes(source)
    assert records[0]["transition"]["address"] == {
        "family": "AF_NETLINK",
        "pid": 4321,
        "groups": 0,
    }
    assert records[1]["transition"]["address"]["groups"] == 1


def test_packet_socket_and_sockaddr_are_policy_visible_without_address_bytes():
    source = _line(
        "socket(AF_PACKET, SOCK_RAW|SOCK_CLOEXEC, htons(ETH_P_ALL))",
        "3<PACKET:[303]>",
    ) + _line(
        "connect(3<PACKET:[303]>, {sa_family=AF_PACKET, "
        "sll_protocol=htons(ETH_P_ALL), sll_ifindex=2, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=6, "
        "sll_addr=[0x50, 0x41, 0x59, 0x4c, 0x4f, 0x41]}, 20)",
        timestamp="1700000050.000002",
    )
    records = normalize_bytes(source)
    assert records[0]["transition"]["protocol"] == "ETH_P_ALL"
    assert records[0]["transition"]["created_fd"]["provenance"] == {
        "kind": "socket",
        "protocol": "PACKET",
    }
    assert records[1]["transition"]["address"] == {
        "family": "AF_PACKET",
        "protocol": "ETH_P_ALL",
    }
    assert "PAYLOA" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    ("domain", "socket_type", "protocol"),
    [
        ("AF_INET", "SOCK_DGRAM", "IPPROTO_UDPLITE"),
        ("AF_INET6", "SOCK_RAW", "IPPROTO_GRE"),
        ("AF_CAN", "SOCK_RAW", "CAN_RAW"),
        ("AF_BLUETOOTH", "SOCK_STREAM", "BTPROTO_RFCOMM"),
        ("AF_VSOCK", "SOCK_STREAM", "0"),
    ],
)
def test_pinned_known_socket_domains_types_and_protocols_normalize(
    domain, socket_type, protocol
):
    record = normalize_bytes(
        _line(
            f"socket({domain}, {socket_type}, {protocol})",
            "-1 EPERM (Operation not permitted)",
        )
    )[0]
    assert record["transition"]["domain"] == domain
    assert record["transition"]["protocol"] == (0 if protocol == "0" else protocol)


@pytest.mark.parametrize(
    "annotation",
    [
        "UDPLITE:[127.0.0.1:7400]",
        "UDPLITEv6:[[::1]:7400]",
        "RAW:[101]",
        "RAWv6:[102]",
        "DCCP:[103]",
        "SCTPv6:[104]",
        "PING:[105]",
        'UNIX-STREAM:[106,@"ANNOTATION_PAYLOAD_SECRET"]',
        "PACKET:[107]",
    ],
)
def test_pinned_socket_annotations_retain_protocol_without_payload(annotation):
    record = normalize_bytes(_line(f"close(9<{annotation}>)"))[0]
    provenance = record["transition"]["closed_fd"]["provenance"]
    assert provenance["kind"] == "socket"
    assert provenance["protocol"] == annotation.split(":", 1)[0]
    assert "PAYLOAD_SECRET" not in canonical_ndjson([record])


def test_abstract_unix_address_and_scm_rights_reach_the_sink_without_name_leaks():
    source = _line(
        'recvmsg(4<UNIX-STREAM:[44,@"SOURCE_SECRET"]>, '
        '{msg_name={sa_family=AF_UNIX, sun_path=@"ABSTRACT_SECRET"}, '
        "msg_namelen=16, msg_iov=[], msg_iovlen=0, "
        "msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, "
        'cmsg_type=SCM_RIGHTS, cmsg_data=[8<UNIX-STREAM:[88,@"RIGHTS_SECRET"]>]}], '
        "msg_controllen=24, msg_flags=0}, 0)",
        "1",
    )
    record = normalize_bytes(source)[0]
    assert record["address"] == {
        "family": "AF_UNIX",
        "path": {"kind": "unix", "abstract": True},
    }
    assert record["control"]["scm_rights"][0][0]["provenance"] == {
        "kind": "socket",
        "protocol": "UNIX-STREAM",
    }
    rendered = canonical_ndjson([record])
    assert not any(
        secret in rendered
        for secret in ("SOURCE_SECRET", "ABSTRACT_SECRET", "RIGHTS_SECRET")
    )


def test_socket_option_setup_retains_identity_level_option_and_length_only():
    source = _line(
        'setsockopt(3<UDP:[127.0.0.1:7400]>, SOL_SOCKET, SO_REUSEADDR, "OPTION_PAYLOAD_SECRET", 4)'
    ) + _line(
        "getsockopt(3<UDP:[127.0.0.1:7400]>, SOL_IP, IP_MULTICAST_TTL, [1], [4])",
        timestamp="1700000050.000002",
    )
    records = normalize_bytes(source)
    assert records[0]["transition"] == {
        "operation": "setsockopt",
        "fd": {
            "fd": 3,
            "provenance": {"kind": "socket", "protocol": "UDP"},
        },
        "level": "SOL_SOCKET",
        "option": "SO_REUSEADDR",
        "length": 4,
    }
    assert records[1]["transition"]["operation"] == "getsockopt"
    assert records[1]["transition"]["level"] == "SOL_IP"
    assert records[1]["transition"]["option"] == "IP_MULTICAST_TTL"
    assert "OPTION_PAYLOAD_SECRET" not in canonical_ndjson(records)


def test_other_socket_setup_calls_preserve_fd_and_safe_operation_metadata():
    source = (
        _line("listen(3<TCP:[127.0.0.1:7400]>, 16)")
        + _line(
            "shutdown(3<TCP:[127.0.0.1:7400]>, SHUT_RDWR)",
            timestamp="1700000050.000002",
        )
        + _line(
            "getpeername(3<TCP:[127.0.0.1:7400]>, {sa_family=AF_INET, "
            'sin_port=htons(7401), sin_addr=inet_addr("127.0.0.1")}, [16])',
            timestamp="1700000050.000003",
        )
    )
    records = normalize_bytes(source)
    assert records[0]["transition"]["backlog"] == 16
    assert records[1]["transition"]["how"] == "SHUT_RDWR"
    assert records[2]["transition"]["fd"]["provenance"]["protocol"] == "TCP"
    assert records[2]["transition"]["address"]["family"] == "AF_INET"


@pytest.mark.parametrize("name", ["syscall_0x1c3", "syscall_0xffffffffffffffff"])
def test_unknown_native_syscall_names_are_rejected_as_unsupported_abi(name):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            _line(f"{name}(0, 0, 0)", "-1 ENOSYS (Function not implemented)")
        )


def test_pinned_test_manifest_includes_all_trace_revision_suites():
    paths = TEST_MANIFEST.read_text(encoding="utf-8").splitlines()
    assert "scripts/holoagent0_setup/tests/test_trace_normalizer_revision3.py" in paths
    assert "scripts/holoagent0_setup/tests/test_trace_normalizer_revision4.py" in paths
    assert len(paths) == len(set(paths))
    repository_root = ROOT.parents[1]
    discovered = {
        path.relative_to(repository_root).as_posix()
        for path in (ROOT / "tests").glob("test_*.py")
    }
    assert set(paths) == discovered
