from pathlib import Path

import pytest

from holoagent0_setup.trace_normalizer import (
    TraceDecodeError,
    TraceNormalizer,
    canonical_ndjson,
    normalize_bytes,
)


ROOT = Path(__file__).parents[1]
TEST_MANIFEST = ROOT / "test-manifest-v1.txt"


def _line(
    call: str,
    result: str = "0",
    *,
    pid: int = 84,
    timestamp: str = "1700000053.000001",
    duration: str = "0.000001",
) -> bytes:
    prefix = f"{pid:<5} {timestamp} "
    padding = " " * max(1, 40 - len(prefix) - len(call))
    return f"{prefix}{call}{padding}= {result} <{duration}>\n".encode()


@pytest.mark.parametrize(("phase", "prefix"), [("BEGIN", "H0B"), ("END", "H0E")])
def test_pinned_pr_set_name_marker_ellipsis_preserves_phase_and_token(phase, prefix):
    token = "0123456789ab"
    record = normalize_bytes(_line(f'prctl(PR_SET_NAME, "{prefix}{token}"...)'))[0]
    assert record["marker"] == {"phase": phase, "token": token}
    assert record["pid"] == 84
    assert record["entry_index"] == record["exit_index"] == 0
    assert record["result"] == {"value": 0}


def test_failed_pinned_marker_ellipsis_remains_visible_with_failure_result():
    record = normalize_bytes(
        _line(
            'prctl(PR_SET_NAME, "H0B0123456789ab"...)',
            "-1 EPERM (Operation not permitted)",
        )
    )[0]
    assert record["marker"] == {"phase": "BEGIN", "token": "0123456789ab"}
    assert record["result"]["errno"] == "EPERM"


def test_no_ellipsis_fifteen_byte_name_cannot_gain_pinned_marker_authority():
    record = normalize_bytes(_line('prctl(PR_SET_NAME, "H0B0123456789ab")'))[0]
    assert "marker" not in record


@pytest.mark.parametrize(
    "call",
    [
        'prctl(PR_SET_NAME, "H0X0123456789ab"...)',
        'prctl(PR_SET_NAME, "H0B0123456789AB"...)',
        'prctl(PR_SET_NAME, "H0B0123456789a"...)',
        'prctl(PR_SET_NAME, "H0B0123456789abc"...)',
        'prctl(PR_SET_NAME, "H0B0123456789abPAYLOAD_SENTINEL"...)',
        'prctl(PR_GET_NAME, "H0B0123456789ab"...)',
        'prctl(PR_SET_NAME, "ordinary"...)',
        'write(1, "PAYLOAD_SENTINEL"..., 16)',
    ],
)
def test_every_nonmarker_ellipsis_remains_rejected(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call))


def test_marker_result_alignment_counts_the_displayed_ellipsis_columns():
    source = _line('prctl(PR_SET_NAME, "H0B0123456789ab"...)')
    assert b'"...) = 0' in source
    assert normalize_bytes(source)[0]["marker"]["phase"] == "BEGIN"
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source.replace(b'"...) =', b'"...)  ='))


def test_packet_zero_halen_omits_address_and_accepts_numeric_or_named_ifindex():
    source = _line(
        "connect(-1, {sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        "sll_ifindex=4207869677, sll_hatype=ARPHRD_ETHER, "
        "sll_pkttype=PACKET_HOST, sll_halen=0}, 20)",
        "-1 EBADF (Bad file descriptor)",
    ) + _line(
        "connect(-1, {sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        'sll_ifindex=if_nametoindex("INTERFACE_PAYLOAD_SECRET"), '
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0}, 20)",
        "-1 EBADF (Bad file descriptor)",
        timestamp="1700000053.000002",
    )
    records = normalize_bytes(source)
    assert records[0]["transition"]["address"] == {
        "family": "AF_PACKET",
        "protocol": "ETH_P_ALL",
        "ifindex": {"kind": "numeric", "value": 4207869677},
    }
    assert records[1]["transition"]["address"] == {
        "family": "AF_PACKET",
        "protocol": "ETH_P_ALL",
        "ifindex": {"kind": "name"},
    }
    assert "INTERFACE_PAYLOAD_SECRET" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    "address",
    [
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=1}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0, "
        "sll_addr=[]}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=-1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        'sll_ifindex=if_nametoindex("bad")|1, sll_hatype=ARPHRD_ETHER, '
        "sll_pkttype=PACKET_HOST, sll_halen=0}",
    ],
)
def test_packet_zero_halen_keeps_full_structural_validation(address):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            _line(
                f"connect(-1, {address}, 20)",
                "-1 EBADF (Bad file descriptor)",
            )
        )


def test_structurally_translated_socket_options_retain_identity_and_redact_values():
    source = (
        _line("getsockopt(6<TCP:[127.0.0.1:7400]>, SOL_TCP, TCP_MAXSEG, [536], [4])")
        + _line(
            "getsockopt(7<UNIX-STREAM:[707]>, SOL_SOCKET, SO_ACCEPTCONN, [1], [4])",
            timestamp="1700000053.000002",
        )
        + _line(
            "setsockopt(7<UNIX-STREAM:[707]>, SOL_SOCKET, SO_PASSCRED, "
            '"SOCKET_OPTION_PAYLOAD_SECRET", 4)',
            timestamp="1700000053.000003",
        )
        + _line(
            "setsockopt(8<PACKET:[808]>, SOL_XDP, XDP_UMEM_REG, "
            '"SOCKET_OPTION_PAYLOAD_SECRET", 16)',
            timestamp="1700000053.000004",
        )
    )
    records = normalize_bytes(source)
    assert [record["transition"]["option"] for record in records] == [
        "TCP_MAXSEG",
        "SO_ACCEPTCONN",
        "SO_PASSCRED",
        "XDP_UMEM_REG",
    ]
    assert records[0]["transition"]["fd"]["provenance"]["protocol"] == "TCP"
    assert records[3]["transition"]["level"] == "SOL_XDP"
    assert records[3]["transition"]["length"] == 16
    assert "SOCKET_OPTION_PAYLOAD_SECRET" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    ("level", "option"),
    [
        ("SOL_tcp", "TCP_MAXSEG"),
        ("SOL_", "TCP_MAXSEG"),
        ("IPPROTO_TCP", "TCP_MAXSEG"),
        ("SOL_TCP|SOL_UDP", "TCP_MAXSEG"),
        ("SOL_TCP", "tcp_MAXSEG"),
        ("SOL_TCP", "TCP-MAXSEG"),
        ("SOL_TCP", "TCP__MAXSEG"),
        ("SOL_TCP", "42"),
    ],
)
def test_socket_option_tokens_reject_nontranslated_or_malformed_grammar(level, option):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(f"setsockopt(6<TCP:[606]>, {level}, {option}, [1], 4)"))


def test_pinned_test_manifest_includes_revision5_suite():
    paths = TEST_MANIFEST.read_text(encoding="utf-8").splitlines()
    assert "scripts/holoagent0_setup/tests/test_trace_normalizer_revision5.py" in paths
    assert len(paths) == len(set(paths))


def test_record_sink_mutation_cannot_change_returned_nested_evidence():
    sink_records = []

    def mutating_sink(record):
        sink_records.append(record)
        record["result"]["value"] = 999
        record["transition"]["created_fd"]["provenance"]["protocol"] = "MUTATED"
        record["sink_only"] = {"nested": ["mutation"]}

    normalizer = TraceNormalizer(record_sink=mutating_sink)
    records = normalizer.feed(
        _line("socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP)", "7<UDP:[7]>")
    )
    records.extend(normalizer.finish())

    assert len(sink_records) == 1
    assert records[0]["result"]["value"] == 7
    assert records[0]["transition"]["created_fd"]["provenance"]["protocol"] == "UDP"
    assert "sink_only" not in records[0]
