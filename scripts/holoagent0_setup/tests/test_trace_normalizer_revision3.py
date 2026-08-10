import inspect
import json
from pathlib import Path

import pytest

import holoagent0_setup.trace_normalizer as trace_module
from holoagent0_setup.trace_normalizer import (
    TraceDecodeError,
    TraceNormalizer,
    canonical_ndjson,
    normalize_bytes,
)


ROOT = Path(__file__).parents[1]
POLICY = ROOT / "policies/holoagent0-trace-tool-v1.json"


def _line(pid: int, body: str, timestamp: str = "1700000040.000001") -> bytes:
    # strace 6.6 src/strace.c printleader(): dedicated -o and -f use "%-5u"
    # and then tprint_space(), for a minimum-width PID field plus one separator.
    return f"{pid:<5} {timestamp} {body}\n".encode()


def _require_record_sink():
    if "record_sink" not in inspect.signature(TraceNormalizer).parameters:
        pytest.fail(
            "TraceNormalizer lacks the required immediate record_sink authority"
        )


def test_dedicated_output_fd_argv_template_is_exact_digest_bound_and_injection_safe():
    expected = (
        "--kill-on-exit",
        "-f",
        "-yy",
        "-ttt",
        "-T",
        "--no-abbrev",
        "--string-limit=1048576",
        "--quiet=none",
        "--trace=all",
        "--raw=read,readv,pread64,preadv,preadv2,write,writev,pwrite64,pwritev,pwritev2,sendfile,splice,vmsplice,tee,copy_file_range",
        "--output=/proc/self/fd/{output_fd}",
    )
    assert getattr(trace_module, "STRACE_ARGUMENT_TEMPLATE", None) == expected
    builder = getattr(trace_module, "strace_arguments_for_output_fd", None)
    assert callable(builder)
    assert builder(17) == (*expected[:-1], "--output=/proc/self/fd/17")
    for invalid in (True, False, -1, 0, 1, 2, "17", "17 --trace=none", 2**31):
        with pytest.raises((TypeError, ValueError)):
            builder(invalid)
    row = json.loads(POLICY.read_text(encoding="utf-8"))["rows"][0]
    assert tuple(row["argv"]["options"]) == expected


def test_exact_strace_6_6_dedicated_output_framing_accepts_short_and_wide_pids():
    source = _line(7, "getpid() = 7 <0.000001>") + _line(
        12345, "getpid() = 12345 <0.000001>", "1700000040.000002"
    )
    records = normalize_bytes(source)
    assert [record["pid"] for record in records] == [7, 12345]


@pytest.mark.parametrize(
    "source",
    [
        b"7 1700000040.000001 getpid() = 7 <0.000001>\n",
        b"[pid     7] 1700000040.000001 getpid() = 7 <0.000001>\n",
        b"    7 1700000040.000001 getpid() = 7 <0.000001>\n",
    ],
)
def test_unpinned_or_ambiguous_pid_framing_is_rejected(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


@pytest.mark.parametrize(
    ("annotation", "protocol"),
    [
        ("TCP:[127.0.0.1:41000->127.0.0.1:7400]", "TCP"),
        ("TCPv6:[[::1]:41001->[::1]:7400]", "TCPv6"),
        ("UDP:[127.0.0.1:41002->127.0.0.1:7401]", "UDP"),
        ("UDPv6:[[::1]:41003->[::1]:7401]", "UDPv6"),
        ('UNIX:[101->202,"/tmp/FD_PATH_SECRET.sock"]', "UNIX"),
        ("NETLINK:[ROUTE:4321]", "NETLINK"),
    ],
)
def test_real_strace_yy_socket_annotations_are_redacted_but_keep_protocol(
    annotation, protocol
):
    record = normalize_bytes(_line(71, f"close(9<{annotation}>) = 0 <0.000001>"))[0]
    provenance = record["transition"]["fd"]["provenance"]
    assert provenance == {"kind": "socket", "protocol": protocol}
    rendered = canonical_ndjson([record])
    for secret in ("127.0.0.1", "41000", "::1", "/tmp", "FD_PATH_SECRET", "4321"):
        assert secret not in rendered


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP",
            {"domain": "AF_INET", "type": "SOCK_STREAM", "protocol": "IPPROTO_IP"},
        ),
        (
            "AF_INET6, SOCK_RAW, IPPROTO_RAW",
            {"domain": "AF_INET6", "type": "SOCK_RAW", "protocol": "IPPROTO_RAW"},
        ),
        (
            "AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE",
            {"domain": "AF_NETLINK", "type": "SOCK_RAW", "protocol": "NETLINK_ROUTE"},
        ),
    ],
)
def test_valid_policy_prohibited_socket_attempts_still_normalize(arguments, expected):
    record = normalize_bytes(
        _line(
            72, f"socket({arguments}) = -1 EPERM (Operation not permitted) <0.000001>"
        )
    )[0]
    transition = record["transition"]
    assert {key: transition[key] for key in expected} == expected
    assert transition["operation"] == "socket"


def test_malformed_non_strace_socket_tokens_still_fail_closed():
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            _line(
                72,
                "socket(AF_INET;PAYLOAD_SENTINEL, SOCK_STREAM, IPPROTO_TCP) "
                "= -1 EPERM (Operation not permitted) <0.000001>",
            )
        )


def _rights_line(pid: int = 73, timestamp: str = "1700000041.000001") -> bytes:
    return _line(
        pid,
        "recvmsg(4<socket:[44]>, {msg_name=NULL, msg_namelen=0, msg_iov=[], "
        "msg_iovlen=0, msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, "
        "cmsg_type=SCM_RIGHTS, cmsg_data=[8<socket:[88]>]}], "
        "msg_controllen=24, msg_flags=0}, 0) = 1 <0.000001>",
        timestamp,
    )


def test_record_sink_observes_valid_rights_record_before_later_same_chunk_failure():
    _require_record_sink()
    seen = []
    parser = TraceNormalizer(record_sink=seen.append)
    source = _rights_line() + _line(73, "NOT_A_SYSCALL", "1700000041.000002")
    with pytest.raises(TraceDecodeError) as first:
        parser.feed(source)
    assert len(seen) == 1
    assert seen[0]["control"]["scm_rights"] == [
        [{"fd": 8, "provenance": {"inode": 88, "kind": "socket"}}]
    ]
    for operation in (
        lambda: parser.feed(_line(73, "getpid() = 73 <0.000001>")),
        parser.finish,
    ):
        with pytest.raises(TraceDecodeError) as later:
            operation()
        assert str(later.value) == str(first.value)
    assert len(seen) == 1


@pytest.mark.parametrize("cut", [0, 1, 5, 64, 127, 255])
def test_record_sink_chunk_boundaries_have_no_duplicates(cut):
    _require_record_sink()
    source = _rights_line() + _line(73, "getpid() = 73 <0.000001>", "1700000041.000002")
    cut = min(cut, len(source))
    seen = []
    parser = TraceNormalizer(record_sink=seen.append)
    parser.feed(source[:cut])
    parser.feed(source[cut:])
    parser.finish()
    assert [record["record_index"] for record in seen] == [0, 1]


def test_record_sink_failure_is_terminal_redacted_and_never_retried():
    _require_record_sink()
    seen = []

    def failing_sink(record):
        seen.append(record)
        raise RuntimeError("SINK_SECRET")

    parser = TraceNormalizer(record_sink=failing_sink)
    with pytest.raises(TraceDecodeError) as first:
        parser.feed(_rights_line())
    assert "SINK_SECRET" not in str(first.value)
    assert len(seen) == 1
    with pytest.raises(TraceDecodeError) as later:
        parser.finish()
    assert str(later.value) == str(first.value)
    assert len(seen) == 1


@pytest.mark.parametrize(
    ("body", "operation"),
    [
        (
            "accept(-1, 0x7fff0000, 0x7fff0010) = -1 EBADF (Bad file descriptor) <0.000001>",
            "accept",
        ),
        (
            "accept4(-1, 0x7fff0000, 0x7fff0010, SOCK_CLOEXEC) "
            "= -1 EBADF (Bad file descriptor) <0.000001>",
            "accept4",
        ),
        (
            "getsockname(-1, 0x7fff0000, 0x7fff0010) "
            "= -1 EBADF (Bad file descriptor) <0.000001>",
            "getsockname",
        ),
    ],
)
def test_failed_socket_output_pointer_forms_preserve_attempt_without_effect(
    body, operation
):
    record = normalize_bytes(_line(74, body))[0]
    assert record["transition"] == {"operation": operation, "fd": {"fd": -1}}
    assert record["result"]["errno"] == "EBADF"


def test_failed_recvfrom_output_pointers_and_negative_fd_are_structural():
    record = normalize_bytes(
        _line(
            74,
            "recvfrom(-1, 0x7fff0000, 64, 0, 0x7fff0100, 0x7fff0110) "
            "= -1 EBADF (Bad file descriptor) <0.000001>",
        )
    )[0]
    assert record["fds"] == [{"fd": -1}]
    assert record["lengths"] == {"count": 64}
    assert "address" not in record


@pytest.mark.parametrize(
    ("message", "expected_lengths"),
    [("0x7fff0000", None), ("{msg_namelen=16}", {"name_length": 16})],
)
def test_failed_recvmsg_pointer_and_restricted_partial_forms(message, expected_lengths):
    record = normalize_bytes(
        _line(
            74,
            f"recvmsg(-1, {message}, MSG_DONTWAIT) "
            "= -1 EBADF (Bad file descriptor) <0.000001>",
        )
    )[0]
    assert record["fds"] == [{"fd": -1}]
    assert record["flags"] == ["MSG_DONTWAIT"]
    if expected_lengths is None:
        assert "lengths" not in record
    else:
        assert record["lengths"] == expected_lengths


@pytest.mark.parametrize(
    ("restart", "text"),
    [
        ("ERESTARTSYS", "To be restarted if SA_RESTART is set"),
        ("ERESTARTNOINTR", "To be restarted"),
        ("ERESTARTNOHAND", "To be restarted if no handler"),
        ("ERESTART_RESTARTBLOCK", "Interrupted by signal"),
    ],
)
def test_closed_restart_family_is_policy_visible(restart, text):
    record = normalize_bytes(
        _line(
            75,
            "recvfrom(3<TCP:[127.0.0.1:7400]>, 0x7fff0000, 64, 0, NULL, NULL) "
            f"= ? {restart} ({text}) <0.000001>",
        )
    )[0]
    assert record["result"] == {"interrupted": True, "restart": restart}
    assert record["fds"][0]["provenance"] == {"kind": "socket", "protocol": "TCP"}


def test_recvmmsg_left_timeout_suffix_is_structured():
    record = normalize_bytes(
        _line(
            76,
            "recvmmsg(3<UDP:[127.0.0.1:7400]>, [{msg_hdr={msg_name=NULL, "
            "msg_namelen=0, msg_iov=[], msg_iovlen=0, msg_control=NULL, "
            "msg_controllen=0, msg_flags=0}, msg_len=0}], 1, 0, "
            "{tv_sec=1, tv_nsec=0}) = 1 (left {tv_sec=0, tv_nsec=12345678}) <0.000001>",
        )
    )[0]
    assert record["result"] == {
        "value": 1,
        "timeout_left": {"seconds": 0, "nanoseconds": 12345678},
    }


def test_partial_sendmmsg_retains_all_endpoints_and_rights_but_only_completed_lengths():
    source = _line(
        77,
        "sendmmsg(3<UDP:[127.0.0.1:7400]>, [{msg_hdr={msg_name={sa_family=AF_INET, "
        'sin_port=htons(7400), sin_addr=inet_addr("192.0.2.10")}, msg_namelen=16, '
        "msg_iov=[], msg_iovlen=0, msg_control=NULL, msg_controllen=0, msg_flags=0}, "
        "msg_len=8}, {msg_hdr={msg_name={sa_family=AF_INET6, sin6_port=htons(7401), "
        'sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::2", &sin6_addr), '
        "sin6_scope_id=0}, msg_namelen=28, msg_iov=[], msg_iovlen=0, "
        "msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, "
        "cmsg_data=[9<TCP:[127.0.0.1:9]>]}], msg_controllen=24, msg_flags=0}}], "
        "2, 0) = 1 <0.000001>",
    )
    record = normalize_bytes(source)[0]
    assert record["lengths"] == {"message_count": 1, "requested_message_count": 2}
    assert [message["address"]["ip"] for message in record["messages"]] == [
        "192.0.2.10",
        "2001:db8::2",
    ]
    assert record["messages"][1]["control"]["scm_rights"] == [
        [{"fd": 9, "provenance": {"kind": "socket", "protocol": "TCP"}}]
    ]


def test_vfork_success_has_copied_fd_table_and_clone_files_alone_is_shared():
    records = normalize_bytes(
        _line(78, "vfork() = 79 <0.000001>")
        + _line(
            78,
            "clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = 80 <0.000001>",
            "1700000040.000002",
        )
    )
    assert records[0]["transition"]["fd_table"] == "copied"
    assert records[1]["transition"]["fd_table"] == "shared"
