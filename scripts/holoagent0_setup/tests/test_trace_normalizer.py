import hashlib
import json
import math
from pathlib import Path
import re

import pytest

from holoagent0_setup.trace_normalizer import (
    DECODED_ADDRESS_SYSCALLS,
    RAW_PAYLOAD_SYSCALLS,
    STRACE_ARGUMENTS,
    STRACE_ENVIRONMENT,
    TraceDecodeError,
    TraceNormalizer as _TraceNormalizer,
    canonical_ndjson,
    normalize_bytes as _normalize_bytes,
)


ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
FIXTURES = ROOT / "fixtures/strace"
SENTINELS = (
    "PAYLOAD_SENTINEL",
    "FRAGMENTED_SECRET",
    "SOCKET_SECRET",
    "CONTROL_SECRET",
    "FD_PATH_SECRET",
    "EXEC_PATH_SECRET",
    "EXEC_ARG_SECRET",
    "RIGHTS_SECRET",
    "SPOOF_SECRET",
)


def _align_reviewed_results(source: bytes) -> bytes:
    lines = []
    for line in source.splitlines(keepends=True):
        ending = b"\n" if line.endswith(b"\n") else b""
        body = line[: -len(ending)] if ending else line
        match = re.fullmatch(rb"(.*\))( +)= (.*)", body)
        if match is not None:
            body = (
                match.group(1)
                + b" " * max(1, 40 - len(match.group(1)))
                + b"= "
                + match.group(3)
            )
        lines.append(body + ending)
    return b"".join(lines)


def normalize_bytes(source: bytes, **bounds):
    return _normalize_bytes(_align_reviewed_results(source), **bounds)


class TraceNormalizer(_TraceNormalizer):
    def _decode_line(self, encoded: bytes):
        return super()._decode_line(_align_reviewed_results(encoded))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _strict_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def _load_json(path: Path):
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_strict_object_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def test_fixture_manifest_is_closed_canonical_digest_bound_and_complete():
    manifest_path = FIXTURES / "manifest-v1.json"
    manifest = _load_json(manifest_path)
    assert (
        manifest_path.read_bytes()
        == (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    assert set(manifest) == {"$id", "schema_version", "cases", "additionalProperties"}
    assert manifest["additionalProperties"] is False
    names = [case["name"] for case in manifest["cases"]]
    assert len(names) == len(set(names)) == 14
    declared = {"manifest-v1.json"}
    for case in manifest["cases"]:
        allowed = {
            "name",
            "input",
            "input_sha256",
            "expected",
            "expected_sha256",
            "record_count",
            "reject",
        }
        assert set(case) <= allowed
        assert set(case) >= {"name", "input", "input_sha256", "record_count", "reject"}
        input_path = FIXTURES / case["input"]
        assert input_path.is_file() and not input_path.is_symlink()
        assert _sha256(input_path) == case["input_sha256"]
        declared.add(case["input"])
        if case["reject"]:
            assert "expected" not in case and "expected_sha256" not in case
        else:
            expected_path = FIXTURES / case["expected"]
            assert expected_path.is_file() and not expected_path.is_symlink()
            assert _sha256(expected_path) == case["expected_sha256"]
            assert len(expected_path.read_text().splitlines()) == case["record_count"]
            declared.add(case["expected"])
    assert declared == {path.name for path in FIXTURES.iterdir()}


def test_manifest_cases_match_exact_canonical_output_without_payload_leakage():
    manifest = _load_json(FIXTURES / "manifest-v1.json")
    for case in manifest["cases"]:
        source = (FIXTURES / case["input"]).read_bytes()
        if case["reject"]:
            with pytest.raises(TraceDecodeError) as caught:
                normalize_bytes(source)
            rendered = str(caught.value)
        else:
            records = normalize_bytes(source)
            rendered = canonical_ndjson(records)
            assert rendered.encode() == (FIXTURES / case["expected"]).read_bytes()
        assert not any(secret in rendered for secret in SENTINELS)


def test_cyclonedds_0_10_5_runtime_representative_golden_is_exact_and_payload_free():
    # Sanitized deterministic reconstruction of the observed 0.10.5 syscall
    # structure; it is intentionally not represented as byte-for-byte raw strace.
    stem = "cyclonedds-0.10.5-runtime-representative"
    source = (FIXTURES / f"{stem}.input").read_bytes()
    expected = (FIXTURES / f"{stem}.expected.ndjson").read_bytes()
    records = normalize_bytes(source)
    target_records = [json.loads(line) for line in expected.splitlines()]

    assert canonical_ndjson(target_records).encode() == expected
    assert [
        (
            record["pid"],
            record["transition"]["fd"]["fd"],
            record["transition"]["level"],
            record["transition"]["option"],
            record["transition"]["value"],
            record["transition"]["length"],
        )
        for record in target_records
        if record.get("syscall") == "setsockopt"
        and record["transition"]["option"].startswith("IP_MULTICAST_")
    ] == [
        (100, 11, "SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
        (100, 11, "SOL_IP", "IP_MULTICAST_TTL", 1, 1),
        (100, 11, "SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
        (101, 21, "SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
        (101, 21, "SOL_IP", "IP_MULTICAST_TTL", 1, 1),
        (101, 21, "SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
    ]
    assert canonical_ndjson(records).encode() == expected
    assert b"RTPS" not in source and b"SECRET" not in source
    assert [
        record["transition"]["address"]["port"]
        for record in records
        if record.get("syscall") == "bind"
    ] == [26650, 26651, 26660, 26661, 0, 0]
    assert [
        record["transition"]["address"]["port"]
        for record in records
        if record.get("syscall") == "getsockname"
    ] == [40000, 40001]
    setup_options = [
        record
        for record in records
        if record.get("syscall") == "setsockopt"
        and record["transition"]["option"].startswith("IP_MULTICAST_")
    ]
    assert [
        (
            record["pid"],
            record["transition"]["fd"]["fd"],
            record["transition"]["level"],
            record["transition"]["option"],
            record["transition"]["value"],
            record["transition"]["length"],
        )
        for record in setup_options
    ] == [
        (100, 11, "SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
        (100, 11, "SOL_IP", "IP_MULTICAST_TTL", 1, 1),
        (100, 11, "SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
        (101, 21, "SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
        (101, 21, "SOL_IP", "IP_MULTICAST_TTL", 1, 1),
        (101, 21, "SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
    ]
    assert [
        record["transition"]["fd"]["fd"]
        for record in records
        if record.get("syscall") == "setsockopt"
        and record["transition"]["option"] == "IP_ADD_MEMBERSHIP"
    ] == [7, 8]

    for pid, fd in ((100, 11), (101, 21)):
        registration = [
            record
            for record in records
            if record.get("pid") == pid
            and (
                record.get("syscall") in {"bind", "getsockname"}
                or (
                    record.get("syscall") == "setsockopt"
                    and record["transition"]["option"].startswith("IP_MULTICAST_")
                )
            )
            and record["transition"]["fd"]["fd"] == fd
        ]
        assert [record["syscall"] for record in registration] == [
            "bind",
            "setsockopt",
            "setsockopt",
            "setsockopt",
            "getsockname",
        ]
        assert [record["transition"].get("option") for record in registration[1:4]] == [
            "IP_MULTICAST_IF",
            "IP_MULTICAST_TTL",
            "IP_MULTICAST_LOOP",
        ]
        registered_at = registration[-1]["record_index"]
        assert all(
            record["record_index"] > registered_at
            for record in records
            if record.get("fds")
            and record["fds"][0]["fd"] == fd
            and record.get("syscall")
            in {
                "connect",
                "read",
                "readv",
                "recvfrom",
                "recvmsg",
                "sendto",
                "sendmsg",
                "write",
                "writev",
            }
        )

    clones = [record for record in records if record.get("syscall") == "clone"]
    assert [record["transition"]["child_pid"] for record in clones] == [1100, 1101]
    assert all(
        {"CLONE_THREAD", "CLONE_FILES"} <= set(record["transition"]["flags"])
        for record in clones
    )
    sends = [record for record in records if record.get("syscall") == "sendto"]
    assert {(record["pid"], record["fds"][0]["fd"]) for record in sends} == {
        (1100, 11),
        (1101, 21),
    }
    assert {record["address"]["port"] for record in sends} == {
        26650,
        26660,
        26661,
        26662,
        26663,
    }
    assert all(record["address"]["port"] != 26651 for record in sends)
    assert {
        record["address"]["port"]
        for record in records
        if record.get("syscall") == "recvfrom"
    } == {40001}
    end_index = next(
        record["record_index"]
        for record in records
        if record.get("marker", {}).get("phase") == "END"
    )
    exits = [record for record in records if record.get("kind") == "exit"]
    assert [(record["pid"], record["exit_code"]) for record in exits] == [
        (1100, 0),
        (1101, 0),
        (100, 0),
        (101, 0),
    ]
    closes = [record for record in records if record.get("syscall") == "close"]
    assert [
        (record["pid"], record["transition"]["closed_fd"]["fd"]) for record in closes
    ] == [(100, 7), (100, 8), (100, 9), (100, 10), (100, 11), (101, 21)]
    assert max(record["record_index"] for record in exits + closes) < end_index
    assert not any(
        record.get("syscall") in {"wait4", "waitid", "waitpid"} for record in records
    )


@pytest.mark.parametrize(
    ("option", "argument", "length", "expected_value"),
    [
        ("IP_MULTICAST_IF", 'inet_addr("127.0.0.1")', 4, "127.0.0.1"),
        ("IP_MULTICAST_TTL", "[1]", 1, 1),
        ("IP_MULTICAST_LOOP", "[1]", 1, 1),
    ],
)
def test_cyclonedds_tx_setup_option_values_are_canonical_and_payload_free(
    option, argument, length, expected_value
):
    source = (
        "100   1700000070.000001 "
        f"setsockopt(11<UDP:[127.0.0.1:0]>, SOL_IP, {option}, "
        f"{argument}, {length}) = 0 <0.000001>\n"
    ).encode()

    (record,) = normalize_bytes(source)

    assert record["transition"] == {
        "operation": "setsockopt",
        "fd": {"fd": 11, "provenance": {"kind": "socket", "protocol": "UDP"}},
        "level": "SOL_IP",
        "option": option,
        "value": expected_value,
        "length": length,
    }
    assert argument not in canonical_ndjson([record])


def test_exact_reviewed_invocation_and_platform_contract():
    assert STRACE_ARGUMENTS == (
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
    assert STRACE_ENVIRONMENT == {"LC_ALL": "C", "TZ": "UTC"}
    assert RAW_PAYLOAD_SYSCALLS == frozenset(
        {
            "read",
            "readv",
            "pread64",
            "preadv",
            "preadv2",
            "write",
            "writev",
            "pwrite64",
            "pwritev",
            "pwritev2",
            "sendfile",
            "splice",
            "vmsplice",
            "tee",
            "copy_file_range",
        }
    )
    assert DECODED_ADDRESS_SYSCALLS == frozenset(
        {"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
    )


def test_payload_text_cannot_spoof_endpoint_or_scm_rights_metadata():
    source = (
        "301   1700000020.000001 sendmsg(7<socket:[7]>, "
        '{msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="SPOOF_SECRET '
        'sa_family=AF_INET, sin_port=htons(31337), sin_addr=inet_addr(\\"203.0.113.9\\") '
        'cmsg_type=SCM_RIGHTS, cmsg_data=[99</secret>]}", iov_len=160}], msg_iovlen=1, '
        "msg_control=NULL, msg_controllen=0, msg_flags=0}, 0) = 1 <0.000001>\n"
    ).encode()
    rendered = canonical_ndjson(normalize_bytes(source))
    record = json.loads(rendered)
    assert "address" not in record and "control" not in record
    assert "203.0.113.9" not in rendered
    assert "SPOOF_SECRET" not in rendered and "secret" not in rendered


@pytest.mark.parametrize("name", ["sendmmsg", "recvmmsg"])
def test_message_vectors_preserve_every_structural_endpoint_and_rights_group(name):
    timeout = ", NULL" if name == "recvmmsg" else ""
    source = (
        f"302   1700000020.000002 {name}(8<socket:[8]>, ["
        "{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), "
        'sin_addr=inet_addr("192.0.2.10")}, msg_namelen=16, msg_iov=[], msg_iovlen=0, '
        "msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, "
        "cmsg_data=[9</private/a>]}, {cmsg_len=20, cmsg_level=SOL_SOCKET, "
        "cmsg_type=SCM_RIGHTS, cmsg_data=[10<socket:[10]>]}], msg_controllen=48, "
        "msg_flags=0}, msg_len=0}, {msg_hdr={msg_name={sa_family=AF_INET6, "
        "sin6_port=htons(443), sin6_flowinfo=htonl(0), "
        'inet_pton(AF_INET6, "2001:db8::2", &sin6_addr), sin6_scope_id=0}, '
        "msg_namelen=28, msg_iov=[], msg_iovlen=0, msg_control=NULL, "
        "msg_controllen=0, msg_flags=0}, msg_len=0}], 2, 0"
        + timeout
        + ") = 2 <0.000002>\n"
    ).encode()
    record = normalize_bytes(source)[0]
    assert [message["address"]["ip"] for message in record["messages"]] == [
        "192.0.2.10",
        "2001:db8::2",
    ]
    assert record["messages"][0]["control"]["scm_rights"] == [
        [{"fd": 9, "provenance": {"kind": "path"}}],
        [{"fd": 10, "provenance": {"inode": 10, "kind": "socket"}}],
    ]
    assert "private" not in canonical_ndjson([record])


@pytest.mark.parametrize(
    ("name", "arguments", "expected_fds", "length_key", "length"),
    [
        ("read", "0x3, 0x7fff0000, 0x10", [3], "count", 16),
        ("readv", "0x3, 0x7fff0000, 0x2", [3], "iov_count", 2),
        ("pread64", "0x3, 0x7fff0000, 0x10, 0x20", [3], "count", 16),
        ("preadv", "0x3, 0x7fff0000, 0x2, 0x20", [3], "iov_count", 2),
        ("preadv2", "0x3, 0x7fff0000, 0x2, 0x20, 0, 0x8", [3], "iov_count", 2),
        ("write", "0x4, 0x7fff0000, 0x10", [4], "count", 16),
        ("writev", "0x4, 0x7fff0000, 0x2", [4], "iov_count", 2),
        ("pwrite64", "0x4, 0x7fff0000, 0x10, 0x20", [4], "count", 16),
        ("pwritev", "0x4, 0x7fff0000, 0x2, 0x20", [4], "iov_count", 2),
        ("pwritev2", "0x4, 0x7fff0000, 0x2, 0x20, 0, 0x2", [4], "iov_count", 2),
        ("sendfile", "0x4, 0x3, 0, 0x10", [4, 3], "count", 16),
        ("splice", "0x3, 0, 0x4, 0, 0x10, 0x1", [3, 4], "count", 16),
        ("vmsplice", "0x4, 0x7fff0000, 0x2, 0x2", [4], "iov_count", 2),
        ("tee", "0x3, 0x4, 0x10, 0x2", [3, 4], "count", 16),
        ("copy_file_range", "0x3, 0, 0x4, 0, 0x10, 0", [3, 4], "count", 16),
    ],
)
def test_exact_raw_hex_grammar_preserves_all_fd_operands(
    name, arguments, expected_fds, length_key, length
):
    source = f"303   1700000021.000001 {name}({arguments}) = 0x10 <0.000001>\n".encode()
    record = normalize_bytes(source)[0]
    assert [item["fd"] for item in record["fds"]] == expected_fds
    assert record["lengths"][length_key] == length
    assert record["result"]["value"] == 16
    assert "private" not in canonical_ndjson([record])


@pytest.mark.parametrize(
    "source",
    [
        b"303   1.0 sendfile(0x4, 0x7fff0000, 0x10) = 0x10 <0.1>\n",
        b'303   1.0 read(0x3, "decoded payload", 0x10) = 0x10 <0.1>\n',
        b"303   1.0 splice(0x3, 0, 0x4, 0x10, 0x1) = 0x10 <0.1>\n",
        b"303   1.0 write(77</tmp/annotated>, 0x7fff0000, 0x4) = 0x4 <0.1>\n",
    ],
)
def test_malformed_raw_shapes_fail_closed_without_fallback(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_fd_and_process_transitions_are_structured_and_path_secret_free():
    source = b"".join(
        line + b"\n"
        for line in [
            b"400   2.000001 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3<socket:[33]> <0.1>",
            b"400   2.000002 socketpair(AF_UNIX, SOCK_STREAM, 0, [4<socket:[44]>, 5<socket:[55]>]) = 0 <0.1>",
            b'400   2.000003 accept(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.3")}, [16]) = 6<socket:[66]> <0.1>',
            b'400   2.000004 accept4(3<socket:[33]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::3", &sin6_addr), sin6_scope_id=0}, [28], SOCK_CLOEXEC) = 7<socket:[77]> <0.1>',
            b'400   2.000005 bind(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.1>',
            b'400   2.000006 connect(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.53")}, 16) = 0 <0.1>',
            b'400   2.000007 getsockname(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0 <0.1>',
            b"400   2.000008 dup(3</private/SECRET_PATH>) = 8</private/SECRET_PATH> <0.1>",
            b"400   2.000009 dup2(3</private/SECRET_PATH>, 9) = 9</private/SECRET_PATH> <0.1>",
            b"400   2.000010 dup3(3</private/SECRET_PATH>, 10, O_CLOEXEC) = 10</private/SECRET_PATH> <0.1>",
            b"400   2.000011 fcntl(3</private/SECRET_PATH>, F_DUPFD_CLOEXEC, 11) = 11</private/SECRET_PATH> <0.1>",
            b"400   2.000012 fork() = 500 <0.1>",
            b"400   2.000013 vfork() = 501 <0.1>",
            b"400   2.000014 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = 502 <0.1>",
            b'400   2.000015 execve("/private/SECRET_PATH", ["SECRET_ARG"], 0x7fff0000) = 0 <0.1>',
            b"400   2.000016 close(8</private/SECRET_PATH>) = 0 <0.1>",
            b"400   2.000017 close_range(3, 4294967295, CLOSE_RANGE_CLOEXEC) = 0 <0.1>",
            b"400   2.000018 unshare(CLONE_FILES) = 0 <0.1>",
            b"400   2.000019 pidfd_getfd(11<anon_inode:[pidfd]>, 3, 0) = 12</private/SECRET_PATH> <0.1>",
        ]
    )
    records = normalize_bytes(source)
    operations = [record["transition"]["operation"] for record in records]
    assert operations == [
        "socket",
        "socketpair",
        "accept",
        "accept4",
        "bind",
        "connect",
        "getsockname",
        "dup",
        "dup2",
        "dup3",
        "fcntl_dup",
        "fork",
        "vfork",
        "clone",
        "exec",
        "close",
        "close_range",
        "unshare_files",
        "pidfd_getfd",
    ]
    assert records[1]["transition"]["created_fds"] == [
        {"fd": 4, "provenance": {"inode": 44, "kind": "socket"}},
        {"fd": 5, "provenance": {"inode": 55, "kind": "socket"}},
    ]
    assert records[13]["transition"]["fd_table"] == "shared"
    assert records[-1]["result"]["fd"]["provenance"] == {"kind": "path"}
    rendered = canonical_ndjson(records)
    assert "SECRET_PATH" not in rendered and "SECRET_ARG" not in rendered


def test_malformed_policy_relevant_transition_fails_closed():
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b"1     1.0 socketpair(AF_UNIX, SOCK_STREAM, 0, SECRET) = 0 <0.1>\n"
        )


@pytest.mark.parametrize(
    ("source", "operation", "required"),
    [
        (
            b"410   3.000001 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = -1 EMFILE (Too many open files) <0.1>\n",
            "socket",
            {"domain": "AF_INET", "protocol": "IPPROTO_TCP"},
        ),
        (
            b"410   3.000002 socketpair(AF_UNIX, SOCK_STREAM, 0, 0x7fff0000) = -1 EMFILE (Too many open files) <0.1>\n",
            "socketpair",
            {"domain": "AF_UNIX", "protocol": 0},
        ),
        (
            b"410   3.000003 accept(3<socket:[33]>, NULL, NULL) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "accept",
            {"source_fd": {"fd": 3, "provenance": {"kind": "socket", "inode": 33}}},
        ),
        (
            b"410   3.000004 accept4(3<socket:[33]>, NULL, NULL, SOCK_CLOEXEC) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "accept4",
            {"flags": ["SOCK_CLOEXEC"]},
        ),
        (
            b"410   3.000005 dup(3</private/FAIL_SECRET>) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "dup",
            {"source_fd": {"fd": 3, "provenance": {"kind": "path"}}},
        ),
        (
            b"410   3.000006 dup2(3</private/FAIL_SECRET>, 9) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "dup2",
            {"target_fd": {"fd": 9}},
        ),
        (
            b"410   3.000007 dup3(3</private/FAIL_SECRET>, 10, O_CLOEXEC) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "dup3",
            {"flags": ["O_CLOEXEC"]},
        ),
        (
            b"410   3.000008 fcntl(3</private/FAIL_SECRET>, F_DUPFD_CLOEXEC, 11) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "fcntl_dup",
            {"minimum_fd": 11, "cloexec": True},
        ),
        (
            b"410   3.000009 fcntl(3</private/FAIL_SECRET>, F_DUPFD, 11) = -1 EBADF (Bad file descriptor) <0.1>\n",
            "fcntl_dup",
            {"minimum_fd": 11, "cloexec": False},
        ),
        (
            b"410   3.000010 fork() = -1 EAGAIN (Resource temporarily unavailable) <0.1>\n",
            "fork",
            {},
        ),
        (
            b"410   3.000011 vfork() = -1 EAGAIN (Resource temporarily unavailable) <0.1>\n",
            "vfork",
            {},
        ),
        (
            b"410   3.000012 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable) <0.1>\n",
            "clone",
            {"flags": ["CLONE_VM", "CLONE_FILES", "SIGCHLD"]},
        ),
        (
            b"410   3.000013 pidfd_getfd(11<anon_inode:[pidfd]>, 3, 0) = -1 EPERM (Operation not permitted) <0.1>\n",
            "pidfd_getfd",
            {"target_fd": 3},
        ),
    ],
)
def test_failed_fd_and_process_attempts_remain_policy_visible_without_mutation(
    source, operation, required
):
    record = normalize_bytes(source)[0]
    assert record["result"]["value"] == -1
    assert record["transition"]["operation"] == operation
    assert record["transition"] | required == record["transition"]
    assert "created_fd" not in record["transition"]
    assert "created_fds" not in record["transition"]
    assert "child_pid" not in record["transition"]
    assert "fd_table" not in record["transition"]
    assert "FAIL_SECRET" not in canonical_ndjson([record])


def test_failed_pidfd_getfd_is_classifiable_as_prohibited_fd_acquisition():
    record = normalize_bytes(
        b"411   3.1 pidfd_getfd(11<anon_inode:[pidfd]>, 7, 0) = -1 EPERM (Operation not permitted) <0.1>\n"
    )[0]
    reason = (
        "PROHIBITED_FD_ACQUISITION"
        if record["transition"]["operation"] == "pidfd_getfd"
        else "TRACE_DECODE_FAILED"
    )
    assert reason == "PROHIBITED_FD_ACQUISITION"
    assert record["transition"] == {
        "operation": "pidfd_getfd",
        "pidfd": {
            "fd": 11,
            "provenance": {"kind": "anon_inode", "type": "pidfd"},
        },
        "target_fd": 7,
    }


def test_upstream_strace_6_6_ipv6_sockaddr_form_is_exact_and_structured():
    # Derived verbatim from strace-6.6 tests/net-sockaddr.c::check_in6.
    source = (
        b"412   3.2 connect(3<socket:[33]>, {sa_family=AF_INET6, "
        b"sin6_port=htons(12345), sin6_flowinfo=htonl(1234567890), "
        b'inet_pton(AF_INET6, "12:34:56:78:90:ab:cd:ef", &sin6_addr), '
        b"sin6_scope_id=4207869677}, 28) = 0 <0.1>\n"
    )
    record = normalize_bytes(source)[0]
    assert record["transition"]["address"] == {
        "family": "AF_INET6",
        "port": 12345,
        "flowinfo": 1234567890,
        "ip": "12:34:56:78:90:ab:cd:ef",
        "scope_id": 4207869677,
    }


def test_synthetic_ipv6_sockaddr_form_is_not_reviewed():
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b'412   3.3 connect(3<socket:[33]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2001:db8::3")}, 28) = 0 <0.1>\n'
        )


@pytest.mark.parametrize(
    ("protocol", "expected"),
    [("0", 0), ("IPPROTO_UDP", "IPPROTO_UDP"), ("IPPROTO_TCP", "IPPROTO_TCP")],
)
def test_socket_protocol_provenance_remains_distinct(protocol, expected):
    record = normalize_bytes(
        f"413   3.4 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, {protocol}) = 4<socket:[44]> <0.1>\n".encode()
    )[0]
    assert record["transition"]["protocol"] == expected


def test_socketpair_protocol_provenance_is_retained():
    record = normalize_bytes(
        b"413   3.5 socketpair(AF_UNIX, SOCK_STREAM, 0, [4<socket:[44]>, 5<socket:[55]>]) = 0 <0.1>\n"
    )[0]
    assert record["transition"]["protocol"] == 0


@pytest.mark.parametrize(
    "source",
    [
        b"413   3.6 socket(DOMAIN_SECRET, SOCK_STREAM, 0) = 4<socket:[44]> <0.1>\n",
        b"413   3.6 socket(AF_INET, TYPE_SECRET, 0) = 4<socket:[44]> <0.1>\n",
        b"413   3.6 socket(AF_INET, SOCK_STREAM, PROTOCOL_SECRET) = 4<socket:[44]> <0.1>\n",
        b"413   3.6 socket(AF_INET, SOCK_STREAM|PAYLOAD_SECRET, 0) = 4<socket:[44]> <0.1>\n",
    ],
)
def test_socket_domain_type_and_protocol_reject_unreviewed_tokens(source):
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(source)
    assert "SECRET" not in str(caught.value)


def test_fcntl_getfd_setfd_dup_and_closed_non_fd_commands_are_structured():
    source = b"".join(
        line + b"\n"
        for line in [
            b"414   3.700001 fcntl(3</private/FCNTL_SECRET>, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.1>",
            b"414   3.700002 fcntl(3</private/FCNTL_SECRET>, F_SETFD, 0) = 0 <0.1>",
            b"414   3.700003 fcntl(3</private/FCNTL_SECRET>, F_SETFD, FD_CLOEXEC) = 0 <0.1>",
            b"414   3.700004 fcntl(3</private/FCNTL_SECRET>, F_GETFL) = 0x8002 (flags O_RDWR|O_LARGEFILE) <0.1>",
            b"414   3.700005 fcntl(3</private/FCNTL_SECRET>, F_SETFL, O_NONBLOCK) = 0 <0.1>",
            b"414   3.700006 fcntl(3</private/FCNTL_SECRET>, F_DUPFD, 12) = 12</private/FCNTL_SECRET> <0.1>",
        ]
    )
    records = normalize_bytes(source)
    assert [record["transition"]["operation"] for record in records] == [
        "fcntl_getfd",
        "fcntl_setfd",
        "fcntl_setfd",
        "fcntl_getfl",
        "fcntl_setfl",
        "fcntl_dup",
    ]
    assert records[0]["transition"]["cloexec"] is True
    assert records[0]["result"] == {"value": 1, "flags": ["FD_CLOEXEC"]}
    assert records[1]["transition"]["cloexec"] is False
    assert records[2]["transition"]["cloexec"] is True
    assert records[3]["result"] == {
        "value": 32770,
        "flags": ["O_RDWR", "O_LARGEFILE"],
    }
    assert records[4]["transition"]["status_flags"] == ["O_NONBLOCK"]
    assert records[5]["transition"]["created_fd"]["fd"] == 12
    assert "FCNTL_SECRET" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    "source",
    [
        b"414   3.8 fcntl(3, F_UNKNOWN_FD_COMMAND, 0) = 4 <0.1>\n",
        b"414   3.8 fcntl(3, F_GETOWN) = 7 <0.1>\n",
    ],
)
def test_unreviewed_fcntl_commands_fail_closed(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_failed_mutations_preserve_attempt_metadata_without_state_effects():
    source = b"".join(
        line + b"\n"
        for line in [
            b"415   3.900001 fcntl(3</private/MUTATE_SECRET>, F_SETFD, FD_CLOEXEC) = -1 EBADF (Bad file descriptor) <0.1>",
            b'415   3.900002 execve("/private/MUTATE_SECRET", ["arg"], 0x7fff0000) = -1 ENOENT (No such file or directory) <0.1>',
            b"415   3.900003 close(3</private/MUTATE_SECRET>) = -1 EBADF (Bad file descriptor) <0.1>",
        ]
    )
    records = normalize_bytes(source)
    assert records[0]["transition"] == {
        "operation": "fcntl_setfd",
        "source_fd": {"fd": 3, "provenance": {"kind": "path"}},
        "requested_cloexec": True,
    }
    assert records[1]["transition"] == {"operation": "exec"}
    assert records[2]["transition"] == {
        "operation": "close",
        "fd": {"fd": 3, "provenance": {"kind": "path"}},
    }
    assert "MUTATE_SECRET" not in canonical_ndjson(records)


def test_successful_execveat_closes_close_on_exec_descriptors():
    record = normalize_bytes(
        b'416   4.0 execveat(3</private/EXECVEAT_SECRET>, "child", ["child"], 0x7fff0000, AT_EMPTY_PATH) = 0 <0.1>\n'
    )[0]
    assert record["transition"] == {
        "operation": "exec",
        "dirfd": {"fd": 3, "provenance": {"kind": "path"}},
        "flags": ["AT_EMPTY_PATH"],
        "cloexec_fds": "closed",
    }
    assert "EXECVEAT_SECRET" not in canonical_ndjson([record])


def test_recvmmsg_partial_return_uses_success_count_and_retains_requested_vlen():
    source = (
        b"417   4.1 recvmmsg(8<socket:[8]>, [{msg_hdr={msg_name=NULL, "
        b'msg_namelen=0, msg_iov=[{iov_base="PARTIAL_SECRET", iov_len=1}], '
        b"msg_iovlen=1, msg_controllen=0, msg_flags=0}, "
        b"msg_len=1}], 3, MSG_DONTWAIT, NULL) = 1 <0.1>\n"
    )
    record = normalize_bytes(source)[0]
    assert len(record["messages"]) == 1
    assert record["lengths"] == {
        "message_count": 1,
        "requested_message_count": 3,
    }
    assert "PARTIAL_SECRET" not in canonical_ndjson([record])


def test_failed_recvmmsg_retains_attempt_without_decoding_output_pointer():
    record = normalize_bytes(
        b"417   4.2 recvmmsg(8<socket:[8]>, 0x7fff0000, 3, MSG_DONTWAIT, NULL) = -1 EAGAIN (Resource temporarily unavailable) <0.1>\n"
    )[0]
    assert record["messages"] == []
    assert record["lengths"] == {
        "message_count": 0,
        "requested_message_count": 3,
    }
    assert record["result"]["errno"] == "EAGAIN"


def test_recvmmsg_rejects_decoded_vector_count_different_from_successful_return():
    source = (
        b"417   4.3 recvmmsg(8<socket:[8]>, [{msg_hdr={msg_name=NULL, "
        b'msg_namelen=0, msg_iov=[{iov_base="COUNT_SECRET", iov_len=1}], '
        b"msg_iovlen=1, msg_control=NULL, msg_controllen=0, msg_flags=0}, "
        b"msg_len=1}], 3, MSG_DONTWAIT, NULL) = 2 <0.1>\n"
    )
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(source)
    assert "COUNT_SECRET" not in str(caught.value)


def test_policy_tracks_canonical_task5_paths_and_reviewed_byte_digests():
    policy = _load_json(ROOT / "policies/holoagent0-trace-tool-v1.json")
    row = policy["rows"][0]
    parser_path = "scripts/holoagent0_setup/holoagent0_setup/trace_normalizer.py"
    fixture_path = "scripts/holoagent0_setup/fixtures/strace/manifest-v1.json"
    assert (
        row["build"]["recipe_path"]
        == "scripts/holoagent0_setup/provision_strace_6_6.sh"
    )
    assert row["parser"] == {
        "path": parser_path,
        "sha256": _sha256(REPOSITORY_ROOT / parser_path),
        "digest_algorithm": "sha256",
        "review_state": "REVIEWED",
    }
    invocation = {
        "options": row["argv"]["options"],
        "raw_syscalls": row["argv"]["raw_syscalls"],
        "decoded_address_syscalls": row["argv"]["decoded_address_syscalls"],
        "environment": row["argv"]["environment"],
    }
    invocation_digest = hashlib.sha256(
        json.dumps(invocation, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert row["argv"]["canonical_sha256"] == invocation_digest
    assert row["argv"]["review_state"] == "REVIEWED"
    assert row["fixtures"] == {
        "manifest_path": fixture_path,
        "manifest_sha256": _sha256(REPOSITORY_ROOT / fixture_path),
        "digest_algorithm": "sha256",
        "review_state": "REVIEWED",
    }
    assert row["build"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"
    assert row["runtime"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"


@pytest.mark.parametrize(
    "name",
    sorted(
        {
            "read",
            "readv",
            "pread64",
            "preadv",
            "preadv2",
            "write",
            "writev",
            "pwrite64",
            "pwritev",
            "pwritev2",
            "sendfile",
            "splice",
            "vmsplice",
            "tee",
            "copy_file_range",
        }
    ),
)
def test_decoded_payload_form_is_rejected_for_every_raw_syscall(name):
    line = f'200   1700000010.0 {name}(3</a>, "RAW_SECRET", 9) = 1 <0.1>\n'.encode()
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(line)
    assert "RAW_SECRET" not in str(caught.value)


def test_untrusted_errno_text_is_never_emitted_or_repeated_in_errors():
    source = (
        b'1     1.0 openat(AT_FDCWD, "/x", O_RDONLY) = -1 EIO (ERRNO_SECRET) <0.1>\n'
    )
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(source)
    assert "ERRNO_SECRET" not in str(caught.value)


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        (
            "sendto",
            '7<socket:[7]>, "ADDR_SECRET", 11, 0, {sa_family=AF_INET, '
            'sin_port=htons(80), sin_addr=inet_addr("192.0.2.9")}, 16',
        ),
        (
            "recvfrom",
            '7<socket:[7]>, "ADDR_SECRET", 11, 0, {sa_family=AF_INET, '
            'sin_port=htons(80), sin_addr=inet_addr("192.0.2.9")}, [16]',
        ),
        *[
            (
                name,
                "7<socket:[7]>, {msg_name={sa_family=AF_INET, sin_port=htons(80), "
                'sin_addr=inet_addr("192.0.2.9")}, msg_namelen=16, '
                'msg_iov=[{iov_base="ADDR_SECRET", iov_len=11}], msg_iovlen=1, '
                "msg_control=NULL, msg_controllen=0, msg_flags=0}, 0",
            )
            for name in ("sendmsg", "recvmsg")
        ],
        *[
            (
                name,
                "7<socket:[7]>, [{msg_hdr={msg_name={sa_family=AF_INET, "
                'sin_port=htons(80), sin_addr=inet_addr("192.0.2.9")}, msg_namelen=16, '
                'msg_iov=[{iov_base="ADDR_SECRET", iov_len=11}], msg_iovlen=1, '
                "msg_control=NULL, msg_controllen=0, msg_flags=0}, msg_len=11}], 1, 0"
                + (", NULL" if name == "recvmmsg" else ""),
            )
            for name in ("sendmmsg", "recvmmsg")
        ],
    ],
)
def test_every_address_control_syscall_is_transiently_decoded(name, arguments):
    line = f"201   1700000011.0 {name}({arguments}) = 1 <0.1>\n".encode()
    rendered = canonical_ndjson(normalize_bytes(line))
    assert name in rendered and "192.0.2.9" in rendered
    assert "ADDR_SECRET" not in rendered


def test_short_fragmented_feed_and_interleaved_pending_processes():
    source = (FIXTURES / "unfinished-resumed.input").read_bytes()
    normalizer = TraceNormalizer()
    records = []
    for byte in source:
        records.extend(normalizer.feed(bytes([byte])))
    records.extend(normalizer.finish())
    assert (
        canonical_ndjson(records)
        == (FIXTURES / "unfinished-resumed.expected.ndjson").read_text()
    )


@pytest.mark.parametrize(
    "source",
    [
        b'1     1.0 <... read resumed>"x", 1) = 1 <0.1>\n',
        b"1     1.0 read(3, <unfinished ...>\n1     1.1 read(4, <unfinished ...>\n",
        b'1     1.0 read(3, <unfinished ...>\n1     1.1 <... write resumed>"x", 1) = 1 <0.1>\n',
        b"1     1.0 [ Process PID=1 runs in 32 bit mode. ]\n",
        b"1 nan getpid() = 1 <0.1>\n",
        b"1     1.0 getpid() = 1 <inf>\n",
        b'1     1.0 read(3, "x"..., 999) = 1 <0.1>\n',
        b'1     1.0 read(3, "x", 1) = ? <unavailable>\n',
        b"\xff\n",
    ],
)
def test_malformed_unsupported_noncanonical_input_is_rejected(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_finish_rejects_truncated_line_and_pending_syscall():
    parser = TraceNormalizer()
    parser.feed(b"1     1.0 getpid() = 1 <0.1>")
    with pytest.raises(TraceDecodeError):
        parser.finish()
    parser = TraceNormalizer()
    parser.feed(b"1     1.0 read(3, <unfinished ...>\n")
    with pytest.raises(TraceDecodeError):
        parser.finish()


def test_resource_bounds_are_enforced():
    parser = TraceNormalizer(
        max_line_bytes=32, max_records=1, max_pending_processes=1, max_input_bytes=64
    )
    with pytest.raises(TraceDecodeError):
        parser.feed(b"x" * 33)
    with pytest.raises(ValueError):
        TraceNormalizer(max_line_bytes=0)
    with pytest.raises(TraceDecodeError):
        normalize_bytes(b"1     1.0 getpid() = 1 <0.1>\n", max_input_bytes=8)
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b"1     1.0 getpid() = 1 <0.1>\n1     1.1 getpid() = 1 <0.1>\n",
            max_records=1,
        )
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b"1     1.0 read(3, <unfinished ...>\n2     1.1 read(3, <unfinished ...>\n",
            max_pending_processes=1,
        )
    assert math.isfinite(float("1.0"))


def test_pipe2_creation_retains_non_socket_provenance_for_policy_replay():
    (record,) = normalize_bytes(
        b"90    1700000080.000001 pipe2([5<pipe:[105]>, 6<pipe:[105]>], "
        b"O_CLOEXEC) = 0 <0.000001>\n"
    )

    assert record["transition"] == {
        "operation": "pipe",
        "created_fds": [
            {"fd": 5, "provenance": {"kind": "pipe", "inode": 105}},
            {"fd": 6, "provenance": {"kind": "pipe", "inode": 105}},
        ],
        "cloexec": True,
    }
