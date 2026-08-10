import hashlib
import json
import math
from pathlib import Path

import pytest

from holoagent0_setup.trace_normalizer import (
    DECODED_ADDRESS_SYSCALLS,
    RAW_PAYLOAD_SYSCALLS,
    STRACE_ARGUMENTS,
    STRACE_ENVIRONMENT,
    TraceDecodeError,
    TraceNormalizer,
    canonical_ndjson,
    normalize_bytes,
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
    assert len(names) == len(set(names)) == 8
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
        "301 1700000020.000001 sendmsg(7<socket:[7]>, "
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
        f"302 1700000020.000002 {name}(8<socket:[8]>, ["
        "{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(80), "
        'sin_addr=inet_addr("192.0.2.10")}, msg_namelen=16, msg_iov=[], msg_iovlen=0, '
        "msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, "
        "cmsg_data=[9</private/a>]}, {cmsg_len=20, cmsg_level=SOL_SOCKET, "
        "cmsg_type=SCM_RIGHTS, cmsg_data=[10<socket:[10]>]}], msg_controllen=48, "
        "msg_flags=0}, msg_len=0}, {msg_hdr={msg_name={sa_family=AF_INET6, "
        'sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2001:db8::2")}, '
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
    source = f"303 1700000021.000001 {name}({arguments}) = 0x10 <0.000001>\n".encode()
    record = normalize_bytes(source)[0]
    assert [item["fd"] for item in record["fds"]] == expected_fds
    assert record["lengths"][length_key] == length
    assert record["result"]["value"] == 16
    assert "private" not in canonical_ndjson([record])


@pytest.mark.parametrize(
    "source",
    [
        b"303 1.0 sendfile(0x4, 0x7fff0000, 0x10) = 0x10 <0.1>\n",
        b'303 1.0 read(0x3, "decoded payload", 0x10) = 0x10 <0.1>\n',
        b"303 1.0 splice(0x3, 0, 0x4, 0x10, 0x1) = 0x10 <0.1>\n",
    ],
)
def test_malformed_raw_shapes_fail_closed_without_fallback(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_fd_and_process_transitions_are_structured_and_path_secret_free():
    source = b"".join(
        line + b"\n"
        for line in [
            b"400 2.000001 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3<socket:[33]> <0.1>",
            b"400 2.000002 socketpair(AF_UNIX, SOCK_STREAM, 0, [4<socket:[44]>, 5<socket:[55]>]) = 0 <0.1>",
            b'400 2.000003 accept(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.3")}, [16]) = 6<socket:[66]> <0.1>',
            b'400 2.000004 accept4(3<socket:[33]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_addr=inet_pton(AF_INET6, "2001:db8::3")}, [28], SOCK_CLOEXEC) = 7<socket:[77]> <0.1>',
            b'400 2.000005 bind(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.1>',
            b'400 2.000006 connect(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.53")}, 16) = 0 <0.1>',
            b'400 2.000007 getsockname(3<socket:[33]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, [16]) = 0 <0.1>',
            b"400 2.000008 dup(3</private/SECRET_PATH>) = 8</private/SECRET_PATH> <0.1>",
            b"400 2.000009 dup2(3</private/SECRET_PATH>, 9) = 9</private/SECRET_PATH> <0.1>",
            b"400 2.000010 dup3(3</private/SECRET_PATH>, 10, O_CLOEXEC) = 10</private/SECRET_PATH> <0.1>",
            b"400 2.000011 fcntl(3</private/SECRET_PATH>, F_DUPFD_CLOEXEC, 11) = 11</private/SECRET_PATH> <0.1>",
            b"400 2.000012 fork() = 500 <0.1>",
            b"400 2.000013 vfork() = 501 <0.1>",
            b"400 2.000014 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = 502 <0.1>",
            b'400 2.000015 execve("/private/SECRET_PATH", ["SECRET_ARG"], 0x7fff0000) = 0 <0.1>',
            b"400 2.000016 close(8</private/SECRET_PATH>) = 0 <0.1>",
            b"400 2.000017 close_range(3, 4294967295, CLOSE_RANGE_CLOEXEC) = 0 <0.1>",
            b"400 2.000018 unshare(CLONE_FILES) = 0 <0.1>",
            b"400 2.000019 pidfd_getfd(11<anon_inode:[pidfd]>, 3, 0) = 12</private/SECRET_PATH> <0.1>",
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
            b"1 1.0 socketpair(AF_UNIX, SOCK_STREAM, 0, SECRET) = 0 <0.1>\n"
        )


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
    line = f'200 1700000010.0 {name}(3</a>, "RAW_SECRET", 9) = 1 <0.1>\n'.encode()
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(line)
    assert "RAW_SECRET" not in str(caught.value)


def test_untrusted_errno_text_is_never_emitted_or_repeated_in_errors():
    source = b'1 1.0 openat(AT_FDCWD, "/x", O_RDONLY) = -1 EIO (ERRNO_SECRET) <0.1>\n'
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
    line = f"201 1700000011.0 {name}({arguments}) = 1 <0.1>\n".encode()
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
        b'1 1.0 <... read resumed>"x", 1) = 1 <0.1>\n',
        b"1 1.0 read(3, <unfinished ...>\n1 1.1 read(4, <unfinished ...>\n",
        b'1 1.0 read(3, <unfinished ...>\n1 1.1 <... write resumed>"x", 1) = 1 <0.1>\n',
        b"1 1.0 [ Process PID=1 runs in 32 bit mode. ]\n",
        b"1 nan getpid() = 1 <0.1>\n",
        b"1 1.0 getpid() = 1 <inf>\n",
        b'1 1.0 read(3, "x"..., 999) = 1 <0.1>\n',
        b'1 1.0 read(3, "x", 1) = ? <unavailable>\n',
        b"\xff\n",
    ],
)
def test_malformed_unsupported_noncanonical_input_is_rejected(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_finish_rejects_truncated_line_and_pending_syscall():
    parser = TraceNormalizer()
    parser.feed(b"1 1.0 getpid() = 1 <0.1>")
    with pytest.raises(TraceDecodeError):
        parser.finish()
    parser = TraceNormalizer()
    parser.feed(b"1 1.0 read(3, <unfinished ...>\n")
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
        normalize_bytes(b"1 1.0 getpid() = 1 <0.1>\n", max_input_bytes=8)
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b"1 1.0 getpid() = 1 <0.1>\n1 1.1 getpid() = 1 <0.1>\n",
            max_records=1,
        )
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            b"1 1.0 read(3, <unfinished ...>\n2 1.1 read(3, <unfinished ...>\n",
            max_pending_processes=1,
        )
    assert math.isfinite(float("1.0"))
