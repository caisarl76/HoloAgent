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
SENTINELS = ("PAYLOAD_SENTINEL", "FRAGMENTED_SECRET", "SOCKET_SECRET", "CONTROL_SECRET")


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
    assert len(names) == len(set(names)) == 6
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
def test_every_raw_payload_syscall_is_safely_redacted(name):
    line = f'200 1700000010.0 {name}(3</a>, "RAW_SECRET", 9) = 1 <0.1>\n'.encode()
    rendered = canonical_ndjson(normalize_bytes(line))
    assert name in rendered
    assert "RAW_SECRET" not in rendered


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("read", '3</a>, "RAW_SECRET", 9'),
        ("readv", '3</a>, [{iov_base="RAW_SECRET", iov_len=9}], 1'),
        ("pread64", '3</a>, "RAW_SECRET", 9, 0'),
        ("preadv", '3</a>, [{iov_base="RAW_SECRET", iov_len=9}], 1, 0'),
        ("preadv2", '3</a>, [{iov_base="RAW_SECRET", iov_len=9}], 1, 0, 0, RWF_NOWAIT'),
        ("write", '4</b>, "RAW_SECRET", 9'),
        ("writev", '4</b>, [{iov_base="RAW_SECRET", iov_len=9}], 1'),
        ("pwrite64", '4</b>, "RAW_SECRET", 9, 0'),
        ("pwritev", '4</b>, [{iov_base="RAW_SECRET", iov_len=9}], 1, 0'),
        ("pwritev2", '4</b>, [{iov_base="RAW_SECRET", iov_len=9}], 1, 0, 0, RWF_DSYNC'),
        ("sendfile", "4</b>, 3</a>, NULL, 9"),
        ("splice", "3</a>, NULL, 4</b>, NULL, 9, SPLICE_F_MOVE"),
        (
            "vmsplice",
            '4</b>, [{iov_base="RAW_SECRET", iov_len=9}], 1, SPLICE_F_NONBLOCK',
        ),
        ("tee", "3</a>, 4</b>, 9, SPLICE_F_NONBLOCK"),
        ("copy_file_range", "3</a>, NULL, 4</b>, NULL, 9, 0"),
    ],
)
def test_every_raw_payload_syscall_accepts_its_native_structural_shape(name, arguments):
    rendered = canonical_ndjson(
        normalize_bytes(f"210 1700000010.0 {name}({arguments}) = 1 <0.1>\n".encode())
    )
    assert name in rendered and "RAW_SECRET" not in rendered


def test_untrusted_errno_text_is_never_emitted_or_repeated_in_errors():
    source = b'1 1.0 openat(AT_FDCWD, "/x", O_RDONLY) = -1 EIO (ERRNO_SECRET) <0.1>\n'
    with pytest.raises(TraceDecodeError) as caught:
        normalize_bytes(source)
    assert "ERRNO_SECRET" not in str(caught.value)


@pytest.mark.parametrize("name", sorted(DECODED_ADDRESS_SYSCALLS))
def test_every_address_control_syscall_is_transiently_decoded(name):
    line = (
        f'201 1700000011.0 {name}(7<socket:[7]>, "ADDR_SECRET", 11, 0, '
        '{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("192.0.2.9")}, 16) '
        "= 1 <0.1>\n"
    ).encode()
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
