import hashlib
import math
import os

import pytest

import holoagent0_setup.atomic_io as atomic_io
from holoagent0_setup.atomic_io import (
    AtomicIOError,
    CanonicalJSONError,
    atomic_write_json,
    atomic_write_json_no_replace,
    canonical_json_bytes,
    read_json_secure,
)


def test_canonical_json_is_stable_and_rejects_non_finite_numbers():
    assert canonical_json_bytes({"z": 1.0, "a": "é", "tiny": 0.000001}) == (
        b'{"a":"\xc3\xa9","tiny":0.000001,"z":1}'
    )
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError, match="finite"):
            canonical_json_bytes({"value": value})


def test_canonical_json_uses_utf16_object_key_order():
    assert canonical_json_bytes({"\ue000": 1, "\U00010000": 2}) == (
        '{"\U00010000":2,"\ue000":1}'.encode()
    )


def test_canonical_json_rejects_lone_unicode_surrogates():
    with pytest.raises(ValueError, match="surrogate"):
        canonical_json_bytes({"value": "\ud800"})


@pytest.mark.parametrize(
    "value",
    [
        type("EvilInt", (int,), {"__str__": lambda self: '0,"injected":true'})(1),
        type("EvilFloat", (float,), {})(1.0),
        type("EvilString", (str,), {})("value"),
        type("EvilList", (list,), {})([1]),
        type("EvilDict", (dict,), {})({"value": 1}),
    ],
)
def test_canonical_json_rejects_scalar_and_container_subclasses(value):
    with pytest.raises(CanonicalJSONError, match="exact builtin"):
        canonical_json_bytes({"value": value})


def test_canonical_json_has_closed_resource_bounds():
    nested = None
    for _ in range(65):
        nested = [nested]
    with pytest.raises(CanonicalJSONError, match="depth"):
        canonical_json_bytes(nested)
    with pytest.raises(CanonicalJSONError, match="collection"):
        canonical_json_bytes(list(range(1025)))
    with pytest.raises(CanonicalJSONError, match="string"):
        canonical_json_bytes("x" * (1024 * 1024 + 1))


def test_canonical_output_budget_stops_before_visiting_later_values(monkeypatch):
    monkeypatch.setattr(atomic_io, "_MAX_OUTPUT_BYTES", 32)
    with pytest.raises(CanonicalJSONError, match="output"):
        canonical_json_bytes(["x" * 64, object()])


def test_canonical_output_budget_rejects_shared_gigabyte_shape_early():
    shared = "x" * (1024 * 1024)
    with pytest.raises(CanonicalJSONError, match="output"):
        canonical_json_bytes([shared] * 1024)


def test_atomic_write_is_canonical_durable_and_described(tmp_path):
    target = tmp_path / "result.json"
    descriptor = atomic_write_json(target, {"b": 2, "a": 1})

    assert target.read_bytes() == b'{"a":1,"b":2}'
    assert descriptor.relative_path == "result.json"
    assert descriptor.size == len(target.read_bytes())
    assert len(descriptor.sha256) == 64
    stat = target.stat()
    assert (descriptor.inode, descriptor.device) == (stat.st_ino, stat.st_dev)
    assert stat.st_mode & 0o777 == 0o600
    assert read_json_secure(target) == ({"a": 1, "b": 2}, descriptor)


def test_no_replace_rejects_replay_symlink_and_path_escape(tmp_path):
    target = tmp_path / "generation-000000.json"
    atomic_write_json_no_replace(target, {"generation": 0})
    with pytest.raises(FileExistsError):
        atomic_write_json_no_replace(target, {"generation": 0})

    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked.json"
    link.symlink_to(outside)
    with pytest.raises((FileExistsError, AtomicIOError)):
        atomic_write_json_no_replace(link, {"generation": 1})
    outside_dir = tmp_path.parent / "outside-dir"
    outside_dir.mkdir(exist_ok=True)
    alias = tmp_path / "alias"
    alias.symlink_to(outside_dir, target_is_directory=True)
    with pytest.raises(AtomicIOError, match="resolved parent"):
        atomic_write_json(alias / "escaped.json", {})


def test_secure_read_rejects_symlink_wrong_mode_and_replacement(tmp_path, monkeypatch):
    target = tmp_path / "artifact.json"
    atomic_write_json(target, {"ok": True})
    link = tmp_path / "artifact-link.json"
    link.symlink_to(target)
    with pytest.raises(AtomicIOError):
        read_json_secure(link)

    target.chmod(0o644)
    with pytest.raises(AtomicIOError, match="mode"):
        read_json_secure(target)

    target.chmod(0o600)
    original_fstat = os.fstat
    calls = 0

    def changing_fstat(fd):
        nonlocal calls
        calls += 1
        stat = original_fstat(fd)
        if calls == 2:
            values = list(stat)
            values[1] += 1
            return os.stat_result(values)
        return stat

    monkeypatch.setattr(os, "fstat", changing_fstat)
    with pytest.raises(AtomicIOError, match="changed while read"):
        read_json_secure(target)


def test_secure_read_rejects_path_replacement_race(tmp_path, monkeypatch):
    target = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    atomic_write_json(target, {"version": 1})
    atomic_write_json(replacement, {"version": 2})
    real_read = os.read
    replaced = False

    def replacing_read(fd, size):
        nonlocal replaced
        data = real_read(fd, size)
        if data and not replaced:
            replaced = True
            os.replace(replacement, target)
        return data

    monkeypatch.setattr(os, "read", replacing_read)
    with pytest.raises(AtomicIOError, match="changed while read|path was replaced"):
        read_json_secure(target)


@pytest.mark.parametrize("operation", ["write", "fsync", "install"])
def test_atomic_write_faults_leave_no_published_partial(
    tmp_path, monkeypatch, operation
):
    target = tmp_path / "artifact.json"
    if operation == "write":
        monkeypatch.setattr(
            os, "write", lambda *_args: (_ for _ in ()).throw(OSError("write"))
        )
    elif operation == "fsync":
        monkeypatch.setattr(
            os, "fsync", lambda *_args: (_ for _ in ()).throw(OSError("fsync"))
        )
    else:
        monkeypatch.setattr(
            os,
            "replace",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("rename")),
        )

    with pytest.raises(AtomicIOError):
        atomic_write_json(target, {"large": "x" * 1024})
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []


def test_no_replace_winner_cannot_be_replaced(tmp_path):
    target = tmp_path / "generation-000001.json"
    first = atomic_write_json_no_replace(target, {"winner": 1})
    with pytest.raises(FileExistsError):
        atomic_write_json_no_replace(target, {"winner": 2})
    value, descriptor = read_json_secure(target)
    assert value == {"winner": 1}
    assert descriptor == first


def test_descriptor_root_escape_is_rejected_before_publication(tmp_path):
    descriptor_root = tmp_path / "evidence"
    descriptor_root.mkdir()
    target = tmp_path / "outside.json"
    with pytest.raises(AtomicIOError, match="descriptor root"):
        atomic_write_json(target, {"bad": True}, relative_to=descriptor_root)
    assert not target.exists()


def test_directory_fsync_failure_reports_error_without_partial_content(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("directory fsync")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(AtomicIOError, match="directory fsync"):
        atomic_write_json(target, {"complete": True})
    assert target.read_bytes() == b'{"complete":true}'


def test_parent_replacement_during_directory_fsync_is_rejected(tmp_path, monkeypatch):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    displaced = tmp_path / "displaced"
    target = evidence / "artifact.json"
    real_fsync = os.fsync
    calls = 0

    def replace_parent_on_directory_fsync(fd):
        nonlocal calls
        calls += 1
        if calls == 2:
            evidence.rename(displaced)
            evidence.mkdir()
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", replace_parent_on_directory_fsync)
    with pytest.raises(AtomicIOError, match="parent.*replaced"):
        atomic_write_json(target, {"complete": True})
    assert not target.exists()
    assert (displaced / "artifact.json").read_bytes() == b'{"complete":true}'


def test_secure_read_rejects_inconsistent_path_and_retained_directory(tmp_path):
    retained = tmp_path / "retained"
    reported = tmp_path / "reported"
    retained.mkdir()
    reported.mkdir()
    atomic_write_json(retained / "artifact.json", {"source": "retained"})
    atomic_write_json(reported / "artifact.json", {"source": "reported"})
    directory_fd = os.open(retained, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(AtomicIOError, match="path.*retained directory"):
            read_json_secure(
                reported / "artifact.json",
                directory_fd=directory_fd,
                relative_to=tmp_path,
            )
    finally:
        os.close(directory_fd)


def test_secure_read_rejects_symlink_ancestor_below_descriptor_root(tmp_path):
    evidence = tmp_path / "evidence"
    outside = tmp_path / "outside"
    evidence.mkdir()
    outside.mkdir()
    nested = outside / "nested"
    nested.mkdir()
    atomic_write_json(nested / "artifact.json", {"source": "outside"})
    alias = evidence / "alias"
    alias.symlink_to(outside, target_is_directory=True)
    directory_fd = os.open(nested, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(AtomicIOError, match="symlink|ancestor|retained directory"):
            read_json_secure(
                alias / "nested/artifact.json",
                directory_fd=directory_fd,
                relative_to=evidence,
            )
    finally:
        os.close(directory_fd)


def test_atomic_write_rechecks_path_identity_after_building_descriptor(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    atomic_write_json(replacement, {"attacker": True})
    real_descriptor = atomic_io._descriptor
    replaced = False

    def replace_before_return(relative_path, data, file_stat):
        nonlocal replaced
        descriptor = real_descriptor(relative_path, data, file_stat)
        if not replaced:
            replaced = True
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setattr(atomic_io, "_descriptor", replace_before_return)
    with pytest.raises(AtomicIOError, match="path was replaced"):
        atomic_write_json(target, {"trusted": True})


def test_atomic_write_rechecks_same_inode_content_after_building_descriptor(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    real_descriptor = atomic_io._descriptor
    changed = False

    def mutate_before_return(relative_path, data, file_stat):
        nonlocal changed
        descriptor = real_descriptor(relative_path, data, file_stat)
        if not changed:
            changed = True
            target.write_bytes(b'{"attacker":true}')
            target.chmod(0o600)
        return descriptor

    monkeypatch.setattr(atomic_io, "_descriptor", mutate_before_return)
    with pytest.raises(AtomicIOError, match="path was replaced|changed"):
        atomic_write_json(target, {"trusted": True})


def test_atomic_write_revalidates_retained_fd_after_final_path_check(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    real_require_path_identity = atomic_io._require_path_identity
    changed = False

    def mutate_after_path_check(*args, **kwargs):
        nonlocal changed
        result = real_require_path_identity(*args, **kwargs)
        if not changed:
            changed = True
            target.write_bytes(b'{"attacker":true}')
            target.chmod(0o600)
        return result

    monkeypatch.setattr(atomic_io, "_require_path_identity", mutate_after_path_check)
    with pytest.raises(AtomicIOError, match="changed|content"):
        atomic_write_json(target, {"trusted": True})


def test_secure_read_revalidates_retained_fd_after_final_path_check(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    atomic_write_json(target, {"trusted": True})
    real_require_path_identity = atomic_io._require_path_identity
    changed = False

    def mutate_after_path_check(*args, **kwargs):
        nonlocal changed
        result = real_require_path_identity(*args, **kwargs)
        if not changed:
            changed = True
            target.write_bytes(b'{"attacker":true}')
            target.chmod(0o600)
        return result

    monkeypatch.setattr(atomic_io, "_require_path_identity", mutate_after_path_check)
    with pytest.raises(AtomicIOError, match="changed|content"):
        read_json_secure(target)


def test_atomic_write_never_rebuilds_descriptor_after_final_verification(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    atomic_write_json(replacement, {"attacker": True})
    real_descriptor = atomic_io._descriptor
    descriptor_calls = 0
    mutated = False

    def mutate_on_terminal_descriptor(relative_path, data, file_stat):
        nonlocal descriptor_calls, mutated
        descriptor_calls += 1
        descriptor = real_descriptor(relative_path, data, file_stat)
        if descriptor_calls == 2:
            mutated = True
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setattr(atomic_io, "_descriptor", mutate_on_terminal_descriptor)
    descriptor = atomic_write_json(target, {"trusted": True})

    assert descriptor_calls == 1
    assert not mutated
    assert descriptor.sha256 == hashlib.sha256(b'{"trusted":true}').hexdigest()
    assert target.read_bytes() == b'{"trusted":true}'


def test_secure_read_never_rebuilds_descriptor_after_final_verification(
    tmp_path, monkeypatch
):
    target = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    atomic_write_json(target, {"trusted": True})
    atomic_write_json(replacement, {"attacker": True})
    real_descriptor = atomic_io._descriptor
    descriptor_calls = 0
    mutated = False

    def mutate_on_terminal_descriptor(relative_path, data, file_stat):
        nonlocal descriptor_calls, mutated
        descriptor_calls += 1
        descriptor = real_descriptor(relative_path, data, file_stat)
        if descriptor_calls == 2:
            mutated = True
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setattr(atomic_io, "_descriptor", mutate_on_terminal_descriptor)
    value, descriptor = read_json_secure(target)

    assert descriptor_calls == 1
    assert not mutated
    assert value == {"trusted": True}
    assert descriptor.sha256 == hashlib.sha256(b'{"trusted":true}').hexdigest()
    assert target.read_bytes() == b'{"trusted":true}'


def test_atomic_write_rebinds_requested_path_after_final_retained_read(
    tmp_path, monkeypatch
):
    parent = tmp_path / "parent"
    displaced = tmp_path / "displaced-parent"
    parent.mkdir()
    target = parent / "artifact.json"
    real_read_stable = atomic_io._read_stable_regular
    reads = 0

    def displace_parent_after_retained_read(*args, **kwargs):
        nonlocal reads
        result = real_read_stable(*args, **kwargs)
        reads += 1
        if reads == 1:
            parent.rename(displaced)
            parent.mkdir()
        return result

    monkeypatch.setattr(
        atomic_io, "_read_stable_regular", displace_parent_after_retained_read
    )
    with pytest.raises(AtomicIOError, match="parent|path|binding|atomic write"):
        atomic_write_json(target, {"trusted": True})

    assert reads == 1
    assert not target.exists()


def test_secure_read_rebinds_requested_path_after_final_retained_read(
    tmp_path, monkeypatch
):
    parent = tmp_path / "parent"
    displaced = tmp_path / "displaced-parent"
    parent.mkdir()
    target = parent / "artifact.json"
    atomic_write_json(target, {"trusted": True})
    real_read_stable = atomic_io._read_stable_regular
    reads = 0

    def displace_parent_after_final_retained_read(*args, **kwargs):
        nonlocal reads
        result = real_read_stable(*args, **kwargs)
        reads += 1
        if reads == 2:
            parent.rename(displaced)
            parent.mkdir()
        return result

    monkeypatch.setattr(
        atomic_io, "_read_stable_regular", displace_parent_after_final_retained_read
    )
    with pytest.raises(AtomicIOError, match="parent|path|binding"):
        read_json_secure(target)

    assert reads == 2
    assert not target.exists()


@pytest.mark.parametrize(
    "raw",
    [
        b'\xef\xbb\xbf{"value":1}',
        '{"value":1}'.encode("utf-16"),
        '{"value":1}'.encode("utf-32"),
        b'{"value":1,"value":2}',
        b'{"value":1e400}',
        b'{"b":2, "a":1}',
        (b"[" * 65) + b"null" + (b"]" * 65),
    ],
)
def test_secure_read_accepts_only_bounded_canonical_utf8_json(tmp_path, raw):
    target = tmp_path / "artifact.json"
    target.write_bytes(raw)
    target.chmod(0o600)
    with pytest.raises(AtomicIOError, match="invalid|canonical|bound"):
        read_json_secure(target)


def test_secure_read_rejects_oversize_input_before_unbounded_read(tmp_path):
    target = tmp_path / "artifact.json"
    target.write_bytes(b'"' + b"x" * (8 * 1024 * 1024) + b'"')
    target.chmod(0o600)
    with pytest.raises(AtomicIOError, match="size bound"):
        read_json_secure(target)


def test_prepublication_verifier_runs_after_staging_before_install(tmp_path):
    target = tmp_path / "result.json"
    events = []

    def verify(staging_path):
        events.append(("verified", staging_path))
        assert not target.exists()
        assert staging_path.parent == tmp_path
        assert staging_path.name.startswith(".result.json.tmp-")
        assert staging_path == next(iter(tmp_path.glob(".result.json.tmp-*")))

    atomic_write_json_no_replace(
        target,
        {"value": 1},
        relative_to=tmp_path,
        pre_publish=verify,
    )
    assert len(events) == 1
    assert events[0][0] == "verified"
    assert events[0][1].name.startswith(".result.json.tmp-")
    assert target.exists()


def test_prepublication_failure_never_installs_or_leaves_staging_file(tmp_path):
    target = tmp_path / "result.json"

    def reject(_staging_path):
        raise RuntimeError("evidence changed")

    with pytest.raises(RuntimeError, match="evidence changed"):
        atomic_write_json_no_replace(
            target,
            {"value": 1},
            relative_to=tmp_path,
            pre_publish=reject,
        )
    assert not target.exists()
    assert list(tmp_path.iterdir()) == []
