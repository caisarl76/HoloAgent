from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import holoagent0_setup.source_gate as source_gate
from holoagent0_setup.source_gate import (
    ASSET_LOCK_SCHEMA,
    APPROVED_ASSET_ROOTS,
    SOURCE_COMMIT,
    SOURCE_LOCK_SCHEMA,
    AssetSpec,
    AssetGateError,
    SourceGateError,
    canonical_asset_manifest,
    load_asset_lock,
    load_source_lock,
    verify_asset_lock,
    verify_manifest_git_objects,
    verify_source_worktree,
    verify_worktree_entry,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
SOURCE_LOCK = PACKAGE_ROOT / "locks/semantic-source-manifest-v1.json"
ASSET_LOCK = PACKAGE_ROOT / "locks/icra_ic4f-assets-v1.json"
APPROVED_SPEC = (
    REPOSITORY_ROOT
    / "docs/superpowers/specs/2026-07-22-holoagent-mujoco-first-design.md"
)
EXPECTED_SOURCE_COMMIT = "ca5ee3e2e9c5afe760fcec457549dc0a2c35c6e8"
EXPECTED_PATH_SET_SHA256 = (
    "968b39b7a16021b65e4d0adbcc33528007d42c7d4c52aee03f9c70c563ad50dc"
)


def _approved_paths() -> tuple[str, ...]:
    text = APPROVED_SPEC.read_text(encoding="utf-8")
    block = text.split("Restore the exact 73-path", 1)[1]
    block = block.split("```text", 1)[1].split("```", 1)[0]
    return tuple(sorted(line.strip() for line in block.splitlines() if line.strip()))


def test_source_lock_declares_reachable_portable_baseline():
    document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    paths = tuple(entry["path"] for entry in document["entries"])

    assert (
        SOURCE_COMMIT,
        document["commit"],
        len(paths),
        "fsr_vln/checkpoints" in paths,
        document["path_set_sha256"],
    ) == (
        EXPECTED_SOURCE_COMMIT,
        EXPECTED_SOURCE_COMMIT,
        73,
        False,
        EXPECTED_PATH_SET_SHA256,
    )


def test_source_lock_is_exact_sorted_approved_73_path_set():
    lock = load_source_lock(SOURCE_LOCK)
    expected = _approved_paths()

    assert lock.schema_version == SOURCE_LOCK_SCHEMA
    assert lock.commit == SOURCE_COMMIT == EXPECTED_SOURCE_COMMIT
    assert len(lock.entries) == 73
    assert "fsr_vln/checkpoints" not in expected
    assert tuple(entry.path for entry in lock.entries) == expected
    assert (
        lock.path_set_sha256
        == hashlib.sha256(
            "".join(f"{path}\n" for path in expected).encode("utf-8")
        ).hexdigest()
    )
    assert [
        (override.path, override.commit, override.mode, override.git_oid)
        for override in lock.reviewed_overrides
    ] == [
        (
            "nav_agent/README.md",
            "d862782b3661e2f2cf155d6e006f11c27063a6b0",
            "100644",
            "291eea5e1969497760c5c48c62a4a04623a09eb6",
        )
    ]
    readme = next(
        entry for entry in lock.entries if entry.path == "nav_agent/README.md"
    )
    assert readme.git_oid == "291eea5e1969497760c5c48c62a4a04623a09eb6"


def test_source_lock_matches_pinned_git_tree_without_restoring_anything():
    before = os.stat(REPOSITORY_ROOT).st_mtime_ns
    result = verify_manifest_git_objects(REPOSITORY_ROOT, SOURCE_LOCK)

    assert result.commit == SOURCE_COMMIT == EXPECTED_SOURCE_COMMIT
    assert result.verified_count == 73
    assert result.provenance == (
        (EXPECTED_SOURCE_COMMIT, 72),
        ("d862782b3661e2f2cf155d6e006f11c27063a6b0", 1),
    )
    assert os.stat(REPOSITORY_ROOT).st_mtime_ns == before


@pytest.mark.parametrize(
    "commit",
    [
        EXPECTED_SOURCE_COMMIT,
        "d862782b3661e2f2cf155d6e006f11c27063a6b0",
    ],
)
def test_source_provenance_commits_are_reachable_ancestors_of_head(commit):
    assert (
        source_gate._run_git(
            REPOSITORY_ROOT, ["merge-base", "--is-ancestor", commit, "HEAD"]
        )
        == ""
    )


def test_current_worktree_passes_reviewed_readme_override_without_mutation():
    before = (REPOSITORY_ROOT / "nav_agent/README.md").read_bytes()

    result = verify_source_worktree(REPOSITORY_ROOT, SOURCE_LOCK)

    assert result.verified_count == 73
    assert result.provenance[-1] == (
        "d862782b3661e2f2cf155d6e006f11c27063a6b0",
        1,
    )
    assert (REPOSITORY_ROOT / "nav_agent/README.md").read_bytes() == before


@pytest.mark.parametrize(
    ("mutation", "detail"),
    [
        ("remove", "reviewed override"),
        ("extra", "reviewed override"),
        ("path", "reviewed override"),
        ("commit", "reviewed override"),
        ("mode", "reviewed override"),
        ("oid", "reviewed override"),
    ],
)
def test_source_lock_rejects_any_readme_override_drift(mutation, detail):
    document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    override = document["reviewed_overrides"][0]
    if mutation == "remove":
        document["reviewed_overrides"] = []
    elif mutation == "extra":
        document["reviewed_overrides"].append(dict(override))
    elif mutation == "path":
        override["path"] = "nav_agent/scripts/run_nav.sh"
    elif mutation == "commit":
        override["commit"] = SOURCE_COMMIT
    elif mutation == "mode":
        override["mode"] = "100755"
    else:
        override["git_oid"] = "0" * 40

    with pytest.raises(SourceGateError, match=detail):
        load_source_lock(document)


def test_source_lock_rejects_readme_entry_mode_drift():
    document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    readme = next(
        entry for entry in document["entries"] if entry["path"] == "nav_agent/README.md"
    )
    readme["mode"] = "100755"

    with pytest.raises(SourceGateError, match="reviewed override"):
        load_source_lock(document)


def test_source_lock_rejects_unlisted_tree_expansion_and_unknown_fields(tmp_path):
    document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    document["entries"].append(
        {
            "path": "nav_agent/humble_localization_nav2/resurrected.py",
            "mode": "100644",
            "kind": "blob",
            "git_oid": "0" * 40,
        }
    )
    document["entries"].sort(key=lambda value: value["path"])
    expanded = tmp_path / "expanded.json"
    expanded.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SourceGateError, match="exact approved path set"):
        load_source_lock(expanded)

    document = json.loads(SOURCE_LOCK.read_text(encoding="utf-8"))
    document["unexpected"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(SourceGateError, match="closed"):
        load_source_lock(unknown)


def test_conflicting_reappeared_path_is_rejected_without_overwrite(tmp_path):
    lock = load_source_lock(SOURCE_LOCK)
    entry = next(value for value in lock.entries if value.kind == "blob")
    path = tmp_path / entry.path
    path.parent.mkdir(parents=True)
    path.write_bytes(b"user-owned-conflict")

    with pytest.raises(SourceGateError, match="SOURCE_BLOB_MISMATCH"):
        verify_worktree_entry(tmp_path, entry)

    assert path.read_bytes() == b"user-owned-conflict"


def test_asset_lock_is_closed_and_pins_approved_roots_counts_and_digests():
    lock = load_asset_lock(ASSET_LOCK)

    assert lock.schema_version == ASSET_LOCK_SCHEMA
    assert lock.graph_identity == "icra_ic4f/graph_20260629211448"
    assert lock.graph_counts == (1, 3, 497)
    assert lock.structured_query_sha256 == (
        "ddcbd21de5223595c515e595192e505289f44b91252ba46643f833a007983047"
    )
    assert lock.room_name_mapping == ("Pantry", "Office", "Hallway")
    assert lock.room_name_mapping_sha256 == (
        "05a9439d16575a1fd76d0bf7bccd7d9f62a24424ac5516f2728c4e04b51d4845"
    )
    assert [
        (
            asset.role,
            asset.relative_path,
            asset.file_count,
            asset.byte_count,
            asset.sha256,
            len(asset.files),
        )
        for asset in lock.assets
    ] == [
        (
            "graph",
            "scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448",
            1229,
            150_066_065,
            "6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050",
            1229,
        ),
        (
            "dataset",
            "rgbd_datasets/icra_ic4f",
            5360,
            2_391_476_669,
            "a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913",
            5360,
        ),
        (
            "checkpoint",
            "checkpoints/open_clip_pytorch_model.bin",
            1,
            1710631365,
            "5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b",
            1,
        ),
    ]
    for asset in lock.assets:
        paths = tuple(entry.relative_path for entry in asset.files)
        assert paths == tuple(sorted(paths, key=os.fsencode))
        assert len(paths) == len(set(paths)) == asset.file_count
        for entry in asset.files:
            assert not Path(entry.relative_path).is_absolute()
            assert ".." not in Path(entry.relative_path).parts
            assert entry.kind in {"regular_file", "symlink"}
            assert len(entry.mode) == 4
            assert all(character in "01234567" for character in entry.mode)
            assert entry.byte_size >= 0
            assert len(entry.sha256) == 64
            assert (entry.symlink_target is None) == (entry.kind == "regular_file")

    document = json.loads(ASSET_LOCK.read_text(encoding="utf-8"))
    document["unknown"] = []
    with pytest.raises(AssetGateError, match="closed"):
        load_asset_lock(document)


def test_generated_asset_lock_exactly_matches_the_three_approved_roots():
    lock = load_asset_lock(ASSET_LOCK)
    measured = source_gate.measure_approved_asset_roots(APPROVED_ASSET_ROOTS)

    assert [
        (
            asset.role,
            measured[asset.role].file_count,
            measured[asset.role].byte_count,
            measured[asset.role].sha256,
            measured[asset.role].files == asset.files,
        )
        for asset in lock.assets
    ] == [
        (
            "graph",
            1229,
            150_066_065,
            "6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050",
            True,
        ),
        (
            "dataset",
            5360,
            2_391_476_669,
            "a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913",
            True,
        ),
        (
            "checkpoint",
            1,
            1_710_631_365,
            "5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b",
            True,
        ),
    ]


def test_canonical_asset_manifest_sorts_bytes_and_rejects_escaping_symlink(tmp_path):
    root = tmp_path / "asset"
    root.mkdir()
    (root / "z.bin").write_bytes(b"z")
    (root / "a.bin").write_bytes(b"a")
    (root / "z.bin").chmod(0o644)
    (root / "a.bin").chmod(0o644)
    (root / "inside-link").symlink_to("a.bin")

    manifest = canonical_asset_manifest(root)
    symlink_digest = hashlib.sha256(b"symlink\0a.bin").hexdigest()
    expected_lines = sorted(
        (
            f"{hashlib.sha256(b'a').hexdigest()}  a.bin\n",
            f"{hashlib.sha256(b'z').hexdigest()}  z.bin\n",
            f"{symlink_digest}  inside-link\n",
        ),
        key=lambda value: value.split("  ", 1)[1].encode("utf-8"),
    )
    assert manifest.file_count == 3
    assert manifest.byte_count == 2
    assert (
        manifest.sha256 == hashlib.sha256("".join(expected_lines).encode()).hexdigest()
    )
    assert [
        (
            entry.relative_path,
            entry.kind,
            entry.mode,
            entry.byte_size,
            entry.symlink_target,
        )
        for entry in manifest.files
    ] == [
        ("a.bin", "regular_file", "0644", 1, None),
        ("inside-link", "symlink", "0777", 0, "a.bin"),
        ("z.bin", "regular_file", "0644", 1, None),
    ]

    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (root / "escape").symlink_to("../../outside")
    with pytest.raises(AssetGateError, match="escapes"):
        canonical_asset_manifest(root)


def test_asset_manifest_streams_regular_files_without_path_read_bytes(
    tmp_path, monkeypatch
):
    root = tmp_path / "asset"
    root.mkdir()
    payload = b"x" * (2 * 1024 * 1024 + 17)
    (root / "large.bin").write_bytes(payload)

    def forbidden_read_bytes(_path):
        raise AssertionError("asset hashing must stream from an identity-safe fd")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    manifest = canonical_asset_manifest(root)

    assert manifest.file_count == 1
    assert manifest.files[0].byte_size == len(payload)
    assert manifest.files[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_asset_manifest_rejects_same_size_in_place_mutation(tmp_path, monkeypatch):
    root = tmp_path / "asset"
    root.mkdir()
    target = root / "payload.bin"
    target.write_bytes(b"before")
    original_read = source_gate.os.read
    mutated = False

    def mutate_between_stream_reads(fd, size):
        nonlocal mutated
        chunk = original_read(fd, size)
        if not chunk and not mutated:
            mutated = True
            target.write_bytes(b"after!")
        return chunk

    monkeypatch.setattr(source_gate.os, "read", mutate_between_stream_reads)
    with pytest.raises(AssetGateError, match="ASSET_IDENTITY_CHANGED"):
        canonical_asset_manifest(root)


def test_asset_manifest_rejects_late_directory_addition(tmp_path, monkeypatch):
    root = tmp_path / "asset"
    root.mkdir()
    (root / "payload.bin").write_bytes(b"payload")
    original = source_gate._stream_regular_fd

    def add_entry_after_hash(fd, subject):
        result = original(fd, subject)
        (root / "late.bin").write_bytes(b"late")
        return result

    monkeypatch.setattr(source_gate, "_stream_regular_fd", add_entry_after_hash)
    with pytest.raises(AssetGateError, match="ASSET_IDENTITY_CHANGED"):
        canonical_asset_manifest(root)


def test_asset_lock_rejects_unknown_duplicate_unsorted_and_unsafe_file_entries():
    document = json.loads(ASSET_LOCK.read_text(encoding="utf-8"))
    first = document["assets"][0]["files"][0]

    unknown = json.loads(json.dumps(document))
    unknown["assets"][0]["files"][0]["unknown"] = True
    with pytest.raises(AssetGateError, match="closed"):
        load_asset_lock(unknown)

    duplicate = json.loads(json.dumps(document))
    duplicate["assets"][0]["files"].insert(0, dict(first))
    duplicate["assets"][0]["file_count"] += 1
    with pytest.raises(AssetGateError, match="sorted unique"):
        load_asset_lock(duplicate)

    unsorted = json.loads(json.dumps(document))
    unsorted["assets"][0]["files"][:2] = reversed(unsorted["assets"][0]["files"][:2])
    with pytest.raises(AssetGateError, match="sorted unique"):
        load_asset_lock(unsorted)

    for unsafe_path in ("/absolute", "../escape", "a/../../escape", "a//b"):
        unsafe = json.loads(json.dumps(document))
        unsafe["assets"][0]["files"][0]["relative_path"] = unsafe_path
        with pytest.raises(AssetGateError, match="normalized relative POSIX"):
            load_asset_lock(unsafe)


def test_locks_reject_duplicate_json_object_keys(tmp_path):
    duplicate_asset_lock = tmp_path / "duplicate-asset.json"
    duplicate_asset_lock.write_text(
        '{"schema_version":"holoagent0-icra-ic4f-assets-v1",'
        '"schema_version":"holoagent0-icra-ic4f-assets-v1"}',
        encoding="utf-8",
    )
    with pytest.raises(AssetGateError, match="duplicate JSON object key"):
        load_asset_lock(duplicate_asset_lock)

    duplicate_source_lock = tmp_path / "duplicate-source.json"
    duplicate_source_lock.write_text(
        '{"schema_version":"holoagent0-semantic-source-manifest-v1",'
        '"schema_version":"holoagent0-semantic-source-manifest-v1"}',
        encoding="utf-8",
    )
    with pytest.raises(SourceGateError, match="duplicate JSON object key"):
        load_source_lock(duplicate_source_lock)


def test_source_worktree_rejects_intermediate_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"outside")
    root = tmp_path / "root"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    entry = type("Entry", (), {})()
    entry.path = "linked/payload"
    entry.mode = "100644"
    entry.kind = "blob"
    header = f"blob {len(b'outside')}\0".encode("ascii")
    entry.git_oid = hashlib.sha1(header + b"outside").hexdigest()

    with pytest.raises(SourceGateError, match="SOURCE_PATH_ESCAPE"):
        verify_worktree_entry(root, entry)


def test_git_runner_uses_absolute_binary_minimal_environment_timeout_and_output_cap(
    tmp_path, monkeypatch
):
    observed = {}

    def fake_run(argv, **kwargs):
        observed["argv"] = argv
        observed.update(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout="x" * (source_gate.GIT_OUTPUT_LIMIT_BYTES + 1),
            stderr="",
        )

    monkeypatch.setattr(source_gate.subprocess, "run", fake_run)
    with pytest.raises(SourceGateError, match="output exceeded"):
        source_gate._run_git(tmp_path, ["version"])

    assert observed["argv"] == ["/usr/bin/git", "version"]
    assert observed["cwd"] == tmp_path
    assert observed["env"] == {
        "LC_ALL": "C",
        "LANG": "C",
        "PATH": "/usr/bin:/bin",
    }
    assert observed["timeout"] == source_gate.GIT_TIMEOUT_SECONDS


def test_git_runner_caps_failure_output_before_reporting_subprocess_error(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        source_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="x" * (source_gate.GIT_OUTPUT_LIMIT_BYTES + 1),
        ),
    )

    with pytest.raises(SourceGateError, match="output exceeded"):
        source_gate._run_git(tmp_path, ["version"])


@pytest.mark.parametrize("mutation", ["missing", "extra", "changed"])
def test_asset_inventory_rejects_missing_extra_or_changed_entries(tmp_path, mutation):
    root = tmp_path / "asset"
    root.mkdir()
    (root / "a.bin").write_bytes(b"a")
    (root / "b.bin").write_bytes(b"b")
    locked = canonical_asset_manifest(root)
    spec = AssetSpec(
        role="fixture",
        kind="directory",
        relative_path=str(root),
        file_count=locked.file_count,
        byte_count=locked.byte_count,
        sha256=locked.sha256,
        files=locked.files,
    )

    if mutation == "missing":
        (root / "a.bin").unlink()
    elif mutation == "extra":
        (root / "extra.bin").write_bytes(b"extra")
    else:
        (root / "a.bin").write_bytes(b"changed")

    with pytest.raises(AssetGateError, match="ASSET_INVENTORY_MISMATCH"):
        source_gate.verify_asset_inventory(root, spec)


def test_asset_inventory_rejects_file_replaced_by_internal_symlink(tmp_path):
    root = tmp_path / "asset"
    root.mkdir()
    (root / "a.bin").write_bytes(b"a")
    (root / "b.bin").write_bytes(b"b")
    locked = canonical_asset_manifest(root)
    spec = AssetSpec(
        role="fixture",
        kind="directory",
        relative_path=str(root),
        file_count=locked.file_count,
        byte_count=locked.byte_count,
        sha256=locked.sha256,
        files=locked.files,
    )
    (root / "a.bin").unlink()
    (root / "a.bin").symlink_to("b.bin")

    with pytest.raises(AssetGateError, match="ASSET_INVENTORY_MISMATCH"):
        source_gate.verify_asset_inventory(root, spec)


def test_asset_verification_requires_exact_explicit_approved_role_roots(tmp_path):
    missing = dict(APPROVED_ASSET_ROOTS)
    missing.pop("dataset")
    with pytest.raises(AssetGateError, match="ASSET_ROOT_MISMATCH"):
        verify_asset_lock(missing, ASSET_LOCK)

    substituted = dict(APPROVED_ASSET_ROOTS)
    substituted["dataset"] = tmp_path
    with pytest.raises(AssetGateError, match="ASSET_ROOT_MISMATCH"):
        verify_asset_lock(substituted, ASSET_LOCK)
