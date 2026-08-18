from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

import holoagent0_setup.source_gate as source_gate
from holoagent0_setup.source_gate import (
    ASSET_LOCK_SCHEMA,
    APPROVED_ASSET_ROOTS,
    SOURCE_COMMIT,
    SOURCE_LOCK_SCHEMA,
    AssetManifest,
    AssetSpec,
    AssetGateError,
    HandoverPaths,
    PathIdentity,
    SourceGateError,
    canonical_asset_manifest,
    load_asset_lock,
    load_source_lock,
    measure_approved_asset_roots,
    prepare_handover_run_directory,
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


def _populate_handover_roots(repository_root, data_root):
    graph = (
        data_root
        / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
    )
    dataset = data_root / "fsr_vln/rgbd_datasets/icra_ic4f"
    checkpoint = data_root / "fsr_vln/checkpoints/open_clip_pytorch_model.bin"
    asset_lock = (
        repository_root / "scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json"
    )
    graph.mkdir(parents=True)
    dataset.mkdir(parents=True)
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_bytes(b"checkpoint")
    asset_lock.parent.mkdir(parents=True)
    asset_lock.write_text("{}", encoding="utf-8")


def _make_handover_layout(tmp_path):
    repository_root = tmp_path / "repository"
    data_root = tmp_path / "data"
    _populate_handover_roots(repository_root, data_root)
    return repository_root, data_root


def _handover_paths(tmp_path):
    return HandoverPaths.from_roots(*_make_handover_layout(tmp_path))


def test_handover_paths_derives_the_exact_roles_and_retains_identity(tmp_path):
    repository_root, data_root = _make_handover_layout(tmp_path)

    paths = HandoverPaths.from_roots(repository_root, data_root)

    assert paths.repository_root == repository_root
    assert paths.data_root == data_root
    assert paths.graph == (
        data_root
        / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
    )
    assert paths.dataset == data_root / "fsr_vln/rgbd_datasets/icra_ic4f"
    assert paths.checkpoint == (
        data_root / "fsr_vln/checkpoints/open_clip_pytorch_model.bin"
    )
    assert paths.asset_lock == (
        repository_root / "scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json"
    )
    assert isinstance(paths.identities, tuple)
    assert tuple(identity.path for identity in paths.identities) == (
        paths.repository_root,
        paths.data_root,
        paths.graph,
        paths.dataset,
        paths.checkpoint,
        paths.asset_lock,
    )
    assert all(isinstance(identity, PathIdentity) for identity in paths.identities)
    assert all(identity.device > 0 for identity in paths.identities)
    assert all(identity.inode > 0 for identity in paths.identities)
    assert all(identity.mode > 0 for identity in paths.identities)
    assert stat.S_ISDIR(paths.identities[0].mode)
    assert stat.S_ISDIR(paths.identities[1].mode)
    assert stat.S_ISDIR(paths.identities[2].mode)
    assert stat.S_ISDIR(paths.identities[3].mode)
    assert stat.S_ISREG(paths.identities[4].mode)
    assert stat.S_ISREG(paths.identities[5].mode)
    assert paths.revalidate() is None


def test_handover_paths_cannot_be_constructed_with_caller_role_paths(tmp_path):
    repository_root, data_root = _make_handover_layout(tmp_path)

    with pytest.raises(TypeError, match="from_roots"):
        HandoverPaths(
            repository_root=repository_root,
            data_root=data_root,
            graph=tmp_path / "substituted",
            dataset=tmp_path / "substituted",
            checkpoint=tmp_path / "substituted",
            asset_lock=tmp_path / "substituted",
            identities=(),
        )


@pytest.mark.parametrize("role", ["repository", "data"])
def test_handover_paths_rejects_relative_roots(tmp_path, role):
    repository_root, data_root = _make_handover_layout(tmp_path)
    roots = {
        "repository": repository_root,
        "data": data_root,
    }
    roots[role] = Path(roots[role].name)

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(roots["repository"], roots["data"])

    assert caught.value.reason == "HANDOVER_PATH_NOT_ABSOLUTE"


@pytest.mark.parametrize("role", ["repository", "data"])
def test_handover_paths_rejects_lexically_unnormalized_roots(tmp_path, role):
    repository_root, data_root = _make_handover_layout(tmp_path)
    roots = {
        "repository": repository_root,
        "data": data_root,
    }
    roots[role] = roots[role] / ".." / roots[role].name

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(roots["repository"], roots["data"])

    assert caught.value.reason == "HANDOVER_PATH_NOT_NORMALIZED"


@pytest.mark.parametrize("kind", ["missing", "file"])
@pytest.mark.parametrize("role", ["repository", "data"])
def test_handover_paths_rejects_missing_or_nondirectory_roots(tmp_path, role, kind):
    repository_root, data_root = _make_handover_layout(tmp_path)
    invalid = tmp_path / f"invalid-{role}-{kind}"
    if kind == "file":
        invalid.write_bytes(b"not a directory")
    roots = {"repository": repository_root, "data": data_root}
    roots[role] = invalid

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(roots["repository"], roots["data"])

    assert caught.value.reason in {
        "HANDOVER_PATH_UNAVAILABLE",
        "HANDOVER_PATH_TYPE_MISMATCH",
    }


@pytest.mark.parametrize("relationship", ["equal", "repository_above", "data_above"])
def test_handover_paths_rejects_root_overlap_in_both_directions(tmp_path, relationship):
    if relationship == "equal":
        repository_root = data_root = tmp_path / "shared"
    elif relationship == "repository_above":
        repository_root = tmp_path / "repository"
        data_root = repository_root / "data"
    else:
        data_root = tmp_path / "data"
        repository_root = data_root / "repository"
    _populate_handover_roots(repository_root, data_root)

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(repository_root, data_root)

    assert caught.value.reason == "HANDOVER_PATH_OVERLAP"


@pytest.mark.parametrize(
    "alias", ["root_component", "root_final", "derived_component", "derived_final"]
)
def test_handover_paths_rejects_root_and_derived_symlink_aliases(tmp_path, alias):
    if alias == "root_component":
        real_parent = tmp_path / "real-parent"
        repository_root = real_parent / "repository"
        data_root = tmp_path / "data"
        _populate_handover_roots(repository_root, data_root)
        (tmp_path / "alias-parent").symlink_to(real_parent, target_is_directory=True)
        repository_root = tmp_path / "alias-parent/repository"
    else:
        repository_root, data_root = _make_handover_layout(tmp_path)
        if alias == "root_final":
            real_repository = tmp_path / "real-repository"
            repository_root.rename(real_repository)
            repository_root.symlink_to(real_repository, target_is_directory=True)
        elif alias == "derived_component":
            component = data_root / "fsr_vln/scene_graphs_opensource"
            real_component = tmp_path / "real-scene-graphs"
            component.rename(real_component)
            component.symlink_to(real_component, target_is_directory=True)
        else:
            graph = (
                data_root
                / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
            )
            real_graph = tmp_path / "real-graph"
            graph.rename(real_graph)
            graph.symlink_to(real_graph, target_is_directory=True)

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(repository_root, data_root)

    assert caught.value.reason == "HANDOVER_PATH_ALIAS"


@pytest.mark.parametrize("role", ["graph", "dataset", "checkpoint", "asset_lock"])
def test_handover_paths_rejects_missing_derived_roles(tmp_path, role):
    paths = _handover_paths(tmp_path)
    target = getattr(paths, role)
    if target.is_dir():
        target.rmdir()
    else:
        target.unlink()

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(paths.repository_root, paths.data_root)

    assert caught.value.reason == "HANDOVER_PATH_UNAVAILABLE"
    assert role in str(caught.value)


@pytest.mark.parametrize("role", ["checkpoint", "asset_lock"])
def test_handover_paths_rejects_nonregular_file_roles(tmp_path, role):
    paths = _handover_paths(tmp_path)
    target = getattr(paths, role)
    target.unlink()
    target.mkdir()

    with pytest.raises(AssetGateError) as caught:
        HandoverPaths.from_roots(paths.repository_root, paths.data_root)

    assert caught.value.reason == "HANDOVER_PATH_TYPE_MISMATCH"
    assert role in str(caught.value)


@pytest.mark.parametrize(
    "role",
    ["repository_root", "data_root", "graph", "dataset", "checkpoint", "asset_lock"],
)
@pytest.mark.parametrize("mutation", ["replacement", "mode"])
def test_handover_paths_revalidate_rejects_role_identity_or_mode_drift(
    tmp_path, role, mutation
):
    paths = _handover_paths(tmp_path)
    target = getattr(paths, role)
    if mutation == "mode":
        target.chmod(stat.S_IMODE(target.stat().st_mode) ^ stat.S_IWUSR)
    elif target.is_dir():
        original = target.with_name(f"{target.name}-original")
        target.rename(original)
        target.mkdir()
    else:
        target.rename(target.with_name(f"{target.name}-original"))
        target.write_bytes(b"replacement")

    with pytest.raises(AssetGateError) as caught:
        paths.revalidate()

    assert caught.value.reason == "HANDOVER_PATH_IDENTITY_CHANGED"
    assert role.replace("_root", "") in str(caught.value)


def test_new_asset_measurement_uses_only_derived_exact_roles(tmp_path, monkeypatch):
    paths = _handover_paths(tmp_path)
    observed = []
    sentinel = AssetManifest(0, 0, hashlib.sha256(b"").hexdigest(), ())

    def measure(path):
        observed.append(path)
        return sentinel

    monkeypatch.setattr(source_gate, "canonical_asset_manifest", measure)

    measured = measure_approved_asset_roots(paths)

    assert measured == {
        "graph": sentinel,
        "dataset": sentinel,
        "checkpoint": sentinel,
    }
    assert observed == [paths.graph, paths.dataset, paths.checkpoint]


def test_new_asset_verification_uses_the_derived_lock_and_role_set(
    tmp_path, monkeypatch
):
    paths = _handover_paths(tmp_path)
    loaded = []
    verified = []
    assets = tuple(
        AssetSpec(role, "file", role, 1, 1, "0" * 64, ())
        for role in ("graph", "dataset", "checkpoint")
    )

    def load(source):
        loaded.append(source)
        return SimpleNamespace(assets=assets)

    def verify(root, asset):
        verified.append((root, asset.role))
        return asset.role

    monkeypatch.setattr(source_gate, "load_asset_lock", load)
    monkeypatch.setattr(source_gate, "verify_asset_inventory", verify)

    assert verify_asset_lock(paths) == ("graph", "dataset", "checkpoint")
    assert loaded == [paths.asset_lock]
    assert verified == [
        (paths.graph, "graph"),
        (paths.dataset, "dataset"),
        (paths.checkpoint, "checkpoint"),
    ]


def test_prepare_handover_run_directory_atomically_creates_owner_only_directory(
    tmp_path,
):
    paths = _handover_paths(tmp_path)
    run_parent = tmp_path / "runs"
    run_parent.mkdir()
    run = run_parent / "fixture"

    identity = prepare_handover_run_directory(run, paths)

    assert identity.path == run
    assert (identity.device, identity.inode, identity.mode) == (
        run.stat().st_dev,
        run.stat().st_ino,
        run.stat().st_mode,
    )
    assert stat.S_ISDIR(identity.mode)
    assert stat.S_IMODE(identity.mode) == 0o700
    assert tuple(run.iterdir()) == ()


def test_prepare_handover_run_directory_accepts_empty_existing_real_directory(
    tmp_path,
):
    paths = _handover_paths(tmp_path)
    run = tmp_path / "empty-run"
    run.mkdir(mode=0o750)

    identity = prepare_handover_run_directory(run, paths)

    assert identity.path == run
    assert identity.inode == run.stat().st_ino
    assert stat.S_IMODE(identity.mode) == 0o750


def test_prepare_handover_run_directory_rejects_relative_path(tmp_path):
    paths = _handover_paths(tmp_path)

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(Path("relative-run"), paths)

    assert caught.value.reason == "RUN_PATH_NOT_ABSOLUTE"


def test_prepare_handover_run_directory_rejects_unnormalized_path(tmp_path):
    paths = _handover_paths(tmp_path)
    run = tmp_path / "runs" / ".." / "run"

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(run, paths)

    assert caught.value.reason == "RUN_PATH_NOT_NORMALIZED"


@pytest.mark.parametrize("kind", ["nonempty", "file"])
def test_prepare_handover_run_directory_rejects_nonempty_or_file_path(tmp_path, kind):
    paths = _handover_paths(tmp_path)
    run = tmp_path / f"{kind}-run"
    if kind == "nonempty":
        run.mkdir()
        (run / "owned-by-user").write_bytes(b"preserve")
    else:
        run.write_bytes(b"preserve")

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(run, paths)

    assert caught.value.reason in {"RUN_DIRECTORY_NOT_EMPTY", "RUN_PATH_INVALID"}
    assert run.exists()
    if kind == "nonempty":
        assert (run / "owned-by-user").read_bytes() == b"preserve"
    else:
        assert run.read_bytes() == b"preserve"


@pytest.mark.parametrize("alias", ["component", "final"])
def test_prepare_handover_run_directory_rejects_symlink_components_and_final(
    tmp_path, alias
):
    paths = _handover_paths(tmp_path)
    real_parent = tmp_path / "real-runs"
    real_parent.mkdir()
    if alias == "component":
        (tmp_path / "linked-runs").symlink_to(real_parent, target_is_directory=True)
        run = tmp_path / "linked-runs/run"
    else:
        real_run = real_parent / "real-run"
        real_run.mkdir()
        run = tmp_path / "linked-run"
        run.symlink_to(real_run, target_is_directory=True)

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(run, paths)

    assert caught.value.reason == "RUN_PATH_ALIAS"


@pytest.mark.parametrize(
    "role",
    ["repository_root", "data_root", "graph", "dataset", "checkpoint", "asset_lock"],
)
@pytest.mark.parametrize("relationship", ["equal", "inside", "above"])
def test_prepare_handover_run_directory_rejects_role_overlap_in_both_directions(
    tmp_path, role, relationship
):
    paths = _handover_paths(tmp_path)
    restricted = getattr(paths, role)
    if relationship == "equal":
        run = restricted
    elif relationship == "inside":
        run = restricted / "run"
    else:
        run = restricted.parent

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(run, paths)

    assert caught.value.reason == "RUN_PATH_OVERLAP"


def test_prepare_handover_run_directory_rejects_identity_replacement_during_open(
    tmp_path, monkeypatch
):
    paths = _handover_paths(tmp_path)
    run = tmp_path / "run"
    run.mkdir()
    original_listdir = source_gate.os.listdir
    replaced = False

    def replace_after_open(path):
        nonlocal replaced
        result = original_listdir(path)
        if not replaced:
            replaced = True
            run.rename(tmp_path / "original-run")
            run.mkdir()
        return result

    monkeypatch.setattr(source_gate.os, "listdir", replace_after_open)

    with pytest.raises(AssetGateError) as caught:
        prepare_handover_run_directory(run, paths)

    assert caught.value.reason == "RUN_IDENTITY_CHANGED"


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


def test_generated_asset_lock_exactly_matches_the_three_derived_roots(
    tmp_path, monkeypatch
):
    lock = load_asset_lock(ASSET_LOCK)
    paths = _handover_paths(tmp_path)
    by_path = {
        getattr(paths, asset.role): AssetManifest(
            file_count=asset.file_count,
            byte_count=asset.byte_count,
            sha256=asset.sha256,
            files=asset.files,
        )
        for asset in lock.assets
    }
    monkeypatch.setattr(
        source_gate,
        "canonical_asset_manifest",
        lambda path: by_path[path],
    )

    measured = source_gate.measure_approved_asset_roots(paths)

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
