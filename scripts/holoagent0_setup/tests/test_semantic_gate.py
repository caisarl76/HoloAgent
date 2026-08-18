from __future__ import annotations

from dataclasses import replace
import hashlib
import importlib.machinery
import inspect
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

import holoagent0_setup.semantic_fixture_node as fixture_module
import holoagent0_setup.semantic_gate as semantic_gate_module
from holoagent0_setup.semantic_gate import (
    CHECKPOINT_SHA256,
    CYCLONE_CONFIG_SET_SHA256,
    DATASET_ROOT_SHA256,
    EXPECTED_SEMANTIC,
    EXPECTED_ROS_NODES,
    GRAPH_ROOT_SHA256,
    GraphCounts,
    GraphSnapshot,
    HMSGSelection,
    ROOM_NAME_MAPPING,
    ROOM_NAME_MAPPING_SHA256,
    RealHMSGRetrievalAdapter,
    SemanticGateError,
    StructuredQuery,
    STRUCTURED_QUERY_SHA256,
    TopicCardinality,
    evaluate_semantic_fixture,
    hmsg_query_configuration,
    import_root_hmsg_runtime,
    load_real_hmsg_adapter,
    offline_natural_language_parser_gate,
    semantic_evidence_reason,
    validate_ros_graph,
    validate_fixture_runtime_environment,
    verify_cyclone_roles,
)
from holoagent0_setup.semantic_fixture_node import SemanticFixtureController
from holoagent0_setup.source_gate import (
    AssetGateError,
    HandoverPaths,
    VerifiedAssetLock,
    canonical_asset_manifest,
    load_asset_lock,
    open_handover_asset_use,
    open_handover_run_directory,
    prepare_handover_run_directory,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
ASSET_LOCK = PACKAGE_ROOT / "locks/icra_ic4f-assets-v1.json"


def _portable_handover_paths(tmp_path: Path) -> HandoverPaths:
    repository_root = tmp_path / "repository"
    data_root = tmp_path / "data"
    graph_module = repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    graph_module.parent.mkdir(parents=True)
    graph_module.write_text("SOURCE = 'root'\n", encoding="utf-8")
    (repository_root / "fsr_vln/perception").mkdir()
    graph = (
        data_root
        / "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448"
    )
    graph.mkdir(parents=True)
    (graph / "graph.bin").write_bytes(b"graph")
    dataset = data_root / "fsr_vln/rgbd_datasets/icra_ic4f"
    dataset.mkdir(parents=True)
    (dataset / "frame.bin").write_bytes(b"dataset")
    checkpoint = data_root / "fsr_vln/checkpoints/open_clip_pytorch_model.bin"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_bytes(b"checkpoint")
    asset_lock = (
        repository_root / "scripts/holoagent0_setup/locks/icra_ic4f-assets-v1.json"
    )
    asset_lock.parent.mkdir(parents=True)
    asset_lock.write_bytes(ASSET_LOCK.read_bytes())
    copied_config = repository_root / "scripts/holoagent0_setup/config"
    copied_config.mkdir(parents=True)
    for source in sorted((PACKAGE_ROOT / "config").glob("cyclonedds-offline-p*.xml")):
        (copied_config / source.name).write_bytes(source.read_bytes())
    return HandoverPaths.from_roots(repository_root, data_root)


def _verified_lock(paths: HandoverPaths) -> VerifiedAssetLock:
    lock = load_asset_lock(paths)
    roles = ("graph", "dataset", "checkpoint")
    manifests = tuple(canonical_asset_manifest(getattr(paths, role)) for role in roles)
    assets = tuple(
        replace(
            next(asset for asset in lock.assets if asset.role == role),
            file_count=manifest.file_count,
            byte_count=manifest.byte_count,
            sha256=manifest.sha256,
            files=manifest.files,
        )
        for role, manifest in zip(roles, manifests)
    )
    return VerifiedAssetLock(lock=replace(lock, assets=assets), manifests=manifests)


def _fake_graph_module(origin: Path, graph_type=object):
    module = SimpleNamespace(
        Graph=graph_type,
        __file__=str(origin),
        __spec__=importlib.machinery.ModuleSpec(
            "memory.hmsg.graph.graph", loader=None, origin=str(origin)
        ),
    )
    return module


def _fake_omega_module(origin: Path, omega_conf=None):
    module = ModuleType("omegaconf")
    module.OmegaConf = object() if omega_conf is None else omega_conf
    module.__file__ = str(origin)
    module.__spec__ = importlib.machinery.ModuleSpec(
        "omegaconf", loader=None, origin=str(origin)
    )
    return module


def _install_transient_forbidden_probe(tmp_path, monkeypatch):
    environment = tmp_path / "transient-forbidden-import"
    package = environment / "rclpy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "transient_probe.py").write_text("PROBED = True\n", encoding="utf-8")
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_probe", raising=False)
    monkeypatch.syspath_prepend(str(environment))

    def trigger():
        importlib.import_module("rclpy.transient_probe")
        sys.modules.pop("rclpy.transient_probe", None)
        sys.modules.pop("rclpy", None)

    return trigger


def test_runtime_import_audit_canonicalizes_cached_relative_import(
    tmp_path, monkeypatch
):
    environment = tmp_path / "relative-forbidden-import"
    package = environment / "rclpy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "transient_relative.py").write_text("PROBED = True\n", encoding="utf-8")
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_relative", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    cached = importlib.import_module("rclpy.transient_relative")
    audit = semantic_gate_module.RuntimeImportAudit()

    with audit:
        assert importlib.import_module(".transient_relative", package="rclpy") is cached

    with pytest.raises(
        SemanticGateError,
        match="FORBIDDEN_RUNTIME_MODULE: rclpy.transient_relative",
    ):
        audit.require_allowed()


def test_runtime_import_audit_rejects_reentry_before_and_after_close():
    audit = semantic_gate_module.RuntimeImportAudit()
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit.__enter__()
    try:
        try:
            with pytest.raises(
                SemanticGateError,
                match="RUNTIME_IMPORT_AUDIT_INVALID: audit re-entry",
            ):
                audit.__enter__()
        finally:
            audit.close()

        with pytest.raises(
            SemanticGateError, match="RUNTIME_IMPORT_AUDIT_INVALID: audit re-entry"
        ):
            audit.__enter__()
    finally:
        semantic_gate_module.builtins.__import__ = original_builtin_import
        importlib.import_module = original_import_module

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_runtime_import_audit_rejects_out_of_order_close_then_recovers_lifo():
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    outer = semantic_gate_module.RuntimeImportAudit()
    inner = semantic_gate_module.RuntimeImportAudit()
    outer.__enter__()
    inner.__enter__()
    try:
        with pytest.raises(
            SemanticGateError,
            match="RUNTIME_IMPORT_AUDIT_INVALID: out-of-order close",
        ):
            outer.close()

        assert semantic_gate_module.builtins.__import__ is not original_builtin_import
        assert importlib.import_module is not original_import_module
        inner.close()
        outer.close()
    finally:
        semantic_gate_module.builtins.__import__ = original_builtin_import
        importlib.import_module = original_import_module
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_runtime_import_audit_force_unwinds_out_of_order_close_during_primary_error():
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    outer = semantic_gate_module.RuntimeImportAudit()
    inner = semantic_gate_module.RuntimeImportAudit()
    outer.__enter__()
    inner.__enter__()

    with pytest.raises(AssertionError, match="primary programmer failure"):
        try:
            raise AssertionError("primary programmer failure")
        finally:
            outer.close()

    inner.close()
    assert semantic_gate_module.RuntimeImportAudit._active_stack == []
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_runtime_import_audit_detects_hook_tamper_and_restores_originals():
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit = semantic_gate_module.RuntimeImportAudit()
    audit.__enter__()
    importlib.import_module = lambda *_args, **_kwargs: None

    with pytest.raises(
        SemanticGateError,
        match="RUNTIME_IMPORT_AUDIT_INVALID: import hooks were replaced",
    ):
        audit.close()

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_runtime_import_audit_hook_tamper_does_not_mask_active_programmer_error():
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit = semantic_gate_module.RuntimeImportAudit()
    audit.__enter__()
    importlib.import_module = lambda *_args, **_kwargs: None

    with pytest.raises(AssertionError, match="primary programmer failure"):
        try:
            raise AssertionError("primary programmer failure")
        finally:
            audit.close()

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def _memory_module_snapshot():
    return {
        name: module
        for name, module in sys.modules.items()
        if name == "memory" or name.startswith("memory.")
    }


def _perception_module_snapshot():
    return {
        name: module
        for name, module in sys.modules.items()
        if name == "perception" or name.startswith("perception.")
    }


class FakeAdapter:
    def __init__(self, *, counts=GraphCounts(1, 3, 497), selection=None):
        self._counts = counts
        self.selection = selection or HMSGSelection(
            graph_identity="icra_ic4f/graph_20260629211448",
            floor_id="0",
            room_id="0_0",
            room_name="Pantry",
            object_id="0_0_81",
            object_name="counter",
            scene_center=(
                -21.526786203133774,
                -0.27579107548158116,
                15.671372634872082,
            ),
        )
        self.queries = []

    def graph_counts(self):
        return self._counts

    def retrieve_structured(self, query):
        self.queries.append(query)
        return self.selection


def test_semantic_fixture_is_exact_and_bypasses_only_external_parser():
    adapter = FakeAdapter()

    result = evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)

    assert len(adapter.queries) == 1
    assert adapter.queries[0].text == "Take me to the counter in the pantry"
    assert adapter.queries[0].room_query == "Pantry"
    assert adapter.queries[0].object_query == "counter"
    assert result.query_text == "Take me to the counter in the pantry"
    assert (result.room_id, result.room_name) == ("0_0", "Pantry")
    assert (result.object_id, result.object_name) == ("0_0_81", "counter")
    assert result.frame_id == "map"
    assert result.position == pytest.approx(
        (-21.526786203133774, -15.671372634872082, -0.27579107548158116),
        abs=1e-6,
    )
    assert result.orientation == (0.0, 0.0, 0.0, 1.0)
    assert math.isclose(
        sum(value * value for value in result.orientation), 1.0, abs_tol=1e-9
    )
    assert result.structured_query_sha256 == STRUCTURED_QUERY_SHA256
    assert result.graph_root_sha256 == GRAPH_ROOT_SHA256
    assert result.dataset_root_sha256 == DATASET_ROOT_SHA256
    assert result.checkpoint_sha256 == CHECKPOINT_SHA256
    assert result.room_name_mapping_sha256 == ROOM_NAME_MAPPING_SHA256
    assert result.bypassed_network_seams == ("external_llm_parser",)
    assert result.pinned_fixture_preprocessing == ("room_name_mapping",)
    document = result.to_document()
    assert set(document) == {
        "schema_version",
        "query_text",
        "graph_identity",
        "floor_id",
        "room",
        "object",
        "frame_id",
        "position",
        "orientation",
        "structured_query_sha256",
        "graph_root_sha256",
        "dataset_root_sha256",
        "checkpoint_sha256",
        "room_name_mapping_sha256",
        "bypassed_network_seams",
        "pinned_fixture_preprocessing",
    }
    assert document["room"] == {"id": "0_0", "name": "Pantry"}
    assert document["object"] == {"id": "0_0_81", "name": "counter"}
    assert json.loads(result.canonical_json()) == document


def test_networked_natural_language_parser_is_explicitly_skipped_offline():
    assert offline_natural_language_parser_gate() == {
        "id": "semantic.natural_language_parser",
        "status": "SKIPPED",
        "role": "diagnostic",
        "reason": "POLICY_DISABLED",
        "measurements": [],
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


@pytest.mark.parametrize(
    ("internal", "closed"),
    [
        ("SEMANTIC_ASSET_UNAVAILABLE", "SEMANTIC_ASSET_MISMATCH"),
        ("CYCLONE_CONFIG_MISMATCH", "UNEXPECTED_DDS_PARTICIPANT"),
        ("ROS_GRAPH_MISMATCH", "UNEXPECTED_ROS_ENDPOINT"),
        ("SEMANTIC_QUERY_INVALID", "SEMANTIC_FIXTURE_MISMATCH"),
        ("SEMANTIC_DEPENDENCY_UNAVAILABLE", "TOOL_RUNTIME_ERROR"),
    ],
)
def test_internal_semantic_errors_translate_to_closed_evidence_reasons(
    internal, closed
):
    assert semantic_evidence_reason(SemanticGateError(internal, "detail")) == closed


def test_structured_query_is_closed_typed_and_asset_bound():
    expected = EXPECTED_SEMANTIC.query
    document = {
        "schema_version": "holoagent0-semantic-query-v1",
        "text": "Take me to the counter in the pantry",
        "floor_query": None,
        "room_query": "Pantry",
        "object_query": "counter",
        "graph_identity": "icra_ic4f/graph_20260629211448",
        "graph_root_sha256": GRAPH_ROOT_SHA256,
        "dataset_root_sha256": DATASET_ROOT_SHA256,
        "checkpoint_sha256": CHECKPOINT_SHA256,
    }

    assert StructuredQuery.from_json(expected.canonical_json()) == expected
    assert expected.to_document() == document

    for key, replacement in (
        ("floor_query", "0"),
        ("text", 123),
        ("graph_identity", "other/graph"),
        ("graph_root_sha256", "0" * 64),
    ):
        invalid = dict(document)
        invalid[key] = replacement
        with pytest.raises(SemanticGateError, match="SEMANTIC_QUERY_INVALID"):
            StructuredQuery.from_json(json.dumps(invalid))

    extra = dict(document, unreviewed=True)
    with pytest.raises(SemanticGateError, match="SEMANTIC_QUERY_INVALID"):
        StructuredQuery.from_json(json.dumps(extra))

    with pytest.raises(SemanticGateError, match="SEMANTIC_QUERY_INVALID"):
        StructuredQuery.from_json(json.dumps(document, indent=2))

    duplicate = expected.canonical_json().replace(
        '"text":', '"text":"Take me to the counter in the pantry","text":', 1
    )
    with pytest.raises(SemanticGateError, match="SEMANTIC_QUERY_INVALID"):
        StructuredQuery.from_json(duplicate)


@pytest.mark.parametrize(
    "adapter",
    [
        FakeAdapter(counts=GraphCounts(2, 3, 497)),
        FakeAdapter(selection=replace(FakeAdapter().selection, object_id="0_0_80")),
        FakeAdapter(
            selection=replace(FakeAdapter().selection, scene_center=(0.0, 0.0, 0.0))
        ),
    ],
)
def test_semantic_fixture_rejects_wrong_graph_counts_identity_or_pose(adapter):
    with pytest.raises(SemanticGateError, match="SEMANTIC_FIXTURE_MISMATCH"):
        evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)


def test_real_adapter_calls_hmsg_room_object_retrieval_and_coordinate_transform():
    calls = []
    room = SimpleNamespace(room_id="0_0", floor_id="0", name="Pantry")
    obj = SimpleNamespace(
        object_id="0_0_81",
        name="counter",
        pcd=SimpleNamespace(
            get_center=lambda: (
                -21.526786203133774,
                -0.27579107548158116,
                15.671372634872082,
            )
        ),
    )
    graph = SimpleNamespace(
        floors=[SimpleNamespace(floor_id="0")],
        rooms=[
            room,
            SimpleNamespace(room_id="0_1", name="Office"),
            SimpleNamespace(room_id="0_2", name="Hallway"),
        ],
        objects=[
            obj,
            *[SimpleNamespace(object_id=f"other_{index}") for index in range(496)],
        ],
        query_hmsg_room=lambda query, **kwargs: (
            calls.append(("room", query, kwargs)) or [0]
        ),
        query_hmsg_object=lambda query, **kwargs: (
            calls.append(("object", query, kwargs)) or ([0], [0], [0.9])
        ),
    )
    adapter = RealHMSGRetrievalAdapter(
        graph,
        graph_identity="icra_ic4f/graph_20260629211448",
    )

    result = evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)

    assert calls == [
        ("room", "Pantry", {"floor_id": -1, "query_method": "label"}),
        (
            "object",
            "counter",
            {
                "floor_id": -1,
                "room_ids": [0],
                "top_k": 1,
                "negative_prompt": ["background"],
            },
        ),
    ]
    assert result.position == EXPECTED_SEMANTIC.position


def test_real_hmsg_query_configuration_derives_assets_only_from_handover_paths(
    tmp_path,
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"
    run_identity = prepare_handover_run_directory(run_directory, paths)

    with open_handover_run_directory(paths, run_identity) as run_authority:
        with open_handover_asset_use(paths, _verified_lock(paths)) as asset_authority:
            configuration = hmsg_query_configuration(
                paths, asset_authority, run_authority
            )
            assert configuration["main"]["use_gpt"] is False
            assert configuration["models"]["clip"]["type"] == "ViT-L/14"
            assert os.path.samefile(configuration["main"]["graph_path"], paths.graph)
            assert os.path.samefile(
                configuration["models"]["clip"]["checkpoint"], paths.checkpoint
            )
            assert os.path.samefile(configuration["main"]["save_path"], run_directory)


def test_real_adapter_public_api_accepts_only_paths_and_run_directory():
    assert tuple(inspect.signature(load_real_hmsg_adapter).parameters) == (
        "paths",
        "run_directory",
    )


def test_root_hmsg_runtime_import_uses_exact_root_origin_and_restores_sys_path(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    expected = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    graph_module = _fake_graph_module(expected)
    omega_conf = object()
    imports = []
    before = tuple(sys.path)

    def import_module(name):
        imports.append((name, tuple(sys.path)))
        assert tuple(sys.path) == before
        if name == "memory.hmsg.graph.graph":
            return graph_module
        if name == "omegaconf":
            return _fake_omega_module(tmp_path / "environment/omegaconf.py", omega_conf)
        raise AssertionError(name)

    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.importlib.import_module", import_module
    )

    loaded_module, loaded_omega_conf, origin = import_root_hmsg_runtime(paths)

    assert (loaded_module, loaded_omega_conf, origin) == (
        graph_module,
        omega_conf,
        expected,
    )
    assert [name for name, _path in imports] == [
        "memory.hmsg.graph.graph",
        "omegaconf",
    ]
    assert tuple(sys.path) == before


def test_root_hmsg_runtime_rejects_agentic_origin(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    wrong = paths.repository_root / "agentic_robot/fsr_vln/memory/hmsg/graph/graph.py"
    wrong.parent.mkdir(parents=True)
    wrong.write_text("# forbidden origin\n", encoding="utf-8")

    def import_module(name):
        if name == "memory.hmsg.graph.graph":
            return _fake_graph_module(wrong)
        return _fake_omega_module(tmp_path / "environment/omegaconf.py")

    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.importlib.import_module", import_module
    )

    with pytest.raises(SemanticGateError, match="unexpected HMSG module origin"):
        import_root_hmsg_runtime(paths)


def test_root_hmsg_runtime_ignores_and_restores_stale_cached_wrong_module(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    stale = tmp_path / "stale/memory/hmsg/graph/graph.py"
    stale.parent.mkdir(parents=True)
    stale.write_text("# stale cached origin\n", encoding="utf-8")
    monkeypatch.setitem(
        sys.modules, "memory.hmsg.graph.graph", _fake_graph_module(stale)
    )
    monkeypatch.setitem(
        sys.modules,
        "omegaconf",
        _fake_omega_module(tmp_path / "environment/omegaconf.py"),
    )

    stale_module = sys.modules["memory.hmsg.graph.graph"]

    graph_module, _omega_conf, origin = import_root_hmsg_runtime(paths)

    assert graph_module is not stale_module
    assert graph_module.SOURCE == "root"
    assert origin == paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    assert sys.modules["memory.hmsg.graph.graph"] is stale_module


def test_root_hmsg_runtime_does_not_execute_competing_regular_memory_package(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    hostile = tmp_path / "hostile"
    marker = tmp_path / "hostile-executed"
    hostile_memory = hostile / "memory"
    hostile_memory.mkdir(parents=True)
    (hostile_memory / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    for name in tuple(_memory_module_snapshot()):
        monkeypatch.delitem(sys.modules, name)
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    monkeypatch.syspath_prepend(str(hostile))
    before_path = tuple(sys.path)

    graph_module, _omega_conf, origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root"
    assert origin == paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    assert not marker.exists()
    assert _memory_module_snapshot() == {}
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_does_not_execute_untracked_local_omegaconf_shadow(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    shadow_marker = tmp_path / "local-omegaconf-executed"
    (fsr_root / "omegaconf.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(shadow_marker)!r}).write_text('executed')\n"
        "raise RuntimeError('untracked OmegaConf shadow executed')\n",
        encoding="utf-8",
    )
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n    SOURCE = 'environment'\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "omegaconf", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    monkeypatch.syspath_prepend(str(fsr_root))
    before_path = tuple(sys.path)

    graph_module, omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root"
    assert omega_conf.SOURCE == "environment"
    assert not shadow_marker.exists()
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_excludes_descendant_omegaconf_shadow_and_restores_state(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    vendor = fsr_root / "vendor"
    vendor.mkdir()
    shadow_marker = tmp_path / "vendor-omegaconf-executed"
    (vendor / "omegaconf.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(shadow_marker)!r}).write_text('executed')\n"
        "raise RuntimeError('vendor OmegaConf shadow executed')\n",
        encoding="utf-8",
    )
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n    SOURCE = 'environment'\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "omegaconf", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    monkeypatch.syspath_prepend(str(vendor))
    before_path = tuple(sys.path)
    before_modules = dict(sys.modules)

    graph_module, omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root"
    assert omega_conf.SOURCE == "environment"
    assert not shadow_marker.exists()
    assert tuple(sys.path) == before_path
    assert set(sys.modules) == set(before_modules)
    assert all(sys.modules[name] is module for name, module in before_modules.items())


def test_root_hmsg_runtime_replaces_cached_local_omegaconf_then_restores_it(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    local_omega_path = fsr_root / "omegaconf.py"
    local_marker = tmp_path / "cached-local-omegaconf-executed"
    local_omega_path.write_text(
        "from pathlib import Path\n"
        f"Path({str(local_marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    class CachedLocalOmegaConf:
        SOURCE = "cached local"

    cached_local = _fake_omega_module(local_omega_path, CachedLocalOmegaConf)
    monkeypatch.setitem(sys.modules, "omegaconf", cached_local)
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n    SOURCE = 'environment'\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(environment))
    before_path = tuple(sys.path)
    before_modules = dict(sys.modules)

    graph_module, omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root"
    assert omega_conf.SOURCE == "environment"
    assert not local_marker.exists()
    assert tuple(sys.path) == before_path
    assert set(sys.modules) == set(before_modules)
    assert all(sys.modules[name] is module for name, module in before_modules.items())
    assert sys.modules["omegaconf"] is cached_local


def test_root_hmsg_runtime_handles_missing_and_non_path_sys_path_entries(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n    SOURCE = 'environment'\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "omegaconf", raising=False)
    opaque_entry = object()
    before_path = (
        str(fsr_root / "missing-vendor"),
        opaque_entry,
        str(environment),
        *sys.path,
    )
    monkeypatch.setattr(sys, "path", list(before_path))

    graph_module, omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root"
    assert omega_conf.SOURCE == "environment"
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_requires_omegaconf_filesystem_origin(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    expected = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    graph_module = _fake_graph_module(expected)
    originless_omega = ModuleType("omegaconf")
    originless_omega.OmegaConf = object()

    def import_module(name):
        if name == "memory.hmsg.graph.graph":
            return graph_module
        if name == "omegaconf":
            return originless_omega
        raise AssertionError(name)

    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.importlib.import_module", import_module
    )

    with pytest.raises(SemanticGateError, match="OmegaConf module.*origin"):
        import_root_hmsg_runtime(paths)


def test_root_hmsg_runtime_isolates_exact_local_perception_from_competing_package(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    local_helper = fsr_root / "perception/helpers.py"
    local_helper.write_text("SOURCE = 'root perception'\n", encoding="utf-8")
    (fsr_root / "memory/hmsg/graph/graph.py").write_text(
        "from perception import helpers\nSOURCE = helpers.SOURCE\n",
        encoding="utf-8",
    )
    hostile = tmp_path / "hostile"
    hostile_perception = hostile / "perception"
    hostile_perception.mkdir(parents=True)
    hostile_marker = tmp_path / "hostile-perception-executed"
    (hostile_perception / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(hostile_marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    (hostile_perception / "helpers.py").write_text(
        "SOURCE = 'hostile perception'\n", encoding="utf-8"
    )
    for name in tuple(_perception_module_snapshot()):
        monkeypatch.delitem(sys.modules, name)
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    monkeypatch.syspath_prepend(str(hostile))
    before_path = tuple(sys.path)

    graph_module, _omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root perception"
    assert Path(graph_module.helpers.__file__) == local_helper
    assert not hostile_marker.exists()
    assert _perception_module_snapshot() == {}
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_ignores_mixed_cache_and_restores_exact_objects(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    stale_root = ModuleType("memory")
    stale_root.__path__ = [str(tmp_path / "stale-memory")]
    stale_leaf = _fake_graph_module(tmp_path / "stale/graph.py")
    monkeypatch.setitem(sys.modules, "memory", stale_root)
    monkeypatch.setitem(sys.modules, "memory.hmsg.graph.graph", stale_leaf)
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    before_modules = _memory_module_snapshot()
    before_path = tuple(sys.path)

    graph_module, _omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module is not stale_leaf
    assert graph_module.SOURCE == "root"
    assert _memory_module_snapshot() == before_modules
    assert all(
        _memory_module_snapshot()[name] is module
        for name, module in before_modules.items()
    )
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_ignores_and_restores_stale_perception_cache(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    local_helper = fsr_root / "perception/helpers.py"
    local_helper.write_text("SOURCE = 'root perception'\n", encoding="utf-8")
    (fsr_root / "memory/hmsg/graph/graph.py").write_text(
        "from perception import helpers\nSOURCE = helpers.SOURCE\n",
        encoding="utf-8",
    )
    stale_root = ModuleType("perception")
    stale_root.__path__ = [str(tmp_path / "stale-perception")]
    stale_helper = ModuleType("perception.helpers")
    stale_helper.SOURCE = "stale perception"
    monkeypatch.setitem(sys.modules, "perception", stale_root)
    monkeypatch.setitem(sys.modules, "perception.helpers", stale_helper)
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    before_modules = _perception_module_snapshot()
    before_path = tuple(sys.path)

    graph_module, _omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "root perception"
    assert Path(graph_module.helpers.__file__) == local_helper
    assert _perception_module_snapshot() == before_modules
    assert all(
        _perception_module_snapshot()[name] is module
        for name, module in before_modules.items()
    )
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_restores_cache_and_path_after_import_failure(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    expected = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    expected.write_text("raise RuntimeError('import boom')\n", encoding="utf-8")
    stale_root = ModuleType("memory")
    monkeypatch.setitem(sys.modules, "memory", stale_root)
    before_modules = _memory_module_snapshot()
    before_path = tuple(sys.path)

    with pytest.raises(SemanticGateError, match="import boom"):
        import_root_hmsg_runtime(paths)

    assert _memory_module_snapshot() == before_modules
    assert sys.modules["memory"] is stale_root
    assert tuple(sys.path) == before_path


@pytest.mark.parametrize("replace_root", [False, True])
def test_root_hmsg_runtime_restores_state_when_repository_root_drifts_at_boundary(
    tmp_path, monkeypatch, replace_root
):
    paths = _portable_handover_paths(tmp_path)
    repository_root = paths.repository_root
    moved_root = tmp_path / "original-repository"
    stale_memory = ModuleType("memory")
    stale_perception = ModuleType("perception")
    monkeypatch.setitem(sys.modules, "memory", stale_memory)
    monkeypatch.setitem(sys.modules, "perception", stale_perception)
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    before_memory = _memory_module_snapshot()
    before_perception = _perception_module_snapshot()
    before_path = tuple(sys.path)
    original_revalidate = HandoverPaths.revalidate
    mutated = False

    def revalidate_then_drift(self):
        nonlocal mutated
        original_revalidate(self)
        if not mutated:
            repository_root.rename(moved_root)
            if replace_root:
                replacement_graph = (
                    repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
                )
                replacement_graph.parent.mkdir(parents=True)
                replacement_graph.write_text(
                    "SOURCE = 'replacement'\n", encoding="utf-8"
                )
                (repository_root / "fsr_vln/perception").mkdir()
            mutated = True

    monkeypatch.setattr(HandoverPaths, "revalidate", revalidate_then_drift)

    with pytest.raises(SemanticGateError) as caught:
        import_root_hmsg_runtime(paths)

    assert caught.value.reason == "SEMANTIC_ASSET_UNAVAILABLE"
    assert _memory_module_snapshot() == before_memory
    assert _perception_module_snapshot() == before_perception
    assert all(
        _memory_module_snapshot()[name] is module
        for name, module in before_memory.items()
    )
    assert all(
        _perception_module_snapshot()[name] is module
        for name, module in before_perception.items()
    )
    assert tuple(sys.path) == before_path


def test_root_hmsg_runtime_restores_the_entire_module_cache(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "transient_dependency.py").write_text(
        "VALUE = 'transient'\n", encoding="utf-8"
    )
    (fsr_root / "memory/hmsg/graph/graph.py").write_text(
        "import transient_dependency\nSOURCE = transient_dependency.VALUE\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "transient_dependency", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    omega_module = _fake_omega_module(tmp_path / "environment/omegaconf.py")
    monkeypatch.setitem(sys.modules, "omegaconf", omega_module)
    before = dict(sys.modules)

    graph_module, _omega_conf, _origin = import_root_hmsg_runtime(paths)

    assert graph_module.SOURCE == "transient"
    assert set(sys.modules) == set(before)
    assert all(sys.modules[name] is module for name, module in before.items())


def test_real_importer_adapter_guards_actual_llm_bindings_during_one_fixed_query(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    fsr_root = paths.repository_root / "fsr_vln"
    llm_utils = fsr_root / "memory/hmsg/utils/llm_utils.py"
    llm_utils.parent.mkdir(parents=True)
    seams = (
        "create_llm_client",
        "create_chat_completion",
        "get_llm_model",
        "parse_hier_query",
        "parse_hier_query_use_prompt_insentence_parse",
        "parse_hier_query_use_prompt_insentence_parse_icra",
        "parse_floor_room_object_gpt35",
        "parse_floor_room_object_gpt40",
        "infer_floor_id_from_query",
        "infer_room_type_from_object_list_chat",
    )
    llm_utils.write_text(
        "CALLS = []\n"
        "def _seam(name):\n"
        "    def invoke(*args, **kwargs):\n"
        "        CALLS.append(name)\n"
        "        raise AssertionError(f'{name} must be bypassed')\n"
        "    return invoke\n"
        + "".join(f"{name} = _seam({name!r})\n" for name in seams)
        + f"ORIGINALS = {{{', '.join(f'{name!r}: {name}' for name in seams)}}}\n",
        encoding="utf-8",
    )
    graph_bound_seams = tuple(
        name
        for name in seams
        if name
        not in {
            "infer_room_type_from_object_list_chat",
            "parse_floor_room_object_gpt40",
        }
    )
    graph_module = fsr_root / "memory/hmsg/graph/graph.py"
    graph_module.write_text(
        "from types import SimpleNamespace\n"
        "from memory.hmsg.utils import llm_utils\n"
        "from memory.hmsg.utils.llm_utils import (\n"
        + "".join(f"    {name},\n" for name in graph_bound_seams)
        + ")\n"
        + f"ORIGINAL_BINDINGS = {{{', '.join(f'{name!r}: {name}' for name in graph_bound_seams)}}}\n"
        "class _PointCloud:\n"
        "    def get_center(self):\n"
        "        return (-21.526786203133774, -0.27579107548158116, 15.671372634872082)\n"
        "class Graph:\n"
        "    def __init__(self, configuration):\n"
        "        assert configuration['main']['use_gpt'] is False\n"
        "        self.query_calls = []\n"
        "        self.floors = [object()]\n"
        "        self.rooms = [\n"
        "            SimpleNamespace(floor_id='0', room_id='0_0', name='Pantry'),\n"
        "            SimpleNamespace(floor_id='0', room_id='0_1', name='Office'),\n"
        "            SimpleNamespace(floor_id='0', room_id='0_2', name='Hallway'),\n"
        "        ]\n"
        "        selected = SimpleNamespace(\n"
        "            object_id='0_0_81', name='counter', pcd=_PointCloud())\n"
        "        self.objects = [selected] + [object() for _ in range(496)]\n"
        "    def load_graph(self, graph_path):\n"
        "        self.graph_path = graph_path\n"
        "    def set_room_names(self, *, room_names):\n"
        "        assert room_names == ['Pantry', 'Office', 'Hallway']\n"
        "    def query_hmsg_room(self, query, **kwargs):\n"
        "        self.query_calls.append(('room', query, kwargs))\n"
        "        return [0]\n"
        "    def query_hmsg_object(self, query, **kwargs):\n"
        "        self.query_calls.append(('object', query, kwargs))\n"
        "        return ([0], [0], [0.9])\n",
        encoding="utf-8",
    )
    environment = tmp_path / "environment"
    environment.mkdir()
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n"
        "    @staticmethod\n"
        "    def create(value):\n"
        "        return value\n",
        encoding="utf-8",
    )
    monkeypatch.delitem(sys.modules, "omegaconf", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda actual_paths: _verified_lock(actual_paths),
    )
    historical_openai = sys.modules.get("openai")
    sys.modules["openai"] = SimpleNamespace(HISTORICAL=True)
    adapter = None
    try:
        adapter = load_real_hmsg_adapter(paths, tmp_path / "run")
        result = evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)
        graph = adapter._graph
        graph_globals = graph.__class__.__init__.__globals__
        imported_llm_utils = graph_globals["llm_utils"]

        assert result.query_text == EXPECTED_SEMANTIC.query.text
        assert result.graph_identity == EXPECTED_SEMANTIC.graph_identity
        assert result.room_id == EXPECTED_SEMANTIC.room_id
        assert result.object_id == EXPECTED_SEMANTIC.object_id
        assert result.position == EXPECTED_SEMANTIC.position
        assert [entry[0] for entry in graph.query_calls] == ["room", "object"]
        assert imported_llm_utils.CALLS == []
        assert all(
            graph_globals[name] is not graph_globals["ORIGINAL_BINDINGS"][name]
            for name in graph_bound_seams
        )
        assert all(
            getattr(imported_llm_utils, name) is not imported_llm_utils.ORIGINALS[name]
            for name in seams
        )
        for name in graph_bound_seams:
            with pytest.raises(
                SemanticGateError, match=f"SEMANTIC_EXTERNAL_LLM_ATTEMPT: {name}"
            ):
                graph_globals[name]()
        with pytest.raises(
            SemanticGateError,
            match="SEMANTIC_EXTERNAL_LLM_ATTEMPT: parse_floor_room_object_gpt40",
        ):
            imported_llm_utils.parse_floor_room_object_gpt40()
        assert imported_llm_utils.CALLS == []
        assert sys.modules["openai"].HISTORICAL is True
        adapter.close()
        adapter = None
        assert all(
            graph_globals[name] is graph_globals["ORIGINAL_BINDINGS"][name]
            for name in graph_bound_seams
        )
        assert all(
            getattr(imported_llm_utils, name) is imported_llm_utils.ORIGINALS[name]
            for name in seams
        )
    finally:
        if adapter is not None:
            adapter.close()
        if historical_openai is None:
            sys.modules.pop("openai", None)
        else:
            sys.modules["openai"] = historical_openai


def test_real_adapter_closes_run_authority_when_llm_guard_detects_tampering():
    def seam(*_args, **_kwargs):
        raise AssertionError("original seam must not run")

    llm_utils = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._LLM_UTILS_SEAMS}
    )
    graph_module = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._GRAPH_LLM_SEAMS}
    )
    setattr(
        graph_module,
        semantic_gate_module._LLM_UTILS_MODULE_ATTRIBUTE,
        llm_utils,
    )
    guard = semantic_gate_module._guard_external_llm_seams(graph_module)
    closed = []
    authority = SimpleNamespace(close=lambda: closed.append(True))
    adapter = RealHMSGRetrievalAdapter(
        SimpleNamespace(),
        graph_identity=EXPECTED_SEMANTIC.graph_identity,
        run_authority=authority,
        llm_guard=guard,
    )
    graph_module.create_llm_client = seam

    with pytest.raises(
        SemanticGateError,
        match="SEMANTIC_EXTERNAL_LLM_ATTEMPT: guarded seam binding changed: "
        "create_llm_client",
    ):
        adapter.close()

    assert closed == [True]


@pytest.mark.parametrize(
    "primary_error",
    (
        AssertionError("query programmer failure"),
        SemanticGateError("QUERY_FIRST_BLOCKER", "query anticipated failure"),
    ),
)
@pytest.mark.parametrize("exit_style", ("finally", "context_manager"))
def test_real_adapter_cleanup_failures_do_not_mask_active_query_error(
    primary_error, exit_style, tmp_path, monkeypatch
):
    trigger = _install_transient_forbidden_probe(tmp_path, monkeypatch)

    def seam(*_args, **_kwargs):
        raise AssertionError("original LLM seam must not run")

    llm_utils = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._LLM_UTILS_SEAMS}
    )
    graph_module = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._GRAPH_LLM_SEAMS}
    )
    setattr(
        graph_module,
        semantic_gate_module._LLM_UTILS_MODULE_ATTRIBUTE,
        llm_utils,
    )
    guard = semantic_gate_module._guard_external_llm_seams(graph_module)
    read_descriptor, write_descriptor = os.pipe()
    authority_closes = []

    class FailingAuthority:
        def revalidate(self):
            os.fstat(read_descriptor)

        def close(self):
            authority_closes.append(True)
            os.close(read_descriptor)
            raise OSError("authority cleanup failure")

    def query_room(*_args, **_kwargs):
        trigger()
        graph_module.create_llm_client = seam
        raise primary_error

    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit = semantic_gate_module.RuntimeImportAudit()
    audit.__enter__()
    adapter = RealHMSGRetrievalAdapter(
        SimpleNamespace(query_hmsg_room=query_room),
        graph_identity=EXPECTED_SEMANTIC.graph_identity,
        run_authority=FailingAuthority(),
        llm_guard=guard,
        import_audit=audit,
    )

    try:
        with pytest.raises(type(primary_error)) as caught:
            if exit_style == "context_manager":
                with adapter:
                    adapter.retrieve_structured(EXPECTED_SEMANTIC.query)
            else:
                try:
                    adapter.retrieve_structured(EXPECTED_SEMANTIC.query)
                finally:
                    adapter.close()
    finally:
        os.close(write_descriptor)
        audit.close()

    assert caught.value is primary_error
    assert authority_closes == [True]
    with pytest.raises(OSError):
        os.fstat(read_descriptor)
    assert graph_module.create_llm_client is seam
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_real_adapter_first_cleanup_error_wins_while_all_cleanup_is_attempted():
    def seam(*_args, **_kwargs):
        raise AssertionError("original LLM seam must not run")

    llm_utils = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._LLM_UTILS_SEAMS}
    )
    graph_module = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._GRAPH_LLM_SEAMS}
    )
    setattr(
        graph_module,
        semantic_gate_module._LLM_UTILS_MODULE_ATTRIBUTE,
        llm_utils,
    )
    guard = semantic_gate_module._guard_external_llm_seams(graph_module)
    graph_module.create_llm_client = seam
    authority_closes = []

    def close_authority():
        authority_closes.append(True)
        raise OSError("later authority cleanup failure")

    adapter = RealHMSGRetrievalAdapter(
        SimpleNamespace(),
        graph_identity=EXPECTED_SEMANTIC.graph_identity,
        run_authority=SimpleNamespace(close=close_authority),
        llm_guard=guard,
    )

    with pytest.raises(
        SemanticGateError,
        match="SEMANTIC_EXTERNAL_LLM_ATTEMPT: guarded seam binding changed: "
        "create_llm_client",
    ):
        adapter.close()

    assert authority_closes == [True]
    assert graph_module.create_llm_client is seam


def test_real_loader_cleanup_failures_do_not_mask_constructor_programmer_error(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_descriptors = []

    def seam(*_args, **_kwargs):
        raise AssertionError("original LLM seam must not run")

    graph_module = None

    class FakeGraph:
        def __init__(self, configuration):
            run_descriptors.append(int(Path(configuration["main"]["save_path"]).name))
            graph_module.create_llm_client = seam
            raise AssertionError("constructor programmer failure")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    graph_module = _fake_graph_module(origin, FakeGraph)
    llm_utils = SimpleNamespace(
        **{name: seam for name in semantic_gate_module._LLM_UTILS_SEAMS}
    )
    for name in semantic_gate_module._GRAPH_LLM_SEAMS:
        setattr(graph_module, name, seam)
    setattr(
        graph_module,
        semantic_gate_module._LLM_UTILS_MODULE_ATTRIBUTE,
        llm_utils,
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            graph_module,
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    authority_closes = []
    original_close = semantic_gate_module.HandoverRunDirectoryAuthority.close

    def close_then_fail(authority):
        authority_closes.append(True)
        original_close(authority)
        raise OSError("loader authority cleanup failure")

    monkeypatch.setattr(
        semantic_gate_module.HandoverRunDirectoryAuthority,
        "close",
        close_then_fail,
    )
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module

    with pytest.raises(AssertionError, match="constructor programmer failure"):
        load_real_hmsg_adapter(paths, tmp_path / "run")

    assert authority_closes == [True]
    assert graph_module.create_llm_client is seam
    for descriptor in run_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module


def test_real_adapter_uses_verified_paths_configuration_and_room_mapping(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"
    observed = {}

    class FakeOmegaConf:
        @staticmethod
        def create(configuration):
            observed["configuration"] = configuration
            return configuration

    class FakeGraph:
        def __init__(self, configuration):
            observed["constructed"] = configuration
            observed["graph_bound"] = os.path.samefile(
                configuration["main"]["graph_path"], paths.graph
            )
            observed["checkpoint_bound"] = os.path.samefile(
                configuration["models"]["clip"]["checkpoint"], paths.checkpoint
            )
            observed["run_bound"] = os.path.samefile(
                configuration["main"]["save_path"], run_directory
            )

        def load_graph(self, graph_path):
            observed["load_bound"] = os.path.samefile(graph_path, paths.graph)

        def set_room_names(self, *, room_names):
            observed["room_names"] = room_names

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.import_root_hmsg_runtime",
        lambda bound: (_fake_graph_module(origin, FakeGraph), FakeOmegaConf, origin),
    )

    adapter = load_real_hmsg_adapter(paths, run_directory)

    assert isinstance(adapter, RealHMSGRetrievalAdapter)
    configuration = observed["configuration"]
    assert configuration["main"]["use_gpt"] is False
    assert configuration["models"]["clip"]["type"] == "ViT-L/14"
    assert configuration["main"]["graph_path"].startswith("/proc/self/fd/")
    assert configuration["main"]["save_path"].startswith("/proc/self/fd/")
    assert configuration["models"]["clip"]["checkpoint"].startswith("/proc/self/fd/")
    assert observed["constructed"] is configuration
    assert observed["graph_bound"] is True
    assert observed["checkpoint_bound"] is True
    assert observed["run_bound"] is True
    assert observed["load_bound"] is True
    assert observed["room_names"] == ["Pantry", "Office", "Hallway"]
    run_descriptor = int(Path(configuration["main"]["save_path"]).name)
    assert os.fstat(run_descriptor)
    adapter.close()
    with pytest.raises(OSError):
        os.fstat(run_descriptor)
    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        adapter.graph_counts()


@pytest.mark.parametrize("phase", ("construction", "load"))
def test_real_adapter_rejects_transient_forbidden_import_during_loading(
    phase, tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    trigger = _install_transient_forbidden_probe(tmp_path, monkeypatch)
    run_descriptors = []

    class FakeGraph:
        def __init__(self, configuration):
            run_descriptors.append(int(Path(configuration["main"]["save_path"]).name))
            if phase == "construction":
                trigger()

        def load_graph(self, _graph_path):
            if phase == "load":
                trigger()

        def set_room_names(self, *, room_names):
            pass

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module

    with pytest.raises(
        SemanticGateError,
        match="FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe",
    ):
        load_real_hmsg_adapter(paths, tmp_path / "run")

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules
    assert run_descriptors
    for descriptor in run_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_real_adapter_restores_lifecycle_audit_without_masking_programmer_exception(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_descriptors = []

    class FakeGraph:
        def __init__(self, configuration):
            run_descriptors.append(int(Path(configuration["main"]["save_path"]).name))
            raise AssertionError("programmer failure")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module

    with pytest.raises(AssertionError, match="programmer failure"):
        load_real_hmsg_adapter(paths, tmp_path / "run")

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert run_descriptors
    for descriptor in run_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_real_adapter_rejects_transient_forbidden_import_during_fixed_query(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    trigger = _install_transient_forbidden_probe(tmp_path, monkeypatch)
    query_calls = []

    class FakeGraph:
        def __init__(self, _configuration):
            self.floors = [object()]
            self.rooms = [
                SimpleNamespace(floor_id="0", room_id="0_0", name="Pantry"),
                SimpleNamespace(floor_id="0", room_id="0_1", name="Office"),
                SimpleNamespace(floor_id="0", room_id="0_2", name="Hallway"),
            ]
            selected = SimpleNamespace(
                object_id="0_0_81",
                name="counter",
                pcd=SimpleNamespace(
                    get_center=lambda: (
                        -21.526786203133774,
                        -0.27579107548158116,
                        15.671372634872082,
                    )
                ),
            )
            self.objects = [selected, *[object() for _ in range(496)]]

        def load_graph(self, _graph_path):
            pass

        def set_room_names(self, *, room_names):
            pass

        def query_hmsg_room(self, query, **kwargs):
            query_calls.append(("room", query, kwargs))
            trigger()
            return [0]

        def query_hmsg_object(self, query, **kwargs):
            query_calls.append(("object", query, kwargs))
            return ([0], [0], [0.9])

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    adapter = load_real_hmsg_adapter(paths, tmp_path / "run")

    try:
        with pytest.raises(
            SemanticGateError,
            match="FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe",
        ):
            evaluate_semantic_fixture(adapter, EXPECTED_SEMANTIC.query)
        assert [call[0] for call in query_calls] == ["room", "object"]
        assert semantic_gate_module.builtins.__import__ is not original_builtin_import
        assert importlib.import_module is not original_import_module
    finally:
        with pytest.raises(
            SemanticGateError,
            match="FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe",
        ):
            adapter.close()

    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules


def test_real_adapter_close_does_not_mask_query_programmer_exception_after_forbidden_import(
    tmp_path, monkeypatch
):
    trigger = _install_transient_forbidden_probe(tmp_path, monkeypatch)
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit = semantic_gate_module._ImportBoundaryAudit()
    audit.__enter__()
    read_descriptor, write_descriptor = os.pipe()

    class DescriptorAuthority:
        def revalidate(self):
            os.fstat(read_descriptor)

        def close(self):
            os.close(read_descriptor)

    def query_room(*_args, **_kwargs):
        trigger()
        raise AssertionError("query programmer failure")

    graph = SimpleNamespace(query_hmsg_room=query_room)
    adapter = RealHMSGRetrievalAdapter(
        graph,
        graph_identity=EXPECTED_SEMANTIC.graph_identity,
        run_authority=DescriptorAuthority(),
        import_audit=audit,
    )

    try:
        with pytest.raises(AssertionError, match="query programmer failure"):
            try:
                adapter.retrieve_structured(EXPECTED_SEMANTIC.query)
            finally:
                adapter.close()
    finally:
        os.close(write_descriptor)
        audit.close()

    with pytest.raises(OSError):
        os.fstat(read_descriptor)
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules


def test_real_adapter_rejects_transient_forbidden_import_during_close_and_restores_hooks(
    tmp_path, monkeypatch
):
    trigger = _install_transient_forbidden_probe(tmp_path, monkeypatch)
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module
    audit = semantic_gate_module._ImportBoundaryAudit()
    audit.__enter__()
    authority_closes = []
    adapter = RealHMSGRetrievalAdapter(
        SimpleNamespace(),
        graph_identity=EXPECTED_SEMANTIC.graph_identity,
        run_authority=SimpleNamespace(close=lambda: authority_closes.append(True)),
        llm_guard=SimpleNamespace(close=trigger),
        import_audit=audit,
    )

    with pytest.raises(
        SemanticGateError,
        match="FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe",
    ):
        adapter.close()

    assert authority_closes == [True]
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules


def test_real_adapter_detects_checkpoint_drift_during_graph_construction(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    leaked_descriptors = []

    class FakeGraph:
        def __init__(self, configuration):
            for value in (
                configuration["main"]["graph_path"],
                configuration["main"]["save_path"],
                configuration["models"]["clip"]["checkpoint"],
            ):
                leaked_descriptors.append(int(Path(value).name))
            paths.checkpoint.write_bytes(b"tampering!")

        def load_graph(self, _graph_path):
            raise AssertionError("load_graph must not run after checkpoint drift")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, tmp_path / "run")

    assert leaked_descriptors
    for descriptor in leaked_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_real_adapter_detects_graph_child_replacement_during_load(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)

    class FakeGraph:
        def __init__(self, _configuration):
            pass

        def load_graph(self, _graph_path):
            target = paths.graph / "graph.bin"
            target.rename(paths.graph / "original-graph.bin")
            target.write_bytes(b"graph")

        def set_room_names(self, *, room_names):
            raise AssertionError("room mapping must not run after graph drift")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, tmp_path / "run")


def test_real_adapter_detects_run_swap_during_graph_construction(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"

    class FakeGraph:
        def __init__(self, _configuration):
            run_directory.rename(tmp_path / "original-run")
            run_directory.mkdir()

        def load_graph(self, _graph_path):
            raise AssertionError("load_graph must not run after run swap")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, run_directory)


def test_real_adapter_revalidates_run_authority_before_later_graph_access(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"

    class FakeGraph:
        floors = [object()]
        rooms = [object(), object(), object()]
        objects = [object()] * 497

        def __init__(self, _configuration):
            pass

        def load_graph(self, _graph_path):
            pass

        def set_room_names(self, *, room_names):
            pass

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    adapter = load_real_hmsg_adapter(paths, run_directory)
    run_directory.rename(tmp_path / "original-run")
    run_directory.mkdir()

    try:
        with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
            adapter.graph_counts()
    finally:
        adapter.close()


def test_real_adapter_revalidates_run_authority_after_later_graph_access(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"

    class FakeGraph:
        rooms = [object(), object(), object()]
        objects = [object()] * 497

        def __init__(self, _configuration):
            self._swapped = False

        @property
        def floors(self):
            if not self._swapped:
                self._swapped = True
                run_directory.rename(tmp_path / "original-run")
                run_directory.mkdir()
            return [object()]

        def load_graph(self, _graph_path):
            pass

        def set_room_names(self, *, room_names):
            pass

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        semantic_gate_module,
        "verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        semantic_gate_module,
        "import_root_hmsg_runtime",
        lambda _bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )
    adapter = load_real_hmsg_adapter(paths, run_directory)

    try:
        with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
            adapter.graph_counts()
    finally:
        adapter.close()


def test_real_adapter_rejects_path_identity_drift_immediately_before_graph_load(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"
    original_graph = tmp_path / "original-graph"

    class FakeGraph:
        def __init__(self, _configuration):
            paths.graph.rename(original_graph)
            paths.graph.mkdir()

        def load_graph(self, _graph_path):
            raise AssertionError("load_graph must not run after path drift")

    origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.import_root_hmsg_runtime",
        lambda bound: (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        ),
    )

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, run_directory)


def test_real_adapter_rejects_run_overlap_before_asset_or_import_work(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.verify_asset_lock",
        lambda _bound: pytest.fail("asset verification must not run"),
    )

    with pytest.raises(SemanticGateError, match="RUN_PATH_OVERLAP"):
        load_real_hmsg_adapter(paths, paths.graph)


def test_real_adapter_rejects_run_identity_drift_after_runtime_import(
    tmp_path, monkeypatch
):
    paths = _portable_handover_paths(tmp_path)
    run_directory = tmp_path / "run"

    class FakeGraph:
        def __init__(self, _configuration):
            pass

        def load_graph(self, _graph_path):
            pass

        def set_room_names(self, *, room_names):
            pass

    def import_after_run_replacement(_paths):
        run_directory.rename(tmp_path / "original-run")
        run_directory.mkdir()
        origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
        return (
            _fake_graph_module(origin, FakeGraph),
            SimpleNamespace(create=lambda value: value),
            origin,
        )

    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.verify_asset_lock",
        lambda bound: _verified_lock(bound),
    )
    monkeypatch.setattr(
        "holoagent0_setup.semantic_gate.import_root_hmsg_runtime",
        import_after_run_replacement,
    )

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, run_directory)


def test_real_adapter_rejects_verified_asset_mismatch(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)

    def reject(_paths):
        raise AssetGateError("ASSET_INVENTORY_MISMATCH", "graph")

    monkeypatch.setattr("holoagent0_setup.semantic_gate.verify_asset_lock", reject)

    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(paths, tmp_path / "run")


def test_cyclone_verification_public_api_accepts_only_handover_paths():
    assert tuple(inspect.signature(verify_cyclone_roles).parameters) == ("paths",)


def test_four_role_cyclone_configs_are_exact_and_identity_bound(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    original_load = semantic_gate_module.load_asset_lock
    observed = []

    def load_identity_bound(source):
        observed.append(source)
        assert source is paths
        return original_load(source)

    monkeypatch.setattr(semantic_gate_module, "load_asset_lock", load_identity_bound)

    contract = verify_cyclone_roles(paths)

    assert observed == [paths]

    assert [(role.role, role.participant_index) for role in contract.configs] == [
        ("fixture", 0),
        ("query_publisher", 1),
        ("result_subscriber", 2),
        ("graph_inspector", 3),
    ]
    assert contract.spdp_port == 26650
    assert contract.data_multicast_receive_port == 26651
    assert contract.unicast_ports == {
        0: (26660, 26661),
        1: (26662, 26663),
        2: (26664, 26665),
        3: (26666, 26667),
    }
    assert contract.domain_id == 77
    assert contract.interface == {
        "name": "lo",
        "autodetermine": False,
        "presence_required": True,
        "multicast": True,
    }
    assert contract.transport == "udp"
    assert contract.allow_multicast == "spdp"
    assert contract.many_sockets_mode is False
    assert contract.spdp_multicast_address == "239.255.0.1"
    assert CYCLONE_CONFIG_SET_SHA256 == (
        "2f4b15dfe1ee168425ad0552c45d5434d068e6ff6bab43c45f82d7869dcb5879"
    )
    assert all(role.uri.startswith("file:") for role in contract.configs)
    assert ROOM_NAME_MAPPING == ("Pantry", "Office", "Hallway")

    fixture = contract.configs[0]
    environment = {
        "RMW_IMPLEMENTATION": "rmw_cyclonedds_cpp",
        "ROS_DOMAIN_ID": "77",
        "ROS_LOCALHOST_ONLY": "1",
        "CYCLONEDDS_URI": fixture.uri,
    }
    validate_fixture_runtime_environment(contract, environment)
    for key in tuple(environment):
        invalid = dict(environment)
        invalid[key] = "invalid"
        with pytest.raises(SemanticGateError, match="CYCLONE_CONFIG_MISMATCH"):
            validate_fixture_runtime_environment(contract, invalid)


def test_cyclone_config_content_mutation_is_rejected(tmp_path):
    paths = _portable_handover_paths(tmp_path)
    target = (
        paths.repository_root
        / "scripts/holoagent0_setup/config/cyclonedds-offline-p2.xml"
    )
    target.write_text(
        target.read_text().replace(
            "<Transport>udp</Transport>", "<Transport>tcp</Transport>"
        )
    )

    with pytest.raises(SemanticGateError, match="CYCLONE_CONFIG_MISMATCH"):
        verify_cyclone_roles(paths)


def test_cyclone_verification_rejects_handover_identity_drift(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    original_load = semantic_gate_module.load_pinned_cyclone_configs

    def load_then_replace_lock(*args, **kwargs):
        contract = original_load(*args, **kwargs)
        content = paths.asset_lock.read_bytes()
        paths.asset_lock.rename(tmp_path / "original-asset-lock.json")
        paths.asset_lock.write_bytes(content)
        return contract

    monkeypatch.setattr(
        semantic_gate_module,
        "load_pinned_cyclone_configs",
        load_then_replace_lock,
    )

    with pytest.raises(SemanticGateError) as caught:
        verify_cyclone_roles(paths)

    assert caught.value.reason == "SEMANTIC_ASSET_UNAVAILABLE"


def _valid_graph_snapshot(*, capture=False):
    return GraphSnapshot(
        scope="holoagent0-semantic-application-v1",
        nodes=EXPECTED_ROS_NODES,
        topics={
            "/holoagent0/semantic_fixture_query": TopicCardinality(
                "std_msgs/msg/String", publishers=1, subscribers=1
            ),
            "/object_pose": TopicCardinality(
                "geometry_msgs/msg/PoseStamped",
                publishers=1,
                subscribers=1 if capture else 0,
            ),
        },
    )


def test_fake_ros_graph_contract_has_exact_cardinality_no_nav2_and_no_cmd_vel():
    before = _valid_graph_snapshot()
    capture = _valid_graph_snapshot(capture=True)
    validate_ros_graph(before, capture_active=False)
    validate_ros_graph(capture, capture_active=True)
    assert len(before.sha256()) == 64
    assert before.sha256() != capture.sha256()

    with pytest.raises(SemanticGateError, match="ROS_GRAPH_MISMATCH"):
        validate_ros_graph(
            replace(_valid_graph_snapshot(), nodes=("/nav2_controller",)),
            capture_active=False,
        )
    snapshot = _valid_graph_snapshot()
    topics = dict(snapshot.topics)
    topics["/cmd_vel"] = TopicCardinality(
        "geometry_msgs/msg/Twist", publishers=1, subscribers=1
    )
    with pytest.raises(SemanticGateError, match="ROS_GRAPH_MISMATCH"):
        validate_ros_graph(replace(snapshot, topics=topics), capture_active=False)
    with pytest.raises(SemanticGateError, match="ROS_GRAPH_MISMATCH"):
        validate_ros_graph(
            replace(snapshot, scope="unfiltered-full-ros-graph"), capture_active=False
        )
    for topic, replacement in (
        (
            "/holoagent0/semantic_fixture_query",
            TopicCardinality("std_msgs/msg/String", publishers=2, subscribers=1),
        ),
        (
            "/object_pose",
            TopicCardinality(
                "geometry_msgs/msg/PoseStamped", publishers=1, subscribers=2
            ),
        ),
        (
            "/object_pose",
            TopicCardinality("geometry_msgs/msg/Pose", publishers=1, subscribers=0),
        ),
    ):
        changed = dict(snapshot.topics)
        changed[topic] = replacement
        with pytest.raises(SemanticGateError, match="ROS_GRAPH_MISMATCH"):
            validate_ros_graph(replace(snapshot, topics=changed), capture_active=False)


def test_fixture_controller_accepts_exact_structured_query_and_publishes_once():
    published = []
    adapter = FakeAdapter()
    controller = SemanticFixtureController(adapter, published.append)
    payload = EXPECTED_SEMANTIC.query.canonical_json()

    result = controller.handle(payload)

    assert published == [result]
    assert adapter.queries == [EXPECTED_SEMANTIC.query]
    assert (
        result.structured_query_sha256
        == hashlib.sha256(payload.encode("utf-8")).hexdigest()
    )
    assert result.position == EXPECTED_SEMANTIC.position
    with pytest.raises(SemanticGateError, match="cardinality"):
        controller.handle(payload)
    assert len(published) == 1


def test_fixture_node_module_is_import_safe_without_ros_dependencies():
    script = (
        "import sys; "
        f"sys.path.insert(0,{str(PACKAGE_ROOT)!r}); "
        "import holoagent0_setup.semantic_fixture_node; "
        "assert 'rclpy' not in sys.modules; "
        "assert 'geometry_msgs' not in sys.modules; "
        "assert 'std_msgs' not in sys.modules"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_fixture_cli_accepts_only_the_two_handover_roots_and_run_controls():
    parameters = fixture_module._parse_arguments(
        [
            "--repository-root",
            "/repository",
            "--data-root",
            "/data",
            "--run-directory",
            "/run",
            "--timeout-seconds",
            "2",
        ]
    )

    assert vars(parameters) == {
        "repository_root": Path("/repository"),
        "data_root": Path("/data"),
        "run_directory": Path("/run"),
        "timeout_seconds": 2.0,
    }
    source = Path(fixture_module.__file__).read_text(encoding="utf-8")
    assert source.count("HandoverPaths.from_roots(") == 1
    for removed in (
        "--asset-lock",
        "--graph-root",
        "--dataset-root",
        "--checkpoint-path",
    ):
        with pytest.raises(SystemExit):
            fixture_module._parse_arguments(
                [
                    "--repository-root",
                    "/repository",
                    "--data-root",
                    "/data",
                    "--run-directory",
                    "/run",
                    removed,
                    "/legacy",
                ]
            )

    with pytest.raises(SystemExit):
        fixture_module._parse_arguments(
            [
                "--repo",
                "/repository",
                "--data",
                "/data",
                "--run",
                "/run",
            ]
        )


def test_fixture_translates_handover_construction_failure_to_semantic_asset_error(
    tmp_path,
):
    with pytest.raises(SemanticGateError) as caught:
        fixture_module.main(
            [
                "--repository-root",
                str(tmp_path / "missing-repository"),
                "--data-root",
                str(tmp_path / "missing-data"),
                "--run-directory",
                str(tmp_path / "run"),
            ]
        )

    assert caught.value.reason == "SEMANTIC_ASSET_UNAVAILABLE"


def test_fixture_rechecks_cyclone_after_heavy_adapter_loading(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    events = []

    class ClosingAdapter(FakeAdapter):
        def close(self):
            events.append("close")

    def load_adapter(_paths, _run_directory):
        events.append("load_adapter")
        target = (
            paths.repository_root
            / "scripts/holoagent0_setup/config/cyclonedds-offline-p0.xml"
        )
        target.write_text(
            target.read_text().replace('<Domain Id="77">', '<Domain Id="76">')
        )
        assert '<Domain Id="76">' in target.read_text()
        return ClosingAdapter()

    fake_rclpy = SimpleNamespace(
        init=lambda **_kwargs: events.append("init"),
        ok=lambda: False,
        shutdown=lambda: events.append("shutdown"),
    )
    monkeypatch.setitem(sys.modules, "rclpy", fake_rclpy)
    monkeypatch.setattr(fixture_module, "load_real_hmsg_adapter", load_adapter)
    monkeypatch.setattr(
        fixture_module, "validate_fixture_runtime_environment", lambda *_: None
    )

    with pytest.raises(SemanticGateError, match="CYCLONE_CONFIG_MISMATCH"):
        fixture_module.main(
            [
                "--repository-root",
                str(paths.repository_root),
                "--data-root",
                str(paths.data_root),
                "--run-directory",
                str(tmp_path / "run"),
            ]
        )

    assert events == ["load_adapter", "close"]


@pytest.mark.parametrize("build_fails", [False, True])
def test_fixture_main_is_bounded_and_shuts_ros_down_on_constructor_failure(
    tmp_path, monkeypatch, build_fails
):
    paths = _portable_handover_paths(tmp_path)
    events = []

    class FakeNode:
        fixture_complete = False
        fixture_error = None

        def destroy_node(self):
            events.append("destroy")

    node = FakeNode()
    state = {"initialized": False}

    def init(*, args):
        assert args == []
        state["initialized"] = True
        events.append("init")

    def ok():
        return state["initialized"]

    def spin_once(observed, *, timeout_sec):
        assert observed is node
        assert 0.0 < timeout_sec <= 0.1
        observed.fixture_complete = True
        events.append("spin_once")

    def shutdown():
        state["initialized"] = False
        events.append("shutdown")

    fake_rclpy = SimpleNamespace(
        init=init, ok=ok, spin_once=spin_once, shutdown=shutdown
    )
    monkeypatch.setitem(sys.modules, "rclpy", fake_rclpy)

    def verify_cyclone(bound_paths):
        assert bound_paths.repository_root == paths.repository_root
        assert bound_paths.asset_lock == paths.asset_lock
        return object()

    monkeypatch.setattr(fixture_module, "verify_cyclone_roles", verify_cyclone)
    monkeypatch.setattr(
        fixture_module, "validate_fixture_runtime_environment", lambda *_: None
    )

    def load_adapter(bound_paths, run_directory):
        assert bound_paths.repository_root == paths.repository_root
        assert bound_paths.data_root == paths.data_root
        assert run_directory == tmp_path / "run"
        return FakeAdapter()

    monkeypatch.setattr(fixture_module, "load_real_hmsg_adapter", load_adapter)

    def build(_adapter):
        if build_fails:
            raise RuntimeError("constructor failed")
        return node

    monkeypatch.setattr(fixture_module, "build_ros_node", build)
    arguments = [
        "--repository-root",
        str(paths.repository_root),
        "--data-root",
        str(paths.data_root),
        "--run-directory",
        str(tmp_path / "run"),
        "--timeout-seconds",
        "1",
    ]

    if build_fails:
        with pytest.raises(RuntimeError, match="constructor failed"):
            fixture_module.main(arguments)
        assert events == ["init", "shutdown"]
    else:
        assert fixture_module.main(arguments) == 0
        assert events == ["init", "spin_once", "destroy", "shutdown"]


def test_fixture_main_shutdown_runs_even_when_node_destroy_fails(tmp_path, monkeypatch):
    paths = _portable_handover_paths(tmp_path)
    events = []

    class FakeNode:
        fixture_complete = True
        fixture_error = None

        def destroy_node(self):
            events.append("destroy")
            raise RuntimeError("destroy failed")

    state = {"initialized": False}
    fake_rclpy = SimpleNamespace(
        init=lambda **_kwargs: state.update(initialized=True),
        ok=lambda: state["initialized"],
        spin_once=lambda *_args, **_kwargs: None,
        shutdown=lambda: (events.append("shutdown"), state.update(initialized=False)),
    )
    monkeypatch.setitem(sys.modules, "rclpy", fake_rclpy)
    monkeypatch.setattr(fixture_module, "verify_cyclone_roles", lambda *_: object())
    monkeypatch.setattr(
        fixture_module, "validate_fixture_runtime_environment", lambda *_: None
    )
    monkeypatch.setattr(
        fixture_module, "load_real_hmsg_adapter", lambda *_: FakeAdapter()
    )
    monkeypatch.setattr(fixture_module, "build_ros_node", lambda _adapter: FakeNode())

    with pytest.raises(RuntimeError, match="destroy failed"):
        fixture_module.main(
            [
                "--repository-root",
                str(paths.repository_root),
                "--data-root",
                str(paths.data_root),
                "--run-directory",
                str(tmp_path / "run"),
            ]
        )
    assert events == ["destroy", "shutdown"]
