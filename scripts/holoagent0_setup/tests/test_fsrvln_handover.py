from __future__ import annotations

import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from holoagent0_setup.atomic_io import (
    AtomicPublicationAmbiguity,
    canonical_json_bytes,
)
from holoagent0_setup.contract import ContractError, ContractSet
import holoagent0_setup.handover_evidence as evidence_module
from holoagent0_setup.handover_evidence import (
    ASSET_FILE,
    ENVIRONMENT_FILE,
    EVIDENCE_ORDER,
    QUERY_FILE,
    REQUIRED_IMPORTS,
    RESULT_FILE,
    SOURCE_FILE,
    build_asset_document,
    build_environment_document,
    build_query_document,
    build_source_document,
    path_identity_document,
    publish_handover_evidence,
    qualify_environment,
    validate_and_publish_stage,
)
from holoagent0_setup.semantic_gate import (
    CHECKPOINT_SHA256,
    DATASET_ROOT_SHA256,
    EXPECTED_SEMANTIC,
    GRAPH_ROOT_SHA256,
    GraphCounts,
    ROOM_NAME_MAPPING_SHA256,
    STRUCTURED_QUERY_SHA256,
    SemanticFixtureResult,
)
from holoagent0_setup.source_gate import (
    HandoverPaths,
    PathIdentity,
    SourceVerification,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
STARTED = "2026-08-18T00:00:00.1234567Z"
FINISHED = "2026-08-18T00:00:01Z"
GIT_SHA = "a" * 40
LOCK_SHA256 = "b" * 64

EXPECTED_IMPORTS = (
    ("pytorch", "torch"),
    ("open3d", "open3d"),
    ("openclip", "open_clip"),
    ("numpy", "numpy"),
    ("omegaconf", "omegaconf"),
    ("faiss", "faiss"),
    ("opencv", "cv2"),
    ("networkx", "networkx"),
    ("pyvista", "pyvista"),
    ("scikit-fmm", "skfmm"),
    ("oss2", "oss2"),
    ("segment-anything", "segment_anything"),
)


def _identity(path: Path) -> PathIdentity:
    observed = path.stat()
    return PathIdentity(path, observed.st_dev, observed.st_ino, observed.st_mode)


def _fake_paths(tmp_path: Path) -> HandoverPaths:
    repository = tmp_path / "repository"
    data = tmp_path / "data"
    graph = data / "graph"
    dataset = data / "dataset"
    checkpoint = data / "checkpoint.bin"
    lock = repository / "asset-lock.json"
    for directory in (repository, data, graph, dataset):
        directory.mkdir()
    checkpoint.write_bytes(b"checkpoint")
    lock.write_bytes(b"lock")
    paths = object.__new__(HandoverPaths)
    values = (
        ("repository_root", repository),
        ("data_root", data),
        ("graph", graph),
        ("dataset", dataset),
        ("checkpoint", checkpoint),
        ("asset_lock", lock),
    )
    for field, value in values:
        object.__setattr__(paths, field, value)
    object.__setattr__(
        paths, "identities", tuple(_identity(path) for _, path in values)
    )
    return paths


def _module(name: str, version: str | None = "1.0", *, origin: str | None = None):
    module = SimpleNamespace(__name__=name)
    if version is not None:
        module.__version__ = version
    if origin is not None:
        module.__file__ = origin
        module.__spec__ = importlib.machinery.ModuleSpec(
            name, loader=None, origin=origin
        )
    return module


def _install_fake_runtime(monkeypatch, paths, *, missing=(), wrong=(), cuda=True):
    calls = []
    modules = {
        module_name: _module(
            module_name,
            None if module_name in {"open_clip", "oss2"} else f"{module_name}-v",
            origin=f"/opt/runtime/{module_name}.py",
        )
        for _display_name, module_name in EXPECTED_IMPORTS
    }
    torch = modules["torch"]
    torch.version = SimpleNamespace(cuda="12.8" if cuda else None)
    torch.cuda = SimpleNamespace(is_available=lambda: cuda)

    def fake_import(name):
        calls.append(name)
        if name in missing:
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        if name in wrong:
            return _module(f"wrong_{name}", origin=f"/wrong/{name}.py")
        return modules[name]

    metadata_calls = []

    def fake_version(distribution):
        metadata_calls.append(distribution)
        if distribution == "open-clip-torch":
            return "2.32.0"
        raise evidence_module.metadata.PackageNotFoundError(distribution)

    graph_origin = paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
    graph_origin.parent.mkdir(parents=True)
    graph_origin.write_text("SOURCE = 'root'\n", encoding="utf-8")
    graph_calls = []

    def fake_graph_import(actual_paths):
        graph_calls.append(actual_paths)
        return object(), object(), graph_origin

    timestamps = iter((STARTED, FINISHED))
    monkeypatch.setattr(evidence_module, "import_module", fake_import)
    monkeypatch.setattr(evidence_module.metadata, "version", fake_version)
    monkeypatch.setattr(evidence_module, "import_root_hmsg_runtime", fake_graph_import)
    monkeypatch.setattr(evidence_module, "_utc_timestamp", lambda: next(timestamps))
    monkeypatch.setattr(evidence_module.platform, "platform", lambda: "Linux-reviewed")
    monkeypatch.setattr(evidence_module.platform, "machine", lambda: "x86_64")
    return calls, metadata_calls, graph_calls, graph_origin


def _semantic_result() -> SemanticFixtureResult:
    expected = EXPECTED_SEMANTIC
    return SemanticFixtureResult(
        query_text=expected.query.text,
        graph_identity=expected.graph_identity,
        floor_id=expected.floor_id,
        room_id=expected.room_id,
        room_name=expected.room_name,
        object_id=expected.object_id,
        object_name=expected.object_name,
        frame_id=expected.frame_id,
        position=expected.position,
        orientation=expected.orientation,
        structured_query_sha256=STRUCTURED_QUERY_SHA256,
        graph_root_sha256=GRAPH_ROOT_SHA256,
        dataset_root_sha256=DATASET_ROOT_SHA256,
        checkpoint_sha256=CHECKPOINT_SHA256,
        room_name_mapping_sha256=ROOM_NAME_MAPPING_SHA256,
        bypassed_network_seams=("external_llm_parser",),
        pinned_fixture_preprocessing=("room_name_mapping",),
    )


def _pass_import_rows() -> list[dict[str, object]]:
    return [
        {
            "name": display_name,
            "module": module_name,
            "status": "PASS",
            "version": "2.7.1" if module_name == "torch" else None,
            "origin": f"/opt/runtime/{module_name}.py",
            "reason": "OK",
        }
        for display_name, module_name in EXPECTED_IMPORTS
    ]


def _pass_documents(paths: HandoverPaths) -> dict[str, dict[str, object]]:
    environment = build_environment_document(
        status="PASS",
        reason="OK",
        started_at=STARTED,
        finished_at=FINISHED,
        os_release="Linux-reviewed",
        machine_architecture="x86_64",
        python={"executable": "/usr/bin/python3.10", "version": "3.10.12"},
        accelerator={
            "label": "CPU",
            "torch_cuda_build": None,
            "cuda_available": False,
        },
        imports=_pass_import_rows(),
        graph_module_origin=str(
            paths.repository_root / "fsr_vln/memory/hmsg/graph/graph.py"
        ),
    )
    source = build_source_document(
        paths,
        status="PASS",
        reason="OK",
        started_at=STARTED,
        finished_at=FINISHED,
        checkout_commit=GIT_SHA,
        verification=SourceVerification(
            commit="c" * 40,
            verified_count=73,
            provenance=((GIT_SHA, 72), ("d" * 40, 1)),
        ),
    )
    asset_specs = tuple(
        SimpleNamespace(role=role) for role in ("graph", "dataset", "checkpoint")
    )
    manifests = tuple(
        SimpleNamespace(file_count=index, byte_count=index * 10, sha256=f"{index:064x}")
        for index in (1, 2, 3)
    )
    asset = build_asset_document(
        paths,
        status="PASS",
        reason="OK",
        started_at=STARTED,
        finished_at=FINISHED,
        asset_lock_sha256=LOCK_SHA256,
        verification=SimpleNamespace(
            lock=SimpleNamespace(assets=asset_specs), manifests=manifests
        ),
    )
    query = build_query_document(
        status="PASS",
        reason="OK",
        started_at=STARTED,
        finished_at=FINISHED,
        query_sha256=STRUCTURED_QUERY_SHA256,
        graph_counts=GraphCounts(1, 3, 497),
        result=_semantic_result(),
    )
    return dict(zip(EVIDENCE_ORDER, (environment, source, asset, query)))


@pytest.fixture
def contract() -> ContractSet:
    return ContractSet(PACKAGE_ROOT)


def test_required_import_constants_are_exact_and_ordered():
    assert REQUIRED_IMPORTS == EXPECTED_IMPORTS
    assert EVIDENCE_ORDER == (
        ENVIRONMENT_FILE,
        SOURCE_FILE,
        ASSET_FILE,
        QUERY_FILE,
    )
    assert RESULT_FILE == "handover-result.json"


def test_environment_attempts_every_import_after_failure_and_reports_exact_rows(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    calls, _metadata_calls, graph_calls, graph_origin = _install_fake_runtime(
        monkeypatch,
        paths,
        missing={"open3d"},
        wrong={"cv2"},
        cuda=False,
    )

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    assert [row["name"] for row in document["imports"]] == [
        name for name, _module_name in EXPECTED_IMPORTS
    ]
    assert document["status"] == "FAIL"
    assert "open3d" in document["reason"]
    rows = {row["module"]: row for row in document["imports"]}
    assert rows["open3d"] == {
        "name": "open3d",
        "module": "open3d",
        "status": "FAIL",
        "version": None,
        "origin": None,
        "reason": "IMPORT_MISSING: open3d",
    }
    assert rows["cv2"]["status"] == "FAIL"
    assert rows["cv2"]["reason"].startswith("IMPORT_IDENTITY_MISMATCH:")
    assert rows["segment_anything"]["status"] == "PASS"
    assert document["os_release"] == "Linux-reviewed"
    assert document["machine_architecture"] == "x86_64"
    assert document["python"]["executable"] == evidence_module.sys.executable
    assert document["python"]["version"] == evidence_module.sys.version
    assert document["accelerator"] == {
        "label": "CPU",
        "torch_cuda_build": None,
        "cuda_available": False,
    }
    assert graph_calls == [paths]
    assert document["graph_module_origin"] == str(graph_origin)
    assert document["started_at"] == STARTED
    assert document["finished_at"] == FINISHED


def test_environment_version_fallback_cuda_and_shared_graph_origin(
    monkeypatch, tmp_path, contract
):
    paths = _fake_paths(tmp_path)
    calls, metadata_calls, graph_calls, graph_origin = _install_fake_runtime(
        monkeypatch, paths, cuda=True
    )

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    assert graph_calls == [paths]
    assert document["status"] == "PASS"
    assert document["accelerator"] == {
        "label": "GPU",
        "torch_cuda_build": "12.8",
        "cuda_available": True,
    }
    assert document["graph_module_origin"] == str(graph_origin)
    versions = {row["module"]: row["version"] for row in document["imports"]}
    assert versions["torch"] == "torch-v"
    assert versions["open_clip"] == "2.32.0"
    assert versions["oss2"] is None
    assert "open-clip-torch" in metadata_calls
    decision = contract.validate_document("fsrvln-environment-v1", document)
    assert decision.ok, decision.errors


def test_environment_rejects_cuda_availability_without_a_cuda_build(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    _install_fake_runtime(monkeypatch, paths, cuda=False)
    torch = _module("torch", "2.7.1", origin="/opt/runtime/torch.py")
    torch.version = SimpleNamespace(cuda=None)
    torch.cuda = SimpleNamespace(is_available=lambda: True)
    real_import = evidence_module.import_module
    monkeypatch.setattr(
        evidence_module,
        "import_module",
        lambda name: torch if name == "torch" else real_import(name),
    )

    document = qualify_environment(paths)

    assert document["status"] == "FAIL"
    torch_row = document["imports"][0]
    assert torch_row["status"] == "FAIL"
    assert torch_row["reason"] == "CUDA_BUILD_MISSING: torch reports CUDA available"


def test_environment_metadata_permission_failure_is_explicit_and_later_imports_run(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    calls, _metadata_calls, _graph_calls, _graph_origin = _install_fake_runtime(
        monkeypatch, paths, cuda=False
    )
    fallback = evidence_module.metadata.version

    def permission_error(distribution):
        if distribution == "open-clip-torch":
            raise PermissionError("metadata denied")
        return fallback(distribution)

    monkeypatch.setattr(evidence_module.metadata, "version", permission_error)

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    row = document["imports"][2]
    assert row["module"] == "open_clip"
    assert row["status"] == "FAIL"
    assert row["version"] is None
    assert row["reason"].startswith(
        "IMPORT_OBSERVATION_FAILED: open_clip: PermissionError: metadata denied"
    )
    assert document["imports"][-1]["module"] == "segment_anything"
    assert document["imports"][-1]["status"] == "PASS"


def test_environment_hostile_version_getter_is_explicit_and_later_imports_run(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    calls, _metadata_calls, _graph_calls, _graph_origin = _install_fake_runtime(
        monkeypatch, paths, cuda=False
    )
    fallback = evidence_module.import_module

    class HostileVersion:
        __name__ = "open3d"
        __file__ = "/opt/runtime/open3d.py"
        __spec__ = importlib.machinery.ModuleSpec(
            "open3d", loader=None, origin=__file__
        )

        @property
        def __version__(self):
            raise RuntimeError("hostile version getter")

    def hostile_import(name):
        if name == "open3d":
            calls.append(name)
            return HostileVersion()
        return fallback(name)

    calls.clear()
    monkeypatch.setattr(evidence_module, "import_module", hostile_import)

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    row = document["imports"][1]
    assert row["module"] == "open3d"
    assert row["status"] == "FAIL"
    assert row["reason"].startswith(
        "IMPORT_OBSERVATION_FAILED: open3d: RuntimeError: hostile version getter"
    )
    assert document["imports"][-1]["status"] == "PASS"


def test_environment_does_not_mistake_attribute_error_getter_for_absent_version(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    calls, _metadata_calls, _graph_calls, _graph_origin = _install_fake_runtime(
        monkeypatch, paths, cuda=False
    )
    fallback = evidence_module.import_module

    class HostileVersion:
        __name__ = "open3d"
        __file__ = "/opt/runtime/open3d.py"
        __spec__ = importlib.machinery.ModuleSpec(
            "open3d", loader=None, origin=__file__
        )

        @property
        def __version__(self):
            raise AttributeError("getter denied version")

    def hostile_import(name):
        if name == "open3d":
            calls.append(name)
            return HostileVersion()
        return fallback(name)

    calls.clear()
    monkeypatch.setattr(evidence_module, "import_module", hostile_import)

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    assert document["imports"][1]["status"] == "FAIL"
    assert "getter denied version" in document["imports"][1]["reason"]


def test_environment_ignores_path_environment_and_rejects_wrong_shared_graph_origin(
    monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    calls, _metadata_calls, _graph_calls, _graph_origin = _install_fake_runtime(
        monkeypatch, paths, cuda=False
    )
    injected = "/environment/must/not/be/used"
    for name in (
        "FSR_VLN_ROOT",
        "FSRVLN_ROOT",
        "HOLOAGENT_DATA_ROOT",
        "PYTHONPATH",
        "DOTENV_PATH",
    ):
        monkeypatch.setenv(name, injected)
    wrong = tmp_path / "agentic_robot/fsr_vln/memory/hmsg/graph/graph.py"
    wrong.parent.mkdir(parents=True)
    wrong.write_text("SOURCE = 'wrong'\n", encoding="utf-8")
    monkeypatch.setattr(
        evidence_module,
        "import_root_hmsg_runtime",
        lambda actual_paths: (object(), object(), wrong),
    )

    document = qualify_environment(paths)

    assert calls == [module for _name, module in EXPECTED_IMPORTS]
    assert document["status"] == "FAIL"
    assert document["graph_module_origin"] is None
    assert document["reason"].startswith("GRAPH_MODULE_ORIGIN_FAILED:")
    assert injected not in json.dumps(document, sort_keys=True)


def test_contract_require_valid_document_is_symmetric_with_result(contract):
    invalid = {"schema_version": "holoagent0.fsrvln.environment.v1"}

    with pytest.raises(ContractError) as caught:
        contract.require_valid_document("fsrvln-environment-v1", invalid)

    assert caught.value.decision.code == "EVIDENCE_SCHEMA_INVALID"


def test_document_builders_emit_valid_pass_fail_and_not_run_shapes(contract, tmp_path):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    schemas = {
        ENVIRONMENT_FILE: "fsrvln-environment-v1",
        SOURCE_FILE: "fsrvln-source-verification-v1",
        ASSET_FILE: "fsrvln-asset-verification-v1",
        QUERY_FILE: "fsrvln-query-result-v1",
    }
    for filename, document in documents.items():
        decision = contract.validate_document(schemas[filename], document)
        assert decision.ok, decision.errors

    query_result = documents[QUERY_FILE]["result"]
    assert query_result == {
        "graph_counts": {"floors": 1, "rooms": 3, "objects": 497},
        "graph_identity": EXPECTED_SEMANTIC.graph_identity,
        "floor_id": EXPECTED_SEMANTIC.floor_id,
        "room": {"id": EXPECTED_SEMANTIC.room_id, "name": "Pantry"},
        "object": {"id": EXPECTED_SEMANTIC.object_id, "name": "counter"},
        "frame_id": "map",
        "position": list(EXPECTED_SEMANTIC.position),
        "orientation": list(EXPECTED_SEMANTIC.orientation),
        "structured_query_sha256": STRUCTURED_QUERY_SHA256,
        "graph_root_sha256": GRAPH_ROOT_SHA256,
        "dataset_root_sha256": DATASET_ROOT_SHA256,
        "checkpoint_sha256": CHECKPOINT_SHA256,
        "room_name_mapping_sha256": ROOM_NAME_MAPPING_SHA256,
    }
    assert documents[QUERY_FILE]["execution_count"] == 1

    not_run_documents = {
        ENVIRONMENT_FILE: build_environment_document(
            status="NOT_RUN",
            reason="EARLIER_BLOCKING_STAGE",
            started_at=STARTED,
            finished_at=FINISHED,
        ),
        SOURCE_FILE: build_source_document(
            paths,
            status="NOT_RUN",
            reason="EARLIER_BLOCKING_STAGE",
            started_at=STARTED,
            finished_at=FINISHED,
        ),
        ASSET_FILE: build_asset_document(
            paths,
            status="NOT_RUN",
            reason="EARLIER_BLOCKING_STAGE",
            started_at=STARTED,
            finished_at=FINISHED,
        ),
        QUERY_FILE: build_query_document(
            status="NOT_RUN",
            reason="EARLIER_BLOCKING_STAGE",
            started_at=STARTED,
            finished_at=FINISHED,
            query_sha256=STRUCTURED_QUERY_SHA256,
        ),
    }
    for filename, document in not_run_documents.items():
        decision = contract.validate_document(schemas[filename], document)
        assert decision.ok, decision.errors
    assert not_run_documents[QUERY_FILE]["execution_count"] == 0
    assert not_run_documents[QUERY_FILE]["result"] is None
    assert not_run_documents[ENVIRONMENT_FILE]["imports"] is None

    failed_source = build_source_document(
        paths,
        status="FAIL",
        reason="SOURCE_MISMATCH",
        started_at=STARTED,
        finished_at=FINISHED,
        checkout_commit=GIT_SHA,
    )
    assert failed_source["source_lock_commit"] is None
    decision = contract.validate_document(
        "fsrvln-source-verification-v1", failed_source
    )
    assert decision.ok, decision.errors


def test_path_identities_serialize_exact_values(tmp_path):
    path = tmp_path / "identity"
    path.mkdir()
    identity = _identity(path)

    assert path_identity_document(identity) == {
        "path": str(identity.path),
        "device": identity.device,
        "inode": identity.inode,
        "mode": identity.mode,
    }


def test_validate_and_publish_stage_validates_before_canonical_no_replace_write(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    document = _pass_documents(paths)[ENVIRONMENT_FILE]

    descriptor = validate_and_publish_stage(
        contract,
        "fsrvln-environment-v1",
        run_directory,
        ENVIRONMENT_FILE,
        document,
    )

    payload = canonical_json_bytes(document)
    assert (run_directory / ENVIRONMENT_FILE).read_bytes() == payload
    assert descriptor.relative_path == ENVIRONMENT_FILE
    assert descriptor.sha256 == hashlib.sha256(payload).hexdigest()
    assert descriptor.size == len(payload)
    with pytest.raises(FileExistsError):
        validate_and_publish_stage(
            contract,
            "fsrvln-environment-v1",
            run_directory,
            ENVIRONMENT_FILE,
            document,
        )


def test_publisher_rejects_schema_valid_one_row_pass_environment_before_any_write(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[ENVIRONMENT_FILE]["imports"] = documents[ENVIRONMENT_FILE]["imports"][:1]

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_terminal_cpu_gpu_disagreement_before_any_write(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[ENVIRONMENT_FILE]["accelerator"] = {
        "label": "GPU",
        "torch_cuda_build": "12.8",
        "cuda_available": True,
    }

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_evidence_publisher_writes_canonical_descriptors_and_terminal_last(
    contract, monkeypatch, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_identity = _identity(run_directory)
    calls = []
    authorities = []

    class RecordingContract:
        def require_valid_document(self, schema_name, document):
            calls.append(("validate", schema_name))
            return contract.require_valid_document(schema_name, document)

    real_write = evidence_module.atomic_write_json_no_replace

    def recording_write(path, document, **kwargs):
        calls.append(("write", path.name))
        authorities.append(
            (kwargs.get("parent_fd"), kwargs.get("expected_parent_identity"))
        )
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", recording_write
    )

    terminal_descriptor = publish_handover_evidence(
        RecordingContract(),
        run_directory,
        documents,
        accepted_implementation_commit=GIT_SHA,
        repository_root=paths.identities[0],
        data_root=paths.identities[1],
        run_directory_identity=run_identity,
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    assert calls == [
        ("validate", "fsrvln-environment-v1"),
        ("write", ENVIRONMENT_FILE),
        ("validate", "fsrvln-source-verification-v1"),
        ("write", SOURCE_FILE),
        ("validate", "fsrvln-asset-verification-v1"),
        ("write", ASSET_FILE),
        ("validate", "fsrvln-query-result-v1"),
        ("write", QUERY_FILE),
        ("validate", "fsrvln-handover-result-v1"),
        ("write", RESULT_FILE),
    ]
    assert terminal_descriptor.relative_path == RESULT_FILE
    terminal_bytes = (run_directory / RESULT_FILE).read_bytes()
    terminal = json.loads(terminal_bytes)
    assert terminal_bytes == canonical_json_bytes(terminal)
    assert terminal["status"] == "PASS"
    assert terminal["first_blocking_reason"] is None
    assert terminal["run_directory"] == path_identity_document(run_identity)
    assert len({parent_fd for parent_fd, _identity_value in authorities}) == 1
    retained_fd = authorities[0][0]
    assert isinstance(retained_fd, int)
    assert retained_fd >= 0
    assert all(
        identity_value == (run_identity.device, run_identity.inode)
        for _parent_fd, identity_value in authorities
    )
    with pytest.raises(OSError):
        os.fstat(retained_fd)
    expected_rows = []
    for filename in EVIDENCE_ORDER:
        payload = (run_directory / filename).read_bytes()
        assert payload == canonical_json_bytes(json.loads(payload))
        expected_rows.append(
            {
                "name": filename,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    assert terminal["evidence_files"] == expected_rows
    assert (
        terminal["bundle_sha256"]
        == hashlib.sha256(canonical_json_bytes(expected_rows)).hexdigest()
    )

    before = {
        filename: (run_directory / filename).read_bytes()
        for filename in (*EVIDENCE_ORDER, RESULT_FILE)
    }
    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=run_identity,
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )
    assert before == {
        filename: (run_directory / filename).read_bytes()
        for filename in (*EVIDENCE_ORDER, RESULT_FILE)
    }


def test_blocking_reason_uses_source_environment_asset_query_operational_order(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    failed_imports = _pass_import_rows()
    failed_imports[1].update(
        status="FAIL",
        version=None,
        origin=None,
        reason="IMPORT_MISSING: open3d",
    )
    documents[ENVIRONMENT_FILE] = build_environment_document(
        status="FAIL",
        reason="IMPORT_MISSING: open3d",
        started_at=STARTED,
        finished_at=FINISHED,
        os_release="Linux-reviewed",
        machine_architecture="x86_64",
        python={"executable": "/usr/bin/python3.10", "version": "3.10.12"},
        accelerator={
            "label": "CPU",
            "torch_cuda_build": None,
            "cuda_available": False,
        },
        imports=failed_imports,
        graph_module_origin=None,
    )
    documents[SOURCE_FILE] = build_source_document(
        paths,
        status="FAIL",
        reason="SOURCE_BLOB_MISMATCH: graph.py",
        started_at=STARTED,
        finished_at=FINISHED,
        checkout_commit=GIT_SHA,
    )
    documents[ASSET_FILE] = build_asset_document(
        paths,
        status="NOT_RUN",
        reason="EARLIER_BLOCKING_STAGE",
        started_at=STARTED,
        finished_at=FINISHED,
    )
    documents[QUERY_FILE] = build_query_document(
        status="NOT_RUN",
        reason="EARLIER_BLOCKING_STAGE",
        started_at=STARTED,
        finished_at=FINISHED,
        query_sha256=STRUCTURED_QUERY_SHA256,
    )

    publish_handover_evidence(
        contract,
        run_directory,
        documents,
        accepted_implementation_commit=None,
        repository_root=paths.identities[0],
        data_root=paths.identities[1],
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["first_blocking_reason"] == "SOURCE_BLOB_MISMATCH: graph.py"
    assert terminal["reason"] == "SOURCE_BLOB_MISMATCH: graph.py"


def test_evidence_publisher_derives_fail_from_first_blocker_and_keeps_partial_rows(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    failed_imports = _pass_import_rows()
    failed_imports[1] = {
        "name": "open3d",
        "module": "open3d",
        "status": "FAIL",
        "version": None,
        "origin": None,
        "reason": "IMPORT_MISSING: open3d",
    }
    documents[ENVIRONMENT_FILE] = build_environment_document(
        status="FAIL",
        reason="IMPORT_MISSING: open3d",
        started_at=STARTED,
        finished_at=FINISHED,
        os_release="Linux-reviewed",
        machine_architecture="x86_64",
        python={"executable": "/usr/bin/python3.10", "version": "3.10.12"},
        accelerator={
            "label": "CPU",
            "torch_cuda_build": None,
            "cuda_available": False,
        },
        imports=failed_imports,
        graph_module_origin=None,
    )
    documents[ASSET_FILE] = build_asset_document(
        paths,
        status="NOT_RUN",
        reason="EARLIER_BLOCKING_STAGE",
        started_at=STARTED,
        finished_at=FINISHED,
    )
    documents[QUERY_FILE] = build_query_document(
        status="NOT_RUN",
        reason="EARLIER_BLOCKING_STAGE",
        started_at=STARTED,
        finished_at=FINISHED,
        query_sha256=STRUCTURED_QUERY_SHA256,
    )

    publish_handover_evidence(
        contract,
        run_directory,
        documents,
        accepted_implementation_commit=None,
        repository_root=paths.identities[0],
        data_root=paths.identities[1],
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["reason"] == "IMPORT_MISSING: open3d"
    assert terminal["first_blocking_reason"] == "IMPORT_MISSING: open3d"
    assert [
        json.loads((run_directory / filename).read_bytes())["status"]
        for filename in EVIDENCE_ORDER
    ] == ["FAIL", "PASS", "NOT_RUN", "NOT_RUN"]


@pytest.mark.parametrize("failed_filename", (ENVIRONMENT_FILE, ASSET_FILE))
def test_stage_validation_failure_attempts_every_later_stage_without_terminal(
    contract, monkeypatch, tmp_path, failed_filename
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    documents[failed_filename]["unreviewed"] = True
    calls = []

    class RecordingContract:
        def require_valid_document(self, schema_name, document):
            calls.append(("validate", schema_name))
            return contract.require_valid_document(schema_name, document)

    real_write = evidence_module.atomic_write_json_no_replace

    def recording_write(path, document, **kwargs):
        calls.append(("write", path.name))
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", recording_write
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            RecordingContract(),
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert [entry for entry in calls if entry[0] == "validate"] == [
        ("validate", "fsrvln-environment-v1"),
        ("validate", "fsrvln-source-verification-v1"),
        ("validate", "fsrvln-asset-verification-v1"),
        ("validate", "fsrvln-query-result-v1"),
    ]
    assert [entry[1] for entry in calls if entry[0] == "write"] == [
        filename for filename in EVIDENCE_ORDER if filename != failed_filename
    ]
    assert not (run_directory / RESULT_FILE).exists()


@pytest.mark.parametrize("failed_filename", (ENVIRONMENT_FILE, ASSET_FILE))
def test_stage_write_failure_attempts_all_four_writes_without_terminal(
    contract, monkeypatch, tmp_path, failed_filename
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    attempts = []
    real_write = evidence_module.atomic_write_json_no_replace

    def fail_selected(path, document, **kwargs):
        attempts.append(path.name)
        if path.name == failed_filename:
            raise OSError(f"injected {failed_filename} write failure")
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(evidence_module, "atomic_write_json_no_replace", fail_selected)

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert attempts == list(EVIDENCE_ORDER)
    assert not (run_directory / RESULT_FILE).exists()


def test_run_directory_replacement_fails_closed_and_later_attempts_keep_authority(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    retained_identity = _identity(run_directory)
    moved_directory = tmp_path / "run-retained"
    attempts = []
    authority_arguments = []
    real_write = evidence_module.atomic_write_json_no_replace

    def replace_after_first_write(path, document, **kwargs):
        attempts.append(path.name)
        authority_arguments.append(
            (kwargs.get("parent_fd"), kwargs.get("expected_parent_identity"))
        )
        descriptor = real_write(path, document, **kwargs)
        if path.name == ENVIRONMENT_FILE:
            run_directory.rename(moved_directory)
            run_directory.mkdir(mode=0o700)
        return descriptor

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", replace_after_first_write
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=retained_identity,
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert attempts == list(EVIDENCE_ORDER)
    assert len({fd for fd, _identity_value in authority_arguments}) == 1
    retained_fd = authority_arguments[0][0]
    assert isinstance(retained_fd, int)
    assert all(
        identity_value == (retained_identity.device, retained_identity.inode)
        for _fd, identity_value in authority_arguments
    )
    with pytest.raises(OSError):
        os.fstat(retained_fd)
    assert not (run_directory / RESULT_FILE).exists()
    assert not (moved_directory / RESULT_FILE).exists()


def test_ambiguous_terminal_is_quarantined_and_never_returned_as_success(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    real_write = evidence_module.atomic_write_json_no_replace

    def install_then_raise(path, document, **kwargs):
        descriptor = real_write(path, document, **kwargs)
        if path.name == RESULT_FILE:
            raise AtomicPublicationAmbiguity(
                "injected terminal durability ambiguity", descriptor
            )
        return descriptor

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", install_then_raise
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            repository_root=paths.identities[0],
            data_root=paths.identities[1],
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert not (run_directory / RESULT_FILE).exists()
    quarantines = tuple(run_directory.glob(f".{RESULT_FILE}.quarantine-*"))
    assert len(quarantines) == 1
    quarantined = json.loads(quarantines[0].read_bytes())
    assert quarantined["status"] == "PASS"
