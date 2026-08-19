from __future__ import annotations

import hashlib
import importlib
import importlib.machinery
import json
import os
from dataclasses import replace
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

import pytest

from holoagent0_setup.atomic_io import (
    AtomicPublicationAmbiguity,
    canonical_json_bytes,
)
from holoagent0_setup.contract import ContractError, ContractSet
import holoagent0_setup.handover_evidence as evidence_module
import holoagent0_setup.semantic_gate as semantic_gate_module
import holoagent0_setup.source_gate as source_gate_module
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
    publish_handover_evidence as _publish_handover_evidence,
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
    AssetGateError,
    HandoverPaths,
    PathIdentity,
    SourceGateError,
    SourceVerification,
    VerifiedAssetLock,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
STARTED = "2026-08-18T00:00:00.1234567Z"
FINISHED = "2026-08-18T00:00:01Z"
GIT_SHA = "a" * 40
LOCK_SHA256 = hashlib.sha256(b"lock").hexdigest()

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


def test_documentation_defines_the_closed_unsigned_stage_a_contract():
    document = (REPOSITORY_ROOT / "docs/FSR_VLN_HOLOAGENT_HANDOVER.md").read_text(
        encoding="utf-8"
    )
    stage_a, marker, history = document.partition("## Superseded Historical Evidence")

    assert marker
    required_stage_a = (
        "holoagent0-fsrvln-handover-v1",
        "Accepted implementation commit: UNSIGNED — acceptance not yet performed",
        "git clone --no-recurse-submodules",
        "repository_root/fsr_vln",
        "fsr_vln/scene_graphs_opensource/horizon/icra_ic4f/graph_20260629211448",
        "fsr_vln/rgbd_datasets/icra_ic4f",
        "fsr_vln/checkpoints/open_clip_pytorch_model.bin",
        GRAPH_ROOT_SHA256,
        DATASET_ROOT_SHA256,
        CHECKPOINT_SHA256,
        "Take me to the counter in the pantry",
        "Room: `0_0` (`Pantry`)",
        "Object: `0_0_81` (`counter`)",
        "(-21.526786203133774, -15.671372634872082, -0.27579107548158116)",
        "environment.json",
        "source-verification.json",
        "asset-verification.json",
        "query-result.json",
        "handover-result.json",
        "at least 10 GB",
        "Outgoing owner:",
        "Incoming owner:",
        "Second verified asset copy:",
        "UNSIGNED — acceptance not yet performed",
        "agentic_robot/fsr_vln/",
        "NOT QUALIFIED BY THIS HANDOVER",
    )
    for required in required_stage_a:
        assert required in stage_a

    command_match = re.search(
        r"```bash\n(?P<command>[^`]*python -m "
        r"holoagent0_setup\.fsrvln_handover[^`]*)\n```",
        stage_a,
    )
    assert command_match is not None
    command = command_match.group("command")
    assert re.findall(r"--[a-z][a-z-]*", command) == [
        "--repository-root",
        "--data-root",
        "--run-directory",
    ]

    for forbidden in (
        "--recursive",
        "--graph",
        "--dataset",
        "--checkpoint",
        "--asset-lock",
        "Stage A source: `agentic_robot/fsr_vln`",
        "Stage A runtime: `agentic_robot/fsr_vln`",
        "Incoming owner: TBD",
        "Status: PASS",
        "Final result: PASS",
        ".worktrees/holoagent0-workstation-pc2-setup/docs/",
    ):
        assert forbidden not in stage_a

    assert "fsr_vln/environment.yaml" in stage_a
    assert "agentic_robot/fsr_vln/environment.yaml" in stage_a
    assert "Neither environment YAML is an acceptance authority" in stage_a
    assert "does not prescribe a transfer tool" in stage_a
    assert "f164095abb0045a69c0b8eb23683063be3deaa38" in history
    assert "74" in history
    assert "ROS" in history
    assert "Jihun" in history


def test_documentation_commit_field_supports_release_identity_extraction():
    document = (REPOSITORY_ROOT / "docs/FSR_VLN_HOLOAGENT_HANDOVER.md").read_text(
        encoding="utf-8"
    )
    unsigned = "Accepted implementation commit: UNSIGNED — acceptance not yet performed"
    implementation_sha = "a" * 40
    assert document.splitlines().count(unsigned) == 1
    signed = document.replace(
        unsigned,
        f"Accepted implementation commit: `{implementation_sha}`",
        1,
    )

    completed = subprocess.run(
        [
            "/usr/bin/sed",
            "-n",
            r"s/^Accepted implementation commit: `\([0-9a-f]\{40\}\)`$/\1/p",
        ],
        input=signed,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )

    assert completed.stdout == implementation_sha + "\n"


def test_documentation_clone_and_ancestry_verification_is_fail_closed():
    document = (REPOSITORY_ROOT / "docs/FSR_VLN_HOLOAGENT_HANDOVER.md").read_text(
        encoding="utf-8"
    )
    clone_block = document.split("```bash\n", 1)[1].split("\n```", 1)[0]

    assert clone_block.splitlines()[0] == "set -euo pipefail"
    assert clone_block.splitlines()[1] == "umask 0022"
    assert clone_block.index("umask 0022") < clone_block.index(
        "git clone --no-recurse-submodules"
    )
    assert clone_block.index("merge-base --is-ancestor") < clone_block.index(
        "checkout --detach"
    )
    fail_fast = subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n/bin/false\necho continued"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert fail_fast.returncode != 0
    assert fail_fast.stdout == ""


def test_documentation_clone_normalizes_the_pinned_installer_mode():
    document = (REPOSITORY_ROOT / "docs/FSR_VLN_HOLOAGENT_HANDOVER.md").read_text(
        encoding="utf-8"
    )
    clone_block = document.split("```bash\n", 1)[1].split("\n```", 1)[0]

    assert clone_block.index("checkout --detach") < clone_block.index("INSTALL_DRIVER=")
    for command in (
        'test -f "$INSTALL_DRIVER"',
        'test ! -L "$INSTALL_DRIVER"',
        'chmod 0644 -- "$INSTALL_DRIVER"',
        'test "$(stat -c \'%a\' -- "$INSTALL_DRIVER")" = 644',
    ):
        assert command in clone_block


def test_acceptance_plan_clone_blocks_are_fail_closed_and_mode_normalizing():
    plan = (
        REPOSITORY_ROOT
        / "docs/superpowers/plans/2026-08-18-fsrvln-fixed-query-handover.md"
    ).read_text(encoding="utf-8")
    clone_blocks = tuple(
        block
        for block in re.findall(r"```bash\n(.*?)\n```", plan, flags=re.DOTALL)
        if "git clone --no-recurse-submodules" in block
    )

    assert len(clone_blocks) == 3
    for block in clone_blocks:
        assert block.splitlines()[:2] == ["set -euo pipefail", "umask 0022"]
        assert block.index("git clone --no-recurse-submodules") < block.index(
            "checkout --detach"
        )
        assert block.index("checkout --detach") < block.index("INSTALL_DRIVER=")
        for command in (
            'test -f "$INSTALL_DRIVER"',
            'test ! -L "$INSTALL_DRIVER"',
            'chmod 0644 -- "$INSTALL_DRIVER"',
            'test "$(stat -c \'%a\' -- "$INSTALL_DRIVER")" = 644',
        ):
            assert command in block


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


def _pass_source_verification() -> SourceVerification:
    return SourceVerification(
        commit="c" * 40,
        verified_count=73,
        provenance=((GIT_SHA, 72), ("d" * 40, 1)),
    )


def _pass_asset_verification() -> VerifiedAssetLock:
    asset_specs = tuple(
        SimpleNamespace(role=role) for role in ("graph", "dataset", "checkpoint")
    )
    manifests = tuple(
        SimpleNamespace(file_count=index, byte_count=index * 10, sha256=digest)
        for index, digest in enumerate(
            (GRAPH_ROOT_SHA256, DATASET_ROOT_SHA256, CHECKPOINT_SHA256), start=1
        )
    )
    return VerifiedAssetLock(
        lock=SimpleNamespace(assets=asset_specs),
        manifests=manifests,
    )


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
        verification=_pass_source_verification(),
    )
    asset = build_asset_document(
        paths,
        status="PASS",
        reason="OK",
        started_at=STARTED,
        finished_at=FINISHED,
        asset_lock_sha256=LOCK_SHA256,
        verification=_pass_asset_verification(),
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


_AUTO_CONTEXT = object()


def publish_handover_evidence(
    contract,
    run_directory,
    documents,
    *,
    paths,
    source_verification=_AUTO_CONTEXT,
    asset_verification=_AUTO_CONTEXT,
    graph_counts=_AUTO_CONTEXT,
    semantic_result=_AUTO_CONTEXT,
    **kwargs,
):
    """Test seam supplying the immutable PASS observations required by the API."""

    if source_verification is _AUTO_CONTEXT:
        source_verification = (
            _pass_source_verification()
            if documents[SOURCE_FILE]["status"] == "PASS"
            else None
        )
    if asset_verification is _AUTO_CONTEXT:
        asset_verification = (
            _pass_asset_verification()
            if documents[ASSET_FILE]["status"] == "PASS"
            else None
        )
    if graph_counts is _AUTO_CONTEXT:
        graph_counts = (
            GraphCounts(1, 3, 497)
            if documents[QUERY_FILE]["status"] == "PASS"
            else None
        )
    if semantic_result is _AUTO_CONTEXT:
        semantic_result = (
            _semantic_result() if documents[QUERY_FILE]["status"] == "PASS" else None
        )
    return _publish_handover_evidence(
        contract,
        run_directory,
        documents,
        paths=paths,
        source_verification=source_verification,
        asset_verification=asset_verification,
        graph_counts=graph_counts,
        semantic_result=semantic_result,
        **kwargs,
    )


def _publish_authoritative_pass(
    contract,
    run_directory,
    documents,
    paths,
    *,
    source_verification=None,
    asset_verification=None,
    graph_counts=None,
    semantic_result=None,
):
    return publish_handover_evidence(
        contract,
        run_directory,
        documents,
        paths=paths,
        source_verification=(
            _pass_source_verification()
            if source_verification is None
            else source_verification
        ),
        asset_verification=(
            _pass_asset_verification()
            if asset_verification is None
            else asset_verification
        ),
        graph_counts=GraphCounts(1, 3, 497) if graph_counts is None else graph_counts,
        semantic_result=_semantic_result()
        if semantic_result is None
        else semantic_result,
        accepted_implementation_commit=GIT_SHA,
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )


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


def test_environment_normalizes_string_subclass_module_version(monkeypatch, tmp_path):
    paths = _fake_paths(tmp_path)
    _install_fake_runtime(monkeypatch, paths, cuda=False)

    class RuntimeVersion(str):
        pass

    torch = _module("torch", origin="/opt/runtime/torch.py")
    torch.__version__ = RuntimeVersion("2.4.1+cu118")
    torch.version = SimpleNamespace(cuda=None)
    torch.cuda = SimpleNamespace(is_available=lambda: False)
    runtime_import = evidence_module.import_module
    monkeypatch.setattr(
        evidence_module,
        "import_module",
        lambda name: torch if name == "torch" else runtime_import(name),
    )

    document = qualify_environment(paths)

    assert document["status"] == "PASS"
    torch_row = document["imports"][0]
    assert torch_row["status"] == "PASS"
    assert torch_row["version"] == "2.4.1+cu118"
    assert type(torch_row["version"]) is str


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
            paths=paths,
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
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_cuda_build_missing_diagnostics_publish_terminal_environment_failure(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    _install_fake_runtime(monkeypatch, paths, cuda=False)
    torch = _module("torch", "2.7.1", origin="/opt/runtime/torch.py")
    torch.version = SimpleNamespace(cuda=None)
    torch.cuda = SimpleNamespace(is_available=lambda: True)
    fake_import = evidence_module.import_module
    monkeypatch.setattr(
        evidence_module,
        "import_module",
        lambda name: torch if name == "torch" else fake_import(name),
    )
    documents = _pass_documents(paths)
    documents[ENVIRONMENT_FILE] = qualify_environment(paths)
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
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)

    publish_handover_evidence(
        contract,
        run_directory,
        documents,
        accepted_implementation_commit=GIT_SHA,
        paths=paths,
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="GPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    assert {path.name for path in run_directory.iterdir()} == {
        *EVIDENCE_ORDER,
        RESULT_FILE,
    }
    published_environment = json.loads((run_directory / ENVIRONMENT_FILE).read_bytes())
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert published_environment == documents[ENVIRONMENT_FILE]
    assert published_environment["accelerator"] == {
        "label": "GPU",
        "torch_cuda_build": None,
        "cuda_available": True,
    }
    assert published_environment["imports"][0]["reason"] == (
        "CUDA_BUILD_MISSING: torch reports CUDA available"
    )
    assert terminal["status"] == "FAIL"
    assert terminal["reason"] == "CUDA_BUILD_MISSING: torch reports CUDA available"
    assert terminal["first_blocking_reason"] == terminal["reason"]
    assert terminal["cpu_gpu_label"] == "GPU"


def test_publisher_rejects_pass_environment_with_wrong_graph_origin(contract, tmp_path):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[ENVIRONMENT_FILE]["graph_module_origin"] = str(
        paths.repository_root / "fsr_vln/agentic/memory/hmsg/graph/graph.py"
    )

    with pytest.raises(RuntimeError, match="graph module origin"):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_coordinated_alternate_source_and_graph_root(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    alternate_root = tmp_path / "alternate-repository"
    alternate_root.mkdir()
    documents[SOURCE_FILE]["repository_root"] = path_identity_document(
        _identity(alternate_root)
    )
    documents[ENVIRONMENT_FILE]["graph_module_origin"] = str(
        alternate_root / "fsr_vln/memory/hmsg/graph/graph.py"
    )

    with pytest.raises(RuntimeError, match="authoritative repository identity"):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize("field", ("device", "inode", "mode"))
def test_publisher_rejects_forged_source_repository_identity_field(
    contract, tmp_path, field
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[SOURCE_FILE]["repository_root"][field] += 1

    with pytest.raises(RuntimeError, match="authoritative repository identity"):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_source_repository_identity_path_alias(contract, tmp_path):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    repository_alias = tmp_path / "repository-alias"
    repository_alias.symlink_to(paths.repository_root, target_is_directory=True)
    documents[SOURCE_FILE]["repository_root"] = {
        **path_identity_document(paths.identities[0]),
        "path": str(repository_alias),
    }
    documents[ENVIRONMENT_FILE]["graph_module_origin"] = str(
        repository_alias / "fsr_vln/memory/hmsg/graph/graph.py"
    )

    with pytest.raises(RuntimeError, match="authoritative repository identity"):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize(
    "field", ("path", "device", "inode", "file_count", "byte_count")
)
def test_publisher_rebuilds_every_asset_observation_field(contract, tmp_path, field):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    graph = documents[ASSET_FILE]["assets"][0]
    if field == "path":
        graph[field] = str(tmp_path / "forged-graph")
    else:
        graph[field] += 1

    with pytest.raises(RuntimeError):
        _publish_authoritative_pass(contract, run_directory, documents, paths)

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize(
    "field", ("source_lock_commit", "verified_count", "provenance")
)
def test_publisher_rebuilds_every_source_verification_field(contract, tmp_path, field):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    if field == "source_lock_commit":
        documents[SOURCE_FILE][field] = "e" * 40
    elif field == "verified_count":
        documents[SOURCE_FILE][field] += 1
    else:
        documents[SOURCE_FILE][field][0]["count"] += 1

    with pytest.raises(RuntimeError):
        _publish_authoritative_pass(contract, run_directory, documents, paths)

    assert list(run_directory.iterdir()) == []


def test_publisher_binds_asset_lock_digest_to_retained_lock_bytes(contract, tmp_path):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[ASSET_FILE]["asset_lock_sha256"] = "f" * 64

    with pytest.raises(RuntimeError):
        _publish_authoritative_pass(contract, run_directory, documents, paths)

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_accepted_commit_mismatch_before_any_write(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            _pass_documents(paths),
            accepted_implementation_commit="e" * 40,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_asset_data_root_mismatch_before_any_write(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    alternate_data = tmp_path / "alternate-data"
    alternate_data.mkdir()
    documents[ASSET_FILE]["data_root"] = path_identity_document(
        _identity(alternate_data)
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize(
    "roles",
    (
        ("dataset", "graph", "checkpoint"),
        ("graph", "graph", "checkpoint"),
    ),
)
def test_publisher_rejects_asset_pass_roles_not_exactly_ordered_unique(
    contract, tmp_path, roles
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    for row, role in zip(documents[ASSET_FILE]["assets"], roles):
        row["role"] = role

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize(
    "mismatch",
    (
        "query_sha256",
        "structured_query_sha256",
        "graph_root_sha256",
        "dataset_root_sha256",
        "checkpoint_sha256",
        "room_name_mapping_sha256",
        "asset_graph_sha256",
        "asset_dataset_sha256",
        "asset_checkpoint_sha256",
    ),
)
def test_publisher_rejects_each_pass_digest_mismatch(contract, tmp_path, mismatch):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    replacement = "f" * 64
    if mismatch == "query_sha256":
        documents[QUERY_FILE]["query_sha256"] = replacement
    elif mismatch.startswith("asset_"):
        role = mismatch.removeprefix("asset_").removesuffix("_sha256")
        row = next(
            row for row in documents[ASSET_FILE]["assets"] if row["role"] == role
        )
        row["sha256"] = replacement
    else:
        documents[QUERY_FILE]["result"][mismatch] = replacement

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


@pytest.mark.parametrize(
    "mismatch",
    (
        "counts",
        "graph_identity",
        "floor_id",
        "room_id",
        "room_name",
        "object_id",
        "object_name",
        "frame_id",
        "position",
        "orientation",
    ),
)
def test_publisher_rejects_each_pass_semantic_mismatch(contract, tmp_path, mismatch):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    result = documents[QUERY_FILE]["result"]
    if mismatch == "counts":
        result["graph_counts"]["objects"] = 496
    elif mismatch == "room_id":
        result["room"]["id"] = "other-room"
    elif mismatch == "room_name":
        result["room"]["name"] = "Office"
    elif mismatch == "object_id":
        result["object"]["id"] = "other-object"
    elif mismatch == "object_name":
        result["object"]["name"] = "table"
    elif mismatch == "position":
        result["position"][0] += 2e-6
    elif mismatch == "orientation":
        result["orientation"] = [0.0, 0.0, 1.0, 0.0]
    else:
        result[mismatch] = f"wrong-{mismatch}"

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert list(run_directory.iterdir()) == []


def test_publisher_rejects_pass_execution_count_before_any_write(
    contract, monkeypatch, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[QUERY_FILE]["execution_count"] = 2
    attempts = []
    real_write = evidence_module.atomic_write_json_no_replace

    def recording_write(path, document, **kwargs):
        attempts.append(path.name)
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", recording_write
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert attempts == []
    assert list(run_directory.iterdir()) == []


def test_publisher_accepts_semantic_position_within_absolute_tolerance(
    contract, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    documents[QUERY_FILE]["result"]["position"][0] += 5e-7
    observed_result = replace(
        _semantic_result(),
        position=tuple(documents[QUERY_FILE]["result"]["position"]),
    )

    publish_handover_evidence(
        contract,
        run_directory,
        documents,
        accepted_implementation_commit=GIT_SHA,
        paths=paths,
        semantic_result=observed_result,
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "PASS"


@pytest.mark.parametrize(
    ("filename", "kind"),
    (
        (ENVIRONMENT_FILE, "regular"),
        (QUERY_FILE, "directory"),
        (RESULT_FILE, "symlink"),
    ),
)
def test_reserved_name_collision_rejects_before_first_write(
    contract, monkeypatch, tmp_path, filename, kind
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    reserved = run_directory / filename
    if kind == "regular":
        reserved.write_bytes(b"reserved")
    elif kind == "directory":
        reserved.mkdir()
    else:
        reserved.symlink_to("missing-target")
    paths = _fake_paths(tmp_path)
    attempts = []
    real_write = evidence_module.atomic_write_json_no_replace

    def recording_write(path, document, **kwargs):
        attempts.append(path.name)
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(
        evidence_module, "atomic_write_json_no_replace", recording_write
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            _pass_documents(paths),
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert attempts == []
    assert tuple(run_directory.iterdir()) == (reserved,)


def test_publisher_snapshots_caller_documents_before_first_write(
    contract, monkeypatch, tmp_path
):
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    expected_query = json.loads(canonical_json_bytes(documents[QUERY_FILE]))
    expected_asset = json.loads(canonical_json_bytes(documents[ASSET_FILE]))
    real_write = evidence_module.atomic_write_json_no_replace
    mutated = False

    def mutate_caller_after_first_write(path, document, **kwargs):
        nonlocal mutated
        descriptor = real_write(path, document, **kwargs)
        if not mutated:
            mutated = True
            documents[QUERY_FILE]["status"] = "FAIL"
            documents[QUERY_FILE]["reason"] = "MUTATED_CALLER_DOCUMENT"
            documents[QUERY_FILE]["query_sha256"] = "f" * 64
            documents[QUERY_FILE]["result"]["structured_query_sha256"] = "f" * 64
            documents[ASSET_FILE]["assets"][0]["role"] = "dataset"
            documents[ASSET_FILE]["assets"][0]["sha256"] = "f" * 64
        return descriptor

    monkeypatch.setattr(
        evidence_module,
        "atomic_write_json_no_replace",
        mutate_caller_after_first_write,
    )

    publish_handover_evidence(
        contract,
        run_directory,
        documents,
        accepted_implementation_commit=GIT_SHA,
        paths=paths,
        run_directory_identity=_identity(run_directory),
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    assert json.loads((run_directory / QUERY_FILE).read_bytes()) == expected_query
    assert json.loads((run_directory / ASSET_FILE).read_bytes()) == expected_asset
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "PASS"
    assert terminal["first_blocking_reason"] is None


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
    replays = []

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
    real_read = evidence_module.read_json_secure

    def recording_read(path, **kwargs):
        replays.append(
            (
                path.name,
                kwargs.get("directory_fd"),
                kwargs.get("relative_to"),
            )
        )
        return real_read(path, **kwargs)

    monkeypatch.setattr(evidence_module, "read_json_secure", recording_read)

    terminal_descriptor = publish_handover_evidence(
        RecordingContract(),
        run_directory,
        documents,
        accepted_implementation_commit=GIT_SHA,
        paths=paths,
        run_directory_identity=run_identity,
        cpu_gpu_label="CPU",
        started_at=STARTED,
        finished_at=FINISHED,
    )

    assert calls[:8] == [
        ("validate", "fsrvln-environment-v1"),
        ("write", ENVIRONMENT_FILE),
        ("validate", "fsrvln-source-verification-v1"),
        ("write", SOURCE_FILE),
        ("validate", "fsrvln-asset-verification-v1"),
        ("write", ASSET_FILE),
        ("validate", "fsrvln-query-result-v1"),
        ("write", QUERY_FILE),
    ]
    replay_validations = [
        ("validate", "fsrvln-environment-v1"),
        ("validate", "fsrvln-source-verification-v1"),
        ("validate", "fsrvln-asset-verification-v1"),
        ("validate", "fsrvln-query-result-v1"),
    ]
    assert calls[8:12] == replay_validations
    assert calls[12:14] == [
        ("validate", "fsrvln-handover-result-v1"),
        ("write", RESULT_FILE),
    ]
    assert calls[14:] == [
        *replay_validations,
        ("validate", "fsrvln-handover-result-v1"),
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
    assert [name for name, _directory_fd, _relative_to in replays] == [
        *EVIDENCE_ORDER,
        *EVIDENCE_ORDER,
        RESULT_FILE,
    ]
    assert all(
        directory_fd == retained_fd and relative_to == run_directory
        for _name, directory_fd, relative_to in replays
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
    calls_before_second_publication = list(calls)
    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=run_identity,
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )
    assert calls == calls_before_second_publication
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
        paths=paths,
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
        accepted_implementation_commit=GIT_SHA,
        paths=paths,
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
    if failed_filename == ASSET_FILE:
        documents[ASSET_FILE]["status"] = "FAIL"
        documents[ASSET_FILE]["reason"] = "INJECTED_SCHEMA_FAILURE"
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
            paths=paths,
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
            paths=paths,
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
            paths=paths,
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


def test_stage_replacement_after_write_is_detected_before_terminal(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    real_write = evidence_module.atomic_write_json_no_replace

    def replace_stage_after_last_write(path, document, **kwargs):
        descriptor = real_write(path, document, **kwargs)
        if path.name == QUERY_FILE:
            target = run_directory / ENVIRONMENT_FILE
            replacement = run_directory / ".replacement-environment"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setattr(
        evidence_module,
        "atomic_write_json_no_replace",
        replace_stage_after_last_write,
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert not (run_directory / RESULT_FILE).exists()


def test_post_terminal_stage_tamper_removes_authoritative_terminal(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    real_write = evidence_module.atomic_write_json_no_replace

    def replace_stage_after_terminal(path, document, **kwargs):
        descriptor = real_write(path, document, **kwargs)
        if path.name == RESULT_FILE:
            target = run_directory / QUERY_FILE
            replacement = run_directory / ".replacement-query"
            replacement.write_bytes(target.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, target)
        return descriptor

    monkeypatch.setattr(
        evidence_module,
        "atomic_write_json_no_replace",
        replace_stage_after_terminal,
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
            run_directory_identity=_identity(run_directory),
            cpu_gpu_label="CPU",
            started_at=STARTED,
            finished_at=FINISHED,
        )

    assert not (run_directory / RESULT_FILE).exists()
    quarantines = tuple(run_directory.glob(f".{RESULT_FILE}.quarantine-*"))
    assert len(quarantines) == 1


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
            paths=paths,
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


def test_late_terminal_collision_is_removed_from_retained_directory(
    contract, monkeypatch, tmp_path
):
    paths = _fake_paths(tmp_path)
    documents = _pass_documents(paths)
    run_directory = tmp_path / "run"
    run_directory.mkdir(mode=0o700)
    real_write = evidence_module.atomic_write_json_no_replace

    def collide_immediately_before_terminal_write(path, document, **kwargs):
        if path.name == RESULT_FILE:
            real_write(path, document, **kwargs)
        return real_write(path, document, **kwargs)

    monkeypatch.setattr(
        evidence_module,
        "atomic_write_json_no_replace",
        collide_immediately_before_terminal_write,
    )

    with pytest.raises(RuntimeError):
        publish_handover_evidence(
            contract,
            run_directory,
            documents,
            accepted_implementation_commit=GIT_SHA,
            paths=paths,
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
    assert {
        path.name for path in run_directory.iterdir() if not path.name.startswith(".")
    } == set(EVIDENCE_ORDER)


def test_cli_requires_exact_three_paths_and_rejects_abbreviations(tmp_path):
    cli = importlib.import_module("holoagent0_setup.fsrvln_handover")
    repository = tmp_path / "repository"
    data = tmp_path / "data"
    run_directory = tmp_path / "run"

    parsed = cli._parse_arguments(
        [
            "--repository-root",
            str(repository),
            "--data-root",
            str(data),
            "--run-directory",
            str(run_directory),
        ]
    )

    assert vars(parsed) == {
        "repository_root": repository,
        "data_root": data,
        "run_directory": run_directory,
    }
    with pytest.raises(SystemExit) as abbreviated:
        cli._parse_arguments(
            [
                "--repository",
                str(repository),
                "--data-root",
                str(data),
                "--run-directory",
                str(run_directory),
            ]
        )
    assert abbreviated.value.code == 2

    for invalid in (
        [],
        [
            "--repository-root",
            str(repository),
            "--data-root",
            str(data),
        ],
        [
            "--repository-root",
            str(repository),
            "--data-root",
            str(data),
            "--run-directory",
            str(run_directory),
            "--unexpected",
        ],
    ):
        with pytest.raises(SystemExit) as misuse:
            cli._parse_arguments(invalid)
        assert misuse.value.code == 2


class _CliAdapter:
    def __init__(self):
        self.closed = False

    def graph_counts(self):
        return GraphCounts(1, 3, 497)

    def close(self):
        self.closed = True

    def __exit__(self, _exc_type, _exc_value, _traceback):
        self.close()


def _install_cli_fakes(monkeypatch, tmp_path, contract, *, failure=None):
    cli = importlib.import_module("holoagent0_setup.fsrvln_handover")
    paths = _fake_paths(tmp_path)
    run_directory = tmp_path / "run"
    calls = []
    captured = {}
    adapter = _CliAdapter()
    source_lock = SimpleNamespace(commit="c" * 40)
    source_verification = _pass_source_verification()
    asset_verification = _pass_asset_verification()
    environment = _pass_documents(paths)[ENVIRONMENT_FILE]

    def fail_or(name, value):
        calls.append(name)
        if failure == name:
            if name in {"checkout_identity", "source_git_objects", "source_worktree"}:
                raise SourceGateError(f"{name.upper()}_FAILED", "injected")
            if name == "asset_inventory":
                raise AssetGateError("ASSET_INVENTORY_FAILED", "injected")
            if name in {"graph_load", "query_once"}:
                from holoagent0_setup.semantic_gate import SemanticGateError

                raise SemanticGateError(f"{name.upper()}_FAILED", "injected")
            if name == "environment":
                raise OSError("injected environment failure")
        return value

    def from_roots(repository_root, data_root):
        assert repository_root == paths.repository_root
        assert data_root == paths.data_root
        return fail_or("paths", paths)

    def prepare(actual_run_directory, actual_paths):
        assert actual_run_directory == run_directory
        assert actual_paths is paths
        actual_run_directory.mkdir(mode=0o700)
        return fail_or("run_directory", _identity(actual_run_directory))

    monkeypatch.setattr(cli.HandoverPaths, "from_roots", from_roots)
    monkeypatch.setattr(cli, "prepare_handover_run_directory", prepare)
    monkeypatch.setattr(cli, "load_source_lock", lambda source: source_lock)
    monkeypatch.setattr(
        cli,
        "verify_checkout_identity",
        lambda repository, lock: fail_or("checkout_identity", GIT_SHA),
    )
    monkeypatch.setattr(
        cli,
        "verify_manifest_git_objects",
        lambda repository, lock: fail_or("source_git_objects", source_verification),
    )
    monkeypatch.setattr(
        cli,
        "verify_source_worktree",
        lambda repository, lock: fail_or("source_worktree", source_verification),
    )
    monkeypatch.setattr(
        cli, "qualify_environment", lambda actual: fail_or("environment", environment)
    )
    monkeypatch.setattr(
        cli,
        "verify_asset_lock",
        lambda actual: fail_or("asset_inventory", asset_verification),
    )
    monkeypatch.setattr(
        cli,
        "load_real_hmsg_adapter",
        lambda actual_paths, actual_run: fail_or("graph_load", adapter),
    )
    monkeypatch.setattr(
        cli,
        "evaluate_semantic_fixture",
        lambda actual_adapter, query: fail_or("query_once", _semantic_result()),
    )
    monkeypatch.setattr(cli, "sha256_retained_asset_lock", lambda actual: LOCK_SHA256)
    monkeypatch.setattr(cli, "ContractSet", lambda root: contract)

    builder_names = (
        ("build_environment_document", "environment_evidence"),
        ("build_source_document", "source_evidence"),
        ("build_asset_document", "asset_evidence"),
        ("build_query_document", "query_evidence"),
    )
    for function_name, call_name in builder_names:
        original = getattr(cli, function_name)

        def recording_builder(*args, _original=original, _name=call_name, **kwargs):
            calls.append(_name)
            return _original(*args, **kwargs)

        monkeypatch.setattr(cli, function_name, recording_builder)

    def publish(actual_contract, actual_run_directory, documents, **contexts):
        calls.append("terminal_evidence")
        captured["documents"] = documents
        captured["contexts"] = contexts
        return publish_handover_evidence(
            contract,
            actual_run_directory,
            documents,
            **contexts,
        )

    monkeypatch.setattr(cli, "publish_handover_evidence", publish)
    argv = [
        "--repository-root",
        str(paths.repository_root),
        "--data-root",
        str(paths.data_root),
        "--run-directory",
        str(run_directory),
    ]
    return cli, paths, run_directory, calls, captured, adapter, argv


def test_cli_success_order_runs_the_structured_query_exactly_once(
    monkeypatch, tmp_path, contract
):
    cli, paths, _run, calls, captured, adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )

    assert cli.main(argv) == 0

    assert calls == [
        "paths",
        "run_directory",
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment",
        "asset_inventory",
        "graph_load",
        "query_once",
        "environment_evidence",
        "source_evidence",
        "asset_evidence",
        "query_evidence",
        "terminal_evidence",
    ]
    assert captured["documents"][QUERY_FILE]["execution_count"] == 1
    assert captured["documents"][QUERY_FILE]["status"] == "PASS"
    assert captured["contexts"]["paths"] is paths
    assert captured["contexts"]["source_verification"] == _pass_source_verification()
    assert captured["contexts"]["asset_verification"] == _pass_asset_verification()
    assert captured["contexts"]["graph_counts"] == GraphCounts(1, 3, 497)
    assert captured["contexts"]["semantic_result"] == _semantic_result()
    assert adapter.closed


def test_cli_outer_audit_tamper_is_recorded_once_and_still_publishes_five_records(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, calls, captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    original_import_module = importlib.import_module

    def tamper_import_hook(_repository, _lock):
        calls.append("source_worktree")
        importlib.import_module = lambda *_args, **_kwargs: None
        return _pass_source_verification()

    monkeypatch.setattr(cli, "verify_source_worktree", tamper_import_hook)

    assert cli.main(argv) == 1

    assert importlib.import_module is original_import_module
    assert calls == [
        "paths",
        "run_directory",
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment_evidence",
        "source_evidence",
        "asset_evidence",
        "query_evidence",
        "terminal_evidence",
    ]
    documents = captured["documents"]
    assert documents[SOURCE_FILE]["status"] == "FAIL"
    assert documents[SOURCE_FILE]["reason"] == "RUNTIME_IMPORT_AUDIT_INVALID"
    for filename in (ENVIRONMENT_FILE, ASSET_FILE, QUERY_FILE):
        assert documents[filename]["status"] == "NOT_RUN"
        assert documents[filename]["reason"] == "RUNTIME_IMPORT_AUDIT_INVALID"
    assert sorted(path.name for path in run_directory.iterdir()) == sorted(
        (*EVIDENCE_ORDER, RESULT_FILE)
    )
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["first_blocking_reason"] == "RUNTIME_IMPORT_AUDIT_INVALID"


def test_cli_source_blocker_survives_outer_audit_tamper_and_publishes_five_records(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, calls, captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    original_import_module = importlib.import_module

    def tamper_import_hook_then_fail(_repository, _lock):
        calls.append("source_worktree")
        importlib.import_module = lambda *_args, **_kwargs: None
        raise SourceGateError("SOURCE_FIRST_BLOCKER", "injected")

    monkeypatch.setattr(cli, "verify_source_worktree", tamper_import_hook_then_fail)

    assert cli.main(argv) == 1

    assert importlib.import_module is original_import_module
    assert calls == [
        "paths",
        "run_directory",
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment_evidence",
        "source_evidence",
        "asset_evidence",
        "query_evidence",
        "terminal_evidence",
    ]
    documents = captured["documents"]
    assert documents[SOURCE_FILE]["status"] == "FAIL"
    assert documents[SOURCE_FILE]["reason"] == "SOURCE_FIRST_BLOCKER"
    for filename in (ENVIRONMENT_FILE, ASSET_FILE, QUERY_FILE):
        assert documents[filename]["status"] == "NOT_RUN"
        assert documents[filename]["reason"] == "SOURCE_FIRST_BLOCKER"
    assert sorted(path.name for path in run_directory.iterdir()) == sorted(
        (*EVIDENCE_ORDER, RESULT_FILE)
    )
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["first_blocking_reason"] == "SOURCE_FIRST_BLOCKER"


@pytest.mark.parametrize(
    "failure",
    (
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment",
        "asset_inventory",
        "graph_load",
        "query_once",
    ),
)
def test_cli_first_operational_exception_stops_later_gates_and_publishes_failure(
    monkeypatch, tmp_path, contract, failure
):
    cli, _paths, run_directory, calls, captured, adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract, failure=failure
    )

    assert cli.main(argv) == 1

    documents = captured["documents"]
    assert {path.name for path in run_directory.iterdir()} == {
        *EVIDENCE_ORDER,
        RESULT_FILE,
    }
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    first_reason = terminal["first_blocking_reason"]
    assert terminal["status"] == "FAIL"
    assert first_reason
    assert terminal["reason"] == first_reason
    failed_index = {
        "checkout_identity": 0,
        "source_git_objects": 0,
        "source_worktree": 0,
        "environment": 1,
        "asset_inventory": 2,
        "graph_load": 3,
        "query_once": 3,
    }[failure]
    operational_order = (
        SOURCE_FILE,
        ENVIRONMENT_FILE,
        ASSET_FILE,
        QUERY_FILE,
    )
    for index, filename in enumerate(operational_order):
        if index < failed_index:
            assert documents[filename]["status"] == "PASS"
        elif index == failed_index:
            assert documents[filename]["status"] == "FAIL"
            assert documents[filename]["reason"] == first_reason
        else:
            assert documents[filename]["status"] == "NOT_RUN"
            assert documents[filename]["reason"] == first_reason
    expected_execution_count = 1 if failure == "query_once" else 0
    assert documents[QUERY_FILE]["execution_count"] == expected_execution_count
    assert calls[-5:] == [
        "environment_evidence",
        "source_evidence",
        "asset_evidence",
        "query_evidence",
        "terminal_evidence",
    ]
    if failure in {"graph_load", "query_once"}:
        assert adapter.closed is (failure == "query_once")


def test_cli_environment_fail_is_first_blocker_and_stops_assets(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, calls, captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    environment_root = tmp_path / "environment-observation"
    environment_root.mkdir()
    environment = captured_environment = _pass_documents(_fake_paths(environment_root))[
        ENVIRONMENT_FILE
    ]
    captured_environment["status"] = "FAIL"
    captured_environment["reason"] = "IMPORT_MISSING: open3d"
    monkeypatch.setattr(cli, "qualify_environment", lambda actual: environment)

    assert cli.main(argv) == 1

    assert "asset_inventory" not in calls
    assert "graph_load" not in calls
    assert "query_once" not in calls
    documents = captured["documents"]
    assert documents[ENVIRONMENT_FILE]["status"] == "FAIL"
    assert documents[ASSET_FILE]["status"] == "NOT_RUN"
    assert documents[QUERY_FILE]["status"] == "NOT_RUN"
    assert all(
        documents[filename]["reason"] == "IMPORT_MISSING: open3d"
        for filename in (ENVIRONMENT_FILE, ASSET_FILE, QUERY_FILE)
    )
    assert json.loads((run_directory / RESULT_FILE).read_bytes())["status"] == "FAIL"


@pytest.mark.parametrize(
    "reason",
    (
        "HANDOVER_PATH_NOT_ABSOLUTE",
        "HANDOVER_PATH_ALIAS",
        "HANDOVER_PATH_OVERLAP",
        "RUN_PATH_ALIAS",
        "RUN_PATH_OVERLAP",
        "RUN_DIRECTORY_NOT_EMPTY",
    ),
)
def test_cli_untrusted_paths_exit_two_without_semantic_or_evidence_work(
    monkeypatch, tmp_path, reason
):
    cli = importlib.import_module("holoagent0_setup.fsrvln_handover")
    repository = tmp_path / "repository"
    data = tmp_path / "data"
    run_directory = tmp_path / "run"
    repository.mkdir()
    data.mkdir()
    calls = []

    if reason.startswith("RUN_"):
        fake_paths = SimpleNamespace(revalidate=lambda: None)
        monkeypatch.setattr(cli.HandoverPaths, "from_roots", lambda *args: fake_paths)

        def reject_run(*args):
            raise AssetGateError(reason, "unsafe run directory")

        monkeypatch.setattr(cli, "prepare_handover_run_directory", reject_run)
    else:

        def reject_paths(*args):
            raise AssetGateError(reason, "unsafe handover roots")

        monkeypatch.setattr(cli.HandoverPaths, "from_roots", reject_paths)

    for name in (
        "qualify_environment",
        "verify_asset_lock",
        "load_real_hmsg_adapter",
        "evaluate_semantic_fixture",
        "publish_handover_evidence",
    ):
        monkeypatch.setattr(
            cli, name, lambda *args, _name=name, **kwargs: calls.append(_name)
        )

    assert (
        cli.main(
            [
                "--repository-root",
                str(repository),
                "--data-root",
                str(data),
                "--run-directory",
                str(run_directory),
            ]
        )
        == 2
    )
    assert calls == []
    if run_directory.exists():
        assert list(run_directory.iterdir()) == []


def test_cli_rejects_source_verification_disagreement(monkeypatch, tmp_path, contract):
    cli, _paths, run_directory, calls, captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    monkeypatch.setattr(
        cli,
        "verify_source_worktree",
        lambda repository, lock: (
            calls.append("source_worktree")
            or SourceVerification(
                commit="c" * 40,
                verified_count=72,
                provenance=(("c" * 40, 72),),
            )
        ),
    )

    assert cli.main(argv) == 1

    assert "environment" not in calls
    source = captured["documents"][SOURCE_FILE]
    assert source["status"] == "FAIL"
    assert source["reason"] == "SOURCE_VERIFICATION_MISMATCH"
    assert json.loads((run_directory / RESULT_FILE).read_bytes())["status"] == "FAIL"


def test_cli_fails_if_a_forbidden_runtime_module_enters_the_query_path(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, _calls, captured, adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )

    def load_forbidden(_adapter, _query):
        sys.modules["rclpy.testing"] = SimpleNamespace()
        return _semantic_result()

    monkeypatch.setattr(cli, "evaluate_semantic_fixture", load_forbidden)
    try:
        assert cli.main(argv) == 1
    finally:
        sys.modules.pop("rclpy.testing", None)

    query = captured["documents"][QUERY_FILE]
    assert query["status"] == "FAIL"
    assert query["reason"] == "FORBIDDEN_RUNTIME_MODULE: rclpy.testing"
    assert query["execution_count"] == 1
    assert adapter.closed
    assert json.loads((run_directory / RESULT_FILE).read_bytes())["status"] == "FAIL"


def test_cli_rejects_transient_forbidden_import_restored_by_real_graph_boundary(
    monkeypatch, tmp_path, contract
):
    cli, paths, run_directory, _calls, _captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    fsr_root = paths.repository_root / "fsr_vln"
    graph_module = fsr_root / "memory/hmsg/graph/graph.py"
    graph_module.parent.mkdir(parents=True)
    graph_module.write_text(
        "import sys\n"
        "import rclpy.transient_probe\n"
        "sys.modules.pop('rclpy.transient_probe', None)\n"
        "sys.modules.pop('rclpy', None)\n"
        "SOURCE = 'root'\n",
        encoding="utf-8",
    )
    (fsr_root / "perception").mkdir()
    environment = tmp_path / "import-environment"
    (environment / "rclpy").mkdir(parents=True)
    (environment / "rclpy/__init__.py").write_text("", encoding="utf-8")
    (environment / "rclpy/transient_probe.py").write_text(
        "PROBED = True\n", encoding="utf-8"
    )
    (environment / "omegaconf.py").write_text(
        "class OmegaConf:\n    pass\n", encoding="utf-8"
    )
    monkeypatch.delitem(sys.modules, "omegaconf", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_probe", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    passing_environment = _pass_documents(paths)[ENVIRONMENT_FILE]

    def qualify_through_real_import_boundary(actual_paths):
        semantic_gate_module.import_root_hmsg_runtime(actual_paths)
        return passing_environment

    monkeypatch.setattr(
        cli, "qualify_environment", qualify_through_real_import_boundary
    )

    assert cli.main(argv) == 1
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["first_blocking_reason"] == (
        "FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe"
    )


def test_cli_rejects_transient_forbidden_import_from_passing_environment_gate(
    monkeypatch, tmp_path, contract
):
    cli, paths, run_directory, calls, captured, adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    environment_root = tmp_path / "environment-import-root"
    package = environment_root / "rclpy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "transient_environment.py").write_text(
        "PROBED = True\n", encoding="utf-8"
    )
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_environment", raising=False)
    monkeypatch.syspath_prepend(str(environment_root))
    passing_environment = _pass_documents(paths)[ENVIRONMENT_FILE]
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module

    def hostile_environment(_actual_paths):
        calls.append("environment")
        importlib.import_module("rclpy.transient_environment")
        sys.modules.pop("rclpy.transient_environment", None)
        sys.modules.pop("rclpy", None)
        return passing_environment

    monkeypatch.setattr(cli, "qualify_environment", hostile_environment)

    assert cli.main(argv) == 1

    reason = "FORBIDDEN_RUNTIME_MODULE: rclpy.transient_environment"
    assert calls == [
        "paths",
        "run_directory",
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment",
        "environment_evidence",
        "source_evidence",
        "asset_evidence",
        "query_evidence",
        "terminal_evidence",
    ]
    documents = captured["documents"]
    assert documents[SOURCE_FILE]["status"] == "PASS"
    assert documents[ENVIRONMENT_FILE]["status"] == "FAIL"
    assert documents[ENVIRONMENT_FILE]["reason"] == reason
    assert documents[ASSET_FILE]["status"] == "NOT_RUN"
    assert documents[ASSET_FILE]["reason"] == reason
    assert documents[QUERY_FILE]["status"] == "NOT_RUN"
    assert documents[QUERY_FILE]["reason"] == reason
    assert documents[QUERY_FILE]["execution_count"] == 0
    assert not adapter.closed
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["first_blocking_reason"] == reason
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_environment" not in sys.modules


def test_cli_environment_import_audit_does_not_mask_programmer_exception(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, calls, _captured, adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    environment_root = tmp_path / "failing-environment-import-root"
    package = environment_root / "rclpy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "transient_environment.py").write_text(
        "PROBED = True\n", encoding="utf-8"
    )
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_environment", raising=False)
    monkeypatch.syspath_prepend(str(environment_root))
    original_builtin_import = semantic_gate_module.builtins.__import__
    original_import_module = importlib.import_module

    def hostile_environment(_actual_paths):
        calls.append("environment")
        importlib.import_module("rclpy.transient_environment")
        sys.modules.pop("rclpy.transient_environment", None)
        sys.modules.pop("rclpy", None)
        raise AssertionError("environment programmer failure")

    monkeypatch.setattr(cli, "qualify_environment", hostile_environment)

    with pytest.raises(AssertionError, match="environment programmer failure"):
        cli.main(argv)

    assert calls == [
        "paths",
        "run_directory",
        "checkout_identity",
        "source_git_objects",
        "source_worktree",
        "environment",
    ]
    assert not adapter.closed
    assert list(run_directory.iterdir()) == []
    assert semantic_gate_module.builtins.__import__ is original_builtin_import
    assert importlib.import_module is original_import_module
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_environment" not in sys.modules


def test_cli_rejects_transient_forbidden_import_across_real_adapter_lifecycle(
    monkeypatch, tmp_path, contract
):
    cli, _paths, run_directory, _calls, captured, _adapter, argv = _install_cli_fakes(
        monkeypatch, tmp_path, contract
    )
    environment = tmp_path / "runtime-import-environment"
    package = environment / "rclpy"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "transient_probe.py").write_text("PROBED = True\n", encoding="utf-8")
    monkeypatch.delitem(sys.modules, "rclpy", raising=False)
    monkeypatch.delitem(sys.modules, "rclpy.transient_probe", raising=False)
    monkeypatch.syspath_prepend(str(environment))
    lifecycle = {}
    query_calls = []

    def transient_import():
        importlib.import_module("rclpy.transient_probe")
        sys.modules.pop("rclpy.transient_probe", None)
        sys.modules.pop("rclpy", None)

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
    graph = SimpleNamespace(
        floors=[object()],
        rooms=[
            SimpleNamespace(floor_id="0", room_id="0_0", name="Pantry"),
            SimpleNamespace(floor_id="0", room_id="0_1", name="Office"),
            SimpleNamespace(floor_id="0", room_id="0_2", name="Hallway"),
        ],
        objects=[selected, *[object() for _ in range(496)]],
    )

    def query_room(query, **kwargs):
        query_calls.append(("room", query, kwargs))
        transient_import()
        return [0]

    def query_object(query, **kwargs):
        query_calls.append(("object", query, kwargs))
        return ([0], [0], [0.9])

    graph.query_hmsg_room = query_room
    graph.query_hmsg_object = query_object

    def load_adapter(_actual_paths, _actual_run):
        audit = semantic_gate_module._ImportBoundaryAudit()
        audit.__enter__()
        authority_closes = []
        adapter = semantic_gate_module.RealHMSGRetrievalAdapter(
            graph,
            graph_identity=EXPECTED_SEMANTIC.graph_identity,
            run_authority=SimpleNamespace(
                close=lambda: authority_closes.append(True), revalidate=lambda: None
            ),
            import_audit=audit,
        )
        lifecycle.update(
            audit=audit,
            adapter=adapter,
            authority_closes=authority_closes,
        )
        return adapter

    monkeypatch.setattr(cli, "load_real_hmsg_adapter", load_adapter)
    monkeypatch.setattr(
        cli, "evaluate_semantic_fixture", semantic_gate_module.evaluate_semantic_fixture
    )

    try:
        assert cli.main(argv) == 1
    finally:
        audit = lifecycle.get("audit")
        if audit is not None:
            audit.close()

    assert [call[0] for call in query_calls] == ["room", "object"]
    assert lifecycle["authority_closes"] == [True]
    assert "rclpy" not in sys.modules
    assert "rclpy.transient_probe" not in sys.modules
    query = captured["documents"][QUERY_FILE]
    assert query["status"] == "FAIL"
    assert query["reason"] == "FORBIDDEN_RUNTIME_MODULE: rclpy.transient_probe"
    assert query["execution_count"] == 1
    terminal = json.loads((run_directory / RESULT_FILE).read_bytes())
    assert terminal["status"] == "FAIL"
    assert terminal["first_blocking_reason"] == query["reason"]


@pytest.mark.parametrize("operation", ("import", "help"))
def test_cli_import_and_help_are_light_and_non_ros_in_a_fresh_process(operation):
    package_root = PACKAGE_ROOT
    lines = [
        "import sys",
        f"sys.path.insert(0, {str(package_root)!r})",
        "import holoagent0_setup.fsrvln_handover as cli",
    ]
    if operation == "help":
        lines.extend(
            (
                "try:",
                "    cli._parse_arguments(['--help'])",
                "except SystemExit as error:",
                "    assert error.code == 0",
                "else:",
                "    raise AssertionError('--help did not exit')",
            )
        )
    lines.extend(
        (
            "forbidden=('rclpy','nav2','agentos','agentic_robot','unitree','unitree_sdk2py')",
            "loaded=sorted(name for name in sys.modules if name.startswith(forbidden))",
            "assert not loaded, loaded",
        )
    )
    script = "\n".join(lines)

    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_public_retained_asset_lock_digest_is_bound_to_the_retained_bytes(tmp_path):
    paths = _fake_paths(tmp_path)
    digest = getattr(evidence_module, "sha256_retained_asset_lock")

    assert digest(paths) == LOCK_SHA256


def test_checkout_identity_resolves_exact_head_and_proves_locked_commit_ancestor(
    monkeypatch,
):
    source_path = PACKAGE_ROOT / "locks/semantic-source-manifest-v1.json"
    lock = source_gate_module.load_source_lock(source_path)
    calls = []

    def run_git(repository_root, arguments):
        calls.append((repository_root, arguments))
        if arguments[0] == "rev-parse":
            return f"{GIT_SHA}\n"
        return ""

    monkeypatch.setattr(source_gate_module, "_run_git", run_git)
    verify_checkout_identity = getattr(source_gate_module, "verify_checkout_identity")

    assert verify_checkout_identity(Path("/repository"), lock) == GIT_SHA
    assert calls == [
        (Path("/repository"), ["rev-parse", "--verify", "HEAD^{commit}"]),
        (
            Path("/repository"),
            ["merge-base", "--is-ancestor", lock.commit, GIT_SHA],
        ),
    ]
    assert source_gate_module.load_source_lock(lock) == lock
    assert source_gate_module.load_source_lock(lock) is not lock
