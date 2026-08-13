from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import holoagent0_setup.semantic_fixture_node as fixture_module
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
    load_real_hmsg_adapter,
    offline_natural_language_parser_gate,
    semantic_evidence_reason,
    validate_ros_graph,
    validate_fixture_runtime_environment,
    verify_cyclone_roles,
)
from holoagent0_setup.semantic_fixture_node import SemanticFixtureController
from holoagent0_setup.source_gate import APPROVED_ASSET_ROOTS


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = PACKAGE_ROOT.parents[1]
ASSET_LOCK = PACKAGE_ROOT / "locks/icra_ic4f-assets-v1.json"


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


def test_real_hmsg_query_configuration_uses_owned_output_not_asset_roots(tmp_path):
    graph = APPROVED_ASSET_ROOTS["graph"]
    checkpoint = APPROVED_ASSET_ROOTS["checkpoint"]
    configuration = hmsg_query_configuration(
        graph_path=graph,
        checkpoint_path=checkpoint,
        run_directory=tmp_path,
    )

    assert configuration == {
        "main": {
            "use_gpt": False,
            "graph_path": str(graph),
            "save_path": str(tmp_path),
        },
        "models": {"clip": {"type": "ViT-L/14", "checkpoint": str(checkpoint)}},
    }


def test_real_adapter_fails_closed_when_assets_or_dependencies_are_unavailable(
    tmp_path,
):
    roots = dict(APPROVED_ASSET_ROOTS)
    roots["graph"] = tmp_path / "unapproved-graph"
    with pytest.raises(SemanticGateError, match="SEMANTIC_ASSET_UNAVAILABLE"):
        load_real_hmsg_adapter(REPOSITORY_ROOT, ASSET_LOCK, roots, tmp_path)


def test_four_role_cyclone_configs_are_exact_and_digest_bound():
    contract = verify_cyclone_roles(REPOSITORY_ROOT, ASSET_LOCK)

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
    copied = tmp_path / "repository"
    copied_config = copied / "scripts/holoagent0_setup/config"
    copied_config.mkdir(parents=True)
    for source in sorted((PACKAGE_ROOT / "config").glob("cyclonedds-offline-p*.xml")):
        (copied_config / source.name).write_bytes(source.read_bytes())
    target = copied_config / "cyclonedds-offline-p2.xml"
    target.write_text(
        target.read_text().replace(
            "<Transport>udp</Transport>", "<Transport>tcp</Transport>"
        )
    )

    with pytest.raises(SemanticGateError, match="CYCLONE_CONFIG_MISMATCH"):
        verify_cyclone_roles(copied, ASSET_LOCK)


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


@pytest.mark.parametrize("build_fails", [False, True])
def test_fixture_main_is_bounded_and_shuts_ros_down_on_constructor_failure(
    tmp_path, monkeypatch, build_fails
):
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
    monkeypatch.setattr(fixture_module, "verify_cyclone_roles", lambda *_: object())
    monkeypatch.setattr(
        fixture_module, "validate_fixture_runtime_environment", lambda *_: None
    )
    monkeypatch.setattr(
        fixture_module, "load_real_hmsg_adapter", lambda *_: FakeAdapter()
    )

    def build(_adapter):
        if build_fails:
            raise RuntimeError("constructor failed")
        return node

    monkeypatch.setattr(fixture_module, "build_ros_node", build)
    arguments = [
        "--repository-root",
        str(REPOSITORY_ROOT),
        "--asset-lock",
        str(ASSET_LOCK),
        "--graph-root",
        str(APPROVED_ASSET_ROOTS["graph"]),
        "--dataset-root",
        str(APPROVED_ASSET_ROOTS["dataset"]),
        "--checkpoint-path",
        str(APPROVED_ASSET_ROOTS["checkpoint"]),
        "--run-directory",
        str(tmp_path),
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
                str(REPOSITORY_ROOT),
                "--asset-lock",
                str(ASSET_LOCK),
                "--graph-root",
                str(APPROVED_ASSET_ROOTS["graph"]),
                "--dataset-root",
                str(APPROVED_ASSET_ROOTS["dataset"]),
                "--checkpoint-path",
                str(APPROVED_ASSET_ROOTS["checkpoint"]),
                "--run-directory",
                str(tmp_path),
            ]
        )
    assert events == ["destroy", "shutdown"]
