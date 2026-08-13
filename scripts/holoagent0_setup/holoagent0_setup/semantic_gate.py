"""Exact, fail-closed semantic fixture contracts with lazy heavy dependencies."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any, Mapping, Protocol

from .cyclone_policy import (
    CONFIG_SET_SHA256,
    CycloneConfigError,
    CycloneConfigSet,
    load_pinned_cyclone_configs,
)
from .source_gate import (
    AssetGateError,
    load_asset_lock,
    verify_asset_lock,
)


CYCLONE_CONFIG_SET_SHA256 = CONFIG_SET_SHA256
GRAPH_ROOT_SHA256 = "6e8e27504598c0fe28836b2148ec77732be00ca9cf6d5640f7193332da98e050"
DATASET_ROOT_SHA256 = "a28fea956a4520330a76d90f75a60f7781602bfd19cd13e510b2574d39b4a913"
CHECKPOINT_SHA256 = "5ddb47339f44e4fd9cace3d3960d38af1b51a25857440cfae90afc44706d7e2b"
STRUCTURED_QUERY_SHA256 = (
    "ddcbd21de5223595c515e595192e505289f44b91252ba46643f833a007983047"
)
ROOM_NAME_MAPPING = ("Pantry", "Office", "Hallway")
ROOM_NAME_MAPPING_SHA256 = (
    "05a9439d16575a1fd76d0bf7bccd7d9f62a24424ac5516f2728c4e04b51d4845"
)


class SemanticGateError(RuntimeError):
    """The exact semantic fixture or its isolation contract failed."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}")


def offline_natural_language_parser_gate() -> dict[str, object]:
    """Return the explicit offline disposition for the networked parser seam."""
    return {
        "id": "semantic.natural_language_parser",
        "status": "SKIPPED",
        "role": "diagnostic",
        "reason": "POLICY_DISABLED",
        "measurements": [],
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


def semantic_evidence_reason(error: SemanticGateError) -> str:
    """Translate internal diagnostics to the closed result-policy vocabulary."""
    if error.reason in {
        "SEMANTIC_ASSET_UNAVAILABLE",
        "ASSET_LOCK_INVALID",
        "ASSET_INVENTORY_MISMATCH",
    }:
        return "SEMANTIC_ASSET_MISMATCH"
    if error.reason == "CYCLONE_CONFIG_MISMATCH":
        return "UNEXPECTED_DDS_PARTICIPANT"
    if error.reason == "ROS_GRAPH_MISMATCH":
        return "UNEXPECTED_ROS_ENDPOINT"
    if error.reason in {
        "SEMANTIC_QUERY_INVALID",
        "SEMANTIC_CARDINALITY_MISMATCH",
        "SEMANTIC_FIXTURE_MISMATCH",
    }:
        return "SEMANTIC_FIXTURE_MISMATCH"
    return "TOOL_RUNTIME_ERROR"


@dataclass(frozen=True)
class StructuredQuery:
    schema_version: str
    text: str
    floor_query: None
    room_query: str
    object_query: str
    graph_identity: str
    graph_root_sha256: str
    dataset_root_sha256: str
    checkpoint_sha256: str

    def to_document(self) -> dict[str, str | None]:
        return {
            "schema_version": self.schema_version,
            "text": self.text,
            "floor_query": self.floor_query,
            "room_query": self.room_query,
            "object_query": self.object_query,
            "graph_identity": self.graph_identity,
            "graph_root_sha256": self.graph_root_sha256,
            "dataset_root_sha256": self.dataset_root_sha256,
            "checkpoint_sha256": self.checkpoint_sha256,
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @classmethod
    def from_json(cls, payload: str) -> "StructuredQuery":
        if type(payload) is not str:
            raise SemanticGateError(
                "SEMANTIC_QUERY_INVALID", "structured query payload must be text"
            )

        def reject_duplicate_keys(
            pairs: list[tuple[str, Any]],
        ) -> dict[str, Any]:
            document: dict[str, Any] = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError(f"duplicate field: {key}")
                document[key] = value
            return document

        try:
            document = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise SemanticGateError("SEMANTIC_QUERY_INVALID", str(error)) from error
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "text",
            "floor_query",
            "room_query",
            "object_query",
            "graph_identity",
            "graph_root_sha256",
            "dataset_root_sha256",
            "checkpoint_sha256",
        }:
            raise SemanticGateError(
                "SEMANTIC_QUERY_INVALID", "structured query uses a closed schema"
            )
        if (
            type(document["schema_version"]) is not str
            or type(document["text"]) is not str
            or document["floor_query"] is not None
            or type(document["room_query"]) is not str
            or type(document["object_query"]) is not str
            or type(document["graph_identity"]) is not str
            or type(document["graph_root_sha256"]) is not str
            or type(document["dataset_root_sha256"]) is not str
            or type(document["checkpoint_sha256"]) is not str
        ):
            raise SemanticGateError(
                "SEMANTIC_QUERY_INVALID", "structured query fields have invalid types"
            )
        query = cls(
            schema_version=document["schema_version"],
            text=document["text"],
            floor_query=None,
            room_query=document["room_query"],
            object_query=document["object_query"],
            graph_identity=document["graph_identity"],
            graph_root_sha256=document["graph_root_sha256"],
            dataset_root_sha256=document["dataset_root_sha256"],
            checkpoint_sha256=document["checkpoint_sha256"],
        )
        if query.canonical_json() != EXPECTED_SEMANTIC.query.canonical_json():
            raise SemanticGateError(
                "SEMANTIC_QUERY_INVALID", "query differs from the approved fixture"
            )
        if payload != query.canonical_json():
            raise SemanticGateError(
                "SEMANTIC_QUERY_INVALID", "query encoding is not canonical"
            )
        return query


@dataclass(frozen=True)
class SemanticExpectation:
    query: StructuredQuery
    graph_identity: str
    floor_id: str
    room_id: str
    room_name: str
    object_id: str
    object_name: str
    frame_id: str
    position: tuple[float, float, float]
    orientation: tuple[float, float, float, float]


EXPECTED_SEMANTIC = SemanticExpectation(
    query=StructuredQuery(
        schema_version="holoagent0-semantic-query-v1",
        text="Take me to the counter in the pantry",
        floor_query=None,
        room_query="Pantry",
        object_query="counter",
        graph_identity="icra_ic4f/graph_20260629211448",
        graph_root_sha256=GRAPH_ROOT_SHA256,
        dataset_root_sha256=DATASET_ROOT_SHA256,
        checkpoint_sha256=CHECKPOINT_SHA256,
    ),
    graph_identity="icra_ic4f/graph_20260629211448",
    floor_id="0",
    room_id="0_0",
    room_name="Pantry",
    object_id="0_0_81",
    object_name="counter",
    frame_id="map",
    position=(-21.526786203133774, -15.671372634872082, -0.27579107548158116),
    orientation=(0.0, 0.0, 0.0, 1.0),
)


@dataclass(frozen=True)
class GraphCounts:
    floors: int
    rooms: int
    objects: int


@dataclass(frozen=True)
class HMSGSelection:
    graph_identity: str
    floor_id: str
    room_id: str
    room_name: str
    object_id: str
    object_name: str
    scene_center: tuple[float, float, float]


@dataclass(frozen=True)
class SemanticFixtureResult:
    query_text: str
    graph_identity: str
    floor_id: str
    room_id: str
    room_name: str
    object_id: str
    object_name: str
    frame_id: str
    position: tuple[float, float, float]
    orientation: tuple[float, float, float, float]
    structured_query_sha256: str
    graph_root_sha256: str
    dataset_root_sha256: str
    checkpoint_sha256: str
    room_name_mapping_sha256: str
    bypassed_network_seams: tuple[str]
    pinned_fixture_preprocessing: tuple[str]

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": "holoagent0-semantic-result-v1",
            "query_text": self.query_text,
            "graph_identity": self.graph_identity,
            "floor_id": self.floor_id,
            "room": {"id": self.room_id, "name": self.room_name},
            "object": {"id": self.object_id, "name": self.object_name},
            "frame_id": self.frame_id,
            "position": list(self.position),
            "orientation": list(self.orientation),
            "structured_query_sha256": self.structured_query_sha256,
            "graph_root_sha256": self.graph_root_sha256,
            "dataset_root_sha256": self.dataset_root_sha256,
            "checkpoint_sha256": self.checkpoint_sha256,
            "room_name_mapping_sha256": self.room_name_mapping_sha256,
            "bypassed_network_seams": list(self.bypassed_network_seams),
            "pinned_fixture_preprocessing": list(self.pinned_fixture_preprocessing),
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.to_document(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )


class HMSGRetrievalAdapter(Protocol):
    def graph_counts(self) -> GraphCounts: ...

    def retrieve_structured(self, query: StructuredQuery) -> HMSGSelection: ...


def _fixture_failure(detail: str) -> None:
    raise SemanticGateError("SEMANTIC_FIXTURE_MISMATCH", detail)


def evaluate_semantic_fixture(
    adapter: HMSGRetrievalAdapter,
    query: StructuredQuery,
) -> SemanticFixtureResult:
    """Exercise HMSG lookup and the production scene-to-map axis transform.

    Only the external LLM parser is bypassed in the query path. The graph's
    generic room labels receive the reviewed, digest-bound room-name mapping
    as fixture preparation; HMSG room/object retrieval and the reviewed
    coordinate transform remain in the exercised path.
    """
    if query.canonical_json() != EXPECTED_SEMANTIC.query.canonical_json():
        _fixture_failure("received query is not the approved fixture")
    query_digest = hashlib.sha256(query.canonical_json().encode("utf-8")).hexdigest()
    if query_digest != STRUCTURED_QUERY_SHA256:
        _fixture_failure("structured query digest is not pinned")
    counts = adapter.graph_counts()
    if counts != GraphCounts(1, 3, 497):
        _fixture_failure(f"graph counts are {counts!r}")
    selection = adapter.retrieve_structured(query)
    expected_identity = (
        EXPECTED_SEMANTIC.graph_identity,
        EXPECTED_SEMANTIC.floor_id,
        EXPECTED_SEMANTIC.room_id,
        EXPECTED_SEMANTIC.room_name,
        EXPECTED_SEMANTIC.object_id,
        EXPECTED_SEMANTIC.object_name,
    )
    actual_identity = (
        selection.graph_identity,
        selection.floor_id,
        selection.room_id,
        selection.room_name,
        selection.object_id,
        selection.object_name,
    )
    if actual_identity != expected_identity:
        _fixture_failure(f"node identity is {actual_identity!r}")
    if len(selection.scene_center) != 3 or not all(
        math.isfinite(value) for value in selection.scene_center
    ):
        _fixture_failure("scene center is not a finite 3-vector")

    scene_x, scene_y, scene_z = selection.scene_center
    position = (float(scene_x), float(-scene_z), float(scene_y))
    if any(
        not math.isclose(actual, expected, rel_tol=0.0, abs_tol=1e-6)
        for actual, expected in zip(position, EXPECTED_SEMANTIC.position)
    ):
        _fixture_failure(f"map position is {position!r}")
    orientation = EXPECTED_SEMANTIC.orientation
    if not math.isclose(
        sum(value * value for value in orientation), 1.0, rel_tol=0.0, abs_tol=1e-9
    ):
        _fixture_failure("orientation is not normalized")
    return SemanticFixtureResult(
        query_text=query.text,
        graph_identity=selection.graph_identity,
        floor_id=selection.floor_id,
        room_id=selection.room_id,
        room_name=selection.room_name,
        object_id=selection.object_id,
        object_name=selection.object_name,
        frame_id=EXPECTED_SEMANTIC.frame_id,
        position=position,
        orientation=orientation,
        structured_query_sha256=query_digest,
        graph_root_sha256=GRAPH_ROOT_SHA256,
        dataset_root_sha256=DATASET_ROOT_SHA256,
        checkpoint_sha256=CHECKPOINT_SHA256,
        room_name_mapping_sha256=ROOM_NAME_MAPPING_SHA256,
        bypassed_network_seams=("external_llm_parser",),
        pinned_fixture_preprocessing=("room_name_mapping",),
    )


class RealHMSGRetrievalAdapter:
    """Thin adapter around the restored HMSG retrieval methods."""

    def __init__(self, graph: Any, *, graph_identity: str) -> None:
        self._graph = graph
        self._graph_identity = graph_identity

    def graph_counts(self) -> GraphCounts:
        return GraphCounts(
            floors=len(self._graph.floors),
            rooms=len(self._graph.rooms),
            objects=len(self._graph.objects),
        )

    def retrieve_structured(self, query: StructuredQuery) -> HMSGSelection:
        if query.canonical_json() != EXPECTED_SEMANTIC.query.canonical_json():
            _fixture_failure("adapter received an unapproved structured query")
        room_indices = self._graph.query_hmsg_room(
            query.room_query, floor_id=-1, query_method="label"
        )
        if not isinstance(room_indices, (list, tuple)) or len(room_indices) != 1:
            _fixture_failure("room retrieval did not return exactly one room")
        object_result = self._graph.query_hmsg_object(
            query.object_query,
            floor_id=-1,
            room_ids=list(room_indices),
            top_k=1,
            negative_prompt=["background"],
        )
        if not isinstance(object_result, tuple) or len(object_result) < 2:
            _fixture_failure("object retrieval returned an invalid result")
        object_indices, object_room_indices = object_result[:2]
        if len(object_indices) != 1 or len(object_room_indices) != 1:
            _fixture_failure("object retrieval did not return exactly one object")
        room_index = int(room_indices[0])
        if int(object_room_indices[0]) != room_index:
            _fixture_failure("object retrieval returned a different room")
        object_index = int(object_indices[0])
        try:
            room = self._graph.rooms[room_index]
            selected_object = self._graph.objects[object_index]
            raw_center = selected_object.pcd.get_center()
            center = tuple(float(value) for value in raw_center)
        except (AttributeError, IndexError, TypeError, ValueError) as error:
            _fixture_failure(f"retrieved HMSG node is invalid: {error}")
        if len(center) != 3:
            _fixture_failure("object center is not a 3-vector")
        return HMSGSelection(
            graph_identity=self._graph_identity,
            floor_id=str(room.floor_id),
            room_id=str(room.room_id),
            room_name=str(room.name),
            object_id=str(selected_object.object_id),
            object_name=str(selected_object.name),
            scene_center=center,  # type: ignore[arg-type]
        )


def hmsg_query_configuration(
    *, graph_path: Path, checkpoint_path: Path, run_directory: Path
) -> dict[str, Any]:
    """Build the minimal real-Graph query configuration with owned outputs."""
    return {
        "main": {
            "use_gpt": False,
            "graph_path": str(graph_path),
            "save_path": str(run_directory),
        },
        "models": {
            "clip": {
                "type": "ViT-L/14",
                "checkpoint": str(checkpoint_path),
            }
        },
    }


def load_real_hmsg_adapter(
    repository_root: Path,
    asset_source: Path | Mapping[str, Any],
    asset_roots: Mapping[str, Path],
    run_directory: Path,
) -> RealHMSGRetrievalAdapter:
    """Verify assets, then lazily import and load the real HMSG graph."""
    root = Path(repository_root).resolve(strict=True)
    run_root = Path(run_directory)
    try:
        if not run_root.is_absolute():
            raise ValueError("semantic run directory must be absolute")
        run_root = run_root.resolve(strict=True)
        if not run_root.is_dir():
            raise ValueError("semantic run directory is not a directory")
        for value in asset_roots.values():
            asset_root = Path(value).resolve(strict=True)
            if run_root == asset_root or (
                asset_root.is_dir() and run_root.is_relative_to(asset_root)
            ):
                raise ValueError("semantic run directory overlaps an asset root")
        lock = load_asset_lock(asset_source)
        verify_asset_lock(asset_roots, asset_source)
    except (AssetGateError, OSError, ValueError) as error:
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error

    fsr_root = root / "fsr_vln"
    fsr_path = str(fsr_root)
    inserted_path = fsr_path not in sys.path
    if inserted_path:
        sys.path.insert(0, fsr_path)
    try:
        from memory.hmsg.graph import graph as graph_module  # type: ignore[import-not-found]
        from omegaconf import OmegaConf  # type: ignore[import-not-found]

        module_path = Path(graph_module.__file__).resolve(strict=True)
        expected_module_path = (fsr_root / "memory/hmsg/graph/graph.py").resolve(
            strict=True
        )
        if module_path != expected_module_path:
            raise ValueError(f"unexpected HMSG module origin: {module_path}")
        Graph = graph_module.Graph

        graph_path = Path(asset_roots["graph"])
        checkpoint_path = Path(asset_roots["checkpoint"])
        configuration = OmegaConf.create(
            hmsg_query_configuration(
                graph_path=graph_path,
                checkpoint_path=checkpoint_path,
                run_directory=run_root,
            )
        )
        graph = Graph(configuration)
        graph.load_graph(str(graph_path))
        graph.set_room_names(room_names=list(lock.room_name_mapping))
    except Exception as error:
        raise SemanticGateError(
            "SEMANTIC_DEPENDENCY_UNAVAILABLE", str(error)
        ) from error
    finally:
        if inserted_path:
            try:
                sys.path.remove(fsr_path)
            except ValueError:
                pass
    return RealHMSGRetrievalAdapter(graph, graph_identity=lock.graph_identity)


def verify_cyclone_roles(
    repository_root: Path, asset_source: Path | Mapping[str, Any]
) -> CycloneConfigSet:
    """Delegate Cyclone authority to the existing production policy loader."""
    root = Path(repository_root).resolve(strict=True)
    try:
        lock = load_asset_lock(asset_source)
        contract = load_pinned_cyclone_configs(
            root / "scripts/holoagent0_setup/config", repository_root=root
        )
        locked_descriptors = tuple(
            (
                config.role,
                config.participant_index,
                config.relative_path,
                config.sha256,
            )
            for config in lock.cyclone_configs
        )
        measured_descriptors = tuple(
            (
                config.role,
                config.participant_index,
                config.repository_relative_path,
                config.sha256,
            )
            for config in contract.configs
        )
        if (
            lock.cyclone_config_set_sha256 != contract.aggregate_sha256
            or locked_descriptors != measured_descriptors
        ):
            raise ValueError("asset lock and Cyclone policy disagree")
        return contract
    except (AssetGateError, CycloneConfigError, OSError, ValueError) as error:
        raise SemanticGateError("CYCLONE_CONFIG_MISMATCH", str(error)) from error


def validate_fixture_runtime_environment(
    contract: CycloneConfigSet, environment: Mapping[str, str]
) -> None:
    """Bind the fixture process to participant zero before ROS initialization."""
    fixture = next(
        (config for config in contract.configs if config.role == "fixture"), None
    )
    expected = {
        "RMW_IMPLEMENTATION": "rmw_cyclonedds_cpp",
        "ROS_DOMAIN_ID": str(contract.domain_id),
        "ROS_LOCALHOST_ONLY": "1",
        "CYCLONEDDS_URI": None if fixture is None else fixture.uri,
    }
    if fixture is None or any(
        environment.get(key) != value for key, value in expected.items()
    ):
        raise SemanticGateError(
            "CYCLONE_CONFIG_MISMATCH",
            "fixture runtime environment is not bound to participant zero",
        )


@dataclass(frozen=True)
class TopicCardinality:
    type_name: str
    publishers: int
    subscribers: int


@dataclass(frozen=True)
class GraphSnapshot:
    scope: str
    nodes: tuple[str, ...]
    topics: Mapping[str, TopicCardinality]

    def canonical_json(self) -> str:
        document = {
            "schema_version": "holoagent0-semantic-graph-snapshot-v1",
            "scope": self.scope,
            "nodes": list(self.nodes),
            "topics": [
                {
                    "name": name,
                    "type_name": cardinality.type_name,
                    "publishers": cardinality.publishers,
                    "subscribers": cardinality.subscribers,
                }
                for name, cardinality in sorted(self.topics.items())
            ],
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )

    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


EXPECTED_ROS_NODES = tuple(
    sorted(
        (
            "/holoagent0_semantic_fixture",
            "/holoagent0_semantic_graph_inspector",
            "/holoagent0_semantic_query_publisher",
            "/holoagent0_semantic_result_subscriber",
        )
    )
)


def validate_ros_graph(snapshot: GraphSnapshot, *, capture_active: bool) -> None:
    """Validate an application-filtered snapshot; infrastructure is out of scope."""
    if snapshot.scope != "holoagent0-semantic-application-v1":
        raise SemanticGateError("ROS_GRAPH_MISMATCH", "snapshot scope is not exact")
    if snapshot.nodes != EXPECTED_ROS_NODES:
        raise SemanticGateError("ROS_GRAPH_MISMATCH", "node set is not exact")
    if any("nav2" in node.lower() for node in snapshot.nodes):
        raise SemanticGateError("ROS_GRAPH_MISMATCH", "Nav2 node observed")
    if "/cmd_vel" in snapshot.topics:
        raise SemanticGateError("ROS_GRAPH_MISMATCH", "/cmd_vel endpoint observed")
    expected = {
        "/holoagent0/semantic_fixture_query": TopicCardinality(
            "std_msgs/msg/String", publishers=1, subscribers=1
        ),
        "/object_pose": TopicCardinality(
            "geometry_msgs/msg/PoseStamped",
            publishers=1,
            subscribers=1 if capture_active else 0,
        ),
    }
    if dict(snapshot.topics) != expected:
        raise SemanticGateError("ROS_GRAPH_MISMATCH", "topic cardinality is not exact")
