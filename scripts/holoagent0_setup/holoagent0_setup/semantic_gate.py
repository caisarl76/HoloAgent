"""Exact, fail-closed semantic fixture contracts with lazy heavy dependencies."""

from __future__ import annotations

import builtins
from dataclasses import dataclass
import hashlib
import importlib
import importlib.machinery
import json
import math
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Mapping, Protocol

from .cyclone_policy import (
    CONFIG_SET_SHA256,
    CycloneConfigError,
    CycloneConfigSet,
    load_pinned_cyclone_configs,
)
from .source_gate import (
    AssetGateError,
    HandoverAssetUseAuthority,
    HandoverPaths,
    HandoverRunDirectoryAuthority,
    load_asset_lock,
    open_handover_asset_use,
    open_handover_run_directory,
    prepare_handover_run_directory,
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
FORBIDDEN_RUNTIME_MODULE_PREFIXES = (
    "rclpy",
    "nav2",
    "agentos",
    "agentic_robot",
    "unitree",
    "unitree_sdk2py",
)
_GRAPH_LLM_SEAMS = (
    "create_llm_client",
    "create_chat_completion",
    "get_llm_model",
    "parse_hier_query",
    "parse_hier_query_use_prompt_insentence_parse",
    "parse_hier_query_use_prompt_insentence_parse_icra",
    "parse_floor_room_object_gpt35",
    "infer_floor_id_from_query",
)
_LLM_UTILS_SEAMS = (
    *_GRAPH_LLM_SEAMS,
    "parse_floor_room_object_gpt40",
    "infer_room_type_from_object_list_chat",
)
_LLM_UTILS_MODULE_ATTRIBUTE = "_holoagent0_llm_utils_module"


class SemanticGateError(RuntimeError):
    """The exact semantic fixture or its isolation contract failed."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}")


class RuntimeImportAudit:
    """Record every requested import even when the module cache is restored."""

    def __init__(self) -> None:
        self._requested: set[str] = set()
        self._original_builtin_import = None
        self._original_import_module = None

    def __enter__(self) -> "RuntimeImportAudit":
        original_builtin_import = builtins.__import__
        original_import_module = importlib.import_module
        self._original_builtin_import = original_builtin_import
        self._original_import_module = original_import_module

        def audited_builtin_import(
            name, globals=None, locals=None, fromlist=(), level=0
        ):
            if isinstance(name, str):
                self._requested.add(name)
            return original_builtin_import(name, globals, locals, fromlist, level)

        def audited_import_module(name, package=None):
            if isinstance(name, str):
                self._requested.add(name)
            if package is None:
                return original_import_module(name)
            return original_import_module(name, package)

        builtins.__import__ = audited_builtin_import
        importlib.import_module = audited_import_module
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._original_builtin_import is not None:
            builtins.__import__ = self._original_builtin_import
            self._original_builtin_import = None
        if self._original_import_module is not None:
            importlib.import_module = self._original_import_module
            self._original_import_module = None

    def require_allowed(self) -> None:
        forbidden = sorted(
            name
            for name in self._requested
            if name.startswith(FORBIDDEN_RUNTIME_MODULE_PREFIXES)
        )
        if forbidden:
            raise SemanticGateError(
                "FORBIDDEN_RUNTIME_MODULE",
                forbidden[0],
            )


_ImportBoundaryAudit = RuntimeImportAudit


class _ExternalLLMGuard:
    """Keep every networked or natural-language LLM seam fail-closed."""

    def __init__(self, graph_module: Any, llm_utils_module: Any) -> None:
        self._bindings: list[tuple[Any, str, Any, Any]] = []
        try:
            self._guard(graph_module, _GRAPH_LLM_SEAMS)
            self._guard(llm_utils_module, _LLM_UTILS_SEAMS)
        except Exception:
            self._restore()
            raise

    def _guard(self, owner: Any, names: tuple[str, ...]) -> None:
        for name in names:
            original = getattr(owner, name, None)
            if not callable(original):
                raise SemanticGateError(
                    "SEMANTIC_DEPENDENCY_UNAVAILABLE",
                    f"required external LLM seam is absent: {name}",
                )

            def reject(*_args, _name=name, **_kwargs):
                raise SemanticGateError(
                    "SEMANTIC_EXTERNAL_LLM_ATTEMPT",
                    _name,
                )

            setattr(owner, name, reject)
            self._bindings.append((owner, name, original, reject))

    def _restore(self) -> tuple[str, ...]:
        changed: list[str] = []
        for owner, name, original, guard in reversed(self._bindings):
            if getattr(owner, name, None) is not guard:
                changed.append(name)
            setattr(owner, name, original)
        self._bindings.clear()
        return tuple(sorted(set(changed)))

    def close(self) -> None:
        changed = self._restore()
        if changed:
            raise SemanticGateError(
                "SEMANTIC_EXTERNAL_LLM_ATTEMPT",
                f"guarded seam binding changed: {', '.join(changed)}",
            )


def _guard_external_llm_seams(graph_module: Any) -> _ExternalLLMGuard | None:
    llm_utils_module = getattr(graph_module, _LLM_UTILS_MODULE_ATTRIBUTE, None)
    has_graph_seam = any(hasattr(graph_module, name) for name in _GRAPH_LLM_SEAMS)
    if llm_utils_module is None and not has_graph_seam:
        return None
    if llm_utils_module is None:
        raise SemanticGateError(
            "SEMANTIC_DEPENDENCY_UNAVAILABLE",
            "Graph LLM bindings have no retained llm_utils module",
        )
    return _ExternalLLMGuard(graph_module, llm_utils_module)


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

    def __init__(
        self,
        graph: Any,
        *,
        graph_identity: str,
        run_authority: HandoverRunDirectoryAuthority | None = None,
        llm_guard: _ExternalLLMGuard | None = None,
        import_audit: RuntimeImportAudit | None = None,
    ) -> None:
        self._graph = graph
        self._graph_identity = graph_identity
        self._run_authority = run_authority
        self._llm_guard = llm_guard
        self._import_audit = import_audit
        self._closed = False

    def _revalidate_run_authority(self) -> None:
        if self._closed:
            raise SemanticGateError(
                "SEMANTIC_ASSET_UNAVAILABLE", "HMSG adapter is closed"
            )
        if self._run_authority is None:
            return
        try:
            self._run_authority.revalidate()
        except AssetGateError as error:
            raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error

    def close(self) -> None:
        active_exception = sys.exc_info()[0] is not None
        self._closed = True
        guard = self._llm_guard
        self._llm_guard = None
        authority = self._run_authority
        self._run_authority = None
        audit = self._import_audit
        self._import_audit = None
        try:
            try:
                if guard is not None:
                    guard.close()
            finally:
                if authority is not None:
                    authority.close()
        except BaseException:
            if audit is not None:
                audit.close()
            raise
        else:
            if audit is not None:
                try:
                    if not active_exception:
                        audit.require_allowed()
                finally:
                    audit.close()

    def __enter__(self) -> "RealHMSGRetrievalAdapter":
        self._revalidate_run_authority()
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def graph_counts(self) -> GraphCounts:
        self._revalidate_run_authority()
        try:
            counts = GraphCounts(
                floors=len(self._graph.floors),
                rooms=len(self._graph.rooms),
                objects=len(self._graph.objects),
            )
        finally:
            self._revalidate_run_authority()
        if self._import_audit is not None:
            self._import_audit.require_allowed()
        return counts

    def retrieve_structured(self, query: StructuredQuery) -> HMSGSelection:
        self._revalidate_run_authority()
        try:
            selection = self._retrieve_structured(query)
        finally:
            self._revalidate_run_authority()
        if self._import_audit is not None:
            self._import_audit.require_allowed()
        return selection

    def _retrieve_structured(self, query: StructuredQuery) -> HMSGSelection:
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
    paths: HandoverPaths,
    asset_authority: HandoverAssetUseAuthority,
    run_authority: HandoverRunDirectoryAuthority,
) -> dict[str, Any]:
    """Build the minimal real-Graph query configuration with owned outputs."""
    if (
        not isinstance(paths, HandoverPaths)
        or not isinstance(asset_authority, HandoverAssetUseAuthority)
        or not isinstance(run_authority, HandoverRunDirectoryAuthority)
    ):
        raise AssetGateError(
            "ASSET_ROOT_MISMATCH",
            "validated handover and retained descriptor authorities are required",
        )
    return {
        "main": {
            "use_gpt": False,
            "graph_path": str(asset_authority.descriptor_path("graph")),
            "save_path": str(run_authority.descriptor_path),
        },
        "models": {
            "clip": {
                "type": "ViT-L/14",
                "checkpoint": str(asset_authority.descriptor_path("checkpoint")),
            }
        },
    }


def _validate_root_namespace_module(
    name: str, module: Any, namespace_root: Path
) -> None:
    specification = getattr(module, "__spec__", None)
    origin = getattr(specification, "origin", None)
    if origin not in {None, "namespace"}:
        if not isinstance(origin, str):
            raise ValueError(f"unexpected {name} module origin: {origin!r}")
        resolved = Path(origin)
        if not resolved.is_absolute():
            raise ValueError(f"unexpected {name} module origin: {origin}")
        resolved = resolved.resolve(strict=True)
        if namespace_root not in resolved.parents:
            raise ValueError(f"unexpected {name} module origin: {resolved}")
        return
    locations = getattr(specification, "submodule_search_locations", None)
    if locations is None:
        locations = getattr(module, "__path__", None)
    if locations is None:
        raise ValueError(f"namespace module {name} has no search locations")
    resolved_locations = tuple(
        Path(location).resolve(strict=True) for location in locations
    )
    if not resolved_locations or any(
        location != namespace_root and namespace_root not in location.parents
        for location in resolved_locations
    ):
        raise ValueError(
            f"unexpected {name} namespace locations: {resolved_locations!r}"
        )


def _module_filesystem_origins(module: Any) -> tuple[Path, ...]:
    specification = getattr(module, "__spec__", None)
    candidates = (
        getattr(specification, "origin", None),
        getattr(module, "__file__", None),
    )
    origins: list[Path] = []
    for candidate in candidates:
        if candidate in {None, "built-in", "frozen", "namespace"}:
            continue
        if not isinstance(candidate, str):
            continue
        origin = Path(candidate)
        if not origin.is_absolute():
            continue
        resolved = origin.resolve(strict=False)
        if resolved not in origins:
            origins.append(resolved)
    return tuple(origins)


def _path_is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _environment_import_path_allowed(entry: Any, fsr_root: Path) -> bool:
    if not isinstance(entry, str):
        return False
    try:
        resolved = Path(entry or ".").resolve(strict=True)
    except FileNotFoundError:
        try:
            resolved = Path(entry or ".").resolve(strict=False)
        except (OSError, RuntimeError):
            return False
    except (OSError, RuntimeError):
        return False
    return not _path_is_within(resolved, fsr_root)


def import_root_hmsg_runtime(
    paths: HandoverPaths,
) -> tuple[Any, Any, Path]:
    """Lazily import HMSG only from the retained root-level FSR-VLN tree."""
    try:
        if not isinstance(paths, HandoverPaths):
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH",
                "a validated HandoverPaths instance is required",
            )
        paths.revalidate()
    except AssetGateError as error:
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error

    fsr_root = paths.repository_root / "fsr_vln"
    namespace_roots = {
        "memory": fsr_root / "memory",
        "perception": fsr_root / "perception",
    }
    expected_module_path = fsr_root / "memory/hmsg/graph/graph.py"
    original_sys_path = list(sys.path)
    original_sys_modules = dict(sys.modules)
    original_repository_modules = {
        name: module
        for name, module in sys.modules.items()
        if any(
            name == namespace or name.startswith(f"{namespace}.")
            for namespace in namespace_roots
        )
    }
    try:
        for name in tuple(original_repository_modules):
            sys.modules.pop(name, None)
        for namespace, namespace_root in namespace_roots.items():
            namespace_module = ModuleType(namespace)
            namespace_specification = importlib.machinery.ModuleSpec(
                namespace, loader=None, is_package=True
            )
            namespace_specification.submodule_search_locations = [str(namespace_root)]
            namespace_module.__spec__ = namespace_specification
            namespace_module.__path__ = [str(namespace_root)]
            namespace_module.__package__ = namespace
            sys.modules[namespace] = namespace_module
        paths.revalidate()
        try:
            fsr_resolved = fsr_root.resolve(strict=True)
        except OSError as error:
            raise AssetGateError(
                "HANDOVER_PATH_IDENTITY_CHANGED",
                f"repository-local HMSG source root: {error}",
            ) from error
        cached_local_omega = {
            name
            for name, module in sys.modules.items()
            if (name == "omegaconf" or name.startswith("omegaconf."))
            and any(
                _path_is_within(origin, fsr_resolved)
                for origin in _module_filesystem_origins(module)
            )
        }
        if "omegaconf" in cached_local_omega:
            cached_local_omega = {
                name
                for name in sys.modules
                if name == "omegaconf" or name.startswith("omegaconf.")
            }
        for name in cached_local_omega:
            sys.modules.pop(name, None)
        sys.path[:] = [
            entry
            for entry in sys.path
            if _environment_import_path_allowed(entry, fsr_resolved)
        ]
        audit = RuntimeImportAudit()
        with audit:
            graph_module = importlib.import_module("memory.hmsg.graph.graph")
            omega_module = importlib.import_module("omegaconf")
        audit.require_allowed()
        omega_origins = _module_filesystem_origins(omega_module)
        if not omega_origins:
            raise ValueError("OmegaConf module has no filesystem origin")
        if any(_path_is_within(origin, fsr_resolved) for origin in omega_origins):
            raise ValueError(f"unexpected OmegaConf module origin: {omega_origins!r}")
        OmegaConf = omega_module.OmegaConf
        specification = getattr(graph_module, "__spec__", None)
        raw_origin = getattr(specification, "origin", None) or getattr(
            graph_module, "__file__", None
        )
        if not isinstance(raw_origin, str):
            raise ValueError("HMSG module has no filesystem origin")
        module_path = Path(raw_origin)
        if not module_path.is_absolute():
            raise ValueError(f"unexpected HMSG module origin: {raw_origin}")
        module_path = module_path.resolve(strict=True)
        expected_resolved = expected_module_path.resolve(strict=True)
        if (
            expected_resolved != expected_module_path
            or module_path != expected_module_path
        ):
            raise ValueError(f"unexpected HMSG module origin: {module_path}")
        for namespace, namespace_root in namespace_roots.items():
            for name, module in tuple(sys.modules.items()):
                if name == namespace or name.startswith(f"{namespace}."):
                    _validate_root_namespace_module(name, module, namespace_root)
        llm_utils_module = sys.modules.get("memory.hmsg.utils.llm_utils")
        if llm_utils_module is not None:
            setattr(
                graph_module,
                _LLM_UTILS_MODULE_ATTRIBUTE,
                llm_utils_module,
            )
        return graph_module, OmegaConf, module_path
    except AssetGateError as error:
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error
    except SemanticGateError:
        raise
    except Exception as error:
        raise SemanticGateError(
            "SEMANTIC_DEPENDENCY_UNAVAILABLE", str(error)
        ) from error
    finally:
        for name in tuple(sys.modules):
            if name not in original_sys_modules:
                sys.modules.pop(name, None)
        for name, module in original_sys_modules.items():
            sys.modules[name] = module
        sys.path[:] = original_sys_path


def load_real_hmsg_adapter(
    paths: HandoverPaths, run_directory: Path
) -> RealHMSGRetrievalAdapter:
    """Verify retained authority, then load the root-level real HMSG graph."""
    try:
        if not isinstance(paths, HandoverPaths):
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH",
                "a validated HandoverPaths instance is required",
            )
        paths.revalidate()
        run_identity = prepare_handover_run_directory(run_directory, paths)
        paths.revalidate()
        verification = verify_asset_lock(paths)
    except (AssetGateError, OSError, ValueError) as error:
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error

    import_audit = RuntimeImportAudit()
    import_audit.__enter__()
    llm_guard: _ExternalLLMGuard | None = None
    run_authority: HandoverRunDirectoryAuthority | None = None

    def close_loading_resources() -> None:
        try:
            if llm_guard is not None:
                llm_guard.close()
        finally:
            try:
                if run_authority is not None:
                    run_authority.close()
            finally:
                import_audit.close()

    try:
        graph_module, OmegaConf, _module_origin = import_root_hmsg_runtime(paths)
        import_audit.require_allowed()
        llm_guard = _guard_external_llm_seams(graph_module)
        import_audit.require_allowed()
        paths.revalidate()
        run_authority = open_handover_run_directory(paths, run_identity)
        with open_handover_asset_use(paths, verification) as asset_authority:
            configuration = OmegaConf.create(
                hmsg_query_configuration(
                    paths,
                    asset_authority,
                    run_authority,
                )
            )
            graph = graph_module.Graph(configuration)
            import_audit.require_allowed()
            run_authority.revalidate()
            asset_authority.revalidate()
            graph.load_graph(str(asset_authority.descriptor_path("graph")))
            import_audit.require_allowed()
            run_authority.revalidate()
            asset_authority.revalidate()
            graph.set_room_names(room_names=list(verification.lock.room_name_mapping))
            import_audit.require_allowed()
    except SemanticGateError:
        close_loading_resources()
        raise
    except AssetGateError as error:
        close_loading_resources()
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error
    except (AttributeError, ImportError, RuntimeError, ValueError) as error:
        close_loading_resources()
        raise SemanticGateError(
            "SEMANTIC_DEPENDENCY_UNAVAILABLE", str(error)
        ) from error
    except BaseException:
        close_loading_resources()
        raise
    return RealHMSGRetrievalAdapter(
        graph,
        graph_identity=verification.lock.graph_identity,
        run_authority=run_authority,
        llm_guard=llm_guard,
        import_audit=import_audit,
    )


def verify_cyclone_roles(paths: HandoverPaths) -> CycloneConfigSet:
    """Delegate Cyclone authority to the existing production policy loader."""
    try:
        if not isinstance(paths, HandoverPaths):
            raise AssetGateError(
                "ASSET_ROOT_MISMATCH",
                "a validated HandoverPaths instance is required",
            )
        paths.revalidate()
        lock = load_asset_lock(paths)
        paths.revalidate()
        contract = load_pinned_cyclone_configs(
            paths.repository_root / "scripts/holoagent0_setup/config",
            repository_root=paths.repository_root,
        )
        paths.revalidate()
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
    except AssetGateError as error:
        raise SemanticGateError("SEMANTIC_ASSET_UNAVAILABLE", str(error)) from error
    except (CycloneConfigError, OSError, ValueError) as error:
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
