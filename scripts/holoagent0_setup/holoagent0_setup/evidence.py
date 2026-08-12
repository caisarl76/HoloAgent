"""Stable, retained Task 8 evidence artifacts and bounded redaction.

This module owns the file-descriptor side of the offline evidence boundary.  A
caller may describe artifacts, but only a :class:`EvidenceBinder` derives the
identity, digest, size, and record count that become authoritative evidence.
"""

from __future__ import annotations

import copy
import base64
import binascii
import ctypes
from dataclasses import dataclass, field, replace
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock
from types import MappingProxyType
from typing import Iterable, Mapping
from urllib.parse import unquote, unquote_plus

from .atomic_io import (
    ArtifactDescriptor,
    AtomicIOError,
    atomic_write_json_no_replace,
    canonical_json_bytes,
)
from .cyclone_policy import CONFIG_ROLES, EXPECTED_CONFIG_SHA256
from .contract import ContractSet
from .ledger import (
    LedgerCandidate,
    LedgerChainError,
    LedgerHead,
    LedgerStore,
    _build_generation_zero,
)
from .process_identity import ProcessIdentity, ProcessIdentityError
from .trace_policy import PolicyViolation, TracePolicy


REQUIRED_OFFLINE_ARTIFACTS = (
    "trace",
    "bootstrap_report",
    "ledger_chain_manifest",
    "ownership_journal",
    "violation_journal",
    "host_observer_pre",
    "host_observer_post",
)
_CREDENTIAL_MARKERS = (
    "API_KEY",
    "AUTH",
    "CREDENTIAL",
    "ENDPOINT",
    "PASSWORD",
    "SECRET",
    "TOKEN",
)
_PROXY_VARIABLES = frozenset({"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"})
_MAX_JOURNAL_RECORD_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
_SIGNALS = ("HUP", "INT", "TERM")
_BOOTSTRAP_TERMINAL_STATES = frozenset(
    {
        "COORDINATOR_LAUNCH_COMMITTED",
        "PRE_COORDINATOR_INTERRUPTED",
        "FINALIZER_ONLY_BOOTSTRAP_FAILURE",
        "NOT_STARTED_BOOTSTRAP_FAILURE",
    }
)
_HANDOFF_STATES = frozenset(
    {
        "NOT_APPLICABLE",
        "AWAITING_READY",
        "AWAITING_ACCEPTANCE",
        "PENDING_FORWARD",
        "READY",
        "FAILED",
    }
)
_MAX_OBSERVER_ITEMS = 4096
_MAX_OBSERVER_ITEM_BYTES = 16 * 1024
_MFD_CLOEXEC = 0x0001
_MFD_ALLOW_SEALING = 0x0002
_F_ADD_SEALS = 1033
_F_GET_SEALS = 1034
_F_SEAL_SEAL = 0x0001
_F_SEAL_SHRINK = 0x0002
_F_SEAL_GROW = 0x0004
_F_SEAL_WRITE = 0x0008
_REQUIRED_MEMFD_SEALS = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE


class ArtifactBindingError(RuntimeError):
    """An evidence artifact could not be created or bound without ambiguity."""


_HOST_OBSERVER_RECEIPT_AUTHORITY = object()


@dataclass(frozen=True)
class JournalReceipt:
    index: int
    previous_digest: str | None
    record_sha256: str


@dataclass(frozen=True)
class BoundArtifact:
    relative_path: str
    sha256: str
    size: int
    record_count: int
    inode: int
    device: int
    mode: int
    result_fields: Mapping[str, object] = field(
        default_factory=lambda: MappingProxyType({}), compare=True
    )

    def as_result_json(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size": self.size,
            **copy.deepcopy(dict(self.result_fields)),
        }

    def as_binding_json(self) -> dict[str, object]:
        return {
            **self.as_result_json(),
            "record_count": self.record_count,
            "inode": self.inode,
            "device": self.device,
            "mode": self.mode,
        }


class HostObserverArtifactReceipt:
    """Opaque writer-local acknowledgement; never supervisor authority."""

    __slots__ = ("_artifact", "_authority", "_fd")

    def __init__(
        self,
        artifact: BoundArtifact,
        authority: object,
        fd: int,
    ) -> None:
        if authority is not _HOST_OBSERVER_RECEIPT_AUTHORITY:
            raise ArtifactBindingError("host observer receipt authority is invalid")
        if type(fd) is not int or fd < 0:
            raise ArtifactBindingError("host observer receipt descriptor is invalid")
        self._artifact = artifact
        self._authority = authority
        self._fd = fd

    @property
    def relative_path(self) -> str:
        return self._artifact.relative_path

    @property
    def record_count(self) -> int:
        return self._artifact.record_count

    def close(self) -> None:
        """Release an unused receipt without weakening any persisted artifact."""

        _close_no_throw(getattr(self, "_fd", -1))
        self._fd = -1

    def __del__(self) -> None:
        self.close()


@dataclass(frozen=True)
class ArtifactRequirement:
    path: Path
    expected_mode: int = 0o400

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise ArtifactBindingError("artifact path must be a pathlib.Path")
        if type(self.expected_mode) is not int or self.expected_mode not in {
            0o400,
            0o600,
        }:
            raise ArtifactBindingError("artifact expected mode is not reviewed")


@dataclass(frozen=True)
class TraceRuntimeEvidence:
    """Supervisor-observed identities and exits for one closed trace stream."""

    trace_state: str
    tracer_identity: ProcessIdentity | None
    normalizer_identity: ProcessIdentity | None
    tracer_exit_code: int | None
    normalizer_exit_code: int | None
    tool_policy_row_sha256: str | None
    compatibility_fixture_passed: bool | None
    not_started_reason: str | None

    def __post_init__(self) -> None:
        if self.trace_state not in {"FULL", "FINALIZER_ONLY", "NOT_STARTED"}:
            raise ArtifactBindingError("trace state is invalid")
        for identity in (self.tracer_identity, self.normalizer_identity):
            if identity is not None and type(identity) is not ProcessIdentity:
                raise ArtifactBindingError("trace process identity is invalid")
        for exit_code in (self.tracer_exit_code, self.normalizer_exit_code):
            if exit_code is not None and (
                type(exit_code) is not int or not 0 <= exit_code <= 255
            ):
                raise ArtifactBindingError("trace process exit is invalid")
        digest = self.tool_policy_row_sha256
        if digest is not None and not _is_sha256(digest):
            raise ArtifactBindingError("trace tool-policy digest is invalid")
        if (
            self.compatibility_fixture_passed is not None
            and type(self.compatibility_fixture_passed) is not bool
        ):
            raise ArtifactBindingError("trace fixture result is invalid")


@dataclass(frozen=True)
class TracePolicyReplayEvidence:
    """Immutable launch facts required to replay the canonical trace policy."""

    coordinator_pid: int
    participants: Mapping[int, Mapping[str, object]]
    namespace_loopback_only: bool
    initial_fd_manifest: Mapping[int, object]

    def __post_init__(self) -> None:
        if type(self.coordinator_pid) is not int or self.coordinator_pid <= 0:
            raise ArtifactBindingError("trace-policy coordinator PID is invalid")
        if self.namespace_loopback_only is not True:
            raise ArtifactBindingError("trace-policy namespace boundary is invalid")
        if not isinstance(self.participants, Mapping):
            raise ArtifactBindingError("trace-policy participants are invalid")
        participants: dict[int, Mapping[str, object]] = {}
        indexes: set[int] = set()
        for pid, raw in self.participants.items():
            if (
                type(pid) is not int
                or pid <= 0
                or not isinstance(raw, Mapping)
                or set(raw) != {"index", "config_digest"}
            ):
                raise ArtifactBindingError("trace-policy participant is invalid")
            index = raw["index"]
            digest = raw["config_digest"]
            if (
                type(index) is not int
                or index not in EXPECTED_CONFIG_SHA256
                or digest != EXPECTED_CONFIG_SHA256[index]
                or index in indexes
            ):
                raise ArtifactBindingError("trace-policy participant pin is invalid")
            indexes.add(index)
            participants[pid] = MappingProxyType(
                {"index": index, "config_digest": digest}
            )
        if indexes and indexes != set(EXPECTED_CONFIG_SHA256):
            raise ArtifactBindingError("trace-policy participant set is incomplete")
        if not isinstance(self.initial_fd_manifest, Mapping) or set(
            self.initial_fd_manifest
        ) != {self.coordinator_pid}:
            raise ArtifactBindingError("trace-policy initial FD manifest is invalid")
        raw_entries = self.initial_fd_manifest[self.coordinator_pid]
        if not isinstance(raw_entries, (list, tuple)):
            raise ArtifactBindingError("trace-policy initial FD manifest is invalid")
        entries: list[Mapping[str, object]] = []
        seen_fds: set[int] = set()
        for raw in raw_entries:
            if (
                not isinstance(raw, Mapping)
                or not {"fd", "kind", "cloexec"}.issubset(raw)
                or set(raw) - {"fd", "kind", "inode", "cloexec"}
            ):
                raise ArtifactBindingError("trace-policy initial FD entry is invalid")
            fd = raw["fd"]
            if type(fd) is not int or fd < 0 or fd in seen_fds:
                raise ArtifactBindingError("trace-policy initial FD entry is invalid")
            seen_fds.add(fd)
            entries.append(MappingProxyType(copy.deepcopy(dict(raw))))
        object.__setattr__(self, "participants", MappingProxyType(participants))
        object.__setattr__(
            self,
            "initial_fd_manifest",
            MappingProxyType({self.coordinator_pid: tuple(entries)}),
        )


@dataclass(frozen=True)
class EvidenceContext:
    """Closed domain inputs required to independently derive offline evidence."""

    trace: TraceRuntimeEvidence
    ledger_contract: ContractSet
    expected_run_id: str
    expected_ledger_nonce: str
    marker_token: str
    expected_host_observer_identity: ProcessIdentity
    trace_policy_replay: TracePolicyReplayEvidence | None = None
    log_paths: tuple[Path, ...] = ()
    tracked_paths: tuple[Path, ...] = ()
    tracked_symlinks: tuple[tuple[Path, str], ...] = ()
    publication_paths: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if type(self.trace) is not TraceRuntimeEvidence:
            raise ArtifactBindingError("trace evidence context is invalid")
        if self.trace.trace_state == "NOT_STARTED":
            if self.trace_policy_replay is not None:
                raise ArtifactBindingError(
                    "NOT_STARTED trace cannot have trace-policy replay evidence"
                )
        elif type(self.trace_policy_replay) is not TracePolicyReplayEvidence:
            raise ArtifactBindingError(
                "started trace requires trace-policy replay evidence"
            )
        elif (
            self.trace.trace_state == "FULL"
            and not self.trace_policy_replay.participants
        ):
            raise ArtifactBindingError("FULL trace requires pinned DDS participants")
        elif (
            self.trace.trace_state == "FINALIZER_ONLY"
            and self.trace_policy_replay.participants
        ):
            raise ArtifactBindingError(
                "FINALIZER_ONLY trace cannot authorize DDS participants"
            )
        if not isinstance(self.ledger_contract, ContractSet):
            raise ArtifactBindingError("ledger contract is invalid")
        if type(self.expected_run_id) is not str or not self.expected_run_id:
            raise ArtifactBindingError("expected ledger run ID is invalid")
        if not _is_sha256(self.expected_ledger_nonce):
            raise ArtifactBindingError("expected ledger nonce is invalid")
        if (
            type(self.marker_token) is not str
            or not self.marker_token
            or len(self.marker_token) > 256
        ):
            raise ArtifactBindingError("trace marker token is invalid")
        if type(self.expected_host_observer_identity) is not ProcessIdentity:
            raise ArtifactBindingError("host observer identity is invalid")
        for collection in (
            self.log_paths,
            self.tracked_paths,
            self.publication_paths,
        ):
            if type(collection) is not tuple or any(
                not isinstance(path, Path) for path in collection
            ):
                raise ArtifactBindingError("secret scan path inventory is invalid")
        if type(self.tracked_symlinks) is not tuple or any(
            type(row) is not tuple
            or len(row) != 2
            or not isinstance(row[0], Path)
            or type(row[1]) is not str
            or len(row[1]) != 40
            for row in self.tracked_symlinks
        ):
            raise ArtifactBindingError("tracked symlink inventory is invalid")


@dataclass(frozen=True)
class PublicationFreeze:
    """Opaque proof that the retained bundle passed a final publication check."""

    bundle_sha256: str
    retained_fd_count: int
    snapshot_sha256: str
    snapshot_fd_count: int
    _sequence: int


@dataclass(frozen=True)
class EvidenceBundle:
    artifacts: Mapping[str, BoundArtifact]
    bundle_sha256: str
    semantic_dds_window: str
    dds_begin_record_index: int | None
    dds_end_record_index: int | None
    marker_token: str

    def as_result_artifacts(self) -> dict[str, dict[str, object]]:
        return {
            name: artifact.as_result_json() for name, artifact in self.artifacts.items()
        }

    def as_result_evidence(self) -> dict[str, object]:
        return {
            **self.as_result_artifacts(),
            "semantic_dds_window": self.semantic_dds_window,
            "dds_begin_record_index": self.dds_begin_record_index,
            "dds_end_record_index": self.dds_end_record_index,
            "marker_token": self.marker_token,
            "bundle_sha256": self.bundle_sha256,
        }


class AppendOnlyJournal:
    """One owned, hash-chained NDJSON journal sealed read-only at closure."""

    def __init__(
        self,
        path: Path,
        relative_to: Path,
        fd: int,
        allowed_kinds: frozenset[str] | None,
        secret_sentinels: frozenset[str],
    ) -> None:
        self._path = path
        self._relative_to = relative_to
        self._fd = fd
        self._allowed_kinds = allowed_kinds
        self._secret_sentinels = secret_sentinels
        self._next_index = 0
        self._previous_digest: str | None = None
        self._stream_digest = hashlib.sha256()
        self._stream_size = 0
        self._sealed = False
        self._lock = RLock()

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        relative_to: Path,
        allowed_kinds: Iterable[str] | None = None,
        secret_sentinels: Iterable[str] = (),
    ) -> "AppendOnlyJournal":
        path = Path(path)
        root = _closed_root(Path(relative_to))
        _require_lexical_child(path, root)
        if path.is_symlink():
            raise ArtifactBindingError("journal path is a symlink")
        kinds = None
        if allowed_kinds is not None:
            kinds = frozenset(allowed_kinds)
            if not kinds or any(type(kind) is not str or not kind for kind in kinds):
                raise ArtifactBindingError("journal kind allowlist is invalid")
        sentinels = frozenset(secret_sentinels)
        if any(type(value) is not str or not value for value in sentinels):
            raise ArtifactBindingError("secret sentinel set is invalid")
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(path, flags, 0o600)
            file_stat = os.fstat(fd)
            _require_file_stat(file_stat, 0o600)
            os.fsync(fd)
            _fsync_directory(path.parent)
        except OSError as error:
            raise ArtifactBindingError("journal creation failed") from error
        return cls(path, root, fd, kinds, sentinels)

    def append(self, kind: str, payload: Mapping[str, object]) -> JournalReceipt:
        with self._lock:
            if self._sealed or self._fd < 0:
                raise ArtifactBindingError("journal is sealed")
            if type(kind) is not str or not kind:
                raise ArtifactBindingError("journal record kind is invalid")
            if self._allowed_kinds is not None and kind not in self._allowed_kinds:
                raise ArtifactBindingError("journal record kind is not allowed")
            if type(payload) is not dict:
                raise ArtifactBindingError("journal payload must be an exact object")
            if _contains_any_secret(payload, self._secret_sentinels):
                raise ArtifactBindingError("secret sentinel cannot enter a journal")
            core = {
                "index": self._next_index,
                "kind": kind,
                "previous_digest": self._previous_digest,
                "payload": dict(payload),
            }
            digest = hashlib.sha256(canonical_json_bytes(core)).hexdigest()
            record = {**core, "record_sha256": digest}
            encoded = canonical_json_bytes(record) + b"\n"
            if len(encoded) > _MAX_JOURNAL_RECORD_BYTES:
                raise ArtifactBindingError("journal record exceeds the byte bound")
            try:
                _write_all(self._fd, encoded)
                os.fsync(self._fd)
            except OSError as error:
                raise ArtifactBindingError("journal append failed") from error
            receipt = JournalReceipt(self._next_index, self._previous_digest, digest)
            self._stream_digest.update(encoded)
            self._stream_size += len(encoded)
            self._next_index += 1
            self._previous_digest = digest
            return receipt

    def seal(self) -> BoundArtifact:
        with self._lock:
            if self._sealed or self._fd < 0:
                raise ArtifactBindingError("journal is sealed")
            fd = self._fd
            bound_fd = -1
            try:
                os.fsync(fd)
                os.fchmod(fd, 0o400)
                os.fsync(fd)
                _fsync_directory(self._path.parent)
                file_stat = os.fstat(fd)
                _require_file_stat(file_stat, 0o400)
                root_fd = _open_absolute_directory(self._relative_to)
                try:
                    bound, bound_fd = _bind_one(
                        self._path,
                        self._relative_to,
                        root_fd=root_fd,
                        expected_mode=0o400,
                        secret_sentinels=self._secret_sentinels,
                        domain="journal",
                    )
                finally:
                    _close_no_throw(root_fd)
                if (file_stat.st_dev, file_stat.st_ino) != (
                    bound.device,
                    bound.inode,
                ):
                    raise ArtifactBindingError("journal path binding changed at seal")
                if (
                    bound.record_count != self._next_index
                    or bound.size != self._stream_size
                    or bound.sha256 != self._stream_digest.hexdigest()
                ):
                    raise ArtifactBindingError("journal chain changed during seal")
                return bound
            except ArtifactBindingError as error:
                raise ArtifactBindingError(
                    "journal chain changed during seal"
                ) from error
            except OSError as error:
                raise ArtifactBindingError("journal seal failed") from error
            finally:
                if bound_fd >= 0:
                    _close_no_throw(bound_fd)
                _close_no_throw(fd)
                self._fd = -1
                self._sealed = True


class EvidenceBinder:
    """Retain and revalidate the exact closed artifact inode set."""

    def __init__(
        self,
        run_root: Path,
        *,
        context: EvidenceContext,
        secret_sentinels: Iterable[str] = (),
    ) -> None:
        self.run_root = _closed_root(Path(run_root))
        self._root_fd = _open_absolute_directory(self.run_root)
        if type(context) is not EvidenceContext:
            raise ArtifactBindingError("evidence context is invalid")
        self._context = context
        self._secret_sentinels = frozenset(secret_sentinels)
        if any(
            type(sentinel) is not str or not sentinel
            for sentinel in self._secret_sentinels
        ):
            raise ArtifactBindingError("secret sentinel set is invalid")
        self._retained: dict[str, int] = {}
        self._support_artifacts: dict[str, BoundArtifact] = {}
        self._support_paths: dict[str, Path] = {}
        self._frozen: dict[str, tuple[int, str, int]] = {}
        self._bundle: EvidenceBundle | None = None
        self._freeze_sequence = 0
        self._active_freeze: PublicationFreeze | None = None
        self._scan_inventory: tuple[tuple[str, Path], ...] = ()
        self._symlink_inventory: tuple[tuple[Path, int, int, bytes, str], ...] = ()
        self._run_inventory: tuple[str, ...] = ()
        self._ownership_writer_identities: tuple[ProcessIdentity, ...] = ()
        self._publication_temporary: tuple[BoundArtifact, int] | None = None
        self._lock = RLock()

    @property
    def retained_fd_count(self) -> int:
        return len(self._retained)

    def bind(self, requirements: Mapping[str, ArtifactRequirement]) -> EvidenceBundle:
        with self._lock:
            if self._retained:
                raise ArtifactBindingError("binder already retains an artifact set")
            if (
                type(requirements) is not dict
                or tuple(requirements) != REQUIRED_OFFLINE_ARTIFACTS
            ):
                raise ArtifactBindingError("offline artifact inventory is not exact")
            bound: dict[str, BoundArtifact] = {}
            retained: dict[str, int] = {}
            support: dict[str, BoundArtifact] = {}
            try:
                for name in REQUIRED_OFFLINE_ARTIFACTS:
                    requirement = requirements[name]
                    if type(requirement) is not ArtifactRequirement:
                        raise ArtifactBindingError("artifact requirement is not exact")
                    if name in {"host_observer_pre", "host_observer_post"}:
                        expected_observer_path = self.run_root / f"{name}.json"
                        if (
                            Path(os.path.abspath(requirement.path))
                            != expected_observer_path
                        ):
                            raise ArtifactBindingError(
                                "host observer must use its fixed run-root path"
                            )
                    artifact, fd = _bind_one(
                        requirement.path,
                        self.run_root,
                        root_fd=self._root_fd,
                        expected_mode=requirement.expected_mode,
                        secret_sentinels=self._secret_sentinels,
                        domain=name,
                    )
                    bound[name] = artifact
                    retained[name] = fd
                (
                    bound,
                    window,
                    begin,
                    end,
                    ledger_support,
                    ownership_writer_identities,
                ) = self._derive_descriptors(bound, retained)
                for name, (artifact, fd) in ledger_support.items():
                    support[name] = artifact
                    retained[name] = fd
                    self._support_paths[name] = self.run_root / artifact.relative_path
                self._scan_inventory = _secret_scan_inventory(
                    self.run_root, self._context
                )
                self._symlink_inventory = _tracked_symlink_inventory(
                    self._context, self._secret_sentinels
                )
                self._run_inventory = _run_tree_inventory(self._root_fd)
                known_run_paths = {
                    self.run_root / artifact.relative_path
                    for artifact in (*bound.values(), *support.values())
                }
                scan_support = self._bind_secret_scan_targets(
                    self._scan_inventory, known_run_paths=known_run_paths
                )
                for name, (artifact, fd, path) in scan_support.items():
                    support[name] = artifact
                    retained[name] = fd
                    self._support_paths[name] = path
                result_tree: dict[str, object] = {
                    name: bound[name].as_result_json()
                    for name in REQUIRED_OFFLINE_ARTIFACTS
                }
                result_tree.update(
                    semantic_dds_window=window,
                    dds_begin_record_index=begin,
                    dds_end_record_index=end,
                    marker_token=self._context.marker_token,
                )
                bundle_digest = hashlib.sha256(
                    canonical_json_bytes(result_tree)
                ).hexdigest()
                bundle = EvidenceBundle(
                    MappingProxyType(bound),
                    bundle_digest,
                    window,
                    begin,
                    end,
                    self._context.marker_token,
                )
                self._retained = retained
                self._support_artifacts = support
                self._ownership_writer_identities = ownership_writer_identities
                self._bundle = bundle
                return bundle
            except BaseException:
                for fd in retained.values():
                    _close_no_throw(fd)
                raise

    def revalidate(self, bundle: EvidenceBundle) -> None:
        with self._lock:
            if bundle is not self._bundle or any(
                name not in self._retained for name in REQUIRED_OFFLINE_ARTIFACTS
            ):
                raise ArtifactBindingError(
                    "artifact bundle is not retained by this binder"
                )
            for name in REQUIRED_OFFLINE_ARTIFACTS:
                expected = bundle.artifacts[name]
                try:
                    observed = _describe_retained(
                        self._retained[name],
                        expected.relative_path,
                        expected.mode,
                        secret_sentinels=self._secret_sentinels,
                        domain=name,
                    )
                except ArtifactBindingError as error:
                    raise ArtifactBindingError(
                        "artifact changed after binding"
                    ) from error
                _require_retained_path(self._root_fd, expected, observed)
                if _base_artifact(observed) != _base_artifact(expected):
                    raise ArtifactBindingError("artifact changed after binding")
            for name, expected in self._support_artifacts.items():
                observed = _describe_retained(
                    self._retained[name],
                    expected.relative_path,
                    expected.mode,
                    secret_sentinels=self._secret_sentinels,
                    domain=(
                        "ledger_generation"
                        if name.startswith("ledger-generation:")
                        else "secret_scan"
                    ),
                )
                if _base_artifact(observed) != _base_artifact(expected):
                    raise ArtifactBindingError("support artifact changed after binding")
                try:
                    if name.startswith("ledger-generation:"):
                        _require_retained_path(self._root_fd, expected, observed)
                    else:
                        _require_path_identity(
                            self._support_paths[name], expected, observed
                        )
                except ArtifactBindingError as error:
                    raise ArtifactBindingError(
                        "support artifact changed after binding"
                    ) from error
            if (
                _tracked_symlink_inventory(self._context, self._secret_sentinels)
                != self._symlink_inventory
            ):
                raise ArtifactBindingError("tracked symlink changed after binding")
            result_tree = {
                **bundle.as_result_artifacts(),
                "semantic_dds_window": bundle.semantic_dds_window,
                "dds_begin_record_index": bundle.dds_begin_record_index,
                "dds_end_record_index": bundle.dds_end_record_index,
                "marker_token": bundle.marker_token,
            }
            digest = hashlib.sha256(canonical_json_bytes(result_tree)).hexdigest()
            if digest != bundle.bundle_sha256:
                raise ArtifactBindingError("artifact bundle digest changed")

    def freeze_for_publication(self, bundle: EvidenceBundle) -> PublicationFreeze:
        """Seal an immutable copied snapshot after every evidence writer exits."""

        with self._lock:
            self.revalidate(bundle)
            self._require_inventory_unchanged(publication_active=False)
            self._require_writer_identities_absent(bundle)
            self._seal_persistent_evidence_directories()
            self._close_frozen()
            frozen: dict[str, tuple[int, str, int]] = {}
            snapshot_rows: list[dict[str, object]] = []
            expected = {
                **dict(bundle.artifacts),
                **self._support_artifacts,
            }
            try:
                for name in sorted(expected):
                    artifact = expected[name]
                    fd = self._retained[name]
                    data = _read_retained_bytes(fd)
                    if (
                        hashlib.sha256(data).hexdigest() != artifact.sha256
                        or len(data) != artifact.size
                    ):
                        raise ArtifactBindingError(
                            "artifact changed while publication snapshot was copied"
                        )
                    snapshot_fd = _sealed_memfd(name, data)
                    frozen[name] = (snapshot_fd, artifact.sha256, artifact.size)
                    snapshot_rows.append(
                        {
                            "name": name,
                            "sha256": artifact.sha256,
                            "size": artifact.size,
                        }
                    )
            except BaseException:
                for snapshot_fd, _digest, _size in frozen.values():
                    _close_no_throw(snapshot_fd)
                raise
            snapshot_sha256 = _snapshot_rows_sha256(snapshot_rows)
            self._frozen = frozen
            self._freeze_sequence += 1
            freeze = PublicationFreeze(
                bundle.bundle_sha256,
                len(self._retained),
                snapshot_sha256,
                len(frozen),
                self._freeze_sequence,
            )
            self._active_freeze = freeze
            return freeze

    def register_publication_temporary(
        self,
        bundle: EvidenceBundle,
        freeze: PublicationFreeze,
        path: Path,
    ) -> None:
        """Bind the exact atomic staging file allowed during final publication."""

        with self._lock:
            if bundle is not self._bundle or freeze is not self._active_freeze:
                raise ArtifactBindingError("publication temporary token is not current")
            if self._publication_temporary is not None:
                raise ArtifactBindingError(
                    "publication temporary was already registered"
                )
            relative = _require_lexical_child(Path(path), self.run_root)
            if not _is_configured_publication_temporary(
                relative, self._context, self.run_root
            ):
                raise ArtifactBindingError(
                    "publication temporary does not match a configured target"
                )
            observed = set(_run_tree_inventory(self._root_fd))
            expected = set(self._run_inventory)
            if observed - expected != {relative} or expected - observed:
                raise ArtifactBindingError(
                    "publication temporary inventory is not exact"
                )
            artifact, fd = _bind_one(
                Path(path),
                self.run_root,
                root_fd=self._root_fd,
                expected_mode=0o600,
                secret_sentinels=self._secret_sentinels,
                domain=None,
            )
            self._publication_temporary = artifact, fd

    def revalidate_for_publication(
        self, bundle: EvidenceBundle, freeze: PublicationFreeze
    ) -> dict[str, object]:
        """Perform the last check immediately before the atomic result rename."""

        with self._lock:
            if freeze is not self._active_freeze:
                raise ArtifactBindingError("publication freeze token is not current")
            if (
                freeze.bundle_sha256 != bundle.bundle_sha256
                or freeze.retained_fd_count != len(self._retained)
                or freeze.snapshot_fd_count != len(self._frozen)
            ):
                raise ArtifactBindingError("publication freeze binding changed")
            self._require_inventory_unchanged(publication_active=True)
            self._require_writer_identities_absent(bundle)
            self.revalidate(bundle)
            rows = []
            for name in sorted(self._frozen):
                fd, expected_digest, expected_size = self._frozen[name]
                try:
                    seals = fcntl.fcntl(fd, _F_GET_SEALS)
                    data = _read_retained_bytes(fd)
                except OSError as error:
                    raise ArtifactBindingError(
                        "publication snapshot is unavailable"
                    ) from error
                if seals != _REQUIRED_MEMFD_SEALS:
                    raise ArtifactBindingError("publication snapshot is not immutable")
                if (
                    len(data) != expected_size
                    or hashlib.sha256(data).hexdigest() != expected_digest
                ):
                    raise ArtifactBindingError("publication snapshot changed")
                rows.append(
                    {"name": name, "sha256": expected_digest, "size": expected_size}
                )
            if _snapshot_rows_sha256(rows) != freeze.snapshot_sha256:
                raise ArtifactBindingError("publication snapshot binding changed")
            return bundle.as_result_evidence()

    def close(self) -> None:
        with self._lock:
            for fd in self._retained.values():
                _close_no_throw(fd)
            self._close_frozen()
            self._retained = {}
            self._support_artifacts = {}
            self._support_paths = {}
            self._scan_inventory = ()
            self._symlink_inventory = ()
            self._run_inventory = ()
            self._ownership_writer_identities = ()
            if self._publication_temporary is not None:
                _close_no_throw(self._publication_temporary[1])
            self._publication_temporary = None
            self._bundle = None
            self._active_freeze = None
            _close_no_throw(self._root_fd)
            self._root_fd = -1

    def _close_frozen(self) -> None:
        for fd, _digest, _size in self._frozen.values():
            _close_no_throw(fd)
        self._frozen = {}

    def _require_inventory_unchanged(self, *, publication_active: bool) -> None:
        observed_scan = _secret_scan_inventory(self.run_root, self._context)
        if publication_active and self._publication_temporary is not None:
            temporary_path = (
                self.run_root / self._publication_temporary[0].relative_path
            )
            observed_scan = tuple(
                row for row in observed_scan if row[1] != temporary_path
            )
        if observed_scan != self._scan_inventory:
            raise ArtifactBindingError("secret scan inventory changed after binding")
        observed_symlinks = _tracked_symlink_inventory(
            self._context, self._secret_sentinels
        )
        if observed_symlinks != self._symlink_inventory:
            raise ArtifactBindingError("tracked symlink changed after binding")
        observed = set(_run_tree_inventory(self._root_fd))
        expected = set(self._run_inventory)
        permitted: set[str] = set()
        if publication_active and self._publication_temporary is not None:
            permitted.add(self._publication_temporary[0].relative_path)
            observed_temporary = _describe_retained(
                self._publication_temporary[1],
                self._publication_temporary[0].relative_path,
                0o600,
                secret_sentinels=self._secret_sentinels,
            )
            _require_retained_path(
                self._root_fd,
                self._publication_temporary[0],
                observed_temporary,
            )
            if _base_artifact(observed_temporary) != _base_artifact(
                self._publication_temporary[0]
            ):
                raise ArtifactBindingError("publication temporary changed")
        extras = observed - expected - permitted
        if extras or expected - observed:
            raise ArtifactBindingError("run artifact inventory changed after binding")

    def _require_writer_identities_absent(self, bundle: EvidenceBundle) -> None:
        identities: list[ProcessIdentity] = list(self._ownership_writer_identities)
        artifacts = bundle.as_result_artifacts()
        trace = artifacts["trace"]
        bootstrap = artifacts["bootstrap_report"]
        for value in (
            trace.get("tracer_identity"),
            trace.get("normalizer_identity"),
            bootstrap.get("handoff", {}).get("signal_ready_identity"),
        ):
            if value is not None:
                identities.append(ProcessIdentity.from_dict(value))
        for identity in identities:
            if identity.matches_proc():
                raise ArtifactBindingError(
                    "evidence writer identity remains live at publication freeze"
                )

    def _seal_persistent_evidence_directories(self) -> None:
        """Leave referenced evidence files/directories read-only after publication."""

        directories = set()
        for artifact in (
            *self._bundle.artifacts.values(),
            *self._support_artifacts.values(),
        ):
            if not artifact.relative_path:
                continue
            path = Path(artifact.relative_path)
            absolute = path if path.is_absolute() else self.run_root / path
            try:
                absolute.relative_to(self.run_root)
            except ValueError:
                # Tracked secret-scan inputs are revalidated but are not part of
                # the supervisor-owned evidence subtree and must not be chmod'd.
                continue
            directories.add(absolute.parent)
        for directory in sorted(
            directories, key=lambda path: len(path.parts), reverse=True
        ):
            if directory == self.run_root:
                continue
            try:
                directory.chmod(0o500)
                _fsync_directory(directory)
            except OSError as error:
                raise ArtifactBindingError(
                    "persistent evidence directory could not be frozen"
                ) from error

    def _derive_descriptors(
        self,
        bound: dict[str, BoundArtifact],
        retained: Mapping[str, int],
    ) -> tuple[
        dict[str, BoundArtifact],
        str,
        int | None,
        int | None,
        dict[str, tuple[BoundArtifact, int]],
        tuple[ProcessIdentity, ...],
    ]:
        trace_records = _parse_ndjson(_read_retained_bytes(retained["trace"]), "trace")
        trace_fields, window, begin, end = _trace_result_fields(
            trace_records, self._context.trace, self._context.marker_token
        )
        bound["trace"] = _with_result_fields(bound["trace"], trace_fields)

        bootstrap = _parse_json_object(
            _read_retained_bytes(retained["bootstrap_report"]),
            "bootstrap report",
        )
        bootstrap_fields = _bootstrap_result_fields(
            bootstrap,
            run_nonce=self._context.expected_ledger_nonce,
            trace_records=trace_records,
        )
        bound["bootstrap_report"] = _with_result_fields(
            bound["bootstrap_report"], bootstrap_fields
        )

        ownership = _parse_ndjson(
            _read_retained_bytes(retained["ownership_journal"]),
            "ownership_journal",
        )
        ownership_head = _validate_hash_journal(ownership, None)
        ownership_writer_identities: list[ProcessIdentity] = []
        participant_pids: set[int] = set()
        for record in ownership:
            payload = record["payload"]
            if type(payload) is not dict:
                raise ArtifactBindingError("ownership journal payload is invalid")
            try:
                identity = ProcessIdentity.from_dict(payload["identity"])
            except ProcessIdentityError as error:
                raise ArtifactBindingError(
                    "ownership journal identity is invalid"
                ) from error
            ownership_writer_identities.append(identity)
            sequence = record["index"] + 1
            expected_kind = (
                "OWNERSHIP_RECORD" if sequence == 1 else "PARTICIPANT_RECORD"
            )
            if record["kind"] != expected_kind:
                raise ArtifactBindingError("ownership journal kind/order is invalid")
            if not _is_sha256(payload.get("request_sha256")):
                raise ArtifactBindingError("ownership journal role/digest is invalid")
            if sequence == 1:
                if (
                    set(payload)
                    != {
                        "identity",
                        "role",
                        "request_sha256",
                    }
                    or payload["role"] != "action_child"
                ):
                    raise ArtifactBindingError("ownership journal role is invalid")
                broker_request = {
                    "type": "OWNERSHIP_RECORD",
                    "run_nonce": self._context.expected_ledger_nonce,
                    "sequence": sequence,
                    "identity": identity.as_dict(),
                    "role": "action_child",
                }
            else:
                index = sequence - 2
                if (
                    set(payload)
                    != {
                        "identity",
                        "role",
                        "request_sha256",
                        "participant_index",
                        "config_digest",
                    }
                    or index not in range(4)
                    or payload["participant_index"] != index
                    or payload["role"] != CONFIG_ROLES[index]
                    or payload["config_digest"] != EXPECTED_CONFIG_SHA256[index]
                    or identity.pid in participant_pids
                    or identity.pid == ownership_writer_identities[0].pid
                ):
                    raise ArtifactBindingError(
                        "participant ownership binding is invalid"
                    )
                participant_pids.add(identity.pid)
                broker_request = {
                    "type": "PARTICIPANT_RECORD",
                    "run_nonce": self._context.expected_ledger_nonce,
                    "sequence": sequence,
                    "identity": identity.as_dict(),
                    "role": payload["role"],
                    "participant_index": index,
                    "config_digest": payload["config_digest"],
                }
            expected_request_sha256 = hashlib.sha256(
                canonical_json_bytes(broker_request)
            ).hexdigest()
            if payload["request_sha256"] != expected_request_sha256:
                raise ArtifactBindingError(
                    "ownership journal request binding is invalid"
                )
        if self._context.trace.trace_state == "FULL" and len(ownership) != 5:
            raise ArtifactBindingError("participant ownership inventory is incomplete")
        if self._context.trace.trace_state == "FULL":
            replay = self._context.trace_policy_replay
            journal_authority = {
                identity.pid: {
                    "index": index,
                    "config_digest": EXPECTED_CONFIG_SHA256[index],
                }
                for index, identity in enumerate(ownership_writer_identities[1:])
            }
            if replay is None or replay.participants != journal_authority:
                raise ArtifactBindingError(
                    "participant ownership/replay authority mismatch"
                )
        bound["ownership_journal"] = _with_result_fields(
            bound["ownership_journal"],
            {"record_count": len(ownership), "head_record_sha256": ownership_head},
        )

        violations = _parse_ndjson(
            _read_retained_bytes(retained["violation_journal"]),
            "violation_journal",
        )
        violation_head = _validate_hash_journal(violations, None)
        _validate_violation_records(
            violations,
            trace_records,
            self._context.ledger_contract,
            self._context.trace_policy_replay,
            bootstrap_fields["initial_fd_manifest"],
            self._context.marker_token,
        )
        bound["violation_journal"] = _with_result_fields(
            bound["violation_journal"],
            {
                "violation_count": len(violations),
                "head_record_sha256": violation_head,
            },
        )

        pre = _observer_result_fields(
            _parse_json_object(
                _read_retained_bytes(retained["host_observer_pre"]),
                "host observer",
            ),
            self._context.expected_host_observer_identity,
        )
        post = _observer_result_fields(
            _parse_json_object(
                _read_retained_bytes(retained["host_observer_post"]),
                "host observer",
            ),
            self._context.expected_host_observer_identity,
        )
        if (
            pre["state"] == post["state"] == "OBSERVED"
            and pre["network_namespace_inode"] != post["network_namespace_inode"]
        ):
            raise ArtifactBindingError("host observer namespace changed")
        bound["host_observer_pre"] = _with_result_fields(
            bound["host_observer_pre"], pre
        )
        bound["host_observer_post"] = _with_result_fields(
            bound["host_observer_post"], post
        )

        manifest = _parse_json_object(
            _read_retained_bytes(retained["ledger_chain_manifest"]),
            "ledger chain manifest",
        )
        ledger_fields, ledger_window, support = _validate_ledger_chain(
            manifest,
            self.run_root,
            self._root_fd,
            self._context,
            self._secret_sentinels,
        )
        if ledger_window != window:
            for _name, (_artifact, fd) in support.items():
                _close_no_throw(fd)
            raise ArtifactBindingError("ledger and trace DDS window disagree")
        bound["ledger_chain_manifest"] = _with_result_fields(
            bound["ledger_chain_manifest"], ledger_fields
        )
        return (
            bound,
            window,
            begin,
            end,
            support,
            tuple(ownership_writer_identities),
        )

    def _bind_secret_scan_targets(
        self,
        inventories: tuple[tuple[str, Path], ...],
        *,
        known_run_paths: set[Path],
    ) -> dict[str, tuple[BoundArtifact, int, Path]]:
        support: dict[str, tuple[BoundArtifact, int, Path]] = {}
        try:
            for kind, path in inventories:
                if path in known_run_paths:
                    continue
                key = f"secret-{kind}:{len(support)}"
                artifact, fd = _bind_scan_target(path, self._secret_sentinels)
                support[key] = (artifact, fd, path)
            return support
        except BaseException:
            for _artifact, fd, _path in support.values():
                _close_no_throw(fd)
            raise


def write_host_observer_artifact(
    path: Path,
    *,
    relative_to: Path,
    state: str,
    cause_gate: str | None = None,
    reason: str | None = None,
    collector_identity: ProcessIdentity | None = None,
    network_namespace_inode: int | None = None,
    observed_processes: tuple[str, ...] = (),
    observed_services: tuple[str, ...] = (),
    observed_listeners: tuple[str, ...] = (),
    internet_socket_attempts: tuple[str, ...] = (),
    trusted_inspection: Mapping[str, object] | None = None,
) -> HostObserverArtifactReceipt:
    if state not in {"OBSERVED", "NOT_RUN"}:
        raise ArtifactBindingError("host observer state is invalid")
    inventories = (
        observed_processes,
        observed_services,
        observed_listeners,
        internet_socket_attempts,
    )
    for inventory in inventories:
        _require_observer_inventory(inventory)
    normalized_inspection = (
        None
        if trusted_inspection is None
        else _normalize_trusted_host_inspection(
            trusted_inspection,
            observed_listeners=list(observed_listeners),
        )
    )
    if state == "NOT_RUN":
        if (
            collector_identity is not None
            or network_namespace_inode is not None
            or any(inventories)
            or normalized_inspection is not None
        ):
            raise ArtifactBindingError(
                "NOT_RUN observer must contain zero observations"
            )
        valid_cause = (
            cause_gate == "safety.workstation_preflight"
            and reason in {"EARLIER_BLOCKING_GATE", "INTERRUPTED_BEFORE_GATE"}
        ) or (
            cause_gate == "safety.workstation_postflight"
            and reason == "POSTFLIGHT_FAILED"
        )
        if not valid_cause:
            raise ArtifactBindingError("NOT_RUN observer cause is invalid")
    else:
        if type(collector_identity) is not ProcessIdentity:
            raise ArtifactBindingError("OBSERVED collector identity is invalid")
        if type(network_namespace_inode) is not int or network_namespace_inode <= 0:
            raise ArtifactBindingError("OBSERVED namespace inode is invalid")
        if cause_gate is not None or reason is not None:
            raise ArtifactBindingError(
                "OBSERVED artifact cannot name an earlier blocker"
            )
        if internet_socket_attempts:
            raise ArtifactBindingError(
                "OBSERVED host observer contains an internet socket attempt"
            )
        if normalized_inspection is None:
            raise ArtifactBindingError(
                "OBSERVED host observer requires trusted inspection evidence"
            )
    value = {
        "state": state,
        "collector_identity": (
            None if collector_identity is None else collector_identity.as_dict()
        ),
        "network_namespace_inode": network_namespace_inode,
        "observed_processes": list(observed_processes),
        "observed_services": list(observed_services),
        "observed_listeners": list(observed_listeners),
        "internet_socket_attempts": list(internet_socket_attempts),
        "trusted_inspection": normalized_inspection,
        "cause_gate": cause_gate,
        "reason": reason,
    }
    try:
        descriptor = atomic_write_json_no_replace(
            path,
            value,
            mode=0o400,
            relative_to=relative_to,
        )
    except (AtomicIOError, OSError, ValueError) as error:
        raise ArtifactBindingError("host observer artifact write failed") from error
    artifact = _from_atomic_descriptor(descriptor, record_count=0, mode=0o400)
    root = _closed_root(relative_to)
    root_fd = _open_absolute_directory(root)
    try:
        retained, fd = _bind_one(
            path,
            root,
            root_fd=root_fd,
            expected_mode=0o400,
            domain="host_observer_receipt",
        )
    finally:
        _close_no_throw(root_fd)
    if _base_artifact(retained) != _base_artifact(artifact):
        _close_no_throw(fd)
        raise ArtifactBindingError(
            "host observer receipt differs from persisted artifact"
        )
    return HostObserverArtifactReceipt(
        artifact,
        _HOST_OBSERVER_RECEIPT_AUTHORITY,
        fd,
    )


def redact_environment(
    environment: Mapping[str, str], *, network_namespace: str | None
) -> dict[str, object]:
    if type(environment) is not dict or any(
        type(key) is not str or type(value) is not str
        for key, value in environment.items()
    ):
        raise ArtifactBindingError("environment must contain exact string pairs")
    credentials = sorted(
        key
        for key in environment
        if key.upper() not in _PROXY_VARIABLES
        and any(marker in key.upper() for marker in _CREDENTIAL_MARKERS)
    )
    proxies = sorted(key for key in environment if key.upper() in _PROXY_VARIABLES)
    return {
        "network_namespace": network_namespace,
        "ros_domain_id": _optional_domain(environment.get("ROS_DOMAIN_ID")),
        "ros_localhost_only": _optional_boolean(environment.get("ROS_LOCALHOST_ONLY")),
        "credential_variables_present": credentials,
        "proxy_variables_present": proxies,
    }


def redact_value(value: object, secret_sentinels: Iterable[str] = ()) -> object:
    sentinels = frozenset(secret_sentinels)
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise ArtifactBindingError("evidence object key is not a string")
            upper = key.upper()
            if upper in _PROXY_VARIABLES or any(
                marker in upper for marker in _CREDENTIAL_MARKERS
            ):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_value(child, sentinels)
        return result
    if type(value) is list:
        return [redact_value(child, sentinels) for child in value]
    if type(value) is tuple:
        return [redact_value(child, sentinels) for child in value]
    if type(value) is str:
        redacted = value
        for sentinel in sentinels:
            redacted = redacted.replace(sentinel, "[REDACTED]")
        return redacted
    if value is None or type(value) in {bool, int, float}:
        return value
    raise ArtifactBindingError("evidence value is outside the closed JSON model")


def _bind_one(
    path: Path,
    root: Path,
    *,
    root_fd: int,
    expected_mode: int,
    secret_sentinels: frozenset[str] = frozenset(),
    domain: str | None = None,
) -> tuple[BoundArtifact, int]:
    path = Path(path)
    relative = _require_lexical_child(path, root)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd, path_before = _open_beneath(root_fd, relative, flags)
        observed = _describe_retained(
            fd,
            relative,
            expected_mode,
            secret_sentinels=secret_sentinels,
            domain=domain,
        )
        path_after = _stat_beneath(root_fd, relative)
        if (path_before.st_dev, path_before.st_ino) != (
            observed.device,
            observed.inode,
        ) or (path_after.st_dev, path_after.st_ino) != (
            observed.device,
            observed.inode,
        ):
            raise ArtifactBindingError("artifact path binding changed")
        return observed, fd
    except BaseException:
        if "fd" in locals():
            _close_no_throw(fd)
        raise


def _describe_retained(
    fd: int,
    relative_path: str,
    expected_mode: int,
    *,
    secret_sentinels: frozenset[str] = frozenset(),
    domain: str | None = None,
) -> BoundArtifact:
    try:
        before = os.fstat(fd)
        _require_file_stat(before, expected_mode)
        data = _read_retained_bytes(fd)
        _require_no_secret(data, secret_sentinels)
        record_count = 0
        if domain in {
            "trace",
            "ownership_journal",
            "violation_journal",
            "journal",
        }:
            records = _parse_ndjson(data, domain)
            record_count = len(records)
            if domain == "trace":
                _validate_trace_record_order(records)
            elif domain in {"ownership_journal", "violation_journal", "journal"}:
                _validate_hash_journal(records, None)
        elif domain not in {None, "secret_scan", "ledger_generation"}:
            _parse_json_object(data, domain.replace("_", " "))
        elif domain == "ledger_generation":
            _parse_json_object(data, "ledger generation")
        after = os.fstat(fd)
        if _stable_identity(before) != _stable_identity(after):
            raise ArtifactBindingError("artifact changed while read")
        return BoundArtifact(
            relative_path=relative_path,
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            record_count=record_count,
            inode=after.st_ino,
            device=after.st_dev,
            mode=stat.S_IMODE(after.st_mode),
        )
    except OSError as error:
        raise ArtifactBindingError("artifact descriptor read failed") from error


def _closed_root(root: Path) -> Path:
    try:
        absolute = Path(os.path.abspath(root))
        resolved = root.resolve(strict=True)
        root_stat = os.stat(resolved, follow_symlinks=False)
    except OSError as error:
        raise ArtifactBindingError("evidence root is unavailable") from error
    if absolute != resolved:
        raise ArtifactBindingError("evidence root contains a symlink")
    if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.getuid():
        raise ArtifactBindingError("evidence root owner/type is invalid")
    return resolved


def _open_absolute_directory(path: Path) -> int:
    """Open an absolute directory one component at a time without symlink traversal."""

    absolute = Path(os.path.abspath(path))
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        observed = os.fstat(current)
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
            raise ArtifactBindingError("evidence root owner/type is invalid")
        return current
    except BaseException:
        _close_no_throw(current)
        raise


def _open_beneath(
    root_fd: int, relative_path: str, flags: int
) -> tuple[int, os.stat_result]:
    parts = Path(relative_path).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ArtifactBindingError("artifact relative path is invalid")
    directory_fd = os.dup(root_fd)
    try:
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        for component in parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        before = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode):
            raise ArtifactBindingError("artifact path is a symlink")
        fd = os.open(parts[-1], flags, dir_fd=directory_fd)
        after = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            _close_no_throw(fd)
            raise ArtifactBindingError("artifact path binding changed")
        return fd, after
    except OSError as error:
        raise ArtifactBindingError(
            "artifact path cannot be opened beneath root"
        ) from error
    finally:
        _close_no_throw(directory_fd)


def _stat_beneath(root_fd: int, relative_path: str) -> os.stat_result:
    fd, path_stat = _open_beneath(
        root_fd,
        relative_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    _close_no_throw(fd)
    return path_stat


def _require_lexical_child(path: Path, root: Path) -> str:
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ArtifactBindingError("artifact path escapes evidence root") from error
    if not relative.parts or ".." in relative.parts:
        raise ArtifactBindingError("artifact path escapes evidence root")
    try:
        parent = absolute.parent.resolve(strict=True)
    except OSError as error:
        raise ArtifactBindingError("artifact parent is unavailable") from error
    if parent != absolute.parent:
        raise ArtifactBindingError("artifact parent contains a symlink")
    return relative.as_posix()


def _require_file_stat(value: os.stat_result, expected_mode: int) -> None:
    if not stat.S_ISREG(value.st_mode):
        raise ArtifactBindingError("artifact is not a regular file")
    if value.st_uid != os.getuid():
        raise ArtifactBindingError("artifact owner is invalid")
    if stat.S_IMODE(value.st_mode) != expected_mode:
        raise ArtifactBindingError("artifact mode changed or is invalid")


def _from_atomic_descriptor(
    descriptor: ArtifactDescriptor, *, record_count: int, mode: int
) -> BoundArtifact:
    return BoundArtifact(
        descriptor.relative_path,
        descriptor.sha256,
        descriptor.size,
        record_count,
        descriptor.inode,
        descriptor.device,
        mode,
    )


def _with_result_fields(
    artifact: BoundArtifact, fields: Mapping[str, object]
) -> BoundArtifact:
    try:
        canonical_json_bytes(dict(fields))
    except (TypeError, ValueError) as error:
        raise ArtifactBindingError("artifact result fields are invalid") from error
    return replace(
        artifact, result_fields=MappingProxyType(copy.deepcopy(dict(fields)))
    )


def _base_artifact(artifact: BoundArtifact) -> tuple[object, ...]:
    return (
        artifact.relative_path,
        artifact.sha256,
        artifact.size,
        artifact.record_count,
        artifact.inode,
        artifact.device,
        artifact.mode,
    )


def _require_retained_path(
    root_fd: int, expected: BoundArtifact, observed: BoundArtifact
) -> None:
    try:
        path_stat = _stat_beneath(root_fd, expected.relative_path)
    except (OSError, ArtifactBindingError) as error:
        raise ArtifactBindingError("artifact path changed") from error
    if stat.S_ISLNK(path_stat.st_mode):
        raise ArtifactBindingError("artifact path changed to a symlink")
    if (path_stat.st_dev, path_stat.st_ino) != (observed.device, observed.inode):
        raise ArtifactBindingError("artifact path binding changed")


def _require_path_identity(
    path: Path, expected: BoundArtifact, observed: BoundArtifact
) -> None:
    parent_fd = -1
    try:
        absolute = Path(os.path.abspath(path))
        parent_fd = _open_absolute_directory(absolute.parent)
        path_stat = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
    except (OSError, ArtifactBindingError) as error:
        raise ArtifactBindingError("artifact path changed") from error
    finally:
        _close_no_throw(parent_fd)
    if (
        stat.S_ISLNK(path_stat.st_mode)
        or (
            path_stat.st_dev,
            path_stat.st_ino,
        )
        != (expected.device, expected.inode)
        or (
            path_stat.st_dev,
            path_stat.st_ino,
        )
        != (
            observed.device,
            observed.inode,
        )
    ):
        raise ArtifactBindingError("artifact path binding changed")


def _sealed_memfd(name: str, data: bytes) -> int:
    fd = -1
    try:
        memfd_name = f"holoagent0-evidence-{name[:32]}"
        if hasattr(os, "memfd_create"):
            fd = os.memfd_create(
                memfd_name,
                _MFD_CLOEXEC | _MFD_ALLOW_SEALING,
            )
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            fd = libc.syscall(
                319,
                memfd_name.encode("ascii", "strict"),
                _MFD_CLOEXEC | _MFD_ALLOW_SEALING,
            )
            if fd < 0:
                error_number = ctypes.get_errno()
                raise OSError(error_number, os.strerror(error_number))
        _write_all(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, _F_ADD_SEALS, _REQUIRED_MEMFD_SEALS)
        if fcntl.fcntl(fd, _F_GET_SEALS) != _REQUIRED_MEMFD_SEALS:
            raise ArtifactBindingError("publication snapshot sealing failed")
        return fd
    except (OSError, AttributeError) as error:
        if fd >= 0:
            _close_no_throw(fd)
        raise ArtifactBindingError("publication snapshot sealing failed") from error


def _read_retained_bytes(fd: int) -> bytes:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = bytearray()
        while True:
            chunk = os.read(fd, min(64 * 1024, _MAX_ARTIFACT_BYTES - len(data) + 1))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > _MAX_ARTIFACT_BYTES:
                raise ArtifactBindingError("artifact exceeds the byte bound")
        return bytes(data)
    except OSError as error:
        raise ArtifactBindingError("artifact descriptor read failed") from error


def _parse_json_object(data: bytes, description: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactBindingError(f"{description} is not valid JSON") from error
    if type(value) is not dict:
        raise ArtifactBindingError(f"{description} must be an exact object")
    if canonical_json_bytes(value) != data:
        raise ArtifactBindingError(f"{description} is not canonical JSON")
    return value


def _parse_ndjson(data: bytes, description: str) -> list[dict[str, object]]:
    if not data:
        return []
    if not data.endswith(b"\n"):
        raise ArtifactBindingError(f"{description} NDJSON is not newline terminated")
    records: list[dict[str, object]] = []
    for line in data[:-1].split(b"\n"):
        if not line:
            raise ArtifactBindingError(f"{description} NDJSON contains an empty record")
        try:
            value = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ArtifactBindingError(
                f"{description} NDJSON record is invalid"
            ) from error
        if type(value) is not dict:
            raise ArtifactBindingError(f"{description} NDJSON record must be an object")
        if canonical_json_bytes(value) != line:
            raise ArtifactBindingError(f"{description} NDJSON record is not canonical")
        records.append(value)
    return records


def _validate_trace_record_order(records: list[dict[str, object]]) -> None:
    for index, record in enumerate(records):
        if record.get("record_index") != index or type(record.get("pid")) is not int:
            raise ArtifactBindingError("trace record index/PID sequence is invalid")


def _validate_hash_journal(
    records: list[dict[str, object]], required_kind: str | None
) -> str | None:
    previous: str | None = None
    for index, record in enumerate(records):
        if set(record) != {
            "index",
            "kind",
            "previous_digest",
            "payload",
            "record_sha256",
        }:
            raise ArtifactBindingError("journal record is not closed")
        if record["index"] != index or record["previous_digest"] != previous:
            raise ArtifactBindingError(
                "journal hash chain index/predecessor is invalid"
            )
        if required_kind is not None and record["kind"] != required_kind:
            raise ArtifactBindingError("journal kind is invalid")
        if type(record["kind"]) is not str or type(record["payload"]) is not dict:
            raise ArtifactBindingError("journal record fields are invalid")
        core = {
            "index": record["index"],
            "kind": record["kind"],
            "previous_digest": record["previous_digest"],
            "payload": record["payload"],
        }
        expected = hashlib.sha256(canonical_json_bytes(core)).hexdigest()
        if record["record_sha256"] != expected:
            raise ArtifactBindingError("journal record digest breaks hash chain")
        previous = expected
    return previous


def _validate_violation_records(
    records: list[dict[str, object]],
    trace_records: list[dict[str, object]],
    contract: ContractSet,
    replay: TracePolicyReplayEvidence | None,
    bootstrap_initial_fd_manifest: object,
    marker_token: str,
) -> None:
    allowed_reasons = frozenset(
        contract.allowed_gate_reasons("offline.network_policy", "FAIL")
    )
    trace_payloads: list[dict[str, object]] = []
    supervisor_sequence = 0
    for record in records:
        payload = record["payload"]
        if type(payload) is not dict:
            raise ArtifactBindingError("violation journal payload is not closed")
        kind = record["kind"]
        if kind == "TRACE_VIOLATION_RECORD":
            if set(payload) != {"reason", "record_index", "pid", "operation"}:
                raise ArtifactBindingError(
                    "trace violation journal payload is not closed"
                )
            trace_index = payload["record_index"]
            if type(trace_index) is not int or not 0 <= trace_index < len(
                trace_records
            ):
                raise ArtifactBindingError(
                    "trace violation journal record index is invalid"
                )
            trace_payloads.append(copy.deepcopy(payload))
        elif kind == "SUPERVISOR_VIOLATION_RECORD":
            if set(payload) != {"reason", "event_sequence", "pid", "operation"}:
                raise ArtifactBindingError(
                    "supervisor violation journal payload is not closed"
                )
            if payload["event_sequence"] != supervisor_sequence:
                raise ArtifactBindingError(
                    "supervisor violation event sequence is invalid"
                )
            supervisor_sequence += 1
        else:
            raise ArtifactBindingError("violation journal kind is invalid")
        reason = payload["reason"]
        pid = payload["pid"]
        operation = payload["operation"]
        if (
            reason not in allowed_reasons
            or type(pid) is not int
            or pid <= 0
            or type(operation) is not str
            or not operation
        ):
            raise ArtifactBindingError("violation journal payload fields are invalid")
    if replay is None:
        if trace_records or trace_payloads:
            raise ArtifactBindingError("trace-policy replay evidence is unavailable")
        return
    if type(replay) is not TracePolicyReplayEvidence:
        raise ArtifactBindingError("trace-policy replay evidence is invalid")
    _bind_replay_fd_manifest(replay, bootstrap_initial_fd_manifest)
    sink = _ReplayViolationSink()
    try:
        policy = TracePolicy(
            coordinator_pid=replay.coordinator_pid,
            marker_token=marker_token,
            participants={pid: dict(row) for pid, row in replay.participants.items()},
            namespace_loopback_only=replay.namespace_loopback_only,
            initial_fd_manifest={
                pid: [dict(row) for row in rows]
                for pid, rows in replay.initial_fd_manifest.items()
            },
            violation_sink=sink,
        )
        for trace_record in trace_records:
            policy.feed(trace_record)
        policy.finalize(trace_integrity_ok=True)
    except (TypeError, ValueError) as error:
        raise ArtifactBindingError("trace-policy replay failed") from error
    emitted = [
        {
            "reason": violation.reason,
            "record_index": violation.record_index,
            "pid": violation.pid,
            "operation": violation.operation,
        }
        for violation in sink.violations
    ]
    if any(payload["reason"] not in allowed_reasons for payload in emitted):
        raise ArtifactBindingError("trace policy emitted an unreviewed violation")
    if trace_payloads != emitted:
        raise ArtifactBindingError(
            "violation journal differs from canonical trace-policy replay"
        )


class _ReplayViolationSink:
    def __init__(self) -> None:
        self.violations: list[PolicyViolation] = []

    def persist(self, violation: PolicyViolation) -> None:
        if type(violation) is not PolicyViolation:
            raise ValueError("trace policy emitted an invalid violation")
        self.violations.append(violation)


def _bind_replay_fd_manifest(
    replay: TracePolicyReplayEvidence, bootstrap_manifest: object
) -> None:
    if not isinstance(bootstrap_manifest, list):
        raise ArtifactBindingError("bootstrap initial FD manifest is invalid")
    bootstrap_fds = {
        (row.get("fd"), row.get("cloexec"))
        for row in bootstrap_manifest
        if isinstance(row, Mapping)
    }
    replay_fds = {
        (row.get("fd"), row.get("cloexec"))
        for row in replay.initial_fd_manifest[replay.coordinator_pid]
    }
    if len(bootstrap_fds) != len(bootstrap_manifest) or bootstrap_fds != replay_fds:
        raise ArtifactBindingError(
            "trace-policy replay FD manifest differs from bootstrap evidence"
        )


def _trace_result_fields(
    records: list[dict[str, object]],
    runtime: TraceRuntimeEvidence,
    marker_token: str,
) -> tuple[dict[str, object], str, int | None, int | None]:
    _validate_trace_record_order(records)
    active_fields = (
        runtime.tracer_identity,
        runtime.normalizer_identity,
        runtime.tracer_exit_code,
        runtime.normalizer_exit_code,
        runtime.tool_policy_row_sha256,
        runtime.compatibility_fixture_passed,
    )
    if runtime.trace_state == "NOT_STARTED":
        if records or any(value is not None for value in active_fields):
            raise ArtifactBindingError(
                "NOT_STARTED trace cannot contain records or process evidence"
            )
        if runtime.not_started_reason not in {
            "TRACE_NOT_STARTED",
            "TRACE_BOOTSTRAP_FAILED",
        }:
            raise ArtifactBindingError("NOT_STARTED trace reason is invalid")
    else:
        if not records or any(value is None for value in active_fields):
            raise ArtifactBindingError(
                "started trace requires records, identities, exits, and tool evidence"
            )
        if runtime.not_started_reason is not None:
            raise ArtifactBindingError("started trace cannot have a not-started reason")
    markers: list[tuple[str, str, int]] = []
    for record in records:
        marker = record.get("marker")
        if marker is None:
            continue
        if (
            type(marker) is not dict
            or set(marker) != {"phase", "token"}
            or marker.get("phase") not in {"BEGIN", "END"}
            or type(marker.get("token")) is not str
        ):
            raise ArtifactBindingError("trace marker is invalid")
        markers.append((marker["phase"], marker["token"], record["record_index"]))
    if not markers:
        window, begin, end = "NOT_ENTERED", None, None
    elif (
        len(markers) == 2
        and markers[0][0] == "BEGIN"
        and markers[1][0] == "END"
        and markers[0][1] == markers[1][1] == marker_token
        and markers[0][2] < markers[1][2]
    ):
        window, begin, end = "CLOSED", markers[0][2], markers[1][2]
    else:
        raise ArtifactBindingError("trace marker sequence is invalid")
    identities = {record["pid"] for record in records if type(record.get("pid")) is int}
    fields = {
        "trace_state": runtime.trace_state,
        "serialized_record_count": len(records),
        "tracee_count": len(identities),
        "tracer_identity": (
            None
            if runtime.tracer_identity is None
            else runtime.tracer_identity.as_dict()
        ),
        "normalizer_identity": (
            None
            if runtime.normalizer_identity is None
            else runtime.normalizer_identity.as_dict()
        ),
        "tracer_exit_code": runtime.tracer_exit_code,
        "normalizer_exit_code": runtime.normalizer_exit_code,
        "tool_policy_row_sha256": runtime.tool_policy_row_sha256,
        "compatibility_fixture_passed": runtime.compatibility_fixture_passed,
        "not_started_reason": runtime.not_started_reason,
    }
    return fields, window, begin, end


def _bootstrap_result_fields(
    value: dict[str, object], *, run_nonce: str, trace_records: list[dict[str, object]]
) -> dict[str, object]:
    expected = {
        "schema_version",
        "terminal_launch_state",
        "coordinator_launch_committed",
        "first_signal",
        "handoff",
        "toolchain",
        "initial_fd_manifest",
        "final_fd_manifest",
        "sanitation_actions",
        "rebinding_actions",
        "live_fixture_passed",
    }
    if (
        set(value) != expected
        or value["schema_version"] != "holoagent0.bootstrap-report.v1"
        or value["terminal_launch_state"] not in _BOOTSTRAP_TERMINAL_STATES
        or type(value["coordinator_launch_committed"]) is not bool
        or value["first_signal"] not in {None, *_SIGNALS}
        or type(value["live_fixture_passed"]) is not bool
    ):
        raise ArtifactBindingError("bootstrap report is not closed")
    committed = value["terminal_launch_state"] == "COORDINATOR_LAUNCH_COMMITTED"
    if value["coordinator_launch_committed"] is not committed:
        raise ArtifactBindingError("bootstrap launch state is inconsistent")
    handoff = _validate_bootstrap_handoff(
        value["handoff"],
        committed,
        run_nonce=run_nonce,
        trace_records=trace_records,
    )
    if (
        handoff["terminal_state"] == "NOT_APPLICABLE"
        and handoff["pending_signal"] != value["first_signal"]
    ):
        raise ArtifactBindingError(
            "non-applicable bootstrap handoff signal differs from bootstrap"
        )
    toolchain = value["toolchain"]
    if type(toolchain) is not dict or set(toolchain) != {"expected", "observed"}:
        raise ArtifactBindingError("bootstrap toolchain report is not closed")
    expected_toolchain = _closed_string_scalar_object(toolchain["expected"])
    observed_toolchain = _closed_string_scalar_object(toolchain["observed"])
    clean_bootstrap = value["terminal_launch_state"] != "NOT_STARTED_BOOTSTRAP_FAILURE"
    if clean_bootstrap and expected_toolchain != observed_toolchain:
        raise ArtifactBindingError("bootstrap observed toolchain differs from pin")
    initial_fds = _validate_fd_manifest(value["initial_fd_manifest"])
    final_fds = _validate_fd_manifest(value["final_fd_manifest"])
    sanitation = _closed_string_list(value["sanitation_actions"], "sanitation")
    rebinding = _closed_string_list(value["rebinding_actions"], "rebinding")
    if clean_bootstrap and not value["live_fixture_passed"]:
        raise ArtifactBindingError("clean bootstrap requires the live fixture")
    return {
        "terminal_launch_state": value["terminal_launch_state"],
        "coordinator_launch_committed": committed,
        "first_signal": value["first_signal"],
        "handoff": handoff,
        "toolchain": {
            "expected": _tool_value_rows(expected_toolchain),
            "observed": _tool_value_rows(observed_toolchain),
        },
        "initial_fd_manifest": initial_fds,
        "final_fd_manifest": final_fds,
        "sanitation_actions": sanitation,
        "rebinding_actions": rebinding,
        "live_fixture_passed": value["live_fixture_passed"],
    }


def _validate_bootstrap_handoff(
    value: object,
    committed: bool,
    *,
    run_nonce: str,
    trace_records: list[dict[str, object]],
) -> dict[str, object]:
    expected = {
        "event_sequence",
        "terminal_state",
        "signal_ready_identity",
        "signal_ready_sequence",
        "signal_ready_sha256",
        "signal_ready_accepted_sequence",
        "signal_ready_accepted_sha256",
        "inherited_mask",
        "unblocked_mask",
        "pending_signal",
        "acceptance_count",
        "forward_target_pgid",
        "forward_count",
        "unblock_trace_record_index",
        "first_functional_trace_record_index",
    }
    if type(value) is not dict or set(value) != expected:
        raise ArtifactBindingError("bootstrap handoff is not closed")
    events = value["event_sequence"]
    if type(events) is not list or len(events) > 64:
        raise ArtifactBindingError("bootstrap handoff event sequence is invalid")
    normalized_events = []
    for index, event in enumerate(events):
        if (
            type(event) is not dict
            or set(event) != {"sequence", "state"}
            or event["sequence"] != index
            or event["state"] not in _HANDOFF_STATES
        ):
            raise ArtifactBindingError("bootstrap handoff event is invalid")
        normalized_events.append(copy.deepcopy(event))
    inherited = _closed_signal_mask(value["inherited_mask"])
    unblocked = _closed_signal_mask(value["unblocked_mask"])
    if inherited != list(_SIGNALS):
        raise ArtifactBindingError("bootstrap inherited signal mask is invalid")
    if value["pending_signal"] not in {None, *_SIGNALS}:
        raise ArtifactBindingError("bootstrap pending signal is invalid")
    acceptance = value["acceptance_count"]
    forward = value["forward_count"]
    if acceptance not in {0, 1} or forward not in {0, 1}:
        raise ArtifactBindingError("bootstrap handoff counts are invalid")
    if value["forward_target_pgid"] is not None and (
        type(value["forward_target_pgid"]) is not int
        or value["forward_target_pgid"] <= 0
    ):
        raise ArtifactBindingError("bootstrap forward PGID is invalid")
    identity = value["signal_ready_identity"]
    if identity is not None:
        try:
            identity = ProcessIdentity.from_dict(identity).as_dict()
        except ProcessIdentityError as error:
            raise ArtifactBindingError("bootstrap ready identity is invalid") from error
    nullable_sequences = (
        value["signal_ready_sequence"],
        value["signal_ready_accepted_sequence"],
    )
    if any(
        item is not None and (type(item) is not int or item < 0)
        for item in nullable_sequences
    ) or any(
        item is not None and not _is_sha256(item)
        for item in (
            value["signal_ready_sha256"],
            value["signal_ready_accepted_sha256"],
        )
    ):
        raise ArtifactBindingError("bootstrap handoff sequence/digest is invalid")
    unblock_index = value["unblock_trace_record_index"]
    functional_index = value["first_functional_trace_record_index"]
    if any(
        item is not None
        and (type(item) is not int or item < 0 or item >= len(trace_records))
        for item in (unblock_index, functional_index)
    ):
        raise ArtifactBindingError("bootstrap handoff trace index is invalid")
    if committed and value["terminal_state"] == "READY":
        states = [event["state"] for event in normalized_events]
        allowed_states = {
            ("AWAITING_READY", "AWAITING_ACCEPTANCE", "READY"),
            (
                "AWAITING_READY",
                "AWAITING_ACCEPTANCE",
                "PENDING_FORWARD",
                "READY",
            ),
        }
        if (
            unblock_index is not None
            and functional_index is not None
            and unblock_index >= functional_index
        ):
            raise ArtifactBindingError(
                "bootstrap handoff trace functional ordering is invalid"
            )
        if (
            value["terminal_state"] != "READY"
            or tuple(states) not in allowed_states
            or ("PENDING_FORWARD" in states and value["pending_signal"] is None)
            or identity is None
            or any(item is None for item in nullable_sequences)
            or not _is_sha256(value["signal_ready_sha256"])
            or not _is_sha256(value["signal_ready_accepted_sha256"])
            or acceptance != 1
            or unblocked != list(_SIGNALS)
            or unblock_index is None
            or (functional_index is None and value["pending_signal"] is None)
            or (value["pending_signal"] is not None and forward != 1)
        ):
            raise ArtifactBindingError("committed bootstrap handoff is incomplete")
        unblock_record = trace_records[unblock_index]
        if (
            unblock_record.get("pid") != identity["pid"]
            or unblock_record.get("syscall") != "rt_sigprocmask"
            or unblock_record.get("result", {}).get("value") != 0
            or (
                functional_index is not None
                and trace_records[functional_index].get("pid") != identity["pid"]
            )
        ):
            raise ArtifactBindingError(
                "bootstrap handoff trace unblock/functional records are invalid"
            )
        expected_request_sha256, expected_acceptance_sha256 = _handoff_message_digests(
            run_nonce=run_nonce,
            sequence=value["signal_ready_sequence"],
            identity=identity,
            inherited=inherited,
        )
        if (
            value["signal_ready_accepted_sequence"] != value["signal_ready_sequence"]
            or value["signal_ready_sha256"] != expected_request_sha256
            or value["signal_ready_accepted_sha256"] != expected_acceptance_sha256
            or (forward == 1 and value["forward_target_pgid"] != identity["pgid"])
            or (forward == 0 and value["forward_target_pgid"] is not None)
            or (forward == 1 and value["pending_signal"] is None)
        ):
            raise ArtifactBindingError(
                "committed bootstrap handoff request/acceptance binding is invalid"
            )
    elif committed and value["terminal_state"] == "FAILED":
        states = [event["state"] for event in normalized_events]
        allowed_states = {
            ("AWAITING_READY", "FAILED"),
            ("AWAITING_READY", "PENDING_FORWARD", "FAILED"),
            ("AWAITING_READY", "AWAITING_ACCEPTANCE", "FAILED"),
            (
                "AWAITING_READY",
                "AWAITING_ACCEPTANCE",
                "PENDING_FORWARD",
                "FAILED",
            ),
        }
        if tuple(states) not in allowed_states or (
            "PENDING_FORWARD" in states and value["pending_signal"] is None
        ):
            raise ArtifactBindingError("failed bootstrap handoff history is invalid")
        if acceptance == 0:
            request_items = (
                identity,
                value["signal_ready_sequence"],
                value["signal_ready_sha256"],
            )
            request_present = all(item is not None for item in request_items)
            awaiting_acceptance = "AWAITING_ACCEPTANCE" in states
            if (
                value["signal_ready_accepted_sequence"] is not None
                or value["signal_ready_accepted_sha256"] is not None
                or unblocked
                or forward
                or value["forward_target_pgid"] is not None
                or unblock_index is not None
                or functional_index is not None
                or request_present != awaiting_acceptance
                or (
                    not request_present
                    and any(item is not None for item in request_items)
                )
                or (
                    value["pending_signal"] is not None
                    and "PENDING_FORWARD" not in states
                )
            ):
                raise ArtifactBindingError(
                    "failed unaccepted handoff request/activity is inconsistent"
                )
            if request_present:
                expected_request_sha256, _expected_acceptance_sha256 = (
                    _handoff_message_digests(
                        run_nonce=run_nonce,
                        sequence=value["signal_ready_sequence"],
                        identity=identity,
                        inherited=inherited,
                    )
                )
                if value["signal_ready_sha256"] != expected_request_sha256:
                    raise ArtifactBindingError(
                        "failed unaccepted handoff request digest is invalid"
                    )
        if acceptance == 1:
            if (
                identity is None
                or "AWAITING_ACCEPTANCE" not in states
                or value["signal_ready_sequence"] is None
                or value["signal_ready_accepted_sequence"]
                != value["signal_ready_sequence"]
                or not _is_sha256(value["signal_ready_sha256"])
                or not _is_sha256(value["signal_ready_accepted_sha256"])
            ):
                raise ArtifactBindingError(
                    "failed accepted handoff binding is incomplete"
                )
            expected_request_sha256, expected_acceptance_sha256 = (
                _handoff_message_digests(
                    run_nonce=run_nonce,
                    sequence=value["signal_ready_sequence"],
                    identity=identity,
                    inherited=inherited,
                )
            )
            unblock_is_bound = (
                unblocked == list(_SIGNALS)
                and unblock_index is not None
                and trace_records[unblock_index].get("pid") == identity["pid"]
                and trace_records[unblock_index].get("syscall") == "rt_sigprocmask"
                and trace_records[unblock_index].get("result", {}).get("value") == 0
            )
            remained_blocked = (
                not unblocked and unblock_index is None and functional_index is None
            )
            if (
                value["signal_ready_sha256"] != expected_request_sha256
                or value["signal_ready_accepted_sha256"] != expected_acceptance_sha256
                or not (unblock_is_bound or remained_blocked)
                or (
                    functional_index is not None
                    and (
                        unblock_index is None
                        or unblock_index >= functional_index
                        or trace_records[functional_index].get("pid") != identity["pid"]
                    )
                )
                or (
                    forward == 1
                    and (
                        value["pending_signal"] is None
                        or value["forward_target_pgid"] != identity["pgid"]
                    )
                )
                or (forward == 0 and value["forward_target_pgid"] is not None)
            ):
                raise ArtifactBindingError(
                    "failed accepted handoff request/acceptance binding is invalid"
                )
    elif value["terminal_state"] == "NOT_APPLICABLE":
        if (
            normalized_events
            or identity is not None
            or any(item is not None for item in nullable_sequences)
            or value["signal_ready_sha256"] is not None
            or value["signal_ready_accepted_sha256"] is not None
            or acceptance
            or unblocked
            or forward
            or value["forward_target_pgid"] is not None
            or unblock_index is not None
            or functional_index is not None
        ):
            raise ArtifactBindingError("non-applicable bootstrap handoff has activity")
    elif value["terminal_state"] != "FAILED":
        raise ArtifactBindingError("bootstrap handoff terminal state is invalid")
    return {
        **copy.deepcopy(value),
        "event_sequence": normalized_events,
        "signal_ready_identity": identity,
        "inherited_mask": inherited,
        "unblocked_mask": unblocked,
    }


def _handoff_message_digests(
    *,
    run_nonce: str,
    sequence: int,
    identity: dict[str, object],
    inherited: list[str],
) -> tuple[str, str]:
    request = {
        "type": "SIGNAL_READY",
        "run_nonce": run_nonce,
        "sequence": sequence,
        "identity": identity,
        "blocked_signals": inherited,
        "dispositions": {signal_name: True for signal_name in _SIGNALS},
    }
    request_sha256 = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
    acceptance_message = {
        "type": "SIGNAL_READY_ACCEPTED",
        "run_nonce": run_nonce,
        "identity": identity,
        "request_sequence": sequence,
        "request_sha256": request_sha256,
    }
    return request_sha256, hashlib.sha256(
        canonical_json_bytes(acceptance_message)
    ).hexdigest()


def _observer_result_fields(
    value: dict[str, object], expected_identity: ProcessIdentity
) -> dict[str, object]:
    expected = {
        "state",
        "collector_identity",
        "network_namespace_inode",
        "observed_processes",
        "observed_services",
        "observed_listeners",
        "internet_socket_attempts",
        "trusted_inspection",
        "cause_gate",
        "reason",
    }
    if set(value) != expected or value["state"] not in {"OBSERVED", "NOT_RUN"}:
        raise ArtifactBindingError("host observer object is not closed")
    inventories = {}
    for key in (
        "observed_processes",
        "observed_services",
        "observed_listeners",
        "internet_socket_attempts",
    ):
        inventories[key] = _require_observer_inventory(value[key])
    if value["state"] == "OBSERVED":
        try:
            collector = ProcessIdentity.from_dict(value["collector_identity"])
        except ProcessIdentityError as error:
            raise ArtifactBindingError("host observer identity is invalid") from error
        if collector != expected_identity:
            raise ArtifactBindingError("host observer identity differs from pin")
        if (
            type(value["network_namespace_inode"]) is not int
            or value["network_namespace_inode"] <= 0
            or value["cause_gate"] is not None
            or value["reason"] is not None
        ):
            raise ArtifactBindingError("OBSERVED host observer is invalid")
        if inventories["internet_socket_attempts"]:
            raise ArtifactBindingError("host observer contains a socket attempt")
        inspection = _normalize_trusted_host_inspection(
            value["trusted_inspection"],
            observed_listeners=inventories["observed_listeners"],
        )
    elif (
        value["collector_identity"] is not None
        or value["network_namespace_inode"] is not None
        or any(inventories[key] for key in inventories)
        or value["trusted_inspection"] is not None
        or type(value["cause_gate"]) is not str
        or not value["cause_gate"]
        or (
            (value["cause_gate"], value["reason"])
            not in {
                (
                    "safety.workstation_preflight",
                    "EARLIER_BLOCKING_GATE",
                ),
                (
                    "safety.workstation_preflight",
                    "INTERRUPTED_BEFORE_GATE",
                ),
                (
                    "safety.workstation_postflight",
                    "POSTFLIGHT_FAILED",
                ),
            }
        )
    ):
        raise ArtifactBindingError("NOT_RUN host observer is invalid")
    else:
        inspection = None
    observation = {
        "state": value["state"],
        "collector_identity": value["collector_identity"],
        "network_namespace_inode": value["network_namespace_inode"],
        **inventories,
        "trusted_inspection": inspection,
        "cause_gate": value["cause_gate"],
        "reason": value["reason"],
    }
    return {
        "state": value["state"],
        "collector_identity": value["collector_identity"],
        "network_namespace_inode": value["network_namespace_inode"],
        "process_count": len(inventories["observed_processes"]),
        "service_count": len(inventories["observed_services"]),
        "listener_count": len(inventories["observed_listeners"]),
        "internet_socket_attempt_count": len(inventories["internet_socket_attempts"]),
        "observation_sha256": hashlib.sha256(
            canonical_json_bytes(observation)
        ).hexdigest(),
        "trusted_inspection": inspection,
        "cause_gate": value["cause_gate"],
        "reason": value["reason"],
    }


def _normalize_trusted_host_inspection(
    value: object, *, observed_listeners: list[str]
) -> dict[str, object]:
    expected = {
        "gateway_status_command",
        "gateway_status_exit",
        "gateway_status_sha256",
        "gateway_status_state",
        "service_definitions",
        "listener_command",
        "listener_inventory",
    }
    if type(value) is not dict or set(value) != expected:
        raise ArtifactBindingError("trusted host inspection object is not closed")
    gateway_command = _closed_command(value["gateway_status_command"], maximum_items=16)
    listener_command = _closed_command(value["listener_command"], maximum_items=8)
    service_definitions = _require_observer_inventory(value["service_definitions"])
    listener_inventory = _require_observer_inventory(value["listener_inventory"])
    if (
        len(gateway_command) != 6
        or not gateway_command[0].startswith("/")
        or gateway_command[1:]
        != ["gateway", "status", "--deep", "--no-probe", "--json"]
        or value["gateway_status_exit"] != 0
        or not _is_sha256(value["gateway_status_sha256"])
        or value["gateway_status_state"] not in {"INACTIVE", "ACTIVE"}
        or len(listener_command) != 3
        or not listener_command[0].startswith("/")
        or listener_command[1:] != ["-H", "-ltnp"]
        or listener_inventory != observed_listeners
    ):
        raise ArtifactBindingError("trusted host inspection evidence is invalid")
    return {
        "gateway_status_command": gateway_command,
        "gateway_status_exit": value["gateway_status_exit"],
        "gateway_status_sha256": value["gateway_status_sha256"],
        "gateway_status_state": value["gateway_status_state"],
        "service_definitions": service_definitions,
        "listener_command": listener_command,
        "listener_inventory": listener_inventory,
    }


def _closed_command(value: object, *, maximum_items: int) -> list[str]:
    if (
        type(value) not in {tuple, list}
        or not value
        or len(value) > maximum_items
        or any(
            type(item) is not str
            or not item
            or len(item.encode("utf-8")) > _MAX_OBSERVER_ITEM_BYTES
            for item in value
        )
    ):
        raise ArtifactBindingError("trusted host inspection command is invalid")
    return list(value)


def _validate_ledger_chain(
    manifest: dict[str, object],
    run_root: Path,
    root_fd: int,
    context: EvidenceContext,
    secret_sentinels: frozenset[str],
) -> tuple[dict[str, object], str, dict[str, tuple[BoundArtifact, int]]]:
    expected_keys = {
        "schema_version",
        "accepted_generation",
        "accepted_sha256",
        "generation_count",
        "generations",
    }
    if set(manifest) != expected_keys or manifest["schema_version"] != (
        "holoagent0.ledger-chain-manifest.v1"
    ):
        raise ArtifactBindingError("ledger chain manifest is not closed")
    accepted = manifest["accepted_generation"]
    count = manifest["generation_count"]
    generations = manifest["generations"]
    if (
        type(accepted) is not int
        or accepted < 0
        or type(count) is not int
        or count != accepted + 1
        or type(generations) is not list
        or len(generations) != count
        or not _is_sha256(manifest["accepted_sha256"])
    ):
        raise ArtifactBindingError("ledger accepted generation/count is invalid")
    ledger_root = run_root / "ledger"
    try:
        root_stat = os.stat(ledger_root, follow_symlinks=False)
    except OSError as error:
        raise ArtifactBindingError("ledger root is unavailable") from error
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != 0o700
    ):
        raise ArtifactBindingError("ledger root owner/type/mode is invalid")
    expected_names = {f"generation-{index:06d}.json" for index in range(count)}
    if {path.name for path in ledger_root.iterdir()} != expected_names:
        raise ArtifactBindingError("ledger generation inventory is not exact")
    retained: dict[str, tuple[BoundArtifact, int]] = {}
    previous_digest: str | None = None
    previous_document: dict[str, object] | None = None
    final_window = ""
    try:
        for index, entry in enumerate(generations):
            if type(entry) is not dict or set(entry) != {
                "generation",
                "relative_path",
                "sha256",
                "size",
                "previous_generation",
                "previous_digest",
                "sealed",
            }:
                raise ArtifactBindingError("ledger manifest entry is not closed")
            relative = f"ledger/generation-{index:06d}.json"
            if (
                entry["generation"] != index
                or entry["relative_path"] != relative
                or entry["previous_generation"] != (None if index == 0 else index - 1)
                or entry["previous_digest"] != previous_digest
                or type(entry["sealed"]) is not bool
                or entry["sealed"] != (index == accepted)
            ):
                raise ArtifactBindingError(
                    "ledger manifest predecessor/seal is invalid"
                )
            artifact, fd = _bind_one(
                run_root / relative,
                run_root,
                root_fd=root_fd,
                expected_mode=0o400,
                secret_sentinels=secret_sentinels,
                domain="ledger_generation",
            )
            retained[f"ledger-generation:{index}"] = (artifact, fd)
            if entry["sha256"] != artifact.sha256 or entry["size"] != artifact.size:
                raise ArtifactBindingError("ledger manifest descriptor mismatch")
            document = _parse_json_object(_read_retained_bytes(fd), "ledger generation")
            decision = context.ledger_contract.validate_document(
                "holoagent0-offline-ledger-v1", document
            )
            if not decision.ok:
                raise ArtifactBindingError("ledger generation schema is invalid")
            if (
                document["generation"] != index
                or document["previous_generation"] != entry["previous_generation"]
                or document["previous_digest"] != entry["previous_digest"]
                or document["sealed"] != entry["sealed"]
                or document["run_id"] != context.expected_run_id
                or document["ledger_nonce"] != context.expected_ledger_nonce
            ):
                raise ArtifactBindingError("ledger generation lineage is invalid")
            if index == 0:
                expected_genesis = _build_generation_zero(
                    context.expected_run_id,
                    context.expected_ledger_nonce,
                    context.ledger_contract,
                )
                if document != expected_genesis:
                    raise ArtifactBindingError(
                        "ledger generation zero differs from the canonical genesis"
                    )
            else:
                assert previous_document is not None
                assert previous_digest is not None
                _replay_ledger_transition(
                    previous_document,
                    previous_digest,
                    document,
                    context,
                )
            previous_digest = artifact.sha256
            previous_document = document
            final_window = document["semantic_dds_window"]
        if previous_digest != manifest["accepted_sha256"]:
            raise ArtifactBindingError("ledger accepted digest is invalid")
        accepted_action_state_sha256 = hashlib.sha256(
            canonical_json_bytes(
                {
                    # Gates 25--27 are supervisor-owned finalizers and do not
                    # exist in the coordinator's accepted action state.  Bind
                    # exactly gates 1--24 plus the terminal DDS window so the
                    # later result can add finalizer decisions without making
                    # its accepted-ledger digest self-contradictory.
                    "gates": previous_document["gates"][:24],
                    "semantic_dds_window": previous_document["semantic_dds_window"],
                }
            )
        ).hexdigest()
        return (
            {
                "accepted_generation": accepted,
                "accepted_sha256": manifest["accepted_sha256"],
                "immutable_generation_count": count,
                "accepted_action_state_sha256": accepted_action_state_sha256,
            },
            final_window,
            retained,
        )
    except BaseException:
        for _artifact, fd in retained.values():
            _close_no_throw(fd)
        raise


def _bind_scan_target(
    path: Path, secret_sentinels: frozenset[str]
) -> tuple[BoundArtifact, int]:
    path = Path(path)
    parent_fd = -1
    try:
        absolute = Path(os.path.abspath(path))
        parent_fd = _open_absolute_directory(absolute.parent)
        before = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise ArtifactBindingError("secret scan target owner/type is invalid")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(absolute.name, flags, dir_fd=parent_fd)
        observed = _describe_retained(
            fd,
            absolute.as_posix(),
            stat.S_IMODE(before.st_mode),
            secret_sentinels=secret_sentinels,
            domain="secret_scan",
        )
        after = os.stat(absolute.name, dir_fd=parent_fd, follow_symlinks=False)
        if (after.st_dev, after.st_ino) != (observed.device, observed.inode):
            raise ArtifactBindingError("secret scan path binding changed")
        return observed, fd
    except BaseException:
        if "fd" in locals():
            _close_no_throw(fd)
        raise
    finally:
        _close_no_throw(parent_fd)


def _replay_ledger_transition(
    previous: Mapping[str, object],
    previous_digest: str,
    candidate_document: Mapping[str, object],
    context: EvidenceContext,
) -> None:
    """Run the production LedgerStore transition validator without publishing."""

    candidate = LedgerCandidate(
        generation=candidate_document["generation"],
        previous_generation=candidate_document["previous_generation"],
        previous_digest=candidate_document["previous_digest"],
        run_id=candidate_document["run_id"],
        ledger_nonce=candidate_document["ledger_nonce"],
        gates=candidate_document["gates"],
        sealed=candidate_document["sealed"],
        semantic_dds_window=candidate_document["semantic_dds_window"],
    )
    replay = object.__new__(LedgerStore)
    replay._lock = RLock()
    replay.contract = context.ledger_contract
    replay.run_id = context.expected_run_id
    replay.run_nonce = context.expected_ledger_nonce
    replay._head = LedgerHead(
        previous["generation"], previous_digest, previous["sealed"]
    )
    replay._current = copy.deepcopy(dict(previous))
    try:
        replay._validate_successor(candidate, candidate_document["gates"])
    except LedgerChainError as error:
        raise ArtifactBindingError(
            f"ledger transition is not monotonic: {error}"
        ) from error


def _snapshot_rows_sha256(rows: Iterable[Mapping[str, object]]) -> str:
    """Hash an ordered snapshot inventory without a collection-size loophole."""

    digest = hashlib.sha256(b"HOLOAGENT0_SNAPSHOT_ROWS_V1\0")
    count = 0
    for row in rows:
        encoded = canonical_json_bytes(dict(row))
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        count += 1
    digest.update(count.to_bytes(8, "big"))
    return digest.hexdigest()


def _require_no_secret(data: bytes, sentinels: frozenset[str]) -> None:
    if not sentinels:
        return
    encoded_sentinels = tuple(sentinel.encode("utf-8") for sentinel in sentinels)
    if any(sentinel in data for sentinel in encoded_sentinels):
        raise ArtifactBindingError("secret sentinel found in artifact")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        # Tracked repositories legitimately include binary assets.  Ignore
        # undecodable bytes while preserving all ASCII reversible encodings;
        # the raw-byte check above covers an exact sentinel spanning them.
        text = data.decode("utf-8", errors="ignore")
    candidates = _decoded_secret_candidates(text)
    if any(sentinel in candidate for sentinel in sentinels for candidate in candidates):
        raise ArtifactBindingError("secret sentinel found in artifact")
    semantic_values: list[object] = []
    try:
        semantic_values.append(json.loads(text))
    except json.JSONDecodeError:
        for line in text.splitlines():
            try:
                semantic_values.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if any(_contains_secret_value(value, sentinels) for value in semantic_values):
        raise ArtifactBindingError("secret sentinel found in artifact")


def _decoded_secret_candidates(text: str) -> frozenset[str]:
    """Return bounded reversible encodings that may conceal a reviewed sentinel."""

    candidates = {text}
    frontier = {text}
    for _round in range(3):
        next_frontier: set[str] = set()
        for value in frontier:
            transforms = {
                html.unescape(value),
                unquote(value),
                unquote_plus(value),
                re.sub(
                    r"\\u([0-9a-fA-F]{4})",
                    lambda match: chr(int(match.group(1), 16)),
                    value,
                ),
                re.sub(
                    r"\\x([0-9a-fA-F]{2})",
                    lambda match: chr(int(match.group(1), 16)),
                    value,
                ),
            }
            for token in re.findall(
                r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{8,}={0,2}", value
            ):
                padded = token + "=" * ((4 - len(token) % 4) % 4)
                for decoder in (base64.b64decode, base64.urlsafe_b64decode):
                    try:
                        decoded = decoder(padded.encode()).decode("utf-8", "strict")
                    except (binascii.Error, UnicodeError, ValueError):
                        continue
                    transforms.add(decoded)
            for token in re.findall(
                r"(?<![0-9a-fA-F])[0-9a-fA-F]{8,}(?![0-9a-fA-F])", value
            ):
                if len(token) % 2:
                    continue
                try:
                    transforms.add(bytes.fromhex(token).decode("utf-8", "strict"))
                except (UnicodeError, ValueError):
                    pass
            for transformed in transforms:
                if (
                    transformed not in candidates
                    and len(transformed) <= _MAX_ARTIFACT_BYTES
                ):
                    candidates.add(transformed)
                    next_frontier.add(transformed)
        frontier = next_frontier
        if not frontier:
            break
    return frozenset(candidates)


def _secret_scan_inventory(
    run_root: Path, context: EvidenceContext
) -> tuple[tuple[str, Path], ...]:
    if not context.tracked_paths:
        raise ArtifactBindingError("tracked secret-scan root inventory is empty")
    collected: dict[Path, str] = {}

    def collect(kind: str, root: Path, *, logs_only: bool) -> None:
        absolute = Path(os.path.abspath(root))
        paths = _safe_regular_file_inventory(absolute)
        for path in paths:
            if logs_only and path.suffix.lower() not in {".log", ".out", ".err"}:
                continue
            collected.setdefault(path, kind)

    # Every pre-existing regular file in the run root is part of the immutable
    # publication boundary.  Core and ledger artifacts are already retained;
    # this inventory closes over all remaining support files as well.
    collect("run", run_root, logs_only=False)
    for path in context.log_paths:
        collect("log", path, logs_only=False)
    for path in context.tracked_paths:
        collect("tracked", path, logs_only=False)
    if not any(kind == "tracked" for kind in collected.values()):
        raise ArtifactBindingError("tracked secret-scan inventory is empty")
    return tuple((kind, path) for path, kind in sorted(collected.items()))


def _tracked_symlink_inventory(
    context: EvidenceContext,
    secret_sentinels: frozenset[str],
) -> tuple[tuple[Path, int, int, bytes, str], ...]:
    """Verify and retain the exact reviewed Git-symlink identity set."""

    inventory: list[tuple[Path, int, int, bytes, str]] = []
    for configured_path, expected_oid in context.tracked_symlinks:
        path = Path(os.path.abspath(configured_path))
        try:
            before = path.lstat()
            if not stat.S_ISLNK(before.st_mode) or before.st_uid != os.getuid():
                raise ArtifactBindingError("tracked symlink owner/type is invalid")
            target = os.readlink(os.fsencode(path))
            after = path.lstat()
        except ArtifactBindingError:
            raise
        except OSError as error:
            raise ArtifactBindingError("tracked symlink is unavailable") from error
        if (
            not stat.S_ISLNK(after.st_mode)
            or after.st_uid != os.getuid()
            or (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_size,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_uid,
                after.st_size,
            )
        ):
            raise ArtifactBindingError("tracked symlink changed during inspection")
        header = f"blob {len(target)}\0".encode("ascii")
        if hashlib.sha1(header + target).hexdigest() != expected_oid:
            raise ArtifactBindingError("tracked symlink Git blob is invalid")
        _require_no_secret(target, secret_sentinels)
        inventory.append((path, before.st_dev, before.st_ino, target, expected_oid))
    return tuple(inventory)


def _safe_regular_file_inventory(root: Path) -> tuple[Path, ...]:
    parent_fd = _open_absolute_directory(root.parent)
    try:
        observed = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        if observed.st_uid != os.getuid() or stat.S_ISLNK(observed.st_mode):
            raise ArtifactBindingError("secret scan root owner/type is invalid")
        if stat.S_ISREG(observed.st_mode):
            return (root,)
        if not stat.S_ISDIR(observed.st_mode):
            raise ArtifactBindingError("secret scan root type is invalid")
        root_fd = os.open(
            root.name,
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        try:
            return tuple(
                root / relative for relative in _walk_regular_files_fd(root_fd)
            )
        finally:
            _close_no_throw(root_fd)
    except OSError as error:
        raise ArtifactBindingError("secret scan root is unavailable") from error
    finally:
        _close_no_throw(parent_fd)


def _walk_regular_files_fd(directory_fd: int, prefix: str = "") -> list[str]:
    files: list[str] = []
    for name in sorted(os.listdir(directory_fd)):
        relative = name if not prefix else f"{prefix}/{name}"
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != os.getuid():
            raise ArtifactBindingError("secret scan inventory contains a symlink")
        if stat.S_ISREG(observed.st_mode):
            files.append(relative)
        elif stat.S_ISDIR(observed.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                files.extend(_walk_regular_files_fd(child_fd, relative))
            finally:
                _close_no_throw(child_fd)
        else:
            raise ArtifactBindingError("secret scan inventory type is invalid")
    return files


def _run_tree_inventory(run_root_fd: int) -> tuple[str, ...]:
    try:
        return tuple(_walk_directory_fd(run_root_fd))
    except OSError as error:
        raise ArtifactBindingError("run artifact inventory is unavailable") from error


def _walk_directory_fd(directory_fd: int, prefix: str = "") -> list[str]:
    inventory: list[str] = []
    for name in sorted(os.listdir(directory_fd)):
        if name in {".", ".."} or "/" in name:
            raise ArtifactBindingError("run artifact inventory name is invalid")
        relative = name if not prefix else f"{prefix}/{name}"
        observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != os.getuid():
            raise ArtifactBindingError("run artifact inventory contains a symlink")
        if stat.S_ISDIR(observed.st_mode):
            child_fd = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_fd,
            )
            try:
                inventory.append(relative)
                inventory.extend(_walk_directory_fd(child_fd, relative))
            finally:
                _close_no_throw(child_fd)
        elif stat.S_ISREG(observed.st_mode):
            inventory.append(relative)
        else:
            raise ArtifactBindingError("run artifact inventory type is invalid")
    return inventory


def _is_configured_publication_temporary(
    relative: str, context: EvidenceContext, run_root: Path
) -> bool:
    for path in context.publication_paths:
        absolute = Path(os.path.abspath(path))
        try:
            candidate = absolute.relative_to(run_root).as_posix()
        except ValueError as error:
            raise ArtifactBindingError(
                "publication path escapes the run root"
            ) from error
        parent = Path(candidate).parent.as_posix()
        prefix = f".{Path(candidate).name}.tmp-"
        observed = Path(relative)
        if observed.parent.as_posix() == parent and observed.name.startswith(prefix):
            return True
    return False


def _require_observer_inventory(value: object) -> list[str]:
    if (
        type(value) not in {tuple, list}
        or len(value) > _MAX_OBSERVER_ITEMS
        or any(
            type(item) is not str
            or not item
            or len(item.encode("utf-8")) > _MAX_OBSERVER_ITEM_BYTES
            for item in value
        )
    ):
        raise ArtifactBindingError("host observer inventory is invalid")
    normalized = list(value)
    if normalized != sorted(set(normalized)):
        raise ArtifactBindingError("host observer inventory is not sorted and unique")
    return normalized


def _closed_signal_mask(value: object) -> list[str]:
    if type(value) is not list or any(signal not in _SIGNALS for signal in value):
        raise ArtifactBindingError("bootstrap signal mask is invalid")
    if value != [signal for signal in _SIGNALS if signal in value]:
        raise ArtifactBindingError("bootstrap signal mask order is invalid")
    return list(value)


def _closed_string_list(value: object, description: str) -> list[str]:
    if (
        type(value) is not list
        or len(value) > 4096
        or any(type(item) is not str or not item or len(item) > 4096 for item in value)
    ):
        raise ArtifactBindingError(f"bootstrap {description} actions are invalid")
    return list(value)


def _closed_string_scalar_object(value: object) -> dict[str, object]:
    if type(value) is not dict or len(value) > 128:
        raise ArtifactBindingError("bootstrap toolchain values are invalid")
    if any(
        type(key) is not str
        or not key
        or (item is not None and type(item) not in {str, int, bool})
        for key, item in value.items()
    ):
        raise ArtifactBindingError("bootstrap toolchain values are invalid")
    return copy.deepcopy(value)


def _tool_value_rows(value: Mapping[str, object]) -> list[dict[str, object]]:
    return [
        {"name": name, "value": copy.deepcopy(value[name])} for name in sorted(value)
    ]


def _validate_fd_manifest(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) > 4096:
        raise ArtifactBindingError("bootstrap FD manifest is invalid")
    result = []
    previous = -1
    for item in value:
        if (
            type(item) is not dict
            or set(item) != {"fd", "target", "cloexec"}
            or type(item["fd"]) is not int
            or item["fd"] < 0
            or item["fd"] <= previous
            or type(item["target"]) is not str
            or not item["target"]
            or len(item["target"]) > 4096
            or type(item["cloexec"]) is not bool
        ):
            raise ArtifactBindingError("bootstrap FD manifest is invalid")
        result.append(copy.deepcopy(item))
        previous = item["fd"]
    return result


def _contains_secret_value(value: object, sentinels: frozenset[str]) -> bool:
    if type(value) is str:
        return any(sentinel in value for sentinel in sentinels)
    if type(value) is list:
        return any(_contains_secret_value(child, sentinels) for child in value)
    if type(value) is dict:
        return any(
            _contains_secret_value(key, sentinels)
            or _contains_secret_value(child, sentinels)
            for key, child in value.items()
        )
    return False


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _stable_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("zero-length journal write")
        view = view[written:]


def _close_no_throw(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _fsync_directory(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = -1
    try:
        directory_fd = os.open(path, flags)
        directory_stat = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise ArtifactBindingError("artifact parent is not a directory")
        os.fsync(directory_fd)
    except OSError as error:
        raise ArtifactBindingError("artifact directory fsync failed") from error
    finally:
        if directory_fd >= 0:
            _close_no_throw(directory_fd)


def _contains_any_secret(value: object, sentinels: frozenset[str]) -> bool:
    if not sentinels:
        return False
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise ArtifactBindingError("journal payload is not canonical JSON") from error
    return any(sentinel.encode("utf-8") in encoded for sentinel in sentinels)


def _optional_domain(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        domain = int(value)
    except ValueError as error:
        raise ArtifactBindingError("ROS_DOMAIN_ID is invalid") from error
    if not 0 <= domain <= 232:
        raise ArtifactBindingError("ROS_DOMAIN_ID is invalid")
    return domain


def _optional_boolean(value: str | None) -> bool | None:
    if value is None:
        return None
    if value == "1":
        return True
    if value == "0":
        return False
    raise ArtifactBindingError("ROS_LOCALHOST_ONLY is invalid")
