"""Immutable acknowledged ledger generations for the offline supervisor."""

from __future__ import annotations

import copy
import ctypes
from dataclasses import dataclass
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Mapping, Sequence

from .atomic_io import (
    ArtifactDescriptor,
    AtomicIOError,
    AtomicPublicationAmbiguity,
    atomic_write_json_no_replace,
    read_json_secure,
)
from .constants import OFFLINE_GATE_ORDER
from .contract import ContractSet


_NONCE = re.compile(r"^[0-9a-f]{64}$")


class LedgerChainError(ValueError):
    """A ledger candidate violates schema, continuity, or immutability."""


class _DirectoryPublicationAmbiguity(OSError):
    """The staging directory was renamed before a post-rename check failed."""


@dataclass(frozen=True)
class LedgerHead:
    generation: int
    digest: str
    sealed: bool


@dataclass(frozen=True)
class LedgerCandidate:
    generation: int
    previous_generation: int
    previous_digest: str
    run_id: str
    ledger_nonce: str
    gates: Sequence[Mapping[str, object]]
    sealed: bool = False
    semantic_dds_window: str = "NOT_ENTERED"

    def as_json(self) -> dict[str, object]:
        return {
            "schema_version": "holoagent0.offline-ledger.v1",
            "run_id": self.run_id,
            "ledger_nonce": self.ledger_nonce,
            "generation": self.generation,
            "previous_generation": self.previous_generation,
            "previous_digest": self.previous_digest,
            "sealed": self.sealed,
            "semantic_dds_window": self.semantic_dds_window,
            "gates": copy.deepcopy(list(self.gates)),
        }


@dataclass(frozen=True)
class _PendingPublication:
    generation: int
    value: Mapping[str, object]
    descriptor: ArtifactDescriptor


class LedgerStore:
    """Supervisor-owned no-replace ledger with acknowledged head continuity."""

    def __init__(
        self,
        root: Path,
        contract: ContractSet,
        run_id: str,
        run_nonce: str,
        head: LedgerHead,
        current: Mapping[str, object],
        root_identity: tuple[int, int],
        descriptors: Sequence[ArtifactDescriptor],
        root_fd: int,
    ) -> None:
        self._lock = threading.RLock()
        self.root = root
        self.contract = contract
        self.run_id = run_id
        self.run_nonce = run_nonce
        self.head = head
        self._current = copy.deepcopy(dict(current))
        self._root_identity = root_identity
        self._descriptors = tuple(descriptors)
        self._root_fd = root_fd
        self._pending_publication: _PendingPublication | None = None

    @property
    def head(self) -> LedgerHead:
        """Return the acknowledged head while excluding concurrent publication."""

        with self._lock:
            return self._head

    @head.setter
    def head(self, value: LedgerHead) -> None:
        with self._lock:
            self._head = value

    @property
    def current(self) -> dict[str, object]:
        """Return a defensive snapshot of the acknowledged head document."""

        with self._lock:
            return copy.deepcopy(self._current)

    @classmethod
    def create(
        cls,
        root: Path,
        contract: ContractSet,
        run_nonce: str,
        *,
        run_id: str = "offline-run",
    ) -> "LedgerStore":
        if _NONCE.fullmatch(run_nonce) is None:
            raise LedgerChainError("ledger nonce must be 64 lowercase hex characters")
        if not run_id or len(run_id) > 128:
            raise LedgerChainError("run ID is outside the closed ledger bounds")
        root_fd = -1
        parent_fd = -1
        root_identity: tuple[int, int] | None = None
        root_name = ""
        staging_name = ""
        staging_path = Path()
        transferred = False
        try:
            (
                root,
                staging_path,
                root_fd,
                root_stat,
                parent_fd,
                root_name,
                staging_name,
            ) = _create_staging_directory_no_follow(Path(root))
            root_identity = (root_stat.st_dev, root_stat.st_ino)
        except OSError as error:
            raise LedgerChainError(
                f"ledger directory creation failed: {error}"
            ) from error
        try:
            genesis = _build_generation_zero(run_id, run_nonce, contract)
            decision = contract.validate_document(
                "holoagent0-offline-ledger-v1", genesis
            )
            if not decision.ok:
                raise LedgerChainError(
                    "generation zero schema invalid: " + "; ".join(decision.errors)
                )
            try:
                descriptor = atomic_write_json_no_replace(
                    staging_path / "generation-000000.json",
                    genesis,
                    mode=0o400,
                    parent_fd=root_fd,
                    expected_parent_identity=root_identity,
                )
            except AtomicPublicationAmbiguity as error:
                descriptor = _reconcile_generation_zero(
                    staging_path,
                    root_fd,
                    genesis,
                    error.expected_artifact,
                    error,
                )
            os.fsync(root_fd)
            publication_error: BaseException | None = None
            try:
                _publish_directory_no_replace(
                    parent_fd, staging_name, root_name, root.parent
                )
            except _DirectoryPublicationAmbiguity as error:
                publication_error = error
            descriptor = _reconcile_published_generation_zero(
                root,
                parent_fd,
                root_fd,
                root_identity,
                genesis,
                descriptor,
                publication_error,
            )
            store = cls(
                root,
                contract,
                run_id,
                run_nonce,
                LedgerHead(0, descriptor.sha256, False),
                genesis,
                root_identity,
                (descriptor,),
                root_fd,
            )
            os.close(parent_fd)
            parent_fd = -1
            transferred = True
            return store
        except LedgerChainError:
            raise
        except (AtomicIOError, OSError, ValueError) as error:
            raise LedgerChainError(
                f"generation zero install failed: {error}"
            ) from error
        finally:
            if not transferred and root_fd >= 0:
                os.close(root_fd)
            if parent_fd >= 0:
                os.close(parent_fd)

    def append(self, candidate: LedgerCandidate) -> LedgerHead:
        with self._lock:
            return self._append_locked(candidate)

    def _append_locked(self, candidate: LedgerCandidate) -> LedgerHead:
        value = candidate.as_json()
        self._verify_immutable_chain()
        self._validate_successor(candidate, value["gates"])
        decision = self.contract.validate_document(
            "holoagent0-offline-ledger-v1", value
        )
        if not decision.ok:
            raise LedgerChainError(
                "candidate schema invalid: " + "; ".join(decision.errors)
            )
        path = self.root / f"generation-{candidate.generation:06d}.json"
        pending = self._pending_publication
        if pending is not None:
            if pending.generation != candidate.generation or pending.value != value:
                raise LedgerChainError(
                    "a different pending publication must be resolved first"
                )
            return self._reconcile_installed_candidate(
                path,
                value,
                candidate,
                pending.descriptor,
                "pending generation reconciliation failed",
                LedgerChainError("retrying this store's pending publication"),
            )
        try:
            descriptor = atomic_write_json_no_replace(
                path,
                value,
                mode=0o400,
                parent_fd=self._root_fd,
                expected_parent_identity=self._root_identity,
            )
        except FileExistsError as error:
            raise LedgerChainError("generation file already exists") from error
        except AtomicPublicationAmbiguity as error:
            self._record_pending_publication(candidate, value, error.expected_artifact)
            return self._reconcile_installed_candidate(
                path,
                value,
                candidate,
                error.expected_artifact,
                "generation install failed",
                error,
            )
        except (AtomicIOError, OSError, ValueError) as error:
            raise LedgerChainError(f"generation install failed: {error}") from error
        self._record_pending_publication(candidate, value, descriptor)
        return self._acknowledge_candidate(candidate, value, descriptor)

    def _record_pending_publication(
        self,
        candidate: LedgerCandidate,
        value: Mapping[str, object],
        descriptor: ArtifactDescriptor,
    ) -> None:
        pending = self._pending_publication
        if pending is not None and (
            pending.generation != candidate.generation
            or pending.value != value
            or pending.descriptor != descriptor
        ):
            raise LedgerChainError("a different pending publication is unresolved")
        self._pending_publication = _PendingPublication(
            candidate.generation, copy.deepcopy(dict(value)), descriptor
        )

    def _reconcile_installed_candidate(
        self,
        path: Path,
        value: Mapping[str, object],
        candidate: LedgerCandidate,
        publication_proof: ArtifactDescriptor,
        failure_prefix: str,
        original_error: BaseException,
    ) -> LedgerHead:
        try:
            os.fsync(self._root_fd)
            observed, descriptor = read_json_secure(
                path,
                expected_mode=0o400,
                relative_to=self.root,
                directory_fd=self._root_fd,
            )
            if observed != value:
                raise LedgerChainError(
                    "occupied generation does not match the validated candidate"
                )
            if descriptor != publication_proof:
                raise LedgerChainError(
                    "occupied generation does not match this call's publication proof"
                )
            return self._acknowledge_candidate(candidate, value, descriptor)
        except (AtomicIOError, LedgerChainError, OSError, ValueError) as error:
            raise LedgerChainError(f"{failure_prefix}: {error}") from original_error

    def _acknowledge_candidate(
        self,
        candidate: LedgerCandidate,
        value: Mapping[str, object],
        descriptor: ArtifactDescriptor,
    ) -> LedgerHead:
        candidate_descriptors = self._descriptors + (descriptor,)
        self._verify_immutable_chain(candidate_descriptors)
        self._descriptors = candidate_descriptors
        self._current = copy.deepcopy(dict(value))
        self.head = LedgerHead(
            candidate.generation,
            descriptor.sha256,
            candidate.sealed,
        )
        self._pending_publication = None
        return self.head

    def close(self) -> None:
        """Release the retained ledger directory descriptor."""

        with self._lock:
            if self._root_fd >= 0:
                os.close(self._root_fd)
                self._root_fd = -1

    def seal(self, candidate: LedgerCandidate) -> LedgerHead:
        with self._lock:
            if not candidate.sealed:
                raise LedgerChainError("terminal generation must be sealed")
            return self._append_locked(candidate)

    def _validate_successor(
        self,
        candidate: LedgerCandidate,
        candidate_gates: Sequence[Mapping[str, object]],
    ) -> None:
        if self.head.sealed:
            raise LedgerChainError("ledger is already sealed")
        if candidate.generation <= self.head.generation:
            raise LedgerChainError("repeated generation or replay")
        if candidate.generation != self.head.generation + 1:
            raise LedgerChainError("generation gap")
        if candidate.previous_generation != self.head.generation:
            raise LedgerChainError("stale predecessor generation")
        if candidate.previous_digest != self.head.digest:
            raise LedgerChainError("stale predecessor digest or fork")
        if candidate.run_id != self.run_id:
            raise LedgerChainError("run ID changed across ledger generations")
        if candidate.ledger_nonce != self.run_nonce:
            raise LedgerChainError("ledger nonce changed across generations")
        if (
            list(candidate_gates) == self._current["gates"]
            and candidate.semantic_dds_window == self._current["semantic_dds_window"]
            and candidate.sealed == self.head.sealed
        ):
            raise LedgerChainError("candidate has no state transition")
        recovery_postflight = bool(
            len(candidate_gates) > 23
            and candidate_gates[23].get("status") == "FAIL"
            and candidate_gates[23].get("reason") == "POSTFLIGHT_FAILED"
        )
        if recovery_postflight:
            if list(candidate_gates[:23]) != list(self._current["gates"][:23]):
                raise LedgerChainError(
                    "recovery candidate contains unacknowledged action progress"
                )
            current_window = self._current["semantic_dds_window"]
            if candidate.semantic_dds_window != current_window and not (
                current_window == "OPEN" and candidate.semantic_dds_window == "CLOSED"
            ):
                raise LedgerChainError(
                    "recovery candidate contains unacknowledged DDS progression"
                )
        self._validate_window(candidate.semantic_dds_window)
        self._validate_gate_transitions(candidate_gates, candidate.sealed)
        if candidate.sealed:
            postflight = next(
                (
                    gate
                    for gate in candidate_gates
                    if gate.get("id") == "safety.workstation_postflight"
                ),
                None,
            )
            self._validate_sealed_action_state(
                candidate_gates, allow_recovery_suffix=recovery_postflight
            )
            if postflight is None or postflight.get("status") not in {"PASS", "FAIL"}:
                raise LedgerChainError(
                    "sealed generation requires terminal workstation postflight"
                )
            if candidate.semantic_dds_window == "OPEN":
                raise LedgerChainError(
                    "sealed generation cannot retain an OPEN DDS window"
                )

    @staticmethod
    def _validate_sealed_action_state(
        candidate_gates: Sequence[Mapping[str, object]],
        *,
        allow_recovery_suffix: bool,
    ) -> None:
        actions = list(candidate_gates[:23])
        not_run = [
            index
            for index, gate in enumerate(actions)
            if gate.get("status") == "NOT_RUN"
        ]
        blocking = [
            index
            for index, gate in enumerate(actions)
            if gate.get("status") == "FAIL"
            and gate.get("role") in {"required", "required_qualification"}
        ]
        if not not_run:
            if blocking and blocking[0] != len(actions) - 1:
                raise LedgerChainError("sealed action state advances after a blocker")
            return
        first_not_run = not_run[0]
        if not_run != list(range(first_not_run, len(actions))):
            raise LedgerChainError("sealed action state must have a NOT_RUN suffix")
        suffix_reasons = {gate.get("reason") for gate in actions[first_not_run:]}
        if suffix_reasons == {"INTERRUPTED_BEFORE_GATE"}:
            return
        if suffix_reasons == {"EARLIER_BLOCKING_GATE"} and (
            (blocking and blocking[0] == first_not_run - 1) or allow_recovery_suffix
        ):
            return
        raise LedgerChainError(
            "sealed action state lacks a blocker or exact interruption suffix"
        )

    def _validate_window(self, candidate_window: str) -> None:
        current_window = self._current["semantic_dds_window"]
        allowed = {
            "NOT_ENTERED": {"NOT_ENTERED", "OPEN"},
            "OPEN": {"OPEN", "CLOSED"},
            "CLOSED": {"CLOSED"},
        }
        if candidate_window not in allowed.get(current_window, set()):
            raise LedgerChainError("non-monotonic semantic DDS window transition")

    def _validate_gate_transitions(
        self,
        candidate_gates: Sequence[Mapping[str, object]],
        candidate_sealed: bool,
    ) -> None:
        current_gates = self._current["gates"]
        if len(candidate_gates) != len(current_gates):
            raise LedgerChainError("candidate gate sequence length changed")
        changed_action_indexes: list[int] = []
        interrupted_indexes: list[int] = []
        for index, (previous, candidate, gate_id) in enumerate(
            zip(current_gates, candidate_gates, OFFLINE_GATE_ORDER)
        ):
            if candidate.get("id") != gate_id:
                raise LedgerChainError("candidate gate order changed")
            previous_status = previous.get("status")
            candidate_status = candidate.get("status")
            if (
                index < 23
                and previous_status == "NOT_RUN"
                and previous.get("reason") == "INTERRUPTED_BEFORE_GATE"
                and candidate != previous
            ):
                raise LedgerChainError(
                    f"interrupted action gate cannot resume: {gate_id}"
                )
            if index < 23 and candidate != previous:
                changed_action_indexes.append(index)
                interrupted = copy.deepcopy(previous)
                interrupted["reason"] = "INTERRUPTED_BEFORE_GATE"
                if (
                    previous_status == "NOT_RUN"
                    and previous.get("reason") == "EARLIER_BLOCKING_GATE"
                    and candidate == interrupted
                ):
                    interrupted_indexes.append(index)
            if previous_status != "NOT_RUN" and candidate != previous:
                raise LedgerChainError(f"non-monotonic gate transition for {gate_id}")
            if (
                previous_status == "NOT_RUN"
                and candidate_status == "NOT_RUN"
                and candidate != previous
                and index not in interrupted_indexes
            ):
                raise LedgerChainError(f"non-monotonic NOT_RUN mutation for {gate_id}")
        if list(candidate_gates[24:]) != list(current_gates[24:]):
            raise LedgerChainError(
                "supervisor-owned finalizers cannot be written to the working ledger"
            )
        gate24_changed = candidate_gates[23] != current_gates[23]
        if gate24_changed and not candidate_sealed:
            raise LedgerChainError("gate 24 may transition only in a sealed generation")
        if candidate_sealed and not gate24_changed:
            raise LedgerChainError("sealed generation must transition gate 24")
        if interrupted_indexes:
            expected_interrupted = list(range(interrupted_indexes[0], 23))
            if interrupted_indexes != expected_interrupted:
                raise LedgerChainError(
                    "interruption suffix must cover every remaining action gate"
                )
            candidate_not_run = [
                index
                for index, gate in enumerate(candidate_gates[:23])
                if gate.get("status") == "NOT_RUN"
            ]
            if candidate_not_run != expected_interrupted:
                raise LedgerChainError(
                    "every NOT_RUN action must belong to the exact interruption suffix"
                )
        terminal_changes = [
            index
            for index in changed_action_indexes
            if index not in interrupted_indexes
        ]
        if terminal_changes:
            if any(
                gate.get("status") == "FAIL"
                and gate.get("role") in {"required", "required_qualification"}
                for gate in current_gates[:23]
            ):
                raise LedgerChainError(
                    "action gate advanced after an earlier blocking failure"
                )
            next_action = next(
                index
                for index, gate in enumerate(current_gates[:23])
                if gate.get("status") == "NOT_RUN"
            )
            if terminal_changes[0] != next_action:
                raise LedgerChainError("action gate advanced out of profile order")
            expected = list(range(terminal_changes[0], terminal_changes[-1] + 1))
            if terminal_changes != expected:
                raise LedgerChainError("action gates advanced out of profile order")
            blocking_in_candidate = [
                index
                for index in terminal_changes
                if candidate_gates[index].get("status") == "FAIL"
                and candidate_gates[index].get("role")
                in {"required", "required_qualification"}
            ]
            if (
                blocking_in_candidate
                and terminal_changes[-1] > blocking_in_candidate[0]
            ):
                raise LedgerChainError(
                    "action gate advanced after a blocking failure in the same generation"
                )
        if interrupted_indexes and terminal_changes:
            if interrupted_indexes[0] != terminal_changes[-1] + 1:
                raise LedgerChainError(
                    "interruption suffix must immediately follow action progression"
                )

    def _verify_immutable_chain(
        self, descriptors: Sequence[ArtifactDescriptor] | None = None
    ) -> None:
        self._require_retained_root_identity()
        for generation, expected in enumerate(
            self._descriptors if descriptors is None else descriptors
        ):
            path = self.root / f"generation-{generation:06d}.json"
            try:
                _value, observed = read_json_secure(
                    path, expected_mode=0o400, directory_fd=self._root_fd
                )
            except AtomicIOError as error:
                raise LedgerChainError(
                    f"immutable generation changed: {generation}"
                ) from error
            if observed != expected:
                raise LedgerChainError(f"immutable generation changed: {generation}")
        self._require_retained_root_identity()

    def _require_retained_root_identity(self) -> None:
        try:
            root_stat = self.root.stat(follow_symlinks=False)
            retained_stat = os.fstat(self._root_fd)
        except OSError as error:
            raise LedgerChainError("immutable ledger root changed") from error
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.getuid()
            or stat.S_IMODE(root_stat.st_mode) != 0o700
            or (root_stat.st_dev, root_stat.st_ino) != self._root_identity
            or (retained_stat.st_dev, retained_stat.st_ino) != self._root_identity
        ):
            raise LedgerChainError("immutable ledger root changed")


def _build_generation_zero(
    run_id: str, run_nonce: str, contract: ContractSet
) -> dict[str, object]:
    profile = contract.policies["holoagent0-gate-policy-v1"]["profiles"][
        "workstation_offline"
    ]
    gates = []
    for gate_id in profile["gate_order"]:
        gates.append(
            {
                "id": gate_id,
                "status": "NOT_RUN",
                "role": profile["roles"][gate_id],
                "reason": "EARLIER_BLOCKING_GATE",
                "measurements": [],
                "thresholds": [],
                "log_paths": [],
                "child_command_exit_code": None,
            }
        )
    return {
        "schema_version": "holoagent0.offline-ledger.v1",
        "run_id": run_id,
        "ledger_nonce": run_nonce,
        "generation": 0,
        "previous_generation": None,
        "previous_digest": None,
        "sealed": False,
        "semantic_dds_window": "NOT_ENTERED",
        "gates": gates,
    }


def _create_staging_directory_no_follow(
    requested: Path,
) -> tuple[Path, Path, int, os.stat_result, int, str, str]:
    """Create a private sibling staging root without publishing the final name."""

    root = Path(os.path.abspath(requested))
    components = root.parts[1:]
    if not components:
        raise OSError("ledger root must not be the filesystem root")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open("/", flags)
    staging_fd = -1
    try:
        for component in components[:-1]:
            next_fd = -1
            try:
                try:
                    next_fd = os.open(component, flags, dir_fd=parent_fd)
                except FileNotFoundError:
                    next_fd, _created_stat = _mkdir_private_at(parent_fd, component)
                    os.fsync(parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
                next_fd = -1
            finally:
                if next_fd >= 0:
                    os.close(next_fd)

        final_name = components[-1]
        try:
            os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError(f"ledger directory already exists: {root}")

        for _attempt in range(32):
            staging_name = (
                f".{final_name}.staging-{os.getpid()}-{secrets.token_hex(16)}"
            )
            try:
                staging_fd, root_stat = _mkdir_private_at(parent_fd, staging_name)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate an unpredictable ledger staging name")
        os.fsync(parent_fd)
        staging_path = root.parent / staging_name
        result_parent_fd = parent_fd
        parent_fd = -1
        root_fd = staging_fd
        staging_fd = -1
        return (
            root,
            staging_path,
            root_fd,
            root_stat,
            result_parent_fd,
            final_name,
            staging_name,
        )
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if parent_fd >= 0:
            os.close(parent_fd)


def _mkdir_private_at(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    """mkdirat, chmod, and reopen the exact inode despite a hostile umask."""

    os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    path_fd = -1
    usable_fd = -1
    try:
        path_flags = (
            getattr(os, "O_PATH", 0) | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        )
        if not getattr(os, "O_PATH", 0):
            raise OSError("Linux O_PATH is required for identity-bound chmod")
        path_fd = os.open(name, path_flags, dir_fd=parent_fd)
        created_stat = os.fstat(path_fd)
        if not stat.S_ISDIR(created_stat.st_mode) or created_stat.st_uid != os.getuid():
            raise OSError("new directory owner/type mismatch")
        os.chmod(f"/proc/self/fd/{path_fd}", 0o700)
        secured_stat = os.fstat(path_fd)
        if (secured_stat.st_dev, secured_stat.st_ino) != (
            created_stat.st_dev,
            created_stat.st_ino,
        ) or stat.S_IMODE(secured_stat.st_mode) != 0o700:
            raise OSError("new directory chmod did not bind to the created inode")
        usable_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        usable_stat = os.fstat(usable_fd)
        if (usable_stat.st_dev, usable_stat.st_ino) != (
            secured_stat.st_dev,
            secured_stat.st_ino,
        ) or stat.S_IMODE(usable_stat.st_mode) != 0o700:
            raise OSError("usable directory fd differs from the secured inode")
        result_fd = usable_fd
        usable_fd = -1
        return result_fd, usable_stat
    finally:
        if usable_fd >= 0:
            os.close(usable_fd)
        if path_fd >= 0:
            os.close(path_fd)


def _publish_directory_no_replace(
    parent_fd: int,
    staging_name: str,
    final_name: str,
    lexical_parent: Path,
) -> None:
    _require_lexical_directory_identity(lexical_parent, parent_fd)
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise OSError("Linux renameat2 is required for no-replace publication")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(staging_name),
        parent_fd,
        os.fsencode(final_name),
        1,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), final_name)
    try:
        _require_lexical_directory_identity(lexical_parent, parent_fd)
    except OSError as error:
        raise _DirectoryPublicationAmbiguity(
            "ledger parent identity check failed after directory publication"
        ) from error


def _open_directory_path_no_follow(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    current_fd = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            if component in {"", ".", ".."}:
                raise OSError("ledger path contains an unsafe ancestor")
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        result_fd = current_fd
        current_fd = -1
        return result_fd
    finally:
        if current_fd >= 0:
            os.close(current_fd)


def _require_lexical_directory_identity(path: Path, retained_fd: int) -> None:
    walked_fd = -1
    try:
        walked_fd = _open_directory_path_no_follow(path)
        walked_stat = os.fstat(walked_fd)
        retained_stat = os.fstat(retained_fd)
        if (
            not stat.S_ISDIR(walked_stat.st_mode)
            or not stat.S_ISDIR(retained_stat.st_mode)
            or (walked_stat.st_dev, walked_stat.st_ino)
            != (retained_stat.st_dev, retained_stat.st_ino)
        ):
            raise OSError("ledger lexical parent identity changed")
    finally:
        if walked_fd >= 0:
            os.close(walked_fd)


def _require_published_root_identity(
    root: Path,
    retained_parent_fd: int,
    retained_root_fd: int,
    expected_identity: tuple[int, int],
) -> None:
    """Bind the requested final path to the retained initialized root inode."""

    walked_parent_fd = -1
    first_root_fd = -1
    observed_root_fd = -1
    final_root_fd = -1
    try:
        walked_parent_fd = _open_directory_path_no_follow(root.parent)
        walked_parent_stat = os.fstat(walked_parent_fd)
        retained_parent_stat = os.fstat(retained_parent_fd)
        if (walked_parent_stat.st_dev, walked_parent_stat.st_ino) != (
            retained_parent_stat.st_dev,
            retained_parent_stat.st_ino,
        ):
            raise OSError("ledger lexical parent identity changed")

        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        first_root_fd = os.open(root.name, flags, dir_fd=walked_parent_fd)
        retained_root_stat = os.fstat(retained_root_fd)
        first_root_stat = os.fstat(first_root_fd)
        path_stat = os.stat(root.name, dir_fd=walked_parent_fd, follow_symlinks=False)
        for observed in (retained_root_stat, first_root_stat, path_stat):
            if (
                not stat.S_ISDIR(observed.st_mode)
                or observed.st_uid != os.getuid()
                or stat.S_IMODE(observed.st_mode) != 0o700
                or (observed.st_dev, observed.st_ino) != expected_identity
            ):
                raise OSError("published ledger root identity changed")

        # Re-open after the path observation so replacement during the first
        # verification cannot hide behind the retained descriptor.
        observed_root_fd = os.open(root.name, flags, dir_fd=walked_parent_fd)
        observed_root_stat = os.fstat(observed_root_fd)
        if (
            (observed_root_stat.st_dev, observed_root_stat.st_ino) != expected_identity
            or stat.S_IMODE(observed_root_stat.st_mode) != 0o700
            or observed_root_stat.st_uid != os.getuid()
        ):
            raise OSError("published ledger root identity changed")

        # Finish parent verification before the final component-wise no-follow
        # reopen of the requested root. That reopen, not a descriptor retained
        # through an earlier parent namespace, is the acknowledgment boundary.
        _require_lexical_directory_identity(root.parent, retained_parent_fd)
        final_root_fd = _open_directory_path_no_follow(root)
        final_root_stat = os.fstat(final_root_fd)
        if (
            not stat.S_ISDIR(final_root_stat.st_mode)
            or (final_root_stat.st_dev, final_root_stat.st_ino) != expected_identity
            or stat.S_IMODE(final_root_stat.st_mode) != 0o700
            or final_root_stat.st_uid != os.getuid()
        ):
            raise OSError("published ledger root identity changed")
    finally:
        if final_root_fd >= 0:
            os.close(final_root_fd)
        if observed_root_fd >= 0:
            os.close(observed_root_fd)
        if first_root_fd >= 0:
            os.close(first_root_fd)
        if walked_parent_fd >= 0:
            os.close(walked_parent_fd)


def _reconcile_published_generation_zero(
    root: Path,
    parent_fd: int,
    root_fd: int,
    root_identity: tuple[int, int],
    genesis: Mapping[str, object],
    publication_proof: ArtifactDescriptor,
    initial_error: BaseException | None,
) -> ArtifactDescriptor:
    """Acknowledge only this call's exact published root and generation zero."""

    last_error = initial_error
    for _attempt in range(3):
        try:
            _require_lexical_directory_identity(root.parent, parent_fd)
            _require_published_root_identity(root, parent_fd, root_fd, root_identity)
            os.fsync(root_fd)
            os.fsync(parent_fd)
            _require_lexical_directory_identity(root.parent, parent_fd)
            _require_published_root_identity(root, parent_fd, root_fd, root_identity)
            observed, descriptor = read_json_secure(
                root / "generation-000000.json",
                expected_mode=0o400,
                relative_to=root,
                directory_fd=root_fd,
            )
            if observed != genesis or descriptor != publication_proof:
                raise LedgerChainError(
                    "generation zero install failed: published root proof mismatch"
                )
            _require_published_root_identity(root, parent_fd, root_fd, root_identity)
            return descriptor
        except LedgerChainError:
            raise
        except (AtomicIOError, OSError, ValueError) as error:
            last_error = error
    raise LedgerChainError(
        f"generation zero install failed: published root reconciliation failed: {last_error}"
    ) from last_error


def _reconcile_generation_zero(
    root: Path,
    root_fd: int,
    genesis: Mapping[str, object],
    publication_proof: ArtifactDescriptor,
    original_error: BaseException,
) -> ArtifactDescriptor:
    try:
        os.fsync(root_fd)
        observed, descriptor = read_json_secure(
            root / "generation-000000.json",
            expected_mode=0o400,
            relative_to=root,
            directory_fd=root_fd,
        )
        if observed != genesis or descriptor != publication_proof:
            raise LedgerChainError(
                "generation zero does not match this call's publication proof"
            )
        return descriptor
    except (AtomicIOError, LedgerChainError, OSError, ValueError) as error:
        raise LedgerChainError(
            f"generation zero publication reconciliation failed: {error}"
        ) from original_error
