"""FD provenance and closed UDP policy for canonical trace records."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Mapping

from .cyclone_policy import EXPECTED_CONFIG_SHA256


META_PORTS = {0: 26660, 1: 26662, 2: 26664, 3: 26666}
DATA_PORTS = {0: 26661, 1: 26663, 2: 26665, 3: 26667}
_PARTICIPANT_INDEXES = frozenset(range(4))
_LOCAL_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1"})
_NEUTRAL_SOCKET_DOMAINS = frozenset({"AF_UNIX", "AF_NETLINK"})
_REVIEWED_INHERITED_FD_KINDS = frozenset({"character_device", "pipe", "regular_file"})
_REVIEWED_RAW_FD_KINDS = frozenset({"character_device", "path", "pipe"})
_REVIEWED_GENERIC_FD_SYSCALLS = frozenset({"open", "openat"})
_SPDP_ADDRESS = "239.255.0.1"
_SPDP_PORT = 26650
_DATA_MULTICAST_PORT = 26651
_TX_SETUP_OPTIONS = (
    ("SOL_IP", "IP_MULTICAST_IF", "127.0.0.1", 4),
    ("SOL_IP", "IP_MULTICAST_TTL", 1, 1),
    ("SOL_IP", "IP_MULTICAST_LOOP", 1, 1),
)

_OUTBOUND_SYSCALLS = frozenset(
    {"write", "writev", "pwrite64", "pwritev", "pwritev2", "vmsplice"}
)
_INBOUND_SYSCALLS = frozenset({"read", "readv", "pread64", "preadv", "preadv2"})
_MESSAGE_OUTBOUND = frozenset({"sendto", "sendmsg", "sendmmsg"})
_MESSAGE_INBOUND = frozenset({"recvfrom", "recvmsg", "recvmmsg"})
_IO_URING_SYSCALLS = frozenset(
    {"io_uring_setup", "io_uring_enter", "io_uring_register"}
)


CanonicalRecord = Mapping[str, object]
Endpoint = tuple[str, int]


@dataclass(frozen=True)
class PolicyDecision:
    status: Literal["PASS", "FAIL", "SKIPPED"]
    reason: str
    violation_index: int | None


@dataclass(frozen=True)
class PolicyViolation:
    reason: str
    record_index: int | None
    pid: int | None
    operation: str


class ViolationJournal:
    """Append-only policy violations, retaining authoritative first failure."""

    def __init__(self, sink: object) -> None:
        persist = getattr(sink, "persist", None)
        if not callable(persist):
            raise ValueError("violation sink must provide persist()")
        self._sink = sink
        self._violations: list[PolicyViolation] = []

    def persist(self, violation: PolicyViolation) -> None:
        self._sink.persist(violation)
        self._violations.append(violation)

    @property
    def violation_count(self) -> int:
        return len(self._violations)

    @property
    def first_violation(self) -> PolicyViolation | None:
        return self._violations[0] if self._violations else None

    @property
    def violations(self) -> tuple[PolicyViolation, ...]:
        return tuple(self._violations)


@dataclass
class _OpenDescription:
    kind: str
    domain: object = None
    socket_type: tuple[object, ...] = ()
    protocol: object = None
    inode: int | None = None
    local: Endpoint | None = None
    peer: Endpoint | None = None
    local_conflict: bool = False
    peer_conflict: bool = False
    endpoint_poisoned: bool = False
    message_peers: list[tuple[str, Endpoint]] = field(default_factory=list)


@dataclass
class _FdEntry:
    description: _OpenDescription
    cloexec: bool = False


@dataclass
class _TxRegistration:
    participant: int
    description: _OpenDescription
    original_fd: int
    stage: int = 0
    endpoint: Endpoint | None = None
    poisoned: bool = False


class FDProvenance:
    """Model Linux descriptor tables and shared open-file descriptions."""

    def __init__(
        self,
        initial_manifest: Mapping[int, object] | None = None,
    ) -> None:
        self._tables: dict[int, dict[int, _FdEntry]] = {}
        self.integrity_error: str | None = None
        if initial_manifest is not None:
            self._seed_initial_manifest(initial_manifest)

    def _seed_initial_manifest(self, manifest: Mapping[int, object]) -> None:
        if not isinstance(manifest, Mapping) or len(manifest) > 64:
            raise ValueError("invalid initial FD manifest")
        for raw_pid, raw_entries in manifest.items():
            pid = _exact_int(raw_pid)
            if pid is None or pid <= 0 or not isinstance(raw_entries, list):
                raise ValueError("invalid initial FD manifest")
            if len(raw_entries) > 256:
                raise ValueError("invalid initial FD manifest")
            table: dict[int, _FdEntry] = {}
            for raw_entry in raw_entries:
                if not isinstance(raw_entry, Mapping) or not {
                    "fd",
                    "kind",
                    "cloexec",
                }.issubset(raw_entry):
                    raise ValueError("invalid initial FD manifest")
                if set(raw_entry) - {"fd", "kind", "inode", "cloexec"}:
                    raise ValueError("invalid initial FD manifest")
                fd = _exact_int(raw_entry.get("fd"))
                kind = raw_entry.get("kind")
                cloexec = raw_entry.get("cloexec")
                inode = raw_entry.get("inode")
                if (
                    fd is None
                    or fd < 0
                    or fd in table
                    or kind not in _REVIEWED_INHERITED_FD_KINDS
                    or type(cloexec) is not bool
                    or (inode is not None and (_exact_int(inode) is None or inode < 0))
                ):
                    raise ValueError("invalid initial FD manifest")
                table[fd] = _FdEntry(
                    description=_OpenDescription(
                        kind=str(kind),
                        inode=None if inode is None else int(inode),
                    ),
                    cloexec=cloexec,
                )
            self._tables[pid] = table

    def describe(self, pid: int, fd: int) -> dict[str, object] | None:
        entry = self._entry(pid, fd)
        if entry is None:
            return None
        description = entry.description
        return {
            "kind": description.kind,
            "domain": description.domain,
            "socket_type": list(description.socket_type),
            "protocol": description.protocol,
            "inode": description.inode,
            "local": description.local,
            "peer": description.peer,
            "cloexec": entry.cloexec,
            "local_conflict": description.local_conflict,
            "peer_conflict": description.peer_conflict,
            "message_peers": tuple(description.message_peers),
        }

    def socket_description(self, pid: int, fd: int) -> _OpenDescription | None:
        entry = self._entry(pid, fd)
        if entry is None or entry.description.kind != "socket":
            return None
        return entry.description

    def description(self, pid: int, fd: int) -> _OpenDescription | None:
        entry = self._entry(pid, fd)
        return None if entry is None else entry.description

    def descriptions_in_range(
        self, pid: int, first_fd: int, last_fd: int
    ) -> tuple[_OpenDescription, ...]:
        table = self._tables.get(pid, {})
        return tuple(
            {
                id(entry.description): entry.description
                for fd, entry in table.items()
                if first_fd <= fd <= last_fd
            }.values()
        )

    def descriptions_for_pid(self, pid: int) -> tuple[_OpenDescription, ...]:
        table = self._tables.get(pid, {})
        return tuple(
            {
                id(entry.description): entry.description for entry in table.values()
            }.values()
        )

    def description_is_open(self, description: _OpenDescription) -> bool:
        return any(
            entry.description is description
            for table in self._tables.values()
            for entry in table.values()
        )

    def _latch_integrity(self, reason: str) -> None:
        if self.integrity_error is None:
            self.integrity_error = reason

    def apply(self, record: CanonicalRecord) -> None:
        if record.get("kind") == "exit":
            pid = _exact_int(record.get("pid"))
            if pid is not None:
                self._tables.pop(pid, None)
            return
        if record.get("kind") != "syscall":
            return
        pid = _exact_int(record.get("pid"))
        if pid is None:
            return
        self._record_message_peers(pid, record)
        transition = record.get("transition")
        if not isinstance(transition, Mapping):
            self._create_generic_fd(pid, record)
            return
        operation = transition.get("operation")
        if not isinstance(operation, str):
            return

        if operation == "pipe":
            self._create_pipe(pid, transition, record)
        elif operation == "socket":
            self._create_socket(pid, transition, record)
        elif operation == "socketpair":
            self._create_socketpair(pid, transition, record)
        elif operation in {"accept", "accept4"}:
            self._accept(pid, transition, record)
        elif operation in {"bind", "connect", "getsockname", "getpeername"}:
            self._apply_endpoint(pid, operation, transition, record)
        elif operation in {"dup", "dup2", "dup3", "fcntl_dup"}:
            self._duplicate(pid, operation, transition, record)
        elif operation in {"fork", "vfork", "clone"}:
            self._create_process(pid, transition, record)
        elif operation == "unshare_files":
            self._unshare(pid, record)
        elif operation == "fcntl_setfd":
            self._set_cloexec(pid, transition, record)
        elif operation == "exec":
            self._exec(pid, transition, record)
        elif operation == "close":
            self._close(pid, transition, record)
        elif operation == "close_range":
            self._close_range(pid, transition, record)

    def _create_generic_fd(self, pid: int, record: CanonicalRecord) -> None:
        if not _succeeded(record):
            return
        result = record.get("result")
        descriptor = result.get("fd") if isinstance(result, Mapping) else None
        reviewed_creation = record.get("syscall") in _REVIEWED_GENERIC_FD_SYSCALLS
        if descriptor is None:
            if reviewed_creation:
                self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return
        fd = _fd_number(descriptor)
        result_value = _exact_int(result.get("value"))
        if (
            not reviewed_creation
            or not isinstance(descriptor, Mapping)
            or set(descriptor) != {"fd", "provenance"}
            or fd is None
            or fd < 0
            or result_value != fd
            or not _reviewed_raw_nonsocket_annotation(descriptor)
            or self._entry(pid, fd) is not None
        ):
            self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return
        provenance = descriptor["provenance"]
        kind = str(provenance["kind"])
        inode = _exact_int(provenance.get("inode"))
        self._table(pid)[fd] = _FdEntry(
            description=_OpenDescription(kind=kind, inode=inode),
            cloexec=False,
        )

    def _entry(self, pid: int, fd: int) -> _FdEntry | None:
        table = self._tables.get(pid)
        return None if table is None else table.get(fd)

    def _table(self, pid: int) -> dict[int, _FdEntry]:
        return self._tables.setdefault(pid, {})

    def _create_socket(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        created = _fd_number(transition.get("created_fd"))
        if created is None or not _succeeded(record):
            return
        socket_type = transition.get("socket_type")
        type_items = tuple(socket_type) if isinstance(socket_type, list) else ()
        self._table(pid)[created] = _FdEntry(
            description=_OpenDescription(
                kind="socket",
                domain=transition.get("domain"),
                socket_type=type_items,
                protocol=transition.get("protocol"),
                inode=_fd_inode(transition.get("created_fd")),
            ),
            cloexec="SOCK_CLOEXEC" in type_items,
        )

    def _create_pipe(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        created = transition.get("created_fds")
        cloexec = transition.get("cloexec")
        if (
            not _succeeded(record)
            or not isinstance(created, list)
            or len(created) != 2
            or type(cloexec) is not bool
        ):
            return
        table = self._table(pid)
        for descriptor in created:
            fd = _fd_number(descriptor)
            provenance = (
                descriptor.get("provenance")
                if isinstance(descriptor, Mapping)
                else None
            )
            inode = (
                _exact_int(provenance.get("inode"))
                if isinstance(provenance, Mapping) and provenance.get("kind") == "pipe"
                else None
            )
            if fd is None or fd < 0 or inode is None or inode < 0:
                self._latch_integrity("UNKNOWN_FD_PROVENANCE")
                continue
            table[fd] = _FdEntry(
                description=_OpenDescription(kind="pipe", inode=inode),
                cloexec=cloexec,
            )

    def _create_socketpair(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        created = transition.get("created_fds")
        if not _succeeded(record) or not isinstance(created, list):
            return
        socket_type = transition.get("socket_type")
        type_items = tuple(socket_type) if isinstance(socket_type, list) else ()
        table = self._table(pid)
        for descriptor in created:
            fd = _fd_number(descriptor)
            if fd is None:
                continue
            table[fd] = _FdEntry(
                description=_OpenDescription(
                    kind="socket",
                    domain=transition.get("domain"),
                    socket_type=type_items,
                    protocol=transition.get("protocol"),
                    inode=_fd_inode(descriptor),
                ),
                cloexec="SOCK_CLOEXEC" in type_items,
            )

    def _accept(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        source = _fd_number(transition.get("source_fd"))
        created = _fd_number(transition.get("created_fd"))
        if source is None or created is None or not _succeeded(record):
            return
        source_entry = self._entry(pid, source)
        if source_entry is None:
            return
        source_description = source_entry.description
        peer = _endpoint(transition.get("address"))
        flags = transition.get("flags")
        flag_items = tuple(flags) if isinstance(flags, list) else ()
        self._table(pid)[created] = _FdEntry(
            description=_OpenDescription(
                kind=source_description.kind,
                domain=source_description.domain,
                socket_type=source_description.socket_type,
                protocol=source_description.protocol,
                inode=_fd_inode(transition.get("created_fd")),
                local=source_description.local,
                peer=peer,
            ),
            cloexec="SOCK_CLOEXEC" in flag_items,
        )

    def _apply_endpoint(
        self,
        pid: int,
        operation: str,
        transition: Mapping[str, object],
        record: CanonicalRecord,
    ) -> None:
        if not _succeeded(record):
            return
        fd = _fd_number(transition.get("fd"))
        endpoint = _endpoint(transition.get("address"))
        if fd is None or endpoint is None:
            return
        entry = self._entry(pid, fd)
        if entry is None or entry.description.kind != "socket":
            return
        description = entry.description
        if operation in {"bind", "getsockname"}:
            wildcard_refinement = (
                description.local is not None
                and description.local[0] == "0.0.0.0"
                and endpoint[0] == "127.0.0.1"
                and description.local[1] == endpoint[1]
            )
            port_zero_refinement = (
                operation == "getsockname"
                and description.local == ("127.0.0.1", 0)
                and endpoint[0] == "127.0.0.1"
                and endpoint[1] != 0
            )
            if wildcard_refinement or port_zero_refinement:
                description.local = endpoint
            elif description.local is not None and description.local != endpoint:
                description.local_conflict = True
            else:
                description.local = endpoint
        else:
            if description.peer is not None and description.peer != endpoint:
                description.peer_conflict = True
            else:
                description.peer = endpoint

    def _duplicate(
        self,
        pid: int,
        operation: str,
        transition: Mapping[str, object],
        record: CanonicalRecord,
    ) -> None:
        source = _fd_number(transition.get("source_fd"))
        created = _fd_number(transition.get("created_fd"))
        if source is None or created is None or not _succeeded(record):
            return
        source_entry = self._entry(pid, source)
        if source_entry is None:
            if operation in {"dup2", "dup3"}:
                self._table(pid).pop(created, None)
            self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return
        if operation == "dup2" and source == created:
            return
        cloexec = False
        if operation == "dup3":
            flags = transition.get("flags")
            cloexec = isinstance(flags, list) and "O_CLOEXEC" in flags
        elif operation == "fcntl_dup":
            cloexec = transition.get("cloexec") is True
        self._table(pid)[created] = _FdEntry(source_entry.description, cloexec)

    def _create_process(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        child = _exact_int(transition.get("child_pid"))
        if child is None or child <= 0 or not _succeeded(record):
            return
        parent_table = self._table(pid)
        if transition.get("fd_table") == "shared":
            self._tables[child] = parent_table
        elif transition.get("fd_table") == "copied":
            self._tables[child] = {
                fd: _FdEntry(entry.description, entry.cloexec)
                for fd, entry in parent_table.items()
            }

    def _unshare(self, pid: int, record: CanonicalRecord) -> None:
        if not _succeeded(record):
            return
        table = self._table(pid)
        self._tables[pid] = {
            fd: _FdEntry(entry.description, entry.cloexec)
            for fd, entry in table.items()
        }

    def _set_cloexec(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        source = _fd_number(transition.get("source_fd"))
        entry = None if source is None else self._entry(pid, source)
        if (
            entry is not None
            and _succeeded(record)
            and type(transition.get("cloexec")) is bool
        ):
            entry.cloexec = transition["cloexec"]

    def _exec(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        if not _succeeded(record) or transition.get("cloexec_fds") != "closed":
            return
        shared_table = self._table(pid)
        table = {
            fd: _FdEntry(entry.description, entry.cloexec)
            for fd, entry in shared_table.items()
        }
        self._tables[pid] = table
        for fd in tuple(table):
            if table[fd].cloexec:
                del table[fd]

    def _close(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        closed = _fd_number(transition.get("closed_fd"))
        if closed is not None and _succeeded(record):
            self._table(pid).pop(closed, None)

    def _close_range(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        if not _succeeded(record):
            return
        first = _exact_int(transition.get("first_fd"))
        last = _exact_int(transition.get("last_fd"))
        flags = transition.get("flags")
        if first is None or last is None or not isinstance(flags, list):
            return
        if "CLOSE_RANGE_UNSHARE" in flags:
            self._unshare(pid, record)
        table = self._table(pid)
        selected = [fd for fd in table if first <= fd <= last]
        if "CLOSE_RANGE_CLOEXEC" in flags:
            for fd in selected:
                table[fd].cloexec = True
        else:
            for fd in selected:
                del table[fd]

    def _record_message_peers(self, pid: int, record: CanonicalRecord) -> None:
        if not _succeeded(record):
            return
        syscall = record.get("syscall")
        if syscall not in _MESSAGE_OUTBOUND | _MESSAGE_INBOUND:
            return
        fds = record.get("fds")
        if not isinstance(fds, list) or not fds:
            return
        fd = _fd_number(fds[0])
        description = None if fd is None else self.socket_description(pid, fd)
        if description is None:
            return
        direction = "outbound" if syscall in _MESSAGE_OUTBOUND else "inbound"
        for endpoint in _record_endpoints(record):
            description.message_peers.append((direction, endpoint))


class _MarkerWindow:
    def __init__(self, coordinator_pid: int, token: str) -> None:
        self._coordinator_pid = coordinator_pid
        self._token = token
        self._state: Literal["BEFORE", "ACTIVE", "AFTER", "POISONED"] = "BEFORE"
        self._begin_entry_index: int | None = None
        self._begin_exit_index: int | None = None

    @property
    def active(self) -> bool:
        return self._state == "ACTIVE"

    @property
    def state(self) -> str:
        return self._state

    @property
    def began(self) -> bool:
        return self._state in {"ACTIVE", "AFTER"}

    @property
    def complete(self) -> bool:
        return self._state == "AFTER"

    def authorizes(self, record: CanonicalRecord) -> bool:
        if not self.active:
            return False
        entry_index = _exact_int(record.get("entry_index"))
        exit_index = _exact_int(record.get("exit_index"))
        if (
            entry_index is None
            or exit_index is None
            or self._begin_entry_index is None
            or self._begin_exit_index is None
        ):
            return False
        return (
            entry_index > self._begin_entry_index
            and exit_index > self._begin_exit_index
        )

    def consume(self, record: CanonicalRecord) -> str | None:
        marker = record.get("marker")
        if marker is None:
            return None
        result = record.get("result")
        value = result.get("value") if isinstance(result, Mapping) else None
        if (
            record.get("kind") != "syscall"
            or record.get("syscall") != "prctl"
            or record.get("pid") != self._coordinator_pid
            or not isinstance(marker, Mapping)
            or marker.get("token") != self._token
            or value != 0
        ):
            return self._poison()
        phase = marker.get("phase")
        if phase == "BEGIN" and self._state == "BEFORE":
            entry_index = _exact_int(record.get("entry_index"))
            exit_index = _exact_int(record.get("exit_index"))
            if entry_index is None or exit_index is None:
                return self._poison()
            self._state = "ACTIVE"
            self._begin_entry_index = entry_index
            self._begin_exit_index = exit_index
            return None
        if phase == "END" and self._state == "ACTIVE":
            entry_index = _exact_int(record.get("entry_index"))
            exit_index = _exact_int(record.get("exit_index"))
            if (
                entry_index is None
                or exit_index is None
                or self._begin_entry_index is None
                or self._begin_exit_index is None
                or entry_index <= self._begin_entry_index
                or exit_index <= self._begin_exit_index
            ):
                return self._poison()
            self._state = "AFTER"
            return None
        return self._poison()

    def _poison(self) -> str:
        self._state = "POISONED"
        return "INVALID_MARKER"


class TracePolicy:
    """Classify canonical trace records under the single reviewed UDP window."""

    def __init__(
        self,
        *,
        coordinator_pid: int,
        marker_token: str,
        participants: Mapping[int, Mapping[str, object]],
        namespace_loopback_only: bool,
        initial_fd_manifest: Mapping[int, object],
        violation_sink: object,
    ) -> None:
        if _exact_int(coordinator_pid) is None or coordinator_pid <= 0:
            raise ValueError("coordinator PID must be a positive integer")
        if not isinstance(initial_fd_manifest, Mapping) or set(initial_fd_manifest) != {
            coordinator_pid
        }:
            raise ValueError("initial FD manifest must contain only the coordinator")
        participant_copy = copy.deepcopy(dict(participants))
        self._participants = MappingProxyType(
            {
                pid: MappingProxyType(dict(participant))
                for pid, participant in participant_copy.items()
                if isinstance(participant, Mapping)
            }
        )
        self._coordinator_pid = coordinator_pid
        self._namespace_loopback_only = namespace_loopback_only is True
        self._configuration_valid = self._validate_configuration()
        self.provenance = FDProvenance(initial_fd_manifest)
        self.markers = _MarkerWindow(coordinator_pid, marker_token)
        self.journal = ViolationJournal(violation_sink)
        self.trace_integrity_error: str | None = None
        self._root_pid_by_index = {
            participant["index"]: pid
            for pid, participant in self._participants.items()
            if self._configuration_valid
        }
        self._configured_root_roles = {
            pid: index for index, pid in self._root_pid_by_index.items()
        }
        self._task_roles = {
            pid: participant["index"]
            for pid, participant in self._participants.items()
            if self._configuration_valid
        }
        self._active_participants: set[int] = set()
        self._exited_roots: set[int] = set()
        self._accepted_root_execs: set[int] = set()
        self._root_activity: set[int] = set()
        self._live_workers: dict[int, int] = {}
        self._socket_owners: dict[int, int] = {}
        self._tracked_sockets: dict[int, _OpenDescription] = {}
        self._explicitly_closed: set[int] = set()
        self._receive_ports: dict[int, int] = {}
        self._tx_by_participant: dict[int, _TxRegistration] = {}
        self._tx_by_description: dict[int, _TxRegistration] = {}
        self._registered_endpoints: dict[int, _TxRegistration] = {}

    def feed(self, record: CanonicalRecord) -> PolicyDecision:
        marker = record.get("marker")
        if marker is not None:
            marker_reason = self.markers.consume(record)
            if marker_reason is not None:
                self._latch_integrity(marker_reason)
            if record.get("kind") == "syscall" and record.get("syscall") == "prctl":
                if (
                    marker_reason is None
                    and isinstance(marker, Mapping)
                    and marker.get("phase") == "END"
                    and not self._lifecycle_closed()
                ):
                    self._latch_integrity("INCOMPLETE_PARTICIPANT_LIFECYCLE")
                return PolicyDecision("PASS", "OK", None)

        pid = _exact_int(record.get("pid"))
        if record.get("kind") == "exit":
            if pid is not None:
                self._handle_exit(pid)
            self.provenance.apply(record)
            self._sync_provenance_integrity()
            return PolicyDecision("PASS", "OK", None)

        pre_description = self._description_for_record(pid, record)
        interposition_descriptions = self._interposition_descriptions(pid, record)
        close_range_closes = self._close_range_closes(record)
        self.provenance.apply(record)
        self._sync_provenance_integrity()
        reason = self._classify(record, pre_description, interposition_descriptions)
        transition = record.get("transition")
        if (
            isinstance(transition, Mapping)
            and transition.get("operation") == "close"
            and pid is not None
        ):
            self._handle_close(pid, pre_description, record)
        if close_range_closes and interposition_descriptions and pid is not None:
            for description in interposition_descriptions:
                self._handle_close(pid, description, record)
        if reason is None:
            return PolicyDecision("PASS", "OK", None)
        violation = PolicyViolation(
            reason=reason,
            record_index=_exact_int(record.get("record_index")),
            pid=pid,
            operation=str(record.get("syscall", record.get("kind", "unknown"))),
        )
        self.journal.persist(violation)
        return PolicyDecision("FAIL", reason, violation.record_index)

    def finalize(self, trace_integrity_ok: bool) -> PolicyDecision:
        first = self.journal.first_violation
        if first is not None:
            return PolicyDecision("FAIL", first.reason, first.record_index)
        if self.markers.active:
            self._latch_integrity("MISSING_END_MARKER")
        if self.markers.complete and not self._lifecycle_closed():
            self._latch_integrity("INCOMPLETE_PARTICIPANT_LIFECYCLE")
        if trace_integrity_ok and self.trace_integrity_error is None:
            return PolicyDecision("PASS", "OK", None)
        return PolicyDecision("SKIPPED", "DEPENDENCY_NOT_AVAILABLE", None)

    def _validate_configuration(self) -> bool:
        if (
            set(EXPECTED_CONFIG_SHA256) != _PARTICIPANT_INDEXES
            or any(type(index) is not int for index in EXPECTED_CONFIG_SHA256)
            or any(not _is_digest(digest) for digest in EXPECTED_CONFIG_SHA256.values())
        ):
            return False
        indexes: list[int] = []
        if len(self._participants) != 4:
            return False
        for pid, participant in self._participants.items():
            if (
                _exact_int(pid) is None
                or pid <= 0
                or not isinstance(participant, Mapping)
                or set(participant) != {"index", "config_digest"}
            ):
                return False
            index = _exact_int(participant.get("index"))
            digest = participant.get("config_digest")
            if index is None or index not in _PARTICIPANT_INDEXES:
                return False
            if not _is_digest(digest) or digest != EXPECTED_CONFIG_SHA256.get(index):
                return False
            indexes.append(index)
        return set(indexes) == _PARTICIPANT_INDEXES and len(indexes) == 4

    def _participant_index(self, pid: object) -> int | None:
        if not self._configuration_valid:
            return None
        exact_pid = _exact_int(pid)
        if exact_pid is None:
            return None
        return self._task_roles.get(exact_pid)

    def _latch_integrity(self, reason: str) -> None:
        if self.trace_integrity_error is None:
            self.trace_integrity_error = reason

    def _sync_provenance_integrity(self) -> None:
        if self.provenance.integrity_error is not None:
            self._latch_integrity(self.provenance.integrity_error)

    def _description_for_record(
        self, pid: int | None, record: CanonicalRecord
    ) -> _OpenDescription | None:
        if pid is None:
            return None
        transition = record.get("transition")
        if isinstance(transition, Mapping):
            for key in ("fd", "source_fd", "closed_fd"):
                fd = _fd_number(transition.get(key))
                if fd is not None:
                    return self.provenance.socket_description(pid, fd)
        fds = record.get("fds")
        if isinstance(fds, list) and fds:
            fd = _fd_number(fds[0])
            if fd is not None:
                return self.provenance.socket_description(pid, fd)
        return None

    def _interposition_descriptions(
        self, pid: int | None, record: CanonicalRecord
    ) -> tuple[_OpenDescription, ...]:
        if pid is None:
            return ()
        transition = record.get("transition")
        if not isinstance(transition, Mapping):
            return ()
        operation = transition.get("operation")
        if operation == "close_range":
            first_fd = _exact_int(transition.get("first_fd"))
            last_fd = _exact_int(transition.get("last_fd"))
            if first_fd is None or last_fd is None:
                return ()
            return self.provenance.descriptions_in_range(pid, first_fd, last_fd)
        keys: tuple[str, ...]
        if operation in {"dup2", "dup3"}:
            keys = ("source_fd", "target_fd")
        elif operation in {
            "dup",
            "fcntl_dup",
            "fcntl_getfd",
            "fcntl_getfl",
            "fcntl_setfd",
            "fcntl_setfl",
        }:
            keys = ("source_fd",)
        elif operation == "close":
            keys = ("closed_fd", "fd")
        else:
            return ()
        descriptions: dict[int, _OpenDescription] = {}
        for key in keys:
            fd = _fd_number(transition.get(key))
            description = None if fd is None else self.provenance.description(pid, fd)
            if description is not None:
                descriptions[id(description)] = description
        return tuple(descriptions.values())

    @staticmethod
    def _close_range_closes(record: CanonicalRecord) -> bool:
        if not _succeeded(record):
            return False
        transition = record.get("transition")
        if (
            not isinstance(transition, Mapping)
            or transition.get("operation") != "close_range"
        ):
            return False
        flags = transition.get("flags")
        return isinstance(flags, list) and "CLOSE_RANGE_CLOEXEC" not in flags

    def _activate_socket(self, participant: int, description: _OpenDescription) -> None:
        identity = id(description)
        self._active_participants.add(participant)
        self._socket_owners[identity] = participant
        self._tracked_sockets[identity] = description

    def _apply_clone_authority(
        self, pid: int, transition: Mapping[str, object], record: CanonicalRecord
    ) -> None:
        if not _succeeded(record):
            return
        child = _exact_int(transition.get("child_pid"))
        if child is None or child <= 0:
            return
        configured_root_role = self._configured_root_roles.get(child)
        if configured_root_role is not None:
            if configured_root_role in self._exited_roots:
                self._task_roles.pop(child, None)
                self._live_workers.pop(child, None)
                return
            self._task_roles[child] = configured_root_role
            self._live_workers.pop(child, None)
            self._active_participants.add(configured_root_role)
            return
        self._task_roles.pop(child, None)
        self._live_workers.pop(child, None)
        flags = transition.get("flags")
        parent_role = self._task_roles.get(pid)
        if (
            parent_role is None
            or transition.get("fd_table") != "shared"
            or not isinstance(flags, list)
            or not {"CLONE_THREAD", "CLONE_FILES"}.issubset(flags)
        ):
            return
        self._task_roles[child] = parent_role
        self._live_workers[child] = parent_role
        self._active_participants.add(parent_role)
        if self._configured_root_roles.get(pid) == parent_role:
            self._root_activity.add(parent_role)

    def _handle_close(
        self,
        pid: int,
        description: _OpenDescription | None,
        record: CanonicalRecord,
    ) -> None:
        if description is None or not _succeeded(record):
            return
        identity = id(description)
        participant = self._socket_owners.get(identity)
        if participant is None:
            return
        if any(owner == participant for owner in self._live_workers.values()):
            self._latch_integrity("SOCKET_CLOSED_BEFORE_WORKER_EXIT")
        if pid != self._root_pid_by_index.get(participant):
            self._latch_integrity("PARTICIPANT_SOCKET_NOT_ROOT_CLOSED")
        if not self.provenance.description_is_open(description):
            self._explicitly_closed.add(identity)
            registration = self._tx_by_description.get(identity)
            if registration is not None and registration.endpoint is not None:
                self._registered_endpoints.pop(registration.endpoint[1], None)

    def _handle_exit(self, pid: int) -> None:
        participant = self._live_workers.pop(pid, None)
        self._task_roles.pop(pid, None)
        if participant is not None:
            return
        participant = self._configured_root_roles.get(pid)
        if participant is None:
            return
        if pid != self._root_pid_by_index.get(participant):
            return
        if any(owner == participant for owner in self._live_workers.values()):
            self._latch_integrity("ROOT_EXIT_BEFORE_WORKER_EXIT")
        for identity, owner in self._socket_owners.items():
            if owner == participant and identity not in self._explicitly_closed:
                self._latch_integrity("ROOT_EXIT_WITH_OPEN_SOCKET")
                break
        self._exited_roots.add(participant)

    def _lifecycle_closed(self) -> bool:
        if any(
            registration.endpoint is None
            for registration in self._tx_by_participant.values()
        ):
            return False
        for participant in self._active_participants:
            if participant not in self._exited_roots:
                return False
            if any(owner == participant for owner in self._live_workers.values()):
                return False
            for identity, owner in self._socket_owners.items():
                if owner != participant:
                    continue
                description = self._tracked_sockets[identity]
                if (
                    identity not in self._explicitly_closed
                    or self.provenance.description_is_open(description)
                ):
                    return False
        return True

    def _classify(
        self,
        record: CanonicalRecord,
        pre_description: _OpenDescription | None,
        interposition_descriptions: tuple[_OpenDescription, ...],
    ) -> str | None:
        if record.get("kind") != "syscall":
            return None

        syscall = record.get("syscall")
        transition = record.get("transition")
        operation = (
            transition.get("operation") if isinstance(transition, Mapping) else None
        )
        pid = _exact_int(record.get("pid"))
        if syscall in _IO_URING_SYSCALLS:
            return "PROHIBITED_IO_URING"
        if syscall == "ptrace":
            return "TRACE_BYPASS_ATTEMPT"
        if operation == "clone" and isinstance(transition, Mapping):
            flags = transition.get("flags")
            if isinstance(flags, list) and "CLONE_UNTRACED" in flags:
                return "UNTRACED_CHILD_ATTEMPT"
        if operation == "pidfd_getfd" or syscall == "pidfd_getfd":
            return "PROHIBITED_FD_ACQUISITION"
        if _contains_scm_rights(record):
            return "PROHIBITED_FD_TRANSFER"

        if pid is None:
            return None
        interposition = self._classify_tx_interposition(
            operation, interposition_descriptions
        )
        if interposition is not None:
            return interposition
        if _succeeded(record):
            if operation == "exec":
                if not self._apply_root_exec_authority(pid):
                    self._revoke_worker_authority(pid)
            elif operation == "unshare_files":
                self._revoke_split_authority(pid)
            elif operation == "close_range" and isinstance(transition, Mapping):
                flags = transition.get("flags")
                if isinstance(flags, list) and "CLOSE_RANGE_UNSHARE" in flags:
                    self._revoke_split_authority(pid)
        if operation in {"fork", "vfork", "clone"} and isinstance(transition, Mapping):
            self._apply_clone_authority(pid, transition, record)
            return None
        if operation in {"socket", "socketpair"} and isinstance(transition, Mapping):
            return self._classify_socket_creation(pid, transition, record)
        if operation in {"bind", "connect", "getsockname", "getpeername"}:
            if isinstance(transition, Mapping):
                return self._classify_endpoint_transition(
                    pid, operation, transition, record, pre_description
                )
        if operation in {"accept", "accept4", "listen"}:
            if isinstance(transition, Mapping):
                return self._classify_server_operation(pid, transition)
        if operation in {"getsockopt", "setsockopt", "shutdown"}:
            if isinstance(transition, Mapping):
                return self._classify_socket_control(
                    pid, operation, transition, record, pre_description
                )
        if syscall in _MESSAGE_OUTBOUND | _MESSAGE_INBOUND:
            return self._classify_message_io(pid, str(syscall), record, pre_description)
        if syscall in _OUTBOUND_SYSCALLS | _INBOUND_SYSCALLS | {
            "sendfile",
            "splice",
            "tee",
            "copy_file_range",
        }:
            return self._classify_raw_io(pid, str(syscall), record)
        return None

    def _apply_root_exec_authority(self, pid: int) -> bool:
        participant = self._configured_root_roles.get(pid)
        if participant is None:
            return False
        self._active_participants.add(participant)
        if (
            participant in self._accepted_root_execs
            or participant in self._root_activity
            or participant in self._exited_roots
            or self._task_roles.get(pid) != participant
        ):
            self._task_roles.pop(pid, None)
            self._latch_integrity("CONFIGURED_ROOT_IDENTITY_REPLACED")
            return True
        self._accepted_root_execs.add(participant)
        return True

    def _revoke_worker_authority(self, pid: int) -> None:
        if pid in self._live_workers:
            self._task_roles.pop(pid, None)

    def _revoke_split_authority(self, pid: int) -> None:
        configured_role = self._configured_root_roles.get(pid)
        if configured_role is not None and self._task_roles.get(pid) == configured_role:
            for worker_pid, participant in self._live_workers.items():
                if participant == configured_role:
                    self._task_roles.pop(worker_pid, None)
            return
        self._revoke_worker_authority(pid)

    def _classify_tx_interposition(
        self,
        operation: object,
        descriptions: tuple[_OpenDescription, ...],
    ) -> str | None:
        if operation not in {
            "close",
            "close_range",
            "dup",
            "dup2",
            "dup3",
            "fcntl_dup",
            "fcntl_getfd",
            "fcntl_getfl",
            "fcntl_setfd",
            "fcntl_setfl",
        }:
            return None
        violation = False
        for description in descriptions:
            registration = self._tx_by_description.get(id(description))
            if registration is not None and registration.endpoint is None:
                registration.poisoned = True
                violation = True
        return "UNEXPECTED_NETWORK_ATTEMPT" if violation else None

    def _classify_socket_creation(
        self,
        pid: int,
        transition: Mapping[str, object],
        record: CanonicalRecord,
    ) -> str | None:
        domain = transition.get("domain")
        if domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        if domain != "AF_INET":
            return "UNEXPECTED_NETWORK_ATTEMPT"
        socket_type = transition.get("socket_type")
        protocol = transition.get("protocol")
        is_udp = (
            isinstance(socket_type, list)
            and "SOCK_DGRAM" in socket_type
            and all(
                item in {"SOCK_DGRAM", "SOCK_CLOEXEC", "SOCK_NONBLOCK"}
                for item in socket_type
            )
            and protocol in {0, "IPPROTO_UDP"}
        )
        if not is_udp or not self._network_context_valid(pid, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if _succeeded(record):
            created_fd = _fd_number(transition.get("created_fd"))
            description = (
                None
                if created_fd is None
                else self.provenance.socket_description(pid, created_fd)
            )
            participant = self._participant_index(pid)
            if description is None or participant is None:
                self._latch_integrity("MISSING_SOCKET_PROVENANCE")
                return "UNEXPECTED_NETWORK_ATTEMPT"
            self._activate_socket(participant, description)
        return None

    def _classify_endpoint_transition(
        self,
        pid: int,
        operation: str,
        transition: Mapping[str, object],
        record: CanonicalRecord,
        pre_description: _OpenDescription | None,
    ) -> str | None:
        fd = _fd_number(transition.get("fd"))
        description = pre_description
        if description is None:
            self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return self._missing_socket_reason(transition.get("fd"))
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        registration = self._tx_by_description.get(id(description))
        if not _succeeded(record):
            description.endpoint_poisoned = True
            if registration is not None:
                registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if description.endpoint_poisoned:
            if registration is not None:
                registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if (
            description.domain != "AF_INET"
            or "SOCK_DGRAM" not in description.socket_type
            or description.protocol not in {0, "IPPROTO_UDP"}
            or not self._network_context_valid(pid, record)
        ):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        endpoint = _endpoint(transition.get("address"))
        participant = self._participant_index(pid)
        owner = self._socket_owners.get(id(description))
        if (
            participant is None
            or participant != owner
            or endpoint is None
            or fd is None
        ):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if operation == "getsockname":
            if registration is None:
                if (
                    _succeeded(record)
                    and self._receive_ports.get(id(description)) is not None
                    and not description.local_conflict
                    and description.local == endpoint
                ):
                    return None
                return "UNEXPECTED_NETWORK_ATTEMPT"
            return self._classify_getsockname(
                fd, description, registration, endpoint, record
            )
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if operation == "bind":
            return self._classify_bind(participant, fd, description, endpoint, record)
        if registration is None or registration.endpoint is None:
            if registration is not None:
                registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if registration.poisoned or fd != registration.original_fd:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if operation != "connect" or not self._tx_destination_allowed(endpoint):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if description.peer_conflict:
            registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        return None

    def _classify_bind(
        self,
        participant: int,
        fd: int,
        description: _OpenDescription,
        endpoint: Endpoint,
        record: CanonicalRecord,
    ) -> str | None:
        if description.local_conflict:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if endpoint == ("127.0.0.1", 0):
            existing = self._tx_by_participant.get(participant)
            if existing is not None and existing.description is not description:
                return "UNEXPECTED_NETWORK_ATTEMPT"
            if existing is not None:
                existing.poisoned = True
                return "UNEXPECTED_NETWORK_ATTEMPT"
            if _succeeded(record) and existing is None:
                registration = _TxRegistration(participant, description, fd)
                self._tx_by_participant[participant] = registration
                self._tx_by_description[id(description)] = registration
            return None
        if not self._receive_bind_allowed(participant, endpoint):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if _succeeded(record):
            self._receive_ports[id(description)] = endpoint[1]
        return None

    def _classify_getsockname(
        self,
        fd: int,
        description: _OpenDescription,
        registration: _TxRegistration,
        endpoint: Endpoint,
        record: CanonicalRecord,
    ) -> str | None:
        if not _succeeded(record):
            registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if registration.endpoint is not None:
            if (
                endpoint == registration.endpoint
                and description.local == registration.endpoint
                and not description.local_conflict
            ):
                return None
            registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if (
            registration.poisoned
            or registration.stage != len(_TX_SETUP_OPTIONS)
            or fd != registration.original_fd
            or endpoint[0] != "127.0.0.1"
            or endpoint[1] == 0
            or description.local_conflict
        ):
            registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        existing = self._registered_endpoints.get(endpoint[1])
        if existing is not None and existing is not registration:
            registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        registration.endpoint = endpoint
        self._registered_endpoints[endpoint[1]] = registration
        return None

    def _classify_server_operation(
        self, pid: int, transition: Mapping[str, object]
    ) -> str | None:
        fd_value = transition.get("source_fd", transition.get("fd"))
        fd = _fd_number(fd_value)
        description = (
            None if fd is None else self.provenance.socket_description(pid, fd)
        )
        if description is None:
            return self._missing_socket_reason(fd_value)
        return (
            None
            if description.domain in _NEUTRAL_SOCKET_DOMAINS
            else "UNEXPECTED_NETWORK_ATTEMPT"
        )

    def _classify_socket_control(
        self,
        pid: int,
        operation: str,
        transition: Mapping[str, object],
        record: CanonicalRecord,
        pre_description: _OpenDescription | None,
    ) -> str | None:
        fd = _fd_number(transition.get("fd"))
        description = pre_description
        if description is None:
            self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return self._missing_socket_reason(transition.get("fd"))
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        participant = self._participant_index(pid)
        if (
            participant is None
            or participant != self._socket_owners.get(id(description))
            or fd is None
        ):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        registration = self._tx_by_description.get(id(description))
        if registration is not None:
            signature = (
                transition.get("level"),
                transition.get("option"),
                transition.get("value"),
                transition.get("length"),
            )
            exact_reviewed = signature in _TX_SETUP_OPTIONS
            if operation != "setsockopt":
                if registration.endpoint is None:
                    registration.poisoned = True
                return "UNEXPECTED_NETWORK_ATTEMPT"
            if not _succeeded(record):
                if fd == registration.original_fd and exact_reviewed:
                    return None
                registration.poisoned = True
                return "UNEXPECTED_NETWORK_ATTEMPT"
            if (
                registration.endpoint is not None
                or registration.poisoned
                or fd != registration.original_fd
                or registration.stage >= len(_TX_SETUP_OPTIONS)
                or signature != _TX_SETUP_OPTIONS[registration.stage]
            ):
                registration.poisoned = True
                return "UNEXPECTED_NETWORK_ATTEMPT"
            registration.stage += 1
            return None

        receive_port = self._receive_ports.get(id(description))
        if (
            operation == "setsockopt"
            and receive_port in {_SPDP_PORT, _DATA_MULTICAST_PORT}
            and transition.get("option") in {"IP_ADD_MEMBERSHIP", "IP_DROP_MEMBERSHIP"}
            and _valid_multicast_membership(transition)
        ):
            return None
        return "UNEXPECTED_NETWORK_ATTEMPT"

    def _classify_message_io(
        self,
        pid: int,
        syscall: str,
        record: CanonicalRecord,
        pre_description: _OpenDescription | None,
    ) -> str | None:
        fds = record.get("fds")
        if not isinstance(fds, list) or not fds:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        fd_value = fds[0]
        fd = _fd_number(fd_value)
        description = pre_description
        if description is None:
            self._latch_integrity("UNKNOWN_FD_PROVENANCE")
            return self._missing_socket_reason(fd_value)
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        endpoints = _message_endpoints(record, description.peer)
        if endpoints is None or not endpoints:
            registration = self._tx_by_description.get(id(description))
            if registration is not None and registration.endpoint is None:
                registration.poisoned = True
            return "UNEXPECTED_NETWORK_ATTEMPT"
        direction = "outbound" if syscall in _MESSAGE_OUTBOUND else "inbound"
        return self._classify_socket_io(
            pid, fd, description, record, direction, endpoints
        )

    def _classify_raw_io(
        self, pid: int, syscall: str, record: CanonicalRecord
    ) -> str | None:
        fds = record.get("fds")
        if not isinstance(fds, list):
            return None
        directions = _raw_directions(syscall, len(fds))
        for fd_value, direction in zip(fds, directions):
            fd = _fd_number(fd_value)
            description = None if fd is None else self.provenance.description(pid, fd)
            if description is None:
                if _reviewed_raw_nonsocket_annotation(fd_value):
                    continue
                if _fd_is_socket(fd_value):
                    self._latch_integrity("UNKNOWN_FD_PROVENANCE")
                    return "UNEXPECTED_NETWORK_ATTEMPT"
                self._latch_integrity("UNKNOWN_FD_PROVENANCE")
                continue
            if description.kind != "socket":
                continue
            if description.domain in _NEUTRAL_SOCKET_DOMAINS:
                continue
            endpoints = () if description.peer is None else (description.peer,)
            reason = self._classify_socket_io(
                pid, fd, description, record, direction, endpoints
            )
            if reason is not None:
                return reason
        return None

    def _classify_socket_io(
        self,
        pid: int,
        fd: int | None,
        description: _OpenDescription,
        record: CanonicalRecord,
        direction: str,
        endpoints: tuple[Endpoint, ...],
    ) -> str | None:
        registration = self._tx_by_description.get(id(description))
        if registration is not None and registration.endpoint is None:
            registration.poisoned = True
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        participant = self._participant_index(pid)
        if participant is None or participant != self._socket_owners.get(
            id(description)
        ):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if registration is not None:
            if (
                direction != "outbound"
                or registration.endpoint is None
                or registration.poisoned
                or fd != registration.original_fd
                or not endpoints
                or not all(
                    self._tx_destination_allowed(endpoint) for endpoint in endpoints
                )
            ):
                return "UNEXPECTED_NETWORK_ATTEMPT"
            return None
        receive_port = self._receive_ports.get(id(description))
        if direction != "inbound" or receive_port is None or not endpoints:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        return (
            None
            if all(self._registered_source_allowed(endpoint) for endpoint in endpoints)
            else "UNEXPECTED_NETWORK_ATTEMPT"
        )

    def _descriptor_context_valid(
        self,
        pid: int,
        description: _OpenDescription,
        record: CanonicalRecord,
    ) -> bool:
        return (
            description.domain == "AF_INET"
            and "SOCK_DGRAM" in description.socket_type
            and description.protocol in {0, "IPPROTO_UDP"}
            and not description.local_conflict
            and not description.peer_conflict
            and self._network_context_valid(pid, record)
        )

    def _network_context_valid(self, pid: int, record: CanonicalRecord) -> bool:
        participant = self._participant_index(pid)
        valid = self.markers.authorizes(record) and participant is not None
        if valid and self._configured_root_roles.get(pid) == participant:
            self._root_activity.add(participant)
        return valid

    def _receive_bind_allowed(self, participant: int, endpoint: Endpoint) -> bool:
        address, port = endpoint
        if address == "0.0.0.0" and not self._namespace_loopback_only:
            return False
        return address in _LOCAL_ADDRESSES and port in {
            _SPDP_PORT,
            _DATA_MULTICAST_PORT,
            META_PORTS[participant],
            DATA_PORTS[participant],
        }

    @staticmethod
    def _tx_destination_allowed(remote: Endpoint) -> bool:
        if remote == (_SPDP_ADDRESS, _SPDP_PORT):
            return True
        return remote[0] == "127.0.0.1" and remote[1] in range(26660, 26668)

    def _registered_source_allowed(self, remote: Endpoint) -> bool:
        if remote[0] != "127.0.0.1":
            return False
        registration = self._registered_endpoints.get(remote[1])
        return (
            registration is not None
            and registration.endpoint == remote
            and not registration.poisoned
            and self.provenance.description_is_open(registration.description)
        )

    @staticmethod
    def _missing_socket_reason(fd_value: object) -> str:
        del fd_value
        return "UNEXPECTED_NETWORK_ATTEMPT"


def _valid_multicast_membership(transition: Mapping[str, object]) -> bool:
    membership = transition.get("membership")
    return (
        transition.get("level") == "SOL_IP"
        and transition.get("length") == 8
        and isinstance(membership, Mapping)
        and set(membership) == {"group", "interface"}
        and membership.get("group") == _SPDP_ADDRESS
        and membership.get("interface") == "127.0.0.1"
    )


def _raw_directions(syscall: str, fd_count: int) -> tuple[str, ...]:
    if syscall in _OUTBOUND_SYSCALLS:
        return ("outbound",) * fd_count
    if syscall in _INBOUND_SYSCALLS:
        return ("inbound",) * fd_count
    if syscall == "sendfile":
        return ("outbound", "inbound")[:fd_count]
    if syscall in {"splice", "tee", "copy_file_range"}:
        return ("inbound", "outbound")[:fd_count]
    return ()


def _record_endpoints(record: CanonicalRecord) -> tuple[Endpoint, ...]:
    direct = _endpoint(record.get("address"))
    if direct is not None:
        return (direct,)
    messages = record.get("messages")
    if not isinstance(messages, list):
        return ()
    endpoints: list[Endpoint] = []
    for message in messages:
        if isinstance(message, Mapping):
            endpoint = _endpoint(message.get("address"))
            if endpoint is not None:
                endpoints.append(endpoint)
    return tuple(endpoints)


def _message_endpoints(
    record: CanonicalRecord, connected_peer: Endpoint | None
) -> tuple[Endpoint, ...] | None:
    direct = _endpoint(record.get("address"))
    if direct is not None:
        return (direct,)
    messages = record.get("messages")
    if not isinstance(messages, list):
        return (connected_peer,) if connected_peer is not None else None
    endpoints: list[Endpoint] = []
    for message in messages:
        endpoint = (
            _endpoint(message.get("address")) if isinstance(message, Mapping) else None
        )
        if endpoint is None:
            endpoint = connected_peer
        if endpoint is None:
            return None
        endpoints.append(endpoint)
    return tuple(endpoints)


def _contains_scm_rights(value: object) -> bool:
    if isinstance(value, Mapping):
        if "scm_rights" in value:
            return True
        return any(_contains_scm_rights(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_scm_rights(item) for item in value)
    return False


def _endpoint(value: object) -> Endpoint | None:
    if not isinstance(value, Mapping) or value.get("family") != "AF_INET":
        return None
    address = value.get("ip")
    port = _exact_int(value.get("port"))
    if not isinstance(address, str) or port is None or not 0 <= port <= 65535:
        return None
    return address, port


def _fd_number(value: object) -> int | None:
    if not isinstance(value, Mapping):
        return None
    return _exact_int(value.get("fd"))


def _fd_inode(value: object) -> int | None:
    if not isinstance(value, Mapping):
        return None
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        return None
    return _exact_int(provenance.get("inode"))


def _fd_is_socket(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    provenance = value.get("provenance")
    return isinstance(provenance, Mapping) and provenance.get("kind") == "socket"


def _reviewed_raw_nonsocket_annotation(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        return False
    kind = provenance.get("kind")
    if kind not in _REVIEWED_RAW_FD_KINDS:
        return False
    if kind == "path":
        return set(provenance) == {"kind"}
    inode = _exact_int(provenance.get("inode"))
    return set(provenance) == {"kind", "inode"} and inode is not None and inode >= 0


def _succeeded(record: CanonicalRecord) -> bool:
    result = record.get("result")
    if not isinstance(result, Mapping):
        return False
    value = _exact_int(result.get("value"))
    return value is not None and value >= 0


def _exact_int(value: object) -> int | None:
    return value if type(value) is int else None


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
