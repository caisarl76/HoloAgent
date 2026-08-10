"""FD provenance and closed UDP policy for canonical trace records."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Literal, Mapping

from .cyclone_policy import EXPECTED_CONFIG_SHA256


META_PORTS = {0: 26660, 1: 26662, 2: 26664, 3: 26666}
DATA_PORTS = {0: 26661, 1: 26663, 2: 26665, 3: 26667}
_PARTICIPANT_INDEXES = frozenset(range(4))
_LOCAL_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1"})
_NEUTRAL_SOCKET_DOMAINS = frozenset({"AF_UNIX", "AF_NETLINK"})
_REVIEWED_INHERITED_FD_KINDS = frozenset({"character_device", "pipe", "regular_file"})
_SPDP_ADDRESS = "239.255.0.1"
_SPDP_PORT = 26650

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


class ViolationJournal:
    """Append-only policy violations, retaining authoritative first failure."""

    def __init__(self) -> None:
        self._violations: list[PolicyViolation] = []

    def persist(self, violation: PolicyViolation) -> None:
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
    message_peers: list[tuple[str, Endpoint]] = field(default_factory=list)


@dataclass
class _FdEntry:
    description: _OpenDescription
    cloexec: bool = False


class FDProvenance:
    """Model Linux descriptor tables and shared open-file descriptions."""

    def __init__(
        self,
        initial_manifest: Mapping[int, object] | None = None,
    ) -> None:
        self._tables: dict[int, dict[int, _FdEntry]] = {}
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

    def apply(self, record: CanonicalRecord) -> None:
        if record.get("kind") != "syscall":
            return
        pid = _exact_int(record.get("pid"))
        if pid is None:
            return
        self._record_message_peers(pid, record)
        transition = record.get("transition")
        if not isinstance(transition, Mapping):
            return
        operation = transition.get("operation")
        if not isinstance(operation, str):
            return

        if operation == "socket":
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
            if wildcard_refinement:
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
        initial_fd_manifest: Mapping[int, object] | None = None,
    ) -> None:
        self._participants = copy.deepcopy(dict(participants))
        self._namespace_loopback_only = namespace_loopback_only is True
        self._configuration_valid = self._validate_configuration()
        self.provenance = FDProvenance(initial_fd_manifest)
        self.markers = _MarkerWindow(coordinator_pid, marker_token)
        self.journal = ViolationJournal()
        self.trace_integrity_error: str | None = None

    def feed(self, record: CanonicalRecord) -> PolicyDecision:
        self.provenance.apply(record)
        reason = self._classify(record)
        if reason is None:
            return PolicyDecision("PASS", "OK", None)
        violation = PolicyViolation(reason, _exact_int(record.get("record_index")))
        self.journal.persist(violation)
        return PolicyDecision("FAIL", reason, violation.record_index)

    def finalize(self, trace_integrity_ok: bool) -> PolicyDecision:
        first = self.journal.first_violation
        if first is not None:
            return PolicyDecision("FAIL", first.reason, first.record_index)
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
            if _exact_int(pid) is None or not isinstance(participant, Mapping):
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
        participant = self._participants.get(exact_pid)
        if not isinstance(participant, Mapping):
            return None
        return _exact_int(participant.get("index"))

    def _classify(self, record: CanonicalRecord) -> str | None:
        marker_reason = self.markers.consume(record)
        if marker_reason is not None:
            if self.trace_integrity_error is None:
                self.trace_integrity_error = marker_reason
            return None
        if record.get("kind") != "syscall":
            return None

        syscall = record.get("syscall")
        transition = record.get("transition")
        operation = (
            transition.get("operation") if isinstance(transition, Mapping) else None
        )
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

        pid = _exact_int(record.get("pid"))
        if pid is None:
            return None
        if operation in {"socket", "socketpair"} and isinstance(transition, Mapping):
            return self._classify_socket_creation(pid, transition, record)
        if operation in {"bind", "connect", "getsockname", "getpeername"}:
            if isinstance(transition, Mapping):
                return self._classify_endpoint_transition(
                    pid, operation, transition, record
                )
        if operation in {"accept", "accept4", "listen"}:
            if isinstance(transition, Mapping):
                return self._classify_server_operation(pid, transition)
        if operation in {"getsockopt", "setsockopt", "shutdown"}:
            if isinstance(transition, Mapping):
                return self._classify_socket_control(pid, operation, transition, record)
        if syscall in _MESSAGE_OUTBOUND | _MESSAGE_INBOUND:
            return self._classify_message_io(pid, str(syscall), record)
        if syscall in _OUTBOUND_SYSCALLS | _INBOUND_SYSCALLS | {
            "sendfile",
            "splice",
            "tee",
            "copy_file_range",
        }:
            return self._classify_raw_io(pid, str(syscall), record)
        return None

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
        return None

    def _classify_endpoint_transition(
        self,
        pid: int,
        operation: str,
        transition: Mapping[str, object],
        record: CanonicalRecord,
    ) -> str | None:
        fd = _fd_number(transition.get("fd"))
        description = (
            None if fd is None else self.provenance.socket_description(pid, fd)
        )
        if description is None:
            return self._missing_socket_reason(transition.get("fd"))
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        endpoint = _endpoint(transition.get("address"))
        participant = self._participant_index(pid)
        if participant is None or endpoint is None:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if operation in {"bind", "getsockname"}:
            if description.local_conflict or not _bind_allowed(participant, endpoint):
                return "UNEXPECTED_NETWORK_ATTEMPT"
            return None
        if description.peer_conflict or description.local is None:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if not self._outbound_allowed(participant, description.local, endpoint):
            return "UNEXPECTED_NETWORK_ATTEMPT"
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
    ) -> str | None:
        fd = _fd_number(transition.get("fd"))
        description = (
            None if fd is None else self.provenance.socket_description(pid, fd)
        )
        if description is None:
            return self._missing_socket_reason(transition.get("fd"))
        if (
            operation == "setsockopt"
            and transition.get("option") in {"IP_ADD_MEMBERSHIP", "IP_DROP_MEMBERSHIP"}
            and (
                description.domain != "AF_INET"
                or not _valid_multicast_membership(transition)
            )
        ):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if operation == "shutdown":
            participant = self._participant_index(pid)
            if (
                participant is None
                or description.local is None
                or description.peer is None
                or not self._outbound_allowed(
                    participant, description.local, description.peer
                )
            ):
                return "UNEXPECTED_NETWORK_ATTEMPT"
        return None

    def _classify_message_io(
        self, pid: int, syscall: str, record: CanonicalRecord
    ) -> str | None:
        fds = record.get("fds")
        if not isinstance(fds, list) or not fds:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        fd_value = fds[0]
        fd = _fd_number(fd_value)
        description = (
            None if fd is None else self.provenance.socket_description(pid, fd)
        )
        if description is None:
            return self._missing_socket_reason(fd_value)
        if description.domain in _NEUTRAL_SOCKET_DOMAINS:
            return None
        if not self._descriptor_context_valid(pid, description, record):
            return "UNEXPECTED_NETWORK_ATTEMPT"
        participant = self._participant_index(pid)
        if participant is None or description.local is None:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        endpoints = _message_endpoints(record, description.peer)
        if endpoints is None or not endpoints:
            return "UNEXPECTED_NETWORK_ATTEMPT"
        if syscall in _MESSAGE_OUTBOUND:
            allowed = all(
                self._outbound_allowed(participant, description.local, endpoint)
                for endpoint in endpoints
            )
        else:
            allowed = all(
                _inbound_allowed(participant, description.local, endpoint)
                for endpoint in endpoints
            )
        return None if allowed else "UNEXPECTED_NETWORK_ATTEMPT"

    def _classify_raw_io(
        self, pid: int, syscall: str, record: CanonicalRecord
    ) -> str | None:
        fds = record.get("fds")
        if not isinstance(fds, list):
            return None
        directions = _raw_directions(syscall, len(fds))
        for fd_value, direction in zip(fds, directions):
            fd = _fd_number(fd_value)
            description = (
                None if fd is None else self.provenance.socket_description(pid, fd)
            )
            if description is None:
                if _fd_is_socket(fd_value):
                    return "INHERITED_SOCKET_FD"
                continue
            if description.domain in _NEUTRAL_SOCKET_DOMAINS:
                continue
            if not self._descriptor_context_valid(pid, description, record):
                return "UNEXPECTED_NETWORK_ATTEMPT"
            participant = self._participant_index(pid)
            if (
                participant is None
                or description.local is None
                or description.peer is None
            ):
                return "UNEXPECTED_NETWORK_ATTEMPT"
            if direction == "outbound":
                allowed = self._outbound_allowed(
                    participant, description.local, description.peer
                )
            else:
                allowed = _inbound_allowed(
                    participant, description.local, description.peer
                )
            if not allowed:
                return "UNEXPECTED_NETWORK_ATTEMPT"
        return None

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
        return (
            self.markers.authorizes(record) and self._participant_index(pid) is not None
        )

    def _outbound_allowed(
        self, participant: int, local: Endpoint, remote: Endpoint
    ) -> bool:
        local_ip, local_port = local
        if local_ip == "0.0.0.0":
            if not self._namespace_loopback_only:
                return False
            local_ip = "127.0.0.1"
        if local_ip != "127.0.0.1":
            return False
        if remote == (_SPDP_ADDRESS, _SPDP_PORT):
            return local_port == META_PORTS[participant]
        if remote[0] != "127.0.0.1":
            return False
        if local_port == META_PORTS[participant]:
            return remote[1] in META_PORTS.values()
        if local_port == DATA_PORTS[participant]:
            return remote[1] in DATA_PORTS.values()
        return False

    @staticmethod
    def _missing_socket_reason(fd_value: object) -> str:
        return (
            "INHERITED_SOCKET_FD"
            if _fd_is_socket(fd_value)
            else "UNEXPECTED_NETWORK_ATTEMPT"
        )


def _bind_allowed(participant: int, endpoint: Endpoint) -> bool:
    address, port = endpoint
    return address in _LOCAL_ADDRESSES and port in {
        _SPDP_PORT,
        META_PORTS[participant],
        DATA_PORTS[participant],
    }


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


def _inbound_allowed(participant: int, local: Endpoint, remote: Endpoint) -> bool:
    local_address, local_port = local
    remote_address, remote_port = remote
    if local_address not in _LOCAL_ADDRESSES or remote_address != "127.0.0.1":
        return False
    if local_port == _SPDP_PORT:
        return remote_port in META_PORTS.values()
    if local_port == META_PORTS[participant]:
        return remote_port in META_PORTS.values()
    if local_port == DATA_PORTS[participant]:
        return remote_port in DATA_PORTS.values()
    return False


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
