"""Bounded, payload-free normalization for the reviewed strace 6.6 stream."""

from __future__ import annotations

from dataclasses import dataclass
import errno as errno_module
import ipaddress
import json
import os
import re
from typing import Iterable


RAW_PAYLOAD_SYSCALL_ORDER = (
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "sendfile",
    "splice",
    "vmsplice",
    "tee",
    "copy_file_range",
)
STRACE_ARGUMENTS = (
    "--kill-on-exit",
    "-f",
    "-yy",
    "-ttt",
    "-T",
    "--no-abbrev",
    "--string-limit=1048576",
    "--quiet=none",
    "--trace=all",
    f"--raw={','.join(RAW_PAYLOAD_SYSCALL_ORDER)}",
)
STRACE_ENVIRONMENT = {"LC_ALL": "C", "TZ": "UTC"}
RAW_PAYLOAD_SYSCALLS = frozenset(RAW_PAYLOAD_SYSCALL_ORDER)
DECODED_ADDRESS_SYSCALLS = frozenset(
    {"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
)

_PREFIX = re.compile(r"^([1-9][0-9]*) ([0-9]+(?:\.[0-9]+)?) (.+)$")
_CALL = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\) = (.+) <([0-9]+(?:\.[0-9]+)?)>$")
_UNFINISHED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)<unfinished \.\.\.>$")
_RESUMED = re.compile(r"^<\.\.\. ([A-Za-z_][A-Za-z0-9_]*) resumed>(.*)$")
_SIGNAL = re.compile(r"^--- (SIG[A-Z0-9]+) \{.*\} ---$")
_EXITED = re.compile(r"^\+\+\+ exited with ([0-9]+) \+\+\+$")
_KILLED = re.compile(r"^\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
_NUMBER_TEXT = r"(?:0|[1-9][0-9]*|0x[0-9a-f]+)"
_FD = re.compile(r"^([0-9]+)(?:<([^>]*)>)?$")
_INTEGER = re.compile(rf"^-?{_NUMBER_TEXT}$")
_RAW_INTEGER = re.compile(r"^(?:0|0x[0-9a-f]+)$")
_ERRNO = re.compile(r"^(-1) ([A-Z][A-Z0-9_]*) \(([^\r\n()]*)\)$")


class TraceDecodeError(ValueError):
    """The stream is outside the single reviewed strace serialization."""


@dataclass(frozen=True)
class _Pending:
    syscall: str
    arguments_prefix: str
    timestamp: str
    entry_index: int


def _fail(code: str) -> TraceDecodeError:
    # Error text deliberately excludes source text, which may contain payload bytes.
    return TraceDecodeError(f"strace decode rejected: {code}")


def _split_arguments(value: str) -> list[str]:
    if not value:
        return []
    result: list[str] = []
    start = 0
    stack: list[str] = []
    quote = False
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = False
            continue
        if character == '"':
            quote = True
        elif character in pairs:
            stack.append(pairs[character])
        elif character in ")]}":
            if not stack or stack.pop() != character:
                raise _fail("unbalanced-arguments")
        elif character == "," and not stack:
            result.append(value[start:index].strip())
            start = index + 1
    if quote or escaped or stack:
        raise _fail("unbalanced-arguments")
    result.append(value[start:].strip())
    if any(not item for item in result):
        raise _fail("empty-argument")
    return result


def _integer(value: str, code: str) -> int:
    if not _INTEGER.fullmatch(value):
        raise _fail(code)
    try:
        return int(value, 0)
    except ValueError as error:  # pragma: no cover - guarded by the expression
        raise _fail(code) from error


def _raw_integer(value: str, code: str) -> int:
    if _RAW_INTEGER.fullmatch(value) is None:
        raise _fail(code)
    return int(value, 0)


def _provenance(value: str) -> dict[str, object]:
    inode = re.fullmatch(r"(socket|pipe):\[([0-9]+)\]", value)
    if inode is not None:
        return {"kind": inode.group(1), "inode": int(inode.group(2))}
    anon = re.fullmatch(r"anon_inode:\[([A-Za-z0-9_-]+)\]", value)
    if anon is not None:
        return {"kind": "anon_inode", "type": anon.group(1)}
    if value.startswith("/"):
        return {"kind": "path"}
    raise _fail("unsupported-fd-provenance")


def _fd(value: str, code: str) -> dict[str, object]:
    match = _FD.fullmatch(value)
    if match is None:
        raise _fail(code)
    record: dict[str, object] = {"fd": int(match.group(1), 0)}
    provenance = match.group(2)
    if provenance is not None:
        if len(provenance) > 4096 or any(ord(char) < 32 for char in provenance):
            raise _fail("invalid-fd-provenance")
        record["provenance"] = _provenance(provenance)
    return record


def _result(value: str) -> dict[str, object]:
    errno = _ERRNO.fullmatch(value)
    if errno is not None:
        errno_number = next(
            (
                number
                for number, name in errno_module.errorcode.items()
                if name == errno.group(2)
            ),
            None,
        )
        if errno_number is None or os.strerror(errno_number) != errno.group(3):
            raise _fail("noncanonical-errno")
        return {
            "value": -1,
            "errno": errno.group(2),
            "errno_text": errno.group(3),
        }
    descriptor = _FD.fullmatch(value)
    if descriptor is not None:
        fd = _fd(value, "invalid-return-fd")
        result: dict[str, object] = {"value": fd["fd"]}
        if descriptor.group(2) is not None:
            result["fd"] = fd
        return result
    if not _INTEGER.fullmatch(value):
        raise _fail("unsupported-return")
    return {"value": int(value, 0)}


def _raw_result(value: str) -> dict[str, object]:
    errno = _ERRNO.fullmatch(value)
    if errno is not None:
        return _result(value)
    return {"value": _raw_integer(value, "invalid-raw-return")}


def _flags(value: str) -> list[str]:
    if value in {"0", "NULL"}:
        return []
    flags = value.split("|")
    if not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", flag) for flag in flags):
        raise _fail("invalid-flags")
    return flags


def _fields(value: str, code: str) -> dict[str, str]:
    if not (value.startswith("{") and value.endswith("}")):
        raise _fail(code)
    inner = value[1:-1]
    result: dict[str, str] = {}
    for item in _split_arguments(inner):
        key, separator, field_value = item.partition("=")
        if (
            separator != "="
            or re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            or key in result
            or not field_value
        ):
            raise _fail(code)
        result[key] = field_value
    return result


def _vector(value: str, code: str) -> list[str]:
    if not (value.startswith("[") and value.endswith("]")):
        raise _fail(code)
    inner = value[1:-1]
    return [] if not inner else _split_arguments(inner)


def _address(value: str) -> dict[str, object] | None:
    if value == "NULL":
        return None
    fields = _fields(value, "sockaddr-grammar")
    family = fields.get("sa_family")
    if family not in {"AF_INET", "AF_INET6", "AF_UNIX"}:
        raise _fail("unsupported-socket-family")
    result: dict[str, object] = {"family": family}
    if family == "AF_INET":
        if set(fields) != {"sa_family", "sin_port", "sin_addr"}:
            raise _fail("sockaddr-inet-fields")
        port = re.fullmatch(r"htons\(([0-9]+)\)", fields["sin_port"])
        address = re.fullmatch(r'inet_addr\("([^"\\]+)"\)', fields["sin_addr"])
        if port is None or address is None:
            raise _fail("sockaddr-inet-values")
        try:
            ip = str(ipaddress.IPv4Address(address.group(1)))
        except ipaddress.AddressValueError as error:
            raise _fail("sockaddr-inet-address") from error
    elif family == "AF_INET6":
        if set(fields) != {"sa_family", "sin6_port", "sin6_addr"}:
            raise _fail("sockaddr-inet6-fields")
        port = re.fullmatch(r"htons\(([0-9]+)\)", fields["sin6_port"])
        address = re.fullmatch(
            r'inet_pton\(AF_INET6, "([^"\\]+)"\)', fields["sin6_addr"]
        )
        if port is None or address is None:
            raise _fail("sockaddr-inet6-values")
        try:
            ip = str(ipaddress.IPv6Address(address.group(1)))
        except ipaddress.AddressValueError as error:
            raise _fail("sockaddr-inet6-address") from error
    else:
        if set(fields) != {"sa_family", "sun_path"}:
            raise _fail("sockaddr-unix-fields")
        if re.fullmatch(r'"(?:[^"\\]|\\.)*"', fields["sun_path"]) is None:
            raise _fail("sockaddr-unix-path")
        result["path"] = {"kind": "unix"}
        return result
    port_value = int(port.group(1))
    if port_value > 65535:
        raise _fail("invalid-socket-port")
    result.update(port=port_value, ip=ip)
    return result


def _control(value: str) -> dict[str, object] | None:
    if value == "NULL":
        return None
    groups: list[list[dict[str, object]]] = []
    for item in _vector(value, "control-vector"):
        fields = _fields(item, "control-message")
        if fields.get("cmsg_type") != "SCM_RIGHTS":
            continue
        if fields.get("cmsg_level") != "SOL_SOCKET" or "cmsg_data" not in fields:
            raise _fail("scm-rights-fields")
        descriptors = [
            _fd(fd, "invalid-scm-rights-fd")
            for fd in _vector(fields["cmsg_data"], "scm-rights-vector")
        ]
        if not descriptors:
            raise _fail("empty-scm-rights")
        groups.append(descriptors)
    return None if not groups else {"scm_rights": groups}


def _message(value: str) -> dict[str, object]:
    fields = _fields(value, "message-header")
    required = {
        "msg_name",
        "msg_namelen",
        "msg_iov",
        "msg_iovlen",
        "msg_control",
        "msg_controllen",
        "msg_flags",
    }
    if set(fields) != required:
        raise _fail("message-header-fields")
    iov_count = _integer(fields["msg_iovlen"], "invalid-message-iov-count")
    if iov_count != len(_vector(fields["msg_iov"], "message-iov-vector")):
        raise _fail("message-iov-count-mismatch")
    result: dict[str, object] = {"lengths": {"iov_count": iov_count}}
    address = _address(fields["msg_name"])
    if address is not None:
        result["address"] = address
    control = _control(fields["msg_control"])
    if control is not None:
        result["control"] = control
    return result


_RAW_GRAMMAR = {
    "read": (3, (0,), 2, None, "count"),
    "readv": (3, (0,), 2, None, "iov_count"),
    "pread64": (4, (0,), 2, None, "count"),
    "preadv": (4, (0,), 2, None, "iov_count"),
    "preadv2": (6, (0,), 2, 5, "iov_count"),
    "write": (3, (0,), 2, None, "count"),
    "writev": (3, (0,), 2, None, "iov_count"),
    "pwrite64": (4, (0,), 2, None, "count"),
    "pwritev": (4, (0,), 2, None, "iov_count"),
    "pwritev2": (6, (0,), 2, 5, "iov_count"),
    "sendfile": (4, (0, 1), 3, None, "count"),
    "splice": (6, (0, 2), 4, 5, "count"),
    "vmsplice": (4, (0,), 2, 3, "iov_count"),
    "tee": (4, (0, 1), 2, 3, "count"),
    "copy_file_range": (6, (0, 2), 4, 5, "count"),
}


def _raw_metadata(name: str, arguments: list[str]) -> dict[str, object]:
    arity, fd_indexes, length_index, flag_index, length_key = _RAW_GRAMMAR[name]
    if len(arguments) != arity:
        raise _fail("raw-syscall-arity")
    for index, argument in enumerate(arguments):
        if index in fd_indexes:
            _raw_integer(argument, "invalid-raw-fd")
        else:
            _raw_integer(argument, "invalid-raw-number")
    metadata: dict[str, object] = {
        "fds": [
            {"fd": _raw_integer(arguments[index], "invalid-raw-fd")}
            for index in fd_indexes
        ],
        "lengths": {
            length_key: _raw_integer(arguments[length_index], "invalid-raw-length")
        },
    }
    if flag_index is not None:
        metadata["flags"] = _raw_integer(arguments[flag_index], "invalid-raw-flags")
    return metadata


def _address_metadata(name: str, arguments: list[str]) -> dict[str, object]:
    arity = {
        "sendto": 6,
        "recvfrom": 6,
        "sendmsg": 3,
        "recvmsg": 3,
        "sendmmsg": 4,
        "recvmmsg": 5,
    }[name]
    if len(arguments) != arity:
        raise _fail("address-syscall-arity")
    metadata: dict[str, object] = {"fds": [_fd(arguments[0], "invalid-socket-fd")]}
    if name in {"sendto", "recvfrom"}:
        metadata["lengths"] = {"count": _integer(arguments[2], "invalid-count")}
        sockaddr_length = re.fullmatch(r"\[?([0-9]+)\]?", arguments[-1])
        if sockaddr_length is None:
            raise _fail("invalid-sockaddr-length")
        metadata["lengths"]["sockaddr"] = int(sockaddr_length.group(1))
        metadata["flags"] = _flags(arguments[3])
        address = _address(arguments[4])
        if address is not None:
            metadata["address"] = address
    elif name in {"sendmsg", "recvmsg"}:
        message = _message(arguments[1])
        metadata.update(message)
        metadata["flags"] = _flags(arguments[2])
    else:
        messages = []
        for item in _vector(arguments[1], "message-vector"):
            fields = _fields(item, "message-vector-entry")
            if set(fields) != {"msg_hdr", "msg_len"}:
                raise _fail("message-vector-entry-fields")
            messages.append(_message(fields["msg_hdr"]))
        message_count = _integer(arguments[2], "invalid-message-count")
        if len(messages) != message_count:
            raise _fail("message-vector-count-mismatch")
        metadata["messages"] = messages
        metadata["lengths"] = {"message_count": message_count}
        metadata["flags"] = _flags(arguments[3])
    return metadata


_TRANSITION_SYSCALLS = frozenset(
    {
        "socket",
        "socketpair",
        "accept",
        "accept4",
        "bind",
        "connect",
        "getsockname",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "fork",
        "vfork",
        "clone",
        "execve",
        "close",
        "close_range",
        "unshare",
        "pidfd_getfd",
    }
)


def _arity(arguments: list[str], expected: int, code: str) -> None:
    if len(arguments) != expected:
        raise _fail(code)


def _returned_fd(result: dict[str, object], code: str) -> dict[str, object]:
    descriptor = result.get("fd")
    if not isinstance(descriptor, dict):
        raise _fail(code)
    return descriptor


def _named_arguments(arguments: list[str], code: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for argument in arguments:
        key, separator, value = argument.partition("=")
        if (
            separator != "="
            or re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            or key in result
            or not value
        ):
            raise _fail(code)
        result[key] = value
    return result


def _transition_metadata(
    name: str, arguments: list[str], result: dict[str, object]
) -> dict[str, object]:
    transition: dict[str, object] = {"operation": name}
    if name == "socket":
        _arity(arguments, 3, "socket-arity")
        transition.update(
            domain=arguments[0],
            socket_type=_flags(arguments[1]),
            created_fd=_returned_fd(result, "socket-return-fd"),
        )
    elif name == "socketpair":
        _arity(arguments, 4, "socketpair-arity")
        descriptors = [
            _fd(value, "socketpair-fd")
            for value in _vector(arguments[3], "socketpair-vector")
        ]
        if len(descriptors) != 2:
            raise _fail("socketpair-count")
        transition.update(
            domain=arguments[0],
            socket_type=_flags(arguments[1]),
            created_fds=descriptors,
        )
    elif name in {"accept", "accept4"}:
        _arity(arguments, 3 if name == "accept" else 4, f"{name}-arity")
        transition.update(
            source_fd=_fd(arguments[0], f"{name}-source-fd"),
            address=_address(arguments[1]),
            created_fd=_returned_fd(result, f"{name}-return-fd"),
        )
        if name == "accept4":
            transition["flags"] = _flags(arguments[3])
    elif name in {"bind", "connect", "getsockname"}:
        _arity(arguments, 3, f"{name}-arity")
        transition.update(
            fd=_fd(arguments[0], f"{name}-fd"),
            address=_address(arguments[1]),
        )
    elif name == "dup":
        _arity(arguments, 1, "dup-arity")
        transition.update(
            source_fd=_fd(arguments[0], "dup-source-fd"),
            created_fd=_returned_fd(result, "dup-return-fd"),
        )
    elif name in {"dup2", "dup3"}:
        _arity(arguments, 2 if name == "dup2" else 3, f"{name}-arity")
        transition.update(
            source_fd=_fd(arguments[0], f"{name}-source-fd"),
            target_fd=_fd(arguments[1], f"{name}-target-fd"),
            created_fd=_returned_fd(result, f"{name}-return-fd"),
        )
        if name == "dup3":
            transition["flags"] = _flags(arguments[2])
    elif name == "fcntl":
        _arity(arguments, 3, "fcntl-arity")
        if arguments[1] not in {"F_DUPFD", "F_DUPFD_CLOEXEC"}:
            raise _fail("unreviewed-fcntl-command")
        transition.update(
            operation="fcntl_dup",
            source_fd=_fd(arguments[0], "fcntl-source-fd"),
            minimum_fd=_integer(arguments[2], "fcntl-minimum-fd"),
            cloexec=arguments[1] == "F_DUPFD_CLOEXEC",
            created_fd=_returned_fd(result, "fcntl-return-fd"),
        )
    elif name in {"fork", "vfork"}:
        _arity(arguments, 0, f"{name}-arity")
        transition.update(
            child_pid=result["value"],
            fd_table="copied" if name == "fork" else "shared-until-exec",
        )
    elif name == "clone":
        fields = _named_arguments(arguments, "clone-arguments")
        flags = fields.get("flags")
        if flags is None:
            raise _fail("clone-flags")
        flag_names = _flags(flags)
        transition.update(
            child_pid=result["value"],
            flags=flag_names,
            fd_table="shared" if "CLONE_FILES" in flag_names else "copied",
        )
    elif name == "execve":
        _arity(arguments, 3, "execve-arity")
        if result.get("value") != 0:
            raise _fail("execve-not-successful")
        transition.update(operation="exec", cloexec_fds="closed")
    elif name == "close":
        _arity(arguments, 1, "close-arity")
        transition["closed_fd"] = _fd(arguments[0], "close-fd")
    elif name == "close_range":
        _arity(arguments, 3, "close-range-arity")
        transition.update(
            first_fd=_integer(arguments[0], "close-range-first"),
            last_fd=_integer(arguments[1], "close-range-last"),
            flags=_flags(arguments[2]),
        )
    elif name == "unshare":
        _arity(arguments, 1, "unshare-arity")
        flags = _flags(arguments[0])
        if "CLONE_FILES" not in flags:
            raise _fail("unreviewed-unshare")
        transition.update(operation="unshare_files", flags=flags)
    elif name == "pidfd_getfd":
        _arity(arguments, 3, "pidfd-getfd-arity")
        if _integer(arguments[2], "pidfd-getfd-flags") != 0:
            raise _fail("pidfd-getfd-nonzero-flags")
        transition.update(
            pidfd=_fd(arguments[0], "pidfd-getfd-pidfd"),
            target_fd=_integer(arguments[1], "pidfd-getfd-target"),
            created_fd=_returned_fd(result, "pidfd-getfd-return-fd"),
        )
    return transition


class TraceNormalizer:
    """Incrementally normalize one canonical linux-x86_64 strace 6.6 stream."""

    def __init__(
        self,
        *,
        max_line_bytes: int = 2_097_152,
        max_records: int = 1_000_000,
        max_pending_processes: int = 4096,
        max_input_bytes: int = 67_108_864,
    ) -> None:
        bounds = (max_line_bytes, max_records, max_pending_processes, max_input_bytes)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in bounds
        ):
            raise ValueError("trace bounds must be positive integers")
        self.max_line_bytes = max_line_bytes
        self.max_records = max_records
        self.max_pending_processes = max_pending_processes
        self.max_input_bytes = max_input_bytes
        self._buffer = bytearray()
        self._input_bytes = 0
        self._pending: dict[int, _Pending] = {}
        self._records = 0
        self._entries = 0
        self._exits = 0
        self._finished = False

    def feed(self, chunk: bytes) -> list[dict[str, object]]:
        if self._finished:
            raise TraceDecodeError("strace decode rejected: feed-after-finish")
        if not isinstance(chunk, bytes):
            raise TypeError("trace chunks must be bytes")
        self._input_bytes += len(chunk)
        if self._input_bytes > self.max_input_bytes:
            raise _fail("input-bound")
        self._buffer.extend(chunk)
        records: list[dict[str, object]] = []
        while True:
            newline = self._buffer.find(b"\n")
            if newline < 0:
                if len(self._buffer) > self.max_line_bytes:
                    raise _fail("line-bound")
                break
            if newline > self.max_line_bytes:
                raise _fail("line-bound")
            line = bytes(self._buffer[:newline])
            del self._buffer[: newline + 1]
            records.extend(self._decode_line(line))
        return records

    def finish(self) -> list[dict[str, object]]:
        if self._finished:
            raise TraceDecodeError("strace decode rejected: duplicate-finish")
        self._finished = True
        if self._buffer:
            raise _fail("truncated-line")
        if self._pending:
            raise _fail("pending-syscall")
        return []

    def _decode_line(self, encoded: bytes) -> list[dict[str, object]]:
        if not encoded or b"\r" in encoded or b"\x00" in encoded:
            raise _fail("noncanonical-line")
        try:
            line = encoded.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise _fail("noncanonical-encoding") from error
        if any(ord(character) < 32 for character in line):
            raise _fail("control-character")
        prefix = _PREFIX.fullmatch(line)
        if prefix is None:
            raise _fail("line-grammar")
        pid = int(prefix.group(1))
        timestamp = prefix.group(2)
        body = prefix.group(3)
        if "runs in " in body and " bit mode" in body:
            raise _fail("unsupported-personality")

        unfinished = _UNFINISHED.fullmatch(body)
        if unfinished is not None:
            if pid in self._pending:
                raise _fail("duplicate-unfinished")
            if len(self._pending) >= self.max_pending_processes:
                raise _fail("pending-process-bound")
            entry_index = self._entries
            self._entries += 1
            self._pending[pid] = _Pending(
                syscall=unfinished.group(1),
                arguments_prefix=unfinished.group(2),
                timestamp=timestamp,
                entry_index=entry_index,
            )
            return []

        resumed = _RESUMED.fullmatch(body)
        if resumed is not None:
            pending = self._pending.pop(pid, None)
            if pending is None:
                raise _fail("orphan-resumed")
            if pending.syscall != resumed.group(1):
                raise _fail("resumed-syscall-mismatch")
            exit_index = self._exits
            self._exits += 1
            combined = f"{pending.syscall}({pending.arguments_prefix}{resumed.group(2)}"
            return [
                self._decode_complete(
                    pid, pending.timestamp, combined, pending.entry_index, exit_index
                )
            ]

        signal = _SIGNAL.fullmatch(body)
        if signal is not None:
            return [
                self._emit(
                    {
                        "kind": "signal",
                        "pid": pid,
                        "timestamp": timestamp,
                        "signal": signal.group(1),
                    }
                )
            ]
        exited = _EXITED.fullmatch(body)
        if exited is not None:
            if pid in self._pending:
                raise _fail("exit-with-pending-syscall")
            return [
                self._emit(
                    {
                        "kind": "exit",
                        "pid": pid,
                        "timestamp": timestamp,
                        "exit_code": int(exited.group(1)),
                    }
                )
            ]
        killed = _KILLED.fullmatch(body)
        if killed is not None:
            if pid in self._pending:
                raise _fail("exit-with-pending-syscall")
            return [
                self._emit(
                    {
                        "kind": "exit",
                        "pid": pid,
                        "timestamp": timestamp,
                        "signal": killed.group(1),
                    }
                )
            ]

        entry_index = self._entries
        exit_index = self._exits
        self._entries += 1
        self._exits += 1
        return [self._decode_complete(pid, timestamp, body, entry_index, exit_index)]

    def _decode_complete(
        self, pid: int, timestamp: str, body: str, entry_index: int, exit_index: int
    ) -> dict[str, object]:
        if "..." in body:
            raise _fail("abbreviated-field")
        call = _CALL.fullmatch(body)
        if call is None:
            raise _fail("syscall-grammar")
        name, arguments_text, result_text, duration = call.groups()
        arguments = _split_arguments(arguments_text)
        record: dict[str, object] = {
            "kind": "syscall",
            "pid": pid,
            "timestamp": timestamp,
            "duration": duration,
            "entry_index": entry_index,
            "exit_index": exit_index,
            "syscall": name,
        }
        if name in RAW_PAYLOAD_SYSCALLS:
            record.update(_raw_metadata(name, arguments))
        elif name in DECODED_ADDRESS_SYSCALLS:
            record.update(_address_metadata(name, arguments))
        # Generic syscalls retain no arguments: the reviewed safe structural subset
        # is identity, timing, and native return metadata only.
        result = (
            _raw_result(result_text)
            if name in RAW_PAYLOAD_SYSCALLS
            else _result(result_text)
        )
        record["result"] = result
        if name in _TRANSITION_SYSCALLS:
            record["transition"] = _transition_metadata(name, arguments, result)
        return self._emit(record)

    def _emit(self, record: dict[str, object]) -> dict[str, object]:
        if self._records >= self.max_records:
            raise _fail("record-bound")
        record["record_index"] = self._records
        self._records += 1
        return record


def normalize_bytes(source: bytes, **bounds: int) -> list[dict[str, object]]:
    normalizer = TraceNormalizer(**bounds)
    records = normalizer.feed(source)
    records.extend(normalizer.finish())
    return records


def normalize_lines(lines: Iterable[bytes], **bounds: int) -> list[dict[str, object]]:
    normalizer = TraceNormalizer(**bounds)
    records: list[dict[str, object]] = []
    for line in lines:
        records.extend(normalizer.feed(line))
    records.extend(normalizer.finish())
    return records


def canonical_ndjson(records: Iterable[dict[str, object]]) -> str:
    return "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
        for record in records
    )
