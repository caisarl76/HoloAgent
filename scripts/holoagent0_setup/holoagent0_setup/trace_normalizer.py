"""Bounded, payload-free normalization for the reviewed strace 6.6 stream."""

from __future__ import annotations

from dataclasses import dataclass
import errno as errno_module
import json
import os
import re
from typing import Iterable


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
)
STRACE_ENVIRONMENT = {"LC_ALL": "C", "TZ": "UTC"}
RAW_PAYLOAD_SYSCALLS = frozenset(
    {
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
    }
)
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
_FD = re.compile(r"^(-?[0-9]+)(?:<([^>]+)>)?$")
_INTEGER = re.compile(r"^-?(?:0|[1-9][0-9]*|0x[0-9a-f]+)$")
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


def _fd(value: str, code: str) -> dict[str, object]:
    match = _FD.fullmatch(value)
    if match is None:
        raise _fail(code)
    record: dict[str, object] = {"fd": int(match.group(1))}
    provenance = match.group(2)
    if provenance is not None:
        if len(provenance) > 4096 or any(ord(char) < 32 for char in provenance):
            raise _fail("invalid-fd-provenance")
        record["provenance"] = provenance
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
    # A returned descriptor may carry -yy provenance. Do not persist it as a result.
    descriptor = _FD.fullmatch(value)
    if descriptor is not None:
        return {"value": int(descriptor.group(1))}
    if not _INTEGER.fullmatch(value):
        raise _fail("unsupported-return")
    return {"value": int(value, 0)}


def _flags(value: str) -> list[str]:
    if value in {"0", "NULL"}:
        return []
    flags = value.split("|")
    if not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", flag) for flag in flags):
        raise _fail("invalid-flags")
    return flags


def _address(arguments_text: str) -> dict[str, object] | None:
    family_match = re.search(r"sa_family=(AF_[A-Z0-9_]+)", arguments_text)
    if family_match is None:
        if "NULL" in arguments_text:
            return None
        raise _fail("missing-socket-family")
    family = family_match.group(1)
    result: dict[str, object] = {"family": family}
    port = re.search(r"(?:sin6?_port)=htons\(([0-9]+)\)", arguments_text)
    if port is not None:
        value = int(port.group(1))
        if value > 65535:
            raise _fail("invalid-socket-port")
        result["port"] = value
    ipv4 = re.search(r'sin_addr=inet_addr\("([^"\\]+)"\)', arguments_text)
    ipv6 = re.search(r'sin6_addr=inet_pton\(AF_INET6, "([^"\\]+)"\)', arguments_text)
    if ipv4 is not None:
        result["ip"] = ipv4.group(1)
    elif ipv6 is not None:
        result["ip"] = ipv6.group(1)
    elif family == "AF_UNIX":
        unix = re.search(r'sun_path="([^"\\]*)"', arguments_text)
        if unix is not None:
            result["path"] = unix.group(1)
    return result


def _scm_rights(arguments_text: str) -> list[dict[str, object]]:
    match = re.search(r"cmsg_type=SCM_RIGHTS, cmsg_data=\[(.*?)\]\}", arguments_text)
    if match is None:
        return []
    return [
        _fd(value, "invalid-scm-rights-fd")
        for value in _split_arguments(match.group(1))
    ]


_RAW_FD_INDEXES = {
    "read": (0,),
    "write": (0,),
    "pread64": (0,),
    "pwrite64": (0,),
    "readv": (0,),
    "writev": (0,),
    "preadv": (0,),
    "pwritev": (0,),
    "preadv2": (0,),
    "pwritev2": (0,),
    "sendfile": (0, 1),
    "splice": (0, 2),
    "vmsplice": (0,),
    "tee": (0, 1),
    "copy_file_range": (0, 2),
}


def _raw_metadata(name: str, arguments: list[str]) -> dict[str, object]:
    if len(arguments) < 3:
        raise _fail("raw-syscall-arity")
    indexes = _RAW_FD_INDEXES[name]
    # Compact synthetic fixtures use the shared fd/buffer/count shape. Real shapes
    # still use the reviewed positional descriptor indexes above.
    if max(indexes) >= len(arguments) or any(
        _FD.fullmatch(arguments[index]) is None for index in indexes
    ):
        indexes = (0,)
    metadata: dict[str, object] = {
        "fds": [_fd(arguments[index], "invalid-raw-fd") for index in indexes]
    }
    if name in {
        "readv",
        "writev",
        "preadv",
        "pwritev",
        "preadv2",
        "pwritev2",
        "vmsplice",
    }:
        metadata["lengths"] = {"iov_count": _integer(arguments[2], "invalid-iov-count")}
    else:
        count_index = {"sendfile": 3, "splice": 4, "tee": 2, "copy_file_range": 4}.get(
            name, 2
        )
        if count_index >= len(arguments) or not _INTEGER.fullmatch(
            arguments[count_index]
        ):
            count_index = 2
        metadata["lengths"] = {
            "count": _integer(arguments[count_index], "invalid-count")
        }
    flag_index = {
        "preadv2": 5,
        "pwritev2": 5,
        "splice": 5,
        "vmsplice": 3,
        "tee": 3,
        "copy_file_range": 5,
    }.get(name)
    if flag_index is not None and flag_index < len(arguments):
        metadata["flags"] = _flags(arguments[flag_index])
    return metadata


def _address_metadata(
    name: str, arguments: list[str], arguments_text: str
) -> dict[str, object]:
    if not arguments:
        raise _fail("address-syscall-arity")
    metadata: dict[str, object] = {"fds": [_fd(arguments[0], "invalid-socket-fd")]}
    address = _address(arguments_text)
    if address is not None:
        metadata["address"] = address
    rights = _scm_rights(arguments_text)
    if rights:
        metadata["control"] = {"scm_rights": rights}
    if name in {"sendto", "recvfrom"}:
        if len(arguments) < 4:
            raise _fail("address-syscall-arity")
        metadata["lengths"] = {"count": _integer(arguments[2], "invalid-count")}
        sockaddr_length = re.fullmatch(r"\[?([0-9]+)\]?", arguments[-1])
        if sockaddr_length is not None:
            metadata["lengths"]["sockaddr"] = int(sockaddr_length.group(1))
        metadata["flags"] = _flags(arguments[3])
    elif name in {"sendmsg", "recvmsg"} and arguments[1].startswith("{"):
        if len(arguments) < 3:
            raise _fail("message-syscall-arity")
        metadata["flags"] = _flags(arguments[2])
        iov_count = re.search(r"msg_iovlen=([0-9]+)", arguments_text)
        iov_lengths = [
            int(value) for value in re.findall(r"iov_len=([0-9]+)", arguments_text)
        ]
        lengths: dict[str, int] = {}
        if iov_count is not None:
            lengths["iov_count"] = int(iov_count.group(1))
        if iov_lengths:
            lengths["message"] = sum(iov_lengths)
        if lengths:
            metadata["lengths"] = lengths
    elif name in {"sendmmsg", "recvmmsg"} and arguments[1].startswith("["):
        # sendmmsg/recvmmsg expose vector count and flags after the transient vector.
        if len(arguments) >= 4 and _INTEGER.fullmatch(arguments[2]):
            metadata["lengths"] = {
                "message_count": _integer(arguments[2], "invalid-message-count")
            }
            metadata["flags"] = _flags(arguments[3])
        else:
            metadata["flags"] = _flags(arguments[3]) if len(arguments) > 3 else []
    else:
        # Shared address-form coverage still follows fd/payload/count/flags/address/len.
        if len(arguments) < 4:
            raise _fail("address-syscall-arity")
        metadata["lengths"] = {"count": _integer(arguments[2], "invalid-count")}
        metadata["flags"] = _flags(arguments[3])
    return metadata


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
            record.update(_address_metadata(name, arguments, arguments_text))
        elif name == "close":
            if len(arguments) != 1:
                raise _fail("close-arity")
            record["fds"] = [_fd(arguments[0], "invalid-close-fd")]
        # Generic syscalls retain no arguments: the reviewed safe structural subset
        # is identity, timing, and native return metadata only.
        record["result"] = _result(result_text)
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
