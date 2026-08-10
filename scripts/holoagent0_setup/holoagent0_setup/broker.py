"""Bounded canonical messages over reviewed anonymous pipes only."""

from __future__ import annotations

from enum import Enum
import fcntl
import math
import os
from pathlib import Path
import select
import stat
import time
from typing import Callable

from holoagent0_setup.atomic_io import (
    AtomicIOError,
    CanonicalJSONError,
    _decode_canonical_json,
    canonical_json_bytes,
)
from holoagent0_setup.process_identity import ProcessIdentity, ProcessIdentityError


class BrokerProtocolError(RuntimeError):
    """A broker frame or local pipe operation violated the closed protocol."""


class MessageType(str, Enum):
    SIGNAL_READY = "SIGNAL_READY"
    SIGNAL_READY_ACCEPTED = "SIGNAL_READY_ACCEPTED"
    LEDGER_CANDIDATE = "LEDGER_CANDIDATE"
    LEDGER_ACCEPTED = "LEDGER_ACCEPTED"
    OWNERSHIP_RECORD = "OWNERSHIP_RECORD"


MAX_PAYLOAD_BYTES = 4096
MAX_LEDGER_CANDIDATE_PAYLOAD_BYTES = 65536
MAX_FRAME_PAYLOAD_BYTES = 65536
_DEFAULT_TIMEOUT_SECONDS = 1.0
_MAX_DEADLINE_INTERVAL_SECONDS = 30.0
_SIGNALS = ["HUP", "INT", "TERM"]
_IDENTITY_KEYS = {
    "pid",
    "pgid",
    "start_time",
    "executable_path",
    "executable_sha256",
}
_MESSAGE_KEYS = {
    MessageType.SIGNAL_READY: {
        "type",
        "run_nonce",
        "sequence",
        "identity",
        "blocked_signals",
        "dispositions",
    },
    MessageType.SIGNAL_READY_ACCEPTED: {
        "type",
        "run_nonce",
        "identity",
        "request_sequence",
        "request_sha256",
    },
    MessageType.LEDGER_CANDIDATE: {
        "type",
        "run_nonce",
        "sequence",
        "generation",
        "previous_generation",
        "previous_digest",
        "candidate",
    },
    MessageType.LEDGER_ACCEPTED: {
        "type",
        "run_nonce",
        "sequence",
        "generation",
        "ledger_sha256",
    },
    MessageType.OWNERSHIP_RECORD: {
        "type",
        "run_nonce",
        "sequence",
        "identity",
        "role",
    },
}


def write_frame(
    fd: int,
    message: object,
    *,
    deadline: int | float | None = None,
    ledger_validator: Callable[[dict[str, object]], bool] | None = None,
) -> None:
    """Write one canonical length-prefixed message before an absolute deadline."""

    _require_fd(fd)
    absolute_deadline = _deadline(deadline)
    stable_fd = _duplicate_broker_fd(fd)
    try:
        _require_anonymous_pipe(stable_fd, readable=False)
        try:
            payload = canonical_json_bytes(message)
        except (CanonicalJSONError, RuntimeError) as error:
            raise BrokerProtocolError(
                "message cannot be encoded canonically"
            ) from error
        if not payload or len(payload) > _payload_limit(message):
            raise BrokerProtocolError("frame exceeds reviewed bound")
        _decode_canonical_message(payload, ledger_validator=ledger_validator)
        _write_all(
            stable_fd,
            len(payload).to_bytes(4, "big") + payload,
            absolute_deadline,
        )
    finally:
        _close_no_throw(stable_fd)


def read_frame(
    fd: int,
    *,
    deadline: int | float | None = None,
    exact_one: bool = False,
    ledger_validator: Callable[[dict[str, object]], bool] | None = None,
) -> dict[str, object]:
    """Read and validate one canonical message from an anonymous pipe."""

    _require_fd(fd)
    if type(exact_one) is not bool:
        raise BrokerProtocolError("exact_one must be an exact boolean")
    absolute_deadline = _deadline(deadline)
    stable_fd = _duplicate_broker_fd(fd)
    try:
        _require_anonymous_pipe(stable_fd, readable=True)
        prefix = _read_exact(stable_fd, 4, absolute_deadline, "length prefix")
        length = int.from_bytes(prefix, "big")
        if length == 0:
            raise BrokerProtocolError("zero-length frames are prohibited")
        if length > MAX_FRAME_PAYLOAD_BYTES:
            raise BrokerProtocolError("frame exceeds reviewed bound")
        payload = _read_exact(stable_fd, length, absolute_deadline, "payload")
        value = _decode_canonical_value(payload)
        if length > _payload_limit(value):
            raise BrokerProtocolError("frame exceeds reviewed bound")
        message = validate_message(value, ledger_validator=ledger_validator)
        if exact_one:
            _require_channel_eof(stable_fd, absolute_deadline)
        return message
    finally:
        _close_no_throw(stable_fd)


def validate_message(
    message: object,
    *,
    ledger_validator: Callable[[dict[str, object]], bool] | None = None,
) -> dict[str, object]:
    """Validate and return one exact closed protocol object."""

    if type(message) is not dict:
        raise BrokerProtocolError("broker message must be an exact object")
    message_type_value = message.get("type")
    if type(message_type_value) is not str:
        raise BrokerProtocolError("broker message type must be an exact string")
    try:
        message_type = MessageType(message_type_value)
    except ValueError as error:
        raise BrokerProtocolError("unknown broker message type") from error
    if set(message) != _MESSAGE_KEYS[message_type] or any(
        type(key) is not str for key in message
    ):
        raise BrokerProtocolError("broker message keys are not closed")
    _require_nonce(message["run_nonce"])

    if message_type is MessageType.SIGNAL_READY:
        _require_sequence(message["sequence"], "sequence")
        _require_identity(message["identity"])
        if (
            type(message["blocked_signals"]) is not list
            or message["blocked_signals"] != _SIGNALS
        ):
            raise BrokerProtocolError("blocked signal mask is not exact")
        dispositions = message["dispositions"]
        if (
            type(dispositions) is not dict
            or set(dispositions) != set(_SIGNALS)
            or any(
                type(value) is not bool or not value for value in dispositions.values()
            )
        ):
            raise BrokerProtocolError(
                "signal dispositions are not exact and successful"
            )
    elif message_type is MessageType.SIGNAL_READY_ACCEPTED:
        _require_identity(message["identity"])
        _require_sequence(message["request_sequence"], "request_sequence")
        _require_digest(message["request_sha256"], "request_sha256")
    elif message_type is MessageType.LEDGER_CANDIDATE:
        _require_sequence(message["sequence"], "sequence")
        _require_nonnegative_integer(message["generation"], "generation")
        previous = message["previous_generation"]
        if previous is not None:
            _require_nonnegative_integer(previous, "previous_generation")
        digest = message["previous_digest"]
        if digest is not None:
            _require_digest(digest, "previous_digest")
        if type(message["candidate"]) is not dict:
            raise BrokerProtocolError("ledger candidate must be an exact object")
        candidate = message["candidate"]
        if ledger_validator is None:
            raise BrokerProtocolError("ledger candidate validator is required")
        try:
            message_before = canonical_json_bytes(message)
            candidate_before = canonical_json_bytes(candidate)
            callback_candidate = _decode_canonical_json(
                candidate_before, Path("<ledger-candidate-copy>")
            )
        except (AtomicIOError, CanonicalJSONError, RuntimeError) as error:
            raise BrokerProtocolError("ledger candidate copy failed") from error
        if type(callback_candidate) is not dict:
            raise BrokerProtocolError("ledger candidate copy is invalid")
        try:
            valid_ledger = ledger_validator(callback_candidate)
        except Exception as error:
            raise BrokerProtocolError("ledger candidate validator failed") from error
        try:
            callback_after = canonical_json_bytes(callback_candidate)
            candidate_after = canonical_json_bytes(candidate)
            message_after = canonical_json_bytes(message)
        except (CanonicalJSONError, RuntimeError) as error:
            raise BrokerProtocolError(
                "ledger candidate validator mutated input"
            ) from error
        if (
            callback_after != candidate_before
            or candidate_after != candidate_before
            or message_after != message_before
        ):
            raise BrokerProtocolError("ledger candidate validator mutated input")
        if valid_ledger is not True:
            raise BrokerProtocolError("ledger candidate failed closed validation")
        if (
            candidate.get("ledger_nonce") != message["run_nonce"]
            or candidate.get("generation") != message["generation"]
            or candidate.get("previous_generation") != message["previous_generation"]
            or candidate.get("previous_digest") != message["previous_digest"]
        ):
            raise BrokerProtocolError("ledger candidate outer binding mismatch")
    elif message_type is MessageType.LEDGER_ACCEPTED:
        _require_sequence(message["sequence"], "sequence")
        _require_nonnegative_integer(message["generation"], "generation")
        _require_digest(message["ledger_sha256"], "ledger_sha256")
    else:
        _require_sequence(message["sequence"], "sequence")
        _require_identity(message["identity"])
        role = message["role"]
        if type(role) is not str or not role or _utf8_length(role, "role") > 128:
            raise BrokerProtocolError("ownership role is invalid")
    return message


def _decode_canonical_message(
    payload: bytes,
    *,
    ledger_validator: Callable[[dict[str, object]], bool] | None = None,
) -> dict[str, object]:
    value = _decode_canonical_value(payload)
    return validate_message(value, ledger_validator=ledger_validator)


def _decode_canonical_value(payload: bytes) -> object:
    try:
        return _decode_canonical_json(payload, Path("<broker-frame>"))
    except AtomicIOError as error:
        raise BrokerProtocolError("frame contains invalid canonical JSON") from error


def _payload_limit(message: object) -> int:
    if (
        type(message) is dict
        and message.get("type") == MessageType.LEDGER_CANDIDATE.value
    ):
        return MAX_LEDGER_CANDIDATE_PAYLOAD_BYTES
    return MAX_PAYLOAD_BYTES


def _require_identity(value: object) -> None:
    if type(value) is not dict or set(value) != _IDENTITY_KEYS:
        raise BrokerProtocolError("process identity is not a closed object")
    try:
        ProcessIdentity.from_dict(value)
    except ProcessIdentityError as error:
        raise BrokerProtocolError("process identity is invalid") from error


def _require_nonce(value: object) -> None:
    if type(value) is not str or not value or _utf8_length(value, "run nonce") > 256:
        raise BrokerProtocolError("run nonce is invalid")


def _utf8_length(value: str, name: str) -> int:
    try:
        return len(value.encode("utf-8", errors="strict"))
    except UnicodeError as error:
        raise BrokerProtocolError(f"{name} contains invalid Unicode") from error


def _require_sequence(value: object, name: str) -> None:
    if type(value) is not int or value <= 0:
        raise BrokerProtocolError(f"{name} must be an exact positive integer")


def _require_nonnegative_integer(value: object, name: str) -> None:
    if type(value) is not int or value < 0:
        raise BrokerProtocolError(f"{name} must be an exact nonnegative integer")


def _require_digest(value: object, name: str) -> None:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BrokerProtocolError(f"{name} must be lowercase SHA-256")


def _require_fd(fd: object) -> None:
    if type(fd) is not int or fd < 0:
        raise BrokerProtocolError(
            "file descriptor must be an exact nonnegative integer"
        )


def _duplicate_broker_fd(fd: int) -> int:
    try:
        return os.dup(fd)
    except OSError as error:
        raise BrokerProtocolError("broker descriptor is invalid") from error


def _close_no_throw(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _require_anonymous_pipe(fd: int, *, readable: bool) -> None:
    try:
        file_stat = os.fstat(fd)
        target = os.readlink(f"/proc/self/fd/{fd}")
        access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
    except OSError as error:
        raise BrokerProtocolError("broker descriptor is invalid") from error
    if (
        not stat.S_ISFIFO(file_stat.st_mode)
        or not target.startswith("pipe:[")
        or not target.endswith("]")
    ):
        raise BrokerProtocolError("broker descriptor is not an anonymous pipe")
    expected_mode = os.O_RDONLY if readable else os.O_WRONLY
    if access_mode != expected_mode:
        raise BrokerProtocolError("broker descriptor uses the wrong pipe end")


def _deadline(value: int | float | None) -> float:
    if value is None:
        return time.monotonic() + _DEFAULT_TIMEOUT_SECONDS
    if type(value) not in {int, float}:
        raise BrokerProtocolError("deadline must be an exact finite number")
    try:
        finite = math.isfinite(value)
        absolute = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise BrokerProtocolError("deadline conversion failed") from error
    if not finite:
        raise BrokerProtocolError("deadline must be an exact finite number")
    now = time.monotonic()
    if absolute <= now:
        raise BrokerProtocolError("broker deadline has expired")
    if absolute - now > _MAX_DEADLINE_INTERVAL_SECONDS:
        raise BrokerProtocolError("broker deadline exceeds the reviewed interval")
    return absolute


def _wait(fd: int, *, readable: bool, deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerProtocolError("broker timeout")
        try:
            readers, writers, _errors = select.select(
                [fd] if readable else [], [] if readable else [fd], [], remaining
            )
        except InterruptedError:
            continue
        except (OSError, OverflowError, ValueError) as error:
            raise BrokerProtocolError("broker descriptor polling failed") from error
        if readers or writers:
            return
        raise BrokerProtocolError("broker timeout")


def _read_exact(fd: int, size: int, deadline: float, part: str) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        _wait(fd, readable=True, deadline=deadline)
        try:
            chunk = os.read(fd, remaining)
        except InterruptedError:
            continue
        except OSError as error:
            raise BrokerProtocolError(f"broker {part} read failed") from error
        if not chunk:
            raise BrokerProtocolError(f"broker EOF during {part}")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(fd: int, data: bytes, deadline: float) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        _wait(fd, readable=False, deadline=deadline)
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        except OSError as error:
            raise BrokerProtocolError("broker frame write failed") from error
        if written <= 0:
            raise BrokerProtocolError("broker frame write made no progress")
        offset += written


def _require_channel_eof(fd: int, deadline: float) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BrokerProtocolError("broker timeout waiting for channel EOF")
        try:
            readers, _writers, _errors = select.select([fd], [], [], remaining)
            if not readers:
                raise BrokerProtocolError("broker timeout waiting for channel EOF")
            trailing = os.read(fd, 1)
        except InterruptedError:
            continue
        except BrokerProtocolError:
            raise
        except (OSError, OverflowError, ValueError) as error:
            raise BrokerProtocolError("broker trailing-data check failed") from error
        if trailing:
            raise BrokerProtocolError("broker frame has trailing data")
        return
