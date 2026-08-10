"""Closed-protocol and bounded anonymous-pipe framing tests."""

from __future__ import annotations

import os
from pathlib import Path
import socket
import time

import pytest

from holoagent0_setup.atomic_io import canonical_json_bytes
import holoagent0_setup.broker as broker_module
from holoagent0_setup.broker import (
    BrokerProtocolError,
    MessageType,
    read_frame,
    write_frame,
)
from holoagent0_setup.contract import ContractSet
from holoagent0_setup.ledger import _build_generation_zero


IDENTITY = {
    "pid": 101,
    "pgid": 101,
    "start_time": 9001,
    "executable_path": "/usr/bin/python3.10",
    "executable_sha256": "a" * 64,
}


def ready_message() -> dict[str, object]:
    return {
        "type": MessageType.SIGNAL_READY.value,
        "run_nonce": "run-0123456789abcdef",
        "sequence": 1,
        "identity": dict(IDENTITY),
        "blocked_signals": ["HUP", "INT", "TERM"],
        "dispositions": {"HUP": True, "INT": True, "TERM": True},
    }


def ledger_candidate_message() -> dict[str, object]:
    nonce = "b" * 64
    return {
        "type": MessageType.LEDGER_CANDIDATE.value,
        "run_nonce": nonce,
        "sequence": 1,
        "generation": 0,
        "previous_generation": None,
        "previous_digest": None,
        "candidate": {
            "ledger_nonce": nonce,
            "generation": 0,
            "previous_generation": None,
            "previous_digest": None,
        },
    }


def _raw_frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _raise_after_stable_duplicate_close(monkeypatch):
    duplicated = []
    active_duplicates = set()
    real_dup = os.dup
    real_close = os.close

    def track_dup(fd):
        duplicated_fd = real_dup(fd)
        duplicated.append(duplicated_fd)
        active_duplicates.add(duplicated_fd)
        return duplicated_fd

    def close_then_raise(fd):
        is_duplicate = fd in active_duplicates
        real_close(fd)
        if is_duplicate:
            active_duplicates.remove(fd)
            raise OSError("injected stable duplicate close failure")

    monkeypatch.setattr(broker_module.os, "dup", track_dup)
    monkeypatch.setattr(broker_module.os, "close", close_then_raise)
    return duplicated, active_duplicates


def _read_raw(raw: bytes, *, keep_writer: bool = False) -> dict[str, object]:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, raw)
        if not keep_writer:
            os.close(write_fd)
            write_fd = -1
        return read_frame(read_fd, deadline=time.monotonic() + 0.2, exact_one=True)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_message_type_is_exactly_the_reviewed_closed_set():
    assert {item.value for item in MessageType} == {
        "SIGNAL_READY",
        "SIGNAL_READY_ACCEPTED",
        "LEDGER_CANDIDATE",
        "LEDGER_ACCEPTED",
        "OWNERSHIP_RECORD",
    }


def test_canonical_frame_round_trip_over_anonymous_pipe():
    read_fd, write_fd = os.pipe()
    try:
        write_frame(write_fd, ready_message(), deadline=time.monotonic() + 0.2)
        os.close(write_fd)
        write_fd = -1
        assert (
            read_frame(read_fd, deadline=time.monotonic() + 0.2, exact_one=True)
            == ready_message()
        )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(type="UNKNOWN"),
        lambda value: value.update(sequence=True),
        lambda value: value.update(sequence=0),
        lambda value: value.update(run_nonce=""),
        lambda value: value.update(run_nonce="\ud800"),
        lambda value: value.update(blocked_signals=["TERM", "INT", "HUP"]),
        lambda value: value["identity"].update(pid=True),
        lambda value: value["identity"].update(executable_sha256="A" * 64),
        lambda value: value["dispositions"].update(INT=False),
    ],
)
def test_write_rejects_unknown_messages_keys_types_and_invalid_signal_schema(mutation):
    message = ready_message()
    mutation(message)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError):
            write_frame(write_fd, message, deadline=time.monotonic() + 0.2)
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"type":"SIGNAL_READY","type":"SIGNAL_READY"}',
        b'{ "type":"SIGNAL_READY"}',
        b"\xef\xbb\xbf{}",
        b"[]",
        b"null",
    ],
)
def test_reader_rejects_duplicates_noncanonical_json_and_non_objects(payload):
    with pytest.raises(BrokerProtocolError):
        _read_raw(_raw_frame(payload))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00\x00",
        b"\x00\x00\x00\x00",
        (65537).to_bytes(4, "big"),
        (12).to_bytes(4, "big") + b"{}",
        _raw_frame(canonical_json_bytes(ready_message())) + b"x",
    ],
)
def test_reader_rejects_eof_partial_zero_overlong_and_trailing_frames(raw):
    with pytest.raises(BrokerProtocolError):
        _read_raw(raw)


def test_reader_times_out_on_partial_payload_while_writer_remains_open():
    payload = canonical_json_bytes(ready_message())
    with pytest.raises(BrokerProtocolError, match="timeout"):
        _read_raw(len(payload).to_bytes(4, "big") + payload[:3], keep_writer=True)


def test_exact_one_requires_channel_eof_by_deadline():
    read_fd, write_fd = os.pipe()
    try:
        write_frame(write_fd, ready_message(), deadline=time.monotonic() + 0.2)
        with pytest.raises(BrokerProtocolError, match="timeout"):
            read_frame(read_fd, deadline=time.monotonic() + 0.02, exact_one=True)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_multi_frame_channel_does_not_require_eof():
    read_fd, write_fd = os.pipe()
    try:
        write_frame(write_fd, ready_message(), deadline=time.monotonic() + 0.2)
        assert read_frame(read_fd, deadline=time.monotonic() + 0.2) == ready_message()
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_reader_and_writer_reject_socket_or_wrong_pipe_end_misuse():
    left, right = socket.socketpair()
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError, match="anonymous pipe"):
            write_frame(left.fileno(), ready_message())
        with pytest.raises(BrokerProtocolError):
            write_frame(read_fd, ready_message())
        with pytest.raises(BrokerProtocolError):
            read_frame(write_fd, deadline=time.monotonic() + 0.01)
    finally:
        left.close()
        right.close()
        os.close(read_fd)
        os.close(write_fd)


def test_named_fifo_is_not_accepted_as_anonymous_pipe(tmp_path):
    fifo = tmp_path / "broker.fifo"
    os.mkfifo(fifo, 0o600)
    fd = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    try:
        with pytest.raises(BrokerProtocolError, match="anonymous pipe"):
            write_frame(fd, ready_message())
    finally:
        os.close(fd)


def test_short_reads_writes_and_eintr_are_retried(monkeypatch):
    read_fd, write_fd = os.pipe()
    real_write = os.write
    real_read = os.read
    write_calls = 0
    read_calls = 0

    def interrupted_short_write(fd, data):
        nonlocal write_calls
        write_calls += 1
        if write_calls == 1:
            raise InterruptedError
        return real_write(fd, data[:7])

    def interrupted_short_read(fd, size):
        nonlocal read_calls
        read_calls += 1
        if read_calls == 1:
            raise InterruptedError
        return real_read(fd, min(size, 3))

    try:
        monkeypatch.setattr(broker_module.os, "write", interrupted_short_write)
        write_frame(write_fd, ready_message(), deadline=time.monotonic() + 0.2)
        monkeypatch.setattr(broker_module.os, "read", interrupted_short_read)
        assert read_frame(read_fd, deadline=time.monotonic() + 0.2) == ready_message()
        assert write_calls > 2
        assert read_calls > 2
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_writer_uses_stable_pipe_duplicate_across_validator_fd_rebind(tmp_path):
    message = ledger_candidate_message()
    rebound_path = tmp_path / "rebound-write"
    rebound_fd = os.open(rebound_path, os.O_RDWR | os.O_CREAT, 0o600)
    read_fd, write_fd = os.pipe()
    rebound = False

    def rebind_original(_candidate):
        nonlocal rebound
        if not rebound:
            os.close(write_fd)
            os.dup2(rebound_fd, write_fd)
            rebound = True
        return True

    try:
        write_frame(
            write_fd,
            message,
            deadline=time.monotonic() + 0.2,
            ledger_validator=rebind_original,
        )
        assert rebound_path.read_bytes() == b""
        assert (
            read_frame(
                read_fd,
                deadline=time.monotonic() + 0.2,
                exact_one=True,
                ledger_validator=lambda _candidate: True,
            )
            == message
        )
    finally:
        os.close(read_fd)
        os.close(write_fd)
        os.close(rebound_fd)


def test_reader_uses_stable_pipe_duplicate_for_exact_one_after_validator_rebind(
    tmp_path,
):
    message = ledger_candidate_message()
    payload = canonical_json_bytes(message)
    rebound_path = tmp_path / "rebound-read"
    rebound_fd = os.open(rebound_path, os.O_RDWR | os.O_CREAT, 0o600)
    read_fd, write_fd = os.pipe()
    os.write(write_fd, _raw_frame(payload) + b"x")
    os.close(write_fd)
    write_fd = -1

    def rebind_original(_candidate):
        os.close(read_fd)
        os.dup2(rebound_fd, read_fd)
        return True

    try:
        with pytest.raises(BrokerProtocolError, match="trailing"):
            read_frame(
                read_fd,
                deadline=time.monotonic() + 0.2,
                exact_one=True,
                ledger_validator=rebind_original,
            )
        assert rebound_path.read_bytes() == b""
    finally:
        os.close(read_fd)
        os.close(rebound_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_stable_broker_duplicates_close_after_success(monkeypatch):
    duplicated = []
    real_dup = os.dup

    def track_dup(fd):
        duplicated.append(real_dup(fd))
        return duplicated[-1]

    monkeypatch.setattr(broker_module.os, "dup", track_dup)
    read_fd, write_fd = os.pipe()
    try:
        write_frame(write_fd, ready_message(), deadline=time.monotonic() + 0.2)
        os.close(write_fd)
        write_fd = -1
        assert (
            read_frame(read_fd, deadline=time.monotonic() + 0.2, exact_one=True)
            == ready_message()
        )
        assert len(duplicated) == 2
        for duplicated_fd in duplicated:
            with pytest.raises(OSError):
                os.fstat(duplicated_fd)
        os.fstat(read_fd)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_successful_read_returns_frame_when_stable_duplicate_close_raises(monkeypatch):
    payload = canonical_json_bytes(ready_message())
    read_fd, write_fd = os.pipe()
    os.write(write_fd, _raw_frame(payload))
    os.close(write_fd)
    duplicated, active_duplicates = _raise_after_stable_duplicate_close(monkeypatch)
    try:
        assert (
            read_frame(read_fd, deadline=time.monotonic() + 0.2, exact_one=True)
            == ready_message()
        )
        assert len(duplicated) == 1
        assert active_duplicates == set()
        with pytest.raises(OSError):
            os.fstat(duplicated[0])
        os.fstat(read_fd)
    finally:
        os.close(read_fd)


@pytest.mark.parametrize("operation", ["read", "write"])
def test_primary_broker_error_is_not_masked_by_duplicate_close_error(
    monkeypatch, operation
):
    read_fd, write_fd = os.pipe()
    if operation == "read":
        os.close(write_fd)
        write_fd = -1
    else:
        os.close(read_fd)
        read_fd = -1
    duplicated, active_duplicates = _raise_after_stable_duplicate_close(monkeypatch)
    caller_fd = read_fd if operation == "read" else write_fd
    try:
        with pytest.raises(BrokerProtocolError, match="EOF|frame write"):
            if operation == "read":
                read_frame(read_fd, deadline=time.monotonic() + 0.2)
            else:
                write_frame(
                    write_fd,
                    ready_message(),
                    deadline=time.monotonic() + 0.2,
                )
        assert len(duplicated) == 1
        assert active_duplicates == set()
        with pytest.raises(OSError):
            os.fstat(duplicated[0])
        os.fstat(caller_fd)
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_stable_broker_duplicates_close_after_validator_failures(monkeypatch):
    duplicated = []
    real_dup = os.dup

    def track_dup(fd):
        duplicated.append(real_dup(fd))
        return duplicated[-1]

    monkeypatch.setattr(broker_module.os, "dup", track_dup)
    message = ledger_candidate_message()
    payload = canonical_json_bytes(message)
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError, match="validation"):
            write_frame(
                write_fd,
                message,
                deadline=time.monotonic() + 0.2,
                ledger_validator=lambda _candidate: False,
            )
        os.write(write_fd, _raw_frame(payload))
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(BrokerProtocolError, match="validation"):
            read_frame(
                read_fd,
                deadline=time.monotonic() + 0.2,
                ledger_validator=lambda _candidate: False,
            )
        assert len(duplicated) == 2
        for duplicated_fd in duplicated:
            with pytest.raises(OSError):
                os.fstat(duplicated_fd)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_deadlines_and_exact_builtin_fd_and_message_types_are_enforced():
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError):
            write_frame(True, ready_message())
        with pytest.raises(BrokerProtocolError):
            write_frame(write_fd, dict(ready_message()), deadline=True)
        with pytest.raises(BrokerProtocolError, match="deadline"):
            read_frame(read_fd, deadline=time.monotonic() - 1)
        with pytest.raises(BrokerProtocolError, match="interval"):
            write_frame(write_fd, ready_message(), deadline=time.monotonic() + 3600)
        with pytest.raises(BrokerProtocolError):
            write_frame(write_fd, ready_message(), deadline=10**10000)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_real_generation_zero_ledger_candidate_round_trips_above_control_bound():
    contract_root = Path(__file__).resolve().parents[1]
    contract = ContractSet(contract_root)
    nonce = "b" * 64
    ledger = _build_generation_zero("offline-run", nonce, contract)
    message = {
        "type": MessageType.LEDGER_CANDIDATE.value,
        "run_nonce": nonce,
        "sequence": 1,
        "generation": 0,
        "previous_generation": None,
        "previous_digest": None,
        "candidate": ledger,
    }

    def validate_ledger(value):
        return contract.validate_document("holoagent0-offline-ledger-v1", value).ok

    payload = canonical_json_bytes(message)
    assert broker_module.MAX_PAYLOAD_BYTES < len(payload) <= 65536
    read_fd, write_fd = os.pipe()
    try:
        write_frame(
            write_fd,
            message,
            deadline=time.monotonic() + 0.2,
            ledger_validator=validate_ledger,
        )
        os.close(write_fd)
        write_fd = -1
        assert (
            read_frame(
                read_fd,
                deadline=time.monotonic() + 0.2,
                exact_one=True,
                ledger_validator=validate_ledger,
            )
            == message
        )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_writer_rejects_ledger_candidate_above_reviewed_ledger_bound():
    nonce = "b" * 64
    message = {
        "type": MessageType.LEDGER_CANDIDATE.value,
        "run_nonce": nonce,
        "sequence": 1,
        "generation": 1,
        "previous_generation": 0,
        "previous_digest": "a" * 64,
        "candidate": {
            "ledger_nonce": nonce,
            "generation": 1,
            "previous_generation": 0,
            "previous_digest": "a" * 64,
            "padding": "x" * 65536,
        },
    }
    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError, match="bound"):
            write_frame(write_fd, message, ledger_validator=lambda _value: True)
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_control_payload_over_4096_is_rejected_on_write_and_read():
    message = {
        "type": MessageType.OWNERSHIP_RECORD.value,
        "run_nonce": "nonce",
        "sequence": 1,
        "identity": dict(IDENTITY),
        "role": "x" * 5000,
    }
    payload = canonical_json_bytes(message)
    assert 4096 < len(payload) <= 65536

    read_fd, write_fd = os.pipe()
    try:
        with pytest.raises(BrokerProtocolError, match="bound"):
            write_frame(write_fd, message, deadline=time.monotonic() + 0.2)
        os.write(write_fd, _raw_frame(payload))
        os.close(write_fd)
        write_fd = -1
        with pytest.raises(BrokerProtocolError, match="bound"):
            read_frame(read_fd, deadline=time.monotonic() + 0.2)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


@pytest.mark.parametrize("direction", ["write", "read"])
def test_ledger_validator_mutation_is_rejected_without_touching_original(
    direction,
):
    message = ledger_candidate_message()
    original = canonical_json_bytes(message)

    def mutate_then_true(candidate):
        candidate["injected"] = True
        return True

    read_fd, write_fd = os.pipe()
    try:
        if direction == "write":
            with pytest.raises(BrokerProtocolError, match="mutat"):
                write_frame(
                    write_fd,
                    message,
                    deadline=time.monotonic() + 0.2,
                    ledger_validator=mutate_then_true,
                )
        else:
            os.write(write_fd, _raw_frame(original))
            os.close(write_fd)
            write_fd = -1
            with pytest.raises(BrokerProtocolError, match="mutat"):
                read_frame(
                    read_fd,
                    deadline=time.monotonic() + 0.2,
                    ledger_validator=mutate_then_true,
                )
        assert canonical_json_bytes(message) == original
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_validate_message_rejects_surrogate_ownership_role():
    message = {
        "type": MessageType.OWNERSHIP_RECORD.value,
        "run_nonce": "nonce",
        "sequence": 1,
        "identity": dict(IDENTITY),
        "role": "\ud800",
    }
    with pytest.raises(BrokerProtocolError):
        broker_module.validate_message(message)


def test_ledger_candidate_requires_semantic_validator_and_exact_outer_binding():
    contract_root = Path(__file__).resolve().parents[1]
    contract = ContractSet(contract_root)
    nonce = "b" * 64
    ledger = _build_generation_zero("offline-run", nonce, contract)
    message = {
        "type": MessageType.LEDGER_CANDIDATE.value,
        "run_nonce": nonce,
        "sequence": 1,
        "generation": 0,
        "previous_generation": None,
        "previous_digest": None,
        "candidate": ledger,
    }

    with pytest.raises(BrokerProtocolError, match="validator"):
        broker_module.validate_message(message)

    def validate_ledger(value):
        return contract.validate_document("holoagent0-offline-ledger-v1", value).ok

    assert (
        broker_module.validate_message(message, ledger_validator=validate_ledger)
        == message
    )
    for field, wrong in [
        ("run_nonce", "c" * 64),
        ("generation", 1),
        ("previous_generation", 0),
        ("previous_digest", "d" * 64),
    ]:
        malformed = dict(message)
        malformed[field] = wrong
        with pytest.raises(BrokerProtocolError, match="binding"):
            broker_module.validate_message(malformed, ledger_validator=validate_ledger)

    malformed = dict(message)
    malformed["candidate"] = dict(ledger, unexpected=True)
    with pytest.raises(BrokerProtocolError, match="ledger"):
        broker_module.validate_message(malformed, ledger_validator=validate_ledger)
