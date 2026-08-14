"""Side-effect-free readiness checks for the Python 3.10 G1 chatbot."""

from __future__ import annotations

import ast
import _thread
from contextlib import ExitStack
from dataclasses import dataclass
import errno
import hashlib
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from threading import current_thread, main_thread
import time
from typing import Callable, Mapping
from unittest.mock import patch


REQUIRED_IMPORTS = (
    "aiohttp",
    "loguru",
    "numpy",
    "openai",
    "pyaudio",
    "pydub",
    "websockets",
)
REQUIRED_PROVIDER_VARIABLES = (
    "CHATBOT_ASR_APP_KEY",
    "CHATBOT_ASR_ACCESS_KEY",
    "CHATBOT_ARK_API_KEY",
    "CHATBOT_TTS_APP_KEY",
    "CHATBOT_TTS_ACCESS_KEY",
)
PYPROJECT_MAX_BYTES = 16 * 1024
CONFIGURATION_MAX_BYTES = 64 * 1024
DEFAULT_READINESS_TIMEOUT_SECONDS = 5.0
MAX_READINESS_TIMEOUT_SECONDS = 30.0
PYTHON_EXECUTABLE = Path("/usr/bin/python3.10")
PYTHON_EXECUTABLE_SHA256 = (
    "7d51cd6b48b521277f5caa4610a82126e315fa2be4df069823a8b1eeb5bd4a86"
)
CHATBOT_CHILD_CONTROL_SCHEMA = "holoagent0.chatbot-child-control.v1"
CHATBOT_CHILD_CONTROL_MAX_BYTES = 4 * 1024
CHATBOT_CHILD_RESULT_MAX_BYTES = 64 * 1024
CHATBOT_CHILD_POLL_SECONDS = 0.01
CHATBOT_CHILD_TERM_GRACE_SECONDS = 0.25
CHATBOT_CHILD_KILL_GRACE_SECONDS = 1.0
_CHATBOT_CHILD_ENTRY = Path(__file__).resolve().parents[1] / "chatbot_child.py"
_CREDENTIAL_MINIMUM_LENGTH = 4
_CREDENTIAL_PLACEHOLDERS = frozenset({"changeme", "placeholder", "xxxx"})
_CONFIG_ROOT_KEYS = {
    "audio_device",
    "asr",
    "tts",
    "llm",
    "work_dir",
    "language",
    "wake_up_text",
    "sleep_text",
    "system_prompt_zh_path",
    "system_prompt_en_path",
    "hooks",
}


@dataclass(frozen=True)
class ExternalReadiness:
    label: str
    exit_code: int


@dataclass(frozen=True)
class AudioInventory:
    input_count: int
    output_count: int
    matching_full_duplex_count: int

    def __post_init__(self) -> None:
        if (
            type(self.input_count) is not int
            or self.input_count < 0
            or type(self.output_count) is not int
            or self.output_count < 0
            or type(self.matching_full_duplex_count) is not int
            or self.matching_full_duplex_count < 0
            or self.matching_full_duplex_count > self.input_count
            or self.matching_full_duplex_count > self.output_count
        ):
            raise ValueError("invalid audio inventory")


@dataclass(frozen=True)
class ChatbotGateResult:
    gates: tuple[dict[str, object], ...]
    label: str
    exit_code: int


@dataclass(frozen=True)
class _OwnedChildIdentity:
    pid: int
    pgid: int
    start_time_ticks: int


class OfflineStartupSideEffectAttempt(RuntimeError):
    """A configuration-only startup attempted a prohibited operation."""


class ChatbotReadinessTimeout(TimeoutError):
    """The single reviewed chatbot readiness deadline expired."""


class ChatbotChildContainmentError(RuntimeError):
    """A spawned chatbot child could not be proven reaped and contained."""


class _WholeReadinessDeadline:
    def __init__(self, timeout_seconds: float) -> None:
        if (
            type(timeout_seconds) is not float
            or timeout_seconds < 0.01
            or timeout_seconds > MAX_READINESS_TIMEOUT_SECONDS
            or current_thread() is not main_thread()
        ):
            raise ValueError("chatbot readiness bound is invalid")
        self._timeout_seconds = timeout_seconds
        self._started = 0.0
        self._previous_handler: object = signal.SIG_DFL

    def __enter__(self) -> "_WholeReadinessDeadline":
        previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
        if previous_delay != 0.0 or previous_interval != 0.0:
            raise RuntimeError("chatbot readiness alarm is unavailable")
        self._previous_handler = signal.getsignal(signal.SIGALRM)
        self._started = time.monotonic()
        signal.signal(signal.SIGALRM, self._timed_out)
        try:
            signal.setitimer(signal.ITIMER_REAL, self._timeout_seconds)
        except BaseException:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
            finally:
                signal.signal(signal.SIGALRM, self._previous_handler)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        cleanup_error: BaseException | None = None
        try:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        except BaseException as error:
            cleanup_error = error
        try:
            signal.signal(signal.SIGALRM, self._previous_handler)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None and exc_type is None:
            raise cleanup_error
        if (
            exc_type is None
            and time.monotonic() - self._started > self._timeout_seconds
        ):
            raise ChatbotReadinessTimeout("chatbot readiness timed out")

    @staticmethod
    def _timed_out(_signum: int, _frame: object) -> None:
        raise ChatbotReadinessTimeout("chatbot readiness timed out")


class StartupSideEffectSpies:
    """Value-blind spies: only the closed operation kind is retained."""

    def __init__(self) -> None:
        self._attempted_kinds: list[str] = []

    @property
    def attempted_kinds(self) -> tuple[str, ...]:
        return tuple(self._attempted_kinds)

    def _attempt(self, kind: str) -> None:
        self._attempted_kinds.append(kind)
        raise OfflineStartupSideEffectAttempt(kind)

    def process_spawn(self, *_args: object, **_kwargs: object) -> None:
        self._attempt("process_spawn")

    def network(self, *_args: object, **_kwargs: object) -> None:
        self._attempt("network")

    def microphone(self, *_args: object, **_kwargs: object) -> None:
        self._attempt("microphone")


class _PythonOfflineSideEffectGuard:
    """Block cached and direct Python process/network entry points."""

    _NETWORK_SOCKET_METHODS = (
        "connect",
        "connect_ex",
        "send",
        "sendall",
        "sendto",
        "sendmsg",
        "sendfile",
    )
    _NETWORK_MODULE_FUNCTIONS = (
        "create_connection",
        "getaddrinfo",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
    )
    _SUBPROCESS_FUNCTIONS = (
        "Popen",
        "run",
        "call",
        "check_call",
        "check_output",
    )
    _AUDIT_NETWORK_EVENTS = frozenset(
        {
            "socket.__new__",
            "socket.bind",
            "socket.connect",
            "socket.sendmsg",
            "socket.sendto",
            "socket.getaddrinfo",
            "socket.gethostbyaddr",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
            "socket.gethostname",
        }
    )
    _AUDIT_PROCESS_EVENTS = frozenset(
        {
            "os.exec",
            "os.fork",
            "os.forkpty",
            "os.posix_spawn",
            "os.spawn",
            "os.system",
            "subprocess.Popen",
        }
    )
    _AUDIT_PROBE_EVENT = "holoagent0.chatbot.audit_probe"
    _active_guard: "_PythonOfflineSideEffectGuard | None" = None
    _audit_probe_acknowledged = False
    _audit_hook_installed = False

    def __init__(self) -> None:
        self.network_attempts: list[str] = []
        self.process_attempts: list[str] = []
        self._entry_thread_identities: frozenset[int] | None = None
        self._stack: ExitStack | None = None
        self._used = False

    def __enter__(self) -> "_PythonOfflineSideEffectGuard":
        if self._used:
            raise RuntimeError("Python side-effect guard is single-use")
        self._used = True
        if self._stack is not None or type(self)._active_guard is not None:
            raise RuntimeError("Python side-effect guard is already active")
        stack = ExitStack()
        self._stack = stack
        self._entry_thread_identities = frozenset(sys._current_frames())
        try:
            if not type(self)._audit_hook_installed:
                type(self)._audit_probe_acknowledged = False
                sys.addaudithook(type(self)._audit_hook)
                sys.audit(type(self)._AUDIT_PROBE_EVENT)
                if not type(self)._audit_probe_acknowledged:
                    raise RuntimeError("Python audit hook installation was not proven")
                type(self)._audit_hook_installed = True
            type(self)._active_guard = self
            for name in self._NETWORK_SOCKET_METHODS:
                if hasattr(socket.socket, name):
                    stack.enter_context(
                        patch.object(
                            socket.socket,
                            name,
                            self._blocked("network", f"socket.socket.{name}"),
                        )
                    )
            stack.enter_context(
                patch.object(
                    socket,
                    "socket",
                    self._blocked("network", "socket.socket"),
                )
            )
            for name in self._NETWORK_MODULE_FUNCTIONS:
                if hasattr(socket, name):
                    stack.enter_context(
                        patch.object(
                            socket,
                            name,
                            self._blocked("network", f"socket.{name}"),
                        )
                    )
            for name in self._SUBPROCESS_FUNCTIONS:
                stack.enter_context(
                    patch.object(
                        subprocess,
                        name,
                        self._blocked("process", f"subprocess.{name}"),
                    )
                )
            for name in dir(os):
                if name in {"fork", "forkpty", "system"} or name.startswith(
                    ("exec", "spawn", "posix_spawn")
                ):
                    candidate = getattr(os, name)
                    if callable(candidate):
                        stack.enter_context(
                            patch.object(
                                os,
                                name,
                                self._blocked("process", f"os.{name}"),
                            )
                        )
            stack.enter_context(
                patch.object(
                    multiprocessing.Process,
                    "start",
                    self._blocked("process", "multiprocessing.Process.start"),
                )
            )
            stack.enter_context(
                patch.object(
                    threading.Thread,
                    "start",
                    self._blocked("process", "threading.Thread.start"),
                )
            )
            if callable(getattr(threading, "_start_new_thread", None)):
                stack.enter_context(
                    patch.object(
                        threading,
                        "_start_new_thread",
                        self._blocked("process", "threading._start_new_thread"),
                    )
                )
            stack.enter_context(
                patch.object(
                    _thread,
                    "start_new_thread",
                    self._blocked("process", "_thread.start_new_thread"),
                )
            )
        except BaseException:
            if type(self)._active_guard is self:
                type(self)._active_guard = None
            stack.close()
            self._stack = None
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        stack = self._stack
        if stack is None:
            raise RuntimeError("Python side-effect guard is not active")
        try:
            if exc_type is None:
                self.reject_new_live_threads()
        finally:
            self._stack = None
            try:
                stack.close()
            finally:
                if type(self)._active_guard is self:
                    type(self)._active_guard = None

    def reject_new_live_threads(self) -> None:
        entry_threads = self._entry_thread_identities
        if entry_threads is None:
            raise RuntimeError("Python side-effect guard is not active")
        if set(sys._current_frames()).difference(entry_threads):
            self._reject("process", "thread.live")

    @classmethod
    def _audit_hook(cls, event: str, _arguments: tuple[object, ...]) -> None:
        if event == cls._AUDIT_PROBE_EVENT:
            cls._audit_probe_acknowledged = True
            return
        guard = cls._active_guard
        if guard is None:
            return
        if event in cls._AUDIT_NETWORK_EVENTS:
            guard._reject("network", f"audit:{event}")
        if event in cls._AUDIT_PROCESS_EVENTS:
            guard._reject("process", f"audit:{event}")

    def _blocked(self, category: str, operation: str):
        def blocked(*_args: object, **_kwargs: object) -> None:
            self._reject(category, operation)

        return blocked

    def _reject(self, category: str, operation: str) -> None:
        inventory = {
            "network": self.network_attempts,
            "process": self.process_attempts,
        }.get(category)
        if inventory is None:
            raise RuntimeError("offline side-effect category is invalid")
        inventory.append(operation)
        raise OfflineStartupSideEffectAttempt(category)


class ChatbotOfflineSideEffectGuard:
    """Block process, network, and reviewed chatbot stream entry points."""

    _AUDIO_DEVICE_METHODS = (
        "start_streams",
        "restart_input_stream",
        "_open_input_stream",
        "_open_output_stream",
        "_start_arecord",
        "_start_aplay",
    )

    def __init__(self) -> None:
        self._offline_guard = _PythonOfflineSideEffectGuard()
        self.microphone_attempts: list[str] = []
        self._patched_audio_entries: set[tuple[int, str]] = set()
        self._stack: ExitStack | None = None
        self._used = False

    @property
    def process_attempts(self) -> tuple[str, ...]:
        return tuple(self._offline_guard.process_attempts)

    @property
    def network_attempts(self) -> tuple[str, ...]:
        return tuple(self._offline_guard.network_attempts)

    @property
    def side_effect_attempted(self) -> bool:
        return bool(
            self.process_attempts or self.network_attempts or self.microphone_attempts
        )

    def __enter__(self) -> "ChatbotOfflineSideEffectGuard":
        if self._used:
            raise RuntimeError("chatbot side-effect guard is single-use")
        self._used = True
        if self._stack is not None:
            raise RuntimeError("chatbot side-effect guard is already active")
        stack = ExitStack()
        self._stack = stack
        try:
            stack.enter_context(self._offline_guard)
            bootstrap = getattr(importlib, "_bootstrap")
            original_find_and_load = bootstrap._find_and_load
            stack.enter_context(
                patch.object(
                    bootstrap,
                    "_find_and_load",
                    self._guarded_find_and_load(original_find_and_load),
                )
            )
            for module_name, module in tuple(sys.modules.items()):
                self._patch_loaded_audio_module(module_name, module)
        except BaseException:
            stack.close()
            self._stack = None
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        stack = self._stack
        if stack is None:
            raise RuntimeError("chatbot side-effect guard is not active")
        self._stack = None
        stack.close()

    def reject_new_live_threads(self) -> None:
        self._offline_guard.reject_new_live_threads()

    def _blocked_microphone(self, operation: str):
        def blocked(*_args: object, **_kwargs: object) -> None:
            self.microphone_attempts.append(operation)
            raise OfflineStartupSideEffectAttempt("microphone")

        return blocked

    def _guarded_find_and_load(self, original_find_and_load):
        def guarded(module_name: str, import_function: object):
            module = original_find_and_load(module_name, import_function)
            self._patch_loaded_audio_module(module_name, module)
            return module

        return guarded

    def _patch_loaded_audio_module(
        self, module_name: str, module: object | None
    ) -> None:
        stack = self._stack
        if stack is None or module is None:
            return
        if module_name == "pyaudio":
            owner = getattr(module, "PyAudio", None)
            self._patch_audio_method(stack, owner, "open", "pyaudio.PyAudio.open")
            return
        if not module_name.endswith("audio_device"):
            return
        owner = getattr(module, "AudioDevice", None)
        for method_name in self._AUDIO_DEVICE_METHODS:
            self._patch_audio_method(
                stack,
                owner,
                method_name,
                f"{module_name}.AudioDevice.{method_name}",
            )

    def _patch_audio_method(
        self,
        stack: ExitStack,
        owner: object | None,
        method_name: str,
        operation: str,
    ) -> None:
        if owner is None or not hasattr(owner, method_name):
            return
        identity = (id(owner), method_name)
        if identity in self._patched_audio_entries:
            return
        stack.enter_context(
            patch.object(owner, method_name, self._blocked_microphone(operation))
        )
        self._patched_audio_entries.add(identity)


def classify_external_readiness(*, credentials: bool, audio: bool) -> ExternalReadiness:
    if type(credentials) is not bool or type(audio) is not bool:
        raise TypeError("external readiness inputs must be exact booleans")
    label, exit_code = {
        (True, True): ("PASS_HOLOAGENT0_OFFLINE", 0),
        (False, True): ("READY_CREDENTIALS_REQUIRED", 10),
        (True, False): ("READY_AUDIO_HARDWARE_REQUIRED", 10),
        (False, False): ("READY_CREDENTIALS_AND_AUDIO_REQUIRED", 10),
    }[(credentials, audio)]
    return ExternalReadiness(label, exit_code)


def _measurement(name: str, value: int | bool) -> dict[str, object]:
    return {"name": name, "value": value, "unit": None}


def _gate(
    gate_id: str,
    status: str,
    reason: str,
    *,
    role: str,
    measurements: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    return {
        "id": gate_id,
        "status": status,
        "role": role,
        "reason": reason,
        "measurements": list(measurements),
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


def _not_run(gate_id: str, role: str) -> dict[str, object]:
    return _gate(
        gate_id,
        "NOT_RUN",
        "EARLIER_BLOCKING_GATE",
        role=role,
    )


def _failure_after_dependencies(
    dependency_gate: dict[str, object],
) -> ChatbotGateResult:
    return ChatbotGateResult(
        gates=(
            dependency_gate,
            _not_run("chatbot.configuration", "required"),
            _not_run("chatbot.credentials", "qualification"),
            _not_run("chatbot.audio_hardware", "qualification"),
        ),
        label="FAIL_CHATBOT",
        exit_code=1,
    )


def _failure_after_configuration(
    dependency_gate: dict[str, object],
    configuration_gate: dict[str, object],
) -> ChatbotGateResult:
    return ChatbotGateResult(
        gates=(
            dependency_gate,
            configuration_gate,
            _not_run("chatbot.credentials", "qualification"),
            _not_run("chatbot.audio_hardware", "qualification"),
        ),
        label="FAIL_CHATBOT",
        exit_code=1,
    )


def _dependency_gate(
    importability: tuple[tuple[str, bool], ...],
    *,
    passed: bool,
    guard: ChatbotOfflineSideEffectGuard | None = None,
) -> dict[str, object]:
    measurements = tuple(
        _measurement(f"{name}_importable", available)
        for name, available in importability
    )
    if guard is not None and guard.side_effect_attempted:
        measurements += _side_effect_measurements(guard)
    return _gate(
        "chatbot.dependencies",
        "PASS" if passed else "FAIL",
        "OK" if passed else "CHATBOT_DEPENDENCY_MISSING",
        role="required",
        measurements=measurements,
    )


def _configuration_gate(
    guard: ChatbotOfflineSideEffectGuard,
    *,
    passed: bool,
) -> dict[str, object]:
    return _gate(
        "chatbot.configuration",
        "PASS" if passed else "FAIL",
        "OK" if passed else "CHATBOT_CONFIG_INVALID",
        role="required",
        measurements=_side_effect_measurements(guard),
    )


def _read_bounded_text(path: Path, max_bytes: int) -> str:
    with Path(path).open("rb") as stream:
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("chatbot input exceeds byte bound")
    return payload.decode("utf-8", errors="strict")


def _declared_dependencies(pyproject_path: Path) -> frozenset[str]:
    text = _read_bounded_text(pyproject_path, PYPROJECT_MAX_BYTES)
    project_marker = "[project]\n"
    if project_marker not in text:
        raise ValueError("chatbot project table is missing")
    project = text.split(project_marker, 1)[1].split("\n[", 1)[0]
    prefix = "dependencies = ["
    if prefix not in project:
        raise ValueError("chatbot dependencies are missing")
    encoded = "[" + project.split(prefix, 1)[1].split("]", 1)[0] + "]"
    dependencies = ast.literal_eval(encoded)
    if not isinstance(dependencies, list) or any(
        type(value) is not str for value in dependencies
    ):
        raise ValueError("chatbot dependencies are invalid")
    names = {
        value.split("[", 1)[0]
        .split("<", 1)[0]
        .split(">", 1)[0]
        .split("=", 1)[0]
        .split("!", 1)[0]
        .split("~", 1)[0]
        .strip()
        .lower()
        for value in dependencies
    }
    return frozenset(names)


def _default_dependency_probe(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate chatbot configuration key")
        result[key] = value
    return result


def _load_configuration(configuration_path: Path) -> dict[str, object]:
    document = json.loads(
        _read_bounded_text(configuration_path, CONFIGURATION_MAX_BYTES),
        object_pairs_hook=_unique_json_object,
        parse_constant=lambda _token: (_ for _ in ()).throw(
            ValueError("non-JSON chatbot configuration value")
        ),
    )
    if type(document) is not dict or set(document) != _CONFIG_ROOT_KEYS:
        raise ValueError("chatbot configuration root is invalid")
    return document


def _require_mapping(value: object, required: set[str]) -> dict[str, object]:
    if type(value) is not dict or not required.issubset(value):
        raise ValueError("chatbot configuration section is invalid")
    return value


def _require_string(mapping: Mapping[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        raise ValueError("chatbot configuration string is invalid")
    return value


def _require_positive_integer(mapping: Mapping[str, object], key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int or value <= 0:
        raise ValueError("chatbot configuration integer is invalid")
    return value


def validate_configuration_startup(
    configuration: Mapping[str, object], spies: StartupSideEffectSpies
) -> None:
    """Validate fields consumed at G1 startup without importing or starting G1."""

    if type(spies) is not StartupSideEffectSpies:
        raise TypeError("startup spies are required")
    audio = _require_mapping(
        configuration["audio_device"], {"device_name", "channels", "chunk_size"}
    )
    _require_string(audio, "device_name")
    _require_positive_integer(audio, "channels")
    _require_positive_integer(audio, "chunk_size")

    asr = _require_mapping(
        configuration["asr"],
        {"app_id", "access_key", "end_window_size", "rate", "seg_duration", "url"},
    )
    for key in ("app_id", "access_key", "url"):
        _require_string(asr, key)
    for key in ("end_window_size", "rate", "seg_duration"):
        _require_positive_integer(asr, key)

    tts = _require_mapping(
        configuration["tts"],
        {"app_id", "access_key", "voice_type", "resource_id", "endpoint"},
    )
    for key in ("app_id", "access_key", "voice_type", "resource_id", "endpoint"):
        _require_string(tts, key)

    llm = _require_mapping(
        configuration["llm"], {"llm_doubao_model", "ark_api_key", "ark_base_url"}
    )
    for key in ("llm_doubao_model", "ark_api_key", "ark_base_url"):
        _require_string(llm, key)

    for key in (
        "work_dir",
        "language",
        "wake_up_text",
        "sleep_text",
        "system_prompt_zh_path",
        "system_prompt_en_path",
    ):
        _require_string(configuration, key)
    if type(configuration["hooks"]) is not dict:
        raise ValueError("chatbot hooks are invalid")


def _configuration_startup(
    checker: Callable[[Mapping[str, object], StartupSideEffectSpies], None],
    configuration: Mapping[str, object],
    spies: StartupSideEffectSpies,
) -> None:
    checker(configuration, spies)
    if spies.attempted_kinds:
        raise OfflineStartupSideEffectAttempt("configuration startup rejected")


def _audio_device_rows(pyaudio_module: object) -> tuple[dict[str, object], ...]:
    audio = getattr(pyaudio_module, "PyAudio")()
    rows: list[dict[str, object]] = []
    try:
        count = audio.get_device_count()
        if type(count) is not int or count < 0 or count > 4096:
            raise ValueError("audio device count is invalid")
        for index in range(count):
            device = audio.get_device_info_by_index(index)
            if not isinstance(device, Mapping):
                raise ValueError("audio device information is invalid")
            input_channels = device.get("maxInputChannels", 0)
            output_channels = device.get("maxOutputChannels", 0)
            if not isinstance(input_channels, (int, float)) or not isinstance(
                output_channels, (int, float)
            ):
                raise ValueError("audio channel inventory is invalid")
            rows.append(
                {
                    "name": device.get("name"),
                    "maxInputChannels": input_channels,
                    "maxOutputChannels": output_channels,
                }
            )
    finally:
        audio.terminate()
    return tuple(rows)


def enumerate_audio_devices(
    pyaudio_module: object, configured_device_name: str
) -> AudioInventory:
    """Count matching full-duplex devices without opening an audio stream."""

    return _normalize_inventory(
        _audio_device_rows(pyaudio_module), configured_device_name
    )


def _default_audio_enumerator() -> tuple[dict[str, object], ...]:
    pyaudio_module = importlib.import_module("pyaudio")
    return _audio_device_rows(pyaudio_module)


def _normalize_inventory(value: object, configured_device_name: str) -> AudioInventory:
    if type(configured_device_name) is not str or not configured_device_name:
        raise ValueError("configured audio device name is invalid")
    if type(value) is AudioInventory:
        return value
    if type(value) not in {tuple, list}:
        raise ValueError("audio inventory is invalid")
    input_count = 0
    output_count = 0
    matching_full_duplex_count = 0
    if len(value) > 4096:
        raise ValueError("audio inventory exceeds bound")
    for device in value:
        if not isinstance(device, Mapping):
            raise ValueError("audio inventory row is invalid")
        input_channels = device.get("maxInputChannels", 0)
        output_channels = device.get("maxOutputChannels", 0)
        name = device.get("name")
        if (
            not isinstance(input_channels, (int, float))
            or not isinstance(output_channels, (int, float))
            or type(name) is not str
        ):
            raise ValueError("audio channel inventory is invalid")
        input_count += int(input_channels > 0)
        output_count += int(output_channels > 0)
        matching_full_duplex_count += int(
            input_channels > 0
            and output_channels > 0
            and configured_device_name.casefold() in name.casefold()
        )
    return AudioInventory(
        input_count=input_count,
        output_count=output_count,
        matching_full_duplex_count=matching_full_duplex_count,
    )


def _credential_presence(
    environment: Mapping[str, str],
) -> tuple[tuple[str, bool], ...]:
    presence: list[tuple[str, bool]] = []
    for name in REQUIRED_PROVIDER_VARIABLES:
        try:
            value = environment[name] if name in environment else None
            stripped = value.strip() if type(value) is str else ""
            present = (
                len(stripped) >= _CREDENTIAL_MINIMUM_LENGTH
                and stripped.casefold() not in _CREDENTIAL_PLACEHOLDERS
            )
        except Exception:
            present = False
        presence.append((name, present))
    return tuple(presence)


def _side_effect_measurements(
    guard: ChatbotOfflineSideEffectGuard,
) -> tuple[dict[str, object], ...]:
    return (
        _measurement(
            "process_spawn_attempted",
            bool(guard.process_attempts),
        ),
        _measurement(
            "network_attempted",
            bool(guard.network_attempts),
        ),
        _measurement(
            "microphone_attempted",
            bool(guard.microphone_attempts),
        ),
    )


def _run_chatbot_gates_core(
    *,
    pyproject_path: Path,
    configuration_path: Path,
    dependency_probe: Callable[[str], bool] = _default_dependency_probe,
    audio_enumerator: Callable[[], object] = _default_audio_enumerator,
    startup_checker: Callable[
        [Mapping[str, object], StartupSideEffectSpies], None
    ] = validate_configuration_startup,
    environment: Mapping[str, str] | None = None,
    startup_timeout_seconds: float = DEFAULT_READINESS_TIMEOUT_SECONDS,
) -> ChatbotGateResult:
    """Return the fixed four chatbot gates without live speech or API access."""

    importability: list[tuple[str, bool]] = []
    dependency_gate = _dependency_gate((), passed=False)
    spies = StartupSideEffectSpies()
    guard = ChatbotOfflineSideEffectGuard()
    stage = "dependencies"
    declarations_valid = False
    try:
        with _WholeReadinessDeadline(startup_timeout_seconds), guard:
            declared = _declared_dependencies(pyproject_path)
            declarations_valid = set(REQUIRED_IMPORTS).issubset(declared)
            for name in REQUIRED_IMPORTS:
                try:
                    available = dependency_probe(name)
                except ChatbotReadinessTimeout:
                    raise
                except OfflineStartupSideEffectAttempt:
                    raise
                except Exception:
                    available = False
                importability.append((name, available is True))
                guard.reject_new_live_threads()
                if guard.side_effect_attempted:
                    raise OfflineStartupSideEffectAttempt(
                        "dependency side effect rejected"
                    )
            dependencies_ok = declarations_valid and all(
                available for _, available in importability
            )
            dependency_gate = _dependency_gate(
                tuple(importability), passed=dependencies_ok
            )
            if not dependencies_ok:
                return _failure_after_dependencies(dependency_gate)

            stage = "configuration"
            configuration = _load_configuration(configuration_path)
            validate_configuration_startup(configuration, StartupSideEffectSpies())
            configured_device_name = _require_string(
                _require_mapping(
                    configuration["audio_device"],
                    {"device_name", "channels", "chunk_size"},
                ),
                "device_name",
            )
            _configuration_startup(startup_checker, configuration, spies)
            guard.reject_new_live_threads()
            if guard.side_effect_attempted:
                raise OfflineStartupSideEffectAttempt(
                    "configuration startup side effect rejected"
                )
            inventory = _normalize_inventory(audio_enumerator(), configured_device_name)
            guard.reject_new_live_threads()
            if guard.side_effect_attempted:
                raise OfflineStartupSideEffectAttempt(
                    "audio inventory side effect rejected"
                )

            source_environment = os.environ if environment is None else environment
            credential_presence = _credential_presence(source_environment)
            guard.reject_new_live_threads()
            if guard.side_effect_attempted:
                raise OfflineStartupSideEffectAttempt(
                    "credential inspection side effect rejected"
                )
            configuration_gate = _configuration_gate(guard, passed=True)
            credentials = all(present for _, present in credential_presence)
            audio = inventory.matching_full_duplex_count > 0
            credential_gate = _gate(
                "chatbot.credentials",
                "PASS" if credentials else "QUALIFIED",
                "OK" if credentials else "CREDENTIALS_MISSING",
                role="qualification",
                measurements=tuple(
                    _measurement(f"{name}_present", present)
                    for name, present in credential_presence
                ),
            )
            audio_gate = _gate(
                "chatbot.audio_hardware",
                "PASS" if audio else "QUALIFIED",
                "OK" if audio else "AUDIO_HARDWARE_MISSING",
                role="qualification",
                measurements=(
                    _measurement("audio_input_device_count", inventory.input_count),
                    _measurement("audio_output_device_count", inventory.output_count),
                    _measurement(
                        "matching_full_duplex_device_count",
                        inventory.matching_full_duplex_count,
                    ),
                    _measurement(
                        "configured_full_duplex_device_present",
                        audio,
                    ),
                    _measurement("audio_stream_opened", False),
                ),
            )
            decision = classify_external_readiness(credentials=credentials, audio=audio)
            return ChatbotGateResult(
                gates=(
                    dependency_gate,
                    configuration_gate,
                    credential_gate,
                    audio_gate,
                ),
                label=decision.label,
                exit_code=decision.exit_code,
            )
    except OfflineStartupSideEffectAttempt:
        if stage == "dependencies":
            dependency_gate = _dependency_gate(
                tuple(importability),
                passed=False,
                guard=guard,
            )
            return _failure_after_dependencies(dependency_gate)
        return _failure_after_configuration(
            dependency_gate,
            _configuration_gate(guard, passed=False),
        )
    except Exception:
        if stage == "dependencies":
            dependency_gate = _dependency_gate(tuple(importability), passed=False)
            return _failure_after_dependencies(dependency_gate)
        return _failure_after_configuration(
            dependency_gate,
            _configuration_gate(guard, passed=False),
        )


def _closed_child_failure() -> ChatbotGateResult:
    return _failure_after_dependencies(_dependency_gate((), passed=False))


def _canonical_json_bytes(document: object) -> bytes:
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _valid_readiness_timeout(timeout_seconds: object) -> bool:
    return (
        type(timeout_seconds) is float
        and 0.01 <= timeout_seconds <= MAX_READINESS_TIMEOUT_SECONDS
    )


def _encode_chatbot_child_control(
    *,
    pyproject_path: Path,
    configuration_path: Path,
    timeout_seconds: float,
) -> bytes:
    if not _valid_readiness_timeout(timeout_seconds):
        raise ValueError("chatbot child timeout is invalid")
    paths = (Path(pyproject_path), Path(configuration_path))
    if any(not path.is_absolute() for path in paths):
        raise ValueError("chatbot child paths must be absolute")
    document = {
        "configuration_path": str(paths[1]),
        "pyproject_path": str(paths[0]),
        "schema_version": CHATBOT_CHILD_CONTROL_SCHEMA,
        "timeout_seconds": timeout_seconds,
    }
    payload = _canonical_json_bytes(document)
    if len(payload) > CHATBOT_CHILD_CONTROL_MAX_BYTES:
        raise ValueError("chatbot child control exceeds bound")
    return payload


def _decode_chatbot_child_control(payload: bytes) -> tuple[Path, Path, float]:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CHATBOT_CHILD_CONTROL_MAX_BYTES
    ):
        raise ValueError("chatbot child control is invalid")
    document = json.loads(
        payload.decode("utf-8"),
        parse_constant=lambda _token: (_ for _ in ()).throw(
            ValueError("chatbot child control constant is invalid")
        ),
    )
    if (
        type(document) is not dict
        or set(document)
        != {
            "schema_version",
            "pyproject_path",
            "configuration_path",
            "timeout_seconds",
        }
        or document["schema_version"] != CHATBOT_CHILD_CONTROL_SCHEMA
        or type(document["pyproject_path"]) is not str
        or type(document["configuration_path"]) is not str
        or not _valid_readiness_timeout(document["timeout_seconds"])
        or _canonical_json_bytes(document) != payload
    ):
        raise ValueError("chatbot child control is not closed")
    pyproject_path = Path(document["pyproject_path"])
    configuration_path = Path(document["configuration_path"])
    if (
        not pyproject_path.is_absolute()
        or not configuration_path.is_absolute()
        or "\0" in str(pyproject_path)
        or "\0" in str(configuration_path)
    ):
        raise ValueError("chatbot child control paths are invalid")
    return pyproject_path, configuration_path, document["timeout_seconds"]


def _chatbot_result_document(result: ChatbotGateResult) -> dict[str, object]:
    return {
        "exit_code": result.exit_code,
        "gates": list(result.gates),
        "label": result.label,
    }


def _encode_chatbot_child_result(result: ChatbotGateResult) -> bytes:
    payload = _canonical_json_bytes(_chatbot_result_document(result))
    if len(payload) > CHATBOT_CHILD_RESULT_MAX_BYTES:
        raise ValueError("chatbot child result exceeds bound")
    return payload


def _measurement_rows(
    gate: dict[str, object], expected_names: tuple[str, ...]
) -> tuple[dict[str, object], ...]:
    measurements = gate["measurements"]
    if type(measurements) is not list or len(measurements) != len(expected_names):
        raise ValueError("chatbot child measurements are invalid")
    rows = tuple(measurements)
    for row, expected_name in zip(rows, expected_names, strict=True):
        if (
            type(row) is not dict
            or set(row) != {"name", "value", "unit"}
            or row["name"] != expected_name
            or row["unit"] is not None
        ):
            raise ValueError("chatbot child measurement is not closed")
    return rows


def _validate_child_gate_shape(
    gate: object, gate_id: str, role: str
) -> dict[str, object]:
    if (
        type(gate) is not dict
        or set(gate)
        != {
            "id",
            "status",
            "role",
            "reason",
            "measurements",
            "thresholds",
            "log_paths",
            "child_command_exit_code",
        }
        or gate["id"] != gate_id
        or gate["role"] != role
        or gate["thresholds"] != []
        or gate["log_paths"] != []
        or gate["child_command_exit_code"] is not None
    ):
        raise ValueError("chatbot child gate is not closed")
    return gate


def _validate_dependency_child_gate(gate: dict[str, object]) -> None:
    status_reason = (gate["status"], gate["reason"])
    if status_reason not in {
        ("PASS", "OK"),
        ("FAIL", "CHATBOT_DEPENDENCY_MISSING"),
    }:
        raise ValueError("chatbot dependency child gate is invalid")
    measurements = gate["measurements"]
    if type(measurements) is not list:
        raise ValueError("chatbot dependency measurements are invalid")
    names = tuple(
        row.get("name") if type(row) is dict else None for row in measurements
    )
    import_names = tuple(f"{name}_importable" for name in REQUIRED_IMPORTS)
    import_count = 0
    while (
        import_count < len(names)
        and import_count < len(import_names)
        and names[import_count] == import_names[import_count]
    ):
        import_count += 1
    remaining_names = names[import_count:]
    side_effect_names = (
        "process_spawn_attempted",
        "network_attempted",
        "microphone_attempted",
    )
    if remaining_names not in {(), side_effect_names}:
        raise ValueError("chatbot dependency evidence names are invalid")
    for row in measurements:
        if (
            type(row) is not dict
            or set(row) != {"name", "value", "unit"}
            or type(row["value"]) is not bool
            or row["unit"] is not None
        ):
            raise ValueError("chatbot dependency evidence is invalid")
    if remaining_names and not any(row["value"] for row in measurements[import_count:]):
        raise ValueError("chatbot dependency side-effect evidence is untruthful")
    if gate["status"] == "PASS" and (
        import_count != len(REQUIRED_IMPORTS)
        or remaining_names
        or not all(row["value"] for row in measurements)
    ):
        raise ValueError("chatbot dependency pass evidence is incomplete")


def _decode_chatbot_child_result(payload: bytes) -> ChatbotGateResult:
    if (
        type(payload) is not bytes
        or not payload
        or len(payload) > CHATBOT_CHILD_RESULT_MAX_BYTES
    ):
        raise ValueError("chatbot child result is invalid")
    document = json.loads(
        payload.decode("utf-8"),
        parse_constant=lambda _token: (_ for _ in ()).throw(
            ValueError("chatbot child result constant is invalid")
        ),
    )
    if (
        type(document) is not dict
        or set(document) != {"exit_code", "gates", "label"}
        or _canonical_json_bytes(document) != payload
        or type(document["exit_code"]) is not int
        or type(document["gates"]) is not list
        or len(document["gates"]) != 4
    ):
        raise ValueError("chatbot child result is not closed")
    dependency = _validate_child_gate_shape(
        document["gates"][0], "chatbot.dependencies", "required"
    )
    configuration = _validate_child_gate_shape(
        document["gates"][1], "chatbot.configuration", "required"
    )
    credentials = _validate_child_gate_shape(
        document["gates"][2], "chatbot.credentials", "qualification"
    )
    audio = _validate_child_gate_shape(
        document["gates"][3], "chatbot.audio_hardware", "qualification"
    )
    _validate_dependency_child_gate(dependency)
    side_effect_names = (
        "process_spawn_attempted",
        "network_attempted",
        "microphone_attempted",
    )
    if configuration["status"] == "NOT_RUN":
        if configuration["reason"] != "EARLIER_BLOCKING_GATE":
            raise ValueError("chatbot configuration child gate is invalid")
        _measurement_rows(configuration, ())
    else:
        if (configuration["status"], configuration["reason"]) not in {
            ("PASS", "OK"),
            ("FAIL", "CHATBOT_CONFIG_INVALID"),
        }:
            raise ValueError("chatbot configuration child gate is invalid")
        rows = _measurement_rows(configuration, side_effect_names)
        if any(type(row["value"]) is not bool for row in rows):
            raise ValueError("chatbot configuration evidence is invalid")
        if configuration["status"] == "PASS" and any(row["value"] for row in rows):
            raise ValueError("chatbot configuration pass evidence is inconsistent")
    later_not_run = configuration["status"] in {"NOT_RUN", "FAIL"}
    if dependency["status"] == "PASS" and configuration["status"] == "NOT_RUN":
        raise ValueError("chatbot dependency pass cannot skip configuration")
    if later_not_run:
        for gate in (credentials, audio):
            if (gate["status"], gate["reason"]) != (
                "NOT_RUN",
                "EARLIER_BLOCKING_GATE",
            ):
                raise ValueError("chatbot later child gate is invalid")
            _measurement_rows(gate, ())
        expected_label = "FAIL_CHATBOT"
        expected_exit = 1
    else:
        credential_rows = _measurement_rows(
            credentials,
            tuple(f"{name}_present" for name in REQUIRED_PROVIDER_VARIABLES),
        )
        if any(type(row["value"]) is not bool for row in credential_rows):
            raise ValueError("chatbot credential child evidence is invalid")
        credentials_present = all(row["value"] for row in credential_rows)
        if (credentials["status"], credentials["reason"]) != (
            ("PASS", "OK")
            if credentials_present
            else ("QUALIFIED", "CREDENTIALS_MISSING")
        ):
            raise ValueError("chatbot credential child gate is inconsistent")
        audio_rows = _measurement_rows(
            audio,
            (
                "audio_input_device_count",
                "audio_output_device_count",
                "matching_full_duplex_device_count",
                "configured_full_duplex_device_present",
                "audio_stream_opened",
            ),
        )
        if (
            any(
                type(row["value"]) is not int or row["value"] < 0
                for row in audio_rows[:3]
            )
            or type(audio_rows[3]["value"]) is not bool
            or audio_rows[4]["value"] is not False
        ):
            raise ValueError("chatbot audio child evidence is invalid")
        audio_present = audio_rows[3]["value"]
        input_count, output_count, matching_count = (
            row["value"] for row in audio_rows[:3]
        )
        if (
            matching_count > input_count
            or matching_count > output_count
            or audio_present is not (matching_count > 0)
        ):
            raise ValueError("chatbot audio child evidence is inconsistent")
        if (audio["status"], audio["reason"]) != (
            ("PASS", "OK") if audio_present else ("QUALIFIED", "AUDIO_HARDWARE_MISSING")
        ):
            raise ValueError("chatbot audio child gate is inconsistent")
        decision = classify_external_readiness(
            credentials=credentials_present,
            audio=audio_present,
        )
        expected_label = decision.label
        expected_exit = decision.exit_code
    if dependency["status"] == "FAIL":
        if configuration["status"] != "NOT_RUN":
            raise ValueError("chatbot dependency failure did not stop later gates")
        expected_label = "FAIL_CHATBOT"
        expected_exit = 1
    if document["label"] != expected_label or document["exit_code"] != expected_exit:
        raise ValueError("chatbot child result decision is inconsistent")
    return ChatbotGateResult(
        gates=tuple(document["gates"]),
        label=document["label"],
        exit_code=document["exit_code"],
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_process_start_time(pid: int) -> int:
    payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing_parenthesis = payload.rfind(")")
    fields = payload[closing_parenthesis + 2 :].split()
    if closing_parenthesis < 1 or len(fields) < 20:
        raise OSError("chatbot child process identity is invalid")
    value = int(fields[19])
    if value <= 0:
        raise OSError("chatbot child process start time is invalid")
    return value


def _bind_owned_child(process: subprocess.Popen[bytes]) -> _OwnedChildIdentity:
    pid = process.pid
    pgid = os.getpgid(pid)
    identity = _OwnedChildIdentity(pid, pgid, _read_process_start_time(pid))
    if pid <= 1 or pgid != pid:
        raise OSError("chatbot child process group is not owned")
    return identity


def _root_identity_matches(identity: _OwnedChildIdentity) -> bool:
    try:
        return (
            os.getpgid(identity.pid) == identity.pgid
            and _read_process_start_time(identity.pid) == identity.start_time_ticks
        )
    except (OSError, ValueError):
        return False


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError as error:
        if error.errno != errno.ESRCH:
            raise
        return False
    return True


def _wait_for_group_absence(pgid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _process_group_exists(pgid):
            return True
        time.sleep(CHATBOT_CHILD_POLL_SECONDS)
    return not _process_group_exists(pgid)


def _owned_child_or_group_present(process: subprocess.Popen[bytes], pgid: int) -> bool:
    try:
        root_present = process.poll() is None
    except BaseException:
        root_present = True
    try:
        group_present = _process_group_exists(pgid)
    except BaseException:
        group_present = True
    return root_present or group_present


def _wait_for_owned_term_cleanup(process: subprocess.Popen[bytes], pgid: int) -> bool:
    deadline = time.monotonic() + CHATBOT_CHILD_TERM_GRACE_SECONDS
    while time.monotonic() < deadline:
        if not _owned_child_or_group_present(process, pgid):
            return True
        time.sleep(CHATBOT_CHILD_POLL_SECONDS)
    return not _owned_child_or_group_present(process, pgid)


def _finalize_owned_child(
    process: subprocess.Popen[bytes],
    _identity: _OwnedChildIdentity | None,
) -> bool:
    pid = getattr(process, "pid", None)
    pgid = pid if type(pid) is int and pid > 1 else None
    group_was_present = True
    if pgid is not None:
        try:
            group_was_present = _process_group_exists(pgid)
        except BaseException:
            pass

    wait_error = None
    try:
        if pgid is not None and _owned_child_or_group_present(process, pgid):
            try:
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError as error:
                if error.errno != errno.ESRCH:
                    raise
            except BaseException:
                pass
            if not _wait_for_owned_term_cleanup(process, pgid):
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError as error:
                    if error.errno != errno.ESRCH:
                        raise
                except BaseException:
                    pass
    finally:
        try:
            process.wait(timeout=CHATBOT_CHILD_KILL_GRACE_SECONDS)
        except BaseException as error:
            wait_error = error

    group_absent = False
    if pgid is not None:
        try:
            if wait_error is None:
                group_absent = _wait_for_group_absence(
                    pgid,
                    CHATBOT_CHILD_KILL_GRACE_SECONDS,
                )
            else:
                group_absent = not _process_group_exists(pgid)
        except BaseException:
            pass
    if wait_error is not None or process.returncode is None or not group_absent:
        raise ChatbotChildContainmentError(
            "chatbot child cleanup could not be proven"
        ) from wait_error
    return group_was_present


def _close_chatbot_control_descriptor(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("chatbot child control write failed")
        offset += written


def _run_owned_chatbot_child(
    *,
    command: tuple[str, ...],
    control: bytes,
    timeout_seconds: float,
) -> ChatbotGateResult:
    if (
        type(command) is not tuple
        or len(command) < 4
        or command[:3] != (str(PYTHON_EXECUTABLE), "-I", "-B")
        or any(type(argument) is not str or "\0" in argument for argument in command)
        or not _valid_readiness_timeout(timeout_seconds)
    ):
        return _closed_child_failure()
    try:
        _decode_chatbot_child_control(control)
    except Exception:
        return _closed_child_failure()
    read_descriptor = -1
    write_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    identity: _OwnedChildIdentity | None = None
    transport_failed = False
    try:
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        with tempfile.TemporaryFile(mode="w+b") as result_file:
            operation_failed = False
            residual_group = False
            try:
                os.fchmod(result_file.fileno(), 0o600)
                if os.fstat(result_file.fileno()).st_mode & 0o777 != 0o600:
                    raise OSError("chatbot child result file mode is invalid")
                process = subprocess.Popen(
                    command,
                    stdin=read_descriptor,
                    stdout=result_file,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                )
                _close_chatbot_control_descriptor(read_descriptor)
                read_descriptor = -1
                identity = _bind_owned_child(process)
                if not hasattr(resource, "prlimit"):
                    raise OSError("chatbot child file limit is unavailable")
                resource.prlimit(
                    identity.pid,
                    resource.RLIMIT_FSIZE,
                    (
                        CHATBOT_CHILD_RESULT_MAX_BYTES,
                        CHATBOT_CHILD_RESULT_MAX_BYTES,
                    ),
                )
                _write_all(write_descriptor, control)
                _close_chatbot_control_descriptor(write_descriptor)
                write_descriptor = -1
                deadline = time.monotonic() + timeout_seconds
                while process.poll() is None:
                    if (
                        os.fstat(result_file.fileno()).st_size
                        > CHATBOT_CHILD_RESULT_MAX_BYTES
                        or time.monotonic() >= deadline
                        or not _root_identity_matches(identity)
                    ):
                        transport_failed = True
                        break
                    time.sleep(CHATBOT_CHILD_POLL_SECONDS)
                if (
                    os.fstat(result_file.fileno()).st_size
                    > CHATBOT_CHILD_RESULT_MAX_BYTES
                ):
                    transport_failed = True
            except Exception:
                operation_failed = True
            finally:
                if process is not None:
                    residual_group = _finalize_owned_child(process, identity)
            if (
                operation_failed
                or residual_group
                or transport_failed
                or process.returncode != 0
            ):
                return _closed_child_failure()
            result_file.seek(0)
            payload = result_file.read(CHATBOT_CHILD_RESULT_MAX_BYTES + 1)
            return _decode_chatbot_child_result(payload)
    except ChatbotChildContainmentError:
        raise
    except Exception:
        return _closed_child_failure()
    finally:
        for descriptor in (read_descriptor, write_descriptor):
            _close_chatbot_control_descriptor(descriptor)


def run_chatbot_gates(
    *,
    pyproject_path: Path,
    configuration_path: Path,
    startup_timeout_seconds: float = DEFAULT_READINESS_TIMEOUT_SECONDS,
) -> ChatbotGateResult:
    """Run the chatbot readiness probe in one owned fresh-exec child."""

    try:
        if _sha256_file(PYTHON_EXECUTABLE) != PYTHON_EXECUTABLE_SHA256:
            raise OSError("chatbot interpreter identity mismatch")
        control = _encode_chatbot_child_control(
            pyproject_path=Path(pyproject_path),
            configuration_path=Path(configuration_path),
            timeout_seconds=startup_timeout_seconds,
        )
    except Exception:
        return _closed_child_failure()
    return _run_owned_chatbot_child(
        command=(
            str(PYTHON_EXECUTABLE),
            "-I",
            "-B",
            str(_CHATBOT_CHILD_ENTRY),
        ),
        control=control,
        timeout_seconds=startup_timeout_seconds,
    )


def _chatbot_child_main() -> int:
    try:
        payload = sys.stdin.buffer.read(CHATBOT_CHILD_CONTROL_MAX_BYTES + 1)
        pyproject_path, configuration_path, timeout_seconds = (
            _decode_chatbot_child_control(payload)
        )
        result = _run_chatbot_gates_core(
            pyproject_path=pyproject_path,
            configuration_path=configuration_path,
            startup_timeout_seconds=timeout_seconds,
        )
        encoded = _encode_chatbot_child_result(result)
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        return 70
