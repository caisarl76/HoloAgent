"""Side-effect-free readiness checks for the Python 3.10 G1 chatbot."""

from __future__ import annotations

import ast
import _thread
from contextlib import ExitStack
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import importlib
import json
import multiprocessing
import os
from pathlib import Path, PurePosixPath
import resource
import signal
import socket
import stat
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
CHATBOT_SOURCE_MANIFEST_MAX_BYTES = 8 * 1024 * 1024
CHATBOT_SOURCE_MAX_BYTES = 2 * 1024 * 1024
CHATBOT_MANIFEST_RELATIVE_PATH = PurePosixPath(
    "scripts/holoagent0_setup/manifests/git-tracked-files-v1.txt"
)
CHATBOT_CHILD_RELATIVE_PATH = PurePosixPath("scripts/holoagent0_setup/chatbot_child.py")
CHATBOT_GATE_RELATIVE_PATH = PurePosixPath(
    "scripts/holoagent0_setup/holoagent0_setup/chatbot_gate.py"
)
REQUIRED_CHATBOT_SOURCE_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)
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
class ChatbotSourceAuthority:
    repository_root: Path
    tracked_manifest_sha256: str


@dataclass(frozen=True)
class _OwnedChildIdentity:
    pid: int
    pgid: int
    start_time_ticks: int


@dataclass(frozen=True)
class _ProcessRecord:
    pid: int
    pgrp: int
    state: str
    start_time_ticks: int


@dataclass(frozen=True)
class _ChildWaitStatus:
    pid: int
    code: int
    status: int


class OfflineStartupSideEffectAttempt(RuntimeError):
    """A configuration-only startup attempted a prohibited operation."""


class ChatbotReadinessTimeout(TimeoutError):
    """The single reviewed chatbot readiness deadline expired."""


class ChatbotChildContainmentError(RuntimeError):
    """A spawned chatbot child could not be proven reaped and contained."""


class ChatbotSourceAuthorityError(RuntimeError):
    """Chatbot source bytes could not be bound to reviewed authority."""


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


def _is_lower_hex(value: object, length: int) -> bool:
    return bool(
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _chatbot_authority_open_flags() -> tuple[int, int]:
    required = ("O_CLOEXEC", "O_NOFOLLOW", "O_DIRECTORY")
    values = tuple(getattr(os, name, None) for name in required)
    if any(type(value) is not int for value in values):
        raise ChatbotSourceAuthorityError("chatbot source opening is unavailable")
    close_on_exec, no_follow, directory = values
    return (
        os.O_RDONLY | close_on_exec | no_follow,
        os.O_RDONLY | close_on_exec | no_follow | directory,
    )


def _open_chatbot_authority_relative(
    root_descriptor: int,
    relative_path: PurePosixPath,
) -> int:
    file_flags, directory_flags = _chatbot_authority_open_flags()
    components = relative_path.parts
    if (
        not components
        or relative_path.is_absolute()
        or ".." in components
        or str(relative_path) != relative_path.as_posix()
    ):
        raise ChatbotSourceAuthorityError("chatbot source path is invalid")
    parent_descriptor = root_descriptor
    opened_directories: list[int] = []
    result_descriptor = -1
    cleanup_error: BaseException | None = None
    try:
        for component in components[:-1]:
            parent_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            if parent_descriptor < 3:
                raise OSError("invalid chatbot source directory descriptor")
            opened_directories.append(parent_descriptor)
        result_descriptor = os.open(
            components[-1],
            file_flags,
            dir_fd=parent_descriptor,
        )
        if result_descriptor < 3:
            raise OSError("invalid chatbot source descriptor")
    except ChatbotSourceAuthorityError:
        raise
    except BaseException as error:
        raise ChatbotSourceAuthorityError(
            "chatbot source path is unavailable"
        ) from error
    finally:
        for descriptor in reversed(opened_directories):
            try:
                os.close(descriptor)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            if result_descriptor >= 0:
                try:
                    os.close(result_descriptor)
                except BaseException:
                    pass
                result_descriptor = -1
            raise ChatbotSourceAuthorityError(
                "chatbot source directory cleanup failed"
            ) from cleanup_error
    return result_descriptor


def _stable_chatbot_authority_payload(
    descriptor: int,
    relative_path: PurePosixPath,
    *,
    maximum_bytes: int,
    source_hook: Callable[[str, Path, int], None] | None,
) -> bytes:
    try:
        before = os.fstat(descriptor)
        if (
            descriptor < 3
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o111
            or before.st_nlink < 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise ChatbotSourceAuthorityError(
                "chatbot source authority file identity is invalid"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise ChatbotSourceAuthorityError(
                    "chatbot source authority file is truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ChatbotSourceAuthorityError(
                "chatbot source authority file exceeds its bound"
            )
        if source_hook is not None:
            source_hook("after_read", Path(str(relative_path)), descriptor)
        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise ChatbotSourceAuthorityError(
                "chatbot source authority file changed during verification"
            )
        return b"".join(chunks)
    except ChatbotSourceAuthorityError:
        raise
    except BaseException as error:
        raise ChatbotSourceAuthorityError(
            "chatbot source authority file is unavailable"
        ) from error


def _chatbot_manifest_source_oids(
    payload: bytes, expected_sha256: str
) -> dict[str, str]:
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ChatbotSourceAuthorityError(
            "chatbot source manifest digest is unreviewed"
        )
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ChatbotSourceAuthorityError(
            "chatbot source manifest is undecodable"
        ) from error
    if not text.endswith("\n") or "\r" in text or "\0" in text:
        raise ChatbotSourceAuthorityError("chatbot source manifest is noncanonical")
    rows: list[tuple[str, str, str]] = []
    for encoded in text.splitlines():
        try:
            metadata, relative = encoded.split("\t", 1)
            mode, oid = metadata.split(" ", 1)
        except ValueError as error:
            raise ChatbotSourceAuthorityError(
                "chatbot source manifest row is invalid"
            ) from error
        path = PurePosixPath(relative)
        if (
            mode not in {"100644", "100755", "120000"}
            or not relative
            or path.is_absolute()
            or ".." in path.parts
            or relative != path.as_posix()
            or oid != "SELF"
            and not _is_lower_hex(oid, 40)
        ):
            raise ChatbotSourceAuthorityError("chatbot source manifest row is invalid")
        rows.append((mode, oid, relative))
    paths = tuple(row[2] for row in rows)
    if not rows or paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
        raise ChatbotSourceAuthorityError(
            "chatbot source manifest inventory is invalid"
        )
    by_path = {relative: (mode, oid) for mode, oid, relative in rows}
    result: dict[str, str] = {}
    for required_path in (
        CHATBOT_CHILD_RELATIVE_PATH,
        CHATBOT_GATE_RELATIVE_PATH,
    ):
        row = by_path.get(str(required_path))
        if row is None or row[0] != "100644" or not _is_lower_hex(row[1], 40):
            raise ChatbotSourceAuthorityError(
                "chatbot source manifest row is unavailable"
            )
        result[str(required_path)] = row[1]
    return result


def _chatbot_source_memfd_parameters() -> tuple[int, int, int, int]:
    required = (
        (os, "MFD_ALLOW_SEALING"),
        (os, "MFD_CLOEXEC"),
        (fcntl, "F_ADD_SEALS"),
        (fcntl, "F_GET_SEALS"),
        (fcntl, "F_SEAL_WRITE"),
        (fcntl, "F_SEAL_GROW"),
        (fcntl, "F_SEAL_SHRINK"),
        (fcntl, "F_SEAL_SEAL"),
    )
    values = tuple(getattr(module, name, None) for module, name in required)
    if any(type(value) is not int for value in values):
        raise ChatbotSourceAuthorityError("chatbot source sealing is unavailable")
    (
        allow_sealing,
        close_on_exec,
        add_seals,
        get_seals,
        seal_write,
        seal_grow,
        seal_shrink,
        seal_seal,
    ) = values
    seal_mask = seal_write | seal_grow | seal_shrink | seal_seal
    if seal_mask != REQUIRED_CHATBOT_SOURCE_SEALS:
        raise ChatbotSourceAuthorityError("chatbot source sealing constants changed")
    return allow_sealing | close_on_exec, add_seals, get_seals, seal_mask


def _create_chatbot_source_memfd(name: str, flags: int) -> int:
    creator = getattr(os, "memfd_create", None)
    if not callable(creator):
        raise ChatbotSourceAuthorityError("chatbot source memfd is unavailable")
    descriptor = creator(name, flags)
    if type(descriptor) is not int or descriptor < 3:
        raise ChatbotSourceAuthorityError("chatbot source memfd is invalid")
    return descriptor


def _write_chatbot_source_snapshot(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if type(written) is not int or written <= 0:
            raise ChatbotSourceAuthorityError("chatbot source snapshot write failed")
        offset += written


def _sealed_chatbot_source_git_oid(descriptor: int) -> str:
    metadata = os.fstat(descriptor)
    digest = hashlib.sha1()
    digest.update(f"blob {metadata.st_size}\0".encode("ascii"))
    os.lseek(descriptor, 0, os.SEEK_SET)
    remaining = metadata.st_size
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            raise ChatbotSourceAuthorityError("sealed chatbot source is truncated")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise ChatbotSourceAuthorityError("sealed chatbot source exceeds its bound")
    return digest.hexdigest()


def _close_chatbot_source_descriptors(descriptors: list[int]) -> BaseException | None:
    cleanup_error: BaseException | None = None
    while descriptors:
        descriptor = descriptors.pop()
        try:
            os.close(descriptor)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
    return cleanup_error


def _prepare_chatbot_source_snapshots(
    authority: ChatbotSourceAuthority,
    *,
    _source_hook: Callable[[str, Path, int], None] | None = None,
) -> tuple[int, int]:
    if (
        not isinstance(authority, ChatbotSourceAuthority)
        or not isinstance(authority.repository_root, Path)
        or not authority.repository_root.is_absolute()
        or "\0" in str(authority.repository_root)
        or not _is_lower_hex(authority.tracked_manifest_sha256, 64)
        or _source_hook is not None
        and not callable(_source_hook)
    ):
        raise ChatbotSourceAuthorityError("chatbot source authority is invalid")
    file_flags, directory_flags = _chatbot_authority_open_flags()
    del file_flags
    repository_descriptors: list[int] = []
    snapshot_descriptors: list[int] = []
    failure: BaseException | None = None
    try:
        root_descriptor = os.open(str(authority.repository_root), directory_flags)
        repository_descriptors.append(root_descriptor)
        root_metadata = os.fstat(root_descriptor)
        if (
            root_descriptor < 3
            or not stat.S_ISDIR(root_metadata.st_mode)
            or root_metadata.st_uid != os.geteuid()
        ):
            raise ChatbotSourceAuthorityError(
                "chatbot source repository root identity is invalid"
            )
        opened_list: list[tuple[PurePosixPath, int]] = []
        for relative_path in (
            CHATBOT_MANIFEST_RELATIVE_PATH,
            CHATBOT_CHILD_RELATIVE_PATH,
            CHATBOT_GATE_RELATIVE_PATH,
        ):
            descriptor = _open_chatbot_authority_relative(
                root_descriptor,
                relative_path,
            )
            opened_list.append((relative_path, descriptor))
            repository_descriptors.append(descriptor)
        opened = tuple(opened_list)
        if _source_hook is not None:
            for relative_path, descriptor in opened:
                _source_hook("after_open", Path(str(relative_path)), descriptor)
        payloads = {
            str(relative_path): _stable_chatbot_authority_payload(
                descriptor,
                relative_path,
                maximum_bytes=(
                    CHATBOT_SOURCE_MANIFEST_MAX_BYTES
                    if relative_path == CHATBOT_MANIFEST_RELATIVE_PATH
                    else CHATBOT_SOURCE_MAX_BYTES
                ),
                source_hook=_source_hook,
            )
            for relative_path, descriptor in opened
        }
        expected_oids = _chatbot_manifest_source_oids(
            payloads[str(CHATBOT_MANIFEST_RELATIVE_PATH)],
            authority.tracked_manifest_sha256,
        )
        flags, add_seals, get_seals, required_seals = _chatbot_source_memfd_parameters()
        for name, relative_path in (
            ("holoagent0-chatbot-entry", CHATBOT_CHILD_RELATIVE_PATH),
            ("holoagent0-chatbot-gate", CHATBOT_GATE_RELATIVE_PATH),
        ):
            descriptor = _create_chatbot_source_memfd(name, flags)
            snapshot_descriptors.append(descriptor)
            _write_chatbot_source_snapshot(
                descriptor,
                payloads[str(relative_path)],
            )
            fcntl.fcntl(descriptor, add_seals, required_seals)
            observed = fcntl.fcntl(descriptor, get_seals)
            if type(observed) is not int or observed & required_seals != required_seals:
                raise ChatbotSourceAuthorityError(
                    "sealed chatbot source snapshot is incomplete"
                )
            if (
                _sealed_chatbot_source_git_oid(descriptor)
                != expected_oids[str(relative_path)]
            ):
                raise ChatbotSourceAuthorityError(
                    "sealed chatbot source Git OID mismatch"
                )
            os.lseek(descriptor, 0, os.SEEK_SET)
    except ChatbotSourceAuthorityError as error:
        failure = error
    except BaseException as error:
        failure = ChatbotSourceAuthorityError(
            "chatbot source authority verification failed"
        )
        failure.__cause__ = error
    repository_cleanup_error = _close_chatbot_source_descriptors(repository_descriptors)
    if repository_cleanup_error is not None:
        failure = ChatbotSourceAuthorityError(
            "chatbot source repository descriptor cleanup failed"
        )
        failure.__cause__ = repository_cleanup_error
    if failure is not None:
        snapshot_cleanup_error = _close_chatbot_source_descriptors(snapshot_descriptors)
        if snapshot_cleanup_error is not None:
            failure = ChatbotSourceAuthorityError(
                "chatbot source snapshot cleanup failed"
            )
            failure.__cause__ = snapshot_cleanup_error
        raise failure
    if len(snapshot_descriptors) != 2:
        cleanup_error = _close_chatbot_source_descriptors(snapshot_descriptors)
        error = ChatbotSourceAuthorityError("chatbot source snapshots are incomplete")
        if cleanup_error is not None:
            error.__cause__ = cleanup_error
        raise error
    return snapshot_descriptors[0], snapshot_descriptors[1]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_process_record(
    pid: int,
    *,
    _proc_root: Path = Path("/proc"),
) -> _ProcessRecord:
    if type(pid) is not int or pid <= 0:
        raise ChatbotChildContainmentError("chatbot process identity is invalid")
    try:
        payload = (_proc_root / str(pid) / "stat").read_text(encoding="ascii")
    except FileNotFoundError:
        raise
    except BaseException as error:
        raise ChatbotChildContainmentError(
            "chatbot process identity is unreadable"
        ) from error
    try:
        opening_parenthesis = payload.find("(")
        closing_parenthesis = payload.rfind(")")
        fields = payload[closing_parenthesis + 2 :].split()
        state = fields[0]
        pgrp = int(fields[2])
        start_time_ticks = int(fields[19])
        encoded_pid = int(payload[:opening_parenthesis].strip())
        if (
            opening_parenthesis < 1
            or closing_parenthesis <= opening_parenthesis
            or len(fields) < 20
            or encoded_pid != pid
            or len(state) != 1
            or not state.isascii()
            or not state.isalpha()
            or pgrp <= 0
            or start_time_ticks <= 0
        ):
            raise ValueError("invalid proc stat")
        return _ProcessRecord(pid, pgrp, state, start_time_ticks)
    except (IndexError, ValueError) as error:
        raise ChatbotChildContainmentError(
            "chatbot process identity is malformed"
        ) from error


def _enumerate_process_group(
    pgid: int,
    *,
    _proc_root: Path = Path("/proc"),
) -> tuple[_ProcessRecord, ...]:
    if type(pgid) is not int or pgid <= 1:
        raise ChatbotChildContainmentError("chatbot process group is invalid")
    try:
        entries = tuple(_proc_root.iterdir())
    except BaseException as error:
        raise ChatbotChildContainmentError(
            "chatbot process group enumeration failed"
        ) from error
    records: list[_ProcessRecord] = []
    for entry in entries:
        if not entry.name.isascii() or not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            record = _read_process_record(pid, _proc_root=_proc_root)
        except FileNotFoundError as error:
            if error.errno == errno.ENOENT:
                continue
            raise ChatbotChildContainmentError(
                "chatbot process group enumeration failed"
            ) from error
        if record.pgrp == pgid:
            records.append(record)
    return tuple(sorted(records, key=lambda record: record.pid))


def _bind_owned_child(process: subprocess.Popen[bytes]) -> _OwnedChildIdentity:
    pid = process.pid
    try:
        pgid = os.getpgid(pid)
        record = _read_process_record(pid)
    except BaseException as error:
        raise OSError("chatbot child process identity is unavailable") from error
    identity = _OwnedChildIdentity(pid, pgid, record.start_time_ticks)
    if (
        type(pid) is not int
        or pid <= 1
        or pgid != pid
        or record.pid != pid
        or record.pgrp != pgid
    ):
        raise OSError("chatbot child process group is not owned")
    return identity


def _observe_owned_root_exit(
    identity: _OwnedChildIdentity,
) -> _ChildWaitStatus | None:
    try:
        observed = os.waitid(
            os.P_PID,
            identity.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except BaseException as error:
        raise ChatbotChildContainmentError(
            "chatbot child wait status is unavailable"
        ) from error
    if observed is None:
        return None
    pid = getattr(observed, "si_pid", None)
    code = getattr(observed, "si_code", None)
    status = getattr(observed, "si_status", None)
    allowed_codes = {
        getattr(os, "CLD_EXITED", None),
        getattr(os, "CLD_KILLED", None),
        getattr(os, "CLD_DUMPED", None),
    }
    allowed_codes.discard(None)
    if (
        type(pid) is not int
        or pid != identity.pid
        or type(code) is not int
        or code not in allowed_codes
        or type(status) is not int
        or status < 0
        or status > 255
    ):
        raise ChatbotChildContainmentError("chatbot child wait status is malformed")
    return _ChildWaitStatus(pid, code, status)


def _require_owned_root_record(
    identity: _OwnedChildIdentity,
    records: tuple[_ProcessRecord, ...],
) -> _ProcessRecord:
    roots = tuple(record for record in records if record.pid == identity.pid)
    if (
        len(roots) != 1
        or roots[0].pgrp != identity.pgid
        or roots[0].start_time_ticks != identity.start_time_ticks
    ):
        raise ChatbotChildContainmentError("chatbot child process identity changed")
    return roots[0]


def _root_only_dead_state(
    identity: _OwnedChildIdentity,
    wait_status: _ChildWaitStatus | None,
    records: tuple[_ProcessRecord, ...],
) -> bool:
    root = _require_owned_root_record(identity, records)
    if root.state in {"Z", "X"} and wait_status is None:
        raise ChatbotChildContainmentError(
            "chatbot child wait status contradicts process state"
        )
    if wait_status is not None and root.state not in {"Z", "X"}:
        raise ChatbotChildContainmentError(
            "chatbot child wait status contradicts process state"
        )
    return wait_status is not None and len(records) == 1 and root.state in {"Z", "X"}


def _observe_owned_group_coherently(
    identity: _OwnedChildIdentity,
    wait_status: _ChildWaitStatus | None,
    deadline: float,
) -> tuple[_ChildWaitStatus | None, tuple[_ProcessRecord, ...]]:
    immediate_retry_available = True
    dead_root_observed = False
    while True:
        if wait_status is None:
            wait_status = _observe_owned_root_exit(identity)
        records = _enumerate_process_group(identity.pgid)
        root = _require_owned_root_record(identity, records)
        root_is_dead = root.state in {"Z", "X"}
        if wait_status is not None:
            if not root_is_dead:
                raise ChatbotChildContainmentError(
                    "chatbot child wait status contradicts process state"
                )
            return wait_status, records
        if not root_is_dead:
            if dead_root_observed:
                raise ChatbotChildContainmentError(
                    "chatbot child process state reversed after exit"
                )
            return wait_status, records
        dead_root_observed = True
        if immediate_retry_available:
            immediate_retry_available = False
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChatbotChildContainmentError(
                "chatbot child wait status contradicts process state"
            )
        time.sleep(min(CHATBOT_CHILD_POLL_SECONDS, remaining))


def _signal_owned_group(
    identity: _OwnedChildIdentity,
    records: tuple[_ProcessRecord, ...],
    signum: int,
) -> None:
    _require_owned_root_record(identity, records)
    try:
        os.killpg(identity.pgid, signum)
    except ProcessLookupError as error:
        if error.errno != errno.ESRCH:
            raise ChatbotChildContainmentError(
                "chatbot child group signal failed"
            ) from error
    except BaseException as error:
        raise ChatbotChildContainmentError(
            "chatbot child group signal failed"
        ) from error


def _observe_until_root_only_dead(
    identity: _OwnedChildIdentity,
    wait_status: _ChildWaitStatus | None,
    timeout_seconds: float,
) -> tuple[bool, _ChildWaitStatus | None, tuple[_ProcessRecord, ...]]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        wait_status, records = _observe_owned_group_coherently(
            identity,
            wait_status,
            deadline,
        )
        if _root_only_dead_state(identity, wait_status, records):
            return True, wait_status, records
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, wait_status, records
        time.sleep(min(CHATBOT_CHILD_POLL_SECONDS, remaining))


def _wait_status_returncode(status: _ChildWaitStatus) -> int:
    if status.code == os.CLD_EXITED:
        return status.status
    if status.code in {os.CLD_KILLED, os.CLD_DUMPED} and status.status > 0:
        return -status.status
    raise ChatbotChildContainmentError("chatbot child wait status is malformed")


def _final_group_absence(pgid: int) -> None:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError as error:
        if error.errno == errno.ESRCH:
            return
        raise ChatbotChildContainmentError(
            "chatbot child group absence is unproven"
        ) from error
    except BaseException as error:
        raise ChatbotChildContainmentError(
            "chatbot child group absence is unproven"
        ) from error
    raise ChatbotChildContainmentError("chatbot child process group remains")


def _finalize_unbound_child(process: subprocess.Popen[bytes]) -> None:
    cleanup_error: BaseException | None = None
    try:
        process.kill()
    except ProcessLookupError as error:
        if error.errno != errno.ESRCH:
            cleanup_error = error
    except BaseException as error:
        cleanup_error = error
    try:
        process.wait(timeout=CHATBOT_CHILD_KILL_GRACE_SECONDS)
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    if process.returncode is None:
        cleanup_error = cleanup_error or RuntimeError("chatbot child was not reaped")
    if cleanup_error is not None:
        raise ChatbotChildContainmentError(
            "unbound chatbot child cleanup could not be proven"
        ) from cleanup_error


def _finalize_owned_child(
    process: subprocess.Popen[bytes],
    identity: _OwnedChildIdentity,
    observed_wait_status: _ChildWaitStatus | None,
) -> bool:
    wait_status = observed_wait_status
    cleanup_error: BaseException | None = None
    residual_group = False
    try:
        wait_status, records = _observe_owned_group_coherently(
            identity,
            wait_status,
            time.monotonic() + CHATBOT_CHILD_POLL_SECONDS,
        )
        clean = _root_only_dead_state(identity, wait_status, records)
        if not clean:
            residual_group = True
            _signal_owned_group(identity, records, signal.SIGTERM)
            clean, wait_status, records = _observe_until_root_only_dead(
                identity,
                wait_status,
                CHATBOT_CHILD_TERM_GRACE_SECONDS,
            )
            if not clean:
                _signal_owned_group(identity, records, signal.SIGKILL)
                clean, wait_status, records = _observe_until_root_only_dead(
                    identity,
                    wait_status,
                    CHATBOT_CHILD_KILL_GRACE_SECONDS,
                )
                if not clean:
                    raise ChatbotChildContainmentError(
                        "chatbot child group survived SIGKILL"
                    )
    except BaseException as error:
        cleanup_error = error
    wait_result: object = None
    try:
        wait_result = process.wait(timeout=CHATBOT_CHILD_KILL_GRACE_SECONDS)
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    if (
        type(wait_result) is not int
        or type(process.returncode) is not int
        or wait_result != process.returncode
    ):
        cleanup_error = cleanup_error or RuntimeError(
            "chatbot child reap result is invalid"
        )
    if wait_status is None:
        cleanup_error = cleanup_error or RuntimeError(
            "chatbot child exit was not observed before reaping"
        )
    else:
        try:
            expected_returncode = _wait_status_returncode(wait_status)
        except BaseException as error:
            expected_returncode = None
            if cleanup_error is None:
                cleanup_error = error
        if expected_returncode != process.returncode:
            cleanup_error = cleanup_error or RuntimeError(
                "chatbot child wait status disagrees with return code"
            )
    try:
        _final_group_absence(identity.pgid)
    except BaseException as error:
        if cleanup_error is None:
            cleanup_error = error
    if cleanup_error is not None:
        raise ChatbotChildContainmentError(
            "chatbot child cleanup could not be proven"
        ) from cleanup_error
    return residual_group


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
    source_descriptors: tuple[int, int] | tuple[()] = (),
) -> ChatbotGateResult:
    source_descriptor_list = (
        list(source_descriptors)
        if type(source_descriptors) is tuple
        and all(
            type(descriptor) is int and descriptor >= 3
            for descriptor in source_descriptors
        )
        else []
    )
    source_shape_valid = not source_descriptors or (
        len(source_descriptors) == 2
        and len(set(source_descriptors)) == 2
        and len(command) == 5
        and command[3] == f"/proc/self/fd/{source_descriptors[0]}"
        and command[4] == str(source_descriptors[1])
    )
    if (
        type(command) is not tuple
        or len(command) < 4
        or command[:3] != (str(PYTHON_EXECUTABLE), "-I", "-B")
        or any(type(argument) is not str or "\0" in argument for argument in command)
        or not _valid_readiness_timeout(timeout_seconds)
        or not source_shape_valid
    ):
        cleanup_error = _close_chatbot_source_descriptors(source_descriptor_list)
        if cleanup_error is not None:
            raise ChatbotSourceAuthorityError(
                "chatbot source snapshot cleanup failed"
            ) from cleanup_error
        return _closed_child_failure()
    try:
        _decode_chatbot_child_control(control)
    except Exception:
        cleanup_error = _close_chatbot_source_descriptors(source_descriptor_list)
        if cleanup_error is not None:
            raise ChatbotSourceAuthorityError(
                "chatbot source snapshot cleanup failed"
            ) from cleanup_error
        return _closed_child_failure()
    if signal.getsignal(signal.SIGCHLD) is not signal.SIG_DFL:
        cleanup_error = _close_chatbot_source_descriptors(source_descriptor_list)
        error = ChatbotChildContainmentError(
            "chatbot child requires default SIGCHLD disposition"
        )
        if cleanup_error is not None:
            raise error from cleanup_error
        raise error
    read_descriptor = -1
    write_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    identity: _OwnedChildIdentity | None = None
    transport_failed = False
    source_cleanup_error: BaseException | None = None
    observed_wait_status: _ChildWaitStatus | None = None
    lifecycle_error: ChatbotChildContainmentError | None = None
    try:
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC)
        with tempfile.TemporaryFile(mode="w+b") as result_file:
            operation_failed = False
            residual_group = False
            try:
                os.fchmod(result_file.fileno(), 0o600)
                if os.fstat(result_file.fileno()).st_mode & 0o777 != 0o600:
                    raise OSError("chatbot child result file mode is invalid")
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=read_descriptor,
                        stdout=result_file,
                        stderr=subprocess.DEVNULL,
                        close_fds=True,
                        start_new_session=True,
                        pass_fds=source_descriptors,
                    )
                finally:
                    source_cleanup_error = _close_chatbot_source_descriptors(
                        source_descriptor_list
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
                while True:
                    observed_wait_status, records = _observe_owned_group_coherently(
                        identity,
                        observed_wait_status,
                        deadline,
                    )
                    root = _require_owned_root_record(identity, records)
                    if observed_wait_status is not None:
                        if root.state not in {"Z", "X"}:
                            raise ChatbotChildContainmentError(
                                "chatbot child wait status contradicts process state"
                            )
                        break
                    if (
                        os.fstat(result_file.fileno()).st_size
                        > CHATBOT_CHILD_RESULT_MAX_BYTES
                        or time.monotonic() >= deadline
                    ):
                        transport_failed = True
                        break
                    time.sleep(CHATBOT_CHILD_POLL_SECONDS)
                if (
                    os.fstat(result_file.fileno()).st_size
                    > CHATBOT_CHILD_RESULT_MAX_BYTES
                ):
                    transport_failed = True
            except ChatbotChildContainmentError as error:
                lifecycle_error = error
            except Exception:
                operation_failed = True
            finally:
                if process is not None:
                    try:
                        if identity is None:
                            _finalize_unbound_child(process)
                        else:
                            residual_group = _finalize_owned_child(
                                process,
                                identity,
                                observed_wait_status,
                            )
                    except ChatbotChildContainmentError as error:
                        if lifecycle_error is None:
                            lifecycle_error = error
            if lifecycle_error is not None:
                raise lifecycle_error
            if source_cleanup_error is not None:
                raise ChatbotSourceAuthorityError(
                    "chatbot source snapshot cleanup failed"
                ) from source_cleanup_error
            if (
                operation_failed
                or residual_group
                or transport_failed
                or process is None
                or process.returncode != 0
            ):
                return _closed_child_failure()
            result_file.seek(0)
            payload = result_file.read(CHATBOT_CHILD_RESULT_MAX_BYTES + 1)
            return _decode_chatbot_child_result(payload)
    except ChatbotChildContainmentError:
        raise
    except ChatbotSourceAuthorityError:
        raise
    except Exception:
        return _closed_child_failure()
    finally:
        for descriptor in (read_descriptor, write_descriptor):
            _close_chatbot_control_descriptor(descriptor)
        cleanup_error = _close_chatbot_source_descriptors(source_descriptor_list)
        if cleanup_error is not None:
            raise ChatbotSourceAuthorityError(
                "chatbot source snapshot cleanup failed"
            ) from cleanup_error


def run_chatbot_gates(
    *,
    source_authority: ChatbotSourceAuthority,
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
    source_descriptors = _prepare_chatbot_source_snapshots(source_authority)
    return _run_owned_chatbot_child(
        command=(
            str(PYTHON_EXECUTABLE),
            "-I",
            "-B",
            f"/proc/self/fd/{source_descriptors[0]}",
            str(source_descriptors[1]),
        ),
        control=control,
        timeout_seconds=startup_timeout_seconds,
        source_descriptors=source_descriptors,
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
