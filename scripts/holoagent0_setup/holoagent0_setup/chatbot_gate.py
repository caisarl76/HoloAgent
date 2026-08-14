"""Side-effect-free readiness checks for the Python 3.10 G1 chatbot."""

from __future__ import annotations

import ast
from contextlib import ExitStack
from dataclasses import dataclass
import importlib
import json
import multiprocessing
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from threading import current_thread, main_thread
import time
from typing import Callable, Mapping
from unittest.mock import patch


REQUIRED_IMPORTS = ("aiohttp", "loguru", "pyaudio", "pydub", "websockets")
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

    def __post_init__(self) -> None:
        if (
            type(self.input_count) is not int
            or self.input_count < 0
            or type(self.output_count) is not int
            or self.output_count < 0
        ):
            raise ValueError("invalid audio inventory")


@dataclass(frozen=True)
class ChatbotGateResult:
    gates: tuple[dict[str, object], ...]
    label: str
    exit_code: int


class OfflineStartupSideEffectAttempt(RuntimeError):
    """A configuration-only startup attempted a prohibited operation."""


class ChatbotReadinessTimeout(TimeoutError):
    """The single reviewed chatbot readiness deadline expired."""


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
        signal.setitimer(signal.ITIMER_REAL, self._timeout_seconds)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, self._previous_handler)
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
    _active_guard: "_PythonOfflineSideEffectGuard | None" = None
    _audit_hook_installed = False

    def __init__(self) -> None:
        self.network_attempts: list[str] = []
        self.process_attempts: list[str] = []
        self._stack: ExitStack | None = None

    def __enter__(self) -> "_PythonOfflineSideEffectGuard":
        if self._stack is not None or type(self)._active_guard is not None:
            raise RuntimeError("Python side-effect guard is already active")
        stack = ExitStack()
        self._stack = stack
        try:
            if not type(self)._audit_hook_installed:
                sys.addaudithook(type(self)._audit_hook)
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
        self._stack = None
        try:
            stack.close()
        finally:
            if type(self)._active_guard is self:
                type(self)._active_guard = None

    @classmethod
    def _audit_hook(cls, event: str, _arguments: tuple[object, ...]) -> None:
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
    importability: tuple[tuple[str, bool], ...], *, passed: bool
) -> dict[str, object]:
    return _gate(
        "chatbot.dependencies",
        "PASS" if passed else "FAIL",
        "OK" if passed else "CHATBOT_DEPENDENCY_MISSING",
        role="required",
        measurements=tuple(
            _measurement(f"{name}_importable", available)
            for name, available in importability
        ),
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


def enumerate_audio_devices(pyaudio_module: object) -> AudioInventory:
    """Count input/output devices without ever opening an audio stream."""

    audio = getattr(pyaudio_module, "PyAudio")()
    input_count = 0
    output_count = 0
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
            input_count += int(input_channels > 0)
            output_count += int(output_channels > 0)
    finally:
        audio.terminate()
    return AudioInventory(input_count=input_count, output_count=output_count)


def _default_audio_enumerator() -> AudioInventory:
    pyaudio_module = importlib.import_module("pyaudio")
    return enumerate_audio_devices(pyaudio_module)


def _normalize_inventory(value: object) -> AudioInventory:
    if type(value) is AudioInventory:
        return value
    if type(value) not in {tuple, list}:
        raise ValueError("audio inventory is invalid")
    input_count = 0
    output_count = 0
    if len(value) > 4096:
        raise ValueError("audio inventory exceeds bound")
    for device in value:
        if not isinstance(device, Mapping):
            raise ValueError("audio inventory row is invalid")
        input_channels = device.get("maxInputChannels", 0)
        output_channels = device.get("maxOutputChannels", 0)
        if not isinstance(input_channels, (int, float)) or not isinstance(
            output_channels, (int, float)
        ):
            raise ValueError("audio channel inventory is invalid")
        input_count += int(input_channels > 0)
        output_count += int(output_channels > 0)
    return AudioInventory(input_count=input_count, output_count=output_count)


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


def run_chatbot_gates(
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
            _configuration_startup(startup_checker, configuration, spies)
            inventory = _normalize_inventory(audio_enumerator())

            configuration_gate = _configuration_gate(guard, passed=True)
            source_environment = os.environ if environment is None else environment
            credential_presence = _credential_presence(source_environment)
            credentials = all(present for _, present in credential_presence)
            audio = inventory.input_count > 0 and inventory.output_count > 0
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
        if (
            stage == "dependencies"
            and declarations_valid
            and guard.side_effect_attempted
        ):
            dependency_gate = _dependency_gate(
                tuple((name, True) for name in REQUIRED_IMPORTS), passed=True
            )
            return _failure_after_configuration(
                dependency_gate,
                _configuration_gate(guard, passed=False),
            )
        if stage == "dependencies":
            dependency_gate = _dependency_gate(tuple(importability), passed=False)
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
