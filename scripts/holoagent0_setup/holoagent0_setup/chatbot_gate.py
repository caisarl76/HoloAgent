"""Side-effect-free readiness checks for the Python 3.10 G1 chatbot."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path
import signal
from threading import current_thread, main_thread
import time
from typing import Callable, Mapping


REQUIRED_IMPORTS = ("aiohttp", "loguru", "pyaudio", "pydub", "websockets")
REQUIRED_PROVIDER_VARIABLES = (
    "CHATBOT_ASR_APP_KEY",
    "CHATBOT_ASR_ACCESS_KEY",
    "CHATBOT_ARK_API_KEY",
    "CHATBOT_TTS_APP_KEY",
    "CHATBOT_TTS_ACCESS_KEY",
)
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


def _declared_dependencies(pyproject_path: Path) -> frozenset[str]:
    text = Path(pyproject_path).read_text(encoding="utf-8")
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
        Path(configuration_path).read_text(encoding="utf-8"),
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


def _bounded_startup(
    checker: Callable[[Mapping[str, object], StartupSideEffectSpies], None],
    configuration: Mapping[str, object],
    spies: StartupSideEffectSpies,
    timeout_seconds: float,
) -> None:
    if (
        type(timeout_seconds) is not float
        or timeout_seconds <= 0.0
        or timeout_seconds > 5.0
        or current_thread() is not main_thread()
    ):
        raise ValueError("chatbot startup bound is invalid")
    previous_delay, previous_interval = signal.getitimer(signal.ITIMER_REAL)
    if previous_delay != 0.0 or previous_interval != 0.0:
        raise RuntimeError("chatbot startup alarm is unavailable")
    previous_handler = signal.getsignal(signal.SIGALRM)

    def timed_out(_signum: int, _frame: object) -> None:
        raise TimeoutError("chatbot startup timed out")

    started = time.monotonic()
    signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, timeout_seconds)
    try:
        checker(configuration, spies)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
    if time.monotonic() - started > timeout_seconds or spies.attempted_kinds:
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
            present = (
                name in environment
                and type(environment[name]) is str
                and bool(environment[name])
            )
        except Exception:
            present = False
        presence.append((name, present))
    return tuple(presence)


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
    startup_timeout_seconds: float = 1.0,
) -> ChatbotGateResult:
    """Return the fixed four chatbot gates without live speech or API access."""

    importability: list[tuple[str, bool]] = []
    declarations_valid = False
    try:
        declared = _declared_dependencies(pyproject_path)
        declarations_valid = set(REQUIRED_IMPORTS).issubset(declared)
    except Exception:
        declarations_valid = False
    for name in REQUIRED_IMPORTS:
        try:
            available = dependency_probe(name)
            importability.append((name, available is True))
        except Exception:
            importability.append((name, False))
    dependencies_ok = (
        declarations_valid
        and len(importability) == len(REQUIRED_IMPORTS)
        and all(available for _, available in importability)
    )
    dependency_gate = _gate(
        "chatbot.dependencies",
        "PASS" if dependencies_ok else "FAIL",
        "OK" if dependencies_ok else "CHATBOT_DEPENDENCY_MISSING",
        role="required",
        measurements=tuple(
            _measurement(f"{name}_importable", available)
            for name, available in importability
        ),
    )
    if not dependencies_ok:
        return _failure_after_dependencies(dependency_gate)

    spies = StartupSideEffectSpies()
    try:
        configuration = _load_configuration(configuration_path)
        validate_configuration_startup(configuration, StartupSideEffectSpies())
        _bounded_startup(
            startup_checker,
            configuration,
            spies,
            startup_timeout_seconds,
        )
        inventory = _normalize_inventory(audio_enumerator())
    except Exception:
        configuration_gate = _gate(
            "chatbot.configuration",
            "FAIL",
            "CHATBOT_CONFIG_INVALID",
            role="required",
            measurements=(
                _measurement(
                    "process_spawn_attempted",
                    "process_spawn" in spies.attempted_kinds,
                ),
                _measurement("network_attempted", "network" in spies.attempted_kinds),
                _measurement(
                    "microphone_attempted", "microphone" in spies.attempted_kinds
                ),
            ),
        )
        return _failure_after_configuration(dependency_gate, configuration_gate)

    configuration_gate = _gate(
        "chatbot.configuration",
        "PASS",
        "OK",
        role="required",
        measurements=(
            _measurement("process_spawn_attempted", False),
            _measurement("network_attempted", False),
            _measurement("microphone_attempted", False),
        ),
    )
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
