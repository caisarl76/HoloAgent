from __future__ import annotations

import builtins
import _thread
import importlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from types import ModuleType

import pytest

import holoagent0_setup.chatbot_gate as chatbot_gate

from holoagent0_setup.chatbot_gate import (
    OfflineStartupSideEffectAttempt,
    REQUIRED_IMPORTS,
    REQUIRED_PROVIDER_VARIABLES,
    classify_external_readiness,
    enumerate_audio_devices,
    run_chatbot_gates,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CHATBOT_ROOT = REPOSITORY_ROOT / "agentic_robot/chatbot/g1"
PYPROJECT = CHATBOT_ROOT / "pyproject.toml"
CONFIG = CHATBOT_ROOT / "g1.json"


def test_chatbot_gate_import_does_not_require_agentos_or_yaml(monkeypatch):
    module_name = "holoagent0_setup.chatbot_gate"
    loaded = sys.modules.pop(module_name)
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "yaml" or name.endswith("agentos_gate"):
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    try:
        reloaded = importlib.import_module(module_name)
        assert reloaded.REQUIRED_IMPORTS == REQUIRED_IMPORTS
    finally:
        sys.modules[module_name] = loaded


@pytest.mark.parametrize("install_mode", ["no_op", "veto"])
def test_chatbot_guard_requires_audited_installation_acknowledgement(install_mode):
    package_root = str(Path(chatbot_gate.__file__).resolve().parents[1])
    script = """
import sys
sys.path.insert(0, sys.argv[1])
from holoagent0_setup.chatbot_gate import _PythonOfflineSideEffectGuard

if sys.argv[2] == "no_op":
    sys.addaudithook = lambda _hook: None
else:
    def veto(_hook):
        raise RuntimeError("vetoed")
    sys.addaudithook = veto

try:
    with _PythonOfflineSideEffectGuard():
        pass
except RuntimeError:
    raise SystemExit(0)
raise SystemExit(9)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, package_root, install_mode],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0


def test_chatbot_guard_supports_repeated_distinct_instances():
    with chatbot_gate.ChatbotOfflineSideEffectGuard():
        pass
    with chatbot_gate.ChatbotOfflineSideEffectGuard():
        pass


def test_chatbot_guard_instance_is_explicitly_single_use():
    guard = chatbot_gate.ChatbotOfflineSideEffectGuard()

    with guard:
        pass

    with pytest.raises(RuntimeError, match="single-use"):
        with guard:
            pass


def test_chatbot_deadline_restores_handler_when_timer_activation_fails(monkeypatch):
    previous_handler = object()
    handler_calls = []
    timer_calls = []

    monkeypatch.setattr(signal, "getitimer", lambda _which: (0.0, 0.0))
    monkeypatch.setattr(signal, "getsignal", lambda _signum: previous_handler)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda signum, handler: handler_calls.append((signum, handler)),
    )

    def setitimer(which, delay):
        timer_calls.append((which, delay))
        if delay:
            raise RuntimeError("activation failed")

    monkeypatch.setattr(signal, "setitimer", setitimer)

    with pytest.raises(RuntimeError, match="activation failed"):
        with chatbot_gate._WholeReadinessDeadline(1.0):
            pass

    assert timer_calls == [(signal.ITIMER_REAL, 1.0), (signal.ITIMER_REAL, 0.0)]
    assert handler_calls[-1] == (signal.SIGALRM, previous_handler)


def test_chatbot_deadline_restores_handler_when_timer_cancellation_fails(
    monkeypatch,
):
    previous_handler = object()
    handler_calls = []

    monkeypatch.setattr(signal, "getitimer", lambda _which: (0.0, 0.0))
    monkeypatch.setattr(signal, "getsignal", lambda _signum: previous_handler)
    monkeypatch.setattr(
        signal,
        "signal",
        lambda signum, handler: handler_calls.append((signum, handler)),
    )

    def setitimer(_which, delay):
        if not delay:
            raise RuntimeError("cancellation failed")

    monkeypatch.setattr(signal, "setitimer", setitimer)

    with pytest.raises(RuntimeError, match="cancellation failed"):
        with chatbot_gate._WholeReadinessDeadline(1.0):
            pass

    assert handler_calls[-1] == (signal.SIGALRM, previous_handler)


class DependencyProbe:
    def __init__(self, missing: tuple[str, ...] = ()) -> None:
        self.missing = set(missing)
        self.queries: list[str] = []

    def __call__(self, name: str) -> bool:
        self.queries.append(name)
        return name not in self.missing


def _devices(*, audio: bool):
    if not audio:
        return ()
    return (
        {"name": "private input", "maxInputChannels": 1, "maxOutputChannels": 0},
        {"name": "private output", "maxInputChannels": 0, "maxOutputChannels": 2},
    )


def _statuses(result):
    return [(gate["id"], gate["status"], gate["reason"]) for gate in result.gates]


def _configuration_measurements(result):
    return {row["name"]: row["value"] for row in result.gates[1]["measurements"]}


@pytest.mark.parametrize(
    ("credentials", "audio", "label", "exit_code"),
    [
        (True, True, "PASS_HOLOAGENT0_OFFLINE", 0),
        (False, True, "READY_CREDENTIALS_REQUIRED", 10),
        (True, False, "READY_AUDIO_HARDWARE_REQUIRED", 10),
        (False, False, "READY_CREDENTIALS_AND_AUDIO_REQUIRED", 10),
    ],
)
def test_chatbot_qualification_matrix(credentials, audio, label, exit_code):
    result = classify_external_readiness(credentials=credentials, audio=audio)

    assert (result.label, result.exit_code) == (label, exit_code)


@pytest.mark.parametrize(
    ("credentials", "audio", "expected_statuses", "label", "exit_code"),
    [
        (
            True,
            True,
            [
                ("chatbot.credentials", "PASS", "OK"),
                ("chatbot.audio_hardware", "PASS", "OK"),
            ],
            "PASS_HOLOAGENT0_OFFLINE",
            0,
        ),
        (
            False,
            True,
            [
                ("chatbot.credentials", "QUALIFIED", "CREDENTIALS_MISSING"),
                ("chatbot.audio_hardware", "PASS", "OK"),
            ],
            "READY_CREDENTIALS_REQUIRED",
            10,
        ),
        (
            True,
            False,
            [
                ("chatbot.credentials", "PASS", "OK"),
                ("chatbot.audio_hardware", "QUALIFIED", "AUDIO_HARDWARE_MISSING"),
            ],
            "READY_AUDIO_HARDWARE_REQUIRED",
            10,
        ),
        (
            False,
            False,
            [
                ("chatbot.credentials", "QUALIFIED", "CREDENTIALS_MISSING"),
                ("chatbot.audio_hardware", "QUALIFIED", "AUDIO_HARDWARE_MISSING"),
            ],
            "READY_CREDENTIALS_AND_AUDIO_REQUIRED",
            10,
        ),
    ],
)
def test_chatbot_gates_apply_qualification_matrix_without_leaking_values(
    credentials, audio, expected_statuses, label, exit_code
):
    sentinel = "provider-secret-must-never-enter-evidence"
    environment = (
        {name: sentinel for name in REQUIRED_PROVIDER_VARIABLES} if credentials else {}
    )
    probe = DependencyProbe()
    startup_calls = []

    def startup_checker(configuration, spies):
        assert configuration["audio_device"]["channels"] == 1
        assert spies.attempted_kinds == ()
        startup_calls.append(True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: _devices(audio=audio),
        startup_checker=startup_checker,
        environment=environment,
    )

    assert _statuses(result)[:2] == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "PASS", "OK"),
    ]
    assert _statuses(result)[2:] == expected_statuses
    assert (result.label, result.exit_code) == (label, exit_code)
    assert probe.queries == list(REQUIRED_IMPORTS)
    assert startup_calls == [True]
    assert sentinel not in repr(result)
    assert all(gate["log_paths"] == [] for gate in result.gates)
    assert [gate["role"] for gate in result.gates] == [
        "required",
        "required",
        "qualification",
        "qualification",
    ]

    credentials_measurements = result.gates[2]["measurements"]
    assert [row["name"] for row in credentials_measurements] == [
        f"{name}_present" for name in REQUIRED_PROVIDER_VARIABLES
    ]
    assert all(row["value"] is credentials for row in credentials_measurements)
    assert all(sentinel not in repr(row) for row in credentials_measurements)


def test_chatbot_dependency_failure_is_blocking_and_queries_exact_five_modules():
    probe = DependencyProbe(("pyaudio",))
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "FAIL", "CHATBOT_DEPENDENCY_MISSING"),
        ("chatbot.configuration", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert probe.queries == list(REQUIRED_IMPORTS)
    assert calls == []


def test_chatbot_dependency_probe_exception_is_redacted_and_does_not_skip_queries():
    secret = "dependency-probe-secret-must-not-escape"
    queries = []

    def probe(name):
        queries.append(name)
        if name == "pyaudio":
            raise RuntimeError(secret)
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert result.label == "FAIL_CHATBOT"
    assert queries == list(REQUIRED_IMPORTS)
    assert secret not in repr(result)


def test_chatbot_dependency_probe_is_bounded_and_attributed_to_dependencies():
    calls = []

    def blocked_probe(name):
        calls.append(name)
        time.sleep(0.05)
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=blocked_probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
        startup_timeout_seconds=0.01,
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == [REQUIRED_IMPORTS[0]]


def test_chatbot_uses_one_deadline_across_dependencies_and_startup():
    first_probe = True

    def slow_probe(_name):
        nonlocal first_probe
        if first_probe:
            first_probe = False
            time.sleep(0.1)
        return True

    def slow_startup(_configuration, _spies):
        time.sleep(0.1)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=slow_probe,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=slow_startup,
        environment={},
        startup_timeout_seconds=0.15,
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"


def test_chatbot_audio_enumerator_is_bounded_as_configuration():
    def blocked_audio():
        time.sleep(0.05)
        return _devices(audio=True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=blocked_audio,
        startup_checker=lambda *_args: None,
        environment={},
        startup_timeout_seconds=0.01,
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"


@pytest.mark.parametrize("invalid_bound", [0.0, -1.0, 31.0, 1])
def test_chatbot_rejects_invalid_whole_readiness_bounds_before_callbacks(
    invalid_bound,
):
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=lambda name: calls.append(name) or True,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
        startup_timeout_seconds=invalid_bound,
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == []


def test_chatbot_rejects_oversized_pyproject_before_dependency_probe(tmp_path):
    oversized = tmp_path / "pyproject.toml"
    oversized.write_text(
        PYPROJECT.read_text(encoding="utf-8") + "\n#" + "x" * 70_000,
        encoding="utf-8",
    )
    calls = []

    result = run_chatbot_gates(
        pyproject_path=oversized,
        configuration_path=CONFIG,
        dependency_probe=lambda name: calls.append(name) or True,
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert _statuses(result)[0] == (
        "chatbot.dependencies",
        "FAIL",
        "CHATBOT_DEPENDENCY_MISSING",
    )
    assert calls == []


def test_chatbot_rejects_oversized_json_before_startup_or_audio(tmp_path):
    oversized = tmp_path / "g1.json"
    oversized.write_bytes(CONFIG.read_bytes() + b" " * 70_000)
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=oversized,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"
    assert calls == []


def test_chatbot_hostile_environment_mapping_cannot_leak_a_credential_value():
    secret = "environment-secret-must-not-escape"

    class HostileEnvironment(dict):
        def __contains__(self, _key):
            raise RuntimeError(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=HostileEnvironment(),
    )

    assert result.label == "READY_CREDENTIALS_REQUIRED"
    assert secret not in repr(result)


@pytest.mark.parametrize("attempt", ["process", "network"])
def test_chatbot_rechecks_guard_after_hostile_credential_mapping(attempt):
    secret = "hostile-credential-side-effect-secret-must-not-escape"
    cached_popen = subprocess.Popen
    cached_socket = socket.socket

    class HostileEnvironment(dict):
        attempted = False

        def __contains__(self, _key):
            if not self.attempted:
                self.attempted = True
                try:
                    if attempt == "process":
                        cached_popen([secret])
                    else:
                        cached_socket(socket.AF_INET, socket.SOCK_STREAM).close()
                except OfflineStartupSideEffectAttempt:
                    pass
            return True

        def __getitem__(self, _key):
            return secret

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=HostileEnvironment(),
    )

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    evidence = _configuration_measurements(result)
    evidence_name = (
        "process_spawn_attempted" if attempt == "process" else "network_attempted"
    )
    assert evidence[evidence_name] is True
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        " \t\n",
        "x",
        "xxxx",
        "  XxXx  ",
        "placeholder",
        "PlaceHolder",
        "changeme",
        "ChangeMe",
    ],
)
def test_chatbot_credentials_reject_short_and_closed_placeholder_values(
    invalid_value,
):
    valid_secret = "valid-provider-secret-must-not-enter-evidence"
    environment = {name: valid_secret for name in REQUIRED_PROVIDER_VARIABLES}
    environment[REQUIRED_PROVIDER_VARIABLES[2]] = invalid_value

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    measurements = result.gates[2]["measurements"]
    assert _statuses(result)[2] == (
        "chatbot.credentials",
        "QUALIFIED",
        "CREDENTIALS_MISSING",
    )
    assert (result.label, result.exit_code) == (
        "READY_CREDENTIALS_REQUIRED",
        10,
    )
    assert [row["value"] for row in measurements] == [True, True, False, True, True]
    assert all(type(row["value"]) is bool for row in measurements)
    assert valid_secret not in repr(result)


def test_chatbot_credentials_accept_five_valid_non_placeholder_values():
    values = (
        "real-key",
        "replace-me",
        "your-key-here",
        "abcd",
        "placeholder-real",
    )
    environment = dict(zip(REQUIRED_PROVIDER_VARIABLES, values, strict=True))

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    assert _statuses(result)[2] == ("chatbot.credentials", "PASS", "OK")
    assert (result.label, result.exit_code) == ("PASS_HOLOAGENT0_OFFLINE", 0)
    assert all(value not in repr(result) for value in values)


def test_chatbot_credentials_report_only_presence_with_one_missing_variable():
    secret = "partial-provider-secret-must-not-enter-evidence"
    environment = {name: secret for name in REQUIRED_PROVIDER_VARIABLES}
    del environment[REQUIRED_PROVIDER_VARIABLES[2]]

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment=environment,
    )

    measurements = result.gates[2]["measurements"]
    assert [row["value"] for row in measurements] == [
        True,
        True,
        False,
        True,
        True,
    ]
    assert (result.label, result.exit_code) == (
        "READY_CREDENTIALS_REQUIRED",
        10,
    )
    assert secret not in repr(result)


def test_chatbot_invalid_json_is_blocking_and_never_reaches_startup_or_audio(tmp_path):
    invalid = tmp_path / "g1.json"
    invalid.write_text('{"audio_device":', encoding="utf-8")
    calls = []

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=invalid,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert calls == []


@pytest.mark.parametrize("attempt", ["process_spawn", "network", "microphone"])
def test_chatbot_configuration_startup_fails_closed_on_side_effect_spy(attempt):
    secret = "secret exception text must not escape"

    def startup_checker(_configuration, spies):
        getattr(spies, attempt)(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": False,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


def test_chatbot_guard_blocks_and_records_cached_subprocess_constructor():
    secret = "/definitely-missing-provider-secret"
    cached_popen = subprocess.Popen

    def startup_checker(_configuration, _spies):
        cached_popen([secret])

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["process_spawn_attempted"] is True
    assert secret not in repr(result)


def test_chatbot_guard_blocks_and_records_direct_socket_operation():
    secret = "socket-secret-must-not-escape"

    def startup_checker(_configuration, _spies):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["network_attempted"] is True
    assert secret not in repr(result)


def test_chatbot_guard_blocks_loaded_pyaudio_stream_open(monkeypatch):
    secret = "microphone-secret-must-not-escape"
    opened = []
    pyaudio_module = ModuleType("pyaudio")

    class FakePyAudio:
        def open(self, *_args, **_kwargs):
            opened.append(True)

    pyaudio_module.PyAudio = FakePyAudio
    monkeypatch.setitem(sys.modules, "pyaudio", pyaudio_module)

    def startup_checker(_configuration, _spies):
        pyaudio_module.PyAudio().open(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["microphone_attempted"] is True
    assert opened == []
    assert secret not in repr(result)


def test_chatbot_guard_blocks_loaded_audio_device_stream_method(monkeypatch):
    secret = "audio-device-secret-must-not-escape"
    started = []
    audio_device_module = ModuleType("chatbot.audio.audio_device")

    class FakeAudioDevice:
        def start_streams(self, *_args, **_kwargs):
            started.append(True)

    audio_device_module.AudioDevice = FakeAudioDevice
    monkeypatch.setitem(sys.modules, "chatbot.audio.audio_device", audio_device_module)

    def startup_checker(_configuration, _spies):
        audio_device_module.AudioDevice().start_streams(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert _configuration_measurements(result)["microphone_attempted"] is True
    assert started == []
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("operation", "expected_measurement"),
    [
        ("cached_process", "process_spawn_attempted"),
        ("direct_socket", "network_attempted"),
    ],
)
def test_chatbot_guard_classifies_dependency_side_effect_as_configuration_failure(
    operation, expected_measurement
):
    secret = "/definitely-missing-dependency-provider-secret"
    cached_popen = subprocess.Popen
    calls = []

    def dependency_probe(name):
        calls.append(name)
        if operation == "cached_process":
            cached_popen([secret])
        else:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()
        return True

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=dependency_probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.gates[0]["measurements"] == [
        {"name": f"{name}_importable", "value": True, "unit": None}
        for name in REQUIRED_IMPORTS
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": expected_measurement == "process_spawn_attempted",
        "network_attempted": expected_measurement == "network_attempted",
        "microphone_attempted": False,
    }
    assert (result.label, result.exit_code) == ("FAIL_CHATBOT", 1)
    assert calls == [REQUIRED_IMPORTS[0]]
    assert secret not in repr(result)


def test_chatbot_guard_detects_dependency_side_effect_even_when_probe_catches_it():
    secret = "/definitely-missing-caught-provider-secret"
    cached_popen = subprocess.Popen
    calls = []

    def dependency_probe(name):
        calls.append(name)
        try:
            cached_popen([secret])
        except Exception:
            return True
        raise AssertionError("guarded process constructor did not raise")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=dependency_probe,
        audio_enumerator=lambda: calls.append("audio"),
        startup_checker=lambda *_args: calls.append("startup"),
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result)[:2] == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
    ]
    assert all(row["value"] is True for row in result.gates[0]["measurements"])
    assert _configuration_measurements(result)["process_spawn_attempted"] is True
    assert calls == [REQUIRED_IMPORTS[0]]
    assert secret not in repr(result)


@pytest.mark.parametrize("import_style", ["standard", "importlib", "cached"])
@pytest.mark.parametrize("module_kind", ["pyaudio", "audio_device"])
def test_chatbot_guard_blocks_late_imported_audio_stream_entry_points(
    tmp_path, monkeypatch, request, import_style, module_kind
):
    secret = "late-audio-provider-secret-must-not-escape"
    if module_kind == "pyaudio":
        module_name = "pyaudio"
        module_path = tmp_path / "pyaudio.py"
        side_effect_name = "OPENED"
        module_path.write_text(
            "OPENED = []\n"
            "class PyAudio:\n"
            "    def open(self, *_args, **_kwargs):\n"
            "        OPENED.append(True)\n",
            encoding="utf-8",
        )
    else:
        package = tmp_path / "fixture_chatbot_audio"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        module_name = "fixture_chatbot_audio.audio_device"
        module_path = package / "audio_device.py"
        side_effect_name = "STARTED"
        module_path.write_text(
            "STARTED = []\n"
            "class AudioDevice:\n"
            "    def start_streams(self, *_args, **_kwargs):\n"
            "        STARTED.append(True)\n",
            encoding="utf-8",
        )
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, module_name, raising=False)
    request.addfinalizer(lambda: sys.modules.pop(module_name, None))
    if module_kind == "audio_device":
        request.addfinalizer(lambda: sys.modules.pop("fixture_chatbot_audio", None))
    cached_importer = importlib.import_module

    def startup_checker(_configuration, _spies):
        if import_style == "standard":
            module = builtins.__import__(module_name, fromlist=("*",))
        elif import_style == "importlib":
            module = importlib.import_module(module_name)
        else:
            module = cached_importer(module_name)
        if module_kind == "pyaudio":
            module.PyAudio().open(secret)
        else:
            module.AudioDevice().start_streams(secret)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    measurements = _configuration_measurements(result)
    imported = sys.modules[module_name]
    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert measurements == {
        "process_spawn_attempted": False,
        "network_attempted": False,
        "microphone_attempted": True,
    }
    assert getattr(imported, side_effect_name) == []
    assert secret not in repr(result)


@pytest.mark.parametrize(
    ("operation", "expected_measurement"),
    [
        ("cached_process", "process_spawn_attempted"),
        ("cached_socket", "network_attempted"),
        ("late_microphone", "microphone_attempted"),
    ],
)
def test_chatbot_configuration_fails_when_startup_catches_real_guard_attempt(
    tmp_path, monkeypatch, request, operation, expected_measurement
):
    secret = "/definitely-missing-caught-startup-secret"
    cached_popen = subprocess.Popen
    cached_socket = socket.socket
    audio_calls = []
    opened = []
    if operation == "late_microphone":
        module_path = tmp_path / "pyaudio.py"
        module_path.write_text(
            "OPENED = []\n"
            "class PyAudio:\n"
            "    def open(self, *_args, **_kwargs):\n"
            "        OPENED.append(True)\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))
        monkeypatch.delitem(sys.modules, "pyaudio", raising=False)
        request.addfinalizer(lambda: sys.modules.pop("pyaudio", None))

    def startup_checker(_configuration, _spies):
        try:
            if operation == "cached_process":
                cached_popen([secret])
            elif operation == "cached_socket":
                cached_socket(socket.AF_INET, socket.SOCK_STREAM).close()
            else:
                module = importlib.import_module("pyaudio")
                opened.append(module)
                module.PyAudio().open(secret)
        except OfflineStartupSideEffectAttempt:
            return
        raise AssertionError("guarded startup operation did not raise")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: audio_calls.append(True) or _devices(audio=True),
        startup_checker=startup_checker,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": expected_measurement == "process_spawn_attempted",
        "network_attempted": expected_measurement == "network_attempted",
        "microphone_attempted": expected_measurement == "microphone_attempted",
    }
    assert audio_calls == []
    if opened:
        assert opened[0].OPENED == []
    assert secret not in repr(result)


def test_chatbot_configuration_fails_when_audio_inventory_catches_guard_attempt():
    secret = "/definitely-missing-caught-audio-secret"
    cached_popen = subprocess.Popen
    process_returned = []

    def audio_enumerator():
        try:
            cached_popen([secret])
        except OfflineStartupSideEffectAttempt:
            return _devices(audio=True)
        process_returned.append(True)
        return _devices(audio=True)

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=CONFIG,
        dependency_probe=DependencyProbe(),
        audio_enumerator=audio_enumerator,
        startup_checker=lambda *_args: None,
        environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
    )

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert process_returned == []
    assert secret not in repr(result)


def test_chatbot_guard_rejects_cached_waiting_worker_escape_and_cleans_fixture():
    secret = "waiting-worker-secret-must-not-escape"
    cached_start = _thread.start_new_thread
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    def wait_worker():
        try:
            started.set()
            release.wait(2.0)
        finally:
            finished.set()

    def startup_checker(_configuration, _spies):
        cached_start(wait_worker, ())
        assert started.wait(1.0)

    try:
        result = run_chatbot_gates(
            pyproject_path=PYPROJECT,
            configuration_path=CONFIG,
            dependency_probe=DependencyProbe(),
            audio_enumerator=lambda: _devices(audio=True),
            startup_checker=startup_checker,
            environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
        )
    finally:
        release.set()
        assert finished.wait(2.0)

    assert _statuses(result) == [
        ("chatbot.dependencies", "PASS", "OK"),
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


@pytest.mark.parametrize(
    "thread_entry",
    ["thread_start", "threading_start_new", "low_level_start_new"],
)
def test_chatbot_configuration_fails_when_startup_catches_thread_attempt(
    thread_entry,
):
    secret = "caught-thread-secret-must-not-escape"
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    worker = None

    def wait_worker():
        try:
            started.set()
            release.wait(2.0)
        finally:
            finished.set()

    def startup_checker(_configuration, _spies):
        nonlocal worker
        try:
            if thread_entry == "thread_start":
                worker = threading.Thread(target=wait_worker, daemon=True)
                worker.start()
            elif thread_entry == "threading_start_new":
                threading._start_new_thread(wait_worker, ())
            else:
                _thread.start_new_thread(wait_worker, ())
        except OfflineStartupSideEffectAttempt:
            return
        assert started.wait(1.0)

    try:
        result = run_chatbot_gates(
            pyproject_path=PYPROJECT,
            configuration_path=CONFIG,
            dependency_probe=DependencyProbe(),
            audio_enumerator=lambda: _devices(audio=True),
            startup_checker=startup_checker,
            environment={name: secret for name in REQUIRED_PROVIDER_VARIABLES},
        )
    finally:
        release.set()
        if worker is not None and worker.ident is not None:
            worker.join(timeout=2.0)
        elif started.is_set():
            finished.wait(2.0)

    assert _statuses(result)[1:] == [
        ("chatbot.configuration", "FAIL", "CHATBOT_CONFIG_INVALID"),
        ("chatbot.credentials", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
        ("chatbot.audio_hardware", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert _configuration_measurements(result) == {
        "process_spawn_attempted": True,
        "network_attempted": False,
        "microphone_attempted": False,
    }
    assert secret not in repr(result)


def test_audio_inventory_never_opens_a_stream_and_records_no_device_names():
    calls = []

    class FakeAudio:
        def get_device_count(self):
            return 2

        def get_device_info_by_index(self, index):
            return (
                {
                    "name": "sensitive microphone name",
                    "maxInputChannels": 1,
                    "maxOutputChannels": 0,
                },
                {
                    "name": "sensitive speaker name",
                    "maxInputChannels": 0,
                    "maxOutputChannels": 2,
                },
            )[index]

        def open(self, *_args, **_kwargs):
            raise AssertionError("offline inventory must never open a stream")

        def terminate(self):
            calls.append("terminate")

    class FakePyAudioModule:
        @staticmethod
        def PyAudio():
            calls.append("construct")
            return FakeAudio()

    inventory = enumerate_audio_devices(FakePyAudioModule())

    assert inventory.input_count == 1
    assert inventory.output_count == 1
    assert repr(inventory) == "AudioInventory(input_count=1, output_count=1)"
    assert calls == ["construct", "terminate"]


def test_chatbot_rejects_structurally_incomplete_configuration(tmp_path):
    invalid = tmp_path / "g1.json"
    invalid.write_text(json.dumps({"audio_device": {}}), encoding="utf-8")

    result = run_chatbot_gates(
        pyproject_path=PYPROJECT,
        configuration_path=invalid,
        dependency_probe=DependencyProbe(),
        audio_enumerator=lambda: _devices(audio=True),
        startup_checker=lambda *_args: None,
        environment={},
    )

    assert _statuses(result)[1] == (
        "chatbot.configuration",
        "FAIL",
        "CHATBOT_CONFIG_INVALID",
    )
    assert result.label == "FAIL_CHATBOT"
