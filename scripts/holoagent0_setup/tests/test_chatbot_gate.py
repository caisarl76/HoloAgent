from __future__ import annotations

import json
from pathlib import Path

import pytest

from holoagent0_setup.chatbot_gate import (
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
