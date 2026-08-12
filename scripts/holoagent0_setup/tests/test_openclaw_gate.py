from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

import pytest

from holoagent0_setup.openclaw_gate import (
    CommandResult,
    LifecycleObservation,
    ListenerObservation,
    OpenClawGate,
    OpenClawGateError,
    OwnedProcess,
    ProcessObservation,
    ServiceObservation,
    SmokeRuntime,
    verify_owned_loopback_listener,
)


@dataclass
class FakeObserver:
    observations: list[LifecycleObservation]

    def observe(self) -> LifecycleObservation:
        return self.observations.pop(0)


class FakeRunner:
    def __init__(self, responses: list[CommandResult]) -> None:
        self.responses = responses
        self.commands: list[tuple[str, ...]] = []
        self.mutations: list[tuple[str, ...]] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        environment: dict[str, str],
        pass_fds: tuple[int, ...] = (),
    ):
        assert pass_fds == ()
        self.commands.append(command)
        if any(part in {"start", "restart", "install", "fix"} for part in command):
            self.mutations.append(command)
        return self.responses.pop(0)


EMPTY = LifecycleObservation(processes=(), services=(), listeners=())


def _success_responses() -> list[CommandResult]:
    return [
        CommandResult(0, json.dumps({"valid": True}), ""),
        CommandResult(0, json.dumps({"checksRun": 1, "findings": []}), ""),
        CommandResult(0, json.dumps({"checksRun": 4, "findings": []}), ""),
    ]


def test_preexisting_gateway_refuses_mutation():
    observer = FakeObserver(
        [
            LifecycleObservation(
                processes=(),
                services=(ServiceObservation("openclaw-gateway.service", "loaded"),),
                listeners=(),
            )
        ]
    )
    runner = FakeRunner([])
    gate = OpenClawGate(observer=observer, runner=runner)

    result = gate.preexisting(cli_path=None)

    assert result.status == "FAIL"
    assert result.reason == "PREEXISTING_OPENCLAW"
    assert runner.commands == []
    assert runner.mutations == []


def test_status_inspection_is_deep_no_probe_and_read_only():
    runner = FakeRunner(
        [
            CommandResult(
                0,
                '{"service":{"loaded":false,"runtime":{"status":"stopped"}}}',
                "",
            )
        ]
    )
    gate = OpenClawGate(observer=FakeObserver([EMPTY]), runner=runner)

    result = gate.preexisting(cli_path=Path("/isolated/bin/openclaw"))

    assert result.status == "PASS"
    assert runner.commands == [
        (
            "/isolated/bin/openclaw",
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        )
    ]
    assert runner.mutations == []


@pytest.mark.parametrize(
    "observation",
    [
        LifecycleObservation(
            processes=(ProcessObservation(17, 33, "/opt/openclaw/bin/node"),),
            services=(),
            listeners=(),
        ),
        LifecycleObservation(
            processes=(),
            services=(),
            listeners=(ListenerObservation("127.0.0.1", 18789, 17),),
        ),
    ],
)
def test_process_or_actual_listener_is_preexisting(observation):
    gate = OpenClawGate(observer=FakeObserver([observation]), runner=FakeRunner([]))
    assert gate.preexisting(cli_path=None).reason == "PREEXISTING_OPENCLAW"


def test_configuration_and_doctor_commands_are_exact_read_only(tmp_path):
    config = tmp_path / "openclaw.json"
    state = tmp_path / "state"
    runner = FakeRunner(_success_responses())
    gate = OpenClawGate(observer=FakeObserver([EMPTY, EMPTY]), runner=runner)

    result = gate.validate_read_only(
        cli_path=Path("/isolated/bin/openclaw"),
        config_path=config,
        state_dir=state,
        token="x" * 43,
    )

    assert result.status == "PASS"
    assert runner.commands == [
        ("/isolated/bin/openclaw", "config", "validate", "--json"),
        (
            "/isolated/bin/openclaw",
            "doctor",
            "--lint",
            "--only",
            "core/doctor/gateway-config",
            "--severity-min",
            "warning",
            "--json",
        ),
        (
            "/isolated/bin/openclaw",
            "doctor",
            "--lint",
            "--severity-min",
            "error",
            "--json",
        ),
    ]
    assert runner.mutations == []
    assert result.environment["OPENCLAW_CONFIG_PATH"] == str(config)
    assert result.environment["OPENCLAW_STATE_DIR"] == str(state)
    assert "OPENCLAW_GATEWAY_TOKEN" not in repr(result)


@pytest.mark.parametrize(
    ("responses", "reason"),
    [
        (
            [CommandResult(0, '{"valid":false}', "")],
            "OPENCLAW_CONFIG_INVALID",
        ),
        (
            [
                CommandResult(0, '{"valid":true}', ""),
                CommandResult(
                    0,
                    '{"checksRun":1,"findings":[{"severity":"warning"}]}',
                    "",
                ),
            ],
            "OPENCLAW_LINT_FINDING",
        ),
        (
            [
                CommandResult(0, '{"valid":true}', ""),
                CommandResult(0, '{"checksRun":1,"findings":[]}', ""),
                CommandResult(
                    0,
                    '{"checksRun":2,"findings":[{"severity":"error"}]}',
                    "",
                ),
            ],
            "OPENCLAW_LINT_FINDING",
        ),
    ],
)
def test_config_and_lint_thresholds_fail_closed(responses, reason, tmp_path):
    gate = OpenClawGate(
        observer=FakeObserver([EMPTY, EMPTY]), runner=FakeRunner(responses)
    )

    result = gate.validate_read_only(
        cli_path=Path("/isolated/bin/openclaw"),
        config_path=tmp_path / "openclaw.json",
        state_dir=tmp_path / "state",
        token="x" * 43,
    )

    assert result.status == "FAIL"
    assert result.reason == reason


def test_failed_validation_still_runs_postflight_with_safety_precedence(tmp_path):
    post = LifecycleObservation(
        processes=(),
        services=(),
        listeners=(ListenerObservation("127.0.0.1", 18789, 42),),
    )
    observer = FakeObserver([EMPTY, post])
    gate = OpenClawGate(
        observer=observer,
        runner=FakeRunner([CommandResult(0, '{"valid":false}', "")]),
    )

    result = gate.validate_read_only(
        cli_path=Path("/isolated/bin/openclaw"),
        config_path=tmp_path / "openclaw.json",
        state_dir=tmp_path / "state",
        token="x" * 43,
    )

    assert result.status == "FAIL"
    assert result.reason == "PREEXISTING_OPENCLAW"
    assert observer.observations == []


def test_postflight_new_listener_fails_read_only_lifecycle(tmp_path):
    post = LifecycleObservation(
        processes=(),
        services=(),
        listeners=(ListenerObservation("127.0.0.1", 18789, 42),),
    )
    gate = OpenClawGate(
        observer=FakeObserver([EMPTY, post]), runner=FakeRunner(_success_responses())
    )

    result = gate.validate_read_only(
        cli_path=Path("/isolated/bin/openclaw"),
        config_path=tmp_path / "openclaw.json",
        state_dir=tmp_path / "state",
        token="x" * 43,
    )

    assert result.status == "FAIL"
    assert result.reason == "PREEXISTING_OPENCLAW"


def test_smoke_listener_requires_actual_owned_loopback_socket():
    observed = LifecycleObservation(
        processes=(ProcessObservation(77, 99, "/isolated/node"),),
        services=(),
        listeners=(ListenerObservation("127.0.0.1", 18888, 77),),
    )
    verify_owned_loopback_listener(observed, pid=77, port=18888)

    with pytest.raises(OpenClawGateError, match="loopback"):
        verify_owned_loopback_listener(
            LifecycleObservation(
                processes=observed.processes,
                services=(),
                listeners=(ListenerObservation("0.0.0.0", 18888, 77),),
            ),
            pid=77,
            port=18888,
        )
    with pytest.raises(OpenClawGateError, match="ownership"):
        verify_owned_loopback_listener(observed, pid=78, port=18888)

    with pytest.raises(OpenClawGateError, match="loopback"):
        verify_owned_loopback_listener(
            LifecycleObservation(
                processes=observed.processes,
                services=(),
                listeners=(
                    ListenerObservation("127.0.0.1", 18888, 77),
                    ListenerObservation("0.0.0.0", 18889, 77),
                ),
            ),
            pid=77,
            port=18888,
        )


@pytest.mark.parametrize(
    "status",
    [
        {"service": {"loaded": True, "runtime": {"status": "stopped"}}},
        {"service": {"loaded": False, "runtime": {"status": "running"}}},
    ],
)
def test_status_json_claiming_loaded_or_running_gateway_is_preexisting(status):
    runner = FakeRunner([CommandResult(0, json.dumps(status), "")])
    gate = OpenClawGate(observer=FakeObserver([EMPTY]), runner=runner)

    assert gate.preexisting(Path("/isolated/bin/openclaw")).reason == (
        "PREEXISTING_OPENCLAW"
    )


@pytest.mark.parametrize(
    "status",
    [
        {"running": True},
        {"service": None},
        {"service": {"loaded": "false", "runtime": {"status": "stopped"}}},
        {"service": {"loaded": False, "runtime": {}}},
    ],
)
def test_preexisting_status_rejects_malformed_pinned_shape(status):
    runner = FakeRunner([CommandResult(0, json.dumps(status), "")])
    gate = OpenClawGate(observer=FakeObserver([EMPTY]), runner=runner)

    result = gate.preexisting(Path("/isolated/bin/openclaw"))

    assert result.status == "FAIL"


@pytest.mark.parametrize(
    "runtime_status",
    ["unknown", "inactive", "failed", "starting", "STOPPED"],
)
def test_preexisting_status_accepts_only_reviewed_inactive_state(runtime_status):
    runner = FakeRunner(
        [
            CommandResult(
                0,
                json.dumps(
                    {
                        "service": {
                            "loaded": False,
                            "runtime": {"status": runtime_status},
                        }
                    }
                ),
                "",
            )
        ]
    )
    gate = OpenClawGate(observer=FakeObserver([EMPTY]), runner=runner)

    result = gate.preexisting(Path("/isolated/bin/openclaw"))

    assert result.status == "FAIL"
    assert result.reason == "TOOL_RUNTIME_ERROR"
    assert result.reason == "TOOL_RUNTIME_ERROR"


class FakeSmokeProcess:
    def __init__(self, *, pid=77, pgid=77, start_time_ticks=99, executable="/cli"):
        self.identity = OwnedProcess(pid, pgid, start_time_ticks, executable)
        self.stops: list[OwnedProcess] = []
        self.waited = False

    def start(self, command, *, environment):
        self.command = command
        self.environment = dict(environment)
        return self.identity

    def stop(self, identity):
        self.stops.append(identity)


def test_smoke_runtime_uses_authenticated_loopback_and_finally_cleanup():
    owned = ProcessObservation(77, 99, "/cli")
    observer = FakeObserver(
        [
            EMPTY,
            LifecycleObservation(
                (owned,), (), (ListenerObservation("127.0.0.1", 18888, 77),)
            ),
            EMPTY,
        ]
    )
    runner = FakeRunner([CommandResult(9, "", "rpc failed")])
    process = FakeSmokeProcess()
    smoke = SmokeRuntime(observer=observer, runner=runner, processes=process)

    with pytest.raises(OpenClawGateError, match="smoke status"):
        smoke.run(
            cli_path=Path("/cli"),
            config_path=Path("/config"),
            state_dir=Path("/state"),
            token="x" * 43,
            port=18888,
        )

    assert process.command == (
        "/cli",
        "gateway",
        "run",
        "--bind",
        "loopback",
        "--port",
        "18888",
    )
    assert process.environment["OPENCLAW_GATEWAY_TOKEN"] == "x" * 43
    assert runner.commands == [
        ("/cli", "gateway", "status", "--deep", "--require-rpc", "--json")
    ]
    assert process.stops == [process.identity]


def test_smoke_runtime_success_requires_running_status_and_clean_postflight():
    owned = ProcessObservation(77, 99, "/cli")
    observer = FakeObserver(
        [
            EMPTY,
            LifecycleObservation(
                (owned,), (), (ListenerObservation("127.0.0.1", 18888, 77),)
            ),
            EMPTY,
        ]
    )
    process = FakeSmokeProcess()
    runner = FakeRunner(
        [
            CommandResult(
                0,
                json.dumps(
                    {
                        "service": {
                            "loaded": False,
                            "runtime": {"status": "stopped"},
                        },
                        "rpc": {"ok": True},
                    }
                ),
                "",
            )
        ]
    )

    SmokeRuntime(observer=observer, runner=runner, processes=process).run(
        cli_path=Path("/cli"),
        config_path=Path("/config"),
        state_dir=Path("/state"),
        token="x" * 43,
        port=18888,
    )

    assert process.stops == [process.identity]
    assert runner.commands[0][-3:] == ("--deep", "--require-rpc", "--json")


@pytest.mark.parametrize(
    "status",
    [
        {
            "service": {"loaded": True, "runtime": {"status": "running"}},
            "rpc": {"ok": False},
        },
        {"service": {"loaded": True, "runtime": {"status": "running"}}},
        {"running": True, "rpc": {"ok": True}},
    ],
)
def test_smoke_runtime_rejects_nonready_or_malformed_pinned_status(status):
    owned = ProcessObservation(77, 99, "/cli")
    observer = FakeObserver(
        [
            EMPTY,
            LifecycleObservation(
                (owned,), (), (ListenerObservation("127.0.0.1", 18888, 77),)
            ),
            EMPTY,
        ]
    )
    process = FakeSmokeProcess()
    smoke = SmokeRuntime(
        observer=observer,
        runner=FakeRunner([CommandResult(0, json.dumps(status), "")]),
        processes=process,
    )

    with pytest.raises(OpenClawGateError, match="smoke status"):
        smoke.run(
            cli_path=Path("/cli"),
            config_path=Path("/config"),
            state_dir=Path("/state"),
            token="x" * 43,
            port=18888,
        )

    assert process.stops == [process.identity]


def test_smoke_runtime_refuses_identity_changed_cleanup_as_safety_failure():
    process = FakeSmokeProcess()
    observer = FakeObserver(
        [
            EMPTY,
            LifecycleObservation(
                (ProcessObservation(77, 100, "/cli"),),
                (),
                (ListenerObservation("127.0.0.1", 18888, 77),),
            ),
            EMPTY,
        ]
    )
    smoke = SmokeRuntime(observer=observer, runner=FakeRunner([]), processes=process)

    with pytest.raises(OpenClawGateError, match="identity"):
        smoke.run(
            cli_path=Path("/cli"),
            config_path=Path("/config"),
            state_dir=Path("/state"),
            token="x" * 43,
            port=18888,
        )

    assert process.stops == [process.identity]
