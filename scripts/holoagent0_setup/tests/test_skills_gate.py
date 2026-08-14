from __future__ import annotations

from pathlib import Path

from holoagent0_setup.skills_gate import (
    EXPECTED_SKILLS,
    SkillCommandResult,
    run_skills_gates,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class FakeRunner:
    def __init__(self, results: list[SkillCommandResult] | None = None) -> None:
        self.commands: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []
        self._results = list(results or ())

    def run(self, command, *, environment, pass_fds=()):
        assert type(command) is tuple
        assert pass_fds == ()
        self.commands.append(command)
        self.environments.append(dict(environment))
        if self._results:
            return self._results.pop(0)
        if command[-1].endswith("validate_skills.py"):
            stdout = "HoloAgent skill validation passed.\n" + "".join(
                f"- {name}\n" for name in EXPECTED_SKILLS
            )
        elif command[-1].endswith("list_skills.py"):
            stdout = "HoloAgent skills:\n" + "".join(
                f"- {name}\n" for name in EXPECTED_SKILLS
            )
        else:
            stdout = "dry-run request only\n"
        return SkillCommandResult(0, stdout, "")


def _statuses(result):
    return [(gate["id"], gate["status"], gate["reason"]) for gate in result.gates]


def test_skills_gate_validates_all_five_and_only_executes_pinned_dry_runs():
    runner = FakeRunner()

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "PASS", "OK"),
        ("skills.dry_run", "PASS", "OK"),
    ]
    assert result.exit_code == 0
    assert len(runner.commands) == 6
    assert all(command[0] == "/usr/bin/python3.10" for command in runner.commands)
    assert all(command[1] == "-B" for command in runner.commands)
    assert runner.commands[0][-1].endswith("validate_skills.py")
    assert runner.commands[1][-1].endswith("list_skills.py")
    assert all("--dry-run" in command for command in runner.commands[2:])
    assert all(
        "-c" not in command and "--shell" not in command for command in runner.commands
    )
    assert all(
        environment == {"PATH": "/usr/bin:/bin"} for environment in runner.environments
    )
    assert all(gate["role"] == "required" for gate in result.gates)
    assert all(gate["log_paths"] == [] for gate in result.gates)
    assert "run_dameon" not in repr(runner.commands)
    assert "run_g1_background_daemon" not in repr(runner.commands)

    registry_measurements = {
        item["name"]: item["value"] for item in result.gates[0]["measurements"]
    }
    dry_run_measurements = {
        item["name"]: item["value"] for item in result.gates[1]["measurements"]
    }
    assert registry_measurements == {"validated_skill_count": 5}
    assert dry_run_measurements == {
        "dry_run_helper_count": 4,
        "side_effect_attempted": False,
        "remaining_process_group": False,
    }


def test_skills_gate_rejects_a_tracked_digest_mismatch_before_any_command():
    runner = FakeRunner()

    result = run_skills_gates(
        repository_root=REPOSITORY_ROOT,
        runner=runner,
        digest_reader=lambda _path: "0" * 64,
    )

    assert _statuses(result) == [
        ("skills.registry", "FAIL", "DIGEST_MISMATCH"),
        ("skills.dry_run", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1
    assert runner.commands == []


def test_skills_gate_rejects_registry_output_that_does_not_name_exact_five():
    runner = FakeRunner(
        [
            SkillCommandResult(0, "HoloAgent skill validation passed.\n", ""),
            SkillCommandResult(0, "HoloAgent skills:\n- arm-skill\n", ""),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "FAIL", "PLAN_INVALID"),
        ("skills.dry_run", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1
    assert len(runner.commands) == 2


def test_skills_gate_rejects_an_unreviewed_sixth_registry_entry():
    registry = "".join(f"- {name}\n" for name in (*EXPECTED_SKILLS, "rogue-skill"))
    runner = FakeRunner(
        [
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(0, registry, ""),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "FAIL", "PLAN_INVALID"),
        ("skills.dry_run", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1


def test_skills_gate_maps_dry_run_failure_without_persisting_child_output():
    secret = "credential-shaped-value-must-not-escape"
    registry = "".join(f"- {name}\n" for name in EXPECTED_SKILLS)
    runner = FakeRunner(
        [
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(3, secret, secret),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "PASS", "OK"),
        ("skills.dry_run", "FAIL", "TOOL_RUNTIME_ERROR"),
    ]
    assert result.exit_code == 1
    assert secret not in repr(result)


def test_skills_gate_fails_closed_on_any_reported_side_effect_attempt():
    registry = "".join(f"- {name}\n" for name in EXPECTED_SKILLS)
    runner = FakeRunner(
        [
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(
                0,
                "dry-run request only",
                "",
                side_effect_attempted=True,
            ),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "PASS", "OK"),
        ("skills.dry_run", "FAIL", "OFFLINE_SIDE_EFFECT_ATTEMPT"),
    ]
    assert result.exit_code == 1


def test_skills_gate_rejects_a_remaining_command_process_group():
    registry = "".join(f"- {name}\n" for name in EXPECTED_SKILLS)
    runner = FakeRunner(
        [
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(0, registry, ""),
            SkillCommandResult(
                0,
                "dry-run request only",
                "",
                remaining_process_group=True,
            ),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result)[-1] == (
        "skills.dry_run",
        "FAIL",
        "OFFLINE_SIDE_EFFECT_ATTEMPT",
    )
    assert result.exit_code == 1
