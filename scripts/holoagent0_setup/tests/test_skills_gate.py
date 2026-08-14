from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from holoagent0_setup.openclaw_gate import LocalCommandRunner
import holoagent0_setup.skills_gate as skills_gate
from holoagent0_setup.skills_gate import (
    EXPECTED_SKILLS,
    PYTHON_EXECUTABLE,
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
        assert len(pass_fds) == 1
        assert command[3] == f"/proc/self/fd/{pass_fds[0]}"
        os.fstat(pass_fds[0])
        self.commands.append(command)
        self.environments.append(dict(environment))
        if self._results:
            return self._results.pop(0)
        if len(self.commands) == 1:
            stdout = _validator_output()
        elif len(self.commands) == 2:
            stdout = _list_output()
        else:
            stdout = "dry-run request only\n"
        return SkillCommandResult(0, stdout, "")


def _statuses(result):
    return [(gate["id"], gate["status"], gate["reason"]) for gate in result.gates]


def _validator_output():
    return (
        "HoloAgent skill validation passed.\n"
        + "".join(f"- {name}\n" for name in EXPECTED_SKILLS)
        + "\nWarnings:\n- workflow: missing recommended directory scripts/\n"
    )


def _list_output(inventory=EXPECTED_SKILLS):
    return "HoloAgent skills:\n" + "".join(
        f"- {name}\n  readme: yes\n" for name in inventory
    )


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
    assert all(command[1:3] == ("-I", "-B") for command in runner.commands)
    assert all(command[3].startswith("/proc/self/fd/") for command in runner.commands)
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
    assert dry_run_measurements == {"dry_run_helper_count": 4}


def test_skills_gate_real_default_runner_omits_unavailable_negative_telemetry():
    result = run_skills_gates(repository_root=REPOSITORY_ROOT)

    assert _statuses(result) == [
        ("skills.registry", "PASS", "OK"),
        ("skills.dry_run", "PASS", "OK"),
    ]
    assert result.gates[1]["measurements"] == [
        {"name": "dry_run_helper_count", "value": 4, "unit": None}
    ]


def _direct_command(script: Path, *arguments: str) -> tuple[str, ...]:
    return (str(PYTHON_EXECUTABLE), "-I", "-B", str(script), *arguments)


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def test_verified_skill_descriptor_survives_a_path_swap(tmp_path):
    script = tmp_path / "reviewed.py"
    replacement = tmp_path / "replacement.py"
    reviewed_content = b'print("reviewed-bytes")\n'
    script.write_bytes(reviewed_content)
    replacement.write_text('print("replacement-bytes")\n', encoding="utf-8")

    class SwapThenRun:
        def run(self, command, *, environment, pass_fds=()):
            replacement.replace(script)
            return LocalCommandRunner(timeout_seconds=2.0).run(
                command,
                environment=environment,
                pass_fds=pass_fds,
            )

    result = skills_gate._run_command(
        SwapThenRun(),
        _direct_command(script),
        expected_script_digest=_digest(reviewed_content),
    )

    assert result.exit_code == 0
    assert result.stdout == "reviewed-bytes\n"


def test_verified_skill_descriptor_rejects_a_symlink(tmp_path):
    target = tmp_path / "target.py"
    link = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    target.write_bytes(content)
    link.symlink_to(target)

    with pytest.raises(OSError):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(link),
            expected_script_digest=_digest(content),
        )


def test_verified_skill_descriptor_is_closed_when_runner_raises(tmp_path):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed")\n'
    script.write_bytes(content)
    passed_descriptor = None

    class RaisingRunner:
        def run(self, _command, *, environment, pass_fds=()):
            nonlocal passed_descriptor
            passed_descriptor = pass_fds[0]
            raise RuntimeError("runner failed")

    with pytest.raises(RuntimeError, match="runner failed"):
        skills_gate._run_command(
            RaisingRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    assert passed_descriptor is not None
    with pytest.raises(OSError):
        os.fstat(passed_descriptor)


def test_isolated_skill_command_ignores_injected_user_site(tmp_path):
    script = tmp_path / "reviewed.py"
    content = b"""\
try:
    import holoagent0_user_site_probe
except ModuleNotFoundError:
    print("isolated")
else:
    print("injected")
"""
    script.write_bytes(content)
    user_base = tmp_path / "user-base"
    user_site = user_base / "lib/python3.10/site-packages"
    user_site.mkdir(parents=True)
    (user_site / "holoagent0_user_site_probe.py").write_text(
        "INJECTED = True\n", encoding="utf-8"
    )

    class InjectedUserSiteRunner:
        def run(self, command, *, environment, pass_fds=()):
            process_environment = {
                **environment,
                "PYTHONUSERBASE": str(user_base),
            }
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=process_environment,
                pass_fds=pass_fds,
            )
            return SkillCommandResult(
                completed.returncode,
                completed.stdout,
                completed.stderr,
            )

    result = skills_gate._run_command(
        InjectedUserSiteRunner(),
        _direct_command(script),
        expected_script_digest=_digest(content),
    )

    assert result.exit_code == 0
    assert result.stdout == "isolated\n"


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
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(0, _list_output(("arm-skill",)), ""),
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
    runner = FakeRunner(
        [
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(
                0,
                _list_output((*EXPECTED_SKILLS, "rogue-skill")),
                "",
            ),
        ]
    )

    result = run_skills_gates(repository_root=REPOSITORY_ROOT, runner=runner)

    assert _statuses(result) == [
        ("skills.registry", "FAIL", "PLAN_INVALID"),
        ("skills.dry_run", "NOT_RUN", "EARLIER_BLOCKING_GATE"),
    ]
    assert result.exit_code == 1


@pytest.mark.parametrize(
    "inventory",
    [
        (*EXPECTED_SKILLS, "unexpected_skill"),
        (*EXPECTED_SKILLS, "Unexpected-Skill"),
        (*EXPECTED_SKILLS, EXPECTED_SKILLS[-1]),
    ],
)
def test_skills_gate_rejects_every_unclosed_or_duplicate_list_entry(inventory):
    runner = FakeRunner(
        [
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(0, _list_output(inventory), ""),
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
    runner = FakeRunner(
        [
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(0, _list_output(), ""),
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
    runner = FakeRunner(
        [
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(0, _list_output(), ""),
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
    runner = FakeRunner(
        [
            SkillCommandResult(0, _validator_output(), ""),
            SkillCommandResult(0, _list_output(), ""),
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
