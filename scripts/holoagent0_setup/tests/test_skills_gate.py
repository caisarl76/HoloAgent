from __future__ import annotations

import errno
import fcntl
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


def _record_skill_descriptors(monkeypatch):
    repository_descriptors = []
    memfd_descriptors = []
    real_open = os.open
    real_memfd_create = os.memfd_create

    def open_reviewed_script(path, flags):
        descriptor = real_open(path, flags)
        repository_descriptors.append(descriptor)
        return descriptor

    def create_skill_memfd(name, flags):
        descriptor = real_memfd_create(name, flags)
        memfd_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(
        skills_gate,
        "_open_reviewed_skill_script",
        open_reviewed_script,
        raising=False,
    )
    monkeypatch.setattr(
        skills_gate,
        "_create_skill_memfd",
        create_skill_memfd,
        raising=False,
    )
    return repository_descriptors, memfd_descriptors


def _assert_descriptors_closed(*descriptor_groups):
    for descriptor in {item for group in descriptor_groups for item in group}:
        with pytest.raises(OSError):
            os.fstat(descriptor)


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


def test_sealed_skill_snapshot_survives_in_place_inode_mutation(tmp_path):
    script = tmp_path / "reviewed.py"
    reviewed_content = b'print("reviewed-original")\n'
    script.write_bytes(reviewed_content)

    class MutateThenRun:
        def run(self, command, *, environment, pass_fds=()):
            script.write_text('print("mutated-in-place")\n', encoding="utf-8")
            return LocalCommandRunner(timeout_seconds=2.0).run(
                command,
                environment=environment,
                pass_fds=pass_fds,
            )

    result = skills_gate._run_command(
        MutateThenRun(),
        _direct_command(script),
        expected_script_digest=_digest(reviewed_content),
    )

    assert result.exit_code == 0
    assert result.stdout == "reviewed-original\n"


def test_skill_runner_receives_only_a_fully_sealed_memfd(tmp_path):
    script = tmp_path / "reviewed.py"
    content = b'print("sealed")\n'
    script.write_bytes(content)

    class InspectSealedRunner:
        def run(self, command, *, environment, pass_fds=()):
            descriptor = pass_fds[0]
            observed = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
            required = (
                fcntl.F_SEAL_WRITE
                | fcntl.F_SEAL_GROW
                | fcntl.F_SEAL_SHRINK
                | fcntl.F_SEAL_SEAL
            )
            assert observed & required == required
            assert os.readlink(f"/proc/self/fd/{descriptor}").startswith("/memfd:")
            with pytest.raises(OSError):
                os.write(descriptor, b"mutation")
            return LocalCommandRunner(timeout_seconds=2.0).run(
                command,
                environment=environment,
                pass_fds=pass_fds,
            )

    result = skills_gate._run_command(
        InspectSealedRunner(),
        _direct_command(script),
        expected_script_digest=_digest(content),
    )

    assert result.exit_code == 0
    assert result.stdout == "sealed\n"


def test_before_seal_mutation_is_sealed_then_rejected(tmp_path, monkeypatch):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed")\n'
    script.write_bytes(content)
    events = []
    real_fcntl = fcntl.fcntl

    def record_seals(descriptor, operation, argument=0):
        if operation == fcntl.F_ADD_SEALS:
            events.append("add_seals")
        elif operation == fcntl.F_GET_SEALS:
            events.append("get_seals")
        return real_fcntl(descriptor, operation, argument)

    def mutate_snapshot(stage, descriptor):
        events.append(stage)
        if stage == "before_seal":
            assert os.pwrite(descriptor, b"X", 0) == 1

    monkeypatch.setattr(fcntl, "fcntl", record_seals)
    runner = FakeRunner()

    with pytest.raises(OSError, match="sealed skill snapshot digest mismatch"):
        skills_gate._run_command(
            runner,
            _direct_command(script),
            expected_script_digest=_digest(content),
            _snapshot_hook=mutate_snapshot,
        )

    assert events == ["before_seal", "add_seals", "get_seals"]
    assert runner.commands == []


def test_skill_snapshot_is_sealed_before_hash(tmp_path, monkeypatch):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed")\n'
    script.write_bytes(content)
    events = []
    real_fcntl = fcntl.fcntl
    real_descriptor_sha256 = skills_gate._descriptor_sha256

    def record_seals(descriptor, operation, argument=0):
        if operation == fcntl.F_ADD_SEALS:
            events.append("add_seals")
        elif operation == fcntl.F_GET_SEALS:
            events.append("get_seals")
        return real_fcntl(descriptor, operation, argument)

    def record_hash(descriptor):
        events.append("hash")
        return real_descriptor_sha256(descriptor)

    def record_boundary(stage, _descriptor):
        events.append(stage)

    monkeypatch.setattr(fcntl, "fcntl", record_seals)
    monkeypatch.setattr(skills_gate, "_descriptor_sha256", record_hash)

    skills_gate._run_command(
        FakeRunner(),
        _direct_command(script),
        expected_script_digest=_digest(content),
        _snapshot_hook=record_boundary,
    )

    assert events == [
        "before_seal",
        "add_seals",
        "get_seals",
        "hash",
        "after_seal",
    ]


def test_after_seal_mutation_fails_and_original_snapshot_executes(tmp_path):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed-original")\n'
    script.write_bytes(content)
    observed_errno = None

    def try_mutation(stage, descriptor):
        nonlocal observed_errno
        if stage != "after_seal":
            return
        try:
            os.pwrite(descriptor, b"X", 0)
        except OSError as error:
            observed_errno = error.errno

    result = skills_gate._run_command(
        LocalCommandRunner(timeout_seconds=2.0),
        _direct_command(script),
        expected_script_digest=_digest(content),
        _snapshot_hook=try_mutation,
    )

    assert observed_errno == errno.EPERM
    assert result.exit_code == 0
    assert result.stdout == "reviewed-original\n"


def test_sealed_skill_execution_blocks_when_memfd_create_is_unavailable(
    tmp_path,
    monkeypatch,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    repository_descriptors = []
    real_open = os.open

    def open_reviewed_script(path, flags):
        descriptor = real_open(path, flags)
        repository_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(
        skills_gate,
        "_open_reviewed_skill_script",
        open_reviewed_script,
        raising=False,
    )
    monkeypatch.delattr(os, "memfd_create")

    with pytest.raises(OSError, match="memfd"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    _assert_descriptors_closed(repository_descriptors)


@pytest.mark.parametrize(
    ("module", "attribute"),
    [
        (os, "MFD_ALLOW_SEALING"),
        (os, "MFD_CLOEXEC"),
        (fcntl, "F_ADD_SEALS"),
        (fcntl, "F_GET_SEALS"),
        (fcntl, "F_SEAL_WRITE"),
        (fcntl, "F_SEAL_GROW"),
        (fcntl, "F_SEAL_SHRINK"),
        (fcntl, "F_SEAL_SEAL"),
    ],
)
def test_sealed_skill_execution_blocks_when_a_required_constant_is_unavailable(
    tmp_path,
    monkeypatch,
    module,
    attribute,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    monkeypatch.delattr(module, attribute)

    with pytest.raises(OSError, match="memfd sealing is unavailable"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )


def test_skill_execution_closes_descriptors_when_memfd_create_fails(
    tmp_path,
    monkeypatch,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    repository_descriptors = []
    real_open = os.open

    def open_reviewed_script(path, flags):
        descriptor = real_open(path, flags)
        repository_descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(
        skills_gate,
        "_open_reviewed_skill_script",
        open_reviewed_script,
        raising=False,
    )
    monkeypatch.setattr(
        skills_gate,
        "_create_skill_memfd",
        lambda *_args: (_ for _ in ()).throw(OSError("memfd create failed")),
        raising=False,
    )

    with pytest.raises(OSError, match="memfd create failed"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    _assert_descriptors_closed(repository_descriptors)


def test_skill_execution_closes_descriptors_when_memfd_write_fails(
    tmp_path,
    monkeypatch,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    repository_descriptors, memfd_descriptors = _record_skill_descriptors(monkeypatch)
    monkeypatch.setattr(
        skills_gate,
        "_write_skill_memfd",
        lambda *_args: (_ for _ in ()).throw(OSError("memfd write failed")),
        raising=False,
    )

    with pytest.raises(OSError, match="memfd write failed"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    _assert_descriptors_closed(repository_descriptors, memfd_descriptors)


def test_skill_execution_closes_descriptors_when_add_seals_fails(
    tmp_path,
    monkeypatch,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    repository_descriptors, memfd_descriptors = _record_skill_descriptors(monkeypatch)
    real_fcntl = fcntl.fcntl

    def fail_add_seals(descriptor, operation, argument=0):
        if operation == fcntl.F_ADD_SEALS:
            raise OSError("add seals failed")
        return real_fcntl(descriptor, operation, argument)

    monkeypatch.setattr(fcntl, "fcntl", fail_add_seals)

    with pytest.raises(OSError, match="add seals failed"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    _assert_descriptors_closed(repository_descriptors, memfd_descriptors)


def test_skill_execution_closes_descriptors_on_incomplete_seal_mask(
    tmp_path,
    monkeypatch,
):
    script = tmp_path / "reviewed.py"
    content = b'print("must-not-run")\n'
    script.write_bytes(content)
    repository_descriptors, memfd_descriptors = _record_skill_descriptors(monkeypatch)
    real_fcntl = fcntl.fcntl

    def omit_write_seal(descriptor, operation, argument=0):
        if operation == fcntl.F_GET_SEALS:
            return fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        return real_fcntl(descriptor, operation, argument)

    monkeypatch.setattr(fcntl, "fcntl", omit_write_seal)

    with pytest.raises(OSError, match="snapshot is incomplete"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    _assert_descriptors_closed(repository_descriptors, memfd_descriptors)


@pytest.mark.parametrize("runner_raises", [False, True])
def test_skill_repository_and_memfd_descriptors_close_after_runner(
    tmp_path,
    monkeypatch,
    runner_raises,
):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed")\n'
    script.write_bytes(content)
    repository_descriptors, memfd_descriptors = _record_skill_descriptors(monkeypatch)

    class ClosureRunner:
        def run(self, _command, *, environment, pass_fds=()):
            assert len(repository_descriptors) == 1
            assert len(memfd_descriptors) == 1
            assert pass_fds == (memfd_descriptors[0],)
            repository_target = Path(
                f"/proc/self/fd/{repository_descriptors[0]}"
            ).resolve()
            assert repository_target != script.resolve()
            os.fstat(memfd_descriptors[0])
            if runner_raises:
                raise RuntimeError("runner failed")
            return SkillCommandResult(0, "reviewed\n", "")

    if runner_raises:
        with pytest.raises(RuntimeError, match="runner failed"):
            skills_gate._run_command(
                ClosureRunner(),
                _direct_command(script),
                expected_script_digest=_digest(content),
            )
    else:
        result = skills_gate._run_command(
            ClosureRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )
        assert result.stdout == "reviewed\n"

    _assert_descriptors_closed(repository_descriptors, memfd_descriptors)


@pytest.mark.parametrize("failed_descriptor", ["repository", "memfd"])
def test_skill_descriptor_close_failure_is_blocking(
    tmp_path,
    monkeypatch,
    failed_descriptor,
):
    script = tmp_path / "reviewed.py"
    content = b'print("reviewed")\n'
    script.write_bytes(content)
    repository_descriptors, memfd_descriptors = _record_skill_descriptors(monkeypatch)
    real_close = os.close
    failed = False

    def fail_selected_close(descriptor):
        nonlocal failed
        should_fail = (
            failed_descriptor == "repository"
            and descriptor in repository_descriptors
            or failed_descriptor == "memfd"
            and descriptor in memfd_descriptors
        )
        real_close(descriptor)
        if should_fail and not failed:
            failed = True
            raise OSError(f"{failed_descriptor} close failed")

    monkeypatch.setattr(
        skills_gate,
        "_close_skill_descriptor",
        fail_selected_close,
        raising=False,
    )

    with pytest.raises(OSError, match=rf"{failed_descriptor} close failed"):
        skills_gate._run_command(
            FakeRunner(),
            _direct_command(script),
            expected_script_digest=_digest(content),
        )

    assert failed is True
    _assert_descriptors_closed(repository_descriptors, memfd_descriptors)


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
