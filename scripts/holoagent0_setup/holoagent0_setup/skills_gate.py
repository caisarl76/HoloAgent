"""Observation-only validation for the tracked HoloAgent skill registry."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Callable, Protocol

from .openclaw_gate import LocalCommandRunner


PYTHON_EXECUTABLE = Path("/usr/bin/python3.10")
PYTHON_EXECUTABLE_SHA256 = (
    "7d51cd6b48b521277f5caa4610a82126e315fa2be4df069823a8b1eeb5bd4a86"
)
EXPECTED_SKILLS = (
    "arm-skill",
    "rel-move-skill",
    "robot-service",
    "sem-nav-skill",
    "workflow",
)
_SKILLS_ROOT = Path("agentic_robot/agentOS/holoagent_skills")
_VALIDATOR = _SKILLS_ROOT / "scripts/validate_skills.py"
_LIST = _SKILLS_ROOT / "scripts/list_skills.py"
_PINNED_REPOSITORY_FILES = {
    _VALIDATOR: "2c8470fd693630373414c6fd8042a79cbdd6bfb01bd93548c0ca8dea5908430f",
    _LIST: "900bf2520fd8015e7e1101526667d294d14512de323ddb8d368a1074b7100bbe",
    _SKILLS_ROOT / "skills/arm-skill/SKILL.md": (
        "4a1a4b8cc7fe5c0009519a19f505c91ab65ad717946eaf5fbae4e86f55c8c731"
    ),
    _SKILLS_ROOT / "skills/rel-move-skill/SKILL.md": (
        "3c4411e31102b4cc7234c40dae90f477f0115be6036ef552cbb04571a2c03ccd"
    ),
    _SKILLS_ROOT / "skills/robot-service/SKILL.md": (
        "173a15dde515ac9addc0b5888ca21ab3d985130bc3fa0334543d5c479f3b4cab"
    ),
    _SKILLS_ROOT / "skills/sem-nav-skill/SKILL.md": (
        "ce599451f798f5bd625c0bf3e6a85050e397c13a2422694af4189515979d52b3"
    ),
    _SKILLS_ROOT / "skills/workflow/SKILL.md": (
        "046d093cbaa9703729ffdc00175d336a753ad08fef094ccd71e4ffcb449f20e3"
    ),
    _SKILLS_ROOT / "skills/arm-skill/scripts/trigger_arm_skill.py": (
        "fd486fa55da2f8010a9d4c562ddc7dd32378d16e9928c2f5beb9c0aca02769e0"
    ),
    _SKILLS_ROOT / "skills/rel-move-skill/scripts/relative_move.py": (
        "a73b8b9738e3ffe0949d1e6a78561baae260878bc4a8446c3df661bb0a1b1136"
    ),
    _SKILLS_ROOT / "skills/robot-service/scripts/service_request.py": (
        "b6c57a09ec24b59e38384352d05bd4f491f37b452ddb6e9b803de29b06423b46"
    ),
    _SKILLS_ROOT / "skills/sem-nav-skill/scripts/semantic_nav.py": (
        "d2523a13072a5f127476c9f0d16f3c49bcea1eca16c36cf12c1ba1b159af255c"
    ),
}
_OUTPUT_LIMIT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SkillCommandResult:
    """Bounded, redaction-safe command facts accepted from a runner."""

    exit_code: int
    stdout: str
    stderr: str
    side_effect_attempted: bool = False
    remaining_process_group: bool = False


class SkillCommandRunner(Protocol):
    def run(
        self,
        command: tuple[str, ...],
        *,
        environment: dict[str, str],
        pass_fds: tuple[int, ...] = (),
    ) -> object: ...


@dataclass(frozen=True)
class SkillsGateResult:
    gates: tuple[dict[str, object], ...]
    exit_code: int


def _measurement(name: str, value: int | bool) -> dict[str, object]:
    return {"name": name, "value": value, "unit": None}


def _gate(
    gate_id: str,
    status: str,
    reason: str,
    measurements: tuple[dict[str, object], ...] = (),
) -> dict[str, object]:
    return {
        "id": gate_id,
        "status": status,
        "role": "required",
        "reason": reason,
        "measurements": list(measurements),
        "thresholds": [],
        "log_paths": [],
        "child_command_exit_code": None,
    }


def _not_run() -> dict[str, object]:
    return _gate("skills.dry_run", "NOT_RUN", "EARLIER_BLOCKING_GATE")


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise OSError("pinned file is unavailable")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identities_match(
    repository_root: Path, digest_reader: Callable[[Path], str]
) -> bool:
    try:
        if digest_reader(PYTHON_EXECUTABLE) != PYTHON_EXECUTABLE_SHA256:
            return False
        for relative, expected in _PINNED_REPOSITORY_FILES.items():
            path = repository_root / relative
            if digest_reader(path) != expected:
                return False
    except (OSError, TypeError, ValueError):
        return False
    return True


def _command_result(value: object) -> SkillCommandResult:
    result = SkillCommandResult(
        exit_code=getattr(value, "exit_code"),
        stdout=getattr(value, "stdout"),
        stderr=getattr(value, "stderr"),
        side_effect_attempted=getattr(value, "side_effect_attempted", False),
        remaining_process_group=getattr(value, "remaining_process_group", False),
    )
    if (
        type(result.exit_code) is not int
        or result.exit_code < 0
        or result.exit_code > 255
        or type(result.stdout) is not str
        or type(result.stderr) is not str
        or type(result.side_effect_attempted) is not bool
        or type(result.remaining_process_group) is not bool
        or len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
        > _OUTPUT_LIMIT_BYTES
    ):
        raise ValueError("invalid bounded command result")
    return result


def _run_command(
    runner: SkillCommandRunner, command: tuple[str, ...]
) -> SkillCommandResult:
    if (
        type(command) is not tuple
        or not command
        or any(type(argument) is not str for argument in command)
        or command[0] != str(PYTHON_EXECUTABLE)
    ):
        raise ValueError("unreviewed skill command")
    value = runner.run(command, environment={"PATH": "/usr/bin:/bin"}, pass_fds=())
    return _command_result(value)


def _reported_skills(output: str) -> tuple[str, ...]:
    names = {
        line[2:]
        for line in output.splitlines()
        if line.startswith("- ") and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", line[2:])
    }
    return tuple(sorted(names))


def _registry_commands(repository_root: Path) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (str(PYTHON_EXECUTABLE), "-B", str(repository_root / relative))
        for relative in (_VALIDATOR, _LIST)
    )


def _dry_run_commands(repository_root: Path) -> tuple[tuple[str, ...], ...]:
    base = (str(PYTHON_EXECUTABLE), "-B")
    return (
        (
            *base,
            str(
                repository_root
                / _SKILLS_ROOT
                / "skills/arm-skill/scripts/trigger_arm_skill.py"
            ),
            "--skill",
            "high_wave",
            "--dry-run",
        ),
        (
            *base,
            str(
                repository_root
                / _SKILLS_ROOT
                / "skills/rel-move-skill/scripts/relative_move.py"
            ),
            "--forward",
            "0.0",
            "--left",
            "0.0",
            "--rotation",
            "0.0",
            "--dry-run",
        ),
        (
            *base,
            str(
                repository_root
                / _SKILLS_ROOT
                / "skills/robot-service/scripts/service_request.py"
            ),
            "--endpoint",
            "/health",
            "--method",
            "GET",
            "--dry-run",
        ),
        (
            *base,
            str(
                repository_root
                / _SKILLS_ROOT
                / "skills/sem-nav-skill/scripts/semantic_nav.py"
            ),
            "--floor",
            "offline",
            "--room",
            "offline",
            "--object",
            "offline",
            "--dry-run",
        ),
    )


def run_skills_gates(
    *,
    repository_root: Path,
    runner: SkillCommandRunner | None = None,
    digest_reader: Callable[[Path], str] = _sha256_file,
) -> SkillsGateResult:
    """Run only pinned registry inspection and true helper dry-runs."""

    root = Path(repository_root)
    if not _identities_match(root, digest_reader):
        return SkillsGateResult(
            gates=(
                _gate("skills.registry", "FAIL", "DIGEST_MISMATCH"),
                _not_run(),
            ),
            exit_code=1,
        )

    command_runner = runner or LocalCommandRunner(timeout_seconds=10.0)
    try:
        registry_results = tuple(
            _run_command(command_runner, command)
            for command in _registry_commands(root)
        )
    except Exception:
        registry_results = ()
    registry_valid = (
        len(registry_results) == 2
        and all(result.exit_code == 0 for result in registry_results)
        and all(
            not result.side_effect_attempted and not result.remaining_process_group
            for result in registry_results
        )
        and all(
            _reported_skills(result.stdout) == EXPECTED_SKILLS
            for result in registry_results
        )
    )
    if not registry_valid:
        return SkillsGateResult(
            gates=(
                _gate("skills.registry", "FAIL", "PLAN_INVALID"),
                _not_run(),
            ),
            exit_code=1,
        )

    registry_gate = _gate(
        "skills.registry",
        "PASS",
        "OK",
        (_measurement("validated_skill_count", len(EXPECTED_SKILLS)),),
    )
    side_effect_attempted = False
    remaining_process_group = False
    try:
        for command in _dry_run_commands(root):
            if "--dry-run" not in command:
                raise ValueError("motion-capable helper lacks dry-run")
            result = _run_command(command_runner, command)
            side_effect_attempted |= result.side_effect_attempted
            remaining_process_group |= result.remaining_process_group
            if side_effect_attempted or remaining_process_group:
                return SkillsGateResult(
                    gates=(
                        registry_gate,
                        _gate(
                            "skills.dry_run",
                            "FAIL",
                            "OFFLINE_SIDE_EFFECT_ATTEMPT",
                            (
                                _measurement("dry_run_helper_count", 4),
                                _measurement("side_effect_attempted", True),
                                _measurement(
                                    "remaining_process_group",
                                    remaining_process_group,
                                ),
                            ),
                        ),
                    ),
                    exit_code=1,
                )
            if result.exit_code != 0 or not result.stdout:
                raise RuntimeError("dry-run command failed")
    except Exception:
        return SkillsGateResult(
            gates=(
                registry_gate,
                _gate("skills.dry_run", "FAIL", "TOOL_RUNTIME_ERROR"),
            ),
            exit_code=1,
        )

    return SkillsGateResult(
        gates=(
            registry_gate,
            _gate(
                "skills.dry_run",
                "PASS",
                "OK",
                (
                    _measurement("dry_run_helper_count", 4),
                    _measurement("side_effect_attempted", False),
                    _measurement("remaining_process_group", False),
                ),
            ),
        ),
        exit_code=0,
    )
