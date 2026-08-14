"""Observation-only validation for the tracked HoloAgent skill registry."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import stat
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
REQUIRED_SKILL_MEMFD_SEALS = (
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
)


@dataclass(frozen=True)
class SkillCommandResult:
    """Bounded, redaction-safe command facts accepted from a runner."""

    exit_code: int
    stdout: str
    stderr: str
    side_effect_attempted: bool | None = None
    remaining_process_group: bool | None = None


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
        side_effect_attempted=getattr(value, "side_effect_attempted", None),
        remaining_process_group=getattr(value, "remaining_process_group", None),
    )
    if (
        type(result.exit_code) is not int
        or result.exit_code < 0
        or result.exit_code > 255
        or type(result.stdout) is not str
        or type(result.stderr) is not str
        or type(result.side_effect_attempted) not in {bool, type(None)}
        or type(result.remaining_process_group) not in {bool, type(None)}
        or len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8"))
        > _OUTPUT_LIMIT_BYTES
    ):
        raise ValueError("invalid bounded command result")
    return result


def _open_reviewed_skill_script(path: str, flags: int) -> int:
    return os.open(path, flags)


def _create_skill_memfd(name: str, flags: int) -> int:
    creator = getattr(os, "memfd_create", None)
    if not callable(creator):
        raise OSError("memfd creation is unavailable")
    descriptor = creator(name, flags)
    if type(descriptor) is not int or descriptor < 3:
        raise OSError("invalid skill memfd descriptor")
    return descriptor


def _skill_memfd_name(script_path: str) -> str:
    path = Path(script_path)
    if not path.is_absolute() or "\0" in script_path:
        raise OSError("invalid reviewed skill path")
    name = f"../../{script_path.removeprefix('/')}"
    if len(name.encode("utf-8")) > 249:
        raise OSError("reviewed skill path is too long for a memfd")
    return name


def _write_skill_memfd(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if type(written) is not int or written <= 0 or written > len(remaining):
            raise OSError("incomplete skill memfd write")
        remaining = remaining[written:]


def _close_skill_descriptor(descriptor: int) -> None:
    os.close(descriptor)


def _skill_memfd_parameters() -> tuple[int, int, int, int]:
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
    values = []
    for module, name in required:
        value = getattr(module, name, None)
        if type(value) is not int:
            raise OSError("memfd sealing is unavailable")
        values.append(value)
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
    if seal_mask != REQUIRED_SKILL_MEMFD_SEALS:
        raise OSError("memfd sealing constants changed")
    return allow_sealing | close_on_exec, add_seals, get_seals, seal_mask


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _run_command(
    runner: SkillCommandRunner,
    command: tuple[str, ...],
    *,
    expected_script_digest: str,
) -> SkillCommandResult:
    if (
        type(command) is not tuple
        or len(command) < 4
        or any(type(argument) is not str for argument in command)
        or command[0] != str(PYTHON_EXECUTABLE)
        or command[1:3] != ("-I", "-B")
        or not Path(command[3]).is_absolute()
        or type(expected_script_digest) is not str
        or len(expected_script_digest) != 64
        or any(
            character not in "0123456789abcdef" for character in expected_script_digest
        )
    ):
        raise ValueError("unreviewed skill command")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if type(no_follow) is not int:
        raise OSError("no-follow script opening is unavailable")
    repository_descriptor = _open_reviewed_skill_script(
        command[3],
        os.O_RDONLY | os.O_CLOEXEC | no_follow,
    )
    memfd_descriptor = None
    try:
        before = os.fstat(repository_descriptor)
        if repository_descriptor < 3 or not stat.S_ISREG(before.st_mode):
            raise OSError("reviewed skill script is not a regular file")
        digest = hashlib.sha256()
        payload_parts = []
        os.lseek(repository_descriptor, 0, os.SEEK_SET)
        for chunk in iter(lambda: os.read(repository_descriptor, 1024 * 1024), b""):
            digest.update(chunk)
            payload_parts.append(chunk)
        after = os.fstat(repository_descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise OSError("reviewed skill script changed during verification")
        if digest.hexdigest() != expected_script_digest:
            raise OSError("reviewed skill script digest mismatch")
        payload = b"".join(payload_parts)
        flags, add_seals, get_seals, required_seals = _skill_memfd_parameters()
        memfd_descriptor = _create_skill_memfd(_skill_memfd_name(command[3]), flags)
        _write_skill_memfd(memfd_descriptor, payload)
        if _descriptor_sha256(memfd_descriptor) != expected_script_digest:
            raise OSError("sealed skill snapshot digest mismatch")
        fcntl.fcntl(memfd_descriptor, add_seals, required_seals)
        observed_seals = fcntl.fcntl(memfd_descriptor, get_seals)
        if (
            type(observed_seals) is not int
            or observed_seals & required_seals != required_seals
        ):
            raise OSError("sealed skill snapshot is incomplete")
        os.lseek(memfd_descriptor, 0, os.SEEK_SET)

        descriptor_to_close = repository_descriptor
        repository_descriptor = None
        _close_skill_descriptor(descriptor_to_close)
        verified_command = (
            *command[:3],
            f"/proc/self/fd/{memfd_descriptor}",
            *command[4:],
        )
        value = runner.run(
            verified_command,
            environment={"PATH": "/usr/bin:/bin"},
            pass_fds=(memfd_descriptor,),
        )
        return _command_result(value)
    finally:
        cleanup_error = None
        if repository_descriptor is not None:
            descriptor_to_close = repository_descriptor
            repository_descriptor = None
            try:
                _close_skill_descriptor(descriptor_to_close)
            except BaseException as error:
                cleanup_error = error
        if memfd_descriptor is not None:
            descriptor_to_close = memfd_descriptor
            memfd_descriptor = None
            try:
                _close_skill_descriptor(descriptor_to_close)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error


def _list_inventory(output: str) -> tuple[str, ...] | None:
    lines = output.splitlines()
    if not lines or lines[0] != "HoloAgent skills:":
        return None
    names: list[str] = []
    for line in lines[1:]:
        if not line:
            continue
        if line.startswith("- "):
            name = line[2:]
            if not name:
                return None
            names.append(name)
            continue
        if line.startswith("  ") and names:
            continue
        return None
    return tuple(names)


def _registry_commands(
    repository_root: Path,
) -> tuple[tuple[tuple[str, ...], str], ...]:
    return tuple(
        (
            (
                str(PYTHON_EXECUTABLE),
                "-I",
                "-B",
                str(repository_root / relative),
            ),
            _PINNED_REPOSITORY_FILES[relative],
        )
        for relative in (_VALIDATOR, _LIST)
    )


def _dry_run_commands(
    repository_root: Path,
) -> tuple[tuple[tuple[str, ...], str], ...]:
    base = (str(PYTHON_EXECUTABLE), "-I", "-B")
    arm_script = _SKILLS_ROOT / "skills/arm-skill/scripts/trigger_arm_skill.py"
    relative_move_script = (
        _SKILLS_ROOT / "skills/rel-move-skill/scripts/relative_move.py"
    )
    service_script = _SKILLS_ROOT / "skills/robot-service/scripts/service_request.py"
    semantic_nav_script = _SKILLS_ROOT / "skills/sem-nav-skill/scripts/semantic_nav.py"
    return (
        (
            (
                *base,
                str(repository_root / arm_script),
                "--skill",
                "high_wave",
                "--dry-run",
            ),
            _PINNED_REPOSITORY_FILES[arm_script],
        ),
        (
            (
                *base,
                str(repository_root / relative_move_script),
                "--forward",
                "0.0",
                "--left",
                "0.0",
                "--rotation",
                "0.0",
                "--dry-run",
            ),
            _PINNED_REPOSITORY_FILES[relative_move_script],
        ),
        (
            (
                *base,
                str(repository_root / service_script),
                "--endpoint",
                "/health",
                "--method",
                "GET",
                "--dry-run",
            ),
            _PINNED_REPOSITORY_FILES[service_script],
        ),
        (
            (
                *base,
                str(repository_root / semantic_nav_script),
                "--floor",
                "offline",
                "--room",
                "offline",
                "--object",
                "offline",
                "--dry-run",
            ),
            _PINNED_REPOSITORY_FILES[semantic_nav_script],
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
            _run_command(
                command_runner,
                command,
                expected_script_digest=expected_digest,
            )
            for command, expected_digest in _registry_commands(root)
        )
    except Exception:
        registry_results = ()
    registry_valid = (
        len(registry_results) == 2
        and all(result.exit_code == 0 for result in registry_results)
        and all(
            result.side_effect_attempted is not True
            and result.remaining_process_group is not True
            for result in registry_results
        )
        and _list_inventory(registry_results[1].stdout) == EXPECTED_SKILLS
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
    dry_run_results: list[SkillCommandResult] = []
    try:
        for command, expected_digest in _dry_run_commands(root):
            if "--dry-run" not in command:
                raise ValueError("motion-capable helper lacks dry-run")
            result = _run_command(
                command_runner,
                command,
                expected_script_digest=expected_digest,
            )
            dry_run_results.append(result)
            if (
                result.side_effect_attempted is True
                or result.remaining_process_group is True
            ):
                measurements = [_measurement("dry_run_helper_count", 4)]
                if result.side_effect_attempted is True:
                    measurements.append(_measurement("side_effect_attempted", True))
                if result.remaining_process_group is True:
                    measurements.append(_measurement("remaining_process_group", True))
                return SkillsGateResult(
                    gates=(
                        registry_gate,
                        _gate(
                            "skills.dry_run",
                            "FAIL",
                            "OFFLINE_SIDE_EFFECT_ATTEMPT",
                            tuple(measurements),
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

    measurements = [_measurement("dry_run_helper_count", 4)]
    if all(result.side_effect_attempted is False for result in dry_run_results):
        measurements.append(_measurement("side_effect_attempted", False))
    if all(result.remaining_process_group is False for result in dry_run_results):
        measurements.append(_measurement("remaining_process_group", False))
    return SkillsGateResult(
        gates=(
            registry_gate,
            _gate(
                "skills.dry_run",
                "PASS",
                "OK",
                tuple(measurements),
            ),
        ),
        exit_code=0,
    )
