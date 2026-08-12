"""Pinned OpenClaw artifact and read-only lifecycle authorities."""

from __future__ import annotations

import argparse
import base64
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
from typing import Mapping, Protocol, Sequence
from urllib import request as urllib_request
from urllib import error as urllib_error
import uuid

from .atomic_io import (
    AtomicIOError,
    atomic_write_bytes_no_replace,
    canonical_json_bytes,
)
from .contract import ContractSet


OPENCLAW_VERSION = "2026.7.1-2"
OPENCLAW_INTEGRITY = (
    "sha512-ycF3yPcbjN6bUPeaUx6Mh6vze1hQWoD3CT/wWcmD7a8xaHHHRUaAlaq+lFxMHf1ss"
    "EgODVAwjlzYqp2twkYZ7g=="
)
NODE_VERSION = "24.15.0"
NODE_TARBALL_SHA256 = "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6"
INSTALLER_SHA256 = "21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1"
INSTALLER_URL = "https://openclaw.ai/install-cli.sh"
REGISTRY_URL = "https://registry.npmjs.org/openclaw/2026.7.1-2"
TARBALL_URL = "https://registry.npmjs.org/openclaw/-/openclaw-2026.7.1-2.tgz"
NODE_TARBALL_URL = "https://nodejs.org/dist/v24.15.0/node-v24.15.0-linux-x64.tar.xz"
CONFIG_TEMPLATE_CONTENT = b"""{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_GATEWAY_TOKEN}"
    }
  }
}
"""
CONFIG_TEMPLATE_GIT_BLOB = hashlib.sha1(
    f"blob {len(CONFIG_TEMPLATE_CONTENT)}\0".encode("ascii") + CONFIG_TEMPLATE_CONTENT,
    usedforsecurity=False,
).hexdigest()
INSTALL_DRIVER_PATH = Path(__file__).resolve().parents[1] / "openclaw_install_driver.sh"
INSTALL_DRIVER_SHA256 = (
    "a8480748009b3f070d5d456eb8297896a7fe28b41f58015a17013dce4059a672"
)


class ProvisioningError(RuntimeError):
    """A pinned provisioning invariant did not hold."""


class OpenClawGateError(RuntimeError):
    """A read-only lifecycle invariant did not hold."""


class OpenClawSafetyError(OpenClawGateError):
    """An owned cleanup or isolation invariant did not hold."""


class _ProvisioningSignal(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(signum)
        self.signum = signum


@dataclass(frozen=True)
class RegistryDocument:
    version: str
    tarball: str
    integrity: str
    shasum: str
    response_sha256: str


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    type: str
    sha256: str | None
    symlink_target: str | None
    executable: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "type": self.type,
            "sha256": self.sha256,
            "symlink_target": self.symlink_target,
            "executable": self.executable,
        }


@dataclass(frozen=True)
class PayloadManifest:
    entries: tuple[ManifestEntry, ...]
    sha256: str

    @classmethod
    def create(cls, entries: Sequence[ManifestEntry]) -> "PayloadManifest":
        ordered = tuple(sorted(entries, key=lambda entry: entry.path))
        if len({entry.path for entry in ordered}) != len(ordered):
            raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: duplicate path")
        hasher = hashlib.sha256()
        hasher.update(b"[")
        for index, entry in enumerate(ordered):
            if index:
                hasher.update(b",")
            hasher.update(canonical_json_bytes(entry.as_dict()))
        hasher.update(b"]")
        digest = hasher.hexdigest()
        return cls(ordered, digest)


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    start_time_ticks: int
    executable: str


@dataclass(frozen=True)
class ServiceObservation:
    name: str
    state: str


@dataclass(frozen=True)
class ListenerObservation:
    address: str
    port: int
    pid: int | None


@dataclass(frozen=True)
class LifecycleObservation:
    processes: tuple[ProcessObservation, ...]
    services: tuple[ServiceObservation, ...]
    listeners: tuple[ListenerObservation, ...]

    @property
    def has_openclaw_state(self) -> bool:
        return bool(self.processes or self.services or self.listeners)


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class GateResult:
    status: str
    reason: str
    environment: Mapping[str, str]
    observation: LifecycleObservation | None = None


class LifecycleObserver(Protocol):
    def observe(self) -> LifecycleObservation: ...


class CommandRunner(Protocol):
    def run(
        self,
        command: tuple[str, ...],
        *,
        environment: dict[str, str],
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult: ...


class ArtifactFetcher(Protocol):
    def fetch(self, url: str, destination: Path) -> None: ...


class LocalCommandRunner:
    """Run one argv-only local command without a shell."""

    def __init__(self, *, timeout_seconds: float = 120.0) -> None:
        self._timeout_seconds = timeout_seconds

    def run(
        self,
        command: tuple[str, ...],
        *,
        environment: dict[str, str],
        pass_fds: tuple[int, ...] = (),
    ) -> CommandResult:
        if (
            not command
            or any(type(argument) is not str for argument in command)
            or not Path(command[0]).is_absolute()
        ):
            raise ProvisioningError("TOOL_RUNTIME_ERROR: invalid command")
        if (
            type(pass_fds) is not tuple
            or len(set(pass_fds)) != len(pass_fds)
            or any(type(fd) is not int or fd < 3 for fd in pass_fds)
        ):
            raise ProvisioningError("TOOL_RUNTIME_ERROR: invalid passed descriptor")
        try:
            for descriptor in pass_fds:
                os.fstat(descriptor)
        except OSError as error:
            raise ProvisioningError(
                "TOOL_RUNTIME_ERROR: invalid passed descriptor"
            ) from error
        process_environment = _minimal_environment(environment)
        try:
            with (
                tempfile.TemporaryFile() as stdout_file,
                tempfile.TemporaryFile() as stderr_file,
            ):
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=process_environment,
                    pass_fds=pass_fds,
                    start_new_session=True,
                )
                try:
                    identity = OwnedProcess(
                        process.pid,
                        os.getpgid(process.pid),
                        _read_proc_start_time(process.pid),
                        os.readlink(f"/proc/{process.pid}/exe"),
                    )
                except BaseException:
                    _terminate_unregistered_session(process)
                    raise
                try:
                    exit_code = process.wait(timeout=self._timeout_seconds)
                except BaseException:
                    _terminate_process_group(process, identity)
                    raise
                if _pgid_members(identity.pgid):
                    _terminate_process_group(process, identity, leader_reaped=True)
                    raise ProvisioningError(
                        "TOOL_RUNTIME_ERROR: command descendants remained"
                    )
                stdout = _read_bounded_output(stdout_file, "stdout")
                stderr = _read_bounded_output(stderr_file, "stderr")
        except ProvisioningError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            raise ProvisioningError("TOOL_RUNTIME_ERROR") from error
        return CommandResult(exit_code, stdout, stderr)


class HttpsArtifactFetcher:
    """Fetch an exact HTTPS URL into a fresh destination."""

    _MAX_BYTES = {
        REGISTRY_URL: 2 * 1024 * 1024,
        TARBALL_URL: 512 * 1024 * 1024,
        INSTALLER_URL: 2 * 1024 * 1024,
        NODE_TARBALL_URL: 256 * 1024 * 1024,
    }

    class _NoRedirect(urllib_request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    def fetch(self, url: str, destination: Path) -> None:
        if url not in self._MAX_BYTES or not url.startswith("https://"):
            raise ProvisioningError("INSTALLER_PIN_MISMATCH: non-HTTPS artifact")
        destination = Path(destination)
        if destination.exists() or destination.is_symlink():
            raise ProvisioningError("INSTALLER_PIN_MISMATCH: destination exists")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        )
        try:
            opener = urllib_request.build_opener(self._NoRedirect())
            with opener.open(url, timeout=60) as response:
                if response.geturl() != url:
                    raise ProvisioningError(
                        "INSTALLER_PIN_MISMATCH: unexpected redirect"
                    )
                with temporary.open("xb") as output:
                    total = 0
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > self._MAX_BYTES[url]:
                            raise ProvisioningError(
                                "INSTALLER_PIN_MISMATCH: artifact is oversized"
                            )
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            os.link(temporary, destination, follow_symlinks=False)
            temporary.unlink()
            directory_fd = os.open(
                destination.parent,
                os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except ProvisioningError:
            raise
        except (
            FileExistsError,
            OSError,
            ValueError,
            urllib_error.URLError,
        ) as error:
            raise ProvisioningError(
                "TOOL_RUNTIME_ERROR: artifact fetch failed"
            ) from error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


class LocalLifecycleObserver:
    """Observe local OpenClaw processes, service definitions, and TCP listeners."""

    _PID_PATTERN = re.compile(r"pid=(\d+)")

    def __init__(self, *, watched_ports: Sequence[int] = (18789,)) -> None:
        if any(
            type(port) is not int or not 1 <= port <= 65535 for port in watched_ports
        ):
            raise ProvisioningError("TOOL_RUNTIME_ERROR: invalid watched port")
        self._watched_ports = frozenset(watched_ports)

    def observe(self) -> LifecycleObservation:
        processes = self._processes()
        services = self._services()
        listeners = self._listeners({process.pid for process in processes})
        return LifecycleObservation(
            tuple(sorted(processes, key=lambda value: value.pid)),
            tuple(sorted(services, key=lambda value: (value.name, value.state))),
            tuple(
                sorted(
                    listeners,
                    key=lambda value: (value.address, value.port, value.pid or -1),
                )
            ),
        )

    @staticmethod
    def _processes() -> list[ProcessObservation]:
        observations: list[ProcessObservation] = []
        try:
            entries = tuple(Path("/proc").iterdir())
        except OSError as error:
            raise ProvisioningError(
                "TOOL_RUNTIME_ERROR: proc inspection failed"
            ) from error
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                pid = int(entry.name)
                executable = os.readlink(entry / "exe")
                command = (entry / "cmdline").read_bytes().split(b"\0")
                arguments = [
                    value.decode("utf-8", errors="replace")
                    for value in command
                    if value
                ]
                is_openclaw = Path(executable).name in {
                    "openclaw",
                    "openclaw-gateway",
                } or any(
                    "/node_modules/openclaw/" in value
                    or Path(value).name in {"openclaw", "openclaw-gateway"}
                    for value in arguments
                )
                if not is_openclaw:
                    continue
                start_time = _read_proc_start_time(pid)
                if start_time != _read_proc_start_time(pid):
                    continue
            except FileNotFoundError:
                continue
            except PermissionError as error:
                raise ProvisioningError(
                    "TOOL_RUNTIME_ERROR: proc inspection is incomplete"
                ) from error
            except (OSError, ValueError, IndexError) as error:
                raise ProvisioningError(
                    "TOOL_RUNTIME_ERROR: proc inspection failed"
                ) from error
            observations.append(ProcessObservation(pid, start_time, executable))
        return observations

    @staticmethod
    def _services() -> list[ServiceObservation]:
        roots = [
            Path("/run/systemd/system"),
            Path("/etc/systemd/system"),
            Path("/usr/local/lib/systemd/system"),
            Path("/usr/lib/systemd/system"),
            Path("/lib/systemd/system"),
            Path("/etc/systemd/user"),
            Path("/usr/local/lib/systemd/user"),
            Path("/usr/lib/systemd/user"),
            Path("/lib/systemd/user"),
        ]
        user_config = os.environ.get("XDG_CONFIG_HOME")
        if user_config:
            roots.append(Path(user_config) / "systemd/user")
        else:
            roots.append(Path.home() / ".config/systemd/user")
        roots.append(Path.home() / ".local/share/systemd/user")
        runtime_root = os.environ.get("XDG_RUNTIME_DIR")
        if runtime_root:
            roots.append(Path(runtime_root) / "systemd/user")
            roots.append(Path(runtime_root) / "systemd/transient")
        seen: set[str] = set()
        observations: list[ServiceObservation] = []
        for root in roots:
            try:
                candidates = tuple(root.glob("openclaw-gateway*"))
            except OSError as error:
                raise ProvisioningError(
                    "TOOL_RUNTIME_ERROR: service definition inspection failed"
                ) from error
            for candidate in candidates:
                if candidate.name in seen:
                    continue
                seen.add(candidate.name)
                observations.append(ServiceObservation(candidate.name, "defined"))
        systemctl = next(
            (
                path
                for path in ("/usr/bin/systemctl", "/bin/systemctl")
                if Path(path).is_file()
            ),
            None,
        )
        if systemctl is None:
            raise ProvisioningError("TOOL_RUNTIME_ERROR: systemctl is unavailable")
        if systemctl is not None:
            commands = (
                (
                    systemctl,
                    "list-units",
                    "--all",
                    "--type=service",
                    "--plain",
                    "--no-legend",
                    "openclaw-gateway*",
                ),
                (
                    systemctl,
                    "--user",
                    "list-units",
                    "--all",
                    "--type=service",
                    "--plain",
                    "--no-legend",
                    "openclaw-gateway*",
                ),
            )
            for command in commands:
                environment: dict[str, str] = {}
                if "--user" in command:
                    runtime_dir = os.environ.get(
                        "XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"
                    )
                    environment = {
                        "HOME": str(Path.home()),
                        "XDG_RUNTIME_DIR": runtime_dir,
                        "DBUS_SESSION_BUS_ADDRESS": os.environ.get(
                            "DBUS_SESSION_BUS_ADDRESS",
                            f"unix:path={runtime_dir}/bus",
                        ),
                    }
                try:
                    completed = LocalCommandRunner(timeout_seconds=10).run(
                        command, environment=environment
                    )
                except ProvisioningError as error:
                    raise ProvisioningError(
                        "TOOL_RUNTIME_ERROR: service inspection failed"
                    ) from error
                if completed.exit_code != 0:
                    raise ProvisioningError(
                        "TOOL_RUNTIME_ERROR: service inspection failed"
                    )
                for line in completed.stdout.splitlines():
                    fields = line.split()
                    if not fields or not fields[0].startswith("openclaw-gateway"):
                        continue
                    name = fields[0]
                    state = "loaded:" + ":".join(fields[1:4])
                    if name not in seen:
                        seen.add(name)
                        observations.append(ServiceObservation(name, state))
        return observations

    def _listeners(self, openclaw_pids: set[int]) -> list[ListenerObservation]:
        ss_path = next(
            (path for path in ("/usr/bin/ss", "/bin/ss") if Path(path).is_file()),
            None,
        )
        if ss_path is None:
            raise ProvisioningError("TOOL_RUNTIME_ERROR: ss is unavailable")
        try:
            completed = LocalCommandRunner(timeout_seconds=10).run(
                (ss_path, "-H", "-ltnp"), environment={}
            )
        except ProvisioningError as error:
            raise ProvisioningError(
                "TOOL_RUNTIME_ERROR: ss inspection failed"
            ) from error
        if completed.exit_code != 0:
            raise ProvisioningError("TOOL_RUNTIME_ERROR: ss inspection failed")
        observations: list[ListenerObservation] = []
        for line in completed.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            local = fields[3]
            try:
                address, port_text = _split_socket_endpoint(local)
                port = int(port_text)
            except ValueError:
                continue
            match = self._PID_PATTERN.search(line)
            pid = int(match.group(1)) if match else None
            if port in self._watched_ports or (
                pid is not None and pid in openclaw_pids
            ):
                observations.append(ListenerObservation(address, port, pid))
        return observations


@dataclass(frozen=True)
class ProvisioningPaths:
    output_dir: Path
    download_dir: Path
    prefix: Path
    configuration_root: Path
    configuration: Path
    state_dir: Path
    record: Path
    schema: Path
    template: Path
    quarantine_dir: Path
    previous_record: Path | None

    @classmethod
    def for_test_root(cls, root: Path) -> "ProvisioningPaths":
        root = Path(os.path.abspath(root))
        package_root = Path(__file__).resolve().parents[1]
        configuration_root = root / "configuration"
        return cls(
            output_dir=root / "evidence",
            download_dir=root / "evidence/downloads",
            prefix=root / "prefix",
            configuration_root=configuration_root,
            configuration=configuration_root / "openclaw.json",
            state_dir=configuration_root / "state",
            record=root / "evidence/openclaw-provisioning-v1.json",
            schema=package_root / "schemas/openclaw-provisioning-v1.schema.json",
            template=package_root / "config/openclaw-local-v1.json",
            quarantine_dir=root / "evidence/quarantine",
            previous_record=None,
        )

    @classmethod
    def for_user_paths(
        cls,
        *,
        output_dir: Path,
        prefix: Path,
        configuration_root: Path,
        previous_record: Path | None = None,
    ) -> "ProvisioningPaths":
        output_dir = Path(os.path.abspath(output_dir))
        prefix = Path(os.path.abspath(prefix))
        configuration_root = Path(os.path.abspath(configuration_root))
        package_root = Path(__file__).resolve().parents[1]
        return cls(
            output_dir=output_dir,
            download_dir=output_dir / "downloads",
            prefix=prefix,
            configuration_root=configuration_root,
            configuration=configuration_root / "openclaw.json",
            state_dir=configuration_root / "state",
            record=output_dir / "openclaw-provisioning-v1.json",
            schema=package_root / "schemas/openclaw-provisioning-v1.schema.json",
            template=package_root / "config/openclaw-local-v1.json",
            quarantine_dir=output_dir / "quarantine",
            previous_record=(
                Path(os.path.abspath(previous_record))
                if previous_record is not None
                else None
            ),
        )


@dataclass(frozen=True)
class OwnedProcess:
    pid: int
    pgid: int
    start_time_ticks: int
    executable: str


class SmokeProcessController(Protocol):
    def start(
        self, command: tuple[str, ...], *, environment: dict[str, str]
    ) -> OwnedProcess: ...

    def stop(self, identity: OwnedProcess) -> None: ...


class LocalSmokeProcessController:
    """Own one process group and signal it only while its identity is stable."""

    def __init__(self, *, term_timeout_seconds: float = 10.0) -> None:
        self._term_timeout_seconds = term_timeout_seconds
        self._children: dict[int, subprocess.Popen[str]] = {}

    def start(
        self, command: tuple[str, ...], *, environment: dict[str, str]
    ) -> OwnedProcess:
        process_environment = _minimal_environment(environment)
        process: subprocess.Popen[str] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                env=process_environment,
                start_new_session=True,
            )
            executable = os.readlink(f"/proc/{process.pid}/exe")
            identity = OwnedProcess(
                process.pid,
                os.getpgid(process.pid),
                _read_proc_start_time(process.pid),
                executable,
            )
        except (OSError, ValueError) as error:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=self._term_timeout_seconds)
                except subprocess.SubprocessError:
                    pass
            raise OpenClawGateError("smoke process start failed") from error
        self._children[process.pid] = process
        return identity

    def stop(self, identity: OwnedProcess) -> None:
        process = self._children.pop(identity.pid, None)
        if process is None:
            raise OpenClawGateError("smoke process identity is not owned")
        if process.poll() is not None:
            if _pgid_members(identity.pgid):
                _terminate_process_group(process, identity, leader_reaped=True)
            return
        try:
            _terminate_process_group(
                process, identity, timeout_seconds=self._term_timeout_seconds
            )
        except (OSError, ProvisioningError) as error:
            raise OpenClawGateError("smoke cleanup identity changed") from error


def installer_command(
    driver_fd: int,
    installer_fd: int,
    *,
    prefix: Path,
    tarball: Path,
) -> tuple[str, ...]:
    tarball = Path(tarball)
    if (
        any(type(value) is not int or value < 3 for value in (driver_fd, installer_fd))
        or driver_fd == installer_fd
        or not tarball.is_absolute()
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: invalid installer fd")
    prefix = Path(prefix)
    return (
        "/usr/bin/bash",
        "--noprofile",
        "--norc",
        f"/proc/self/fd/{driver_fd}",
        str(installer_fd),
        "--prefix",
        str(prefix),
        "--version",
        f"file:{tarball}",
        "--node-version",
        NODE_VERSION,
        "--no-onboard",
        "--json",
    )


def npm_package_spec(tarball: Path) -> str:
    tarball = Path(tarball)
    if not tarball.is_absolute():
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: package path is not absolute")
    return f"openclaw@file:{tarball}"


def verify_registry_document(payload: bytes) -> RegistryDocument:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
        dist = value["dist"]
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH") from error
    if (
        value.get("version") != OPENCLAW_VERSION
        or not isinstance(dist, dict)
        or dist.get("tarball") != TARBALL_URL
        or dist.get("integrity") != OPENCLAW_INTEGRITY
        or not isinstance(dist.get("shasum"), str)
        or len(dist["shasum"]) != 40
        or any(character not in "0123456789abcdef" for character in dist["shasum"])
    ):
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    return RegistryDocument(
        OPENCLAW_VERSION,
        TARBALL_URL,
        OPENCLAW_INTEGRITY,
        dist["shasum"],
        hashlib.sha256(payload).hexdigest(),
    )


def compute_sri(path: Path) -> str:
    try:
        payload = Path(path).read_bytes()
    except OSError as error:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH") from error
    return "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode(
        "ascii"
    )


def verify_sri(path: Path, expected_integrity: str) -> str:
    if expected_integrity != OPENCLAW_INTEGRITY:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    observed = compute_sri(path)
    if observed != OPENCLAW_INTEGRITY or observed != expected_integrity:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    return observed


def _safe_relative(path: str) -> PurePosixPath:
    candidate = PurePosixPath(path)
    if (
        not path
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or candidate.as_posix() != path
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: unsafe path")
    return candidate


def _safe_symlink_target(owner: PurePosixPath, target: str) -> None:
    target_path = PurePosixPath(target)
    if target_path.is_absolute():
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: escaping symlink")
    depth = len(owner.parent.parts)
    for part in target_path.parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: escaping symlink")
        elif part not in {"", "."}:
            depth += 1


def build_tar_payload_manifest(path: Path) -> PayloadManifest:
    entries: dict[str, ManifestEntry] = {}
    seen: set[str] = set()
    try:
        archive = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    with archive:
        for member in archive.getmembers():
            normalized = member.name.rstrip("/")
            raw = _safe_relative(normalized)
            if not raw.parts or raw.parts[0] != "package":
                raise ProvisioningError(
                    "INSTALLED_PAYLOAD_MISMATCH: missing package prefix"
                )
            relative = PurePosixPath(*raw.parts[1:])
            if not relative.parts:
                continue
            relative_text = relative.as_posix()
            if relative_text in seen:
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: duplicate path")
            seen.add(relative_text)
            for depth in range(1, len(relative.parts)):
                parent = PurePosixPath(*relative.parts[:depth]).as_posix()
                entries.setdefault(
                    parent,
                    ManifestEntry(parent, "directory", None, None, True),
                )
            executable = bool(member.mode & 0o111)
            if member.isdir():
                existing = entries.get(relative_text)
                if existing is not None and existing.type != "directory":
                    raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
                entries[relative_text] = ManifestEntry(
                    relative_text, "directory", None, None, executable
                )
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
                digest = hashlib.sha256(source.read()).hexdigest()
                entries[relative_text] = ManifestEntry(
                    relative_text, "file", digest, None, executable
                )
            elif member.issym():
                _safe_symlink_target(relative, member.linkname)
                entries[relative_text] = ManifestEntry(
                    relative_text,
                    "symlink",
                    None,
                    member.linkname,
                    executable,
                )
            else:
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: unsupported type")
    return PayloadManifest.create(tuple(entries.values()))


def build_directory_manifest(
    root: Path, *, exclude_top_level: Sequence[str] = ()
) -> PayloadManifest:
    root = Path(root)
    excluded = frozenset(exclude_top_level)
    entries: list[ManifestEntry] = []
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[0] in excluded:
            continue
        metadata = path.lstat()
        relative_text = relative.as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            entries.append(
                ManifestEntry(
                    relative_text,
                    "directory",
                    None,
                    None,
                    bool(metadata.st_mode & 0o111),
                )
            )
        elif stat.S_ISREG(metadata.st_mode):
            entries.append(
                ManifestEntry(
                    relative_text,
                    "file",
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    None,
                    bool(metadata.st_mode & 0o111),
                )
            )
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(path)
            _safe_symlink_target(PurePosixPath(relative_text), target)
            entries.append(
                ManifestEntry(
                    relative_text,
                    "symlink",
                    None,
                    target,
                    bool(metadata.st_mode & 0o111),
                )
            )
        else:
            raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH: unsupported type")
    return PayloadManifest.create(entries)


def require_matching_payload(
    expected: PayloadManifest, actual: PayloadManifest
) -> None:
    if (
        type(expected) is not PayloadManifest
        or type(actual) is not PayloadManifest
        or expected.sha256 != actual.sha256
        or expected.entries != actual.entries
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")


def configuration_template_sha256(path: Path) -> str:
    try:
        payload = Path(path).read_bytes()
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if payload != CONFIG_TEMPLATE_CONTENT:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    return hashlib.sha256(payload).hexdigest()


def copy_pinned_configuration(source: Path, destination: Path) -> None:
    try:
        payload = Path(source).read_bytes()
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if payload != CONFIG_TEMPLATE_CONTENT:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    destination = Path(os.path.abspath(destination))
    _create_private_directory_no_symlinks(destination.parent)
    if destination.exists() or destination.is_symlink():
        try:
            if (
                not destination.is_file()
                or destination.is_symlink()
                or destination.read_bytes() != payload
                or stat.S_IMODE(destination.stat().st_mode) != 0o600
            ):
                raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        except OSError as error:
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
        return

    try:
        atomic_write_bytes_no_replace(
            destination,
            payload,
            mode=0o600,
            relative_to=destination.parent,
        )
    except (AtomicIOError, FileExistsError) as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error


def _create_private_directory_no_symlinks(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir(mode=0o700)
            except OSError as error:
                raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
            metadata = current.lstat()
        except OSError as error:
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")


def _require_reusable_configuration(paths: ProvisioningPaths) -> None:
    root = paths.configuration_root
    try:
        metadata = root.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        names = {entry.name for entry in root.iterdir()}
        if names != {paths.configuration.name, paths.state_dir.name}:
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        state_metadata = paths.state_dir.lstat()
        if (
            stat.S_ISLNK(state_metadata.st_mode)
            or not stat.S_ISDIR(state_metadata.st_mode)
            or state_metadata.st_uid != os.getuid()
            or stat.S_IMODE(state_metadata.st_mode) != 0o700
            or any(paths.state_dir.iterdir())
        ):
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        copy_pinned_configuration(paths.template, paths.configuration)
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error


def validate_provisioning_record(
    record: Mapping[str, object], schema_path: Path
) -> None:
    schema_path = Path(schema_path)
    try:
        digest = hashlib.sha256(schema_path.read_bytes()).hexdigest()
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if record.get("schema_sha256") != digest:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    try:
        contract = ContractSet(schema_path.parents[1])
        decision = contract.validate_document("openclaw-provisioning-v1", record)
    except Exception as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if not decision.ok:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")


def verify_provisioning_record_file(
    record_path: Path, paths: ProvisioningPaths
) -> dict[str, object]:
    """Revalidate pinned provisioning evidence without network access."""

    paths = _validate_provisioning_paths(paths)
    try:
        record = json.loads(_read_exact_regular_file(record_path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if not isinstance(record, dict):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    validate_provisioning_record(record, paths.schema)
    if record.get("status") != "PASS" or record.get("reason") != "OK":
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    mode = record.get("provisioning_mode")
    if mode not in {"FRESH_INSTALL", "VERIFIED_EXISTING_PREFIX"}:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    pins = record.get("pins")
    if (
        not isinstance(pins, dict)
        or pins.get("configuration_template_git_blob") != CONFIG_TEMPLATE_GIT_BLOB
        or pins.get("configuration_template_path") != str(paths.template)
        or pins.get("configuration_template_sha256")
        != configuration_template_sha256(paths.template)
    ):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    configuration_template_sha256(paths.template)
    _require_installed_configuration(paths.configuration)

    saved_downloads = _saved_download_directory(record_path)
    registry_path = saved_downloads / "registry.json"
    tarball_path = saved_downloads / "openclaw.tgz"
    installer_path = saved_downloads / "install-cli.sh"
    node_tarball_path = saved_downloads / "node-v24.15.0-linux-x64.tar.xz"
    registry_payload = _read_exact_regular_file(registry_path)
    saved_registry = verify_registry_document(registry_payload)
    recorded_registry = record.get("registry")
    if not isinstance(recorded_registry, dict) or recorded_registry != {
        "response_sha256": saved_registry.response_sha256,
        "version": saved_registry.version,
        "dist": {
            "tarball": saved_registry.tarball,
            "integrity": saved_registry.integrity,
            "shasum": saved_registry.shasum,
        },
    }:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    observed_sri = verify_sri(tarball_path, saved_registry.integrity)
    tarball_payload = _read_exact_regular_file(tarball_path)
    recorded_package = record.get("package")
    if not isinstance(recorded_package, dict) or recorded_package != {
        "tarball_sha256": hashlib.sha256(tarball_payload).hexdigest(),
        "tarball_sri": observed_sri,
        "byte_size": len(tarball_payload),
    }:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    _require_sha256(installer_path, INSTALLER_SHA256, "INSTALLER_PIN_MISMATCH")
    _require_sha256(node_tarball_path, NODE_TARBALL_SHA256, "INSTALLER_PIN_MISMATCH")
    expected_payload = build_tar_payload_manifest(tarball_path)

    prefix_manifest = build_directory_manifest(paths.prefix)
    target = record.get("target_prefix")
    if not isinstance(target, dict) or target != {
        "root": str(paths.prefix),
        "sha256": prefix_manifest.sha256,
        "entries": [entry.as_dict() for entry in prefix_manifest.entries],
    }:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    package_root = _find_package_root(paths.prefix)
    _package, declared_bin = _verify_installed_package(package_root)
    payload = build_directory_manifest(
        package_root, exclude_top_level=("node_modules",)
    )
    require_matching_payload(expected_payload, payload)
    recorded_payload = record.get("payload")
    if (
        not isinstance(recorded_payload, dict)
        or recorded_payload.get("matches") is not True
        or recorded_payload.get("actual_manifest_sha256") != payload.sha256
        or recorded_payload.get("expected_manifest_sha256") != expected_payload.sha256
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    cli_path = _require_launcher_binding(paths.prefix, package_root, declared_bin)
    node_path = _find_node_binary(paths.prefix)
    npm_cli_path, npm_version = _find_npm_cli(paths.prefix)
    _require_node_runtime_binding(
        node_tarball_path,
        node_path=node_path,
        npm_cli_path=npm_cli_path,
    )
    _require_install_driver(INSTALL_DRIVER_PATH)
    installer = record.get("installer")
    if not isinstance(installer, dict) or any(
        (
            installer.get("node_path") != str(node_path),
            installer.get("node_sha256") != _sha256_file(node_path),
            installer.get("npm_cli_path") != str(npm_cli_path),
            installer.get("npm_cli_sha256") != _sha256_file(npm_cli_path),
            installer.get("driver_path") != str(INSTALL_DRIVER_PATH),
            installer.get("driver_sha256") != INSTALL_DRIVER_SHA256,
            installer.get("openclaw_cli_path") != str(cli_path),
            installer.get("openclaw_cli_sha256")
            != _sha256_file_following_safe_symlink(cli_path, paths.prefix),
            pins.get("npm_version") != npm_version,
        )
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    if mode == "FRESH_INSTALL":
        if record.get("lineage") is not None:
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        _require_recorded_installer_argv(
            installer.get("argv"),
            prefix=paths.prefix,
            tarball=saved_downloads / "openclaw.tgz",
        )
    else:
        _verify_reuse_lineage(record, paths)
        _require_recorded_existing_argv(
            installer.get("argv"),
            prefix=paths.prefix,
            previous_record=paths.previous_record,
            recorded_lineage=record.get("lineage"),
        )
    configuration = record.get("configuration")
    if (
        not isinstance(configuration, dict)
        or configuration.get("template_sha256")
        != configuration_template_sha256(paths.template)
        or configuration.get("installed_sha256") != _sha256_file(paths.configuration)
        or configuration.get("valid") is not True
        or configuration.get("lint_findings") != []
    ):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    empty_observation = {"processes": [], "services": [], "listeners": []}
    if (
        record.get("before_observation") != empty_observation
        or record.get("after_observation") != empty_observation
    ):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    expected_device = record.get("quarantine_device")
    expected_mount_id = record.get("quarantine_mount_id")
    observed_bindings = {
        _nearest_existing_filesystem(path)
        for path in (Path(record_path).parent, paths.prefix, paths.configuration_root)
    }
    if (
        type(expected_device) is not int
        or type(expected_mount_id) is not int
        or observed_bindings != {(expected_device, expected_mount_id)}
    ):
        raise ProvisioningError("ATOMIC_WRITE_FAILED")
    return record


def _saved_download_directory(record_path: Path) -> Path:
    record_path = Path(os.path.abspath(record_path))
    parent = record_path.parent
    downloads = parent / "downloads"
    try:
        parent_metadata = parent.lstat()
        downloads_metadata = downloads.lstat()
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent.resolve(strict=True) != parent
            or stat.S_ISLNK(downloads_metadata.st_mode)
            or not stat.S_ISDIR(downloads_metadata.st_mode)
            or downloads.resolve(strict=True).parent != parent
        ):
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error
    return downloads


def _build_reuse_lineage(
    previous_record: Path, paths: ProvisioningPaths
) -> dict[str, object]:
    previous_record = Path(os.path.abspath(previous_record))
    if (
        previous_record == paths.record
        or previous_record.name != "openclaw-provisioning-v1.json"
    ):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    try:
        metadata = previous_record.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or previous_record.resolve(strict=True) != previous_record
        ):
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
        before_payload = _read_exact_regular_file(previous_record)
        parent = verify_provisioning_record_file(previous_record, paths)
        after_payload = _read_exact_regular_file(previous_record)
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error
    if (
        before_payload != after_payload
        or parent.get("provisioning_mode") != "FRESH_INSTALL"
    ):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    target = parent.get("target_prefix")
    if not isinstance(target, dict) or not isinstance(target.get("sha256"), str):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    return {
        "parent_record_path": str(previous_record),
        "parent_record_sha256": hashlib.sha256(before_payload).hexdigest(),
        "parent_run_id": parent["run_id"],
        "parent_schema_sha256": parent["schema_sha256"],
        "parent_target_prefix_sha256": target["sha256"],
    }


def _verify_reuse_lineage(
    record: Mapping[str, object], paths: ProvisioningPaths
) -> None:
    lineage = record.get("lineage")
    if not isinstance(lineage, dict):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    parent_path = lineage.get("parent_record_path")
    if not isinstance(parent_path, str) or not parent_path.startswith("/"):
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    expected = _build_reuse_lineage(Path(parent_path), paths)
    if lineage != expected:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")


def _require_installed_configuration(path: Path) -> None:
    try:
        metadata = Path(path).lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or Path(path).read_bytes() != CONFIG_TEMPLATE_CONTENT
        ):
            raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH") from error


class ProvisioningRuntime:
    """Execute the pinned, fail-closed OpenClaw provisioning transaction."""

    def __init__(
        self,
        *,
        observer: LifecycleObserver,
        runner: CommandRunner,
        fetcher: ArtifactFetcher,
    ) -> None:
        self._observer = observer
        self._runner = runner
        self._fetcher = fetcher

    def provision(self, paths: ProvisioningPaths) -> dict[str, object]:
        paths = _validate_provisioning_paths(paths)
        _require_install_driver(INSTALL_DRIVER_PATH)
        schema_payload = _read_exact_regular_file(paths.schema)
        schema_sha256 = hashlib.sha256(schema_payload).hexdigest()
        template_sha256 = configuration_template_sha256(paths.template)
        if paths.prefix.is_symlink():
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
        quarantine_device, quarantine_mount_id = _require_quarantine_binding(paths)
        started_at = _utc_now()
        before = LifecycleObservation((), (), ())
        preflight_completed = False
        try:
            before = self._observer.observe()
            preflight_completed = True
            return self._provision_pass(
                paths,
                schema_sha256=schema_sha256,
                template_sha256=template_sha256,
                started_at=started_at,
                before=before,
                quarantine_device=quarantine_device,
                quarantine_mount_id=quarantine_mount_id,
            )
        except BaseException as error:
            reason = _provisioning_reason(error)
            try:
                after = self._observer.observe()
            except BaseException:
                after = None
                reason = "TOOL_RUNTIME_ERROR"
            if after is not None and after.has_openclaw_state:
                reason = "PREEXISTING_OPENCLAW"
            if preflight_completed:
                _publish_failed_provisioning_record(
                    paths,
                    schema_sha256=schema_sha256,
                    template_sha256=template_sha256,
                    started_at=started_at,
                    before=before,
                    after=after,
                    reason=reason,
                    quarantine_device=quarantine_device,
                    quarantine_mount_id=quarantine_mount_id,
                )
            if isinstance(error, (KeyboardInterrupt, SystemExit, _ProvisioningSignal)):
                raise
            raise ProvisioningError(reason) from error

    def _provision_pass(
        self,
        paths: ProvisioningPaths,
        *,
        schema_sha256: str,
        template_sha256: str,
        started_at: str,
        before: LifecycleObservation,
        quarantine_device: int,
        quarantine_mount_id: int,
    ) -> dict[str, object]:
        if before.has_openclaw_state:
            raise ProvisioningError("PREEXISTING_OPENCLAW")

        configuration_preexisting = (
            paths.configuration_root.exists() or paths.configuration_root.is_symlink()
        )
        if configuration_preexisting:
            _require_reusable_configuration(paths)

        if paths.prefix.is_symlink():
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
        preexisting_prefix = paths.prefix.exists()
        if preexisting_prefix and not paths.prefix.is_dir():
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
        lineage: dict[str, object] | None = None
        if preexisting_prefix:
            if paths.previous_record is None:
                raise ProvisioningError("INSTALLER_PIN_MISMATCH")
            lineage = _build_reuse_lineage(paths.previous_record, paths)
            existing_package = _find_package_root(paths.prefix)
            _package, existing_declared = _verify_installed_package(existing_package)
            existing_cli = _require_launcher_binding(
                paths.prefix, existing_package, existing_declared
            )
            existing_node = _find_node_binary(paths.prefix)
            existing_entry = (existing_package / existing_declared).resolve(strict=True)
            lifecycle = OpenClawGate(
                observer=self._observer, runner=self._runner
            ).preexisting(
                existing_cli,
                node_path=existing_node,
                entry_path=existing_entry,
            )
            if lifecycle.status != "PASS":
                raise ProvisioningError(lifecycle.reason)

        _create_private_directory_no_symlinks(paths.output_dir)
        _create_private_directory_no_symlinks(paths.download_dir)
        registry_path = paths.download_dir / "registry.json"
        tarball_path = paths.download_dir / "openclaw.tgz"
        installer_path = paths.download_dir / "install-cli.sh"
        node_tarball_path = paths.download_dir / "node-v24.15.0-linux-x64.tar.xz"

        self._fetcher.fetch(REGISTRY_URL, registry_path)
        registry = verify_registry_document(_read_exact_regular_file(registry_path))
        self._fetcher.fetch(TARBALL_URL, tarball_path)
        observed_sri = verify_sri(tarball_path, registry.integrity)
        tarball_sha256 = hashlib.sha256(
            _read_exact_regular_file(tarball_path)
        ).hexdigest()
        tarball_path.chmod(0o400)
        self._fetcher.fetch(INSTALLER_URL, installer_path)
        _require_sha256(installer_path, INSTALLER_SHA256, "INSTALLER_PIN_MISMATCH")
        installer_sha256 = INSTALLER_SHA256
        self._fetcher.fetch(NODE_TARBALL_URL, node_tarball_path)
        _require_sha256(
            node_tarball_path, NODE_TARBALL_SHA256, "INSTALLER_PIN_MISMATCH"
        )
        installer_path.chmod(0o700)

        expected_payload = build_tar_payload_manifest(tarball_path)
        prefix_identity: tuple[int, int] | None = None
        configuration_identity: tuple[int, int] | None = None
        install_argv: tuple[str, ...]
        try:
            if preexisting_prefix:
                install_argv = (
                    "verify-existing-prefix",
                    str(paths.prefix),
                    str(paths.previous_record),
                )
            else:
                _create_private_directory_no_symlinks(paths.prefix)
                prefix_metadata = paths.prefix.lstat()
                prefix_identity = (prefix_metadata.st_dev, prefix_metadata.st_ino)
                _install_verified_node_tarball(node_tarball_path, paths.prefix)
                _verify_preinstalled_node_runtime(self._runner, paths.prefix)
                npm_cache = paths.output_dir / "npm-cache"
                _create_private_directory_no_symlinks(npm_cache)
                driver_fd = -1
                installer_fd = -1
                try:
                    driver_fd = _create_sealed_file_fd(
                        INSTALL_DRIVER_PATH,
                        INSTALL_DRIVER_SHA256,
                        label="openclaw-driver",
                    )
                    installer_fd = _create_sealed_file_fd(
                        installer_path,
                        INSTALLER_SHA256,
                        label="openclaw-installer",
                    )
                    _require_private_verified_input(
                        tarball_path,
                        parent=paths.download_dir,
                        expected_sha256=tarball_sha256,
                    )
                    if verify_sri(tarball_path, registry.integrity) != observed_sri:
                        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
                    install_argv = installer_command(
                        driver_fd,
                        installer_fd,
                        prefix=paths.prefix,
                        tarball=tarball_path.resolve(strict=True),
                    )
                    result = self._runner.run(
                        install_argv,
                        environment={
                            "HOME": str(paths.prefix.parent),
                            "OPENCLAW_PREFIX": str(paths.prefix),
                            "OPENCLAW_NO_ONBOARD": "1",
                            "OPENCLAW_NODE_VERSION": NODE_VERSION,
                            "OPENCLAW_VERSION": (
                                f"file:{tarball_path.resolve(strict=True)}"
                            ),
                            "OPENCLAW_INSTALL_METHOD": "npm",
                            "NPM_CONFIG_USERCONFIG": "/dev/null",
                            "NPM_CONFIG_GLOBALCONFIG": "/dev/null",
                            "NPM_CONFIG_CACHE": str(npm_cache),
                            "HOLOAGENT0_EXPECTED_OPENCLAW_VERSION": OPENCLAW_VERSION,
                            "HOLOAGENT0_EXPECTED_OPENCLAW_TARBALL": str(
                                tarball_path.resolve(strict=True)
                            ),
                        },
                        pass_fds=(driver_fd, installer_fd),
                    )
                finally:
                    for descriptor in (driver_fd, installer_fd):
                        if descriptor >= 0:
                            os.close(descriptor)
                if result.exit_code != 0 or not _installer_reported_success(
                    result.stdout
                ):
                    raise ProvisioningError("TOOL_RUNTIME_ERROR")

            package_root = _find_package_root(paths.prefix)
            _package_json, declared_bin = _verify_installed_package(package_root)
            actual_payload = build_directory_manifest(
                package_root, exclude_top_level=("node_modules",)
            )
            require_matching_payload(expected_payload, actual_payload)
            if not preexisting_prefix:
                _install_reviewed_launcher(paths.prefix, package_root, declared_bin)
            cli_path = _require_launcher_binding(
                paths.prefix, package_root, declared_bin
            )
            node_path = _find_node_binary(paths.prefix)
            npm_cli_path, npm_version = _find_npm_cli(paths.prefix)
            _require_node_runtime_binding(
                node_tarball_path,
                node_path=node_path,
                npm_cli_path=npm_cli_path,
            )
            entry_path = (package_root / declared_bin).resolve(strict=True)
            version_result = self._runner.run(
                (str(node_path), str(entry_path), "--version"),
                environment={"HOME": str(paths.prefix.parent)},
            )
            if (
                version_result.exit_code != 0
                or version_result.stdout.strip() != OPENCLAW_VERSION
            ):
                raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")

            if not configuration_preexisting:
                _create_private_directory_no_symlinks(paths.configuration_root)
                configuration_metadata = paths.configuration_root.lstat()
                configuration_identity = (
                    configuration_metadata.st_dev,
                    configuration_metadata.st_ino,
                )
            copy_pinned_configuration(paths.template, paths.configuration)
            _create_private_directory_no_symlinks(paths.state_dir)
            token = secrets.token_urlsafe(32)
            if len(token) < 43:
                raise ProvisioningError("OPENCLAW_CONFIG_INVALID")
            gate = OpenClawGate(observer=self._observer, runner=self._runner)
            read_only = gate.validate_read_only(
                cli_path=cli_path,
                config_path=paths.configuration,
                state_dir=paths.state_dir,
                token=token,
                preflight_observation=before,
                node_path=node_path,
                entry_path=entry_path,
            )
            if read_only.status != "PASS" or read_only.observation is None:
                raise ProvisioningError(read_only.reason)
            after = read_only.observation
            _require_reusable_configuration(paths)

            prefix_manifest = build_directory_manifest(paths.prefix)
            record: dict[str, object] = {
                "schema_version": "holoagent0.openclaw.provisioning.v1",
                "schema_sha256": schema_sha256,
                "run_id": uuid.uuid4().hex,
                "started_at": started_at,
                "ended_at": _utc_now(),
                "hostname": platform.node() or "unknown",
                "architecture": platform.machine() or "unknown",
                "status": "PASS",
                "reason": "OK",
                "provisioning_mode": (
                    "VERIFIED_EXISTING_PREFIX"
                    if preexisting_prefix
                    else "FRESH_INSTALL"
                ),
                "lineage": lineage,
                "quarantine_device": quarantine_device,
                "quarantine_mount_id": quarantine_mount_id,
                "pins": {
                    "package_name": "openclaw",
                    "package_version": OPENCLAW_VERSION,
                    "node_version": NODE_VERSION,
                    "node_tarball_sha256": NODE_TARBALL_SHA256,
                    "npm_version": npm_version,
                    "installer_path": INSTALLER_URL,
                    "installer_sha256": installer_sha256,
                    "registry_document_url": REGISTRY_URL,
                    "configuration_template_path": str(paths.template),
                    "configuration_template_git_blob": CONFIG_TEMPLATE_GIT_BLOB,
                    "configuration_template_sha256": template_sha256,
                },
                "registry": {
                    "response_sha256": registry.response_sha256,
                    "version": registry.version,
                    "dist": {
                        "tarball": registry.tarball,
                        "integrity": registry.integrity,
                        "shasum": registry.shasum,
                    },
                },
                "package": {
                    "tarball_sha256": tarball_sha256,
                    "tarball_sri": observed_sri,
                    "byte_size": tarball_path.stat().st_size,
                },
                "payload": {
                    "expected_manifest_sha256": expected_payload.sha256,
                    "actual_manifest_sha256": actual_payload.sha256,
                    "matches": True,
                },
                "installer": {
                    "node_path": str(node_path),
                    "node_sha256": _sha256_file(node_path),
                    "npm_cli_path": str(npm_cli_path),
                    "npm_cli_sha256": _sha256_file(npm_cli_path),
                    "driver_path": str(INSTALL_DRIVER_PATH),
                    "driver_sha256": INSTALL_DRIVER_SHA256,
                    "openclaw_cli_path": str(cli_path),
                    "openclaw_cli_sha256": _sha256_file_following_safe_symlink(
                        cli_path, paths.prefix
                    ),
                    "argv": list(install_argv),
                },
                "target_prefix": {
                    "root": str(paths.prefix),
                    "sha256": prefix_manifest.sha256,
                    "entries": [entry.as_dict() for entry in prefix_manifest.entries],
                },
                "configuration": {
                    "template_sha256": template_sha256,
                    "installed_sha256": _sha256_file(paths.configuration),
                    "valid": True,
                    "lint_findings": [],
                },
                "before_observation": _observation_document(before),
                "after_observation": _observation_document(after),
            }
            if token in json.dumps(record, sort_keys=True):
                raise ProvisioningError("OPENCLAW_CONFIG_MISMATCH")
            validate_provisioning_record(record, paths.schema)
            try:
                encoded_record = (
                    json.dumps(
                        record,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                atomic_write_bytes_no_replace(
                    paths.record,
                    encoded_record,
                    mode=0o600,
                    relative_to=paths.output_dir,
                )
            except (AtomicIOError, FileExistsError) as error:
                raise ProvisioningError("ATOMIC_WRITE_FAILED") from error
            return record
        except BaseException:
            if prefix_identity is not None:
                _quarantine_owned_directory(
                    paths,
                    paths.prefix,
                    prefix_identity,
                    label="prefix",
                )
            if configuration_identity is not None:
                _quarantine_owned_directory(
                    paths,
                    paths.configuration_root,
                    configuration_identity,
                    label="configuration",
                )
            raise


class SmokeRuntime:
    """Run one separately authorized authenticated loopback smoke session."""

    def __init__(
        self,
        *,
        observer: LifecycleObserver,
        runner: CommandRunner,
        processes: SmokeProcessController,
    ) -> None:
        self._observer = observer
        self._runner = runner
        self._processes = processes

    def run(
        self,
        *,
        cli_path: Path,
        config_path: Path,
        state_dir: Path,
        token: str,
        port: int,
        node_path: Path | None = None,
        entry_path: Path | None = None,
    ) -> None:
        if not isinstance(token, str) or len(token) < 43:
            raise OpenClawGateError("smoke authentication token is invalid")
        if type(port) is not int or not 1024 <= port <= 65535:
            raise OpenClawGateError("smoke loopback port is invalid")
        before = self._observer.observe()
        if before.has_openclaw_state or any(
            listener.port == port for listener in before.listeners
        ):
            raise OpenClawGateError("smoke port or lifecycle is not clean")
        environment = {
            "HOME": str(Path(state_dir).parent),
            "OPENCLAW_CONFIG_PATH": str(config_path),
            "OPENCLAW_STATE_DIR": str(state_dir),
            "OPENCLAW_GATEWAY_TOKEN": token,
        }
        command = (
            *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
            "gateway",
            "run",
            "--bind",
            "loopback",
            "--port",
            str(port),
        )
        identity = self._processes.start(command, environment=environment)
        verified_identity = False
        primary_error: BaseException | None = None
        try:
            _wait_for_smoke_readiness(
                self._observer,
                identity=identity,
                port=port,
                timeout_seconds=10.0,
            )
            verified_identity = True
            status = self._runner.run(
                (
                    *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
                    "gateway",
                    "status",
                    "--deep",
                    "--require-rpc",
                    "--json",
                ),
                environment=environment,
            )
            value = _command_json(status)
            if value is None or not _smoke_status_is_ready(value):
                raise OpenClawGateError("smoke status failed")
        except BaseException as error:
            primary_error = error
        cleanup_error: BaseException | None = None
        try:
            self._processes.stop(identity)
            after = self._observer.observe()
            if after.has_openclaw_state:
                raise OpenClawGateError("smoke cleanup left OpenClaw state")
        except BaseException as error:
            cleanup_error = error
        if cleanup_error is not None:
            raise OpenClawSafetyError("smoke safety cleanup failed") from cleanup_error
        if primary_error is not None:
            if not verified_identity:
                raise OpenClawSafetyError(
                    "smoke process identity changed"
                ) from primary_error
            raise primary_error


def _validate_provisioning_paths(paths: ProvisioningPaths) -> ProvisioningPaths:
    if type(paths) is not ProvisioningPaths:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: invalid paths")
    absolute_fields = (
        paths.output_dir,
        paths.download_dir,
        paths.prefix,
        paths.configuration_root,
        paths.configuration,
        paths.state_dir,
        paths.record,
        paths.schema,
        paths.template,
        paths.quarantine_dir,
        *((paths.previous_record,) if paths.previous_record is not None else ()),
    )
    if any(not Path(value).is_absolute() for value in absolute_fields):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: paths must be absolute")
    filesystem_root = Path(paths.output_dir.anchor)
    if any(
        value == filesystem_root
        for value in (paths.output_dir, paths.prefix, paths.configuration_root)
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: broad path is prohibited")
    if (
        paths.download_dir.parent != paths.output_dir
        or paths.record.parent != paths.output_dir
        or paths.quarantine_dir.parent != paths.output_dir
        or paths.configuration.parent != paths.configuration_root
        or paths.state_dir.parent != paths.configuration_root
        or len(
            {
                paths.output_dir,
                paths.prefix,
                paths.configuration_root,
            }
        )
        != 3
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: path layout is invalid")
    authority_roots = (paths.output_dir, paths.prefix, paths.configuration_root)
    if any(
        _paths_overlap(left, right)
        for index, left in enumerate(authority_roots)
        for right in authority_roots[index + 1 :]
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH: paths overlap")
    return paths


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _read_exact_regular_file(path: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            Path(path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProvisioningError("INSTALLER_PIN_MISMATCH: non-regular artifact")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError(
            "INSTALLER_PIN_MISMATCH: artifact unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


_LINUX_MFD_CLOEXEC = 0x0001
_LINUX_MFD_ALLOW_SEALING = 0x0002
_LINUX_F_ADD_SEALS = 1033
_LINUX_F_GET_SEALS = 1034
_INSTALLER_MEMFD_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


def _create_sealed_file_fd(path: Path, expected_sha256: str, *, label: str) -> int:
    payload = _read_exact_regular_file(path)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
        or hashlib.sha256(payload).hexdigest() != expected_sha256
        or not re.fullmatch(r"[a-z0-9-]{1,64}", label)
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    descriptor = -1
    try:
        descriptor = _memfd_create(
            f"holoagent0-{label}",
            _LINUX_MFD_CLOEXEC | _LINUX_MFD_ALLOW_SEALING,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short memfd write")
            offset += written
        fcntl.fcntl(descriptor, _LINUX_F_ADD_SEALS, _INSTALLER_MEMFD_SEALS)
        observed_seals = fcntl.fcntl(descriptor, _LINUX_F_GET_SEALS)
        if observed_seals & _INSTALLER_MEMFD_SEALS != _INSTALLER_MEMFD_SEALS:
            raise OSError("installer memfd seals are incomplete")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except (AttributeError, OSError) as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error


def _create_sealed_installer_fd(path: Path) -> int:
    return _create_sealed_file_fd(
        path,
        INSTALLER_SHA256,
        label="openclaw-installer",
    )


def _require_recorded_installer_argv(
    argv: object, *, prefix: Path, tarball: Path
) -> None:
    if not isinstance(argv, list) or any(type(value) is not str for value in argv):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    if len(argv) != 13:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    driver_match = re.fullmatch(r"/proc/self/fd/([0-9]+)", argv[3])
    installer_match = re.fullmatch(r"[0-9]+", argv[4])
    if driver_match is None or installer_match is None:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    driver_fd = int(driver_match.group(1))
    installer_fd = int(installer_match.group(0))
    expected = [
        "/usr/bin/bash",
        "--noprofile",
        "--norc",
        argv[3],
        argv[4],
        "--prefix",
        str(prefix),
        "--version",
        f"file:{tarball}",
        "--node-version",
        NODE_VERSION,
        "--no-onboard",
        "--json",
    ]
    if (
        driver_fd < 3
        or installer_fd < 3
        or driver_fd == installer_fd
        or argv != expected
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")


def _require_recorded_existing_argv(
    argv: object,
    *,
    prefix: Path,
    previous_record: Path | None,
    recorded_lineage: object,
) -> None:
    if not isinstance(recorded_lineage, dict):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    lineage_path = recorded_lineage.get("parent_record_path")
    if previous_record is not None and str(previous_record) != lineage_path:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    expected = ["verify-existing-prefix", str(prefix), lineage_path]
    if (
        not isinstance(lineage_path, str)
        or not isinstance(argv, list)
        or any(type(value) is not str for value in argv)
        or argv != expected
    ):
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")


def _require_private_verified_input(
    path: Path, *, parent: Path, expected_sha256: str
) -> None:
    try:
        parent_metadata = parent.lstat()
        path_metadata = path.lstat()
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.getuid()
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or path.parent != parent
            or stat.S_ISLNK(path_metadata.st_mode)
            or not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_uid != os.getuid()
            or stat.S_IMODE(path_metadata.st_mode) != 0o400
            or _require_sha256(path, expected_sha256, "REGISTRY_INTEGRITY_MISMATCH")
            != expected_sha256
        ):
            raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH")
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("REGISTRY_INTEGRITY_MISMATCH") from error


def _memfd_create(name: str, flags: int) -> int:
    try:
        function = ctypes.CDLL(None, use_errno=True).memfd_create
    except AttributeError as error:
        raise OSError("memfd_create is unavailable") from error
    function.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    descriptor = function(name.encode("ascii"), flags)
    if descriptor < 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    return descriptor


def _require_sha256(path: Path, expected: str, reason: str) -> str:
    observed = hashlib.sha256(_read_exact_regular_file(path)).hexdigest()
    if observed != expected:
        raise ProvisioningError(reason)
    return observed


def _require_install_driver(path: Path) -> None:
    try:
        metadata = Path(path).lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o644
        ):
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error
    _require_sha256(path, INSTALL_DRIVER_SHA256, "INSTALLER_PIN_MISMATCH")


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error


def _sha256_file_following_safe_symlink(path: Path, root: Path) -> str:
    try:
        resolved = Path(path).resolve(strict=True)
        resolved.relative_to(Path(root).resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    return _sha256_file(resolved)


def _installer_reported_success(output: str) -> bool:
    values: list[dict[str, object]] = []
    for line in output.splitlines() or (output,):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    matching = [
        value
        for value in values
        if value.get("event") == "holoagent0-reviewed-subset"
        and value.get("ok") is True
        and value.get("version") == OPENCLAW_VERSION
    ]
    return len(matching) == 1


def _find_package_root(prefix: Path) -> Path:
    candidates = (
        prefix / "lib/node_modules/openclaw",
        prefix / "node/lib/node_modules/openclaw",
        prefix / f"tools/node-v{NODE_VERSION}/lib/node_modules/openclaw",
    )
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            return candidate
    raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")


def _verify_installed_package(package_root: Path) -> tuple[dict[str, object], str]:
    try:
        value = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProvisioningError("OPENCLAW_VERSION_MISMATCH") from error
    if not isinstance(value, dict) or value.get("version") != OPENCLAW_VERSION:
        raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")
    declared = value.get("bin")
    if isinstance(declared, str):
        bin_path = declared
    elif isinstance(declared, dict) and isinstance(declared.get("openclaw"), str):
        bin_path = declared["openclaw"]
    else:
        raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")
    relative = _safe_relative(bin_path)
    target = package_root / relative
    try:
        target.resolve(strict=True).relative_to(package_root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    if not target.is_file():
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    return value, relative.as_posix()


def _find_cli(prefix: Path) -> Path | None:
    candidates = (
        prefix / "bin/openclaw",
        prefix / f"tools/node-v{NODE_VERSION}/bin/openclaw",
        prefix / "node/bin/openclaw",
    )
    return next((candidate for candidate in candidates if candidate.exists()), None)


def _require_launcher_binding(prefix: Path, package_root: Path, declared: str) -> Path:
    cli = _find_cli(prefix)
    if cli is None:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
    declared_target = (package_root / declared).resolve(strict=True)
    try:
        if cli.is_symlink():
            if cli.resolve(strict=True) != declared_target:
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
        else:
            payload = cli.read_bytes()
            expected_wrapper = (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                f'exec "{prefix}/tools/node/bin/node" '
                f'"{declared_target}" "$@"\n'
            ).encode("utf-8")
            if payload != expected_wrapper or not os.access(cli, os.X_OK):
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
        cli.resolve(strict=True).relative_to(prefix.resolve(strict=True))
    except ProvisioningError:
        raise
    except (OSError, ValueError) as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    return cli


def _install_reviewed_launcher(prefix: Path, package_root: Path, declared: str) -> Path:
    cli = prefix / "bin/openclaw"
    declared_target = (package_root / declared).resolve(strict=True)
    reviewed = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec "{prefix}/tools/node/bin/node" '
        f'"{declared_target}" "$@"\n'
    ).encode("utf-8")
    try:
        if cli.exists() or cli.is_symlink():
            metadata = cli.lstat()
            if not (
                stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
            ) or cli.parent.resolve(strict=True) != (prefix / "bin").resolve(
                strict=True
            ):
                raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH")
            cli.unlink()
        atomic_write_bytes_no_replace(
            cli,
            reviewed,
            mode=0o700,
            relative_to=prefix,
        )
    except ProvisioningError:
        raise
    except (AtomicIOError, FileExistsError, OSError) as error:
        raise ProvisioningError("INSTALLED_PAYLOAD_MISMATCH") from error
    return cli


def _find_node_binary(prefix: Path) -> Path:
    candidates = (
        prefix / "node/bin/node",
        prefix / f"tools/node-v{NODE_VERSION}/bin/node",
        prefix / "tools/node/bin/node",
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve(strict=True)
    raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")


def _find_npm_cli(prefix: Path) -> tuple[Path, str]:
    roots = (
        prefix / "node/lib/node_modules/npm",
        prefix / f"tools/node-v{NODE_VERSION}/lib/node_modules/npm",
        prefix / "tools/node/lib/node_modules/npm",
    )
    for root in roots:
        cli = root / "bin/npm-cli.js"
        metadata = root / "package.json"
        if not cli.is_file() or not metadata.is_file():
            continue
        try:
            value = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        version = value.get("version") if isinstance(value, dict) else None
        if isinstance(version, str) and version:
            return cli.resolve(strict=True), version
    raise ProvisioningError("OPENCLAW_VERSION_MISMATCH")


def _require_node_runtime_binding(
    tarball: Path, *, node_path: Path, npm_cli_path: Path
) -> None:
    expected: dict[str, str] = {}
    try:
        with tarfile.open(tarball, "r:xz") as archive:
            for member in archive.getmembers():
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2:
                    continue
                relative = PurePosixPath(*parts[1:]).as_posix()
                if relative not in {
                    "bin/node",
                    "lib/node_modules/npm/bin/npm-cli.js",
                }:
                    continue
                if not member.isfile():
                    raise ProvisioningError("INSTALLER_PIN_MISMATCH")
                source = archive.extractfile(member)
                if source is None:
                    raise ProvisioningError("INSTALLER_PIN_MISMATCH")
                expected[relative] = hashlib.sha256(source.read()).hexdigest()
    except ProvisioningError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error
    if set(expected) != {
        "bin/node",
        "lib/node_modules/npm/bin/npm-cli.js",
    }:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    if (
        _sha256_file(node_path) != expected["bin/node"]
        or _sha256_file(npm_cli_path) != expected["lib/node_modules/npm/bin/npm-cli.js"]
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")


def _install_verified_node_tarball(tarball: Path, prefix: Path) -> None:
    tools = prefix / "tools"
    node_directory = tools / f"node-v{NODE_VERSION}"
    node_link = tools / "node"
    if node_directory.exists() or node_link.exists() or node_link.is_symlink():
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    _create_private_directory_no_symlinks(tools)
    temporary = tools / f".node-extract-{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o700)
    archive_root = f"node-v{NODE_VERSION}-linux-x64"
    try:
        with tarfile.open(tarball, "r:xz") as archive:
            seen: set[str] = set()
            for member in archive.getmembers():
                normalized = member.name.rstrip("/")
                raw = _safe_relative(normalized)
                if not raw.parts or raw.parts[0] != archive_root:
                    raise ProvisioningError("INSTALLER_PIN_MISMATCH")
                relative = PurePosixPath(*raw.parts[1:])
                relative_text = relative.as_posix() if relative.parts else ""
                if relative_text in seen:
                    raise ProvisioningError("INSTALLER_PIN_MISMATCH")
                seen.add(relative_text)
                if member.issym():
                    _safe_symlink_target(relative, member.linkname)
                elif member.islnk():
                    link = _safe_relative(member.linkname)
                    if not link.parts or link.parts[0] != archive_root:
                        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
                elif not (member.isdir() or member.isfile()):
                    raise ProvisioningError("INSTALLER_PIN_MISMATCH")
            archive.extractall(temporary)
        extracted = temporary / archive_root
        if not extracted.is_dir() or extracted.is_symlink():
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
        os.replace(extracted, node_directory)
        node_link.symlink_to(node_directory.name, target_is_directory=True)
        directory_fd = os.open(
            tools,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except ProvisioningError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def _verify_preinstalled_node_runtime(runner: CommandRunner, prefix: Path) -> None:
    node = prefix / f"tools/node-v{NODE_VERSION}/bin/node"
    npm_cli = prefix / f"tools/node-v{NODE_VERSION}/lib/node_modules/npm/bin/npm-cli.js"
    environment = {"HOME": str(prefix.parent)}
    version = runner.run((str(node), "--version"), environment=environment)
    if version.exit_code != 0 or version.stdout.strip() != f"v{NODE_VERSION}":
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    npm_version = runner.run(
        (str(node), str(npm_cli), "--version"), environment=environment
    )
    if npm_version.exit_code != 0 or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", npm_version.stdout.strip()
    ):
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")
    sqlite_check = runner.run(
        (
            str(node),
            "-e",
            "const {DatabaseSync}=require('node:sqlite');"
            "const d=new DatabaseSync(':memory:');"
            "d.prepare('SELECT 1').get();d.close();process.stdout.write('ok')",
        ),
        environment=environment,
    )
    if sqlite_check.exit_code != 0 or sqlite_check.stdout != "ok":
        raise ProvisioningError("INSTALLER_PIN_MISMATCH")


def _observation_document(observation: LifecycleObservation) -> dict[str, object]:
    return {
        "processes": [
            {
                "pid": process.pid,
                "start_time_ticks": process.start_time_ticks,
                "executable": process.executable,
            }
            for process in observation.processes
        ],
        "services": [
            {"name": service.name, "state": service.state}
            for service in observation.services
        ],
        "listeners": [
            {
                "address": listener.address,
                "port": listener.port,
                "pid": listener.pid,
            }
            for listener in observation.listeners
        ],
    }


def _after_observation_document(
    observation: LifecycleObservation | None,
) -> dict[str, object]:
    if observation is None:
        return {"state": "UNAVAILABLE", "reason": "TOOL_RUNTIME_ERROR"}
    return _observation_document(observation)


_PROVISIONING_REASONS = frozenset(
    {
        "PREEXISTING_OPENCLAW",
        "INSTALLER_PIN_MISMATCH",
        "REGISTRY_INTEGRITY_MISMATCH",
        "INSTALLED_PAYLOAD_MISMATCH",
        "OPENCLAW_VERSION_MISMATCH",
        "OPENCLAW_CONFIG_MISMATCH",
        "OPENCLAW_CONFIG_INVALID",
        "OPENCLAW_LINT_FINDING",
        "TOOL_RUNTIME_ERROR",
        "ATOMIC_WRITE_FAILED",
    }
)


def _provisioning_reason(error: BaseException) -> str:
    if isinstance(error, ProvisioningError):
        reason = str(error).split(":", 1)[0]
        if reason in _PROVISIONING_REASONS:
            return reason
    return "TOOL_RUNTIME_ERROR"


def _publish_failed_provisioning_record(
    paths: ProvisioningPaths,
    *,
    schema_sha256: str,
    template_sha256: str,
    started_at: str,
    before: LifecycleObservation,
    after: LifecycleObservation | None,
    reason: str,
    quarantine_device: int,
    quarantine_mount_id: int,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema_version": "holoagent0.openclaw.provisioning.v1",
        "schema_sha256": schema_sha256,
        "run_id": uuid.uuid4().hex,
        "started_at": started_at,
        "ended_at": _utc_now(),
        "hostname": platform.node() or "unknown",
        "architecture": platform.machine() or "unknown",
        "status": "FAIL",
        "reason": reason,
        "provisioning_mode": (
            "VERIFIED_EXISTING_PREFIX"
            if paths.previous_record is not None and paths.prefix.exists()
            else "FRESH_INSTALL"
        ),
        "lineage": None,
        "quarantine_device": quarantine_device,
        "quarantine_mount_id": quarantine_mount_id,
        "pins": {
            "package_name": "openclaw",
            "package_version": OPENCLAW_VERSION,
            "node_version": NODE_VERSION,
            "node_tarball_sha256": NODE_TARBALL_SHA256,
            "npm_version": None,
            "installer_path": INSTALLER_URL,
            "installer_sha256": INSTALLER_SHA256,
            "registry_document_url": REGISTRY_URL,
            "configuration_template_path": str(paths.template),
            "configuration_template_git_blob": CONFIG_TEMPLATE_GIT_BLOB,
            "configuration_template_sha256": template_sha256,
        },
        "registry": None,
        "package": None,
        "payload": None,
        "installer": None,
        "target_prefix": {
            "root": str(paths.prefix),
            "sha256": None,
            "entries": [],
        },
        "configuration": {
            "template_sha256": template_sha256,
            "installed_sha256": None,
            "valid": False,
            "lint_findings": [],
        },
        "before_observation": _observation_document(before),
        "after_observation": _after_observation_document(after),
    }
    validate_provisioning_record(record, paths.schema)
    _create_private_directory_no_symlinks(paths.output_dir)
    try:
        atomic_write_bytes_no_replace(
            paths.record,
            json.dumps(
                record,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n",
            mode=0o600,
            relative_to=paths.output_dir,
        )
    except (AtomicIOError, FileExistsError) as error:
        raise ProvisioningError("ATOMIC_WRITE_FAILED") from error
    return record


def _nearest_existing_directory(path: Path) -> tuple[Path, os.stat_result]:
    candidate = Path(os.path.abspath(path))
    while True:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            parent = candidate.parent
            if parent == candidate:
                raise ProvisioningError("ATOMIC_WRITE_FAILED")
            candidate = parent
            continue
        except OSError as error:
            raise ProvisioningError("ATOMIC_WRITE_FAILED") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise ProvisioningError("ATOMIC_WRITE_FAILED")
        return candidate, metadata


def _decode_mountinfo_path(value: str) -> str:
    try:
        return re.sub(
            r"\\([0-7]{3})",
            lambda match: chr(int(match.group(1), 8)),
            value,
        )
    except (ValueError, UnicodeError) as error:
        raise ProvisioningError("ATOMIC_WRITE_FAILED") from error


def _nearest_existing_filesystem(path: Path) -> tuple[int, int]:
    existing, metadata = _nearest_existing_directory(path)
    try:
        resolved = existing.resolve(strict=True)
        candidates: list[tuple[int, int]] = []
        for line in (
            Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        ):
            fields = line.split()
            if len(fields) < 10 or "-" not in fields:
                raise ProvisioningError("ATOMIC_WRITE_FAILED")
            mount_id = int(fields[0])
            mount_point = Path(_decode_mountinfo_path(fields[4]))
            try:
                resolved.relative_to(mount_point)
            except ValueError:
                continue
            candidates.append((len(mount_point.parts), mount_id))
    except ProvisioningError:
        raise
    except (OSError, ValueError) as error:
        raise ProvisioningError("ATOMIC_WRITE_FAILED") from error
    if not candidates:
        raise ProvisioningError("ATOMIC_WRITE_FAILED")
    return metadata.st_dev, max(candidates)[1]


def _require_quarantine_binding(paths: ProvisioningPaths) -> tuple[int, int]:
    if _LIBC_RENAMEAT2 is None:
        raise ProvisioningError("ATOMIC_WRITE_FAILED")
    output_binding = _nearest_existing_filesystem(paths.output_dir)
    required_bindings = {
        output_binding,
        _nearest_existing_filesystem(paths.prefix),
        _nearest_existing_filesystem(paths.configuration_root),
    }
    if len(required_bindings) != 1:
        raise ProvisioningError("ATOMIC_WRITE_FAILED")
    return output_binding


def _quarantine_owned_directory(
    paths: ProvisioningPaths,
    source: Path,
    expected_identity: tuple[int, int],
    *,
    label: str,
) -> None:
    source_parent_fd = -1
    quarantine_fd = -1
    placeholder_name = f".openclaw-{label}-placeholder-{uuid.uuid4().hex}"
    destination_name = f"openclaw-{label}-{uuid.uuid4().hex}"
    placeholder_created = False
    exchanged = False
    try:
        _create_private_directory_no_symlinks(paths.quarantine_dir)
        open_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        source_parent_fd = os.open(source.parent, open_flags)
        quarantine_fd = os.open(paths.quarantine_dir, open_flags)
        metadata = os.stat(
            source.name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != expected_identity
        ):
            raise ProvisioningError("ATOMIC_WRITE_FAILED: owned identity changed")
        os.mkdir(placeholder_name, mode=0o700, dir_fd=quarantine_fd)
        placeholder_created = True
        placeholder = os.stat(
            placeholder_name,
            dir_fd=quarantine_fd,
            follow_symlinks=False,
        )
        placeholder_identity = (placeholder.st_dev, placeholder.st_ino)
        _rename_exchange(
            source_parent_fd,
            source.name,
            quarantine_fd,
            placeholder_name,
        )
        exchanged = True
        moved = os.stat(
            placeholder_name,
            dir_fd=quarantine_fd,
            follow_symlinks=False,
        )
        moved_identity = (moved.st_dev, moved.st_ino)
        if moved_identity != expected_identity:
            _rename_exchange(
                source_parent_fd,
                source.name,
                quarantine_fd,
                placeholder_name,
            )
            exchanged = False
            restored = os.stat(
                source.name,
                dir_fd=source_parent_fd,
                follow_symlinks=False,
            )
            restored_placeholder = os.stat(
                placeholder_name,
                dir_fd=quarantine_fd,
                follow_symlinks=False,
            )
            if (restored.st_dev, restored.st_ino) != moved_identity or (
                restored_placeholder.st_dev,
                restored_placeholder.st_ino,
            ) != placeholder_identity:
                raise ProvisioningError(
                    "ATOMIC_WRITE_FAILED: quarantine restoration failed"
                )
            os.rmdir(placeholder_name, dir_fd=quarantine_fd)
            placeholder_created = False
            os.fsync(source_parent_fd)
            os.fsync(quarantine_fd)
            raise ProvisioningError("ATOMIC_WRITE_FAILED: owned identity changed")
        source_placeholder = os.stat(
            source.name,
            dir_fd=source_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(source_placeholder.st_mode)
            or (source_placeholder.st_dev, source_placeholder.st_ino)
            != placeholder_identity
        ):
            raise ProvisioningError(
                "ATOMIC_WRITE_FAILED: quarantine placeholder changed"
            )
        os.rmdir(source.name, dir_fd=source_parent_fd)
        exchanged = False
        placeholder_created = False
        os.rename(
            placeholder_name,
            destination_name,
            src_dir_fd=quarantine_fd,
            dst_dir_fd=quarantine_fd,
        )
        os.fsync(source_parent_fd)
        os.fsync(quarantine_fd)
    except ProvisioningError:
        raise
    except OSError as error:
        raise ProvisioningError("ATOMIC_WRITE_FAILED: quarantine failed") from error
    finally:
        if placeholder_created and not exchanged and quarantine_fd >= 0:
            try:
                os.rmdir(placeholder_name, dir_fd=quarantine_fd)
            except OSError:
                pass
        if source_parent_fd >= 0:
            os.close(source_parent_fd)
        if quarantine_fd >= 0:
            os.close(quarantine_fd)


_RENAME_EXCHANGE = 2
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _LIBC_RENAMEAT2 is not None:
    _LIBC_RENAMEAT2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    _LIBC_RENAMEAT2.restype = ctypes.c_int


def _rename_exchange(
    source_parent_fd: int,
    source_name: str,
    destination_parent_fd: int,
    destination_name: str,
) -> None:
    if _LIBC_RENAMEAT2 is None:
        raise OSError("renameat2 is unavailable")
    result = _LIBC_RENAMEAT2(
        source_parent_fd,
        os.fsencode(source_name),
        destination_parent_fd,
        os.fsencode(destination_name),
        _RENAME_EXCHANGE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read_proc_start_time(pid: int) -> int:
    payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    suffix = payload[payload.rindex(")") + 2 :].split()
    return int(suffix[19])


def _read_proc_group_state(pid: int) -> tuple[int, str]:
    payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    suffix = payload[payload.rindex(")") + 2 :].split()
    return int(suffix[2]), suffix[0]


def _pgid_members(pgid: int) -> tuple[int, ...]:
    members: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            pid = int(entry.name)
            process_group, state = _read_proc_group_state(pid)
            if process_group == pgid and state not in {"Z", "X", "x"}:
                members.append(pid)
        except (OSError, ValueError, IndexError):
            continue
    return tuple(sorted(members))


def _wait_for_empty_process_group(pgid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _pgid_members(pgid):
            return True
        time.sleep(0.02)
    return not _pgid_members(pgid)


def _terminate_process_group(
    process: subprocess.Popen[object],
    identity: OwnedProcess,
    *,
    leader_reaped: bool = False,
    timeout_seconds: float = 5.0,
) -> None:
    if not leader_reaped and process.poll() is None:
        _require_owned_process_identity(identity)
    if not _pgid_members(identity.pgid):
        if process.poll() is None:
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as error:
                raise OpenClawGateError("process group cleanup timed out") from error
        return
    try:
        os.killpg(identity.pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            pass
    if _wait_for_empty_process_group(identity.pgid, timeout_seconds):
        return
    try:
        os.killpg(identity.pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            raise OpenClawGateError("process group cleanup timed out") from error
    if not _wait_for_empty_process_group(identity.pgid, timeout_seconds):
        raise OpenClawGateError("process group cleanup is incomplete")


def _terminate_unregistered_session(
    process: subprocess.Popen[object], timeout_seconds: float = 5.0
) -> None:
    """Clean a start_new_session child before full identity acquisition."""

    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise ProvisioningError(
            "TOOL_RUNTIME_ERROR: unregistered session cleanup failed"
        ) from error
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        raise ProvisioningError(
            "TOOL_RUNTIME_ERROR: unregistered session cleanup timed out"
        ) from error
    if not _wait_for_empty_process_group(process.pid, timeout_seconds):
        raise ProvisioningError(
            "TOOL_RUNTIME_ERROR: unregistered session cleanup incomplete"
        )


def _read_bounded_output(file: object, label: str, limit: int = 1024 * 1024) -> str:
    try:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        if size > limit:
            raise ProvisioningError(f"TOOL_RUNTIME_ERROR: {label} exceeded bound")
        file.seek(0)
        payload = file.read(limit + 1)
        if len(payload) > limit:
            raise ProvisioningError(f"TOOL_RUNTIME_ERROR: {label} exceeded bound")
        return payload.decode("utf-8", errors="strict")
    except ProvisioningError:
        raise
    except (AttributeError, OSError, UnicodeError) as error:
        raise ProvisioningError(f"TOOL_RUNTIME_ERROR: invalid {label}") from error


def _minimal_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "HOME",
        "PATH",
        "TMPDIR",
        "OPENCLAW_CONFIG_PATH",
        "OPENCLAW_STATE_DIR",
        "OPENCLAW_GATEWAY_TOKEN",
        "OPENCLAW_NO_ONBOARD",
        "OPENCLAW_PREFIX",
        "OPENCLAW_NODE_VERSION",
        "OPENCLAW_VERSION",
        "OPENCLAW_INSTALL_METHOD",
        "NPM_CONFIG_USERCONFIG",
        "NPM_CONFIG_GLOBALCONFIG",
        "NPM_CONFIG_CACHE",
        "HOLOAGENT0_EXPECTED_OPENCLAW_VERSION",
        "HOLOAGENT0_EXPECTED_OPENCLAW_TARBALL",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
    }
    if any(
        key not in allowed
        or type(key) is not str
        or type(value) is not str
        or "\0" in key
        or "\0" in value
        for key, value in overrides.items()
    ):
        raise ProvisioningError("TOOL_RUNTIME_ERROR: unreviewed environment")
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TMPDIR": "/tmp",
    }
    environment.update(overrides)
    return environment


def _require_owned_process_identity(identity: OwnedProcess) -> None:
    try:
        observed = OwnedProcess(
            identity.pid,
            os.getpgid(identity.pid),
            _read_proc_start_time(identity.pid),
            os.readlink(f"/proc/{identity.pid}/exe"),
        )
    except (OSError, ValueError) as error:
        raise OpenClawGateError("smoke process identity changed") from error
    if observed != identity:
        raise OpenClawGateError("smoke process identity changed")


def _verify_observed_process_identity(
    observation: LifecycleObservation, identity: OwnedProcess
) -> None:
    matching = [
        process for process in observation.processes if process.pid == identity.pid
    ]
    if len(matching) != 1:
        raise OpenClawGateError("smoke process identity changed")
    process = matching[0]
    if (
        process.start_time_ticks != identity.start_time_ticks
        or process.executable != identity.executable
    ):
        raise OpenClawGateError("smoke process identity changed")


def _wait_for_smoke_readiness(
    observer: LifecycleObserver,
    *,
    identity: OwnedProcess,
    port: int,
    timeout_seconds: float,
) -> LifecycleObservation:
    deadline = time.monotonic() + timeout_seconds
    while True:
        observation = observer.observe()
        matching = [
            process for process in observation.processes if process.pid == identity.pid
        ]
        if matching:
            _verify_observed_process_identity(observation, identity)
            owned_listeners = [
                listener
                for listener in observation.listeners
                if listener.pid == identity.pid
            ]
            if any(listener.port == port for listener in owned_listeners):
                verify_owned_loopback_listener(observation, pid=identity.pid, port=port)
                return observation
        if time.monotonic() >= deadline:
            raise OpenClawGateError("smoke listener readiness timed out")
        time.sleep(0.05)


def _split_socket_endpoint(value: str) -> tuple[str, str]:
    if value.startswith("["):
        closing = value.rfind("]:")
        if closing < 0:
            raise ValueError(value)
        return value[1:closing], value[closing + 2 :]
    if ":" not in value:
        raise ValueError(value)
    return value.rsplit(":", 1)


class OpenClawGate:
    def __init__(self, *, observer: LifecycleObserver, runner: CommandRunner) -> None:
        if not callable(getattr(observer, "observe", None)) or not callable(
            getattr(runner, "run", None)
        ):
            raise OpenClawGateError("lifecycle adapters are invalid")
        self._observer = observer
        self._runner = runner

    def preexisting(
        self,
        cli_path: Path | None = None,
        *,
        node_path: Path | None = None,
        entry_path: Path | None = None,
    ) -> GateResult:
        observation = self._observer.observe()
        if observation.has_openclaw_state:
            return GateResult("FAIL", "PREEXISTING_OPENCLAW", {})
        if cli_path is None:
            return GateResult("PASS", "OK", {})
        command = (
            *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        )
        result = self._runner.run(command, environment={})
        value = _command_json(result)
        if value is None:
            return GateResult("FAIL", "TOOL_RUNTIME_ERROR", {})
        state = _service_status(value)
        if state is None:
            return GateResult("FAIL", "TOOL_RUNTIME_ERROR", {})
        loaded, runtime_status = state
        if loaded or runtime_status == "running":
            return GateResult("FAIL", "PREEXISTING_OPENCLAW", {})
        return GateResult("PASS", "OK", {})

    def validate_read_only(
        self,
        *,
        cli_path: Path,
        config_path: Path,
        state_dir: Path,
        token: str,
        preflight_observation: LifecycleObservation | None = None,
        node_path: Path | None = None,
        entry_path: Path | None = None,
    ) -> GateResult:
        if not isinstance(token, str) or len(token) < 43:
            return GateResult("FAIL", "OPENCLAW_CONFIG_INVALID", {})
        before = (
            preflight_observation
            if preflight_observation is not None
            else self._observer.observe()
        )
        if before.has_openclaw_state:
            return GateResult("FAIL", "PREEXISTING_OPENCLAW", {})
        environment = {
            "HOME": str(Path(state_dir).parent),
            "OPENCLAW_CONFIG_PATH": str(config_path),
            "OPENCLAW_STATE_DIR": str(state_dir),
            "OPENCLAW_GATEWAY_TOKEN": token,
        }
        commands = (
            (
                *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
                "config",
                "validate",
                "--json",
            ),
            (
                *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
                "doctor",
                "--lint",
                "--only",
                "core/doctor/gateway-config",
                "--severity-min",
                "warning",
                "--json",
            ),
            (
                *_cli_command(cli_path, node_path=node_path, entry_path=entry_path),
                "doctor",
                "--lint",
                "--severity-min",
                "error",
                "--json",
            ),
        )
        reason = "OK"
        command_error: BaseException | None = None
        try:
            config_value = _command_json(
                self._runner.run(commands[0], environment=environment)
            )
            if config_value is None:
                reason = "TOOL_RUNTIME_ERROR"
            elif config_value.get("valid") is not True:
                reason = "OPENCLAW_CONFIG_INVALID"
            if reason == "OK":
                gateway_value = _command_json(
                    self._runner.run(commands[1], environment=environment)
                )
                if gateway_value is None:
                    reason = "TOOL_RUNTIME_ERROR"
                elif (
                    gateway_value.get("checksRun") != 1
                    or gateway_value.get("findings") != []
                ):
                    reason = "OPENCLAW_LINT_FINDING"
            if reason == "OK":
                full_value = _command_json(
                    self._runner.run(commands[2], environment=environment)
                )
                if full_value is None:
                    reason = "TOOL_RUNTIME_ERROR"
                elif (
                    type(full_value.get("checksRun")) is not int
                    or full_value["checksRun"] < 1
                    or full_value.get("findings") != []
                ):
                    reason = "OPENCLAW_LINT_FINDING"
        except BaseException as error:
            command_error = error
            reason = "TOOL_RUNTIME_ERROR"
        after = self._observer.observe()
        if after.has_openclaw_state:
            return GateResult("FAIL", "PREEXISTING_OPENCLAW", {}, after)
        if command_error is not None and not isinstance(command_error, Exception):
            raise command_error
        if reason != "OK":
            return GateResult("FAIL", reason, {}, after)
        return GateResult(
            "PASS",
            "OK",
            {
                "OPENCLAW_CONFIG_PATH": str(config_path),
                "OPENCLAW_STATE_DIR": str(state_dir),
            },
            after,
        )


def _command_json(result: CommandResult) -> dict[str, object] | None:
    if type(result) is not CommandResult or result.exit_code != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _service_status(value: Mapping[str, object]) -> tuple[bool, str] | None:
    service = value.get("service")
    if not isinstance(service, dict):
        return None
    loaded = service.get("loaded")
    runtime = service.get("runtime")
    if type(loaded) is not bool or not isinstance(runtime, dict):
        return None
    runtime_status = runtime.get("status")
    if runtime_status != "stopped" and runtime_status != "running":
        return None
    return loaded, runtime_status


def _smoke_status_is_ready(value: Mapping[str, object]) -> bool:
    rpc = value.get("rpc")
    return (
        _service_status(value) is not None
        and isinstance(rpc, dict)
        and rpc.get("ok") is True
    )


def _cli_command(
    cli_path: Path,
    *,
    node_path: Path | None = None,
    entry_path: Path | None = None,
) -> tuple[str, ...]:
    if (node_path is None) != (entry_path is None):
        raise OpenClawGateError("CLI runtime binding is incomplete")
    if node_path is not None and entry_path is not None:
        return (str(node_path), str(entry_path))
    return (str(cli_path),)


def verify_owned_loopback_listener(
    observation: LifecycleObservation, *, pid: int, port: int
) -> None:
    if not any(process.pid == pid for process in observation.processes):
        raise OpenClawGateError("listener ownership is not verified")
    owned = [listener for listener in observation.listeners if listener.pid == pid]
    matching = [listener for listener in owned if listener.port == port]
    if not matching or any(listener.pid != pid for listener in matching):
        raise OpenClawGateError("listener ownership is not verified")
    if any(listener.address not in {"127.0.0.1", "::1"} for listener in owned):
        raise OpenClawGateError("listener is not loopback-only")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-sri")
    verify.add_argument("--tarball", required=True)
    verify.add_argument("--integrity", required=True)
    provision = subparsers.add_parser("provision")
    provision.add_argument("--output-dir", required=True)
    provision.add_argument("--prefix")
    provision.add_argument("--configuration-root")
    provision.add_argument("--previous-record")
    verify_record = subparsers.add_parser("verify-record")
    verify_record.add_argument("--record", required=True)
    verify_record.add_argument("--prefix", required=True)
    verify_record.add_argument("--configuration-root", required=True)
    smoke = subparsers.add_parser("smoke")
    smoke.add_argument("--cli-path", required=True)
    smoke.add_argument("--node-path")
    smoke.add_argument("--entry-path")
    smoke.add_argument("--config-path", required=True)
    smoke.add_argument("--state-dir", required=True)
    smoke.add_argument("--port", required=True, type=int)
    smoke.add_argument("--record")
    smoke.add_argument("--prefix")
    smoke.add_argument("--authorized-live-smoke", action="store_true")
    return parser


def _account_home() -> Path:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        metadata = home.lstat()
        if (
            not home.is_absolute()
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise ProvisioningError("INSTALLER_PIN_MISMATCH")
        return home
    except ProvisioningError:
        raise
    except (KeyError, OSError) as error:
        raise ProvisioningError("INSTALLER_PIN_MISMATCH") from error


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "verify-sri":
        try:
            observed = verify_sri(Path(args.tarball), args.integrity)
        except ProvisioningError:
            return 1
        print(json.dumps({"integrity": observed}, sort_keys=True))
        return 0
    if args.command == "provision":
        account_home = _account_home()
        prefix = Path(args.prefix) if args.prefix else account_home / ".openclaw"
        configuration_root = (
            Path(args.configuration_root)
            if args.configuration_root
            else account_home / ".openclaw-holoagent0"
        )
        paths = ProvisioningPaths.for_user_paths(
            output_dir=Path(args.output_dir),
            prefix=prefix,
            configuration_root=configuration_root,
            previous_record=(
                Path(args.previous_record) if args.previous_record else None
            ),
        )
        runtime = ProvisioningRuntime(
            observer=LocalLifecycleObserver(),
            runner=LocalCommandRunner(),
            fetcher=HttpsArtifactFetcher(),
        )
        previous_handlers: dict[int, object] = {}

        def interrupt_provision(signum: int, _frame: object) -> None:
            raise _ProvisioningSignal(signum)

        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupt_provision)
        try:
            record = runtime.provision(paths)
        except _ProvisioningSignal as error:
            return 128 + error.signum
        except ProvisioningError as error:
            print(
                json.dumps(
                    {
                        "status": "FAIL",
                        "reason": str(error).split(":", 1)[0],
                        "record": str(paths.record),
                    },
                    sort_keys=True,
                )
            )
            return 1
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        print(
            json.dumps(
                {"status": record["status"], "record": str(paths.record)},
                sort_keys=True,
            )
        )
        return 0
    if args.command == "verify-record":
        record_path = Path(args.record).resolve()
        paths = ProvisioningPaths.for_user_paths(
            output_dir=record_path.parent,
            prefix=Path(args.prefix),
            configuration_root=Path(args.configuration_root),
        )
        try:
            record = verify_provisioning_record_file(record_path, paths)
        except ProvisioningError:
            return 1
        print(
            json.dumps(
                {"status": record["status"], "record": str(record_path)},
                sort_keys=True,
            )
        )
        return 0
    if args.command == "smoke":
        if not args.authorized_live_smoke:
            print(
                json.dumps(
                    {"status": "FAIL", "reason": "LIVE_SMOKE_NOT_AUTHORIZED"},
                    sort_keys=True,
                )
            )
            return 2
        if (
            not args.node_path
            or not args.entry_path
            or not args.record
            or not args.prefix
        ):
            return 2
        record_path = Path(args.record).resolve()
        smoke_paths = ProvisioningPaths.for_user_paths(
            output_dir=record_path.parent,
            prefix=Path(args.prefix),
            configuration_root=Path(args.config_path).parent,
        )
        try:
            verify_provisioning_record_file(record_path, smoke_paths)
            package_root = _find_package_root(smoke_paths.prefix)
            _package, declared = _verify_installed_package(package_root)
            expected_cli = _require_launcher_binding(
                smoke_paths.prefix, package_root, declared
            )
            expected_node = _find_node_binary(smoke_paths.prefix)
            expected_entry = (package_root / declared).resolve(strict=True)
            if (
                Path(args.cli_path).resolve(strict=True)
                != expected_cli.resolve(strict=True)
                or Path(args.node_path).resolve(strict=True) != expected_node
                or Path(args.entry_path).resolve(strict=True) != expected_entry
                or Path(args.state_dir).resolve() != smoke_paths.state_dir
            ):
                return 2
        except (OSError, ProvisioningError):
            return 1
        runtime = SmokeRuntime(
            observer=LocalLifecycleObserver(watched_ports=(18789, args.port)),
            runner=LocalCommandRunner(timeout_seconds=30),
            processes=LocalSmokeProcessController(),
        )
        token = secrets.token_urlsafe(32)
        previous_handlers: dict[int, object] = {}

        def interrupt(_signum: int, _frame: object) -> None:
            raise KeyboardInterrupt

        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupt)
        try:
            runtime.run(
                cli_path=Path(args.cli_path),
                config_path=Path(args.config_path),
                state_dir=Path(args.state_dir),
                token=token,
                port=args.port,
                node_path=Path(args.node_path),
                entry_path=Path(args.entry_path),
            )
        except OpenClawSafetyError:
            return 30
        except (OpenClawGateError, KeyboardInterrupt):
            return 1
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        print(json.dumps({"status": "PASS", "reason": "OK"}, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
