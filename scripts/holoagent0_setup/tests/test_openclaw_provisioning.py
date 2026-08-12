from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
from typing import Mapping

import pytest

from holoagent0_setup.openclaw_gate import (
    CONFIG_TEMPLATE_CONTENT,
    CONFIG_TEMPLATE_GIT_BLOB,
    INSTALLER_SHA256,
    NODE_TARBALL_SHA256,
    NODE_VERSION,
    OPENCLAW_INTEGRITY,
    OPENCLAW_VERSION,
    LocalCommandRunner,
    HttpsArtifactFetcher,
    ProvisioningPaths,
    ProvisioningRuntime,
    ProvisioningError,
    build_directory_manifest,
    build_tar_payload_manifest,
    compute_sri,
    configuration_template_sha256,
    copy_pinned_configuration,
    installer_command,
    npm_package_spec,
    require_matching_payload,
    validate_provisioning_record,
    verify_provisioning_record_file,
    verify_registry_document,
    verify_sri,
)


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas/openclaw-provisioning-v1.schema.json"
)
SCRIPT_PATH = Path(__file__).resolve().parents[1] / "provision_openclaw.sh"
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config/openclaw-local-v1.json"
INSTALL_DRIVER_PATH = Path(__file__).resolve().parents[1] / "openclaw_install_driver.sh"


def _portable_unsealed_memfd(name: str) -> int:
    import holoagent0_setup.openclaw_gate as gate_module

    return gate_module._memfd_create(name, gate_module._LINUX_MFD_ALLOW_SEALING)


def _seal_memfd(descriptor: int) -> None:
    import holoagent0_setup.openclaw_gate as gate_module

    fcntl.fcntl(
        descriptor,
        gate_module._LINUX_F_ADD_SEALS,
        gate_module._INSTALLER_MEMFD_SEALS,
    )


def _tarball(tmp_path: Path, entries: list[tuple[str, bytes, int]]) -> Path:
    path = tmp_path / "openclaw.tgz"
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("package/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        for name, content, mode in entries:
            member = tarfile.TarInfo(f"package/{name}")
            member.mode = mode
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return path


def _valid_record(schema_sha256: str) -> dict[str, object]:
    digest = "1" * 64
    observation = {"processes": [], "services": [], "listeners": []}
    return {
        "schema_version": "holoagent0.openclaw.provisioning.v1",
        "schema_sha256": schema_sha256,
        "run_id": "run-1",
        "started_at": "2026-08-12T00:00:00Z",
        "ended_at": "2026-08-12T00:00:01Z",
        "hostname": "workstation",
        "architecture": "x86_64",
        "status": "PASS",
        "reason": "OK",
        "provisioning_mode": "FRESH_INSTALL",
        "lineage": None,
        "quarantine_device": 1,
        "quarantine_mount_id": 1,
        "pins": {
            "package_name": "openclaw",
            "package_version": OPENCLAW_VERSION,
            "node_version": NODE_VERSION,
            "node_tarball_sha256": NODE_TARBALL_SHA256,
            "npm_version": "11.0.0",
            "installer_path": "https://openclaw.ai/install-cli.sh",
            "installer_sha256": INSTALLER_SHA256,
            "registry_document_url": ("https://registry.npmjs.org/openclaw/2026.7.1-2"),
            "configuration_template_path": str(CONFIG_PATH),
            "configuration_template_git_blob": CONFIG_TEMPLATE_GIT_BLOB,
            "configuration_template_sha256": (
                configuration_template_sha256(CONFIG_PATH)
            ),
        },
        "registry": {
            "response_sha256": digest,
            "version": OPENCLAW_VERSION,
            "dist": {
                "tarball": (
                    "https://registry.npmjs.org/openclaw/-/openclaw-2026.7.1-2.tgz"
                ),
                "integrity": OPENCLAW_INTEGRITY,
                "shasum": "2" * 40,
            },
        },
        "package": {
            "tarball_sha256": digest,
            "tarball_sri": OPENCLAW_INTEGRITY,
            "byte_size": 1,
        },
        "payload": {
            "expected_manifest_sha256": digest,
            "actual_manifest_sha256": digest,
            "matches": True,
        },
        "installer": {
            "node_path": "/prefix/node",
            "node_sha256": digest,
            "npm_cli_path": "/prefix/npm-cli.js",
            "npm_cli_sha256": digest,
            "driver_path": str(INSTALL_DRIVER_PATH),
            "driver_sha256": "a8480748009b3f070d5d456eb8297896a7fe28b41f58015a17013dce4059a672",
            "openclaw_cli_path": "/prefix/openclaw",
            "openclaw_cli_sha256": digest,
            "argv": [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "/proc/self/fd/17",
                "19",
                "--prefix",
                "/prefix",
                "--version",
                "file:/evidence/downloads/openclaw.tgz",
                "--node-version",
                NODE_VERSION,
                "--no-onboard",
                "--json",
            ],
        },
        "target_prefix": {"root": "/prefix", "sha256": digest, "entries": []},
        "configuration": {
            "template_sha256": configuration_template_sha256(CONFIG_PATH),
            "installed_sha256": configuration_template_sha256(CONFIG_PATH),
            "valid": True,
            "lint_findings": [],
        },
        "before_observation": observation,
        "after_observation": observation,
    }


def test_literal_pins_and_installer_use_verified_local_tarball(tmp_path):
    tarball = (tmp_path / "openclaw.tgz").resolve()
    tarball.write_bytes(b"verified")

    command = installer_command(
        17,
        19,
        prefix=Path("/isolated/prefix"),
        tarball=tarball,
    )

    assert OPENCLAW_VERSION == "2026.7.1-2"
    assert NODE_VERSION == "24.15.0"
    assert INSTALLER_SHA256 == (
        "21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1"
    )
    assert NODE_TARBALL_SHA256 == (
        "472655581fb851559730c48763e0c9d3bc25975c59d518003fc0849d3e4ba0f6"
    )
    assert command == (
        "/usr/bin/bash",
        "--noprofile",
        "--norc",
        "/proc/self/fd/17",
        "19",
        "--prefix",
        "/isolated/prefix",
        "--version",
        f"file:{tarball}",
        "--node-version",
        "24.15.0",
        "--no-onboard",
        "--json",
    )
    assert npm_package_spec(tarball) == f"openclaw@file:{tarball}"
    assert all("latest" not in argument for argument in command)


def test_recorded_installer_argv_requires_exact_sealed_driver_shape(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    prefix = Path("/isolated/prefix")
    tarball = tmp_path / "openclaw.tgz"
    command = installer_command(17, 19, prefix=prefix, tarball=tarball)
    gate_module._require_recorded_installer_argv(
        list(command), prefix=prefix, tarball=tarball
    )

    for replacement in (
        [*command[:3], str(INSTALL_DRIVER_PATH), *command[4:]],
        [*command[:4], "17", *command[5:]],
        [*command[:-1], "--onboard"],
    ):
        with pytest.raises(ProvisioningError, match="INSTALLED_PAYLOAD_MISMATCH"):
            gate_module._require_recorded_installer_argv(
                replacement, prefix=prefix, tarball=tarball
            )


def test_no_refresh_install_driver_sources_pin_and_never_calls_service_paths(tmp_path):
    fake_installer = tmp_path / "install-cli.sh"
    prohibited = tmp_path / "prohibited"
    fake_installer.write_text(
        """#!/usr/bin/env bash
[[ "${OPENCLAW_INSTALL_CLI_SH_NO_RUN:-0}" == 1 ]] || exit 70
PREFIX=""
OPENCLAW_VERSION=""
NODE_VERSION=""
INSTALL_METHOD="npm"
RUN_ONBOARD=0
JSON=0
SET_NPM_PREFIX=0
parse_args() {
  while (($#)); do
    case "$1" in
      --prefix) PREFIX=$2; shift 2 ;;
      --version) OPENCLAW_VERSION=$2; shift 2 ;;
      --node-version) NODE_VERSION=$2; shift 2 ;;
      --no-onboard) RUN_ONBOARD=0; shift ;;
      --json) JSON=1; shift ;;
      *) exit 69 ;;
    esac
  done
}
node_dir() { printf '%s/tools/node-v%s\\n' "$PREFIX" "$NODE_VERSION"; }
node_bin() { printf '%s/bin/node\\n' "$(node_dir)"; }
npm_bin() { printf '%s/bin/npm\\n' "$(node_dir)"; }
install_openclaw() {
  [[ ! -e "/proc/self/fd/${HOLOAGENT0_TEST_DRIVER_FD}" ]] || exit 66
  [[ ! -e "/proc/self/fd/${HOLOAGENT0_TEST_INSTALLER_FD}" ]] || exit 68
  printf 'install\\n'
}
emit_json() { printf '%s\\n' "$1"; }
refresh_gateway_service_if_loaded() { printf refresh > "$PROHIBITED"; exit 71; }
install_node() { printf install-node > "$PROHIBITED"; exit 72; }
ensure_git() { printf ensure-git > "$PROHIBITED"; exit 73; }
resolve_openclaw_version() { printf resolve > "$PROHIBITED"; exit 74; }
fix_npm_prefix_if_needed() { printf prefix > "$PROHIBITED"; exit 75; }
main() { printf main > "$PROHIBITED"; exit 76; }
""",
        encoding="utf-8",
    )
    fake_installer.chmod(0o700)
    test_driver = tmp_path / "openclaw_install_driver.sh"
    test_driver.write_text(
        INSTALL_DRIVER_PATH.read_text(encoding="utf-8").replace(
            INSTALLER_SHA256,
            hashlib.sha256(fake_installer.read_bytes()).hexdigest(),
        ),
        encoding="utf-8",
    )
    driver_fd = _portable_unsealed_memfd("openclaw-driver-test")
    os.write(driver_fd, test_driver.read_bytes())
    fake_node_bin = tmp_path / f"prefix/tools/node-v{NODE_VERSION}/bin"
    fake_node_bin.mkdir(parents=True)
    for name in ("node", "npm"):
        executable = fake_node_bin / name
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)

    installer_fd = _portable_unsealed_memfd("openclaw-installer-test")
    os.write(installer_fd, fake_installer.read_bytes())
    _seal_memfd(installer_fd)
    _seal_memfd(driver_fd)
    os.lseek(driver_fd, 0, os.SEEK_SET)
    os.lseek(installer_fd, 0, os.SEEK_SET)
    with pytest.raises(OSError):
        os.write(installer_fd, b"attacker")
    with pytest.raises(OSError):
        os.ftruncate(installer_fd, 0)
    fake_installer.write_text("attacker replacement\n", encoding="utf-8")
    while installer_fd < 30:
        high_fd = fcntl.fcntl(installer_fd, fcntl.F_DUPFD, 30)
        os.close(installer_fd)
        installer_fd = high_fd

    try:
        completed = subprocess.run(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                f"/proc/self/fd/{driver_fd}",
                str(installer_fd),
                "--prefix",
                str(tmp_path / "prefix"),
                "--version",
                "file:/verified/openclaw.tgz",
                "--node-version",
                NODE_VERSION,
                "--no-onboard",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
            pass_fds=(driver_fd, installer_fd),
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(tmp_path),
                "OPENCLAW_PREFIX": str(tmp_path / "prefix"),
                "HOLOAGENT0_EXPECTED_OPENCLAW_VERSION": OPENCLAW_VERSION,
                "HOLOAGENT0_EXPECTED_OPENCLAW_TARBALL": "/verified/openclaw.tgz",
                "PROHIBITED": str(prohibited),
                "HOLOAGENT0_TEST_INSTALLER_FD": str(installer_fd),
                "HOLOAGENT0_TEST_DRIVER_FD": str(driver_fd),
            },
        )
    finally:
        os.close(driver_fd)
        os.close(installer_fd)

    assert completed.returncode == 0, completed.stderr
    assert "install" in completed.stdout
    assert '"event":"holoagent0-reviewed-subset"' in completed.stdout
    assert f'"version":"{OPENCLAW_VERSION}"' in completed.stdout
    assert not prohibited.exists()


def test_install_driver_rejects_unsealed_installer_fd(tmp_path):
    installer_fd = _portable_unsealed_memfd("unsealed-installer")
    os.write(installer_fd, b"#!/bin/bash\n")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                str(INSTALL_DRIVER_PATH),
                str(installer_fd),
            ],
            check=False,
            capture_output=True,
            text=True,
            pass_fds=(installer_fd,),
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(tmp_path),
                "OPENCLAW_PREFIX": str(tmp_path / "prefix"),
                "HOLOAGENT0_EXPECTED_OPENCLAW_VERSION": OPENCLAW_VERSION,
                "HOLOAGENT0_EXPECTED_OPENCLAW_TARBALL": "/verified/openclaw.tgz",
            },
        )
    finally:
        os.close(installer_fd)

    assert completed.returncode != 0


def test_recorded_owned_directories_are_quarantined_even_if_path_disappears():
    import inspect
    import holoagent0_setup.openclaw_gate as gate_module

    source = inspect.getsource(gate_module.ProvisioningRuntime._provision_pass)
    assert "prefix_identity is not None and paths.prefix.exists()" not in source
    assert (
        "configuration_identity is not None and paths.configuration_root.exists()"
        not in source
    )


def test_install_driver_is_digest_bound_and_rejects_mutation_or_symlink(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    assert gate_module.INSTALL_DRIVER_SHA256 == (
        "a8480748009b3f070d5d456eb8297896a7fe28b41f58015a17013dce4059a672"
    )
    gate_module._require_install_driver(INSTALL_DRIVER_PATH)

    mutated = tmp_path / "driver.sh"
    mutated.write_bytes(INSTALL_DRIVER_PATH.read_bytes() + b"\n")
    mutated.chmod(0o644)
    with pytest.raises(ProvisioningError, match="INSTALLER_PIN_MISMATCH"):
        gate_module._require_install_driver(mutated)

    linked = tmp_path / "driver-link.sh"
    linked.symlink_to(INSTALL_DRIVER_PATH)
    with pytest.raises(ProvisioningError, match="INSTALLER_PIN_MISMATCH"):
        gate_module._require_install_driver(linked)

    source = INSTALL_DRIVER_PATH.read_text(encoding="utf-8")
    assert "installer_fd=$1" in source
    assert "observed & required" in source
    assert '/usr/bin/sha256sum "$installer_fd_path"' in source
    assert 'source "$installer_fd_path"' in source
    assert "installer_path" not in source


def test_exact_regular_file_read_is_bound_to_opened_inode(tmp_path, monkeypatch):
    import holoagent0_setup.openclaw_gate as gate_module

    target = tmp_path / "artifact"
    replacement = tmp_path / "replacement"
    target.write_bytes(b"expected")
    replacement.write_bytes(b"attacker")
    original_read_bytes = Path.read_bytes

    def swap_before_path_read(path: Path) -> bytes:
        if path == target:
            os.replace(replacement, target)
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", swap_before_path_read)

    assert gate_module._read_exact_regular_file(target) == b"expected"


def test_local_runner_passes_only_explicit_file_descriptors():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"sealed")
    os.close(write_fd)
    try:
        result = LocalCommandRunner().run(
            (
                "/usr/bin/python3.10",
                "-I",
                "-S",
                "-c",
                "import os,sys; print(os.read(int(sys.argv[1]), 6).decode())",
                str(read_fd),
            ),
            environment={},
            pass_fds=(read_fd,),
        )
    finally:
        os.close(read_fd)

    assert result.exit_code == 0
    assert result.stdout == "sealed\n"


def test_sealed_file_snapshot_survives_source_path_swap(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    source = tmp_path / "reviewed"
    source.write_bytes(b"reviewed bytes")
    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    descriptor = gate_module._create_sealed_file_fd(
        source,
        expected,
        label="reviewed-test",
    )
    try:
        source.write_bytes(b"attacker replacement")
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, 1024) == b"reviewed bytes"
        assert (
            fcntl.fcntl(descriptor, gate_module._LINUX_F_GET_SEALS)
            & gate_module._INSTALLER_MEMFD_SEALS
            == gate_module._INSTALLER_MEMFD_SEALS
        )
    finally:
        os.close(descriptor)


def test_registry_integrity_is_compared_before_tarball_acceptance():
    valid = {
        "version": OPENCLAW_VERSION,
        "dist": {
            "tarball": (
                "https://registry.npmjs.org/openclaw/-/openclaw-2026.7.1-2.tgz"
            ),
            "integrity": OPENCLAW_INTEGRITY,
            "shasum": "a" * 40,
        },
    }
    verified = verify_registry_document(json.dumps(valid).encode())
    assert verified.version == OPENCLAW_VERSION
    assert verified.integrity == OPENCLAW_INTEGRITY

    raced = json.loads(json.dumps(valid))
    raced["dist"]["integrity"] = (
        "sha512-" + base64.b64encode(b"wrong" * 12 + b"xxxx").decode()
    )
    with pytest.raises(ProvisioningError, match="REGISTRY_INTEGRITY_MISMATCH"):
        verify_registry_document(json.dumps(raced).encode())


def test_sri_is_computed_from_downloaded_bytes(tmp_path):
    tarball = tmp_path / "openclaw.tgz"
    payload = b"verified registry payload"
    tarball.write_bytes(payload)
    expected = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()

    assert compute_sri(tarball) == expected
    with pytest.raises(ProvisioningError, match="REGISTRY_INTEGRITY_MISMATCH"):
        verify_sri(tarball, expected)
    with pytest.raises(ProvisioningError, match="REGISTRY_INTEGRITY_MISMATCH"):
        verify_sri(tarball, OPENCLAW_INTEGRITY)


def test_sri_rejects_caller_integrity_that_is_not_the_reviewed_pin(tmp_path):
    tarball = tmp_path / "openclaw.tgz"
    payload = b"attacker-selected package"
    tarball.write_bytes(payload)
    attacker_integrity = (
        "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    )

    with pytest.raises(ProvisioningError, match="REGISTRY_INTEGRITY_MISMATCH"):
        verify_sri(tarball, attacker_integrity)


def test_tar_and_installed_payload_manifests_are_byte_bound(tmp_path):
    tarball = _tarball(
        tmp_path,
        [
            ("package.json", b'{"version":"2026.7.1-2"}\n', 0o644),
            ("bin/openclaw.js", b"#!/usr/bin/env node\n", 0o755),
        ],
    )
    installed = tmp_path / "installed"
    (installed / "bin").mkdir(parents=True)
    (installed / "package.json").write_bytes(b'{"version":"2026.7.1-2"}\n')
    (installed / "bin/openclaw.js").write_bytes(b"#!/usr/bin/env node\n")
    (installed / "bin/openclaw.js").chmod(0o755)

    expected = build_tar_payload_manifest(tarball)
    actual = build_directory_manifest(installed, exclude_top_level=("node_modules",))
    require_matching_payload(expected, actual)
    assert expected.sha256 == actual.sha256
    assert [entry.path for entry in expected.entries] == [
        "bin",
        "bin/openclaw.js",
        "package.json",
    ]
    assert expected.entries[0].type == "directory"

    (installed / "bin/openclaw.js").write_bytes(b"changed\n")
    with pytest.raises(ProvisioningError, match="INSTALLED_PAYLOAD_MISMATCH"):
        require_matching_payload(
            expected,
            build_directory_manifest(installed, exclude_top_level=("node_modules",)),
        )


def test_tar_manifest_rejects_parent_traversal_and_escaping_symlink(tmp_path):
    parent = tmp_path / "parent.tgz"
    with tarfile.open(parent, "w:gz") as archive:
        member = tarfile.TarInfo("package/../../outside")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ProvisioningError, match="INSTALLED_PAYLOAD_MISMATCH"):
        build_tar_payload_manifest(parent)

    escaping = tmp_path / "escaping.tgz"
    with tarfile.open(escaping, "w:gz") as archive:
        member = tarfile.TarInfo("package/bin/openclaw")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside"
        archive.addfile(member)
    with pytest.raises(ProvisioningError, match="INSTALLED_PAYLOAD_MISMATCH"):
        build_tar_payload_manifest(escaping)


def test_pinned_config_is_exact_and_copied_once_mode_0600(tmp_path):
    assert CONFIG_PATH.read_bytes() == CONFIG_TEMPLATE_CONTENT
    destination = tmp_path / "openclaw.json"

    copy_pinned_configuration(CONFIG_PATH, destination)

    assert destination.read_bytes() == CONFIG_TEMPLATE_CONTENT
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    copy_pinned_configuration(CONFIG_PATH, destination)

    destination.write_text("{}\n", encoding="utf-8")
    before = destination.read_bytes()
    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        copy_pinned_configuration(CONFIG_PATH, destination)
    assert destination.read_bytes() == before


def test_config_copy_rejects_symlink_parent_without_external_write(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(external, target_is_directory=True)
    destination = linked_parent / "openclaw.json"

    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        copy_pinned_configuration(CONFIG_PATH, destination)

    assert list(external.iterdir()) == []


def test_config_copy_uses_no_replace_link_and_fsyncs_parent(tmp_path, monkeypatch):
    destination = tmp_path / "config" / "openclaw.json"
    destination.parent.mkdir(mode=0o700)
    observed_link: list[tuple[object, ...]] = []
    observed_directory_fsync: list[int] = []
    real_link = os.link
    real_fsync = os.fsync

    def recording_link(*args, **kwargs):
        observed_link.append((*args, kwargs))
        return real_link(*args, **kwargs)

    def recording_fsync(fd: int):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            observed_directory_fsync.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "link", recording_link)
    monkeypatch.setattr(os, "fsync", recording_fsync)

    copy_pinned_configuration(CONFIG_PATH, destination)

    assert len(observed_link) == 1
    assert observed_directory_fsync
    assert not list(destination.parent.glob(".openclaw.json.tmp-*"))


def test_node_runtime_is_bound_to_the_verified_node_tarball(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    tarball = tmp_path / "node.tar.xz"
    expected = {
        "bin/node": b"node-binary",
        "lib/node_modules/npm/bin/npm-cli.js": b"npm-cli",
    }
    with tarfile.open(tarball, "w:xz") as archive:
        for relative, payload in expected.items():
            member = tarfile.TarInfo(f"node-v{NODE_VERSION}-linux-x64/{relative}")
            member.mode = 0o755
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    node = tmp_path / "node"
    npm = tmp_path / "npm-cli.js"
    node.write_bytes(expected["bin/node"])
    npm.write_bytes(expected["lib/node_modules/npm/bin/npm-cli.js"])

    gate_module._require_node_runtime_binding(tarball, node_path=node, npm_cli_path=npm)

    npm.write_bytes(b"substituted")
    with pytest.raises(ProvisioningError, match="INSTALLER_PIN_MISMATCH"):
        gate_module._require_node_runtime_binding(
            tarball, node_path=node, npm_cli_path=npm
        )


def test_verified_node_tarball_is_installed_into_owned_prefix(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    tarball = tmp_path / "node.tar.xz"
    root = f"node-v{NODE_VERSION}-linux-x64"
    with tarfile.open(tarball, "w:xz") as archive:
        for relative, payload in {
            "bin/node": b"node-binary",
            "lib/node_modules/npm/bin/npm-cli.js": b"npm-cli",
        }.items():
            member = tarfile.TarInfo(f"{root}/{relative}")
            member.mode = 0o755
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    prefix = tmp_path / "prefix"
    prefix.mkdir(mode=0o700)

    gate_module._install_verified_node_tarball(tarball, prefix)

    assert (prefix / f"tools/node-v{NODE_VERSION}/bin/node").read_bytes() == (
        b"node-binary"
    )
    assert (prefix / "tools/node").resolve() == (prefix / f"tools/node-v{NODE_VERSION}")


def test_local_runner_scrubs_ambient_environment_and_kills_group_children(
    monkeypatch,
):
    monkeypatch.setenv("NODE_OPTIONS", "--require=/attacker.js")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid")
    runner = LocalCommandRunner(timeout_seconds=2)

    environment = runner.run(("/usr/bin/env",), environment={})

    assert "NODE_OPTIONS=" not in environment.stdout
    assert "HTTPS_PROXY=" not in environment.stdout
    with pytest.raises(ProvisioningError, match="command descendants remained"):
        runner.run(("/bin/sh", "-c", "sleep 30 &"), environment={})


def test_pgid_members_include_live_processes_and_exclude_terminal_zombies(
    monkeypatch,
):
    import holoagent0_setup.openclaw_gate as gate_module

    entries = tuple(Path(f"/proc/{pid}") for pid in (101, 102, 103, 104))
    monkeypatch.setattr(
        gate_module.Path,
        "iterdir",
        lambda path: entries if path == Path("/proc") else (),
    )
    monkeypatch.setattr(
        gate_module,
        "_read_proc_group_state",
        lambda pid: (77, {101: "S", 102: "R", 103: "Z", 104: "X"}[pid]),
    )

    assert gate_module._pgid_members(77) == (101, 102)


def test_https_fetcher_denies_redirect_before_following():
    handler = HttpsArtifactFetcher._NoRedirect()
    assert (
        handler.redirect_request(None, None, 302, "Found", {}, "https://evil") is None
    )


def test_closed_provisioning_schema_digest_is_authoritative():
    schema_sha256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    record = _valid_record(schema_sha256)

    validate_provisioning_record(record, SCHEMA_PATH)

    record["schema_sha256"] = "0" * 64
    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        validate_provisioning_record(record, SCHEMA_PATH)

    record = _valid_record(schema_sha256)
    record["unexpected"] = True
    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        validate_provisioning_record(record, SCHEMA_PATH)


@pytest.mark.parametrize("field", ["registry", "package", "payload", "installer"])
def test_pass_record_requires_concrete_artifact_evidence(field):
    schema_sha256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    record = _valid_record(schema_sha256)
    record[field] = None

    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        validate_provisioning_record(record, SCHEMA_PATH)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        (
            "before_observation",
            {
                "processes": [
                    {"pid": 7, "start_time_ticks": 1, "executable": "/tmp/openclaw"}
                ],
                "services": [],
                "listeners": [],
            },
        ),
        (
            "after_observation",
            {
                "processes": [],
                "services": [{"name": "openclaw.service", "state": "defined"}],
                "listeners": [],
            },
        ),
        ("configuration.valid", False),
        ("configuration.lint_findings", ["warning"]),
    ],
)
def test_pass_schema_requires_empty_observations_and_clean_configuration(
    mutation, value
):
    schema_sha256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    record = _valid_record(schema_sha256)
    if mutation.startswith("configuration."):
        record["configuration"][mutation.split(".", 1)[1]] = value
    else:
        record[mutation] = value

    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        validate_provisioning_record(record, SCHEMA_PATH)


def test_existing_prefix_schema_closes_mode_lineage_and_argv():
    schema_sha256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    record = _valid_record(schema_sha256)
    parent_path = "/evidence/parent/openclaw-provisioning-v1.json"
    record.update(
        provisioning_mode="VERIFIED_EXISTING_PREFIX",
        lineage={
            "parent_record_path": parent_path,
            "parent_record_sha256": "3" * 64,
            "parent_run_id": "parent-run",
            "parent_schema_sha256": "4" * 64,
            "parent_target_prefix_sha256": "5" * 64,
        },
    )
    record["installer"]["argv"] = [
        "verify-existing-prefix",
        "/prefix",
        parent_path,
    ]

    validate_provisioning_record(record, SCHEMA_PATH)

    for mode, lineage, argv in (
        ("VERIFIED_EXISTING_PREFIX", None, record["installer"]["argv"]),
        ("FRESH_INSTALL", record["lineage"], record["installer"]["argv"]),
        ("OTHER", record["lineage"], record["installer"]["argv"]),
        ("VERIFIED_EXISTING_PREFIX", record["lineage"], ["trusted-by-sentinel"]),
    ):
        mutated = json.loads(json.dumps(record))
        mutated["provisioning_mode"] = mode
        mutated["lineage"] = lineage
        mutated["installer"]["argv"] = argv
        with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
            validate_provisioning_record(mutated, SCHEMA_PATH)


@pytest.mark.parametrize(
    "bindings",
    [
        [(10, 1), (20, 1), (10, 1)],
        [(10, 1), (10, 2), (10, 1)],
    ],
    ids=["distinct-device", "forced-exdev-distinct-mount"],
)
def test_quarantine_boundary_mismatch_fails_before_observation_fetch_or_mutation(
    tmp_path, monkeypatch, bindings
):
    import holoagent0_setup.openclaw_gate as gate_module

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    observer = _EmptyObserver()
    fetcher = _FakeFetcher({})
    runtime = ProvisioningRuntime(
        observer=observer,
        runner=_RecordingRunner(paths.prefix, b""),
        fetcher=fetcher,
    )

    monkeypatch.setattr(
        gate_module,
        "_nearest_existing_filesystem",
        lambda path: bindings[
            {
                paths.output_dir: 0,
                paths.prefix: 1,
                paths.configuration_root: 2,
            }[path]
        ],
        raising=False,
    )

    with pytest.raises(ProvisioningError, match="ATOMIC_WRITE_FAILED"):
        runtime.provision(paths)

    assert observer.calls == 0
    assert fetcher.calls == []
    assert not paths.output_dir.exists()
    assert not paths.prefix.exists()
    assert not paths.configuration_root.exists()


def test_provisioning_shell_rejects_attacker_directory_symlink(tmp_path):
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    linked_wrapper = attacker / "provision_openclaw.sh"
    linked_wrapper.symlink_to(SCRIPT_PATH)

    completed = subprocess.run(
        [str(linked_wrapper), "--dry-run", "--output-dir", str(tmp_path / "out")],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "WRAPPER_IDENTITY_MISMATCH" in completed.stderr

    package_alias = attacker / "package-root"
    package_alias.symlink_to(SCRIPT_PATH.parent, target_is_directory=True)
    completed = subprocess.run(
        [
            str(package_alias / "provision_openclaw.sh"),
            "--dry-run",
            "--output-dir",
            str(tmp_path / "out"),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "WRAPPER_IDENTITY_MISMATCH" in completed.stderr


def test_provisioning_shell_accepts_dot_relative_canonical_invocation(tmp_path):
    repository_root = SCRIPT_PATH.parents[2]
    relative_wrapper = Path("./scripts/holoagent0_setup/provision_openclaw.sh")

    completed = subprocess.run(
        [str(relative_wrapper), "--dry-run", "--output-dir", str(tmp_path / "out")],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["network_performed"] is False


def test_provisioning_shell_is_syntax_valid_and_dry_run_is_network_free(tmp_path):
    subprocess.run(["bash", "-n", str(SCRIPT_PATH)], check=True)
    completed = subprocess.run(
        [str(SCRIPT_PATH), "--dry-run", "--output-dir", str(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == 0, completed.stderr
    dry_run = json.loads(completed.stdout)
    assert dry_run["package"] == "openclaw@2026.7.1-2"
    assert dry_run["node_version"] == NODE_VERSION
    assert dry_run["installer_sha256"] == INSTALLER_SHA256
    assert dry_run["network_performed"] is False


def test_provisioning_shell_ignores_hostile_path_cwd_and_pythonpath(tmp_path):
    hostile_cwd = tmp_path / "hostile-cwd"
    hostile_bin = tmp_path / "hostile-bin"
    hostile_pythonpath = tmp_path / "hostile-pythonpath"
    hostile_cwd.mkdir()
    hostile_bin.mkdir()
    hostile_pythonpath.mkdir()
    path_marker = tmp_path / "path-hijacked"
    import_marker = tmp_path / "pythonpath-hijacked"
    bash_marker = tmp_path / "bash-hijacked"
    dirname_marker = tmp_path / "dirname-hijacked"
    bash_env_marker = tmp_path / "bash-env-hijacked"
    fake_python = hostile_bin / "python3"
    fake_python.write_text(
        f"#!/bin/sh\nprintf hijacked > {path_marker}\nexit 91\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o700)
    for name, marker in (("bash", bash_marker), ("dirname", dirname_marker)):
        executable = hostile_bin / name
        executable.write_text(
            f"#!/bin/sh\nprintf hijacked > {marker}\nexit 92\n",
            encoding="utf-8",
        )
        executable.chmod(0o700)
    bash_env = tmp_path / "hostile-bash-env"
    bash_env.write_text(
        f"printf hijacked > {bash_env_marker}\n",
        encoding="utf-8",
    )
    (hostile_pythonpath / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(import_marker)!r}).write_text('hijacked')\n",
        encoding="utf-8",
    )
    (hostile_cwd / "holoagent0_setup").mkdir()
    (hostile_cwd / "holoagent0_setup/__init__.py").write_text("", encoding="utf-8")
    (hostile_cwd / "holoagent0_setup/openclaw_gate.py").write_text(
        f"from pathlib import Path\nPath({str(import_marker)!r}).write_text('cwd')\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [str(SCRIPT_PATH), "--dry-run", "--output-dir", str(tmp_path / "evidence")],
        cwd=hostile_cwd,
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{hostile_bin}:/usr/bin:/bin",
            "PYTHONPATH": str(hostile_pythonpath),
            "BASH_ENV": str(bash_env),
        },
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["network_performed"] is False
    assert not path_marker.exists()
    assert not import_marker.exists()
    assert not bash_marker.exists()
    assert not dirname_marker.exists()
    assert not bash_env_marker.exists()


def test_provisioning_shell_has_explicit_live_authorization_and_isolated_python(
    tmp_path,
):
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    assert source.startswith("#!/bin/bash -p\n")
    assert "--authorized-live-provisioning" in source
    assert "LIVE_PROVISIONING_NOT_AUTHORIZED" in source
    assert 'readonly REVIEWED_PYTHON="/usr/bin/python3.10"' in source
    assert "env -i" in source
    assert 'CDPATH= builtin cd -- "$script_parent"' in source
    assert "-I" in source
    assert "-S" in source
    assert "export PYTHONPATH" not in source
    assert '"HOME=${HOME:-/nonexistent}"' not in source

    output_dir = tmp_path / "evidence"
    completed = subprocess.run(
        [str(SCRIPT_PATH), "--output-dir", str(output_dir)],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "LIVE_PROVISIONING_NOT_AUTHORIZED" in completed.stderr
    assert not output_dir.exists()


def test_default_account_home_ignores_hostile_environment(monkeypatch, tmp_path):
    import pwd
    import holoagent0_setup.openclaw_gate as gate_module

    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    monkeypatch.setenv("HOME", str(tmp_path / "hostile-home"))

    assert gate_module._account_home() == account_home
    assert gate_module._account_home() != Path(os.environ["HOME"])


class _FakeFetcher:
    def __init__(self, payloads: Mapping[str, bytes]) -> None:
        self.payloads = dict(payloads)
        self.calls: list[tuple[str, Path]] = []

    def fetch(self, url: str, destination: Path) -> None:
        self.calls.append((url, destination))
        destination.write_bytes(self.payloads[url])


class _RecordingRunner(LocalCommandRunner):
    def __init__(self, prefix: Path, package_bytes: bytes) -> None:
        self.prefix = prefix
        self.package_bytes = package_bytes
        self.commands: list[tuple[str, ...]] = []
        self.environments: list[dict[str, str]] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        environment: dict[str, str],
        pass_fds: tuple[int, ...] = (),
    ):
        from holoagent0_setup.openclaw_gate import CommandResult

        self.commands.append(command)
        self.environments.append(dict(environment))
        if pass_fds:
            assert len(pass_fds) == 2
            assert command[3] == f"/proc/self/fd/{pass_fds[0]}"
            assert command[4] == str(pass_fds[1])
        if "--version" in command and any(part.startswith("file:") for part in command):
            package = self.prefix / "lib/node_modules/openclaw"
            (package / "bin").mkdir(parents=True)
            (package / "package.json").write_bytes(
                b'{"name":"openclaw","version":"2026.7.1-2",'
                b'"bin":{"openclaw":"bin/openclaw.js"}}\n'
            )
            (package / "bin/openclaw.js").write_bytes(self.package_bytes)
            (package / "bin/openclaw.js").chmod(0o755)
            (self.prefix / "bin").mkdir()
            (self.prefix / "bin/openclaw").symlink_to(
                "../lib/node_modules/openclaw/bin/openclaw.js"
            )
            (self.prefix / "node/bin").mkdir(parents=True)
            (self.prefix / "node/bin/node").write_bytes(b"node")
            (self.prefix / "node/bin/node").chmod(0o755)
            (self.prefix / "node/lib/node_modules/npm/bin").mkdir(parents=True)
            (self.prefix / "node/lib/node_modules/npm/bin/npm-cli.js").write_bytes(
                b"npm"
            )
            (self.prefix / "node/lib/node_modules/npm/package.json").write_bytes(
                b'{"name":"npm","version":"11.0.0"}\n'
            )
            return CommandResult(
                0,
                '{"event":"holoagent0-reviewed-subset","ok":true,'
                '"version":"2026.7.1-2"}',
                "",
            )
        if command[-3:] == ("config", "validate", "--json"):
            return CommandResult(0, '{"valid":true}', "")
        if command[-1:] == ("--version",):
            return CommandResult(0, OPENCLAW_VERSION + "\n", "")
        if command[-5:] == (
            "gateway",
            "status",
            "--deep",
            "--no-probe",
            "--json",
        ):
            return CommandResult(
                0,
                '{"service":{"loaded":false,"runtime":{"status":"stopped"}}}',
                "",
            )
        if "--only" in command:
            return CommandResult(0, '{"checksRun":1,"findings":[]}', "")
        if "doctor" in command:
            return CommandResult(0, '{"checksRun":3,"findings":[]}', "")
        raise AssertionError(command)


class _EmptyObserver:
    def __init__(self) -> None:
        self.calls = 0

    def observe(self):
        from holoagent0_setup.openclaw_gate import LifecycleObservation

        self.calls += 1
        return LifecycleObservation((), (), ())


def _runtime_tarball(tmp_path: Path) -> tuple[bytes, bytes]:
    cli = b"#!/usr/bin/env node\n"
    path = _tarball(
        tmp_path,
        [
            (
                "package.json",
                b'{"name":"openclaw","version":"2026.7.1-2",'
                b'"bin":{"openclaw":"bin/openclaw.js"}}\n',
                0o644,
            ),
            ("bin/openclaw.js", cli, 0o755),
        ],
    )
    return path.read_bytes(), cli


def test_provisioning_runtime_refuses_preexisting_state_before_fetch_or_mutation(
    tmp_path,
):
    from holoagent0_setup.openclaw_gate import (
        LifecycleObservation,
        ListenerObservation,
    )

    class ExistingObserver:
        def observe(self):
            return LifecycleObservation(
                (), (), (ListenerObservation("127.0.0.1", 18789, 42),)
            )

    fetcher = _FakeFetcher({})
    runner = _RecordingRunner(tmp_path / "prefix", b"")
    runtime = ProvisioningRuntime(
        observer=ExistingObserver(), runner=runner, fetcher=fetcher
    )
    paths = ProvisioningPaths.for_test_root(tmp_path)

    with pytest.raises(ProvisioningError, match="PREEXISTING_OPENCLAW"):
        runtime.provision(paths)

    assert fetcher.calls == []
    assert runner.commands == []
    assert not paths.prefix.exists()
    assert not paths.configuration.parent.exists()
    failed_record = json.loads(paths.record.read_text())
    assert failed_record["status"] == "FAIL"
    assert failed_record["reason"] == "PREEXISTING_OPENCLAW"
    validate_provisioning_record(failed_record, SCHEMA_PATH)


def test_provisioning_runtime_rejects_symlinked_prefix_before_fetch(tmp_path):
    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    paths.output_dir.mkdir(mode=0o700, parents=True)
    external = tmp_path / "external"
    external.mkdir()
    paths.prefix.symlink_to(external, target_is_directory=True)
    fetcher = _FakeFetcher({})
    runtime = ProvisioningRuntime(
        observer=_EmptyObserver(),
        runner=_RecordingRunner(paths.prefix, b""),
        fetcher=fetcher,
    )

    with pytest.raises(ProvisioningError, match="INSTALLER_PIN_MISMATCH"):
        runtime.provision(paths)

    assert fetcher.calls == []
    assert list(external.iterdir()) == []


def test_provisioning_paths_reject_overlapping_authority_roots(tmp_path):
    from dataclasses import replace

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    overlapping = replace(paths, prefix=paths.download_dir)
    runtime = ProvisioningRuntime(
        observer=_EmptyObserver(),
        runner=_RecordingRunner(overlapping.prefix, b""),
        fetcher=_FakeFetcher({}),
    )

    with pytest.raises(ProvisioningError, match="paths overlap"):
        runtime.provision(overlapping)


def test_provisioning_runtime_binds_local_tarball_cli_token_and_atomic_record(
    tmp_path, monkeypatch
):
    import holoagent0_setup.openclaw_gate as gate_module

    tarball_bytes, cli_bytes = _runtime_tarball(tmp_path)
    registry = json.dumps(
        {
            "version": OPENCLAW_VERSION,
            "dist": {
                "tarball": gate_module.TARBALL_URL,
                "integrity": OPENCLAW_INTEGRITY,
                "shasum": "a" * 40,
            },
        }
    ).encode()
    installer = b"#!/bin/sh\n"
    fetcher = _FakeFetcher(
        {
            gate_module.REGISTRY_URL: registry,
            gate_module.TARBALL_URL: tarball_bytes,
            gate_module.INSTALLER_URL: installer,
            gate_module.NODE_TARBALL_URL: b"node-tarball",
        }
    )
    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    observer = _EmptyObserver()
    runner = _RecordingRunner(paths.prefix, cli_bytes)
    runtime = ProvisioningRuntime(observer=observer, runner=runner, fetcher=fetcher)
    real_sha256 = gate_module._require_sha256
    real_verify_sri = gate_module.verify_sri

    def test_sha256(path: Path, expected: str, reason: str) -> str:
        if path.name in {
            "install-cli.sh",
            "node-v24.15.0-linux-x64.tar.xz",
        }:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        return real_sha256(path, expected, reason)

    monkeypatch.setattr(gate_module, "_require_sha256", test_sha256)
    monkeypatch.setattr(
        gate_module,
        "verify_sri",
        lambda path, expected: (
            OPENCLAW_INTEGRITY
            if expected == OPENCLAW_INTEGRITY
            else real_verify_sri(path, expected)
        ),
    )
    monkeypatch.setattr(
        gate_module,
        "_require_node_runtime_binding",
        lambda tarball, *, node_path, npm_cli_path: None,
    )
    monkeypatch.setattr(
        gate_module,
        "_install_verified_node_tarball",
        lambda tarball, prefix: None,
    )
    monkeypatch.setattr(
        gate_module,
        "_verify_preinstalled_node_runtime",
        lambda runner, prefix: None,
    )
    real_sealed_file = gate_module._create_sealed_file_fd

    def test_sealed_file(path: Path, expected: str, *, label: str) -> int:
        if path.name == "install-cli.sh":
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
        return real_sealed_file(path, expected, label=label)

    monkeypatch.setattr(gate_module, "_create_sealed_file_fd", test_sealed_file)
    monkeypatch.setattr(gate_module.secrets, "token_urlsafe", lambda size: "t" * 43)

    record = runtime.provision(paths)

    assert record["status"] == "PASS"
    assert paths.record.exists()
    assert json.loads(paths.record.read_text()) == record
    validate_provisioning_record(record, SCHEMA_PATH)
    install_command = runner.commands[0]
    local_specs = [part for part in install_command if part.startswith("file:")]
    assert local_specs == [f"file:{paths.download_dir / 'openclaw.tgz'}"]
    assert observer.calls == 2
    assert paths.configuration.read_bytes() == CONFIG_TEMPLATE_CONTENT
    serialized = paths.record.read_text()
    assert "t" * 43 not in serialized
    assert "OPENCLAW_GATEWAY_TOKEN" not in runner.environments[1]
    assert all("OPENCLAW_GATEWAY_TOKEN" in env for env in runner.environments[2:])
    assert verify_provisioning_record_file(paths.record, paths) == record

    for field, forged_value in (
        ("configuration_template_path", "/attacker/template.json"),
        ("configuration_template_sha256", "0" * 64),
        ("configuration_template_git_blob", "0" * 40),
    ):
        forged_pin_record = json.loads(json.dumps(record))
        forged_pin_record["pins"][field] = forged_value
        forged_pin_path = paths.output_dir / f"forged-{field}.json"
        forged_pin_path.write_text(json.dumps(forged_pin_record), encoding="utf-8")
        with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
            verify_provisioning_record_file(forged_pin_path, paths)

    from dataclasses import replace

    reuse_output = tmp_path / "reuse-evidence"
    reuse_paths = replace(
        paths,
        output_dir=reuse_output,
        download_dir=reuse_output / "downloads",
        record=reuse_output / "openclaw-provisioning-v1.json",
        quarantine_dir=reuse_output / "quarantine",
        previous_record=paths.record,
    )
    reuse_record = runtime.provision(reuse_paths)

    assert reuse_record["provisioning_mode"] == "VERIFIED_EXISTING_PREFIX"
    assert reuse_record["installer"]["argv"] == [
        "verify-existing-prefix",
        str(paths.prefix),
        str(paths.record),
    ]
    assert reuse_record["lineage"] == {
        "parent_record_path": str(paths.record),
        "parent_record_sha256": hashlib.sha256(paths.record.read_bytes()).hexdigest(),
        "parent_run_id": record["run_id"],
        "parent_schema_sha256": record["schema_sha256"],
        "parent_target_prefix_sha256": record["target_prefix"]["sha256"],
    }
    assert verify_provisioning_record_file(reuse_paths.record, reuse_paths) == (
        reuse_record
    )
    forged_lineage = json.loads(json.dumps(reuse_record))
    forged_lineage["lineage"]["parent_run_id"] = "wrong-run"
    forged_lineage_path = reuse_output / "forged-lineage.json"
    forged_lineage_path.write_text(json.dumps(forged_lineage), encoding="utf-8")
    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        verify_provisioning_record_file(forged_lineage_path, reuse_paths)

    registry_path = paths.download_dir / "registry.json"
    registry_bytes = registry_path.read_bytes()
    registry_path.write_bytes(registry_bytes + b" ")
    with pytest.raises(ProvisioningError, match="REGISTRY_INTEGRITY_MISMATCH"):
        verify_provisioning_record_file(paths.record, paths)
    registry_path.write_bytes(registry_bytes)

    package_entry = paths.prefix / "lib/node_modules/openclaw/bin/openclaw.js"
    package_entry.write_bytes(b"#!/usr/bin/env node\n// forged\n")
    forged_payload = build_directory_manifest(
        paths.prefix / "lib/node_modules/openclaw",
        exclude_top_level=("node_modules",),
    )
    forged_prefix = build_directory_manifest(paths.prefix)
    forged_record = json.loads(json.dumps(record))
    forged_record["payload"].update(
        expected_manifest_sha256=forged_payload.sha256,
        actual_manifest_sha256=forged_payload.sha256,
    )
    forged_record["target_prefix"] = {
        "root": str(paths.prefix),
        "sha256": forged_prefix.sha256,
        "entries": [entry.as_dict() for entry in forged_prefix.entries],
    }
    forged_path = paths.output_dir / "forged-provisioning.json"
    forged_path.write_text(json.dumps(forged_record), encoding="utf-8")

    with pytest.raises(ProvisioningError, match="INSTALLED_PAYLOAD_MISMATCH"):
        verify_provisioning_record_file(forged_path, paths)


def test_installer_success_requires_explicit_pinned_version():
    import holoagent0_setup.openclaw_gate as gate_module

    assert gate_module._installer_reported_success(
        '{"event":"holoagent0-reviewed-subset","ok":true,"version":"2026.7.1-2"}'
    )
    assert not gate_module._installer_reported_success('{"event":"done","ok":true}')
    assert not gate_module._installer_reported_success(
        '{"event":"done","ok":true,"version":"2026.7.1-2"}'
    )
    assert not gate_module._installer_reported_success(
        '{"event":"holoagent0-reviewed-subset","ok":true,'
        '"version":"2026.7.1-2"}\n'
        '{"event":"holoagent0-reviewed-subset","ok":true,'
        '"version":"2026.7.1-2"}'
    )


def test_pinned_installer_wrapper_is_replaced_by_declared_bin_wrapper(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    prefix = tmp_path / "prefix"
    package = prefix / "tools/node-v24.15.0/lib/node_modules/openclaw"
    (package / "bin").mkdir(parents=True)
    (package / "bin/openclaw.mjs").write_bytes(b"#!/usr/bin/env node\n")
    (prefix / "bin").mkdir()
    installer_wrapper = prefix / "bin/openclaw"
    installer_wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'exec "{prefix}/tools/node/bin/node" '
        f'"{package}/dist/entry.js" "$@"\n',
        encoding="utf-8",
    )
    installer_wrapper.chmod(0o755)

    gate_module._install_reviewed_launcher(prefix, package, "bin/openclaw.mjs")

    assert (
        gate_module._require_launcher_binding(prefix, package, "bin/openclaw.mjs")
        == installer_wrapper
    )
    assert str(package / "bin/openclaw.mjs") in installer_wrapper.read_text()


def test_service_definition_roots_include_global_user_units():
    import inspect
    from holoagent0_setup.openclaw_gate import LocalLifecycleObserver

    source = inspect.getsource(LocalLifecycleObserver._services)
    assert 'Path("/etc/systemd/user")' in source


def test_preexisting_prefix_is_verified_before_any_fetch(monkeypatch, tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module
    from dataclasses import replace

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    paths.prefix.mkdir(mode=0o700, parents=True)
    previous = tmp_path / "previous.json"
    paths = replace(paths, previous_record=previous)
    events: list[str] = []
    fetcher = _FakeFetcher({})
    runtime = ProvisioningRuntime(
        observer=_EmptyObserver(),
        runner=_RecordingRunner(paths.prefix, b""),
        fetcher=fetcher,
    )

    monkeypatch.setattr(
        gate_module,
        "_build_reuse_lineage",
        lambda record, value: (
            events.append("verify-record")
            or {
                "parent_record_path": str(record),
                "parent_record_sha256": "1" * 64,
                "parent_run_id": "parent-run",
                "parent_schema_sha256": "2" * 64,
                "parent_target_prefix_sha256": "3" * 64,
            }
        ),
    )
    monkeypatch.setattr(
        gate_module,
        "_find_package_root",
        lambda prefix: paths.prefix / "package",
    )
    monkeypatch.setattr(
        gate_module,
        "_verify_installed_package",
        lambda package: ({}, "bin/openclaw.mjs"),
    )
    monkeypatch.setattr(
        gate_module,
        "_require_launcher_binding",
        lambda prefix, package, declared: paths.prefix / "bin/openclaw",
    )
    monkeypatch.setattr(
        gate_module,
        "_find_node_binary",
        lambda prefix: paths.prefix / "tools/node/bin/node",
    )
    monkeypatch.setattr(
        gate_module.Path,
        "resolve",
        lambda self, strict=False: self.absolute(),
    )
    monkeypatch.setattr(
        gate_module.OpenClawGate,
        "preexisting",
        lambda self, *args, **kwargs: (
            events.append("status-no-probe")
            or gate_module.GateResult("FAIL", "PREEXISTING_OPENCLAW", {})
        ),
    )

    with pytest.raises(ProvisioningError, match="PREEXISTING_OPENCLAW"):
        runtime.provision(paths)

    assert events == ["verify-record", "status-no-probe"]
    assert fetcher.calls == []
    assert json.loads(paths.record.read_text())["reason"] == "PREEXISTING_OPENCLAW"


def test_failed_process_identity_acquisition_cleans_unregistered_session(
    monkeypatch,
):
    import holoagent0_setup.openclaw_gate as gate_module

    cleaned: list[int] = []
    monkeypatch.setattr(
        gate_module,
        "_read_proc_start_time",
        lambda pid: (_ for _ in ()).throw(FileNotFoundError(pid)),
    )
    monkeypatch.setattr(
        gate_module,
        "_terminate_unregistered_session",
        lambda process: cleaned.append(process.pid),
    )

    with pytest.raises(ProvisioningError, match="TOOL_RUNTIME_ERROR"):
        LocalCommandRunner().run(("/bin/true",), environment={})

    assert len(cleaned) == 1


def test_failed_postflight_observer_is_recorded_as_unavailable(tmp_path):
    class PostflightFailureObserver:
        def __init__(self) -> None:
            self.calls = 0

        def observe(self):
            from holoagent0_setup.openclaw_gate import LifecycleObservation

            self.calls += 1
            if self.calls == 1:
                return LifecycleObservation((), (), ())
            raise OSError("observer unavailable")

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    runtime = ProvisioningRuntime(
        observer=PostflightFailureObserver(),
        runner=_RecordingRunner(paths.prefix, b""),
        fetcher=_FakeFetcher({}),
    )

    with pytest.raises(ProvisioningError, match="TOOL_RUNTIME_ERROR"):
        runtime.provision(paths)

    record = json.loads(paths.record.read_text(encoding="utf-8"))
    assert record["status"] == "FAIL"
    assert record["reason"] == "TOOL_RUNTIME_ERROR"
    assert record["after_observation"] == {
        "state": "UNAVAILABLE",
        "reason": "TOOL_RUNTIME_ERROR",
    }
    validate_provisioning_record(record, SCHEMA_PATH)


def test_pass_record_rejects_unavailable_postflight_observation():
    schema_sha256 = hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()
    record = _valid_record(schema_sha256)
    record["after_observation"] = {
        "state": "UNAVAILABLE",
        "reason": "TOOL_RUNTIME_ERROR",
    }

    with pytest.raises(ProvisioningError, match="OPENCLAW_CONFIG_MISMATCH"):
        validate_provisioning_record(record, SCHEMA_PATH)


def test_identity_bound_quarantine_moves_the_expected_directory(tmp_path):
    import holoagent0_setup.openclaw_gate as gate_module

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    paths.output_dir.mkdir(mode=0o700, parents=True)
    source = paths.prefix
    source.mkdir(mode=0o700)
    (source / "owned").write_text("expected", encoding="utf-8")
    metadata = source.lstat()
    expected_identity = (metadata.st_dev, metadata.st_ino)

    gate_module._quarantine_owned_directory(
        paths,
        source,
        expected_identity,
        label="prefix",
    )

    assert not source.exists()
    quarantined = tuple(paths.quarantine_dir.iterdir())
    assert len(quarantined) == 1
    assert (quarantined[0].stat().st_dev, quarantined[0].stat().st_ino) == (
        expected_identity
    )
    assert (quarantined[0] / "owned").read_text(encoding="utf-8") == "expected"


def test_identity_bound_quarantine_restores_source_swapped_before_exchange(
    tmp_path, monkeypatch
):
    import holoagent0_setup.openclaw_gate as gate_module

    paths = ProvisioningPaths.for_test_root(tmp_path / "runtime")
    paths.output_dir.mkdir(mode=0o700, parents=True)
    source = paths.prefix
    source.mkdir(mode=0o700)
    (source / "owned").write_text("expected", encoding="utf-8")
    expected_metadata = source.lstat()
    expected_identity = (expected_metadata.st_dev, expected_metadata.st_ino)
    saved_expected = source.parent / "saved-expected"
    unrelated = source.parent / "unrelated"
    unrelated.mkdir(mode=0o700)
    (unrelated / "owned").write_text("unrelated", encoding="utf-8")
    unrelated_identity = (unrelated.stat().st_dev, unrelated.stat().st_ino)
    real_exchange = gate_module._rename_exchange
    calls = 0

    def swap_then_exchange(
        source_parent_fd: int,
        source_name: str,
        destination_parent_fd: int,
        destination_name: str,
    ) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            os.rename(source, saved_expected)
            os.rename(unrelated, source)
        real_exchange(
            source_parent_fd,
            source_name,
            destination_parent_fd,
            destination_name,
        )

    monkeypatch.setattr(gate_module, "_rename_exchange", swap_then_exchange)

    with pytest.raises(ProvisioningError, match="owned identity changed"):
        gate_module._quarantine_owned_directory(
            paths,
            source,
            expected_identity,
            label="prefix",
        )

    assert calls == 2
    assert (source.stat().st_dev, source.stat().st_ino) == unrelated_identity
    assert (source / "owned").read_text(encoding="utf-8") == "unrelated"
    assert (saved_expected.stat().st_dev, saved_expected.stat().st_ino) == (
        expected_identity
    )
    assert list(paths.quarantine_dir.iterdir()) == []
