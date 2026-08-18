"""Closed standalone invocation and retained run-root authority contracts."""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import pickle
import stat

import pytest

import holoagent0_setup.invocation as invocation_module
from holoagent0_setup.invocation import (
    InvocationError,
    RunRootAuthority,
    _InvocationSources,
    _parse_offline_invocation,
)


_RUN_ID = "workstation-offline-20260818T010203Z-0123456789abcdef0123456789abcdef"
_OTHER_RUN_ID = "workstation-offline-20260818T010203Z-fedcba9876543210fedcba9876543210"
_CONCRETE_POSIX_PATH = type(Path())


class _LyingPosixPath(_CONCRETE_POSIX_PATH):
    def __eq__(self, _other):
        return True

    def __ne__(self, _other):
        return False

    __hash__ = _CONCRETE_POSIX_PATH.__hash__


class _DeceptivePosixPath(_CONCRETE_POSIX_PATH):
    def __new__(cls, actual_path, claimed_path):
        instance = super().__new__(cls, actual_path)
        instance._claimed_path = os.fspath(claimed_path)
        return instance

    def __fspath__(self):
        return self._claimed_path

    def __str__(self):
        return self._claimed_path


def _owned_output_root(parent: Path, name: str = "offline-output") -> Path:
    output_root = parent / name
    output_root.mkdir(mode=0o700)
    output_root.chmod(0o700)
    return output_root


def _sources(tmp_path: Path, **changes: object) -> _InvocationSources:
    values = {
        "now_utc": lambda: datetime(2026, 8, 18, 1, 2, 3, tzinfo=timezone.utc),
        "token_bytes": lambda size: bytes(range(size)),
        "cwd": lambda: tmp_path,
        "effective_uid": os.geteuid,
    }
    values.update(changes)
    return _InvocationSources(**values)


def test_public_parse_generates_closed_standalone_offline_invocation(tmp_path):
    output_root = _owned_output_root(tmp_path)
    invocation = _parse_offline_invocation(
        ["--output-root", str(output_root)],
        sources=_InvocationSources(
            now_utc=lambda: datetime(2026, 8, 18, 1, 2, 3, tzinfo=timezone.utc),
            token_bytes=lambda size: bytes(range(size)),
            cwd=lambda: tmp_path,
            effective_uid=os.geteuid,
        ),
    )

    assert invocation.mode == "workstation_offline"
    assert invocation.run_id == (
        "workstation-offline-20260818T010203Z-000102030405060708090a0b0c0d0e0f"
    )
    assert invocation.invocation_role == "standalone"
    assert invocation.parent_run_id is None
    assert invocation.lineage_nonce is None
    assert invocation.run_root_authority.expected_run_root == (
        output_root / invocation.run_id
    )
    assert not invocation.run_root_authority.expected_run_root.exists()
    invocation.run_root_authority.close()


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--output-root", "one", "--output-root", "two"],
        ["--output-roo", "one"],
        ["--unknown", "one"],
        ["positional"],
        ["--run-id", "chosen", "--output-root", "one"],
        ["--mode", "workstation_offline", "--output-root", "one"],
        ["--parent-run-id", "parent", "--output-root", "one"],
        ["--lineage-nonce", "a" * 64, "--output-root", "one"],
        ["--factory", "module.factory", "--output-root", "one"],
        ["--plugin", "chosen", "--output-root", "one"],
        ["--module", "chosen", "--output-root", "one"],
        ["--command", "chosen", "--output-root", "one"],
        ["--tool", "chosen", "--output-root", "one"],
    ],
)
def test_public_offline_invocation_rejects_nonclosed_grammar(tmp_path, argv):
    with pytest.raises(InvocationError, match="invalid offline invocation"):
        _parse_offline_invocation(argv, sources=_sources(tmp_path))


def test_public_offline_invocation_allows_help_to_exit_zero(tmp_path):
    with pytest.raises(SystemExit) as observed:
        _parse_offline_invocation(["--help"], sources=_sources(tmp_path))

    assert observed.value.code == 0


def test_public_offline_invocation_anchors_relative_root_without_resolving(
    tmp_path,
):
    output_root = _owned_output_root(tmp_path)
    invocation = _parse_offline_invocation(
        ["--output-root", output_root.name], sources=_sources(tmp_path)
    )

    assert invocation.output_root == output_root
    invocation.run_root_authority.close()


def test_public_offline_invocation_creates_only_final_output_root_component(tmp_path):
    output_root = tmp_path / "new-output"

    invocation = _parse_offline_invocation(
        ["--output-root", str(output_root)], sources=_sources(tmp_path)
    )

    assert output_root.is_dir()
    assert stat.S_IMODE(output_root.stat().st_mode) == 0o700
    assert not invocation.run_root_authority.expected_run_root.exists()
    invocation.run_root_authority.close()


def test_public_offline_invocation_rejects_recursively_missing_parent(tmp_path):
    output_root = tmp_path / "missing" / "output"

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)], sources=_sources(tmp_path)
        )

    assert not output_root.parent.exists()


@pytest.mark.parametrize("symlink_component", ["intermediate", "final"])
def test_public_offline_invocation_rejects_symlink_at_every_component(
    tmp_path, symlink_component
):
    safe = tmp_path / "safe"
    safe.mkdir(mode=0o700)
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    if symlink_component == "intermediate":
        link = safe / "linked-parent"
        link.symlink_to(target, target_is_directory=True)
        output_root = link / "output"
    else:
        link = safe / "output"
        link.symlink_to(target, target_is_directory=True)
        output_root = link

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)], sources=_sources(tmp_path)
        )


def test_public_offline_invocation_rejects_wrong_output_root_type(tmp_path):
    output_root = tmp_path / "not-a-directory"
    output_root.write_text("material", encoding="utf-8")

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)], sources=_sources(tmp_path)
        )


def test_public_offline_invocation_rejects_wrong_output_root_owner(tmp_path):
    output_root = _owned_output_root(tmp_path)

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)],
            sources=_sources(tmp_path, effective_uid=lambda: os.geteuid() + 1),
        )


@pytest.mark.parametrize("mode", [0o750, 0o770, 0o707])
def test_public_offline_invocation_rejects_wrong_output_root_mode(tmp_path, mode):
    output_root = _owned_output_root(tmp_path)
    output_root.chmod(mode)

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)], sources=_sources(tmp_path)
        )


@pytest.mark.parametrize("parent_mode", [0o720, 0o702])
def test_public_offline_invocation_rejects_writable_creation_parent(
    tmp_path, parent_mode
):
    parent = tmp_path / "unsafe-parent"
    parent.mkdir(mode=0o700)
    parent.chmod(parent_mode)

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(parent / "output")], sources=_sources(tmp_path)
        )

    assert not (parent / "output").exists()


def test_public_offline_invocation_requires_aware_utc_clock(tmp_path):
    output_root = _owned_output_root(tmp_path)

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)],
            sources=_sources(
                tmp_path,
                now_utc=lambda: datetime(2026, 8, 18, 1, 2, 3),
            ),
        )


def test_public_offline_invocation_requires_exact_random_material(tmp_path):
    output_root = _owned_output_root(tmp_path)

    with pytest.raises(InvocationError):
        _parse_offline_invocation(
            ["--output-root", str(output_root)],
            sources=_sources(tmp_path, token_bytes=lambda _size: b"too-short"),
        )


def test_public_offline_invocation_requests_exactly_sixteen_random_bytes(tmp_path):
    output_root = _owned_output_root(tmp_path)
    requested = []

    def token_bytes(size):
        requested.append(size)
        return b"\x01" * size

    invocation = _parse_offline_invocation(
        ["--output-root", str(output_root)],
        sources=_sources(tmp_path, token_bytes=token_bytes),
    )

    assert requested == [16]
    invocation.run_root_authority.close()


@pytest.mark.parametrize(
    "basename",
    [
        "run-authority",
        "../" + _RUN_ID,
        _RUN_ID.upper(),
        "workstation-offline-20260818T010203Z-0" * 2,
    ],
)
def test_run_root_authority_rejects_unsafe_or_nongenerated_basename(tmp_path, basename):
    output_root = _owned_output_root(tmp_path)

    with pytest.raises(InvocationError):
        RunRootAuthority.open(output_root, basename)


def test_run_root_authority_is_nonserializable(tmp_path):
    authority = RunRootAuthority.open(_owned_output_root(tmp_path), _RUN_ID)
    try:
        with pytest.raises(TypeError):
            pickle.dumps(authority)
    finally:
        authority.close()


def test_run_root_authority_cannot_be_forged_by_direct_construction(tmp_path):
    authority = RunRootAuthority.open(_owned_output_root(tmp_path), _RUN_ID)
    descriptor = authority._output_root_fd
    identity = authority._output_root_identity
    expected = authority.expected_run_root
    effective_uid = authority._effective_uid
    authority.close()
    exposed_seal = getattr(invocation_module, "_RUN_ROOT_AUTHORITY_SEAL", None)
    constructor_fields = {
        "output_root_fd": descriptor,
        "output_root_identity": identity,
        "expected_run_root": expected,
        "run_basename": _RUN_ID,
        "effective_uid": effective_uid,
    }
    if exposed_seal is not None:
        constructor_fields["_seal"] = exposed_seal

    with pytest.raises(InvocationError):
        RunRootAuthority(**constructor_fields)


def _forge_run_root_authority(
    output_root: Path,
    *,
    run_basename: str,
    expected_run_root: Path,
    identity_offset: int = 0,
) -> tuple[RunRootAuthority, int]:
    descriptor = os.open(
        output_root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    observed = os.fstat(descriptor)
    authority = object.__new__(RunRootAuthority)
    authority._consumed = False
    authority._effective_uid = os.geteuid()
    authority._expected_run_root = expected_run_root
    authority._output_root_fd = descriptor
    authority._output_root_identity = (
        observed.st_dev,
        observed.st_ino + identity_offset,
    )
    authority._run_basename = run_basename
    if "_output_root" in RunRootAuthority.__slots__:
        authority._output_root = output_root
    return authority, descriptor


def test_run_root_authority_revalidates_forged_unsafe_basename_before_mkdir(
    tmp_path,
):
    output_root = _owned_output_root(tmp_path)
    invalid_run_root = output_root / "not-a-generated-run-id"
    authority, descriptor = _forge_run_root_authority(
        output_root,
        run_basename=invalid_run_root.name,
        expected_run_root=invalid_run_root,
    )

    with pytest.raises(InvocationError):
        authority.create(invalid_run_root)

    assert authority.consumed is True
    assert not invalid_run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_recomputes_forged_expected_path_before_mkdir(tmp_path):
    output_root = _owned_output_root(tmp_path)
    actual_run_root = output_root / _RUN_ID
    claimed_run_root = output_root / _OTHER_RUN_ID
    authority, descriptor = _forge_run_root_authority(
        output_root,
        run_basename=_RUN_ID,
        expected_run_root=claimed_run_root,
    )

    with pytest.raises(InvocationError):
        authority.create(claimed_run_root)

    assert authority.consumed is True
    assert not actual_run_root.exists()
    assert not claimed_run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_revalidates_forged_identity_before_mkdir(tmp_path):
    output_root = _owned_output_root(tmp_path)
    run_root = output_root / _RUN_ID
    authority, descriptor = _forge_run_root_authority(
        output_root,
        run_basename=_RUN_ID,
        expected_run_root=run_root,
        identity_offset=1,
    )

    with pytest.raises(InvocationError):
        authority.create(run_root)

    assert authority.consumed is True
    assert not run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_rejects_forged_lying_stored_path_before_mkdir(
    tmp_path,
):
    output_root = _owned_output_root(tmp_path)
    actual_run_root = output_root / _RUN_ID
    claimed_run_root = tmp_path / "outside" / _RUN_ID
    lying_expected = _LyingPosixPath(claimed_run_root)
    authority, descriptor = _forge_run_root_authority(
        output_root,
        run_basename=_RUN_ID,
        expected_run_root=lying_expected,
    )

    with pytest.raises(InvocationError):
        authority.create(claimed_run_root)

    assert authority.consumed is True
    assert not actual_run_root.exists()
    assert not claimed_run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_rejects_deceptive_path_argument_before_mkdir(tmp_path):
    output_root = _owned_output_root(tmp_path)
    actual_run_root = output_root / _RUN_ID
    claimed_run_root = tmp_path / "outside-argument" / _RUN_ID
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    descriptor = authority._output_root_fd
    deceptive_argument = _DeceptivePosixPath(actual_run_root, claimed_run_root)

    with pytest.raises(InvocationError):
        authority.create(deceptive_argument)

    assert authority.consumed is True
    assert not actual_run_root.exists()
    assert not claimed_run_root.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_open_rejects_deceptive_path_subclass(tmp_path):
    actual_output_root = tmp_path / "actual-subclass-root"
    claimed_output_root = tmp_path / "claimed-subclass-root"
    deceptive_output_root = _DeceptivePosixPath(
        actual_output_root,
        claimed_output_root,
    )

    with pytest.raises(InvocationError):
        RunRootAuthority.open(deceptive_output_root, _RUN_ID)

    assert not actual_output_root.exists()
    assert not claimed_output_root.exists()


def test_run_root_authority_creates_exact_mode_and_consumes_descriptor(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    retained_expected = authority.expected_run_root

    created = authority.create(output_root / _RUN_ID)

    assert type(created) is _CONCRETE_POSIX_PATH
    assert created == output_root / _RUN_ID
    assert created is not retained_expected
    assert created.is_dir()
    assert stat.S_IMODE(created.stat().st_mode) == 0o700
    assert authority.consumed is True


def test_run_root_authority_retains_directory_cloexec_descriptor(tmp_path):
    authority = RunRootAuthority.open(_owned_output_root(tmp_path), _RUN_ID)
    descriptor = authority._output_root_fd
    try:
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        assert fcntl.fcntl(descriptor, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    finally:
        authority.close()


def test_run_root_authority_rejects_wrong_expected_path_and_consumes(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)

    with pytest.raises(InvocationError):
        authority.create(output_root / f"{_RUN_ID}0")

    assert authority.consumed is True
    assert not authority.expected_run_root.exists()


def test_run_root_authority_rejects_parent_identity_drift(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    moved = tmp_path / "moved-output"
    output_root.rename(moved)
    output_root.mkdir(mode=0o700)

    with pytest.raises(InvocationError):
        authority.create(output_root / _RUN_ID)

    assert authority.consumed is True
    assert not (output_root / _RUN_ID).exists()
    assert not (moved / _RUN_ID).exists()


def test_run_root_authority_rejects_parent_mode_drift(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    output_root.chmod(0o750)

    with pytest.raises(InvocationError):
        authority.create(output_root / _RUN_ID)

    assert authority.consumed is True
    assert not authority.expected_run_root.exists()


def test_run_root_authority_rejects_collision_without_reuse(tmp_path):
    output_root = _owned_output_root(tmp_path)
    collision = output_root / _RUN_ID
    collision.mkdir(mode=0o700)
    marker = collision / "material"
    marker.write_text("retain", encoding="utf-8")
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    descriptor = authority._output_root_fd

    with pytest.raises(InvocationError):
        authority.create(collision)

    assert authority.consumed is True
    assert marker.read_text(encoding="utf-8") == "retain"
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_run_root_authority_rejects_replay_without_deleting_created_root(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    created = authority.create(output_root / _RUN_ID)

    with pytest.raises(InvocationError):
        authority.create(output_root / _RUN_ID)

    assert created.is_dir()


def test_run_root_authority_close_consumes_and_closes_descriptor(tmp_path):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    descriptor = authority._output_root_fd

    authority.close()

    assert authority.consumed is True
    with pytest.raises(OSError):
        os.fstat(descriptor)


@pytest.mark.parametrize("drift", ["identity", "owner", "mode"])
def test_run_root_authority_rejects_post_mkdir_drift_and_retains_material(
    tmp_path, monkeypatch, drift
):
    output_root = _owned_output_root(tmp_path)
    authority = RunRootAuthority.open(output_root, _RUN_ID)
    original_stat = invocation_module.os.stat

    def drifted_stat(path, *args, **kwargs):
        observed = original_stat(path, *args, **kwargs)
        if path != _RUN_ID or kwargs.get("dir_fd") is None:
            return observed
        values = list(observed)
        if drift == "identity":
            values[1] += 1
        elif drift == "owner":
            values[4] += 1
        else:
            values[0] = (values[0] & ~0o777) | 0o755
        return os.stat_result(values)

    monkeypatch.setattr(invocation_module.os, "stat", drifted_stat)

    with pytest.raises(InvocationError):
        authority.create(output_root / _RUN_ID)

    assert authority.consumed is True
    assert (output_root / _RUN_ID).is_dir()
