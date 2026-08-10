import errno
import json
import os
from pathlib import Path
import re
import shutil

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"


def _namespace():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision13_test"}
    padding = "\n" * source[: match.start(1)].count("\n")
    exec(compile(padding + match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=1.0)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=1.0)
    return staged, runner, pins, measurement


def _assert_closed(fd):
    with pytest.raises(OSError) as captured:
        os.fstat(fd)
    assert captured.value.errno == errno.EBADF


def test_approval_marker_fd_is_read_write_retained_through_success_and_closed(
    tmp_path, monkeypatch
):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    created = []
    observed_live = []
    real_open = os.open

    def track_marker_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == ns["APPROVAL_MARKER"] and flags & os.O_CREAT:
            created.append((fd, flags, os.fstat(fd)))
        return fd

    monkeypatch.setattr(ns["os"], "open", track_marker_open)

    def after_approval(_path):
        try:
            current = os.fstat(created[0][0])
        except OSError:
            observed_live.append(False)
        else:
            expected = created[0][2]
            observed_live.append(
                (current.st_dev, current.st_ino) == (expected.st_dev, expected.st_ino)
            )

    try:
        transition = ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=1.0,
            after_approval=after_approval,
        )
        assert transition.state == "PUBLISHED"
        assert len(created) == 1
        assert created[0][1] & os.O_ACCMODE == os.O_RDWR
        assert observed_live == [True]
        _assert_closed(created[0][0])
    finally:
        measurement.close()


def test_valid_approved_hardlink_replacement_is_ambiguous_and_never_mutated(
    tmp_path, monkeypatch
):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    original_link = tmp_path / ".retained-original-marker"
    victim = tmp_path / ".valid-approved-victim"
    expected = ns["_approval_payload"](measurement, pins)
    victim.write_bytes(expected)
    victim.chmod(0o600)
    victim_before = victim.read_bytes()
    created = []
    observed_live = []
    real_open = os.open

    def track_marker_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if path == ns["APPROVAL_MARKER"] and flags & os.O_CREAT:
            created.append((fd, os.fstat(fd)))
        return fd

    monkeypatch.setattr(ns["os"], "open", track_marker_open)

    def retain_original(path):
        os.link(path / ns["APPROVAL_MARKER"], original_link)

    def replace_with_valid_victim(path):
        try:
            value = os.fstat(created[0][0])
        except OSError:
            observed_live.append(False)
        else:
            expected_identity = created[0][1]
            observed_live.append(
                (value.st_dev, value.st_ino)
                == (expected_identity.st_dev, expected_identity.st_ino)
            )
        os.unlink(path / ns["APPROVAL_MARKER"])
        os.link(victim, path / ns["APPROVAL_MARKER"])

    try:
        with pytest.raises(ns["PublicationError"], match="AMBIGUOUS") as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=1.0,
                before_rename=retain_original,
                after_approval=replace_with_valid_victim,
            )

        assert captured.value.transition.state == "PUBLISHED"
        assert observed_live == [True]
        assert original_link.read_bytes() == expected
        assert victim.read_bytes() == victim_before
        assert (destination / ns["APPROVAL_MARKER"]).read_bytes() == victim_before
        original_value = original_link.stat()
        victim_value = victim.stat()
        assert (original_value.st_dev, original_value.st_ino) != (
            victim_value.st_dev,
            victim_value.st_ino,
        )
        _assert_closed(created[0][0])
    finally:
        measurement.close()


def test_rollback_marker_name_is_revalidated_after_retained_fd_fsync(
    tmp_path, monkeypatch
):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    original_link = tmp_path / ".retained-rollback-marker"
    victim = tmp_path / ".valid-approved-victim"
    approved = ns["_approval_payload"](measurement, pins)
    victim.write_bytes(approved)
    victim.chmod(0o600)
    real_fsync = os.fsync
    swapped = []

    def retain_original(path):
        os.link(path / ns["APPROVAL_MARKER"], original_link)

    def fail_after_rename(_path):
        raise OSError("force rollback")

    def swap_after_rollback_fsync(fd):
        real_fsync(fd)
        if swapped:
            return
        try:
            payload = os.pread(fd, 8193, 0)
            marker = json.loads(payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if marker.get("state") != "ROLLBACK_PREPARED":
            return
        os.unlink(ns["APPROVAL_MARKER"], dir_fd=measurement.root_fd)
        os.link(
            victim,
            ns["APPROVAL_MARKER"],
            dst_dir_fd=measurement.root_fd,
            follow_symlinks=False,
        )
        swapped.append(True)

    monkeypatch.setattr(ns["os"], "fsync", swap_after_rollback_fsync)
    try:
        with pytest.raises(ns["PublicationError"], match="AMBIGUOUS") as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=1.0,
                before_rename=retain_original,
                after_rename=fail_after_rename,
            )

        assert captured.value.transition.state == "PUBLISHED"
        assert swapped == [True]
        assert json.loads(original_link.read_bytes())["state"] == "ROLLBACK_PREPARED"
        assert victim.read_bytes() == approved
        assert (destination / ns["APPROVAL_MARKER"]).read_bytes() == approved
    finally:
        measurement.close()


@pytest.mark.parametrize("state", ["PUBLISHED", "ROLLBACK_PREPARED"])
def test_published_transition_cleanup_leaves_residue_and_forces_status_three(
    tmp_path, state
):
    ns = _namespace()
    registry = ns["OwnedPathRegistry"](tmp_path)
    retained = registry.create_directory(".stage", mode=0o700)
    os.rename(
        retained.name,
        "install",
        src_dir_fd=registry.parent_fd,
        dst_dir_fd=registry.parent_fd,
    )
    retained.name = "install"
    residue = b'{"state":"ROLLBACK_PREPARED"}\n'
    (tmp_path / "install" / ns["APPROVAL_MARKER"]).write_bytes(residue)
    transition = ns["PublicationTransition"](
        state,
        str(tmp_path / "install"),
        str(tmp_path / ".unused-quarantine"),
        retained.device,
        retained.inode,
    )

    try:
        report = ns["aggregate_cleanup"](
            [
                (
                    "output",
                    lambda: ns["cleanup_publication_stage"](
                        registry, retained, transition
                    ),
                )
            ]
        )
        status = 3 if not report.succeeded else 0
        assert report.failures == ("output",)
        assert status == 3
        assert retained.fd == -1
        assert (tmp_path / "install").is_dir()
        assert (tmp_path / "install" / ns["APPROVAL_MARKER"]).read_bytes() == residue
    finally:
        registry.close()


def test_remove_tree_swap_after_clear_preserves_foreign_and_retained_directories(
    tmp_path,
):
    ns = _namespace()
    registry = ns["OwnedPathRegistry"](tmp_path)
    retained = registry.create_directory("owned", mode=0o700)
    (tmp_path / "owned" / "cleared-before-swap").write_text("owned", encoding="utf-8")
    moved_original = tmp_path / ".retained-original"
    replacement = tmp_path / "owned"
    real_clear = registry._clear_directory

    def clear_then_swap(directory_fd):
        real_clear(directory_fd)
        os.rename(
            retained.name,
            moved_original.name,
            src_dir_fd=registry.parent_fd,
            dst_dir_fd=registry.parent_fd,
        )
        os.mkdir(retained.name, mode=0o700, dir_fd=registry.parent_fd)

    registry._clear_directory = clear_then_swap
    try:
        with pytest.raises(ns["PathIdentityError"]):
            registry.remove_tree(retained)
        assert retained.fd == -1
        assert replacement.is_dir()
        assert list(replacement.iterdir()) == []
        assert moved_original.is_dir()
        assert list(moved_original.iterdir()) == []
    finally:
        registry.close()


def test_remove_tree_symlink_replacement_is_never_unlinked(tmp_path):
    ns = _namespace()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep", encoding="utf-8")
    registry = ns["OwnedPathRegistry"](tmp_path)
    retained = registry.create_directory("owned", mode=0o700)
    moved_original = tmp_path / ".retained-original"
    os.rename(tmp_path / retained.name, moved_original)
    replacement = tmp_path / retained.name
    replacement.symlink_to(outside, target_is_directory=True)

    try:
        with pytest.raises(ns["PathIdentityError"]):
            registry.remove_tree(retained)
        assert retained.fd == -1
        assert replacement.is_symlink()
        assert os.readlink(replacement) == str(outside)
        assert (outside / "keep").read_text(encoding="utf-8") == "keep"
        assert moved_original.is_dir()
    finally:
        registry.close()
