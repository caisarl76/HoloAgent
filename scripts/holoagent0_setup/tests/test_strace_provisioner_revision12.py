import errno
import fcntl
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
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision12_test"}
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


def _probe_exclusive_lock_and_mutate(path: Path, label: str, observations: list):
    fd = os.open(path / "bin" / "strace", os.O_RDWR | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            assert error.errno in {errno.EACCES, errno.EAGAIN}
            observations.append((label, "blocked"))
            return
        observations.append((label, "acquired"))
        final = os.fstat(fd).st_size - 1
        original = os.pread(fd, 1, final)
        os.pwrite(fd, bytes([original[0] ^ 0x01]), final)
        os.fsync(fd)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def test_publication_holds_one_elf_lock_through_commit_and_callbacks(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    observations = []

    def probe(label):
        return lambda path: _probe_exclusive_lock_and_mutate(path, label, observations)

    try:
        transition = ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=1.0,
            before_rename=probe("before_rename"),
            after_rename=probe("after_rename"),
            after_approval=probe("after_approval"),
        )
        assert transition.state == "PUBLISHED"
        assert observations == [
            ("before_rename", "blocked"),
            ("after_rename", "blocked"),
            ("after_approval", "blocked"),
        ]

        published_fd = os.open(
            destination / "bin" / "strace", os.O_RDONLY | os.O_NOFOLLOW
        )
        try:
            fcntl.flock(published_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(published_fd, fcntl.LOCK_UN)
        finally:
            os.close(published_fd)
    finally:
        measurement.close()


def test_rollback_revalidates_destination_after_marker_transition(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    moved_original = tmp_path / ".retained-original"
    foreign_payload = b"foreign destination must remain untouched\n"

    def fail_after_rename(_destination):
        raise OSError("force rollback")

    real_transition = ns["_transition_marker_state"]

    def transition_then_swap(directory_fd, state, **fields):
        result = real_transition(directory_fd, state, **fields)
        if state == "ROLLBACK_PREPARED":
            os.rename(destination, moved_original)
            destination.mkdir(mode=0o700)
            (destination / "foreign-content").write_bytes(foreign_payload)
        return result

    ns["_transition_marker_state"] = transition_then_swap
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
                after_rename=fail_after_rename,
            )

        assert captured.value.transition.state == "ROLLBACK_PREPARED"
        assert destination.is_dir()
        assert (destination / "foreign-content").read_bytes() == foreign_payload
        assert not quarantine.exists()

        moved = moved_original.stat()
        retained = os.fstat(measurement.root_fd)
        assert (moved.st_dev, moved.st_ino) == (
            retained.st_dev,
            retained.st_ino,
        )
        marker = json.loads(
            (moved_original / ns["APPROVAL_MARKER"]).read_text(encoding="utf-8")
        )
        assert marker["state"] == "ROLLBACK_PREPARED"
        assert marker["install_device"] == retained.st_dev
        assert marker["install_inode"] == retained.st_ino
    finally:
        measurement.close()
