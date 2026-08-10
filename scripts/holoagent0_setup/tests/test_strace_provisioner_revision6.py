import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import time

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
    assert match is not None, "the complete provisioner must be embedded in the recipe"
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision6_test"}
    exec(compile(match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _python_script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3.10\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=0.5)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=0.5)
    return staged, runner, pins, measurement


def test_recipe_has_no_executed_helper_outside_closed_digest_boundary():
    source = SCRIPT.read_text(encoding="utf-8")
    _namespace()
    embedded = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        source,
        flags=re.DOTALL,
    ).group(1)
    assert "holoagent0_setup.strace_publication" not in source
    assert "holoagent0_setup.atomic_io" not in source
    original = hashlib.sha256(source.encode()).hexdigest()
    drifted = source.replace(embedded, embedded + "\n# adversarial drift", 1)
    assert hashlib.sha256(drifted.encode()).hexdigest() != original


def test_signal_latch_precedes_allocation_and_cleanup_failure_beats_signal(tmp_path):
    ns = _namespace()
    source = ns["inspect"].getsource(ns["provision"])
    assert source.index("SignalLatch") < source.index("OwnedPathRegistry")
    latch = ns["SignalLatch"]()
    latch.record(signal.SIGTERM)
    latch.record(signal.SIGHUP)
    assert latch.final_status(cleanup_succeeded=True, ordinary_status=7) == 143
    assert latch.final_status(cleanup_succeeded=False, ordinary_status=7) == 3


def test_signal_during_owned_process_is_bounded_and_leaves_no_stage(tmp_path):
    ns = _namespace()
    target = _python_script(
        tmp_path / "ignore-term.py",
        "import signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    started = time.monotonic()
    with pytest.raises(ns["OwnedProcessTimeout"]):
        runner.run([str(target)], timeout=0.05)
    assert time.monotonic() - started < 1.0
    assert not list(tmp_path.glob(".holoagent0-*"))


def test_identity_validation_failure_never_returns_success_or_releases_target(tmp_path):
    ns = _namespace()
    ready = tmp_path / "target-ran"
    target = _python_script(
        tmp_path / "target.py",
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).touch()\n",
    )

    def invalid_identity(pid):
        return ns["ProcessIdentity"](pid, os.getpgrp(), os.getsid(0), 1, "S")

    runner = ns["OwnedSessionRunner"](
        term_grace=0.05, kill_grace=0.2, identity_reader=invalid_identity
    )
    with pytest.raises(ns["ProcessIdentityError"]):
        runner.run([str(target), str(ready)], timeout=0.5)
    assert not ready.exists()


def test_candidate_publish_failure_cleans_identity_bound_stage(tmp_path):
    ns = _namespace()
    destination = tmp_path / "candidate.json"

    def replace_stage(stage):
        moved = tmp_path / "moved"
        os.rename(stage, moved)
        stage.symlink_to(tmp_path / "outside")

    with pytest.raises(ns["PublicationError"]):
        ns["publish_candidate_evidence"](
            destination,
            {"schema_version": "candidate.v1"},
            before_commit=replace_stage,
        )
    assert not destination.exists()
    assert not list(tmp_path.glob(".holoagent0-candidate-*"))


@pytest.mark.parametrize("fault", ["post_rename_fsync", "post_rename_identity"])
def test_post_rename_fault_rolls_install_out_of_consumer_path(tmp_path, fault):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"

    def fail_after_rename(_installed):
        if fault == "post_rename_fsync":
            raise OSError("injected post-rename fsync failure")
        raise ns["PublicationError"]("injected identity failure")

    with pytest.raises(ns["PublicationError"], match="ROLLED_BACK"):
        ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=0.5,
            after_rename=fail_after_rename,
        )
    assert not destination.exists()
    assert quarantine.is_dir()
    measurement.close()


def test_signal_after_install_rename_rolls_back_before_exit(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    latch = ns["SignalLatch"]()

    def signal_after_rename(_installed):
        latch.record(signal.SIGTERM)
        raise ns["ProvisioningInterrupted"](143)

    with pytest.raises(ns["PublicationError"], match="ROLLED_BACK"):
        ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=0.5,
            after_rename=signal_after_rename,
        )
    assert latch.final_status(cleanup_succeeded=True, ordinary_status=0) == 143
    assert not destination.exists()
    assert quarantine.is_dir()
    measurement.close()


def test_approval_marker_is_closed_and_final_verify_remeasures_elf(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    ns["publish_install_directory"](
        staged, destination, quarantine, measurement, pins, runner, deadline=0.5
    )
    marker = json.loads((destination / ".holoagent0-install-approved.json").read_text())
    assert marker["schema_version"] == "holoagent0.strace-install-approval.v1"
    assert marker["elf_sha256"] == pins.sha256
    ns["verify_approved_install"](destination, pins, runner, deadline=0.5)
    with (destination / "bin/strace").open("r+b") as stream:
        stream.write(b"BAD!")
    with pytest.raises(ns["PublicationError"]):
        ns["verify_approved_install"](destination, pins, runner, deadline=0.5)
    measurement.close()
