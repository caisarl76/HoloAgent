import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
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
    namespace = {"__name__": "holoagent0_embedded_provisioner_test"}
    exec(compile(match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _python_script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3.10\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def _alive_non_zombie(pid: int) -> bool:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return False
    closing = text.rfind(")")
    return closing >= 0 and text[closing + 2 :].split()[0] != "Z"


def _wait_for(path: Path, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def test_thin_shell_execs_one_digest_bound_stdlib_python_provisioner():
    source = SCRIPT.read_text(encoding="utf-8")
    namespace = _namespace()
    prefix = source.split("# BEGIN_PROVISIONER_PYTHON", 1)[0]
    assert prefix.count("exec /usr/bin/python3.10") == 1
    assert "BEGIN_OWNED_PROCESS_HELPERS" not in source
    assert "subprocess" in namespace
    assert not (ROOT / "holoagent0_setup/strace_publication.py").exists()


def test_target_progresses_only_after_stable_new_session_identity(tmp_path):
    ns = _namespace()
    ready = tmp_path / "target-progressed"
    verified = tmp_path / "identity-verified"
    target = _python_script(
        tmp_path / "target.py",
        "from pathlib import Path\nimport sys\n"
        "assert Path(sys.argv[2]).exists()\nPath(sys.argv[1]).touch()\n",
    )

    def on_verified(identity):
        assert identity.pid == identity.pgid == identity.sid
        assert not ready.exists()
        verified.touch()

    runner = ns["OwnedSessionRunner"](term_grace=0.1, kill_grace=0.2)
    result = runner.run(
        [str(target), str(ready), str(verified)],
        timeout=1.0,
        on_verified=on_verified,
    )
    assert result.returncode == 0
    assert ready.exists()


def test_identity_failure_or_pid_reuse_never_releases_target(tmp_path):
    ns = _namespace()
    ready = tmp_path / "must-not-exist"
    target = _python_script(
        tmp_path / "target.py",
        "from pathlib import Path\nimport sys\nPath(sys.argv[1]).touch()\n",
    )
    real_reader = ns["read_process_identity"]
    calls = 0

    def reused_pid(pid):
        nonlocal calls
        calls += 1
        identity = real_reader(pid)
        if calls > 1:
            return ns["ProcessIdentity"](
                identity.pid,
                identity.pgid,
                identity.sid,
                identity.start_time + 1,
                identity.state,
            )
        return identity

    runner = ns["OwnedSessionRunner"](
        term_grace=0.1,
        kill_grace=0.2,
        identity_reader=reused_pid,
    )
    with pytest.raises(ns["ProcessIdentityError"]):
        runner.run([str(target), str(ready)], timeout=1.0)
    assert not ready.exists()


def test_fast_child_is_verified_and_unrelated_caller_session_survives(tmp_path):
    ns = _namespace()
    unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
    try:
        seen = []
        runner = ns["OwnedSessionRunner"](term_grace=0.1, kill_grace=0.2)
        result = runner.run(
            ["/usr/bin/true"], timeout=1.0, on_verified=lambda value: seen.append(value)
        )
        assert result.returncode == 0
        assert len(seen) == 1
        assert _alive_non_zombie(unrelated.pid)
    finally:
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait()


def test_leader_exit_still_cleans_term_ignoring_session_descendant(tmp_path):
    ns = _namespace()
    pid_file = tmp_path / "descendant.pid"
    leader = _python_script(
        tmp_path / "leader.py",
        "import subprocess, sys\nfrom pathlib import Path\n"
        "child = subprocess.Popen(['/usr/bin/python3.10', '-c', "
        "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.1, kill_grace=0.4)
    result = runner.run([str(leader), str(pid_file)], timeout=1.0)
    assert result.returncode == 0
    descendant = int(pid_file.read_text())
    assert not _alive_non_zombie(descendant)


def test_timeout_escalates_term_to_kill_without_unbounded_wait(tmp_path):
    ns = _namespace()
    target = _python_script(
        tmp_path / "ignore-term.py",
        "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.1, kill_grace=0.3)
    started = time.monotonic()
    with pytest.raises(ns["OwnedProcessTimeout"]):
        runner.run([str(target)], timeout=0.1)
    assert time.monotonic() - started < 1.5


def test_first_signal_is_latched_and_cleanup_masks_repeated_mixed_signals():
    ns = _namespace()
    source = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        SCRIPT.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    ).group(1)
    harness = (
        source
        + """
latch = SignalLatch()
latch.install()
os.kill(os.getpid(), signal.SIGTERM)
with latch.block_for_cleanup():
    os.kill(os.getpid(), signal.SIGINT)
    os.kill(os.getpid(), signal.SIGHUP)
    time.sleep(0.05)
os._exit(latch.final_status(cleanup_succeeded=True, ordinary_status=0))
"""
    )
    completed = subprocess.run(
        ["/usr/bin/python3.10", "-c", harness], timeout=2, check=False
    )
    assert completed.returncode == 143

    latch = ns["SignalLatch"]()
    latch.record(signal.SIGTERM)
    latch.record(signal.SIGINT)
    assert latch.final_status(cleanup_succeeded=True, ordinary_status=0) == 143
    assert latch.final_status(cleanup_succeeded=False, ordinary_status=0) == 3


def test_candidate_stage_is_identity_bound_and_path_swap_is_never_followed(tmp_path):
    ns = _namespace()
    target = tmp_path / "outside"
    target.write_text("untouched", encoding="utf-8")
    registry = ns["OwnedPathRegistry"](tmp_path)
    stage = registry.create_file(".candidate-stage", mode=0o600)
    moved = tmp_path / "attacker-kept-file"
    os.rename(tmp_path / stage.name, moved)
    (tmp_path / stage.name).symlink_to(target)
    with pytest.raises(ns["PathIdentityError"]):
        registry.remove_file(stage)
    assert target.read_text(encoding="utf-8") == "untouched"
    assert not (tmp_path / stage.name).exists()
    assert moved.exists()
    registry.close()


def test_candidate_stage_rejects_dangling_symlink_without_residue(tmp_path):
    ns = _namespace()
    dangling = tmp_path / ".candidate-stage"
    dangling.symlink_to(tmp_path / "missing")
    registry = ns["OwnedPathRegistry"](tmp_path)
    with pytest.raises(FileExistsError):
        registry.create_file(dangling.name, mode=0o600)
    assert dangling.is_symlink()
    registry.close()


def _write_fake_docker(path: Path) -> None:
    _python_script(
        path,
        """import os, sys, time
from pathlib import Path
state = Path(os.environ['FAKE_DOCKER_STATE'])
behavior = os.environ.get('FAKE_DOCKER_BEHAVIOR', 'normal')
args = sys.argv[1:]
if behavior == 'hang':
    time.sleep(30)
if args[:2] == ['container', 'ls']:
    if (state / 'present').exists():
        print((state / 'name').read_text().strip() + '|' + (state / 'label').read_text().strip())
elif args and args[0] == 'inspect':
    if not (state / 'present').exists():
        raise SystemExit(1)
    print((state / 'nonce').read_text().strip())
elif args and args[0] == 'run':
    (state / 'run-called').touch()
    (state / 'launch-request').touch()
    time.sleep(30)
elif args and args[0] == 'rm':
    if behavior == 'remove-error':
        raise SystemExit(55)
    (state / 'rm-called').touch()
    (state / 'present').unlink(missing_ok=True)
else:
    raise SystemExit(64)
""",
    )


def test_docker_cleanup_observes_delayed_daemon_materialization_and_removes_it(
    tmp_path,
):
    ns = _namespace()
    state = tmp_path / "docker-state"
    state.mkdir()
    fake = tmp_path / "docker"
    _write_fake_docker(fake)
    name = "holoagent0-strace-fixed"
    nonce = "0123456789abcdef0123456789abcdef"
    (state / "name").write_text(name)
    (state / "nonce").write_text(nonce)
    (state / "label").write_text(f"holoagent0.strace.owner={nonce}")
    daemon = _python_script(
        tmp_path / "daemon.py",
        "import sys,time\nfrom pathlib import Path\n"
        "state=Path(sys.argv[1])\n"
        "deadline=time.monotonic()+2\n"
        "while not (state/'launch-request').exists() and time.monotonic()<deadline: time.sleep(.01)\n"
        "time.sleep(.15)\n(state/'present').touch()\n",
    )
    daemon_process = subprocess.Popen([str(daemon), str(state)], start_new_session=True)
    environment = os.environ.copy()
    environment["FAKE_DOCKER_STATE"] = str(state)
    owner = ns["DockerOwner"](
        str(fake),
        ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2),
        name=name,
        nonce=nonce,
        stabilization=0.45,
        command_timeout=0.15,
    )
    try:
        with pytest.raises(ns["OwnedProcessTimeout"]):
            owner.run_container(["fake-image", "true"], timeout=0.08, env=environment)
        assert (state / "rm-called").exists()
        assert not (state / "present").exists()
    finally:
        daemon_process.wait(timeout=2)


def test_docker_collision_and_cleanup_error_are_fail_closed_and_bounded(tmp_path):
    ns = _namespace()
    state = tmp_path / "docker-state"
    state.mkdir()
    fake = tmp_path / "docker"
    _write_fake_docker(fake)
    name = "holoagent0-strace-fixed"
    nonce = "0123456789abcdef0123456789abcdef"
    (state / "name").write_text(name)
    (state / "nonce").write_text("foreign")
    (state / "label").write_text("holoagent0.strace.owner=foreign")
    (state / "present").touch()
    unrelated = tmp_path / "unrelated-container"
    unrelated.write_text("untouched")
    environment = os.environ.copy()
    environment["FAKE_DOCKER_STATE"] = str(state)
    owner = ns["DockerOwner"](
        str(fake),
        ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2),
        name=name,
        nonce=nonce,
        stabilization=0.15,
        command_timeout=0.1,
    )
    with pytest.raises(ns["DockerOwnershipError"]):
        owner.run_container(["fake-image", "true"], timeout=0.1, env=environment)
    assert not (state / "run-called").exists()
    assert unrelated.read_text() == "untouched"

    (state / "nonce").write_text(nonce)
    (state / "label").write_text(f"holoagent0.strace.owner={nonce}")
    environment["FAKE_DOCKER_BEHAVIOR"] = "remove-error"
    started = time.monotonic()
    with pytest.raises(ns["DockerCleanupError"]):
        owner.cleanup(env=environment)
    assert time.monotonic() - started < 1.5
    assert unrelated.read_text() == "untouched"


@pytest.mark.parametrize(
    "phase",
    [
        "archive_transfer",
        "archive_validation",
        "archive_extraction",
        "elf_validation",
        "elf_version",
    ],
)
def test_every_blocking_phase_uses_owned_session_and_explicit_deadline(tmp_path, phase):
    ns = _namespace()
    target = _python_script(
        tmp_path / f"{phase}.py",
        "import signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    started = time.monotonic()
    with pytest.raises(ns["OwnedProcessTimeout"]):
        ns["run_blocking_phase"](phase, [str(target)], runner, deadline=0.05)
    assert time.monotonic() - started < 1.0


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=0.5)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=0.5)
    return staged, runner, pins, measurement


def test_publication_rejects_measured_a_swapped_for_malicious_b(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    measured_a = staged / "bin/strace"
    measured_a.rename(staged / "bin/measured-a")
    shutil.copyfile("/usr/bin/false", measured_a)
    os.chmod(measured_a, 0o755)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    with pytest.raises(ns["PublicationError"]):
        ns["publish_install_directory"](
            staged, destination, quarantine, measurement, pins, runner, deadline=0.5
        )
    assert not destination.exists()
    assert not quarantine.exists()
    measurement.close()


def test_approval_binds_identity_and_pins_and_final_verify_detects_mutation(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"

    def mutate_after_approval(installed: Path):
        with (installed / "bin/strace").open("r+b") as stream:
            stream.seek(0)
            stream.write(b"BAD!")
            stream.flush()
            os.fsync(stream.fileno())

    with pytest.raises(ns["PublicationError"], match="ROLLED_BACK"):
        ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=0.5,
            after_approval=mutate_after_approval,
        )
    assert not destination.exists()
    assert quarantine.is_dir()
    marker = json.loads((quarantine / ".holoagent0-install-approved.json").read_text())
    assert marker["elf_size"] == pins.size
    assert marker["elf_sha256"] == pins.sha256
    assert marker["version_output_sha256"] == pins.version_sha256
    assert marker["staging_device"] == measurement.root_device
    assert marker["staging_inode"] == measurement.root_inode
    measurement.close()


def test_cleanup_uses_retained_parent_fd_and_rejects_root_symlink_swap(tmp_path):
    ns = _namespace()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep")
    registry = ns["OwnedPathRegistry"](tmp_path)
    tree = registry.create_directory("owned-tree", mode=0o700)
    moved = tmp_path / "attacker-moved-tree"
    os.rename(tmp_path / tree.name, moved)
    (tmp_path / tree.name).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ns["PathIdentityError"]):
        registry.remove_tree(tree)
    assert (outside / "keep").read_text() == "keep"
    assert not (tmp_path / tree.name).exists()
    assert moved.is_dir()
    registry.close()
