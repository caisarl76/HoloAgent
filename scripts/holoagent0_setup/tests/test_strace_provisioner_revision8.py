import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading
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
    assert match is not None
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision8_test"}
    padding = "\n" * source[: match.start(1)].count("\n")
    exec(compile(padding + match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _python_script(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/python3.10\n" + body, encoding="utf-8")
    path.chmod(0o700)
    return path


def _alive_non_zombie(pid: int) -> bool:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
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


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=0.5)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=0.5)
    return staged, runner, pins, measurement


def test_cleanup_runner_is_latch_independent_but_preserves_ownership(tmp_path):
    ns = _namespace()
    latch = ns["SignalLatch"]()
    latch.record(signal.SIGTERM)
    functional = ns["OwnedSessionRunner"](
        term_grace=0.05, kill_grace=0.2, signal_latch=latch
    )
    cleanup = functional.for_cleanup()
    with pytest.raises(ns["ProvisioningInterrupted"]):
        functional.run(["/usr/bin/true"], timeout=0.2)
    result = cleanup.run(["/usr/bin/true"], timeout=0.2)
    assert result.returncode == 0
    assert cleanup.signal_latch is None
    assert cleanup.term_grace == functional.term_grace
    assert cleanup.kill_grace == functional.kill_grace


def _write_identity_docker(path: Path) -> None:
    _python_script(
        path,
        """import os, sys, time
from pathlib import Path
state = Path(os.environ['FAKE_DOCKER_STATE'])
behavior = os.environ.get('FAKE_DOCKER_BEHAVIOR', 'normal')
args = sys.argv[1:]
if args[:2] == ['container', 'ls']:
    if (state/'present').exists():
        print('|'.join(((state/'name').read_text().strip(), (state/'label').read_text().strip(), (state/'id').read_text().strip())))
elif args and args[0] == 'create':
    (state/'create-called').touch(); (state/'launch-request').touch(); time.sleep(30)
elif args and args[0] == 'inspect':
    identity = args[-1]
    if not (state/'present').exists() or identity != (state/'id').read_text().strip(): raise SystemExit(1)
    print('|'.join(((state/'id').read_text().strip(), (state/'name').read_text().strip(), (state/'nonce').read_text().strip())))
    if behavior == 'replace-after-inspect':
        (state/'id').write_text('b'*64)
elif args and args[0] == 'rm':
    identity = args[-1]
    (state/'rm-arg').write_text(identity)
    if behavior == 'remove-error': raise SystemExit(55)
    if identity != (state/'id').read_text().strip(): raise SystemExit(66)
    (state/'present').unlink(missing_ok=True)
elif args and args[0] == 'start':
    (state/'start-called').touch(); time.sleep(30)
else:
    raise SystemExit(64)
""",
    )


def test_signal_during_response_less_create_never_adopts_late_inventory_id(tmp_path):
    ns = _namespace()
    state = tmp_path / "state"
    state.mkdir()
    fake = tmp_path / "docker"
    _write_identity_docker(fake)
    name = "holoagent0-strace-fixed"
    nonce = "0123456789abcdef0123456789abcdef"
    container_id = "a" * 64
    for filename, value in (
        ("name", name),
        ("nonce", nonce),
        ("label", f"holoagent0.strace.owner={nonce}"),
        ("id", container_id),
    ):
        (state / filename).write_text(value)
    latch = ns["SignalLatch"]()
    functional = ns["OwnedSessionRunner"](
        term_grace=0.05, kill_grace=0.2, signal_latch=latch
    )
    environment = ns["closed_command_env"]({"FAKE_DOCKER_STATE": str(state)})
    owner = ns["DockerOwner"](
        str(fake),
        functional,
        cleanup_runner=functional.for_cleanup(),
        name=name,
        nonce=nonce,
        stabilization=0.35,
        command_timeout=0.15,
    )

    def materialize_and_signal():
        _wait_for(state / "launch-request")
        latch.record(signal.SIGTERM)
        time.sleep(0.12)
        (state / "present").touch()

    worker = threading.Thread(target=materialize_and_signal)
    worker.start()
    with pytest.raises(ns["DockerCleanupError"]):
        owner.run_container(["fake-image", "true"], timeout=1.0, env=environment)
    worker.join(timeout=2)
    assert not (state / "rm-arg").exists()
    assert (state / "present").exists()
    assert not (state / "start-called").exists()


def test_signal_cleanup_failure_has_harness_status_three(tmp_path):
    ns = _namespace()
    latch = ns["SignalLatch"]()
    latch.record(signal.SIGINT)
    report = ns["aggregate_cleanup"](
        [("docker", lambda: (_ for _ in ()).throw(RuntimeError("remove failed")))]
    )
    assert not report.succeeded
    assert (
        latch.final_status(cleanup_succeeded=report.succeeded, ordinary_status=0) == 3
    )


def test_aggregate_cleanup_attempts_every_resource_after_first_failure():
    ns = _namespace()
    called = []

    def action(name, fail=False):
        def run():
            called.append(name)
            if fail:
                raise RuntimeError(name)

        return run

    report = ns["aggregate_cleanup"](
        [
            ("docker", action("docker", fail=True)),
            ("measurement", action("measurement")),
            ("output", action("output")),
            ("quarantine", action("quarantine")),
            ("root", action("root")),
        ]
    )
    assert called == ["docker", "measurement", "output", "quarantine", "root"]
    assert report.failures == ("docker",)


def test_runner_drains_large_output_without_pipe_deadlock(tmp_path):
    ns = _namespace()
    writer = _python_script(
        tmp_path / "writer.py",
        "import os\npayload=b'x'*(1024*1024+123)\nos.write(1,payload)\nos.write(2,b'e'*4096)\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    result = runner.run([str(writer)], timeout=1.5)
    assert result.returncode == 0
    assert result.stdout == b"x" * (1024 * 1024 + 123)
    assert result.stderr == b"e" * 4096
    assert ns["MAX_CAPTURE_BYTES"] >= len(result.stdout) + len(result.stderr)


def test_forked_descendant_is_cleaned_and_baseline_child_survives(tmp_path):
    ns = _namespace()
    pid_file = tmp_path / "escaped.pid"
    leader = _python_script(
        tmp_path / "leader.py",
        "import subprocess,sys\nfrom pathlib import Path\n"
        "child=subprocess.Popen(['/usr/bin/python3.10','-c','import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n",
    )
    unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
    try:
        runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.4)
        assert runner.run([str(leader), str(pid_file)], timeout=1.0).returncode == 0
        assert not _alive_non_zombie(int(pid_file.read_text()))
        assert _alive_non_zombie(unrelated.pid)
    finally:
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait()


def test_build_argv_uses_exact_shell_flags_and_retained_fd_mounts(tmp_path):
    ns = _namespace()
    argv = ns["build_container_argv"](
        "sha256:" + "a" * 64,
        Path(f"/proc/{os.getpid()}/fd/10/source/strace-6.6"),
        Path(f"/proc/{os.getpid()}/fd/10/build"),
        Path(f"/proc/{os.getpid()}/fd/11"),
        uid=1000,
        gid=1000,
    )
    assert argv[-4:] == [
        "/bin/sh",
        "-eu",
        "-c",
        "cd /build && /src/configure --prefix=/out --disable-gcc-Werror "
        "&& make -j1 && make install",
    ]
    mounts = [argv[index + 1] for index, item in enumerate(argv) if item == "--volume"]
    assert all(value.startswith(f"/proc/{os.getpid()}/fd/") for value in mounts)


def test_provision_anchors_snapshot_extraction_and_docker_mounts_to_retained_fds():
    _namespace()
    source = SCRIPT.read_text(encoding="utf-8")
    provision = re.search(
        r"def provision\(.*?\n(?=def main\()", source, flags=re.DOTALL
    ).group(0)
    assert "retained_fd_path(root.fd" in provision
    assert "retained_fd_path(snapshot.fd" in provision
    assert "root_path /" not in provision


def test_docker_rejects_same_label_id_replacement_and_never_removes_it(tmp_path):
    ns = _namespace()
    state = tmp_path / "state"
    state.mkdir()
    fake = tmp_path / "docker"
    _write_identity_docker(fake)
    name = "holoagent0-strace-fixed"
    nonce = "0123456789abcdef0123456789abcdef"
    for filename, value in (
        ("name", name),
        ("nonce", nonce),
        ("label", f"holoagent0.strace.owner={nonce}"),
        ("id", "a" * 64),
    ):
        (state / filename).write_text(value)
    (state / "present").touch()
    environment = ns["closed_command_env"](
        {
            "FAKE_DOCKER_STATE": str(state),
            "FAKE_DOCKER_BEHAVIOR": "replace-after-inspect",
        }
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    owner = ns["DockerOwner"](
        str(fake),
        runner,
        cleanup_runner=runner.for_cleanup(),
        name=name,
        nonce=nonce,
        stabilization=0.15,
        command_timeout=0.1,
    )
    with pytest.raises(ns["DockerOwnershipError"]):
        owner.cleanup(env=environment)
    assert (state / "present").exists()
    assert not (state / "rm-arg").exists()


def test_approval_is_fsynced_in_staging_before_rename_and_rollback_is_quarantined(
    tmp_path,
):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    observed = []

    def before_rename(stage):
        marker = json.loads((stage / ".holoagent0-install-approved.json").read_text())
        observed.append(marker["state"])

    def after_rename(_installed):
        raise OSError("force rollback")

    with pytest.raises(ns["PublicationError"]) as captured:
        ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=0.5,
            before_rename=before_rename,
            after_rename=after_rename,
        )
    assert observed == ["APPROVED"]
    assert captured.value.transition.state == "QUARANTINED"
    assert not destination.exists()
    marker = json.loads((quarantine / ".holoagent0-install-approved.json").read_text())
    assert marker["state"] == "QUARANTINED"
    measurement.close()


def test_pre_marker_failure_never_exposes_consumer_path(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"

    def before_marker(_stage):
        raise OSError("marker write failed")

    with pytest.raises(ns["PublicationError"]):
        ns["publish_install_directory"](
            staged,
            destination,
            quarantine,
            measurement,
            pins,
            runner,
            deadline=0.5,
            before_marker=before_marker,
        )
    assert not destination.exists()
    assert not quarantine.exists()
    measurement.close()


def test_exact_strace_version_first_line_is_required():
    ns = _namespace()
    ns["require_strace_6_6"](b"strace -- version 6.6\nCopyright details\n")
    for value in (
        b"wrapper\nstrace -- version 6.6\n",
        b"strace -- version 6.6.1\n",
        b"strace -- version 6.6 trailing\n",
    ):
        with pytest.raises(ns["PublicationError"]):
            ns["require_strace_6_6"](value)


def test_direct_launcher_and_command_environment_are_hermetic():
    ns = _namespace()
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env -S /usr/bin/python3.10 -I -S\n")
    environment = ns["closed_command_env"]({"DOCKER_HOST": "unix:///run/docker.sock"})
    assert environment == {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "0",
        "DOCKER_HOST": "unix:///run/docker.sock",
    }
    assert not any(
        "PROXY" in key or key in {"PYTHONPATH", "TAR_OPTIONS"} for key in environment
    )
    curl = ns["archive_transfer_argv"](None, Path("/tmp/snapshot"))
    assert curl[1] == "--disable"
    assert "--noproxy" in curl and "*" in curl


def test_hashing_is_owned_bounded_and_uses_retained_fd(tmp_path):
    ns = _namespace()
    data = tmp_path / "data"
    data.write_bytes(b"payload")
    fd = os.open(data, os.O_RDONLY | os.O_NOFOLLOW)
    hasher = _python_script(
        tmp_path / "stalled-hasher.py",
        "import signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n",
    )
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    started = time.monotonic()
    try:
        with pytest.raises(ns["OwnedProcessTimeout"]):
            ns["hash_retained_fd"](fd, runner, deadline=0.05, hasher=str(hasher))
    finally:
        os.close(fd)
    assert time.monotonic() - started < 1.0
    embedded = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        SCRIPT.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    ).group(1)
    assert "def _hash_path" not in embedded
    assert "def _hash_fd" not in embedded
