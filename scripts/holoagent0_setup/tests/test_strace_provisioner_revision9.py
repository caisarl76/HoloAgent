import fcntl
import hashlib
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
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision9_test"}
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


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=0.5)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=0.5)
    return staged, runner, pins, measurement


def test_release_trampoline_cannot_load_hostile_user_site_or_pythonpath(tmp_path):
    ns = _namespace()
    side_effect = tmp_path / "python-startup-ran"
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(side_effect)!r}).touch()\n",
        encoding="utf-8",
    )
    user_site = tmp_path / "userbase/lib/python3.10/site-packages"
    user_site.mkdir(parents=True)
    (user_site / "hostile.pth").write_text(
        f"import pathlib; pathlib.Path({str(side_effect)!r}).touch()\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(hostile)
    environment["PYTHONUSERBASE"] = str(tmp_path / "userbase")
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    result = runner.run(["/usr/bin/true"], timeout=1.0, env=environment)
    assert result.returncode == 0
    assert not side_effect.exists()


def test_every_embedded_python_child_uses_exact_isolated_flags():
    ns = _namespace()
    assert ns["isolated_python_argv"]("print('ok')", "arg") == [
        "/usr/bin/python3.10",
        "-I",
        "-S",
        "-c",
        "print('ok')",
        "arg",
    ]
    source = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        SCRIPT.read_text(encoding="utf-8"),
        flags=re.DOTALL,
    ).group(1)
    assert '[PYTHON, "-c"' not in source
    assert "isolated_python_argv(_RELEASE_TRAMPOLINE" in source
    assert "isolated_python_argv(_ELF_VALIDATOR" in source
    assert "isolated_python_argv(_ARCHIVE_VALIDATOR_PROGRAM" in source


class _DockerRunner:
    def __init__(self, ns, *, replacement=False, create_error=None):
        self.ns = ns
        self.replacement = replacement
        self.create_error = create_error
        self.calls = []
        self.present = False
        self.identity = "a" * 64
        self.name = "holoagent0-strace-fixed"
        self.nonce = "0123456789abcdef0123456789abcdef"

    def for_cleanup(self):
        return self

    def run(self, argv, *, timeout, env=None, **_kwargs):
        argv = tuple(map(str, argv))
        self.calls.append(argv)
        args = argv[1:]
        if args[:2] == ("container", "ls"):
            payload = b""
            if self.present:
                payload = (
                    f"{self.name}|holoagent0.strace.owner={self.nonce}|"
                    f"{self.identity}\n"
                ).encode()
            return subprocess.CompletedProcess(argv, 0, payload, b"")
        if args and args[0] == "create":
            if self.create_error is not None:
                raise self.create_error
            self.present = True
            return subprocess.CompletedProcess(argv, 0, ("a" * 64 + "\n").encode(), b"")
        if args and args[0] == "inspect":
            requested = args[-1]
            if not self.present or requested != self.identity:
                return subprocess.CompletedProcess(argv, 1, b"", b"")
            payload = f"{self.identity}|/{self.name}|{self.nonce}\n".encode()
            if self.replacement:
                self.identity = "b" * 64
                self.replacement = False
            return subprocess.CompletedProcess(argv, 0, payload, b"")
        if args and args[0] == "start":
            return subprocess.CompletedProcess(argv, 0, b"built", b"")
        if args and args[0] == "rm":
            if args[-1] != self.identity:
                return subprocess.CompletedProcess(argv, 66, b"", b"")
            self.present = False
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)


def _docker_owner(ns, runner, *, stabilization=0.03):
    return ns["DockerOwner"](
        "/usr/bin/docker",
        runner,
        cleanup_runner=runner,
        name=runner.name,
        nonce=runner.nonce,
        stabilization=stabilization,
        command_timeout=0.1,
    )


def test_docker_binds_create_id_and_inspects_it_before_start():
    ns = _namespace()
    runner = _DockerRunner(ns)
    owner = _docker_owner(ns, runner)
    result = owner.run_container(["image", "true"], timeout=0.2, env={})
    assert result.returncode == 0
    verbs = [call[1] for call in runner.calls if len(call) > 1]
    assert verbs.index("inspect") < verbs.index("start")
    start = next(call for call in runner.calls if call[1] == "start")
    remove = next(call for call in runner.calls if call[1] == "rm")
    assert start[-1] == remove[-1] == "a" * 64
    assert owner.created_identity.container_id == "a" * 64


def test_docker_same_label_id_replacement_is_never_started_or_removed():
    ns = _namespace()
    runner = _DockerRunner(ns, replacement=True)
    owner = _docker_owner(ns, runner)
    with pytest.raises(ns["DockerCleanupError"]):
        owner.run_container(["image", "true"], timeout=0.2, env={})
    assert not any(call[1] == "start" for call in runner.calls)
    assert not any(call[1] == "rm" for call in runner.calls)
    assert runner.present


def test_response_less_create_late_materialization_is_cleanup_failure(tmp_path):
    ns = _namespace()
    runner = _DockerRunner(
        ns,
        create_error=ns["OwnedProcessTimeout"](["/usr/bin/docker", "create"]),
    )
    owner = _docker_owner(ns, runner, stabilization=0.04)

    def materialize_after_observation():
        time.sleep(0.09)
        runner.present = True

    worker = threading.Thread(target=materialize_after_observation)
    worker.start()
    with pytest.raises(ns["DockerCleanupError"]):
        owner.run_container(["image", "true"], timeout=0.02, env={})
    worker.join(timeout=1)
    assert runner.present
    assert not any(call[1] == "start" for call in runner.calls)
    assert not any(call[1] == "rm" for call in runner.calls)


def test_discovery_exception_still_kills_tracked_forked_child_only(tmp_path):
    ns = _namespace()
    escaped_pid = tmp_path / "escaped.pid"
    leader = _python_script(
        tmp_path / "leader.py",
        "import subprocess,sys,time\nfrom pathlib import Path\n"
        "child=subprocess.Popen(['/usr/bin/python3.10','-I','-S','-c',"
        "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\ntime.sleep(30)\n",
    )
    unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
    escaped = None
    try:
        runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.4)
        original = runner._discover_descendants
        raised = False

        def discover_then_fail(identity, baseline, tracked):
            nonlocal raised
            if not raised:
                _wait_for(escaped_pid)
                original(identity, baseline, tracked)
                raised = True
                raise RuntimeError("injected descendant discovery failure")
            return original(identity, baseline, tracked)

        runner._discover_descendants = discover_then_fail
        with pytest.raises(RuntimeError, match="discovery failure"):
            runner.run([str(leader), str(escaped_pid)], timeout=1.0)
        escaped = int(escaped_pid.read_text())
        assert not _alive_non_zombie(escaped)
        assert _alive_non_zombie(unrelated.pid)
    finally:
        if escaped is not None and _alive_non_zombie(escaped):
            os.kill(escaped, signal.SIGKILL)
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait()


def test_validated_archive_is_sealed_and_same_bytes_reach_child(tmp_path):
    ns = _namespace()
    payload = b"immutable archive bytes"
    snapshot = ns["create_sealable_archive"]("holoagent0-strace-test")
    try:
        os.write(snapshot.fd, payload)
        ns["seal_retained_archive"](snapshot)
        ns["verify_sealed_archive"](snapshot)
        required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK
        assert fcntl.fcntl(snapshot.fd, fcntl.F_GET_SEALS) & required == required
        with pytest.raises(OSError):
            os.write(snapshot.fd, b"mutation")
        probe = _python_script(
            tmp_path / "hash-fd.py",
            "import hashlib,sys\n"
            "with open(sys.argv[1], 'rb', buffering=0) as stream: "
            "print(hashlib.sha256(stream.read()).hexdigest())\n",
        )
        runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
        result = runner.run(
            [str(probe), f"/proc/self/fd/{snapshot.fd}"],
            timeout=0.5,
            env=ns["closed_command_env"](),
            pass_fds=(snapshot.fd,),
        )
        assert result.stdout.strip().decode() == hashlib.sha256(payload).hexdigest()
    finally:
        snapshot.close()


def test_rollback_prepared_callback_observes_nonapproved_destination(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    seen = []

    def fail_functionally(_installed):
        raise OSError("force rollback")

    def fail_after_rollback_prepared(path):
        marker = json.loads((path / ns["APPROVAL_MARKER"]).read_text())
        seen.append(marker["state"])
        raise OSError("crash after rollback preparation")

    try:
        with pytest.raises(ns["PublicationError"]) as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=0.5,
                after_rename=fail_functionally,
                after_rollback_prepared=fail_after_rollback_prepared,
            )
        assert seen == ["ROLLBACK_PREPARED"]
        assert captured.value.transition.state == "ROLLBACK_PREPARED"
        assert destination.is_dir()
        assert not quarantine.exists()
        marker = json.loads((destination / ns["APPROVAL_MARKER"]).read_text())
        assert marker["state"] != "APPROVED"
    finally:
        measurement.close()


def test_rollback_marker_failure_keeps_retained_published_identity(
    tmp_path, monkeypatch
):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"

    def fail_functionally(_installed):
        raise OSError("force rollback")

    def fail_marker(_directory_fd, _state, **_fields):
        raise OSError("marker fsync failed")

    monkeypatch.setitem(ns, "_transition_marker_state", fail_marker)
    try:
        with pytest.raises(ns["PublicationError"]) as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=0.5,
                after_rename=fail_functionally,
            )
        value = destination.stat()
        assert (value.st_dev, value.st_ino) == (
            measurement.root_device,
            measurement.root_inode,
        )
        assert captured.value.transition.state == "PUBLISHED"
        assert not quarantine.exists()
    finally:
        measurement.close()


def test_signal_survives_successful_publication_rollback(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    latch = ns["SignalLatch"]()

    def interrupt_after_rename(_installed):
        latch.record(signal.SIGTERM)

    try:
        with pytest.raises(ns["ProvisioningInterrupted"]) as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=0.5,
                after_rename=interrupt_after_rename,
                signal_latch=latch,
            )
        assert captured.value.status == 143
        assert captured.value.transition.state == "ROLLBACK_PREPARED"
        assert destination.is_dir()
        assert not quarantine.exists()
        marker = json.loads((destination / ns["APPROVAL_MARKER"]).read_text())
        assert marker["state"] == "ROLLBACK_PREPARED"
    finally:
        measurement.close()


def test_explicit_interruption_survives_rollback_without_latch(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"

    def interrupt_after_rename(_installed):
        raise ns["ProvisioningInterrupted"](143)

    try:
        with pytest.raises(
            ns["ProvisioningInterrupted"], match="ROLLED_BACK"
        ) as captured:
            ns["publish_install_directory"](
                staged,
                destination,
                quarantine,
                measurement,
                pins,
                runner,
                deadline=0.5,
                after_rename=interrupt_after_rename,
            )
        assert isinstance(captured.value, ns["PublicationError"])
        assert captured.value.status == 143
        assert captured.value.transition.state == "ROLLBACK_PREPARED"
        assert destination.is_dir()
        assert not quarantine.exists()
        marker = json.loads((destination / ns["APPROVAL_MARKER"]).read_text())
        assert marker["state"] == "ROLLBACK_PREPARED"
    finally:
        measurement.close()


def test_cli_cleanup_failure_overrides_archive_error_and_runs_later_finalizer(
    tmp_path, monkeypatch
):
    ns = _namespace()
    archive = tmp_path / "invalid.tar.xz"
    archive.write_bytes(b"not an xz archive")
    ns["SOURCE_SIZE"] = archive.stat().st_size
    ns["SOURCE_SHA256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    fake_script = tmp_path / "provision.sh"
    fake_script.write_text("reviewed recipe", encoding="utf-8")
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "holoagent0-trace-tool-v1.json").write_text(
        json.dumps(
            {
                "schema_version": "holoagent0.trace-tool-policy.v1",
                "rows": [{"build": {}, "runtime": {}}],
            }
        ),
        encoding="utf-8",
    )
    candidate = tmp_path / "candidate.json"
    later_finalizer = []
    registry_type = ns["OwnedPathRegistry"]
    original_remove = registry_type.remove_tree
    original_close = registry_type.close

    def remove_then_fail(self, entry):
        original_remove(self, entry)
        raise OSError("injected cleanup failure")

    def observed_close(self):
        later_finalizer.append(self.parent)
        return original_close(self)

    monkeypatch.setattr(registry_type, "remove_tree", remove_then_fail)
    monkeypatch.setattr(registry_type, "close", observed_close)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    status = ns["main"](
        [
            str(fake_script),
            "--archive",
            str(archive),
            "--candidate-evidence",
            str(candidate),
        ]
    )
    assert status == 3
    assert later_finalizer
