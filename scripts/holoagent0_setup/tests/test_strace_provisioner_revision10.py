import hashlib
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

import pytest


ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"


def _namespace():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision10_test"}
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


def test_provisioner_has_supported_direct_isolated_python_shebang():
    assert SCRIPT.read_text(encoding="utf-8").startswith(
        "#!/usr/bin/env -S /usr/bin/python3.10 -I -S\n"
    )


def test_direct_isolated_python_entrypoint_ignores_shell_and_python_startup(tmp_path):
    shell_side_effect = tmp_path / "shell-startup-ran"
    python_side_effect = tmp_path / "python-startup-ran"
    shell_startup = tmp_path / "hostile-shell-startup"
    shell_startup.write_text(
        f"/usr/bin/touch {str(shell_side_effect)!r}\n", encoding="utf-8"
    )
    hostile_python = tmp_path / "hostile-python"
    hostile_python.mkdir()
    (hostile_python / "sitecustomize.py").write_text(
        f"from pathlib import Path\nPath({str(python_side_effect)!r}).touch()\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment.update(
        {
            "BASH_ENV": str(shell_startup),
            "ENV": str(shell_startup),
            "PYTHONPATH": str(hostile_python),
            "PYTHONHOME": str(tmp_path / "missing-python-home"),
            "PYTHONSTARTUP": str(hostile_python / "sitecustomize.py"),
        }
    )
    result = subprocess.run(
        [str(SCRIPT)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
        timeout=5,
    )
    assert result.returncode == 2
    assert result.stderr.startswith(f"usage: {SCRIPT} ")
    assert not shell_side_effect.exists()
    assert not python_side_effect.exists()


def test_irreversible_release_filter_denies_escape_when_discovery_never_works(
    tmp_path,
):
    ns = _namespace()
    child_pid = tmp_path / "child.pid"
    escape_result = tmp_path / "escape.result"
    leader = _python_script(
        tmp_path / "leader.py",
        "import subprocess,sys,time\n"
        "from pathlib import Path\n"
        "program = '''import os,signal,sys,time\n"
        "from pathlib import Path\n"
        "try:\n"
        "    os.setsid()\n"
        "except PermissionError:\n"
        "    outcome = 'DENIED'\n"
        "else:\n"
        "    outcome = 'ESCAPED'\n"
        "Path(sys.argv[1]).write_text(outcome)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "time.sleep(30)\n'''\n"
        "child=subprocess.Popen(['/usr/bin/python3.10','-I','-S','-c',program,sys.argv[2]])\n"
        "Path(sys.argv[1]).write_text(str(child.pid))\n"
        "time.sleep(30)\n",
    )
    unrelated = subprocess.Popen(["/usr/bin/sleep", "30"], start_new_session=True)
    escaped = None
    try:
        runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.4)

        def discovery_always_fails(_identity, _baseline, _tracked):
            _wait_for(escape_result)
            raise RuntimeError("persistent discovery failure before tracking")

        runner._discover_descendants = discovery_always_fails
        with pytest.raises(ns["OwnedCleanupError"]):
            runner.run([str(leader), str(child_pid), str(escape_result)], timeout=1.0)
        escaped = int(child_pid.read_text())
        assert escape_result.read_text() == "DENIED"
        assert not _alive_non_zombie(escaped)
        assert _alive_non_zombie(unrelated.pid)
    finally:
        if escaped is not None and _alive_non_zombie(escaped):
            os.kill(escaped, signal.SIGKILL)
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait()


class _ResponseLessDockerRunner:
    def __init__(self, ns):
        self.ns = ns
        self.calls = []
        self.created = False
        self.name = "holoagent0-strace-fixed"
        self.nonce = "0123456789abcdef0123456789abcdef"
        self.inventory_id = "b" * 64

    def for_cleanup(self):
        return self

    def run(self, argv, *, timeout, env=None, **_kwargs):
        del timeout, env
        argv = tuple(map(str, argv))
        self.calls.append(argv)
        args = argv[1:]
        if args[:2] == ("container", "ls"):
            payload = b""
            if self.created:
                payload = (
                    f"{self.name}|holoagent0.strace.owner={self.nonce}|"
                    f"{self.inventory_id}\n"
                ).encode()
            return subprocess.CompletedProcess(argv, 0, payload, b"")
        if args and args[0] == "create":
            self.created = True
            raise self.ns["OwnedProcessTimeout"](argv)
        if args and args[0] in {"inspect", "start", "rm"}:
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        raise AssertionError(argv)


def test_response_less_create_never_adopts_same_label_inventory_replacement():
    ns = _namespace()
    runner = _ResponseLessDockerRunner(ns)
    owner = ns["DockerOwner"](
        "/usr/bin/docker",
        runner,
        cleanup_runner=runner,
        name=runner.name,
        nonce=runner.nonce,
        stabilization=0.02,
        command_timeout=0.1,
    )
    with pytest.raises(ns["DockerCleanupError"], match="cleanup failed"):
        owner.run_container(["fake-image", "true"], timeout=0.1, env={})
    verbs = [call[1] for call in runner.calls if len(call) > 1]
    assert "start" not in verbs
    assert "rm" not in verbs
    assert owner.created_identity is None
    assert runner.created


class _SwapAfterAbiRunner:
    def __init__(self, ns, candidate: Path, replacement: Path):
        self.delegate = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
        self.candidate = candidate
        self.replacement = replacement
        self.targets = []
        self.swapped = False

    def run(self, argv, *, timeout, **kwargs):
        argv = list(map(str, argv))
        if argv[-1] == "--version":
            self.targets.append(argv[0])
            return subprocess.CompletedProcess(argv, 0, b"strace -- version 6.6\n", b"")
        if argv[0] == "/usr/bin/sha256sum":
            self.targets.append(argv[-1])
            return self.delegate.run(argv, timeout=timeout, **kwargs)
        self.targets.append(argv[-1])
        result = self.delegate.run(argv, timeout=timeout, **kwargs)
        if not self.swapped:
            os.replace(self.replacement, self.candidate)
            self.swapped = True
        return result


def test_candidate_elf_abi_version_and_hash_share_one_retained_fd_across_swap(
    tmp_path,
):
    ns = _namespace()
    candidate = tmp_path / "strace"
    replacement = tmp_path / "replacement"
    shutil.copyfile("/usr/bin/true", candidate)
    shutil.copyfile("/usr/bin/false", replacement)
    candidate.chmod(0o755)
    replacement.chmod(0o755)
    expected = hashlib.sha256(candidate.read_bytes()).hexdigest()
    runner = _SwapAfterAbiRunner(ns, candidate, replacement)
    pins = ns["measure_elf_pins"](candidate, runner, deadline=0.5)
    assert pins.sha256 == expected
    assert len(runner.targets) == 3
    assert len(set(runner.targets)) == 1
    assert runner.targets[0].startswith("/proc/self/fd/")
    assert hashlib.sha256(candidate.read_bytes()).hexdigest() != expected


def test_signal_first_seen_during_successful_finalization_overrides_primary_error(
    tmp_path, monkeypatch
):
    ns = _namespace()
    fake_script = tmp_path / "provision_strace_6_6.sh"
    fake_script.write_text("reviewed", encoding="utf-8")
    candidate = tmp_path / "candidate.json"
    temp_parent = tmp_path / "temporary"
    temp_parent.mkdir()
    monkeypatch.setenv("TMPDIR", str(temp_parent))
    monkeypatch.setitem(ns, "_load_policy", lambda _path: {})
    monkeypatch.setitem(ns, "validate_build_pins", lambda *_args, **_kwargs: None)

    def fail_transfer(*_args, **_kwargs):
        raise ns["ArchiveValidationError"]("primary input failure")

    monkeypatch.setitem(ns, "transfer_archive", fail_transfer)
    registry_type = ns["OwnedPathRegistry"]
    original_remove = registry_type.remove_tree

    def remove_then_signal(self, entry):
        original_remove(self, entry)
        signal.raise_signal(signal.SIGTERM)

    monkeypatch.setattr(registry_type, "remove_tree", remove_then_signal)
    old_handlers = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    try:
        status = ns["main"]([str(fake_script), "--candidate-evidence", str(candidate)])
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    assert status == 143
    assert list(temp_parent.iterdir()) == []
