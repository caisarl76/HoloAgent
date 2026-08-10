import errno
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat

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
    namespace = {"__name__": "holoagent0_embedded_provisioner_revision11_test"}
    padding = "\n" * source[: match.start(1)].count("\n")
    exec(compile(padding + match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _owned_runner(ns):
    return ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)


def _copy_elf(tmp_path: Path) -> Path:
    candidate = tmp_path / "strace"
    shutil.copyfile("/usr/bin/true", candidate)
    candidate.chmod(0o755)
    return candidate


def test_clone3_is_enosys_while_other_escape_syscalls_remain_eperm():
    ns = _namespace()
    program = r"""
import ctypes
import errno
import json
import os

libc = ctypes.CDLL(None, use_errno=True)
results = {}
for name, number, arguments in (
    ("clone3", 435, (0, 0)),
    ("clone_namespace", 56, (0x00020000 | 17, 0, 0, 0, 0)),
    ("setsid", 112, ()),
    ("unshare", 272, (0,)),
    ("setns", 308, (-1, 0)),
):
    ctypes.set_errno(0)
    returned = libc.syscall(number, *arguments)
    results[name] = [returned, ctypes.get_errno()]
print(json.dumps(results, sort_keys=True))
"""
    result = _owned_runner(ns).run(
        ["/usr/bin/python3.10", "-I", "-S", "-c", program],
        timeout=1.0,
        env=ns["closed_command_env"](),
    )
    assert result.returncode == 0
    observed = json.loads(result.stdout)
    assert observed["clone3"] == [-1, errno.ENOSYS]
    assert observed["clone_namespace"] == [-1, errno.EPERM]
    assert observed["setsid"] == [-1, errno.EPERM]
    assert observed["unshare"] == [-1, errno.EPERM]
    assert observed["setns"] == [-1, errno.EPERM]


def test_clone3_enosys_preserves_python_thread_and_process_fallbacks():
    ns = _namespace()
    program = r"""
import subprocess
import threading
import os

seen = []
worker = threading.Thread(target=lambda: seen.append("thread"))
worker.start()
worker.join()
pid = os.fork()
if pid == 0:
    os._exit(0)
forked, status = os.waitpid(pid, 0)
child = subprocess.run(["/usr/bin/true"], check=False)
assert seen == ["thread"]
assert forked == pid and os.waitstatus_to_exitcode(status) == 0
assert child.returncode == 0
"""
    result = _owned_runner(ns).run(
        ["/usr/bin/python3.10", "-I", "-S", "-c", program],
        timeout=1.0,
        env=ns["closed_command_env"](),
    )
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")


class _MutateAfterVersionRunner:
    def __init__(self, ns, candidate: Path):
        self.delegate = _owned_runner(ns)
        self.candidate = candidate
        self.lock_was_held = []
        self.mutated = False

    def run(self, argv, *, timeout, **kwargs):
        probe_fd = os.open(self.candidate, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.lock_was_held.append(True)
            else:
                self.lock_was_held.append(False)
                fcntl.flock(probe_fd, fcntl.LOCK_UN)
        finally:
            os.close(probe_fd)
        result = self.delegate.run(argv, timeout=timeout, **kwargs)
        if list(map(str, argv))[-1] == "--version" and not self.mutated:
            write_fd = os.open(self.candidate, os.O_RDWR | os.O_NOFOLLOW)
            try:
                final = os.fstat(write_fd).st_size - 1
                original = os.pread(write_fd, 1, final)
                os.pwrite(write_fd, bytes([original[0] ^ 0x01]), final)
                os.fsync(write_fd)
            finally:
                os.close(write_fd)
            self.mutated = True
        return result


def test_measure_elf_rejects_same_inode_same_size_mutation_between_semantic_phases(
    tmp_path,
):
    ns = _namespace()
    candidate = _copy_elf(tmp_path)
    before = candidate.stat()
    runner = _MutateAfterVersionRunner(ns, candidate)
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ns["PublicationError"], match="changed"):
            ns["_measure_elf_fd"](fd, runner, 1.0)
    finally:
        os.close(fd)
    after = candidate.stat()
    assert (after.st_dev, after.st_ino, after.st_size) == (
        before.st_dev,
        before.st_ino,
        before.st_size,
    )
    assert runner.mutated
    assert runner.lock_was_held and all(runner.lock_was_held)


def test_verify_elf_rejects_same_inode_same_size_mutation_after_version(tmp_path):
    ns = _namespace()
    candidate = _copy_elf(tmp_path)
    baseline_runner = _owned_runner(ns)
    pins = ns["measure_elf_pins"](candidate, baseline_runner, deadline=1.0)
    runner = _MutateAfterVersionRunner(ns, candidate)
    fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ns["PublicationError"], match="changed"):
            ns["_verify_elf_fd"](fd, pins, runner, 1.0)
    finally:
        os.close(fd)
    assert runner.mutated
    assert runner.lock_was_held and all(runner.lock_was_held)


def test_docker_client_uses_owned_empty_config_and_explicit_local_socket(tmp_path):
    ns = _namespace()
    root = tmp_path / "retained-root"
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    hostile = tmp_path / "hostile-docker-config"
    hostile.mkdir()
    (hostile / "config.json").write_text(
        json.dumps(
            {
                "credsStore": "hostile-helper",
                "currentContext": "remote-context",
            }
        ),
        encoding="utf-8",
    )
    daemon_socket = Path("/run/docker.sock")
    assert stat.S_ISSOCK(daemon_socket.stat().st_mode)
    ambient = {
        "HOME": str(tmp_path / "hostile-home"),
        "DOCKER_CONFIG": str(hostile),
        "DOCKER_CONTEXT": "remote-context",
        "DOCKER_HOST": f"unix://{daemon_socket}",
    }
    context = None
    try:
        context = ns["create_docker_client_context"](root_fd, ambient)
        expected_config = ns["retained_fd_path"](context.directory_fd)
        assert context.environment == {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
            "TZ": "UTC",
            "SOURCE_DATE_EPOCH": "0",
            "DOCKER_HOST": f"unix://{daemon_socket}",
            "DOCKER_CONFIG": str(expected_config),
        }
        assert stat.S_IMODE(os.fstat(context.directory_fd).st_mode) == 0o700
        config_fd = os.open(
            "config.json",
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=context.directory_fd,
        )
        try:
            assert stat.S_IMODE(os.fstat(config_fd).st_mode) == 0o600
            assert os.read(config_fd, 16) == b"{}\n"
        finally:
            os.close(config_fd)
        assert str(hostile) not in context.environment.values()
        assert "DOCKER_CONTEXT" not in context.environment
        assert "HOME" not in context.environment
    finally:
        if context is not None:
            context.close()
        os.close(root_fd)


def test_docker_cleanup_keeps_the_same_closed_environment_after_signal(tmp_path):
    ns = _namespace()
    root = tmp_path / "retained-root"
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    daemon_socket = Path("/run/docker.sock")
    assert stat.S_ISSOCK(daemon_socket.stat().st_mode)
    context = None
    try:
        context = ns["create_docker_client_context"](root_fd, {})
        before = dict(context.environment)
        assert before["DOCKER_HOST"] == "unix:///var/run/docker.sock"
        latch = ns["SignalLatch"]()
        latch.record(15)
        with latch.block_for_cleanup():
            cleanup_environment = context.environment
        assert cleanup_environment == before
        assert cleanup_environment is context.environment
    finally:
        if context is not None:
            context.close()
        os.close(root_fd)


@pytest.mark.parametrize(
    "docker_host",
    [
        "tcp://remote.example:2375",
        "unix:///run/../tmp/docker.sock",
        "unix:///etc/passwd",
    ],
)
def test_docker_client_rejects_nonlocal_noncanonical_or_nonsocket_host(
    tmp_path, docker_host
):
    ns = _namespace()
    root = tmp_path / "retained-root"
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ns["ProvisioningError"], match="Docker|docker|socket"):
            ns["create_docker_client_context"](root_fd, {"DOCKER_HOST": docker_host})
        assert list(root.iterdir()) == []
    finally:
        os.close(root_fd)


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = _owned_runner(ns)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=1.0)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=1.0)
    return staged, runner, pins, measurement


def test_quarantine_name_replacement_never_mutates_or_confuses_foreign_tree(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    quarantine = tmp_path / ".quarantine"
    moved_expected = tmp_path / "expected-inode-moved"
    foreign_payload = b'{"foreign":true,"state":"APPROVED"}\n'

    def fail_functionally(_installed):
        raise OSError("force rollback")

    def replace_quarantine_name(path):
        os.rename(path, moved_expected)
        path.mkdir(mode=0o700)
        (path / ns["APPROVAL_MARKER"]).write_bytes(foreign_payload)
        (path / "foreign-content").write_text("untouched", encoding="utf-8")

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
                after_rename=fail_functionally,
                after_quarantine_rename=replace_quarantine_name,
            )
        assert captured.value.transition.state == "QUARANTINE_PREPARED"
        assert (quarantine / ns["APPROVAL_MARKER"]).read_bytes() == foreign_payload
        assert (quarantine / "foreign-content").read_text() == "untouched"
        expected_marker = json.loads(
            (moved_expected / ns["APPROVAL_MARKER"]).read_text()
        )
        assert expected_marker["state"] == "ROLLBACK_PREPARED"
        moved = moved_expected.stat()
        assert (moved.st_dev, moved.st_ino) == (
            measurement.root_device,
            measurement.root_inode,
        )
    finally:
        measurement.close()
