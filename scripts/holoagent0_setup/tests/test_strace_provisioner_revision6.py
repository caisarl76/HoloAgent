import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import time

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"
EXTERNAL_PUBLICATION_HELPER = ROOT / "holoagent0_setup/strace_publication.py"


def _source_section(name: str) -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(rf"# BEGIN_{name}\n(.*?)\n# END_{name}", source, flags=re.DOTALL)
    assert match is not None, f"missing reviewed {name} section"
    return match.group(1)


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _wait_for_while_running(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if path.exists():
            return
        status = process.poll()
        if status is not None:
            raise AssertionError(f"process exited {status} before creating {path}")
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_gone(pid: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return
        time.sleep(0.01)
    raise AssertionError(f"process {pid} survived its cleanup bound")


def _write_fake_docker(path: Path) -> None:
    path.write_text(
        """#!/bin/bash
set -euo pipefail
state="${FAKE_DOCKER_STATE:?}"
behavior="${FAKE_DOCKER_BEHAVIOR:-success}"
alive() {
    local pid
    pid="$(cat "$state/external.pid")"
    [[ -r "/proc/$pid/stat" ]] || return 1
    [[ "$(awk '{print $3}' "/proc/$pid/stat")" != "Z" ]]
}
command="$1"
shift
if [[ "$command" == "container" && "$1" == "ls" ]]; then
    if [[ "$behavior" == "collision" ]]; then
        printf '%s\n' 'holoagent0-strace-collision|foreign-owner'
    elif [[ -f "$state/name" ]] && alive; then
        printf '%s|%s\n' "$(cat "$state/name")" "$(cat "$state/label")"
    fi
elif [[ "$command" == "inspect" ]]; then
    alive || exit 1
    cat "$state/nonce"
elif [[ "$command" == "run" ]]; then
    : > "$state/run-called"
    [[ "$behavior" != "collision" ]] || exit 66
    name=""
    label=""
    while (($#)); do
        case "$1" in
            --name) name="$2"; shift 2 ;;
            --label) label="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    printf '%s\n' "$name" > "$state/name"
    printf '%s\n' "$label" > "$state/label"
    printf '%s\n' "${label#*=}" > "$state/nonce"
    : > "$state/run-ready-before-cid"
    /usr/bin/sleep 300
elif [[ "$command" == "rm" ]]; then
    : > "$state/rm-called"
    if [[ "$behavior" == "remove-fail" ]]; then
        exit 55
    fi
    if [[ "$behavior" == "remove-hang" ]]; then
        /usr/bin/sleep 300
    fi
    pid="$(cat "$state/external.pid")"
    /bin/kill -TERM -- "-$pid"
    printf '%s\n' "$*" > "$state/removed-args"
else
    exit 64
fi
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _start_fake_docker_harness(tmp_path: Path, behavior: str):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    state = tmp_path / "state"
    state.mkdir()
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    fake_docker = tmp_path / "fake-docker"
    _write_fake_docker(fake_docker)
    external = subprocess.Popen(
        ["/usr/bin/setsid", "/usr/bin/sleep", "300"], start_new_session=False
    )
    (state / "external.pid").write_text(f"{external.pid}\n", encoding="ascii")
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'install_staging_dir=""',
            helpers,
            "install_provisioner_traps",
            'run_owned_docker "$2" run --network=none fake-image true',
        )
    )
    environment = os.environ.copy()
    environment["FAKE_DOCKER_STATE"] = str(state)
    environment["FAKE_DOCKER_BEHAVIOR"] = behavior
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "fake-docker-harness",
            str(private_temp),
            str(fake_docker),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    return process, external, state, private_temp


def test_recipe_has_no_executed_helper_outside_its_closed_digest_boundary():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "# BEGIN_PUBLICATION_HELPER" in source
    assert "holoagent0_setup.strace_publication" not in source
    assert "holoagent0_setup.atomic_io" not in source
    assert not EXTERNAL_PUBLICATION_HELPER.exists()

    embedded = _source_section("PUBLICATION_HELPER")
    original_digest = hashlib.sha256(source.encode()).hexdigest()
    drifted_source = source.replace(embedded, embedded + "\n# adversarial drift", 1)
    assert hashlib.sha256(drifted_source.encode()).hexdigest() != original_digest


def test_signal_traps_are_active_before_any_owned_directory_allocation():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.index("\ninstall_provisioner_traps\n") < source.index(
        "allocate_owned_directory temp_dir"
    )
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    allocation = helpers.index("allocate_owned_directory()")
    assign = helpers.index('printf -v "$variable_name"', allocation)
    mkdir = helpers.index("/usr/bin/mkdir", allocation)
    assert assign < mkdir


def test_signal_during_owned_directory_allocation_leaves_no_residue(tmp_path):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    fake_mkdir = tmp_path / "fake-mkdir"
    ready = tmp_path / "mkdir-ready"
    fake_mkdir.write_text(
        """#!/bin/bash
set -euo pipefail
target="${!#}"
/usr/bin/mkdir --mode=0700 -- "$target"
: > "${ALLOCATION_READY:?}"
/usr/bin/sleep 300
""",
        encoding="utf-8",
    )
    fake_mkdir.chmod(0o700)
    helpers = helpers.replace("/usr/bin/mkdir", str(fake_mkdir))
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir=""',
            'install_staging_dir=""',
            helpers,
            "install_provisioner_traps",
            'allocate_owned_directory temp_dir "$1" allocation-test',
        )
    )
    environment = os.environ.copy()
    environment["ALLOCATION_READY"] = str(ready)
    process = subprocess.Popen(
        ["bash", "-c", harness, "allocation-harness", str(tmp_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    _wait_for_while_running(ready, process)
    created = next(tmp_path.glob("allocation-test-*"))
    os.kill(process.pid, signal.SIGTERM)
    _stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 143, stderr
    assert not created.exists()


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    [("HUP", 129), ("INT", 130), ("TERM", 143)],
)
def test_signal_before_cid_creation_removes_external_daemon_container_by_owned_name(
    tmp_path, signal_name, expected_status
):
    process, external, state, private_temp = _start_fake_docker_harness(
        tmp_path, "success"
    )
    unrelated = subprocess.Popen(
        ["/usr/bin/setsid", "/usr/bin/sleep", "300"], start_new_session=False
    )
    try:
        _wait_for(state / "run-ready-before-cid")
        os.kill(process.pid, getattr(signal, f"SIG{signal_name}"))
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == expected_status, stderr
        external.wait(timeout=2)
        assert (state / "rm-called").exists()
        assert "holoagent0-strace-" in (state / "removed-args").read_text()
        assert _process_exists(unrelated.pid)
        assert not private_temp.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if external.poll() is None:
            os.killpg(external.pid, signal.SIGKILL)
            external.wait()
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGKILL)
            unrelated.wait()


@pytest.mark.parametrize("behavior", ["remove-fail", "remove-hang"])
def test_container_removal_failure_or_hang_is_bounded_and_fail_closed(
    tmp_path, behavior
):
    process, external, state, _private_temp = _start_fake_docker_harness(
        tmp_path, behavior
    )
    started = time.monotonic()
    try:
        _wait_for(state / "run-ready-before-cid")
        os.kill(process.pid, signal.SIGTERM)
        _stdout, stderr = process.communicate(timeout=8)
        assert process.returncode == 3, stderr
        assert time.monotonic() - started < 8
        assert _process_exists(external.pid)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if external.poll() is None:
            os.killpg(external.pid, signal.SIGKILL)
            external.wait()


def test_container_name_collision_fails_before_run_and_leaves_foreign_process(
    tmp_path,
):
    process, external, state, _private_temp = _start_fake_docker_harness(
        tmp_path, "collision"
    )
    try:
        _stdout, stderr = process.communicate(timeout=8)
        assert process.returncode == 3, stderr
        assert not (state / "run-called").exists()
        assert _process_exists(external.pid)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if external.poll() is None:
            os.killpg(external.pid, signal.SIGKILL)
            external.wait()


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    [("HUP", 129), ("INT", 130), ("TERM", 143)],
)
def test_latched_signal_wins_when_process_identity_validation_fails(
    tmp_path, signal_name, expected_status
):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    ready = tmp_path / "identity-ready"
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'install_staging_dir=""',
            'identity_ready="$2"',
            helpers,
            "process_identity() {",
            '    : > "$identity_ready"',
            "    /usr/bin/sleep 0.25",
            "    return 1",
            "}",
            "install_provisioner_traps",
            "run_owned_process /usr/bin/sleep 0.5",
        )
    )
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "identity-failure-harness",
            str(private_temp),
            str(ready),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for(ready)
        os.kill(process.pid, getattr(signal, f"SIG{signal_name}"))
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == expected_status, stderr
        assert not private_temp.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def test_killed_candidate_publisher_cleans_parent_known_staging_file(tmp_path):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    stage = tmp_path / ".candidate-owned-stage"
    stage.write_bytes(b"")
    stage.chmod(0o600)
    destination = tmp_path / "candidate.json"
    ready = tmp_path / "candidate-ready"
    publisher = tmp_path / "candidate-publisher"
    publisher.write_text(
        """#!/bin/bash
set -euo pipefail
: > "$3"
/usr/bin/sleep 300
: > "$2"
""",
        encoding="utf-8",
    )
    publisher.chmod(0o700)
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'install_staging_dir=""',
            'owned_candidate_staging_path="$2"',
            'owned_candidate_device="$(/usr/bin/stat -c %d -- "$2")"',
            'owned_candidate_inode="$(/usr/bin/stat -c %i -- "$2")"',
            helpers,
            "install_provisioner_traps",
            'run_owned_publication "$3" "$2" "$4" "$5"',
        )
    )
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "candidate-stage-harness",
            str(private_temp),
            str(stage),
            str(publisher),
            str(destination),
            str(ready),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_while_running(ready, process)
    assert stage.exists()
    os.kill(process.pid, signal.SIGTERM)
    _stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 143, stderr
    assert not stage.exists()
    assert not destination.exists()


@pytest.mark.parametrize("fault", ["post_rename_fsync", "post_rename_identity"])
def test_post_rename_fault_rolls_install_out_of_consumer_path(tmp_path, fault):
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN_PUBLICATION_HELPER\n(.*?)\n# END_PUBLICATION_HELPER",
        source,
        flags=re.DOTALL,
    )
    assert match is not None
    namespace = {"__name__": "embedded_publication_fault_test"}
    exec(compile(match.group(1), str(SCRIPT), "exec"), namespace)

    staged = tmp_path / ".install-staged"
    staged.mkdir()
    (staged / "bin").mkdir()
    (staged / "bin/strace").write_bytes(b"reviewed-elf")
    destination = tmp_path / "install"
    quarantine = tmp_path / ".install-quarantine"

    if fault == "post_rename_fsync":

        def fail_fsync(_fd):
            raise OSError("injected post-rename fsync failure")

        namespace["_fsync_install_parent"] = fail_fsync
    else:

        def fail_identity(*_args):
            raise namespace["PublicationError"]("injected identity failure")

        namespace["_validate_published_install"] = fail_identity

    with pytest.raises(namespace["PublicationError"]):
        namespace["publish_install_directory"](staged, destination, quarantine)
    assert not destination.exists()
    assert quarantine.is_dir()
    assert not (destination / ".holoagent0-install-approved.json").exists()


def test_signal_after_install_rename_rolls_back_before_exit(tmp_path):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    staged = tmp_path / ".install-staged"
    staged.mkdir()
    (staged / "bin").mkdir()
    (staged / "bin/strace").write_bytes(b"reviewed-elf")
    destination = tmp_path / "install"
    quarantine = tmp_path / ".install-quarantine"
    ready = tmp_path / "renamed-ready"
    publisher = tmp_path / "install-publisher"
    publisher.write_text(
        """#!/bin/bash
set -euo pipefail
/bin/mv -- "$1" "$2"
: > "$3"
/usr/bin/sleep 300
""",
        encoding="utf-8",
    )
    publisher.chmod(0o700)
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'install_staging_dir="$2"',
            helpers,
            "install_provisioner_traps",
            'record_owned_install_publication "$2" "$3" "$4"',
            'run_owned_publication "$5" "$2" "$3" "$6"',
        )
    )
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "install-rename-harness",
            str(private_temp),
            str(staged),
            str(destination),
            str(quarantine),
            str(publisher),
            str(ready),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for_while_running(ready, process)
    assert destination.is_dir()
    os.kill(process.pid, signal.SIGTERM)
    _stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 143, stderr
    assert not destination.exists()
    assert not quarantine.exists()
