import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tarfile
import time

import pytest


ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"
POLICY = ROOT / "policies/holoagent0-trace-tool-v1.json"
EXPECTED_SHA256 = "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
REAL_ARCHIVE_OPT_IN = "HOLOAGENT0_VERIFY_STRACE_SOURCE_ARCHIVE"
REAL_ARCHIVE_PATH = "HOLOAGENT0_STRACE_SOURCE_ARCHIVE"


def _run(*args: str, env=None):
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        text=True,
        capture_output=True,
        cwd=REPOSITORY_ROOT,
        env=env,
        check=False,
    )


def _tar(path: Path, members):
    with tarfile.open(path, "w:xz") as archive:
        for member in members:
            info = tarfile.TarInfo(member[0])
            kind = member[1]
            if kind == "file":
                data = member[2]
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = member[2]
                archive.addfile(info)
            elif kind == "device":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)


def _validate_members(archive: Path):
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN_ARCHIVE_VALIDATOR\n(.*?)\n# END_ARCHIVE_VALIDATOR",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, "provisioner must expose its exact embedded validator"
    return subprocess.run(
        ["/usr/bin/python3.10", "-c", match.group(1), str(archive), "strace-6.6"],
        text=True,
        capture_output=True,
        check=False,
    )


def _run_cleanup_trap_harness(tmp_path: Path, command: str):
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("cleanup() {")
    end = source.index('snapshot="$temp_dir/strace-6.6.tar.xz"')
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    (private_temp / "owned").write_text("owned", encoding="utf-8")
    candidate = tmp_path / "candidate.json"
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'candidate="$2"',
            source[start:end],
            command,
            ': > "$candidate"',
        )
    )
    completed = subprocess.run(
        [
            "bash",
            "-c",
            harness,
            "cleanup-trap-harness",
            str(private_temp),
            str(candidate),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, private_temp, candidate


def _source_section(name: str) -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(rf"# BEGIN_{name}\n(.*?)\n# END_{name}", source, flags=re.DOTALL)
    assert match is not None, f"provisioner must expose its exact {name} helpers"
    return match.group(1)


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


def _wait_gone(pid: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_exists(pid):
            return
        time.sleep(0.01)
    raise AssertionError(f"owned process {pid} survived cleanup")


def _write_fake_docker(path: Path) -> None:
    path.write_text(
        """#!/bin/bash
set -euo pipefail
state_dir="${FAKE_DOCKER_STATE:?}"
command="$1"
shift
if [[ "$command" == "run" ]]; then
    cidfile=""
    while (($#)); do
        if [[ "$1" == "--cidfile" ]]; then
            cidfile="$2"
            shift 2
        else
            shift
        fi
    done
    [[ -n "$cidfile" ]]
    cid="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    printf '%s\n' "$cid" > "$cidfile"
    /usr/bin/sleep 300 &
    container_pid=$!
    trap 'kill -TERM "$container_pid" 2>/dev/null || :; wait "$container_pid" 2>/dev/null || :; exit 143' HUP INT TERM
    printf '%s\n' "$$" > "$state_dir/client.pid"
    printf '%s\n' "$container_pid" > "$state_dir/container.pid"
    : > "$state_dir/ready"
    wait "$container_pid"
elif [[ "$command" == "rm" ]]; then
    [[ "$1" == "--force" ]]
    [[ "$2" == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ]]
    container_pid="$(cat "$state_dir/container.pid")"
    /bin/kill -TERM -- "-$container_pid" 2>/dev/null || :
    printf '%s\n' "$2" > "$state_dir/removed.cid"
else
    exit 64
fi
""",
        encoding="utf-8",
    )
    path.chmod(0o700)


def test_script_has_exact_usage_and_fails_closed_for_bad_cli(tmp_path):
    completed = _run()
    assert completed.returncode == 2
    assert completed.stderr == (
        f"usage: {SCRIPT} [--archive ARCHIVE] "
        "(--output-dir OUTPUT_DIR | --candidate-evidence FILE)\n"
    )
    assert _run("--unknown").returncode == 2
    assert _run("--output-dir", "relative").returncode != 0
    assert _run("--output-dir", str(tmp_path / "../escape")).returncode != 0


def test_source_archive_contract_is_explicit_opt_in_and_fails_clearly_without_path():
    if os.environ.get(REAL_ARCHIVE_OPT_IN) != "1":
        pytest.skip(f"set {REAL_ARCHIVE_OPT_IN}=1 to run the pinned source gate")
    configured = os.environ.get(REAL_ARCHIVE_PATH)
    assert configured, (
        f"{REAL_ARCHIVE_PATH} must name the immutable strace 6.6 archive when "
        f"{REAL_ARCHIVE_OPT_IN}=1"
    )
    archive = Path(configured)
    assert archive.is_file() and not archive.is_symlink()
    assert archive.stat().st_size == 2420364
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == EXPECTED_SHA256


def test_archive_contract_is_checked_before_pending_build_pins(tmp_path):
    archive = tmp_path / "not-the-pinned-source.tar.xz"
    archive.write_bytes(b"hermetic-invalid-source")
    before = POLICY.read_bytes()
    completed = _run(
        "--archive", str(archive), "--output-dir", str(tmp_path / "install")
    )
    assert completed.returncode == 2
    assert "source archive size mismatch" in completed.stderr
    assert "PENDING_REPRODUCIBLE_BUILD" not in completed.stderr
    assert POLICY.read_bytes() == before
    assert not (tmp_path / "install").exists()


def test_archive_must_be_regular_nonsymlink_and_exact_size_hash(tmp_path):
    output = str(tmp_path / "install")
    wrong_size = tmp_path / "wrong-size.tar.xz"
    wrong_size.write_bytes(b"bad")
    symlink = tmp_path / "archive-link"
    symlink.symlink_to(wrong_size)
    assert _run("--archive", str(symlink), "--output-dir", output).returncode != 0
    result = _run("--archive", str(wrong_size), "--output-dir", output)
    assert result.returncode != 0 and "size" in result.stderr.lower()
    wrong_hash = tmp_path / "wrong-hash.tar.xz"
    wrong_hash.write_bytes(b"\0" * 2420364)
    result = _run("--archive", str(wrong_hash), "--output-dir", output)
    assert result.returncode != 0 and "sha256" in result.stderr.lower()


@pytest.mark.parametrize(
    "member",
    [
        ("/absolute", "file", b"x"),
        ("strace-6.6/../../escape", "file", b"x"),
        ("strace-6.6/link", "symlink", "../../escape"),
        ("strace-6.6/device", "device", None),
        ("other-top/file", "file", b"x"),
    ],
)
def test_tar_member_validation_rejects_unsafe_paths_types_and_wrong_top(
    tmp_path, member
):
    archive = tmp_path / "bad.tar.xz"
    _tar(archive, [member])
    result = _validate_members(archive)
    assert result.returncode != 0
    assert "archive" in result.stderr.lower()
    assert not (tmp_path / "install").exists()


def test_private_temp_cleanup_and_no_policy_mutation(tmp_path):
    temp_parent = tmp_path / "temp-parent"
    temp_parent.mkdir()
    env = os.environ.copy()
    env["TMPDIR"] = str(temp_parent)
    before = POLICY.read_bytes()
    archive = tmp_path / "invalid-source.tar.xz"
    archive.write_bytes(b"invalid")
    result = _run(
        "--archive",
        str(archive),
        "--output-dir",
        str(tmp_path / "install"),
        env=env,
    )
    assert result.returncode == 2
    assert list(temp_parent.iterdir()) == []
    assert POLICY.read_bytes() == before


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    [("HUP", 129), ("INT", 130), ("TERM", 143)],
)
def test_signal_terminates_reaps_owned_fake_docker_and_removes_exact_container_only(
    tmp_path, signal_name, expected_status
):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    state = tmp_path / "state"
    state.mkdir()
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    fake_docker = tmp_path / "fake-docker"
    _write_fake_docker(fake_docker)
    unrelated = subprocess.Popen(
        ["/usr/bin/setsid", "/usr/bin/sleep", "300"], start_new_session=False
    )
    harness = "\n".join(
        (
            "set -euo pipefail",
            'temp_dir="$1"',
            'docker_bin="$2"',
            helpers,
            "install_provisioner_traps",
            'run_owned_docker "$docker_bin" run --network=none fake-image true',
        )
    )
    environment = os.environ.copy()
    environment["FAKE_DOCKER_STATE"] = str(state)
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "owned-docker-harness",
            str(private_temp),
            str(fake_docker),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    try:
        _wait_for(state / "ready")
        client_pid = int((state / "client.pid").read_text())
        container_pid = int((state / "container.pid").read_text())
        os.kill(process.pid, getattr(signal, f"SIG{signal_name}"))
        _stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == expected_status, stderr
        _wait_gone(client_pid)
        _wait_gone(container_pid)
        assert (state / "removed.cid").read_text().strip() == "a" * 64
        assert _process_exists(unrelated.pid)
        assert not private_temp.exists()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if unrelated.poll() is None:
            unrelated.terminate()
            unrelated.wait()


def test_precommit_signal_kills_owned_publisher_before_any_artifact_is_visible(
    tmp_path,
):
    helpers = _source_section("OWNED_PROCESS_HELPERS")
    private_temp = tmp_path / "private-temp"
    private_temp.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    destination = tmp_path / "candidate.json"
    publisher = tmp_path / "fake-publisher"
    publisher.write_text(
        """#!/bin/bash
set -euo pipefail
: > "$1/ready"
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
            helpers,
            "install_provisioner_traps",
            'run_owned_publication "$2" "$3" "$4"',
        )
    )
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            harness,
            "publication-harness",
            str(private_temp),
            str(publisher),
            str(state),
            str(destination),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _wait_for(state / "ready")
    os.kill(process.pid, signal.SIGTERM)
    _stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 143, stderr
    assert not destination.exists()
    assert not private_temp.exists()


def test_candidate_and_install_publication_are_atomic_no_replace(tmp_path):
    publication = importlib.import_module("holoagent0_setup.strace_publication")
    candidate = tmp_path / "candidate.json"
    evidence = {"schema_version": "candidate.v1", "nested": {"value": 1}}
    publication.publish_candidate_evidence(candidate, evidence)
    assert json.loads(candidate.read_text()) == evidence
    assert candidate.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        publication.publish_candidate_evidence(candidate, {"attacker": True})
    assert json.loads(candidate.read_text()) == evidence

    staged = tmp_path / ".install-staged"
    staged.mkdir()
    (staged / "strace").write_bytes(b"reviewed-elf")
    staged_inode = staged.stat().st_ino
    installed = tmp_path / "install"
    publication.publish_install_directory(staged, installed)
    assert installed.stat().st_ino == staged_inode
    assert (installed / "strace").read_bytes() == b"reviewed-elf"


def test_install_publication_rejects_empty_destination_race_and_cross_filesystem_shape(
    tmp_path,
):
    publication = importlib.import_module("holoagent0_setup.strace_publication")
    staged = tmp_path / ".install-staged"
    staged.mkdir()
    destination = tmp_path / "install"
    destination.mkdir()
    destination_inode = destination.stat().st_ino
    with pytest.raises(FileExistsError):
        publication.publish_install_directory(staged, destination)
    assert destination.stat().st_ino == destination_inode
    assert staged.is_dir()

    other_parent = tmp_path / "other"
    other_parent.mkdir()
    with pytest.raises(publication.PublicationError, match="same parent"):
        publication.publish_install_directory(staged, other_parent / "install")


@pytest.mark.parametrize(
    ("signal_name", "expected_status"),
    [("HUP", 129), ("INT", 130), ("TERM", 143)],
)
def test_signal_traps_use_deterministic_status_cleanup_and_publish_nothing(
    tmp_path, signal_name, expected_status
):
    before = POLICY.read_bytes()
    completed, private_temp, candidate = _run_cleanup_trap_harness(
        tmp_path, f'kill -s {signal_name} "$$"'
    )
    assert completed.returncode == expected_status
    assert not private_temp.exists()
    assert not candidate.exists()
    assert POLICY.read_bytes() == before


def test_ordinary_exit_cleanup_preserves_failing_command_status(tmp_path):
    before = POLICY.read_bytes()
    completed, private_temp, candidate = _run_cleanup_trap_harness(tmp_path, "exit 7")
    assert completed.returncode == 7
    assert not private_temp.exists()
    assert not candidate.exists()
    assert POLICY.read_bytes() == before


def test_recipe_is_pinned_fail_closed_and_build_command_is_deterministic():
    source = SCRIPT.read_text()
    assert "set -euo pipefail" in source
    assert 'SOURCE_URL="https://strace.io/files/6.6/strace-6.6.tar.xz"' in source
    assert "--network=none" in source
    assert "--pull=never" in source
    assert "cd /build" in source and "/src/configure" in source
    assert "LC_ALL=C" in source and "TZ=UTC" in source and "umask 0022" in source
    assert "PENDING_REPRODUCIBLE_BUILD" in source
    assert "docker" in source
    assert "EM_X86_64" in source
    assert "strace -- version 6.6" in source
    policy = json.loads(POLICY.read_text())
    row = policy["rows"][0]
    assert row["build"]["container_image_digest"] is None
    assert row["build"]["recipe_sha256"] is None
    assert row["runtime"]["elf_sha256"] is None
    assert row["build"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"
    assert row["runtime"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"


def test_recipe_uses_fixed_reviewed_gcc_builder_repository_with_pending_digest():
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"docker.io/library/gcc@${pins[2]}"' in source
    assert "docker.io/library/debian@" not in source
    row = json.loads(POLICY.read_text(encoding="utf-8"))["rows"][0]
    assert row["build"]["container_image_digest"] is None
    assert row["build"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"


def test_candidate_measurement_is_separate_from_reviewed_install_and_never_edits_policy():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "candidate-evidence" in source
    assert "CANDIDATE_MEASUREMENT" in source
    assert "runtime pins are required for reviewed install" in source
    assert "atomic_write_json_no_replace" in source
    assert "/usr/bin/mv --" not in source
    assert "run_owned_publication" in source
    assert (
        "policy_path.write" not in source
        and "POLICY_PATH"
        not in re.sub(r'POLICY_PATH="[^"]+"', "", source).split(
            "CANDIDATE_MEASUREMENT", 1
        )[-1]
    )


def test_no_archive_mode_cannot_download_before_recipe_and_container_validation():
    source = SCRIPT.read_text(encoding="utf-8")
    validation = source.index("validate_build_pins")
    download = source.index('"$SOURCE_URL"')
    assert validation < download
    assert "/usr/bin/curl" in source


def test_reviewed_commands_are_absolute_and_caller_path_cannot_replace_integrity_tools():
    source = SCRIPT.read_text(encoding="utf-8")
    for tool in (
        "cp",
        "curl",
        "cut",
        "docker",
        "mkdir",
        "mktemp",
        "rm",
        "setsid",
        "sha256sum",
        "stat",
        "tar",
    ):
        assert f"/usr/bin/{tool}" in source
    assert re.search(r"(?m)(?<!/usr/bin/)\bdocker run\b", source) is None
    assert re.search(r"(?m)^PATH='/usr/bin:/bin'$", source)
