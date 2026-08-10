import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"
POLICY = ROOT / "policies/holoagent0-trace-tool-v1.json"
EXPECTED_SHA256 = "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
REAL_ARCHIVE_OPT_IN = "HOLOAGENT0_VERIFY_STRACE_SOURCE_ARCHIVE"
REAL_ARCHIVE_PATH = "HOLOAGENT0_STRACE_SOURCE_ARCHIVE"


def _namespace():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# BEGIN_PROVISIONER_PYTHON\n(.*?)\n# END_PROVISIONER_PYTHON",
        source,
        flags=re.DOTALL,
    )
    assert match is not None, "the complete provisioner must be embedded in the recipe"
    namespace = {"__name__": "holoagent0_embedded_provisioner_base_test"}
    padding = "\n" * source[: match.start(1)].count("\n")
    exec(compile(padding + match.group(1), str(SCRIPT), "exec"), namespace)
    return namespace


def _run(*args: str, env=None):
    _namespace()
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        text=True,
        capture_output=True,
        cwd=REPOSITORY_ROOT,
        env=env,
        check=False,
        timeout=5,
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


def _elf_fixture(tmp_path: Path, ns):
    staged = tmp_path / ".install-stage"
    (staged / "bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", staged / "bin/strace")
    os.chmod(staged / "bin/strace", 0o755)
    runner = ns["OwnedSessionRunner"](term_grace=0.05, kill_grace=0.2)
    pins = ns["measure_elf_pins"](staged / "bin/strace", runner, deadline=0.5)
    measurement = ns["retain_staged_install"](staged, pins, runner, deadline=0.5)
    return staged, runner, pins, measurement


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


def test_source_archive_contract_is_explicit_opt_in_and_exact():
    _namespace()
    if os.environ.get(REAL_ARCHIVE_OPT_IN) != "1":
        pytest.skip(f"set {REAL_ARCHIVE_OPT_IN}=1 to run the pinned source gate")
    configured = os.environ.get(REAL_ARCHIVE_PATH)
    assert configured
    archive = Path(configured)
    assert archive.is_file() and not archive.is_symlink()
    assert archive.stat().st_size == 2420364
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == EXPECTED_SHA256


def test_archive_contract_precedes_pending_build_pins_and_never_mutates_policy(
    tmp_path,
):
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
    _namespace()
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
    ns = _namespace()
    archive = tmp_path / "bad.tar.xz"
    _tar(archive, [member])
    with pytest.raises(ns["ArchiveValidationError"]):
        ns["validate_archive_members"](archive, "strace-6.6")


def test_private_temp_cleanup_and_no_policy_mutation(tmp_path):
    _namespace()
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


def test_candidate_publication_is_mode_0600_atomic_no_replace_and_race_safe(tmp_path):
    ns = _namespace()
    candidate = tmp_path / "candidate.json"
    evidence = {"schema_version": "candidate.v1", "nested": {"value": 1}}
    ns["publish_candidate_evidence"](candidate, evidence)
    assert json.loads(candidate.read_text()) == evidence
    assert candidate.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        ns["publish_candidate_evidence"](candidate, {"attacker": True})
    assert json.loads(candidate.read_text()) == evidence

    raced = tmp_path / "raced.json"

    def occupy_destination(_stage):
        raced.write_text("attacker", encoding="utf-8")

    with pytest.raises(FileExistsError):
        ns["publish_candidate_evidence"](
            raced, evidence, before_commit=occupy_destination
        )
    assert raced.read_text() == "attacker"
    assert not list(tmp_path.glob(".holoagent0-candidate-*"))


def test_install_publication_is_no_replace_and_requires_same_parent(tmp_path):
    ns = _namespace()
    staged, runner, pins, measurement = _elf_fixture(tmp_path, ns)
    destination = tmp_path / "install"
    destination.mkdir()
    destination_inode = destination.stat().st_ino
    quarantine = tmp_path / ".quarantine"
    with pytest.raises(FileExistsError):
        ns["publish_install_directory"](
            staged, destination, quarantine, measurement, pins, runner, deadline=0.5
        )
    assert destination.stat().st_ino == destination_inode
    assert staged.is_dir()
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ns["PublicationError"], match="same parent"):
        ns["publish_install_directory"](
            staged,
            other / "install",
            other / ".quarantine",
            measurement,
            pins,
            runner,
            deadline=0.5,
        )
    measurement.close()


def test_recipe_pins_source_builder_environment_and_all_blocking_phases():
    ns = _namespace()
    assert ns["SOURCE_URL"] == "https://strace.io/files/6.6/strace-6.6.tar.xz"
    assert ns["SOURCE_SIZE"] == 2420364
    assert ns["SOURCE_SHA256"] == EXPECTED_SHA256
    assert ns["BUILD_ENV"] == {
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": "0",
    }
    assert ns["BLOCKING_PHASES"] == frozenset(
        {
            "archive_transfer",
            "archive_validation",
            "archive_extraction",
            "elf_validation",
            "elf_version",
        }
    )
    policy = json.loads(POLICY.read_text())
    row = policy["rows"][0]
    assert row["build"]["container_image_digest"] is None
    assert row["build"]["recipe_sha256"] is None
    assert row["runtime"]["elf_sha256"] is None
    assert row["build"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"
    assert row["runtime"]["review_state"] == "PENDING_REPRODUCIBLE_BUILD"


def test_build_argv_is_deterministic_offline_and_uses_fixed_gcc_repository(tmp_path):
    ns = _namespace()
    argv = ns["build_container_argv"](
        "sha256:" + "a" * 64,
        tmp_path / "source",
        tmp_path / "build",
        tmp_path / "install",
        uid=1000,
        gid=1000,
    )
    assert argv[:3] == ["/usr/bin/docker", "run", "--pull=never"]
    assert "--network=none" in argv
    assert "docker.io/library/gcc@sha256:" + "a" * 64 in argv
    assert not any("debian" in item for item in argv)
    assert argv[-2:] == [
        "/bin/sh",
        "cd /build && /src/configure --prefix=/out --disable-gcc-Werror "
        "&& make -j1 && make install",
    ]


def test_no_archive_mode_validates_build_pins_before_transfer(tmp_path):
    _namespace()
    source = SCRIPT.read_text(encoding="utf-8")
    main_source = re.search(
        r"def provision\(.*?\n(?=def main\()", source, flags=re.DOTALL
    ).group(0)
    assert main_source.index("validate_build_pins") < main_source.index(
        "transfer_archive"
    )
    result = _run("--candidate-evidence", str(tmp_path / "candidate.json"))
    assert result.returncode == 3
    assert "PENDING_REPRODUCIBLE_BUILD" in result.stderr
    assert "curl" not in result.stderr.lower()
    assert "exec /usr/bin/python3.10" in source


def test_candidate_measurement_never_amends_policy_or_claims_reviewed_install():
    ns = _namespace()
    source = SCRIPT.read_text(encoding="utf-8")
    publisher = re.search(
        r"def publish_candidate_evidence\(.*?\n(?=def publish_install_directory\()",
        source,
        flags=re.DOTALL,
    ).group(0)
    assert "CANDIDATE_MEASUREMENT" in json.dumps(
        ns["candidate_evidence"](
            "recipe", "sha256:" + "a" * 64, ns["ElfPins"](1, "b" * 64, "c" * 64)
        )
    )
    assert "POLICY_PATH" not in publisher
    assert "write_text" not in publisher
