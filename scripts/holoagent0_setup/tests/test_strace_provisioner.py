import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
SCRIPT = ROOT / "provision_strace_6_6.sh"
POLICY = ROOT / "policies/holoagent0-trace-tool-v1.json"
REAL_ARCHIVE = Path("/tmp/strace-6.6.tar.xz")
EXPECTED_SHA256 = "421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"


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


def test_real_archive_contract_is_verified_offline_before_pins(tmp_path):
    assert REAL_ARCHIVE.stat().st_size == 2420364
    assert hashlib.sha256(REAL_ARCHIVE.read_bytes()).hexdigest() == EXPECTED_SHA256
    before = POLICY.read_bytes()
    completed = _run(
        "--archive", str(REAL_ARCHIVE), "--output-dir", str(tmp_path / "install")
    )
    assert completed.returncode == 3
    assert "PENDING_REPRODUCIBLE_BUILD" in completed.stderr
    assert POLICY.read_bytes() == before
    assert not (tmp_path / "install").exists()


def test_archive_must_be_regular_nonsymlink_and_exact_size_hash(tmp_path):
    output = str(tmp_path / "install")
    symlink = tmp_path / "archive-link"
    symlink.symlink_to(REAL_ARCHIVE)
    assert _run("--archive", str(symlink), "--output-dir", output).returncode != 0
    wrong_size = tmp_path / "wrong-size.tar.xz"
    wrong_size.write_bytes(b"bad")
    result = _run("--archive", str(wrong_size), "--output-dir", output)
    assert result.returncode != 0 and "size" in result.stderr.lower()
    wrong_hash = tmp_path / "wrong-hash.tar.xz"
    data = bytearray(REAL_ARCHIVE.read_bytes())
    data[-1] ^= 1
    wrong_hash.write_bytes(data)
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
    result = _run(
        "--archive",
        str(REAL_ARCHIVE),
        "--output-dir",
        str(tmp_path / "install"),
        env=env,
    )
    assert result.returncode == 3
    assert list(temp_parent.iterdir()) == []
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


def test_candidate_measurement_is_separate_from_reviewed_install_and_never_edits_policy():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "candidate-evidence" in source
    assert "CANDIDATE_MEASUREMENT" in source
    assert "runtime pins are required for reviewed install" in source
    assert "os.replace" in source
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
        "mv",
        "rm",
        "sha256sum",
        "stat",
        "tar",
    ):
        assert f"/usr/bin/{tool}" in source
    assert re.search(r"(?m)(?<!/usr/bin/)\bdocker run\b", source) is None
    assert re.search(r"(?m)^PATH='/usr/bin:/bin'$", source)
