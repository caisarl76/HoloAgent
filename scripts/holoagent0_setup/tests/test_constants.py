import os
from pathlib import Path
import subprocess
import sys

import pytest

from holoagent0_setup.constants import OFFLINE_GATE_ORDER, PROFILE_MODES
from holoagent0_setup.invocation import OfflineInvocation

from conftest import manifest_test_paths


def run_manifest_entrypoint(manifest_path: Path) -> subprocess.CompletedProcess[str]:
    package_root = Path(__file__).parents[1]
    repository_root = package_root.parents[1]
    environment = os.environ.copy()
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTHONPATH"] = "scripts/holoagent0_setup"
    return subprocess.run(
        [
            sys.executable,
            str(package_root / "tests/conftest.py"),
            str(manifest_path),
        ],
        cwd=repository_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_offline_gate_order_is_closed() -> None:
    assert PROFILE_MODES == (
        "workstation_offline",
        "workstation_mujoco",
        "pc2_inventory",
        "pc2_camera",
        "pc2_full_streams",
    )
    expected_gate_order = (
        "source.repository",
        "runtime.workstation",
        "safety.workstation_preflight",
        "openclaw.preexisting",
        "openclaw.version_pin",
        "openclaw.registry_integrity",
        "openclaw.config_pin",
        "openclaw.config_validate",
        "openclaw.doctor_lint",
        "skills.registry",
        "skills.dry_run",
        "agentos.plan_schema",
        "agentos.offline_execution",
        "agentos.network_attempts",
        "source.semantic_blobs",
        "semantic.asset_lock",
        "semantic.fixture_graph",
        "semantic.fixture_query",
        "semantic.natural_language_parser",
        "chatbot.dependencies",
        "chatbot.configuration",
        "chatbot.credentials",
        "chatbot.audio_hardware",
        "safety.workstation_postflight",
        "offline.trace_integrity",
        "offline.network_policy",
        "offline.evidence_binding",
    )
    assert len(OFFLINE_GATE_ORDER) == 27
    assert OFFLINE_GATE_ORDER == expected_gate_order
    assert OFFLINE_GATE_ORDER[:4] == (
        "source.repository",
        "runtime.workstation",
        "safety.workstation_preflight",
        "openclaw.preexisting",
    )
    assert OFFLINE_GATE_ORDER[-4:] == (
        "safety.workstation_postflight",
        "offline.trace_integrity",
        "offline.network_policy",
        "offline.evidence_binding",
    )


def test_offline_invocation_result_path_is_deterministic() -> None:
    invocation = OfflineInvocation(
        mode="workstation_offline",
        output_root=Path("/tmp/results"),
        run_id="run-001",
        invocation_role="standalone",
        parent_run_id=None,
        lineage_nonce=None,
    )

    assert invocation.result_path == Path("/tmp/results/run-001/result.json")


def test_test_manifest_lists_existing_tests_and_rejects_empty_manifest(
    tmp_path: Path,
) -> None:
    package_root = Path(__file__).parents[1]
    manifest_path = package_root / "test-manifest-v1.txt"
    assert manifest_path.read_text(encoding="utf-8").splitlines() == [
        "scripts/holoagent0_setup/tests/test_constants.py"
    ]
    listed_paths = manifest_test_paths(manifest_path)

    assert listed_paths == (package_root / "tests/test_constants.py",)
    assert all(path.is_file() for path in listed_paths)

    empty_manifest = tmp_path / "empty-manifest.txt"
    empty_manifest.write_text("\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at least one test path"):
        manifest_test_paths(empty_manifest)

    missing_manifest = tmp_path / "missing-manifest.txt"
    missing_manifest.write_text("tests/does-not-exist.py\n", encoding="utf-8")
    with pytest.raises(FileNotFoundError, match="does-not-exist.py"):
        manifest_test_paths(missing_manifest)


@pytest.mark.parametrize("manifest_contents", ["", "\n# no selected tests\n"])
def test_manifest_entrypoint_rejects_zero_selected_tests(
    tmp_path: Path,
    manifest_contents: str,
) -> None:
    manifest_path = tmp_path / "empty-manifest.txt"
    manifest_path.write_text(manifest_contents, encoding="utf-8")

    completed = run_manifest_entrypoint(manifest_path)

    assert completed.returncode == 2
    assert "test manifest must list at least one test path" in completed.stderr


def test_manifest_entrypoint_rejects_missing_test_before_pytest(tmp_path: Path) -> None:
    manifest_path = tmp_path / "missing-manifest.txt"
    manifest_path.write_text("missing_test.py\n", encoding="utf-8")

    completed = run_manifest_entrypoint(manifest_path)

    assert completed.returncode == 2
    assert "test manifest lists missing files" in completed.stderr
    assert "missing_test.py" in completed.stderr


def test_manifest_entrypoint_runs_only_the_listed_test(tmp_path: Path) -> None:
    listed_test = tmp_path / "listed_test.py"
    listed_test.write_text(
        "def test_listed_manifest_entry():\n    assert True\n",
        encoding="utf-8",
    )
    (tmp_path / "unlisted_test.py").write_text(
        "def test_unlisted_manifest_entry():\n    assert False\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "valid-manifest.txt"
    manifest_path.write_text("listed_test.py\n", encoding="utf-8")

    completed = run_manifest_entrypoint(manifest_path)

    assert completed.returncode == 0
    assert "1 passed" in completed.stdout


def test_readme_invokes_the_validating_manifest_entrypoint() -> None:
    package_root = Path(__file__).parents[1]
    readme = (package_root / "README.md").read_text(encoding="utf-8")

    assert "/usr/bin/python3.10 scripts/holoagent0_setup/tests/conftest.py" in readme
    assert "scripts/holoagent0_setup/test-manifest-v1.txt" in readme
