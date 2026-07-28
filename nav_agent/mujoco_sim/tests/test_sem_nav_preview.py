from __future__ import annotations

import os
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "nav_agent" / "scripts" / "run_sem_nav.sh"


def test_documented_sem_nav_no_motion_preview_executes_without_local_env_file():
    environment = dict(os.environ)
    environment.update(
        {
            "PRINT_SEM_NAV_COMMANDS": "1",
            "START_G1_PUBVEL": "0",
            "G1_DRY_RUN": "1",
            "ALLOW_G1_MOTION": "0",
        }
    )

    result = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Semantic navigation stack command preview" in result.stdout
    assert "START_G1_PUBVEL: 0" in result.stdout
    assert "g1_pubvel_node" in result.stdout and "disabled." in result.stdout
