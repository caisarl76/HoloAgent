from __future__ import annotations

import importlib
from pathlib import Path
import sys


def test_source_has_no_unitree_sdk_imports():
    package = Path(__file__).parents[1] / "holoagent_mujoco"
    text = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))

    forbidden = "unitree" + "_sdk"
    assert forbidden not in text.lower()


def test_importing_backend_does_not_load_unitree_modules():
    before = set(sys.modules)

    importlib.import_module("holoagent_mujoco.backend")

    loaded = set(sys.modules) - before
    forbidden_prefixes = ("unitree" + "_sdk2", "unitree" + "_sdk2py")
    assert not [name for name in loaded if name.startswith(forbidden_prefixes)]
