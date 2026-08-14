#!/usr/bin/python3.10
"""Fresh-exec entry point for the bounded chatbot readiness child."""

from __future__ import annotations

from pathlib import Path
import sys


PACKAGE_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKAGE_ROOT))

from holoagent0_setup.chatbot_gate import _chatbot_child_main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(_chatbot_child_main())
