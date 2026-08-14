#!/usr/bin/python3.10
"""Fresh-exec entry point for the bounded chatbot readiness child."""

from __future__ import annotations

from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import sys


def _load_sealed_gate():
    if len(sys.argv) != 2:
        raise RuntimeError("sealed chatbot gate descriptor is required")
    encoded_descriptor = sys.argv[1]
    if (
        not encoded_descriptor.isascii()
        or not encoded_descriptor.isdecimal()
        or str(int(encoded_descriptor)) != encoded_descriptor
    ):
        raise RuntimeError("sealed chatbot gate descriptor is invalid")
    descriptor = int(encoded_descriptor)
    if descriptor < 3:
        raise RuntimeError("sealed chatbot gate descriptor is invalid")
    module_name = "holoagent0_sealed_chatbot_gate"
    loader = SourceFileLoader(module_name, f"/proc/self/fd/{descriptor}")
    spec = spec_from_loader(module_name, loader)
    if spec is None:
        raise RuntimeError("sealed chatbot gate loader is unavailable")
    module = module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


if __name__ == "__main__":
    raise SystemExit(_load_sealed_gate()._chatbot_child_main())
