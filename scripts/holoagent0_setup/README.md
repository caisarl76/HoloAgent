# HoloAgent0 setup

This package contains the initial deterministic contracts for HoloAgent0
offline setup validation. Run the reviewed Task 1 test manifest from the
repository root with:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=scripts/holoagent0_setup \
  /usr/bin/python3.10 scripts/holoagent0_setup/tests/conftest.py \
  scripts/holoagent0_setup/test-manifest-v1.txt
```

`test-manifest-v1.txt` contains one repository-relative setup test path per
line. The Task 1 runner ignores blank and comment-only lines, rejects a
manifest with zero selected tests, verifies every listed file before pytest
discovery, and runs only those paths. It intentionally does not pin a
historical test count.
