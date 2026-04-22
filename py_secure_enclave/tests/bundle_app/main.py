"""
Entry point for the bundled test runner.

py2app freezes this file into a .app. At runtime it imports the
test_secure_enclave module (baked in via setup.py's `includes`) and runs the
unittest suite, exiting 0 on success and 1 on failure so the shell driver
can propagate the result.

When frozen, stdout/stderr from a .app don't flow back to the terminal that
launched it, so we redirect them to a log file next to the .app and tail it
from the driver script.
"""
from __future__ import annotations

import os
import sys
import unittest


def _redirect_output_when_frozen() -> str | None:
    if not getattr(sys, "frozen", False):
        return None
    # sys.executable → <bundle>/Contents/MacOS/<AppName>
    bundle_dir = os.path.abspath(os.path.join(os.path.dirname(sys.executable), "..", ".."))
    log_path = os.path.join(os.path.dirname(bundle_dir), "test_output.log")
    # Line-buffered so the tail -f in run_tests.sh is responsive.
    log = open(log_path, "w", buffering=1)
    sys.stdout = log
    sys.stderr = log
    return log_path


def main() -> int:
    _redirect_output_when_frozen()

    import test_secure_enclave  # noqa: F401 — pulled in by py2app `includes`

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_secure_enclave)
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
