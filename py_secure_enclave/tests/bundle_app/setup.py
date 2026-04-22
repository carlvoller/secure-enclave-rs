"""
py2app configuration for the Secure Enclave test bundle.

Usage (invoked by run_tests.sh):

    python setup.py py2app --no-strip

Notes:
  * The parent ``tests/`` directory is added to sys.path at build time so
    py2app's module graph can discover ``test_secure_enclave.py`` via the
    ``includes`` option.
  * ``packages=['py_secure_enclave']`` forces py2app to copy the entire
    package tree — crucially including the compiled ``_native`` extension —
    as-is, rather than trying to flatten it into the zipped site-packages.
  * LSUIElement hides the Dock icon so the test run doesn't flash one up.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.abspath(os.path.dirname(__file__))
TESTS_DIR = os.path.abspath(os.path.join(HERE, ".."))
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

from setuptools import setup  # noqa: E402

# Bundle id is driven by run_tests.sh so the Info.plist, the entitlements, and
# the provisioning profile all agree on a single value.
BUNDLE_ID = os.environ.get("BUNDLE_ID")
if not BUNDLE_ID:
    sys.exit("setup.py: BUNDLE_ID env var is required (set by run_tests.sh).")

APP = ["main.py"]

OPTIONS = {
    "argv_emulation": False,
    "includes": ["test_secure_enclave"],
    # py_secure_enclave's Rust extension imports `json` dynamically via PyO3,
    # which py2app's static module graph doesn't see — force-include it.
    "packages": ["py_secure_enclave", "json"],
    "plist": {
        "CFBundleName": "SecureEnclaveTests",
        "CFBundleDisplayName": "SecureEnclaveTests",
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": "0.1.0",
        "CFBundleShortVersionString": "0.1.0",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
    },
}

setup(
    name="SecureEnclaveTests",
    app=APP,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
