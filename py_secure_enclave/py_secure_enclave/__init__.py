"""
py_secure_enclave — macOS Secure Enclave bindings.

The compiled Rust extension lives at ``py_secure_enclave._native``.
Everything is re-exported here so callers use the stable top-level namespace:

    from py_secure_enclave import SecureEnclaveKey, AccessControlFlags
"""

from ._native import (
    AccessControlFlags,
    AuthFailedError,
    KeyNotFoundError,
    SecureEnclaveError,
    SecureEnclaveJWT,
    SecureEnclaveKey,
    UserCancelledError,
)

__all__ = [
    "AccessControlFlags",
    "AuthFailedError",
    "KeyNotFoundError",
    "SecureEnclaveError",
    "SecureEnclaveJWT",
    "SecureEnclaveKey",
    "UserCancelledError",
]
