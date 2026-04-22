use pyo3::prelude::*;

mod error;
mod jwt;
mod key;

use error::{AuthFailedError, KeyNotFoundError, SecureEnclaveError, UserCancelledError};
use jwt::PySecureEnclaveJWT;
use key::{PyAccessControlFlags, PySecureEnclaveKey};

/// Python bindings for macOS Secure Enclave operations.
///
/// Provides hardware-backed key generation, ECDSA signing/verification,
/// ECIES encryption/decryption, ECDH key exchange, and ES256 JWT signing.
/// Private key material never leaves the Secure Enclave.
///
/// Quick start::
///
///     from py_secure_enclave import SecureEnclaveKey, AccessControlFlags
///
///     key = SecureEnclaveKey.generate(
///         tag=b"com.myapp.signing-key",
///         access_flags=AccessControlFlags.BIOMETRY_ANY,
///     )
///     sig = key.sign(b"hello world")
///     assert key.verify(b"hello world", sig)
///     key.remove()
// Function name must match the last component of module-name in pyproject.toml
// ("py_secure_enclave._native"), which is what Python looks for as PyInit__native.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySecureEnclaveKey>()?;
    m.add_class::<PyAccessControlFlags>()?;
    m.add_class::<PySecureEnclaveJWT>()?;

    m.add("SecureEnclaveError", m.py().get_type::<SecureEnclaveError>())?;
    m.add("KeyNotFoundError",   m.py().get_type::<KeyNotFoundError>())?;
    m.add("AuthFailedError",    m.py().get_type::<AuthFailedError>())?;
    m.add("UserCancelledError", m.py().get_type::<UserCancelledError>())?;

    Ok(())
}
