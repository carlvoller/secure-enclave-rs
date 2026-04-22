use pyo3::{create_exception, exceptions::PyException, PyErr};
use secure_enclave_rs::Error;

create_exception!(py_secure_enclave, SecureEnclaveError, PyException);
create_exception!(py_secure_enclave, KeyNotFoundError, SecureEnclaveError);
create_exception!(py_secure_enclave, AuthFailedError, SecureEnclaveError);
create_exception!(py_secure_enclave, UserCancelledError, SecureEnclaveError);

/// Convert a `secure_enclave_rs::Error` to the appropriate Python exception.
/// Uses a free function to avoid the orphan rule (both `Error` and `PyErr` are
/// from external crates).
pub(crate) fn to_py_err(e: Error) -> PyErr {
    let msg = e.to_string();
    match e {
        Error::NotFound => KeyNotFoundError::new_err(msg),
        Error::AuthFailed => AuthFailedError::new_err(msg),
        Error::UserCancelled => UserCancelledError::new_err(msg),
        _ => SecureEnclaveError::new_err(msg),
    }
}
