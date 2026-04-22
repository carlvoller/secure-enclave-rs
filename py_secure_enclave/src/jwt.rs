use pyo3::{exceptions::PyValueError, prelude::*, types::PyString};
use secure_enclave_rs::SecureEnclaveJWT as RustJWT;

use crate::{error::to_py_err, key::PySecureEnclaveKey};

fn py_to_json(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    let json_mod = PyModule::import(py, "json")?;
    let json_str: String = json_mod.call_method1("dumps", (obj,))?.extract()?;
    serde_json::from_str(&json_str)
        .map_err(|e| PyValueError::new_err(format!("JSON serialization failed: {e}")))
}

fn json_to_py<'py>(py: Python<'py>, val: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    let json_mod = PyModule::import(py, "json")?;
    let s = PyString::new(py, &val.to_string());
    json_mod.call_method1("loads", (s,))
}

/// Builder for ES256 JWTs signed by a Secure Enclave private key.
///
/// The key is accepted at :meth:`sign` time so the builder can be prepared
/// independently of the key handle.
///
/// Example::
///
///     import time
///     from py_secure_enclave import SecureEnclaveKey, SecureEnclaveJWT
///
///     key = SecureEnclaveKey.get(b"my-service-key")
///     now = int(time.time())
///
///     jwt = SecureEnclaveJWT()
///     jwt.with_headers({"kid": "key-id"})
///     jwt.with_claims({"iss": "client-id",
///                      "aud": ["https://example.com/token"],
///                      "iat": now, "exp": now + 300})
///     token = jwt.sign(key)
///     # POST token as client_assertion in the OAuth2 token request
#[pyclass(name = "SecureEnclaveJWT")]
pub struct PySecureEnclaveJWT {
    headers: serde_json::Value,
    claims: serde_json::Value,
}

#[pymethods]
impl PySecureEnclaveJWT {
    /// Create a new JWT builder. Default headers include ``"alg": "ES256"``
    /// and ``"typ": "JWT"``, which are protected and cannot be overwritten.
    #[new]
    pub fn new() -> Self {
        Self {
            headers: serde_json::json!({}),
            claims: serde_json::json!({}),
        }
    }

    /// Merge additional header fields. ``"alg"`` and ``"typ"`` are protected.
    /// Later calls do not overwrite earlier values for the same key.
    ///
    /// :param headers: JSON-serializable ``dict``.
    pub fn with_headers(&mut self, py: Python<'_>, headers: &Bound<'_, PyAny>) -> PyResult<()> {
        let val = py_to_json(py, headers)?;
        if let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
            (&mut self.headers, val)
        {
            for (k, v) in src {
                dst.entry(k).or_insert(v);
            }
        }
        Ok(())
    }

    /// Merge payload claims. Later calls overwrite earlier values for the same key.
    ///
    /// :param claims: JSON-serializable ``dict``.
    pub fn with_claims(&mut self, py: Python<'_>, claims: &Bound<'_, PyAny>) -> PyResult<()> {
        let val = py_to_json(py, claims)?;
        if let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
            (&mut self.claims, val)
        {
            for (k, v) in src {
                dst.insert(k, v);
            }
        }
        Ok(())
    }

    /// Sign the JWT with ``key`` and return ``header.payload.signature``.
    ///
    /// :param key: A private :class:`SecureEnclaveKey`.
    /// :raises AuthFailedError: If authentication fails.
    /// :raises UserCancelledError: If the user cancels the prompt.
    pub fn sign(&self, key: &PySecureEnclaveKey) -> PyResult<String> {
        RustJWT::new(&key.inner)
            .map_err(to_py_err)?
            .with_headers(self.headers.clone())
            .map_err(to_py_err)?
            .with_claims(self.claims.clone())
            .map_err(to_py_err)?
            .sign()
            .map_err(to_py_err)
    }

    /// Verify the ES256 signature of ``token``. Raises on failure.
    ///
    /// Does **not** validate claims (``exp``, ``iss``, ``aud``).
    ///
    /// :param key: Public or private :class:`SecureEnclaveKey`.
    /// :param token: Compact JWT string.
    /// :raises SecureEnclaveError: If the signature is invalid or malformed.
    pub fn verify(&self, key: &PySecureEnclaveKey, token: &str) -> PyResult<()> {
        RustJWT::new(&key.inner)
            .map_err(to_py_err)?
            .verify(token)
            .map_err(to_py_err)
    }

    /// Verify ``token`` and decode its header and payload.
    ///
    /// :returns: ``(headers_dict, claims_dict)`` tuple.
    /// :raises SecureEnclaveError: If the signature is invalid or malformed.
    pub fn verify_and_decode<'py>(
        &self,
        py: Python<'py>,
        key: &PySecureEnclaveKey,
        token: &str,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyAny>)> {
        let (headers, claims) = RustJWT::new(&key.inner)
            .map_err(to_py_err)?
            .verify_and_get_payload(token)
            .map_err(to_py_err)?;
        Ok((json_to_py(py, &headers)?, json_to_py(py, &claims)?))
    }

    fn __repr__(&self) -> String {
        format!(
            "SecureEnclaveJWT(headers={}, claims={})",
            self.headers, self.claims
        )
    }
}