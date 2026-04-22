use pyo3::{prelude::*, types::PyBytes};
use secure_enclave_rs::{
    derive_shared_secret, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions,
};

use crate::error::to_py_err;

/// Bitflag controlling how a Secure Enclave key is protected.
///
/// Combine with ``|``::
///
///     flags = AccessControlFlags.BIOMETRY_ANY | AccessControlFlags.DEVICE_PASSCODE
///
/// ``PRIVATE_KEY_USAGE`` is always included automatically by
/// :meth:`SecureEnclaveKey.generate`.
#[pyclass(name = "AccessControlFlags")]
pub struct PyAccessControlFlags {
    pub(crate) bits: u64,
}

#[pymethods]
#[allow(non_snake_case)]
impl PyAccessControlFlags {
    #[new]
    pub fn new(bits: u64) -> Self {
        Self { bits }
    }

    fn __or__(&self, other: &Self) -> Self {
        Self { bits: self.bits | other.bits }
    }

    fn __ror__(&self, other: &Self) -> Self {
        Self { bits: self.bits | other.bits }
    }

    fn __and__(&self, other: &Self) -> Self {
        Self { bits: self.bits & other.bits }
    }

    fn __int__(&self) -> u64 {
        self.bits
    }

    fn __repr__(&self) -> String {
        format!("AccessControlFlags({:#034b})", self.bits)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.bits == other.bits
    }

    /// No additional authentication beyond device unlock.
    #[classattr]
    fn EMPTY() -> Self { Self { bits: 0 } }

    /// Biometry (any enrolled finger / face) or device passcode.
    #[classattr]
    fn USER_PRESENCE() -> Self { Self { bits: 1 << 0 } }

    /// Any enrolled Touch ID finger or Face ID. Survives enrolment changes.
    #[classattr]
    fn BIOMETRY_ANY() -> Self { Self { bits: 1 << 1 } }

    /// Biometry tied to the current enrolment set. Key becomes inaccessible if
    /// biometrics are re-enrolled.
    #[classattr]
    fn BIOMETRY_CURRENT_SET() -> Self { Self { bits: 1 << 3 } }

    /// Device passcode required.
    #[classattr]
    fn DEVICE_PASSCODE() -> Self { Self { bits: 1 << 4 } }

    /// Paired Apple Watch (deprecated by Apple).
    #[classattr]
    fn WATCH() -> Self { Self { bits: 1 << 5 } }

    /// Any *one* of the combined requirements must be satisfied.
    #[classattr]
    fn OR() -> Self { Self { bits: 1 << 14 } }

    /// *All* combined requirements must be satisfied.
    #[classattr]
    fn AND() -> Self { Self { bits: 1 << 15 } }

    /// Restricts key usage to private-key operations (always added automatically).
    #[classattr]
    fn PRIVATE_KEY_USAGE() -> Self { Self { bits: 1 << 30 } }

    /// Enables an app-supplied password as a second factor.
    #[classattr]
    fn APPLICATION_PASSWORD() -> Self { Self { bits: 1 << 31 } }
}

impl PyAccessControlFlags {
    pub fn to_flags(&self) -> SecAccessControlFlags {
        SecAccessControlFlags::from_bits_truncate(self.bits)
    }
}

/// A handle to a Secure Enclave key.
///
/// For SE-backed private keys the key material never leaves the hardware.
/// All cryptographic operations are performed inside the Secure Enclave.
///
/// .. warning::
///    ``SecureEnclaveKey`` is not thread-safe and must only be used from the
///    thread on which it was created.
#[pyclass(unsendable, name = "SecureEnclaveKey")]
pub struct PySecureEnclaveKey {
    pub(crate) inner: SecureEnclaveKey,
}

#[pymethods]
impl PySecureEnclaveKey {
    /// Generate a new Secure Enclave–backed P-256 key pair.
    ///
    /// :param tag: Unique byte tag used to retrieve the key later.
    /// :param access_flags: Protection policy. Use :class:`AccessControlFlags`
    ///     to require biometry or a passcode. ``PRIVATE_KEY_USAGE`` is always
    ///     included automatically.
    /// :param permanent: Persist the key in the keychain (default ``True``).
    #[staticmethod]
    #[pyo3(signature = (tag, access_flags=None, permanent=true))]
    pub fn generate(
        tag: &[u8],
        access_flags: Option<&PyAccessControlFlags>,
        permanent: bool,
    ) -> PyResult<Self> {
        let flags = access_flags
            .map(|f| f.to_flags())
            .unwrap_or(SecAccessControlFlags::empty());
        SecureEnclaveKey::generate(&SecureEnclaveKeyOptions { tag, access_flags: flags, permanent })
            .map(|k| Self { inner: k })
            .map_err(to_py_err)
    }

    /// Retrieve an existing SE private key from the keychain.
    ///
    /// :param tag: The tag used when the key was generated.
    /// :raises KeyNotFoundError: If no matching key exists.
    #[staticmethod]
    pub fn get(tag: &[u8]) -> PyResult<Self> {
        SecureEnclaveKey::get(tag)
            .map(|k| Self { inner: k })
            .map_err(to_py_err)
    }

    /// Delete the keychain entry for the key with the given ``tag`` without
    /// needing an existing handle. Useful for cleanup at startup.
    ///
    /// :raises KeyNotFoundError: If no matching entry exists.
    #[staticmethod]
    pub fn remove_by_tag(tag: &[u8]) -> PyResult<()> {
        SecureEnclaveKey::remove_by_tag(tag).map_err(to_py_err)
    }

    /// Reconstruct a public key handle from raw X9.62 uncompressed bytes
    /// (``04 || X || Y``, 65 bytes for P-256).
    ///
    /// :raises SecureEnclaveError: If the bytes are not a valid P-256 point.
    #[staticmethod]
    pub fn from_public_key_bytes(bytes: &[u8]) -> PyResult<Self> {
        SecureEnclaveKey::from_public_key_bytes(bytes)
            .map(|k| Self { inner: k })
            .map_err(to_py_err)
    }

    /// Delete the keychain entry for this key.
    ///
    /// :raises KeyNotFoundError: If the entry no longer exists.
    pub fn remove(&self) -> PyResult<()> {
        self.inner.remove().map_err(to_py_err)
    }

    /// Return the public-key counterpart of this private key.
    ///
    /// :raises SecureEnclaveError: If called on a public key handle.
    pub fn public_key(&self) -> PyResult<Self> {
        self.inner.public_key()
            .map(|k| Self { inner: k })
            .map_err(to_py_err)
    }

    /// Export the public key as 65-byte X9.62 uncompressed bytes
    /// (``04 || X || Y``). Share these with a server during enrollment.
    pub fn public_key_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.public_key_bytes().map_err(to_py_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Sign ``data`` with ECDSA-SHA256 using this private key.
    ///
    /// :returns: DER-encoded ECDSA signature bytes.
    /// :raises AuthFailedError: If authentication fails.
    /// :raises UserCancelledError: If the user dismisses the prompt.
    pub fn sign<'py>(&self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.inner.sign(data).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &sig))
    }

    /// Verify a DER-encoded ECDSA-SHA256 ``signature`` over ``data``.
    ///
    /// :returns: ``True`` if valid, ``False`` otherwise.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> PyResult<bool> {
        self.inner.verify(data, signature).map_err(to_py_err)
    }

    /// Encrypt ``plaintext`` using ECIES (X9.63/SHA-256/AES-GCM, random IV).
    ///
    /// Accepts both private and public key handles.
    pub fn encrypt<'py>(&self, py: Python<'py>, plaintext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let ct = self.inner.encrypt(plaintext).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &ct))
    }

    /// Decrypt an ECIES ``ciphertext`` produced by :meth:`encrypt`.
    ///
    /// :raises AuthFailedError: If the key requires authentication and it fails.
    pub fn decrypt<'py>(&self, py: Python<'py>, ciphertext: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let pt = self.inner.decrypt(ciphertext).map_err(to_py_err)?;
        Ok(PyBytes::new(py, &pt))
    }

    /// Perform ECDH key exchange with a peer and return ``output_len`` bytes of
    /// derived key material (X9.63 KDF with SHA-256).
    ///
    /// :param peer_public_key_bytes: Peer's 65-byte X9.62 uncompressed public key.
    /// :param output_len: Output size in bytes (default ``32`` = AES-256 key).
    /// :param shared_info: Optional context for domain separation.
    #[pyo3(signature = (peer_public_key_bytes, output_len=32, shared_info=None))]
    pub fn derive_shared_secret<'py>(
        &self,
        py: Python<'py>,
        peer_public_key_bytes: &[u8],
        output_len: usize,
        shared_info: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let secret = derive_shared_secret(
            &self.inner,
            peer_public_key_bytes,
            output_len,
            shared_info.unwrap_or(&[]),
        )
        .map_err(to_py_err)?;
        Ok(PyBytes::new(py, &secret))
    }

    /// Trigger biometric or passcode authentication.
    ///
    /// :raises AuthFailedError: If authentication fails.
    /// :raises UserCancelledError: If the user cancels.
    pub fn authenticate(&self) -> PyResult<()> {
        self.inner.authenticate().map_err(to_py_err)
    }

    fn __repr__(&self) -> &'static str {
        "SecureEnclaveKey(<SE-backed P-256 key>)"
    }
}