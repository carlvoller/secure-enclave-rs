use crate::cf::{self, OwnedData};
use crate::error::{Error, OsStatus, Result, ERR_SEC_VERIFY_FAILED};
use crate::key_management::SecureEnclaveKey;
use crate::security::{self, types::*};

impl SecureEnclaveKey {
    /// Sign `data` using ECDSA-SHA256.
    /// 
    /// This method expects the key to be a private key.
    ///
    /// For keys with biometric or passcode access control the OS will present the
    /// authentication prompt automatically before performing the signing operation.
    ///
    /// This uses ECDSA over P-256 with SHA-256 hashing performed by the
    /// Security framework (`kSecKeyAlgorithmECDSASignatureMessageX962SHA256`).
    /// Please pass the raw message and not a hashed message.
    ///
    /// Returns the DER-encoded signature.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.is_public_key {
            return Err(Error::InvalidInput(
                "this key is a public key. expected a private key for signing",
            ));
        }

        let data_ref = OwnedData::new(data);
        let mut err: CFErrorRef = std::ptr::null_mut();

        let sig_ref = unsafe {
            security::SecKeyCreateSignature(
                self.raw(),
                security::kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                data_ref.as_raw(),
                &mut err,
            )
        };
        unsafe { cf::consume_cf_error(err) }?;
        if sig_ref.is_null() {
            return Err(Error::NullResult);
        }
        Ok(OwnedData::from_raw(sig_ref).to_vec())
    }

    /// Verify that `signature` over `data` is valid.
    ///
    /// If the SecureEnclaveKey is a private key, the public key pair is used from `SecureEnclaveKey::public_key()`
    ///
    /// `signature` must be in X9.62 DER-encoded format as produced by [`sign`].
    ///
    /// Returns `Ok(true)` for a valid signature, `Ok(false)` for an invalid one,
    /// or `Err` if the framework itself encountered an error (malformed input, etc.).
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let key = if self.is_public_key {
            self
        } else {
            &self.public_key()?
        };

        let data_ref = OwnedData::new(data);
        let sig_ref = OwnedData::new(signature);
        let mut err: CFErrorRef = std::ptr::null_mut();

        let ok = unsafe {
            security::SecKeyVerifySignature(
                key.raw(),
                security::kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                data_ref.as_raw(),
                sig_ref.as_raw(),
                &mut err,
            )
        };

        // SecKeyVerifySignature signals a cryptographically invalid signature
        // by setting err to errSecVerifyFailed; only framework-level problems
        // should propagate as Err. Inline the error handling so we can peek
        // at the code before consuming the CFError.
        if !err.is_null() {
            let code = unsafe { security::CFErrorGetCode(err) as OsStatus };
            unsafe { security::CFRelease(err as CFTypeRef) };
            if code == ERR_SEC_VERIFY_FAILED {
                return Ok(false);
            }
            return Err(Error::Os(code));
        }

        Ok(ok != 0)
    }
}
