use crate::SecureEnclaveKey;
use objc2_core_foundation::{CFData, CFError};
use objc2_security::kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;

use crate::cf;
use crate::error::{Error, Result};

impl SecureEnclaveKey {
    /// Encrypt `plaintext`.
    ///
    /// If this key is a private key, it's public key pair will be used to encrypt `plaintext`.
    ///
    /// Returns the ECIES ciphertext blob, which includes the ephemeral public key,
    /// the AES-GCM ciphertext, and the authentication tag.
    ///
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = if self.is_public_key {
            self
        } else {
            &self.public_key()?
        };

        let plain_data = CFData::from_bytes(plaintext);
        let mut err: *mut CFError = std::ptr::null_mut();

        let cipher_data = unsafe {
            key.raw().encrypted_data(
                kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                &plain_data,
                &mut err,
            )
        };
        unsafe { cf::consume_cf_error(err) }?;
        Ok(cipher_data.ok_or(Error::NullResult)?.to_vec())
    }

    /// Decrypt `ciphertext`.
    ///
    /// This method expects this key to be a private key.
    ///
    /// If the key has biometric or passcode access control the OS will prompt for
    /// authentication before decrypting.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.is_public_key {
            return Err(Error::InvalidInput(
                "this key is a public key. expected a private key for decryption",
            ));
        }

        let cipher_data = CFData::from_bytes(ciphertext);
        let mut err: *mut CFError = std::ptr::null_mut();

        let plain_data = unsafe {
            self.raw().decrypted_data(
                kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                &cipher_data,
                &mut err,
            )
        };
        unsafe { cf::consume_cf_error(err) }?;
        Ok(plain_data.ok_or(Error::NullResult)?.to_vec())
    }
}
