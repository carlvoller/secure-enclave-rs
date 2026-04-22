use crate::SecureEnclaveKey;
use crate::cf::{self, OwnedData};
use crate::error::{Error, Result};
use crate::security::{self, types::*};

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

        let plain_data = OwnedData::new(plaintext);
        let mut err: CFErrorRef = std::ptr::null_mut();

        let cipher_ref = unsafe {
            security::SecKeyCreateEncryptedData(
                key.raw(),
                security::kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                plain_data.as_raw(),
                &mut err,
            )
        };
        unsafe { cf::consume_cf_error(err) }?;
        if cipher_ref.is_null() {
            return Err(Error::NullResult);
        }
        Ok(OwnedData::from_raw(cipher_ref).to_vec())
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

        let cipher_data = OwnedData::new(ciphertext);
        let mut err: CFErrorRef = std::ptr::null_mut();

        let plain_ref = unsafe {
            security::SecKeyCreateDecryptedData(
                self.raw(),
                security::kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM,
                cipher_data.as_raw(),
                &mut err,
            )
        };
        unsafe { cf::consume_cf_error(err) }?;
        if plain_ref.is_null() {
            return Err(Error::NullResult);
        }
        Ok(OwnedData::from_raw(plain_ref).to_vec())
    }
}
