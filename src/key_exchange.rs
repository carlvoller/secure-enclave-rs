use std::os::raw::c_void;

use crate::cf::{self, OwnedData, OwnedDict, OwnedNumber};
use crate::error::{Error, Result};
use crate::key_management::{self, SecureEnclaveKey};
use crate::security::{self, types::*};

/// Derive a shared secret via ECDH between `local_private_key` and
/// `peer_public_key_bytes` (X9.62 uncompressed P-256 point, 65 bytes).
///
/// `output_len` controls how many bytes the X9.63 KDF produces.
/// 32 bytes is appropriate for use as an AES-256 key.
///
/// `shared_info` is optional additional data mixed into the KDF (analogous to
/// the "info" parameter in HKDF). Pass an empty slice if not needed.
pub fn derive_shared_secret(
    local_private_key: &SecureEnclaveKey,
    peer_public_key_bytes: &[u8],
    output_len: usize,
    shared_info: &[u8],
) -> Result<Vec<u8>> {
    if local_private_key.is_public_key {
        return Err(Error::InvalidInput(
            "derive_shared_secret takes a private key. public key was supplied.",
        ));
    }

    let peer_pub = key_management::public_key_from_bytes(peer_public_key_bytes)?;
    let requested_size = OwnedNumber::from_i32(output_len as i32);

    let params = if shared_info.is_empty() {
        unsafe {
            OwnedDict::new(&[(
                security::kSecKeyKeyExchangeParameterRequestedSize as *const c_void,
                requested_size.as_raw() as *const c_void,
            )])
        }
    } else {
        let info_data = OwnedData::new(shared_info);
        unsafe {
            OwnedDict::new(&[
                (
                    security::kSecKeyKeyExchangeParameterRequestedSize as *const c_void,
                    requested_size.as_raw() as *const c_void,
                ),
                (
                    security::kSecKeyKeyExchangeParameterSharedInfo as *const c_void,
                    info_data.as_raw() as *const c_void,
                ),
            ])
        }
    };

    let mut err: CFErrorRef = std::ptr::null_mut();
    let secret_ref = unsafe {
        security::SecKeyCopyKeyExchangeResult(
            local_private_key.raw(),
            security::kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
            peer_pub.raw(),
            params.as_raw(),
            &mut err,
        )
    };
    unsafe { cf::consume_cf_error(err) }?;
    if secret_ref.is_null() {
        return Err(Error::NullResult);
    }
    Ok(OwnedData::from_raw(secret_ref).to_vec())
}
