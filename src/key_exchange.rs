use objc2_core_foundation::{CFData, CFError, CFNumber};
use objc2_security::{
    kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256, kSecKeyKeyExchangeParameterRequestedSize,
    kSecKeyKeyExchangeParameterSharedInfo,
};

use crate::cf;
use crate::error::{Error, Result};
use crate::key_management::{self, SecureEnclaveKey};

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
    let requested_size = CFNumber::new_i32(output_len as i32);

    let params = if shared_info.is_empty() {
        cf::dict(&[(
            unsafe { kSecKeyKeyExchangeParameterRequestedSize },
            &requested_size,
        )])
    } else {
        let info_data = CFData::from_bytes(shared_info);
        cf::dict(&[
            (
                unsafe { kSecKeyKeyExchangeParameterRequestedSize },
                &requested_size,
            ),
            (unsafe { kSecKeyKeyExchangeParameterSharedInfo }, &info_data),
        ])
    };

    let mut err: *mut CFError = std::ptr::null_mut();
    let secret = unsafe {
        local_private_key.raw().key_exchange_result(
            kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256,
            peer_pub.raw(),
            params.as_opaque(),
            &mut err,
        )
    };
    unsafe { cf::consume_cf_error(err) }?;
    Ok(secret.ok_or(Error::NullResult)?.to_vec())
}
