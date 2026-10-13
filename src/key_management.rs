use std::ptr::NonNull;

use objc2_core_foundation::{
    CFBoolean, CFData, CFError, CFNumber, CFOptionFlags, CFRetained, CFType,
};
use objc2_security::{
    SecAccessControl, SecAccessControlCreateFlags, SecItemCopyMatching, SecItemDelete, SecKey,
    kSecAttrAccessControl, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAttrApplicationTag,
    kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeySizeInBits,
    kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID,
    kSecAttrTokenIDSecureEnclave, kSecClass, kSecClassKey, kSecMatchLimit, kSecMatchLimitOne,
    kSecPrivateKeyAttrs, kSecReturnRef,
};

use crate::access_control::SecAccessControlFlags;
use crate::cf;
use crate::error::{Error, Result};

/// A handle to a Secure Enclave key.
///
/// Adops a Secure Enclave Key reference.
/// When dropped, the reference is released to free memory
///
/// Obtain a handle via [`SecureEnclaveKey::generate`] (new key) or
/// [`SecureEnclaveKey::get`] (existing keychain entry). Reconstruct a public
/// key from raw bytes with [`SecureEnclaveKey::from_public_key_bytes`].
pub struct SecureEnclaveKey {
    tag: Vec<u8>, // Owned copy of the key tag

    pub(crate) key_ref: CFRetained<SecKey>,
    pub(crate) is_public_key: bool,
}

/// Options controlling how a Secure Enclave key pair is generated.
pub struct SecureEnclaveKeyOptions<'a> {
    /// Binary tag used to retrieve the key from the keychain.
    /// Must be unique per key within your app.
    pub tag: &'a [u8],
    /// Access control flags. See `access_control::SecAccessControlFlags`
    pub access_flags: SecAccessControlFlags,
    /// Whether to store the private key handle in the keychain permanently.
    /// Set to `false` only for ephemeral keys used within a single session.
    pub permanent: bool,
}

// TODO: I'm not sure if the Security Framework is thread safe.
// This is the only documentation I could find and it implies it _might_ be, but not always on macOS:
// https://developer.apple.com/documentation/security/working-with-concurrency?language=objc
// unsafe impl Send for SecuredEnclaveKey {}
// unsafe impl Sync for SecuredEnclaveKey {}

impl SecureEnclaveKey {
    pub(crate) fn raw(&self) -> &SecKey {
        &self.key_ref
    }

    /// Return the public-key counterpart of this key.
    /// For an Secure Enclave private key this extracts the public half of the key.
    pub fn public_key(&self) -> Result<SecureEnclaveKey> {
        if self.is_public_key {
            return Err(Error::InvalidInput(
                "can't get a public key of a public key",
            ));
        }

        let key_ref = unsafe { self.key_ref.public_key() }.ok_or(Error::NullResult)?;
        Ok(SecureEnclaveKey {
            key_ref,
            tag: self.tag.clone(),
            is_public_key: true,
        })
    }

    /// Generate a Secure Enclave–backed P-256 key pair and optionally persist
    /// the private key handle in the keychain.
    ///
    /// Returns the private key handle. Use [`SecureEnclaveKey::public_key`] to
    /// obtain the public half, or [`SecureEnclaveKey::public_key_bytes`] to
    /// export it as bytes for server registration.
    pub fn generate(opts: &SecureEnclaveKeyOptions) -> Result<Self> {
        let acl = create_access_control(opts.access_flags)?;
        let tag = CFData::from_bytes(opts.tag);
        let key_size = CFNumber::new_i32(256);

        // Inner dict: private key attributes (tag, permanence, access control).
        let private_attrs = unsafe {
            cf::dict(&[
                (kSecAttrIsPermanent, CFBoolean::new(opts.permanent)),
                (kSecAttrApplicationTag, &tag),
                (kSecAttrAccessControl, &acl),
            ])
        };

        // Outer dict: key type, size, token (SE), and the private key sub-dict.
        let params = unsafe {
            cf::dict(&[
                (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                (kSecAttrKeySizeInBits, &key_size),
                (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave),
                (kSecPrivateKeyAttrs, private_attrs.as_opaque()),
            ])
        };

        let mut err: *mut CFError = std::ptr::null_mut();
        let key_ref = unsafe { SecKey::new_random_key(params.as_opaque(), &mut err) };
        unsafe { cf::consume_cf_error(err) }?;
        let key_ref = key_ref.ok_or(Error::NullResult)?;
        Ok(Self {
            key_ref,
            tag: opts.tag.to_vec(),
            is_public_key: false,
        })
    }

    /// Retrieve a previously stored Secure Enclave private key from the keychain by its `tag`.
    ///
    /// Returns `Error::NotFound` if no matching key exists.
    pub fn get(tag: &[u8]) -> Result<Self> {
        let tag_data = CFData::from_bytes(tag);

        let query = unsafe {
            cf::dict(&[
                (kSecClass, kSecClassKey),
                (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                (kSecAttrApplicationTag, &tag_data),
                (kSecReturnRef, CFBoolean::new(true)),
                (kSecMatchLimit, kSecMatchLimitOne),
            ])
        };

        let mut result: *const CFType = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_opaque(), &mut result) };
        cf::check_os_status(status)?;
        let result = NonNull::new(result.cast_mut()).ok_or(Error::NullResult)?;
        // SecItemCopyMatching with kSecReturnRef gives us a CoreFoundation reference i'm responsible for.
        let key_ref = unsafe { CFRetained::from_raw(result) }
            .downcast::<SecKey>()
            .map_err(|_| Error::NullResult)?;
        Ok(Self {
            key_ref,
            tag: tag.to_vec(),
            is_public_key: false,
        })
    }

    /// Delete the keychain entry for this key.
    ///
    /// Returns [`Error::NotFound`] if the entry no longer exists.
    pub fn remove(&self) -> Result<()> {
        Self::remove_by_tag(&self.tag)
    }

    /// Delete the keychain entry for the key with the given `tag` without
    /// needing an existing handle. Useful for cleanup at startup.
    ///
    /// Returns [`Error::NotFound`] if no matching entry exists.
    pub fn remove_by_tag(tag: &[u8]) -> Result<()> {
        let tag_data = CFData::from_bytes(tag);

        let query = unsafe {
            cf::dict(&[
                (kSecClass, kSecClassKey),
                (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
                (kSecAttrApplicationTag, &tag_data),
            ])
        };

        let status = unsafe { SecItemDelete(query.as_opaque()) };
        cf::check_os_status(status)
    }

    /// Export the public key as 65-byte X9.62 uncompressed point data
    /// (`04 || X || Y`). Share these bytes with a server during enrollment.
    ///
    /// Works on both private and public key handles.
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let pub_key = if self.is_public_key {
            self
        } else {
            &self.public_key()?
        };

        let mut err: *mut CFError = std::ptr::null_mut();
        let data_ref = unsafe { pub_key.raw().external_representation(&mut err) };
        unsafe { cf::consume_cf_error(err) }?;
        Ok(data_ref.ok_or(Error::NullResult)?.to_vec())
    }

    /// Trigger biometric or passcode authentication by signing an internal
    /// challenge with this key. The OS presents Face ID / Touch ID or the
    /// passcode prompt automatically.
    ///
    /// Returns `Ok(())` if the user authenticates. Use [`Error::is_auth_failed`]
    /// and [`Error::is_user_cancelled`] to distinguish failure modes.
    ///
    /// For server-verified flows use [`SecureEnclaveKey::sign`] with a
    /// server-provided nonce instead.
    pub fn authenticate(&self) -> Result<()> {
        self.sign(b"se-local-auth-challenge")?;
        Ok(())
    }

    /// Reconstruct a public key handle from raw X9.62 uncompressed bytes
    /// (`04 || X || Y`, 65 bytes for P-256).
    ///
    /// Use this on the server side to verify a client signature, or to perform
    /// ECDH with a peer's public key without having a keychain handle.
    pub fn from_public_key_bytes(bytes: &[u8]) -> Result<SecureEnclaveKey> {
        public_key_from_bytes(bytes)
    }
}

pub(crate) fn create_access_control(
    flags: SecAccessControlFlags,
) -> Result<CFRetained<SecAccessControl>> {
    let flags = SecAccessControlCreateFlags::from_bits_retain(
        (flags | SecAccessControlFlags::PRIVATE_KEY_USAGE).bits() as CFOptionFlags,
    );
    let mut err: *mut CFError = std::ptr::null_mut();
    let acl = unsafe {
        SecAccessControl::with_flags(
            None,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &mut err,
        )
    };
    unsafe { cf::consume_cf_error(err) }?;
    acl.ok_or(Error::NullResult)
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> Result<SecureEnclaveKey> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::InvalidInput(
            "expected 65-byte X9.62 uncompressed public key (04 || X || Y)",
        ));
    }

    let key_data = CFData::from_bytes(bytes);
    let key_size = CFNumber::new_i32(256);

    let attrs = unsafe {
        cf::dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom),
            (kSecAttrKeyClass, kSecAttrKeyClassPublic),
            (kSecAttrKeySizeInBits, &key_size),
        ])
    };

    let mut err: *mut CFError = std::ptr::null_mut();
    let key_ref = unsafe { SecKey::with_data(&key_data, attrs.as_opaque(), &mut err) };
    unsafe { cf::consume_cf_error(err) }?;
    let key_ref = key_ref.ok_or(Error::NullResult)?;
    Ok(SecureEnclaveKey {
        key_ref,
        tag: Vec::new(),
        is_public_key: true,
    })
}
