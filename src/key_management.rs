use std::os::raw::c_void;

use crate::access_control::SecAccessControlFlags;
use crate::cf::{self, OwnedData, OwnedDict, OwnedNumber};
use crate::error::{Error, Result};
use crate::security::{self, types::*};

/// A handle to a Secure Enclave key.
///
/// Adops a Secure Enclave Key reference.
/// When dropped, CFRelease is called on the reference to free memory
///
/// Obtain a handle via [`SecureEnclaveKey::generate`] (new key) or
/// [`SecureEnclaveKey::get`] (existing keychain entry). Reconstruct a public
/// key from raw bytes with [`SecureEnclaveKey::from_public_key_bytes`].
pub struct SecureEnclaveKey {
    tag: Vec<u8>, // Owned copy of the key tag

    pub(crate) key_ref: SecKeyRef,
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

impl Drop for SecureEnclaveKey {
    fn drop(&mut self) {
        if !self.key_ref.is_null() {
            unsafe { security::CFRelease(self.key_ref as CFTypeRef) }
        }
    }
}

impl SecureEnclaveKey {
    pub(crate) fn raw(&self) -> SecKeyRef {
        self.key_ref
    }

    /// Return the public-key counterpart of this key.
    /// For an Secure Enclave private key this extracts the public half of the key.
    pub fn public_key(&self) -> Result<SecureEnclaveKey> {
        if self.is_public_key {
            return Err(Error::InvalidInput(
                "can't get a public key of a public key",
            ));
        }

        let ptr = unsafe { security::SecKeyCopyPublicKey(self.key_ref) };
        if ptr.is_null() {
            return Err(Error::NullResult);
        }
        Ok(SecureEnclaveKey {
            key_ref: ptr,
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
        let tag = OwnedData::new(opts.tag);
        let key_size = OwnedNumber::from_i32(256);

        // Inner dict: private key attributes (tag, permanence, access control).
        let private_attrs = unsafe {
            OwnedDict::new(&[
                (
                    security::kSecAttrIsPermanent as *const c_void,
                    if opts.permanent {
                        security::kCFBooleanTrue as *const c_void
                    } else {
                        security::kCFBooleanFalse as *const c_void
                    },
                ),
                (
                    security::kSecAttrApplicationTag as *const c_void,
                    tag.as_raw() as *const c_void,
                ),
                (
                    security::kSecAttrAccessControl as *const c_void,
                    acl.0 as *const c_void,
                ),
            ])
        };

        // Outer dict: key type, size, token (SE), and the private key sub-dict.
        let params = unsafe {
            OwnedDict::new(&[
                (
                    security::kSecAttrKeyType as *const c_void,
                    security::kSecAttrKeyTypeECSECPrimeRandom as *const c_void,
                ),
                (
                    security::kSecAttrKeySizeInBits as *const c_void,
                    key_size.as_raw() as *const c_void,
                ),
                (
                    security::kSecAttrTokenID as *const c_void,
                    security::kSecAttrTokenIDSecureEnclave as *const c_void,
                ),
                (
                    security::kSecPrivateKeyAttrs as *const c_void,
                    private_attrs.as_raw() as *const c_void,
                ),
            ])
        };

        let mut err: CFErrorRef = std::ptr::null_mut();
        let key_ref = unsafe { security::SecKeyCreateRandomKey(params.as_raw(), &mut err) };
        unsafe { cf::consume_cf_error(err) }?;
        if key_ref.is_null() {
            return Err(Error::NullResult);
        }
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
        let tag_data = OwnedData::new(tag);

        let query = unsafe {
            OwnedDict::new(&[
                (
                    security::kSecClass as *const c_void,
                    security::kSecClassKey as *const c_void,
                ),
                (
                    security::kSecAttrKeyType as *const c_void,
                    security::kSecAttrKeyTypeECSECPrimeRandom as *const c_void,
                ),
                (
                    security::kSecAttrApplicationTag as *const c_void,
                    tag_data.as_raw() as *const c_void,
                ),
                (
                    security::kSecReturnRef as *const c_void,
                    security::kCFBooleanTrue as *const c_void,
                ),
                (
                    security::kSecMatchLimit as *const c_void,
                    security::kSecMatchLimitOne as *const c_void,
                ),
            ])
        };

        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { security::SecItemCopyMatching(query.as_raw(), &mut result) };
        cf::check_os_status(status)?;
        if result.is_null() {
            return Err(Error::NullResult);
        }
        // SecItemCopyMatching with kSecReturnRef gives us a CoreFoundation reference i'm responsible for.
        Ok(Self {
            key_ref: result as SecKeyRef,
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
        let tag_data = OwnedData::new(tag);

        let query = unsafe {
            OwnedDict::new(&[
                (
                    security::kSecClass as *const c_void,
                    security::kSecClassKey as *const c_void,
                ),
                (
                    security::kSecAttrKeyType as *const c_void,
                    security::kSecAttrKeyTypeECSECPrimeRandom as *const c_void,
                ),
                (
                    security::kSecAttrApplicationTag as *const c_void,
                    tag_data.as_raw() as *const c_void,
                ),
            ])
        };

        let status = unsafe { security::SecItemDelete(query.as_raw()) };
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

        let mut err: CFErrorRef = std::ptr::null_mut();
        let data_ref =
            unsafe { security::SecKeyCopyExternalRepresentation(pub_key.raw(), &mut err) };
        unsafe { cf::consume_cf_error(err) }?;
        if data_ref.is_null() {
            return Err(Error::NullResult);
        }
        Ok(OwnedData::from_raw(data_ref).to_vec())
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

pub(crate) struct SecAccessControl(pub(crate) SecAccessControlRef);

impl Drop for SecAccessControl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { security::CFRelease(self.0 as CFTypeRef) }
        }
    }
}

pub(crate) fn create_access_control(flags: SecAccessControlFlags) -> Result<SecAccessControl> {
    let mut err: CFErrorRef = std::ptr::null_mut();
    let acl = unsafe {
        security::SecAccessControlCreateWithFlags(
            security::kCFAllocatorDefault,
            security::kSecAttrAccessibleWhenUnlockedThisDeviceOnly as CFTypeRef,
            (flags | SecAccessControlFlags::PRIVATE_KEY_USAGE).bits(),
            &mut err,
        )
    };
    unsafe { cf::consume_cf_error(err) }?;
    if acl.is_null() {
        return Err(Error::NullResult);
    }
    Ok(SecAccessControl(acl))
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> Result<SecureEnclaveKey> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(Error::InvalidInput(
            "expected 65-byte X9.62 uncompressed public key (04 || X || Y)",
        ));
    }

    let key_data = OwnedData::new(bytes);
    let key_size = OwnedNumber::from_i32(256);

    let attrs = unsafe {
        OwnedDict::new(&[
            (
                security::kSecAttrKeyType as *const c_void,
                security::kSecAttrKeyTypeECSECPrimeRandom as *const c_void,
            ),
            (
                security::kSecAttrKeyClass as *const c_void,
                security::kSecAttrKeyClassPublic as *const c_void,
            ),
            (
                security::kSecAttrKeySizeInBits as *const c_void,
                key_size.as_raw() as *const c_void,
            ),
        ])
    };

    let mut err: CFErrorRef = std::ptr::null_mut();
    let key_ref =
        unsafe { security::SecKeyCreateWithData(key_data.as_raw(), attrs.as_raw(), &mut err) };
    unsafe { cf::consume_cf_error(err) }?;
    if key_ref.is_null() {
        return Err(Error::NullResult);
    }
    Ok(SecureEnclaveKey {
        key_ref,
        tag: Vec::new(),
        is_public_key: true,
    })
}
