use bitflags::bitflags;
use objc2_security::SecAccessControlCreateFlags;

bitflags! {

    /// Specify the access control parameters for your key.
    ///
    /// Use this enum to describe how you want to secure your key.
    /// For example, to require the user supply either their passcode or their current set of biometry, use:
    /// ```rust
    /// use secure_enclave_rs::SecAccessControlFlags;
    ///
    /// let access_controls = SecAccessControlFlags::BIOMETRY_CURRENT_SET | SecAccessControlFlags::AND | SecAccessControlFlags::DEVICE_PASSCODE;
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecAccessControlFlags: u64 {
        /// Requires biometric or the device's passcode to access the key
        const USER_PRESENCE        = SecAccessControlCreateFlags::UserPresence.bits() as u64;

        /// Require TouchID (including all enrolled fingers) or FaceID.
        /// This key will still be accessible if more fingers are enrolled or removed from the device (TouchID) or if FaceID is re-enrolled
        const BIOMETRY_ANY         = SecAccessControlCreateFlags::BiometryAny.bits() as u64;

        /// Require TouchID (including all enrolled fingers) or FaceID.
        /// This key is only accessible using the currently available TouchID fingers or FaceID settings.
        /// If TouchID or FaceID is changed, this key becomes inaccessible
        const BIOMETRY_CURRENT_SET = SecAccessControlCreateFlags::BiometryCurrentSet.bits() as u64;

        /// Requires the use of the device's passcode in order to access this key.
        const DEVICE_PASSCODE      = SecAccessControlCreateFlags::DevicePasscode.bits() as u64;

        /// Requires an Apple Watch paired nearby in order to access the key.
        /// This is currently deprecated here:
        /// https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/watch?language=objc
        const WATCH                = SecAccessControlCreateFlags::Watch.bits() as u64;

        /// When combined with other flags, any **one** of the requirements must
        /// be satisfied (logical OR). Combine with [`AND`](Self::AND) to build
        /// compound policies, e.g. `BIOMETRY_ANY | OR | DEVICE_PASSCODE`.
        const OR                   = SecAccessControlCreateFlags::Or.bits() as u64;

        /// When combined with other flags, **all** requirements must be
        /// satisfied (logical AND).
        const AND                  = SecAccessControlCreateFlags::And.bits() as u64;

        /// Indicates that the key will be stored in Secure Enclave. This field is autoset in this library.
        const PRIVATE_KEY_USAGE    = SecAccessControlCreateFlags::PrivateKeyUsage.bits() as u64;

        /// Enables the use of an application supplied password to generate DEKs
        const APPLICATION_PASSWORD = SecAccessControlCreateFlags::ApplicationPassword.bits() as u64;
    }
}
