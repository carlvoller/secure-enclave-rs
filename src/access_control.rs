pub(crate) use crate::security::types::{
    SecAccessControlCreateFlags, kSecAccessControlAnd, kSecAccessControlApplicationPassword,
    kSecAccessControlBiometryAny, kSecAccessControlBiometryCurrentSet,
    kSecAccessControlDevicePasscode, kSecAccessControlOr, kSecAccessControlPrivateKeyUsage,
    kSecAccessControlUserPresence, kSecAccessControlWatch,
};
use bitflags::bitflags;

bitflags! {

    /// Specify the access control parameters for your key.
    ///
    /// Use this enum to describe how you want to secure your key.
    /// For example, to require the user supply either their passcode or their current set of biometry, use:
    /// ```rust
    /// let access_controls = SecAccessControl::BIOMETRY_CURRENT_SET | SecAccessControl::AND | SecAccessControl::DEVICE_PASSCODE;
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SecAccessControlFlags: SecAccessControlCreateFlags {
        /// Requires biometric or the device's passcode to access the key
        const USER_PRESENCE        = kSecAccessControlUserPresence;

        /// Require TouchID (including all enrolled fingers) or FaceID.
        /// This key will still be accessible if more fingers are enrolled or removed from the device (TouchID) or if FaceID is re-enrolled
        const BIOMETRY_ANY         = kSecAccessControlBiometryAny;

        /// Require TouchID (including all enrolled fingers) or FaceID.
        /// This key is only accessible using the currently available TouchID fingers or FaceID settings.
        /// If TouchID or FaceID is changed, this key becomes inaccessible
        const BIOMETRY_CURRENT_SET = kSecAccessControlBiometryCurrentSet;

        /// Requires the use of the device's passcode in order to access this key.
        const DEVICE_PASSCODE      = kSecAccessControlDevicePasscode;

        /// Requires an Apple Watch paired nearby in order to access the key.
        /// This is currently deprecated here:
        /// https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/watch?language=objc
        const WATCH                = kSecAccessControlWatch;

        /// When combined with other flags, any **one** of the requirements must
        /// be satisfied (logical OR). Combine with [`AND`](Self::AND) to build
        /// compound policies, e.g. `BIOMETRY_ANY | OR | DEVICE_PASSCODE`.
        const OR                   = kSecAccessControlOr;

        /// When combined with other flags, **all** requirements must be
        /// satisfied (logical AND).
        const AND                  = kSecAccessControlAnd;

        /// Indicates that the key will be stored in Secure Enclave. This field is autoset in this library.
        const PRIVATE_KEY_USAGE    = kSecAccessControlPrivateKeyUsage;

        /// Enables the use of an application supplied password to generate DEKs
        const APPLICATION_PASSWORD = kSecAccessControlApplicationPassword;
    }
}
