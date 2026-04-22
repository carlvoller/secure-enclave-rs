use std::fmt;

pub type OsStatus = i32;

pub const ERR_SEC_ITEM_NOT_FOUND: OsStatus = -25300;
pub const ERR_SEC_AUTH_FAILED: OsStatus = -25293;
pub const ERR_SEC_USER_CANCELED: OsStatus = -128;
pub const ERR_SEC_VERIFY_FAILED: OsStatus = -67808;

#[derive(Debug)]
pub enum Error {
    /// Non-zero `OSStatus` returned by the Security framework.
    Os(OsStatus),
    /// A Security/CF function returned a null pointer without populating the error out-param.
    NullResult,
    /// No matching keychain item was found (`errSecItemNotFound`).
    NotFound,
    /// Caller provided invalid input.
    InvalidInput(&'static str),
    /// The user cancelled the request.
    UserCancelled,
    /// The user failed to successfully authenticate. Possibly due to incorrect biometrics, or incorrect passcodes.
    AuthFailed,

    /// The JWT claims are malformed or invalid
    #[cfg(feature = "jwt")]
    InvalidJWTClaims,

    /// The JWT signature does not match.
    #[cfg(feature = "jwt")]
    InvalidJWTSignature,
}

impl Error {
    /// Return the underlying `OSStatus` code if this is an `Os` variant.
    pub fn os_status(&self) -> Option<OsStatus> {
        if let Error::Os(s) = self {
            Some(*s)
        } else {
            None
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Os(s) => write!(f, "Security framework error (OSStatus {})", s),
            Error::NullResult => write!(f, "unexpected null from Security framework"),
            Error::NotFound => write!(f, "no matching keychain item found"),
            Error::UserCancelled => write!(f, "user cancelled the request"),
            Error::AuthFailed => write!(f, "user failed to authenticate"),
            Error::InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            
            #[cfg(feature = "jwt")]
            Error::InvalidJWTClaims => write!(f, "invalid jwt claims supplied"),
            #[cfg(feature = "jwt")]
            Error::InvalidJWTSignature => write!(f, "jwt has an invalid signature"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
