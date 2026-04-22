pub(crate) mod cf;
mod security;

pub(crate) mod access_control;
pub(crate) mod encryption;
pub(crate) mod error;
#[cfg(feature = "jwt")]
pub(crate) mod jwt;
pub(crate) mod key_exchange;
pub(crate) mod key_management;
pub(crate) mod signing;

pub use access_control::SecAccessControlFlags;
pub use error::{Error, Result};
pub use key_management::{SecureEnclaveKey, SecureEnclaveKeyOptions};
pub use key_exchange::derive_shared_secret;

#[cfg(feature = "jwt")]
pub use jwt::SecureEnclaveJWT;
