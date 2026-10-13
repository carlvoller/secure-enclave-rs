use objc2_core_foundation::{CFDictionary, CFError, CFRetained, CFString, CFType};
use objc2_security::{errSecAuthFailed, errSecItemNotFound, errSecSuccess, errSecUserCanceled};

use crate::error::{Error, OsStatus, Result};

/// Build a `CFDictionary` from (key, value) pairs.
///
/// The dictionary retains every key and value, so the source objects may be
/// dropped after this call.
pub(crate) fn dict(pairs: &[(&CFString, &CFType)]) -> CFRetained<CFDictionary<CFString, CFType>> {
    let keys: Vec<&CFString> = pairs.iter().map(|p| p.0).collect();
    let vals: Vec<&CFType> = pairs.iter().map(|p| p.1).collect();
    CFDictionary::from_slices(&keys, &vals)
}

/// Take ownership of a `CFError` produced by a Security framework call.
///
/// Returns `None` if `err` is null.
///
/// # Safety
/// `err` must be either null or a valid, owned (+1) `CFError`.
pub(crate) unsafe fn take_cf_error(err: *mut CFError) -> Option<CFRetained<CFError>> {
    std::ptr::NonNull::new(err).map(|err| unsafe { CFRetained::from_raw(err) })
}

/// Consume a `CFError` produced by a Security framework call.
///
/// If `err` is non-null the error code is extracted, the CF object is released,
/// and `Err` is returned. If `err` is null, `Ok(())` is returned.
///
/// # Safety
/// `err` must be either null or a valid, owned (+1) `CFError`.
pub(crate) unsafe fn consume_cf_error(err: *mut CFError) -> Result<()> {
    match unsafe { take_cf_error(err) } {
        Some(err) => Err(Error::Os(err.code() as OsStatus)),
        None => Ok(()),
    }
}

/// Map an `OSStatus` to a `Result`.
pub(crate) fn check_os_status(status: OsStatus) -> Result<()> {
    match status {
        errSecSuccess => Ok(()),
        errSecAuthFailed => Err(Error::AuthFailed),
        errSecUserCanceled => Err(Error::UserCancelled),
        errSecItemNotFound => Err(Error::NotFound),
        s => Err(Error::Os(s)),
    }
}
