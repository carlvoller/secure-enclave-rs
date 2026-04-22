use std::ffi::CString;
use std::os::raw::c_void;

use crate::error::{
    ERR_SEC_AUTH_FAILED, ERR_SEC_ITEM_NOT_FOUND, ERR_SEC_USER_CANCELED, Error, OsStatus, Result,
};
use crate::security::{self, types::*};

/// Internal wrapper for CoreFoundation objects and helper utilities.
///
/// Implements Drop on the CoreFoundation Object, which calls CFRelease to free memory.
pub(crate) struct OwnedData(pub(crate) CFDataRef);

impl OwnedData {
    /// Create a `CFData` containing a copy of `bytes`.
    pub(crate) fn new(bytes: &[u8]) -> Self {
        let ptr = unsafe {
            security::CFDataCreate(
                security::kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len() as CFIndex,
            )
        };
        Self(ptr)
    }

    /// Wraps the raw CoreFoundation pointer. Panics if `ptr` is null.
    pub(crate) fn from_raw(ptr: CFDataRef) -> Self {
        assert!(!ptr.is_null(), "OwnedData::from_raw called with null");
        Self(ptr)
    }

    pub(crate) fn as_raw(&self) -> CFDataRef {
        self.0
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe {
            let ptr = security::CFDataGetBytePtr(self.0);
            let len = security::CFDataGetLength(self.0) as usize;
            std::slice::from_raw_parts(ptr, len)
        }
    }

    pub(crate) fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl Drop for OwnedData {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { security::CFRelease(self.0 as CFTypeRef) }
        }
    }
}

// keeping this in case i need it in the future
#[allow(dead_code)]
pub(crate) struct OwnedString(pub(crate) CFStringRef);

#[allow(dead_code)]
impl OwnedString {
    /// Create a `CFString` from a Rust `&str` (UTF-8). Returns `None` if the
    /// string contains interior null bytes or if CF allocation fails.
    pub(crate) fn new(s: &str) -> Option<Self> {
        let c = CString::new(s).ok()?;
        let ptr = unsafe {
            security::CFStringCreateWithCString(
                security::kCFAllocatorDefault,
                c.as_ptr(),
                kCFStringEncodingUTF8,
            )
        };
        if ptr.is_null() { None } else { Some(Self(ptr)) }
    }

    pub(crate) fn as_raw(&self) -> CFStringRef {
        self.0
    }
}

impl Drop for OwnedString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { security::CFRelease(self.0 as CFTypeRef) }
        }
    }
}

pub(crate) struct OwnedNumber(pub(crate) CFNumberRef);

impl OwnedNumber {
    pub(crate) fn from_i32(v: i32) -> Self {
        let ptr = unsafe {
            security::CFNumberCreate(
                security::kCFAllocatorDefault,
                kCFNumberSInt32Type,
                &v as *const i32 as *const c_void,
            )
        };
        Self(ptr)
    }

    // keeping this in case i need it in the future
    #[allow(dead_code)]
    pub(crate) fn from_i64(v: i64) -> Self {
        let ptr = unsafe {
            security::CFNumberCreate(
                security::kCFAllocatorDefault,
                kCFNumberSInt64Type,
                &v as *const i64 as *const c_void,
            )
        };
        Self(ptr)
    }

    pub(crate) fn as_raw(&self) -> CFNumberRef {
        self.0
    }
}

impl Drop for OwnedNumber {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { security::CFRelease(self.0 as CFTypeRef) }
        }
    }
}

pub(crate) struct OwnedDict(pub(crate) CFDictionaryRef);

impl OwnedDict {
    /// Build a `CFDictionary` from raw (key, value) pairs of opaque CF pointers.
    ///
    /// `CFDictionaryCreate` with `kCFTypeDictionaryKeyCallBacks` retains every key
    /// and value, so all source `Owned*` objects may be dropped after this call.
    ///
    /// # Safety
    /// Every pointer in `pairs` must be a valid, live CF object of the correct type.
    pub(crate) unsafe fn new(pairs: &[(*const c_void, *const c_void)]) -> Self {
        let keys: Vec<*const c_void> = pairs.iter().map(|p| p.0).collect();
        let vals: Vec<*const c_void> = pairs.iter().map(|p| p.1).collect();
        let ptr = unsafe {
            security::CFDictionaryCreate(
                security::kCFAllocatorDefault,
                keys.as_ptr() as *const CFTypeRef,
                vals.as_ptr() as *const CFTypeRef,
                pairs.len() as CFIndex,
                &security::kCFTypeDictionaryKeyCallBacks,
                &security::kCFTypeDictionaryValueCallBacks,
            )
        };
        Self(ptr)
    }

    pub(crate) fn as_raw(&self) -> CFDictionaryRef {
        self.0
    }
}

impl Drop for OwnedDict {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { security::CFRelease(self.0 as CFTypeRef) }
        }
    }
}

/// Consume a `CFErrorRef` produced by a Security framework call.
///
/// If `err` is non-null the error code is extracted, the CF object is released,
/// and `Err` is returned. If `err` is null, `Ok(())` is returned.
///
/// # Safety
/// `err` must be either null or a valid `CFErrorRef`.
pub(crate) unsafe fn consume_cf_error(err: CFErrorRef) -> Result<()> {
    if err.is_null() {
        Ok(())
    } else {
        let code = unsafe { security::CFErrorGetCode(err) as OsStatus };
        unsafe { security::CFRelease(err as CFTypeRef) };
        Err(Error::Os(code))
    }
}

/// Map an `OSStatus` to a `Result`.
pub(crate) fn check_os_status(status: OsStatus) -> Result<()> {
    match status {
        0 => Ok(()),
        ERR_SEC_AUTH_FAILED => Err(Error::AuthFailed),
        ERR_SEC_USER_CANCELED => Err(Error::UserCancelled),
        ERR_SEC_ITEM_NOT_FOUND => Err(Error::NotFound),
        s => Err(Error::Os(s)),
    }
}
