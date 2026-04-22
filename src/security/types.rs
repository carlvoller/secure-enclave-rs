#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]

use std::os::raw::c_void;

// MacOS CoreFoundation types

#[repr(C)]
pub struct __CFString(c_void);
pub type CFStringRef = *const __CFString;

#[repr(C)]
pub struct __CFDictionary(c_void);
pub type CFDictionaryRef = *const __CFDictionary;
pub type CFMutableDictionaryRef = *mut __CFDictionary;

#[repr(C)]
pub struct __CFArray(c_void);
pub type CFArrayRef = *const __CFArray;

#[repr(C)]
pub struct __CFData(c_void);
pub type CFDataRef = *const __CFData;
pub type CFMutableDataRef = *mut __CFData;

#[repr(C)]
pub struct __CFError(c_void);
pub type CFErrorRef = *mut __CFError;

#[repr(C)]
pub struct __CFAllocator(c_void);
pub type CFAllocatorRef = *const __CFAllocator;

#[repr(C)]
pub struct __CFNumber(c_void);
pub type CFNumberRef = *const __CFNumber;

#[repr(C)]
pub struct __CFBoolean(c_void);
pub type CFBooleanRef = *const __CFBoolean;

/// Opaque callback structs used with CFDictionaryCreate.
#[repr(C)]
pub struct CFDictionaryKeyCallBacks {
    _private: [u8; 0],
}

#[repr(C)]
pub struct CFDictionaryValueCallBacks {
    _private: [u8; 0],
}

pub type CFTypeRef = *const c_void;
pub type CFIndex = isize;
pub type CFOptionFlags = u64;
pub type CFTypeID = usize;
pub type Boolean = u8;
pub type CFStringEncoding = u32;
pub type CFNumberType = i64;

// Security Enclave Types

pub type OSStatus = i32;

#[repr(C)]
pub struct OpaqueSecKeyRef(c_void);
pub type SecKeyRef = *const OpaqueSecKeyRef;

#[repr(C)]
pub struct OpaqueSecAccessControlRef(c_void);
pub type SecAccessControlRef = *const OpaqueSecAccessControlRef;

/// `SecKeyAlgorithm` is a strongly-typed `CFStringRef` in the Apple headers.
/// https://developer.apple.com/documentation/security/seckeyalgorithm
pub type SecKeyAlgorithm = CFStringRef;


pub type SecKeyOperationType = CFIndex;
pub const kSecKeyOperationTypeSign: SecKeyOperationType = 0;
pub const kSecKeyOperationTypeVerify: SecKeyOperationType = 1;
pub const kSecKeyOperationTypeEncrypt: SecKeyOperationType = 2;
pub const kSecKeyOperationTypeDecrypt: SecKeyOperationType = 3;
pub const kSecKeyOperationTypeKeyExchange: SecKeyOperationType = 4;

pub type SecAccessControlCreateFlags = CFOptionFlags;
pub const kSecAccessControlUserPresence: SecAccessControlCreateFlags = 1 << 0;
pub const kSecAccessControlBiometryAny: SecAccessControlCreateFlags = 1 << 1;
pub const kSecAccessControlBiometryCurrentSet: SecAccessControlCreateFlags = 1 << 3;
pub const kSecAccessControlDevicePasscode: SecAccessControlCreateFlags = 1 << 4;
pub const kSecAccessControlWatch: SecAccessControlCreateFlags = 1 << 5;
pub const kSecAccessControlOr: SecAccessControlCreateFlags = 1 << 14;
pub const kSecAccessControlAnd: SecAccessControlCreateFlags = 1 << 15;
pub const kSecAccessControlPrivateKeyUsage: SecAccessControlCreateFlags = 1 << 30;
pub const kSecAccessControlApplicationPassword: SecAccessControlCreateFlags = 1 << 31;


pub const kCFStringEncodingASCII: CFStringEncoding = 0x0600;
pub const kCFStringEncodingUTF8: CFStringEncoding = 0x0800_0100;

pub const kCFNumberSInt8Type: CFNumberType = 1;
pub const kCFNumberSInt16Type: CFNumberType = 2;
pub const kCFNumberSInt32Type: CFNumberType = 3;
pub const kCFNumberSInt64Type: CFNumberType = 4;
pub const kCFNumberIntType: CFNumberType = 9;
pub const kCFNumberLongType: CFNumberType = 10;
pub const kCFNumberLongLongType: CFNumberType = 11;
pub const kCFNumberNSIntegerType: CFNumberType = 15;
