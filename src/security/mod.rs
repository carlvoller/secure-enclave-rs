#![allow(non_snake_case, non_upper_case_globals)]

pub mod types;

use std::os::raw::{c_char, c_void};
use types::*;

#[allow(dead_code)]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Generates a new public-private key pair.
    /// Pass `kSecAttrTokenIDSecureEnclave` in `parameters` to create an SE-backed key.
    /// https://developer.apple.com/documentation/security/seckeycreaterandomkey(_:_:)?language=objc
    pub fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;

    /// Gets the public key associated with the given private key.
    /// https://developer.apple.com/documentation/security/seckeycopypublickey(_:)?language=objc
    pub fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;

    /// Gets the attributes of a given key.
    /// https://developer.apple.com/documentation/security/seckeycopyattributes(_:)?language=objc
    pub fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;

    /// Returns the unique identifier of the opaque type to which a key object belongs.
    /// https://developer.apple.com/documentation/security/seckeygettypeid()?language=objc
    pub fn SecKeyGetTypeID() -> CFTypeID;

    /// Returns a Boolean indicating whether a key is suitable for an operation using a certain algorithm.
    /// https://developer.apple.com/documentation/security/seckeyisalgorithmsupported(_:_:_:)?language=objc
    pub fn SecKeyIsAlgorithmSupported(
        key: SecKeyRef,
        operation: SecKeyOperationType,
        algorithm: SecKeyAlgorithm,
    ) -> Boolean;

    /// Returns an external representation of the given key suitable for the key’s type.
    ///
    /// The operation fails if the key is not exportable, for example if it is bound to a smart card or to the Secure Enclave.
    /// It also fails in macOS if the key has the attribute kSecKeyExtractable set to false.
    /// The method returns data in the PKCS #1 format for an RSA key.
    ///
    /// For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y.
    /// For an elliptic curve private key, the output is formatted as the public key concatenated with the big endian encoding of the secret scalar, or 04 || X || Y || K.
    /// All of these representations use constant size integers, including leading zeros as needed.
    /// form: `04 || X || Y` (65 bytes for P-256).
    /// https://developer.apple.com/documentation/security/seckeycopyexternalrepresentation(_:_:)?language=objc
    pub fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;

    /// Restores a key from an external representation of that key.
    /// The attributes must specify at minimum `kSecAttrKeyType` and `kSecAttrKeyClass`.
    /// https://developer.apple.com/documentation/security/seckeycreatewithdata(_:_:_:)?language=objc
    pub fn SecKeyCreateWithData(
        keyData: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;

    /// Creates the cryptographic signature for a block of data using a private key and specified algorithm.
    /// Returns a `CFDataRef` containing the signature, or NULL on failure.
    /// https://developer.apple.com/documentation/security/seckeycreatesignature(_:_:_:_:)?language=objc
    pub fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        dataToSign: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    /// Verifies the cryptographic signature of a block of data using a public key and specified algorithm.
    /// Returns non-zero on success.
    /// https://developer.apple.com/documentation/security/seckeyverifysignature(_:_:_:_:_:)?language=objc
    pub fn SecKeyVerifySignature(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        signedData: CFDataRef,
        signature: CFDataRef,
        error: *mut CFErrorRef,
    ) -> Boolean;

    /// Encrypts a block of data using a public key and specified algorithm.
    /// Returns a `CFDataRef` containing the ciphertext, or NULL on failure.
    /// https://developer.apple.com/documentation/security/seckeycreateencrypteddata(_:_:_:_:)?language=objc
    pub fn SecKeyCreateEncryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        plaintext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    /// Decrypts a block of data using a private key and specified algorithm.
    /// Returns a `CFDataRef` containing the plaintext, or NULL on failure.
    /// https://developer.apple.com/documentation/security/seckeycreatedecrypteddata(_:_:_:_:)?language=objc
    pub fn SecKeyCreateDecryptedData(
        key: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        ciphertext: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    /// Performs the Diffie-Hellman style of key exchange with optional key-derivation steps.
    /// `kSecKeyKeyExchangeParameterRequestedSize` and `kSecKeyKeyExchangeParameterSharedInfo`.
    /// https://developer.apple.com/documentation/security/seckeycopykeyexchangeresult(_:_:_:_:_:)?language=objc
    pub fn SecKeyCopyKeyExchangeResult(
        privateKey: SecKeyRef,
        algorithm: SecKeyAlgorithm,
        publicKey: SecKeyRef,
        parameters: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;

    /// Adds one or more items to a keychain.
    /// Pass `std::ptr::null_mut()` for `result` when the return value is not needed.
    /// https://developer.apple.com/documentation/security/secitemadd(_:_:)?language=objc
    pub fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;

    /// Returns one or more keychain items that match a search query, or copies attributes of specific keychain items.
    /// https://developer.apple.com/documentation/security/secitemcopymatching(_:_:)?language=objc
    pub fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;

    /// Modifies items that match a search query.
    /// https://developer.apple.com/documentation/security/secitemupdate(_:_:)?language=objc
    pub fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) -> OSStatus;

    /// Deletes items that match a search query.
    /// https://developer.apple.com/documentation/security/secitemdelete(_:)?language=objc
    pub fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;

    /// Creates a new access control object with the specified protection type and flags.
    /// https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)?language=objc
    pub fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: SecAccessControlCreateFlags,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;

    /// Returns the unique identifier of the opaque type to which a keychain item access control object belongs.
    /// https://developer.apple.com/documentation/security/secaccesscontrolgettypeid()?language=objc
    pub fn SecAccessControlGetTypeID() -> CFTypeID;

    /// Returns a string explaining the meaning of a security result code.
    /// `reserved` must be NULL as its reserved for future use
    /// https://developer.apple.com/documentation/security/seccopyerrormessagestring(_:_:)?language=objc
    pub fn SecCopyErrorMessageString(status: OSStatus, reserved: *mut c_void) -> CFStringRef;

    // Keychain attribute name constants
    pub static kSecClass: CFStringRef;
    pub static kSecClassKey: CFStringRef;
    pub static kSecClassCertificate: CFStringRef;
    pub static kSecClassIdentity: CFStringRef;

    // Key type & token
    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    pub static kSecAttrTokenID: CFStringRef;
    pub static kSecAttrTokenIDSecureEnclave: CFStringRef;

    // Key identification
    pub static kSecAttrApplicationLabel: CFStringRef;
    pub static kSecAttrApplicationTag: CFStringRef;
    pub static kSecAttrLabel: CFStringRef;

    // Key parameters
    pub static kSecAttrKeySizeInBits: CFStringRef;
    pub static kSecAttrEffectiveKeySize: CFStringRef;
    pub static kSecAttrKeyClass: CFStringRef;
    pub static kSecAttrKeyClassPrivate: CFStringRef;
    pub static kSecAttrKeyClassPublic: CFStringRef;

    // Storage & protection
    pub static kSecAttrAccessControl: CFStringRef;
    pub static kSecAttrAccessible: CFStringRef;
    pub static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    pub static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
    pub static kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly: CFStringRef;
    pub static kSecAttrAccessibleWhenUnlocked: CFStringRef;
    pub static kSecAttrAccessibleAfterFirstUnlock: CFStringRef;
    pub static kSecAttrIsPermanent: CFStringRef;
    pub static kSecAttrIsExtractable: CFStringRef;
    pub static kSecAttrSynchronizable: CFStringRef;

    // Key capability flags
    pub static kSecAttrCanEncrypt: CFStringRef;
    pub static kSecAttrCanDecrypt: CFStringRef;
    pub static kSecAttrCanSign: CFStringRef;
    pub static kSecAttrCanVerify: CFStringRef;
    pub static kSecAttrCanDerive: CFStringRef;
    pub static kSecAttrCanWrap: CFStringRef;
    pub static kSecAttrCanUnwrap: CFStringRef;

    // Return types
    pub static kSecReturnRef: CFStringRef;
    pub static kSecReturnData: CFStringRef;
    pub static kSecReturnAttributes: CFStringRef;
    pub static kSecReturnPersistentRef: CFStringRef;

    // Match constraints
    pub static kSecMatchLimit: CFStringRef;
    pub static kSecMatchLimitOne: CFStringRef;
    pub static kSecMatchLimitAll: CFStringRef;
    pub static kSecMatchItemList: CFStringRef;

    // Key generation sub-dictionaries
    pub static kSecPrivateKeyAttrs: CFStringRef;
    pub static kSecPublicKeyAttrs: CFStringRef;

    // Authentication & UI
    pub static kSecUseOperationPrompt: CFStringRef;
    pub static kSecUseAuthenticationUI: CFStringRef;
    pub static kSecUseAuthenticationContext: CFStringRef;
    pub static kSecUseAuthenticationUIAllow: CFStringRef;
    pub static kSecUseAuthenticationUIFail: CFStringRef;
    pub static kSecUseAuthenticationUISkip: CFStringRef;

    // Key exchange parameters
    pub static kSecKeyKeyExchangeParameterRequestedSize: CFStringRef;
    pub static kSecKeyKeyExchangeParameterSharedInfo: CFStringRef;

    // SecKeyAlgorithm constants

    // ECDSA — digest input (caller pre-hashes)
    pub static kSecKeyAlgorithmECDSASignatureRFC4754: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureDigestX962SHA512: SecKeyAlgorithm;

    // ECDSA — message input (framework hashes internally)
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDSASignatureMessageX962SHA512: SecKeyAlgorithm;

    // ECIES standard (X9.63 KDF, fixed IV)
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA1AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardX963SHA512AESGCM: SecKeyAlgorithm;

    // ECIES standard (variable IV)
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA512AESGCM: SecKeyAlgorithm;

    // ECIES cofactor (X9.63 KDF, fixed IV)
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorX963SHA512AESGCM: SecKeyAlgorithm;

    // ECIES cofactor (variable IV)
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA224AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA384AESGCM: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA512AESGCM: SecKeyAlgorithm;

    // ECDH key exchange — standard (X9.63 KDF)
    pub static kSecKeyAlgorithmECDHKeyExchangeStandard: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeStandardX963SHA512: SecKeyAlgorithm;

    // ECDH key exchange — cofactor
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactor: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA1: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA224: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA256: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA384: SecKeyAlgorithm;
    pub static kSecKeyAlgorithmECDHKeyExchangeCofactorX963SHA512: SecKeyAlgorithm;
}

#[allow(dead_code)]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {

    pub fn CFRelease(cf: CFTypeRef);
    pub fn CFRetain(cf: CFTypeRef) -> CFTypeRef;

    pub fn CFErrorGetCode(err: CFErrorRef) -> CFIndex;
    pub fn CFErrorCopyDescription(err: CFErrorRef) -> CFStringRef;
    pub fn CFErrorCopyUserInfo(err: CFErrorRef) -> CFDictionaryRef;

    /// Quickly obtains a pointer to a C-string buffer containing the characters of a string in a given encoding.
    /// https://developer.apple.com/documentation/corefoundation/cfstringgetcstringptr(_:_:)?language=objc
    pub fn CFStringGetCStringPtr(
        theString: CFStringRef,
        encoding: CFStringEncoding,
    ) -> *const c_char;

    /// Copies the character contents of a string to a local C string buffer after converting the characters to a given encoding.
    /// Returns non-zero on success.
    /// https://developer.apple.com/documentation/corefoundation/cfstringgetcstring(_:_:_:_:)?language=objc
    pub fn CFStringGetCString(
        theString: CFStringRef,
        buffer: *mut c_char,
        bufferSize: CFIndex,
        encoding: CFStringEncoding,
    ) -> Boolean;

    pub fn CFStringGetLength(theString: CFStringRef) -> CFIndex;

    /// Creates an immutable string from a C string.
    /// The C string must be NULL terminated.
    /// https://developer.apple.com/documentation/corefoundation/cfstringcreatewithcstring(_:_:_:)?language=objc
    pub fn CFStringCreateWithCString(
        alloc: CFAllocatorRef,
        cStr: *const c_char,
        encoding: CFStringEncoding,
    ) -> CFStringRef;

    pub fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    pub fn CFDataGetLength(theData: CFDataRef) -> CFIndex;
    pub fn CFDataGetBytePtr(theData: CFDataRef) -> *const u8;

    pub fn CFDictionaryCreate(
        allocator: CFAllocatorRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        numValues: CFIndex,
        keyCallBacks: *const CFDictionaryKeyCallBacks,
        valueCallBacks: *const CFDictionaryValueCallBacks,
    ) -> CFDictionaryRef;

    pub fn CFDictionaryGetValue(theDict: CFDictionaryRef, key: *const c_void) -> *const c_void;

    pub fn CFDictionaryGetCount(theDict: CFDictionaryRef) -> CFIndex;

    pub fn CFNumberCreate(
        allocator: CFAllocatorRef,
        theType: CFNumberType,
        valuePtr: *const c_void,
    ) -> CFNumberRef;

    pub fn CFNumberGetValue(
        number: CFNumberRef,
        theType: CFNumberType,
        valuePtr: *mut c_void,
    ) -> Boolean;

    pub fn CFBooleanGetValue(boolean: CFBooleanRef) -> Boolean;

    pub fn CFArrayGetCount(theArray: CFArrayRef) -> CFIndex;
    pub fn CFArrayGetValueAtIndex(theArray: CFArrayRef, idx: CFIndex) -> *const c_void;

    // CoreFoundation constants

    pub static kCFAllocatorDefault: CFAllocatorRef;
    pub static kCFBooleanTrue: CFBooleanRef;
    pub static kCFBooleanFalse: CFBooleanRef;
    pub static kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    pub static kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
}
