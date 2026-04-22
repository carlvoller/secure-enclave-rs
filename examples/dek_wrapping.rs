/// Data encryption key (DEK) wrapping example.
///
/// The SE protects a random AES key; the AES key protects the data.
/// The plaintext DEK is in memory only while data is being accessed.
///
/// Note: XOR is used as a stand-in for AES-256-GCM — use `aes-gcm` in production.
///
/// Run with:
///   cargo run --example dek_wrapping
use secure_enclave_rs::{Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

const TAG: &[u8] = b"com.example.secure-enclave.dek-wrapping-demo";
const WRONG_TAG: &[u8] = b"com.example.secure-enclave.dek-wrapping-demo.wrong";

fn main() {
    for tag in [TAG, WRONG_TAG] {
        match SecureEnclaveKey::remove_by_tag(tag) {
            Ok(()) => println!("[setup] Removed leftover key."),
            Err(Error::NotFound) => {}
            Err(e) => panic!("[setup] Cleanup error: {e}"),
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // ENROLLMENT — run once when the user sets up the protected store
    // ════════════════════════════════════════════════════════════════════════
    println!("\nEnrollment");

    // 1. SE key pair. Swap in SecAccessControlFlags::BIOMETRY_ANY to require
    //    Face ID before each DEK unwrap.
    let se_key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    println!("  SE key: {}", hex(&se_key.public_key_bytes().unwrap()));

    // 2. Random 32-byte AES-256 DEK.
    let dek: [u8; 32] = random_bytes();
    println!("\n  DEK (only visible now): {}", hex(&dek));

    // 3. Wrap the DEK with the SE public key via ECIES.
    //    The wrapped form is safe to store anywhere.
    let wrapped_dek = se_key.encrypt(&dek).expect("Failed to wrap DEK.");
    println!("  Wrapped DEK ({} bytes): {}", wrapped_dek.len(), hex(&wrapped_dek));

    // 4. Encrypt some data with the DEK and discard the plaintext DEK.
    let plaintext = b"Sensitive database record. Use AES-256-GCM in production.";
    let ciphertext = xor_encrypt(&dek, plaintext);
    println!("\n  Data encrypted with DEK ({} bytes).", plaintext.len());

    // Only `wrapped_dek` and `ciphertext` need to be persisted.
    let _ = dek;
    drop(se_key);
    println!("  Plaintext DEK discarded. Only the wrapped form persists.");

    // ════════════════════════════════════════════════════════════════════════
    // DATA ACCESS — each session that needs to read the protected data
    // ════════════════════════════════════════════════════════════════════════
    println!("\nData access (new session)");

    // 5. Retrieve the SE key from the keychain.
    let se_key = SecureEnclaveKey::get(TAG).expect("SE key not found.");
    println!("  SE key retrieved.");

    // 6. Unwrap the DEK inside the SE. If biometric protection is set, the OS
    //    will prompt for Face ID / Touch ID here.
    let unwrapped: Vec<u8> = se_key.decrypt(&wrapped_dek).expect("Failed to unwrap DEK.");
    let unwrapped_dek: [u8; 32] = unwrapped.try_into().unwrap();
    println!("  DEK unwrapped (32 bytes).");

    // 7. Decrypt the data with the DEK, then discard it.
    let recovered = xor_encrypt(&unwrapped_dek, &ciphertext);
    assert_eq!(recovered, plaintext);
    println!("  Decrypted: {:?}", std::str::from_utf8(&recovered).unwrap());
    println!("  ✓ Data integrity verified.");
    let _ = unwrapped_dek;
    println!("  Plaintext DEK discarded again.");

    // Wrong key is rejected
    println!("\nWrong key is rejected");

    let wrong = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: WRONG_TAG,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .unwrap();

    match wrong.decrypt(&wrapped_dek) {
        Err(e) => println!("  ✓ Wrong key rejected: {e}"),
        Ok(_) => panic!("Wrong key should not decrypt the DEK."),
    }

    SecureEnclaveKey::remove_by_tag(TAG).unwrap();
    SecureEnclaveKey::remove_by_tag(WRONG_TAG).unwrap();
    println!("\n[cleanup] Keys deleted. Done.");
}

fn xor_encrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &b)| b ^ key[i % 32]).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((t >> (i % 64)) ^ (i as u128 * 0x9E3779B9)) as u8;
    }
    buf
}
