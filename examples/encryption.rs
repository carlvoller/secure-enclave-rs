/// ECIES asymmetric encryption / decryption example.
///
/// Run with:
///   cargo run --example encryption
use secure_enclave_rs::{Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

const TAG: &[u8] = b"com.example.secure-enclave.encryption-demo";

fn main() {
    match SecureEnclaveKey::remove_by_tag(TAG) {
        Ok(()) => println!("[setup] Removed leftover key from a previous run."),
        Err(Error::NotFound) => {}
        Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
    }

    println!("\nGenerating SE key pair");

    let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    println!("  Public key: {}", hex(&key.public_key_bytes().unwrap()));

    // Encrypt with the public key
    // encrypt() accepts a private key and automatically uses its public half,
    // or you can pass key.public_key()? explicitly.
    println!("\nEncrypting");

    let message = b"Hello from the Secure Enclave!";
    println!("  Plaintext:  {:?}", std::str::from_utf8(message).unwrap());

    let ciphertext = key.encrypt(message).expect("Encryption failed.");
    println!("  Ciphertext ({} bytes): {}", ciphertext.len(), hex(&ciphertext));

    // Decrypt with the private SE key
    println!("\nDecrypting");

    let recovered = key.decrypt(&ciphertext).expect("Decryption failed.");
    assert_eq!(recovered, message);
    println!("  Recovered:  {:?}", std::str::from_utf8(&recovered).unwrap());
    println!("  ✓ Plaintext matches original.");

    // Show non-determinism (random IV per ECIES spec)
    println!("\nDemonstrating random IV");

    let ct2 = key.encrypt(message).unwrap();
    assert_ne!(ciphertext, ct2);
    println!("  First  ciphertext: {}", hex(&ciphertext));
    println!("  Second ciphertext: {}", hex(&ct2));
    println!("  ✓ Ciphertexts differ (random IV confirmed).");
    assert_eq!(key.decrypt(&ct2).unwrap(), message);
    println!("  ✓ Both decrypt to the same plaintext.");

    key.remove().expect("Cleanup failed.");
    println!("\n[cleanup] Key deleted. Done.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
