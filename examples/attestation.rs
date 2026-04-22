/// Client attestation example — enrollment, challenge signing, server verification.
///
/// Run with:
///   cargo run --example attestation
///
/// Note: uses `SecAccessControlFlags::empty()` (no biometric prompt) for a
/// runnable demo. In production use `SecureEnclaveKey::generate` with
/// `SecAccessControlFlags::BIOMETRY_ANY`.
use secure_enclave_rs::{Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

const TAG: &[u8] = b"com.example.secure-enclave.attestation-demo";

fn main() {
    match SecureEnclaveKey::remove_by_tag(TAG) {
        Ok(()) => println!("[setup] Removed leftover key from a previous run."),
        Err(Error::NotFound) => {}
        Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
    }

    // Step 1: Enrollment (client side, once per device)
    println!("\nStep 1: Enrollment");

    let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    // Export the public key to register with the server.
    // In production: POST these bytes to your backend during device setup.
    let public_key_bytes = key.public_key_bytes().expect("Failed to export public key.");
    println!("  Public key ({} bytes):", public_key_bytes.len());
    println!("    {}", hex(&public_key_bytes));
    println!("  → [client] Sends public key to server for registration.");

    // Step 2: Attestation (client, each auth)
    println!("\nStep 2: Attestation challenge");

    // Server sends a fresh random nonce (≥ 16 bytes). Never reuse nonces.
    let server_nonce: [u8; 32] = random_bytes();
    println!("  Server nonce: {}", hex(&server_nonce));

    let key = SecureEnclaveKey::get(TAG).expect("Key not found.");
    let signature = key.sign(&server_nonce).expect("Signing failed.");
    println!("  Signature ({} bytes): {}", signature.len(), hex(&signature));
    println!("  → [client] Sends signature back to server.");

    // Step 3: Server-side verification 
    println!("\nStep 3: Server-side verification");

    // Server reconstructs the public key from the registered bytes and verifies.
    let public_key = SecureEnclaveKey::from_public_key_bytes(&public_key_bytes)
        .expect("Failed to reconstruct public key.");

    let valid = public_key
        .verify(&server_nonce, &signature)
        .expect("Verification error.");

    assert!(valid);
    println!("  ✓ Signature VALID — request is from the enrolled device.");

    // Demonstrate that a tampered nonce is rejected.
    let mut bad_nonce = server_nonce;
    bad_nonce[0] ^= 0xFF;
    let rejected = public_key.verify(&bad_nonce, &signature).unwrap_or(false);
    assert!(!rejected);
    println!("  ✓ Tampered nonce correctly rejected.");

    SecureEnclaveKey::remove_by_tag(TAG).expect("Cleanup failed.");
    println!("\n[cleanup] Key deleted. Done.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn random_bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    for (i, b) in buf.iter_mut().enumerate() {
        *b = ((t >> (i % 32)) ^ (i as u32 * 0x6B)) as u8;
    }
    buf
}
