/// Key lifecycle example — generate, find, inspect, delete.
///
/// Run with:
///   cargo run --example key_exists
use secure_enclave_rs::{Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

const TAG: &[u8] = b"com.example.secure-enclave.key-exists-demo";

fn main() {
    // Clean up any key left over from a previous run
    match SecureEnclaveKey::remove_by_tag(TAG) {
        Ok(()) => println!("[setup] Removed leftover key from a previous run."),
        Err(Error::NotFound) => {}
        Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
    }

    // 1. Check before creation
    println!("\nChecking for key before creation");

    match SecureEnclaveKey::get(TAG) {
        Err(Error::NotFound) => println!("  Key does not exist yet (expected on a fresh run)."),
        Ok(_) => unreachable!("just deleted it"),
        Err(e) => panic!("Unexpected error: {e}"),
    }

    // 2. Generate and store a key
    println!("\nGenerating key");

    // PRIVATE_KEY_USAGE is always OR'd in automatically by generate().
    // Add BIOMETRY_ANY to require Face ID / Touch ID on every use.
    let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::empty(), // device-unlock only
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    println!("  Key generated and stored in the keychain.");

    // 3. Find the key by tag
    println!("\nRetrieving key from keychain");

    let found = SecureEnclaveKey::get(TAG).expect("Key should exist now.");
    println!("  Key retrieved successfully by tag.");
    drop(found);

    // 4. Inspect the public key
    println!("\nInspecting public key");

    let pub_bytes = key.public_key_bytes().expect("Failed to export public key.");

    // P-256 uncompressed: 04 || 32-byte X || 32-byte Y = 65 bytes
    assert_eq!(pub_bytes.len(), 65);
    assert_eq!(pub_bytes[0], 0x04);

    println!("  Length : {} bytes", pub_bytes.len());
    println!("  Prefix : 0x{:02x} (uncompressed point)", pub_bytes[0]);
    println!("  X coord: {}", hex(&pub_bytes[1..33]));
    println!("  Y coord: {}", hex(&pub_bytes[33..65]));

    let _pub_key = key.public_key().expect("Failed to get public key handle.");
    println!("  Public key handle obtained.");

    // 5. Confirm existence, delete, confirm gone
    println!("\nDelete and confirm");

    assert!(matches!(SecureEnclaveKey::get(TAG), Ok(_)), "Key should exist.");
    println!("  ✓ Key present in keychain.");

    key.remove().expect("Failed to delete key.");
    println!("  Key deleted.");

    match SecureEnclaveKey::get(TAG) {
        Err(Error::NotFound) => println!("  ✓ Key is gone — NotFound returned as expected."),
        Ok(_) => panic!("Key should have been deleted!"),
        Err(e) => panic!("Unexpected error: {e}"),
    }

    println!("\nDone.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
