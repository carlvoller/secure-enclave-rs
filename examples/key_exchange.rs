/// ECDH key exchange example — two parties deriving the same shared secret.
///
/// Run with:
///   cargo run --example key_exchange
use secure_enclave_rs::{
    derive_shared_secret, Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions,
};

const TAG_A: &[u8] = b"com.example.secure-enclave.key-exchange-demo.device-a";
const TAG_B: &[u8] = b"com.example.secure-enclave.key-exchange-demo.device-b";

fn main() {
    for tag in [TAG_A, TAG_B] {
        match SecureEnclaveKey::remove_by_tag(tag) {
            Ok(()) => println!("[setup] Removed leftover key."),
            Err(Error::NotFound) => {}
            Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
        }
    }

    // Each device generates its own SE key pair
    println!("\nGenerating SE key pairs");

    let key_a = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG_A,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate Device A key.");

    let key_b = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG_B,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate Device B key.");

    println!("  Device A: SE key generated.");
    println!("  Device B: SE key generated.");

    // Exchange public keys 
    // In production these bytes are sent over the network. Private keys never
    // leave their respective devices.
    println!("\nExchanging public keys");

    let pub_a = key_a.public_key_bytes().unwrap();
    let pub_b = key_b.public_key_bytes().unwrap();
    println!("  Device A public key: {}", hex(&pub_a));
    println!("  Device B public key: {}", hex(&pub_b));

    // Derive shared secret (ECDH)
    println!("\nDeriving shared secret");

    // ECDH property: A_priv × B_pub == B_priv × A_pub
    let secret_a = derive_shared_secret(&key_a, &pub_b, 32, &[])
        .expect("Device A key exchange failed.");
    let secret_b = derive_shared_secret(&key_b, &pub_a, 32, &[])
        .expect("Device B key exchange failed.");

    println!("  Device A secret: {}", hex(&secret_a));
    println!("  Device B secret: {}", hex(&secret_b));
    assert_eq!(secret_a, secret_b);
    println!("  ✓ Secrets match — both devices derived the same 32-byte key.");

    // Domain separation via shared_info
    println!("\nShared info for domain separation");

    let context = b"myapp-v1-session-key";
    let keyed_a = derive_shared_secret(&key_a, &pub_b, 32, context).unwrap();
    let keyed_b = derive_shared_secret(&key_b, &pub_a, 32, context).unwrap();

    assert_eq!(keyed_a, keyed_b);
    assert_ne!(keyed_a, secret_a, "shared_info must change the output.");
    println!("  With context {:?}: {}", std::str::from_utf8(context).unwrap(), hex(&keyed_a));
    println!("  ✓ Context-bound key matches between devices and differs from plain secret.");

    SecureEnclaveKey::remove_by_tag(TAG_A).unwrap();
    SecureEnclaveKey::remove_by_tag(TAG_B).unwrap();
    println!("\n[cleanup] Both keys deleted. Done.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
