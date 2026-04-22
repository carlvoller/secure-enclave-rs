/// JWT ES256 client assertion example.
///
/// Replaces file-based private keys for signing OAuth2 / RFC 7523 JWT client
/// assertions. The SE private key never leaves the hardware.
///
/// Run with:
///   cargo run --example jwt_assertion --features jwt
///
use secure_enclave_rs::{
    Error, SecAccessControlFlags, SecureEnclaveJWT, SecureEnclaveKey, SecureEnclaveKeyOptions,
};
use serde_json::json;

const KEY_ID: &str = "my-service-client-id";
const AUDIENCE: &str = "https://example.com/token";
const TAG: &[u8] = b"com.example.secure-enclave.jwt-demo";

fn main() {
    match SecureEnclaveKey::remove_by_tag(TAG) {
        Ok(()) => println!("[setup] Removed leftover key from a previous run."),
        Err(Error::NotFound) => {}
        Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
    }

    // Enrollment
    println!("\nEnrollment");

    let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::empty(),
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    let pub_bytes = key
        .public_key_bytes()
        .expect("Failed to export public key.");
    println!("  Key ID  : {}", KEY_ID);
    println!("  Pub key : {}", hex(&pub_bytes));

    // Sign a JWT client assertion
    println!("\nSigning JWT assertion");

    // In a running service, retrieve the key on each request:
    let key = SecureEnclaveKey::get(TAG).expect("SE key not found.");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // SecureEnclaveJWT replaces signAssertion() + loadPrivateKey().
    let token = SecureEnclaveJWT::new(&key)
        .expect("Failed to create JWT signer.")
        .with_headers(json!({ "kid": KEY_ID }))
        .expect("Invalid headers.")
        .with_claims(json!({
            "iss": KEY_ID,
            "aud": [AUDIENCE],
            "iat": now,
            "exp": now + 300,
        }))
        .expect("Invalid claims.")
        .sign()
        .expect("Signing failed.");

    println!("  Signed JWT:\n    {}", token);

    // Decode the payload
    println!("\nDecoded payload");

    let (headers, claims) = key
        .public_key()
        .and_then(|pub_key| {
            SecureEnclaveJWT::new(&pub_key)
                .expect("Failed to create verifier.")
                .verify_and_get_payload(&token)
        })
        .expect("Verification failed.");

    println!("  Headers : {}", headers);
    println!("  Claims  : {}", claims);

    // How the token is used
    println!("\nUsage in a token exchange request");
    println!("  POST {AUDIENCE}");
    println!("  client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
    println!("  client_assertion=<the JWT above>");

    // Verify signature
    println!("\nVerifying signature");

    let pub_key = key.public_key().expect("Failed to get public key.");
    let verifier = SecureEnclaveJWT::new(&pub_key).expect("Failed to create verifier.");

    verifier.verify(&token).expect("Valid token should verify.");
    println!("  ✓ Signature valid.");

    // Corrupt the signature and confirm rejection.
    let mut tampered = token.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });

    match verifier.verify(&tampered) {
        Err(_) => println!("  ✓ Tampered token correctly rejected."),
        Ok(()) => panic!("Tampered token should have been rejected."),
    }

    SecureEnclaveKey::remove_by_tag(TAG).expect("Cleanup failed.");
    println!("\n[cleanup] Key deleted. Done.");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
