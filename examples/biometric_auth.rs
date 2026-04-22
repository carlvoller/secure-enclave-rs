/// Biometric authentication example.
///
/// ⚠ This example will display a Face ID / Touch ID / passcode prompt.
///   Run it interactively on a Mac with a Secure Enclave.
///
/// Run with:
///   cargo run --example biometric_auth
use secure_enclave_rs::{Error, SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

const TAG: &[u8] = b"com.example.secure-enclave.biometric-auth-demo";

fn main() {
    match SecureEnclaveKey::remove_by_tag(TAG) {
        Ok(()) => println!("[setup] Removed leftover key from a previous run."),
        Err(Error::NotFound) => {}
        Err(e) => panic!("[setup] Unexpected cleanup error: {e}"),
    }

    // Enrollment (once per device / user account)
    println!("\nEnrollment");

    // BIOMETRY_ANY: any enrolled Face ID or Touch ID finger can unlock the key.
    // PRIVATE_KEY_USAGE is always included automatically.
    let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
        tag: TAG,
        access_flags: SecAccessControlFlags::BIOMETRY_ANY,
        permanent: true,
    })
    .expect("Failed to generate SE key — ensure a Secure Enclave is present.");

    println!("  Biometric-protected SE key stored in the keychain.");
    println!("  The private key material never leaves the Secure Enclave.");

    // Authentication
    println!("\nAuthentication");
    println!("  Waiting for biometric prompt… (approve with Face ID / Touch ID)");

    match key.authenticate() {
        Ok(()) => {
            println!("  ✓ Authentication succeeded — access granted.");
            run_protected_operation();
        }
        Err(Error::UserCancelled) => {
            println!("  ✗ User cancelled — access denied.");
        }
        Err(Error::AuthFailed) => {
            println!("  ✗ Biometric check failed — access denied.");
        }
        Err(e) => {
            println!("  ✗ Unexpected error: {e}");
        }
    }

    // Retrieve on a subsequent launch
    println!("\nRetrieving enrolled key on a later app launch");
    let enrolled = SecureEnclaveKey::get(TAG).expect("Enrolled key should be in keychain.");
    println!("  Key retrieved by tag — ready for the next authenticate() call.");
    drop(enrolled);

    SecureEnclaveKey::remove_by_tag(TAG).expect("Cleanup failed.");
    println!("\n[cleanup] Key deleted. Done.");
}

fn run_protected_operation() {
    println!("  → Running protected operation (showing secrets, approving a payment…)");
}
