# secure-enclave-rs

Safe Rust bindings to Apple's Secure Enclave, built on the macOS Security
framework. Created because nothing else in the Rust ecosystem wraps the Secure Enclave APIs without leaking `unsafe` CoreFoundation pointers or pulling in the entire `security-framework` crate.

Python bindings live alongside in [`py_secure_enclave/`](./py_secure_enclave/).

## Features

Use hardware-backed P-256 keys in the Secure Enclave, with:

- Key generation with arbitrary `SecAccessControl` policies
  (biometry, device passcode, application password, combinations)
- Persistence in the keychain by application tag
- ECDSA-SHA256 signing and verification
- ECIES encryption / decryption (X9.63 KDF + AES-GCM)
- ECDH key agreement with X9.63 KDF
- Optional ES256 JWT signing (RFC 7519 / RFC 7523) under the `jwt` feature
- Public-key export as X9.62 uncompressed bytes; reconstruction from bytes
  for server-side verification

Private keys never leaves Apple's Secure Enclave.

## Requirements

Just macOS with Secure Enclave:
- Apple Silicon or
- Intel with a T2 chip or later

## Installation

```toml
[dependencies]
secure-enclave-rs = "1"

# For JWT / ES256 support:
secure-enclave-rs = { version = "1", features = ["jwt"] }
```

## Quick example

```rust
use secure_enclave_rs::{SecAccessControlFlags, SecureEnclaveKey, SecureEnclaveKeyOptions};

let key = SecureEnclaveKey::generate(&SecureEnclaveKeyOptions {
    tag: b"com.example.signing-key",
    access_flags: SecAccessControlFlags::BIOMETRY_ANY,
    permanent: true,
})?;

let sig = key.sign(b"hello world")?;         // prompts Face ID / Touch ID
assert!(key.verify(b"hello world", &sig)?);

let peer_pub = &[0x04u8; 65]; // peer's X9.62 uncompressed public key
let shared = secure_enclave_rs::derive_shared_secret(&key, peer_pub, 32, &[])?;
```

Full end-to-end examples in [`examples/`](./examples/):

| File | Demonstrates |
| --- | --- |
| `key_exists.rs` | Generate, persist, retrieve, remove |
| `encryption.rs` | ECIES encrypt / decrypt |
| `key_exchange.rs` | ECDH shared secret derivation |
| `biometric_auth.rs` | `BIOMETRY_ANY` + `DEVICE_PASSCODE` flags |
| `attestation.rs` | Server-verified challenge / response |
| `dek_wrapping.rs` | Wrapping a symmetric DEK with an SE key |
| `jwt_assertion.rs` | ES256 JWT (requires `--features jwt`) |

Run one with `cargo run --example encryption`.

## Code signing and entitlements

Only code-signed processes can use Apple's Secure Enclave. However, different operations have different entitlement requirements. None of the methods in this library work in an unsigned binary on a Mac with System Integrity Protection (SIP) enabled.

### Ephemeral keys (`permanent: false`)

If you don't intend to store keys permanently in the Secure Enclave, you only need the process to be **code-signed**. An ad-hoc signature is enough
(`codesign -s - target/debug/my-binary`). Apple Development certificates
also work. No provisioning profile, no special entitlements.

Everything except keychain persistence works here — sign, verify, encrypt,
decrypt, ECDH, JWT signing.

### Persistent keys (`permanent: true`)

Calls into `SecItemAdd` / `SecItemCopyMatching` require the binary to
present a **keychain access group**. As such, you'll need these three things too:

1. An **Apple Development** code-signing identity (not ad-hoc).
2. A `keychain-access-groups` entitlement at sign time, e.g.

   ```xml
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
     "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0"><dict>
     <key>com.apple.application-identifier</key>
     <string>TEAMID.com.example.myapp</string>
     <key>com.apple.developer.team-identifier</key>
     <string>TEAMID</string>
     <key>keychain-access-groups</key>
     <array><string>TEAMID.com.example.myapp</string></array>
   </dict></plist>
   ```

3. A matching macOS **provisioning profile** embedded in the `.app` as
   `Contents/embedded.provisionprofile`. Because `keychain-access-groups`
   is a *restricted* entitlement, AMFI kills the process at launch without
   one (`Code Signing Error: No matching profile found`).

   Any Apple ID, including a free Personal Team, can issue a Development
   profile from Xcode. No paid Developer Program required. See the
   [`py_secure_enclave` README](./py_secure_enclave/README.md#one-time-xcode-setup)
   for step-by-step instructions; the resulting `.provisionprofile` works
   for both Rust and Python consumers.

Without a profile, `SecureEnclaveKey::generate(..., permanent: true)` and
`get` / `remove_by_tag` all return `Error::Os(-34018)`
(`errSecMissingEntitlement`).

### Biometric / passcode access flags

No additional entitlements beyond the above. MacOS handles displaying a popup prompt and the Secure Enclave handles the evaluation.

## Thread safety

`SecureEnclaveKey` is deliberately not `Send`/`Sync` as Apple's
documentation is ambiguous about concurrency guarantees on macOS
Security-framework objects, so the type is pinned to its creating thread.

## License

Copyright © 2026, Carl Ian Voller. Released under the BSD-3-Clause License.
