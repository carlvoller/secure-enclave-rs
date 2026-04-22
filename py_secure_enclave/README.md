# py-secure-enclave

Python bindings to macOS Secure Enclave, built on [secure-enclave-rs](../) with PyO3.

I built this library because previously there was no way to interact with Apple's Secure Enclave from Python. This is likely due to the strict signing requirements on MacOS to use the Secure Enclave, however there is a limited subset of use cases in the Python world that may benefit form this. (Such as creating Python bundles)

```python
from py_secure_enclave import SecureEnclaveKey, AccessControlFlags

key = SecureEnclaveKey.generate(
    tag=b"com.example.signing-key",
    access_flags=AccessControlFlags.BIOMETRY_ANY,
)
sig = key.sign(b"hello world")              # prompts Face ID / Touch ID
assert key.verify(b"hello world", sig)
```

Private key never leaves Apple's Secure Enclave.

## ⚠️ You can't just `pip install` and `python main.py`

Apple's Secure Enclave is reachable only to **code-signed** processes. A
plain `python` REPL or script is unsigned by default, so:

- `SecureEnclaveKey.generate(..., permanent=True)` fails with `errSecMissingEntitlement`.
- `SecureEnclaveKey.get(...)` / `remove_by_tag(...)` fail the same way.
- Even the ephemeral-key paths only work when the host `python` binary
  itself is code-signed, which the system-shipped `python3` is but
  a Homebrew or `pyenv`-built one generally is not.

**To use this package for anything real, you must bundle the Python
interpreter that runs your code into a code-signed `.app` with a
provisioning profile.** Tools like
[`py2app`](https://py2app.readthedocs.io/) or
[`PyInstaller`](https://pyinstaller.org/) work. You can refer to
[`tests/bundle_app/`](./tests/bundle_app/) for a minimal py2app
reference implementation.

> This is **EXTREMELY NOT** recommended but, you could also sign your entire Python Binary. This has horrendous security implications and you would basically be building a back-door into your device's Secure Enclave. I mention this in case you might be thinking about doing this. Don't do this unless you plan to throw out your Mac and all its data by tomorrow. You've been warned.

## Requirements

- macOS with a Secure Enclave:
    - Apple Silicon or
    - Intel with a T2 chip or later
- Python ≥ 3.9
- For building from source: a Rust toolchain + [maturin](https://www.maturin.rs/)

## Install

```sh
pip install py-secure-enclave
```

Or from source:

```sh
git clone https://github.com/carlvoller/secure-enclave-rs
cd secure-enclave-rs/py_secure_enclave
python -m venv .venv && source .venv/bin/activate
pip install maturin
maturin develop --release
```

## Documentation

```python
from py_secure_enclave import (
    AccessControlFlags,
    SecureEnclaveKey,
    SecureEnclaveJWT,
    SecureEnclaveError,
    KeyNotFoundError,
    AuthFailedError,
    UserCancelledError,
)
```

`SecureEnclaveKey`:

- `generate(tag, access_flags=None, permanent=True)` → P-256 key in SE
- `get(tag)` → retrieve an existing persistent key
- `from_public_key_bytes(bytes)` → reconstruct a public-only handle
- `remove()` / `remove_by_tag(tag)`
- `public_key()` / `public_key_bytes()` (65-byte X9.62 uncompressed)
- `sign(data)` → DER ECDSA-SHA256 signature
- `verify(data, signature)` → bool
- `encrypt(plaintext)` / `decrypt(ciphertext)` → ECIES (X9.63 KDF, AES-GCM)
- `derive_shared_secret(peer_public_key_bytes, output_len=32, shared_info=None)`
- `authenticate()` → force the biometric / passcode prompt

`AccessControlFlags` — bitflag composable with `|`:
`EMPTY`, `USER_PRESENCE`, `BIOMETRY_ANY`, `BIOMETRY_CURRENT_SET`,
`DEVICE_PASSCODE`, `APPLICATION_PASSWORD`, `OR`, `AND`,
`PRIVATE_KEY_USAGE` (auto-added).

`SecureEnclaveJWT` — builder for ES256 tokens:

```python
jwt = SecureEnclaveJWT()
jwt.with_headers({"kid": "service-key"})
jwt.with_claims({"iss": "me", "aud": ["https://example.com"], "iat": now, "exp": now + 300})
token = jwt.sign(key)

headers, claims = SecureEnclaveJWT().verify_and_decode(key.public_key(), token)
```

Full API with type stubs: [`py_secure_enclave/__init__.pyi`](./py_secure_enclave/__init__.pyi).

## Bundling your app

Because of the code-signing requirement above, the deployment model is
**your app ships a Python interpreter**, not *the user's Python imports
your library*.

The shape of the bundle must be:

```
YourApp.app/
| - Contents/
|   | - Info.plist
|   | - MacOS/                        ← entrypoint binary + embedded python
|   | - Frameworks/                   ← libpython + native .so files
|   | - Resources/                    ← your Python code + py_secure_enclave
|   | - embedded.provisionprofile     ← required for persistent keys
```

and it must be signed recursively with entitlements:

```xml
<?xml version="1.0" encoding="UTF-8"?>
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

See [`tests/bundle_app/run_tests.sh`](./tests/bundle_app/run_tests.sh)
for a complete worked example: py2app build → embed profile →
recursive `codesign` → launch + capture exit code.

### One-time Xcode setup (provisioning profile)

You can issue a **free** Development provisioning profile from any Apple
ID — including a free "Personal Team". A paid Apple Developer Program
account is **not** required.

1. Xcode → Settings → Accounts → add your Apple ID.
2. File → New → Project → macOS → App.
3. Set the Bundle Identifier to match what you'll put in `Info.plist`
   and `keychain-access-groups`.
4. Pick your Team under Signing & Capabilities.
5. `+ Capability` → **Keychain Sharing**.
6. Product → Build (⌘B) once.

Xcode writes the profile to
`~/Library/Developer/Xcode/UserData/Provisioning Profiles/<uuid>.provisionprofile`.
You can delete the scratch Xcode project after this — the profile persists.

Profiles issued by a free Personal Team are good for 7 days on iOS and
considerably longer on macOS (1 year last time I check).

## Running the test suite

```sh
cd tests/bundle_app
BUNDLE_ID=com.example.myapp-tests ./run_tests.sh
```

`BUNDLE_ID` must match the id on the provisioning profile you created.
The script auto-detects the profile, extracts the team id, picks the
matching codesigning identity, builds with py2app, embeds the profile,
recursively signs, and runs the bundled binary.

To exercise the biometric / passcode paths interactively:

```sh
SECURE_ENCLAVE_INTERACTIVE=1 BUNDLE_ID=... ./run_tests.sh
```

## Troubleshooting

**`SecureEnclaveError: Security framework error (OSStatus -34018)`** —
`errSecMissingEntitlement`. The host process doesn't have the
`keychain-access-groups` entitlement. Your bundle needs to be signed with
the entitlements plist above **and** the matching provisioning profile
must be present at `Contents/embedded.provisionprofile`.

**`Code Signing Error: No matching profile found` (SIGKILL at launch)** —
AMFI refused the binary. Either the profile isn't embedded, the profile's
`application-identifier` doesn't match the entitlements you signed with, or
you claimed entitlements the profile doesn't grant (e.g. `get-task-allow`
on a profile that doesn't include it). Inspect with:

```sh
codesign --display --entitlements :- /path/to/YourApp.app
security cms -D -i /path/to/YourApp.app/Contents/embedded.provisionprofile
```

**`ModuleNotFoundError: No module named 'json'` (inside bundle)** —
py2app's static module graph sometimes misses modules the PyO3 layer
imports dynamically. Add them to `packages` in your `setup.py`:

```python
OPTIONS = {"packages": ["py_secure_enclave", "json"]}
```

## License

Copyright © 2026, Carl Ian Voller. Released under the BSD-3-Clause License.