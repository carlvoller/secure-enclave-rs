"""
Non-interactive tests for the py_secure_enclave SecureEnclaveKey class.

All tests use AccessControlFlags.EMPTY so no biometric / passcode prompts fire.
Interactive paths (BIOMETRY_ANY, DEVICE_PASSCODE, authenticate()) are exercised
separately by InteractiveTests, which is skipped by default.

These tests require the process to be code-signed with the keychain-access-groups
entitlement — run them via tests/bundle_app/run_tests.sh.
"""
from __future__ import annotations

import os
import time
import unittest
import uuid

from py_secure_enclave import (
    AccessControlFlags,
    KeyNotFoundError,
    SecureEnclaveError,
    SecureEnclaveJWT,
    SecureEnclaveKey,
)

# Namespace every keychain tag under the bundle id set by run_tests.sh so
# the Info.plist, the entitlements, and any leaked tags all trace back to
# the same value.
_BUNDLE_ID = os.environ.get("BUNDLE_ID")
if not _BUNDLE_ID:
    raise RuntimeError(
        "BUNDLE_ID env var is required (set by tests/bundle_app/run_tests.sh)."
    )
TAG_PREFIX = _BUNDLE_ID.encode() + b"."


def fresh_tag(name: str) -> bytes:
    return TAG_PREFIX + name.encode() + b"." + uuid.uuid4().hex.encode()


class TestAccessControlFlags(unittest.TestCase):
    def test_empty_is_zero(self):
        self.assertEqual(int(AccessControlFlags.EMPTY), 0)

    def test_or_combines_bits(self):
        combined = AccessControlFlags.BIOMETRY_ANY | AccessControlFlags.DEVICE_PASSCODE
        self.assertEqual(
            int(combined),
            int(AccessControlFlags.BIOMETRY_ANY) | int(AccessControlFlags.DEVICE_PASSCODE),
        )

    def test_and_masks_bits(self):
        combined = AccessControlFlags.BIOMETRY_ANY | AccessControlFlags.DEVICE_PASSCODE
        masked = combined & AccessControlFlags.BIOMETRY_ANY
        self.assertEqual(int(masked), int(AccessControlFlags.BIOMETRY_ANY))

    def test_equality(self):
        self.assertEqual(
            AccessControlFlags.BIOMETRY_ANY | AccessControlFlags.DEVICE_PASSCODE,
            AccessControlFlags.DEVICE_PASSCODE | AccessControlFlags.BIOMETRY_ANY,
        )


class SEKeyTestBase(unittest.TestCase):
    """Generates a fresh non-interactive SecureEnclaveKey for each test and cleans it up."""

    def setUp(self) -> None:
        self.tag = fresh_tag(self.id().rsplit(".", 1)[-1])
        try:
            SecureEnclaveKey.remove_by_tag(self.tag)
        except KeyNotFoundError:
            pass
        self.key = SecureEnclaveKey.generate(
            tag=self.tag,
            access_flags=AccessControlFlags.EMPTY,
            permanent=True,
        )

    def tearDown(self) -> None:
        try:
            SecureEnclaveKey.remove_by_tag(self.tag)
        except KeyNotFoundError:
            pass


class TestGenerateRetrieveRemove(SEKeyTestBase):
    def test_generate_returns_handle(self):
        self.assertIsInstance(self.key, SecureEnclaveKey)

    def test_get_retrieves_same_public_key(self):
        fetched = SecureEnclaveKey.get(self.tag)
        self.assertEqual(fetched.public_key_bytes(), self.key.public_key_bytes())

    def test_get_missing_raises(self):
        with self.assertRaises(KeyNotFoundError):
            SecureEnclaveKey.get(fresh_tag("definitely-missing"))

    def test_remove_by_tag_deletes(self):
        SecureEnclaveKey.remove_by_tag(self.tag)
        with self.assertRaises(KeyNotFoundError):
            SecureEnclaveKey.get(self.tag)
        # Second removal now fails.
        with self.assertRaises(KeyNotFoundError):
            SecureEnclaveKey.remove_by_tag(self.tag)

    def test_remove_handle_deletes(self):
        # Regenerate into a separate handle so we can call .remove() on it.
        key = SecureEnclaveKey.get(self.tag)
        key.remove()
        with self.assertRaises(KeyNotFoundError):
            SecureEnclaveKey.get(self.tag)


class TestPublicKey(SEKeyTestBase):
    def test_public_key_bytes_length(self):
        pub = self.key.public_key_bytes()
        self.assertEqual(len(pub), 65, "P-256 uncompressed point is 65 bytes")
        self.assertEqual(pub[0], 0x04, "uncompressed point prefix")

    def test_public_key_handle_roundtrip(self):
        pub_handle = self.key.public_key()
        self.assertEqual(pub_handle.public_key_bytes(), self.key.public_key_bytes())

    def test_from_public_key_bytes_roundtrip(self):
        raw = self.key.public_key_bytes()
        reconstructed = SecureEnclaveKey.from_public_key_bytes(raw)
        self.assertEqual(reconstructed.public_key_bytes(), raw)

    def test_from_public_key_bytes_rejects_garbage(self):
        with self.assertRaises(SecureEnclaveError):
            SecureEnclaveKey.from_public_key_bytes(b"\x04" + b"\x00" * 64)


class TestSignVerify(SEKeyTestBase):
    def test_sign_and_verify(self):
        msg = b"hello from the secure enclave"
        sig = self.key.sign(msg)
        self.assertIsInstance(sig, bytes)
        self.assertGreater(len(sig), 0)
        self.assertTrue(self.key.verify(msg, sig))

    def test_verify_fails_on_tampered_message(self):
        sig = self.key.sign(b"original message")
        self.assertFalse(self.key.verify(b"tampered message", sig))

    def test_verify_fails_on_tampered_signature(self):
        sig = bytearray(self.key.sign(b"msg"))
        sig[-1] ^= 0x01
        self.assertFalse(self.key.verify(b"msg", bytes(sig)))

    def test_signature_nondeterministic(self):
        # ECDSA with a random k produces different signatures each call.
        sig1 = self.key.sign(b"same input")
        sig2 = self.key.sign(b"same input")
        self.assertNotEqual(sig1, sig2)
        self.assertTrue(self.key.verify(b"same input", sig1))
        self.assertTrue(self.key.verify(b"same input", sig2))

    def test_public_key_handle_verifies(self):
        sig = self.key.sign(b"payload")
        pub = self.key.public_key()
        self.assertTrue(pub.verify(b"payload", sig))

    def test_verify_via_from_public_key_bytes(self):
        raw = self.key.public_key_bytes()
        pub = SecureEnclaveKey.from_public_key_bytes(raw)
        sig = self.key.sign(b"msg")
        self.assertTrue(pub.verify(b"msg", sig))


class TestEncryptDecrypt(SEKeyTestBase):
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"Hello, ECIES world!"
        ct = self.key.encrypt(plaintext)
        self.assertNotEqual(ct, plaintext)
        self.assertEqual(self.key.decrypt(ct), plaintext)

    def test_encryption_is_randomised(self):
        msg = b"deterministic input"
        ct1 = self.key.encrypt(msg)
        ct2 = self.key.encrypt(msg)
        self.assertNotEqual(ct1, ct2, "ECIES uses a random ephemeral key / IV")
        self.assertEqual(self.key.decrypt(ct1), msg)
        self.assertEqual(self.key.decrypt(ct2), msg)

    def test_encrypt_via_public_key_handle(self):
        msg = b"encrypt via public handle"
        pub = self.key.public_key()
        ct = pub.encrypt(msg)
        self.assertEqual(self.key.decrypt(ct), msg)

    def test_encrypt_via_reconstructed_public_key(self):
        msg = b"encrypt via from_public_key_bytes"
        pub = SecureEnclaveKey.from_public_key_bytes(self.key.public_key_bytes())
        ct = pub.encrypt(msg)
        self.assertEqual(self.key.decrypt(ct), msg)

    def test_decrypt_garbage_raises(self):
        with self.assertRaises(SecureEnclaveError):
            self.key.decrypt(b"not a real ECIES blob")


class TestKeyExchange(unittest.TestCase):
    def setUp(self) -> None:
        self.alice_tag = fresh_tag("alice")
        self.bob_tag = fresh_tag("bob")
        self.alice = SecureEnclaveKey.generate(
            tag=self.alice_tag, access_flags=AccessControlFlags.EMPTY, permanent=True
        )
        self.bob = SecureEnclaveKey.generate(
            tag=self.bob_tag, access_flags=AccessControlFlags.EMPTY, permanent=True
        )

    def tearDown(self) -> None:
        for tag in (self.alice_tag, self.bob_tag):
            try:
                SecureEnclaveKey.remove_by_tag(tag)
            except KeyNotFoundError:
                pass

    def test_shared_secret_matches(self):
        alice_secret = self.alice.derive_shared_secret(self.bob.public_key_bytes())
        bob_secret = self.bob.derive_shared_secret(self.alice.public_key_bytes())
        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(len(alice_secret), 32)

    def test_shared_secret_custom_length(self):
        secret = self.alice.derive_shared_secret(self.bob.public_key_bytes(), output_len=16)
        self.assertEqual(len(secret), 16)

    def test_shared_info_changes_output(self):
        pk = self.bob.public_key_bytes()
        s1 = self.alice.derive_shared_secret(pk, output_len=32, shared_info=b"context-A")
        s2 = self.alice.derive_shared_secret(pk, output_len=32, shared_info=b"context-B")
        self.assertNotEqual(s1, s2)
        s1_again = self.alice.derive_shared_secret(pk, output_len=32, shared_info=b"context-A")
        self.assertEqual(s1, s1_again)


class TestSecureEnclaveJWT(SEKeyTestBase):
    def _build(self, **claims) -> str:
        jwt = SecureEnclaveJWT()
        jwt.with_headers({"kid": "test-key"})
        jwt.with_claims(claims)
        return jwt.sign(self.key)

    def test_sign_returns_compact_form(self):
        now = int(time.time())
        token = self._build(iss="tester", iat=now, exp=now + 60)
        self.assertEqual(token.count("."), 2)

    def test_verify_accepts_valid_token(self):
        now = int(time.time())
        token = self._build(iss="tester", iat=now, exp=now + 60)
        SecureEnclaveJWT().verify(self.key, token)  # no exception = pass

    def test_verify_and_decode_roundtrip(self):
        now = int(time.time())
        token = self._build(iss="tester", sub="user-42", iat=now, exp=now + 60)
        headers, claims = SecureEnclaveJWT().verify_and_decode(self.key, token)
        self.assertEqual(headers.get("alg"), "ES256")
        self.assertEqual(headers.get("kid"), "test-key")
        self.assertEqual(claims["iss"], "tester")
        self.assertEqual(claims["sub"], "user-42")

    def test_verify_rejects_tampered_signature(self):
        now = int(time.time())
        token = self._build(iss="tester", iat=now, exp=now + 60)
        head, payload, sig = token.split(".")
        tampered_sig = "A" + sig[1:] if sig[0] != "A" else "B" + sig[1:]
        tampered = f"{head}.{payload}.{tampered_sig}"
        with self.assertRaises(SecureEnclaveError):
            SecureEnclaveJWT().verify(self.key, tampered)

    def test_verify_with_public_key_handle(self):
        now = int(time.time())
        token = self._build(iss="tester", iat=now, exp=now + 60)
        pub = self.key.public_key()
        SecureEnclaveJWT().verify(pub, token)


@unittest.skipUnless(
    os.environ.get("SECURE_ENCLAVE_INTERACTIVE") == "1",
    "Set SECURE_ENCLAVE_INTERACTIVE=1 to exercise biometric / passcode prompts.",
)
class InteractiveTests(unittest.TestCase):
    """Interactive paths. Skipped by default so the suite can run unattended."""

    def test_biometric_sign(self):
        tag = fresh_tag("interactive-bio")
        try:
            SecureEnclaveKey.remove_by_tag(tag)
        except KeyNotFoundError:
            pass
        key = SecureEnclaveKey.generate(
            tag=tag,
            access_flags=AccessControlFlags.BIOMETRY_ANY,
            permanent=True,
        )
        try:
            sig = key.sign(b"authenticated payload")
            self.assertTrue(key.verify(b"authenticated payload", sig))
        finally:
            SecureEnclaveKey.remove_by_tag(tag)


if __name__ == "__main__":
    unittest.main(verbosity=2)
