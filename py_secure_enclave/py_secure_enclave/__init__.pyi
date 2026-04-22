"""
py_secure_enclave — Python bindings for macOS Secure Enclave operations.

All cryptographic operations involving private keys are performed inside the
Secure Enclave; private key material never leaves the hardware.

Requires macOS with a Secure Enclave (Apple Silicon or Intel T2 and later).
"""

from __future__ import annotations

class SecureEnclaveError(Exception):
    """Base exception for all Secure Enclave errors."""

class KeyNotFoundError(SecureEnclaveError):
    """Raised when no matching keychain item exists (errSecItemNotFound)."""

class AuthFailedError(SecureEnclaveError):
    """Raised when biometric or passcode authentication fails."""

class UserCancelledError(SecureEnclaveError):
    """Raised when the user dismisses the authentication prompt."""

class AccessControlFlags:
    """
    Bitflag controlling how a Secure Enclave key is protected.

    Combine with ``|``::

        flags = AccessControlFlags.BIOMETRY_ANY | AccessControlFlags.DEVICE_PASSCODE

    ``PRIVATE_KEY_USAGE`` is always included automatically by
    :meth:`SecureEnclaveKey.generate`.
    """

    EMPTY: AccessControlFlags
    """No additional authentication beyond device unlock."""

    USER_PRESENCE: AccessControlFlags
    """Biometry (any enrolled finger / face) or device passcode."""

    BIOMETRY_ANY: AccessControlFlags
    """Any enrolled Touch ID finger or Face ID. Survives enrolment changes."""

    BIOMETRY_CURRENT_SET: AccessControlFlags
    """
    Biometry tied to the current enrolment set.
    The key becomes inaccessible if biometrics are re-enrolled.
    """

    DEVICE_PASSCODE: AccessControlFlags
    """Device passcode required."""

    WATCH: AccessControlFlags
    """Paired Apple Watch (deprecated by Apple)."""

    OR: AccessControlFlags
    """Any *one* of the combined requirements must be satisfied."""

    AND: AccessControlFlags
    """*All* combined requirements must be satisfied."""

    PRIVATE_KEY_USAGE: AccessControlFlags
    """Restricts usage to private-key operations (always added automatically)."""

    APPLICATION_PASSWORD: AccessControlFlags
    """Enables an app-supplied password as a second factor."""

    def __init__(self, bits: int) -> None: ...
    def __or__(self, other: AccessControlFlags) -> AccessControlFlags: ...
    def __ror__(self, other: AccessControlFlags) -> AccessControlFlags: ...
    def __and__(self, other: AccessControlFlags) -> AccessControlFlags: ...
    def __int__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

class SecureEnclaveKey:
    """
    A handle to a Secure Enclave key.

    For SE-backed private keys the key material never leaves the hardware.
    All cryptographic operations are performed inside the Secure Enclave.

    .. warning::
       ``SecureEnclaveKey`` is not thread-safe and must only be used from the
       thread on which it was created.
    """

    @staticmethod
    def generate(
        tag: bytes,
        access_flags: AccessControlFlags | None = None,
        permanent: bool = True,
    ) -> SecureEnclaveKey:
        """
        Generate a new Secure Enclave–backed P-256 key pair.

        :param tag: Unique byte tag used to retrieve the key later.
        :param access_flags: Protection policy; defaults to device-unlock only.
            Use :class:`AccessControlFlags` to require biometry or a passcode.
        :param permanent: When ``True`` (default) the key is persisted in the
            keychain across app launches.
        :raises SecureEnclaveError: If key generation fails (e.g. no SE present).
        """
        ...

    @staticmethod
    def get(tag: bytes) -> SecureEnclaveKey:
        """
        Retrieve an existing SE private key from the keychain.

        :param tag: The tag used when the key was generated.
        :raises KeyNotFoundError: If no matching key exists.
        """
        ...

    @staticmethod
    def remove_by_tag(tag: bytes) -> None:
        """
        Delete the keychain entry for the key with the given ``tag``.

        Useful for cleanup at startup without needing an existing handle.

        :raises KeyNotFoundError: If no matching entry exists.
        """
        ...

    @staticmethod
    def from_public_key_bytes(bytes: bytes) -> SecureEnclaveKey:
        """
        Reconstruct a public key handle from raw X9.62 uncompressed bytes
        (``04 || X || Y``, 65 bytes for P-256).

        Use this to verify signatures or run ECDH when you only have the peer's
        public key bytes, not a keychain handle.

        :raises SecureEnclaveError: If the bytes are not a valid P-256 point.
        """
        ...

    def remove(self) -> None:
        """
        Delete the keychain entry for this key.

        :raises KeyNotFoundError: If the entry no longer exists.
        """
        ...

    def public_key(self) -> SecureEnclaveKey:
        """
        Return the public-key counterpart of this private key.

        :raises SecureEnclaveError: If called on a public key handle.
        """
        ...

    def public_key_bytes(self) -> bytes:
        """
        Export the public key as 65-byte X9.62 uncompressed bytes
        (``04 || X || Y``). Share these with a server during enrollment.
        """
        ...

    def sign(self, data: bytes) -> bytes:
        """
        Sign ``data`` with ECDSA-SHA256 using this private key.

        For keys with biometric or passcode protection the OS will present the
        authentication prompt before signing.

        :returns: DER-encoded ECDSA signature bytes.
        :raises AuthFailedError: If authentication fails.
        :raises UserCancelledError: If the user dismisses the prompt.
        """
        ...

    def verify(self, data: bytes, signature: bytes) -> bool:
        """
        Verify a DER-encoded ECDSA-SHA256 ``signature`` over ``data``.

        Accepts both private and public key handles.

        :returns: ``True`` if the signature is valid, ``False`` otherwise.
        """
        ...

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt ``plaintext`` using ECIES (X9.63/SHA-256/AES-GCM, random IV).

        Accepts both private and public key handles; the public half is used
        automatically for private keys.

        :returns: ECIES ciphertext blob.
        """
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt an ECIES ``ciphertext`` produced by :meth:`encrypt`.

        Requires the private key. Decryption runs inside the SE.

        :raises AuthFailedError: If the key requires authentication and it fails.
        """
        ...

    def derive_shared_secret(
        self,
        peer_public_key_bytes: bytes,
        output_len: int = 32,
        shared_info: bytes | None = None,
    ) -> bytes:
        """
        Perform ECDH key exchange with a peer and return derived key material.

        Uses X9.63 KDF with SHA-256.

        :param peer_public_key_bytes: Peer's 65-byte X9.62 uncompressed public key.
        :param output_len: Number of output bytes. Default 32 (AES-256 key size).
        :param shared_info: Optional context for domain separation. Pass ``b""``
            or omit for no context.
        :returns: ``output_len`` bytes of shared key material.
        """
        ...

    def authenticate(self) -> None:
        """
        Trigger biometric or passcode authentication by signing an internal
        challenge. The OS presents Face ID / Touch ID or the passcode prompt.

        Returns on success; raises on failure.

        :raises AuthFailedError: If authentication fails.
        :raises UserCancelledError: If the user cancels the prompt.
        """
        ...

# SecureEnclaveJWT

class SecureEnclaveJWT:
    """
    Builder for ES256 JWTs signed by a Secure Enclave private key.

    The key is passed at :meth:`sign` time rather than at construction, so the
    builder can be prepared independently of the key handle.

    Example — signing an OAuth2 client assertion::

        import time
        from py_secure_enclave import SecureEnclaveKey, SecureEnclaveJWT

        key = SecureEnclaveKey.get(b"my-service-key")
        now = int(time.time())

        jwt = SecureEnclaveJWT()
        jwt.with_headers({"kid": "key-id"})
        jwt.with_claims({
            "iss": "my-client-id",
            "aud": ["https://example.com/token"],
            "iat": now,
            "exp": now + 300,
        })
        token = jwt.sign(key)
        # POST token as client_assertion in the token request
    """

    def __init__(self) -> None:
        """Create a new JWT builder with default ES256 headers."""
        ...

    def with_headers(self, headers: dict) -> None:
        """
        Merge additional JWT header fields.

        ``"alg"`` and ``"typ"`` are protected and cannot be overwritten.
        Call multiple times to accumulate fields.

        :param headers: JSON-serializable ``dict`` of header fields.
        """
        ...

    def with_claims(self, claims: dict) -> None:
        """
        Merge payload claims into the JWT body.

        Later calls overwrite earlier ones for the same key.

        :param claims: JSON-serializable ``dict`` of claim values.
        """
        ...

    def sign(self, key: SecureEnclaveKey) -> str:
        """
        Sign the JWT with ``key`` and return the compact serialization
        ``header.payload.signature``.

        :param key: A private :class:`SecureEnclaveKey`.
        :returns: Compact JWT string.
        :raises AuthFailedError: If authentication fails.
        :raises UserCancelledError: If the user cancels the prompt.
        """
        ...

    def verify(self, key: SecureEnclaveKey, token: str) -> None:
        """
        Verify the ES256 signature of ``token``.

        Does **not** validate claims (``exp``, ``iss``, ``aud``).

        :param key: Public or private :class:`SecureEnclaveKey`.
        :param token: Compact JWT string.
        :raises SecureEnclaveError: If the signature is invalid or malformed.
        """
        ...

    def verify_and_decode(
        self,
        key: SecureEnclaveKey,
        token: str,
    ) -> tuple[dict, dict]:
        """
        Verify ``token`` and decode its header and payload.

        :param key: Public or private :class:`SecureEnclaveKey`.
        :param token: Compact JWT string.
        :returns: ``(headers_dict, claims_dict)`` tuple.
        :raises SecureEnclaveError: If the signature is invalid or malformed.
        """
        ...
