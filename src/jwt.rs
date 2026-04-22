
use crate::error::{Error, Result};
use crate::key_management::SecureEnclaveKey;

use serde_json::{Value, json};

/// ES256 JWT signing and verification using Secure Enclave keys.
///
/// Use Secure Enclave to sign JWT Client Assertions (RFC 7523 / OAuth 2.0 private_key_jwt).
/// The private key stays in the device's Secure Enclave.
///
/// Useful for creating machine specific assertions that cryptographically
/// verify the calling machine. I personally use this for signing assertion for M2M OAuth.
///
///
/// # NOTE
/// The Apple Security framework returns ECDSA signatures in X9.62 DER encoding.
/// JWT ES256 requires raw R||S encoding (exactly 64 bytes for P-256).
/// This module handles that conversion for you.
pub struct SecureEnclaveJWT<'a> {
    key: &'a SecureEnclaveKey,
    headers: serde_json::Value,
    claims: serde_json::Value,
}

impl<'a> SecureEnclaveJWT<'a> {

    /// Create a new SecureEnclaveJWT provider.
    /// The SecureEnclaveJWT provides utilities to help in JWT signing and verification.
    ///
    /// Accepts either a private or a public key handle. Signing requires a
    /// private key and is enforced in [`sign`]; verification works with either.
    pub fn new(key: &'a SecureEnclaveKey) -> Result<Self> {
        Ok(Self {
            key,
            headers: json!({
                "alg": "ES256",
                "typ": "JWT"
            }),
            claims: json!({}),
        })
    }

    /// Write claims into the JWT header. You cannot specify the "alg" or "typ" claim. Doing so is a no-op.
    pub fn with_headers(mut self, headers: serde_json::Value) -> Result<Self> {
        let default_claims = json!({
            "alg": "ES256",
            "typ": "JWT"
        });

        if let (Value::Object(mut dst_map), Value::Object(src_map)) = (default_claims, headers) {
            for (k, v) in src_map {
                dst_map.entry(k.clone()).or_insert(v.clone());
            }

            self.headers = dst_map.into();

            Ok(self)
        } else {
            Err(Error::InvalidJWTClaims)
        }
    }

    /// Write claims into the JWT payload. Merges `claims` into the existing
    /// payload object; later calls take precedence over earlier ones.
    pub fn with_claims(mut self, claims: serde_json::Value) -> Result<Self> {
        if let (Value::Object(mut dst_map), Value::Object(src_map)) =
            (self.claims, claims)
        {
            for (k, v) in src_map {
                dst_map.insert(k, v);
            }
            self.claims = dst_map.into();
            Ok(self)
        } else {
            Err(Error::InvalidJWTClaims)
        }
    }

    /// Sign the JWT with the previously provided headers and claims.
    pub fn sign(&self) -> Result<String> {
        if self.key.is_public_key {
            return Err(Error::InvalidInput(
                "SecureEnclaveJWT::sign() requires a private key. public key was supplied",
            ));
        }
        let header_encoded = base64url(self.headers.to_string().as_bytes());
        let claims_encoded = base64url(self.claims.to_string().as_bytes());

        let signing_input = format!("{}.{}", header_encoded, claims_encoded);

        // Sign returns DER; JWT ES256 needs raw R||S (64 bytes).
        let der_sig = self.key.sign(signing_input.as_bytes())?;
        let raw_sig = der_to_raw_rs(&der_sig).ok_or(Error::InvalidInput(
            "malformed DER ECDSA signature from Secure Enclave",
        ))?;

        Ok(format!("{}.{}", signing_input, base64url(&raw_sig)))
    }

    /// Extract a refernce to the Public Key from Secure Enclave.
    // pub fn get_public_key(&self) -> Result<SecureEnclaveKey> {
    //     self.key.public_key()
    // }

    /// Verifies if the token passed has a valid signature.
    pub fn verify(&self, token: &str) -> Result<()> {
        let (signing_input, sig_b64) = split_jwt(token).ok_or(Error::InvalidInput(
            "JWT must have exactly three dot-separated parts",
        ))?;

        let raw_sig = base64url_decode(sig_b64)
            .ok_or(Error::InvalidInput("invalid base64url in JWT signature"))?;

        // Security framework verify expects DER; JWT signature is raw R||S.
        let der_sig = raw_rs_to_der(&raw_sig).ok_or(Error::InvalidInput(
            "JWT ES256 signature must be 64 bytes (R||S)",
        ))?;

        let is_valid = self.key.verify(signing_input.as_bytes(), &der_sig)?;

        if !is_valid {
            Err(Error::InvalidJWTSignature)
        } else {
            Ok(())
        }
    }

    /// Verifies if the token passed has a valid signature and returns the header and body claims.
    pub fn verify_and_get_payload(
        &self,
        token: &str,
    ) -> Result<(serde_json::Value, serde_json::Value)> {
        self.verify(token)?;

        let mut split_token = token.splitn(3, ".");

        // next() advances once; nth(1) would skip over the claims and read the
        // signature. A valid token is guaranteed to have both parts.
        let headers = decode_payload_section(split_token.next().unwrap())?;
        let claims = decode_payload_section(split_token.next().unwrap())?;

        Ok((headers, claims))
    }
}

fn decode_payload_section(section: &str) -> Result<serde_json::Value> {
    // let raw_str_bytes = base64url_decode(section);
    if let Some(raw_str_bytes) = base64url_decode(section) {
        Ok(serde_json::from_slice(&raw_str_bytes).map_err(|_| Error::InvalidJWTClaims)?)
    } else {
        Err(Error::InvalidJWTClaims)
    }
}

fn der_to_raw_rs(der: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    if *der.get(i)? != 0x30 {
        return None;
    }
    i += 1;

    // Length byte: 0x81 means the next byte holds the actual length
    if *der.get(i)? == 0x81 {
        i += 2;
    } else {
        i += 1;
    }

    let (r, i) = read_der_int(der, i)?;
    let (s, _) = read_der_int(der, i)?;

    let mut out = [0u8; 64];
    // Left-pad R into bytes 0..32, skipping any DER-added leading 0x00
    let r_src = if r.len() > 32 { &r[r.len() - 32..] } else { r };
    out[32 - r_src.len()..32].copy_from_slice(r_src);
    // Left-pad S into bytes 32..64
    let s_src = if s.len() > 32 { &s[s.len() - 32..] } else { s };
    out[64 - s_src.len()..64].copy_from_slice(s_src);

    Some(out.to_vec())
}

fn read_der_int(der: &[u8], mut i: usize) -> Option<(&[u8], usize)> {
    if *der.get(i)? != 0x02 {
        return None;
    }
    i += 1;
    let len = *der.get(i)? as usize;
    i += 1;
    let val = der.get(i..i + len)?;
    Some((val, i + len))
}

fn raw_rs_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.len() != 64 {
        return None;
    }

    let r = der_int(&raw[..32]);
    let s = der_int(&raw[32..]);

    let inner_len = 2 + r.len() + 2 + s.len();
    let mut der = Vec::with_capacity(2 + inner_len);
    der.push(0x30);
    der.push(inner_len as u8);
    der.push(0x02);
    der.push(r.len() as u8);
    der.extend_from_slice(&r);
    der.push(0x02);
    der.push(s.len() as u8);
    der.extend_from_slice(&s);
    Some(der)
}

fn der_int(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[start..];
    let mut out = Vec::with_capacity(trimmed.len() + 1);
    if trimmed[0] & 0x80 != 0 {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn base64url(bytes: &[u8]) -> String {
    const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4 + 2) / 3);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        out.push(CHARS[b0 >> 2] as char);
        out.push(CHARS[(b0 & 3) << 4 | b1 >> 4] as char);
        if chunk.len() > 1 {
            out.push(CHARS[(b1 & 15) << 2 | b2 >> 6] as char);
        }
        if chunk.len() > 2 {
            out.push(CHARS[b2 & 63] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    let pad = (4 - s.len() % 4) % 4;
    let mut buf: Vec<u8> = s
        .as_bytes()
        .iter()
        .map(|&b| match b {
            b'-' => b'+',
            b'_' => b'/',
            other => other,
        })
        .collect();
    buf.extend(std::iter::repeat(b'=').take(pad));

    if buf.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(buf.len() * 3 / 4);
    for chunk in buf.chunks(4) {
        let a = b64_val(chunk[0])? as u32;
        let b = b64_val(chunk[1])? as u32;
        out.push(((a << 2) | (b >> 4)) as u8);
        if chunk[2] != b'=' {
            let c = b64_val(chunk[2])? as u32;
            out.push(((b << 4) | (c >> 2)) as u8);
            if chunk[3] != b'=' {
                let d = b64_val(chunk[3])? as u32;
                out.push(((c << 6) | d) as u8);
            }
        }
    }
    Some(out)
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(26 + b - b'a'),
        b'0'..=b'9' => Some(52 + b - b'0'),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn split_jwt(token: &str) -> Option<(&str, &str)> {
    let last_dot = token.rfind('.')?;
    if token[..last_dot].contains('.') {
        Some((&token[..last_dot], &token[last_dot + 1..]))
    } else {
        None
    }
}
