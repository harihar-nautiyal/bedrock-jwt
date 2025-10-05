//! # JWT Verifier for Minecraft: Bedrock Edition
//!
//! This module provides the core functionality for verifying the chain of JWT tokens
//! sent by a Minecraft: Bedrock Edition client. It handles cryptographic signature
//! verification, public key extraction, and decoding of player data.

use base64::{engine::general_purpose, Engine as _};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use p384::PublicKey;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

/// Represents the claims extracted from the player's JWT token.
///
/// This struct contains the player's display name, UUID, and XUID.
#[derive(Debug, Deserialize)]
pub struct PlayerClaims {
    /// The player's display name (in-game name).
    #[serde(rename = "displayName")]
    pub display_name: String,
    /// The player's unique identifier (UUID).
    #[serde(rename = "identity")]
    pub uuid: String,
    /// The player's Xbox User ID (XUID).
    #[serde(rename = "XUID")]
    pub xuid: String,
}

/// Represents the possible errors that can occur during JWT verification.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Indicates that a JWT token has an invalid format (not enough parts).
    #[error("Invalid token format")]
    InvalidTokenFormat,
    /// Indicates that the 'x5u' (X.509 URL) header parameter is missing from a token.
    #[error("x5u not found in header")]
    MissingX5U,
    /// Indicates a failure in Base64 decoding.
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    /// Indicates a failure in parsing JSON data.
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    /// Indicates a failure in building a public key from its representation.
    #[error("Public key build failed: {0}")]
    PublicKeyBuild(String),
    /// Indicates that the token was not signed by the trusted Mojang public key.
    #[error("Token not signed by trusted Mojang key")]
    MojangKeyMismatch,
    /// Indicates that the token's signature is invalid.
    #[error("Invalid signature")]
    InvalidSignature,
    /// Indicates an error related to ECDSA signature operations.
    #[error("ECDSA signature error: {0}")]
    Ecdsa(#[from] ecdsa::Error),
}

/// Decodes a Base64 URL-safe encoded string with no padding.
///
/// # Arguments
///
/// * `s` - The Base64 URL-safe encoded string to decode.
///
/// # Returns
///
/// A `Result` containing the decoded bytes or a `base64::DecodeError`.
pub fn decode_b64_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

/// Decodes a standard Base64 encoded string.
///
/// # Arguments
///
/// * `s` - The standard Base64 encoded string to decode.
///
/// # Returns
///
/// A `Result` containing the decoded bytes or a `base64::DecodeError`.
pub fn decode_b64_standard(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

/// Builds a P-384 public key from a Base64 encoded string.
///
/// This function supports several common public key formats.
///
/// # Arguments
///
/// * `b64` - The Base64 encoded public key.
///
/// # Returns
///
/// A `Result` containing the `p384::PublicKey` or an `AuthError`.
pub fn build_public_key_from_b64(b64: &str) -> Result<PublicKey, AuthError> {
    let bytes = decode_b64_standard(b64)?;

    if !bytes.is_empty() && bytes[0] == 0x30 {
        PublicKey::from_public_key_der(&bytes).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else if bytes.len() == 97 && bytes[0] == 0x04 {
        PublicKey::from_sec1_bytes(&bytes).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else if bytes.len() == 96 {
        let mut sec1 = Vec::with_capacity(97);
        sec1.push(0x04u8);
        sec1.extend_from_slice(&bytes);
        PublicKey::from_sec1_bytes(&sec1).map_err(|e| AuthError::PublicKeyBuild(e.to_string()))
    } else {
        Err(AuthError::PublicKeyBuild(format!(
            "Unsupported key format/length: {} bytes",
            bytes.len()
        )))
    }
}

/// Converts a JOSE (JWS) format signature to a DER-encoded signature.
///
/// # Arguments
///
/// * `jose_sig` - The signature in JOSE format.
///
/// # Returns
///
/// A `Result` containing the DER-encoded signature or an `AuthError`.
pub fn jose_sig_to_der(jose_sig: &[u8]) -> Result<Vec<u8>, AuthError> {
    if jose_sig.len() % 2 != 0 {
        return Err(AuthError::InvalidSignature);
    }
    let n = jose_sig.len() / 2;
    let r = &jose_sig[..n];
    let s = &jose_sig[n..];

    fn encode_integer_be(bytes: &[u8]) -> Vec<u8> {
        let mut i = 0usize;
        while i < bytes.len() && bytes[i] == 0 {
            i += 1;
        }
        let mut v = bytes[i..].to_vec();
        if v.is_empty() {
            v.push(0u8);
        }
        if v[0] & 0x80 != 0 {
            let mut pref = vec![0u8];
            pref.extend_from_slice(&v);
            pref
        } else {
            v
        }
    }

    let r_enc = encode_integer_be(r);
    let s_enc = encode_integer_be(s);

    let mut seq = Vec::new();
    seq.push(0x02);
    seq.push(r_enc.len() as u8);
    seq.extend_from_slice(&r_enc);
    seq.push(0x02);
    seq.push(s_enc.len() as u8);
    seq.extend_from_slice(&s_enc);

    let mut der = Vec::new();
    der.push(0x30);
    der.push(seq.len() as u8);
    der.extend_from_slice(&seq);

    Ok(der)
}

/// Decodes the header of a JWT and extracts the 'x5u' (X.509 URL) value.
///
/// # Arguments
///
/// * `header_b64` - The Base64 URL-safe encoded header of the JWT.
///
/// # Returns
///
/// A `Result` containing the 'x5u' value as a string or an `AuthError`.
pub fn decode_header_get_x5u(header_b64: &str) -> Result<String, AuthError> {
    let header_bytes = decode_b64_url_nopad(header_b64)?;
    let header_json: Value = serde_json::from_slice(&header_bytes)?;
    if let Some(x5u) = header_json.get("x5u") {
        if let Some(s) = x5u.as_str() {
            return Ok(s.to_string());
        }
    }
    Err(AuthError::MissingX5U)
}

/// Verifies a chain of JWT tokens from a Minecraft: Bedrock Edition client.
///
/// This function performs the following steps:
/// 1. Decodes and verifies each token in the chain.
/// 2. Ensures that the chain is properly linked, with each token being signed by the key from the previous one.
/// 3. Verifies that the second token in the chain is signed by the trusted Mojang public key.
/// 4. Extracts and returns the player's claims from the final token in the chain.
///
/// # Arguments
///
/// * `raw_chain` - A slice of strings, where each string is a raw JWT token.
/// * `mojang_key_b64` - The Base64 encoded Mojang public key.
///
/// # Returns
///
/// A `Result` containing the `PlayerClaims` if verification is successful, or an `AuthError` if it fails.
pub fn verify_chain(raw_chain: &[&str], mojang_key_b64: &str) -> Result<PlayerClaims, AuthError> {
    let tokens: Vec<String> = raw_chain
        .iter()
        .map(|t| t.replace('\n', "").replace('\r', ""))
        .collect();

    let first_parts: Vec<&str> = tokens[0].split('.').collect();
    if first_parts.len() != 3 {
        return Err(AuthError::InvalidTokenFormat);
    }
    let mut next_public_b64 = decode_header_get_x5u(first_parts[0])?;

    let mojang_pk = build_public_key_from_b64(mojang_key_b64)?;

    for (i, token) in tokens.iter().enumerate() {
        let current_pub = build_public_key_from_b64(&next_public_b64)?;

        if i == 1 {
            let cur_der = current_pub.to_public_key_der().map_err(|e| AuthError::PublicKeyBuild(e.to_string()))?;
            let moj_der = mojang_pk.to_public_key_der().map_err(|e| AuthError::PublicKeyBuild(e.to_string()))?;
            if cur_der.as_ref() != moj_der.as_ref() {
                return Err(AuthError::MojangKeyMismatch);
            }
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidTokenFormat);
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signing_input_bytes = signing_input.as_bytes();

        let sig_bytes = decode_b64_url_nopad(parts[2])?;
        let der_sig = jose_sig_to_der(&sig_bytes)?;

        let verifying_key = VerifyingKey::from(&current_pub);
        let signature = EcdsaSignature::from_der(&der_sig)?;

        if verifying_key.verify(signing_input_bytes, &signature).is_err() {
            return Err(AuthError::InvalidSignature);
        }

        let payload_bytes = decode_b64_url_nopad(parts[1])?;
        let payload_json: Value = serde_json::from_slice(&payload_bytes)?;
        if let Some(id_pk) = payload_json.get("identityPublicKey") {
            if let Some(s) = id_pk.as_str() {
                next_public_b64 = s.to_string();
            }
        }
    }

    let final_token = &tokens[tokens.len() - 1];
    let parts: Vec<&str> = final_token.split('.').collect();
    let payload = decode_b64_url_nopad(parts[1])?;
    let v: Value = serde_json::from_slice(&payload)?;
    let extra_data: PlayerClaims = serde_json::from_value(v["extraData"].clone())?;

    Ok(extra_data)
}