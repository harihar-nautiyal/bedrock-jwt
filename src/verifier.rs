use serde::Deserialize;
use serde_json::Value;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use base64::{engine::general_purpose, Engine};
use anyhow::{Result};
use thiserror::Error;

/// Final player claims extracted from the last token
#[derive(Debug, Clone, Deserialize)]
pub struct PlayerClaims {
    pub display_name: String,
    pub uuid: String,
    pub xuid: String,
}


/// Custom errors for JWT verification
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing x5u in header")]
    MissingX5U,

    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Invalid EC public key format")]
    InvalidKey,

    #[error("JWT decode error: {0}")]
    JwtDecode(#[from] jsonwebtoken::errors::Error),

    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("Token {0} not signed by trusted Mojang key")]
    MojangKeyMismatch(usize),
}

/// Verify a Mojang x5u JWT chain and return the final player's claims.
pub fn verify_chain(raw_chain: &[&str], mojang_key_b64: &str) -> Result<PlayerClaims, AuthError> {
    // Clean up tokens
    let tokens: Vec<String> = raw_chain
        .iter()
        .map(|t| t.replace('\n', "").replace('\r', ""))
        .collect();

    // Parse first token header
    let header = decode_header(&tokens[0])?;
    let mut next_pub_b64 = header
        .x5u
        .ok_or(AuthError::MissingX5U)?;

    // Validation settings
    let mut validation = Validation::new(Algorithm::ES384);
    validation.validate_exp = false;
    validation.validate_nbf = false;

    for (i, token_str) in tokens.iter().enumerate() {
        let decoding_key = b64_to_key(&next_pub_b64);

        if i == 1 {
            let current_bytes = decode_base64_standard(&next_pub_b64);
            let mojang_bytes = decode_base64_standard(mojang_key_b64);
            if current_bytes != mojang_bytes {
                return Err(AuthError::MojangKeyMismatch(i + 1));
            }
        }

        let token_data = decode::<Value>(token_str, &decoding_key, &validation)?;

        // Update chain for next iteration
        if let Some(id_pub) = token_data.claims.get("identityPublicKey") {
            if let Some(pk_str) = id_pub.as_str() {
                next_pub_b64 = pk_str.to_string();
            }
        }
    }

    // Extract final player data
    let final_token = &tokens[tokens.len() - 1];
    let parts: Vec<&str> = final_token.split('.').collect();
    let payload_bytes = decode_base64_url(parts[1]);
    let final_payload: Value = serde_json::from_slice(&payload_bytes)?;

    let extra = &final_payload["extraData"];
    Ok(PlayerClaims {
        display_name: extra["displayName"].as_str().unwrap_or("").to_string(),
        uuid: extra["identity"].as_str().unwrap_or("").to_string(),
        xuid: extra["XUID"].as_str().unwrap_or("").to_string(),
    })
}


fn b64_to_key(key_b64: &str) -> DecodingKey {
    let key_bytes = decode_base64_standard(key_b64);
    if key_bytes.len() == 97 && key_bytes[0] == 0x04 {
        let x_b64 = general_purpose::STANDARD.encode(&key_bytes[1..49]);
        let y_b64 = general_purpose::STANDARD.encode(&key_bytes[49..97]);
        DecodingKey::from_ec_components(&x_b64, &y_b64)
            .expect("Invalid EC coordinates")
    } else {
        DecodingKey::from_ec_der(&key_bytes)
    }
}

fn decode_base64_standard(b64: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(b64).expect("Invalid base64")
}

fn decode_base64_url(b64: &str) -> Vec<u8> {
    general_purpose::URL_SAFE_NO_PAD.decode(b64).expect("Invalid base64url")
}
