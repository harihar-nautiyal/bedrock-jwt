use base64::{engine::general_purpose, Engine as _};
use p384::pkcs8::{DecodePublicKey, EncodePublicKey};
use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use p384::PublicKey;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct PlayerClaims {
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "identity")]
    pub uuid: String,
    #[serde(rename = "XUID")]
    pub xuid: String,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid token format")]
    InvalidTokenFormat,
    #[error("x5u not found in header")]
    MissingX5U,
    #[error("Base64 decoding failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),
    #[error("Public key build failed: {0}")]
    PublicKeyBuild(String),
    #[error("Token not signed by trusted Mojang key")]
    MojangKeyMismatch,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("ECDSA signature error: {0}")]
    Ecdsa(#[from] ecdsa::Error),
}

pub fn decode_b64_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

pub fn decode_b64_standard(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

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
