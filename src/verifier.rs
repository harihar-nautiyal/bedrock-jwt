use base64::{engine::general_purpose, Engine as _};
use p384::pkcs8::DecodePublicKey;
use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use p384::PublicKey;
use serde_json::Value;
use std::process::exit;
use ecdsa::elliptic_curve::pkcs8::EncodePublicKey;


fn decode_b64_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

fn decode_b64_standard(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

fn build_public_key_from_b64(b64: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let bytes = decode_b64_standard(b64)?;

    if !bytes.is_empty() && bytes[0] == 0x30 {
        let pk = PublicKey::from_public_key_der(&bytes)?;
        Ok(pk)
    } else if bytes.len() == 97 && bytes[0] == 0x04 {
        Ok(PublicKey::from_sec1_bytes(&bytes)?)
    } else if bytes.len() == 96 {
        let mut sec1 = Vec::with_capacity(97);
        sec1.push(0x04u8);
        sec1.extend_from_slice(&bytes);
        Ok(PublicKey::from_sec1_bytes(&sec1)?)
    } else {
        Err(format!("Unsupported key format/length: {} bytes", bytes.len()).into())
    }
}

fn jose_sig_to_der(jose_sig: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if jose_sig.len() % 2 != 0 {
        return Err("JOSE signature length is not even".into());
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

fn decode_header_get_x5u(header_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let header_bytes = decode_b64_url_nopad(header_b64)?;
    let header_json: Value = serde_json::from_slice(&header_bytes)?;
    if let Some(x5u) = header_json.get("x5u") {
        if let Some(s) = x5u.as_str() {
            return Ok(s.to_string());
        }
    }
    Err("x5u not found in header".into())
}

fn print_final_extra_data(final_token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = final_token.split('.').collect();
    if parts.len() != 3 {
        return Err("final token not JWT format".into());
    }
    let payload = decode_b64_url_nopad(parts[1])?;
    let v: Value = serde_json::from_slice(&payload)?;
    let extra = v.get("extraData").unwrap_or(&Value::Null);
    println!("--- Verified Player Data (from final token) ---");
    println!(
        "  Display Name: {}",
        extra
            .get("displayName")
            .and_then(|x| x.as_str())
            .unwrap_or("(none)")
    );
    println!(
        "  UUID:         {}",
        extra.get("identity").and_then(|x| x.as_str()).unwrap_or("(none)")
    );
    println!(
        "  XUID:         {}",
        extra.get("XUID").and_then(|x| x.as_str()).unwrap_or("(none)")
    );
    println!("-----------------------------------------------");
    Ok(())
}

pub fn verify_chain(raw_chain: &[&str], mojang_key_b64: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- JWT Chain Verification (x5u flow) ---");

    let tokens: Vec<String> = raw_chain
        .iter()
        .map(|t| t.replace('\n', "").replace('\r', ""))
        .collect();

    // first header -> get x5u
    let first_parts: Vec<&str> = tokens[0].split('.').collect();
    if first_parts.len() != 3 {
        return Err("first token not in JWT format".into());
    }
    let mut next_public_b64 = decode_header_get_x5u(first_parts[0])?;

    let mojang_pk = build_public_key_from_b64(mojang_key_b64)?;

    for (i, token) in tokens.iter().enumerate() {
        println!("\n--- Verifying Token {} ---", i + 1);

        let current_pub = match build_public_key_from_b64(&next_public_b64) {
            Ok(k) => k,
            Err(e) => {
                return Err(format!("Failed to parse public key used for verifying token {}: {}", i + 1, e).into());
            }
        };

        if i == 1 {
            let cur_der = current_pub.to_public_key_der()?;
            let moj_der = mojang_pk.to_public_key_der()?;
            if cur_der.as_ref() != moj_der.as_ref() {
                return Err("Token 2 was NOT signed by the trusted Mojang public key!".into());
            } else {
                println!("Mojang trust check PASSED.");
            }
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(format!("Token {} not in header.payload.signature format", i + 1).into());
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signing_input_bytes = signing_input.as_bytes();

        // Decode JOSE signature (r||s) from base64url
        let sig_bytes = decode_b64_url_nopad(parts[2])?;
        let der_sig = jose_sig_to_der(&sig_bytes)?;

        // Build verifying key and verify
        let verifying_key = VerifyingKey::from(&current_pub);
        let signature = EcdsaSignature::from_der(&der_sig)
            .map_err(|e| format!("invalid DER signature for token {}: {}", i + 1, e))?;

        if let Err(_) = verifying_key.verify(signing_input_bytes, &signature) {
            return Err(format!("Verification failed: signature invalid for token {}", i + 1).into());
        } else {
            println!("Token {} signature is VALID.", i + 1);
        }

        // get identityPublicKey from payload (for next iteration)
        let payload_bytes = decode_b64_url_nopad(parts[1])?;
        let payload_json: Value = serde_json::from_slice(&payload_bytes)?;
        if let Some(id_pk) = payload_json.get("identityPublicKey") {
            if let Some(s) = id_pk.as_str() {
                next_public_b64 = s.to_string();
            }
        }
    }

    println!("\n==================================================");
    println!("  SUCCESS: ENTIRE TOKEN CHAIN IS CRYPTOGRAPHICALLY VALID!");
    println!("==================================================\n");

    print_final_extra_data(&tokens[tokens.len() - 1])?;

    Ok(())
}