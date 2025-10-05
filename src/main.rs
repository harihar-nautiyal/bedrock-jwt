use base64::{engine::general_purpose, Engine as _};
use p384::pkcs8::DecodePublicKey;
use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature, VerifyingKey};
use p384::PublicKey;
use serde_json::Value;
use std::process::exit;
use ecdsa::elliptic_curve::pkcs8::EncodePublicKey;

const RAW_TOKEN_CHAIN: [&str; 3] = [
    // Keep these exact (cleaned) JWT strings from your Python script:
    "eyJhbGciOiJFUzM4NCIsIng1dSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFV2xlMzZiYkh3ak5pRXEzN3FEeW9SalI2ZGVUamJpb1NienBqK05qOHNSOVUxVjlpeGJ0bVpRRldiaVBVMThwaGN3K25lbGFPU0ptcmovM1JObVNUdzg5OTBxL3pMUjdDSHVKdkQ5VE4weHNJdDIxRVhueHFlV3h4UU8wcVBaNHkifQo.eyJjZXJ0aWZpY2F0ZUF1dGhvcml0eSI6dHJ1ZSwiZXhwIjoxNzU5NzI5NjkyLCJpZGVudGl0eVB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFQ1JYdWVKZVREcU5SUmdKaS92bFJ1ZkJ5dS8yRzBpMkVidDZZTWFyNVFYL1IwRElJeXJKTWNVcHJ1SzRRdmVUZkpTVHAzU2hscTRHazM0Y0QvNEdVV3drdjBEVnV6ZXVCK3RYaWphN0hCeGlpMDNOSERiUEFEMEFLbkxyMndkQXAiLCJuYmYiOjE3NTk1NTY4MzJ9Cg.b8kdeWaWkOZRquTCn0tFUYy98x46XfJc6mc100lVtIBlwU16b5JHNV8bOoAVNUs7Ke2gKoM76RsBVekeJy9cDvr0UQ1ARTorEr6AfevfXlBG6bdmCbY7zrxe1zp-WYTz",
    "eyJ4NXQiOiJsQjgwV2tIY0RnV1ctRWItbGw4dmtwZ05rZjAiLCJ4NXUiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRUNSWHVlSmVURHFOUlJnSmkvdmxSdWZCeXUvMkcwaTJFYnQ2WU1hcjVRWC9SMERJSXlySk1jVXBydUs0UXZlVGZKU1RwM1NobHE0R2szNGNELzRHVVd3a3YwRFZ1emV1Qit0WGlqYTdIQnhpaTAzTkhEYlBBRDBBS25McjJ3ZEFwIiwiYWxnIjoiRVMzODQifQ.eyJuYmYiOjE3NTk1NTY4MzIsInJhbmRvbU5vbmNlIjotODE3NTY2NTYxMzg3OTM2NzAyMCwiaXNzIjoiTW9qYW5nIiwiZXhwIjoxNzU5NzI5NjkyLCJjZXJ0aWZpY2F0ZUF1dGhvcml0eSI6dHJ1ZSwiaWF0IjoxNzU5NTU2ODkyLCJpZGVudGl0eVB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFV2NkNXlpN2xXNkRvT3ZRbDFzYXhLcEM5eFZ4UFJDNGI0SXVZTXRTaEpmYkFmV1ZsNHhQTXpGUFRNTlFNNmsvY0pFaXY4VmpHUm5qOFh4aDhNTzZ5VFpPazZITTBsRXlhd3lEV3NOdjI3ZHFWTDU2aGtPcGthTU1oZ2JuWWMzYm8ifQ.ZphXNewjRyNQNgwmxJTK5zrTwz-sp2CqfsnvDXCABqEbc4UgU77mkOMfhxHhSsUoJ3XotU93gUBIN-ngruUE6qs1T6e_Xh84LwOUn6Feoc0CCiYWdfIwxYU1fZOgnFIR",
    "eyJ4NXQiOiI2bnpGakxiRTBiTkh6ajVCYXJnMzhUdGROSDQiLCJ4NXUiOiJNSFl3RUFZSEtvWkl6ajBDQVFZRks0RUVBQ0lEWWdBRVdjZDV5aTdsVzZEb092UWwxc2F4S3BDOXhWeFBSQzRiNEl1WU10U2hKZmJBZldWbDR4UE16RlBUTU5RTTZrL2NKRWl2OFZqR1JuajhYeGg4TU82eVRaT2s2SE0wbEV5YXd5RFdzTnYyN2RxVkw1NmhrT3BrYU1NaGdiblljM2JvIiwiYWxnIjoiRVMzODQifQ.eyJuYmYiOjE3NTk1OTQ5MDAsImV4dHJhRGF0YSI6eyJpZGVudGl0eSI6IjYwMGYxNTQ4LWU5NGItMzBjMS05MGNlLWI2Y2JiYTA0MWQ4NCIsImRpc3BsYXlOYW1lIjoiaGFyaWhhcm5hdXRpeWFsIiwiWFVJRCI6IjI1MzU0MzU0ODAwODE2NzQiLCJ0aXRsZUlkIjoiMTczOTk0NzQzNiIsInNhbmRib3hJZCI6IlJFVEFJTCJ9LCJyYW5kb21Ob25jZSI6LTQ0MTY2MzI1NTcwNTc4ODIwNzksImlzcyI6Ik1vamFuZyIsImV4cCI6MTc1OTY4MTM2MCwiaWF0IjoxNzU5NTk0OTYwLCJpZGVudGl0eVB1YmxpY0tleSI6Ik1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFV2xlMzZiYkh3ak5pRXEzN3FEeW9SalI2ZGVUamJpb1NienBqK05qOHNSOVUxVjlpeGJ0bVpRRldiaVBVMThwaGN3K25lbGFPU0ptcmovM1JObVNUdzg5OTBxL3pMUjdDSHVKdkQ5VE4weHNJdDIxRVhueHFlV3h4UU8wcVBaNHkifQ.1Rj5JvGXE3Fej-85gnMkJdE4LZQgKZPOYvf8I5bMXFT2jPkOaVZri1zmwjkd3K_UF_1lnj_osF2rvtamvB73HL6IdzEu0v6h8p4HGJytS84Cudf1VXT-8HQVyIIZINL-",
];

const MOJANG_PUBLIC_KEY_B64: &str =
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAECRXueJeTDqNRRgJi/vlRufByu/2G0i2Ebt6YMar5QX/R0DIIyrJMcUpruK4QveTfJSTp3Shlq4Gk34cD/4GUWwkv0DVuzeuB+tXija7HBxii03NHDbPAD0AKnLr2wdAp";

fn decode_b64_url_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

fn decode_b64_standard(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(s)
}

/// Build a p384 PublicKey from base64 (either SPKI DER or raw SEC1 / raw X||Y)
fn build_public_key_from_b64(b64: &str) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let bytes = decode_b64_standard(b64)?;

    // Heuristics:
    // - If starts with 0x30, treat as DER SubjectPublicKeyInfo (SPKI)
    // - If length == 97 and first == 0x04, it's SEC1 uncompressed (0x04|X|Y)
    // - If length == 96, it's raw X||Y, so prepend 0x04.
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

/// Convert JOSE ECDSA signature (r || s) -> ASN.1/DER encoded ECDSA signature.
/// For P-384, r and s are each 48 bytes, so JOSE sig length is 96 bytes.
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

fn verify_x5u_chain() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- JWT Chain Verification (x5u flow) ---");

    let tokens: Vec<String> = RAW_TOKEN_CHAIN
        .iter()
        .map(|t| t.replace('\n', "").replace('\r', ""))
        .collect();

    // first header -> get x5u
    let first_parts: Vec<&str> = tokens[0].split('.').collect();
    if first_parts.len() != 3 {
        return Err("first token not in JWT format".into());
    }
    let mut next_public_b64 = decode_header_get_x5u(first_parts[0])?;

    // prepare mojang public key (PublicKey) for comparison on token 2
    let mojang_pk = build_public_key_from_b64(MOJANG_PUBLIC_KEY_B64)?;

    for (i, token) in tokens.iter().enumerate() {
        println!("\n--- Verifying Token {} ---", i + 1);

        // Build public key (used to verify this token) from next_public_b64 (from previous step)
        let current_pub = match build_public_key_from_b64(&next_public_b64) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Failed to parse public key used for verifying token {}: {}", i + 1, e);
                exit(1);
            }
        };

        // On token 2, ensure current_pub equals mojang_pk
        if i == 1 {
            let cur_der = current_pub.to_public_key_der()?;
            let moj_der = mojang_pk.to_public_key_der()?;
            if cur_der.as_ref() != moj_der.as_ref() {
                eprintln!("\nFATAL ERROR: Token 2 was NOT signed by the trusted Mojang public key!");
                exit(1);
            } else {
                println!("Mojang trust check PASSED.");
            }
        }

        // Split token -> header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            eprintln!("Token {} not in header.payload.signature format", i + 1);
            exit(1);
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
            // optional fallback: try pre-hash verify (uncomment if needed)
            // let digest = sha2::Sha384::digest(signing_input_bytes);
            // if verifying_key.verify_digest(digest, &signature).is_err() { ... }
            eprintln!("Verification failed: signature invalid for token {}", i + 1);
            exit(1);
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

fn main() {
    if let Err(e) = verify_x5u_chain() {
        eprintln!("FATAL ERROR: Verification failed. Details: {}", e);
        std::process::exit(1);
    }
}
