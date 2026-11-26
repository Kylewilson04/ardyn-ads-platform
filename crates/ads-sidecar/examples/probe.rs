// probe.rs — full client-side sovereign protocol against a live sidecar.
// Run: cargo run --release -p ads-sidecar --example probe -- <BASE_URL>
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ads_core::compute_baseline_state_digest;
use ads_core::hkdf_sha256;
use ads_ddc::DestructionDataCertificate;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hex;
use rand_core::{OsRng, RngCore};
use serde_json::json;

use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() {
    let base = std::env::args().nth(1).expect("usage: probe <BASE_URL>");
    let client = reqwest::Client::new();

    // 1. Fetch gateway health + X25519 pubkey
    let health: serde_json::Value = client
        .get(format!("{}/v1/health", base))
        .send().await.unwrap()
        .json().await.unwrap();
    println!("HEALTH: {}", serde_json::to_string_pretty(&health).unwrap());
    let gw_pk_bytes: [u8; 32] = hex::decode(health["gateway_x25519_pub_hex"].as_str().unwrap())
        .unwrap().try_into().unwrap();
    let gw_pk = PublicKey::from(gw_pk_bytes);

    // 2. Client ephemeral + seal ingress payload (X25519 -> HKDF -> AES-256-GCM)
    let client_sk = StaticSecret::random_from_rng(OsRng);
    let client_pk = PublicKey::from(&client_sk);
    let session_id = format!(
        "hermes-probe-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    );
    let shared = client_sk.diffie_hellman(&gw_pk);
    let k_ingress =
        hkdf_sha256(shared.as_bytes(), session_id.as_bytes(), b"ARDYN_ADS_INGRESS_V1").unwrap();
    let cipher = Aes256Gcm::new_from_slice(&k_ingress).unwrap();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let plaintext = b"Transient QA probe record for sovereign destruction verification".to_vec();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &plaintext, aad: session_id.as_bytes() },
        )
        .unwrap();

    // 3. POST /v1/sovereign/execute
    let body = json!({
        "session_id": session_id,
        "tenant_id": "hermes-qa",
        "client_ephemeral_pub_hex": hex::encode(client_pk.as_bytes()),
        "ingress_nonce_hex": hex::encode(nonce),
        "ingress_ciphertext_hex": hex::encode(ct),
    });
    let resp = client
        .post(format!("{}/v1/sovereign/execute", base))
        .json(&body)
        .send().await.unwrap();
    let status = resp.status();
    // RAW body text — the wire payload substring is the canonical DDC bytes
    let raw_text = resp.text().await.unwrap();
    let resp_json: serde_json::Value = serde_json::from_str(&raw_text).unwrap();
    println!("EXECUTE STATUS: {}", status);
    if !status.is_success() {
        println!("ERROR RESPONSE: {}", serde_json::to_string_pretty(&resp_json).unwrap());
        std::process::exit(1);
    }
    let event_id = resp_json["event_id"].as_str().unwrap().to_string();
    println!("EVENT: {} status={}", event_id, resp_json["status"].as_str().unwrap());

    // Canonical payload bytes = exact substring of the raw wire body (as the TS SDK does)
    let canonical_bytes = extract_canonical_payload(&raw_text)
        .expect("failed to extract canonical payload substring from raw body");
    println!("CANONICAL PAYLOAD: {} bytes (raw wire substring)", canonical_bytes.len());

    // 4. Deserialize DDC for field access
    let ddc: DestructionDataCertificate =
        serde_json::from_value(resp_json["ddc"].clone()).unwrap();
    let tier = serde_json::to_value(&ddc.payload.verification_tier).unwrap();
    println!("DDC: id={} tier={} completed={} probes={:?}",
        ddc.payload.event_id, tier, ddc.payload.destruction_completed, ddc.payload.probe_summary);
    println!("      phase1: {} bytes / {} passes / mechanism {}",
        ddc.payload.phase1_metrics.bytes_scrubbed, ddc.payload.phase1_metrics.passes_completed,
        ddc.payload.phase1_metrics.isa_mechanism);
    println!("      phase2: {} dispatches, regression_ratio {}",
        ddc.payload.phase2_metrics.dispatches_executed, ddc.payload.phase2_metrics.regression_ratio);
    // 5. Verify Ed25519 signature over the RAW canonical payload bytes
    let signer_hex = health["ddc_signer_ed25519_pub_hex"].as_str().unwrap();
    let vk = VerifyingKey::from_bytes(
        &hex::decode(signer_hex).unwrap().try_into().unwrap(),
    ).unwrap();
    let sig = Signature::from_bytes(
        &hex::decode(&ddc.signature_hex).unwrap().try_into().unwrap(),
    );
    match vk.verify(&canonical_bytes, &sig) {
        Ok(()) => println!("ED25519 DDC SIGNATURE: VERIFIED"),
        Err(e) => println!("ED25519 DDC SIGNATURE: FAILED — {e} (continuing to unwrap to isolate canonicalization)"),
    }

    // Active DDC digest over the raw canonical bytes
    use sha2::Digest as _;
    let ddc_digest: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        h.update(b"ARDYN_DDC_DIGEST_V1:");
        h.update(&canonical_bytes);
        h.update(hex::decode(&ddc.signature_hex).unwrap());
        h.finalize().into()
    };
    println!("ACTIVE DDC DIGEST: {}", hex::encode(ddc_digest));

    // 6. Unwrap release key (DDC-conditioned, Claim 35)
    let gw_eph_bytes: [u8; 32] =
        hex::decode(resp_json["gateway_ephemeral_pub_hex"].as_str().unwrap())
            .unwrap().try_into().unwrap();
    let shared2 = client_sk.diffie_hellman(&PublicKey::from(gw_eph_bytes));
    let mut wrap_info = b"ARDYN_ACTIVE_DDC_WRAP_V1:".to_vec();
    wrap_info.extend_from_slice(&ddc_digest);
    let k_wrap = hkdf_sha256(shared2.as_bytes(), event_id.as_bytes(), &wrap_info).unwrap();
    let wrap_cipher = Aes256Gcm::new_from_slice(&k_wrap).unwrap();
    let wrap_nonce = hex::decode(resp_json["wrap_nonce_hex"].as_str().unwrap()).unwrap();
    let wrapped = hex::decode(resp_json["wrapped_release_seed_hex"].as_str().unwrap()).unwrap();
    let k_release = wrap_cipher
        .decrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload { msg: &wrapped, aad: &ddc_digest },
        )
        .expect("release key unwrap FAILED (DDC mismatch?)");
    println!("RELEASE KEY UNWRAPPED: {} bytes", k_release.len());

    // 7. Decrypt sealed ProtectedResult — the unwrapped release key IS k_seal
    //    (server derived k_seal = HKDF(n_dest, event_id, SEAL||baseline) before wrapping)
    let k_seal = k_release;
    let seal_cipher = Aes256Gcm::new_from_slice(&k_seal).unwrap();
    let result_nonce = hex::decode(resp_json["result_nonce_hex"].as_str().unwrap()).unwrap();
    let sealed_ct = hex::decode(resp_json["sealed_result_ciphertext_hex"].as_str().unwrap()).unwrap();
    let protected_result = seal_cipher
        .decrypt(
            Nonce::from_slice(&result_nonce),
            Payload { msg: &sealed_ct, aad: event_id.as_bytes() },
        )
        .expect("sealed result decrypt FAILED");
    println!("PROTECTED RESULT DECRYPTED: {}", String::from_utf8_lossy(&protected_result));

    // 8. Cross-check via /v1/ddc/verify
    let v = client
        .post(format!("{}/v1/ddc/verify", base))
        .json(&serde_json::to_value(&ddc).unwrap())
        .send().await.unwrap()
        .json::<serde_json::Value>().await.unwrap();
    println!("SIDECAR DDC VERIFY: {}", serde_json::to_string_pretty(&v).unwrap());

    // 9. Ledger receipt + usage token
    println!("LEDGER RECEIPT: {}", serde_json::to_string_pretty(&resp_json["ledger_receipt"]).unwrap());
    println!("USAGE TOKEN: {}", serde_json::to_string_pretty(&resp_json["sovereignty_usage_token"]).unwrap());

    println!("\n=== END-TO-END SOVEREIGN ROUND TRIP: SUCCESS ===");
}

/// Extract the exact canonical JSON substring of `ddc.payload` from the raw
/// response body — mirrors the TS SDK's extractCanonicalDdcPayloadJson.
fn extract_canonical_payload(raw: &str) -> Option<Vec<u8>> {
    let ddc_idx = raw.find("\"ddc\":")?;
    let after = &raw[ddc_idx..];
    let pkey = after.find("\"payload\":")?;
    // start at the opening brace after the payload key
    let brace = after[pkey..].find('{')? + pkey;
    let bytes = after.as_bytes();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut esc = false;
    for (i, &b) in bytes[brace..].iter().enumerate() {
        match b {
            b'\\' if in_str => { esc = !esc; }
            b'"' if !esc => { in_str = !in_str; esc = false; }
            b'{' if !in_str => { depth += 1; }
            b'}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(after[brace..brace + i + 1].as_bytes().to_vec());
                }
            }
            _ => { esc = false; }
        }
    }
    None
}
