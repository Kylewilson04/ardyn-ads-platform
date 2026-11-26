// crates/ads-sidecar/src/main.rs
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
pub mod web;
use ads_core::{
    compute_baseline_state_digest, decrypt_client_ingress, wrap_release_key_with_ddc,
    LifecycleGranularity, MathematicalInterlockVault, ProtectedResultKind,
};
use ads_ddc::{AppendOnlyMerkleLedger, DestructionDataCertificate, LedgerReceipt, TrustedEvidenceGenerator, VerificationTier};
use ads_metering::{SovereigntyMeteringEngine, SovereigntyUsageToken};
use ads_sentinel::{RuntimeEnforcementEngine, VolatileArena};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, sync::{Arc, Mutex}};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub struct SidecarState {
    pub gateway_sk: StaticSecret,
    pub gateway_pk_hex: String,
    pub runtime_engine: RuntimeEnforcementEngine,
    pub evidence_generator: TrustedEvidenceGenerator,
    pub ledger: Mutex<AppendOnlyMerkleLedger>,
    pub metering: SovereigntyMeteringEngine,
    pub upstream_url: Option<String>,
}

impl SidecarState {
    pub fn new(upstream_url: Option<String>, watched_dir: Option<std::path::PathBuf>) -> Self {
        let gateway_sk = StaticSecret::random_from_rng(OsRng);
        let gateway_pk = PublicKey::from(&gateway_sk);
        Self {
            gateway_sk,
            gateway_pk_hex: hex::encode(gateway_pk.as_bytes()),
            runtime_engine: RuntimeEnforcementEngine::new(watched_dir),
            evidence_generator: TrustedEvidenceGenerator::new("https://verify.ardyn.ai/v1/ddc/verify"),
            ledger: Mutex::new(AppendOnlyMerkleLedger::default()),
            metering: SovereigntyMeteringEngine::new(),
            upstream_url,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SovereignExecuteRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub client_ephemeral_pub_hex: String,
    pub ingress_nonce_hex: String,
    pub ingress_ciphertext_hex: String,
    pub granularity: Option<LifecycleGranularity>,
    pub result_kind: Option<ProtectedResultKind>,
    pub simulate_residual_tamper: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SovereignExecutionResponse {
    pub status: String,
    pub event_id: String,
    pub session_id: String,
    pub sealed_result_ciphertext_hex: String,
    pub result_nonce_hex: String,
    pub wrapped_release_seed_hex: String,
    pub wrap_nonce_hex: String,
    pub gateway_ephemeral_pub_hex: String,
    pub ddc: DestructionDataCertificate,
    pub ledger_receipt: LedgerReceipt,
    pub sovereignty_usage_token: SovereigntyUsageToken,
}

pub static CREDITS: std::sync::OnceLock<std::sync::Arc<ads_metering::credits::CreditEngine>> =
    std::sync::OnceLock::new();
pub static PAYMENT_PROVIDERS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

async fn health_handler(State(state): State<Arc<SidecarState>>) -> (axum::http::HeaderMap, Json<serde_json::Value>) {
    let root = state.ledger.lock().unwrap().current_root_hex();
    let tree_size = state.ledger.lock().unwrap().leaves_len();
    let host = env::var("HOSTNAME").ok().unwrap_or_else(|| "ads-node".into());
    let mut h = axum::http::HeaderMap::new();
    h.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    (h, Json(serde_json::json!({
        "status": "ok",
        "service": "ardyn-ads-sidecar",
        "version": env!("CARGO_PKG_VERSION"),
        "organization": "ARDYN INTELLIGENCE SYSTEMS INC.",
        "instance_id": host,
        "assurance_tier": "SINGLE_TENANT_SECURE_METAL",
        "isa_scrubber_mechanism": "x86_64_MOVNTDQ_CLFLUSH_SFENCE",
        "phase2_dispatches_per_event": 15,
        "mandatory_probes": ["MemoryIntegrityProbe", "DiskArtefactProbe", "KvSnapshotProbe", "NonceIntegrityProbe"],
        "protected_state_manifest_digest_hex": root,
        "merkle_ledger_tree_size": tree_size,
        "acta_notarization_default_url": "https://acta-server-998422936041.us-west1.run.app",
        "acta_auto_notarize_configured": false,
        "status": "SOVEREIGN_ACTIVE",
        "organization": "ARDYN INTELLIGENCE SYSTEMS INC.",
        "gateway_x25519_pub_hex": state.gateway_pk_hex,
        "ddc_signer_ed25519_pub_hex": state.evidence_generator.public_key_hex,
        "attestation_root_id": state.evidence_generator.attestation_root_id,
        "metering_ed25519_pub_hex": state.metering.pubkey_hex,
        "ledger_merkle_root_hex": root,
        "gateway_x25519_public_key_hex": state.gateway_pk_hex,
        "credits": CREDITS.get().map(|c| serde_json::json!({
            "enabled": true,
            "price_cents_per_ddc": c.price_cents(),
            "min_deposit_cents": ads_metering::credits::MIN_DEPOSIT_CENTS,
            "payment_providers": PAYMENT_PROVIDERS
                .get()
                .cloned()
                .unwrap_or_else(|| vec!["promo_code".into(), "moonpay_commerce_pending".into(), "stripe_pending".into()]),
        })).unwrap_or(serde_json::json!(null)),
    })))
}

async fn execute_handler(
    State(state): State<Arc<SidecarState>>,
    Json(req): Json<SovereignExecuteRequest>,
) -> Result<Json<SovereignExecutionResponse>, (StatusCode, Json<serde_json::Value>)> {
    sovereign_execute(state, req).await.map(Json)
}

/// Shared destructive pipeline used by both the /v1/sovereign/execute native
/// route and the web-console /v1/execute compatibility route.
pub async fn sovereign_execute(
    state: Arc<SidecarState>,
    req: SovereignExecuteRequest,
) -> Result<SovereignExecutionResponse, (StatusCode, Json<serde_json::Value>)> {
    let event_id = Uuid::new_v4().to_string();
    let client_pub: [u8; 32] = hex::decode(&req.client_ephemeral_pub_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid client pubkey"}))))?;
    let nonce_bytes = hex::decode(&req.ingress_nonce_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid ingress nonce"}))))?;
    let ct_bytes = hex::decode(&req.ingress_ciphertext_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid ingress ciphertext"}))))?;

    let mut arena = VolatileArena::allocate(256 * 1024)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))))?;

    // 1. Decrypt client payload into volatile mlock'd arena
    let mut plaintext = decrypt_client_ingress(
        &state.gateway_sk,
        client_pub,
        &req.session_id,
        &nonce_bytes,
        &ct_bytes,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))))?;

    arena.write_slice(0, &plaintext).unwrap();

    // 2. Dispatch to upstream container or built-in Incident Response triage
    let mut raw_output = if let Some(ref url) = state.upstream_url {
        let client = reqwest::Client::new();
        client
            .post(url)
            .header("X-Ardyn-Internal-Volatile", "1")
            .body(plaintext.clone())
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": e.to_string()}))))?
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": e.to_string()}))))?
            .to_vec()
    } else {
        serde_json::to_vec(&serde_json::json!({
            "SovereignEngine": "ARDYN INTELLIGENCE SYSTEMS INC.",
            "IncidentTriage": "CRITICAL_CONTAINMENT_READY",
            "ZeroPersistence": true
        }))
        .unwrap()
    };
    plaintext.zeroize();

    // 3. Seal ProtectedResult and blind DestructionNonce prior to zeroisation
    let (vault, sealed) = MathematicalInterlockVault::seal_and_blind(&event_id, arena.size_bytes, &raw_output)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;
    raw_output.zeroize();

    // 4. Dual-Phase Verifiable Zeroisation (Phase 1 MOVNTDQ+CLFLUSH + Phase 2 15-pass Scrubber)
    let (mut p1_ok, p1_summary) = arena.scrub_phase1(3);
    if req.simulate_residual_tamper.unwrap_or(false) {
        let _ = arena.write_slice(64, &[0xDE, 0xAD, 0xBE, 0xEF]);
        p1_ok = false;
    }
    let (p2_ok, p2_summary) = VolatileArena::scrub_phase2_accelerator(256 * 1024);

    // 5. Measure physical post-wipe arena state & evaluate all 4 Runtime Probes
    let post_wipe_bytes = arena.read_all();
    let actual_digest = compute_baseline_state_digest(&event_id, arena.size_bytes, &post_wipe_bytes);
    let verdict = state.runtime_engine.evaluate(
        &req.session_id,
        p1_ok,
        p2_ok,
        &sealed.nonce_commitment_hex,
    );

    // 6. Verify & Derive Release Key (or trigger Fail-Closed Atomic Abort burning N_dest)
    let k_release = match vault.verify_and_derive_release_key(actual_digest, verdict.all_probes_passed) {
        Ok(k) => k,
        Err(abort_err) => {
            state.metering.record_abort();
            return Err((
                StatusCode::LOCKED,
                Json(serde_json::json!({
                    "status": "ATOMIC_ABORT_FAIL_CLOSED",
                    "error": abort_err.to_string(),
                    "ddc_issued": false,
                    "release_material_burned": true
                })),
            ));
        }
    };

    // 7. Mint Ed25519 Signed Destruction Data Certificate (DDC)
    let mut proof_hasher = Sha256::new();
    proof_hasher.update(b"ARDYN_DESTRUCTION_PROOF_V1:");
    proof_hasher.update(actual_digest);
    proof_hasher.update(hex::decode(&verdict.evidence_commitment_hex).unwrap_or_default());
    let destruction_proof_hash_hex = hex::encode(proof_hasher.finalize());

    let ddc = state
        .evidence_generator
        .mint_certificate(
            verdict.all_probes_passed,
            event_id.clone(),
            req.session_id.clone(),
            VerificationTier::TelemetryBackedHardwareInferred,
            req.granularity.unwrap_or(LifecycleGranularity::PerRequest),
            req.result_kind.unwrap_or(ProtectedResultKind::InferenceOutput),
            sealed.result_commitment_hex.clone(),
            destruction_proof_hash_hex,
            sealed.nonce_commitment_hex.clone(),
            verdict.monotonic_counter,
            p1_summary,
            p2_summary,
            verdict.probe_summary,
            None,
        )
        .map_err(|e| (StatusCode::LOCKED, Json(serde_json::json!({"error": e.to_string()}))))?;

    // 8. Active DDC-Conditioned Release Key Wrapping (Claim 35)
    let ddc_digest = ddc.compute_active_ddc_digest().unwrap();
    let (wrapped_hex, wrap_nonce_hex, gw_ephem_hex) =
        wrap_release_key_with_ddc(&event_id, client_pub, k_release, &ddc_digest)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))))?;

    let ledger_receipt = state.ledger.lock().unwrap().append(&ddc).unwrap();
    let usage_token = state.metering.issue_usage_token(&req.tenant_id, &ddc);

    Ok(SovereignExecutionResponse {
        status: "RELEASED_AFTER_VERIFIED_DESTRUCTION".to_string(),
        event_id,
        session_id: req.session_id,
        sealed_result_ciphertext_hex: sealed.ciphertext_hex,
        result_nonce_hex: sealed.result_nonce_hex,
        wrapped_release_seed_hex: wrapped_hex,
        wrap_nonce_hex,
        gateway_ephemeral_pub_hex: gw_ephem_hex,
        ddc,
        ledger_receipt,
        sovereignty_usage_token: usage_token,
    })
}

async fn verify_ddc_handler(
    State(state): State<Arc<SidecarState>>,
    Json(ddc): Json<DestructionDataCertificate>,
) -> Json<serde_json::Value> {
    let ok = TrustedEvidenceGenerator::verify_certificate(&ddc, Some(&state.evidence_generator.public_key_hex)).is_ok();
    Json(serde_json::json!({
        "valid": ok,
        "attestation_root_id": state.evidence_generator.attestation_root_id
    }))
}

async fn underwriter_report_handler(
    State(state): State<Arc<SidecarState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<ads_metering::UnderwriterZeroRetentionReport> {
    let tenant = params.get("tenant_id").cloned().unwrap_or_else(|| "default-tenant".to_string());
    let root = state.ledger.lock().unwrap().current_root_hex();
    Json(state.metering.generate_underwriter_report(&tenant, root))
}

pub fn build_router(state: Arc<SidecarState>) -> Router {
    Router::new()
        .route("/v1/health", get(health_handler))
        .route("/v1/sovereign/execute", post(execute_handler))
        .route("/v1/ddc/verify", post(verify_ddc_handler))
        .route("/v1/underwriter/report", get(underwriter_report_handler))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    let upstream = env::var("ADS_UPSTREAM_URL").ok();
    let listen_addr = env::var("ADS_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let state = Arc::new(SidecarState::new(upstream, None));

    // Prepaid credits (OpenRouter-style deposits): $25 min, $0.50 per DDC.
    let price = env::var("ADS_EVENT_PRICE_CENTS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(ads_metering::credits::DEFAULT_EVENT_PRICE_CENTS);
    let persist = env::var("ADS_CREDITS_FILE").ok().map(std::path::PathBuf::from);
    let credits = Arc::new(ads_metering::credits::CreditEngine::new(price, persist));
    let provider = ads_metering::credits::PromoCodeProvider::from_env(
        &env::var("ADS_PROMO_CODES").unwrap_or_default(),
    );
    let demo_seeds: Vec<(String, i64)> = env::var("ADS_DEMO_SEEDS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let mut it = pair.trim().splitn(2, ':');
            let t = it.next()?.trim().to_string();
            let c = it.next()?.trim().parse::<i64>().ok()?;
            Some((t, c))
        })
        .collect();

    let _ = CREDITS.set(credits.clone());
    let keyless: Vec<String> = env::var("ADS_KEYLESS_TENANTS")
        .unwrap_or_else(|_| "ardyn_web_console".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let tenant_auth = Arc::new(ads_metering::credits::TenantKeyAuth::new(
        env::var("ADS_TENANT_MASTER_KEY").ok().as_deref(),
        keyless,
    ));
    let stripe_secret = env::var("STRIPE_SECRET_KEY").ok().filter(|s| !s.trim().is_empty());
    let stripe_webhook_secret = env::var("STRIPE_WEBHOOK_SECRET").ok().filter(|s| !s.trim().is_empty());
    let moonpay = web::MoonPayCommerceConfig::from_env();
    let mut providers = vec!["promo_code".to_string()];
    providers.push(if moonpay.is_checkout_configured() {
        "moonpay_commerce".to_string()
    } else {
        "moonpay_commerce_pending".to_string()
    });
    providers.push(if stripe_secret.is_some() {
        "stripe".to_string()
    } else {
        "stripe_pending".to_string()
    });
    let _ = PAYMENT_PROVIDERS.set(providers);

    let web_state = Arc::new(web::WebState {
        core: state.clone(),
        credits: credits.clone(),
        provider,
        tenant_auth,
        admin_key: env::var("ADS_ADMIN_KEY").ok(),
        stripe_secret,
        stripe_webhook_secret,
        moonpay,
        demo_seeds,
    });
    web::seed_demo_accounts(&web_state);

    // Native sovereign routes + web-console compatibility routes on one service.
    let app = build_router(state).merge(web::build_web_router(web_state));
    let listener = tokio::net::TcpListener::bind(&listen_addr).await.expect("Bind failed");
    println!(
        "ARDYN INTELLIGENCE SYSTEMS INC. — Sovereign Sidecar v{} listening on {} (credits: {}c/DDC, min deposit {}c)",
        env!("CARGO_PKG_VERSION"),
        listen_addr,
        price,
        ads_metering::credits::MIN_DEPOSIT_CENTS
    );
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
    use ads_core::hkdf_sha256;

    #[tokio::test]
    async fn test_e2e_positive_and_fail_closed_negative_paths() {
        let state = Arc::new(SidecarState::new(None, None));
        let gw_pk_bytes: [u8; 32] = hex::decode(&state.gateway_pk_hex).unwrap().try_into().unwrap();
        let gw_pk = PublicKey::from(gw_pk_bytes);

        let client_sk = StaticSecret::random_from_rng(OsRng);
        let client_pk = PublicKey::from(&client_sk);
        let session_id = "sess-rust-e2e-01".to_string();

        let shared = client_sk.diffie_hellman(&gw_pk);
        let k_in = hkdf_sha256(shared.as_bytes(), session_id.as_bytes(), b"ARDYN_ADS_INGRESS_V1").unwrap();
        let nonce = [7u8; 12];
        let ct = Aes256Gcm::new_from_slice(&k_in)
            .unwrap()
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: b"{\"secret\":\"genomic-sequence\"}", aad: session_id.as_bytes() })
            .unwrap();

        // 1. Positive Path Execution
        let ok_res = execute_handler(
            State(state.clone()),
            Json(SovereignExecuteRequest {
                session_id: session_id.clone(),
                tenant_id: "cyber-sec-01".to_string(),
                client_ephemeral_pub_hex: hex::encode(client_pk.as_bytes()),
                ingress_nonce_hex: hex::encode(nonce),
                ingress_ciphertext_hex: hex::encode(&ct),
                granularity: Some(LifecycleGranularity::PerRequest),
                result_kind: Some(ProtectedResultKind::InferenceOutput),
                simulate_residual_tamper: Some(false),
            }),
        )
        .await
        .expect("Positive sovereign execution must succeed")
        .0;

        assert!(TrustedEvidenceGenerator::verify_certificate(&ok_res.ddc, Some(&state.evidence_generator.public_key_hex)).is_ok());
        assert_eq!(ok_res.ddc.payload.phase2_metrics.dispatches_executed, 15);
        assert!(ok_res.ddc.payload.phase2_metrics.regression_ratio >= 10.0);

        // Client unwraps release key using Active DDC digest
        let ddc_digest = ok_res.ddc.compute_active_ddc_digest().unwrap();
        let ephem_pk_bytes: [u8; 32] = hex::decode(&ok_res.gateway_ephemeral_pub_hex).unwrap().try_into().unwrap();
        let out_shared = client_sk.diffie_hellman(&PublicKey::from(ephem_pk_bytes));
        let mut wrap_info = b"ARDYN_ACTIVE_DDC_WRAP_V1:".to_vec();
        wrap_info.extend_from_slice(&ddc_digest);
        let k_wrap = hkdf_sha256(out_shared.as_bytes(), ok_res.event_id.as_bytes(), &wrap_info).unwrap();

        let k_result = Aes256Gcm::new_from_slice(&k_wrap)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&hex::decode(&ok_res.wrap_nonce_hex).unwrap()),
                Payload { msg: &hex::decode(&ok_res.wrapped_release_seed_hex).unwrap(), aad: &ddc_digest },
            )
            .expect("Active DDC key unwrap must succeed");

        let decrypted_output = Aes256Gcm::new_from_slice(&k_result)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&hex::decode(&ok_res.result_nonce_hex).unwrap()),
                Payload { msg: &hex::decode(&ok_res.sealed_result_ciphertext_hex).unwrap(), aad: ok_res.event_id.as_bytes() },
            )
            .expect("ProtectedResult decryption must succeed");
        assert!(String::from_utf8_lossy(&decrypted_output).contains("ARDYN INTELLIGENCE SYSTEMS INC."));

        // 2. Fail-Closed Negative Path (Residual Tamper -> HTTP 423 LOCKED + Nonce Burned)
        let abort_err = execute_handler(
            State(state.clone()),
            Json(SovereignExecuteRequest {
                session_id: "sess-tamper-02".to_string(),
                tenant_id: "cyber-sec-01".to_string(),
                client_ephemeral_pub_hex: hex::encode(client_pk.as_bytes()),
                ingress_nonce_hex: hex::encode(nonce),
                ingress_ciphertext_hex: hex::encode(
                    Aes256Gcm::new_from_slice(&hkdf_sha256(shared.as_bytes(), b"sess-tamper-02", b"ARDYN_ADS_INGRESS_V1").unwrap())
                        .unwrap()
                        .encrypt(Nonce::from_slice(&nonce), Payload { msg: b"{\"secret\":\"leak-test\"}", aad: b"sess-tamper-02" })
                        .unwrap()
                ),
                granularity: None,
                result_kind: None,
                simulate_residual_tamper: Some(true),
            }),
        )
        .await
        .expect_err("Residual memory must trigger Atomic Abort");

        assert_eq!(abort_err.0, StatusCode::LOCKED);
    }
}
