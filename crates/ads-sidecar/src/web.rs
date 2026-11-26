// crates/ads-sidecar/src/web.rs — Ardyn web console contract (v1.1.0).
//
// Drop-in compatibility with the deployed ADS sidecar contract used by
// https://ardyn.ai: GET /v1/pubkey, POST /v1/execute, GET /v1/health — plus
// the prepaid credits endpoints. Adds permissive CORS so browser clients
// (the sovereign-client WebCrypto SDK) can call this pod directly.

use crate::{SidecarState, SovereignExecuteRequest};
use ads_metering::credits::{CreditEngine, PaymentProvider, PromoCodeProvider, MIN_DEPOSIT_CENTS};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

const ADS_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct WebState {
    pub core: Arc<SidecarState>,
    pub credits: Arc<CreditEngine>,
    pub provider: PromoCodeProvider,
    /// Tenants seeded with a complimentary demo balance (e.g. "ardyn_web_console:500").
    pub demo_seeds: Vec<(String, i64)>,
}

pub fn seed_demo_accounts(ws: &WebState) {
    for (tenant, cents) in &ws.demo_seeds {
        let (bal, _) = ws.credits.balance(tenant);
        if bal == 0 {
            ws.credits.seed(tenant, "demo_seed", *cents);
        }
    }
}

// --- CORS (hand-rolled; matches the Cloud Run deployment's permissive policy) ---

async fn cors_mw(method: axum::http::Method, req: axum::extract::Request, next: Next) -> Response {
    let is_preflight = method == axum::http::Method::OPTIONS;
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("Access-Control-Allow-Origin", "*".parse().unwrap());
    h.insert("Access-Control-Allow-Methods", "GET, POST, OPTIONS".parse().unwrap());
    h.insert(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization".parse().unwrap(),
    );
    h.insert("Access-Control-Max-Age", "86400".parse().unwrap());
    if is_preflight {
        *resp.status_mut() = StatusCode::OK;
    }
    resp
}

pub fn build_web_router(ws: Arc<WebState>) -> Router {
    let r = Router::new()
        .route("/v1/pubkey", get(web_pubkey))
        .route("/v1/execute", post(web_execute))
        .route("/v1/credits/balance", get(credits_balance))
        .route("/v1/credits/redeem", post(credits_redeem))
        .with_state(ws);
    r.layer(middleware::from_fn(cors_mw))
}

// --- GET /v1/pubkey ---

async fn web_pubkey(State(ws): State<Arc<WebState>>) -> Json<serde_json::Value> {
    Json(json!({
        "gateway_x25519_public_key_hex": ws.core.gateway_pk_hex,
        "service": "ardyn-ads-sidecar",
        "version": ADS_VERSION,
    }))
}

// --- POST /v1/execute (web contract field names) ---

#[derive(Debug, Deserialize)]
pub struct WebExecuteRequest {
    pub session_id: String,
    pub tenant_id: String,
    pub client_ephemeral_x25519_pub_hex: String,
    pub ingress_nonce_hex: String,
    pub encrypted_payload_hex: String,
    #[serde(default)]
    pub simulate_residual_tamper: Option<bool>,
}

async fn web_execute(
    State(ws): State<Arc<WebState>>,
    Json(req): Json<WebExecuteRequest>,
) -> Response {
    // 0. Credits gate — fail closed BEFORE any crypto work.
    if let Err(e) = ws.credits.authorize(&req.tenant_id) {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({
                "error": format!("{}", e),
                "status": "CREDITS_REQUIRED",
                "balance_cents": ws.credits.balance(&req.tenant_id).0,
                "price_cents": ws.credits.price_cents(),
                "min_deposit_cents": MIN_DEPOSIT_CENTS,
                "redeem_endpoint": "/v1/credits/redeem"
            })),
        )
            .into_response();
    }

    // 1. Map to the core sovereign contract.
    let core_req = SovereignExecuteRequest {
        session_id: req.session_id.clone(),
        tenant_id: req.tenant_id.clone(),
        client_ephemeral_pub_hex: req.client_ephemeral_x25519_pub_hex,
        ingress_nonce_hex: req.ingress_nonce_hex,
        ingress_ciphertext_hex: req.encrypted_payload_hex,
        granularity: None,
        result_kind: None,
        simulate_residual_tamper: req.simulate_residual_tamper,
    };

    // 2. Run the same destructive pipeline.
    match crate::sovereign_execute(ws.core.clone(), core_req).await {
        Ok(resp) => {
            // 3. Idempotent burn on success.
            let ddc_digest = resp
                .ddc
                .compute_active_ddc_digest()
                .map(hex::encode)
                .unwrap_or_default();
            let _ = ws.credits.burn(&req.tenant_id, &req.session_id, &resp.event_id);
            let (bal, _) = ws.credits.balance(&req.tenant_id);
            let tree_size = ws.core.ledger.lock().unwrap().leaves_len();
            Json(json!({
                "status": resp.status,
                "event_id": resp.event_id,
                "session_id": resp.session_id,
                "ddc_digest_hex": ddc_digest,
                "server_ephemeral_x25519_pub_hex": resp.gateway_ephemeral_pub_hex,
                "wrap_nonce_hex": resp.wrap_nonce_hex,
                "wrapped_release_key_hex": resp.wrapped_release_seed_hex,
                "sealed_result": {
                    "ciphertext_hex": resp.sealed_result_ciphertext_hex,
                    "result_nonce_hex": resp.result_nonce_hex,
                },
                "ddc": serde_json::to_value(&resp.ddc).unwrap_or_default(),
                "merkle_inclusion": {
                    "tree_size": tree_size,
                    "leaf_index": resp.ledger_receipt.leaf_index,
                    "ddc_digest_hex": resp.ledger_receipt.ddc_digest_hex,
                },
                "ledger_receipt": serde_json::to_value(&resp.ledger_receipt).unwrap_or_default(),
                "sovereignty_usage_token": serde_json::to_value(&resp.sovereignty_usage_token).unwrap_or_default(),
                "acta_notarization": null,
                "credits": {
                    "charged_cents": ws.credits.price_cents(),
                    "balance_cents": bal
                }
            }))
            .into_response()
        }
        Err((code, body)) => (code, body).into_response(),
    }
}

// --- Credits endpoints ---

#[derive(Debug, Deserialize)]
struct RedeemRequest {
    pub tenant_id: String,
    pub code: String,
}

async fn credits_redeem(
    State(ws): State<Arc<WebState>>,
    Json(req): Json<RedeemRequest>,
) -> Response {
    let value = match ws.provider.quote(&req.code) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("{}", e), "status": "REDEEM_FAILED"})),
            )
                .into_response()
        }
    };
    match ws.credits.redeem(&req.tenant_id, &req.code, value) {
        Ok(balance) => Json(json!({
            "status": "CREDITED",
            "deposited_cents": value,
            "balance_cents": balance,
            "min_deposit_cents": MIN_DEPOSIT_CENTS,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("{}", e), "status": "REDEEM_FAILED"})),
        )
            .into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct BalanceQuery {
    pub tenant_id: String,
}

async fn credits_balance(
    State(ws): State<Arc<WebState>>,
    Query(q): Query<BalanceQuery>,
) -> Json<serde_json::Value> {
    let acct = ws.credits.account_snapshot(&q.tenant_id);
    Json(json!({
        "tenant_id": q.tenant_id,
        "balance_cents": acct.balance_cents,
        "price_cents_per_ddc": ws.credits.price_cents(),
        "min_deposit_cents": MIN_DEPOSIT_CENTS,
        "events_remaining": if ws.credits.price_cents() > 0 { acct.balance_cents / ws.credits.price_cents() } else { 0 },
        "ledger_events": acct.events.len(),
    }))
}
