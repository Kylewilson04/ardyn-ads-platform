// crates/ads-sidecar/src/web.rs — Ardyn web console contract (v1.1.0).
//
// Drop-in compatibility with the deployed ADS sidecar contract used by
// https://ardyn.ai: GET /v1/pubkey, POST /v1/execute, GET /v1/health — plus
// the prepaid credits endpoints. Adds permissive CORS so browser clients
// (the sovereign-client WebCrypto SDK) can call this pod directly.

use crate::{SidecarState, SovereignExecuteRequest};
use ads_metering::credits::{
    CreditEngine, PaymentProvider, PromoCodeProvider, TenantAuthVerdict, TenantKeyAuth,
    MIN_DEPOSIT_CENTS,
};
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
    pub tenant_auth: Arc<TenantKeyAuth>,
    pub admin_key: Option<String>,
    pub stripe_secret: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    /// Tenants seeded with a complimentary demo balance (e.g. "ardyn_web_console:500").
    pub demo_seeds: Vec<(String, i64)>,
}

/// Extract the bearer token from an Authorization header.
fn bearer_of(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

/// Tenant auth gate. Keyless allowlisted tenants pass; protected tenants must
/// present a valid ads_tk_v1 key bound to the same tenant — fail closed.
fn tenant_authorized(ws: &WebState, headers: &axum::http::HeaderMap, tenant_id: &str) -> bool {
    let verdict = ws.tenant_auth.verify(bearer_of(headers).as_deref(), tenant_id);
    matches!(verdict, TenantAuthVerdict::KeylessAllowed | TenantAuthVerdict::Keyed(_))
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
        .route("/v1/credits/checkout", post(credits_checkout))
        .route("/v1/credits/stripe-webhook", post(stripe_webhook))
        .route("/v1/tenants/mint", post(tenants_mint))
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
    headers: axum::http::HeaderMap,
    Json(req): Json<WebExecuteRequest>,
) -> Response {
    // -1. Tenant auth gate — ads_tk_v1 key or keyless allowlist, fail closed.
    if ws.tenant_auth.enabled() && !tenant_authorized(&ws, &headers, &req.tenant_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "TENANT_AUTH_REQUIRED: present a valid ads_tk_v1:<tenant>:<mac> Bearer key bound to this tenant",
                "status": "AUTH_REQUIRED"
            })),
        )
            .into_response();
    }
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
    headers: axum::http::HeaderMap,
    Query(q): Query<BalanceQuery>,
) -> Response {
    if ws.tenant_auth.enabled() && !tenant_authorized(&ws, &headers, &q.tenant_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "TENANT_AUTH_REQUIRED", "status": "AUTH_REQUIRED"})),
        )
            .into_response();
    }
    let acct = ws.credits.account_snapshot(&q.tenant_id);
    Json(json!({
        "tenant_id": q.tenant_id,
        "balance_cents": acct.balance_cents,
        "price_cents_per_ddc": ws.credits.price_cents(),
        "min_deposit_cents": MIN_DEPOSIT_CENTS,
        "events_remaining": if ws.credits.price_cents() > 0 { acct.balance_cents / ws.credits.price_cents() } else { 0 },
        "ledger_events": acct.events.len(),
    }))
    .into_response()
}

// --- Tenant key minting (admin) ---

#[derive(Debug, Deserialize)]
struct MintRequest {
    pub tenant_id: String,
}

async fn tenants_mint(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MintRequest>,
) -> Response {
    let presented = bearer_of(&headers).unwrap_or_default();
    let ok = ws
        .admin_key
        .as_ref()
        .map(|k| !k.is_empty() && k == &presented)
        .unwrap_or(false);
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "ADMIN_KEY_REQUIRED", "status": "AUTH_REQUIRED"})),
        )
            .into_response();
    }
    match ws.tenant_auth.mint(&req.tenant_id) {
        Ok(key) => Json(json!({
            "status": "MINTED",
            "tenant_id": req.tenant_id,
            "tenant_key": key,
            "usage": "Authorization: Bearer <tenant_key>  (bound to this tenant only)",
        }))
        .into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("{}", e), "hint": "set ADS_TENANT_MASTER_KEY to enable key minting"})),
        )
            .into_response(),
    }
}

// --- Stripe checkout (activates when STRIPE_SECRET_KEY is set) ---

#[derive(Debug, Deserialize)]
struct CheckoutRequest {
    pub tenant_id: String,
    pub deposit_cents: i64,
}

async fn credits_checkout(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<CheckoutRequest>,
) -> Response {
    if ws.tenant_auth.enabled() && !tenant_authorized(&ws, &headers, &req.tenant_id) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "TENANT_AUTH_REQUIRED", "status": "AUTH_REQUIRED"})),
        )
            .into_response();
    }
    if req.deposit_cents < MIN_DEPOSIT_CENTS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("MIN_DEPOSIT: below the ${} minimum", MIN_DEPOSIT_CENTS / 100)})),
        )
            .into_response();
    }
    let Some(secret) = ws.stripe_secret.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "STRIPE_NOT_CONFIGURED",
                "hint": "Set STRIPE_SECRET_KEY on the sidecar to enable card checkout; promo-code redemption is available today at /v1/credits/redeem"
            })),
        )
            .into_response();
    };
    // Create a Stripe Checkout Session (deposit = price_data line item).
    let body = [
        ("mode", "payment".to_string()),
        ("success_url", format!("https://ardyn.ai/ads/?checkout=success&tenant={}", req.tenant_id)),
        ("cancel_url", "https://ardyn.ai/ads/?checkout=cancelled".to_string()),
        ("client_reference_id", req.tenant_id.clone()),
        ("line_items[0][quantity]", "1".to_string()),
        ("line_items[0][price_data][currency]".into(), "usd".to_string()),
        ("line_items[0][price_data][unit_amount]".into(), req.deposit_cents.to_string()),
        ("line_items[0][price_data][product_data][name]".into(), format!("Ardyn ADS Sovereign Credits — ${:.2}", req.deposit_cents as f64 / 100.0)),
    ];
    let client = reqwest::Client::new();
    match client
        .post("https://api.stripe.com/v1/checkout/sessions")
        .basic_auth(secret, Some(""))
        .form(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            if status.is_success() {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
                Json(json!({
                    "status": "CHECKOUT_CREATED",
                    "checkout_url": v["url"],
                    "session_id": v["id"],
                    "deposit_cents": req.deposit_cents,
                    "note": "credits are applied by the /v1/credits/stripe-webhook after payment completes"
                }))
                .into_response()
            } else {
                (StatusCode::BAD_GATEWAY, Json(json!({"error": "STRIPE_API_ERROR", "detail": txt}))).into_response()
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "STRIPE_UNREACHABLE", "detail": e.to_string()})),
        )
            .into_response(),
    }
}

// --- Stripe webhook: verifies signature, credits the tenant balance ---

async fn stripe_webhook(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    use hmac::Mac;
    let Some(secret) = ws.stripe_webhook_secret.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "STRIPE_WEBHOOK_NOT_CONFIGURED", "hint": "set STRIPE_WEBHOOK_SECRET"})),
        )
            .into_response();
    };
    let sig = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    // Stripe-Signature: t=<ts>,v1=<hmac>
    let mut ts = String::new();
    let mut v1 = String::new();
    for part in sig.split(',') {
        if let Some(t) = part.strip_prefix("t=") { ts = t.to_string(); }
        if let Some(h) = part.strip_prefix("v1=") { v1 = h.to_string(); }
    }
    let signed = format!("{}.{}", ts, body);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let expect = hex::encode(mac.finalize().into_bytes());
    if v1 != expect {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "INVALID_SIGNATURE"}))).into_response();
    }
    let ev: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "BAD_JSON"}))).into_response(),
    };
    if ev["type"] != "checkout.session.completed" {
        return Json(json!({"status": "IGNORED", "type": ev["type"]})).into_response();
    }
    let tenant = ev["data"]["object"]["client_reference_id"].as_str().unwrap_or_default().to_string();
    let amount = ev["data"]["object"]["amount_total"].as_i64().unwrap_or(0);
    if tenant.is_empty() || amount <= 0 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "MISSING_TENANT_OR_AMOUNT"}))).into_response();
    }
    let session_id = ev["data"]["object"]["id"].as_str().unwrap_or("stripe-unknown").to_string();
    let bal = ws.credits.redeem(&tenant, &format!("stripe:{}", session_id), amount);
    match bal {
        Ok(b) => Json(json!({"status": "CREDITED", "tenant_id": tenant, "credited_cents": amount, "balance_cents": b})).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": format!("{}", e)}))).into_response(),
    }
}
