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

#[derive(Debug, Clone, Default)]
pub struct MoonPayCommerceConfig {
    pub api_base: String,
    pub public_key: Option<String>,
    pub secret_key: Option<String>,
    pub paylink_id: Option<String>,
    pub webhook_secret: Option<String>,
}

impl MoonPayCommerceConfig {
    pub fn from_env() -> Self {
        let non_empty = |k: &str| std::env::var(k).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        Self {
            api_base: non_empty("MOONPAY_COMMERCE_API_BASE")
                .unwrap_or_else(|| "https://api.hel.io".to_string()),
            public_key: non_empty("MOONPAY_COMMERCE_PUBLIC_KEY"),
            secret_key: non_empty("MOONPAY_COMMERCE_SECRET_KEY"),
            paylink_id: non_empty("MOONPAY_COMMERCE_PAYLINK_ID"),
            webhook_secret: non_empty("MOONPAY_COMMERCE_WEBHOOK_SECRET"),
        }
    }

    pub fn is_checkout_configured(&self) -> bool {
        self.public_key.is_some() && self.secret_key.is_some() && self.paylink_id.is_some()
    }

    pub fn is_webhook_configured(&self) -> bool {
        self.webhook_secret.is_some()
    }
}

pub struct WebState {
    pub core: Arc<SidecarState>,
    pub credits: Arc<CreditEngine>,
    pub provider: PromoCodeProvider,
    pub tenant_auth: Arc<TenantKeyAuth>,
    pub admin_key: Option<String>,
    pub stripe_secret: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub moonpay: MoonPayCommerceConfig,
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
        .route("/v1/credits/moonpay/checkout", post(moonpay_checkout))
        .route("/v1/credits/moonpay-webhook", post(moonpay_webhook))
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

// --- Shared HMAC helpers (constant-time) ---

fn hmac_sha256_hex(secret: &str, payload: &[u8]) -> String {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_sha256_verify(secret: &str, payload: &[u8], received_hex: &str) -> bool {
    use subtle::ConstantTimeEq;
    let expected = hmac_sha256_hex(secret, payload);
    let Ok(rx_bytes) = hex::decode(received_hex.trim()) else {
        return false;
    };
    let Ok(exp_bytes) = hex::decode(&expected) else {
        return false;
    };
    if rx_bytes.len() != exp_bytes.len() {
        return false;
    }
    bool::from(rx_bytes.ct_eq(&exp_bytes))
}

fn sign_moonpay_charge_meta(secret: &str, tenant_id: &str, deposit_cents: i64) -> String {
    let msg = format!("ardyn:moonpay:{}:{}", tenant_id, deposit_cents);
    hmac_sha256_hex(secret, msg.as_bytes())
}

fn verify_moonpay_charge_meta(secret: &str, tenant_id: &str, deposit_cents: i64, sig: &str) -> bool {
    let msg = format!("ardyn:moonpay:{}:{}", tenant_id, deposit_cents);
    hmac_sha256_verify(secret, msg.as_bytes(), sig)
}

/// Parse MoonPay Commerce `customerDetails.additionalJSON`, which may arrive as
/// a JSON object, a JSON-encoded string, or a double-encoded JSON string.
fn parse_additional_json(val: &serde_json::Value) -> Option<serde_json::Value> {
    if val.is_object() {
        return Some(val.clone());
    }
    let mut cur = val.as_str()?.trim().to_string();
    for _ in 0..3 {
        if cur.is_empty() {
            return None;
        }
        match serde_json::from_str::<serde_json::Value>(&cur) {
            Ok(serde_json::Value::Object(map)) => return Some(serde_json::Value::Object(map)),
            Ok(serde_json::Value::String(inner)) => cur = inner,
            _ => return None,
        }
    }
    None
}

/// Extract settled USD cents from a MoonPay Commerce `transactionObject` when
/// settled in a USD stablecoin (USDC/USDT/USD).
fn extract_settled_stablecoin_cents(tx_obj: &serde_json::Value) -> Option<i64> {
    let meta = tx_obj.get("meta")?;
    let quote_to = meta
        .get("tokenQuote")
        .and_then(|q| q.get("to"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_uppercase());
    let currency_sym = meta
        .get("currency")
        .and_then(|c| c.get("symbol"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_uppercase());
    let symbol = quote_to.or(currency_sym)?;
    if !matches!(symbol.as_str(), "USDC" | "USDT" | "USD") {
        return None;
    }
    let decimals = meta
        .get("currency")
        .and_then(|c| c.get("decimals"))
        .and_then(|v| v.as_u64())
        .unwrap_or(6) as u32;
    let parse_u128 = |v: Option<&serde_json::Value>| -> Option<u128> {
        v.and_then(|x| {
            x.as_str()
                .and_then(|s| s.trim().parse::<u128>().ok())
                .or_else(|| x.as_u64().map(|n| n as u128))
        })
    };
    let gross_minimal = parse_u128(meta.get("tokenQuote").and_then(|q| q.get("toAmountMinimal")))
        .or_else(|| {
            let amt = parse_u128(meta.get("totalAmount"))
                .or_else(|| parse_u128(meta.get("amount")))?;
            let fee = parse_u128(tx_obj.get("fee")).unwrap_or(0);
            Some(amt.saturating_add(fee))
        })?;
    let scale = 10u128.checked_pow(decimals)?;
    // Round to nearest cent: (gross_minimal * 100 + scale / 2) / scale
    let cents = gross_minimal
        .checked_mul(100)?
        .checked_add(scale / 2)?
        / scale;
    i64::try_from(cents).ok()
}

fn append_cardonly_query(url: &str) -> String {
    if url.contains("cardonly=") {
        url.to_string()
    } else if url.contains('?') {
        format!("{}&cardonly=true", url)
    } else {
        format!("{}?cardonly=true", url)
    }
}

fn url_encode_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

// --- Unified Checkout (MoonPay Commerce + Stripe) ---

#[derive(Debug, Deserialize)]
struct CheckoutRequest {
    pub tenant_id: String,
    pub deposit_cents: i64,
    /// Optional explicit provider: "moonpay" | "stripe". If omitted, prefers
    /// MoonPay Commerce when configured, else Stripe.
    #[serde(default)]
    pub provider: Option<String>,
    /// MoonPay Commerce option: append ?cardonly=true to launch card checkout directly.
    #[serde(default)]
    pub card_only: Option<bool>,
    #[serde(default)]
    pub customer_email: Option<String>,
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

    let wanted = req.provider.as_deref().map(|s| s.trim().to_ascii_lowercase());
    match wanted.as_deref() {
        Some("moonpay") | Some("moonpay_commerce") | Some("helio") => {
            create_moonpay_charge(&ws, &req).await
        }
        Some("stripe") => create_stripe_checkout(&ws, &req).await,
        Some(other) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "UNSUPPORTED_PROVIDER", "provider": other, "supported": ["moonpay", "stripe"]})),
        )
            .into_response(),
        None => {
            if ws.moonpay.is_checkout_configured() {
                create_moonpay_charge(&ws, &req).await
            } else if ws.stripe_secret.is_some() {
                create_stripe_checkout(&ws, &req).await
            } else {
                (
                    StatusCode::NOT_IMPLEMENTED,
                    Json(json!({
                        "error": "PAYMENT_PROVIDER_NOT_CONFIGURED",
                        "hint": "Set MOONPAY_COMMERCE_PUBLIC_KEY + MOONPAY_COMMERCE_SECRET_KEY + MOONPAY_COMMERCE_PAYLINK_ID (card + USDC) or STRIPE_SECRET_KEY on the sidecar; promo-code redemption is available today at /v1/credits/redeem"
                    })),
                )
                    .into_response()
            }
        }
    }
}

async fn moonpay_checkout(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    Json(mut req): Json<CheckoutRequest>,
) -> Response {
    req.provider = Some("moonpay".to_string());
    credits_checkout(State(ws), headers, Json(req)).await
}

async fn create_moonpay_charge(ws: &WebState, req: &CheckoutRequest) -> Response {
    let (Some(public_key), Some(secret_key), Some(paylink_id)) = (
        ws.moonpay.public_key.as_deref(),
        ws.moonpay.secret_key.as_deref(),
        ws.moonpay.paylink_id.as_deref(),
    ) else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "MOONPAY_COMMERCE_NOT_CONFIGURED",
                "hint": "Set MOONPAY_COMMERCE_PUBLIC_KEY, MOONPAY_COMMERCE_SECRET_KEY, and MOONPAY_COMMERCE_PAYLINK_ID (plus MOONPAY_COMMERCE_WEBHOOK_SECRET for automatic crediting)"
            })),
        )
            .into_response();
    };

    let signing_key = ws
        .moonpay
        .webhook_secret
        .as_deref()
        .unwrap_or(secret_key);
    let charge_sig = sign_moonpay_charge_meta(signing_key, &req.tenant_id, req.deposit_cents);
    let meta_json = json!({
        "tenant_id": req.tenant_id,
        "deposit_cents": req.deposit_cents,
        "product": "ardyn_ads_credits",
        "charge_sig": charge_sig,
    })
    .to_string();

    let request_amount = format!("{:.2}", req.deposit_cents as f64 / 100.0);
    let encoded_tenant = url_encode_simple(&req.tenant_id);
    let mut customer_details = serde_json::Map::new();
    customer_details.insert("additionalJSON".to_string(), json!(meta_json));
    if let Some(email) = req.customer_email.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        customer_details.insert("email".to_string(), json!(email));
    }

    let payload = json!({
        "paymentRequestId": paylink_id,
        "requestAmount": request_amount,
        "successRedirectUrl": format!("https://ardyn.ai/ads/?checkout=success&provider=moonpay&tenant={}", encoded_tenant),
        "cancelRedirectUrl": "https://ardyn.ai/ads/?checkout=cancelled&provider=moonpay",
        "prepareRequestBody": {
            "customerDetails": customer_details
        }
    });

    let base = ws.moonpay.api_base.trim_end_matches('/');
    let endpoint = format!("{}/v1/charge/api-key?apiKey={}", base, url_encode_simple(public_key));
    let client = reqwest::Client::new();
    match client
        .post(&endpoint)
        .bearer_auth(secret_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let txt = resp.text().await.unwrap_or_default();
            if status.is_success() {
                let v: serde_json::Value = serde_json::from_str(&txt).unwrap_or_default();
                let Some(page_url) = v.get("pageUrl").and_then(|u| u.as_str()).filter(|s| !s.is_empty()) else {
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"error": "MOONPAY_INVALID_RESPONSE", "detail": txt})),
                    )
                        .into_response();
                };
                let card_url = append_cardonly_query(page_url);
                let chosen_url = if req.card_only.unwrap_or(false) {
                    card_url.clone()
                } else {
                    page_url.to_string()
                };
                let charge_token = page_url
                    .split('?')
                    .next()
                    .unwrap_or(page_url)
                    .rsplit('/')
                    .next()
                    .unwrap_or_default();
                Json(json!({
                    "status": "CHECKOUT_CREATED",
                    "provider": "moonpay_commerce",
                    "checkout_url": chosen_url,
                    "card_checkout_url": card_url,
                    "crypto_checkout_url": page_url,
                    "charge_id": v["id"],
                    "charge_token": charge_token,
                    "deposit_cents": req.deposit_cents,
                    "note": "credits are applied automatically by /v1/credits/moonpay-webhook once payment completes"
                }))
                .into_response()
            } else {
                (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({"error": "MOONPAY_API_ERROR", "upstream_status": status.as_u16(), "detail": txt})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "MOONPAY_UNREACHABLE", "detail": e.to_string()})),
        )
            .into_response(),
    }
}

async fn create_stripe_checkout(ws: &WebState, req: &CheckoutRequest) -> Response {
    let Some(secret) = ws.stripe_secret.clone() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "STRIPE_NOT_CONFIGURED",
                "hint": "Set STRIPE_SECRET_KEY on the sidecar to enable Stripe checkout; promo-code redemption is available today at /v1/credits/redeem"
            })),
        )
            .into_response();
    };
    let body = [
        ("mode", "payment".to_string()),
        ("success_url", format!("https://ardyn.ai/ads/?checkout=success&provider=stripe&tenant={}", url_encode_simple(&req.tenant_id))),
        ("cancel_url", "https://ardyn.ai/ads/?checkout=cancelled&provider=stripe".to_string()),
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
                    "provider": "stripe",
                    "checkout_url": v["url"],
                    "session_id": v["id"],
                    "deposit_cents": req.deposit_cents,
                    "note": "credits are applied by /v1/credits/stripe-webhook after payment completes"
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

// --- MoonPay Commerce webhook: verifies X-Signature HMAC-SHA256, credits tenant idempotently ---

async fn moonpay_webhook(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
    let Some(secret) = ws.moonpay.webhook_secret.as_deref() else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "MOONPAY_WEBHOOK_NOT_CONFIGURED", "hint": "set MOONPAY_COMMERCE_WEBHOOK_SECRET"})),
        )
            .into_response();
    };
    let sig = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if sig.is_empty() || !hmac_sha256_verify(secret, body.as_bytes(), sig) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "INVALID_SIGNATURE"}))).into_response();
    }

    let ev: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"error": "BAD_JSON"}))).into_response(),
    };

    let event_name = ev["event"].as_str().unwrap_or_default();
    if event_name != "CREATED" {
        return Json(json!({"status": "IGNORED", "event": event_name})).into_response();
    }

    // Prefer transactionObject; fall back to parsing stringified `transaction`.
    let tx_obj = if ev["transactionObject"].is_object() {
        ev["transactionObject"].clone()
    } else if let Some(s) = ev["transaction"].as_str() {
        serde_json::from_str::<serde_json::Value>(s).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };
    if !tx_obj.is_object() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "MISSING_TRANSACTION_OBJECT"}))).into_response();
    }

    // Only credit confirmed successful transactions.
    if let Some(tx_status) = tx_obj["meta"]["transactionStatus"].as_str() {
        if !tx_status.eq_ignore_ascii_case("SUCCESS") {
            return Json(json!({
                "status": "IGNORED",
                "reason": "transaction_not_success",
                "transaction_status": tx_status
            }))
            .into_response();
        }
    }

    // Defense-in-depth: scope to configured Pay Link ID when set.
    if let (Some(expected_pl), Some(actual_pl)) = (
        ws.moonpay.paylink_id.as_deref(),
        tx_obj["paylinkId"].as_str(),
    ) {
        if !actual_pl.is_empty() && actual_pl != expected_pl {
            return Json(json!({
                "status": "IGNORED",
                "reason": "paylink_mismatch"
            }))
            .into_response();
        }
    }

    let add_json = parse_additional_json(&tx_obj["meta"]["customerDetails"]["additionalJSON"]);
    let tenant_id = add_json
        .as_ref()
        .and_then(|j| j.get("tenant_id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    if tenant_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "MISSING_TENANT_ID", "hint": "charge additionalJSON must include tenant_id"})),
        )
            .into_response();
    }

    let meta_cents = add_json
        .as_ref()
        .and_then(|j| j.get("deposit_cents"))
        .and_then(|v| v.as_i64());
    let charge_sig = add_json
        .as_ref()
        .and_then(|j| j.get("charge_sig"))
        .and_then(|v| v.as_str());
    let sig_valid = match (meta_cents, charge_sig) {
        (Some(cents), Some(s)) if cents > 0 => {
            verify_moonpay_charge_meta(secret, &tenant_id, cents, s)
                || ws
                    .moonpay
                    .secret_key
                    .as_deref()
                    .map(|k| verify_moonpay_charge_meta(k, &tenant_id, cents, s))
                    .unwrap_or(false)
        }
        _ => false,
    };

    let settled_cents = extract_settled_stablecoin_cents(&tx_obj);
    let amount_cents = match (meta_cents, sig_valid, settled_cents) {
        (Some(cents), true, Some(settled)) => {
            // Cross-check settled stablecoin amount against server-signed charge amount
            // (allow up to 5% difference for on-chain/platform fee deductions).
            if settled < (cents * 95) / 100 {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "UNDERPAID_SETTLEMENT",
                        "expected_cents": cents,
                        "settled_cents": settled
                    })),
                )
                    .into_response();
            }
            cents
        }
        (Some(cents), true, None) => cents,
        (_, _, Some(settled)) if settled > 0 => settled,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "UNVERIFIED_AMOUNT", "hint": "missing signed deposit_cents or stablecoin settlement amount"})),
            )
                .into_response();
        }
    };

    let tx_id = tx_obj["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| ev["chargeToken"].as_str().filter(|s| !s.is_empty()))
        .or_else(|| tx_obj["meta"]["transactionSignature"].as_str().filter(|s| !s.is_empty()))
        .unwrap_or("moonpay-unknown");
    let reference = format!("moonpay:{}", tx_id);

    match ws.credits.deposit_once(&tenant_id, &reference, amount_cents) {
        Ok((bal, newly_credited)) => Json(json!({
            "status": if newly_credited { "CREDITED" } else { "ALREADY_CREDITED" },
            "provider": "moonpay_commerce",
            "tenant_id": tenant_id,
            "credited_cents": if newly_credited { amount_cents } else { 0 },
            "balance_cents": bal,
            "reference": reference
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": format!("{}", e)}))).into_response(),
    }
}

// --- Stripe webhook: verifies signature, credits the tenant balance idempotently ---

async fn stripe_webhook(
    State(ws): State<Arc<WebState>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Response {
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
    if v1.is_empty() || !hmac_sha256_verify(&secret, signed.as_bytes(), &v1) {
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
    let reference = format!("stripe:{}", session_id);
    match ws.credits.deposit_once(&tenant, &reference, amount) {
        Ok((b, newly_credited)) => Json(json!({
            "status": if newly_credited { "CREDITED" } else { "ALREADY_CREDITED" },
            "provider": "stripe",
            "tenant_id": tenant,
            "credited_cents": if newly_credited { amount } else { 0 },
            "balance_cents": b,
            "reference": reference
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({"error": format!("{}", e)}))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use tokio::sync::Mutex as TokioMutex;

    fn test_web_state(api_base: String) -> Arc<WebState> {
        let core = Arc::new(SidecarState::new(None, None));
        let credits = Arc::new(CreditEngine::new(
            ads_metering::credits::DEFAULT_EVENT_PRICE_CENTS,
            None,
        ));
        let mk = "11".repeat(32);
        let tenant_auth = Arc::new(TenantKeyAuth::new(
            Some(&mk),
            vec!["ardyn_web_console".into()],
        ));
        Arc::new(WebState {
            core,
            credits,
            provider: PromoCodeProvider::from_env(""),
            tenant_auth,
            admin_key: Some("adm-secret".into()),
            stripe_secret: None,
            stripe_webhook_secret: None,
            moonpay: MoonPayCommerceConfig {
                api_base,
                public_key: Some("pk_test_123".into()),
                secret_key: Some("sk_test_456".into()),
                paylink_id: Some("pl_ads_001".into()),
                webhook_secret: Some("whsec_shared_token_xyz".into()),
            },
            demo_seeds: vec![],
        })
    }

    async fn resp_json(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!({}));
        (status, v)
    }

    #[tokio::test]
    async fn test_moonpay_checkout_and_signed_webhook_e2e_idempotent() {
        // Spin up local mock MoonPay Commerce API server
        let captured: Arc<TokioMutex<Option<(String, String, serde_json::Value)>>> =
            Arc::new(TokioMutex::new(None));
        let cap_clone = captured.clone();
        let mock_app = Router::new().route(
            "/v1/charge/api-key",
            post(move |Query(q): Query<HashMap<String, String>>, headers: HeaderMap, Json(body): Json<serde_json::Value>| {
                let cap = cap_clone.clone();
                async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_string();
                    let api_key = q.get("apiKey").cloned().unwrap_or_default();
                    *cap.lock().await = Some((api_key, auth, body));
                    Json(json!({
                        "id": "chg_abc123",
                        "pageUrl": "https://app.hel.io/charge/2ac13665-9cfe-4466-b294-05069d57b0a2"
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock_app).await.unwrap() });

        let ws = test_web_state(format!("http://{}", addr));
        let tenant_key = ws.tenant_auth.mint("acme-prod").unwrap();
        let mut hdrs = HeaderMap::new();
        hdrs.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", tenant_key)).unwrap());

        // 1. Create MoonPay checkout (card_only = true)
        let (st, out) = resp_json(
            credits_checkout(
                State(ws.clone()),
                hdrs,
                Json(CheckoutRequest {
                    tenant_id: "acme-prod".into(),
                    deposit_cents: 5000,
                    provider: Some("moonpay".into()),
                    card_only: Some(true),
                    customer_email: Some("billing@acme.io".into()),
                }),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(out["provider"], "moonpay_commerce");
        assert_eq!(
            out["checkout_url"],
            "https://app.hel.io/charge/2ac13665-9cfe-4466-b294-05069d57b0a2?cardonly=true"
        );
        assert_eq!(
            out["crypto_checkout_url"],
            "https://app.hel.io/charge/2ac13665-9cfe-4466-b294-05069d57b0a2"
        );
        assert_eq!(out["charge_token"], "2ac13665-9cfe-4466-b294-05069d57b0a2");

        // Verify upstream MoonPay API call shape
        let (api_key, auth, sent_body) = captured.lock().await.clone().unwrap();
        assert_eq!(api_key, "pk_test_123");
        assert_eq!(auth, "Bearer sk_test_456");
        assert_eq!(sent_body["paymentRequestId"], "pl_ads_001");
        assert_eq!(sent_body["requestAmount"], "50.00");
        let add_json_str = sent_body["prepareRequestBody"]["customerDetails"]["additionalJSON"]
            .as_str()
            .unwrap()
            .to_string();

        // 2. Deliver MoonPay CREATED webhook with DOUBLE-ENCODED additionalJSON (real Helio format)
        let double_encoded = serde_json::to_string(&add_json_str).unwrap();
        let webhook_payload = json!({
            "event": "CREATED",
            "chargeToken": "2ac13665-9cfe-4466-b294-05069d57b0a2",
            "transactionObject": {
                "id": "tx_mp_999",
                "paylinkId": "pl_ads_001",
                "fee": "500000",
                "meta": {
                    "amount": "49500000",
                    "totalAmount": "49500000",
                    "transactionStatus": "SUCCESS",
                    "transactionSignature": "5AYz...",
                    "customerDetails": {
                        "additionalJSON": double_encoded
                    },
                    "tokenQuote": {
                        "from": "USD",
                        "to": "USDC",
                        "toAmountMinimal": "50000000"
                    }
                }
            }
        })
        .to_string();

        let sig = hmac_sha256_hex("whsec_shared_token_xyz", webhook_payload.as_bytes());
        let mut wh_hdrs = HeaderMap::new();
        wh_hdrs.insert("X-Signature", HeaderValue::from_str(&sig).unwrap());

        let (wst, wout) = resp_json(
            moonpay_webhook(State(ws.clone()), wh_hdrs.clone(), webhook_payload.clone()).await,
        )
        .await;
        assert_eq!(wst, StatusCode::OK);
        assert_eq!(wout["status"], "CREDITED");
        assert_eq!(wout["credited_cents"], 5000);
        assert_eq!(wout["balance_cents"], 5000);
        assert_eq!(ws.credits.balance("acme-prod").0, 5000);

        // 3. Replay same webhook -> idempotent ALREADY_CREDITED, balance stays 5000
        let (wst2, wout2) = resp_json(
            moonpay_webhook(State(ws.clone()), wh_hdrs, webhook_payload).await,
        )
        .await;
        assert_eq!(wst2, StatusCode::OK);
        assert_eq!(wout2["status"], "ALREADY_CREDITED");
        assert_eq!(wout2["credited_cents"], 0);
        assert_eq!(ws.credits.balance("acme-prod").0, 5000);
    }

    #[tokio::test]
    async fn test_moonpay_webhook_security_guards() {
        let ws = test_web_state("http://127.0.0.1:1".into());
        let payload = json!({
            "event": "CREATED",
            "transactionObject": {
                "id": "tx_bad_sig",
                "paylinkId": "pl_ads_001",
                "meta": {
                    "transactionStatus": "SUCCESS",
                    "customerDetails": {
                        "additionalJSON": "{\"tenant_id\":\"acme\",\"deposit_cents\":2500}"
                    }
                }
            }
        })
        .to_string();

        // Bad signature -> 401
        let mut bad_hdrs = HeaderMap::new();
        bad_hdrs.insert("X-Signature", HeaderValue::from_static("deadbeef"));
        let (st, _) = resp_json(moonpay_webhook(State(ws.clone()), bad_hdrs, payload.clone()).await).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // Valid signature, but unsigned deposit_cents + no stablecoin settlement -> 400 fail-closed
        let sig = hmac_sha256_hex("whsec_shared_token_xyz", payload.as_bytes());
        let mut ok_hdrs = HeaderMap::new();
        ok_hdrs.insert("X-Signature", HeaderValue::from_str(&sig).unwrap());
        let (st2, out2) = resp_json(moonpay_webhook(State(ws.clone()), ok_hdrs, payload).await).await;
        assert_eq!(st2, StatusCode::BAD_REQUEST);
        assert_eq!(out2["error"], "UNVERIFIED_AMOUNT");
        assert_eq!(ws.credits.balance("acme").0, 0);

        // Wrong paylinkId -> IGNORED
        let wrong_pl = json!({
            "event": "CREATED",
            "transactionObject": {
                "id": "tx_wrong_pl",
                "paylinkId": "pl_other_999",
                "meta": {
                    "transactionStatus": "SUCCESS",
                    "customerDetails": {
                        "additionalJSON": "{\"tenant_id\":\"acme\"}"
                    },
                    "tokenQuote": { "to": "USDC", "toAmountMinimal": "25000000" }
                }
            }
        })
        .to_string();
        let sig_pl = hmac_sha256_hex("whsec_shared_token_xyz", wrong_pl.as_bytes());
        let mut pl_hdrs = HeaderMap::new();
        pl_hdrs.insert("X-Signature", HeaderValue::from_str(&sig_pl).unwrap());
        let (st3, out3) = resp_json(moonpay_webhook(State(ws.clone()), pl_hdrs, wrong_pl).await).await;
        assert_eq!(st3, StatusCode::OK);
        assert_eq!(out3["status"], "IGNORED");
        assert_eq!(ws.credits.balance("acme").0, 0);

        // Direct USDC settlement without charge_sig -> credits exact settled USDC
        let direct_usdc = json!({
            "event": "CREATED",
            "transactionObject": {
                "id": "tx_direct_usdc",
                "paylinkId": "pl_ads_001",
                "meta": {
                    "transactionStatus": "SUCCESS",
                    "customerDetails": {
                        "additionalJSON": "{\"tenant_id\":\"direct-usdc-tenant\"}"
                    },
                    "tokenQuote": { "to": "USDC", "toAmountMinimal": "30000000" }
                }
            }
        })
        .to_string();
        let sig_du = hmac_sha256_hex("whsec_shared_token_xyz", direct_usdc.as_bytes());
        let mut du_hdrs = HeaderMap::new();
        du_hdrs.insert("X-Signature", HeaderValue::from_str(&sig_du).unwrap());
        let (st4, out4) = resp_json(moonpay_webhook(State(ws.clone()), du_hdrs, direct_usdc).await).await;
        assert_eq!(st4, StatusCode::OK);
        assert_eq!(out4["status"], "CREDITED");
        assert_eq!(out4["credited_cents"], 3000);
        assert_eq!(ws.credits.balance("direct-usdc-tenant").0, 3000);
    }

    #[tokio::test]
    async fn test_checkout_enforces_tenant_auth_and_minimum() {
        let ws = test_web_state("http://127.0.0.1:1".into());
        // Protected tenant without key -> 401
        let (st, _) = resp_json(
            credits_checkout(
                State(ws.clone()),
                HeaderMap::new(),
                Json(CheckoutRequest {
                    tenant_id: "private-co".into(),
                    deposit_cents: 2500,
                    provider: Some("moonpay".into()),
                    card_only: None,
                    customer_email: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // Keyless demo tenant below $25 minimum -> 400
        let (st2, _) = resp_json(
            credits_checkout(
                State(ws.clone()),
                HeaderMap::new(),
                Json(CheckoutRequest {
                    tenant_id: "ardyn_web_console".into(),
                    deposit_cents: 500,
                    provider: Some("moonpay".into()),
                    card_only: None,
                    customer_email: None,
                }),
            )
            .await,
        )
        .await;
        assert_eq!(st2, StatusCode::BAD_REQUEST);
    }
}
