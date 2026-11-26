// crates/ads-metering/src/credits.rs — Prepaid sovereign-credit ledger (OpenRouter-style deposits).
//
// Model: tenants pre-fund a balance in US cents (1 credit = $0.01). Every
// successful sovereign execution burns a fixed price (default $0.50 = 50
// cents). Burns are idempotent per (tenant, session_id) — a retried request
// never double-burns. Fails closed: insufficient balance denies execution
// with a 402-class error before any ciphertext is decrypted.
//
// Payment providers are behind `PaymentProvider`. Today: promo codes (manual
// deposits). Stripe checkout slots into the same trait later without touching
// the ledger: create_checkout(cents) -> pending payment, webhook confirms,
// confirm() credits the balance atomically.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

pub const MIN_DEPOSIT_CENTS: i64 = 2500; // $25 minimum deposit
pub const DEFAULT_EVENT_PRICE_CENTS: i64 = 50; // $0.50 per DDC

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditEvent {
    pub kind: String, // "deposit" | "burn" | "refund"
    pub amount_cents: i64,
    pub reference: String, // promo code / session_id / event_id
    pub balance_after_cents: i64,
    pub timestamp_utc_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CreditAccount {
    pub balance_cents: i64,
    pub events: Vec<CreditEvent>,
    pub burned_sessions: Vec<String>, // idempotency: sessions already charged
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct LedgerFile {
    accounts: HashMap<String, CreditAccount>,
}

pub struct CreditEngine {
    accounts: Mutex<HashMap<String, CreditAccount>>,
    price_cents: i64,
    persist_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum CreditError {
    #[error("INSUFFICIENT_CREDITS: balance {balance_cents}c < price {price_cents}c — minimum deposit is ${} ", min_deposit_cents / 100)]
    Insufficient { balance_cents: i64, price_cents: i64, min_deposit_cents: i64 },
    #[error("MIN_DEPOSIT: ${} is below the ${} minimum deposit", requested_cents / 100, min_cents / 100)]
    BelowMinimum { requested_cents: i64, min_cents: i64 },
    #[error("INVALID_PROMO_CODE")]
    InvalidCode,
}

impl CreditEngine {
    pub fn new(price_cents: i64, persist_path: Option<PathBuf>) -> Self {
        let engine = Self {
            accounts: Mutex::new(HashMap::new()),
            price_cents: price_cents.max(1),
            persist_path,
        };
        engine.load();
        engine
    }

    pub fn price_cents(&self) -> i64 {
        self.price_cents
    }

    fn load(&self) {
        if let Some(p) = &self.persist_path {
            if let Ok(txt) = std::fs::read_to_string(p) {
                if let Ok(file) = serde_json::from_str::<LedgerFile>(&txt) {
                    *self.accounts.lock().unwrap() = file.accounts;
                }
            }
        }
    }

    fn persist(&self, accounts: &HashMap<String, CreditAccount>) {
        if let Some(p) = &self.persist_path {
            let file = LedgerFile {
                accounts: accounts.clone(),
            };
            // Ensure the parent directory exists (e.g. /data/ads-credits/).
            if let Some(parent) = p.parent() {
                if std::fs::create_dir_all(parent).is_err() {
                    eprintln!("[credits] WARN: cannot create persist dir {}", parent.display());
                }
            }
            let tmp = p.with_extension("json.tmp");
            match serde_json::to_string_pretty(&file)
                .ok()
                .and_then(|s| std::fs::write(&tmp, s).ok())
            {
                Some(()) => {
                    if std::fs::rename(&tmp, p).is_err() {
                        eprintln!("[credits] WARN: rename failed for {}", p.display());
                    }
                }
                None => eprintln!("[credits] WARN: persist write failed for {}", p.display()),
            }
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Complimentary demo seed (bypasses the deposit minimum; event kind "seed").
    pub fn seed(&self, tenant_id: &str, label: &str, cents: i64) -> i64 {
        let mut accounts = self.accounts.lock().unwrap();
        let acct = accounts.entry(tenant_id.to_string()).or_default();
        acct.balance_cents += cents;
        acct.events.push(CreditEvent {
            kind: "seed".into(),
            amount_cents: cents,
            reference: label.into(),
            balance_after_cents: acct.balance_cents,
            timestamp_utc_ms: Self::now_ms(),
        });
        let bal = acct.balance_cents;
        self.persist(&accounts);
        bal
    }

    /// Deposit via promo code. Enforces the $25 minimum per code redemption.
    pub fn redeem(&self, tenant_id: &str, code: &str, code_value_cents: i64) -> Result<i64, CreditError> {
        if code_value_cents < MIN_DEPOSIT_CENTS {
            return Err(CreditError::BelowMinimum {
                requested_cents: code_value_cents,
                min_cents: MIN_DEPOSIT_CENTS,
            });
        }
        let mut accounts = self.accounts.lock().unwrap();
        let acct = accounts.entry(tenant_id.to_string()).or_default();
        let ev = CreditEvent {
            kind: "deposit".into(),
            amount_cents: code_value_cents,
            reference: format!("promo:{}", code),
            balance_after_cents: acct.balance_cents + code_value_cents,
            timestamp_utc_ms: Self::now_ms(),
        };
        acct.balance_cents += code_value_cents;
        acct.events.push(ev);
        let bal = acct.balance_cents;
        self.persist(&accounts);
        Ok(bal)
    }

    /// Pre-flight check: does this tenant have enough credit for one event?
    pub fn authorize(&self, tenant_id: &str) -> Result<(), CreditError> {
        let accounts = self.accounts.lock().unwrap();
        let bal = accounts.get(tenant_id).map(|a| a.balance_cents).unwrap_or(0);
        if bal < self.price_cents {
            return Err(CreditError::Insufficient {
                balance_cents: bal,
                price_cents: self.price_cents,
                min_deposit_cents: MIN_DEPOSIT_CENTS,
            });
        }
        Ok(())
    }

    /// Idempotent burn for a successfully executed destruction event.
    pub fn burn(&self, tenant_id: &str, session_id: &str, event_id: &str) -> Result<i64, CreditError> {
        let mut accounts = self.accounts.lock().unwrap();
        let acct = accounts.entry(tenant_id.to_string()).or_default();
        if acct.burned_sessions.iter().any(|s| s == session_id) {
            return Ok(acct.balance_cents); // already charged for this session
        }
        if acct.balance_cents < self.price_cents {
            return Err(CreditError::Insufficient {
                balance_cents: acct.balance_cents,
                price_cents: self.price_cents,
                min_deposit_cents: MIN_DEPOSIT_CENTS,
            });
        }
        acct.balance_cents -= self.price_cents;
        acct.burned_sessions.push(session_id.to_string());
        acct.events.push(CreditEvent {
            kind: "burn".into(),
            amount_cents: -self.price_cents,
            reference: format!("{}:{}", session_id, event_id),
            balance_after_cents: acct.balance_cents,
            timestamp_utc_ms: Self::now_ms(),
        });
        let bal = acct.balance_cents;
        self.persist(&accounts);
        Ok(bal)
    }

    pub fn balance(&self, tenant_id: &str) -> (i64, usize) {
        let accounts = self.accounts.lock().unwrap();
        let a = accounts.get(tenant_id);
        (
            a.map(|x| x.balance_cents).unwrap_or(0),
            a.map(|x| x.events.len()).unwrap_or(0),
        )
    }

    pub fn account_snapshot(&self, tenant_id: &str) -> CreditAccount {
        self.accounts
            .lock()
            .unwrap()
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Payment provider interface — Stripe slots in here later.
// ---------------------------------------------------------------------------

/// A payment provider creates deposit intents and confirms them into credits.
/// `PromoCodeProvider` is the Day-1 implementation (manual code redemption).
/// `StripeProvider` (future): create_checkout() returns a Stripe Checkout
/// Session URL; the webhook handler calls confirm() with the session_id after
/// `checkout.session.completed`. The ledger code above needs zero changes.
pub trait PaymentProvider {
    fn name(&self) -> &'static str;
    /// Value in cents this provider will credit for the given payment reference.
    fn quote(&self, reference: &str) -> Result<i64, CreditError>;
}

pub struct PromoCodeProvider {
    /// "CODE1:2500,CODE2:5000" (cents). Codes are single-purpose strings.
    pub codes: HashMap<String, i64>,
}

impl PromoCodeProvider {
    pub fn from_env(spec: &str) -> Self {
        let mut codes = HashMap::new();
        for pair in spec.split(',') {
            let mut it = pair.trim().splitn(2, ':');
            if let (Some(code), Some(cents)) = (it.next(), it.next()) {
                if let Ok(c) = cents.trim().parse::<i64>() {
                    codes.insert(code.trim().to_string(), c);
                }
            }
        }
        Self { codes }
    }
}

impl PaymentProvider for PromoCodeProvider {
    fn name(&self) -> &'static str {
        "promo_code"
    }
    fn quote(&self, reference: &str) -> Result<i64, CreditError> {
        self.codes
            .get(reference.trim())
            .copied()
            .ok_or(CreditError::InvalidCode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CreditEngine {
        CreditEngine::new(DEFAULT_EVENT_PRICE_CENTS, None)
    }

    #[test]
    fn deposit_burn_idempotency_and_min() {
        let e = engine();
        // below minimum rejected
        assert!(matches!(
            e.redeem("t1", "SMALL", 1000),
            Err(CreditError::BelowMinimum { .. })
        ));
        // $25 deposit
        let bal = e.redeem("t1", "LAUNCH25", 2500).unwrap();
        assert_eq!(bal, 2500);
        // 50 events of credit at $0.50
        for i in 0..50 {
            e.authorize("t1").unwrap();
            e.burn("t1", &format!("s{}", i), "evt").unwrap();
        }
        assert_eq!(e.balance("t1").0, 0);
        // retry of an already-burned session does not double burn / does not error
        e.burn("t1", "s0", "evt").unwrap();
        assert_eq!(e.balance("t1").0, 0);
        // authorize fails closed at zero
        assert!(matches!(
            e.authorize("t1"),
            Err(CreditError::Insufficient { .. })
        ));
    }
}

// ---------------------------------------------------------------------------
// Stateless tenant keys — ads_tk_v1:<tenant>:<64-hex-mac>
// Mirrors the acta_tk_v1 scheme on the Acta gateway: the key IS the account.
// MAC = HMAC-SHA256(master_key, "ads_tk_v1:" + tenant), so the sidecar needs
// no key database — possession of the MAC is proof of the tenant binding.
// ---------------------------------------------------------------------------

use hmac::{Hmac, Mac};
use sha2::Digest as _;
type HMAC = Hmac<sha2::Sha256>;

pub struct TenantKeyAuth {
    master_key: Option<[u8; 32]>,
    /// Tenants allowed without a key (e.g. the public web-console demo tenant).
    pub keyless_tenants: Vec<String>,
}

pub const TENANT_KEY_PREFIX: &str = "ads_tk_v1:";

#[derive(Debug, PartialEq)]
pub enum TenantAuthVerdict {
    /// No Authorization header: allowed because the tenant is keyless-allowlisted.
    KeylessAllowed,
    /// Valid key, tenant must equal the key's bound tenant.
    Keyed(String),
    /// Missing/invalid credential for a protected tenant — fail closed.
    Denied,
}

impl TenantKeyAuth {
    /// master_key: hex 32-byte secret from ADS_TENANT_MASTER_KEY. None disables auth.
    pub fn new(master_hex: Option<&str>, keyless: Vec<String>) -> Self {
        let master_key = master_hex
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok());
        Self { master_key, keyless_tenants: keyless }
    }

    pub fn enabled(&self) -> bool {
        self.master_key.is_some()
    }

    pub fn mint(&self, tenant_id: &str) -> Result<String, CreditError> {
        let mk = self
            .master_key
            .as_ref()
            .ok_or(CreditError::InvalidCode)?;
        let mut mac = HMAC::new_from_slice(mk).map_err(|_| CreditError::InvalidCode)?;
        mac.update(format!("{}{}", TENANT_KEY_PREFIX, tenant_id).as_bytes());
        let out = mac.finalize().into_bytes();
        Ok(format!("{}{}:{}", TENANT_KEY_PREFIX, tenant_id, hex::encode(out)))
    }

    pub fn verify(&self, bearer: Option<&str>, tenant_id: &str) -> TenantAuthVerdict {
        // Keyless allowlist always wins (demo console).
        if self.keyless_tenants.iter().any(|t| t == tenant_id) && bearer.is_none() {
            return TenantAuthVerdict::KeylessAllowed;
        }
        let Some(bearer) = bearer else {
            return TenantAuthVerdict::Denied;
        };
        let Some(rest) = bearer.strip_prefix(TENANT_KEY_PREFIX) else {
            return TenantAuthVerdict::Denied;
        };
        let Some((bound_tenant, presented_mac)) = rest.rsplit_once(':') else {
            return TenantAuthVerdict::Denied;
        };
        if bound_tenant != tenant_id {
            return TenantAuthVerdict::Denied; // key bound to a different tenant
        }
        match self.mint(bound_tenant) {
            Ok(expected) if expected == bearer => TenantAuthVerdict::Keyed(bound_tenant.to_string()),
            _ => TenantAuthVerdict::Denied,
        }
    }
}

#[cfg(test)]
mod tenant_key_tests {
    use super::*;

    #[test]
    fn mint_verify_and_failures() {
        let mk = "aa".repeat(32);
        let auth = TenantKeyAuth::new(Some(&mk), vec!["ardyn_web_console".into()]);
        let key = auth.mint("acme-corp").unwrap();
        assert!(key.starts_with("ads_tk_v1:acme-corp:"));
        // valid key + matching tenant
        assert_eq!(auth.verify(Some(&key), "acme-corp"), TenantAuthVerdict::Keyed("acme-corp".into()));
        // key used for a different tenant -> denied
        assert_eq!(auth.verify(Some(&key), "other"), TenantAuthVerdict::Denied);
        // tampered MAC -> denied
        let bad = format!("{}x", &key[..key.len() - 1]);
        assert_eq!(auth.verify(Some(&bad), "acme-corp"), TenantAuthVerdict::Denied);
        // keyless allowlist -> allowed without header
        assert_eq!(auth.verify(None, "ardyn_web_console"), TenantAuthVerdict::KeylessAllowed);
        // protected tenant without key -> denied
        assert_eq!(auth.verify(None, "acme-corp"), TenantAuthVerdict::Denied);
    }
}
