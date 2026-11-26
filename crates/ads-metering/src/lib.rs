// crates/ads-metering/src/lib.rs
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
#![forbid(unsafe_code)]

use ads_ddc::{DestructionDataCertificate, VerificationTier};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereigntyUsageToken {
    pub token_id: String,
    pub tenant_id: String,
    pub session_id: String,
    pub event_id: String,
    pub ddc_digest_hex: String,
    pub bytes_sanitized: u64,
    pub verification_tier: VerificationTier,
    pub billable_sovereignty_units: f64,
    pub timestamp_utc_ns: u128,
    pub metering_pubkey_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnderwriterZeroRetentionReport {
    pub issuer: String,
    pub tenant_id: String,
    pub verified_sovereign_executions: usize,
    pub fail_closed_aborts_enforced: u64,
    pub total_volatile_bytes_provably_zeroized: u64,
    pub persisted_customer_records_count: u64,
    pub ledger_merkle_root_hex: String,
    pub metering_pubkey_hex: String,
    pub signature_hex: String,
}

pub struct SovereigntyMeteringEngine {
    signing_key: SigningKey,
    pub pubkey_hex: String,
    tokens: Mutex<Vec<SovereigntyUsageToken>>,
    aborts: Mutex<u64>,
}

impl SovereigntyMeteringEngine {
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            pubkey_hex,
            tokens: Mutex::new(Vec::new()),
            aborts: Mutex::new(0),
        }
    }

    pub fn record_abort(&self) {
        *self.aborts.lock().unwrap() += 1;
    }

    pub fn issue_usage_token(&self, tenant_id: &str, ddc: &DestructionDataCertificate) -> SovereigntyUsageToken {
        let digest_hex = hex::encode(ddc.compute_active_ddc_digest().expect("Verified DDC"));
        let bytes = ddc.payload.phase1_metrics.bytes_scrubbed;
        let mult = match ddc.payload.verification_tier {
            VerificationTier::SoftwareAttested => 1.0,
            VerificationTier::IndependentlyRuntimeVerified => 1.25,
            VerificationTier::TelemetryBackedHardwareInferred => 1.5,
            VerificationTier::HardwareRootedAttested => 2.0,
        };
        let units = ((bytes as f64 / (1024.0 * 1024.0)).max(1.0) * mult * 10000.0).round() / 10000.0;
        let id_hash = hex::encode(Sha256::digest(format!("{}:{}", ddc.payload.event_id, tenant_id).as_bytes()));

        let mut tok = SovereigntyUsageToken {
            token_id: format!("ardyn-tok-{}", &id_hash[..16]),
            tenant_id: tenant_id.to_string(),
            session_id: ddc.payload.session_id.clone(),
            event_id: ddc.payload.event_id.clone(),
            ddc_digest_hex: digest_hex,
            bytes_sanitized: bytes,
            verification_tier: ddc.payload.verification_tier,
            billable_sovereignty_units: units,
            timestamp_utc_ns: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos(),
            metering_pubkey_hex: self.pubkey_hex.clone(),
            signature_hex: String::new(),
        };
        let msg = serde_json::to_vec(&tok).unwrap();
        tok.signature_hex = hex::encode(self.signing_key.sign(&msg).to_bytes());
        self.tokens.lock().unwrap().push(tok.clone());
        tok
    }

    pub fn generate_underwriter_report(&self, tenant_id: &str, merkle_root_hex: String) -> UnderwriterZeroRetentionReport {
        let tokens = self.tokens.lock().unwrap();
        let filtered: Vec<_> = tokens.iter().filter(|t| t.tenant_id == tenant_id).collect();
        let total_bytes: u64 = filtered.iter().map(|t| t.bytes_sanitized).sum();
        let aborts = *self.aborts.lock().unwrap();

        let mut rep = UnderwriterZeroRetentionReport {
            issuer: "ARDYN INTELLIGENCE SYSTEMS INC.".to_string(),
            tenant_id: tenant_id.to_string(),
            verified_sovereign_executions: filtered.len(),
            fail_closed_aborts_enforced: aborts,
            total_volatile_bytes_provably_zeroized: total_bytes,
            persisted_customer_records_count: 0,
            ledger_merkle_root_hex: merkle_root_hex,
            metering_pubkey_hex: self.pubkey_hex.clone(),
            signature_hex: String::new(),
        };
        let msg = serde_json::to_vec(&rep).unwrap();
        rep.signature_hex = hex::encode(self.signing_key.sign(&msg).to_bytes());
        rep
    }
}
