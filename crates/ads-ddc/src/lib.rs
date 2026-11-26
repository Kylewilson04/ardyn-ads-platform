// crates/ads-ddc/src/lib.rs
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
#![forbid(unsafe_code)]

use ads_core::{LifecycleGranularity, ProtectedResultKind};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationTier {
    SoftwareAttested,
    IndependentlyRuntimeVerified,
    TelemetryBackedHardwareInferred,
    HardwareRootedAttested,
}

#[derive(Debug, Error)]
pub enum DdcError {
    #[error("ARDYN_SIGNATURE_WITHHELD: Independent destruction verification failed (Claims 33-34)")]
    SignatureWithheld,
    #[error("ARDYN_DDC_INVALID: {0}")]
    ValidationFailed(&'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase1ScrubSummary {
    pub bytes_scrubbed: u64,
    pub passes_completed: u32,
    pub cache_lines_flushed: u32,
    pub duration_ns: u64,
    pub isa_mechanism: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Phase2EvictionSummary {
    pub dispatches_executed: u32,
    pub warm_latency_ns: u64,
    pub post_scrub_reload_ns: u64,
    pub regression_ratio: f64,
}

/// Canonical unsigned DDC body with deterministic BTreeMap/struct field ordering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedDdcPayload {
    pub ddc_version: String,
    pub issuer: String,
    pub event_id: String,
    pub session_id: String,
    pub attestation_root_id: String,
    pub verification_tier: VerificationTier,
    pub granularity: LifecycleGranularity,
    pub protected_result_kind: ProtectedResultKind,
    pub protected_result_commitment_hex: String,
    pub destruction_proof_hash_hex: String,
    pub nonce_commitment_hex: String,
    pub monotonic_counter: u64,
    pub destruction_completed: bool,
    pub release_condition_satisfied: bool,
    pub phase1_metrics: Phase1ScrubSummary,
    pub phase2_metrics: Phase2EvictionSummary,
    pub probe_summary: BTreeMap<String, bool>,
    pub hardware_quote_b64: Option<String>,
    pub timestamp_utc_ns: u128,
    pub verification_endpoint: String,
    pub signer_public_key_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestructionDataCertificate {
    pub payload: UnsignedDdcPayload,
    pub signature_hex: String,
}

impl DestructionDataCertificate {
    pub fn canonical_unsigned_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.payload).expect("Deterministic struct serialization")
    }

    pub fn compute_active_ddc_digest(&self) -> Result<[u8; 32], DdcError> {
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|_| DdcError::ValidationFailed("Malformed signature hex"))?;
        let mut hasher = Sha256::new();
        hasher.update(b"ARDYN_DDC_DIGEST_V1:");
        hasher.update(self.canonical_unsigned_bytes());
        hasher.update(&sig_bytes);
        Ok(hasher.finalize().into())
    }
}

pub struct TrustedEvidenceGenerator {
    signing_key: SigningKey,
    pub public_key_hex: String,
    pub attestation_root_id: String,
    pub verification_endpoint: String,
}

impl TrustedEvidenceGenerator {
    pub fn new(verification_endpoint: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let public_key_hex = hex::encode(pub_bytes);
        let root_hash = hex::encode(Sha256::digest(pub_bytes));
        Self {
            signing_key,
            public_key_hex,
            attestation_root_id: format!("did:ardyn:root:{}", &root_hash[..24]),
            verification_endpoint: verification_endpoint.to_string(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mint_certificate(
        &self,
        independent_verification_passed: bool,
        event_id: String,
        session_id: String,
        verification_tier: VerificationTier,
        granularity: LifecycleGranularity,
        protected_result_kind: ProtectedResultKind,
        protected_result_commitment_hex: String,
        destruction_proof_hash_hex: String,
        nonce_commitment_hex: String,
        monotonic_counter: u64,
        phase1_metrics: Phase1ScrubSummary,
        phase2_metrics: Phase2EvictionSummary,
        probe_summary: BTreeMap<String, bool>,
        hardware_quote_b64: Option<String>,
    ) -> Result<DestructionDataCertificate, DdcError> {
        if !independent_verification_passed || probe_summary.values().any(|&ok| !ok) {
            return Err(DdcError::SignatureWithheld);
        }

        let now_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let payload = UnsignedDdcPayload {
            ddc_version: "1.0.0".to_string(),
            issuer: "ARDYN INTELLIGENCE SYSTEMS INC.".to_string(),
            event_id,
            session_id,
            attestation_root_id: self.attestation_root_id.clone(),
            verification_tier,
            granularity,
            protected_result_kind,
            protected_result_commitment_hex,
            destruction_proof_hash_hex,
            nonce_commitment_hex,
            monotonic_counter,
            destruction_completed: true,
            release_condition_satisfied: true,
            phase1_metrics,
            phase2_metrics,
            probe_summary,
            hardware_quote_b64,
            timestamp_utc_ns: now_ns,
            verification_endpoint: self.verification_endpoint.clone(),
            signer_public_key_hex: self.public_key_hex.clone(),
        };

        let canonical_bytes = serde_json::to_vec(&payload).expect("Canonical JSON");
        let sig: Signature = self.signing_key.sign(&canonical_bytes);

        Ok(DestructionDataCertificate {
            payload,
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }

    pub fn verify_certificate(ddc: &DestructionDataCertificate, expected_pub_hex: Option<&str>) -> Result<(), DdcError> {
        if !ddc.payload.destruction_completed || !ddc.payload.release_condition_satisfied {
            return Err(DdcError::ValidationFailed("Destruction or release flag false"));
        }
        if ddc.payload.probe_summary.values().any(|&v| !v) {
            return Err(DdcError::ValidationFailed("One or more runtime probes failed"));
        }
        let key_hex = expected_pub_hex.unwrap_or(&ddc.payload.signer_public_key_hex);
        let pub_bytes: [u8; 32] = hex::decode(key_hex)
            .map_err(|_| DdcError::ValidationFailed("Invalid public key hex"))?
            .try_into()
            .map_err(|_| DdcError::ValidationFailed("Invalid public key length"))?;
        let sig_bytes: [u8; 64] = hex::decode(&ddc.signature_hex)
            .map_err(|_| DdcError::ValidationFailed("Invalid signature hex"))?
            .try_into()
            .map_err(|_| DdcError::ValidationFailed("Invalid signature length"))?;

        let vk = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|_| DdcError::ValidationFailed("Malformed Ed25519 public key"))?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&ddc.canonical_unsigned_bytes(), &sig)
            .map_err(|_| DdcError::ValidationFailed("Ed25519 signature verification failed"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerReceipt {
    pub leaf_index: usize,
    pub event_id: String,
    pub ddc_digest_hex: String,
    pub merkle_root_hex: String,
}

#[derive(Default)]
pub struct AppendOnlyMerkleLedger {
    leaves: Vec<[u8; 32]>,
}

impl AppendOnlyMerkleLedger {
    fn hash_leaf(digest: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(digest);
        h.finalize().into()
    }

    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    pub fn append(&mut self, ddc: &DestructionDataCertificate) -> Result<LedgerReceipt, DdcError> {
        let digest = ddc.compute_active_ddc_digest()?;
        let leaf = Self::hash_leaf(&digest);
        let leaf_index = self.leaves.len();
        self.leaves.push(leaf);
        Ok(LedgerReceipt {
            leaf_index,
            event_id: ddc.payload.event_id.clone(),
            ddc_digest_hex: hex::encode(digest),
            merkle_root_hex: self.current_root_hex(),
        })
    }

    pub fn current_root_hex(&self) -> String {
        if self.leaves.is_empty() {
            return hex::encode(Sha256::digest(b"ARDYN_EMPTY_LEDGER"));
        }
        let mut level = self.leaves.clone();
        while level.len() > 1 {
            let mut next = Vec::with_capacity((level.len() + 1) / 2);
            for chunk in level.chunks(2) {
                let l = &chunk[0];
                let r = if chunk.len() > 1 { &chunk[1] } else { l };
                next.push(Self::hash_nodes(l, r));
            }
            level = next;
        }
        hex::encode(level[0])
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }
}
