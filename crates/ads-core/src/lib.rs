// crates/ads-core/src/lib.rs
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
#![forbid(unsafe_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleGranularity {
    PerRequest,
    PerSession,
    PerTenant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectedResultKind {
    InferenceOutput,
    TrainingModelArtefact,
    DerivedDataProduct,
    DestructionDataCertificate,
    CryptographicKeyOrShare,
    AccessCapabilityOrToken,
    WorkflowAuthorityTransition,
}

#[derive(Debug, Error)]
pub enum AdsInterlockError {
    #[error("ARDYN_ATOMIC_ABORT: Destruction verification failed; DestructionNonce permanently burned")]
    AtomicAbortBurned,
    #[error("ARDYN_CRYPTO_FAILURE: {0}")]
    CryptoFailure(&'static str),
}

pub fn compute_baseline_state_digest(event_id: &str, arena_size: usize, arena_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ARDYN_BASELINE_STATE_V1:");
    hasher.update(event_id.as_bytes());
    hasher.update((arena_size as u64).to_le_bytes());
    hasher.update(arena_bytes);
    hasher.finalize().into()
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], AdsInterlockError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| AdsInterlockError::CryptoFailure("HKDF expansion failed"))?;
    Ok(okm)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MathematicalInterlockVault {
    event_id_bytes: Vec<u8>,
    expected_baseline_digest: [u8; 32],
    blinded_destruction_nonce: [u8; 32],
    nonce_commitment: [u8; 32],
    aborted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedProtectedResult {
    pub ciphertext_hex: String,
    pub result_nonce_hex: String,
    pub result_commitment_hex: String,
    pub nonce_commitment_hex: String,
}

impl MathematicalInterlockVault {
    /// Initializes the interlock against an all-zero non-informational volatile arena baseline,
    /// seals the ProtectedResult, blinds N_dest against H_baseline, and IMMEDIATELY wipes K_seal and N_dest.
    pub fn seal_and_blind(
        event_id: &str,
        arena_size: usize,
        plaintext_result: &[u8],
    ) -> Result<(Self, SealedProtectedResult), AdsInterlockError> {
        let zero_baseline = vec![0u8; arena_size];
        let expected_baseline_digest = compute_baseline_state_digest(event_id, arena_size, &zero_baseline);

        let mut n_dest = [0u8; 32];
        OsRng.fill_bytes(&mut n_dest);

        let mut commit_hasher = Sha256::new();
        commit_hasher.update(b"ARDYN_NONCE_COMMIT_V1:");
        commit_hasher.update(n_dest);
        let nonce_commitment: [u8; 32] = commit_hasher.finalize().into();

        let mut seal_info = b"ARDYN_RESULT_SEAL_V1:".to_vec();
        seal_info.extend_from_slice(&expected_baseline_digest);
        let mut k_seal = hkdf_sha256(&n_dest, event_id.as_bytes(), &seal_info)?;

        let cipher = Aes256Gcm::new_from_slice(&k_seal)
            .map_err(|_| AdsInterlockError::CryptoFailure("Cipher key init failed"))?;
        k_seal.zeroize();

        let mut result_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut result_nonce);

        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&result_nonce),
                Payload {
                    msg: plaintext_result,
                    aad: event_id.as_bytes(),
                },
            )
            .map_err(|_| AdsInterlockError::CryptoFailure("Result encryption failed"))?;

        let result_commitment: [u8; 32] = Sha256::digest(&ciphertext).into();

        // Blind N_dest against expected_baseline_digest and immediately wipe raw N_dest
        let mut mask_hasher = Sha256::new();
        mask_hasher.update(b"ARDYN_INTERLOCK_MASK_V1:");
        mask_hasher.update(expected_baseline_digest);
        let mut mask: [u8; 32] = mask_hasher.finalize().into();

        let mut blinded_destruction_nonce = [0u8; 32];
        for i in 0..32 {
            blinded_destruction_nonce[i] = n_dest[i] ^ mask[i];
        }
        n_dest.zeroize();
        mask.zeroize();

        let sealed = SealedProtectedResult {
            ciphertext_hex: hex::encode(ciphertext),
            result_nonce_hex: hex::encode(result_nonce),
            result_commitment_hex: hex::encode(result_commitment),
            nonce_commitment_hex: hex::encode(nonce_commitment),
        };

        Ok((
            Self {
                event_id_bytes: event_id.as_bytes().to_vec(),
                expected_baseline_digest,
                blinded_destruction_nonce,
                nonce_commitment,
                aborted: false,
            },
            sealed,
        ))
    }

    /// Fail-Closed Negative Path (Steps 316 / 420-424): Permanently burns Blinded_N with CSPRNG entropy.
    pub fn atomic_abort_burn(&mut self) -> AdsInterlockError {
        OsRng.fill_bytes(&mut self.blinded_destruction_nonce);
        self.blinded_destruction_nonce.zeroize();
        self.aborted = true;
        AdsInterlockError::AtomicAbortBurned
    }

    /// Unmasks N_dest ONLY if actual post-wipe arena state matches expected baseline AND independent probes passed.
    pub fn verify_and_derive_release_key(
        mut self,
        actual_post_wipe_digest: [u8; 32],
        independent_probes_ok: bool,
    ) -> Result<[u8; 32], AdsInterlockError> {
        let digest_matches: bool = actual_post_wipe_digest.ct_eq(&self.expected_baseline_digest).into();
        if self.aborted || !independent_probes_ok || !digest_matches {
            return Err(self.atomic_abort_burn());
        }

        let mut mask_hasher = Sha256::new();
        mask_hasher.update(b"ARDYN_INTERLOCK_MASK_V1:");
        mask_hasher.update(actual_post_wipe_digest);
        let mut mask_actual: [u8; 32] = mask_hasher.finalize().into();

        let mut recovered_n_dest = [0u8; 32];
        for i in 0..32 {
            recovered_n_dest[i] = self.blinded_destruction_nonce[i] ^ mask_actual[i];
        }
        mask_actual.zeroize();

        let mut check_commit = Sha256::new();
        check_commit.update(b"ARDYN_NONCE_COMMIT_V1:");
        check_commit.update(recovered_n_dest);
        let actual_commit: [u8; 32] = check_commit.finalize().into();

        if !bool::from(actual_commit.ct_eq(&self.nonce_commitment)) {
            recovered_n_dest.zeroize();
            return Err(self.atomic_abort_burn());
        }

        let mut seal_info = b"ARDYN_RESULT_SEAL_V1:".to_vec();
        seal_info.extend_from_slice(&actual_post_wipe_digest);
        let release_key = hkdf_sha256(&recovered_n_dest, &self.event_id_bytes, &seal_info)?;
        recovered_n_dest.zeroize();
        Ok(release_key)
    }
}

/// Active DDC-Conditioned Release Wrapping (Claim 35):
/// Wraps `k_result_release` to the client's X25519 ephemeral public key using HKDF bound to `ddc_digest`.
pub fn wrap_release_key_with_ddc(
    event_id: &str,
    client_pub_bytes: [u8; 32],
    mut k_result_release: [u8; 32],
    ddc_digest: &[u8; 32],
) -> Result<(String, String, String), AdsInterlockError> {
    let ephem_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephem_pk = PublicKey::from(&ephem_sk);
    let client_pk = PublicKey::from(client_pub_bytes);
    let shared = ephem_sk.diffie_hellman(&client_pk);

    let mut wrap_info = b"ARDYN_ACTIVE_DDC_WRAP_V1:".to_vec();
    wrap_info.extend_from_slice(ddc_digest);
    let mut k_wrap = hkdf_sha256(shared.as_bytes(), event_id.as_bytes(), &wrap_info)?;

    let cipher = Aes256Gcm::new_from_slice(&k_wrap)
        .map_err(|_| AdsInterlockError::CryptoFailure("Wrap cipher init failed"))?;
    k_wrap.zeroize();

    let mut wrap_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut wrap_nonce);

    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: &k_result_release,
                aad: ddc_digest,
            },
        )
        .map_err(|_| AdsInterlockError::CryptoFailure("Wrap encryption failed"))?;
    k_result_release.zeroize();

    Ok((
        hex::encode(wrapped),
        hex::encode(wrap_nonce),
        hex::encode(ephem_pk.as_bytes()),
    ))
}

pub fn decrypt_client_ingress(
    gateway_sk: &StaticSecret,
    client_pub_bytes: [u8; 32],
    session_id: &str,
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AdsInterlockError> {
    let client_pk = PublicKey::from(client_pub_bytes);
    let shared = gateway_sk.diffie_hellman(&client_pk);
    let mut k_ingress = hkdf_sha256(shared.as_bytes(), session_id.as_bytes(), b"ARDYN_ADS_INGRESS_V1")?;
    let cipher = Aes256Gcm::new_from_slice(&k_ingress)
        .map_err(|_| AdsInterlockError::CryptoFailure("Ingress cipher init failed"))?;
    k_ingress.zeroize();

    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: session_id.as_bytes(),
            },
        )
        .map_err(|_| AdsInterlockError::CryptoFailure("Ingress decryption failed"))
}
