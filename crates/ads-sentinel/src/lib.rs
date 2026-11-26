// crates/ads-sentinel/src/lib.rs
// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
use ads_ddc::{Phase1ScrubSummary, Phase2EvictionSummary};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

#[repr(C)]
struct CScrubTelemetry {
    bytes_scrubbed: u64,
    passes_completed: u32,
    cache_lines_flushed: u32,
    duration_ns: u64,
    mlock_status: i32,
    zero_verified: i32,
}

#[repr(C)]
struct CScrubberKernelReport {
    dispatches_executed: u32,
    warm_latency_ns: u64,
    post_scrub_reload_ns: u64,
    regression_ratio: f64,
    eviction_verified: i32,
}

extern "C" {
    fn ardyn_alloc_volatile_arena(size_bytes: usize, out_mlock_ok: *mut i32) -> *mut libc::c_void;
    fn ardyn_free_volatile_arena(ptr: *mut libc::c_void, size_bytes: usize) -> i32;
    fn ardyn_isa_zeroize_arena(
        ptr: *mut libc::c_void,
        size_bytes: usize,
        passes: u32,
        out_telemetry: *mut CScrubTelemetry,
    ) -> i32;
    fn ardyn_execute_phase2_scrubber(
        working_set_bytes: usize,
        cycles: u32,
        passes_per_cycle: u32,
        out_report: *mut CScrubberKernelReport,
    ) -> i32;
}

pub struct VolatileArena {
    ptr: *mut libc::c_void,
    pub size_bytes: usize,
    pub mlock_pinned: bool,
}

unsafe impl Send for VolatileArena {}

impl VolatileArena {
    pub fn allocate(size_bytes: usize) -> Result<Self, &'static str> {
        let aligned = ((size_bytes.max(4096) + 4095) / 4096) * 4096;
        let mut mlock_ok: i32 = 0;
        let ptr = unsafe { ardyn_alloc_volatile_arena(aligned, &mut mlock_ok) };
        if ptr.is_null() {
            return Err("Failed to allocate mlock volatile arena");
        }
        Ok(Self {
            ptr,
            size_bytes: aligned,
            mlock_pinned: mlock_ok == 1,
        })
    }

    pub fn write_slice(&mut self, offset: usize, data: &[u8]) -> Result<(), &'static str> {
        if offset + data.len() > self.size_bytes {
            return Err("Payload exceeds volatile arena capacity");
        }
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), (self.ptr as *mut u8).add(offset), data.len());
        }
        Ok(())
    }

    pub fn read_all(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.ptr as *const u8, self.size_bytes).to_vec() }
    }

    pub fn scrub_phase1(&mut self, passes: u32) -> (bool, Phase1ScrubSummary) {
        let mut telem = CScrubTelemetry {
            bytes_scrubbed: 0,
            passes_completed: 0,
            cache_lines_flushed: 0,
            duration_ns: 0,
            mlock_status: 0,
            zero_verified: 0,
        };
        let rc = unsafe { ardyn_isa_zeroize_arena(self.ptr, self.size_bytes, passes, &mut telem) };
        (
            rc == 0 && telem.zero_verified == 1,
            Phase1ScrubSummary {
                bytes_scrubbed: telem.bytes_scrubbed,
                passes_completed: telem.passes_completed,
                cache_lines_flushed: telem.cache_lines_flushed,
                duration_ns: telem.duration_ns,
                isa_mechanism: "x86_64_MOVNTDQ_CLFLUSH_SFENCE".to_string(),
            },
        )
    }

    pub fn scrub_phase2_accelerator(working_set_bytes: usize) -> (bool, Phase2EvictionSummary) {
        let mut rep = CScrubberKernelReport {
            dispatches_executed: 0,
            warm_latency_ns: 0,
            post_scrub_reload_ns: 0,
            regression_ratio: 0.0,
            eviction_verified: 0,
        };
        let rc = unsafe { ardyn_execute_phase2_scrubber(working_set_bytes, 3, 5, &mut rep) };
        (
            rc == 0 && rep.eviction_verified == 1,
            Phase2EvictionSummary {
                dispatches_executed: rep.dispatches_executed,
                warm_latency_ns: rep.warm_latency_ns,
                post_scrub_reload_ns: rep.post_scrub_reload_ns,
                regression_ratio: rep.regression_ratio,
            },
        )
    }
}

impl Drop for VolatileArena {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                ardyn_free_volatile_arena(self.ptr, self.size_bytes);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationAction {
    RetryDestruction,
    DestroySessionKeys,
    ForceStateDestruction,
    QuarantineSession,
    EscalateAlert,
    HaltComputeExecution,
}

pub struct RuntimeEnforcementVerdict {
    pub all_probes_passed: bool,
    pub monotonic_counter: u64,
    pub probe_summary: BTreeMap<String, bool>,
    pub remediations: Vec<RemediationAction>,
    pub evidence_commitment_hex: String,
}

pub struct RuntimeEnforcementEngine {
    monotonic_counter: Mutex<u64>,
    seen_nonces: Mutex<HashSet<String>>,
    quarantined_sessions: Mutex<HashSet<String>>,
    watched_dir: Option<PathBuf>,
}

impl RuntimeEnforcementEngine {
    pub fn new(watched_dir: Option<PathBuf>) -> Self {
        Self {
            monotonic_counter: Mutex::new(100_000),
            seen_nonces: Mutex::new(HashSet::new()),
            quarantined_sessions: Mutex::new(HashSet::new()),
            watched_dir,
        }
    }

    fn check_zero_swap() -> bool {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmSwap:") {
                    let kb: u64 = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    return kb == 0;
                }
            }
        }
        true
    }

    fn check_disk_artefacts(&self, session_id: &str) -> bool {
        if let Some(ref dir) = self.watched_dir {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.contains(session_id) || name.ends_with(".leak") || name.ends_with(".dump") {
                        return false;
                    }
                }
            }
        }
        true
    }

    pub fn evaluate(
        &self,
        session_id: &str,
        arena_zero_verified: bool,
        phase2_eviction_verified: bool,
        nonce_commitment_hex: &str,
    ) -> RuntimeEnforcementVerdict {
        if self.quarantined_sessions.lock().unwrap().contains(session_id) {
            return RuntimeEnforcementVerdict {
                all_probes_passed: false,
                monotonic_counter: 0,
                probe_summary: BTreeMap::new(),
                remediations: vec![RemediationAction::HaltComputeExecution],
                evidence_commitment_hex: String::new(),
            };
        }

        let mem_ok = Self::check_zero_swap() && arena_zero_verified;
        let disk_ok = self.check_disk_artefacts(session_id);
        let kv_ok = arena_zero_verified && phase2_eviction_verified;

        let (nonce_ok, counter_val) = {
            let mut seen = self.seen_nonces.lock().unwrap();
            let mut ctr = self.monotonic_counter.lock().unwrap();
            if seen.contains(nonce_commitment_hex) {
                (false, *ctr)
            } else {
                seen.insert(nonce_commitment_hex.to_string());
                *ctr += 1;
                (true, *ctr)
            }
        };

        let mut summary = BTreeMap::new();
        summary.insert("DiskArtefactProbe".to_string(), disk_ok);
        summary.insert("KvSnapshotProbe".to_string(), kv_ok);
        summary.insert("MemoryIntegrityProbe".to_string(), mem_ok);
        summary.insert("NonceIntegrityProbe".to_string(), nonce_ok);

        let all_ok = mem_ok && disk_ok && kv_ok && nonce_ok && phase2_eviction_verified;
        let mut remediations = Vec::new();
        if !all_ok {
            self.quarantined_sessions.lock().unwrap().insert(session_id.to_string());
            remediations.extend([
                RemediationAction::DestroySessionKeys,
                RemediationAction::ForceStateDestruction,
                RemediationAction::QuarantineSession,
                RemediationAction::EscalateAlert,
            ]);
        }

        let mut h = Sha256::new();
        h.update(b"ARDYN_RUNTIME_ENFORCEMENT_V1");
        h.update(session_id.as_bytes());
        h.update(counter_val.to_le_bytes());
        for (k, v) in &summary {
            h.update(k.as_bytes());
            h.update([if *v { 1 } else { 0 }]);
        }
        let evidence_commitment_hex = hex::encode(h.finalize());

        RuntimeEnforcementVerdict {
            all_probes_passed: all_ok,
            monotonic_counter: counter_val,
            probe_summary: summary,
            remediations,
            evidence_commitment_hex,
        }
    }
}
