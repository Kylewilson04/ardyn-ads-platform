# ARDYN INTELLIGENCE SYSTEMS INC. — Atomic Data Sovereignty (ADS) Platform (`v1.0.0`)

Production repository implementing **Atomic Data Sovereignty and Destruction-Conditioned Release of Protected Results** (Claims 1–41).

## Repository Layout & Patent Traceability

- `GEMINI_TASK.json` — Master build & verification manifest across all 5 execution gates.
- `native/ardyn_isa_scrubber/` — Hardware-accelerated x86_64 C11 SIMD cache-bypassing volatile memory scrubber (`MOVNTDQ` / `_mm_stream_si128`, `CLFLUSH`, `SFENCE`, `mlock`, `MADV_DONTDUMP`) and 15-dispatch (`3 × 5`) Phase-2 accelerator eviction verifier (`>10x` reload latency regression).
- `crates/ads-core/` — Mathematical Interlock Vault (`Blinded_N`, domain-separated `ARDYN_BASELINE_STATE_V1`, X25519 ECDH + HKDF-SHA256 + AES-256-GCM, Fail-Closed Atomic Abort).
- `crates/ads-ddc/` — Dual-Embodiment Ed25519 Destruction Data Certificates (DDCs) and Append-Only SHA-256 Merkle Transparency Ledger.
- `crates/ads-sentinel/` — Safe Rust FFI bindings to `libardyn_isa_scrubber.so` and the 4 independent Runtime Enforcement Probes (`MemoryIntegrityProbe`, `DiskArtefactProbe`, `KvSnapshotProbe`, `NonceIntegrityProbe`).
- `crates/ads-metering/` — Sovereignty-as-a-Service usage tokens and cyber-insurance `UnderwriterZeroRetentionReport` generator.
- `crates/ads-sidecar/` — Drop-in zero-code-change Sovereign Proxy (`/v1/health`, `/v1/sovereign/execute`, `/v1/ddc/verify`, `/v1/underwriter/report`) and end-to-end Rust integration tests.
- `crates/ads-ebpf/src/sentinel_lsm.c` — Linux Kernel (`>= 5.15`) eBPF LSM probe blocking non-volatile file writes (`lsm/file_permission`) and `ptrace` snooping (`lsm/ptrace_access_check`).
- `sdks/typescript-webcrypto/` — Isomorphic Browser, Edge, and Node.js (`>= 18`) WebCrypto SDK (`@ardyn-intelligence/sovereign-client`) with pre-built ESM (`dist/index.js`), CJS (`dist/index.cjs`), and TypeScript declaration (`dist/index.d.ts`) bundles.
- `deploy/` — Multi-stage `Dockerfile.sidecar`, `docker-compose.yml` mesh, and `kubernetes-sidecar-deployment.yaml`.

## Quick Start

Run all 5 build and verification gates and launch the Sovereign Sidecar on port `8443`:

```bash
./scripts/run_gates.sh --serve
```

Or launch via Docker Compose:

```bash
docker compose -f deploy/docker-compose.yml up --build -d
```
