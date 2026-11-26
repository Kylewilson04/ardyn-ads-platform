#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[Gate 1/5] Building native x86_64 ISA cache-bypassing scrubber..."
gcc -O3 -Wall -Wextra -fPIC -std=c11 -shared \
  -o native/ardyn_isa_scrubber/libardyn_isa_scrubber.so \
  native/ardyn_isa_scrubber/ardyn_isa_scrubber.c

echo "[Gate 2/5] Building & testing Rust Cargo workspace..."
LD_LIBRARY_PATH="$ROOT_DIR/native/ardyn_isa_scrubber" cargo test --workspace --release -- --nocapture

echo "[Gate 3/5] Compiling Linux eBPF LSM enforcement probes..."
clang -O2 -g -target bpf -c crates/ads-ebpf/src/sentinel_lsm.c -o crates/ads-ebpf/sentinel_lsm.bpf.o

echo "[Gate 4/5] Building TypeScript WebCrypto SDK..."
(cd sdks/typescript-webcrypto && npm install && npm run build)

echo "[Gate 5/5] Building Sovereign Sidecar container mesh..."
docker compose -f deploy/docker-compose.yml build

if [[ "${1:-}" == "--serve" ]]; then
  echo "Starting ARDYN Sovereign Sidecar on ${ADS_LISTEN_ADDR:-0.0.0.0:8443}..."
  LD_LIBRARY_PATH="$ROOT_DIR/native/ardyn_isa_scrubber" \
    ADS_LISTEN_ADDR="${ADS_LISTEN_ADDR:-0.0.0.0:8443}" \
    ./target/release/ads-sidecar
fi
