// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.

function hexToBytes(hex) {
  const clean = hex.trim();
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
function concatBytes(...arrays) {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const res = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    res.set(a, offset);
    offset += a.length;
  }
  return res;
}
async function resolveWebCrypto() {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  const nodeCryptoSpec = "node:crypto";
  const mod = await import( /* @vite-ignore */nodeCryptoSpec);
  return mod.webcrypto;
}

/**
 * Extracts the exact canonical JSON substring of `ddc.payload` directly from the raw HTTP body
 * so Rust u128 nanosecond timestamps (> Number.MAX_SAFE_INTEGER) and f64 literals verify byte-for-byte.
 */
function extractCanonicalDdcPayloadJson(rawResponseText, fallbackPayload) {
  const ddcIdx = rawResponseText.indexOf('"ddc":');
  if (ddcIdx === -1) return JSON.stringify(fallbackPayload);
  const payloadKeyIdx = rawResponseText.indexOf('"payload":', ddcIdx);
  if (payloadKeyIdx === -1) return JSON.stringify(fallbackPayload);
  const start = rawResponseText.indexOf("{", payloadKeyIdx);
  if (start === -1) return JSON.stringify(fallbackPayload);
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < rawResponseText.length; i++) {
    const ch = rawResponseText[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        return rawResponseText.slice(start, i + 1);
      }
    }
  }
  return JSON.stringify(fallbackPayload);
}
export class ArdynSovereignClient {
  constructor(sidecarUrl, tenantId = "enterprise-secops-01") {
    this.sidecarUrl = sidecarUrl;
    this.tenantId = tenantId;
  }
  async executeZeroPersistence(sensitiveInput) {
    const webcrypto = await resolveWebCrypto();
    const enc = new TextEncoder();
    const healthRes = await fetch(`${this.sidecarUrl}/v1/health`);
    const health = await healthRes.json();
    const sessionId = webcrypto.randomUUID();
    const clientKeyPair = await webcrypto.subtle.generateKey({
      name: "X25519"
    }, true, ["deriveBits"]);
    const clientPubRaw = new Uint8Array(await webcrypto.subtle.exportKey("raw", clientKeyPair.publicKey));
    const gwPubKey = await webcrypto.subtle.importKey("raw", hexToBytes(health.gateway_x25519_pub_hex), {
      name: "X25519"
    }, false, []);
    const sharedIngressBits = await webcrypto.subtle.deriveBits({
      name: "X25519",
      public: gwPubKey
    }, clientKeyPair.privateKey, 256);
    const kIngress = await this.deriveAesKey(webcrypto, new Uint8Array(sharedIngressBits), enc.encode(sessionId), enc.encode("ARDYN_ADS_INGRESS_V1"), ["encrypt"]);
    const ingressNonce = webcrypto.getRandomValues(new Uint8Array(12));
    const ingressCipher = new Uint8Array(await webcrypto.subtle.encrypt({
      name: "AES-GCM",
      iv: ingressNonce,
      additionalData: enc.encode(sessionId)
    }, kIngress, enc.encode(JSON.stringify(sensitiveInput))));
    const execRes = await fetch(`${this.sidecarUrl}/v1/sovereign/execute`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        session_id: sessionId,
        tenant_id: this.tenantId,
        client_ephemeral_pub_hex: bytesToHex(clientPubRaw),
        ingress_nonce_hex: bytesToHex(ingressNonce),
        ingress_ciphertext_hex: bytesToHex(ingressCipher)
      })
    });
    const rawBodyText = await execRes.text();
    if (!execRes.ok) {
      throw new Error(`ARDYN_FAIL_CLOSED (${execRes.status}): ${rawBodyText}`);
    }
    const bundle = JSON.parse(rawBodyText);
    const ddc = bundle.ddc;

    // 1. Independently verify Ed25519 signature over canonical DDC payload
    const canonicalPayloadStr = extractCanonicalDdcPayloadJson(rawBodyText, ddc.payload);
    const unsignedBytes = enc.encode(canonicalPayloadStr);
    const signerPub = await webcrypto.subtle.importKey("raw", hexToBytes(health.ddc_signer_ed25519_pub_hex), {
      name: "Ed25519"
    }, false, ["verify"]);
    const sigValid = await webcrypto.subtle.verify("Ed25519", signerPub, hexToBytes(ddc.signature_hex), unsignedBytes);
    if (!sigValid || !ddc.payload.destruction_completed) {
      throw new Error("ARDYN_SOVEREIGNTY_REJECT: Invalid Destruction Data Certificate signature!");
    }

    // 2. Compute Active DDC Digest (Claim 35)
    const ddcDigestBuf = await webcrypto.subtle.digest("SHA-256", concatBytes(enc.encode("ARDYN_DDC_DIGEST_V1:"), unsignedBytes, hexToBytes(ddc.signature_hex)));
    const ddcDigest = new Uint8Array(ddcDigestBuf);

    // 3. Unwrap Release Key bound to DDC Digest
    const gwEphemPub = await webcrypto.subtle.importKey("raw", hexToBytes(bundle.gateway_ephemeral_pub_hex), {
      name: "X25519"
    }, false, []);
    const outSharedBits = await webcrypto.subtle.deriveBits({
      name: "X25519",
      public: gwEphemPub
    }, clientKeyPair.privateKey, 256);
    const kWrap = await this.deriveAesKey(webcrypto, new Uint8Array(outSharedBits), enc.encode(bundle.event_id), concatBytes(enc.encode("ARDYN_ACTIVE_DDC_WRAP_V1:"), ddcDigest), ["decrypt"]);
    const rawReleaseKey = new Uint8Array(await webcrypto.subtle.decrypt({
      name: "AES-GCM",
      iv: hexToBytes(bundle.wrap_nonce_hex),
      additionalData: ddcDigest
    }, kWrap, hexToBytes(bundle.wrapped_release_seed_hex)));

    // 4. Decrypt ProtectedResult locally
    const kResult = await webcrypto.subtle.importKey("raw", rawReleaseKey, {
      name: "AES-GCM"
    }, false, ["decrypt"]);
    const plaintextBuf = await webcrypto.subtle.decrypt({
      name: "AES-GCM",
      iv: hexToBytes(bundle.result_nonce_hex),
      additionalData: enc.encode(bundle.event_id)
    }, kResult, hexToBytes(bundle.sealed_result_ciphertext_hex));
    return {
      result: JSON.parse(new TextDecoder().decode(plaintextBuf)),
      ddc
    };
  }
  async deriveAesKey(webcrypto, ikm, salt, info, usages) {
    const baseKey = await webcrypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
    return webcrypto.subtle.deriveKey({
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info
    }, baseKey, {
      name: "AES-GCM",
      length: 256
    }, false, usages);
  }
}