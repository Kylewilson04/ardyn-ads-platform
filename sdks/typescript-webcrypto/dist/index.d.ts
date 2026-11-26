// Copyright (c) 2026 ARDYN INTELLIGENCE SYSTEMS INC. All Rights Reserved.
export interface DestructionDataCertificate {
  payload: {
    ddc_version: string;
    issuer: string;
    event_id: string;
    session_id: string;
    attestation_root_id: string;
    verification_tier: string;
    granularity: string;
    protected_result_kind: string;
    protected_result_commitment_hex: string;
    destruction_proof_hash_hex: string;
    nonce_commitment_hex: string;
    monotonic_counter: number;
    destruction_completed: boolean;
    release_condition_satisfied: boolean;
    phase1_metrics: Record<string, number | string>;
    phase2_metrics: Record<string, number>;
    probe_summary: Record<string, boolean>;
    hardware_quote_b64: string | null;
    timestamp_utc_ns: number;
    verification_endpoint: string;
    signer_public_key_hex: string;
  };
  signature_hex: string;
}

export declare class ArdynSovereignClient {
  private readonly sidecarUrl;
  private readonly tenantId;
  constructor(sidecarUrl: string, tenantId?: string);
  executeZeroPersistence<TIn extends object, TOut = unknown>(
    sensitiveInput: TIn
  ): Promise<{ result: TOut; ddc: DestructionDataCertificate }>;
}
