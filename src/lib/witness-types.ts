// Wire-level witness types shared between the protocol library / SDK and
// the witness service. Extracted from src/witness/types.ts so the SDK's
// compile closure stays inside src/sdk + src/lib: the witness module
// imports LogStore (which imports pg) and must not be dragged into the
// published @sequesign/sdk package by a type-only reference.
// src/witness/types.ts re-exports everything here, so service code keeps
// importing from its existing path unchanged.

export type WitnessRequest = {
  chain_id: string;
  sequence: number;
  action_record_hash: string;
  previous_chain_state: string;
  chain_state: string;
  receipt_schema_version?: string;
  // Direct-mode agent-identity binding (optional, backward compatible). When a
  // direct-mode client sends the public key it is signing with, the witness —
  // which authenticates the same API key — enforces that it matches the key
  // registered to that API key (rejecting a mismatch like the broker does) and
  // returns the account's agent_identity so the client can stamp a registered
  // identity into the receipt. Omitted by older clients → unchanged behavior
  // (no enforcement, self_asserted identity).
  agent_public_key?: string;
};

// The agent-identity block the witness returns when the authenticated API key
// is registered AND the request's agent_public_key matches the registered key.
// The SDK turns this into the receipt's agent_identity_attestation (via
// agentIdentityAttestationFor) so a direct-mode receipt verifies as registered.
export type WitnessAgentIdentity = {
  agent_public_key: string;
  agent_key_registered_at: string;
  // Per-API-key registry (migration 0021): every active registration carries a
  // platform-signed proof, so this is always present (no self_asserted path).
  agent_identity_proof_ref: string;
};

export type LogEntryRef = {
  log_id: string;
  position: number;
  entry_hash: string;
};

export type ChainHead = {
  log_id: string;
  position: number;
  entry_hash: string;
  head_signature: string;
  head_at: string;
};

export type WitnessAttestation = {
  schema_version: "sequesign.witness_attestation.v0.1";
  witness_id: string;
  // 16-hex fingerprint of the witness signing key (config.key.keyId,
  // == keyIdFromPublicKeyPem(witness_public_key)). Stamped into the
  // attestation at receipt schema v1.0.0 so it travels inside the
  // envelope; see src/lib/types.ts WitnessAttestation for the contract.
  witness_key_id: string;
  chain_id: string;
  sequence: number;
  action_record_hash: string;
  previous_chain_state: string;
  chain_state: string;
  witnessed_at: string;
  witness_public_key: string;
  signature_alg: "Ed25519";
  signature: string;
  log_entry?: LogEntryRef;
  chain_head?: ChainHead;
};

export type KeyDiscoveryDocument = {
  schema_version: "sequesign.key_discovery.v0.1";
  keys: Array<{
    key_id: string;
    key_type: "witness";
    public_key: string;
    valid_from: string;
    purposes: string[];
  }>;
};

export type WitnessServiceDescription = {
  service: "sequesign-witness";
  schema_version: "sequesign.witness_attestation.v0.1";
  witness_id: string;
  key_id: string;
  endpoints: {
    sign: { method: "POST"; path: string };
    // v0.6 step #3b.1: deferred-attestation satellite seal. Optional so an
    // older witness description (without it) still satisfies the type.
    sign_satellite?: { method: "POST"; path: string };
    key_discovery: { method: "GET"; path: string };
    health: { method: "GET"; path: string };
    log_head?: { method: "GET"; path: string };
    log_entries?: { method: "GET"; path: string };
    log_completeness?: { method: "GET"; path: string };
    log_export?: { method: "POST"; path: string };
  };
  docs: string;
};

export type Tier = "free" | "paygo" | "enterprise" | "standard" | "managed_isolated" | "byo";
