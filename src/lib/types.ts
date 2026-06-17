export type VerifiabilityClass =
  | "deterministic"
  | "non_deterministic"
  | "counterparty_attested"
  | "tool_captured"
  | "human_signed"
  | "unknown";
export type ReceiptMode = "freeform" | "schema_validated" | "profile_constrained";
export type ActionType = string;
export type EvidenceBlob = {
  schema_version: "sequesign.evidence.v0.1";
  action_id: string;
  action_type: ActionType;
  schema_id?: string;
  schema_hash?: string;
  mime_type: "application/json";
  content: unknown;
};
export type ActionRecord = {
  schema_version: "sequesign.action_record.v0.2";
  action_id: string;
  action_type: ActionType;
  sequence: number;
  chain_id: string;
  actor: { agent_id: string; agent_public_key: string };
  task: { task_id: string; delegator_id: string };
  verifiability_class: VerifiabilityClass;
  evidence_hash: string;
  policy_context_hash?: string;
  previous_chain_state: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
};
export type AgentAttestation = {
  schema_version: "sequesign.agent_attestation.v0.1";
  chain_id: string;
  sequence: number;
  action_record_hash: string;
  chain_state: string;
  agent_id: string;
  agent_public_key: string;
  signature_alg: "Ed25519";
  signature: string;
};
export type WitnessLogEntryRef = {
  log_id: string;
  position: number;
  entry_hash: string;
};
export type WitnessChainHead = {
  log_id: string;
  position: number;
  entry_hash: string;
  head_signature: string;
  head_at: string;
};
// Inclusion proof for a single log entry's appearance in a sealed
// Merkle batch. The audit path is ordered leaf-first per RFC 6962
// section 2.1.1. leaf_index is 0-indexed within the batch (not the
// absolute log position). The verifier reproduces the batch's signing
// message from these fields and checks both the audit path and the
// witness signature against the receipt's witness_public_key.
export type BatchInclusionProof = {
  log_id: string;
  position: number;
  entry_hash: string;
  batch_id: number;
  merkle_root: string;
  tree_size: number;
  leaf_index: number;
  audit_path: string[];
  first_position: number;
  last_position: number;
  batch_sealed_at: string;
  witness_key_id: string;
  witness_signature: string;
};
export type WitnessAttestation = {
  schema_version: "sequesign.witness_attestation.v0.1";
  witness_id: string;
  // 16-hex-char fingerprint of the witness signing key: the first 8
  // bytes of SHA-256 over the DER SubjectPublicKeyInfo of
  // witness_public_key (keyIdFromPublicKeyPem in keys.ts). Locked into
  // the envelope at receipt schema v1.0.0 so an auditor reads the key
  // identity directly rather than recomputing it. Required: every
  // witness attestation carries it. Not part of the signed witness
  // message (that covers witness_id/chain_id/sequence/hashes/timestamp,
  // see messages.ts), so it is a redundant explicit copy of a value
  // derivable from witness_public_key; the verifier rejects a receipt
  // whose witness_key_id disagrees with the recomputed fingerprint.
  witness_key_id: string;
  witness_public_key: string;
  chain_id: string;
  sequence: number;
  action_record_hash: string;
  previous_chain_state: string;
  chain_state: string;
  witnessed_at: string;
  signature_alg: "Ed25519";
  signature: string;
  log_entry?: WitnessLogEntryRef;
  chain_head?: WitnessChainHead;
  batch_inclusion_proof?: BatchInclusionProof;
};
// v0.6 arc: renamed from HumanApprovalAttestation. `party_type`
// records whether the approving party is a human or an (independent)
// agent; it is part of the SIGNED message, so this is a new signed
// payload — hence the bumped schema_version and signing domain (see
// approvalMessage / SEQUESIGN_APPROVAL_V1 in messages.ts). `party_type`
// is a bound attribute, not a separate level. `identity_proof` and
// `attested_evidence_hash` are reserved (unused this version): the
// former for the later registered-key vouching (§6), the latter for
// optional evidence-binding (§6.2). Neither is part of the signed
// message in this version.
export type ApprovalAttestation = {
  schema_version: "sequesign.approval.v1.0.0";
  approval_id: string;
  approver_id: string;
  approver_public_key: string;
  party_type: "human" | "agent";
  approved_task_id: string;
  approved_action_type: string;
  approval_context_hash: string;
  approved_at: string;
  signature_alg: "Ed25519";
  signature: string;
  identity_proof?: IdentityProof;
  attested_evidence_hash?: string;
};
export type CounterpartyAttestation = {
  schema_version: "sequesign.counterparty_attestation.v0.1";
  counterparty_id: string;
  counterparty_public_key: string;
  chain_id: string;
  attested_action_id: string;
  attested_content_hash: string;
  attestation_purpose: string;
  attested_at: string;
  signature_alg: "Ed25519";
  signature: string;
  // Reserved (unused this version), not part of the signed message —
  // so no signing-domain bump yet. Becomes signed + version-bumped when
  // the vouching layer lands (§6).
  identity_proof?: IdentityProof;
};
// v0.6 step #3 (deferred satellites). A sealed receipt R never changes; a
// later approval / counterparty confirmation can arrive as a DETACHED
// satellite that (a) binds to R by `attested_receipt_hash` — the canonical
// hash of R's envelope — and to an action already in R via its inner
// attestation, (b) carries the SAME approval/counterparty attestation an
// in-envelope one would, and (c) is independently witnessed at its OWN time
// T_i (tamper-evident, stronger than the attestation's self-asserted
// timestamp). Once a satellite's witness seal and receipt binding verify,
// the verifier treats its inner attestation EXACTLY like an in-envelope one
// ("born co-located" uniformity, design note §5). A bad satellite is
// dropped, never sinks R (it is not part of sealed R). Revocation is
// deliberately NOT a satellite: positive evidence is monotonic (presence is
// provable, absence is not), so a withdrawal must live where completeness is
// knowable. Satellites are distributed in a top-level `attestations.jsonl`
// sidecar alongside R, mirroring the proofs.jsonl pattern.

// Witness seal over a satellite's content, establishing T_i. The witness
// signs the satellite content hash (attested_receipt_hash + the inner
// attestation), not a chain action, so it has its own message domain
// (SEQUESIGN_SATELLITE_WITNESS_V1, messages.ts). Inclusion-proof fields are
// reserved (optional) for parity with WitnessAttestation; the bundle verify
// checks the signature seal.
export type SatelliteWitnessAttestation = {
  schema_version: "sequesign.satellite_witness.v1.0.0";
  witness_id: string;
  witness_key_id: string;
  witness_public_key: string;
  satellite_content_hash: string;
  witnessed_at: string;
  signature_alg: "Ed25519";
  signature: string;
  log_entry?: WitnessLogEntryRef;
  chain_head?: WitnessChainHead;
  batch_inclusion_proof?: BatchInclusionProof;
};

export type ApprovalSatellite = {
  schema_version: "sequesign.approval_satellite.v1.0.0";
  attested_receipt_hash: string;
  approval: ApprovalAttestation;
  witness_attestation: SatelliteWitnessAttestation;
};

export type CounterpartySatellite = {
  schema_version: "sequesign.counterparty_satellite.v1.0.0";
  attested_receipt_hash: string;
  counterparty: CounterpartyAttestation;
  witness_attestation: SatelliteWitnessAttestation;
};

// One line of the attestations.jsonl satellite sidecar.
export type AttestationSatellite = ApprovalSatellite | CounterpartySatellite;

// Custody of evidence content described from the envelope's
// perspective: where the bytes live now, not who originally captured
// them. v0.4 renamed this field from evidence_source (origin-centric)
// to evidence_custody (custody-centric) so an auditor reading the
// receipt can tell at a glance whether Sequesign has the content.
// A third value (e.g. "transient") is reserved for any future tier
// where Sequesign sees the content but does not durably store it;
// not shipped in v0.4.
export type EvidenceCustodyValue = "sequesign_hosted" | "external_client_managed";

export type EvidenceReference = {
  action_id: string;
  evidence_hash: string;
  evidence_path: string;
  mime_type: string;
  evidence_custody: EvidenceCustodyValue;
};
export type SchemaReference = {
  schema_id: string;
  schema_hash: string;
  schema_path?: string;
  registry_url?: string;
};
export type ProfileReference = {
  profile_id: string;
  profile_hash: string;
  profile_path?: string;
  registry_url?: string;
};
// v1.0.0 is the publish-day receipt schema version: the shape the SDK
// ships at v0.1.0 and the value every customer's stored receipts commit
// to. It is a clean renumber from the development line (the last of
// which was v0.5): pre-customer state, so no migration concerns; older
// v0.x receipts are not supported by this verifier. Relative to v0.5
// the envelope adds the required witness_key_id field on each witness
// attestation. The version is bare semver under the sequesign.receipt
// namespace; see docs/protocol-spec.md section 10 for the versioning
// policy (additive = minor, structural = major).
// v2.0.0 (v0.6 arc): MAJOR bump from v1.0.0 because this is a
// structural change — `human_approval_attestations` renamed to
// `approval_attestations`, the approval attestation gained a signed
// `party_type`, and `verification_level` dropped L4/L5 to independent
// badges (spec §10.1: structural renames/type changes => major). Note
// "v0.6" is the arc/work name, NOT a schema version; the wire value is
// sequesign.receipt.v2.0.0. Pre-customer clean break: older receipts
// are not supported by this verifier.
export type ReceiptSchemaVersion = "sequesign.receipt.v2.0.0";
// Agent identity attestation (PR 15-A). Present on a receipt only when
// it was produced under a registered API key (one the customer
// committed an agent public key to at creation). registered_at is the
// key's registration timestamp; key_fingerprint is "sha256:" plus the
// lowercase hex SHA-256 of the UTF-8 bytes of the PEM-encoded
// agent_public_key as it appears on the receipt (see agentKeyFingerprint
// in hash.ts). Absent on unregistered managed-mode receipts and on
// direct-mode receipts. See docs/trust-model.md for the tier semantics.
export type AgentIdentityAttestation = {
  registered_at: string;
  key_fingerprint: string;
  // The platform's signed statement that key_fingerprint is a registered agent
  // key (issuer "sequesign", role "agent"), so the OFFLINE verifier can confirm
  // "registered" without trusting the receipt's source. Travels as
  // identity_proof.ref (base64url of a SignedRegistrationRecord) — the same
  // primitive approver/counterparty identity uses. Optional for backward
  // compatibility: a legacy attestation with no identity_proof (or one that does
  // not verify against the trusted registration keys) is reported as
  // self_asserted, never registered.
  identity_proof?: IdentityProof;
};
export type AgentActionReceipt = {
  schema_version: ReceiptSchemaVersion;
  receipt_id: string;
  receipt_mode: ReceiptMode;
  agent_id: string;
  agent_public_key: string;
  // Optional: present only for receipts produced under a registered
  // API key. Omitted entirely otherwise (the field never appears as
  // null). Not covered by any signature; the verifier recomputes the
  // fingerprint from agent_public_key.
  agent_identity_attestation?: AgentIdentityAttestation;
  task: {
    task_id: string;
    delegator_id: string;
    delegated_at: string;
    policy_context_hash?: string;
  };
  chain: {
    chain_id: string;
    initial_chain_state: string;
    final_chain_state: string;
    sequence_start: number;
  };
  action_record_hashes: string[];
  agent_attestations: AgentAttestation[];
  witness_attestations: WitnessAttestation[];
  approval_attestations: ApprovalAttestation[];
  counterparty_attestations?: CounterpartyAttestation[];
  evidence_references: EvidenceReference[];
  profile?: ProfileReference;
  schema_references?: SchemaReference[];
};
// A trusted witness key, as supplied to the verifier. Mirrors the entries
// in the witness's /.well-known/sequesign/keys.json discovery document.
// The verifier recomputes the fingerprint from public_key rather than
// trusting key_id blindly.
export type WitnessKey = {
  key_id: string;
  public_key: string;
};

// v0.6 arc: the identity-anchored base level. Approval (old L4) and
// counterparty (old L5) are no longer ladder rungs — they are
// independent badges reported in flags.approval / flags.counterparty
// (see LegState). `witnessed` likewise stays an independent flag. `L1`
// remains the witnessed-only below-ladder fallback. See
// docs/verification-levels-and-deferred-attestation-design.md.
export type VerificationLevel =
  | "NONE"
  | "L0_INTEGRITY_ONLY"
  | "L1_WITNESSED"
  | "L2_KEY_BOUND"
  | "L3_POLICY_BOUND";

// Independent attestation-badge state. `absent`: no such attestation.
// `present_unverified`: a bound, signature-valid attestation exists but
// the signer's identity/role is not yet vouched (no registration proof
// resolved). `present_verified`: identity/role vouched too. In this
// version approval/counterparty never exceed `present_unverified` (the
// vouching layer is a later step); they therefore never elevate the
// reported level. See the design note §7 (the trust-gate).
export type LegState = "absent" | "present_unverified" | "present_verified";

// v0.6 step #2 (multiple-approval semantics): the verifier enumerates the
// valid, deduplicated attestations behind the approval / counterparty
// badges so a relying party can apply its OWN quorum / dual-control
// judgment (the protocol enumerates; it does not impose "require N" — that
// declared-requirement control is v-next). Approvals are deduplicated by
// `approval_id`; counterparties by (`counterparty_id`, `attested_action_id`)
// since the counterparty attestation carries no id. The `*_id` fields let a
// consumer count DISTINCT identities (two signatures from one signer are one
// approver). Each list contains only attestations that are bound,
// signature-valid, and (for approvals) distinct from the executing agent.
export type ApprovalSummary = {
  approval_id: string;
  approver_id: string;
  approver_key_fingerprint: string;
  party_type: "human" | "agent";
  approved_action_type: string;
  approved_at: string;
  // v0.6 step #4: true when this approval carries a valid, trusted
  // `identity_proof` (the approver key is vouched via a registration record
  // the verifier could check against a trusted platform key). A vouched
  // approval flips `flags.approval` to `present_verified`; an unvouched but
  // signature-valid one stays `present_unverified`.
  vouched: boolean;
};
export type CounterpartySummary = {
  counterparty_id: string;
  counterparty_key_fingerprint: string;
  attested_action_id: string;
  attestation_purpose: string;
  attested_at: string;
  // v0.6 step #4: see ApprovalSummary.vouched (drives `flags.counterparty`).
  vouched: boolean;
};

// Reserved, issuer-tagged vouch for an attestation signer's identity/
// role. Unused in this version (no resolver yet); present so the later
// registered-key vouching — and, optionally, external identity
// platforms — is a drop-in with no schema change. `issuer` selects the
// resolver ("sequesign" for our signed registration record); `ref` is
// the opaque credential/record that resolver checks. Design note §6.1.
// An attestation's identity proof: issuer-tagged so the verifier dispatches on
// `issuer` to the matching resolver (§6.1). For `issuer: "sequesign"`, `ref` is
// a self-contained, platform-signed registration token — base64url of a
// SignedRegistrationRecord — that the verifier checks OFFLINE against a trusted
// platform key (no callback). Other issuers are future drop-in resolvers; the
// shape does not change.
export type IdentityProof = {
  issuer: string;
  ref: string;
};

// v0.6 step #4 (vouching, §6). The platform's signed statement that an
// attestation key belongs to a named identity in a given role. Travels inside
// an attestation's `identity_proof.ref` (base64url of the signed wrapper), so
// the receipt remains independently verifiable with no callback.
export type RegistrationRecord = {
  schema_version: "sequesign.registration_record.v1.0.0";
  issuer: "sequesign";
  role: "approver" | "counterparty" | "agent";
  // Present for the approver role (matches the approval's party_type); omitted
  // for counterparty and agent.
  party_type?: "human" | "agent";
  // sha256: fingerprint of the enrolled attestation key (the approver_public_key
  // / counterparty_public_key that signs the A/C, or the agent_public_key that
  // signs the receipt). Binds the record to a key.
  subject_key_fingerprint: string;
  // The named identity the key is registered to: the approver_id /
  // counterparty_id. OMITTED for the agent role — agent registration binds a
  // KEY, not a name (the agent_id in a receipt is a self-asserted label), so
  // the record vouches "this key is a registered agent key" with no name.
  identity?: string;
  registered_at: string;
};

export type SignedRegistrationRecord = {
  record: RegistrationRecord;
  // The platform signing key (PEM) and its sha256: fingerprint. The verifier
  // recomputes the fingerprint from the PEM and requires it in the trusted
  // registration-key set (same trust-anchor pattern as the witness leg).
  platform_key_id: string;
  platform_public_key: string;
  signature_alg: "Ed25519";
  signature: string;
};

// `inclusion_proofs_verified` is four-valued, not boolean-or-null:
// - passed: every witness attestation carries a valid proof.
// - failed: at least one carried proof failed verification (hard fail).
// - partial: some attestations have valid proofs, others have none.
// - not_present: no attestation carries a proof (Phase 1.5 receipt or
//   a Phase 2 receipt where finalize() skipped proof fetch).
export type InclusionProofsVerifiedState = "passed" | "failed" | "partial" | "not_present";

// Provenance of the inclusion proofs the verifier consumed. Proofs are
// uniquely identified by (log_id, position, entry_hash) and never
// change after batch sealing, so they can live in three places:
// embedded in the receipt envelope, in a proofs.jsonl sidecar shipped
// alongside the receipt, or in an online archive served by the
// witness. The verifier checks each source in priority order and
// reports which sources contributed. See PLAN.md section 4.23 for
// the proof-archive architecture.
export type InclusionProofsSource =
  | "embedded"
  | "sidecar"
  | "fetched_online"
  | "mixed"
  | "not_available";
export type VerificationReport = {
  valid: boolean;
  verification_level: VerificationLevel;
  receipt_mode?: ReceiptMode;
  reason?: string;
  // Trust-anchor mode (witness trust-root fix). "external": trusted keys
  // were supplied and used to verify the receipt's witness attestations (a
  // genuine third-party witnessed check). "self": the caller passed the
  // keys it already obtained from the witness it just talked to (an SDK
  // integrity self-check at finalize/inspect, not an adversarial trust
  // check). "none": the receipt carried no witness attestations, so no
  // anchor was needed or used (an L0/integrity-only verification). The
  // verifier UI shows "Witnessed by <fingerprint>" only when this is
  // "external" and witnessed is true. Optional because early failure paths
  // (for example unsupported_schema_version) return before it is set.
  trust_anchor_mode?: "self" | "external" | "none";
  // What trust root was used and which key matched. trusted_key_ids is the
  // set of fingerprints the caller supplied; matched_key_id is the one the
  // receipt's witness key matched, or null when nothing matched. Makes the
  // trust decision visible in the result so callers can audit it.
  witness_trust_anchor?: {
    trusted_key_ids: string[];
    matched_key_id: string | null;
  };
  // Agent identity tier (PR 15-A). Populated on every valid report:
  // "registered" when the receipt carried an agent_identity_attestation
  // whose key_fingerprint matches the embedded agent_public_key,
  // "unregistered" when no attestation was present. A present-but-
  // mismatched fingerprint is a hard failure
  // (agent_identity_attestation_fingerprint_mismatch), not a tier. The
  // verifier reports the tier; it does not enforce that any receipt
  // MUST be registered, and it consults no external registry. Optional
  // on the type because early failure paths return before it is
  // computed.
  agent_identity?:
    | { kind: "registered"; key_fingerprint: string; registered_at: string }
    | { kind: "unregistered" };
  // Identity assurance, derived from agent_identity for machine consumers that
  // gate on it directly. "registered": a broker-vouched
  // agent_identity_attestation is present and matches the embedded key.
  // "self_asserted": none (direct mode, or unregistered managed). This is the
  // separate "is the signing key a vouched identity" signal —
  // verification_level (L2_KEY_BOUND) reflects key-binding only, not who the
  // key belongs to. Optional because early failure paths return before it is
  // computed.
  identity_assurance?: "registered" | "self_asserted";
  action?: { sequence: number; action_type: string };
  expected_evidence_hash?: string;
  computed_evidence_hash?: string;
  profile?: { profile_id: string; profile_hash_verified: boolean };
  flags: {
    hash_integrity: boolean;
    sequence_integrity: boolean;
    schema_valid: boolean | null;
    workflow_profile_valid: boolean | null;
    witnessed: boolean;
    agent_identity_bound: boolean;
    policy_bound: boolean | null;
    // v0.6 arc: independent badges, tri-state (was human_approved /
    // counterparty_confirmed booleans). `present_unverified` does not
    // elevate `verification_level` (which is the identity-anchored base
    // only); a consumer reads these flags for the badge facts.
    approval: LegState;
    counterparty: LegState;
    completeness_verified: boolean | null;
    inclusion_proofs_verified: InclusionProofsVerifiedState;
  };
  completeness?: {
    log_id: string;
    chain_id: string;
    receipt_action_count: number;
    log_entry_count?: number;
    omitted_positions?: number[];
    source: "offline" | "witness_log";
  };
  inclusion_proofs?: {
    total_attestations: number;
    proven_attestations: number;
    failed_attestations: number;
    failed_reasons?: string[];
    source?: InclusionProofsSource;
  };
  // v0.6 step #2: the valid, deduplicated approvals / counterparty
  // confirmations behind the `flags.approval` / `flags.counterparty`
  // badges, enumerated for relying-party quorum judgment. Present (possibly
  // empty) on a successful verification; omitted on early failure paths.
  approvals?: ApprovalSummary[];
  counterparties?: CounterpartySummary[];
  chain?: {
    chain_id: string;
    sequence_start: number;
    sequence_end: number;
    final_chain_state: string;
  };
  details?: string[];
};
