import path from "node:path";
import { readFile } from "node:fs/promises";
import { agentKeyFingerprint, ed25519KeyFingerprint, hashCanonical } from "./hash.js";
import { extendChain } from "./chain.js";
import { readJson, readJsonl, listJsonFiles, writeJson } from "./io.js";
import { validateEvidenceSchema } from "./schema-validation.js";
import { validateWorkflowProfile } from "./profile.js";
import type {
  AgentActionReceipt,
  ActionRecord,
  ApprovalAttestation,
  ApprovalSummary,
  AttestationSatellite,
  BatchInclusionProof,
  CounterpartyAttestation,
  CounterpartySummary,
  EvidenceBlob,
  InclusionProofsSource,
  InclusionProofsVerifiedState,
  LegState,
  SatelliteWitnessAttestation,
  VerificationReport,
  WitnessKey
} from "./types.js";
import {
  agentAttestationMessage,
  witnessAttestationMessage,
  approvalMessage,
  counterpartyAttestationMessage,
  satelliteWitnessMessage
} from "./messages.js";
import { isEd25519PublicKeyPem, keyIdFromPublicKeyPem, verifyEd25519 } from "./keys.js";
import { identityProofVouches } from "./registration.js";
import {
  batchSigningMessage,
  hexToBytes,
  verifyAuditPath
} from "./merkle.js";

function baseFlags() {
  return {
    hash_integrity: false,
    sequence_integrity: false,
    schema_valid: null,
    workflow_profile_valid: null,
    witnessed: false,
    agent_identity_bound: false,
    policy_bound: false,
    approval: "absent" as LegState,
    counterparty: "absent" as LegState,
    completeness_verified: null,
    inclusion_proofs_verified: "not_present" as InclusionProofsVerifiedState
  };
}
function fail(report: Partial<VerificationReport>): VerificationReport {
  return { valid: false, verification_level: "NONE", flags: baseFlags(), ...report };
}

// Thrown when a caller invokes the verifier without a trust anchor. The
// verifier refuses to proceed rather than silently trusting the witness
// key embedded in the receipt: that key is supplied by whoever produced
// the receipt, so trusting it would let any signer forge a witnessed
// receipt. Callers must make the trust decision explicitly by passing
// trustedWitnessKeys (typically from the witness's well-known keys, or a
// pinned key in a Sequesign-operated service).
export class TrustAnchorRequiredError extends Error {
  readonly code = "trust_anchor_required";
  constructor() {
    super(
      "trust_anchor_required: pass trustedWitnessKeys from a trusted source (typically the witness's /.well-known/sequesign/keys.json)."
    );
    this.name = "TrustAnchorRequiredError";
  }
}

// Derives the set of witness keys embedded in a receipt's own witness
// attestations, deduplicated by fingerprint. This is the trust anchor for
// an SDK integrity self-check (trustAnchorMode "self"): the SDK passes the
// keys from the attestations it just collected from the witness it talked
// to. It is NOT an adversarial trust check; a third party must anchor to
// the witness's well-known keys instead (see the verifier UI). Exported so
// the SDK self-verify paths and the "self" callers share one definition.
export function witnessKeysFromReceipt(receipt: AgentActionReceipt): WitnessKey[] {
  const byFingerprint = new Map<string, WitnessKey>();
  for (const att of receipt.witness_attestations ?? []) {
    if (!att.witness_public_key) continue;
    try {
      const keyId = keyIdFromPublicKeyPem(att.witness_public_key);
      if (!byFingerprint.has(keyId)) {
        byFingerprint.set(keyId, { key_id: keyId, public_key: att.witness_public_key });
      }
    } catch {
      // Skip a malformed embedded key; the verifier's trust check will
      // then reject the attestation as not trusted rather than pass it.
    }
  }
  return [...byFingerprint.values()];
}

// Disk convenience for "self" callers that verify an on-disk package they
// produced (the dev CLI and the demos) and do not hold the receipt in
// memory. Reads the envelope and returns its embedded witness keys.
// Integrity self-check only; not an adversarial trust check.
export async function selfTrustedWitnessKeysFromPackage(
  packageDir: string,
  envelopePath?: string
): Promise<WitnessKey[]> {
  const receipt = await readJson<AgentActionReceipt>(
    envelopePath ?? path.join(packageDir, "receipt.json")
  );
  return witnessKeysFromReceipt(receipt);
}

// Parses a pinned trusted-keys value (the WITNESS_TRUSTED_KEYS env var in
// the Sequesign-operated services). Accepts either the witness's
// well-known document shape ({ keys: [...] }) so an operator can paste it
// verbatim, or a bare array of { key_id, public_key }. Returns an empty
// array for an unset/empty value; throws on malformed JSON or shape so a
// misconfiguration fails loudly at startup rather than silently disabling
// the trust anchor.
export function parseTrustedWitnessKeys(raw: string | undefined | null): WitnessKey[] {
  if (!raw || raw.trim().length === 0) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `WITNESS_TRUSTED_KEYS is not valid JSON: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  const fromDocument = !Array.isArray(parsed);
  const entries: unknown[] = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { keys?: unknown }).keys)
      ? ((parsed as { keys: unknown[] }).keys)
      : [];
  if (entries.length === 0) {
    throw new Error(
      "WITNESS_TRUSTED_KEYS parsed but contained no keys. Provide the witness well-known document or an array of { key_id, public_key }."
    );
  }
  const keys = entries
    // Filter to witness keys. A well-known discovery document can carry
    // non-witness keys (agent, approver, counterparty); accepting those as
    // witness anchors would let a receipt signed with a non-witness key
    // pass the trust-root check. In a document we require an explicit
    // key_type "witness" (a missing or misspelled type is not trusted). A
    // bare array of { key_id, public_key } carries no key_type and is
    // taken as operator-listed witness keys.
    .filter((e) => {
      const keyType = (e as { key_type?: unknown }).key_type;
      return fromDocument ? keyType === "witness" : keyType === undefined || keyType === "witness";
    })
    .map((e, i) => {
      const obj = e as { key_id?: unknown; public_key?: unknown };
      if (typeof obj.key_id !== "string" || typeof obj.public_key !== "string") {
        throw new Error(
          `WITNESS_TRUSTED_KEYS entry ${i} must have string key_id and public_key fields.`
        );
      }
      return { key_id: obj.key_id, public_key: obj.public_key };
    });
  if (keys.length === 0) {
    throw new Error(
      fromDocument
        ? "WITNESS_TRUSTED_KEYS is a discovery document with no witness keys (key_type \"witness\"). Provide at least one witness key."
        : "WITNESS_TRUSTED_KEYS contained no usable keys."
    );
  }
  return keys;
}

// v0.6 step #4.2 (vouching): parse the platform registration key-discovery
// document (dashboard-api's /.well-known/sequesign/registration-keys.json) into
// the WitnessKey[] a caller passes as verifyReceiptPackage's
// trustedRegistrationKeys. Same shape and discipline as parseTrustedWitnessKeys
// but filters to key_type "registration" (in a document; a bare array is taken
// as operator-listed registration keys). ONLY an empty/unset input returns []
// (vouching is optional — no anchor configured). A non-empty but malformed
// value, or a document/array with no registration keys, THROWS — so a wrong
// endpoint (e.g. an error JSON) or a misconfigured anchor fails loud instead of
// silently leaving every identity_proof present_unverified.
export function parseTrustedRegistrationKeys(raw: string | undefined | null): WitnessKey[] {
  if (!raw || raw.trim().length === 0) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `registration trusted keys: not valid JSON: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  const fromDocument = !Array.isArray(parsed);
  const entries: unknown[] = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { keys?: unknown }).keys)
      ? (parsed as { keys: unknown[] }).keys
      : [];
  if (entries.length === 0) {
    throw new Error(
      "registration trusted keys: parsed but contained no keys. Provide the registration well-known document or an array of { key_id, public_key }."
    );
  }
  const keys = entries
    .filter((e) => {
      const keyType = (e as { key_type?: unknown }).key_type;
      return fromDocument
        ? keyType === "registration"
        : keyType === undefined || keyType === "registration";
    })
    .map((e, i) => {
      const obj = e as { key_id?: unknown; public_key?: unknown };
      if (typeof obj.key_id !== "string" || typeof obj.public_key !== "string") {
        throw new Error(
          `registration trusted keys: entry ${i} must have string key_id and public_key fields.`
        );
      }
      return { key_id: obj.key_id, public_key: obj.public_key };
    });
  if (keys.length === 0) {
    throw new Error(
      fromDocument
        ? 'registration trusted keys: discovery document has no registration keys (key_type "registration").'
        : "registration trusted keys: contained no usable keys."
    );
  }
  return keys;
}

export type CompletenessQueryResult = {
  log_id: string;
  chain_id: string;
  entry_positions: number[];
  entry_count: number;
};

export interface CompletenessChecker {
  query(args: { chainId: string; logId: string }): Promise<CompletenessQueryResult>;
}

// Result of a single inclusion-proof lookup. The fetcher is uniquely
// addressed by (log_id, position, entry_hash), the same primary key
// the receipt's witness_attestations[i].log_entry carries. The fetcher
// MUST return "found" only when it has a proof whose entry_hash
// matches the request; the verifier still cross-checks the audit
// path and witness signature before accepting the proof.
export type InclusionProofLookupResult =
  | { status: "found"; proof: BatchInclusionProof }
  | { status: "pending"; logId: string; position: number; entryHash: string }
  | { status: "not_found"; logId: string; position: number };

export interface InclusionProofFetcher {
  fetch(args: {
    logId: string;
    position: number;
    entryHash: string;
  }): Promise<InclusionProofLookupResult>;
}

export type VerifyReceiptPackageOptions = {
  // Trust anchor. The witness keys the caller trusts, from a source
  // outside the receipt. The verifier recomputes each key's fingerprint
  // and only accepts a witness attestation whose embedded key matches one
  // of these. Required whenever the receipt carries witness attestations:
  // an empty or missing array then throws TrustAnchorRequiredError and the
  // verifier never falls back to the embedded key. A receipt with no
  // witness attestations verifies to an integrity-only result without an
  // anchor (trust_anchor_mode "none"), so this may be omitted there.
  trustedWitnessKeys?: WitnessKey[];
  // Whether this is a third-party trust check or an integrity self-check.
  // "external": the trusted keys came from the witness's well-known
  // endpoint or a pinned config in a Sequesign-operated service. "self":
  // the caller (an SDK finalize/inspect path) passed the keys it already
  // obtained from the witness it just talked to. Surfaced on the report as
  // trust_anchor_mode (which also reports "none" when no witness
  // attestations were present). Defaults to "external" when witness
  // attestations are present and this is omitted.
  trustAnchorMode?: "self" | "external";
  // v0.6 step #4 (vouching). The platform registration-signing keys the caller
  // trusts (the same shape as trustedWitnessKeys; typically from the platform's
  // well-known registration-keys endpoint). An A/C attestation whose
  // `identity_proof` (issuer "sequesign") carries a registration record signed
  // by one of these keys — and binding the same signer key, role, identity, and
  // party_type — flips its leg to `present_verified`. Omitted/empty: vouching is
  // not evaluated and every present leg stays at most `present_unverified` (the
  // current behavior). Never required; a missing anchor never fails a receipt.
  trustedRegistrationKeys?: WitnessKey[];
  envelopePath?: string;
  completeness?: CompletenessChecker;
  // Optional fetcher for inclusion proofs at verification time. The
  // verifier consults sources in priority order: embedded proof on
  // the attestation, then a proofs.jsonl sidecar in the package
  // directory, then this fetcher. The fetcher is only called when
  // neither embedded nor sidecar has a proof for the attestation.
  // See PLAN.md section 4.23 for the proof-archive architecture.
  inclusionProofs?: InclusionProofFetcher;
};

export async function verifyReceiptPackage(
  packageDir: string,
  options: VerifyReceiptPackageOptions = {}
): Promise<VerificationReport> {
  const envelopePath = options.envelopePath ?? path.join(packageDir, "receipt.json");
  const receipt = await readJson<AgentActionReceipt>(envelopePath);
  // Fail fast on any non-v1.0.0 receipt. The Zod schema in the broker
  // and intermediary rejects non-v1.0.0 envelopes at the wire boundary,
  // but this verifier is also called against on-disk packages and
  // against already-deserialized objects, so the same gate must
  // run here. v1.0.0 is the publish-day version; earlier development
  // receipts (v0.x) are not accepted. Pre-customer state; no
  // transition window. This runs before the trust-anchor gate: an
  // unsupported schema is rejected on its own terms, not masked as a
  // missing trust anchor.
  if (receipt.schema_version !== "sequesign.receipt.v2.0.0") {
    return fail({
      receipt_mode: receipt.receipt_mode,
      reason: `unsupported_schema_version: "${receipt.schema_version}". This verifier accepts only "sequesign.receipt.v2.0.0". Earlier receipts (v1.0.0 and v0.x) are not supported.`
    });
  }
  // Trust-anchor setup. Recompute each trusted key's fingerprint from its
  // PEM rather than trusting the supplied key_id; a witness attestation is
  // accepted only when its embedded key's fingerprint is in this set.
  const trustedFingerprints = new Set<string>();
  for (const key of options.trustedWitnessKeys ?? []) {
    try {
      trustedFingerprints.add(keyIdFromPublicKeyPem(key.public_key));
    } catch {
      // A malformed trusted PEM contributes no fingerprint. If every
      // supplied key is malformed the set is empty and nothing matches,
      // which surfaces as witness_key_not_trusted below rather than a
      // silent pass.
    }
  }
  const trustedKeyIds = [...trustedFingerprints];
  // v0.6 step #4: the platform registration-signing keys, same fingerprinting
  // discipline as the witness anchor. Empty when the caller supplies none, in
  // which case no attestation can be vouched and every present leg stays at
  // most `present_unverified`.
  const trustedRegistrationFingerprints = new Set<string>();
  for (const key of options.trustedRegistrationKeys ?? []) {
    try {
      trustedRegistrationFingerprints.add(keyIdFromPublicKeyPem(key.public_key));
    } catch {
      // A malformed platform PEM contributes no fingerprint (no vouch).
    }
  }
  // The trust anchor is only needed to verify witness signatures. A
  // receipt with no witness attestations can never be witnessed, so it
  // verifies to an integrity-only result with mode "none" and needs no
  // anchor. A receipt that does carry witness attestations must be
  // anchored: refuse rather than trust the key embedded in the receipt.
  const hasWitnessAttestations = receipt.witness_attestations.length > 0;
  if (hasWitnessAttestations && trustedFingerprints.size === 0) {
    throw new TrustAnchorRequiredError();
  }
  const trustAnchorMode: "self" | "external" | "none" = hasWitnessAttestations
    ? (options.trustAnchorMode ?? "external")
    : "none";
  const witnessTrustAnchor: NonNullable<VerificationReport["witness_trust_anchor"]> = {
    trusted_key_ids: trustedKeyIds,
    matched_key_id: null
  };
  const actions = await readJsonl<ActionRecord>(path.join(packageDir, "actions.jsonl"));
  const evidenceFiles = await listJsonFiles(path.join(packageDir, "evidence"));
  const evidence: EvidenceBlob[] = [];
  const evidenceByActionId = new Map<string, EvidenceBlob>();
  for (const file of evidenceFiles) {
    const item = await readJson<EvidenceBlob>(file);
    evidence.push(item);
    evidenceByActionId.set(item.action_id, item);
  }
  let currentState = receipt.chain.initial_chain_state;
  let agentSignaturesOk = true;
  let witnessSignaturesOk = true;
  // policy_bound matches the other optional flags: null when not
  // requested, true when verified, false when malformed. The protocol
  // (spec 3.1.1) requires that when policy binding is requested, every
  // action commits to the same policy_context_hash. The value is computed
  // here; malformed receipts hard-fail after the chain checks below, so
  // only true and null ever reach the success path.
  const taskPolicyHash = receipt.task.policy_context_hash;
  let policyBound: boolean | null;
  if (!taskPolicyHash && !actions.some((a) => a.policy_context_hash)) {
    // Not requested: neither the task nor any action declares a hash.
    policyBound = null;
  } else if (taskPolicyHash && actions.every((a) => a.policy_context_hash === taskPolicyHash)) {
    // Requested and every action commits to the same hash.
    policyBound = true;
  } else {
    // Malformed: a per-action mismatch, or actions bind to a policy the
    // task never declared.
    policyBound = false;
  }
  const details: string[] = [];

  for (let i = 0; i < actions.length; i++) {
    const action = actions[i];
    if (action.sequence !== receipt.chain.sequence_start + i)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "sequence_mismatch",
        action: { sequence: action.sequence, action_type: action.action_type }
      });
    if (action.previous_chain_state !== currentState)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "previous_chain_state_mismatch",
        action: { sequence: action.sequence, action_type: action.action_type }
      });
    const item = evidenceByActionId.get(action.action_id);
    if (!item)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "missing_evidence",
        action: { sequence: action.sequence, action_type: action.action_type }
      });
    const computedEvidenceHash = hashCanonical(item);
    if (computedEvidenceHash !== action.evidence_hash)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "evidence_hash_mismatch",
        action: { sequence: action.sequence, action_type: action.action_type },
        expected_evidence_hash: action.evidence_hash,
        computed_evidence_hash: computedEvidenceHash,
        details: ["The action data has been modified since the chain was constructed."]
      });
    const computedActionHash = hashCanonical(action);
    const expectedActionHash = receipt.action_record_hashes[i];
    if (computedActionHash !== expectedActionHash)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "action_record_hash_mismatch",
        action: { sequence: action.sequence, action_type: action.action_type },
        details: [`Expected ${expectedActionHash}, computed ${computedActionHash}`]
      });
    const expectedNextState = extendChain({
      chainId: action.chain_id,
      sequence: action.sequence,
      previousChainState: currentState,
      actionRecordHash: computedActionHash
    });
    const agentAttestation = receipt.agent_attestations.find((a) => a.sequence === action.sequence);
    if (!agentAttestation) agentSignaturesOk = false;
    else {
      // Agent attestation binding (PR 15-A.1, finding #1). The Ed25519
      // check below proves only that the holder of
      // agent_attestation.agent_public_key signed over the
      // attestation's own fields. It does NOT prove those fields belong
      // to this action or this receipt's declared agent. Without the
      // binding checks here, a malicious package can carry an
      // attestation signed by an unrelated key over an unrelated action
      // hash (chain_state alone is consistent) and still reach
      // L2_IDENTITY_BOUND and above, laundering the work under a
      // more-trusted identity. Bind every identity- and action-level
      // field to the computed action and the receipt before trusting
      // the signature. (sequence is the lookup key above, so it is
      // bound implicitly.)
      const agentBindingFailures: string[] = [];
      if (agentAttestation.chain_id !== action.chain_id)
        agentBindingFailures.push(
          `agent attestation chain_id ${agentAttestation.chain_id} does not match action chain_id ${action.chain_id}`
        );
      if (agentAttestation.action_record_hash !== computedActionHash)
        agentBindingFailures.push(
          `agent attestation action_record_hash does not match the computed action record hash`
        );
      if (agentAttestation.agent_id !== action.actor.agent_id)
        agentBindingFailures.push(
          `agent attestation agent_id ${agentAttestation.agent_id} does not match action actor agent_id ${action.actor.agent_id}`
        );
      if (agentAttestation.agent_id !== receipt.agent_id)
        agentBindingFailures.push(
          `agent attestation agent_id ${agentAttestation.agent_id} does not match receipt agent_id ${receipt.agent_id}`
        );
      if (agentAttestation.agent_public_key !== action.actor.agent_public_key)
        agentBindingFailures.push(
          `agent attestation agent_public_key does not match action actor agent_public_key`
        );
      if (agentAttestation.agent_public_key !== receipt.agent_public_key)
        agentBindingFailures.push(
          `agent attestation agent_public_key does not match receipt agent_public_key`
        );
      if (agentBindingFailures.length > 0)
        return fail({
          receipt_mode: receipt.receipt_mode,
          reason: "agent_attestation_binding_mismatch",
          action: { sequence: action.sequence, action_type: action.action_type },
          details: agentBindingFailures
        });
      const ok = verifyEd25519(
        agentAttestation.agent_public_key,
        agentAttestationMessage({
          chainId: agentAttestation.chain_id,
          sequence: agentAttestation.sequence,
          actionRecordHash: agentAttestation.action_record_hash,
          chainState: agentAttestation.chain_state
        }),
        agentAttestation.signature
      );
      if (!ok || agentAttestation.chain_state !== expectedNextState) agentSignaturesOk = false;
    }
    const witnessAttestation = receipt.witness_attestations.find(
      (a) => a.sequence === action.sequence
    );
    if (!witnessAttestation) witnessSignaturesOk = false;
    else {
      // Witness attestation binding (PR 15-A.1, finding #1). As with
      // the agent attestation above, the signature proves only that the
      // witness key signed over the attestation's own fields. Bind the
      // chain_id, the computed action record hash, and the running
      // chain state to this action so a witness attestation for a
      // different action or chain cannot be transplanted here.
      // (sequence is the lookup key; chain_state is checked against
      // expectedNextState below as before.)
      const witnessBindingFailures: string[] = [];
      if (witnessAttestation.chain_id !== action.chain_id)
        witnessBindingFailures.push(
          `witness attestation chain_id ${witnessAttestation.chain_id} does not match action chain_id ${action.chain_id}`
        );
      if (witnessAttestation.action_record_hash !== computedActionHash)
        witnessBindingFailures.push(
          `witness attestation action_record_hash does not match the computed action record hash`
        );
      if (witnessAttestation.previous_chain_state !== currentState)
        witnessBindingFailures.push(
          `witness attestation previous_chain_state does not match the chain walk's running state`
        );
      if (witnessBindingFailures.length > 0)
        return fail({
          receipt_mode: receipt.receipt_mode,
          reason: "witness_attestation_binding_mismatch",
          action: { sequence: action.sequence, action_type: action.action_type },
          details: witnessBindingFailures
        });
      // Trust-root check (witness trust-root fix). The signature below
      // only proves the holder of witnessAttestation.witness_public_key
      // signed; it says nothing about whether that key is the witness the
      // caller trusts. Bind the embedded key to the supplied trust anchor
      // by fingerprint (handles PEM whitespace and trailing-newline
      // differences) before trusting the signature.
      let embeddedFingerprint: string | null = null;
      try {
        embeddedFingerprint = keyIdFromPublicKeyPem(witnessAttestation.witness_public_key);
      } catch {
        embeddedFingerprint = null;
      }
      // witness_key_id consistency (receipt schema v1.0.0). The field
      // is an explicit copy of the fingerprint of witness_public_key.
      // It is not covered by the witness signature, so an attacker can
      // set it to anything; reject when it disagrees with the recomputed
      // fingerprint so the explicit value can never be trusted over the
      // key it claims to identify. Checked only when the embedded key is
      // a valid PEM (a null fingerprint falls through to the
      // witness_key_not_trusted path below, which reports the bad key).
      if (
        embeddedFingerprint !== null &&
        witnessAttestation.witness_key_id !== embeddedFingerprint
      ) {
        return fail({
          receipt_mode: receipt.receipt_mode,
          reason: "witness_key_id_mismatch",
          action: { sequence: action.sequence, action_type: action.action_type },
          details: [
            `witness attestation witness_key_id ${witnessAttestation.witness_key_id} does not match the fingerprint ${embeddedFingerprint} computed from witness_public_key`
          ]
        });
      }
      if (embeddedFingerprint === null || !trustedFingerprints.has(embeddedFingerprint)) {
        return fail({
          receipt_mode: receipt.receipt_mode,
          reason: "witness_key_not_trusted",
          action: { sequence: action.sequence, action_type: action.action_type },
          trust_anchor_mode: trustAnchorMode,
          witness_trust_anchor: witnessTrustAnchor,
          details: [
            embeddedFingerprint === null
              ? "the embedded witness_public_key is not a valid Ed25519 PEM, so its fingerprint cannot be computed"
              : `embedded witness key fingerprint ${embeddedFingerprint} is not in the trusted set`,
            `trusted fingerprints checked: ${trustedKeyIds.length > 0 ? trustedKeyIds.join(", ") : "(none valid)"}`
          ]
        });
      }
      witnessTrustAnchor.matched_key_id = embeddedFingerprint;
      const ok = verifyEd25519(
        witnessAttestation.witness_public_key,
        witnessAttestationMessage({
          witnessId: witnessAttestation.witness_id,
          chainId: witnessAttestation.chain_id,
          sequence: witnessAttestation.sequence,
          actionRecordHash: witnessAttestation.action_record_hash,
          previousChainState: witnessAttestation.previous_chain_state,
          chainState: witnessAttestation.chain_state,
          witnessedAt: witnessAttestation.witnessed_at
        }),
        witnessAttestation.signature
      );
      if (!ok || witnessAttestation.chain_state !== expectedNextState) witnessSignaturesOk = false;
    }
    currentState = expectedNextState;
  }
  if (currentState !== receipt.chain.final_chain_state)
    return fail({
      receipt_mode: receipt.receipt_mode,
      reason: "final_chain_state_mismatch",
      details: [`Expected ${receipt.chain.final_chain_state}, computed ${currentState}`]
    });

  let schemaValid: boolean | null = null;
  if (
    receipt.receipt_mode === "schema_validated" ||
    receipt.receipt_mode === "profile_constrained"
  ) {
    schemaValid = true;
    for (const item of evidence) {
      const result = await validateEvidenceSchema(item);
      if (!result.valid)
        return fail({
          receipt_mode: receipt.receipt_mode,
          reason: "schema_validation_failed",
          action: {
            sequence: actions.find((a) => a.action_id === item.action_id)?.sequence ?? 0,
            action_type: item.action_type
          },
          flags: {
            ...baseFlags(),
            hash_integrity: true,
            sequence_integrity: true,
            schema_valid: false,
            policy_bound: policyBound
          },
          details: result.errors
        });
    }
  }
  let workflowProfileValid: boolean | null = null;
  let profileReport: VerificationReport["profile"] | undefined;
  if (receipt.receipt_mode === "profile_constrained") {
    if (!receipt.profile)
      return fail({ receipt_mode: receipt.receipt_mode, reason: "missing_profile_binding" });
    const profileResult = await validateWorkflowProfile({
      profileId: receipt.profile.profile_id,
      profileHash: receipt.profile.profile_hash,
      actions,
      evidence
    });
    workflowProfileValid = profileResult.valid;
    profileReport = {
      profile_id: receipt.profile.profile_id,
      profile_hash_verified: profileResult.profileHashVerified
    };
    if (!profileResult.valid)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "workflow_profile_validation_failed",
        profile: profileReport,
        flags: {
          ...baseFlags(),
          hash_integrity: true,
          sequence_integrity: true,
          schema_valid: schemaValid,
          workflow_profile_valid: false,
          policy_bound: policyBound
        },
        details: profileResult.errors
      });
  }
  // v0.6 step #3 (deferred satellites). Bundle verify: a later approval /
  // counterparty confirmation can arrive as a detached, independently
  // witnessed satellite in the top-level attestations.jsonl sidecar. Verify
  // each satellite's witness seal + receipt binding now; the inner
  // attestations of the survivors are folded in below and treated uniformly
  // with the in-envelope ones ("born co-located", design note §5). R itself
  // is unchanged, so its standalone base level is unaffected by which (if
  // any) satellites are present.
  const receiptHash = canonicalReceiptHash(receipt);
  const { approvals: satelliteApprovals, counterparties: satelliteCounterparties } =
    collectSatelliteAttestations(
      await loadSatellites(packageDir),
      receiptHash,
      trustedFingerprints
    );
  const approvals = receipt.approval_attestations;
  // Approval binding (PR 15-A.1, findings #1 and #10). The signature
  // below proves only that the approver key signed the approval. It does
  // NOT prove the approval belongs to this receipt's task, nor that it
  // approves an action that actually occurred in this chain. Without
  // these bindings an approval signed for an unrelated task (or for an
  // action type absent from the chain) could be attached to a receipt.
  // We bind the approval to the receipt task and require its
  // approved_action_type to match a recorded action. We deliberately do
  // NOT bind approval_context_hash to an action's evidence hash:
  // approval_context_hash commits to the opaque human-meaningful context
  // the approver agreed to (see protocol-spec.md 5.3), the approval may
  // be recorded before the action it authorizes exists, and binding it
  // to evidence would be a wire-format change. Receipt binding is
  // achieved via task_id and action_type instead.
  //
  // v0.6 arc: approver/agent distinctness (O3) and per-attestation
  // validity (drop-don't-sink) are enforced in THIS PR (see the badge
  // counting below), because the badge is exposed even at
  // `present_unverified` — a self-minted or all-or-nothing-suppressed
  // badge is wrong output now, not in step #2. Dedup-by-`approval_id`
  // (distinct-identity counting for quorum) remains step #2; this PR
  // keeps the task/action binding hard-fail below. See design note §3/§4.
  const recordedActionTypes = new Set(actions.map((a) => a.action_type));
  for (const att of approvals) {
    const approvalBindingFailures: string[] = [];
    if (att.approved_task_id !== receipt.task.task_id)
      approvalBindingFailures.push(
        `approval approved_task_id ${att.approved_task_id} does not match receipt task_id ${receipt.task.task_id}`
      );
    if (!recordedActionTypes.has(att.approved_action_type))
      approvalBindingFailures.push(
        `approval approved_action_type ${att.approved_action_type} matches no recorded action in this chain`
      );
    if (approvalBindingFailures.length > 0)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "approval_binding_mismatch",
        details: approvalBindingFailures
      });
  }
  // Independent badge, tri-state. `present_verified` is unreachable this
  // version (no identity vouching). An approval counts toward the badge
  // only if it is signature-valid AND its approver key is distinct from
  // the executing agent (O3 — an actor must not mint its own approval
  // badge). Per-attestation: one bad/duplicate/self appended approval
  // must not suppress an otherwise-valid one, so we count independently
  // rather than all-or-nothing.
  // Self-approval check by canonical key FINGERPRINT, not verbatim PEM:
  // agentKeyFingerprint normalizes the PEM before hashing, so a
  // differently-formatted (CRLF/whitespace) copy of the agent key cannot
  // slip an approval past the distinctness guard (O3). A key that can't
  // be fingerprinted (malformed) isn't treated as the agent key, but its
  // signature won't verify either, so it still won't count.
  const agentKeyFp = (() => {
    try {
      return agentKeyFingerprint(receipt.agent_public_key);
    } catch {
      return null;
    }
  })();
  const isAgentKey = (pem: string): boolean => {
    if (agentKeyFp === null) return false;
    try {
      return agentKeyFingerprint(pem) === agentKeyFp;
    } catch {
      return false;
    }
  };
  // Signer-level validity, shared by in-envelope and satellite approvals:
  // party_type in enum, a genuine Ed25519 key (verifyEd25519 /
  // crypto.verify(null,...) also accepts other EdDSA keys, but the
  // enumeration fingerprints the key and a non-Ed25519 key would throw —
  // gate it as invalid/dropped), distinct from the executing agent (O3), and
  // signature-valid.
  const approvalSignerOk = (att: ApprovalAttestation): boolean =>
    (att.party_type === "human" || att.party_type === "agent") &&
    isEd25519PublicKeyPem(att.approver_public_key) &&
    !isAgentKey(att.approver_public_key) &&
    verifyEd25519(
      att.approver_public_key,
      approvalMessage({
        approvalId: att.approval_id,
        approverId: att.approver_id,
        partyType: att.party_type,
        approvedTaskId: att.approved_task_id,
        approvedActionType: att.approved_action_type,
        approvalContextHash: att.approval_context_hash,
        approvedAt: att.approved_at
      }),
      att.signature
    );
  // In-envelope approvals already passed the hard-fail binding loop above.
  // Satellite approvals are NOT part of sealed R, so their binding is checked
  // SOFTLY here — drop on mismatch, never fail R: the inner approval must
  // still name THIS receipt's task and an action type recorded in the chain.
  const approvalBoundToReceipt = (att: ApprovalAttestation): boolean =>
    att.approved_task_id === receipt.task.task_id &&
    recordedActionTypes.has(att.approved_action_type);
  const validApprovals = [
    ...approvals.filter(approvalSignerOk),
    ...satelliteApprovals.filter((att) => approvalBoundToReceipt(att) && approvalSignerOk(att))
  ];
  // v0.6 step #2 (design note §4, lines 107-116): the report ENUMERATES
  // every valid approval — dedup ONLY by `approval_id` so a replayed
  // attestation counts once, but a single approver legitimately approving
  // several action types still surfaces each approval (do NOT collapse by
  // signer). Each entry carries `approver_key_fingerprint` so a relying
  // party can do distinct-identity counting itself ("two signatures from one
  // key are one approver") — that judgment is the consumer's, over the
  // enumerated list, not a fact the verifier bakes in. First-seen wins.
  // v0.6 step #4: a signature-valid approval is `vouched` when it carries an
  // `identity_proof` (issuer "sequesign") whose registration record is signed by
  // a trusted platform key and binds the SAME signer key, role, identity, and
  // party_type. Vouching flips the leg to `present_verified`; an unvouched
  // approval is still enumerated and keeps the leg at `present_unverified`.
  const approvalVouched = (att: ApprovalAttestation): boolean =>
    !!att.identity_proof &&
    att.identity_proof.issuer === "sequesign" &&
    identityProofVouches(
      att.identity_proof.ref,
      {
        role: "approver",
        identity: att.approver_id,
        partyType: att.party_type,
        subjectPublicKeyPem: att.approver_public_key
      },
      trustedRegistrationFingerprints
    );
  // First-seen wins for the enumerated fields. `vouched` is ORed across
  // duplicates of an approval_id ONLY when the duplicate is the SAME signed
  // identity (key + approver_id + action) as the kept entry — so an in-envelope
  // copy and a satellite copy of the *same* approval combine their vouch, but a
  // different attestation that merely reuses the approval_id can never transfer
  // its vouch onto the displayed identity (would mark the wrong key verified).
  const approvalSummaries: ApprovalSummary[] = [];
  const approvalById = new Map<string, ApprovalSummary>();
  for (const att of validApprovals) {
    const fingerprint = ed25519KeyFingerprint(att.approver_public_key);
    const existing = approvalById.get(att.approval_id);
    if (existing) {
      // Carry the vouch only when EVERY signed/displayed field matches — i.e.
      // the duplicate is the same signed approval (an in-envelope copy and its
      // satellite are byte-identical). Matching key + id + party_type + action
      // + time prevents transferring a vouch onto a different attestation that
      // merely reuses the approval_id (incl. a different party_type the proof
      // was not issued for).
      if (
        approvalVouched(att) &&
        existing.approver_key_fingerprint === fingerprint &&
        existing.approver_id === att.approver_id &&
        existing.party_type === att.party_type &&
        existing.approved_action_type === att.approved_action_type &&
        existing.approved_at === att.approved_at
      ) {
        existing.vouched = true;
      }
      continue;
    }
    const summary: ApprovalSummary = {
      approval_id: att.approval_id,
      approver_id: att.approver_id,
      approver_key_fingerprint: fingerprint,
      party_type: att.party_type,
      approved_action_type: att.approved_action_type,
      approved_at: att.approved_at,
      vouched: approvalVouched(att)
    };
    approvalById.set(att.approval_id, summary);
    approvalSummaries.push(summary);
  }
  const approval: LegState = approvalSummaries.some((s) => s.vouched)
    ? "present_verified"
    : approvalSummaries.length > 0
      ? "present_unverified"
      : "absent";
  const counterpartyAttestations = receipt.counterparty_attestations ?? [];
  // Counterparty attestation binding (PR 15-A.1, findings #2, #10,
  // #12). The signature proves only that the counterparty key signed
  // the attestation's fields. Bind the attestation to this chain, to a
  // real action in this chain, and to that action's evidence hash, so a
  // counterparty confirmation cannot be replayed against an unrelated
  // chain or pointed at content it never confirmed. attestation_purpose
  // must be non-empty (previously an implicit expectation).
  const actionsByIdForCounterparty = new Map(actions.map((a) => [a.action_id, a]));
  for (const att of counterpartyAttestations) {
    const counterpartyBindingFailures: string[] = [];
    if (att.chain_id !== receipt.chain.chain_id)
      counterpartyBindingFailures.push(
        `counterparty attestation chain_id ${att.chain_id} does not match receipt chain_id ${receipt.chain.chain_id}`
      );
    const target = actionsByIdForCounterparty.get(att.attested_action_id);
    if (!target)
      counterpartyBindingFailures.push(
        `counterparty attestation attested_action_id ${att.attested_action_id} matches no recorded action in this chain`
      );
    else if (att.attested_content_hash !== target.evidence_hash)
      counterpartyBindingFailures.push(
        `counterparty attestation attested_content_hash does not match the target action's evidence_hash`
      );
    if (!att.attestation_purpose || att.attestation_purpose.length === 0)
      counterpartyBindingFailures.push(`counterparty attestation attestation_purpose is empty`);
    if (counterpartyBindingFailures.length > 0)
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason: "counterparty_attestation_binding_mismatch",
        details: counterpartyBindingFailures
      });
  }
  // Independent badge, tri-state — same posture as approval. Per-
  // attestation: one invalid appended attestation must not suppress an
  // otherwise-valid one, so count independently rather than all-or-
  // nothing. `present_verified` is unreachable this version (no vouching).
  // Signer-level validity shared by in-envelope and satellite counterparties
  // (same Ed25519 gate as approvals — the enumeration fingerprints the key).
  const counterpartySignerOk = (att: CounterpartyAttestation): boolean =>
    isEd25519PublicKeyPem(att.counterparty_public_key) &&
    verifyEd25519(
      att.counterparty_public_key,
      counterpartyAttestationMessage({
        counterpartyId: att.counterparty_id,
        chainId: att.chain_id,
        attestedActionId: att.attested_action_id,
        attestedContentHash: att.attested_content_hash,
        attestationPurpose: att.attestation_purpose,
        attestedAt: att.attested_at
      }),
      att.signature
    );
  // In-envelope counterparties already passed the hard-fail binding loop.
  // Satellite counterparties are NOT part of sealed R, so their binding is
  // checked SOFTLY (drop on mismatch, never fail R): bound to THIS chain, to a
  // recorded action, to that action's evidence hash, with a non-empty purpose.
  const counterpartyBoundToReceipt = (att: CounterpartyAttestation): boolean => {
    if (att.chain_id !== receipt.chain.chain_id) return false;
    const target = actionsByIdForCounterparty.get(att.attested_action_id);
    if (!target || att.attested_content_hash !== target.evidence_hash) return false;
    return !!att.attestation_purpose && att.attestation_purpose.length > 0;
  };
  const validCounterparties = [
    ...counterpartyAttestations.filter(counterpartySignerOk),
    ...satelliteCounterparties.filter(
      (att) => counterpartyBoundToReceipt(att) && counterpartySignerOk(att)
    )
  ];
  // v0.6 step #2: symmetric to approvals — ENUMERATE every valid
  // confirmation, deduping only an exact replay of the same logical
  // confirmation, i.e. the same (counterparty_id, attested_action_id). A
  // counterparty confirming several different actions surfaces each. Each
  // entry carries `counterparty_key_fingerprint` so a relying party can
  // count distinct signers itself. First-seen wins; the "|" separator
  // cannot appear in a canonical counterparty_id or an action_id, so the
  // composite key is unambiguous.
  // v0.6 step #4: same vouching rule as approvals (role "counterparty"; the
  // named identity is counterparty_id; no party_type).
  const counterpartyVouched = (att: CounterpartyAttestation): boolean =>
    !!att.identity_proof &&
    att.identity_proof.issuer === "sequesign" &&
    identityProofVouches(
      att.identity_proof.ref,
      {
        role: "counterparty",
        identity: att.counterparty_id,
        subjectPublicKeyPem: att.counterparty_public_key
      },
      trustedRegistrationFingerprints
    );
  // First-seen wins for the enumerated fields; `vouched` is ORed across
  // duplicates of the same (counterparty_id, attested_action_id) ONLY when the
  // duplicate is the SAME signer key — the dedup key omits the key, so a
  // different key reusing the (id, action) pair must not transfer its vouch onto
  // the displayed fingerprint (would mark the wrong key verified).
  const counterpartySummaries: CounterpartySummary[] = [];
  const counterpartyByKey = new Map<string, CounterpartySummary>();
  for (const att of validCounterparties) {
    const dedupKey = `${att.counterparty_id}|${att.attested_action_id}`;
    const fingerprint = ed25519KeyFingerprint(att.counterparty_public_key);
    const existing = counterpartyByKey.get(dedupKey);
    if (existing) {
      // As with approvals: carry the vouch only for the same signed
      // confirmation — matching signer key + purpose + time (id + action are
      // already equal via the dedup key) — so a different attestation reusing
      // the (id, action) pair cannot transfer its vouch.
      if (
        counterpartyVouched(att) &&
        existing.counterparty_key_fingerprint === fingerprint &&
        existing.attestation_purpose === att.attestation_purpose &&
        existing.attested_at === att.attested_at
      ) {
        existing.vouched = true;
      }
      continue;
    }
    const summary: CounterpartySummary = {
      counterparty_id: att.counterparty_id,
      counterparty_key_fingerprint: fingerprint,
      attested_action_id: att.attested_action_id,
      attestation_purpose: att.attestation_purpose,
      attested_at: att.attested_at,
      vouched: counterpartyVouched(att)
    };
    counterpartyByKey.set(dedupKey, summary);
    counterpartySummaries.push(summary);
  }
  const counterparty: LegState = counterpartySummaries.some((s) => s.vouched)
    ? "present_verified"
    : counterpartySummaries.length > 0
      ? "present_unverified"
      : "absent";
  const witnessed = witnessSignaturesOk && receipt.witness_attestations.length === actions.length;
  const agentIdentityBound =
    agentSignaturesOk && receipt.agent_attestations.length === actions.length;
  // Policy binding is a protocol invariant (spec 3.1.1): when requested,
  // every action must commit to the same policy_context_hash. A false
  // policyBound means the receipt is malformed, which is a hard failure.
  // This mirrors the schema/workflow fail-path flag construction. After
  // this point only true (verified) and null (not requested) remain.
  if (policyBound === false) {
    return fail({
      receipt_mode: receipt.receipt_mode,
      reason: "policy_binding_failed",
      flags: {
        ...baseFlags(),
        hash_integrity: true,
        sequence_integrity: true,
        schema_valid: schemaValid,
        workflow_profile_valid: workflowProfileValid,
        witnessed,
        agent_identity_bound: agentIdentityBound,
        policy_bound: false
      },
      details: taskPolicyHash
        ? [
            `The task declares policy_context_hash ${taskPolicyHash} but not every action record commits to the same value.`
          ]
        : ["Some action records declare policy_context_hash but the task does not."]
    });
  }
  // The early-rejection guard at the top of this function ensures
  // receipt.schema_version === "sequesign.receipt.v1.0.0" by the time
  // we get here, so completeness gating depends only on whether the
  // attestations actually carry log fields.
  const hasLogFields = receipt.witness_attestations.some(
    (att) => att.log_entry !== undefined || att.chain_head !== undefined
  );
  let completenessVerified: boolean | null = null;
  let completenessReport: VerificationReport["completeness"];
  if (hasLogFields) {
    let logEntriesConsistent = true;
    for (let i = 0; i < receipt.witness_attestations.length; i++) {
      const att = receipt.witness_attestations[i];
      if (att.log_entry && att.chain_head) {
        if (att.log_entry.entry_hash !== att.chain_head.entry_hash) {
          logEntriesConsistent = false;
        }
        if (att.log_entry.position !== att.chain_head.position) {
          logEntriesConsistent = false;
        }
        if (att.log_entry.log_id !== att.chain_head.log_id) {
          logEntriesConsistent = false;
        }
      }
    }
    if (!logEntriesConsistent) {
      completenessVerified = false;
      const logId = receipt.witness_attestations[0]?.log_entry?.log_id ?? "global";
      completenessReport = {
        log_id: logId,
        chain_id: receipt.chain.chain_id,
        receipt_action_count: actions.length,
        source: "offline"
      };
    } else if (options.completeness) {
      const logId = receipt.witness_attestations[0]?.log_entry?.log_id ?? "global";
      try {
        const queryResult = await options.completeness.query({
          chainId: receipt.chain.chain_id,
          logId
        });
        const receiptPositions = new Set<number>();
        for (const att of receipt.witness_attestations) {
          if (att.log_entry) receiptPositions.add(att.log_entry.position);
        }
        const omitted = queryResult.entry_positions.filter((p) => !receiptPositions.has(p));
        completenessVerified =
          queryResult.entry_count === actions.length && omitted.length === 0;
        completenessReport = {
          log_id: logId,
          chain_id: receipt.chain.chain_id,
          receipt_action_count: actions.length,
          log_entry_count: queryResult.entry_count,
          omitted_positions: omitted.length > 0 ? omitted : undefined,
          source: "witness_log"
        };
      } catch (err) {
        completenessVerified = null;
        completenessReport = {
          log_id: logId,
          chain_id: receipt.chain.chain_id,
          receipt_action_count: actions.length,
          source: "witness_log"
        };
        details.push(
          `Completeness check could not run: ${err instanceof Error ? err.message : String(err)}.`
        );
      }
    } else {
      completenessVerified = null;
    }
  }

  // Inclusion proofs: for each witness attestation, verify both the
  // Merkle audit path and the witness signature over the canonical
  // batch message. The proof itself can come from three sources
  // checked in priority order: embedded on the attestation, a
  // proofs.jsonl sidecar in the package directory, or an online
  // fetcher passed in options. Failure of any obtained proof is a
  // hard verification failure; absence from every source is permitted
  // and produces "not_present" or "partial". See PLAN.md section
  // 4.23.
  const inclusionResult = await verifyInclusionProofs(
    receipt,
    packageDir,
    options.inclusionProofs
  );
  if (inclusionResult.state === "failed") {
    return fail({
      receipt_mode: receipt.receipt_mode,
      reason: inclusionResult.reasons[0] ?? "inclusion_proof_invalid",
      flags: {
        ...baseFlags(),
        hash_integrity: true,
        sequence_integrity: true,
        schema_valid: schemaValid,
        workflow_profile_valid: workflowProfileValid,
        witnessed,
        agent_identity_bound: agentIdentityBound,
        policy_bound: policyBound,
        approval,
        counterparty,
        completeness_verified: completenessVerified,
        inclusion_proofs_verified: "failed"
      },
      details: inclusionResult.reasons
    });
  }

  // Agent identity attestation (PR 15-A). Present only on receipts
  // produced under a registered API key. The verifier recomputes the
  // key fingerprint from the embedded agent_public_key and reports the
  // tier; it never consults an external registry and never requires a
  // receipt to be registered. Absent attestation -> unregistered.
  // Present-and-matching -> registered. Present-and-mismatched is a hard
  // failure: the attestation claims a key the embedded public key does
  // not hash to. Computed here, after integrity/signature checks, so a
  // tampered receipt fails on the more fundamental error first.
  let agentIdentity: VerificationReport["agent_identity"];
  const attestation = receipt.agent_identity_attestation;
  if (!attestation) {
    agentIdentity = { kind: "unregistered" };
  } else {
    // agentKeyFingerprint normalizes the embedded PEM before hashing, so
    // it matches the canonical fingerprint the broker stamped regardless
    // of the embedded key's formatting. A malformed embedded key cannot
    // produce a fingerprint, which is itself a mismatch.
    let expectedFingerprint: string | null = null;
    try {
      expectedFingerprint = agentKeyFingerprint(receipt.agent_public_key);
    } catch {
      expectedFingerprint = null;
    }
    if (expectedFingerprint === null || attestation.key_fingerprint !== expectedFingerprint) {
      return fail({
        receipt_mode: receipt.receipt_mode,
        reason:
          expectedFingerprint === null
            ? `agent_identity_attestation_fingerprint_mismatch: the embedded agent_public_key is not a valid Ed25519 PEM, so its fingerprint cannot be computed.`
            : `agent_identity_attestation_fingerprint_mismatch: the attestation key_fingerprint (${attestation.key_fingerprint}) does not match the SHA-256 of the embedded agent_public_key (${expectedFingerprint}).`
      });
    }
    agentIdentity = {
      kind: "registered",
      key_fingerprint: attestation.key_fingerprint,
      registered_at: attestation.registered_at
    };
  }

  // v0.6 arc: identity-anchored base only — `L0` → `L2` (identity) →
  // `L3` (+policy), `L1` the witnessed-only fallback. Approval and
  // counterparty are independent badges (flags.approval /
  // flags.counterparty), NOT ladder rungs, so there is no `L4`/`L5`.
  // `witnessed` stays orthogonal: `L2`+ does not require it.
  let verification_level: VerificationReport["verification_level"] = "L0_INTEGRITY_ONLY";
  if (witnessed) verification_level = "L1_WITNESSED";
  if (agentIdentityBound) verification_level = "L2_IDENTITY_BOUND";
  // policyBound is boolean | null here (false hard-failed above). true
  // reaches L3; null (not requested) stays at L2.
  if (agentIdentityBound && policyBound) verification_level = "L3_POLICY_BOUND";
  if (receipt.receipt_mode === "freeform")
    details.push("Schema/profile validation was not requested for this freeform receipt.");
  if (receipt.receipt_mode !== "freeform") details.push("Schema validation passed.");
  if (receipt.receipt_mode === "profile_constrained")
    details.push("Workflow profile validation passed.");
  if (inclusionResult.state === "passed") {
    details.push(
      `Inclusion proofs verified for ${inclusionResult.proven} of ${inclusionResult.total} witness attestations.`
    );
  } else if (inclusionResult.state === "partial") {
    details.push(
      `Inclusion proofs verified for ${inclusionResult.proven} of ${inclusionResult.total} witness attestations; the rest had no proof attached.`
    );
  }
  return {
    valid: true,
    verification_level,
    receipt_mode: receipt.receipt_mode,
    trust_anchor_mode: trustAnchorMode,
    witness_trust_anchor: witnessTrustAnchor,
    agent_identity: agentIdentity,
    profile: profileReport,
    flags: {
      hash_integrity: true,
      sequence_integrity: true,
      schema_valid: schemaValid,
      workflow_profile_valid: workflowProfileValid,
      witnessed,
      agent_identity_bound: agentIdentityBound,
      policy_bound: policyBound,
      approval,
      counterparty,
      completeness_verified: completenessVerified,
      inclusion_proofs_verified: inclusionResult.state
    },
    approvals: approvalSummaries,
    counterparties: counterpartySummaries,
    chain: {
      chain_id: receipt.chain.chain_id,
      sequence_start: receipt.chain.sequence_start,
      sequence_end: receipt.chain.sequence_start + Math.max(actions.length - 1, 0),
      final_chain_state: receipt.chain.final_chain_state
    },
    completeness: completenessReport,
    inclusion_proofs:
      inclusionResult.state !== "not_present"
        ? {
            total_attestations: inclusionResult.total,
            proven_attestations: inclusionResult.proven,
            failed_attestations: 0,
            source: inclusionResult.source
          }
        : undefined,
    details
  };
}

type InclusionVerificationResult =
  | { state: "not_present"; total: number; proven: number; source: InclusionProofsSource }
  | { state: "passed"; total: number; proven: number; source: InclusionProofsSource }
  | { state: "partial"; total: number; proven: number; source: InclusionProofsSource }
  | {
      state: "failed";
      total: number;
      proven: number;
      reasons: string[];
      source: InclusionProofsSource;
    };

async function loadSidecarProofs(packageDir: string): Promise<BatchInclusionProof[]> {
  const sidecarPath = path.join(packageDir, "proofs.jsonl");
  let raw: unknown[];
  try {
    raw = await readJsonl<unknown>(sidecarPath);
  } catch (err: unknown) {
    // Sidecar absent is the normal case for Phase 1.5 receipts and
    // for direct-mode receipts produced without proof embedding.
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === "ENOENT") return [];
    throw err;
  }
  // The witness's POST /log/export writes one line per exported entry
  // and marks each as either {batched: true, ...full proof fields} or
  // {batched: false, log_id, position, entry_hash} when the entry is
  // still in a pending batch. Only complete proofs are usable here;
  // pending rows match the (log_id, position, entry_hash) addressing
  // triple but lack audit_path/merkle_root, which would crash
  // verifySingleInclusionProof. Drop incomplete rows so the verifier
  // falls through to the next source (sidecar miss for that entry).
  return raw.filter(isCompleteInclusionProof);
}

function isCompleteInclusionProof(value: unknown): value is BatchInclusionProof {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.log_id === "string" &&
    typeof v.position === "number" &&
    typeof v.entry_hash === "string" &&
    typeof v.batch_id === "number" &&
    typeof v.merkle_root === "string" &&
    typeof v.tree_size === "number" &&
    typeof v.leaf_index === "number" &&
    Array.isArray(v.audit_path) &&
    typeof v.first_position === "number" &&
    typeof v.last_position === "number" &&
    typeof v.batch_sealed_at === "string" &&
    typeof v.witness_key_id === "string" &&
    typeof v.witness_signature === "string"
  );
}

// v0.6 step #3: the canonical hash of the sealed receipt envelope R. A
// satellite binds to R by carrying this value as `attested_receipt_hash`.
// hashCanonical applies JCS, so the hash is stable regardless of byte
// formatting and independent of any later satellite (which lives in the
// sidecar, never in R).
export function canonicalReceiptHash(receipt: AgentActionReceipt): string {
  return hashCanonical(receipt);
}

// The content a satellite's witness seals: its receipt binding plus the
// inner attestation, canonicalized. Producer (when sealing) and verifier
// (when checking the seal) compute it identically.
export function satelliteContentHash(
  attestedReceiptHash: string,
  attestation: ApprovalAttestation | CounterpartyAttestation
): string {
  return hashCanonical({ attested_receipt_hash: attestedReceiptHash, attestation });
}

// Read the deferred-satellite sidecar (top-level attestations.jsonl). Absent
// is the normal case (no deferred attestations). Parsed defensively, line by
// line: a malformed-JSON line (truncated upload, hand-edit) or a line that is
// not a well-formed satellite is skipped, never fatal — optional deferred
// evidence must never sink an otherwise-valid R.
async function loadSatellites(packageDir: string): Promise<AttestationSatellite[]> {
  let text: string;
  try {
    text = await readFile(path.join(packageDir, "attestations.jsonl"), "utf8");
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === "ENOENT") return [];
    throw err;
  }
  const satellites: AttestationSatellite[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (isAttestationSatellite(parsed)) satellites.push(parsed);
  }
  return satellites;
}

// A satellite is accepted into the bundle only when EVERY field the seal /
// signature message builders read is present and a string. The builders call
// lengthPrefixedUtf8, which throws on a non-string; validating the full
// signed-field shape here means a malformed sidecar line is dropped at load
// (R stays valid) instead of aborting bundle verification downstream.
function hasStringFields(value: unknown, fields: readonly string[]): boolean {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return fields.every((f) => typeof v[f] === "string");
}

const SATELLITE_WITNESS_FIELDS = [
  "witness_id",
  "witness_key_id",
  "witness_public_key",
  "satellite_content_hash",
  "witnessed_at",
  "signature"
] as const;
const APPROVAL_FIELDS = [
  "approval_id",
  "approver_id",
  "approver_public_key",
  "party_type",
  "approved_task_id",
  "approved_action_type",
  "approval_context_hash",
  "approved_at",
  "signature"
] as const;
const COUNTERPARTY_FIELDS = [
  "counterparty_id",
  "counterparty_public_key",
  "chain_id",
  "attested_action_id",
  "attested_content_hash",
  "attestation_purpose",
  "attested_at",
  "signature"
] as const;

// Exported so the SDK's package-writer can apply the EXACT same minimum
// satellite shape when reading the sidecar for its pre-seal dedup guard: a
// line this predicate rejects is one the verifier's loadSatellites would also
// drop, so the SDK must not let such a line occupy a dedup slot (which would
// block an otherwise-valid retry the verifier needs to fold a real attestation
// in). Single source of truth keeps the two in lockstep.
export function isAttestationSatellite(value: unknown): value is AttestationSatellite {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.attested_receipt_hash !== "string") return false;
  if (!hasStringFields(v.witness_attestation, SATELLITE_WITNESS_FIELDS)) return false;
  if (v.schema_version === "sequesign.approval_satellite.v1.0.0")
    return hasStringFields(v.approval, APPROVAL_FIELDS);
  if (v.schema_version === "sequesign.counterparty_satellite.v1.0.0")
    return hasStringFields(v.counterparty, COUNTERPARTY_FIELDS);
  return false;
}

// Verify a satellite's witness seal: it must cover exactly this satellite's
// content, the witness key must be trusted (fingerprint recomputed from the
// PEM, not the declared key_id), the declared key_id must agree, and the
// signature must verify. Establishes T_i + integrity of the satellite.
function satelliteWitnessVerifies(
  witness: SatelliteWitnessAttestation,
  expectedContentHash: string,
  trustedFingerprints: Set<string>
): boolean {
  if (witness.satellite_content_hash !== expectedContentHash) return false;
  let fingerprint: string;
  try {
    fingerprint = keyIdFromPublicKeyPem(witness.witness_public_key);
  } catch {
    return false;
  }
  if (!trustedFingerprints.has(fingerprint)) return false;
  if (witness.witness_key_id !== fingerprint) return false;
  return verifyEd25519(
    witness.witness_public_key,
    satelliteWitnessMessage({
      witnessId: witness.witness_id,
      satelliteContentHash: witness.satellite_content_hash,
      witnessedAt: witness.witnessed_at
    }),
    witness.signature
  );
}

// Bundle step: from the satellites bound to THIS receipt whose witness seal
// verifies, return their inner attestations. A satellite bound to a different
// receipt, or whose seal does not verify, is dropped — it never affects R's
// standalone result. Binding of the inner attestation to a real action/task
// is enforced later, uniformly with the in-envelope attestations.
function collectSatelliteAttestations(
  satellites: AttestationSatellite[],
  receiptHash: string,
  trustedFingerprints: Set<string>
): { approvals: ApprovalAttestation[]; counterparties: CounterpartyAttestation[] } {
  const approvals: ApprovalAttestation[] = [];
  const counterparties: CounterpartyAttestation[] = [];
  for (const sat of satellites) {
    // Defense in depth: any failure hashing or seal-verifying a SINGLE
    // satellite (e.g. a non-JCS string such as a lone UTF-16 surrogate that
    // hashCanonical rejects) drops just that satellite — optional deferred
    // evidence must never abort verification of an otherwise-valid R.
    try {
      if (sat.attested_receipt_hash !== receiptHash) continue;
      if (sat.schema_version === "sequesign.approval_satellite.v1.0.0") {
        const contentHash = satelliteContentHash(sat.attested_receipt_hash, sat.approval);
        if (satelliteWitnessVerifies(sat.witness_attestation, contentHash, trustedFingerprints))
          approvals.push(sat.approval);
      } else {
        const contentHash = satelliteContentHash(sat.attested_receipt_hash, sat.counterparty);
        if (satelliteWitnessVerifies(sat.witness_attestation, contentHash, trustedFingerprints))
          counterparties.push(sat.counterparty);
      }
    } catch {
      continue;
    }
  }
  return { approvals, counterparties };
}

function findSidecarProof(
  sidecarProofs: BatchInclusionProof[],
  ref: { log_id: string; position: number; entry_hash: string }
): BatchInclusionProof | undefined {
  return sidecarProofs.find(
    (p) =>
      p.log_id === ref.log_id &&
      p.position === ref.position &&
      p.entry_hash === ref.entry_hash
  );
}

async function verifyInclusionProofs(
  receipt: AgentActionReceipt,
  packageDir: string,
  fetcher?: InclusionProofFetcher
): Promise<InclusionVerificationResult> {
  const sidecarProofs = await loadSidecarProofs(packageDir);
  const attestations = receipt.witness_attestations;
  const total = attestations.length;
  let proven = 0;
  const sources: InclusionProofsSource[] = [];
  const reasons: string[] = [];

  for (const att of attestations) {
    // Embedded source. Verified the same way as before this PR.
    if (att.batch_inclusion_proof) {
      const fail = verifySingleInclusionProof(att, att.batch_inclusion_proof);
      if (fail) {
        reasons.push(fail);
        continue;
      }
      proven += 1;
      sources.push("embedded");
      continue;
    }

    // Sidecar and fetcher both require log_entry as the addressing
    // key. An attestation without log_entry is unaddressable: the
    // verifier has no way to look up the proof, so it remains
    // unverified. (Equivalent to today's behavior, which left
    // proof-less attestations alone.)
    const ref = att.log_entry;
    if (!ref) continue;

    // Sidecar source. Sidecar takes precedence over the online
    // fetcher; the fetcher is only consulted on a sidecar miss.
    const sidecarProof = findSidecarProof(sidecarProofs, ref);
    if (sidecarProof) {
      const fail = verifySingleInclusionProof(att, sidecarProof);
      if (fail) {
        reasons.push(fail);
        continue;
      }
      proven += 1;
      sources.push("sidecar");
      continue;
    }

    // Online fetcher source. Pending or not_found results leave the
    // attestation unverified; verification degrades gracefully rather
    // than hard-failing. Network errors are treated the same way.
    if (fetcher) {
      let result: InclusionProofLookupResult | undefined;
      try {
        result = await fetcher.fetch({
          logId: ref.log_id,
          position: ref.position,
          entryHash: ref.entry_hash
        });
      } catch {
        result = undefined;
      }
      if (result && result.status === "found") {
        const fail = verifySingleInclusionProof(att, result.proof);
        if (fail) {
          reasons.push(fail);
          continue;
        }
        proven += 1;
        sources.push("fetched_online");
        continue;
      }
    }
  }

  const source = computeOverallSource(proven, sources);

  if (reasons.length > 0) {
    return { state: "failed", total, proven, reasons, source };
  }
  if (proven === 0) return { state: "not_present", total, proven, source };
  if (proven === total) return { state: "passed", total, proven, source };
  return { state: "partial", total, proven, source };
}

function computeOverallSource(
  proven: number,
  sources: InclusionProofsSource[]
): InclusionProofsSource {
  if (proven === 0) return "not_available";
  const unique = new Set(sources);
  if (unique.size === 1) return sources[0];
  return "mixed";
}

function verifySingleInclusionProof(
  attestation: AgentActionReceipt["witness_attestations"][number],
  proof: BatchInclusionProof
): string | null {
  // Bind the proof to this attestation's log_entry. Without this
  // gate, a valid proof for a different log entry signed by the same
  // witness key can be transplanted onto this attestation and the
  // Merkle and batch-signature checks below still pass, producing a
  // false "passed" for inclusion_proofs_verified. The SDK only
  // attaches a proof when log_entry is present, so a missing
  // log_entry alongside a proof is also a mismatch.
  const ref = attestation.log_entry;
  if (
    !ref ||
    proof.log_id !== ref.log_id ||
    proof.position !== ref.position ||
    proof.entry_hash !== ref.entry_hash
  ) {
    return "inclusion_proof_attestation_mismatch";
  }

  // Audit path.
  let leafHash: Buffer;
  try {
    leafHash = hexToBytes(proof.entry_hash);
  } catch {
    return "inclusion_proof_malformed";
  }
  if (leafHash.length !== 32) return "inclusion_proof_malformed";
  let auditPath: Buffer[];
  try {
    auditPath = proof.audit_path.map((h) => hexToBytes(h));
  } catch {
    return "inclusion_proof_malformed";
  }
  let expectedRoot: Buffer;
  try {
    expectedRoot = hexToBytes(proof.merkle_root);
  } catch {
    return "inclusion_proof_malformed";
  }
  if (expectedRoot.length !== 32) return "inclusion_proof_malformed";
  const ok = verifyAuditPath({
    leafHash,
    leafIndex: proof.leaf_index,
    treeSize: proof.tree_size,
    auditPath,
    expectedRoot
  });
  if (!ok) return "inclusion_proof_invalid";

  // Key match: the receipt only carries a single witness public key
  // per attestation. If the proof was signed under a different key
  // (e.g. rotation, or a proof from a different witness), reject.
  let expectedKeyId: string;
  try {
    expectedKeyId = keyIdFromPublicKeyPem(attestation.witness_public_key);
  } catch {
    return "inclusion_proof_malformed";
  }
  if (proof.witness_key_id !== expectedKeyId) {
    return "inclusion_proof_key_mismatch";
  }

  // Batch signature.
  const message = batchSigningMessage({
    logId: proof.log_id,
    batchId: proof.batch_id,
    treeSize: proof.tree_size,
    firstPosition: proof.first_position,
    lastPosition: proof.last_position,
    batchSealedAt: proof.batch_sealed_at,
    merkleRootHex: proof.merkle_root
  });
  if (!verifyEd25519(attestation.witness_public_key, message, proof.witness_signature)) {
    return "inclusion_proof_signature_invalid";
  }
  return null;
}
export async function writeVerificationReport(
  packageDir: string,
  report: VerificationReport
): Promise<void> {
  await writeJson(path.join(packageDir, "verification-report.json"), report);
}
function flagText(v: boolean | null | string): string {
  if (v === null) return "not requested";
  if (typeof v === "string") {
    const friendly: Record<string, string> = {
      not_present: "not present (pending)",
      passed: "PASSED",
      failed: "FAILED",
      partial: "PARTIAL"
    };
    return friendly[v] ?? v;
  }
  return v ? "PASSED" : "FAILED";
}
export function printVerificationReport(report: VerificationReport): void {
  if (report.valid) {
    console.log("Sequesign verification PASSED");
    console.log(`Level: ${report.verification_level}`);
    if (report.receipt_mode) console.log(`Mode: ${report.receipt_mode}`);
    if (report.profile) console.log(`Profile: ${report.profile.profile_id}`);
    console.log(`Schema validation: ${flagText(report.flags.schema_valid)}`);
    console.log(`Workflow validation: ${flagText(report.flags.workflow_profile_valid)}`);
    if (report.chain) {
      console.log(`Chain: ${report.chain.chain_id}`);
      console.log(`Actions: ${report.chain.sequence_end - report.chain.sequence_start + 1}`);
      console.log(`Final state: ${report.chain.final_chain_state.slice(0, 12)}...`);
    }
    if (report.flags.witnessed) console.log("Witness: verified");
    if (report.flags.approval !== "absent")
      console.log(`Approval: ${report.flags.approval}`);
    if (report.flags.counterparty !== "absent")
      console.log(`Counterparty: ${report.flags.counterparty}`);
    if (report.flags.inclusion_proofs_verified !== null) {
      console.log(`Inclusion proofs: ${flagText(report.flags.inclusion_proofs_verified)}`);
    }
    return;
  }
  console.log("Sequesign verification FAILED");
  if (report.reason) console.log(`Reason: ${report.reason}`);
  if (report.action)
    console.log(
      `Action: sequence=${report.action.sequence}, action_type=${report.action.action_type}`
    );
  if (report.expected_evidence_hash)
    console.log(`Expected evidence_hash: ${report.expected_evidence_hash.slice(0, 12)}...`);
  if (report.computed_evidence_hash)
    console.log(`Computed evidence_hash:  ${report.computed_evidence_hash.slice(0, 12)}...`);
  for (const detail of report.details ?? []) console.log(detail);
}
