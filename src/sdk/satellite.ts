// v0.6 step #3b.3: submit a DEFERRED-attestation satellite against an
// already-sealed receipt R (post-finalize).
//
// A sealed receipt never changes (design note §5). A later approval /
// counterparty confirmation is minted as a detached satellite that binds to
// R by `attested_receipt_hash = canonicalReceiptHash(R)`, carries the SAME
// inner attestation an in-envelope one would, is independently witnessed at
// its own time T_i (direct: witness POST /witness/satellite; managed: broker
// POST /v1/satellites, step #3b.2), and is appended to the TOP-LEVEL
// `attestations.jsonl` sidecar the offline verifier reads. The verifier then
// folds a valid satellite's inner attestation into the SAME badge /
// enumeration as a co-located one ("born co-located" uniformity).
//
// Binding is validated against R here as a fail-fast (the verifier is the
// authoritative, order-independent gate): an off-task / off-action / off-
// content satellite is rejected with the SAME error code as the in-envelope
// recordApproval / recordCounterpartyAttestation path, BEFORE a witness
// signature is spent on it. The dedup guard (against both R's in-envelope
// attestations and the existing sidecar) likewise runs before the seal, so a
// re-submit of the same logical attestation is refused without billing.

import { agentKeyFingerprint } from "../lib/hash.js";
import { isEd25519PublicKeyPem, keyIdFromPublicKeyPem, verifyEd25519 } from "../lib/keys.js";
import {
  approvalMessage,
  counterpartyAttestationMessage,
  satelliteWitnessMessage
} from "../lib/messages.js";
import { isCanonicalCounterpartyId, isValidApproverId } from "../lib/package-layout.js";
import type {
  AgentActionReceipt,
  ApprovalAttestation,
  ApprovalSatellite,
  CounterpartyAttestation,
  CounterpartySatellite,
  SatelliteWitnessAttestation
} from "../lib/types.js";
import { canonicalReceiptHash, satelliteContentHash } from "../lib/verify.js";
import type { ResolvedSdkConfig } from "./config.js";
import { ApprovalError, CounterpartyAttestationError, SatelliteError } from "./errors.js";
import { generateApprovalId, nowIso } from "./identifiers.js";
import { createIntermediaryClient } from "./intermediary-client.js";
import { createPackageWriter } from "./package-writer.js";
import { buildApprovalAttestation } from "./recorder.js";
import type { SubmitApprovalSatelliteInput, SubmitCounterpartySatelliteInput } from "./types.js";
import { connectWitness, resolveWitnessConfig } from "./witness-client.js";

// Obtain the witness seal for a satellite, routing to the witness directly
// (direct mode) or through the broker (managed mode), per the SDK config.
async function sealSatellite(
  resolved: ResolvedSdkConfig,
  req: { chainId: string; attestedReceiptHash: string; satelliteContentHash: string }
): Promise<SatelliteWitnessAttestation> {
  if (resolved.mode === "direct") {
    const witness = await connectWitness(resolveWitnessConfig(resolved.witness, undefined));
    return witness.signSatellite(req);
  }
  const client = createIntermediaryClient(resolved.intermediary);
  return client.postSatellite(req);
}

// Check a returned seal against EXACTLY the satellite we submitted, applying
// the same acceptance criteria the offline verifier's satelliteWitnessVerifies
// applies, so the SDK never reports a successful submit for a seal the verifier
// will silently drop (which would also poison the sidecar's dedup slot for that
// id). Direct mode's signSatellite already binds the content hash and verifies
// against the trusted key; this is the equivalent gate for managed mode, where
// the broker relays the seal verbatim and the SDK holds no witness key.
//
//   1. the seal must cover OUR content hash (not some other attestation's);
//   2. witness_key_id must equal the fingerprint of the carried public key
//      (the verifier recomputes the fingerprint and requires agreement);
//   3. the seal must come from the same WITNESS that sealed R (by witness_id) —
//      so a seal from a different witness (e.g. the SDK default witness on a
//      self-hosted package) is refused here instead of appended-then-dropped,
//      while a later seal from the SAME witness under a ROTATED key is still
//      accepted (an externally-anchored verifier that trusts the witness's
//      current well-known key folds it; pinning to R's embedded key would
//      wrongly block deferred satellites after any rotation); and
//   4. the signature must verify against that public key.
function assertSealBindsToContent(
  seal: SatelliteWitnessAttestation,
  expectedContentHash: string,
  trustedWitnessIds: Set<string>
): void {
  if (seal.satellite_content_hash !== expectedContentHash) {
    throw new SatelliteError(
      "satellite_seal_content_mismatch",
      "The witness seal covers a different satellite_content_hash than the one submitted; the verifier would drop this satellite."
    );
  }
  let fingerprint: string;
  try {
    fingerprint = keyIdFromPublicKeyPem(seal.witness_public_key);
  } catch {
    throw new SatelliteError(
      "satellite_seal_invalid",
      "The witness seal's witness_public_key is not a valid Ed25519 public key."
    );
  }
  if (seal.witness_key_id !== fingerprint) {
    throw new SatelliteError(
      "satellite_seal_invalid",
      "The witness seal's witness_key_id does not match the fingerprint of its witness_public_key; the verifier would drop this satellite."
    );
  }
  if (!trustedWitnessIds.has(seal.witness_id)) {
    throw new SatelliteError(
      "satellite_seal_untrusted_witness",
      "The witness seal is from a different witness than the one that sealed the receipt; the verifier would drop this satellite. Submit via the same witness that sealed the receipt."
    );
  }
  const ok = verifyEd25519(
    seal.witness_public_key,
    satelliteWitnessMessage({
      witnessId: seal.witness_id,
      satelliteContentHash: seal.satellite_content_hash,
      witnessedAt: seal.witnessed_at
    }),
    seal.signature
  );
  if (!ok) {
    throw new SatelliteError(
      "satellite_seal_invalid",
      "The witness seal's signature does not verify against the witness_public_key it carries."
    );
  }
}

// True when an approver key is the executing agent's own key, compared by
// canonical fingerprint exactly as the verifier's O3 distinctness guard does
// (so CRLF/whitespace-reformatted copies of the agent key are caught). A key
// that cannot be fingerprinted is not treated as the agent key — its signature
// would not verify anyway, so the verifier drops it on other grounds.
function sharesAgentKey(approverPublicKeyPem: string, agentPublicKeyPem: string): boolean {
  try {
    return agentKeyFingerprint(approverPublicKeyPem) === agentKeyFingerprint(agentPublicKeyPem);
  } catch {
    return false;
  }
}

// Boolean form of the seal-binding check used for scanning EXISTING sidecar
// entries (assertSealBindsToContent above is the throwing form used on a freshly
// returned seal). The seal must cover this content hash, carry a witness_key_id
// equal to its key's fingerprint, come from the same WITNESS that sealed R (by
// witness_id, so a seal from any other witness does not occupy a dedup slot
// while a rotated key from the same witness still does), and verify.
function sealBindsToContent(
  seal: SatelliteWitnessAttestation,
  expectedContentHash: string,
  trustedWitnessIds: Set<string>
): boolean {
  if (seal.satellite_content_hash !== expectedContentHash) return false;
  let fingerprint: string;
  try {
    fingerprint = keyIdFromPublicKeyPem(seal.witness_public_key);
  } catch {
    return false;
  }
  if (seal.witness_key_id !== fingerprint) return false;
  if (!trustedWitnessIds.has(seal.witness_id)) return false;
  return verifyEd25519(
    seal.witness_public_key,
    satelliteWitnessMessage({
      witnessId: seal.witness_id,
      satelliteContentHash: seal.satellite_content_hash,
      witnessedAt: seal.witnessed_at
    }),
    seal.signature
  );
}

// Whether an EXISTING sidecar approval satellite would actually be FOLDED by the
// verifier — i.e. its approval_id legitimately occupies a dedup slot. The
// verifier dedups only over satellites that pass binding + signer + seal
// verification, so the pre-seal guard must apply the same bar: an invalid
// same-id line (bad seal, bad inner signature, self-approval, non-Ed25519 key,
// off-task/off-action) is NOT counted, so a valid retry can still repair the
// package. (Action-type binding needs the recorded action types; when those are
// unavailable the entry is treated as non-folding, the same direction the
// verifier takes when it cannot confirm the binding.)
function approvalSatelliteFoldable(
  sat: ApprovalSatellite,
  receipt: AgentActionReceipt,
  attestedReceiptHash: string,
  recordedActionTypes: Set<string>,
  trustedWitnessIds: Set<string>
): boolean {
  const a = sat.approval;
  if (sat.attested_receipt_hash !== attestedReceiptHash) return false;
  if (a.approved_task_id !== receipt.task.task_id) return false;
  if (!recordedActionTypes.has(a.approved_action_type)) return false;
  if (a.party_type !== "human" && a.party_type !== "agent") return false;
  if (!isEd25519PublicKeyPem(a.approver_public_key)) return false;
  if (sharesAgentKey(a.approver_public_key, receipt.agent_public_key)) return false;
  const verified = verifyEd25519(
    a.approver_public_key,
    approvalMessage({
      approvalId: a.approval_id,
      approverId: a.approver_id,
      partyType: a.party_type,
      approvedTaskId: a.approved_task_id,
      approvedActionType: a.approved_action_type,
      approvalContextHash: a.approval_context_hash,
      approvedAt: a.approved_at
    }),
    a.signature
  );
  if (!verified) return false;
  return sealBindsToContent(
    sat.witness_attestation,
    satelliteContentHash(attestedReceiptHash, a),
    trustedWitnessIds
  );
}

// Counterpart of approvalSatelliteFoldable for counterparty satellites.
function counterpartySatelliteFoldable(
  sat: CounterpartySatellite,
  receipt: AgentActionReceipt,
  attestedReceiptHash: string,
  trustedWitnessIds: Set<string>
): boolean {
  const c = sat.counterparty;
  if (sat.attested_receipt_hash !== attestedReceiptHash) return false;
  if (c.chain_id !== receipt.chain.chain_id) return false;
  const target = receipt.evidence_references.find((e) => e.action_id === c.attested_action_id);
  if (!target || c.attested_content_hash !== target.evidence_hash) return false;
  if (!c.attestation_purpose || c.attestation_purpose.length === 0) return false;
  if (!isEd25519PublicKeyPem(c.counterparty_public_key)) return false;
  const verified = verifyEd25519(
    c.counterparty_public_key,
    counterpartyAttestationMessage({
      counterpartyId: c.counterparty_id,
      chainId: c.chain_id,
      attestedActionId: c.attested_action_id,
      attestedContentHash: c.attested_content_hash,
      attestationPurpose: c.attestation_purpose,
      attestedAt: c.attested_at
    }),
    c.signature
  );
  if (!verified) return false;
  return sealBindsToContent(
    sat.witness_attestation,
    satelliteContentHash(attestedReceiptHash, c),
    trustedWitnessIds
  );
}

// The witness identities (witness_id) that sealed R. A satellite seal is trusted
// when it comes from one of these witnesses, by identity rather than by exact
// key: this matches an externally-anchored verifier that trusts the witness's
// current well-known key (so a deferred satellite still folds after a key
// rotation), while still rejecting a seal from a different witness. The offline
// verifier remains the authoritative trust gate against its own key set.
function trustedWitnessIdsFromReceipt(receipt: AgentActionReceipt): Set<string> {
  return new Set((receipt.witness_attestations ?? []).map((a) => a.witness_id));
}

export async function submitApprovalSatelliteImpl(
  input: SubmitApprovalSatelliteInput,
  resolved: ResolvedSdkConfig
): Promise<ApprovalSatellite> {
  const { receipt } = input;

  // 1. Build / validate the inner approval, mirroring session.recordApproval.
  let approval: ApprovalAttestation;
  if (input.mode === "sign_locally") {
    approval = buildApprovalAttestation({
      approvalId: input.approvalId ?? generateApprovalId(),
      approverId: input.approverId,
      partyType: input.partyType ?? "human",
      approverKeypair: input.approverKeypair,
      // Defaults to the sealed receipt's task, the only task a satellite
      // against R can approve.
      approvedTaskId: input.approvedTaskId ?? receipt.task.task_id,
      approvedActionType: input.approvedActionType,
      approvalContext: input.approvalContext,
      approvedAt: input.approvedAt ?? nowIso(),
      identityProof: input.identityProof
    });
  } else if (input.mode === "attach_signed") {
    approval = input.attestation;
    const message = approvalMessage({
      approvalId: approval.approval_id,
      approverId: approval.approver_id,
      partyType: approval.party_type,
      approvedTaskId: approval.approved_task_id,
      approvedActionType: approval.approved_action_type,
      approvalContextHash: approval.approval_context_hash,
      approvedAt: approval.approved_at
    });
    if (!verifyEd25519(approval.approver_public_key, message, approval.signature)) {
      throw new ApprovalError(
        "approver_signature_invalid",
        `Attached approval's signature does not verify against the supplied approver_public_key (approver_id=${approval.approver_id}).`
      );
    }
  } else {
    throw new ApprovalError(
      "approval_mode_invalid",
      `submitApprovalSatellite requires mode "sign_locally" or "attach_signed".`
    );
  }

  // 2. Bind to R (same codes as the in-envelope path). The verifier folds a
  // satellite approval into the same task/action binding as a co-located one.
  if (approval.approved_task_id !== receipt.task.task_id) {
    throw new ApprovalError(
      "approved_task_id_mismatch",
      `Approval references task ${approval.approved_task_id}; sealed receipt task is ${receipt.task.task_id}.`
    );
  }
  if (!isValidApproverId(approval.approver_id)) {
    throw new ApprovalError(
      "approver_id_invalid",
      `approver_id "${approval.approver_id}" is not a valid lowercase email or label (letters, digits, ".", "_", "+", "-", optional "@domain").`
    );
  }
  // party_type must be one of the enumerated values. sign_locally defaults to
  // "human", but an attach_signed payload (or a JS caller) can carry any value;
  // the verifier's approvalSignerOk drops an approval whose party_type is not
  // "human" | "agent", so gate it before the seal.
  if (approval.party_type !== "human" && approval.party_type !== "agent") {
    throw new ApprovalError(
      "approver_party_type_invalid",
      `party_type "${approval.party_type}" is not "human" or "agent"; the verifier drops an approval with any other party_type.`
    );
  }
  // The key must be a genuine Ed25519 public key. verifyEd25519 delegates to
  // Node's generic EdDSA verifier, which also accepts other EdDSA keys (e.g.
  // Ed448), but the verifier's approvalSignerOk requires isEd25519PublicKeyPem
  // and the enumeration fingerprints the key — so a non-Ed25519 approval is
  // dropped. Gate it here (this also makes the fingerprint-based distinctness
  // check below well-defined, since agentKeyFingerprint is Ed25519-only).
  if (!isEd25519PublicKeyPem(approval.approver_public_key)) {
    throw new ApprovalError(
      "approver_key_not_ed25519",
      "approver_public_key is not an Ed25519 public key; the verifier accepts only Ed25519 approver keys and would drop this approval."
    );
  }
  // O3: an actor must not mint its own approval badge. The verifier folds an
  // approval only when its key is DISTINCT from the executing agent (by
  // canonical fingerprint, so a reformatted copy of the agent key cannot slip
  // through); a self-approval is dropped. Fail fast before the seal so a
  // self-approval never spends a witness signature on a satellite the verifier
  // would silently drop.
  if (sharesAgentKey(approval.approver_public_key, receipt.agent_public_key)) {
    throw new ApprovalError(
      "approver_key_not_distinct",
      "Approval is signed by the executing agent's own key; an approval must be signed by a party distinct from the agent (O3). The verifier drops a self-approval."
    );
  }

  const writer = createPackageWriter(input.packageDirectory);

  // approved_action_type must match an action recorded in R. Action types are
  // not in the envelope, so read them from the package's actions.jsonl. When
  // the package carries no actions file (some custody layouts), skip this
  // fail-fast and let the verifier be the authoritative gate.
  const actions = await writer.readActions();
  if (actions.length > 0 && !actions.some((a) => a.action_type === approval.approved_action_type)) {
    throw new ApprovalError(
      "approved_action_type_mismatch",
      `Approval approves action_type "${approval.approved_action_type}", which matches no action in the sealed receipt. The verifier rejects this binding.`
    );
  }

  // 3. Dedup across BOTH R's in-envelope approvals and the existing sidecar —
  // the same domain the verifier deduplicates over (by approval_id). Only
  // sidecar entries that the verifier would actually FOLD count: it dedups over
  // satellites that pass binding + signer + seal verification (and are bound to
  // THIS receipt), so an invalid / off-receipt same-id line must not occupy a
  // slot — otherwise a valid retry that repairs the package is wrongly refused.
  // Refused before the seal so a re-submit does not spend a witness signature.
  const attestedReceiptHash = canonicalReceiptHash(receipt);
  const trustedWitnessIds = trustedWitnessIdsFromReceipt(receipt);
  const recordedActionTypes = new Set(actions.map((a) => a.action_type));
  const existingApprovalIds = new Set<string>([
    ...(receipt.approval_attestations ?? []).map((a) => a.approval_id),
    ...(await writer.readSatellites())
      .filter(
        (s): s is ApprovalSatellite => s.schema_version === "sequesign.approval_satellite.v1.0.0"
      )
      .filter((s) =>
        approvalSatelliteFoldable(s, receipt, attestedReceiptHash, recordedActionTypes, trustedWitnessIds)
      )
      .map((s) => s.approval.approval_id)
  ]);
  if (existingApprovalIds.has(approval.approval_id)) {
    throw new SatelliteError(
      "approval_id_duplicate",
      `approval_id "${approval.approval_id}" is already attested for this receipt (in the envelope or the satellite sidecar).`
    );
  }

  // 4. Seal + assemble + append.
  const contentHash = satelliteContentHash(attestedReceiptHash, approval);
  const seal = await sealSatellite(resolved, {
    chainId: receipt.chain.chain_id,
    attestedReceiptHash,
    satelliteContentHash: contentHash
  });
  assertSealBindsToContent(seal, contentHash, trustedWitnessIds);
  const satellite: ApprovalSatellite = {
    schema_version: "sequesign.approval_satellite.v1.0.0",
    attested_receipt_hash: attestedReceiptHash,
    approval,
    witness_attestation: seal
  };
  await writer.appendSatelliteLine(satellite);
  return satellite;
}

export async function submitCounterpartySatelliteImpl(
  input: SubmitCounterpartySatelliteInput,
  resolved: ResolvedSdkConfig
): Promise<CounterpartySatellite> {
  const { receipt } = input;
  const counterparty: CounterpartyAttestation = input.attestation;

  // The key must be a genuine Ed25519 public key. verifyEd25519 (below)
  // delegates to Node's generic EdDSA verifier, which also accepts other EdDSA
  // keys (e.g. Ed448), but the verifier's counterpartySignerOk requires
  // isEd25519PublicKeyPem and would drop a non-Ed25519 counterparty — so gate
  // it before spending a seal.
  if (!isEd25519PublicKeyPem(counterparty.counterparty_public_key)) {
    throw new CounterpartyAttestationError(
      "counterparty_key_not_ed25519",
      "counterparty_public_key is not an Ed25519 public key; the verifier accepts only Ed25519 counterparty keys and would drop this attestation."
    );
  }

  // 1. Verify the counterparty's own signature. Unlike a co-located
  // counterparty (verified at verify-time), a satellite costs a witness
  // signature to seal, so a bad signature is caught up front.
  const message = counterpartyAttestationMessage({
    counterpartyId: counterparty.counterparty_id,
    chainId: counterparty.chain_id,
    attestedActionId: counterparty.attested_action_id,
    attestedContentHash: counterparty.attested_content_hash,
    attestationPurpose: counterparty.attestation_purpose,
    attestedAt: counterparty.attested_at
  });
  if (!verifyEd25519(counterparty.counterparty_public_key, message, counterparty.signature)) {
    throw new CounterpartyAttestationError(
      "counterparty_signature_invalid",
      `Counterparty attestation's signature does not verify against the supplied counterparty_public_key (counterparty_id=${counterparty.counterparty_id}).`
    );
  }

  // 2. Bind to R (same codes as the in-envelope path).
  if (counterparty.chain_id !== receipt.chain.chain_id) {
    throw new CounterpartyAttestationError(
      "chain_id_mismatch",
      `Counterparty attestation references chain ${counterparty.chain_id}; sealed receipt chain is ${receipt.chain.chain_id}.`
    );
  }
  const target = receipt.evidence_references.find(
    (e) => e.action_id === counterparty.attested_action_id
  );
  if (!target) {
    throw new CounterpartyAttestationError(
      "attested_action_id_not_found",
      `Counterparty attestation references action ${counterparty.attested_action_id}, which is not in the sealed receipt.`
    );
  }
  if (counterparty.attested_content_hash !== target.evidence_hash) {
    throw new CounterpartyAttestationError(
      "attested_content_hash_mismatch",
      `Counterparty attestation attested_content_hash does not match the evidence_hash of action ${counterparty.attested_action_id} in the sealed receipt.`
    );
  }
  if (!isCanonicalCounterpartyId(counterparty.counterparty_id)) {
    throw new CounterpartyAttestationError(
      "counterparty_id_invalid",
      `counterparty_id "${counterparty.counterparty_id}" is not canonical (lowercase alphanumeric segments joined by single dots or hyphens).`
    );
  }
  // The verifier requires a non-empty attestation_purpose and drops a
  // satellite counterparty without one. Fail fast before the seal so an empty
  // purpose never spends a witness signature on a satellite the verifier would
  // silently drop.
  if (!counterparty.attestation_purpose || counterparty.attestation_purpose.length === 0) {
    throw new CounterpartyAttestationError(
      "attestation_purpose_empty",
      "Counterparty attestation attestation_purpose is empty; the verifier requires a non-empty purpose and drops the attestation."
    );
  }

  const writer = createPackageWriter(input.packageDirectory);

  // 3. Dedup on (counterparty_id, attested_action_id) across R's in-envelope
  // counterparties and the sidecar — the verifier's dedup domain. Only sidecar
  // entries the verifier would actually FOLD count (bound to THIS receipt, with
  // a verifying seal + inner signature + non-empty purpose + Ed25519 key), so an
  // invalid / off-receipt same-key line must not block a valid repair submit.
  // Before the seal so a re-submit does not spend a witness signature.
  const attestedReceiptHash = canonicalReceiptHash(receipt);
  const trustedWitnessIds = trustedWitnessIdsFromReceipt(receipt);
  const key = (id: string, actionId: string) => `${id} ${actionId}`;
  const existing = new Set<string>([
    ...(receipt.counterparty_attestations ?? []).map((c) =>
      key(c.counterparty_id, c.attested_action_id)
    ),
    ...(await writer.readSatellites())
      .filter(
        (s): s is CounterpartySatellite =>
          s.schema_version === "sequesign.counterparty_satellite.v1.0.0"
      )
      .filter((s) => counterpartySatelliteFoldable(s, receipt, attestedReceiptHash, trustedWitnessIds))
      .map((s) => key(s.counterparty.counterparty_id, s.counterparty.attested_action_id))
  ]);
  if (existing.has(key(counterparty.counterparty_id, counterparty.attested_action_id))) {
    throw new SatelliteError(
      "counterparty_attestation_duplicate",
      `counterparty_id "${counterparty.counterparty_id}" already attested action "${counterparty.attested_action_id}" for this receipt (in the envelope or the satellite sidecar).`
    );
  }

  // 4. Seal + assemble + append.
  const contentHash = satelliteContentHash(attestedReceiptHash, counterparty);
  const seal = await sealSatellite(resolved, {
    chainId: receipt.chain.chain_id,
    attestedReceiptHash,
    satelliteContentHash: contentHash
  });
  assertSealBindsToContent(seal, contentHash, trustedWitnessIds);
  const satellite: CounterpartySatellite = {
    schema_version: "sequesign.counterparty_satellite.v1.0.0",
    attested_receipt_hash: attestedReceiptHash,
    counterparty,
    witness_attestation: seal
  };
  await writer.appendSatelliteLine(satellite);
  return satellite;
}
