// Signing-core helper for non-SDK / curl callers (design:
// docs/managed-mode-curl-helper-design.md). These are plain, dependency-free
// functions — Ed25519 via node:crypto plus the existing canonicalize / chain /
// envelope code — exposed as the `@sequesign/sdk/prepare` subpath and driven by
// the `sequesign` CLI (src/sdk/cli.ts). They let a caller in any language build
// and sign a managed-mode `/v1/receipt` (Shape 1) body and assemble the
// `/v1/receipts/finalize` body, without re-implementing the protocol's
// canonicalization and chain math.
//
// The signer computes the bytes it signs: prepare()/sign() build the canonical
// action_record locally and the broker only re-derives and verifies. Chains use
// Shape 1 with a caller-supplied stable receipt_id (matching the SDK's
// intermediary-client), so every per-action row and the finalized envelope bind
// to one id.

import { lengthPrefixedUtf8 } from "../lib/encoding.js";
import { extendChain } from "../lib/chain.js";
import { hashCanonical, sha256Hex } from "../lib/hash.js";
import { signEd25519 } from "../lib/keys.js";
import { agentAttestationMessage } from "../lib/messages.js";
import { assembleAgentActionReceipt, type AssembledAction } from "../lib/envelope.js";
import type {
  ActionRecord,
  AgentActionReceipt,
  AgentAttestation,
  ApprovalAttestation,
  CounterpartyAttestation,
  EvidenceBlob,
  EvidenceReference,
  ProfileReference,
  ReceiptMode,
  SchemaReference,
  VerifiabilityClass
} from "../lib/types.js";
import { buildActionRecord, buildEvidenceBlob } from "./recorder.js";
import type { WitnessRequest } from "../lib/witness-types.js";
import { generateActionId, nowIso } from "./identifiers.js";
import { evidenceFilename } from "./package-writer.js";
import type { EnvelopeCustody, EvidenceCustody } from "./types.js";

// Retention override wire form (mirrors the broker's RetentionOverrideSchema).
export type RetentionInput = { until: string } | { duration: string };

// Sequence-1 chain state, derived from the chain id alone (spec §2.6 framing).
// Identical to SessionState's initialChainState and to the value the helper uses
// for sequence 1's previous_chain_state.
export function initialChainState(chainId: string): string {
  return sha256Hex(lengthPrefixedUtf8(["SEQUESIGN_INITIAL_STATE_V0", chainId]));
}

export interface PrepareInput {
  chainId: string;
  // Stable across the whole chain; the caller generates it once (rec_...). Shape
  // 1 honours it; Shape 2 would reassign it per call (see the design doc §4.2).
  receiptId: string;
  sequence: number;
  // Required when sequence > 1; for sequence 1 it is derived from chainId.
  previousChainState?: string;
  agentId: string;
  agentPublicKeyPem: string;
  taskId: string;
  delegatorId: string;
  delegatedAt?: string;
  actionType: string;
  verifiabilityClass?: VerifiabilityClass;
  policyContextHash?: string;
  timestamp?: string;
  metadata?: Record<string, unknown>;
  schemaId?: string;
  schemaHash?: string;
  evidence: unknown;
  // Default "both" (send evidence). When "customer", the request body carries
  // evidence_hash instead of evidence (the broker never sees the content).
  evidenceCustody?: EvidenceCustody;
  envelopeCustody?: EnvelopeCustody;
  // Multi-action chains defer envelope storage and finalize once at the end.
  // Defaults to true (the helper's primary use is chains).
  deferEnvelopeStorage?: boolean;
  retention?: RetentionInput;
}

export interface PrepareResult {
  // The exact Shape 1 POST body for /v1/receipt. In prepare() its
  // agent_signature is null; the caller fills it after signing
  // attestationMessageB64 and POSTs this verbatim. sign() fills it in.
  requestBody: Record<string, unknown>;
  // Canonical objects + attestation, kept for assemble-finalize (the deferred
  // /v1/receipt response does not echo them back).
  actionRecord: ActionRecord;
  evidenceBlob: EvidenceBlob;
  actionRecordHash: string;
  chainState: string;
  // base64 of the RAW length-prefixed bytes to Ed25519-sign (decode before
  // signing).
  attestationMessageB64: string;
  // signature is "" in prepare(); the caller sets it to the base64 signature
  // (the same value used for request_body.agent_signature). sign() fills it.
  agentAttestation: AgentAttestation;
  // Direct mode: the exact body to POST to the witness's /witness endpoint
  // (commitment hashes only — no evidence, no action_record, no signature).
  // Managed callers ignore this and POST requestBody to the broker instead.
  witnessRequest: WitnessRequest;
}

function resolvePreviousChainState(input: PrepareInput): string {
  if (input.sequence <= 1) {
    return input.previousChainState ?? initialChainState(input.chainId);
  }
  if (!input.previousChainState) {
    throw new PrepareError(
      "previous_chain_state_required",
      `sequence ${input.sequence} requires previous_chain_state (the prior action's chain_state).`
    );
  }
  return input.previousChainState;
}

export class PrepareError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "PrepareError";
    this.code = code;
  }
}

// Build the canonical objects, chain state, attestation bytes, and the Shape 1
// request body (with agent_signature null). Does NOT touch a private key.
export function prepare(input: PrepareInput): PrepareResult {
  if ((input.schemaId === undefined) !== (input.schemaHash === undefined)) {
    throw new PrepareError(
      "schema_binding_incomplete",
      "schema_id and schema_hash must be provided together."
    );
  }
  const sequence = input.sequence;
  const actionType = input.actionType;
  const evidenceCustody = input.evidenceCustody ?? "both";
  const envelopeCustody = input.envelopeCustody ?? "both";
  const deferEnvelopeStorage = input.deferEnvelopeStorage ?? true;
  const verifiabilityClass: VerifiabilityClass = input.verifiabilityClass ?? "deterministic";
  const timestamp = input.timestamp ?? nowIso();
  const previousChainState = resolvePreviousChainState(input);
  const actionId = generateActionId(sequence, actionType);

  const evidenceBlob = buildEvidenceBlob({
    actionId,
    actionType,
    schemaId: input.schemaId,
    schemaHash: input.schemaHash,
    content: input.evidence
  });
  const evidenceHash = hashCanonical(evidenceBlob);

  const actionRecord = buildActionRecord({
    actionId,
    actionType,
    sequence,
    chainId: input.chainId,
    agentId: input.agentId,
    agentPublicKeyPem: input.agentPublicKeyPem,
    taskId: input.taskId,
    delegatorId: input.delegatorId,
    verifiabilityClass,
    evidenceHash,
    policyContextHash: input.policyContextHash,
    previousChainState,
    timestamp,
    metadata: input.metadata
  });
  const actionRecordHash = hashCanonical(actionRecord);
  const chainState = extendChain({
    chainId: input.chainId,
    sequence,
    previousChainState,
    actionRecordHash
  });
  const attestationMessage = agentAttestationMessage({
    chainId: input.chainId,
    sequence,
    actionRecordHash,
    chainState
  });

  const agentAttestation: AgentAttestation = {
    schema_version: "sequesign.agent_attestation.v0.1",
    chain_id: input.chainId,
    sequence,
    action_record_hash: actionRecordHash,
    chain_state: chainState,
    agent_id: input.agentId,
    agent_public_key: input.agentPublicKeyPem,
    signature_alg: "Ed25519",
    signature: ""
  };

  // Shape 1 /v1/receipt body. Mirrors intermediary-client.ts postReceipt so the
  // broker rebuilds a byte-identical action_record. agent_signature is null
  // until the caller (or sign()) fills it; previous_chain_state is omitted on
  // sequence 1 so the broker derives the initial state from chain_id.
  const sendsEvidence = evidenceCustody === "sequesign" || evidenceCustody === "both";
  const requestBody: Record<string, unknown> = {
    agent_id: input.agentId,
    agent_public_key: input.agentPublicKeyPem,
    task_id: input.taskId,
    task_delegator_id: input.delegatorId,
    action_type: actionType,
    agent_signature: null,
    chain_id: input.chainId,
    receipt_id: input.receiptId,
    timestamp,
    verifiability_class: verifiabilityClass,
    evidence_custody: evidenceCustody,
    envelope_custody: envelopeCustody,
    sequence
  };
  if (sendsEvidence) requestBody.evidence = input.evidence;
  else requestBody.evidence_hash = evidenceHash;
  if (input.policyContextHash) requestBody.policy_context_hash = input.policyContextHash;
  if (input.delegatedAt) requestBody.delegated_at = input.delegatedAt;
  if (sequence > 1) requestBody.previous_chain_state = previousChainState;
  if (deferEnvelopeStorage) requestBody.defer_envelope_storage = true;
  if (input.metadata !== undefined) requestBody.metadata = input.metadata;
  if (input.schemaId !== undefined) requestBody.schema_id = input.schemaId;
  if (input.schemaHash !== undefined) requestBody.schema_hash = input.schemaHash;
  if (input.retention !== undefined) requestBody.retention = input.retention;

  // Direct-mode witness body: commitment hashes only. previous_chain_state is
  // always carried (on sequence 1 it is the chain_id-derived initial state),
  // mirroring what the SDK's direct path sends to POST /witness.
  const witnessRequest: WitnessRequest = {
    chain_id: input.chainId,
    sequence,
    action_record_hash: actionRecordHash,
    previous_chain_state: previousChainState,
    chain_state: chainState,
    receipt_schema_version: "sequesign.receipt.v2.0.0"
  };

  return {
    requestBody,
    actionRecord,
    evidenceBlob,
    actionRecordHash,
    chainState,
    attestationMessageB64: attestationMessage.toString("base64"),
    agentAttestation,
    witnessRequest
  };
}

// prepare() + sign the attestation message with the caller's local Ed25519
// private key, filling agent_signature into the request body and the
// attestation. The key never leaves this process.
export function sign(input: PrepareInput, privateKeyPem: string): PrepareResult {
  const result = prepare(input);
  const signature = signEd25519(
    privateKeyPem,
    agentAttestationMessage({
      chainId: input.chainId,
      sequence: input.sequence,
      actionRecordHash: result.actionRecordHash,
      chainState: result.chainState
    })
  );
  result.requestBody.agent_signature = signature;
  result.agentAttestation = { ...result.agentAttestation, signature };
  return result;
}

export interface SessionHeader {
  chainId: string;
  receiptId: string;
  receiptMode: ReceiptMode;
  agent: { agentId: string; agentPublicKeyPem: string };
  task: {
    taskId: string;
    delegatorId: string;
    delegatedAt: string;
    policyContextHash?: string;
  };
  profile?: ProfileReference;
  schemaReferences?: SchemaReference[];
  retention?: RetentionInput;
  evidenceCustody: EvidenceCustody;
  envelopeCustody: EnvelopeCustody;
}

// One accumulated record per action: the signed inputs (from prepare/sign) plus
// the witness attestation returned by /v1/receipt.
export interface FinalizeActionInput {
  actionRecord: ActionRecord;
  evidenceBlob: EvidenceBlob;
  agentAttestation: AgentAttestation;
  witnessAttestation: AssembledAction["witnessAttestation"];
}

export interface AssembleFinalizeInput {
  session: SessionHeader;
  actions: FinalizeActionInput[];
  approvalAttestations?: ApprovalAttestation[];
  counterpartyAttestations?: CounterpartyAttestation[];
  // Direct / local assembly (assemble-receipt): the package holds the evidence
  // and the caller is the custodian, so emit local `evidence/<file>` references
  // with external_client_managed custody regardless of the managed custody flag
  // (mirrors the SDK direct path). Defaults to false (managed behavior).
  localEvidence?: boolean;
}

export interface AssembleFinalizeResult {
  receipt: AgentActionReceipt;
  // The POST /v1/receipts/finalize body. evidence_blobs is omitted when the
  // customer holds evidence (the broker verifies hashes against action_records).
  finalizeBody: Record<string, unknown>;
}

function evidenceReferenceFor(
  action: FinalizeActionInput,
  evidenceCustody: EvidenceCustody,
  localEvidence: boolean
): EvidenceReference {
  const localPath = `evidence/${evidenceFilename(action.actionRecord.sequence, action.actionRecord.action_type)}`;
  // Direct / local assembly: the bytes live in the package and the caller is the
  // custodian, so the reference points at the local file with
  // external_client_managed custody regardless of the managed custody flag.
  if (localEvidence) {
    return {
      action_id: action.actionRecord.action_id,
      evidence_hash: action.actionRecord.evidence_hash,
      evidence_path: localPath,
      mime_type: "application/json",
      evidence_custody: "external_client_managed"
    };
  }
  const customerHoldsEvidence = evidenceCustody === "customer";
  return {
    action_id: action.actionRecord.action_id,
    evidence_hash: action.actionRecord.evidence_hash,
    evidence_path: customerHoldsEvidence ? "external" : localPath,
    mime_type: "application/json",
    evidence_custody: customerHoldsEvidence ? "external_client_managed" : "sequesign_hosted"
  };
}

// Assemble the canonical envelope and the /v1/receipts/finalize body from the
// session header plus the accumulated per-action records. Everything outside the
// session header is derived here, exactly as buildReceiptEnvelope reads it from
// SessionState (src/sdk/envelope.ts).
export function assembleFinalize(input: AssembleFinalizeInput): AssembleFinalizeResult {
  const { session } = input;
  if (input.actions.length === 0) {
    throw new PrepareError("no_actions", "assemble-finalize requires at least one action record.");
  }
  // Sequence order keeps the envelope's parallel arrays aligned.
  const ordered = [...input.actions].sort(
    (a, b) => a.actionRecord.sequence - b.actionRecord.sequence
  );

  const assembled: AssembledAction[] = ordered.map((action) => {
    // action_record_hash is recomputed from the canonical action record (and
    // must equal the attestation's, which the broker re-checks at finalize).
    const recomputed = hashCanonical(action.actionRecord);
    if (recomputed !== action.agentAttestation.action_record_hash) {
      throw new PrepareError(
        "action_record_hash_mismatch",
        `action ${action.actionRecord.action_id}: canonical action_record hash does not match its agent_attestation.action_record_hash.`
      );
    }
    return {
      actionRecordHash: recomputed,
      agentAttestation: action.agentAttestation,
      witnessAttestation: action.witnessAttestation,
      evidenceReference: evidenceReferenceFor(
        action,
        session.evidenceCustody,
        input.localEvidence ?? false
      )
    };
  });

  const last = ordered[ordered.length - 1];
  const first = ordered[0];
  const finalChainState = last.agentAttestation.chain_state;

  const receipt = assembleAgentActionReceipt({
    receiptId: session.receiptId,
    receiptMode: session.receiptMode,
    agent: {
      agentId: session.agent.agentId,
      agentPublicKeyPem: session.agent.agentPublicKeyPem
    },
    task: {
      taskId: session.task.taskId,
      delegatorId: session.task.delegatorId,
      delegatedAt: session.task.delegatedAt,
      policyContextHash: session.task.policyContextHash
    },
    chain: {
      chainId: session.chainId,
      initialChainState: initialChainState(session.chainId),
      finalChainState,
      sequenceStart: first.actionRecord.sequence
    },
    actions: assembled,
    approvalAttestations: input.approvalAttestations,
    counterpartyAttestations: input.counterpartyAttestations,
    profile: session.profile,
    schemaReferences: session.schemaReferences
  });

  const finalizeBody: Record<string, unknown> = {
    receipt,
    action_records: ordered.map((a) => a.actionRecord),
    evidence_custody: session.evidenceCustody,
    envelope_custody: session.envelopeCustody
  };
  if (session.evidenceCustody !== "customer") {
    finalizeBody.evidence_blobs = ordered.map((a) => a.evidenceBlob);
  }
  if (session.retention !== undefined) finalizeBody.retention = session.retention;

  return { receipt, finalizeBody };
}
