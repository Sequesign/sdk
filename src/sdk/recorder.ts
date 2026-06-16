import { extendChain } from "../lib/chain.js";
import { hashCanonical } from "../lib/hash.js";
import { signEd25519, verifyEd25519 } from "../lib/keys.js";
import {
  agentAttestationMessage,
  approvalMessage
} from "../lib/messages.js";
import type {
  ActionRecord,
  AgentAttestation,
  ApprovalAttestation,
  EvidenceBlob,
  IdentityProof,
  VerifiabilityClass
} from "../lib/types.js";
import { ApprovalError } from "./errors.js";
import { nowIso } from "./identifiers.js";
import type { KeyMaterial } from "./types.js";

export interface BuildEvidenceArgs {
  actionId: string;
  actionType: string;
  schemaId?: string;
  schemaHash?: string;
  content: unknown;
}

export function buildEvidenceBlob(args: BuildEvidenceArgs): EvidenceBlob {
  return {
    schema_version: "sequesign.evidence.v0.1",
    action_id: args.actionId,
    action_type: args.actionType,
    schema_id: args.schemaId,
    schema_hash: args.schemaHash,
    mime_type: "application/json",
    content: args.content
  };
}

export interface BuildActionRecordArgs {
  actionId: string;
  actionType: string;
  sequence: number;
  chainId: string;
  agentId: string;
  agentPublicKeyPem: string;
  taskId: string;
  delegatorId: string;
  verifiabilityClass: VerifiabilityClass;
  evidenceHash: string;
  policyContextHash?: string;
  previousChainState: string;
  timestamp?: string;
  metadata?: Record<string, unknown>;
}

export function buildActionRecord(args: BuildActionRecordArgs): ActionRecord {
  return {
    schema_version: "sequesign.action_record.v0.2",
    action_id: args.actionId,
    action_type: args.actionType,
    sequence: args.sequence,
    chain_id: args.chainId,
    actor: {
      agent_id: args.agentId,
      agent_public_key: args.agentPublicKeyPem
    },
    task: {
      task_id: args.taskId,
      delegator_id: args.delegatorId
    },
    verifiability_class: args.verifiabilityClass,
    evidence_hash: args.evidenceHash,
    policy_context_hash: args.policyContextHash,
    previous_chain_state: args.previousChainState,
    timestamp: args.timestamp ?? nowIso(),
    metadata: args.metadata
  };
}

export interface RecorderExtendArgs {
  actionRecord: ActionRecord;
  agentPrivateKeyPem: string;
  agentId: string;
  agentPublicKeyPem: string;
}

export interface RecorderExtendResult {
  actionRecordHash: string;
  nextChainState: string;
  agentAttestation: AgentAttestation;
}

// §3.2 PR 3: shared approval builder. Direct mode owned this helper
// privately in session.ts; managed mode needs the identical builder so
// a sign_locally approval produces a byte-identical ApprovalAttestation
// across both modes. Verifies the signature it just produced as a
// defensive check: a defective Ed25519 implementation would otherwise
// emit a "valid" attestation that the offline verifier rejects. v0.6
// arc: `partyType` (human | agent) is part of the signed message.
export interface BuildApprovalArgs {
  approvalId: string;
  approverId: string;
  partyType: "human" | "agent";
  approverKeypair: KeyMaterial;
  approvedTaskId: string;
  approvedActionType: string;
  approvalContext: unknown;
  approvedAt: string;
  // v0.6 step #4.4 (vouching): optional identity proof attached to the
  // approval. NOT part of the signed message (see approvalMessage), so adding
  // it never changes the signature — it is metadata the verifier resolves to
  // flip the approval leg to present_verified.
  identityProof?: IdentityProof;
}

export function buildApprovalAttestation(
  args: BuildApprovalArgs
): ApprovalAttestation {
  const approvalContextHash = hashCanonical(args.approvalContext);
  const message = approvalMessage({
    approvalId: args.approvalId,
    approverId: args.approverId,
    partyType: args.partyType,
    approvedTaskId: args.approvedTaskId,
    approvedActionType: args.approvedActionType,
    approvalContextHash,
    approvedAt: args.approvedAt
  });
  const signature = signEd25519(args.approverKeypair.privateKeyPem, message);
  if (!verifyEd25519(args.approverKeypair.publicKeyPem, message, signature)) {
    throw new ApprovalError(
      "approver_signature_invalid",
      `Signature produced by sign_locally did not verify against the supplied approver public key (approver_id=${args.approverId}).`
    );
  }
  return {
    schema_version: "sequesign.approval.v1.0.0",
    approval_id: args.approvalId,
    approver_id: args.approverId,
    approver_public_key: args.approverKeypair.publicKeyPem,
    party_type: args.partyType,
    approved_task_id: args.approvedTaskId,
    approved_action_type: args.approvedActionType,
    approval_context_hash: approvalContextHash,
    approved_at: args.approvedAt,
    signature_alg: "Ed25519",
    signature,
    ...(args.identityProof ? { identity_proof: args.identityProof } : {})
  };
}

export function extendChainWithAction(args: RecorderExtendArgs): RecorderExtendResult {
  const actionRecordHash = hashCanonical(args.actionRecord);
  const nextChainState = extendChain({
    chainId: args.actionRecord.chain_id,
    sequence: args.actionRecord.sequence,
    previousChainState: args.actionRecord.previous_chain_state,
    actionRecordHash
  });
  const signature = signEd25519(
    args.agentPrivateKeyPem,
    agentAttestationMessage({
      chainId: args.actionRecord.chain_id,
      sequence: args.actionRecord.sequence,
      actionRecordHash,
      chainState: nextChainState
    })
  );
  const agentAttestation: AgentAttestation = {
    schema_version: "sequesign.agent_attestation.v0.1",
    chain_id: args.actionRecord.chain_id,
    sequence: args.actionRecord.sequence,
    action_record_hash: actionRecordHash,
    chain_state: nextChainState,
    agent_id: args.agentId,
    agent_public_key: args.agentPublicKeyPem,
    signature_alg: "Ed25519",
    signature
  };
  return { actionRecordHash, nextChainState, agentAttestation };
}
