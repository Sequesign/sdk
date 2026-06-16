// Canonical AgentActionReceipt envelope assembly.
//
// This is the single source of truth for how the protocol's envelope
// is composed. Both the SDK (managed and direct mode) and the
// intermediary call this function. The output is what gets written
// to disk, stored in R2, and hashed by the verifier.
//
// Before consolidation, two functions existed (one in src/sdk/
// envelope.ts and one in apps/intermediary/src/receipt-assembly.ts)
// and they drifted on the evidence_path and evidence_source fields
// in customer-custody tiers. Issue #85 tracked the consolidation.
// After consolidation, drift is impossible by construction: there is
// one function.
//
// The function does NOT canonicalize JSON. Callers that need
// canonical JSON for hashing pass the returned envelope through
// hashCanonical or canonicalize; callers that need a wire form pass
// it through JSON.stringify. The function preserves insertion order
// so JSON.stringify output is deterministic across callers.

import type {
  AgentActionReceipt,
  AgentAttestation,
  AgentIdentityAttestation,
  CounterpartyAttestation,
  EvidenceReference,
  ApprovalAttestation,
  ProfileReference,
  ReceiptMode,
  ReceiptSchemaVersion,
  SchemaReference,
  WitnessAttestation
} from "./types.js";

export interface AssembledAction {
  actionRecordHash: string;
  agentAttestation: AgentAttestation;
  witnessAttestation: WitnessAttestation;
  evidenceReference: EvidenceReference;
}

export interface AssembleReceiptArgs {
  receiptId: string;
  receiptMode: ReceiptMode;
  agent: { agentId: string; agentPublicKeyPem: string };
  task: {
    taskId: string;
    delegatorId: string;
    delegatedAt: string;
    policyContextHash?: string;
  };
  chain: {
    chainId: string;
    initialChainState: string;
    finalChainState: string;
    sequenceStart: number;
  };
  actions: AssembledAction[];
  approvalAttestations?: ApprovalAttestation[];
  counterpartyAttestations?: CounterpartyAttestation[];
  profile?: ProfileReference;
  schemaReferences?: SchemaReference[];
  // PR 15-A: present only when the receipt is produced under a
  // registered API key. When omitted, the assembled envelope carries no
  // agent_identity_attestation field at all (byte-identical to a
  // pre-v0.5-feature unregistered receipt).
  agentIdentityAttestation?: AgentIdentityAttestation;
}

const RECEIPT_SCHEMA_VERSION: ReceiptSchemaVersion = "sequesign.receipt.v2.0.0";

export function assembleAgentActionReceipt(
  args: AssembleReceiptArgs
): AgentActionReceipt {
  // v0.5 emits a single receipt schema version. The pre-v0.4 split
  // between v0.2 and v0.3 (based on whether witness attestations
  // carried log fields) is gone; log fields remain optional on the
  // attestation itself, but the receipt schema version no longer
  // toggles to advertise their presence.

  // Profile and schema_references are dropped from the envelope when
  // the caller does not provide them; the AgentActionReceipt type
  // makes both fields optional. We use undefined (which JSON.stringify
  // omits) rather than emitting empty arrays so the wire form stays
  // identical to the pre-consolidation output.
  const profileRef = args.profile
    ? {
        profile_id: args.profile.profile_id,
        profile_hash: args.profile.profile_hash
      }
    : undefined;
  const counterpartyAttestations = args.counterpartyAttestations ?? [];
  const schemaReferences = args.schemaReferences ?? [];

  return {
    schema_version: RECEIPT_SCHEMA_VERSION,
    receipt_id: args.receiptId,
    receipt_mode: args.receiptMode,
    agent_id: args.agent.agentId,
    agent_public_key: args.agent.agentPublicKeyPem,
    // Omitted from the wire form when undefined (JSON.stringify drops
    // undefined-valued keys), so unregistered receipts stay byte-
    // identical to the pre-feature output.
    agent_identity_attestation: args.agentIdentityAttestation,
    task: {
      task_id: args.task.taskId,
      delegator_id: args.task.delegatorId,
      delegated_at: args.task.delegatedAt,
      policy_context_hash: args.task.policyContextHash
    },
    chain: {
      chain_id: args.chain.chainId,
      initial_chain_state: args.chain.initialChainState,
      final_chain_state: args.chain.finalChainState,
      sequence_start: args.chain.sequenceStart
    },
    action_record_hashes: args.actions.map((a) => a.actionRecordHash),
    agent_attestations: args.actions.map((a) => a.agentAttestation),
    witness_attestations: args.actions.map((a) => a.witnessAttestation),
    approval_attestations: args.approvalAttestations ?? [],
    counterparty_attestations:
      counterpartyAttestations.length > 0 ? counterpartyAttestations : undefined,
    evidence_references: args.actions.map((a) => a.evidenceReference),
    profile: profileRef,
    schema_references:
      schemaReferences.length > 0 ? schemaReferences : undefined
  };
}
