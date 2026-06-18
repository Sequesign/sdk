// SDK-side adapter for envelope assembly. The actual envelope shape
// is composed by assembleAgentActionReceipt in @sequesign/lib; this
// module's only job is to translate the SDK's SessionState into the
// shared function's argument set. Both direct mode (SessionImpl) and
// managed mode (ManagedSession) call buildReceiptEnvelope at finalize
// time, and both want the same canonical envelope.
//
// See Issue #85 for the consolidation rationale.

import {
  assembleAgentActionReceipt,
  type AssembledAction
} from "../lib/envelope.js";
import { agentIdentityAttestationFor } from "../lib/agent-identity.js";
import type { AgentActionReceipt } from "../lib/types.js";
import type { SessionState } from "./state.js";

export interface BuildEnvelopeArgs {
  state: SessionState;
  finalChainState: string;
}

export function buildReceiptEnvelope(args: BuildEnvelopeArgs): AgentActionReceipt {
  const { state } = args;
  const actionRecordHashes = state.actionRecordHashes();
  const agentAttestations = state.agentAttestations();
  const witnessAttestations = state.witnessAttestations();
  const evidenceReferences = state.evidenceReferences();
  const actions: AssembledAction[] = actionRecordHashes.map((hash, i) => ({
    actionRecordHash: hash,
    agentAttestation: agentAttestations[i],
    witnessAttestation: witnessAttestations[i],
    evidenceReference: evidenceReferences[i]
  }));
  // Direct mode: when the witness vouched the session's agent key as the one
  // registered to the API key, stamp a registered agent_identity_attestation
  // (managed mode does the equivalent broker-side). Undefined → self_asserted.
  const witnessedIdentity = state.agentIdentity();
  const agentIdentityAttestation = witnessedIdentity
    ? agentIdentityAttestationFor({
        agentPublicKey: witnessedIdentity.agent_public_key,
        agentKeyRegisteredAt: witnessedIdentity.agent_key_registered_at,
        agentIdentityProofRef: witnessedIdentity.agent_identity_proof_ref
      })
    : undefined;
  return assembleAgentActionReceipt({
    receiptId: state.receiptId,
    receiptMode: state.mode,
    agent: {
      agentId: state.agentId,
      agentPublicKeyPem: state.agentPublicKeyPem
    },
    task: {
      taskId: state.taskId,
      delegatorId: state.delegatorId,
      delegatedAt: state.delegatedAt,
      policyContextHash: state.policyContextHash
    },
    chain: {
      chainId: state.chainId,
      initialChainState: state.initialChainState,
      finalChainState: args.finalChainState,
      sequenceStart: state.sequenceStart
    },
    actions,
    approvalAttestations: state.approvals(),
    counterpartyAttestations: state.counterpartyAttestations(),
    profile: state.profile,
    schemaReferences: state.schemaReferences(),
    agentIdentityAttestation
  });
}
