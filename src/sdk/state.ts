import type {
  ActionRecord,
  AgentAttestation,
  BatchInclusionProof,
  CounterpartyAttestation,
  EvidenceReference,
  ApprovalAttestation,
  ProfileReference,
  ReceiptMode,
  SchemaReference,
  WitnessAttestation
} from "../lib/types.js";
import type { RetentionInput, SessionStateSnapshot } from "./types.js";

export interface SessionStateInit {
  chainId: string;
  receiptId: string;
  agentId: string;
  agentPublicKeyPem: string;
  taskId: string;
  delegatorId: string;
  delegatedAt: string;
  policyContextHash?: string;
  mode: ReceiptMode;
  initialChainState: string;
  sequenceStart: number;
  schemaReferences?: SchemaReference[];
  profile?: ProfileReference;
  // §3.1 Retention PR 1: session-level extend-only retention override.
  // ManagedSession reads this on every postReceipt / postFinalize so
  // the broker stamps a single retention_until on the single
  // library.receipts row this session produces.
  retention?: RetentionInput;
}

export class SessionState {
  readonly chainId: string;
  readonly receiptId: string;
  readonly agentId: string;
  readonly agentPublicKeyPem: string;
  readonly taskId: string;
  readonly delegatorId: string;
  readonly delegatedAt: string;
  readonly policyContextHash?: string;
  readonly mode: ReceiptMode;
  readonly initialChainState: string;
  readonly sequenceStart: number;
  readonly profile?: ProfileReference;
  readonly retention?: RetentionInput;

  private _sequenceNext: number;
  private _currentChainState: string;
  private _actions: ActionRecord[] = [];
  private _actionRecordHashes: string[] = [];
  private _agentAttestations: AgentAttestation[] = [];
  private _witnessAttestations: WitnessAttestation[] = [];
  private _approvals: ApprovalAttestation[] = [];
  private _counterpartyAttestations: CounterpartyAttestation[] = [];
  private _evidenceReferences: EvidenceReference[] = [];
  private _schemaReferences: SchemaReference[] = [];
  private _schemaReferenceIds = new Set<string>();
  private _finalized = false;

  constructor(init: SessionStateInit) {
    this.chainId = init.chainId;
    this.receiptId = init.receiptId;
    this.agentId = init.agentId;
    this.agentPublicKeyPem = init.agentPublicKeyPem;
    this.taskId = init.taskId;
    this.delegatorId = init.delegatorId;
    this.delegatedAt = init.delegatedAt;
    this.policyContextHash = init.policyContextHash;
    this.mode = init.mode;
    this.initialChainState = init.initialChainState;
    this.sequenceStart = init.sequenceStart;
    this._sequenceNext = init.sequenceStart;
    this._currentChainState = init.initialChainState;
    this.profile = init.profile;
    this.retention = init.retention;
    for (const ref of init.schemaReferences ?? []) {
      this.addSchemaReference(ref);
    }
  }

  addApproval(att: ApprovalAttestation): void {
    if (this._finalized) {
      throw new Error("Cannot record a human approval on a finalized session.");
    }
    this._approvals.push(att);
  }

  addCounterpartyAttestation(att: CounterpartyAttestation): void {
    if (this._finalized) {
      throw new Error("Cannot record a counterparty attestation on a finalized session.");
    }
    this._counterpartyAttestations.push(att);
  }

  counterpartyAttestations(): CounterpartyAttestation[] {
    return this._counterpartyAttestations.slice();
  }

  addSchemaReference(ref: SchemaReference): void {
    if (this._schemaReferenceIds.has(ref.schema_id)) return;
    this._schemaReferenceIds.add(ref.schema_id);
    this._schemaReferences.push(ref);
  }

  schemaReferences(): SchemaReference[] {
    return this._schemaReferences.slice();
  }

  get sequenceNext(): number {
    return this._sequenceNext;
  }

  get currentChainState(): string {
    return this._currentChainState;
  }

  get finalized(): boolean {
    return this._finalized;
  }

  snapshot(): SessionStateSnapshot {
    return {
      sequenceNext: this._sequenceNext,
      currentChainState: this._currentChainState,
      actionsRecorded: this._actions.length,
      approvalsRecorded: this._approvals.length,
      counterpartyAttestationsRecorded: this._counterpartyAttestations.length,
      finalized: this._finalized
    };
  }

  appendAction(args: {
    action: ActionRecord;
    actionRecordHash: string;
    nextChainState: string;
    agentAttestation: AgentAttestation;
    witnessAttestation: WitnessAttestation;
    evidenceReference: EvidenceReference;
  }): void {
    if (this._finalized) {
      throw new Error("Cannot append an action to a finalized session.");
    }
    this._actions.push(args.action);
    this._actionRecordHashes.push(args.actionRecordHash);
    this._agentAttestations.push(args.agentAttestation);
    this._witnessAttestations.push(args.witnessAttestation);
    this._evidenceReferences.push(args.evidenceReference);
    this._sequenceNext += 1;
    this._currentChainState = args.nextChainState;
  }

  markFinalized(): void {
    this._finalized = true;
  }

  actions(): ActionRecord[] {
    return this._actions.slice();
  }

  actionRecordHashes(): string[] {
    return this._actionRecordHashes.slice();
  }

  agentAttestations(): AgentAttestation[] {
    return this._agentAttestations.slice();
  }

  witnessAttestations(): WitnessAttestation[] {
    return this._witnessAttestations.slice();
  }

  // Attach a fetched inclusion proof to the witness attestation at the
  // given sequence. Used by Session.fetchInclusionProofs() to embed
  // the proofs into the receipt envelope at finalize time.
  attachInclusionProof(sequence: number, proof: BatchInclusionProof): boolean {
    const att = this._witnessAttestations.find((a) => a.sequence === sequence);
    if (!att) return false;
    att.batch_inclusion_proof = proof;
    return true;
  }

  approvals(): ApprovalAttestation[] {
    return this._approvals.slice();
  }

  evidenceReferences(): EvidenceReference[] {
    return this._evidenceReferences.slice();
  }
}
