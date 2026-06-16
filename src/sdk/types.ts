import type {
  ActionRecord,
  AgentAttestation,
  AgentActionReceipt,
  AgentIdentityAttestation,
  ApprovalSatellite,
  BatchInclusionProof,
  CounterpartyAttestation,
  CounterpartySatellite,
  EvidenceBlob,
  EvidenceReference,
  ApprovalAttestation,
  IdentityProof,
  ProfileReference,
  ReceiptMode,
  SchemaReference,
  VerifiabilityClass,
  VerificationReport,
  WitnessAttestation
} from "../lib/types.js";

export type {
  ActionRecord,
  AgentAttestation,
  AgentActionReceipt,
  AgentIdentityAttestation,
  ApprovalSatellite,
  BatchInclusionProof,
  CounterpartyAttestation,
  CounterpartySatellite,
  EvidenceBlob,
  EvidenceReference,
  ApprovalAttestation,
  IdentityProof,
  ProfileReference,
  ReceiptMode,
  SchemaReference,
  VerifiabilityClass,
  VerificationReport,
  WitnessAttestation
};

export interface KeyMaterial {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface WitnessStaticKey {
  keyId: string;
  publicKeyPem: string;
  witnessId?: string;
}

export interface WitnessConfig {
  baseUrl?: string;
  witnessId?: string;
  apiKey?: string;
  requestTimeoutMs?: number;
  maxAttempts?: number;
  retryBaseDelayMs?: number;
  retryBackoffCapMs?: number;
  staticKey?: WitnessStaticKey;
  fetch?: typeof fetch;
}

export type SdkMode = "direct" | "managed";

// Three named tiers map to three of the nine cells in the
// (evidenceCustody x envelopeCustody) matrix. The remaining six cells
// are reachable via the raw custody parameters for advanced use.
//   hosted     -> { evidenceCustody: "both",     envelopeCustody: "both" }
//   hash-only  -> { evidenceCustody: "customer", envelopeCustody: "both" }
//   ephemeral  -> { evidenceCustody: "customer", envelopeCustody: "customer" }
export type SdkTier = "hosted" | "hash-only" | "ephemeral";

export type EvidenceCustody = "sequesign" | "customer" | "both";
export type EnvelopeCustody = "sequesign" | "customer" | "both";

// Stubbed for future work. Phase 3 rejects "client-side" unconditionally;
// the implementation is tracked in GitHub issue #76.
export type EvidenceEncryption = "none" | "client-side";

export interface IntermediaryConfig {
  baseUrl: string;
  apiKey?: string;
  requestTimeoutMs?: number;
  fetch?: typeof fetch;
}

// Canonical name for the managed-mode endpoint config. The hosted
// managed-mode entry point is the broker (broker.sequesign.com);
// "intermediary" is the legacy service name, retired by the
// strangler-fig cutover. Same shape; new code should use BrokerConfig
// and the `broker` key below.
export type BrokerConfig = IntermediaryConfig;

export interface SdkDefaults {
  mode?: SdkMode;
  witness?: WitnessConfig;
  // Canonical managed-mode key: the Sequesign broker. Exactly one of
  // `broker` or `intermediary` may be set; setting both is a config
  // error.
  broker?: BrokerConfig;
  // Deprecated alias for `broker`, kept so existing callers do not
  // break. Prefer `broker` in new code.
  intermediary?: IntermediaryConfig;
  tier?: SdkTier;
  evidenceCustody?: EvidenceCustody;
  envelopeCustody?: EnvelopeCustody;
  evidenceEncryption?: EvidenceEncryption;
}

// Canonical new name for the SDK construction options. `SdkDefaults`
// is preserved as the historical export so existing direct-mode
// callers don't see a rename.
export type SdkConfig = SdkDefaults;

export interface PackageConfig {
  directory: string;
  ifExists?: "fail" | "reset" | "resume";
}

export interface SessionInit {
  agent: {
    agentId: string;
    keypair: KeyMaterial;
  };
  task: {
    taskId: string;
    delegatorId: string;
    delegatedAt?: string;
    policyContextHash?: string;
  };
  mode?: ReceiptMode;
  profile?: ProfileReference;
  schemaReferences?: SchemaReference[];
  chainId?: string;
  receiptId?: string;
  witness?: WitnessConfig;
  // Required in direct mode. Optional in managed mode: when omitted,
  // the session does not write a package to disk and the receipt is
  // returned in-memory from finalize().
  package?: PackageConfig;
  // §3.1 Retention PR 1: optional per-receipt retention override. A
  // session is exactly one receipt (one chain_id, one receipt_id), so
  // the override is session-level rather than per-action. Managed
  // mode forwards this to the broker on /v1/receipt (single-action
  // path) and /v1/receipts/finalize (multi-action path); the broker
  // validates extend-only against the customer's default. Direct
  // mode accepts the field for API symmetry but does not write a
  // library.receipts row, so the value is unused there.
  retention?: RetentionInput;
}

// §3.1 Retention PR 1: wire shape for the per-receipt retention
// override exposed on SessionInit. Either an ISO8601 timestamp
// ("infinity" also accepted under `until`) or an ISO8601 duration.
// The two forms are parsed at the broker, not in the SDK, so a future
// duration format change does not require an SDK release.
export type RetentionInput =
  | { until: string }
  | { duration: string };

export interface UnsupportedClaim {
  claim: string;
  external_attestation: string | null;
}

export interface RecordActionInput {
  actionType: string;
  evidence: unknown;
  verifiabilityClass?: VerifiabilityClass;
  schemaId?: string;
  schemaHash?: string;
  policyContextHash?: string;
  metadata?: Record<string, unknown>;
  unsupportedClaims?: UnsupportedClaim[];
  timestamp?: string;
  actionId?: string;
}

export interface RecordedAction {
  actionId: string;
  actionType: string;
  sequence: number;
  actionRecordHash: string;
  previousChainState: string;
  chainState: string;
  evidenceHash: string;
  evidencePath: string;
  agentAttestation: AgentAttestation;
  witnessAttestation: WitnessAttestation;
  recordedAt: string;
}

export interface SessionStateSnapshot {
  readonly sequenceNext: number;
  readonly currentChainState: string;
  readonly actionsRecorded: number;
  readonly approvalsRecorded: number;
  readonly counterpartyAttestationsRecorded: number;
  readonly finalized: boolean;
}

export interface FinalizeOptions {
  embedVerificationReport?: boolean;
  // When set, finalize() polls the witness for inclusion proofs and
  // embeds them in the envelope before sealing, waiting up to this
  // many milliseconds per attestation. When unset (the default),
  // finalize() returns immediately without proofs; verification of
  // inclusion proofs happens later via a proofs.jsonl sidecar in the
  // package directory or via an online fetch from the witness's
  // /log/inclusion/{position} endpoint. See PLAN.md section 4.23
  // for the proof-archive architecture.
  inclusionProofTimeoutMs?: number;
}

export interface FetchInclusionProofsOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export interface FetchInclusionProofsResult {
  attestationsConsidered: number;
  proofsFetched: number;
  proofsFailed: number;
  failures: Array<{ sequence: number; position: number; reason: string }>;
}

export interface FinalizeResult {
  receiptId: string;
  packageDirectory: string;
  envelopePath: string;
  actionsPath: string;
  initialChainState: string;
  finalChainState: string;
  sequenceStart: number;
  sequenceEnd: number;
  receipt: AgentActionReceipt;
  verification: VerificationReport;
  // Populated when the receipt envelope was stored at Sequesign
  // (managed mode with envelopeCustody "sequesign" or "both"). Absent
  // in direct mode and in managed-mode tiers where the customer holds
  // the envelope.
  receiptUrl?: string;
  r2Key?: string;
}

export interface Session {
  readonly chainId: string;
  readonly receiptId: string;
  readonly mode: ReceiptMode;
  readonly state: SessionStateSnapshot;
  recordAction(input: RecordActionInput): Promise<RecordedAction>;
  recordApproval(input: RecordApprovalInput): Promise<ApprovalAttestation>;
  recordPlan(input: RecordPlanInput): Promise<RecordedAction>;
  recordPlanStep(input: RecordPlanStepInput): Promise<RecordedAction>;
  recordCounterpartyAttestation(
    input: RecordCounterpartyAttestationInput
  ): Promise<CounterpartyAttestation>;
  inspect(): Promise<InspectionReport>;
  wrapTool<TArgs extends readonly unknown[], TResult>(
    spec: ToolWrapSpec<TArgs, TResult>
  ): WrappedTool<TArgs, TResult>;
  checkpoint(): SessionCheckpoint;
  fetchInclusionProofs(
    options?: FetchInclusionProofsOptions
  ): Promise<FetchInclusionProofsResult>;
  finalize(options?: FinalizeOptions): Promise<FinalizeResult>;
}

export type RecordApprovalInput =
  | {
      mode: "sign_locally";
      approvalId?: string;
      approverId: string;
      // v0.6 arc: whether the approving party is a human or an
      // (independent) agent reviewer. Defaults to "human". Recorded as a
      // bound attribute and part of the signed message.
      partyType?: "human" | "agent";
      approverKeypair: KeyMaterial;
      approvedTaskId?: string;
      approvedActionType: string;
      approvalContext: unknown;
      approvedAt?: string;
      // v0.6 step #4.4 (vouching): optional identity proof to attach to the
      // approval. For issuer "sequesign" the ref is the base64url
      // SignedRegistrationRecord returned by dashboard-api POST /registrations
      // (#4.3). It is NOT part of the signed approval message — purely
      // additive — so the verifier can flip the approval leg to
      // present_verified when it resolves against a trusted platform key.
      // attach_signed callers set identity_proof on the attestation directly.
      identityProof?: IdentityProof;
    }
  | {
      mode: "attach_signed";
      attestation: ApprovalAttestation;
    };

export interface RecordPlanInput {
  plan: unknown;
  actionType?: string;
  schemaId?: string;
  schemaHash?: string;
  verifiabilityClass?: VerifiabilityClass;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  actionId?: string;
}

export interface RecordPlanStepInput {
  planActionId: string;
  step: unknown;
  actionType?: string;
  schemaId?: string;
  schemaHash?: string;
  verifiabilityClass?: VerifiabilityClass;
  metadata?: Record<string, unknown>;
  timestamp?: string;
  actionId?: string;
}

export interface RecordCounterpartyAttestationInput {
  attestation: CounterpartyAttestation;
}

// v0.6 step #3b.3: submit a deferred-attestation satellite against an
// already-sealed receipt R (the `receipt` + `packageDirectory` come from a
// prior finalize() FinalizeResult). The approval inputs mirror
// RecordApprovalInput exactly (sign_locally | attach_signed), so a deferred
// approval is expressed identically to an in-envelope one — it just binds to
// the sealed receipt and lands in the top-level attestations.jsonl sidecar.
export type SubmitApprovalSatelliteInput = {
  packageDirectory: string;
  receipt: AgentActionReceipt;
} & RecordApprovalInput;

export interface SubmitCounterpartySatelliteInput {
  packageDirectory: string;
  receipt: AgentActionReceipt;
  attestation: CounterpartyAttestation;
}

export const PLAN_GENERATED_ACTION_TYPE = "plan_generated";
export const PLAN_STEP_EXECUTED_ACTION_TYPE = "plan_step_executed";
export const PLAN_DEVIATION_ACTION_TYPE = "plan_deviation";

export interface WitnessConfigSummary {
  baseUrl: string;
  witnessId?: string;
}

export interface SessionCheckpoint {
  schemaVersion: "sequesign.sdk.session_checkpoint.v0.1";
  receiptId: string;
  chainId: string;
  mode: ReceiptMode;
  profile?: ProfileReference;
  schemaReferences?: SchemaReference[];
  agent: {
    agentId: string;
    agentPublicKey: string;
  };
  task: {
    taskId: string;
    delegatorId: string;
    delegatedAt: string;
    policyContextHash?: string;
  };
  chain: {
    initialChainState: string;
    currentChainState: string;
    sequenceStart: number;
    sequenceNext: number;
  };
  packageDirectory: string;
  witness: WitnessConfigSummary;
}

export interface ResumeOptions {
  witness?: WitnessConfig;
}

export interface InspectionReport {
  receiptId: string;
  chainId: string;
  receiptMode: ReceiptMode;
  sequenceNext: number;
  currentChainState: string;
  initialChainState: string;
  finalized: boolean;
  actions: InspectedAction[];
  outstandingRequirements: OutstandingRequirement[];
  warnings: InspectionWarning[];
  partialVerification: PartialVerificationReport;
}

export interface InspectedAction {
  sequence: number;
  actionType: string;
  actionId: string;
  actionRecordHash: string;
  previousChainState: string;
  chainState: string;
  verifiabilityClass: VerifiabilityClass;
  evidencePath: string;
  witnessVerified: boolean;
  agentSignatureVerified: boolean;
  recordedAt: string;
}

export interface OutstandingRequirement {
  code: string;
  message: string;
  satisfiedBy?: { actionType: string; count?: number };
}

export interface InspectionWarning {
  code: string;
  severity: "info" | "warning" | "critical";
  message: string;
  action?: { sequence: number; actionType: string };
}

export interface PartialVerificationReport {
  available: boolean;
  reason?: string;
  report?: VerificationReport;
}

export type ToolWrapErrorMode = "throw" | "record_error_action";

export interface ToolWrapSpec<TArgs extends readonly unknown[], TResult> {
  actionType: string;
  handler: (...args: TArgs) => TResult | Promise<TResult>;
  schemaId?: string;
  schemaHash?: string;
  verifiabilityClass?: VerifiabilityClass;
  buildEvidence: (args: TArgs, result: TResult) => unknown;
  buildMetadata?: (args: TArgs, result: TResult) => Record<string, unknown>;
  buildErrorEvidence?: (args: TArgs, error: unknown) => unknown;
  onError?: ToolWrapErrorMode;
}

export type WrappedTool<TArgs extends readonly unknown[], TResult> = (
  ...args: TArgs
) => Promise<TResult>;

// One-shot input for sdk.witness(). Combines startSession +
// recordAction + finalize into a single call. Works in both direct
// and managed modes; in managed mode it makes one POST to /v1/receipt
// on the intermediary.
export interface WitnessInput {
  agent: { agentId: string; keypair: KeyMaterial };
  task: { taskId: string; delegatorId: string; policyContextHash?: string };
  actionType: string;
  evidence: unknown;
  verifiabilityClass?: VerifiabilityClass;
  schemaId?: string;
  schemaHash?: string;
  mode?: ReceiptMode;
  chainId?: string;
  receiptId?: string;
  // Defaults to a fresh temp directory in managed mode; defaults to a
  // fresh temp directory in direct mode too (since the convenience API
  // doesn't surface a package path). Callers who want a stable on-disk
  // package use startSession() instead.
  package?: PackageConfig;
}

export interface WitnessResult {
  receipt: AgentActionReceipt;
  receiptId: string;
  chainId: string;
  // Present when envelopeCustody is "sequesign" or "both" (i.e., when
  // the envelope was stored at Sequesign). Absent in direct mode and
  // for ephemeral-tier managed mode.
  receiptUrl?: string;
  r2Key?: string;
}

export interface Sdk {
  startSession(init: SessionInit): Promise<Session>;
  resumeSession(
    checkpoint: SessionCheckpoint,
    keypair: KeyMaterial,
    options?: ResumeOptions
  ): Promise<Session>;
  resumeFromPackage(
    packageDirectory: string,
    keypair: KeyMaterial,
    options?: ResumeOptions
  ): Promise<Session>;
  witness(input: WitnessInput): Promise<WitnessResult>;
  // v0.6 step #3b.3: seal a deferred approval / counterparty satellite
  // against an already-sealed receipt and append it to the package's
  // attestations.jsonl sidecar. Uses the Sdk's configured transport (direct
  // witness or managed broker).
  submitApprovalSatellite(input: SubmitApprovalSatelliteInput): Promise<ApprovalSatellite>;
  submitCounterpartySatellite(
    input: SubmitCounterpartySatelliteInput
  ): Promise<CounterpartySatellite>;
}
