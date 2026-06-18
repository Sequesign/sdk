// Managed-mode session. Mirrors SessionImpl in shape but routes the
// witness round-trip through the intermediary.
//
// §3.2 brings managed mode to feature parity with direct mode (PR 8
// action metadata, PR 9 broker-side schema and profile validation,
// PR 10 the recording methods and customer-side schema/profile
// support). The strategic principle: managed mode is direct mode with
// the orchestration outsourced, not a feature-limited tier.
//
// R2 storage policy:
//   * hosted    -> envelope and evidence go to Sequesign at finalize.
//   * hash-only -> envelope goes to Sequesign at finalize; evidence
//                  stays with the customer.
//   * ephemeral -> nothing goes to Sequesign at finalize; the
//                  customer holds everything. Per-action billing rows
//                  are still written.
//
// Implementation notes:
//   * recordAction posts each action to the broker
//     /v1/receipt with defer_envelope_storage=true; the broker signs,
//     records a billing row, and returns a witness attestation. The
//     SDK assembles the envelope locally and posts it at finalize.
//   * recordApproval and recordCounterpartyAttestation never
//     call the broker. They verify the attestation locally,
//     accumulate it in SessionState, and ride in the envelope at
//     finalize. The broker's finalize handler validates the
//     attestation arrays alongside the action records.
//   * recordPlan, recordPlanStep, and wrapTool are wrappers over
//     managed recordAction, exactly as their direct-mode counterparts
//     are wrappers over direct recordAction.
//   * inspect materializes the in-memory state as a package on disk
//     (a temp directory when packageConfig is not set, the customer's
//     directory when it is) and runs the shared buildInspectionReport.

import path from "node:path";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";

import { hashCanonical, sha256Hex } from "../lib/hash.js";
import { lengthPrefixedUtf8 } from "../lib/encoding.js";
import { verifyEd25519 } from "../lib/keys.js";
import { approvalMessage } from "../lib/messages.js";
import { ensureDir, resetDir } from "../lib/io.js";
import {
  isCanonicalCounterpartyId,
  isValidApproverId
} from "../lib/package-layout.js";
import { verifyReceiptPackage, witnessKeysFromReceipt } from "../lib/verify.js";
import type {
  ActionRecord,
  AgentActionReceipt,
  CounterpartyAttestation,
  EvidenceBlob,
  ApprovalAttestation,
  VerifiabilityClass,
  VerificationReport
} from "../lib/types.js";

import { buildReceiptEnvelope } from "./envelope.js";
import {
  CounterpartyAttestationError,
  FinalizationError,
  ApprovalError,
  NotImplementedError,
  PackageStateError,
  PlanReferenceError,
  SessionStateError
} from "./errors.js";
import {
  generateActionId,
  generateApprovalId,
  generateChainId,
  generateReceiptId,
  nowIso
} from "./identifiers.js";
import { buildInspectionReport } from "./inspect.js";
import type { IntermediaryClient } from "./intermediary-client.js";
import { createIntermediaryClient } from "./intermediary-client.js";
import {
  createPackageWriter,
  evidenceFilename,
  type ApproverPublicKey,
  type CounterpartyPublicKey,
  type PackageWriter
} from "./package-writer.js";
import {
  buildActionRecord,
  buildEvidenceBlob,
  buildApprovalAttestation,
  buildCounterpartyAttestation,
  extendChainWithAction
} from "./recorder.js";
import { applySchemaPolicy } from "./schema-policy.js";
import { SessionState } from "./state.js";
import { createWrappedTool } from "./tool-wrap.js";
import type { ResolvedSdkConfig } from "./config.js";
import type {
  FetchInclusionProofsOptions,
  FetchInclusionProofsResult,
  FinalizeOptions,
  FinalizeResult,
  InspectionReport,
  PackageConfig,
  RecordActionInput,
  RecordCounterpartyAttestationInput,
  RecordApprovalInput,
  RecordPlanInput,
  RecordPlanStepInput,
  RecordedAction,
  Session,
  SessionCheckpoint,
  SessionInit,
  SessionStateSnapshot,
  ToolWrapSpec,
  WrappedTool
} from "./types.js";
import {
  PLAN_GENERATED_ACTION_TYPE,
  PLAN_STEP_EXECUTED_ACTION_TYPE
} from "./types.js";

// §3.2 PR 3: checkpoint and resume parity are not in scope; managed
// sessions cannot persist or resume across processes. fetchInclusion
// Proofs is also out of scope (managed mode does not expose direct
// witness access). Both throw an explicit "not supported in managed
// mode" error so the caller sees a clear diagnostic rather than a
// silent gap.
function managedNotSupported(feature: string): NotImplementedError {
  return new NotImplementedError(
    `${feature} is not supported in managed mode. Use direct mode if you need ${feature}.`
  );
}

export async function startManagedSessionImpl(args: {
  init: SessionInit;
  managed: Extract<ResolvedSdkConfig, { mode: "managed" }>;
}): Promise<Session> {
  const { init, managed } = args;

  // §3.2 PR 3: the freeform-only gate and the no-profile gate are
  // gone. Managed sessions accept schema_validated and
  // profile_constrained modes, carry the profile binding into
  // SessionState, and run the same client-side validation direct
  // mode runs.

  const intermediary = createIntermediaryClient(managed.intermediary);

  const chainId = init.chainId ?? generateChainId();
  const receiptId = init.receiptId ?? generateReceiptId();
  const initialChainState = sha256Hex(
    lengthPrefixedUtf8(["SEQUESIGN_INITIAL_STATE_V0", chainId])
  );
  const mode = init.mode ?? "freeform";

  const state = new SessionState({
    chainId,
    receiptId,
    agentId: init.agent.agentId,
    agentPublicKeyPem: init.agent.keypair.publicKeyPem,
    taskId: init.task.taskId,
    delegatorId: init.task.delegatorId,
    delegatedAt: init.task.delegatedAt ?? nowIso(),
    policyContextHash: init.task.policyContextHash,
    mode,
    initialChainState,
    sequenceStart: 1,
    schemaReferences: init.schemaReferences,
    profile: init.profile,
    retention: init.retention
  });

  return new ManagedSession({
    state,
    managed,
    intermediary,
    agentPrivateKeyPem: init.agent.keypair.privateKeyPem,
    packageConfig: init.package
  });
}

interface ManagedSessionArgs {
  state: SessionState;
  managed: Extract<ResolvedSdkConfig, { mode: "managed" }>;
  intermediary: IntermediaryClient;
  agentPrivateKeyPem: string;
  packageConfig: PackageConfig | undefined;
}

// One cached evidence blob per action, keyed by action_id, so the
// finalize path can stream them into evidence/*.json and (for hosted
// tier) hand them to the intermediary's verifier.
interface CachedEvidence {
  blob: EvidenceBlob;
  filename: string;
}

class ManagedSession implements Session {
  private readonly _state: SessionState;
  private readonly managed: Extract<ResolvedSdkConfig, { mode: "managed" }>;
  private readonly intermediary: IntermediaryClient;
  private readonly agentPrivateKeyPem: string;
  private readonly packageConfig: PackageConfig | undefined;
  private readonly cachedEvidence = new Map<string, CachedEvidence>();
  // Insertion order matches sequence order, which keeps the finalize
  // upload's evidence_blobs array aligned with action_records[i].
  private readonly evidenceOrder: string[] = [];

  constructor(args: ManagedSessionArgs) {
    this._state = args.state;
    this.managed = args.managed;
    this.intermediary = args.intermediary;
    this.agentPrivateKeyPem = args.agentPrivateKeyPem;
    this.packageConfig = args.packageConfig;
  }

  get chainId(): string {
    return this._state.chainId;
  }
  get receiptId(): string {
    return this._state.receiptId;
  }
  get mode() {
    return this._state.mode;
  }
  get state(): SessionStateSnapshot {
    return this._state.snapshot();
  }

  async recordAction(input: RecordActionInput): Promise<RecordedAction> {
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    // §3.2 PR 1 wired metadata through Shape 1. §3.2 PR 3 lifts the
    // schemaId / schemaHash throw: managed mode now runs the same
    // client-side schema policy direct mode runs (so the schema
    // reference lands in SessionState and the SDK throws the same
    // SchemaRequiredError / SchemaHashMismatchError /
    // SchemaValidationError direct mode does). In hosted tier the
    // broker re-runs the per-action schema gate server-side (PR 9);
    // in customer-evidence tiers the broker has no content so this
    // SDK gate is the only check.

    const sequence = this._state.sequenceNext;
    const actionType = input.actionType;
    const actionId = input.actionId ?? generateActionId(sequence, actionType);
    const verifiabilityClass: VerifiabilityClass =
      input.verifiabilityClass ?? "deterministic";

    // Build the evidence blob WITH schema fields so the canonical
    // hash commits them. Without these in the rebuilt blob the
    // broker's server-side reconstruction would diverge and
    // agent_signature_invalid would fire.
    const evidenceBlob = buildEvidenceBlob({
      actionId,
      actionType,
      schemaId: input.schemaId,
      schemaHash: input.schemaHash,
      content: input.evidence
    });
    await applySchemaPolicy(this._state, input, evidenceBlob);

    const evidenceHash = hashCanonical(evidenceBlob);
    const policyContextHash =
      input.policyContextHash ?? this._state.policyContextHash;
    const timestamp = input.timestamp ?? nowIso();
    const previousChainState = this._state.currentChainState;
    const actionRecord = buildActionRecord({
      actionId,
      actionType,
      sequence,
      chainId: this._state.chainId,
      agentId: this._state.agentId,
      agentPublicKeyPem: this._state.agentPublicKeyPem,
      taskId: this._state.taskId,
      delegatorId: this._state.delegatorId,
      verifiabilityClass,
      evidenceHash,
      policyContextHash,
      previousChainState,
      timestamp,
      metadata: input.metadata
    });
    const { actionRecordHash, nextChainState, agentAttestation } =
      extendChainWithAction({
        actionRecord,
        agentPrivateKeyPem: this.agentPrivateKeyPem,
        agentId: this._state.agentId,
        agentPublicKeyPem: this._state.agentPublicKeyPem
      });

    const sendsEvidence =
      this.managed.evidenceCustody === "sequesign" ||
      this.managed.evidenceCustody === "both";

    const response = await this.intermediary.postReceipt({
      agentId: this._state.agentId,
      agentPublicKeyPem: this._state.agentPublicKeyPem,
      taskId: this._state.taskId,
      delegatorId: this._state.delegatorId,
      actionType,
      verifiabilityClass,
      evidence: sendsEvidence ? input.evidence : undefined,
      evidenceHash: sendsEvidence ? undefined : evidenceHash,
      agentSignatureBase64: agentAttestation.signature,
      policyContextHash,
      chainId: this._state.chainId,
      receiptId: this._state.receiptId,
      delegatedAt: this._state.delegatedAt,
      timestamp,
      evidenceCustody: this.managed.evidenceCustody,
      envelopeCustody: this.managed.envelopeCustody,
      sequence,
      previousChainState,
      deferEnvelopeStorage: true,
      metadata: input.metadata,
      schemaId: input.schemaId,
      schemaHash: input.schemaHash,
      retention: this._state.retention
    });

    // Defensive parity check: the intermediary should sign the same
    // chain state the SDK derived. A mismatch is a server-side
    // protocol bug; refuse to record rather than embed a divergent
    // attestation.
    const att = response.witnessAttestation;
    if (
      att.action_record_hash !== actionRecordHash ||
      att.chain_state !== nextChainState ||
      att.previous_chain_state !== previousChainState ||
      att.chain_id !== this._state.chainId ||
      att.sequence !== sequence
    ) {
      throw new FinalizationError(
        "Intermediary returned a witness_attestation that does not match the SDK-derived action record. Refusing to record."
      );
    }

    const evidenceFile = evidenceFilename(sequence, actionType);
    // The envelope's evidence_path and evidence_custody diverge from
    // the local filesystem path when the customer holds evidence.
    // v0.4 collapsed the per-action override into session-level
    // custody, so the SDK pins these to mirror the broker's
    // serializer.
    const customerHoldsEvidence = this.managed.evidenceCustody === "customer";
    const envelopeEvidencePath = customerHoldsEvidence
      ? "external"
      : `evidence/${evidenceFile}`;
    const envelopeEvidenceCustody = customerHoldsEvidence
      ? ("external_client_managed" as const)
      : ("sequesign_hosted" as const);

    this._state.appendAction({
      action: actionRecord,
      actionRecordHash,
      nextChainState,
      agentAttestation,
      witnessAttestation: att,
      evidenceReference: {
        action_id: actionId,
        evidence_hash: evidenceHash,
        evidence_path: envelopeEvidencePath,
        mime_type: "application/json",
        evidence_custody: envelopeEvidenceCustody
      }
    });

    this.cachedEvidence.set(actionId, {
      blob: evidenceBlob,
      filename: evidenceFile
    });
    this.evidenceOrder.push(actionId);

    return {
      actionId,
      actionType,
      sequence,
      actionRecordHash,
      previousChainState: actionRecord.previous_chain_state,
      chainState: nextChainState,
      evidenceHash,
      evidencePath: envelopeEvidencePath,
      agentAttestation,
      witnessAttestation: att,
      recordedAt: actionRecord.timestamp
    };
  }

  async recordApproval(
    input: RecordApprovalInput
  ): Promise<ApprovalAttestation> {
    // §3.2 PR 3: mirrors src/sdk/session.ts recordApproval. No
    // witness call (direct mode does not call the witness either);
    // the attestation accumulates in SessionState and the broker
    // finalize handler validates the array alongside the action
    // records. Managed does NOT persist a per-call checkpoint or
    // write key files eagerly; both are deferred to finalize, where
    // the temp / persistent package directory is materialized.
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    let attestation: ApprovalAttestation;
    if (input.mode === "sign_locally") {
      attestation = buildApprovalAttestation({
        approvalId: input.approvalId ?? generateApprovalId(),
        approverId: input.approverId,
        partyType: input.partyType ?? "human",
        approverKeypair: input.approverKeypair,
        approvedTaskId: input.approvedTaskId ?? this._state.taskId,
        approvedActionType: input.approvedActionType,
        approvalContext: input.approvalContext,
        approvedAt: input.approvedAt ?? nowIso(),
        identityProof: input.identityProof
      });
    } else if (input.mode === "attach_signed") {
      attestation = input.attestation;
      const message = approvalMessage({
        approvalId: attestation.approval_id,
        approverId: attestation.approver_id,
        partyType: attestation.party_type,
        approvedTaskId: attestation.approved_task_id,
        approvedActionType: attestation.approved_action_type,
        approvalContextHash: attestation.approval_context_hash,
        approvedAt: attestation.approved_at
      });
      if (
        !verifyEd25519(attestation.approver_public_key, message, attestation.signature)
      ) {
        throw new ApprovalError(
          "approver_signature_invalid",
          `Attached approval's signature does not verify against the supplied approver_public_key (approver_id=${attestation.approver_id}).`
        );
      }
    } else {
      throw new ApprovalError(
        "approval_mode_invalid",
        `recordApproval requires mode "sign_locally" or "attach_signed".`
      );
    }
    // Task binding (PR 15-A.1, finding #10). Mirrors src/sdk/session.ts:
    // every approval, regardless of mode, must approve THIS session's
    // task. sign_locally could be handed an approvedTaskId for a
    // different task, which the broker / verifier would later reject
    // with approval_binding_mismatch.
    if (attestation.approved_task_id !== this._state.taskId) {
      throw new ApprovalError(
        "approved_task_id_mismatch",
        `Approval references task ${attestation.approved_task_id}; session task is ${this._state.taskId}.`
      );
    }
    // Approval binding (PR 15-A.1, finding #10). Mirrors
    // src/sdk/session.ts: the approval must approve an action_type that
    // actually occurred in this chain, so the broker finalize handler
    // and the verifier do not later reject it with
    // approval_binding_mismatch.
    if (!this._state.actions().some((a) => a.action_type === attestation.approved_action_type)) {
      throw new ApprovalError(
        "approved_action_type_mismatch",
        `Approval approves action_type "${attestation.approved_action_type}", which matches no action recorded in this chain. Record the action before recording its approval.`
      );
    }
    if (!isValidApproverId(attestation.approver_id)) {
      throw new ApprovalError(
        "approver_id_invalid",
        `approver_id "${attestation.approver_id}" is not a valid lowercase email or label (letters, digits, ".", "_", "+", "-", optional "@domain").`
      );
    }
    // One approver_id binds to one key for the life of a chain. The
    // package stores a single keys/approvers/<id>.pub.pem per
    // approver, so a second approval for the same id with a
    // different key is unstorable. The broker's finalize handler
    // enforces the same invariant; surface it here so callers see
    // the error class rather than a generic broker 400.
    const priorApproval = this._state
      .approvals()
      .find((a) => a.approver_id === attestation.approver_id);
    if (
      priorApproval &&
      priorApproval.approver_public_key !== attestation.approver_public_key
    ) {
      throw new ApprovalError(
        "approver_key_mismatch",
        `approver_id "${attestation.approver_id}" already approved with a different approver_public_key in this chain.`
      );
    }
    // v0.6 step #2: one approval_id is recorded once (mirrors
    // src/sdk/session.ts). Prevents a replayed approval_id from being
    // stored twice and inflating a naive count; the verifier deduplicates
    // by approval_id when it enumerates approvals.
    if (this._state.approvals().some((a) => a.approval_id === attestation.approval_id)) {
      throw new ApprovalError(
        "approval_id_duplicate",
        `approval_id "${attestation.approval_id}" was already recorded in this chain.`
      );
    }
    this._state.addApproval(attestation);
    return attestation;
  }

  async recordCounterpartyAttestation(
    input: RecordCounterpartyAttestationInput
  ): Promise<CounterpartyAttestation> {
    // §3.2 PR 3: mirrors src/sdk/session.ts recordCounterpartyAttestation.
    // No witness call. sign_locally builds + signs from the counterparty
    // keypair and derives attested_content_hash from the attested action;
    // attach_signed (mode omitted for back-compat) takes a formed attestation
    // whose signature the broker / verifier validates at finalize.
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    let attestation: CounterpartyAttestation;
    if (input.mode === "sign_locally") {
      const targetForSigning = this._state
        .actions()
        .find((a) => a.action_id === input.attestedActionId);
      if (!targetForSigning) {
        throw new CounterpartyAttestationError(
          "attested_action_id_not_found",
          `Counterparty attestation references action ${input.attestedActionId}, which has not been recorded in this chain.`
        );
      }
      attestation = buildCounterpartyAttestation({
        counterpartyId: input.counterpartyId,
        counterpartyKeypair: input.counterpartyKeypair,
        chainId: this._state.chainId,
        attestedActionId: input.attestedActionId,
        attestedContentHash: targetForSigning.evidence_hash,
        attestationPurpose: input.attestationPurpose,
        attestedAt: input.attestedAt ?? nowIso(),
        identityProof: input.identityProof
      });
    } else {
      attestation = input.attestation;
    }
    if (attestation.chain_id !== this._state.chainId) {
      throw new CounterpartyAttestationError(
        "chain_id_mismatch",
        `Counterparty attestation references chain ${attestation.chain_id}; session chain is ${this._state.chainId}.`
      );
    }
    const target = this._state
      .actions()
      .find((a) => a.action_id === attestation.attested_action_id);
    if (!target) {
      throw new CounterpartyAttestationError(
        "attested_action_id_not_found",
        `Counterparty attestation references action ${attestation.attested_action_id}, which has not been recorded in this chain.`
      );
    }
    // Content binding (PR 15-A.1, findings #2, #12). Mirrors
    // src/sdk/session.ts: the attestation must commit to the exact
    // evidence of the action it confirms.
    if (attestation.attested_content_hash !== target.evidence_hash) {
      throw new CounterpartyAttestationError(
        "attested_content_hash_mismatch",
        `Counterparty attestation attested_content_hash does not match the evidence_hash of action ${attestation.attested_action_id}.`
      );
    }
    if (!isCanonicalCounterpartyId(attestation.counterparty_id)) {
      throw new CounterpartyAttestationError(
        "counterparty_id_invalid",
        `counterparty_id "${attestation.counterparty_id}" is not canonical (lowercase alphanumeric segments joined by single dots or hyphens).`
      );
    }
    const prior = this._state
      .counterpartyAttestations()
      .find((a) => a.counterparty_id === attestation.counterparty_id);
    if (
      prior &&
      prior.counterparty_public_key !== attestation.counterparty_public_key
    ) {
      throw new CounterpartyAttestationError(
        "counterparty_key_mismatch",
        `counterparty_id "${attestation.counterparty_id}" already attested with a different counterparty_public_key in this chain.`
      );
    }
    // v0.6 step #2: a counterparty confirms a given action once (mirrors
    // src/sdk/session.ts). (counterparty_id, attested_action_id) is the
    // logical identity; reject a replay so one confirmation is not stored
    // and counted twice. The verifier deduplicates on the same key.
    if (
      this._state
        .counterpartyAttestations()
        .some(
          (a) =>
            a.counterparty_id === attestation.counterparty_id &&
            a.attested_action_id === attestation.attested_action_id
        )
    ) {
      throw new CounterpartyAttestationError(
        "counterparty_attestation_duplicate",
        `counterparty_id "${attestation.counterparty_id}" already attested action "${attestation.attested_action_id}" in this chain.`
      );
    }
    this._state.addCounterpartyAttestation(attestation);
    return attestation;
  }

  async recordPlan(input: RecordPlanInput): Promise<RecordedAction> {
    // §3.2 PR 3: wrapper over managed recordAction, matching direct.
    const actionType = input.actionType ?? PLAN_GENERATED_ACTION_TYPE;
    return this.recordAction({
      actionType,
      evidence: { plan: input.plan },
      verifiabilityClass: input.verifiabilityClass ?? "deterministic",
      schemaId: input.schemaId,
      schemaHash: input.schemaHash,
      metadata: input.metadata,
      timestamp: input.timestamp,
      actionId: input.actionId
    });
  }

  async recordPlanStep(input: RecordPlanStepInput): Promise<RecordedAction> {
    // §3.2 PR 3: plan-reference check + wrapper over managed
    // recordAction, matching direct.
    const planAction = this._state
      .actions()
      .find((a) => a.action_id === input.planActionId);
    if (!planAction) {
      throw new PlanReferenceError(
        `No recorded plan_generated action with action_id "${input.planActionId}" exists in the chain. Record a plan with recordPlan before referencing it.`,
        input.planActionId
      );
    }
    if (planAction.action_type !== PLAN_GENERATED_ACTION_TYPE) {
      throw new PlanReferenceError(
        `Action "${input.planActionId}" is recorded as "${planAction.action_type}", not "${PLAN_GENERATED_ACTION_TYPE}". recordPlanStep may only reference a previously recorded plan_generated action.`,
        input.planActionId
      );
    }
    const actionType = input.actionType ?? PLAN_STEP_EXECUTED_ACTION_TYPE;
    return this.recordAction({
      actionType,
      evidence: {
        plan_action_id: input.planActionId,
        step: input.step
      },
      verifiabilityClass: input.verifiabilityClass ?? "deterministic",
      schemaId: input.schemaId,
      schemaHash: input.schemaHash,
      metadata: input.metadata,
      timestamp: input.timestamp,
      actionId: input.actionId
    });
  }

  wrapTool<TArgs extends readonly unknown[], TResult>(
    spec: ToolWrapSpec<TArgs, TResult>
  ): WrappedTool<TArgs, TResult> {
    // §3.2 PR 3: identical to direct mode. The wrapped tool routes
    // its success and error recording through managed recordAction.
    return createWrappedTool(this, spec);
  }

  async inspect(): Promise<InspectionReport> {
    // §3.2 PR 3 (Codex P2 follow-up on PR #156): inspect MUST never
    // touch packageConfig.directory and MUST always clean up after
    // itself, matching direct-mode inspect's invariant that the
    // configured package directory is read-only until finalize.
    // Earlier this path called materializePackage which, when
    // packageConfig was set, wrote evidence / actions / keys into
    // the customer's directory; finalize then rejected because the
    // dir was already populated (Finding 2). And when the session
    // was finalized, buildInspectionReport's full-package
    // verification expected receipt.json to be on disk; the
    // managed materialize did not write it (Finding 1). Both bugs
    // collapse to "managed inspect invented its own materialization
    // that disagreed with direct-mode invariants". The fix is one
    // method, always-temp, that also writes receipt.json post-
    // finalize so the verifier sees a complete package.
    const inspectDir = await this.materializeInspectPackage();
    try {
      return await buildInspectionReport({
        state: this._state,
        writer: inspectDir.writer
      });
    } finally {
      await inspectDir.cleanup();
    }
  }

  async finalize(_options: FinalizeOptions = {}): Promise<FinalizeResult> {
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    if (this._state.snapshot().actionsRecorded === 0) {
      throw new FinalizationError(
        "Cannot finalize a session that has not recorded any actions."
      );
    }
    const receipt = buildReceiptEnvelope({
      state: this._state,
      finalChainState: this._state.currentChainState
    });

    // Local verification first. The intermediary will re-run the
    // structural checks on its side, but we want to fail fast on the
    // customer's machine when the package is malformed (and surface
    // the right error class).
    //
    // §3.2 PR 3: when packageConfig is provided, the materialized
    // package becomes the customer's persistent artifact (mirroring
    // direct mode). When packageConfig is absent, the materialization
    // happens in a temp dir that is cleaned up before returning.
    const verifyResult = await this.verifyReceipt(receipt);

    if (!verifyResult.report.valid) {
      throw new FinalizationError(
        `Local verification of the finalized package failed: ${verifyResult.report.reason ?? "unknown"}.`
      );
    }
    // Mirror direct Session.finalize: if approvals/counterparty
    // attestations were recorded but the verifier counts the badge as
    // absent (signature invalid, or a self-approval the v0.6 verifier
    // excludes), refuse to finalize rather than upload a receipt whose
    // attestation verification says "absent".
    if (this._state.approvals().length > 0 && verifyResult.report.flags.approval === "absent") {
      throw new FinalizationError(
        "Local verification reports the recorded approval(s) as absent (invalid signature or self-approval). The receipt was not finalized."
      );
    }
    if (
      this._state.counterpartyAttestations().length > 0 &&
      verifyResult.report.flags.counterparty === "absent"
    ) {
      throw new FinalizationError(
        "Local verification reports the recorded counterparty attestation(s) as absent. The receipt was not finalized."
      );
    }

    // Ephemeral tier (envelope_custody="customer") skips the
    // finalize HTTP call: there is nothing to store at Sequesign.
    // Hosted and hash-only upload the assembled envelope so the
    // intermediary can put it in R2 and index it for retrieval.
    let r2Key: string | undefined;
    let receiptUrl: string | undefined;
    if (this.managed.envelopeCustody !== "customer") {
      const actionRecords = this._state.actions();
      const finalize = await this.intermediary.postFinalize({
        receipt,
        actionRecords,
        evidenceBlobs:
          this.managed.evidenceCustody === "customer"
            ? undefined
            : this.collectEvidenceBlobsInOrder(actionRecords),
        evidenceCustody: this.managed.evidenceCustody,
        envelopeCustody: this.managed.envelopeCustody,
        retention: this._state.retention
      });
      r2Key = finalize.r2Key;
      receiptUrl = finalize.receiptUrl;
    }

    this._state.markFinalized();
    const sequenceStart = this._state.sequenceStart;
    const actionsRecorded = this._state.snapshot().actionsRecorded;

    return {
      receiptId: this._state.receiptId,
      packageDirectory: verifyResult.packageDirectory,
      envelopePath: verifyResult.envelopePath,
      actionsPath: verifyResult.actionsPath,
      initialChainState: this._state.initialChainState,
      finalChainState: this._state.currentChainState,
      sequenceStart,
      sequenceEnd: sequenceStart + actionsRecorded - 1,
      receipt,
      verification: verifyResult.report,
      r2Key,
      receiptUrl
    };
  }

  // Returns evidence blobs in the same order as the actions array so
  // the finalize upload's parallel arrays line up. Throws if any
  // action lacks a cached blob, which would indicate a programming
  // error in recordAction.
  private collectEvidenceBlobsInOrder(
    actionRecords: ActionRecord[]
  ): EvidenceBlob[] {
    const blobs: EvidenceBlob[] = [];
    for (const action of actionRecords) {
      const cached = this.cachedEvidence.get(action.action_id);
      if (!cached) {
        throw new FinalizationError(
          `Internal error: no cached evidence for action ${action.action_id}.`
        );
      }
      blobs.push(cached.blob);
    }
    return blobs;
  }

  // §3.2 PR 3: write the in-memory state (evidence, actions, keys)
  // through a PackageWriter. Shared by both materialize paths so the
  // on-disk shape stays identical between finalize and inspect.
  // Does NOT write receipt.json; that is the finalize commit point
  // and is added by materializePackage (after the witness/finalize
  // round trip) or materializeInspectPackage (only when the session
  // is already finalized).
  private async writeStateInto(writer: PackageWriter): Promise<void> {
    // Write each cached evidence blob. Order does not matter on
    // disk; the verifier indexes by action_id. The cache is
    // populated by every recordAction regardless of evidenceCustody
    // (customer-evidence tiers cache locally for SDK-side
    // verification even though the blob never goes to broker), so
    // inspect on a hash-only / ephemeral session still has the
    // bytes the partial verifier needs.
    for (const actionId of this.evidenceOrder) {
      const cached = this.cachedEvidence.get(actionId);
      if (!cached) continue;
      await writer.writeEvidence(cached.filename, cached.blob);
    }

    // Write actions.jsonl (one line per action).
    for (const action of this._state.actions()) {
      await writer.appendActionLine(action);
    }

    // Write key files: agent, witness, approvers, counterparties.
    // The witness public key is on the first attestation when at
    // least one action has been recorded; managed recordAction
    // always populates witness attestations, so this is safe when
    // the chain is non-empty (inspect on an empty chain has no
    // witness key to write, which the verifier handles).
    const witnessAttestations = this._state.witnessAttestations();
    const firstWitness = witnessAttestations[0];
    const approverPublicKeys: ApproverPublicKey[] = distinctApproverKeysFrom(
      this._state.approvals()
    );
    const counterpartyPublicKeys: CounterpartyPublicKey[] = distinctCounterpartyKeysFrom(
      this._state.counterpartyAttestations()
    );
    await writer.writeKeyFiles({
      agentPublicKeyPem: this._state.agentPublicKeyPem,
      // WitnessIdentity normally comes from key-discovery (witness
      // bootstrap). Managed sessions never run that discovery; the
      // only fields writeKeyFiles reads are publicKeyPem, but the
      // type requires all four. Synthesize from the first
      // attestation: witness_id and witnessed_at are correct;
      // keyId is not transmitted on the wire, so we reuse
      // witness_id (the closest available identifier). This is
      // documentation only; the package only persists the PEM.
      witnessIdentity: firstWitness
        ? {
            witnessId: firstWitness.witness_id,
            keyId: firstWitness.witness_id,
            publicKeyPem: firstWitness.witness_public_key,
            validFrom: firstWitness.witnessed_at
          }
        : undefined,
      approverPublicKeys,
      counterpartyPublicKeys
    });
  }

  // §3.2 PR 3: finalize-path materialization. Honors packageConfig
  // (the customer's persistent directory) and only cleans up the
  // temp dir when packageConfig is absent. inspect does NOT call
  // this; inspect uses materializeInspectPackage which always
  // creates and cleans up a throwaway temp dir.
  private async materializePackage(args: {
    cleanupAfter: boolean;
  }): Promise<{
    writer: PackageWriter;
    directory: string;
    usingTemp: boolean;
    cleanup: () => Promise<void>;
  }> {
    const usingTemp = !this.packageConfig;
    const directory = this.packageConfig
      ? this.packageConfig.directory
      : await mkdtemp(path.join(tmpdir(), "sequesign-managed-"));
    const writer = createPackageWriter(directory);

    if (this.packageConfig) {
      await initPackageDirectory(
        directory,
        this.packageConfig.ifExists ?? "fail"
      );
    }

    await this.writeStateInto(writer);

    const cleanup = async (): Promise<void> => {
      if (usingTemp && args.cleanupAfter) {
        await rm(directory, { recursive: true, force: true });
      }
    };

    return { writer, directory, usingTemp, cleanup };
  }

  // §3.2 PR 3 (Codex P2 follow-up on PR #156): inspect-only
  // materialization. ALWAYS creates a throwaway temp directory and
  // ALWAYS cleans up. Never touches packageConfig.directory, so a
  // subsequent finalize() finds the customer's directory in the
  // expected pre-finalize state (Finding 2: inspect() then
  // finalize() must succeed with the default ifExists: "fail"). On
  // a finalized session also writes receipt.json from
  // buildReceiptEnvelope so buildInspectionReport's
  // verifyReceiptPackage call (state.finalized branch) finds a
  // complete package (Finding 1: finalize() then inspect() must
  // return the finalized inspection report rather than reject). The
  // function is the only managed-side entry point that writes
  // receipt.json outside finalize; the envelope it produces is
  // reconstructed from SessionState (which still holds actions and
  // attestations after markFinalized), so it is byte-identical to
  // the envelope finalize stored.
  private async materializeInspectPackage(): Promise<{
    writer: PackageWriter;
    directory: string;
    cleanup: () => Promise<void>;
  }> {
    const directory = await mkdtemp(
      path.join(tmpdir(), "sequesign-managed-inspect-")
    );
    try {
      const writer = createPackageWriter(directory);
      await this.writeStateInto(writer);
      if (this._state.finalized) {
        const receipt = buildReceiptEnvelope({
          state: this._state,
          finalChainState: this._state.currentChainState
        });
        await writer.writeEnvelope(receipt);
      }
      const cleanup = async (): Promise<void> => {
        await rm(directory, { recursive: true, force: true });
      };
      return { writer, directory, cleanup };
    } catch (err) {
      // Materialization failed partway through. Best-effort clean
      // the half-populated temp dir so we do not leak it; swallow
      // the cleanup failure because the original error is what the
      // caller needs to see.
      await rm(directory, { recursive: true, force: true }).catch(
        () => undefined
      );
      throw err;
    }
  }

  private async verifyReceipt(receipt: AgentActionReceipt): Promise<{
    report: VerificationReport;
    packageDirectory: string;
    envelopePath: string;
    actionsPath: string;
  }> {
    // §3.2 PR 3: materialize the package with a real PackageWriter
    // (replaces the prior inline mkdir/writeFile path). This gives
    // approver and counterparty key files for free via writer
    // .writeKeyFiles, which the verifier needs when the envelope
    // carries approval_attestations or
    // counterparty_attestations.
    const materialized = await this.materializePackage({ cleanupAfter: false });
    const usingTemp = materialized.usingTemp;
    const directory = materialized.directory;
    try {
      await materialized.writer.writeEnvelope(receipt);
      // Integrity self-check anchored to the witness this session used
      // (trust_anchor_mode "self"); a third party anchors to the
      // witness's well-known keys instead.
      const report = await verifyReceiptPackage(directory, {
        trustedWitnessKeys: witnessKeysFromReceipt(receipt),
        trustAnchorMode: "self"
      });
      return {
        report,
        packageDirectory: usingTemp ? "" : directory,
        envelopePath: usingTemp ? "" : path.join(directory, "receipt.json"),
        actionsPath: usingTemp ? "" : materialized.writer.actionsPath()
      };
    } finally {
      if (usingTemp) {
        await rm(directory, { recursive: true, force: true });
      }
    }
  }

  checkpoint(): SessionCheckpoint {
    throw managedNotSupported("checkpoint");
  }
  fetchInclusionProofs(
    _options?: FetchInclusionProofsOptions
  ): Promise<FetchInclusionProofsResult> {
    return Promise.reject(managedNotSupported("fetchInclusionProofs"));
  }
}

// Mirrors the deduplicators in src/sdk/session.ts. First-seen wins
// per id; the call sites above already reject same-id different-key
// pairs, so the ordering is stable.
function distinctApproverKeysFrom(
  attestations: ApprovalAttestation[]
): ApproverPublicKey[] {
  const seen = new Set<string>();
  const result: ApproverPublicKey[] = [];
  for (const att of attestations) {
    if (seen.has(att.approver_id)) continue;
    seen.add(att.approver_id);
    result.push({
      approverId: att.approver_id,
      publicKeyPem: att.approver_public_key
    });
  }
  return result;
}

function distinctCounterpartyKeysFrom(
  attestations: CounterpartyAttestation[]
): CounterpartyPublicKey[] {
  const seen = new Set<string>();
  const result: CounterpartyPublicKey[] = [];
  for (const att of attestations) {
    if (seen.has(att.counterparty_id)) continue;
    seen.add(att.counterparty_id);
    result.push({
      counterpartyId: att.counterparty_id,
      publicKeyPem: att.counterparty_public_key
    });
  }
  return result;
}

async function initPackageDirectory(
  directory: string,
  ifExists: "fail" | "reset" | "resume"
): Promise<void> {
  if (ifExists === "resume") {
    throw new NotImplementedError(
      'package.ifExists="resume" in managed mode'
    );
  }
  if (ifExists === "reset") {
    await resetDir(directory);
    return;
  }
  let exists = false;
  try {
    await stat(directory);
    exists = true;
  } catch {
    exists = false;
  }
  if (exists) {
    throw new PackageStateError(
      `Package directory already exists: ${directory}. Pass package.ifExists="reset" to overwrite.`
    );
  }
  await ensureDir(directory);
}

