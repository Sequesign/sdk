import path from "node:path";
import { stat } from "node:fs/promises";
import { hashCanonical } from "../lib/hash.js";
import { readJson } from "../lib/io.js";
import { verifyEd25519 } from "../lib/keys.js";
import { approvalMessage } from "../lib/messages.js";
import { evaluateMandate } from "../lib/profile.js";
import { resolveGenesisBinding } from "./genesis-binding.js";
import { verifyReceiptPackage, witnessKeysFromReceipt } from "../lib/verify.js";
import { applySchemaPolicy } from "./schema-policy.js";
import { isCanonicalCounterpartyId, isValidApproverId } from "../lib/package-layout.js";
import type {
  CounterpartyAttestation,
  EvidenceBlob,
  ApprovalAttestation,
  ReceiptConformance,
  VerifiabilityClass
} from "../lib/types.js";
import type { WitnessRequest } from "../lib/witness-types.js";
import { buildReceiptEnvelope } from "./envelope.js";
import {
  CounterpartyAttestationError,
  FinalizationError,
  ApprovalError,
  NotImplementedError,
  PackageStateError,
  PlanReferenceError,
  ProfileValidationError,
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
import { buildSessionCheckpoint } from "./resume.js";
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
import { SessionState } from "./state.js";
import { createWrappedTool } from "./tool-wrap.js";
import type {
  FetchInclusionProofsOptions,
  FetchInclusionProofsResult,
  FinalizeOptions,
  FinalizeResult,
  InspectionReport,
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
  WitnessConfig,
  WrappedTool
} from "./types.js";
import { PLAN_GENERATED_ACTION_TYPE, PLAN_STEP_EXECUTED_ACTION_TYPE } from "./types.js";
import {
  connectWitness,
  resolveWitnessConfig,
  DEFAULT_INCLUSION_PROOF_POLL_MS,
  DEFAULT_INCLUSION_PROOF_TIMEOUT_MS,
  type WitnessClient
} from "./witness-client.js";
import { InclusionProofTimeoutError } from "./errors.js";
export async function startSessionImpl(
  init: SessionInit,
  sdkWitnessDefaults: WitnessConfig | undefined
): Promise<Session> {
  const mergedWitnessConfig = resolveWitnessConfig(init.witness, sdkWitnessDefaults);

  const mode = init.mode ?? "freeform";
  if (mode !== "freeform" && mode !== "schema_validated" && mode !== "profile_constrained") {
    throw new PackageStateError(`Unsupported receipt mode: ${String(mode)}`);
  }
  if (mode === "profile_constrained" && !init.profile) {
    throw new PackageStateError(
      "profile_constrained mode requires SessionInit.profile with profile_id and profile_hash."
    );
  }
  if (!init.package) {
    throw new PackageStateError(
      "Direct mode requires init.package. Pass { directory, ifExists } to write the receipt package to disk."
    );
  }
  const pkg = init.package;
  const ifExists = pkg.ifExists ?? "fail";
  if (ifExists === "resume") {
    throw new NotImplementedError(
      'package.ifExists="resume" (planned in M3, use Sdk.resumeSession or Sdk.resumeFromPackage)'
    );
  }
  if (ifExists !== "fail" && ifExists !== "reset") {
    throw new PackageStateError(`Unsupported package.ifExists option: ${String(ifExists)}`);
  }
  if (ifExists === "fail") {
    let exists = false;
    try {
      await stat(pkg.directory);
      exists = true;
    } catch {
      exists = false;
    }
    if (exists) {
      throw new PackageStateError(
        `Package directory already exists: ${pkg.directory}. Pass package.ifExists="reset" to overwrite.`
      );
    }
  }

  const chainId = init.chainId ?? generateChainId();
  const receiptId = init.receiptId ?? generateReceiptId();

  // Genesis binding (template system). Resolve the sealed profile reference and
  // the chain genesis (V1 when parameterized, else V0) via the shared helper so
  // the direct and managed paths cannot drift. A parameterized session commits
  // the mandate (profile_hash + params_hash) and the parties into
  // SEQUESIGN_GENESIS_V1; every other session keeps the byte-identical V0
  // genesis. This runs BEFORE the package writer is initialized, so a binding
  // failure (unknown profile, hash mismatch, bad params) throws without leaving
  // a half-created package directory behind. boundParams travels in the package
  // (params.json) and is restored on resume; undefined on the V0 path.
  const { profileRef, initialChainState, boundParams, profileDocument, profileAuthorSignature } =
    await resolveGenesisBinding({
      chainId,
      taskId: init.task.taskId,
      delegatorId: init.task.delegatorId,
      agentId: init.agent.agentId,
      profile: init.profile,
      params: init.params,
      profileDocument: init.profileDocument,
      profileAuthorSignature: init.profileAuthorSignature
    });

  const writer = createPackageWriter(pkg.directory);
  await writer.initialize(ifExists === "reset");

  const witness: WitnessClient = await connectWitness(mergedWitnessConfig);

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
    profile: profileRef,
    boundParams,
    profileDocument,
    profileAuthorSignature,
    // §3.1 Retention PR 1: accepted for API symmetry with managed
    // mode. Direct mode does not write a library.receipts row (the
    // customer holds the package), so the value is carried in state
    // but never sent on the wire. Keeping it in SessionState means a
    // future direct-to-broker storage path can read it without a
    // breaking API change.
    retention: init.retention
  });

  await writer.writeKeyFiles({
    agentPublicKeyPem: state.agentPublicKeyPem,
    witnessIdentity: witness.currentKey
  });

  // Embed-first packaging (Phase 3): a parameterized session writes its bound
  // values to a top-level params.json so the mandate travels in the package —
  // restorable on resume and re-hashable by an offline verifier. Written once;
  // it survives finalize (not under .in-progress/).
  if (boundParams !== undefined) {
    await writer.writeParams(boundParams);
  }
  // Embed-first packaging (Phase 3): a profile_constrained session writes the
  // resolved profile document to a top-level profile.json so the mandate's
  // rules travel in the package — re-evaluated for conformance and re-hashed
  // (profile_hash) by an offline verifier with no registry. Written once; it
  // survives finalize (not under .in-progress/).
  if (profileDocument !== undefined) {
    await writer.writeProfile(profileDocument);
  }
  // Template system Phase 5: when the parameterized profile carries a
  // template-author signature, write it to a top-level profile.sig.json sidecar
  // so an offline verifier can grade template_authenticity. Written once; it
  // survives finalize (not under .in-progress/).
  if (profileAuthorSignature !== undefined) {
    await writer.writeProfileSig(profileAuthorSignature);
  }

  const session = new SessionImpl(init.agent.keypair.privateKeyPem, state, writer, witness);
  await session.persistCheckpoint();
  return session;
}

// One key file per distinct counterparty_id, keeping the first key seen.
// recordCounterpartyAttestation already rejects a same-id/different-key
// pair, so first-seen is the only key for that id.
function distinctCounterpartyKeys(
  attestations: CounterpartyAttestation[]
): CounterpartyPublicKey[] {
  const seen = new Set<string>();
  const keys: CounterpartyPublicKey[] = [];
  for (const att of attestations) {
    if (seen.has(att.counterparty_id)) continue;
    seen.add(att.counterparty_id);
    keys.push({
      counterpartyId: att.counterparty_id,
      publicKeyPem: att.counterparty_public_key
    });
  }
  return keys;
}

// One key file per distinct approver_id, keeping the first key seen.
// recordApproval rejects a same-id/different-key pair, so first-seen
// is the only key for that id.
function distinctApproverKeys(attestations: ApprovalAttestation[]): ApproverPublicKey[] {
  const seen = new Set<string>();
  const keys: ApproverPublicKey[] = [];
  for (const att of attestations) {
    if (seen.has(att.approver_id)) continue;
    seen.add(att.approver_id);
    keys.push({
      approverId: att.approver_id,
      publicKeyPem: att.approver_public_key
    });
  }
  return keys;
}

export class SessionImpl implements Session {
  private readonly agentPrivateKeyPem: string;
  private readonly _state: SessionState;
  private readonly writer: PackageWriter;
  private readonly witness: WitnessClient;

  constructor(
    agentPrivateKeyPem: string,
    state: SessionState,
    writer: PackageWriter,
    witness: WitnessClient
  ) {
    this.agentPrivateKeyPem = agentPrivateKeyPem;
    this._state = state;
    this.writer = writer;
    this.witness = witness;
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
    const sequence = this._state.sequenceNext;
    const actionType = input.actionType;
    const actionId = input.actionId ?? generateActionId(sequence, actionType);
    const verifiabilityClass: VerifiabilityClass = input.verifiabilityClass ?? "deterministic";
    const evidenceBlob = buildEvidenceBlob({
      actionId,
      actionType,
      schemaId: input.schemaId,
      schemaHash: input.schemaHash,
      content: input.evidence
    });
    await applySchemaPolicy(this._state, input, evidenceBlob);
    const evidenceHash = hashCanonical(evidenceBlob);
    const policyContextHash = input.policyContextHash ?? this._state.policyContextHash;
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
      previousChainState: this._state.currentChainState,
      timestamp: input.timestamp,
      metadata: input.metadata
    });
    const { actionRecordHash, nextChainState, agentAttestation } = extendChainWithAction({
      actionRecord,
      agentPrivateKeyPem: this.agentPrivateKeyPem,
      agentId: this._state.agentId,
      agentPublicKeyPem: this._state.agentPublicKeyPem
    });

    const witnessRequest: WitnessRequest = {
      chain_id: this._state.chainId,
      sequence,
      action_record_hash: actionRecordHash,
      previous_chain_state: this._state.currentChainState,
      chain_state: nextChainState,
      // The witness records this in its transparency-log entry to support format
      // migrations, so it must match the schema version this receipt will
      // finalize as: a parameterized session (profile carries the bound
      // params_hash) seals v2.1.0, everything else v2.0.0. (The per-action
      // attestation the witness signs does not include this field, so the
      // choice does not affect signature verification — only the log index.)
      receipt_schema_version: this._state.profile?.params_hash
        ? "sequesign.receipt.v2.1.0"
        : "sequesign.receipt.v2.0.0",
      // Opt into direct-mode agent-identity binding: tell the witness which key
      // we're signing with. If this key is the one registered to the API key,
      // the witness enforces the match and returns the account's agent_identity
      // (below) so the receipt verifies as a registered identity; if no key is
      // registered, the witness ignores it and the identity stays self_asserted.
      agent_public_key: this._state.agentPublicKeyPem
    };
    const { attestation: witnessAttestation, agentIdentity } =
      await this.witness.signCommitment(witnessRequest);
    // Capture the registered-identity credential (same value on every action).
    if (agentIdentity) this._state.setAgentIdentity(agentIdentity);

    const filename = evidenceFilename(sequence, actionType);
    const evidencePath = `evidence/${filename}`;
    await this.writer.writeEvidence(filename, evidenceBlob);
    await this.writer.appendActionLine(actionRecord);
    await this.writer.appendAttestationLine({
      sequence,
      agent: agentAttestation,
      witness: witnessAttestation
    });

    // Direct mode never sends evidence content to Sequesign; the
    // package is assembled locally and the customer holds the bytes.
    // Custody is therefore external_client_managed regardless of who
    // captured the evidence. v0.4 dropped the per-action override
    // (evidenceSource) since the field is fully derived from session
    // context now.
    const evidenceReference = {
      action_id: actionId,
      evidence_hash: evidenceHash,
      evidence_path: evidencePath,
      mime_type: "application/json",
      evidence_custody: "external_client_managed" as const
    };

    this._state.appendAction({
      action: actionRecord,
      actionRecordHash,
      nextChainState,
      agentAttestation,
      witnessAttestation,
      evidenceReference
    });

    await this.persistCheckpoint();

    return {
      actionId,
      actionType,
      sequence,
      actionRecordHash,
      previousChainState: actionRecord.previous_chain_state,
      chainState: nextChainState,
      evidenceHash,
      evidencePath,
      agentAttestation,
      witnessAttestation,
      recordedAt: actionRecord.timestamp
    };
  }

  async recordApproval(input: RecordApprovalInput): Promise<ApprovalAttestation> {
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
      if (!verifyEd25519(attestation.approver_public_key, message, attestation.signature)) {
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
    // Task binding (PR 15-A.1, finding #10). Every approval, regardless
    // of mode, must approve THIS session's task. attach_signed could
    // carry an approval signed for a different task, and sign_locally
    // could be handed an approvedTaskId that names another task; either
    // way the verifier rejects the finalized package with
    // approval_binding_mismatch, so fail fast here with the
    // specific code. This is mode-agnostic so no future mode can slip an
    // off-task approval through.
    if (attestation.approved_task_id !== this._state.taskId) {
      throw new ApprovalError(
        "approved_task_id_mismatch",
        `Approval references task ${attestation.approved_task_id}; session task is ${this._state.taskId}.`
      );
    }
    // Approval binding (PR 15-A.1, finding #10). Fail fast so an SDK
    // consumer cannot assemble a package the verifier would later reject
    // with approval_binding_mismatch. The approval must approve an
    // action_type that actually occurred in this chain. The verifier is
    // the authoritative, order-independent gate; the SDK requires the
    // approved action to be recorded before its approval (every recorded
    // workflow does this), which catches a wrong action_type here rather
    // than at finalize. (approved_task_id is already bound to the
    // session task in the attach_signed branch above and by construction
    // in sign_locally.)
    if (!this._state.actions().some((a) => a.action_type === attestation.approved_action_type)) {
      throw new ApprovalError(
        "approved_action_type_mismatch",
        `Approval approves action_type "${attestation.approved_action_type}", which matches no action recorded in this chain. Record the action before recording its approval.`
      );
    }
    // The approver_id becomes a path segment under keys/approvers/.
    // Reject ids that are not a valid lowercase email or label so the
    // SDK never writes a key the hosted intermediary would refuse on the
    // same grounds.
    if (!isValidApproverId(attestation.approver_id)) {
      throw new ApprovalError(
        "approver_id_invalid",
        `approver_id "${attestation.approver_id}" is not a valid lowercase email or label (letters, digits, ".", "_", "+", "-", optional "@domain").`
      );
    }
    // One approver_id binds to one key for the life of a chain: the
    // package stores a single keys/approvers/<id>.pub.pem per approver,
    // so a second approval for the same id with a different key is
    // unstorable. Catch it here rather than silently overwriting (or
    // having the intermediary reject the finalize later).
    const priorApproval = this._state
      .approvals()
      .find((a) => a.approver_id === attestation.approver_id);
    if (priorApproval && priorApproval.approver_public_key !== attestation.approver_public_key) {
      throw new ApprovalError(
        "approver_key_mismatch",
        `approver_id "${attestation.approver_id}" already approved with a different approver_public_key in this chain.`
      );
    }
    // v0.6 step #2 (multiple-approval semantics): one approval_id is
    // recorded once. The recorder appends every attestation, so without
    // this guard a replayed approval_id would be stored twice and inflate a
    // naive count. The verifier deduplicates by approval_id when it
    // enumerates approvals; the SDK refuses to assemble a package that
    // carries the same approval_id twice in the first place.
    if (this._state.approvals().some((a) => a.approval_id === attestation.approval_id)) {
      throw new ApprovalError(
        "approval_id_duplicate",
        `approval_id "${attestation.approval_id}" was already recorded in this chain.`
      );
    }
    this._state.addApproval(attestation);
    await this.writer.writeKeyFiles({
      agentPublicKeyPem: this._state.agentPublicKeyPem,
      witnessIdentity: this.witness.currentKey,
      approverPublicKeys: distinctApproverKeys(this._state.approvals())
    });
    await this.persistCheckpoint();
    return attestation;
  }

  async recordPlan(input: RecordPlanInput): Promise<RecordedAction> {
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
    const planAction = this._state.actions().find((a) => a.action_id === input.planActionId);
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

  async recordCounterpartyAttestation(
    input: RecordCounterpartyAttestationInput
  ): Promise<CounterpartyAttestation> {
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    // sign_locally mirrors recordApproval: the SDK builds + signs the
    // attestation from the counterparty's keypair and derives
    // attested_content_hash from the attested action's evidence, so the
    // caller cannot bind a confirmation to content the counterparty never
    // saw. attach_signed (mode omitted for back-compat) takes a fully-formed
    // attestation; its signature is validated at finalize/verify, not here
    // (a deliberate v0.3 choice the test-suite pins).
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
    // Content binding (PR 15-A.1, findings #2, #12). The attestation
    // must commit to the exact evidence of the action it confirms, so a
    // counterparty confirmation cannot be pointed at content the
    // counterparty never saw (and cannot be replayed against a different
    // action's content). Fail fast here; the verifier enforces the same
    // binding with counterparty_attestation_binding_mismatch.
    if (attestation.attested_content_hash !== target.evidence_hash) {
      throw new CounterpartyAttestationError(
        "attested_content_hash_mismatch",
        `Counterparty attestation attested_content_hash does not match the evidence_hash of action ${attestation.attested_action_id}.`
      );
    }
    // The counterparty_id becomes a path segment under
    // keys/counterparty/ in the assembled package. Reject ids that are
    // not filesystem-safe so the SDK never writes a key the hosted
    // intermediary would refuse on the same grounds.
    if (!isCanonicalCounterpartyId(attestation.counterparty_id)) {
      throw new CounterpartyAttestationError(
        "counterparty_id_invalid",
        `counterparty_id "${attestation.counterparty_id}" is not canonical (lowercase alphanumeric segments joined by single dots or hyphens).`
      );
    }
    // One counterparty_id binds to one key for the life of a chain: the
    // package stores a single keys/counterparty/<id>.pub.pem, so a
    // second attestation for the same id with a different key is
    // unstorable. Catch it here rather than silently overwriting (or
    // having the intermediary reject the finalize later).
    const prior = this._state
      .counterpartyAttestations()
      .find((a) => a.counterparty_id === attestation.counterparty_id);
    if (prior && prior.counterparty_public_key !== attestation.counterparty_public_key) {
      throw new CounterpartyAttestationError(
        "counterparty_key_mismatch",
        `counterparty_id "${attestation.counterparty_id}" already attested with a different counterparty_public_key in this chain.`
      );
    }
    // v0.6 step #2: a counterparty confirms a given action once. The
    // counterparty attestation carries no id, so (counterparty_id,
    // attested_action_id) is its logical identity; reject a replay of that
    // pair so a single confirmation cannot be stored (and counted) twice.
    // The verifier deduplicates on the same key when it enumerates.
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
    await this.writer.writeKeyFiles({
      agentPublicKeyPem: this._state.agentPublicKeyPem,
      witnessIdentity: this.witness.currentKey,
      counterpartyPublicKeys: distinctCounterpartyKeys(this._state.counterpartyAttestations())
    });
    await this.persistCheckpoint();
    return attestation;
  }

  async inspect(): Promise<InspectionReport> {
    return buildInspectionReport({ state: this._state, writer: this.writer });
  }

  checkpoint(): SessionCheckpoint {
    return buildSessionCheckpoint({
      state: this._state,
      writer: this.writer,
      witness: this.witness
    });
  }

  async persistCheckpoint(): Promise<void> {
    const checkpoint = this.checkpoint();
    await this.writer.writeCheckpoint(checkpoint);
  }

  // Fetch a Merkle inclusion proof for every recorded action's witness
  // attestation that has a log_entry reference. Failures (timeout,
  // witness unreachable) are non-fatal: the affected attestations
  // simply do not carry a proof, and the receipt still verifies under
  // Phase 1.5 semantics (without the inclusion guarantee).
  async fetchInclusionProofs(
    options: FetchInclusionProofsOptions = {}
  ): Promise<FetchInclusionProofsResult> {
    if (this._state.finalized) {
      throw new SessionStateError("Cannot fetch inclusion proofs after the session is finalized.");
    }
    const attestations = this._state.witnessAttestations();
    const timeoutMs = options.timeoutMs ?? DEFAULT_INCLUSION_PROOF_TIMEOUT_MS;
    const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_INCLUSION_PROOF_POLL_MS;
    let fetched = 0;
    let failed = 0;
    let considered = 0;
    const failures: FetchInclusionProofsResult["failures"] = [];
    for (const att of attestations) {
      if (!att.log_entry) continue;
      if (att.batch_inclusion_proof) {
        fetched += 1;
        continue;
      }
      considered += 1;
      const position = att.log_entry.position;
      const logId = att.log_entry.log_id;
      try {
        const proof = await this.witness.fetchInclusionProof(
          { position, logId },
          { timeoutMs, pollIntervalMs }
        );
        const attached = this._state.attachInclusionProof(att.sequence, proof);
        if (attached) fetched += 1;
      } catch (err) {
        failed += 1;
        const reason =
          err instanceof InclusionProofTimeoutError
            ? "timeout"
            : err instanceof Error
              ? err.message
              : String(err);
        failures.push({ sequence: att.sequence, position, reason });
      }
    }
    if (considered > 0) await this.persistCheckpoint();
    return {
      attestationsConsidered: considered,
      proofsFetched: fetched,
      proofsFailed: failed,
      failures
    };
  }

  wrapTool<TArgs extends readonly unknown[], TResult>(
    spec: ToolWrapSpec<TArgs, TResult>
  ): WrappedTool<TArgs, TResult> {
    return createWrappedTool(this, spec);
  }

  async finalize(options: FinalizeOptions = {}): Promise<FinalizeResult> {
    if (this._state.finalized) {
      throw new SessionStateError("Session is already finalized.");
    }
    if (this._state.snapshot().actionsRecorded === 0) {
      throw new FinalizationError("Cannot finalize a session that has not recorded any actions.");
    }
    let sealedConformance: ReceiptConformance | undefined;
    if (this._state.mode === "profile_constrained" && this._state.profile) {
      const evidenceBlobs = await this.loadAllEvidence();
      const mandate = await evaluateMandate({
        profileId: this._state.profile.profile_id,
        profileHash: this._state.profile.profile_hash,
        actions: this._state.actions(),
        evidence: evidenceBlobs,
        boundParams: this._state.boundParams,
        embeddedProfile: this._state.profileDocument
      });
      // HARD axis: an unresolvable profile or a profile_hash mismatch is not
      // sealable — the mandate identity is broken. Throw, exactly as before.
      if (!mandate.resolved || !mandate.profileHashVerified) {
        throw new ProfileValidationError(this._state.profile.profile_id, mandate.hardErrors);
      }
      // SOFT axis (violation-preserving seal): nonconformant work still seals.
      // Record the producer's self-assessment in the receipt (bumps it to
      // v2.2.0) and warn; a conformant receipt seals no block and stays
      // v2.1.0/v2.0.0. The verifier recomputes conformance either way.
      if (!mandate.conformant) {
        sealedConformance = { conformant: false, violations: mandate.violations };
        console.warn(
          `Sequesign: sealing a receipt whose work does not conform to mandate ${this._state.profile.profile_id}: ${mandate.violations.join("; ")}`
        );
      }
    }
    if (options.inclusionProofTimeoutMs !== undefined) {
      // Explicit opt-in: the caller wants inclusion proofs embedded
      // in the envelope and is willing to wait up to the supplied
      // timeout for the witness to seal a batch containing each log
      // entry. The default (option unset) is the proof-archive path:
      // finalize returns immediately, and the verifier obtains proofs
      // at verification time via sidecar or online fetch. See PLAN.md
      // section 4.23. Best-effort: witness errors are swallowed so a
      // slow or unreachable witness does not block finalization.
      try {
        await this.fetchInclusionProofs({
          timeoutMs: options.inclusionProofTimeoutMs
        });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.warn(`Sequesign: inclusion-proof fetch failed during finalize: ${message}`);
      }
    }
    const receipt = buildReceiptEnvelope({
      state: this._state,
      finalChainState: this._state.currentChainState,
      conformance: sealedConformance
    });
    const envelopePath = await this.writer.writeEnvelope(receipt);
    // Integrity self-check: anchor to the witness this session just
    // obtained attestations from (trust_anchor_mode "self"). This is not
    // an adversarial trust check; a third party verifies against the
    // witness's well-known keys instead.
    const verification = await verifyReceiptPackage(this.writer.directory, {
      trustedWitnessKeys: witnessKeysFromReceipt(receipt),
      trustAnchorMode: "self"
    });
    if (!verification.valid) {
      throw new FinalizationError(
        `Local verification of the finalized package failed: ${verification.reason ?? "unknown"}.`
      );
    }
    if (this._state.approvals().length > 0 && verification.flags.approval === "absent") {
      throw new FinalizationError(
        "Local verification reports an approval signature that does not verify. The receipt was not finalized."
      );
    }
    if (
      this._state.counterpartyAttestations().length > 0 &&
      verification.flags.counterparty === "absent"
    ) {
      throw new FinalizationError(
        "Local verification reports a counterparty attestation whose signature does not verify. The receipt was not finalized."
      );
    }
    if (options.embedVerificationReport ?? true) {
      await this.writer.writeVerificationReport(verification);
    }
    await this.writer.cleanupDraft();
    this._state.markFinalized();
    const sequenceStart = this._state.sequenceStart;
    const actionsRecorded = this._state.snapshot().actionsRecorded;
    return {
      receiptId: this._state.receiptId,
      packageDirectory: this.writer.directory,
      envelopePath,
      actionsPath: this.writer.actionsPath(),
      initialChainState: this._state.initialChainState,
      finalChainState: this._state.currentChainState,
      sequenceStart,
      sequenceEnd: sequenceStart + actionsRecorded - 1,
      receipt,
      verification
    };
  }

  private async loadAllEvidence(): Promise<EvidenceBlob[]> {
    const refs = this._state.evidenceReferences();
    const blobs: EvidenceBlob[] = [];
    for (const ref of refs) {
      const filePath = path.join(this.writer.directory, ref.evidence_path);
      try {
        const blob = await readJson<EvidenceBlob>(filePath);
        blobs.push(blob);
      } catch (err) {
        throw new FinalizationError(
          `Cannot read evidence at ${filePath}: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }
    return blobs;
  }
}
