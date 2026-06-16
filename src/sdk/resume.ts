import path from "node:path";
import { readJson } from "../lib/io.js";
import { extendChain } from "../lib/chain.js";
import { hashCanonical } from "../lib/hash.js";
import { verifyEd25519 } from "../lib/keys.js";
import {
  agentAttestationMessage,
  witnessAttestationMessage
} from "../lib/messages.js";
import type { ActionRecord, EvidenceBlob } from "../lib/types.js";
import { ResumeError } from "./errors.js";
import {
  createPackageWriter,
  type AttestationLine,
  type PackageWriter
} from "./package-writer.js";
import { SessionState } from "./state.js";
import { SessionImpl } from "./session.js";
import type {
  KeyMaterial,
  ResumeOptions,
  Session,
  SessionCheckpoint,
  WitnessConfig,
  WitnessConfigSummary
} from "./types.js";
import {
  connectWitness,
  resolveWitnessConfig,
  type WitnessClient
} from "./witness-client.js";

export const CHECKPOINT_SCHEMA_VERSION = "sequesign.sdk.session_checkpoint.v0.1";

export function serializeCheckpoint(checkpoint: SessionCheckpoint): string {
  return JSON.stringify(checkpoint);
}

export function parseCheckpoint(serialized: string): SessionCheckpoint {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch (err) {
    throw new ResumeError(
      "checkpoint_unparsable",
      "Checkpoint string is not valid JSON.",
      err
    );
  }
  return assertCheckpointShape(parsed);
}

export function assertCheckpointShape(value: unknown): SessionCheckpoint {
  if (!value || typeof value !== "object") {
    throw new ResumeError("checkpoint_malformed", "Checkpoint is not an object.");
  }
  const c = value as Record<string, unknown>;
  if (c.schemaVersion !== CHECKPOINT_SCHEMA_VERSION) {
    throw new ResumeError(
      "checkpoint_schema_mismatch",
      `Checkpoint schemaVersion is "${String(c.schemaVersion)}"; expected "${CHECKPOINT_SCHEMA_VERSION}".`
    );
  }
  const required = [
    "receiptId",
    "chainId",
    "mode",
    "agent",
    "task",
    "chain",
    "packageDirectory",
    "witness"
  ];
  for (const field of required) {
    if (!(field in c)) {
      throw new ResumeError(
        "checkpoint_missing_field",
        `Checkpoint is missing required field "${field}".`
      );
    }
  }
  normalizeCheckpointWitness(c);
  return c as unknown as SessionCheckpoint;
}

// Normalize the witness config (issue #227). The persisted field was
// renamed witness.url -> witness.baseUrl without a schema bump, so a
// legacy checkpoint carries witness.url. Migrate url -> baseUrl in
// place, and reject a witness object that carries neither rather than
// let resume fall through to DEFAULT_WITNESS_BASE_URL and silently
// misroute the resumed session. Called from both checkpoint entry
// points: assertCheckpointShape (the parse path) and resumeSessionImpl
// (the common chokepoint for resumeSession with a pre-built object and
// resumeFromPackage, which reads the on-disk checkpoint directly and
// never passes through assertCheckpointShape).
export function normalizeCheckpointWitness(checkpoint: { witness?: unknown }): void {
  if (!checkpoint.witness || typeof checkpoint.witness !== "object") {
    throw new ResumeError(
      "checkpoint_malformed",
      'Checkpoint field "witness" is not an object.'
    );
  }
  const witness = checkpoint.witness as Record<string, unknown>;
  if (typeof witness.baseUrl === "string" && witness.baseUrl.length > 0) {
    return;
  }
  if (typeof witness.url === "string" && witness.url.length > 0) {
    witness.baseUrl = witness.url;
    delete witness.url;
    return;
  }
  throw new ResumeError(
    "checkpoint_missing_field",
    'Checkpoint field "witness" has neither baseUrl nor the legacy url.'
  );
}

export interface BuildSessionCheckpointArgs {
  state: SessionState;
  writer: PackageWriter;
  witness: WitnessClient;
}

export function buildSessionCheckpoint(args: BuildSessionCheckpointArgs): SessionCheckpoint {
  const { state, writer, witness } = args;
  const snapshot = state.snapshot();
  const witnessSummary: WitnessConfigSummary = {
    baseUrl: witness.config.baseUrl,
    witnessId: witness.witnessId || undefined
  };
  const schemaReferences = state.schemaReferences();
  return {
    schemaVersion: CHECKPOINT_SCHEMA_VERSION,
    receiptId: state.receiptId,
    chainId: state.chainId,
    mode: state.mode,
    schemaReferences: schemaReferences.length > 0 ? schemaReferences : undefined,
    agent: {
      agentId: state.agentId,
      agentPublicKey: state.agentPublicKeyPem
    },
    task: {
      taskId: state.taskId,
      delegatorId: state.delegatorId,
      delegatedAt: state.delegatedAt,
      policyContextHash: state.policyContextHash
    },
    chain: {
      initialChainState: state.initialChainState,
      currentChainState: state.currentChainState,
      sequenceStart: state.sequenceStart,
      sequenceNext: snapshot.sequenceNext
    },
    packageDirectory: writer.directory,
    witness: witnessSummary
  };
}

export interface ResumeSessionImplArgs {
  checkpoint: SessionCheckpoint;
  keypair: KeyMaterial;
  options: ResumeOptions;
  sdkWitnessDefaults: WitnessConfig | undefined;
}

export async function resumeSessionImpl(args: ResumeSessionImplArgs): Promise<Session> {
  const { checkpoint, keypair, options, sdkWitnessDefaults } = args;
  if (checkpoint.schemaVersion !== CHECKPOINT_SCHEMA_VERSION) {
    throw new ResumeError(
      "checkpoint_schema_mismatch",
      `Checkpoint schemaVersion is "${String(checkpoint.schemaVersion)}"; expected "${CHECKPOINT_SCHEMA_VERSION}".`
    );
  }
  // Migrate a legacy witness.url -> baseUrl here too (issue #227):
  // resumeFromPackage reads the on-disk checkpoint and reaches this
  // function without passing through assertCheckpointShape, and
  // resumeSession may be handed a pre-built object directly. This is
  // the common chokepoint, so the migration covers every resume route.
  normalizeCheckpointWitness(checkpoint as unknown as { witness?: unknown });
  if (keypair.publicKeyPem.trim() !== checkpoint.agent.agentPublicKey.trim()) {
    throw new ResumeError(
      "keypair_mismatch",
      "Supplied agent keypair does not match the checkpoint's recorded agent public key."
    );
  }

  const writer = createPackageWriter(checkpoint.packageDirectory);
  if (await writer.envelopeExists()) {
    throw new ResumeError(
      "session_already_finalized",
      `Cannot resume: receipt.json already exists at ${writer.directory}. The session is finalized; produce a new chain instead.`
    );
  }
  await writer.attachExisting();

  const actionsOnDisk = await writer.readActions();
  const attestations = await writer.readAttestations();
  const expectedActions =
    checkpoint.chain.sequenceNext - checkpoint.chain.sequenceStart;
  if (actionsOnDisk.length !== expectedActions) {
    throw new ResumeError(
      "checkpoint_disk_mismatch",
      `Checkpoint expects ${expectedActions} action(s) on disk but found ${actionsOnDisk.length} in actions.jsonl.`
    );
  }
  if (attestations.length !== expectedActions) {
    throw new ResumeError(
      "attestation_disk_mismatch",
      `Checkpoint expects ${expectedActions} attestation entries on disk but found ${attestations.length}.`
    );
  }

  const evidenceByActionId = await loadEvidenceByActionId(writer.directory, actionsOnDisk);

  const state = new SessionState({
    chainId: checkpoint.chainId,
    receiptId: checkpoint.receiptId,
    agentId: checkpoint.agent.agentId,
    agentPublicKeyPem: checkpoint.agent.agentPublicKey,
    taskId: checkpoint.task.taskId,
    delegatorId: checkpoint.task.delegatorId,
    delegatedAt: checkpoint.task.delegatedAt,
    policyContextHash: checkpoint.task.policyContextHash,
    mode: checkpoint.mode,
    initialChainState: checkpoint.chain.initialChainState,
    sequenceStart: checkpoint.chain.sequenceStart,
    schemaReferences: checkpoint.schemaReferences
  });

  let currentChainState = checkpoint.chain.initialChainState;
  for (let i = 0; i < actionsOnDisk.length; i++) {
    const action = actionsOnDisk[i];
    const attestation = attestations.find((a) => a.sequence === action.sequence);
    if (!attestation) {
      throw new ResumeError(
        "attestation_missing",
        `No attestation line found for action sequence ${action.sequence}.`
      );
    }
    const evidence = evidenceByActionId.get(action.action_id);
    if (!evidence) {
      throw new ResumeError(
        "evidence_missing",
        `Evidence for action ${action.action_id} (sequence ${action.sequence}) is missing from the package directory.`
      );
    }
    validateActionChain(action, currentChainState, i, checkpoint.chain.sequenceStart, checkpoint);
    const computedEvidenceHash = hashCanonical(evidence);
    if (computedEvidenceHash !== action.evidence_hash) {
      throw new ResumeError(
        "evidence_hash_mismatch",
        `Evidence for action ${action.action_id} no longer hashes to the recorded value. The package has been tampered with after recording.`,
        { action_id: action.action_id, sequence: action.sequence }
      );
    }
    const computedActionHash = hashCanonical(action);
    const nextChainState = extendChain({
      chainId: action.chain_id,
      sequence: action.sequence,
      previousChainState: currentChainState,
      actionRecordHash: computedActionHash
    });
    validateAttestation(
      attestation,
      action,
      computedActionHash,
      currentChainState,
      nextChainState,
      checkpoint
    );
    state.appendAction({
      action,
      actionRecordHash: computedActionHash,
      nextChainState,
      agentAttestation: attestation.agent,
      witnessAttestation: attestation.witness,
      // Resume only happens in direct mode (managed mode rejects
      // resume entirely; see src/sdk/index.ts). Direct mode never
      // sends evidence content to Sequesign, so the custody value
      // matches the live direct-mode session in src/sdk/session.ts.
      evidenceReference: {
        action_id: action.action_id,
        evidence_hash: action.evidence_hash,
        evidence_path: evidenceRelativePath(action, evidenceByActionId),
        mime_type: "application/json",
        evidence_custody: "external_client_managed" as const
      }
    });
    currentChainState = nextChainState;
  }

  if (currentChainState !== checkpoint.chain.currentChainState) {
    throw new ResumeError(
      "chain_state_mismatch",
      `Recomputed chain state does not match the checkpoint: expected ${checkpoint.chain.currentChainState}, computed ${currentChainState}.`
    );
  }

  const witnessConfig = resolveWitnessConfig(
    {
      ...options.witness,
      baseUrl: options.witness?.baseUrl ?? checkpoint.witness.baseUrl,
      witnessId: options.witness?.witnessId ?? checkpoint.witness.witnessId
    },
    sdkWitnessDefaults
  );
  const witness = await connectWitness(witnessConfig);

  await writer.writeKeyFiles({
    agentPublicKeyPem: state.agentPublicKeyPem,
    witnessIdentity: witness.currentKey
  });

  const session = new SessionImpl(keypair.privateKeyPem, state, writer, witness);
  await session.persistCheckpoint();
  return session;
}

export interface ResumeFromPackageArgs {
  packageDirectory: string;
  keypair: KeyMaterial;
  options: ResumeOptions;
  sdkWitnessDefaults: WitnessConfig | undefined;
}

export async function resumeFromPackageImpl(args: ResumeFromPackageArgs): Promise<Session> {
  const writer = createPackageWriter(args.packageDirectory);
  if (await writer.envelopeExists()) {
    throw new ResumeError(
      "session_already_finalized",
      `Cannot resume from package: receipt.json already exists at ${args.packageDirectory}. The session is finalized.`
    );
  }
  const checkpoint = await writer.readCheckpoint();
  if (!checkpoint) {
    throw new ResumeError(
      "checkpoint_not_found",
      `No on-disk checkpoint at ${args.packageDirectory}/.in-progress/checkpoint.json. Cannot resume from package without it.`
    );
  }
  if (checkpoint.packageDirectory !== args.packageDirectory) {
    checkpoint.packageDirectory = args.packageDirectory;
  }
  return resumeSessionImpl({
    checkpoint,
    keypair: args.keypair,
    options: args.options,
    sdkWitnessDefaults: args.sdkWitnessDefaults
  });
}

async function loadEvidenceByActionId(
  packageDirectory: string,
  actions: ActionRecord[]
): Promise<Map<string, EvidenceBlob>> {
  const map = new Map<string, EvidenceBlob>();
  for (const action of actions) {
    const filename = evidenceFilenameForAction(action);
    const filePath = path.join(packageDirectory, "evidence", filename);
    try {
      const blob = await readJson<EvidenceBlob>(filePath);
      map.set(action.action_id, blob);
    } catch (err) {
      const fallback = path.join(
        packageDirectory,
        "evidence",
        `${action.action_id}.json`
      );
      try {
        const blob = await readJson<EvidenceBlob>(fallback);
        map.set(action.action_id, blob);
      } catch {
        throw new ResumeError(
          "evidence_unreadable",
          `Could not read evidence for action ${action.action_id} from ${filePath} or ${fallback}.`,
          err
        );
      }
    }
  }
  return map;
}

function evidenceFilenameForAction(action: ActionRecord): string {
  const padded = String(action.sequence).padStart(3, "0");
  const safeType = action.action_type.replaceAll("_", "-");
  return `action-${padded}-${safeType}.json`;
}

function evidenceRelativePath(
  action: ActionRecord,
  _evidenceByActionId: Map<string, EvidenceBlob>
): string {
  return `evidence/${evidenceFilenameForAction(action)}`;
}

function validateActionChain(
  action: ActionRecord,
  currentChainState: string,
  index: number,
  sequenceStart: number,
  checkpoint: SessionCheckpoint
): void {
  const expectedSequence = sequenceStart + index;
  if (action.sequence !== expectedSequence) {
    throw new ResumeError(
      "sequence_mismatch",
      `Action at position ${index} declares sequence ${action.sequence}; expected ${expectedSequence}.`
    );
  }
  if (action.previous_chain_state !== currentChainState) {
    throw new ResumeError(
      "previous_chain_state_mismatch",
      `Action at sequence ${action.sequence} declares previous_chain_state ${action.previous_chain_state}; chain walk produced ${currentChainState}.`
    );
  }
  // PR 15-A.1 (finding #11): bind the action's chain, actor, and task
  // fields to the checkpoint. Without this, a tampered actions.jsonl
  // could resume a chain under a different agent identity, chain, or
  // task than the checkpoint records, while still passing the sequence
  // and chain-state walk.
  if (action.chain_id !== checkpoint.chainId) {
    throw new ResumeError(
      "action_chain_id_mismatch",
      `Action at sequence ${action.sequence} declares chain_id ${action.chain_id}; checkpoint chain is ${checkpoint.chainId}.`
    );
  }
  if (action.actor.agent_id !== checkpoint.agent.agentId) {
    throw new ResumeError(
      "action_chain_actor_mismatch",
      `Action at sequence ${action.sequence} declares actor agent_id ${action.actor.agent_id}; checkpoint agent is ${checkpoint.agent.agentId}.`
    );
  }
  if (action.actor.agent_public_key.trim() !== checkpoint.agent.agentPublicKey.trim()) {
    throw new ResumeError(
      "action_chain_actor_mismatch",
      `Action at sequence ${action.sequence} declares an actor agent_public_key that does not match the checkpoint's agent public key.`
    );
  }
  if (action.task.task_id !== checkpoint.task.taskId) {
    throw new ResumeError(
      "action_chain_task_mismatch",
      `Action at sequence ${action.sequence} declares task_id ${action.task.task_id}; checkpoint task is ${checkpoint.task.taskId}.`
    );
  }
  if (action.task.delegator_id !== checkpoint.task.delegatorId) {
    throw new ResumeError(
      "action_chain_task_mismatch",
      `Action at sequence ${action.sequence} declares delegator_id ${action.task.delegator_id}; checkpoint delegator is ${checkpoint.task.delegatorId}.`
    );
  }
}

function validateAttestation(
  attestation: AttestationLine,
  action: ActionRecord,
  actionRecordHash: string,
  previousChainState: string,
  nextChainState: string,
  checkpoint: SessionCheckpoint
): void {
  // PR 15-A.1 (finding #11): bind the agent attestation's identity and
  // action fields to the checkpoint and the recomputed action before
  // trusting its signature. This mirrors the verifier's
  // agent_attestation_binding_mismatch checks: a persisted attestation
  // signed by the wrong key, or carrying the wrong agent_id / chain_id /
  // sequence, must not resume even if its own signature verifies.
  if (attestation.agent.agent_public_key.trim() !== checkpoint.agent.agentPublicKey.trim()) {
    throw new ResumeError(
      "attestation_agent_key_mismatch",
      `Agent attestation at sequence ${attestation.sequence} carries an agent_public_key that does not match the checkpoint's agent public key.`
    );
  }
  if (attestation.agent.agent_id !== checkpoint.agent.agentId) {
    throw new ResumeError(
      "attestation_agent_id_mismatch",
      `Agent attestation at sequence ${attestation.sequence} carries agent_id ${attestation.agent.agent_id}; checkpoint agent is ${checkpoint.agent.agentId}.`
    );
  }
  if (attestation.agent.chain_id !== action.chain_id) {
    throw new ResumeError(
      "attestation_agent_chain_id_mismatch",
      `Agent attestation at sequence ${attestation.sequence} carries chain_id ${attestation.agent.chain_id}; action chain_id is ${action.chain_id}.`
    );
  }
  if (attestation.agent.sequence !== action.sequence) {
    throw new ResumeError(
      "attestation_agent_sequence_mismatch",
      `Agent attestation declares sequence ${attestation.agent.sequence}; action sequence is ${action.sequence}.`
    );
  }
  if (attestation.agent.action_record_hash !== actionRecordHash) {
    throw new ResumeError(
      "agent_attestation_mismatch",
      `Agent attestation at sequence ${attestation.sequence} commits to a different action_record_hash than the recomputed value.`
    );
  }
  if (attestation.agent.chain_state !== nextChainState) {
    throw new ResumeError(
      "agent_attestation_chain_state_mismatch",
      `Agent attestation at sequence ${attestation.sequence} commits to chain state ${attestation.agent.chain_state}; chain walk produced ${nextChainState}.`
    );
  }
  const agentMessage = agentAttestationMessage({
    chainId: attestation.agent.chain_id,
    sequence: attestation.agent.sequence,
    actionRecordHash: attestation.agent.action_record_hash,
    chainState: attestation.agent.chain_state
  });
  if (!verifyEd25519(attestation.agent.agent_public_key, agentMessage, attestation.agent.signature)) {
    throw new ResumeError(
      "agent_signature_invalid",
      `Agent signature for action ${action.action_id} (sequence ${attestation.sequence}) did not verify against the recorded public key.`
    );
  }

  if (attestation.witness.chain_id !== action.chain_id) {
    throw new ResumeError(
      "attestation_witness_chain_id_mismatch",
      `Witness attestation at sequence ${attestation.sequence} carries chain_id ${attestation.witness.chain_id}; action chain_id is ${action.chain_id}.`
    );
  }
  if (attestation.witness.action_record_hash !== actionRecordHash) {
    throw new ResumeError(
      "attestation_witness_action_record_hash_mismatch",
      `Witness attestation at sequence ${attestation.sequence} commits to a different action_record_hash than the recomputed value.`
    );
  }
  if (attestation.witness.sequence !== action.sequence) {
    throw new ResumeError(
      "attestation_witness_sequence_mismatch",
      `Witness attestation declares sequence ${attestation.witness.sequence}; action sequence is ${action.sequence}.`
    );
  }
  if (attestation.witness.previous_chain_state !== previousChainState) {
    throw new ResumeError(
      "witness_attestation_previous_chain_state_mismatch",
      `Witness attestation at sequence ${attestation.sequence} commits to previous_chain_state ${attestation.witness.previous_chain_state}; chain walk produced ${previousChainState}.`
    );
  }
  if (attestation.witness.chain_state !== nextChainState) {
    throw new ResumeError(
      "witness_attestation_chain_state_mismatch",
      `Witness attestation at sequence ${attestation.sequence} commits to chain state ${attestation.witness.chain_state}; chain walk produced ${nextChainState}.`
    );
  }
  const witnessMessage = witnessAttestationMessage({
    witnessId: attestation.witness.witness_id,
    chainId: attestation.witness.chain_id,
    sequence: attestation.witness.sequence,
    actionRecordHash: attestation.witness.action_record_hash,
    previousChainState: attestation.witness.previous_chain_state,
    chainState: attestation.witness.chain_state,
    witnessedAt: attestation.witness.witnessed_at
  });
  if (
    !verifyEd25519(
      attestation.witness.witness_public_key,
      witnessMessage,
      attestation.witness.signature
    )
  ) {
    throw new ResumeError(
      "witness_signature_invalid",
      `Witness signature for action ${action.action_id} (sequence ${attestation.sequence}) did not verify against the embedded witness public key.`
    );
  }
}

