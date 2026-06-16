import path from "node:path";
import { agentAttestationMessage, witnessAttestationMessage } from "../lib/messages.js";
import { verifyEd25519 } from "../lib/keys.js";
import { verifyReceiptPackage, witnessKeysFromReceipt } from "../lib/verify.js";
import type { EvidenceBlob } from "../lib/types.js";
import { readJson } from "../lib/io.js";
import { buildReceiptEnvelope } from "./envelope.js";
import type { PackageWriter } from "./package-writer.js";
import { SessionState } from "./state.js";
import type {
  InspectedAction,
  InspectionReport,
  InspectionWarning,
  OutstandingRequirement,
  PartialVerificationReport
} from "./types.js";

export interface BuildInspectionReportArgs {
  state: SessionState;
  writer: PackageWriter;
}

export async function buildInspectionReport(
  args: BuildInspectionReportArgs
): Promise<InspectionReport> {
  const { state, writer } = args;
  const snapshot = state.snapshot();
  const actions = inspectActions(state);
  const outstandingRequirements = computeOutstandingRequirements(state);
  const warnings = await collectInspectionWarnings(state, writer);
  const partialVerification = await runPartialVerification(state, writer);

  return {
    receiptId: state.receiptId,
    chainId: state.chainId,
    receiptMode: state.mode,
    sequenceNext: snapshot.sequenceNext,
    currentChainState: state.currentChainState,
    initialChainState: state.initialChainState,
    finalized: snapshot.finalized,
    actions,
    outstandingRequirements,
    warnings,
    partialVerification
  };
}

function inspectActions(state: SessionState): InspectedAction[] {
  const records = state.actions();
  const hashes = state.actionRecordHashes();
  const agentAtts = state.agentAttestations();
  const witnessAtts = state.witnessAttestations();
  const evidenceRefs = state.evidenceReferences();

  return records.map((record, i) => {
    const actionRecordHash = hashes[i];
    const agentAtt = agentAtts.find((a) => a.sequence === record.sequence);
    const witnessAtt = witnessAtts.find((w) => w.sequence === record.sequence);
    const evidenceRef = evidenceRefs.find((e) => e.action_id === record.action_id);
    const agentSignatureVerified = agentAtt
      ? verifyEd25519(
          agentAtt.agent_public_key,
          agentAttestationMessage({
            chainId: agentAtt.chain_id,
            sequence: agentAtt.sequence,
            actionRecordHash: agentAtt.action_record_hash,
            chainState: agentAtt.chain_state
          }),
          agentAtt.signature
        )
      : false;
    const witnessVerified = witnessAtt
      ? verifyEd25519(
          witnessAtt.witness_public_key,
          witnessAttestationMessage({
            witnessId: witnessAtt.witness_id,
            chainId: witnessAtt.chain_id,
            sequence: witnessAtt.sequence,
            actionRecordHash: witnessAtt.action_record_hash,
            previousChainState: witnessAtt.previous_chain_state,
            chainState: witnessAtt.chain_state,
            witnessedAt: witnessAtt.witnessed_at
          }),
          witnessAtt.signature
        )
      : false;
    return {
      sequence: record.sequence,
      actionType: record.action_type,
      actionId: record.action_id,
      actionRecordHash,
      previousChainState: record.previous_chain_state,
      chainState: witnessAtt?.chain_state ?? agentAtt?.chain_state ?? "",
      verifiabilityClass: record.verifiability_class,
      evidencePath: evidenceRef?.evidence_path ?? `evidence/${record.action_id}.json`,
      witnessVerified,
      agentSignatureVerified,
      recordedAt: record.timestamp
    };
  });
}

function computeOutstandingRequirements(state: SessionState): OutstandingRequirement[] {
  const requirements: OutstandingRequirement[] = [];
  if (state.snapshot().actionsRecorded === 0) {
    requirements.push({
      code: "no_actions_recorded",
      message:
        "The session has not yet recorded any actions. recordAction must be called at least once before finalize."
    });
  }
  return requirements;
}

async function collectInspectionWarnings(
  state: SessionState,
  writer: PackageWriter
): Promise<InspectionWarning[]> {
  const warnings: InspectionWarning[] = [];
  const records = state.actions();
  for (const record of records) {
    const evidencePath = path.join(
      writer.directory,
      "evidence",
      evidenceFilenameForAction(record.action_id, record.action_type, record.sequence)
    );
    let blob: EvidenceBlob | null = null;
    try {
      blob = await readJson<EvidenceBlob>(evidencePath);
    } catch {
      const refs = state.evidenceReferences();
      const ref = refs.find((r) => r.action_id === record.action_id);
      if (ref) {
        try {
          blob = await readJson<EvidenceBlob>(path.join(writer.directory, ref.evidence_path));
        } catch {
          blob = null;
        }
      }
    }
    if (!blob) continue;
    const claims = extractUnsupportedClaims(blob);
    for (const claim of claims) {
      warnings.push({
        code: "unsupported_agent_claim",
        severity: "warning",
        message: `Agent claim "${claim}" lacks external attestation.`,
        action: { sequence: record.sequence, actionType: record.action_type }
      });
    }
  }
  return warnings;
}

function evidenceFilenameForAction(
  _actionId: string,
  actionType: string,
  sequence: number
): string {
  const padded = String(sequence).padStart(3, "0");
  const safeType = actionType.replaceAll("_", "-");
  return `action-${padded}-${safeType}.json`;
}

function extractUnsupportedClaims(blob: EvidenceBlob): string[] {
  const content = blob.content as Record<string, unknown> | undefined;
  if (!content || typeof content !== "object") return [];
  const raw = (content as { unsupported_claims?: unknown }).unsupported_claims;
  if (!Array.isArray(raw)) return [];
  const claims: string[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as { claim?: unknown; external_attestation?: unknown };
    if (typeof e.claim === "string" && e.external_attestation === null) {
      claims.push(e.claim);
    }
  }
  return claims;
}

async function runPartialVerification(
  state: SessionState,
  writer: PackageWriter
): Promise<PartialVerificationReport> {
  if (state.snapshot().actionsRecorded === 0) {
    return {
      available: false,
      reason: "no_actions_recorded"
    };
  }
  // Both branches are integrity self-checks of a package this SDK
  // produced, so they anchor to the witness keys embedded in the
  // session's own attestations (trust_anchor_mode "self"). A third party
  // anchors to the witness's well-known keys instead.
  const envelopeForKeys = buildReceiptEnvelope({
    state,
    finalChainState: state.currentChainState
  });
  const selfTrust = {
    trustedWitnessKeys: witnessKeysFromReceipt(envelopeForKeys),
    trustAnchorMode: "self" as const
  };
  if (state.snapshot().finalized) {
    const report = await verifyReceiptPackage(writer.directory, selfTrust);
    return { available: true, report };
  }
  const draftPath = await writer.writeDraftEnvelope(envelopeForKeys);
  try {
    const report = await verifyReceiptPackage(writer.directory, {
      ...selfTrust,
      envelopePath: draftPath
    });
    return { available: true, report };
  } finally {
    await writer.cleanupDraft();
  }
}

export function formatInspectionReport(report: InspectionReport): string {
  const lines: string[] = [];
  lines.push("Sequesign audit summary");
  lines.push(`  receipt_id        ${report.receiptId}`);
  lines.push(`  chain_id          ${report.chainId}`);
  lines.push(`  receipt_mode      ${report.receiptMode}`);
  lines.push(`  finalized         ${report.finalized ? "yes" : "no"}`);
  lines.push(`  actions_recorded  ${report.actions.length}`);
  lines.push(`  sequence_next     ${report.sequenceNext}`);
  lines.push(`  current_state     ${shortHash(report.currentChainState)}`);
  if (report.actions.length > 0) {
    lines.push("");
    lines.push("Recorded actions:");
    for (const action of report.actions) {
      lines.push(
        `  ${String(action.sequence).padStart(3, "0")} ${action.actionType.padEnd(28)} ` +
          `state=${shortHash(action.chainState)} ` +
          `witness=${flag(action.witnessVerified)} ` +
          `agent=${flag(action.agentSignatureVerified)}`
      );
    }
  }
  if (report.outstandingRequirements.length > 0) {
    lines.push("");
    lines.push("Outstanding requirements:");
    for (const req of report.outstandingRequirements) {
      lines.push(`  ${req.code}: ${req.message}`);
    }
  }
  if (report.warnings.length > 0) {
    lines.push("");
    lines.push("Warnings:");
    for (const w of report.warnings) {
      const where = w.action
        ? ` (sequence=${w.action.sequence}, action=${w.action.actionType})`
        : "";
      lines.push(`  [${w.severity}] ${w.code}: ${w.message}${where}`);
    }
  }
  lines.push("");
  lines.push("Partial verification:");
  if (!report.partialVerification.available) {
    lines.push(`  not available (${report.partialVerification.reason ?? "unknown"})`);
  } else if (report.partialVerification.report) {
    const r = report.partialVerification.report;
    lines.push(`  valid             ${r.valid}`);
    lines.push(`  level             ${r.verification_level}`);
    if (r.reason) lines.push(`  reason            ${r.reason}`);
    lines.push("  flags:");
    for (const [name, value] of Object.entries(r.flags)) {
      lines.push(`    ${name.padEnd(24)} ${formatFlag(value)}`);
    }
    // PR 15-A: agent identity tier. Present on every valid report.
    if (r.agent_identity) {
      lines.push("");
      if (r.agent_identity.kind === "registered") {
        lines.push("  Agent identity: registered");
        lines.push(`    Key fingerprint: ${r.agent_identity.key_fingerprint}`);
        lines.push(`    Registered at:   ${r.agent_identity.registered_at}`);
      } else {
        lines.push("  Agent identity: unregistered");
      }
    }
  }
  return lines.join("\n");
}

function shortHash(value: string): string {
  if (!value) return "(empty)";
  return value.length > 16 ? `${value.slice(0, 12)}...` : value;
}

function flag(value: boolean): string {
  return value ? "PASSED" : "FAILED";
}

function formatFlag(value: boolean | null | string): string {
  if (value === null) return "not requested";
  if (typeof value === "string") return value;
  return value ? "PASSED" : "FAILED";
}
