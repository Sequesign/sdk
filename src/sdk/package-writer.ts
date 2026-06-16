import path from "node:path";
import { appendFile, readFile, rm } from "node:fs/promises";
import {
  ensureDir,
  readJson,
  readJsonl,
  resetDir,
  writeJson,
  writeJsonl,
  writeText
} from "../lib/io.js";
import type {
  ActionRecord,
  AgentActionReceipt,
  AgentAttestation,
  AttestationSatellite,
  EvidenceBlob,
  WitnessAttestation
} from "../lib/types.js";
import { isAttestationSatellite } from "../lib/verify.js";
import type { WitnessIdentity } from "./key-discovery.js";
import { PackageStateError } from "./errors.js";
import type { SessionCheckpoint } from "./types.js";
import {
  ACTIONS_FILE,
  AGENT_KEY_FILE,
  APPROVER_KEYS_SUBDIR,
  COUNTERPARTY_KEYS_SUBDIR,
  KEYS_DIR,
  WITNESS_KEY_FILE,
  isCanonicalCounterpartyId,
  isValidApproverId,
  publicKeyFilename
} from "../lib/package-layout.js";

export interface AttestationLine {
  sequence: number;
  agent: AgentAttestation;
  witness: WitnessAttestation;
}

export interface PackageWriter {
  readonly directory: string;
  initialize(reset: boolean): Promise<void>;
  attachExisting(): Promise<void>;
  writeEvidence(filename: string, evidence: EvidenceBlob): Promise<string>;
  appendActionLine(action: ActionRecord): Promise<void>;
  appendAttestationLine(line: AttestationLine): Promise<void>;
  writeCheckpoint(checkpoint: SessionCheckpoint): Promise<string>;
  readAttestations(): Promise<AttestationLine[]>;
  // v0.6 step #3b.3: the TOP-LEVEL deferred-satellite sidecar
  // (packageDir/attestations.jsonl), distinct from the per-action draft
  // attestation file above (.in-progress/attestations.jsonl). This is the
  // file the offline verifier's loadSatellites reads. appendSatelliteLine
  // appends one sealed satellite; readSatellites reads the whole sidecar
  // (used for the dedup guard before append).
  appendSatelliteLine(satellite: AttestationSatellite): Promise<void>;
  readSatellites(): Promise<AttestationSatellite[]>;
  readCheckpoint(): Promise<SessionCheckpoint | null>;
  readActions(): Promise<ActionRecord[]>;
  envelopeExists(): Promise<boolean>;
  writeEnvelope(receipt: AgentActionReceipt): Promise<string>;
  writeDraftEnvelope(receipt: AgentActionReceipt): Promise<string>;
  cleanupDraft(): Promise<void>;
  writeKeyFiles(args: WriteKeyFilesArgs): Promise<void>;
  writeVerificationReport(report: unknown): Promise<string>;
  envelopePath(): string;
  actionsPath(): string;
  draftEnvelopePath(): string;
}

export interface CounterpartyPublicKey {
  counterpartyId: string;
  publicKeyPem: string;
}

export interface ApproverPublicKey {
  approverId: string;
  publicKeyPem: string;
}

export interface WriteKeyFilesArgs {
  agentPublicKeyPem: string;
  witnessIdentity?: WitnessIdentity;
  approverPublicKeys?: ApproverPublicKey[];
  counterpartyPublicKeys?: CounterpartyPublicKey[];
}

export function createPackageWriter(directory: string): PackageWriter {
  const evidenceDir = path.join(directory, "evidence");
  const keysDir = path.join(directory, KEYS_DIR);
  const envelopePath = path.join(directory, "receipt.json");
  const actionsPath = path.join(directory, ACTIONS_FILE);
  const draftDir = path.join(directory, ".in-progress");
  const draftEnvelopePath = path.join(draftDir, "receipt.json");
  const attestationsPath = path.join(draftDir, "attestations.jsonl");
  const checkpointPath = path.join(draftDir, "checkpoint.json");
  // Top-level deferred-satellite sidecar (post-finalize). The verifier's
  // loadSatellites reads exactly this path; it is NOT under .in-progress/,
  // so cleanupDraft does not remove it.
  const satellitesPath = path.join(directory, "attestations.jsonl");

  async function fileExists(filePath: string): Promise<boolean> {
    try {
      await readJson(filePath);
      return true;
    } catch {
      return false;
    }
  }

  return {
    directory,
    async initialize(reset: boolean) {
      if (reset) {
        await resetDir(directory);
      } else {
        await ensureDir(directory);
      }
      await ensureDir(evidenceDir);
      await ensureDir(keysDir);
      await ensureDir(draftDir);
    },
    async attachExisting() {
      await ensureDir(draftDir);
    },
    async writeEvidence(filename: string, evidence: EvidenceBlob): Promise<string> {
      if (filename.includes("..") || path.isAbsolute(filename)) {
        throw new PackageStateError(`Invalid evidence filename: ${filename}`);
      }
      const filePath = path.join(evidenceDir, filename);
      await writeJson(filePath, evidence);
      return filePath;
    },
    async appendActionLine(action: ActionRecord) {
      await ensureDir(directory);
      await appendFile(actionsPath, JSON.stringify(action) + "\n", "utf8");
    },
    async appendAttestationLine(line: AttestationLine) {
      await ensureDir(draftDir);
      await appendFile(attestationsPath, JSON.stringify(line) + "\n", "utf8");
    },
    async writeCheckpoint(checkpoint: SessionCheckpoint): Promise<string> {
      await ensureDir(draftDir);
      await writeJson(checkpointPath, checkpoint);
      return checkpointPath;
    },
    async readAttestations(): Promise<AttestationLine[]> {
      try {
        return await readJsonl<AttestationLine>(attestationsPath);
      } catch {
        return [];
      }
    },
    async appendSatelliteLine(satellite: AttestationSatellite) {
      await ensureDir(directory);
      // Guard against a sidecar whose last line is not newline-terminated
      // (valid JSONL without a trailing newline, or a partial prior write):
      // appending directly would concatenate the new object onto that line and
      // leave BOTH unparseable, so the verifier (which splits on newlines)
      // would silently drop the just-submitted satellite. Prefix a newline when
      // the file is non-empty and does not already end with one.
      let prefix = "";
      try {
        const existing = await readFile(satellitesPath, "utf8");
        if (existing.length > 0 && !existing.endsWith("\n")) prefix = "\n";
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code !== "ENOENT") throw err;
      }
      await appendFile(satellitesPath, prefix + JSON.stringify(satellite) + "\n", "utf8");
    },
    async readSatellites(): Promise<AttestationSatellite[]> {
      // Mirror the offline verifier's loadSatellites: parse the sidecar
      // line-by-line and skip ONLY malformed / non-satellite lines. A
      // whole-file [] (what readJsonl yields here, since it throws on the
      // first bad line) would hide every valid satellite from the pre-seal
      // dedup guard, so a re-submit of an existing id would pass dedup, spend
      // another witness signature, and append a duplicate — whereas the
      // verifier still folds the valid lines in. ENOENT (no sidecar yet) is
      // the normal empty case; any other read error is surfaced.
      let text: string;
      try {
        text = await readFile(satellitesPath, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return [];
        throw err;
      }
      const satellites: AttestationSatellite[] = [];
      for (const line of text.split(/\r?\n/)) {
        if (!line.trim()) continue;
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          continue;
        }
        // Use the verifier's own predicate so the dedup guard counts EXACTLY
        // the lines loadSatellites would fold in — a parseable-but-incomplete
        // line (missing attested_receipt_hash / witness_attestation / required
        // inner fields) is dropped here too, so it never blocks a valid retry.
        if (isAttestationSatellite(parsed)) satellites.push(parsed);
      }
      return satellites;
    },
    async readCheckpoint(): Promise<SessionCheckpoint | null> {
      try {
        return await readJson<SessionCheckpoint>(checkpointPath);
      } catch {
        return null;
      }
    },
    async readActions(): Promise<ActionRecord[]> {
      try {
        return await readJsonl<ActionRecord>(actionsPath);
      } catch {
        return [];
      }
    },
    async envelopeExists(): Promise<boolean> {
      return fileExists(envelopePath);
    },
    async writeEnvelope(receipt: AgentActionReceipt): Promise<string> {
      await writeJson(envelopePath, receipt);
      return envelopePath;
    },
    async writeDraftEnvelope(receipt: AgentActionReceipt): Promise<string> {
      await ensureDir(draftDir);
      await writeJson(draftEnvelopePath, receipt);
      return draftEnvelopePath;
    },
    async cleanupDraft() {
      await rm(draftDir, { recursive: true, force: true });
    },
    async writeKeyFiles(args: WriteKeyFilesArgs) {
      await writeText(path.join(keysDir, AGENT_KEY_FILE), args.agentPublicKeyPem);
      if (args.witnessIdentity) {
        await writeText(path.join(keysDir, WITNESS_KEY_FILE), args.witnessIdentity.publicKeyPem);
      }
      for (const approver of args.approverPublicKeys ?? []) {
        if (!isValidApproverId(approver.approverId)) {
          throw new PackageStateError(
            `Cannot write approver key: approver_id "${approver.approverId}" is not a valid lowercase email or label (letters, digits, ".", "_", "+", "-", optional "@domain").`
          );
        }
        await writeText(
          path.join(keysDir, APPROVER_KEYS_SUBDIR, publicKeyFilename(approver.approverId)),
          approver.publicKeyPem
        );
      }
      for (const counterparty of args.counterpartyPublicKeys ?? []) {
        if (!isCanonicalCounterpartyId(counterparty.counterpartyId)) {
          throw new PackageStateError(
            `Cannot write counterparty key: counterparty_id "${counterparty.counterpartyId}" is not canonical (lowercase alphanumeric segments joined by single dots or hyphens).`
          );
        }
        await writeText(
          path.join(
            keysDir,
            COUNTERPARTY_KEYS_SUBDIR,
            publicKeyFilename(counterparty.counterpartyId)
          ),
          counterparty.publicKeyPem
        );
      }
    },
    async writeVerificationReport(report: unknown): Promise<string> {
      const reportPath = path.join(directory, "verification-report.json");
      await writeJson(reportPath, report);
      return reportPath;
    },
    envelopePath(): string {
      return envelopePath;
    },
    actionsPath(): string {
      return actionsPath;
    },
    draftEnvelopePath(): string {
      return draftEnvelopePath;
    }
  };
}

export function evidenceFilename(sequence: number, actionType: string): string {
  const padded = String(sequence).padStart(3, "0");
  const safeType = actionType.replaceAll("_", "-");
  return `action-${padded}-${safeType}.json`;
}
