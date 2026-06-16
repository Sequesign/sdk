#!/usr/bin/env node
// `sequesign` CLI — the non-SDK signing-core helper over a process boundary
// (design: docs/managed-mode-curl-helper-design.md). Reads a JSON request on
// stdin, writes a JSON result on stdout, so a caller in any language drives it
// the way it drives curl. Lives under src/sdk/ so the mirror compiles it to
// dist/sdk/cli.js (see scripts/sync-sdk.ts ENTRY_POINTS + the package bin).
//
//   sequesign prepare  < request.json              # Variant A (no key)
//   sequesign sign --key agent.key.pem < req.json  # Variant B (signs locally)
//   sequesign assemble-finalize --session s.json --actions a.ndjson  # managed
//   sequesign assemble-receipt  --session s.json --actions a.ndjson --out dir
//
// Managed mode POSTs `request_body` to the broker (/v1/receipt + finalize).
// Direct mode POSTs `witness_request` (commitment hashes only) to the witness's
// /witness endpoint, then assemble-receipt writes the verifiable package on disk
// from the signed actions + witness attestations — no broker, agent is custodian.
//
// All wire-facing JSON is snake_case (matching the /v1 contract); this module is
// the only place that maps between that and the camelCase prepare() API.

import { mkdir, readFile, rm } from "node:fs/promises";

import {
  prepare,
  sign,
  assembleFinalize,
  PrepareError,
  type PrepareInput,
  type PrepareResult,
  type SessionHeader,
  type FinalizeActionInput
} from "./prepare.js";
import { createPackageWriter, evidenceFilename } from "./package-writer.js";
import type { ActionRecord, EvidenceBlob } from "../lib/types.js";

function fail(code: string, reason: string): never {
  process.stderr.write(JSON.stringify({ error: code, reason }) + "\n");
  process.exit(1);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function parseJson(text: string, what: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (err) {
    fail(
      "bad_request",
      `${what} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("bad_request", `${what} must be a JSON object.`);
  }
  return value as Record<string, unknown>;
}

function flag(argv: string[], name: string): string | undefined {
  const i = argv.indexOf(name);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
}

// snake_case stdin request -> camelCase PrepareInput.
function toPrepareInput(o: Record<string, unknown>): PrepareInput {
  const req = (k: string): string => {
    const v = o[k];
    if (typeof v !== "string" || v.length === 0) {
      fail("bad_request", `missing or invalid required string field: ${k}`);
    }
    return v;
  };
  if (typeof o.sequence !== "number" || !Number.isInteger(o.sequence) || o.sequence < 1) {
    fail("bad_request", "sequence must be a positive integer.");
  }
  if (o.evidence === undefined) fail("bad_request", "missing required field: evidence");
  return {
    chainId: req("chain_id"),
    receiptId: req("receipt_id"),
    sequence: o.sequence,
    previousChainState:
      typeof o.previous_chain_state === "string" ? o.previous_chain_state : undefined,
    agentId: req("agent_id"),
    agentPublicKeyPem: req("agent_public_key_pem"),
    taskId: req("task_id"),
    delegatorId: req("delegator_id"),
    delegatedAt: typeof o.delegated_at === "string" ? o.delegated_at : undefined,
    actionType: req("action_type"),
    verifiabilityClass: o.verifiability_class as PrepareInput["verifiabilityClass"],
    policyContextHash:
      typeof o.policy_context_hash === "string" ? o.policy_context_hash : undefined,
    timestamp: typeof o.timestamp === "string" ? o.timestamp : undefined,
    metadata: o.metadata as Record<string, unknown> | undefined,
    schemaId: typeof o.schema_id === "string" ? o.schema_id : undefined,
    schemaHash: typeof o.schema_hash === "string" ? o.schema_hash : undefined,
    evidence: o.evidence,
    evidenceCustody: o.evidence_custody as PrepareInput["evidenceCustody"],
    envelopeCustody: o.envelope_custody as PrepareInput["envelopeCustody"],
    deferEnvelopeStorage:
      typeof o.defer_envelope_storage === "boolean" ? o.defer_envelope_storage : undefined,
    retention: o.retention as PrepareInput["retention"]
  };
}

// PrepareResult -> snake_case stdout (request_body / action_record / etc. are
// already wire-shaped; only the wrapper keys differ).
function fromPrepareResult(r: PrepareResult): Record<string, unknown> {
  return {
    request_body: r.requestBody,
    action_record: r.actionRecord,
    evidence_blob: r.evidenceBlob,
    action_record_hash: r.actionRecordHash,
    chain_state: r.chainState,
    attestation_message_b64: r.attestationMessageB64,
    agent_attestation: r.agentAttestation,
    // Direct mode: POST this verbatim to the witness's /witness endpoint.
    witness_request: r.witnessRequest
  };
}

function toSessionHeader(o: Record<string, unknown>): SessionHeader {
  const agent = o.agent as Record<string, unknown> | undefined;
  const task = o.task as Record<string, unknown> | undefined;
  if (!agent || !task) fail("bad_request", "session must include agent and task objects.");
  return {
    chainId: String(o.chain_id),
    receiptId: String(o.receipt_id),
    receiptMode: o.receipt_mode as SessionHeader["receiptMode"],
    agent: {
      agentId: String(agent.agent_id),
      agentPublicKeyPem: String(agent.agent_public_key)
    },
    task: {
      taskId: String(task.task_id),
      delegatorId: String(task.delegator_id),
      delegatedAt: String(task.delegated_at),
      policyContextHash:
        typeof task.policy_context_hash === "string" ? task.policy_context_hash : undefined
    },
    profile: o.profile as SessionHeader["profile"],
    schemaReferences: o.schema_references as SessionHeader["schemaReferences"],
    retention: o.retention as SessionHeader["retention"],
    evidenceCustody: (o.evidence_custody as SessionHeader["evidenceCustody"]) ?? "both",
    envelopeCustody: (o.envelope_custody as SessionHeader["envelopeCustody"]) ?? "both"
  };
}

function toFinalizeAction(o: Record<string, unknown>): FinalizeActionInput {
  return {
    actionRecord: o.action_record as FinalizeActionInput["actionRecord"],
    evidenceBlob: o.evidence_blob as FinalizeActionInput["evidenceBlob"],
    agentAttestation: o.agent_attestation as FinalizeActionInput["agentAttestation"],
    witnessAttestation: o.witness_attestation as FinalizeActionInput["witnessAttestation"]
  };
}

function out(value: unknown): void {
  process.stdout.write(JSON.stringify(value) + "\n");
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const command = argv[0];

  if (command === "prepare") {
    out(fromPrepareResult(prepare(toPrepareInput(parseJson(await readStdin(), "request")))));
    return;
  }

  if (command === "sign") {
    const raw = parseJson(await readStdin(), "request");
    const input = toPrepareInput(raw);
    // Read the key path from the raw request (snake_case, before conversion);
    // toPrepareInput does not carry it. --key takes precedence.
    const resolvedKeyPath =
      flag(argv, "--key") ??
      (typeof raw.agent_private_key_pem_path === "string"
        ? raw.agent_private_key_pem_path
        : undefined);
    if (!resolvedKeyPath)
      fail(
        "bad_request",
        "sign requires --key <path-to-ed25519-private-key.pem> or agent_private_key_pem_path in the request."
      );
    let pem: string;
    try {
      pem = await readFile(resolvedKeyPath, "utf8");
    } catch (err) {
      fail(
        "key_read_failed",
        `could not read private key at ${resolvedKeyPath}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    out(fromPrepareResult(sign(input, pem)));
    return;
  }

  if (command === "assemble-finalize") {
    const sessionPath = flag(argv, "--session");
    const actionsPath = flag(argv, "--actions");
    if (!sessionPath || !actionsPath) {
      fail(
        "bad_request",
        "assemble-finalize requires --session <session.json> and --actions <actions.ndjson>"
      );
    }
    let sessionText: string;
    let actionsText: string;
    try {
      sessionText = await readFile(sessionPath, "utf8");
      actionsText = await readFile(actionsPath, "utf8");
    } catch (err) {
      fail(
        "bad_request",
        `could not read input file: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    const session = toSessionHeader(parseJson(sessionText, "session"));
    const actions: FinalizeActionInput[] = actionsText
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line, i) => toFinalizeAction(parseJson(line, `actions line ${i + 1}`)));
    const { finalizeBody } = assembleFinalize({ session, actions });
    out(finalizeBody);
    return;
  }

  // Direct mode: assemble a verifiable .sequesign package on disk from the
  // signed actions + the witness attestations returned by POST /witness. There
  // is no broker, so the agent is the assembler and custodian. Reuses the same
  // assembleFinalize() core the managed path uses, then writes the package.
  if (command === "assemble-receipt") {
    const sessionPath = flag(argv, "--session");
    const actionsPath = flag(argv, "--actions");
    const outDir = flag(argv, "--out");
    if (!sessionPath || !actionsPath || !outDir) {
      fail(
        "bad_request",
        "assemble-receipt requires --session <session.json>, --actions <actions.ndjson>, and --out <package-dir>"
      );
    }
    let sessionText: string;
    let actionsText: string;
    try {
      sessionText = await readFile(sessionPath, "utf8");
      actionsText = await readFile(actionsPath, "utf8");
    } catch (err) {
      fail(
        "bad_request",
        `could not read input file: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    const session = toSessionHeader(parseJson(sessionText, "session"));
    const actions: FinalizeActionInput[] = actionsText
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line, i) => toFinalizeAction(parseJson(line, `actions line ${i + 1}`)));
    if (actions.length === 0) fail("bad_request", "actions file contained no action records.");
    const ordered = [...actions].sort((a, b) => a.actionRecord.sequence - b.actionRecord.sequence);

    // localEvidence: a direct package holds the evidence locally and the caller
    // is the custodian, so the receipt's evidence_references point at the local
    // files with external_client_managed custody (not sequesign_hosted).
    const { receipt } = assembleFinalize({ session, actions, localEvidence: true });

    // Reset the package dir first: appendActionLine() appends, so reusing a
    // path from a previous run (curl-direct.sh uses a fixed --out) would leave
    // stale action lines and the verifier would walk extra actions and fail.
    await rm(outDir, { recursive: true, force: true });
    await mkdir(outDir, { recursive: true });
    const writer = createPackageWriter(outDir);
    // Always materialize evidence in the local package. Direct mode is the
    // local-custodian path, so the broker's evidence_custody flag must not
    // suppress it — the verifier loads evidence files for every action.
    for (const a of ordered) {
      if (a.evidenceBlob === undefined) {
        fail(
          "bad_request",
          `action sequence ${a.actionRecord.sequence} is missing evidence_blob; assemble-receipt writes evidence into the local package (direct mode holds evidence locally).`
        );
      }
      await writer.writeEvidence(
        evidenceFilename(a.actionRecord.sequence, a.actionRecord.action_type),
        a.evidenceBlob as EvidenceBlob
      );
      await writer.appendActionLine(a.actionRecord as ActionRecord);
    }
    const firstWitness = ordered[0].witnessAttestation;
    await writer.writeKeyFiles({
      agentPublicKeyPem: session.agent.agentPublicKeyPem,
      witnessIdentity: {
        witnessId: firstWitness.witness_id,
        keyId: firstWitness.witness_key_id,
        publicKeyPem: firstWitness.witness_public_key,
        validFrom: firstWitness.witnessed_at
      },
      approverPublicKeys: [],
      counterpartyPublicKeys: []
    });
    const envelopePath = await writer.writeEnvelope(receipt);
    out({ package_dir: outDir, receipt_id: receipt.receipt_id, envelope_path: envelopePath });
    return;
  }

  fail(
    "bad_request",
    `usage: sequesign <prepare|sign|assemble-finalize|assemble-receipt> [...]\n` +
      `  prepare                                          < request.json\n` +
      `  sign --key K.pem                                 < request.json\n` +
      `  assemble-finalize --session s.json --actions a.ndjson\n` +
      `  assemble-receipt  --session s.json --actions a.ndjson --out dir`
  );
}

main().catch((err) => {
  if (err instanceof PrepareError) fail(err.code, err.message);
  fail("internal_error", err instanceof Error ? err.message : String(err));
});
