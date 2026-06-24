/**
 * Example 05 — Record a PROFILE-CONSTRAINED chain (schema + workflow validated).
 *
 * Beyond freeform recording (examples 02 and 04), Sequesign can validate what
 * you record against the registry shipped in this package:
 *   - schema_validated     — each action's evidence must match the registered
 *                            JSON Schema for its actionType;
 *   - profile_constrained  — additionally, the chain must follow a workflow
 *                            profile (allowed/required actions + transitions).
 *
 * This script records the invoice_payment.v0.1 profile end to end in DIRECT
 * mode: task_created -> policy_checked -> llm_invoice_reviewed ->
 * payment_instruction_created. Each action's evidence conforms to its schema
 * and the sequence follows the profile, so the verified receipt reports
 * schema_valid AND workflow_profile_valid.
 *
 * The schema/profile hashes are resolved from the registry via loadProfileById
 * / loadSchemaByActionType — you never hand-compute a hash.
 *
 * Prerequisites (same as example 04):
 *   SEQUESIGN_AGENT_PRIVATE_KEY  the agent Ed25519 PEM you record under
 *   SEQUESIGN_API_KEY            the witness requires a write-class key
 *
 * Run:
 *   npx tsx examples/05-record-profile-constrained.ts
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import path from "node:path";

import {
  createSequesign,
  loadProfileById,
  loadSchemaByActionType
} from "@sequesign/sdk";
import type { KeyMaterial, Session } from "@sequesign/sdk";
import {
  verifyReceiptPackage,
  selfTrustedWitnessKeysFromPackage,
  printVerificationReport
} from "@sequesign/sdk/verify";

const WITNESS_URL = process.env.SEQUESIGN_WITNESS_URL ?? "https://witness.sequesign.com";
const PACKAGE_DIR = path.resolve("out", "example-05.sequesign");
const PROFILE_ID = "sequesign.invoice_payment.v0.1";

function loadAgentKeypair(): KeyMaterial {
  const pem = process.env.SEQUESIGN_AGENT_PRIVATE_KEY;
  if (!pem || !pem.includes("PRIVATE KEY")) {
    throw new Error("SEQUESIGN_AGENT_PRIVATE_KEY is not set to an Ed25519 private key PEM.");
  }
  const priv = createPrivateKey(pem);
  if (priv.asymmetricKeyType !== "ed25519") {
    throw new Error("SEQUESIGN_AGENT_PRIVATE_KEY must be an Ed25519 private key PEM.");
  }
  return {
    privateKeyPem: pem,
    publicKeyPem: createPublicKey(priv).export({ type: "spki", format: "pem" }).toString()
  };
}

// Record one action, attaching the registered schema for its actionType. The
// SDK validates `evidence` against that schema before the action is signed, so
// a non-conforming evidence object throws here rather than producing a receipt
// that fails verification later.
async function recordValidated(
  session: Session,
  actionType: string,
  evidence: Record<string, unknown>
): Promise<void> {
  const schema = await loadSchemaByActionType(actionType);
  if (!schema) throw new Error(`no registered schema for action type "${actionType}"`);
  await session.recordAction({
    actionType,
    evidence,
    schemaId: schema.schemaId,
    schemaHash: schema.schemaHash
  });
  console.log(`  recorded ${actionType} (validated against ${schema.schemaId})`);
}

async function main(): Promise<void> {
  const keypair = loadAgentKeypair();
  const apiKey = process.env.SEQUESIGN_API_KEY;

  // Direct mode: no broker. The agent signs locally; the witness co-signs the
  // commitment hashes; YOU assemble and hold the package (see example 04).
  const sdk = createSequesign({
    mode: "direct",
    witness: { baseUrl: WITNESS_URL, apiKey }
  });

  // Resolve the workflow profile from the bundled registry. The hash binds the
  // receipt to this exact profile definition; the verifier recomputes it.
  const profile = await loadProfileById(PROFILE_ID);
  if (!profile) throw new Error(`no registered profile "${PROFILE_ID}"`);

  const session = await sdk.startSession({
    agent: { agentId: "example-agent", keypair },
    task: { taskId: `example-profile-${Date.now()}`, delegatorId: "finance_team" },
    mode: "profile_constrained",
    profile: { profile_id: profile.profileId, profile_hash: profile.profileHash },
    package: { directory: PACKAGE_DIR, ifExists: "reset" }
  });

  console.log(`Recording the ${PROFILE_ID} chain (schema- and workflow-validated)...`);

  // The required action sequence for this profile. policy_checked is "approved"
  // (the invoice is under the auto-pay limit), so no human_approval_received is
  // required and llm_invoice_reviewed -> payment_instruction_created is a valid
  // transition. (Set decision to "requires_human_approval" and the profile would
  // demand a human_approval_received action before payment.)
  await recordValidated(session, "task_created", {
    task_id: "task_invoice_001",
    description: "Pay invoice INV-4242 from Acme Supplies",
    delegator_id: "finance_team",
    invoice: { invoice_id: "INV-4242", amount_usd: 4200, vendor: "Acme Supplies" }
  });
  await recordValidated(session, "policy_checked", {
    policy_version: "2026-01",
    auto_pay_limit_usd: 5000,
    invoice_amount_usd: 4200,
    decision: "approved",
    reason: "within the $5,000 auto-pay limit"
  });
  await recordValidated(session, "llm_invoice_reviewed", {
    provider: "anthropic",
    model: "claude-opus-4-8",
    invoice_id: "INV-4242",
    prompt: "Review invoice INV-4242 for anomalies before payment.",
    review_summary: "Line items and total match the approved purchase order.",
    concerns: []
  });
  await recordValidated(session, "payment_instruction_created", {
    payment_instruction_id: "pi_001",
    amount_usd: 4200,
    recipient: "Acme Supplies",
    status: "simulated"
  });

  const result = await session.finalize();
  console.log(`\nReceipt assembled locally: ${result.receipt.receipt_id}`);
  console.log(`Package: ${PACKAGE_DIR}`);

  const trustedWitnessKeys = await selfTrustedWitnessKeysFromPackage(PACKAGE_DIR);
  const report = await verifyReceiptPackage(PACKAGE_DIR, {
    trustedWitnessKeys,
    trustAnchorMode: "self"
  });

  console.log("");
  printVerificationReport(report);
  console.log(
    `\nlevel=${report.verification_level}  ` +
      `schema_valid=${report.flags.schema_valid}  ` +
      `workflow_profile_valid=${report.flags.workflow_profile_valid}`
  );
  console.log(`\nRe-verify any time:  npx tsx examples/01-verify-offline.ts ${PACKAGE_DIR}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
