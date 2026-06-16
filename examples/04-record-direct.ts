/**
 * Example 04 — Record an action in DIRECT mode (no broker).
 *
 * Direct mode: the SDK canonicalizes and signs locally and talks to the witness
 * DIRECTLY — there is no broker and no managed storage. The witness sees only
 * the commitment hashes (not your evidence), co-signs, and YOU assemble and hold
 * the receipt package. Compare with example 02 (managed), where the broker calls
 * the witness, assembles, and stores for you.
 *
 * What you'll see:
 *   - one action signed locally and witnessed via POST /witness;
 *   - the receipt package assembled on YOUR machine and verified offline.
 *
 * Prerequisites:
 *   SEQUESIGN_AGENT_PRIVATE_KEY  the agent Ed25519 PEM you record under
 *   SEQUESIGN_API_KEY            the witness requires a write-class key (billing
 *                                / abuse control); passed to the witness only
 *
 * Run:
 *   npx tsx examples/04-record-direct.ts
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import path from "node:path";

import { createSequesign } from "@sequesign/sdk";
import type { KeyMaterial } from "@sequesign/sdk";
import {
  verifyReceiptPackage,
  selfTrustedWitnessKeysFromPackage,
  printVerificationReport
} from "@sequesign/sdk/verify";

const WITNESS_URL = process.env.SEQUESIGN_WITNESS_URL ?? "https://witness.sequesign.com";
const PACKAGE_DIR = path.resolve("out", "example-04.sequesign");

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

async function main(): Promise<void> {
  const keypair = loadAgentKeypair();
  const apiKey = process.env.SEQUESIGN_API_KEY;

  // Direct mode: no broker, no tier — just the witness endpoint. The agent
  // signs locally and the SDK posts the commitment to POST /witness.
  const sdk = createSequesign({
    mode: "direct",
    witness: { baseUrl: WITNESS_URL, apiKey }
  });

  const session = await sdk.startSession({
    agent: { agentId: "example-agent", keypair },
    task: { taskId: `example-direct-${Date.now()}`, delegatorId: "example-operator" },
    mode: "freeform",
    package: { directory: PACKAGE_DIR, ifExists: "reset" }
  });

  console.log(`Recording one action; signing locally and witnessing via ${WITNESS_URL}/witness...`);
  await session.recordAction({
    actionType: "policy_checked",
    evidence: { decision: "approved", reason: "within limit", amount_usd: 100 }
  });

  const result = await session.finalize();
  console.log(`Receipt assembled locally: ${result.receipt.receipt_id}`);
  console.log(`Package: ${PACKAGE_DIR}`);

  const trustedWitnessKeys = await selfTrustedWitnessKeysFromPackage(PACKAGE_DIR);
  const report = await verifyReceiptPackage(PACKAGE_DIR, {
    trustedWitnessKeys,
    trustAnchorMode: "self"
  });

  console.log("");
  printVerificationReport(report);
  console.log(
    `\nlevel=${report.verification_level}  witnessed=${report.flags.witnessed}  ` +
      `agent_identity=${report.agent_identity?.kind}`
  );
  console.log(`\nRe-verify any time:  npx tsx examples/01-verify-offline.ts ${PACKAGE_DIR}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
