/**
 * Example 02 — Record an action in managed mode, then verify it offline.
 *
 * Managed mode: the SDK signs an action with YOUR registered agent key and
 * routes it through the Sequesign broker, which has its witness co-sign it. You
 * get back a receipt carrying a witness attestation and — because the key is
 * registered to your API key — an agent_identity_attestation binding the work
 * to your agent. This script then verifies that receipt offline.
 *
 * What you'll see:
 *   - one action recorded under your registered agent, witnessed by the broker,
 *     and finalized into a receipt package on disk;
 *   - the same package verified locally, printing verification level
 *     L2_IDENTITY_BOUND (witnessed AND bound to your registered identity).
 *
 * Prerequisites (the real, everyday setup — no keys are generated here):
 *   SEQUESIGN_API_KEY            a write-class API key (dashboard.sequesign.com)
 *   SEQUESIGN_AGENT_PRIVATE_KEY  the Ed25519 PEM your API key is registered to
 *
 * Run:
 *   npx tsx examples/02-record-managed.ts
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

import { createSequesign } from "@sequesign/sdk";
import type { KeyMaterial } from "@sequesign/sdk";
import {
  verifyReceiptPackage,
  selfTrustedWitnessKeysFromPackage,
  printVerificationReport
} from "@sequesign/sdk/verify";

const BROKER_URL = process.env.SEQUESIGN_BROKER_URL ?? "https://broker.sequesign.com";
const PACKAGE_DIR = path.resolve("out", "example-02.sequesign");

// Load your registered agent key. This is the key your API key is registered
// to — the same one you use in production, not a throwaway.
function loadAgentKeypair(): KeyMaterial {
  const pem = process.env.SEQUESIGN_AGENT_PRIVATE_KEY;
  if (!pem || !pem.includes("PRIVATE KEY")) {
    throw new Error(
      "SEQUESIGN_AGENT_PRIVATE_KEY is not set. Use the Ed25519 PEM your API key is registered to."
    );
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
  const apiKey = process.env.SEQUESIGN_API_KEY;
  if (!apiKey) {
    console.error(
      "SEQUESIGN_API_KEY is not set. Create a write-class API key at dashboard.sequesign.com."
    );
    process.exit(1);
  }
  const keypair = loadAgentKeypair();

  const sdk = createSequesign({
    mode: "managed",
    tier: "hosted",
    broker: { baseUrl: BROKER_URL, apiKey }
  });

  const session = await sdk.startSession({
    agent: { agentId: "example-agent", keypair },
    task: { taskId: `example-${Date.now()}`, delegatorId: "example-operator" },
    mode: "freeform",
    package: { directory: PACKAGE_DIR, ifExists: "reset" }
  });

  console.log(`Recording one action against ${BROKER_URL}; the witness will co-sign it...`);
  await session.recordAction({
    actionType: "policy_checked",
    evidence: { decision: "approved", reason: "within limit", amount_usd: 100 }
  });

  const result = await session.finalize();
  console.log(`Receipt sealed: ${result.receipt.receipt_id}`);
  console.log(`Package:        ${PACKAGE_DIR}`);

  // The broker stamps agent_identity_attestation into the STORED receipt at
  // /v1/receipts/finalize — it is not in the SDK-built local envelope. So fetch
  // the authoritative broker-stored receipt and overwrite the local one before
  // verifying, or the L2 check below would see "unregistered" even for a
  // correctly registered key.
  if (!result.receiptUrl) {
    console.error(
      "finalize returned no receipt_url, so the broker did not store the envelope " +
        "(expected on the hosted tier). Cannot demonstrate the registered-identity binding."
    );
    process.exit(1);
  }
  console.log(`Stored at:      ${result.receiptUrl} (fetching the authoritative copy)`);
  const stored = await fetch(result.receiptUrl, { headers: { authorization: `Bearer ${apiKey}` } });
  if (!stored.ok) {
    console.error(`GET of the stored receipt failed: HTTP ${stored.status}.`);
    process.exit(1);
  }
  await writeFile(result.envelopePath, JSON.stringify(await stored.json(), null, 2));

  // Verify the broker-stored receipt offline against the witness key embedded
  // in the package.
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

  // This example advertises L2_IDENTITY_BOUND. The broker still accepts a
  // write-class key that is NOT registered to this agent PEM — it just omits
  // the agent_identity_attestation, yielding a valid but lower-level receipt.
  // Fail loudly in that case so the example never claims success without
  // actually demonstrating the registered-identity binding.
  if (!report.valid || report.agent_identity?.kind !== "registered") {
    console.error(
      `\nExpected an identity-bound receipt (L2), got level=${report.verification_level}, ` +
        `agent_identity=${report.agent_identity?.kind}. Use a write-class API key that is ` +
        "REGISTERED to the public key of SEQUESIGN_AGENT_PRIVATE_KEY (dashboard.sequesign.com → API Keys)."
    );
    process.exit(1);
  }

  console.log(`\nRe-verify any time:  npx tsx examples/01-verify-offline.ts ${PACKAGE_DIR}`);
  console.log("Or drag the package folder into https://verify.sequesign.com");
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
