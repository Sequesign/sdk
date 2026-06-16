/**
 * Example 03 — A vouched approval (verified approver identity).
 *
 * A bare approval signature proves only that *some* key signed; it does not
 * prove *whose* key. Vouching closes that gap without giving up offline
 * verification: the approver enrolls its key with the platform, the platform
 * issues a signed registration record, and that record rides inside the
 * approval as a self-contained identity_proof.
 *
 * What you'll see:
 *   - an approver key enrolled (proof-of-possession) → platform identity_proof;
 *   - one action recorded with an approval carrying that proof, finalized;
 *   - the receipt verified TWICE: without the registration anchor the approval
 *     is present_unverified; with it, the approval flips to present_verified
 *     and the approver identity is shown as vouched.
 *
 * Prerequisites:
 *   SEQUESIGN_API_KEY              a write-class API key (dashboard.sequesign.com)
 *   SEQUESIGN_AGENT_PRIVATE_KEY    the agent Ed25519 PEM (registered to the key)
 *   SEQUESIGN_APPROVER_PRIVATE_KEY the approver Ed25519 PEM
 *   SEQUESIGN_APPROVER_ID          the approver identity (e.g. cfo@acme.example)
 *   SEQUESIGN_APPROVER_PARTY_TYPE  optional: "human" (default) or "agent"
 *
 * Run:
 *   npx tsx examples/03-vouch-approval.ts
 */
import { createPrivateKey, createPublicKey } from "node:crypto";
import path from "node:path";

import { createSequesign, registrationChallengeSignature } from "@sequesign/sdk";
import type { KeyMaterial } from "@sequesign/sdk";
import {
  verifyReceiptPackage,
  parseTrustedWitnessKeys,
  parseTrustedRegistrationKeys,
  printVerificationReport
} from "@sequesign/sdk/verify";

const BROKER_URL = process.env.SEQUESIGN_BROKER_URL ?? "https://broker.sequesign.com";
const WITNESS_URL = process.env.SEQUESIGN_WITNESS_URL ?? "https://witness.sequesign.com";
const DASHBOARD_API_URL =
  process.env.SEQUESIGN_DASHBOARD_API_URL ?? "https://dashboard-api.sequesign.com";
const PACKAGE_DIR = path.resolve("out", "example-03.sequesign");
const ACTION_TYPE = "human_approval_received";

function keypairFromPem(label: string, pem: string | undefined): KeyMaterial {
  if (!pem || !pem.includes("PRIVATE KEY")) {
    throw new Error(`${label} is not set to an Ed25519 private key PEM.`);
  }
  const priv = createPrivateKey(pem);
  if (priv.asymmetricKeyType !== "ed25519") {
    throw new Error(`${label} must be an Ed25519 private key.`);
  }
  return {
    privateKeyPem: pem,
    publicKeyPem: createPublicKey(priv).export({ type: "spki", format: "pem" }).toString()
  };
}

async function main(): Promise<void> {
  const apiKey = process.env.SEQUESIGN_API_KEY;
  const approverId = process.env.SEQUESIGN_APPROVER_ID;
  const partyTypeRaw = process.env.SEQUESIGN_APPROVER_PARTY_TYPE ?? "human";
  if (!apiKey || !approverId) {
    console.error(
      "Set SEQUESIGN_API_KEY, SEQUESIGN_AGENT_PRIVATE_KEY, SEQUESIGN_APPROVER_PRIVATE_KEY, and SEQUESIGN_APPROVER_ID."
    );
    process.exit(1);
  }
  if (partyTypeRaw !== "human" && partyTypeRaw !== "agent") {
    console.error(`SEQUESIGN_APPROVER_PARTY_TYPE must be "human" or "agent".`);
    process.exit(1);
  }
  const partyType = partyTypeRaw;
  const agentKeypair = keypairFromPem(
    "SEQUESIGN_AGENT_PRIVATE_KEY",
    process.env.SEQUESIGN_AGENT_PRIVATE_KEY
  );
  const approverKeypair = keypairFromPem(
    "SEQUESIGN_APPROVER_PRIVATE_KEY",
    process.env.SEQUESIGN_APPROVER_PRIVATE_KEY
  );

  // 1. Enroll the approver key: sign the proof-of-possession challenge with the
  //    approver's OWN key, POST it, and receive a platform-signed identity_proof.
  console.log(
    `Enrolling approver "${approverId}" (${partyType}) at ${DASHBOARD_API_URL}/registrations...`
  );
  const subjectSignature = registrationChallengeSignature({
    role: "approver",
    partyType,
    identity: approverId,
    subjectPublicKeyPem: approverKeypair.publicKeyPem,
    subjectPrivateKeyPem: approverKeypair.privateKeyPem
  });
  const enrollRes = await fetch(`${DASHBOARD_API_URL}/registrations`, {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      role: "approver",
      party_type: partyType,
      identity: approverId,
      public_key: approverKeypair.publicKeyPem,
      subject_signature: subjectSignature
    })
  });
  const enrollBody = (await enrollRes.json()) as {
    identity_proof?: { issuer?: string; ref?: string };
  };
  if (
    !enrollRes.ok ||
    enrollBody.identity_proof?.issuer !== "sequesign" ||
    !enrollBody.identity_proof.ref
  ) {
    console.error(`Enrollment failed (HTTP ${enrollRes.status}): ${JSON.stringify(enrollBody)}`);
    process.exit(1);
  }
  const identityProof = { issuer: "sequesign" as const, ref: enrollBody.identity_proof.ref };
  console.log("Enrolled; received a platform-signed identity_proof.");

  // 2. Record one action + an approval that carries the identity_proof.
  const sdk = createSequesign({
    mode: "managed",
    tier: "hosted",
    broker: { baseUrl: BROKER_URL, apiKey }
  });
  const session = await sdk.startSession({
    agent: { agentId: "example-vouch-agent", keypair: agentKeypair },
    task: { taskId: `example-vouch-${Date.now()}`, delegatorId: "example-operator" },
    mode: "freeform",
    package: { directory: PACKAGE_DIR, ifExists: "reset" }
  });
  await session.recordAction({
    actionType: ACTION_TYPE,
    evidence: { summary: "Example: one approved action.", amount_usd: 100 },
    verifiabilityClass: "human_signed"
  });
  await session.recordApproval({
    mode: "sign_locally",
    approverId,
    partyType,
    approverKeypair,
    approvedActionType: ACTION_TYPE,
    approvalContext: { note: "Example vouched approval." },
    identityProof
  });
  const result = await session.finalize();
  console.log(`Receipt sealed: ${result.receipt.receipt_id}\nPackage: ${PACKAGE_DIR}`);

  // 3. Fetch trust anchors: published witness keys + the platform registration key.
  const witnessKeys = parseTrustedWitnessKeys(
    await (await fetch(`${WITNESS_URL}/.well-known/sequesign/keys.json`)).text()
  );
  const registrationKeys = parseTrustedRegistrationKeys(
    await (await fetch(`${DASHBOARD_API_URL}/.well-known/sequesign/registration-keys.json`)).text()
  );

  // 4a. WITHOUT the registration anchor: the approval is present but unverified.
  const unanchored = await verifyReceiptPackage(PACKAGE_DIR, {
    trustedWitnessKeys: witnessKeys,
    trustAnchorMode: "external"
  });
  console.log(`\nWithout registration anchor → approval=${unanchored.flags.approval}`);

  // 4b. WITH it: the approval flips to present_verified and is marked vouched.
  const vouched = await verifyReceiptPackage(PACKAGE_DIR, {
    trustedWitnessKeys: witnessKeys,
    trustAnchorMode: "external",
    trustedRegistrationKeys: registrationKeys
  });
  console.log("");
  printVerificationReport(vouched);
  console.log(
    `\nWith registration anchor → approval=${vouched.flags.approval}  ` +
      `vouched=${vouched.approvals?.[0]?.vouched === true}`
  );
  console.log(`The approval by "${approverId}" is now a VERIFIED identity, offline.`);
  process.exit(vouched.flags.approval === "present_verified" ? 0 : 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
