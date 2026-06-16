/**
 * Example 01 — Verify a receipt offline.
 *
 * This is the whole point of Sequesign: a receipt can be checked by anyone,
 * with NO call to any Sequesign service and NO credentials. This script reads a
 * receipt package from disk, verifies every cryptographic claim in it, and
 * prints the result.
 *
 * What you'll see:
 *   - evidence hashes, the action hash-chain, and the agent + witness
 *     signatures all re-checked locally;
 *   - the verification level (L0 integrity-only → L1 witnessed → L2 identity-
 *     bound → L3 policy-bound) and the independent witnessed / approval flags.
 *
 * No credentials required.
 *
 * Run (after example 02 has produced a package):
 *   npx tsx examples/01-verify-offline.ts [path-to-.sequesign-package]
 *
 * If you omit the path it looks for ./out/example-02.sequesign.
 */
import path from "node:path";

import {
  verifyReceiptPackage,
  selfTrustedWitnessKeysFromPackage,
  printVerificationReport
} from "@sequesign/sdk/verify";

const packageDir = process.argv[2] ?? path.resolve("out", "example-02.sequesign");

async function main(): Promise<void> {
  console.log(`Verifying receipt package: ${packageDir}\n`);

  // Anchor the witness signature to the key embedded in the package itself —
  // an integrity self-check that needs nothing but the files on disk. For
  // genuine third-party verification, fetch the witness's PUBLISHED keys
  // (https://witness.sequesign.com/.well-known/sequesign/keys.json), parse them
  // with parseTrustedWitnessKeys, and pass trustAnchorMode "external" instead.
  const trustedWitnessKeys = await selfTrustedWitnessKeysFromPackage(packageDir);

  const report = await verifyReceiptPackage(packageDir, {
    trustedWitnessKeys,
    trustAnchorMode: "self"
  });

  printVerificationReport(report);

  console.log(
    `\nvalid=${report.valid}  level=${report.verification_level}  ` +
      `witnessed=${report.flags.witnessed}  agent_identity=${report.agent_identity?.kind}`
  );
  process.exit(report.valid ? 0 : 1);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
