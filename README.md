# @sequesign/sdk

TypeScript SDK and reference verifier for Sequesign, a protocol for
cryptographically verifiable receipts of delegated AI work. The agent
signs, the witness signs, the human signs; the result is a receipt any
party can verify offline with no call to any Sequesign service.

Sequesign is patent pending.

## Install

```bash
npm install @sequesign/sdk
```

Requires Node 22.11 or later.

## Record actions (managed mode, hosted broker)

```ts
import { createSequesign } from "@sequesign/sdk";

const sdk = createSequesign({
  mode: "managed",
  tier: "hosted",
  broker: {
    baseUrl: "https://broker.sequesign.com",
    apiKey: process.env.SEQUESIGN_API_KEY
  }
});

const session = await sdk.startSession({
  agent: { agentId: "agent_acme_001", keypair },
  task: { taskId: "task_invoice_001", delegatorId: "finance_team" }
});

await session.recordAction({
  actionType: "policy_checked",
  evidence: { decision: "approved", reason: "within limit" }
});

const { receipt } = await session.finalize();
```

API keys are issued at [dashboard.sequesign.com](https://dashboard.sequesign.com).
A key may be registered to an agent Ed25519 public key at creation;
receipts produced under a registered key carry an
`agent_identity_attestation` binding the work to that keypair.

## Verify a receipt offline

```ts
import {
  verifyReceiptPackage,
  selfTrustedWitnessKeysFromPackage
} from "@sequesign/sdk/verify";

// Integrity self-check: anchor to the witness key embedded in the
// package. For third-party verification, pass the witness's published
// keys (https://witness.sequesign.com/.well-known/sequesign/keys.json)
// instead, with trustAnchorMode "external".
const trustedWitnessKeys = await selfTrustedWitnessKeysFromPackage(packageDir);
const report = await verifyReceiptPackage(packageDir, {
  trustedWitnessKeys,
  trustAnchorMode: "self"
});

console.log(report.valid, report.verification_level);
```

The verifier checks evidence hashes, the action hash chain, agent and
witness signatures, attestation bindings, and (when the receipt declares
them) schema and workflow-profile conformance. Verification levels L0
through L5 and the independent witnessed flag are documented in the
protocol spec.

## Registered-key vouching (verified approver/counterparty identity)

A bare approval signature proves only that *some* key signed; it does not
prove *whose* key. Vouching closes that gap without giving up offline
verification. An approver (or counterparty) enrols its attestation key
with the platform, the platform issues a signed registration record, and
that record travels inside the attestation as a self-contained
`identity_proof` — so the receipt still verifies with no callback.

Enrolment proves possession of the key, then exchanges it for a proof:

```ts
import { registrationChallengeSignature } from "@sequesign/sdk";

// 1. Sign the enrolment challenge with the key you are registering.
const subjectSignature = registrationChallengeSignature({
  role: "approver",
  partyType: "human",
  identity: "cfo@acme.example",
  subjectPublicKeyPem: approverKeypair.publicKeyPem,
  subjectPrivateKeyPem: approverKeypair.privateKeyPem
});

// 2. POST it to dashboard-api with a write-class key or dashboard session.
//    The response carries the proof you keep and attach:
//      { "identity_proof": { "issuer": "sequesign", "ref": "<base64url>" } }
```

Attach the returned `identity_proof` when you record the attestation
(`recordCounterpartyAttestation` takes it the same way):

```ts
await session.recordApproval({
  approverId: "cfo@acme.example",
  partyType: "human",
  approverKeypair,
  // …approval fields…
  identityProof // from the enrolment response
});
```

The proof is metadata, not part of the signed message, so attaching it
never changes the attestation signature. To resolve it at verification
time, pass the platform's published registration keys; a resolved proof
flips that leg's `vouched` flag and raises it from `present_verified`:

```ts
import {
  verifyReceiptPackage,
  parseTrustedRegistrationKeys
} from "@sequesign/sdk/verify";

// https://dashboard-api.sequesign.com/.well-known/sequesign/registration-keys.json
const trustedRegistrationKeys = parseTrustedRegistrationKeys(registrationKeysJson);
const report = await verifyReceiptPackage(packageDir, {
  trustedWitnessKeys,
  trustAnchorMode: "external",
  trustedRegistrationKeys
});
```

Vouching is an independent badge: it raises the approver/counterparty
identity legs but never changes the base L0–L5 level. Omit
`trustedRegistrationKeys` and the receipt still verifies — the leg simply
stays `present_unverified`.

## Direct mode (no broker)

The SDK can also run direct mode: canonicalize and sign locally, with
only the witness service in the loop. Any language can implement the
same wire contract; see the protocol primitives reference with worked
test vectors in the repository's `docs/` directory.

## Documentation

- Protocol spec, trust model, and primitives reference:
  [github.com/Sequesign/protocol](https://github.com/Sequesign/protocol)
- Hosted verifier: [verify.sequesign.com](https://verify.sequesign.com)

## License

Apache License 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
The hosted platform (witnessing, receipt storage, dashboard) is a
separate commercial service and is not covered by this license.
