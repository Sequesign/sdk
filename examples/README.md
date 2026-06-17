# Examples

Runnable, narrated walkthroughs of what Sequesign does. Each script prints what
it is proving as it goes, so you can watch the trust being built and then
re-checked offline.

There are two ways to record (the **SDK**, or the **`sequesign` CLI + curl** for
any language) and two modes (**managed** — the broker calls the witness,
assembles, and stores for you; **direct** — you call the witness yourself and
assemble the receipt locally, no broker). That is the 2×2:

| Record path | Managed (broker)       | Direct (no broker)    |
| ----------- | ---------------------- | --------------------- |
| **SDK**     | `02-record-managed.ts` | `04-record-direct.ts` |
| **curl**    | `curl-managed.sh`      | `curl-direct.sh`      |

Plus the two cross-cutting flows:

| Script                 | Shows                                                   | Needs                           |
| ---------------------- | ------------------------------------------------------- | ------------------------------- |
| `01-verify-offline.ts` | Verify a receipt with **no** Sequesign call and no keys | nothing                         |
| `03-vouch-approval.ts` | A **vouched approver** whose identity verifies offline  | API key + agent + approver keys |

These examples use the keys you already have — your registered agent (and
approver) keys. They do not generate keys; that is not how the SDK is used in
practice.

## Setup

```bash
npm install
npm run build
```

The SDK examples import `@sequesign/sdk`, which resolves to this package's own
build, so `npm run build` must run first. Run the `.ts` examples with
[`tsx`](https://www.npmjs.com/package/tsx); the `.sh` examples need `bash`,
`curl`, `jq`, and `openssl`.

API keys come from [dashboard.sequesign.com](https://dashboard.sequesign.com).
In bash use `export NAME=...`; in PowerShell use `$env:NAME = "..."`.

## 01 — Verify a receipt offline (no credentials)

The core promise: anyone can verify a receipt with nothing but the files and
this library — no network, no trust in Sequesign. Point it at a package any of
the record examples produced:

```bash
npx tsx examples/01-verify-offline.ts ./out/example-02.sequesign
```

```text
Verifying receipt package: ./out/example-02.sequesign

Sequesign verification PASSED
Level: L2_KEY_BOUND
Identity: registered (vouched)
Chain: chn_…
Actions: 1
Witness: verified

valid=true  level=L2_KEY_BOUND  witnessed=true  agent_identity=registered
```

`Level` reflects cryptographic key-binding (`L2_KEY_BOUND`); `Identity`
reflects whether that key is a vouched identity — `registered (vouched)` vs
`self-asserted (unregistered)`. They are independent: direct-mode receipts are
also `L2_KEY_BOUND`, but `self-asserted`.

## 02 — Record an action, managed mode (SDK)

The SDK signs with your registered agent key and routes the action through the
broker, which has the witness co-sign it; the broker stores the receipt.

```bash
export SEQUESIGN_API_KEY="<write-class api key>"
export SEQUESIGN_AGENT_PRIVATE_KEY="$(cat agent.key.pem)"   # the key your API key is registered to
npx tsx examples/02-record-managed.ts
```

```text
Recording one action against https://broker.sequesign.com; the witness will co-sign it...
Receipt sealed: rec_…
Stored at:      https://library.sequesign.com/v1/receipts/rec_…
level=L2_KEY_BOUND  witnessed=true  agent_identity=registered
```

Reaches `L2_KEY_BOUND` with `agent_identity=registered`: the agent
signature binds every action to your key (that is what the L2 level reflects),
and the broker's `agent_identity_attestation` vouches that the key is your
registered identity. Witnessing is orthogonal to the level.

## 04 — Record an action, direct mode (SDK)

No broker: the SDK signs locally, calls the witness directly (it sees only the
commitment hashes), and **you** assemble + hold the receipt.

```bash
export SEQUESIGN_AGENT_PRIVATE_KEY="$(cat agent.key.pem)"
export SEQUESIGN_API_KEY="<write-class api key>"            # the witness requires it
npx tsx examples/04-record-direct.ts
```

```text
Recording one action; signing locally and witnessing via https://witness.sequesign.com/witness...
Receipt assembled locally: rec_…
level=L2_KEY_BOUND  witnessed=true  agent_identity=unregistered
```

Direct mode also reaches `L2_KEY_BOUND` — the level reflects that every
action carries a valid agent signature bound to the receipt's key, which holds
without a broker. What direct mode lacks is the broker-stamped
`agent_identity_attestation`, so `agent_identity` is `unregistered` (vs
`registered` in managed mode). The distinguishing signal between 02 and 04 is
**`agent_identity`, not the level**: a relying party that needs
platform-vouched identity should check `agent_identity.kind === "registered"`,
not the level name. (`agent_id` and `agent_public_key` are self-asserted in
direct mode.)

## curl-managed — managed mode without the SDK

Same managed flow, driven by `sequesign` + `curl` so any language can do it:
sign locally → POST the request body to the broker → assemble + POST the finalize
body.

```bash
export SEQUESIGN_API_KEY="<write-class api key>"
export SEQUESIGN_AGENT_PRIVATE_KEY_PATH=agent.key.pem
bash examples/curl-managed.sh
```

```text
[1] sign the action locally (no network)
[2] POST request_body to the broker; the witness co-signs
[3] assemble the finalize body from the signed action + the witness attestation
[4] POST the finalize body; the broker stores the receipt
{ "receipt_id": "rec_…", "receipt_url": "https://library.sequesign.com/v1/receipts/rec_…" }
DONE — managed receipt recorded via curl.
```

## curl-direct — direct mode without the SDK

The non-SDK direct flow: sign locally, send only the commitment hashes
(`witness_request`) to `POST /witness`, then `assemble-receipt` writes the
package on your machine.

```bash
export SEQUESIGN_API_KEY="<write-class api key>"
export SEQUESIGN_AGENT_PRIVATE_KEY_PATH=agent.key.pem
bash examples/curl-direct.sh
```

```text
[1] sign locally (no network); the result includes a witness_request
[2] POST witness_request (commitment hashes only) to the witness
[3] assemble the receipt package locally (the agent is the custodian)
{ "package_dir": "…/out/curl-direct.sequesign", "receipt_id": "rec_…" }
DONE — direct receipt assembled. Verify it with example 01 or verify.sequesign.com
```

## 03 — A vouched approval

Enrolls an approver key, records an approval carrying the platform's signed
`identity_proof`, and verifies the receipt twice — without the registration
anchor (`present_unverified`) and with it (`present_verified`, vouched).

```bash
export SEQUESIGN_API_KEY="<write-class api key>"
export SEQUESIGN_AGENT_PRIVATE_KEY="$(cat agent.key.pem)"
export SEQUESIGN_APPROVER_PRIVATE_KEY="$(cat approver.key.pem)"
export SEQUESIGN_APPROVER_ID="cfo@acme.example"   # the identity you registered
npx tsx examples/03-vouch-approval.ts
```

`SEQUESIGN_APPROVER_PARTY_TYPE` may be `human` (default) or `agent`.

## Verify in the browser

Every example writes a `.sequesign` package under `./out/`. Drag that folder
into [verify.sequesign.com](https://verify.sequesign.com) to re-verify it in the
browser.

> Sample outputs above are representative and abridged; ids and hashes vary per
> run.
