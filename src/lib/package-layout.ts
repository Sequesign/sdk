// Canonical package layout shared by the SDK package-writer (direct
// mode, writing the package to disk) and the intermediary finalize
// handler (hosted mode, writing the package to R2). Both sides derive
// identical relative paths so a hosted package is byte-equivalent to a
// direct-mode package, modulo the storage prefix.

export const KEYS_DIR = "keys";
export const COUNTERPARTY_KEYS_SUBDIR = "counterparty";
export const APPROVER_KEYS_SUBDIR = "approvers";
export const AGENT_KEY_FILE = "agent.pub.pem";
export const WITNESS_KEY_FILE = "witness.pub.pem";
export const ACTIONS_FILE = "actions.jsonl";
export const EVIDENCE_DIR = "evidence";
// Embed-first packaging (template system Phase 3): the concrete bound
// parameter values for a parameterized (V1-genesis) receipt travel in the
// package as a top-level params.json. It is written once at session start,
// survives finalize (it is NOT under .in-progress/), lets a parameterized
// session be resumed, and lets an offline verifier re-hash the values and
// confirm they match the profile.params_hash committed into the genesis.
// Absent for unparameterized (V0) receipts.
export const PARAMS_FILE = "params.json";

// Embed-first packaging (template system Phase 3): the resolved workflow
// profile document for a profile_constrained receipt travels in the package
// as a top-level profile.json. It is written once at session start, survives
// finalize (it is NOT under .in-progress/), and lets an offline verifier
// re-resolve the mandate's rules — allowed actions, transitions, conditional
// requirements, and parameterized evidence_schemas — and re-verify
// profile_hash WITHOUT a registry. Absent for freeform receipts; the verifier
// falls back to its bundled registry when a profile_constrained package
// predates embedding.
export const PROFILE_FILE = "profile.json";

// Template-author signature (template system Phase 5): the COSE Sign1 by which a
// template author vouches for the profile document travels in the package as a
// top-level profile.sig.json, a sidecar to profile.json. It is a JSON wrapper
// ({ "cose_sign1_b64url": string }) around genuine COSE Sign1 bytes so it reuses
// the same JSON write/store/serve path as profile.json and params.json; the
// decoded bytes are still standard COSE. It is written at session start when the
// bound profile carries an author signature, survives finalize (NOT under
// .in-progress/), and lets an offline verifier grade template_authenticity
// WITHOUT a registry. Absent when the profile has no author signature (the
// mandate content is still hash-bound via genesis; it is simply not
// author-vouched) or for freeform receipts. The signature is over the same
// canonical bytes as profile_hash, so stripping it can only LOWER the grade,
// never forge authenticity.
export const PROFILE_SIG_FILE = "profile.sig.json";

// A counterparty_id becomes a path segment under keys/counterparty/, so
// it must be filesystem-safe and collision-free. Counterparties are
// services, identified by dotted hostnames (counterparty.acme.example):
// accept lowercase alphanumeric segments joined by single dots or
// hyphens; reject path separators, leading or trailing separators,
// uppercase, and anything else that could escape the directory or
// collide once it lands on disk. Rejection rather than silent rewriting
// keeps the id in the filename identical to the id in the attestation.
const CANONICAL_COUNTERPARTY_ID = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

export function isCanonicalCounterpartyId(counterpartyId: string): boolean {
  return CANONICAL_COUNTERPARTY_ID.test(counterpartyId);
}

// An approver_id becomes a path segment under keys/approvers/. Approvers
// are humans, identified by email by convention (brent@acme.com), though
// bare service or role labels (external-approver) are also in use.
// Accept lowercase alphanumerics plus . _ + - for the local label and an
// optional @domain of lowercase alphanumerics plus . and -. Reject
// uppercase (case-folding would let Brent@acme.com and brent@acme.com
// collide as two files for one approver), path separators, and an empty
// id. "@" is filesystem-safe on every major OS and archive format, so the
// id goes verbatim into the filename. This rule is deliberately distinct
// from the counterparty rule: emails and hostnames are different shapes.
const VALID_APPROVER_ID = /^[a-z0-9._+-]+(?:@[a-z0-9.-]+)?$/;

export function isValidApproverId(approverId: string): boolean {
  return VALID_APPROVER_ID.test(approverId);
}

// Leaf filename for a per-identity public key under keys/<subdir>/.
// Callers must validate the id first (isCanonicalCounterpartyId /
// isValidApproverId) and raise their own error (a 400 on the wire, a
// thrown SDK error on disk); this only assembles the leaf so both sides
// produce the same bytes.
export function publicKeyFilename(id: string): string {
  return `${id}.pub.pem`;
}

// Leaf filename for the per-action evidence file under evidence/.
// SDK direct-mode (src/sdk/package-writer.ts), broker, and now
// receipt-library all derive evidence paths from this single helper
// so the read path (the package endpoint) and every write path
// resolve byte-identical keys. action_type underscores collapse to
// hyphens so the filename stays filesystem-safe across formats.
export function evidenceFilename(sequence: number, actionType: string): string {
  const padded = String(sequence).padStart(3, "0");
  const safeType = actionType.replaceAll("_", "-");
  return `action-${padded}-${safeType}.json`;
}

// #212 (PR 286): chain-scoped actions.jsonl grows append-only under
// progressive finalization, but a receipt's downloaded PACKAGE must
// contain only the lines its own envelope covers — the offline
// verifier walks every line and indexes action_record_hashes by
// position, so a sibling's later extension would make an earlier
// receipt's package fail verification. Package-serving handlers call
// this to trim the shared file to the receipt's range
// [sequenceStart, sequenceStart + actionCount). The stored R2 object
// is never modified; this is a per-receipt VIEW at download time.
// Fails open by returning the input unchanged whenever the stored
// file cannot be trimmed to EXACTLY the advertised range — a malformed
// line, a missing sequence (legacy partial write, stale data), or a
// duplicated sequence. Serving the raw file beats producing a
// shortened actions.jsonl that the offline verifier might accept while
// silently omitting actions the envelope promises (Codex P2 on PR
// 286); the raw file lets the verifier see and report the real
// inconsistency.
export function trimActionsJsonlToReceipt(args: {
  actionsJsonl: string;
  sequenceStart: number;
  actionCount: number;
}): string {
  const lines = args.actionsJsonl.split("\n").filter((line) => line.length > 0);
  const bySequence = new Map<number, string>();
  for (const line of lines) {
    let sequence: unknown;
    try {
      sequence = (JSON.parse(line) as { sequence?: unknown }).sequence;
    } catch {
      return args.actionsJsonl;
    }
    if (typeof sequence !== "number" || bySequence.has(sequence)) {
      return args.actionsJsonl;
    }
    bySequence.set(sequence, line);
  }
  const kept: string[] = [];
  for (let i = 0; i < args.actionCount; i++) {
    const line = bySequence.get(args.sequenceStart + i);
    if (line === undefined) {
      return args.actionsJsonl;
    }
    kept.push(line);
  }
  return kept.map((line) => line + "\n").join("");
}
