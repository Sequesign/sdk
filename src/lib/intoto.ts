import { canonicalize } from "./canonicalize.js";
import { canonicalReceiptHash } from "./verify.js";
import { keyIdFromPublicKeyPem } from "./keys.js";
import { signDsse, verifyDsse, type DsseEnvelope } from "./dsse.js";
import type { AgentActionReceipt } from "./types.js";

// in-toto attestation view of a Sequesign receipt (standards-roadmap S2).
// We express a finalized receipt as an in-toto Statement
// (https://in-toto.io/Statement/v1) wrapped in a DSSE envelope (see ./dsse.js)
// signed by the witness key — the independent notary that already signs the
// log's tree heads.
//
// The predicate carries ONLY what the witness can actually prove: the chain
// bounds and the witness attestations (which are signed over sequence /
// action_record_hash / chain states / witnessed_at). Agent-supplied metadata
// that the witnessed chain does not prove — task, agent_id, evidence_references,
// receipt_id — is deliberately excluded, so the witness never DSSE-signs a
// field it did not witness. The subject still pins the exact receipt by its
// canonical digest, so a holder can confirm the attestation is about their
// receipt; the native canonical JSON receipt remains the source of truth.

export const INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
export const INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
// Sequesign's predicate type. Names the claim precisely — "the witnessed
// chain", not "the whole receipt" — so consumers know exactly what the witness
// signature covers. Schema-versioned so the shape can evolve.
export const WITNESSED_CHAIN_PREDICATE_TYPE =
  "https://sequesign.dev/attestation/witnessed-chain/v1";

// One witnessed action, reduced to EXACTLY the fields the witness signs over
// in witnessAttestationMessage (messages.ts) plus the signature that proves
// them. Unsigned attestation fields — witness_public_key, witness_key_id,
// signature_alg, log_entry, chain_head, batch_inclusion_proof, schema_version —
// are deliberately omitted: they are not covered by the witness signature, so
// copying a caller's values into the witness-signed predicate would let forged
// key/proof metadata read as witness-endorsed. (chain_id is carried once at the
// predicate top level; combine it with these fields to recompute the message.)
export type WitnessedAction = {
  witness_id: string;
  sequence: number;
  action_record_hash: string;
  previous_chain_state: string;
  chain_state: string;
  witnessed_at: string;
  signature: string;
};

// The witness-provable facts about a receipt's chain. Every field here is
// either a chain bound that the witness attestations link to (initial/final
// state) or a value signed inside the witnessed actions themselves.
export type WitnessedChainPredicate = {
  chain_id: string;
  sequence_start: number;
  initial_chain_state: string;
  final_chain_state: string;
  action_record_hashes: string[];
  witnessed_actions: WitnessedAction[];
};

export type InTotoSubject = {
  name: string;
  digest: { sha256: string };
};

export type InTotoStatement = {
  _type: typeof INTOTO_STATEMENT_TYPE;
  subject: InTotoSubject[];
  predicateType: string;
  predicate: WitnessedChainPredicate;
};

// Extract the witness-provable facts from a receipt. Deliberately omits task,
// agent_id, evidence_references, receipt_id (top-level fields no signature
// covers) AND every per-attestation field outside the signed witness message
// (see WitnessedAction) — so the witness signs only what it actually witnessed.
export function witnessedChainPredicate(receipt: AgentActionReceipt): WitnessedChainPredicate {
  return {
    chain_id: receipt.chain.chain_id,
    sequence_start: receipt.chain.sequence_start,
    initial_chain_state: receipt.chain.initial_chain_state,
    final_chain_state: receipt.chain.final_chain_state,
    action_record_hashes: receipt.action_record_hashes,
    witnessed_actions: receipt.witness_attestations.map((w) => ({
      witness_id: w.witness_id,
      sequence: w.sequence,
      action_record_hash: w.action_record_hash,
      previous_chain_state: w.previous_chain_state,
      chain_state: w.chain_state,
      witnessed_at: w.witnessed_at,
      signature: w.signature
    }))
  };
}

// Build the in-toto Statement for a receipt. The subject identifies the receipt
// by its canonical digest (so a holder can confirm the attestation is about
// their exact receipt bytes); name is the chain_id, a witness-provable label.
// The predicate is the witnessed-chain claim — not the whole receipt.
export function receiptToInTotoStatement(receipt: AgentActionReceipt): InTotoStatement {
  return {
    _type: INTOTO_STATEMENT_TYPE,
    subject: [
      {
        name: receipt.chain.chain_id,
        digest: { sha256: canonicalReceiptHash(receipt) }
      }
    ],
    predicateType: WITNESSED_CHAIN_PREDICATE_TYPE,
    predicate: witnessedChainPredicate(receipt)
  };
}

// Serialize a Statement to its canonical (RFC 8785 / JCS) bytes — the bytes
// that go in the DSSE payload and that the signature commits to. Canonical so
// the envelope is reproducible byte-for-byte across producers/verifiers.
export function serializeStatement(statement: InTotoStatement): Buffer {
  return Buffer.from(canonicalize(statement), "utf8");
}

// Produce a DSSE-wrapped in-toto attestation for a receipt, signed by the
// witness key. keyid is the witness key id (keyIdFromPublicKeyPem — the same
// 16-hex DER-based id the witness publishes at /.well-known/sequesign/keys.json
// and stamps into witness_key_id), so a client can resolve the signing key
// through the witness's own discovery document. Verification still checks the
// signature cryptographically.
export function signReceiptAsInTotoAttestation(args: {
  receipt: AgentActionReceipt;
  privateKeyPem: string;
  publicKeyPem: string;
}): DsseEnvelope {
  const statement = receiptToInTotoStatement(args.receipt);
  return signDsse({
    payloadType: INTOTO_PAYLOAD_TYPE,
    payload: serializeStatement(statement),
    privateKeyPem: args.privateKeyPem,
    keyid: keyIdFromPublicKeyPem(args.publicKeyPem)
  });
}

// A witnessed_actions entry is well-formed only if it carries EXACTLY the
// witness-signed fields with the right types. Array.isArray is not enough: a
// signed statement could supply `witnessed_actions: [{}]` or `[123]`, and a
// consumer that trusts the returned WitnessedChainPredicate would then read
// missing/non-string fields as verified facts. (chain_id lives once at the
// predicate top level, so it is not repeated per action.)
function isWitnessedAction(value: unknown): value is WitnessedAction {
  if (!value || typeof value !== "object") return false;
  const a = value as Record<string, unknown>;
  return (
    typeof a.witness_id === "string" &&
    typeof a.sequence === "number" &&
    typeof a.action_record_hash === "string" &&
    typeof a.previous_chain_state === "string" &&
    typeof a.chain_state === "string" &&
    typeof a.witnessed_at === "string" &&
    typeof a.signature === "string"
  );
}

export type VerifyInTotoResult =
  | {
      ok: true;
      statement: InTotoStatement;
      predicate: WitnessedChainPredicate;
      subjectDigest: string;
    }
  | { ok: false; reason: string };

// Verify a DSSE-wrapped in-toto witnessed-chain attestation against the witness
// public key: (1) the DSSE signature over the PAE, (2) the in-toto _type and
// predicate type, (3) the subject carries a sha256 digest. When `receipt` is
// supplied, also bind the attestation to it (its canonical hash must equal the
// subject digest), so a holder can confirm the attestation is about exactly
// their receipt. Returns the witnessed-chain predicate + subject digest.
export function verifyReceiptInTotoAttestation(args: {
  envelope: DsseEnvelope;
  publicKeyPem: string;
  receipt?: AgentActionReceipt;
}): VerifyInTotoResult {
  const dsse = verifyDsse({
    envelope: args.envelope,
    publicKeyPem: args.publicKeyPem,
    expectedPayloadType: INTOTO_PAYLOAD_TYPE
  });
  if (!dsse.ok) return { ok: false, reason: dsse.reason };

  let parsed: unknown;
  try {
    parsed = JSON.parse(dsse.payload.toString("utf8"));
  } catch {
    return { ok: false, reason: "DSSE payload is not valid JSON" };
  }
  // JSON.parse can return null or a primitive (e.g. a validly-signed payload of
  // `null`); guard before any property access so a non-object payload yields a
  // failed result instead of throwing when we read `_type`.
  if (parsed === null || typeof parsed !== "object") {
    return { ok: false, reason: "DSSE payload is not a JSON object" };
  }
  const statement = parsed as InTotoStatement;
  if (statement._type !== INTOTO_STATEMENT_TYPE) {
    return { ok: false, reason: `unexpected in-toto _type "${statement._type}"` };
  }
  if (statement.predicateType !== WITNESSED_CHAIN_PREDICATE_TYPE) {
    return { ok: false, reason: `unexpected predicateType "${statement.predicateType}"` };
  }
  if (!statement.predicate || typeof statement.predicate !== "object") {
    return { ok: false, reason: "statement has no predicate" };
  }
  // The DSSE signature only proves the bytes were signed by this key; it does
  // not guarantee the signed Statement has the expected shape. Validate the
  // predicate is a well-formed witnessed-chain claim before returning ok, so
  // clients can trust the typed fields.
  const p = statement.predicate as Partial<WitnessedChainPredicate>;
  if (
    typeof p.chain_id !== "string" ||
    typeof p.sequence_start !== "number" ||
    typeof p.initial_chain_state !== "string" ||
    typeof p.final_chain_state !== "string" ||
    !Array.isArray(p.action_record_hashes) ||
    !Array.isArray(p.witnessed_actions) ||
    // Validate the array ENTRIES too, not just that they are arrays: each hash
    // must be a string and each witnessed action must carry exactly the signed
    // fields. Otherwise `[123]` / `[{}]` would verify ok and hand the caller a
    // predicate whose typed fields are not actually present.
    !p.action_record_hashes.every((h) => typeof h === "string") ||
    !p.witnessed_actions.every(isWitnessedAction)
  ) {
    return { ok: false, reason: "predicate is not a well-formed witnessed-chain claim" };
  }
  const subject = Array.isArray(statement.subject) ? statement.subject[0] : undefined;
  const subjectDigest = subject?.digest?.sha256;
  if (typeof subjectDigest !== "string") {
    return { ok: false, reason: "statement subject has no sha256 digest" };
  }
  if (args.receipt) {
    // canonicalReceiptHash / canonicalize canonicalize (RFC 8785), which throws
    // on non-well-formed Unicode. BOTH the supplied receipt AND the signed
    // predicate are untrusted (a lone surrogate in a predicate string passes the
    // shape guard above but makes JCS throw), so every canonicalize call here
    // must be inside this try — otherwise a throw breaks the function's union
    // contract and surfaces as a 500 in a caller relying on it.
    let receiptHash: string;
    let expectedPredicate: string;
    let actualPredicate: string;
    try {
      receiptHash = canonicalReceiptHash(args.receipt);
      expectedPredicate = canonicalize(witnessedChainPredicate(args.receipt));
      actualPredicate = canonicalize(statement.predicate);
    } catch (err) {
      return {
        ok: false,
        reason: `supplied receipt or signed predicate is not canonicalizable: ${err instanceof Error ? err.message : String(err)}`
      };
    }
    if (receiptHash !== subjectDigest) {
      return { ok: false, reason: "subject digest does not match the supplied receipt" };
    }
    // Bind the signed predicate to the supplied receipt, not just the subject
    // digest. A statement built by signReceiptAsInTotoAttestation derives subject
    // and predicate from one receipt, so this is implied when the digest matches
    // — but don't rely on the signer's construction: require the signed predicate
    // to equal the witnessed-chain predicate of THIS receipt, so the predicate we
    // return provably describes the receipt the caller asked about (not some
    // other chain that merely names this receipt's digest).
    if (actualPredicate !== expectedPredicate) {
      return {
        ok: false,
        reason: "signed predicate does not match the supplied receipt's witnessed chain"
      };
    }
  }

  return { ok: true, statement, predicate: statement.predicate, subjectDigest };
}
