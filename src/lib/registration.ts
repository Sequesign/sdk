// v0.6 step #4 (vouching, §6). Helpers for the platform-signed registration
// record that vouches an attestation key. The record is built account-side
// (dashboard-api, #4.3) and travels inside an A/C attestation's
// `identity_proof.ref` (base64url of the SignedRegistrationRecord); the offline
// verifier decodes + checks it against a trusted platform key and, on a full
// match, flips the attestation's leg to `present_verified`. No callback.

import { ed25519KeyFingerprint } from "./hash.js";
import {
  isEd25519PublicKeyPem,
  keyIdFromPublicKeyPem,
  signEd25519,
  verifyEd25519
} from "./keys.js";
import { registrationChallengeMessage, registrationRecordMessage } from "./messages.js";
import type { RegistrationRecord, SignedRegistrationRecord } from "./types.js";

function recordMessage(record: RegistrationRecord): Buffer {
  return registrationRecordMessage({
    schemaVersion: record.schema_version,
    issuer: record.issuer,
    role: record.role,
    partyType: record.party_type,
    subjectKeyFingerprint: record.subject_key_fingerprint,
    identity: record.identity,
    registeredAt: record.registered_at
  });
}

// Account-side: sign a registration record with the platform key. Returns the
// self-contained wrapper that goes (base64url-encoded) into identity_proof.ref.
export function buildSignedRegistrationRecord(args: {
  record: RegistrationRecord;
  platformPublicKeyPem: string;
  platformPrivateKeyPem: string;
}): SignedRegistrationRecord {
  return {
    record: args.record,
    platform_key_id: keyIdFromPublicKeyPem(args.platformPublicKeyPem),
    platform_public_key: args.platformPublicKeyPem,
    signature_alg: "Ed25519",
    signature: signEd25519(args.platformPrivateKeyPem, recordMessage(args.record))
  };
}

// `identity_proof.ref` is base64url(JSON(SignedRegistrationRecord)).
export function encodeIdentityProofRef(signed: SignedRegistrationRecord): string {
  return Buffer.from(JSON.stringify(signed), "utf8").toString("base64url");
}

// v0.6 step #4.4: enrollment-side proof-of-possession. The subject signs the
// registration challenge with its OWN private key; the value goes in the
// `subject_signature` field of POST /registrations (#4.3), which the endpoint
// verifies before the platform vouches the key. Recompute the fingerprint from
// the public key so the caller cannot accidentally sign a challenge for a
// different key than it enrolls. The args are a discriminated union on role —
// an approver MUST carry party_type, a counterparty MUST NOT — so the signed
// challenge matches exactly what the endpoint verifies (a mismatch would
// produce a signature that always fails enrollment).
export function registrationChallengeSignature(
  args:
    | {
        role: "approver";
        partyType: "human" | "agent";
        identity: string;
        subjectPublicKeyPem: string;
        subjectPrivateKeyPem: string;
      }
    | {
        role: "counterparty";
        identity: string;
        subjectPublicKeyPem: string;
        subjectPrivateKeyPem: string;
      }
): string {
  const partyType = args.role === "approver" ? args.partyType : undefined;
  // Runtime guard for plain-JS callers (the union already covers TS): an
  // approver challenge without a valid party_type would sign the empty-party
  // challenge and always fail POST /registrations, so reject it loudly.
  if (args.role === "approver" && partyType !== "human" && partyType !== "agent") {
    throw new Error(
      'registrationChallengeSignature: role "approver" requires party_type "human" or "agent".'
    );
  }
  const message = registrationChallengeMessage({
    role: args.role,
    partyType,
    identity: args.identity,
    subjectKeyFingerprint: ed25519KeyFingerprint(args.subjectPublicKeyPem)
  });
  return signEd25519(args.subjectPrivateKeyPem, message);
}

// Decode a `sequesign`-issuer ref. Returns null on ANY malformation (bad
// base64, bad JSON, wrong shape) so a broken proof simply leaves the leg
// `present_unverified` instead of throwing — an optional proof must never sink
// an otherwise-valid receipt.
export function decodeIdentityProofRef(ref: string): SignedRegistrationRecord | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(ref, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  const s = parsed as Record<string, unknown>;
  if (
    typeof s.platform_key_id !== "string" ||
    typeof s.platform_public_key !== "string" ||
    typeof s.signature !== "string" ||
    !s.record ||
    typeof s.record !== "object"
  ) {
    return null;
  }
  const r = s.record as Record<string, unknown>;
  const stringFields = [
    "schema_version",
    "issuer",
    "role",
    "subject_key_fingerprint",
    "registered_at"
  ] as const;
  if (!stringFields.every((f) => typeof r[f] === "string")) return null;
  // identity is required for approver/counterparty (the named identity the key
  // is registered to) but OMITTED for the agent role (key-only registration).
  if (r.role === "agent") {
    if (r.identity !== undefined && typeof r.identity !== "string") return null;
  } else if (typeof r.identity !== "string") {
    return null;
  }
  if (r.party_type !== undefined && typeof r.party_type !== "string") return null;
  return parsed as SignedRegistrationRecord;
}

// Verify the platform signature on a registration record and that its signing
// key is trusted. Mirrors the witness leg: recompute the key fingerprint from
// the embedded PEM (never trust the declared id), require it in the trusted
// set, require the declared platform_key_id to agree, then check the signature.
export function registrationRecordSealVerifies(
  signed: SignedRegistrationRecord,
  trustedPlatformFingerprints: Set<string>
): boolean {
  // The platform key must be a genuine Ed25519 key. verifyEd25519 delegates to
  // Node's generic EdDSA verifier, which also accepts other EdDSA keys (e.g.
  // Ed448); the wrapper declares signature_alg "Ed25519" and the protocol
  // expects Ed25519 platform keys, so reject anything else rather than vouch it
  // (mirrors the approval/counterparty signer gate).
  if (!isEd25519PublicKeyPem(signed.platform_public_key)) return false;
  let fingerprint: string;
  try {
    fingerprint = keyIdFromPublicKeyPem(signed.platform_public_key);
  } catch {
    return false;
  }
  if (!trustedPlatformFingerprints.has(fingerprint)) return false;
  if (signed.platform_key_id !== fingerprint) return false;
  return verifyEd25519(signed.platform_public_key, recordMessage(signed.record), signed.signature);
}

// Whether a `sequesign` identity proof vouches a specific attestation: the
// platform seal verifies AND the record binds the SAME key (by fingerprint),
// role, identity, and (for approvals) party_type that the attestation carries.
// `subjectPublicKeyPem` is the attestation's signer key (approver/counterparty).
export function identityProofVouches(
  ref: string,
  expected: {
    role: "approver" | "counterparty";
    identity: string;
    partyType?: "human" | "agent";
    subjectPublicKeyPem: string;
  },
  trustedPlatformFingerprints: Set<string>
): boolean {
  const signed = decodeIdentityProofRef(ref);
  if (!signed) return false;
  if (!registrationRecordSealVerifies(signed, trustedPlatformFingerprints)) return false;
  const r = signed.record;
  if (r.issuer !== "sequesign") return false;
  // Only the exact v1 record format this resolver understands is accepted. A
  // trusted platform could later sign a different schema_version with different
  // semantics; an older verifier must NOT treat that as a v1 vouch.
  if (r.schema_version !== "sequesign.registration_record.v1.0.0") return false;
  if (r.role !== expected.role) return false;
  if (r.identity !== expected.identity) return false;
  if (expected.role === "approver" && r.party_type !== expected.partyType) return false;
  let subjectFingerprint: string;
  try {
    subjectFingerprint = ed25519KeyFingerprint(expected.subjectPublicKeyPem);
  } catch {
    return false;
  }
  return r.subject_key_fingerprint === subjectFingerprint;
}

// Whether a `sequesign` identity proof vouches a REGISTERED AGENT KEY: the
// platform seal verifies AND the record is an agent-role record binding the
// SAME key fingerprint. Key-only — agent registration vouches a key, not a name,
// so there is no identity / party_type to match. `keyFingerprint` is the
// fingerprint the verifier already computed from the receipt's agent_public_key
// (passed in so this resolver never recomputes it with a different function).
// Resolve a `sequesign` agent identity proof to its VOUCHED registration record,
// or null if it does not vouch the given key. Returns the record (not a boolean)
// so the caller reads vouched fields — e.g. registered_at — from inside the
// signed seal rather than from the unsigned attestation. Key-only: agent
// registration vouches a key, not a name. `keyFingerprint` is the fingerprint
// the verifier already computed from the receipt's agent_public_key.
export function agentIdentityProofRecord(
  ref: string,
  expected: { keyFingerprint: string },
  trustedPlatformFingerprints: Set<string>
): RegistrationRecord | null {
  const signed = decodeIdentityProofRef(ref);
  if (!signed) return null;
  if (!registrationRecordSealVerifies(signed, trustedPlatformFingerprints)) return null;
  const r = signed.record;
  if (r.issuer !== "sequesign") return null;
  if (r.schema_version !== "sequesign.registration_record.v1.0.0") return null;
  if (r.role !== "agent") return null;
  if (r.subject_key_fingerprint !== expected.keyFingerprint) return null;
  return r;
}
