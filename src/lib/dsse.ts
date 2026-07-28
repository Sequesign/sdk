import { signEd25519, verifyEd25519 } from "./keys.js";

// DSSE — Dead Simple Signing Envelope (https://github.com/secure-systems-lab/dsse).
// The in-toto / Sigstore signing envelope. Standards-roadmap S2 wraps a
// Sequesign receipt (as an in-toto attestation, see ./intoto.ts) in this
// envelope so supply-chain tooling can consume it. The native JSON receipt
// stays the canonical form; DSSE is an additional, standards-conformant view.
//
// This module is pure (no receipt/log knowledge): it turns a (payloadType,
// payload) pair plus an Ed25519 key into a signed envelope, and verifies the
// reverse. The signature covers the PAE (Pre-Authentication Encoding), never
// the raw payload, so a payload can never be reinterpreted under a different
// payloadType.

const SP = 0x20;
const DSSE_V1 = Buffer.from("DSSEv1", "ascii");

// Node's base64 decoder silently drops out-of-alphabet characters and tolerates
// lax padding, so a byte-altered string (e.g. "YWJj!!!!") can decode to the same
// bytes a genuine value did and would otherwise still "verify". Require the
// canonical padded base64 form — exactly what signDsse / signEd25519 emit via
// Buffer#toString("base64") — so non-canonical payload OR signature strings are
// rejected, matching stricter DSSE tooling.
function isCanonicalBase64(s: string): boolean {
  return Buffer.from(s, "base64").toString("base64") === s;
}

export type DsseSignature = {
  // Optional key hint. We populate it with the signer's key fingerprint so a
  // verifier can select the right key; verification does not depend on it.
  keyid?: string;
  // base64(signature bytes).
  sig: string;
};

export type DsseEnvelope = {
  // base64(SERIALIZED_BODY).
  payload: string;
  // The payload type URI (e.g. application/vnd.in-toto+json).
  payloadType: string;
  signatures: DsseSignature[];
};

// PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
// where LEN is the ASCII-decimal byte length with no leading zeros, SP is a
// single 0x20 space, and type/body are raw bytes. This is the exact byte
// string the signature is computed over.
export function pae(payloadType: string, payload: Buffer): Buffer {
  const typeBytes = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    DSSE_V1,
    Buffer.from([SP]),
    Buffer.from(String(typeBytes.length), "ascii"),
    Buffer.from([SP]),
    typeBytes,
    Buffer.from([SP]),
    Buffer.from(String(payload.length), "ascii"),
    Buffer.from([SP]),
    payload
  ]);
}

// Sign a payload, producing a single-signature DSSE envelope. `payload` is the
// already-serialized body bytes (the caller decides the serialization, e.g.
// canonical JSON for an in-toto Statement). The signature is Ed25519 over the
// PAE, per the DSSE spec.
export function signDsse(args: {
  payloadType: string;
  payload: Buffer;
  privateKeyPem: string;
  keyid?: string;
}): DsseEnvelope {
  const sig = signEd25519(args.privateKeyPem, pae(args.payloadType, args.payload));
  return {
    payload: args.payload.toString("base64"),
    payloadType: args.payloadType,
    signatures: [args.keyid !== undefined ? { keyid: args.keyid, sig } : { sig }]
  };
}

// Attach an additional signature to an existing envelope (e.g. a co-signer /
// notary). The new signature covers the same PAE over the envelope's existing
// payload + payloadType.
export function addDsseSignature(
  envelope: DsseEnvelope,
  args: { privateKeyPem: string; keyid?: string }
): DsseEnvelope {
  const payload = Buffer.from(envelope.payload, "base64");
  const sig = signEd25519(args.privateKeyPem, pae(envelope.payloadType, payload));
  return {
    ...envelope,
    signatures: [
      ...envelope.signatures,
      args.keyid !== undefined ? { keyid: args.keyid, sig } : { sig }
    ]
  };
}

export type VerifyDsseResult =
  | { ok: true; payload: Buffer; payloadType: string }
  | { ok: false; reason: string };

// Verify that at least one signature on the envelope is a valid Ed25519
// signature by `publicKeyPem` over PAE(payloadType, payload). Returns the
// decoded payload bytes + payloadType so the caller can parse the body. When
// `expectedPayloadType` is given, a mismatch is rejected before any signature
// check (DSSE: "Reject if PAYLOAD_TYPE is not a supported type").
export function verifyDsse(args: {
  envelope: DsseEnvelope;
  publicKeyPem: string;
  expectedPayloadType?: string;
}): VerifyDsseResult {
  const env = args.envelope;
  if (
    !env ||
    typeof env.payload !== "string" ||
    typeof env.payloadType !== "string" ||
    !Array.isArray(env.signatures)
  ) {
    return { ok: false, reason: "malformed DSSE envelope" };
  }
  if (args.expectedPayloadType !== undefined && env.payloadType !== args.expectedPayloadType) {
    return {
      ok: false,
      reason: `unexpected payloadType "${env.payloadType}" (wanted "${args.expectedPayloadType}")`
    };
  }
  if (env.signatures.length === 0) {
    return { ok: false, reason: "envelope has no signatures" };
  }
  if (typeof env.payload !== "string" || !isCanonicalBase64(env.payload)) {
    return { ok: false, reason: "payload is not canonical base64" };
  }
  const payload = Buffer.from(env.payload, "base64");
  const message = pae(env.payloadType, payload);
  for (const signature of env.signatures) {
    if (
      signature &&
      typeof signature.sig === "string" &&
      // Reject a non-canonical signature string for the same reason as the
      // payload: a byte-altered sig that Node would silently normalize must not
      // verify, even though the decoded bytes match a genuine signature.
      isCanonicalBase64(signature.sig) &&
      verifyEd25519(args.publicKeyPem, message, signature.sig)
    ) {
      return { ok: true, payload, payloadType: env.payloadType };
    }
  }
  return { ok: false, reason: "no signature verified against the supplied key" };
}
