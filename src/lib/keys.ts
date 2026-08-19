import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
export type DemoKeypair = { publicKeyPem: string; privateKeyPem: string };
export function generateEd25519Keypair(): DemoKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

// 16-hex-char key id: first 8 bytes of SHA-256 over the DER-encoded
// SubjectPublicKeyInfo. Matches the witness key-manager's keyIdFromPublicKey,
// so a verifier can recompute the key id from the public PEM in the
// receipt and compare against a proof's witness_key_id.
export function keyIdFromPublicKeyPem(publicKeyPem: string): string {
  const der = createPublicKey(publicKeyPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}
// Validate that a string is a PEM-encoded Ed25519 public key (PR 15-A
// agent identity registration). Returns ok with the canonical SPKI PEM
// (useful for display / fingerprinting) or a human-readable reason. The
// caller decides whether to store the verbatim input or the normalized
// form; the broker enforces the registered key byte-for-byte against
// what the SDK submits, so the dashboard stores the customer's PEM
// verbatim and only uses this to reject non-Ed25519 or malformed input.
export function parseEd25519PublicKeyPem(
  pem: string
): { ok: true; normalizedPem: string } | { ok: false; reason: string } {
  let key;
  try {
    key = createPublicKey(pem);
  } catch (err) {
    return {
      ok: false,
      reason: `not a valid public key PEM: ${err instanceof Error ? err.message : String(err)}`
    };
  }
  if (key.asymmetricKeyType !== "ed25519") {
    return {
      ok: false,
      reason: `expected an Ed25519 public key, got ${key.asymmetricKeyType ?? "unknown"}`
    };
  }
  return {
    ok: true,
    normalizedPem: key.export({ type: "spki", format: "pem" }).toString()
  };
}
// Return the canonical SPKI PEM for an Ed25519 public key (Node's
// export: LF line endings, no trailing whitespace, 64-char base64
// lines). Two PEMs that decode to the same key normalize to identical
// strings, so callers compare and fingerprint the canonical form rather
// than whatever formatting the customer happened to submit (CRLF vs LF,
// trailing whitespace, etc.). Throws on a malformed or non-Ed25519 PEM.
export function canonicalizeEd25519PublicKeyPem(pem: string): string {
  const parsed = parseEd25519PublicKeyPem(pem);
  if (!parsed.ok) {
    throw new Error(`canonicalizeEd25519PublicKeyPem: ${parsed.reason}`);
  }
  return parsed.normalizedPem;
}

// True only for a well-formed Ed25519 public-key PEM. Use this to gate an
// attestation as valid BEFORE fingerprinting/canonicalizing its key:
// canonicalizeEd25519PublicKeyPem throws on a non-Ed25519 key, so gating here
// lets such an attestation be dropped rather than aborting the whole
// verification.
export function isEd25519PublicKeyPem(pem: string): boolean {
  return parseEd25519PublicKeyPem(pem).ok;
}

// True only for a well-formed Ed25519 PRIVATE-key PEM. signEd25519 now rejects
// a non-Ed25519 key outright (its PKCS#8 parser requires the Ed25519 OID and a
// 32-byte seed), so this is a non-throwing pre-check for callers that want to
// branch rather than catch.
export function isEd25519PrivateKeyPem(pem: string): boolean {
  try {
    return createPrivateKey(pem).asymmetricKeyType === "ed25519";
  } catch {
    return false;
  }
}
// Ed25519 sign/verify run the low-level curve op on @noble/curves rather than
// node:crypto's sign()/verify(): the Cloudflare Workers/Pages runtime
// (nodejs_compat) does NOT implement crypto.sign / crypto.verify — it throws
// "[unenv] crypto.sign is not implemented yet!" — so the deployed live-seal
// Functions could not sign at all. @noble is pure JS and produces byte-identical
// RFC 8032 signatures (verified against node:crypto), so receipts remain
// verifiable by Node verifiers and the witness. node:crypto's KeyObject
// PARSERS (createPublicKey/createPrivateKey) ARE implemented at the edge, so we
// still use them where they add validation.

function pemBodyToDer(pem: string): Buffer {
  return Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
}

// A DER TLV header: tag, and the [start, end) byte range of its content.
function readTlv(der: Buffer, offset: number): { tag: number; start: number; end: number } {
  if (offset + 2 > der.length) throw new Error("DER truncated");
  const tag = der[offset];
  let length = der[offset + 1];
  let cursor = offset + 2;
  if (length & 0x80) {
    const lengthBytes = length & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4) throw new Error("bad DER length");
    length = 0;
    for (let i = 0; i < lengthBytes; i++) length = length * 256 + der[cursor + i];
    cursor += lengthBytes;
  }
  if (cursor + length > der.length) throw new Error("DER truncated");
  return { tag, start: cursor, end: cursor + length };
}

// AlgorithmIdentifier OID for Ed25519 (1.3.101.112), as raw TLV bytes.
const ED25519_OID_TLV = [0x06, 0x03, 0x2b, 0x65, 0x70];

// Extract the 32-byte seed from an RFC 5958 OneAsymmetricKey (PKCS#8) DER by
// WALKING the structure — SEQUENCE { version, AlgorithmIdentifier, privateKey
// OCTET STRING { 0x04 0x20 seed } } — not by slicing the trailing 32 bytes: a
// PKCS#8 v2 key carries an OPTIONAL publicKey field AFTER the seed, so the tail
// would be the public key, producing signatures that fail verification. Throws
// (not signs) on a non-Ed25519 key, so we never emit a bogus signature.
// Mirrors pkcs8Ed25519Seed in apps/demo/src/live/seal.ts.
function ed25519SeedFromPkcs8(der: Buffer): Buffer {
  const outer = readTlv(der, 0);
  if (outer.tag !== 0x30) throw new Error("not a PKCS#8 SEQUENCE");
  const version = readTlv(der, outer.start);
  if (version.tag !== 0x02) throw new Error("no PKCS#8 version field");
  const algorithm = readTlv(der, version.end);
  if (algorithm.tag !== 0x30) throw new Error("no AlgorithmIdentifier");
  if (!ED25519_OID_TLV.every((b, i) => der[algorithm.start + i] === b)) {
    throw new Error("not an Ed25519 private key");
  }
  const privateKey = readTlv(der, algorithm.end);
  if (privateKey.tag !== 0x04) throw new Error("no privateKey OCTET STRING");
  const inner = der.subarray(privateKey.start, privateKey.end);
  if (inner.length !== 34 || inner[0] !== 0x04 || inner[1] !== 0x20) {
    throw new Error("no 32-byte Ed25519 seed");
  }
  return inner.subarray(2, 34);
}

export function signEd25519(privateKeyPem: string, message: Buffer): string {
  const seed = ed25519SeedFromPkcs8(pemBodyToDer(privateKeyPem));
  return Buffer.from(ed25519.sign(message, seed)).toString("base64");
}
export function verifyEd25519(
  publicKeyPem: string,
  message: Buffer,
  signatureBase64: string
): boolean {
  try {
    // createPublicKey validates the FULL SPKI (ASN.1 structure + Ed25519
    // algorithm id), so a 44-byte blob with a usable trailing point but a wrong
    // label/OID is rejected — matching the pre-@noble behavior. It is
    // implemented at the edge (unlike crypto.verify). Export the canonical SPKI
    // DER and take the 32-byte raw point for the curve op.
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") return false;
    const publicKey = key.export({ type: "spki", format: "der" }).subarray(-32);
    // zip215: false pins strict RFC 8032 verification. @noble defaults to
    // zip215: true, which accepts non-canonical encodings node:crypto rejects —
    // and untrusted approver/agent keys reach this helper.
    return ed25519.verify(Buffer.from(signatureBase64, "base64"), message, publicKey, {
      zip215: false
    });
  } catch {
    return false;
  }
}
