import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify
} from "node:crypto";
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
// verifyEd25519 calls crypto.verify(null, ...), which also accepts other
// EdDSA keys (e.g. Ed448), so a non-Ed25519 key can pass signature
// verification yet throw when canonicalized. Gating here lets such an
// attestation be dropped rather than aborting the whole verification.
export function isEd25519PublicKeyPem(pem: string): boolean {
  return parseEd25519PublicKeyPem(pem).ok;
}
export function signEd25519(privateKeyPem: string, message: Buffer): string {
  return cryptoSign(null, message, privateKeyPem).toString("base64");
}
export function verifyEd25519(
  publicKeyPem: string,
  message: Buffer,
  signatureBase64: string
): boolean {
  try {
    return cryptoVerify(null, message, publicKeyPem, Buffer.from(signatureBase64, "base64"));
  } catch {
    return false;
  }
}
