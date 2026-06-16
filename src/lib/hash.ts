import { createHash } from "node:crypto";
import { canonicalize } from "./canonicalize.js";
import { canonicalizeEd25519PublicKeyPem } from "./keys.js";
export function sha256Hex(input: string | Uint8Array): string {
  return createHash("sha256").update(input).digest("hex");
}
export function hashCanonical(value: unknown): string {
  return sha256Hex(canonicalize(value));
}
export function sha256Prefixed(value: unknown): string {
  return `sha256:${hashCanonical(value)}`;
}
// Agent identity key fingerprint (PR 15-A): the literal string
// "sha256:" followed by the lowercase hex SHA-256 of the UTF-8 bytes of
// the CANONICAL SPKI PEM of the Ed25519 public key. The input is
// normalized first (canonicalizeEd25519PublicKeyPem) so two PEMs that
// decode to the same key produce the same fingerprint regardless of
// line endings or whitespace; the trust surface is the key, not its
// formatting. Shared by the broker (envelope assembly) and the offline
// verifier so the two can never disagree on the construction. This
// hashes the canonical PEM bytes directly, not a canonicalized JSON
// value, so it is deliberately NOT sha256Prefixed. Throws on a
// malformed or non-Ed25519 PEM.
// Canonical fingerprint of any Ed25519 public-key PEM: normalize the PEM
// (so formatting/whitespace differences do not matter) then hash. Used to
// compare signer identity regardless of how the key was serialized.
export function ed25519KeyFingerprint(publicKeyPem: string): string {
  return `sha256:${sha256Hex(canonicalizeEd25519PublicKeyPem(publicKeyPem))}`;
}

// Agent-key-named alias, kept for existing callers (the self-approval guard).
export function agentKeyFingerprint(agentPublicKeyPem: string): string {
  return ed25519KeyFingerprint(agentPublicKeyPem);
}
