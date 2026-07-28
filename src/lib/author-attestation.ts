// Template-author signatures (template system Phase 5).
//
// A parameterized mandate's *content* is already authenticated: the embedded
// profile.json is hash-bound into the V1 genesis, so a verifier knows the agent
// committed to exactly those rules (see profile.ts / genesis.ts). What that does
// NOT establish is WHO authored/published the rules — anyone can mint a
// profile.json with any rules and embed it. A template author closes that gap by
// signing the canonical profile bytes; the verifier then grades
// `template_authenticity` (attested / unrecognized / unattested).
//
// Wire format: a COSE Sign1 (RFC 9052) with a DETACHED payload, encoded with the
// hand-rolled deterministic CBOR in cbor.ts (no CBOR/COSE library — same
// "weekend port in any language" discipline as JCS and the RFC 6962 Merkle
// tree). The signature covers the SAME bytes profile_hash is computed over
// (canonicalize(profileDoc)), so an author signature and the genesis binding can
// never disagree about which document was signed.
//
// Untagged COSE Sign1 (a 4-element array, not CBOR tag 18): the artifact only
// ever appears as a profile.sig, so the type is known from context and the tag
// would be redundant — and our CBOR subset intentionally omits tags.
//
// Key discovery is by `kid`: the protected header carries the author_id, and the
// verifier resolves the author's public key from its trusted author-keys anchor
// (mirroring how witness keys resolve by key_id from .well-known). The signing
// key is therefore NOT embedded in the artifact; an author_id the verifier does
// not recognize grades as `unrecognized` (no trust claim), exactly as an
// unverifiable agent identity grades as `self_asserted`.

import { canonicalize } from "./canonicalize.js";
import { encodeCbor, decodeCbor, type CborMap, type CborValue } from "./cbor.js";
import { isEd25519PrivateKeyPem, signEd25519, verifyEd25519 } from "./keys.js";

// COSE header labels (RFC 9052 section 3.1) and the EdDSA algorithm id
// (RFC 9053 / the COSE algorithms registry).
const COSE_LABEL_ALG = 1;
const COSE_LABEL_KID = 4;
const COSE_ALG_EDDSA = -8;

// The COSE Sig_structure context string for a Sign1 (RFC 9052 section 4.4).
const SIG_STRUCTURE_CONTEXT = "Signature1";

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// The exact bytes an author signs / a verifier checks: the JCS canonical form
// of the profile document, identical to what sha256Prefixed(profileDoc) hashes.
export function canonicalProfileBytes(profileDoc: unknown): Uint8Array {
  return utf8(canonicalize(profileDoc));
}

// Build the COSE Sig_structure and return its CBOR bytes (the to-be-signed
// value). Detached payload: the payload bytes go INTO the Sig_structure even
// though the COSE_Sign1 stores nil in the payload slot.
function toBeSigned(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  const sigStructure: CborValue[] = [
    SIG_STRUCTURE_CONTEXT,
    protectedBytes,
    new Uint8Array(0), // external_aad: empty
    payload
  ];
  return encodeCbor(sigStructure);
}

// The protected header is a CBOR map { 1: -8 (EdDSA), 4: kid=author_id }, itself
// wrapped as a byte string per COSE (the "protected" bucket is a bstr-wrapped
// map). Both signer and verifier must serialize it identically; the
// deterministic CBOR encoder guarantees that.
function encodeProtectedHeader(authorId: string): Uint8Array {
  const header: CborMap = new Map<number, CborValue>([
    [COSE_LABEL_ALG, COSE_ALG_EDDSA],
    [COSE_LABEL_KID, utf8(authorId)]
  ]);
  return encodeCbor(header);
}

// Sign a profile document as `authorId`, returning the base64url of the COSE
// Sign1 bytes (base64url so the artifact travels in a JSON-only channel — see
// package-layout PROFILE_SIG_FILE — while the decoded bytes stay genuine COSE).
export function signProfileAuthor(args: {
  profile: unknown;
  authorId: string;
  privateKeyPem: string;
}): string {
  if (!args.authorId) throw new Error("signProfileAuthor: authorId is required");
  // Gate the private key to Ed25519 up front. crypto.sign(null, ...) also
  // accepts other EdDSA keys (e.g. Ed448) and would emit a wrong-length
  // signature (114 bytes) that decodeAuthorAttestation rejects as malformed —
  // so an operator with the wrong key type would otherwise "succeed" at writing
  // a sidecar that every verifier treats as invalid. Fail loud here instead.
  if (!isEd25519PrivateKeyPem(args.privateKeyPem)) {
    throw new Error(
      "signProfileAuthor: privateKeyPem must be an Ed25519 private key (this COSE profile is EdDSA/Ed25519)."
    );
  }
  const protectedBytes = encodeProtectedHeader(args.authorId);
  const payload = canonicalProfileBytes(args.profile);
  const message = Buffer.from(toBeSigned(protectedBytes, payload));
  // signEd25519 returns base64; COSE stores the raw signature bytes.
  const signature = Buffer.from(signEd25519(args.privateKeyPem, message), "base64");
  const coseSign1: CborValue[] = [
    protectedBytes,
    new Map(), // unprotected header: empty
    null, // detached payload
    new Uint8Array(signature)
  ];
  return Buffer.from(encodeCbor(coseSign1)).toString("base64url");
}

export type DecodedAuthorAttestation = {
  authorId: string;
  alg: number;
  protectedBytes: Uint8Array;
  signature: Uint8Array;
};

function asBytes(v: CborValue | undefined): Uint8Array {
  if (!(v instanceof Uint8Array)) throw new Error("author attestation: expected a byte string");
  return v;
}

// Structurally decode a base64url COSE Sign1 profile signature. Throws with a
// specific message on anything malformed — a wrong shape, a non-detached
// payload, an unsupported alg, a missing/empty kid — so the verifier can turn
// the failure into a warning rather than a thrown rejection.
export function decodeAuthorAttestation(coseSign1B64Url: string): DecodedAuthorAttestation {
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(Buffer.from(coseSign1B64Url, "base64url"));
  } catch {
    throw new Error("author attestation: not valid base64url");
  }
  const decoded = decodeCbor(bytes); // throws on malformed / unsupported CBOR
  if (!Array.isArray(decoded) || decoded.length !== 4)
    throw new Error("author attestation: expected a 4-element COSE Sign1 array");
  const [protectedBytes, unprotected, payload, signature] = decoded;
  if (!(protectedBytes instanceof Uint8Array))
    throw new Error("author attestation: protected header must be a byte string");
  if (!(unprotected instanceof Map))
    throw new Error("author attestation: unprotected header must be a map");
  if (payload !== null)
    throw new Error("author attestation: expected a detached payload (nil), got embedded content");
  const sig = asBytes(signature);
  if (sig.length !== 64)
    throw new Error(`author attestation: expected a 64-byte Ed25519 signature, got ${sig.length}`);

  // The protected header must itself be a CBOR map with a supported alg and a
  // non-empty text kid. An empty protected header bstr is also invalid here
  // (COSE allows it, but a Sign1 with no alg is not something we verify).
  if (protectedBytes.length === 0)
    throw new Error("author attestation: protected header is empty (no alg)");
  const header = decodeCbor(protectedBytes);
  if (!(header instanceof Map))
    throw new Error("author attestation: protected header is not a CBOR map");
  const alg = header.get(COSE_LABEL_ALG);
  if (alg !== COSE_ALG_EDDSA)
    throw new Error(`author attestation: unsupported COSE alg ${String(alg)} (expected EdDSA -8)`);
  const kid = header.get(COSE_LABEL_KID);
  if (!(kid instanceof Uint8Array) || kid.length === 0)
    throw new Error("author attestation: protected header is missing a kid (author_id)");
  let authorId: string;
  try {
    authorId = new TextDecoder("utf-8", { fatal: true }).decode(kid);
  } catch {
    throw new Error("author attestation: kid is not valid UTF-8");
  }
  return { authorId, alg, protectedBytes, signature: sig };
}

// Verify a decoded attestation's signature against a profile document and a
// candidate author public key. The caller resolves publicKeyPem from its
// trusted author-keys anchor by decoded.authorId; this function only checks the
// cryptography, recomputing the detached payload from the profile so a verifier
// never trusts payload bytes the artifact might carry.
export function verifyAuthorSignature(args: {
  decoded: DecodedAuthorAttestation;
  profile: unknown;
  publicKeyPem: string;
}): boolean {
  const payload = canonicalProfileBytes(args.profile);
  const message = Buffer.from(toBeSigned(args.decoded.protectedBytes, payload));
  return verifyEd25519(
    args.publicKeyPem,
    message,
    Buffer.from(args.decoded.signature).toString("base64")
  );
}
