// Agent-identity enforcement and attestation helpers, shared by the broker
// (managed mode), the witness (direct mode), and the SDK. Moved here from
// apps/broker/src/agent-identity.ts so all three transports enforce and stamp
// agent identity identically against one source of truth.

import { agentKeyFingerprint } from "./hash.js";
import type { AgentIdentityAttestation } from "./types.js";

// Hard enforcement against the API key's ACTIVE registered agent-key set
// (migration 0021's per-API-key registry).
//
// `hasEverRegistered` distinguishes a key that NEVER enrolled an agent key from
// one that has registrations on file but zero ACTIVE ones (all revoked):
//   - hasEverRegistered === false  → "unregistered" key: every submitted key is
//     allowed (the unregistered-managed tier), and the caller stamps no
//     attestation. This preserves today's behavior for keys that opt out of
//     agent identity entirely.
//   - hasEverRegistered === true   → the key is LOCKED to its active set. The
//     submitted key is allowed only if its canonical fingerprint is in
//     `registeredFingerprints`. An empty active set (the customer revoked every
//     agent key) therefore accepts NOTHING until a new key is enrolled —
//     revocation removes a key from use, it never silently re-opens the API key
//     to arbitrary agent keys.
//
// The comparison is on agentKeyFingerprint (which canonicalizes the SPKI PEM
// first), so two PEMs that decode to the same Ed25519 key match regardless of
// line-ending or whitespace differences. Returns true when the request is
// allowed; false when it must be rejected (including when the submitted key is
// malformed). There is no soft mode and no per-request opt-out.
export function submittedAgentKeyAllowed(args: {
  registeredFingerprints: string[];
  hasEverRegistered: boolean;
  submittedAgentPublicKey: string;
}): boolean {
  if (!args.hasEverRegistered) return true;
  try {
    const submittedFingerprint = agentKeyFingerprint(args.submittedAgentPublicKey);
    return args.registeredFingerprints.includes(submittedFingerprint);
  } catch {
    // A malformed submitted key has no fingerprint and cannot be in the set.
    return false;
  }
}

// Build the agent_identity_attestation for a receipt produced under a MATCHED
// active agent-key registration. In the registry model every registration
// carries a platform-signed proof_ref (issuer "sequesign", role "agent"), so
// the attestation always includes identity_proof and the offline verifier
// reports the agent identity as `registered`.
//
// Callers pass the matched registration's fields. The unregistered/no-match
// path (where the broker stamps NO attestation) is the caller's decision: it
// simply does not call this when there is no matched registration.
export function agentIdentityAttestationFor(args: {
  registeredAt: string;
  agentKeyFingerprint: string;
  agentIdentityProofRef: string;
}): AgentIdentityAttestation {
  return {
    registered_at: args.registeredAt,
    key_fingerprint: args.agentKeyFingerprint,
    identity_proof: {
      issuer: "sequesign",
      ref: args.agentIdentityProofRef
    }
  };
}
