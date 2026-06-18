// Agent-identity enforcement and attestation helpers, shared by the broker
// (managed mode), the witness (direct mode), and the SDK. Moved here from
// apps/broker/src/agent-identity.ts so all three transports enforce and stamp
// agent identity identically against one source of truth.

import { agentKeyFingerprint } from "./hash.js";
import { canonicalizeEd25519PublicKeyPem } from "./keys.js";
import type { AgentIdentityAttestation } from "./types.js";

// Hard enforcement: when the authenticated API key is registered
// (registeredAgentPublicKey non-null), the public key the request presents must
// match the registered key. The match is on the CANONICAL SPKI PEM of each key,
// not raw bytes: two PEMs that decode to the same Ed25519 key are the same key,
// so line-ending or whitespace differences must not cause a false rejection.
// Returns true when the request is allowed (unregistered key, or registered key
// whose submitted key canonicalizes equal to the registered one); false when it
// must be rejected (including when the submitted key is malformed). There is no
// soft mode and no per-request opt-out.
export function submittedAgentKeyAllowed(args: {
  registeredAgentPublicKey: string | null;
  submittedAgentPublicKey: string;
}): boolean {
  if (args.registeredAgentPublicKey === null) return true;
  try {
    return (
      canonicalizeEd25519PublicKeyPem(args.submittedAgentPublicKey) ===
      canonicalizeEd25519PublicKeyPem(args.registeredAgentPublicKey)
    );
  } catch {
    // A malformed submitted (or registered) key cannot match.
    return false;
  }
}

// Build the agent_identity_attestation for a receipt produced under a
// registered API key, or undefined for an unregistered key. Both
// agentPublicKey/agentKeyRegisteredAt are non-null together for a registered
// key (enforced by the api_keys_agent_identity_both_or_neither DB CHECK); we
// guard defensively and return undefined unless both are present. The
// fingerprint is computed over the registered key, which equals the embedded
// agent_public_key once enforcement (submittedAgentKeyAllowed) has confirmed
// the match.
//
// agentIdentityProofRef is the platform-signed agent registration record
// (base64url(SignedRegistrationRecord), issuer "sequesign", role "agent")
// minted at API-key creation. When present we attach it as identity_proof so
// the offline verifier reports the agent identity as `registered` (verifying
// the proof against the published platform registration key). When null — an
// unregistered key, or a registered key created before the proof column existed
// — we still stamp the attestation, but without identity_proof, so the verifier
// reports it as `self_asserted`.
export function agentIdentityAttestationFor(args: {
  agentPublicKey: string | null;
  agentKeyRegisteredAt: string | null;
  agentIdentityProofRef: string | null;
}): AgentIdentityAttestation | undefined {
  if (args.agentPublicKey === null || args.agentKeyRegisteredAt === null) {
    return undefined;
  }
  const attestation: AgentIdentityAttestation = {
    registered_at: args.agentKeyRegisteredAt,
    key_fingerprint: agentKeyFingerprint(args.agentPublicKey)
  };
  if (args.agentIdentityProofRef !== null) {
    attestation.identity_proof = {
      issuer: "sequesign",
      ref: args.agentIdentityProofRef
    };
  }
  return attestation;
}
