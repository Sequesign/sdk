import { lengthPrefixedUtf8 } from "./encoding.js";
export function chainExtensionMessage(p: {
  chainId: string;
  sequence: number;
  previousChainState: string;
  actionRecordHash: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_CHAIN_V0",
    p.chainId,
    String(p.sequence),
    p.previousChainState,
    p.actionRecordHash
  ]);
}
export function agentAttestationMessage(p: {
  chainId: string;
  sequence: number;
  actionRecordHash: string;
  chainState: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_AGENT_ATTESTATION_V0",
    p.chainId,
    String(p.sequence),
    p.actionRecordHash,
    p.chainState
  ]);
}
export function witnessAttestationMessage(p: {
  witnessId: string;
  chainId: string;
  sequence: number;
  actionRecordHash: string;
  previousChainState: string;
  chainState: string;
  witnessedAt: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_WITNESS_ATTESTATION_V0",
    p.witnessId,
    p.chainId,
    String(p.sequence),
    p.actionRecordHash,
    p.previousChainState,
    p.chainState,
    p.witnessedAt
  ]);
}
// v0.6 arc: renamed from humanApprovalMessage. `partyType` is now part
// of the signed bytes, so the domain suffix bumps
// (SEQUESIGN_HUMAN_APPROVAL_V0 -> SEQUESIGN_APPROVAL_V1) — two payload
// shapes must never share one domain string (spec §10). partyType is
// appended after approverId so the field order documents the addition.
export function approvalMessage(p: {
  approvalId: string;
  approverId: string;
  partyType: "human" | "agent";
  approvedTaskId: string;
  approvedActionType: string;
  approvalContextHash: string;
  approvedAt: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_APPROVAL_V1",
    p.approvalId,
    p.approverId,
    p.partyType,
    p.approvedTaskId,
    p.approvedActionType,
    p.approvalContextHash,
    p.approvedAt
  ]);
}
// v0.6 step #3 (deferred satellites). A witness seals a detached satellite
// at its own time T_i by signing over the satellite's content hash (which
// covers attested_receipt_hash + the inner attestation — see
// satelliteContentHash in verify.ts), NOT a chain action, so it has its own
// domain. Two payload shapes must never share a domain string (spec §10).
export function satelliteWitnessMessage(p: {
  witnessId: string;
  satelliteContentHash: string;
  witnessedAt: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_SATELLITE_WITNESS_V1",
    p.witnessId,
    p.satelliteContentHash,
    p.witnessedAt
  ]);
}
export function counterpartyAttestationMessage(p: {
  counterpartyId: string;
  chainId: string;
  attestedActionId: string;
  attestedContentHash: string;
  attestationPurpose: string;
  attestedAt: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_COUNTERPARTY_ATTESTATION_V0",
    p.counterpartyId,
    p.chainId,
    p.attestedActionId,
    p.attestedContentHash,
    p.attestationPurpose,
    p.attestedAt
  ]);
}
// v0.6 step #4 (vouching): the platform signs this over a registration record,
// binding an attestation key (by fingerprint) to a named identity + role. The
// verifier rebuilds it from the record fields and checks the platform signature
// against a trusted platform key. party_type is "" when absent (counterparty).
export function registrationRecordMessage(p: {
  schemaVersion: string;
  issuer: string;
  role: string;
  partyType?: string;
  subjectKeyFingerprint: string;
  // Omitted for the agent role (key-only registration, no named identity);
  // always present for approver/counterparty. Encoded as "" when absent, which
  // leaves approver/counterparty bytes unchanged (they always pass a real
  // identity) and never collides across roles (role is its own field).
  identity?: string;
  registeredAt: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_REGISTRATION_RECORD_V1",
    p.schemaVersion,
    p.issuer,
    p.role,
    p.partyType ?? "",
    p.subjectKeyFingerprint,
    p.identity ?? "",
    p.registeredAt
  ]);
}
// v0.6 step #4.3 (vouching): proof-of-possession challenge. The SUBJECT
// (approver/counterparty) signs this with its OWN private key at enrollment, so
// the platform only vouches a key whose holder proves control — an account
// cannot register someone else's public key under an identity of its choosing.
// Distinct domain from the platform-signed record (and every attestation), per
// spec §10: two payload shapes must never share a domain string. Binds the
// exact (role, party_type, identity, key) so a captured PoP cannot be replayed
// for a different identity or role. party_type is "" when absent (counterparty).
export function registrationChallengeMessage(p: {
  role: string;
  partyType?: string;
  identity: string;
  subjectKeyFingerprint: string;
}): Buffer {
  return lengthPrefixedUtf8([
    "SEQUESIGN_REGISTRATION_CHALLENGE_V1",
    p.role,
    p.partyType ?? "",
    p.identity,
    p.subjectKeyFingerprint
  ]);
}
