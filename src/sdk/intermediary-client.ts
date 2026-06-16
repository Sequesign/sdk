// HTTP client for the Sequesign intermediary. Mirrors witness-client.ts
// in structure but talks to /v1/receipt instead of /witness. The SDK
// uses this in managed mode; direct-mode customers keep talking to
// the witness directly.
//
// Phase 4 adds multi-action chains: postReceipt accepts sequence and
// previous_chain_state explicitly, and the new postFinalize call
// uploads an assembled envelope to the intermediary for R2 storage.
// Phase 3 single-action callers continue to work unchanged.

import type {
  ActionRecord,
  AgentActionReceipt,
  EvidenceBlob,
  SatelliteWitnessAttestation,
  WitnessAttestation
} from "../lib/types.js";
import type {
  EnvelopeCustody,
  EvidenceCustody,
  IntermediaryConfig
} from "./types.js";

export const DEFAULT_INTERMEDIARY_TIMEOUT_MS = 15_000;

export interface ResolvedIntermediaryConfig {
  baseUrl: string;
  apiKey?: string;
  requestTimeoutMs: number;
  fetchImpl: typeof fetch;
}

export function resolveIntermediaryConfig(
  cfg: IntermediaryConfig
): ResolvedIntermediaryConfig {
  return {
    baseUrl: cfg.baseUrl.replace(/\/+$/, ""),
    apiKey: cfg.apiKey,
    requestTimeoutMs: cfg.requestTimeoutMs ?? DEFAULT_INTERMEDIARY_TIMEOUT_MS,
    fetchImpl: cfg.fetch ?? fetch
  };
}

// Shape 1 request body. The SDK builds the action_record locally so
// it can compute the action_record_hash and sign the agent_signature
// before the request leaves the process; the intermediary rebuilds
// the same action_record from these fields and verifies the
// signature against its own hash.
export interface PostReceiptInput {
  agentId: string;
  agentPublicKeyPem: string;
  taskId: string;
  delegatorId: string;
  actionType: string;
  // Present when evidenceCustody is "sequesign" or "both"; absent
  // when "customer" (the SDK sends evidenceHash instead).
  evidence?: unknown;
  // Present when evidenceCustody is "customer"; hex-encoded
  // SHA-256 of the canonical evidence_blob.
  evidenceHash?: string;
  verifiabilityClass?: string;
  agentSignatureBase64: string;
  policyContextHash?: string;
  chainId: string;
  receiptId: string;
  delegatedAt?: string;
  timestamp: string;
  evidenceCustody: EvidenceCustody;
  envelopeCustody: EnvelopeCustody;
  // Phase 4 multi-action chains. The SDK tracks chain state locally
  // and presents the (sequence, previousChainState) pair on every
  // call. The intermediary verifies the agent_signature against the
  // hash that derives from these fields. Default (Phase 2/3 callers):
  // sequence = 1 and previousChainState is omitted, in which case the
  // intermediary derives it from the chain id.
  sequence?: number;
  previousChainState?: string;
  // Phase 4: when true, the intermediary signs and records a billing
  // row but skips envelope assembly and R2 storage. The SDK uploads
  // the assembled envelope via postFinalize at the end of the chain.
  // ManagedSession sets this on every recordAction to keep the
  // multi-action and one-shot paths uniform.
  deferEnvelopeStorage?: boolean;
  // §3.2 PR 1: optional ActionRecord.metadata. The SDK signs the
  // assembled action record (with metadata) locally; this field
  // transmits the same metadata so broker's server-side rebuild
  // hashes identically. Absent (undefined) on every Phase 4 call
  // until §3.2; the broker drops absent metadata in canonical
  // encoding, so existing callers see no behavior change.
  metadata?: Record<string, unknown>;
  // §3.2 PR 3: optional EvidenceBlob.schema_id / schema_hash. The
  // SDK builds its evidence blob with these fields when the session
  // is in schema_validated or profile_constrained mode; transmitting
  // them lets the broker rebuild a byte-identical canonical blob
  // (and PR 9's per-action schema gate run). Both must come
  // together; the broker enforces the pairing via
  // schema_binding_incomplete.
  schemaId?: string;
  schemaHash?: string;
  // §3.1 Retention PR 1: optional per-receipt retention override.
  // Extend-only: the broker validates that the resolved
  // retention_until is at-or-past the customer-default. The two
  // forms are accepted server-side; the SDK passes them through as-
  // is so the broker is the single source of truth on validity.
  retention?: RetentionInput;
}

// §3.1 Retention PR 1: wire shape for the optional retention override
// on /v1/receipt and /v1/receipts/finalize. Mirrors the broker's
// RetentionOverrideSchema.
export type RetentionInput =
  | { until: string }
  | { duration: string };

export interface PostReceiptResult {
  receiptId: string;
  chainId: string;
  witnessAttestation: WitnessAttestation;
  envelopeSchemaVersion: string;
  // Present when envelopeCustody is "sequesign" or "both" AND the
  // legacy single-call path was used. Phase 4 deferred calls leave
  // these undefined; the SDK populates them from the postFinalize
  // response.
  r2Key?: string;
  receiptUrl?: string;
}

export interface PostFinalizeInput {
  receipt: AgentActionReceipt;
  actionRecords: ActionRecord[];
  // Present only when Sequesign holds evidence (hosted tier and the
  // advanced custody cells that send evidence). Hash-only and
  // ephemeral tiers omit this; the intermediary verifies hashes
  // against the action_records alone.
  evidenceBlobs?: EvidenceBlob[];
  // Always set: the SDK knows its own tier at every call site.
  // Mirrors PostReceiptInput so the intermediary's finalize handler
  // can branch storage the same way the per-action handler does.
  evidenceCustody: EvidenceCustody;
  envelopeCustody: EnvelopeCustody;
  // §3.1 Retention PR 1: optional per-receipt retention override.
  // Same shape and semantics as PostReceiptInput.retention; ManagedSession
  // forwards the session-level value here so the multi-action path
  // stamps retention at finalize the same way the single-action path
  // stamps it at /v1/receipt.
  retention?: RetentionInput;
}

export interface PostFinalizeResult {
  receiptId: string;
  chainId: string;
  r2Key: string;
  receiptUrl: string;
  finalActionCount: number;
  envelopeSchemaVersion: string;
}

export interface GetReceiptResult {
  receipt: AgentActionReceipt;
}

// v0.6 step #3b.3: managed-mode deferred-satellite seal. The broker's
// POST /v1/satellites (step #3b.2) relays this to the witness's
// POST /witness/satellite under the same write-key auth as finalize and
// returns the SatelliteWitnessAttestation verbatim. chain_id is the
// receipt's chain (operational metadata for the witness log); the two
// hashes are what the witness seals over.
export interface PostSatelliteInput {
  chainId: string;
  attestedReceiptHash: string;
  satelliteContentHash: string;
}

export interface IntermediaryClient {
  readonly config: ResolvedIntermediaryConfig;
  postReceipt(input: PostReceiptInput): Promise<PostReceiptResult>;
  postFinalize(input: PostFinalizeInput): Promise<PostFinalizeResult>;
  postSatellite(input: PostSatelliteInput): Promise<SatelliteWitnessAttestation>;
  getReceipt(receiptId: string): Promise<GetReceiptResult>;
}

export class IntermediaryRequestError extends Error {
  readonly code: string;
  readonly status: number;
  readonly upstream?: unknown;
  constructor(code: string, status: number, message: string, upstream?: unknown) {
    super(message);
    this.name = "IntermediaryRequestError";
    this.code = code;
    this.status = status;
    this.upstream = upstream;
  }
}

export function createIntermediaryClient(
  cfg: IntermediaryConfig
): IntermediaryClient {
  const resolved = resolveIntermediaryConfig(cfg);

  async function postReceipt(input: PostReceiptInput): Promise<PostReceiptResult> {
    const body: Record<string, unknown> = {
      agent_id: input.agentId,
      agent_public_key: input.agentPublicKeyPem,
      task_id: input.taskId,
      task_delegator_id: input.delegatorId,
      action_type: input.actionType,
      agent_signature: input.agentSignatureBase64,
      chain_id: input.chainId,
      receipt_id: input.receiptId,
      timestamp: input.timestamp,
      evidence_custody: input.evidenceCustody,
      envelope_custody: input.envelopeCustody
    };
    if (input.evidence !== undefined) body.evidence = input.evidence;
    if (input.evidenceHash !== undefined) body.evidence_hash = input.evidenceHash;
    if (input.verifiabilityClass) body.verifiability_class = input.verifiabilityClass;
    if (input.policyContextHash) body.policy_context_hash = input.policyContextHash;
    if (input.delegatedAt) body.delegated_at = input.delegatedAt;
    if (input.sequence !== undefined) body.sequence = input.sequence;
    if (input.previousChainState !== undefined)
      body.previous_chain_state = input.previousChainState;
    if (input.deferEnvelopeStorage)
      body.defer_envelope_storage = input.deferEnvelopeStorage;
    if (input.metadata !== undefined) body.metadata = input.metadata;
    if (input.schemaId !== undefined) body.schema_id = input.schemaId;
    if (input.schemaHash !== undefined) body.schema_hash = input.schemaHash;
    if (input.retention !== undefined) body.retention = input.retention;

    const response = await fetchWithTimeout(
      `${resolved.baseUrl}/v1/receipt`,
      {
        method: "POST",
        headers: buildHeaders(resolved),
        body: JSON.stringify(body)
      },
      resolved
    );
    const parsed = await parseJsonBody(response);
    if (!response.ok) {
      throw new IntermediaryRequestError(
        readErrorCode(parsed),
        response.status,
        `Intermediary POST /v1/receipt returned HTTP ${response.status}: ${readErrorReason(parsed) ?? "(no reason)"}`,
        parsed
      );
    }
    const obj = parsed as Record<string, unknown>;
    const witnessAttestation = obj.witness_attestation;
    if (!witnessAttestation || typeof witnessAttestation !== "object") {
      throw new IntermediaryRequestError(
        "intermediary_response_malformed",
        502,
        "Intermediary response did not include a witness_attestation object."
      );
    }
    return {
      receiptId: String(obj.receipt_id),
      chainId: String(obj.chain_id),
      witnessAttestation: witnessAttestation as WitnessAttestation,
      envelopeSchemaVersion: String(obj.envelope_schema_version),
      r2Key: typeof obj.r2_key === "string" ? obj.r2_key : undefined,
      receiptUrl: typeof obj.receipt_url === "string" ? obj.receipt_url : undefined
    };
  }

  async function postFinalize(input: PostFinalizeInput): Promise<PostFinalizeResult> {
    const body: Record<string, unknown> = {
      receipt: input.receipt,
      action_records: input.actionRecords,
      evidence_custody: input.evidenceCustody,
      envelope_custody: input.envelopeCustody
    };
    if (input.evidenceBlobs) body.evidence_blobs = input.evidenceBlobs;
    if (input.retention !== undefined) body.retention = input.retention;

    const response = await fetchWithTimeout(
      `${resolved.baseUrl}/v1/receipts/finalize`,
      {
        method: "POST",
        headers: buildHeaders(resolved),
        body: JSON.stringify(body)
      },
      resolved
    );
    const parsed = await parseJsonBody(response);
    if (!response.ok) {
      throw new IntermediaryRequestError(
        readErrorCode(parsed),
        response.status,
        `Intermediary POST /v1/receipts/finalize returned HTTP ${response.status}: ${readErrorReason(parsed) ?? "(no reason)"}`,
        parsed
      );
    }
    const obj = parsed as Record<string, unknown>;
    if (
      typeof obj.r2_key !== "string" ||
      typeof obj.receipt_url !== "string" ||
      typeof obj.final_action_count !== "number"
    ) {
      throw new IntermediaryRequestError(
        "intermediary_response_malformed",
        502,
        "Intermediary /v1/receipts/finalize response is missing r2_key, receipt_url, or final_action_count."
      );
    }
    return {
      receiptId: String(obj.receipt_id),
      chainId: String(obj.chain_id),
      r2Key: obj.r2_key,
      receiptUrl: obj.receipt_url,
      finalActionCount: obj.final_action_count,
      envelopeSchemaVersion: String(obj.envelope_schema_version)
    };
  }

  async function postSatellite(
    input: PostSatelliteInput
  ): Promise<SatelliteWitnessAttestation> {
    const response = await fetchWithTimeout(
      `${resolved.baseUrl}/v1/satellites`,
      {
        method: "POST",
        headers: buildHeaders(resolved),
        body: JSON.stringify({
          chain_id: input.chainId,
          attested_receipt_hash: input.attestedReceiptHash,
          satellite_content_hash: input.satelliteContentHash
        })
      },
      resolved
    );
    const parsed = await parseJsonBody(response);
    if (!response.ok) {
      throw new IntermediaryRequestError(
        readErrorCode(parsed),
        response.status,
        `Intermediary POST /v1/satellites returned HTTP ${response.status}: ${readErrorReason(parsed) ?? "(no reason)"}`,
        parsed
      );
    }
    if (!parsed || typeof parsed !== "object") {
      throw new IntermediaryRequestError(
        "intermediary_response_malformed",
        502,
        "Intermediary POST /v1/satellites response was not a JSON object."
      );
    }
    return parsed as SatelliteWitnessAttestation;
  }

  async function getReceipt(receiptId: string): Promise<GetReceiptResult> {
    const response = await fetchWithTimeout(
      `${resolved.baseUrl}/v1/receipts/${encodeURIComponent(receiptId)}`,
      {
        method: "GET",
        headers: buildHeaders(resolved)
      },
      resolved
    );
    const parsed = await parseJsonBody(response);
    if (!response.ok) {
      throw new IntermediaryRequestError(
        readErrorCode(parsed),
        response.status,
        `Intermediary GET /v1/receipts/${receiptId} returned HTTP ${response.status}: ${readErrorReason(parsed) ?? "(no reason)"}`,
        parsed
      );
    }
    return { receipt: parsed as AgentActionReceipt };
  }

  return {
    config: resolved,
    postReceipt,
    postFinalize,
    postSatellite,
    getReceipt
  };
}

function buildHeaders(cfg: ResolvedIntermediaryConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json"
  };
  if (cfg.apiKey) headers.authorization = `Bearer ${cfg.apiKey}`;
  return headers;
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  cfg: ResolvedIntermediaryConfig
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.requestTimeoutMs);
  try {
    return await cfg.fetchImpl(url, { ...init, signal: controller.signal });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new IntermediaryRequestError(
        "intermediary_timeout",
        504,
        `Intermediary did not respond within ${cfg.requestTimeoutMs}ms.`
      );
    }
    throw new IntermediaryRequestError(
      "intermediary_unreachable",
      502,
      `Intermediary request failed: ${err instanceof Error ? err.message : String(err)}`
    );
  } finally {
    clearTimeout(timer);
  }
}

async function parseJsonBody(response: Response): Promise<unknown> {
  const text = await response.text().catch(() => "");
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function readErrorCode(parsed: unknown): string {
  if (parsed && typeof parsed === "object") {
    const code = (parsed as Record<string, unknown>).code;
    if (typeof code === "string") return code;
  }
  return "intermediary_error";
}

function readErrorReason(parsed: unknown): string | undefined {
  if (parsed && typeof parsed === "object") {
    const reason = (parsed as Record<string, unknown>).reason;
    if (typeof reason === "string") return reason;
  }
  return undefined;
}
