import { verifyEd25519 } from "../lib/keys.js";
import { satelliteWitnessMessage, witnessAttestationMessage } from "../lib/messages.js";
import type { BatchInclusionProof, SatelliteWitnessAttestation } from "../lib/types.js";
import type {
  WitnessRequest,
  WitnessAttestation,
  WitnessAgentIdentity
} from "../lib/witness-types.js";
import {
  InclusionProofTimeoutError,
  WitnessKeyRotationLoopError,
  WitnessRequestFailedError,
  WitnessResponseMismatchError,
  WitnessSignatureMismatchError,
  WitnessUnavailableError
} from "./errors.js";
import { createKeyDiscoveryClient, type KeyDiscoveryClient, type WitnessIdentity } from "./key-discovery.js";
import type { WitnessConfig } from "./types.js";

export const DEFAULT_WITNESS_BASE_URL = "https://witness.sequesign.com";
export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_ATTEMPTS = 3;
export const DEFAULT_BASE_DELAY_MS = 250;
export const DEFAULT_BACKOFF_CAP_MS = 2_000;

export interface ResolvedWitnessConfig {
  baseUrl: string;
  witnessId?: string;
  apiKey?: string;
  requestTimeoutMs: number;
  maxAttempts: number;
  retryBaseDelayMs: number;
  retryBackoffCapMs: number;
  fetchImpl: typeof fetch;
  staticIdentity?: WitnessIdentity;
}

export function resolveWitnessConfig(
  override: WitnessConfig | undefined,
  defaults: WitnessConfig | undefined
): ResolvedWitnessConfig {
  const baseUrl = (
    override?.baseUrl ?? defaults?.baseUrl ?? DEFAULT_WITNESS_BASE_URL
  ).replace(/\/+$/, "");
  const witnessId = override?.witnessId ?? defaults?.witnessId;
  const apiKey = override?.apiKey ?? defaults?.apiKey;
  const requestTimeoutMs =
    override?.requestTimeoutMs ?? defaults?.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxAttempts = override?.maxAttempts ?? defaults?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const retryBaseDelayMs =
    override?.retryBaseDelayMs ?? defaults?.retryBaseDelayMs ?? DEFAULT_BASE_DELAY_MS;
  const retryBackoffCapMs =
    override?.retryBackoffCapMs ?? defaults?.retryBackoffCapMs ?? DEFAULT_BACKOFF_CAP_MS;
  const fetchImpl = override?.fetch ?? defaults?.fetch ?? fetch;
  const staticKey = override?.staticKey ?? defaults?.staticKey;
  return {
    baseUrl,
    witnessId,
    apiKey,
    requestTimeoutMs,
    maxAttempts,
    retryBaseDelayMs,
    retryBackoffCapMs,
    fetchImpl,
    staticIdentity: staticKey
      ? {
          witnessId: staticKey.witnessId ?? "",
          keyId: staticKey.keyId,
          publicKeyPem: staticKey.publicKeyPem,
          validFrom: new Date(0).toISOString()
        }
      : undefined
  };
}

export interface FetchInclusionProofOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}

export const DEFAULT_INCLUSION_PROOF_TIMEOUT_MS = 30_000;
export const DEFAULT_INCLUSION_PROOF_POLL_MS = 2_000;

// v0.6 step #3b.3: the request the SDK sends to seal a deferred-attestation
// satellite (witness POST /witness/satellite). chain_id is operational
// metadata (it scopes the witness log row, like the per-action path); only
// satelliteContentHash is sealed. attestedReceiptHash is carried so the
// witness can record the receipt binding on the log entry.
export interface SatelliteSealRequest {
  chainId: string;
  attestedReceiptHash: string;
  satelliteContentHash: string;
}

// The result of a witnessed commitment. agentIdentity is present only when the
// request carried agent_public_key and the witness confirmed it matches the key
// registered to the API key — the SDK turns it into a registered
// agent_identity_attestation. The attestation itself never carries it.
export interface WitnessSignResult {
  attestation: WitnessAttestation;
  agentIdentity?: WitnessAgentIdentity;
}

export interface WitnessClient {
  readonly config: ResolvedWitnessConfig;
  readonly witnessId: string;
  readonly currentKey: WitnessIdentity;
  signCommitment(request: WitnessRequest): Promise<WitnessSignResult>;
  signSatellite(request: SatelliteSealRequest): Promise<SatelliteWitnessAttestation>;
  fetchInclusionProof(
    args: { position: number; logId: string },
    opts?: FetchInclusionProofOptions
  ): Promise<BatchInclusionProof>;
}

export async function connectWitness(
  config: ResolvedWitnessConfig
): Promise<WitnessClient> {
  const discovery: KeyDiscoveryClient = createKeyDiscoveryClient({
    baseUrl: config.baseUrl,
    fetchImpl: config.fetchImpl,
    staticIdentity: config.staticIdentity
  });

  let witnessId = config.witnessId ?? "";
  if (!config.staticIdentity || !witnessId) {
    const description = await discovery.fetchServiceDescription();
    if (!witnessId) witnessId = description.witness_id;
  }

  let currentKey = await discovery.fetchWitnessKey();
  currentKey = { ...currentKey, witnessId };
  if (config.staticIdentity) {
    discovery.setStatic({ ...config.staticIdentity, witnessId });
    currentKey = { ...config.staticIdentity, witnessId };
  }

  async function signCommitment(request: WitnessRequest): Promise<WitnessSignResult> {
    let seenKeyIds = new Set<string>([currentKey.keyId]);
    let lastError: unknown;
    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
      try {
        const response = await doSingleAttempt(config, request);
        // Keep the agent_identity (a session-level credential) out of the
        // per-action witness attestation that lands in the receipt envelope.
        const { agent_identity: agentIdentity, ...attestation } = response;
        validateResponseShape(request, attestation);
        if (witnessId && attestation.witness_id !== witnessId) {
          throw new WitnessResponseMismatchError(
            "witness_id",
            witnessId,
            attestation.witness_id
          );
        }
        let verified = verifyAttestation(attestation, currentKey);
        if (!verified) {
          const refreshed = await discovery.fetchWitnessKey();
          const refreshedWithId: WitnessIdentity = { ...refreshed, witnessId };
          if (refreshedWithId.keyId !== currentKey.keyId) {
            if (seenKeyIds.has(refreshedWithId.keyId)) {
              throw new WitnessKeyRotationLoopError();
            }
            seenKeyIds.add(refreshedWithId.keyId);
            currentKey = refreshedWithId;
            verified = verifyAttestation(attestation, currentKey);
          }
          if (!verified) {
            throw new WitnessSignatureMismatchError(currentKey.keyId);
          }
        }
        return { attestation, agentIdentity };
      } catch (err) {
        lastError = err;
        if (!isRetriable(err) || attempt === config.maxAttempts) {
          if (err instanceof WitnessUnavailableError) throw err;
          if (err instanceof WitnessSignatureMismatchError) throw err;
          if (err instanceof WitnessKeyRotationLoopError) throw err;
          if (err instanceof WitnessResponseMismatchError) throw err;
          if (err instanceof WitnessRequestFailedError) throw err;
          throw new WitnessRequestFailedError(
            `Witness POST /witness failed after ${attempt} attempt(s).`,
            attempt,
            undefined,
            err
          );
        }
        await sleep(backoffDelay(attempt, config));
      }
    }
    throw new WitnessRequestFailedError(
      `Witness POST /witness exhausted ${config.maxAttempts} attempts.`,
      config.maxAttempts,
      undefined,
      lastError
    );
  }

  async function signSatellite(
    request: SatelliteSealRequest
  ): Promise<SatelliteWitnessAttestation> {
    // Mirrors signCommitment: same retry/backoff and one-shot key-rotation
    // refresh, but the seal covers satelliteContentHash (its own message
    // domain) rather than a chain action.
    let seenKeyIds = new Set<string>([currentKey.keyId]);
    let lastError: unknown;
    for (let attempt = 1; attempt <= config.maxAttempts; attempt++) {
      try {
        const attestation = await doSingleSatelliteAttempt(config, request);
        if (attestation.satellite_content_hash !== request.satelliteContentHash) {
          throw new WitnessResponseMismatchError(
            "satellite_content_hash",
            request.satelliteContentHash,
            attestation.satellite_content_hash
          );
        }
        if (witnessId && attestation.witness_id !== witnessId) {
          throw new WitnessResponseMismatchError("witness_id", witnessId, attestation.witness_id);
        }
        let verified = verifySatelliteAttestation(attestation, currentKey);
        if (!verified) {
          const refreshed = await discovery.fetchWitnessKey();
          const refreshedWithId: WitnessIdentity = { ...refreshed, witnessId };
          if (refreshedWithId.keyId !== currentKey.keyId) {
            if (seenKeyIds.has(refreshedWithId.keyId)) {
              throw new WitnessKeyRotationLoopError();
            }
            seenKeyIds.add(refreshedWithId.keyId);
            currentKey = refreshedWithId;
            verified = verifySatelliteAttestation(attestation, currentKey);
          }
          if (!verified) {
            throw new WitnessSignatureMismatchError(currentKey.keyId);
          }
        }
        return attestation;
      } catch (err) {
        lastError = err;
        if (!isRetriable(err) || attempt === config.maxAttempts) {
          if (err instanceof WitnessUnavailableError) throw err;
          if (err instanceof WitnessSignatureMismatchError) throw err;
          if (err instanceof WitnessKeyRotationLoopError) throw err;
          if (err instanceof WitnessResponseMismatchError) throw err;
          if (err instanceof WitnessRequestFailedError) throw err;
          throw new WitnessRequestFailedError(
            `Witness POST /witness/satellite failed after ${attempt} attempt(s).`,
            attempt,
            undefined,
            err
          );
        }
        await sleep(backoffDelay(attempt, config));
      }
    }
    throw new WitnessRequestFailedError(
      `Witness POST /witness/satellite exhausted ${config.maxAttempts} attempts.`,
      config.maxAttempts,
      undefined,
      lastError
    );
  }

  async function fetchInclusionProof(
    args: { position: number; logId: string },
    opts: FetchInclusionProofOptions = {}
  ): Promise<BatchInclusionProof> {
    const { position, logId } = args;
    const timeoutMs = opts.timeoutMs ?? DEFAULT_INCLUSION_PROOF_TIMEOUT_MS;
    const pollIntervalMs = opts.pollIntervalMs ?? DEFAULT_INCLUSION_PROOF_POLL_MS;
    const deadline = Date.now() + timeoutMs;
    const headers: Record<string, string> = {};
    // The witness's inclusion endpoint is public, so the API key is
    // optional. Sending it is harmless against the hosted witness; a
    // self-hosted witness that opted into auth can still consume it.
    if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`;
    // Poll until we get a proof or time out. The witness returns 202
    // with a Retry-After header while the batch has not sealed yet;
    // we honor the header as a hint but never block longer than the
    // configured pollIntervalMs.
    const inclusionUrl = `${config.baseUrl}/log/inclusion/${position}?log_id=${encodeURIComponent(logId)}`;
    while (true) {
      const controller = new AbortController();
      const reqTimeout = setTimeout(() => controller.abort(), config.requestTimeoutMs);
      let response: Response;
      try {
        response = await config.fetchImpl(inclusionUrl, {
          method: "GET",
          headers,
          signal: controller.signal
        });
      } finally {
        clearTimeout(reqTimeout);
      }
      if (response.status === 200) {
        return (await response.json()) as BatchInclusionProof;
      }
      if (response.status !== 202) {
        const body = await response.text().catch(() => "");
        throw new WitnessRequestFailedError(
          `Witness GET /log/inclusion/${position} returned HTTP ${response.status}: ${body}`,
          1,
          response.status
        );
      }
      // Pending: respect Retry-After if smaller than our cap; cap at
      // pollIntervalMs so we wake up regularly to check the deadline.
      const retryAfterHeader = response.headers.get("retry-after");
      const retryAfterSeconds = retryAfterHeader ? Number(retryAfterHeader) : NaN;
      const waitMs =
        Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
          ? Math.min(retryAfterSeconds * 1000, pollIntervalMs)
          : pollIntervalMs;
      if (Date.now() + waitMs > deadline) {
        throw new InclusionProofTimeoutError(position, timeoutMs);
      }
      await sleep(waitMs);
      if (Date.now() >= deadline) {
        throw new InclusionProofTimeoutError(position, timeoutMs);
      }
    }
  }

  return {
    config,
    witnessId,
    get currentKey() {
      return currentKey;
    },
    signCommitment,
    signSatellite,
    fetchInclusionProof
  };
}

class RetriableHttpError extends Error {
  readonly status: number;
  readonly attempt: number;
  constructor(status: number, attempt: number, body: string) {
    super(`Witness POST /witness returned HTTP ${status}: ${body}`);
    this.status = status;
    this.attempt = attempt;
  }
}

class NonRetriableHttpError extends Error {
  readonly status: number;
  constructor(status: number, body: string) {
    super(`Witness POST /witness returned HTTP ${status}: ${body}`);
    this.status = status;
  }
}

async function doSingleAttempt(
  config: ResolvedWitnessConfig,
  request: WitnessRequest
): Promise<WitnessAttestation & { key_id?: string; agent_identity?: WitnessAgentIdentity }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.requestTimeoutMs);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`;
  let response: Response;
  try {
    response = await config.fetchImpl(`${config.baseUrl}/witness`, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
      signal: controller.signal
    });
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
  clearTimeout(timeout);
  if (response.status === 200) {
    return (await response.json()) as WitnessAttestation & {
      key_id?: string;
      agent_identity?: WitnessAgentIdentity;
    };
  }
  const body = await response.text().catch(() => "");
  if (response.status >= 500 || response.status === 408) {
    throw new RetriableHttpError(response.status, 0, body);
  }
  throw new NonRetriableHttpError(response.status, body);
}

async function doSingleSatelliteAttempt(
  config: ResolvedWitnessConfig,
  request: SatelliteSealRequest
): Promise<SatelliteWitnessAttestation> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.requestTimeoutMs);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`;
  let response: Response;
  try {
    response = await config.fetchImpl(`${config.baseUrl}/witness/satellite`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        chain_id: request.chainId,
        attested_receipt_hash: request.attestedReceiptHash,
        satellite_content_hash: request.satelliteContentHash
      }),
      signal: controller.signal
    });
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
  clearTimeout(timeout);
  if (response.status === 200) {
    return (await response.json()) as SatelliteWitnessAttestation;
  }
  const body = await response.text().catch(() => "");
  if (response.status >= 500 || response.status === 408) {
    throw new RetriableHttpError(response.status, 0, body);
  }
  throw new NonRetriableHttpError(response.status, body);
}

function verifySatelliteAttestation(
  attestation: SatelliteWitnessAttestation,
  key: WitnessIdentity
): boolean {
  const message = satelliteWitnessMessage({
    witnessId: attestation.witness_id,
    satelliteContentHash: attestation.satellite_content_hash,
    witnessedAt: attestation.witnessed_at
  });
  return verifyEd25519(key.publicKeyPem, message, attestation.signature);
}

function validateResponseShape(request: WitnessRequest, attestation: WitnessAttestation): void {
  const fields = [
    "chain_id",
    "sequence",
    "action_record_hash",
    "previous_chain_state",
    "chain_state"
  ] as const;
  for (const field of fields) {
    if (attestation[field] !== request[field]) {
      throw new WitnessResponseMismatchError(
        field,
        request[field],
        attestation[field]
      );
    }
  }
}

function verifyAttestation(attestation: WitnessAttestation, key: WitnessIdentity): boolean {
  const message = witnessAttestationMessage({
    witnessId: attestation.witness_id,
    chainId: attestation.chain_id,
    sequence: attestation.sequence,
    actionRecordHash: attestation.action_record_hash,
    previousChainState: attestation.previous_chain_state,
    chainState: attestation.chain_state,
    witnessedAt: attestation.witnessed_at
  });
  return verifyEd25519(key.publicKeyPem, message, attestation.signature);
}

function isRetriable(err: unknown): boolean {
  if (err instanceof RetriableHttpError) return true;
  if (err instanceof Error) {
    if (err.name === "AbortError") return true;
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "ETIMEDOUT") return true;
    if (err.message.toLowerCase().includes("fetch failed")) return true;
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffDelay(attempt: number, config: ResolvedWitnessConfig): number {
  const exponential = config.retryBaseDelayMs * Math.pow(2, attempt - 1);
  const capped = Math.min(exponential, config.retryBackoffCapMs);
  return Math.floor(Math.random() * capped);
}
