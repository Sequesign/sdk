import type { KeyDiscoveryDocument, WitnessServiceDescription } from "../lib/witness-types.js";
import { WitnessUnavailableError } from "./errors.js";

const DEFAULT_CACHE_MS = 5 * 60 * 1000;

export interface WitnessIdentity {
  witnessId: string;
  keyId: string;
  publicKeyPem: string;
  validFrom: string;
}

export interface KeyDiscoveryClient {
  fetchServiceDescription(): Promise<WitnessServiceDescription>;
  // `force` bypasses the time cache and re-fetches the discovery document. Used
  // when a witness signature fails to verify against the cached key, which
  // strongly implies the witness rotated: without a forced refresh a client that
  // fetched < cacheMs before a cutover would keep returning the stale key and
  // fail its first new-key attestation with a non-retriable mismatch. A
  // statically pinned identity is never re-fetched, even with force. Returns the
  // ACTIVE witness key (the first key_type=witness entry).
  fetchWitnessKey(force?: boolean): Promise<WitnessIdentity>;
  // Every published witness key, active first then any retired entries. Used to
  // resolve a signature mismatch during an HA rolling cutover: the attestation
  // may have been signed by a key that is now published only as a RETIRED entry
  // (its signing machine drained before our discovery GET), so the resolver must
  // be able to verify against every witness key, not just the active one. A
  // statically pinned identity returns just the pinned key and never re-fetches.
  fetchAllWitnessKeys(force?: boolean): Promise<WitnessIdentity[]>;
  setStatic(identity: WitnessIdentity): void;
}

export interface KeyDiscoveryOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  cacheMs?: number;
  // Bounds each discovery/service GET. Without it a discovery endpoint that
  // accepts the connection but never responds would hang the caller — including
  // the forced rediscovery now issued from the post-200 signing path.
  requestTimeoutMs?: number;
  staticIdentity?: WitnessIdentity;
}

export function createKeyDiscoveryClient(opts: KeyDiscoveryOptions): KeyDiscoveryClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const cacheMs = opts.cacheMs ?? DEFAULT_CACHE_MS;
  const requestTimeoutMs = opts.requestTimeoutMs;
  // identities[0] is the active witness key; the rest are retired entries. A
  // static pin caches a single identity at fetchedAt === Infinity (never
  // re-fetched).
  let cached: { identities: WitnessIdentity[]; fetchedAt: number } | null = opts.staticIdentity
    ? { identities: [opts.staticIdentity], fetchedAt: Number.POSITIVE_INFINITY }
    : null;

  const base = opts.baseUrl.replace(/\/+$/, "");

  // Issues a GET whose timeout stays armed until the RESPONSE BODY has been
  // fully read — the returned `release` must be called only after the caller
  // consumes the body. Clearing the timer as soon as the headers arrive would
  // leave a server that stalls the body able to hang the caller indefinitely
  // (the forced post-200 rediscovery sits in the signing hot path), so the abort
  // controller must outlive the `.json()` read, not just the fetch.
  async function fetchWithTimeout(
    url: string
  ): Promise<{ response: Response; release: () => void }> {
    if (!requestTimeoutMs || requestTimeoutMs <= 0) {
      const response = await fetchImpl(url, { method: "GET" });
      return { response, release: () => {} };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetchImpl(url, { method: "GET", signal: controller.signal });
      return { response, release: () => clearTimeout(timer) };
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  async function fetchServiceDescription(): Promise<WitnessServiceDescription> {
    let response: Response;
    let release: () => void;
    try {
      ({ response, release } = await fetchWithTimeout(`${base}/`));
    } catch (err) {
      throw new WitnessUnavailableError(`Unable to reach witness service at ${base}/.`, err);
    }
    try {
      if (!response.ok) {
        throw new WitnessUnavailableError(
          `Witness service at ${base}/ responded with status ${response.status}.`
        );
      }
      try {
        return (await response.json()) as WitnessServiceDescription;
      } catch (err) {
        throw new WitnessUnavailableError(
          `Witness service at ${base}/ returned an unparsable JSON body.`,
          err
        );
      }
    } finally {
      release();
    }
  }

  async function fetchDiscovery(): Promise<WitnessIdentity[]> {
    let response: Response;
    let release: () => void;
    try {
      ({ response, release } = await fetchWithTimeout(`${base}/.well-known/sequesign/keys.json`));
    } catch (err) {
      throw new WitnessUnavailableError(
        `Unable to reach witness key discovery at ${base}/.well-known/sequesign/keys.json.`,
        err
      );
    }
    try {
      if (!response.ok) {
        throw new WitnessUnavailableError(
          `Witness key discovery responded with status ${response.status}.`
        );
      }
      let doc: KeyDiscoveryDocument;
      try {
        doc = (await response.json()) as KeyDiscoveryDocument;
      } catch (err) {
        throw new WitnessUnavailableError(
          "Witness key discovery returned an unparsable JSON body.",
          err
        );
      }
      // Every witness key (active + retired). buildKeyDiscoveryDocument emits the
      // active key first, then retired entries, all with key_type=witness.
      const witnessKeys = doc.keys.filter((k) => k.key_type === "witness");
      if (witnessKeys.length === 0) {
        throw new WitnessUnavailableError(
          "Witness key discovery document did not contain a key with key_type=witness."
        );
      }
      return witnessKeys.map((k) => ({
        witnessId: "",
        keyId: k.key_id,
        publicKeyPem: k.public_key,
        validFrom: k.valid_from
      }));
    } finally {
      release();
    }
  }

  // Returns the cached identities, re-fetching when the cache is empty, expired,
  // or explicitly forced. A statically pinned identity (fetchedAt === Infinity)
  // is never re-fetched, even on force — the caller pinned it deliberately.
  async function ensureFresh(force: boolean): Promise<WitnessIdentity[]> {
    const isStatic = cached !== null && cached.fetchedAt === Number.POSITIVE_INFINITY;
    if (cached && (isStatic || (!force && Date.now() - cached.fetchedAt < cacheMs))) {
      return cached.identities;
    }
    const identities = await fetchDiscovery();
    cached = { identities, fetchedAt: Date.now() };
    return identities;
  }

  return {
    async fetchServiceDescription() {
      return fetchServiceDescription();
    },
    async fetchWitnessKey(force = false): Promise<WitnessIdentity> {
      const identities = await ensureFresh(force);
      return identities[0];
    },
    async fetchAllWitnessKeys(force = false): Promise<WitnessIdentity[]> {
      return ensureFresh(force);
    },
    setStatic(identity: WitnessIdentity) {
      cached = { identities: [identity], fetchedAt: Number.POSITIVE_INFINITY };
    }
  };
}
