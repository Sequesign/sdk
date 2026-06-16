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
  fetchWitnessKey(): Promise<WitnessIdentity>;
  setStatic(identity: WitnessIdentity): void;
}

export interface KeyDiscoveryOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
  cacheMs?: number;
  staticIdentity?: WitnessIdentity;
}

export function createKeyDiscoveryClient(opts: KeyDiscoveryOptions): KeyDiscoveryClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const cacheMs = opts.cacheMs ?? DEFAULT_CACHE_MS;
  let cached: { identity: WitnessIdentity; fetchedAt: number } | null = opts.staticIdentity
    ? { identity: opts.staticIdentity, fetchedAt: Number.POSITIVE_INFINITY }
    : null;

  const base = opts.baseUrl.replace(/\/+$/, "");

  async function fetchServiceDescription(): Promise<WitnessServiceDescription> {
    let response: Response;
    try {
      response = await fetchImpl(`${base}/`, { method: "GET" });
    } catch (err) {
      throw new WitnessUnavailableError(
        `Unable to reach witness service at ${base}/.`,
        err
      );
    }
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
  }

  async function fetchDiscovery(): Promise<WitnessIdentity> {
    let response: Response;
    try {
      response = await fetchImpl(`${base}/.well-known/sequesign/keys.json`, { method: "GET" });
    } catch (err) {
      throw new WitnessUnavailableError(
        `Unable to reach witness key discovery at ${base}/.well-known/sequesign/keys.json.`,
        err
      );
    }
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
    const witnessKey = doc.keys.find((k) => k.key_type === "witness");
    if (!witnessKey) {
      throw new WitnessUnavailableError(
        "Witness key discovery document did not contain a key with key_type=witness."
      );
    }
    return {
      witnessId: "",
      keyId: witnessKey.key_id,
      publicKeyPem: witnessKey.public_key,
      validFrom: witnessKey.valid_from
    };
  }

  return {
    async fetchServiceDescription() {
      return fetchServiceDescription();
    },
    async fetchWitnessKey(): Promise<WitnessIdentity> {
      if (cached && Date.now() - cached.fetchedAt < cacheMs) {
        return cached.identity;
      }
      const identity = await fetchDiscovery();
      cached = { identity, fetchedAt: Date.now() };
      return identity;
    },
    setStatic(identity: WitnessIdentity) {
      cached = { identity, fetchedAt: Number.POSITIVE_INFINITY };
    }
  };
}
