// Dynamic template registry — Phase 1 (issue #440): a source abstraction over
// template (profile) discovery, so the SDK can resolve a mandate template from
// more than just the bundled package files — a remote registry, a warm cache —
// WITHOUT weakening any trust property.
//
// The one rule that makes this safe: fetching is DISCOVERY ONLY; trust stays
// local. Specifically —
//   * profile_hash is ALWAYS computed locally (sha256Prefixed over the profile
//     document, exactly as loadProfileById does). A source never supplies the
//     hash; a hostile registry therefore cannot lie about what it served.
//   * a caller may PIN an expected hash. A source whose profile does not hash to
//     the pin is skipped (a substitution attempt, or simply a different
//     version), so a remote can never pass a different document off under a
//     known profile_id.
//   * template_authenticity is unchanged and still graded downstream by the
//     author signature against the verifier's trusted author-keys anchor. A
//     registry SERVING a template does not make it trusted — the author
//     signature does. This module only moves BYTES; it never grades trust.
//
// Nothing here is wired into startSession yet — that integration is the next
// step. This layer is exercised by tests against a stub fetch (no network, no
// platform dependency), per the Phase 1 scope in issue #440.

import { sha256Prefixed } from "./hash.js";
import {
  loadProfileById as loadBundledProfileById,
  type TemplateTier,
  type RegistryManifest
} from "./schema-registry.js";
import type { ProfileSignatureSidecar } from "./types.js";

// A resolved template plus its provenance. Shape-compatible with
// loadProfileById's return (profileId/profile/profileHash/authorSignature/tier)
// so it can stand in for it, with `source` added so callers/telemetry can see
// where a template actually came from.
export type LoadedTemplate = {
  profileId: string;
  profile: Record<string, unknown>;
  profileHash: string;
  authorSignature?: ProfileSignatureSidecar;
  tier: TemplateTier;
  source: string;
};

// The recognized curation tiers. A tier arriving from an untrusted source
// (a remote manifest) is validated against this set; an unknown value (registry
// typo, version skew, malformed data) falls back to "community" rather than
// escaping the TemplateTier union and breaking consumers that switch on it.
const KNOWN_TIERS: ReadonlySet<TemplateTier> = new Set([
  "official",
  "verified",
  "community",
  "experimental"
]);
function normalizeTier(value: unknown): TemplateTier {
  return typeof value === "string" && KNOWN_TIERS.has(value as TemplateTier)
    ? (value as TemplateTier)
    : "community";
}

// A place templates can be resolved from. Implementations MUST compute
// profileHash locally (sha256Prefixed) and MUST NOT trust any hash supplied by
// the backend. `name` is provenance, surfaced as LoadedTemplate.source.
export interface TemplateSource {
  readonly name: string;
  loadProfileById(profileId: string): Promise<LoadedTemplate | null>;
}

// The default, always-present source: the templates bundled into the package
// (or SEQUESIGN_REGISTRY_DIR). Delegates to the existing file loader so its
// behavior is identical — this is the offline fallback that keeps binding
// working with no network and no configuration.
export function bundledTemplateSource(): TemplateSource {
  return {
    name: "bundled",
    async loadProfileById(profileId: string): Promise<LoadedTemplate | null> {
      const loaded = await loadBundledProfileById(profileId);
      if (!loaded) return null;
      return { ...loaded, source: "bundled" };
    }
  };
}

export type RemoteTemplateSourceConfig = {
  // Base URL of the read-only registry, e.g. "https://registry.sequesign.com".
  // Manifest is fetched from `${baseUrl}/${manifestPath}` and each asset from
  // `${baseUrl}/${entry.path}` — the manifest's paths are registry-relative,
  // exactly as they are repo-relative in the bundled registry.
  baseUrl: string;
  // Injected so tests (and non-Node runtimes) supply their own transport; no
  // ambient global fetch is assumed.
  fetchImpl: typeof fetch;
  // Optional read-only bearer token for account-scoped registries. Discovery
  // only — it is never used in verification.
  token?: string;
  // Defaults to "manifest.json".
  manifestPath?: string;
  // Request timeout guard (ms). Omit to leave the fetch untimed.
  requestTimeoutMs?: number;
};

function joinUrl(baseUrl: string, relative: string): string {
  const base = baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl;
  const rel = relative.startsWith("/") ? relative.slice(1) : relative;
  return `${base}/${rel}`;
}

// A registry reached over HTTP(S). Fetches manifest + profile + optional
// signature sidecar, then computes profile_hash LOCALLY. A non-2xx response, a
// missing entry, or malformed JSON resolves to null (the resolver falls through
// to the next source) rather than throwing — except a manifest/profile
// transport error, which propagates so the resolver can distinguish "offline"
// from "not found" and fall back to cache/bundled. The OPTIONAL signature
// sidecar is different: a broken or unreachable sidecar must never fail the
// profile load (the profile is simply unsigned), matching the bundled loader.
export function remoteTemplateSource(config: RemoteTemplateSourceConfig): TemplateSource {
  const manifestPath = config.manifestPath ?? "manifest.json";

  async function getJson<T>(url: string): Promise<{ ok: boolean; body?: T }> {
    const headers: Record<string, string> = { accept: "application/json" };
    if (config.token) headers.authorization = `Bearer ${config.token}`;
    const signal =
      config.requestTimeoutMs && config.requestTimeoutMs > 0
        ? AbortSignal.timeout(config.requestTimeoutMs)
        : undefined;
    const res = await config.fetchImpl(url, { headers, signal });
    if (!res.ok) {
      // Distinguish a definitive not-found from a transient outage. A 408
      // (Request Timeout), 429 (Too Many Requests), or any 5xx is a
      // retryable/server failure — throw so the resolver treats the source as
      // UNAVAILABLE (like a transport exception) and can fall back to a warm
      // cache, rather than concluding the template is definitively absent. A 404
      // (or other 4xx) is a real not-found and returns { ok: false }.
      if (res.status === 408 || res.status === 429 || res.status >= 500) {
        throw new Error(`registry responded ${res.status} for ${url}`);
      }
      return { ok: false };
    }
    try {
      return { ok: true, body: (await res.json()) as T };
    } catch {
      // A 2xx with an unparseable body is a broken registry response, not a
      // transport failure — treat it as "not found here" and fall through.
      return { ok: false };
    }
  }

  return {
    name: "remote",
    async loadProfileById(profileId: string): Promise<LoadedTemplate | null> {
      const manifestRes = await getJson<RegistryManifest>(joinUrl(config.baseUrl, manifestPath));
      if (!manifestRes.ok || !manifestRes.body) return null;
      const entry = manifestRes.body.profiles?.find((p) => p.profile_id === profileId);
      if (!entry) return null;

      const profileRes = await getJson<Record<string, unknown>>(
        joinUrl(config.baseUrl, entry.path)
      );
      if (!profileRes.ok || !profileRes.body) return null;
      const profile = profileRes.body;

      let authorSignature: ProfileSignatureSidecar | undefined;
      if (entry.signature_path) {
        // The sidecar is optional. A missing (404), malformed, OR unreachable
        // (transport throw) sidecar leaves the profile unsigned for authenticity
        // grading — it must not fail the profile load, exactly as in the bundled
        // loader. Only the manifest/profile fetches above are allowed to
        // propagate a transport error (so the resolver can fall back).
        try {
          const sigRes = await getJson<ProfileSignatureSidecar>(
            joinUrl(config.baseUrl, entry.signature_path)
          );
          if (sigRes.ok && sigRes.body && typeof sigRes.body.cose_sign1_b64url === "string") {
            authorSignature = { cose_sign1_b64url: sigRes.body.cose_sign1_b64url };
          }
        } catch {
          authorSignature = undefined;
        }
      }

      return {
        profileId: entry.profile_id,
        profile,
        // Computed locally — never taken from the manifest or any header.
        profileHash: sha256Prefixed(profile),
        authorSignature,
        // An untagged OR unrecognized remote tier defaults to "community": an
        // unvetted remote template must never masquerade as official just by
        // being served, and an unknown value must not escape the TemplateTier
        // union.
        tier: normalizeTier(entry.tier),
        source: "remote"
      };
    }
  };
}

// Deep, structural copy of a resolved template. Cached entries must be isolated
// from the caller's object graph in BOTH directions: a clone is stored so a
// later mutation of the returned object cannot alter the cached bytes, and a
// clone is returned so a caller cannot mutate the cached master. Without this,
// mutating a profile after resolution would leave a cache entry whose bytes no
// longer match its (immutable) profileHash key, silently defeating the
// pinned-lookup anti-substitution guarantee.
function cloneTemplate(template: LoadedTemplate): LoadedTemplate {
  return structuredClone(template);
}

// A hash-addressed template cache. Entries are keyed by (profileId, profileHash)
// and are therefore immutable — a cached template can be reused offline with no
// staleness risk, because a different template would have a different hash and a
// different key.
export interface TemplateCache {
  get(profileId: string, expectedHash?: string): LoadedTemplate | undefined;
  set(template: LoadedTemplate): void;
}

export function inMemoryTemplateCache(): TemplateCache {
  // Composite key `${profileId}${SEP}${profileHash}`. SEP is a NUL, which
  // cannot appear in a profile_id or a "sha256:"-prefixed hex hash, so the two
  // fields can never collide across the boundary. It is written as the escape
  // built at runtime (String.fromCharCode(0)) so the source stays text — a literal NUL byte makes
  // git classify the file as binary and breaks diffs/reviews.
  const SEP = String.fromCharCode(0);
  const byKey = new Map<string, LoadedTemplate>();
  const key = (id: string, hash: string) => `${id}${SEP}${hash}`;
  return {
    get(profileId, expectedHash) {
      if (expectedHash) {
        const hit = byKey.get(key(profileId, expectedHash));
        if (!hit) return undefined;
        const copy = cloneTemplate(hit);
        copy.source = "cache";
        return copy;
      }
      const prefix = `${profileId}${SEP}`;
      let latest: LoadedTemplate | undefined;
      for (const [k, v] of byKey) {
        if (k.startsWith(prefix)) latest = v;
      }
      if (!latest) return undefined;
      const copy = cloneTemplate(latest);
      copy.source = "cache";
      return copy;
    },
    set(template) {
      // Store an isolated snapshot so a later mutation of the caller's object
      // cannot alter the cached bytes behind their hash key. Delete any existing
      // entry first so a re-set moves the key to the END of the Map's insertion
      // order — otherwise, after a profile cycles A -> B -> A, get()'s unpinned
      // "latest" scan would still pick B even though A was resolved most recently.
      const k = key(template.profileId, template.profileHash);
      byKey.delete(k);
      byKey.set(k, cloneTemplate(template));
    }
  };
}

export type TemplateResolverConfig = {
  // Tried in priority order. A typical remote-enabled setup is
  // [remoteTemplateSource(...), bundledTemplateSource()] — prefer fresh, fall
  // back to the bundled copy offline. Bundled-only preserves today's behavior.
  sources: TemplateSource[];
  // Optional warm cache. Defaults to an in-memory one.
  cache?: TemplateCache;
};

export type ResolveOptions = {
  // When set, only a template whose LOCALLY-computed hash equals this is
  // accepted; sources returning a different document under the same id are
  // skipped. This is the anti-substitution guarantee — pass the hash you
  // committed at bind time to fetch exactly that template again.
  expectedHash?: string;
};

export interface TemplateResolver {
  resolveProfile(profileId: string, options?: ResolveOptions): Promise<LoadedTemplate | null>;
}

// Resolution order: hash-addressed cache (only when pinned — unambiguous) →
// each source in priority order → offline cache fallback. A source that throws
// (transport failure) is treated as "unavailable" and the next source is tried;
// a source that returns null (not found there) also falls through. A pinned
// hash mismatch skips that source without failing the whole resolve, so a stale
// or hostile source can never shadow a good one.
export function createTemplateResolver(config: TemplateResolverConfig): TemplateResolver {
  const cache = config.cache ?? inMemoryTemplateCache();
  return {
    async resolveProfile(profileId, options): Promise<LoadedTemplate | null> {
      // Distinguish "no pin" (undefined) from an explicitly-provided pin. A
      // provided-but-empty or malformed pin (e.g. an unset env var normalized to
      // "") is a PROVIDED pin that simply cannot equal any real "sha256:"-prefixed
      // hash, so it must reject every candidate and resolve to null — never
      // silently disable the anti-substitution guarantee via a truthiness check.
      const pin = options?.expectedHash;
      const pinProvided = pin !== undefined;

      // The resolved document must actually BE the requested template: both the
      // source's reported id and the profile document's own profile_id must equal
      // the lookup id. Otherwise a manifest (or custom source) mapping id "X" to a
      // document for "Y" could make resolveProfile("X") return another workflow's
      // rules — this mirrors the inline-binding invariant that a document's id
      // matches its reference. Content-hash pinning alone does not catch this.
      // Null/object-safe: a custom source or deserialized cache entry can return
      // profile: null or omit it entirely, and this runs BEFORE the
      // canonicalization guard — so it must never dereference a non-object.
      const profileIdOf = (p: unknown): string | undefined =>
        p !== null &&
        typeof p === "object" &&
        typeof (p as Record<string, unknown>).profile_id === "string"
          ? ((p as Record<string, unknown>).profile_id as string)
          : undefined;
      const identityMatches = (t: LoadedTemplate): boolean =>
        t.profileId === profileId && profileIdOf(t.profile) === profileId;

      // The profile_hash pins ONLY the profile document — not the sidecar/tier
      // metadata. So the cache is used purely as an OFFLINE FALLBACK, after every
      // source has been consulted: whenever a source is reachable, authorSignature
      // and tier come back fresh (a transiently-missing sidecar, or one added
      // later, is never pinned forever behind an immutable profile hash). A cache
      // entry is also no more trusted than a source, so a cached hit is
      // re-verified: recompute the hash, drop it on a pin mismatch (or if the
      // bytes cannot be canonicalized), and make the recomputed hash authoritative
      // so a stale or forged cached profileHash never reaches the caller.
      const acceptCached = (t: LoadedTemplate | undefined): LoadedTemplate | undefined => {
        if (!t) return undefined;
        if (!identityMatches(t)) return undefined;
        let actualHash: string;
        try {
          actualHash = sha256Prefixed(t.profile);
        } catch {
          return undefined;
        }
        if (pinProvided && actualHash !== pin) return undefined;
        // Deep-clone before returning: a custom cache may hand back its own
        // stored object (inMemoryTemplateCache clones, but the contract can't
        // assume every implementation does), so without this a caller mutating
        // the returned profile would mutate the cache itself. Provenance for an
        // offline cache hit is always "cache" regardless of what the cache stored
        // in `source`; the recomputed hash is authoritative; and the tier is
        // normalized so an unknown value from a custom cache cannot escape the
        // TemplateTier union.
        try {
          return structuredClone({
            ...t,
            profileHash: actualHash,
            tier: normalizeTier(t.tier),
            source: "cache"
          });
        } catch {
          // Non-cloneable data in a custom cache entry makes it unusable — treat
          // it as a miss rather than throwing out of the resolver.
          return undefined;
        }
      };

      // 1. Sources in priority order — always consulted first, so metadata is
      // fresh whenever a source is reachable. Track whether any source was
      // UNAVAILABLE (threw) as opposed to definitively reporting not-found, so
      // the offline fallback below can tell "registry down" from "template
      // withdrawn".
      let anyUnavailable = false;
      for (const source of config.sources) {
        let loaded: LoadedTemplate | null;
        try {
          loaded = await source.loadProfileById(profileId);
        } catch {
          // Transport/unavailable — try the next source (and, ultimately, the
          // offline cache fallback below).
          anyUnavailable = true;
          continue;
        }
        if (!loaded) continue;
        // Reject a document whose identity differs from the lookup (see above),
        // regardless of whether its content hash is valid.
        if (!identityMatches(loaded)) continue;
        // Never trust a source's self-reported hash. Recompute it over the bytes
        // so a misbehaving custom source (a supported extension point) cannot
        // forward a backend-supplied profileHash to satisfy a pin, nor poison the
        // cache with a hash that does not match its own profile. A profile that
        // cannot be canonicalized (a non-JCS value such as a bigint) is an
        // unusable result — skip to the next source rather than letting it reject
        // the whole resolve and shadow a valid fallback.
        let actualHash: string;
        try {
          actualHash = sha256Prefixed(loaded.profile);
        } catch {
          continue;
        }
        if (pinProvided && actualHash !== pin) {
          // Wrong or tampered version for this pin — do not return or cache it.
          continue;
        }
        // Build the accepted template with the resolver's authoritative fields
        // and DEEP-CLONE it, so a custom source that reuses its stored object
        // cannot be corrupted by the caller later mutating what we return. The
        // recomputed hash is authoritative; provenance is the INVOKED source's
        // name (the TemplateSource contract), not the loaded object's
        // self-reported `source`; and the tier is normalized so an unknown value
        // from a custom source cannot escape the TemplateTier union (only
        // remoteTemplateSource normalizes on its own).
        let template: LoadedTemplate;
        try {
          template = structuredClone({
            ...loaded,
            profileHash: actualHash,
            tier: normalizeTier(loaded.tier),
            source: source.name
          });
        } catch {
          // Non-cloneable data on a custom source's result (e.g. a method or
          // other DataCloneError-triggering value) makes it unusable — skip to
          // the next source rather than rejecting the whole resolve.
          continue;
        }
        // The cache is a best-effort accelerator: a write failure (I/O, quota, or
        // serialization in a custom/persistent cache) must not discard an already
        // fetched-and-verified template. Store an isolated CLONE so a custom cache
        // that retains the object it is given cannot be corrupted by the caller
        // later mutating the `template` we return (the read-side clone is too late
        // once the stored object itself has been mutated).
        try {
          cache.set(structuredClone(template));
        } catch {
          // ignore — return the verified result regardless of cache availability
        }
        return template;
      }

      // 2. Offline fallback — reserved for "registry unreachable", NOT for a
      // definitive miss. If at least one source ran and NONE was unavailable, the
      // reachable registries have authoritatively reported the template absent
      // (removed/withdrawn), so we must NOT resurrect a stale cache entry — that
      // would keep discovering a withdrawn template and preserve stale
      // tier/sidecar metadata. Fall back to the cache only when a source was
      // unavailable, or when there are no sources at all (cache-only mode).
      if (!anyUnavailable && config.sources.length > 0) return null;

      // Serve a cached copy if we have one (prefer the pinned hash). The read is
      // best-effort too: a custom/persistent cache throwing from get (I/O,
      // deserialization) is treated as a miss, so a broken optional cache yields
      // null rather than turning source unavailability into an exception.
      let cached: LoadedTemplate | undefined;
      try {
        cached = cache.get(profileId, pin);
      } catch {
        cached = undefined;
      }
      const fallback = acceptCached(cached);
      if (fallback) return fallback;
      return null;
    }
  };
}
