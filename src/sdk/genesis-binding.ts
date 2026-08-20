// Shared genesis binding for the direct and managed session paths.
//
// A session that binds parameters (template system) commits the mandate
// (profile_hash + params_hash) and the parties into the chain genesis
// (SEQUESIGN_GENESIS_V1), which the verifier and the broker recompute and
// check. Every other session keeps the legacy V0 genesis byte-identical, so
// unparameterized receipts are unchanged.
//
// This logic lives in one place so the direct path (src/sdk/session.ts) and
// the managed path (src/sdk/managed-session.ts) cannot drift — two genesis
// implementations that disagreed would be a security hazard, since the hash
// they commit is what the offline verifier reproduces.

import {
  bundledTemplateSource,
  createTemplateResolver,
  type TemplateResolver
} from "../lib/template-source.js";
import { sha256Prefixed } from "../lib/hash.js";
import { bindParameters, paramsHash, type ParameterDeclarations } from "../lib/mandate-params.js";
import { computeGenesisV0, computeGenesisV1 } from "../lib/genesis.js";
import type { ProfileReference, ProfileSignatureSidecar } from "../lib/types.js";
import { PackageStateError, ParameterBindingError } from "./errors.js";

export interface GenesisBindingArgs {
  chainId: string;
  taskId: string;
  delegatorId: string;
  agentId: string;
  profile: ProfileReference | undefined;
  params: Record<string, unknown> | undefined;
  // Inline template support: when provided, the session binds to THIS
  // WorkflowProfile document instead of resolving `profile.profile_id` from the
  // bundled registry (loadProfileById). This lets a caller run a session
  // against a template it just published to the library (or any template not
  // shipped in the SDK). The security invariant is unchanged: the committed
  // profile_hash is the canonical hash of whatever document is used, the same
  // document is embedded (profile.json), and the offline verifier recomputes
  // and re-checks it. `profile.profile_hash` must equal this document's
  // canonical hash. Undefined -> resolve from the registry, as before.
  profileDocument: Record<string, unknown> | undefined;
  // Optional author-vouch sidecar for an inline profileDocument, embedded as
  // profile.sig.json on the parameterized path so the verifier can grade
  // template_authenticity. Ignored when profileDocument is undefined (the
  // registry sidecar is used instead). Undefined for an unsigned inline
  // template.
  profileAuthorSignature: ProfileSignatureSidecar | undefined;
  // Template system Phase 2 (dynamic registry): the resolver used to resolve a
  // profile_constrained session's WorkflowProfile when no inline document is
  // supplied. Undefined -> a bundled-only resolver is constructed here, which is
  // byte-for-byte equivalent to the previous loadProfileById path (fully offline,
  // no configuration). A caller-supplied resolver (SdkConfig.templateResolver)
  // can add a live/account-scoped registry with the bundled copy as fallback.
  // This only affects DISCOVERY: the resolved document's hash is recomputed
  // locally and checked against `profile.profile_hash` below, so a resolver can
  // never weaken the genesis authentication.
  templateResolver: TemplateResolver | undefined;
}

// Lazily constructed default resolver: bundled-only, matching the pre-dynamic
// behavior. Reused across binds that do not pass a resolver. Safe to share —
// bundledTemplateSource is stateless and, in bundled-only mode, the resolver's
// cache is never READ (the single source is always reachable for a hit and
// authoritatively reports a miss), so it cannot serve a stale cross-bind entry.
let defaultBundledResolver: TemplateResolver | undefined;
function bundledOnlyResolver(): TemplateResolver {
  if (!defaultBundledResolver) {
    defaultBundledResolver = createTemplateResolver({ sources: [bundledTemplateSource()] });
  }
  return defaultBundledResolver;
}

// Recursively freeze a plain JSON value so a retained snapshot cannot be
// mutated later (by the caller — who no longer holds this cloned reference — or
// internally). Arrays and objects are frozen; primitives pass through.
function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const v of Object.values(value as Record<string, unknown>)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

// A faithful JSON snapshot of a caller-supplied document, via a JSON round-trip.
// This is used instead of structuredClone deliberately: the committed
// profile_hash (canonical/JCS) and the embedded profile.json (JSON.stringify)
// must render the document identically, but structuredClone preserves non-JSON
// values — e.g. a nested Date, which the canonical hash sees as {} while
// JSON.stringify writes as an ISO string, producing a receipt whose committed
// hash does not match its own profile.json. The round-trip collapses the value
// to exactly what will be written (Date -> ISO string, etc.), so hashing the
// snapshot matches the package and the offline verifier. A value that is not
// JSON-serializable at all (circular, BigInt) is rejected fail-fast.
function jsonSnapshot(value: Record<string, unknown>): Record<string, unknown> {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    serialized = undefined;
  }
  if (typeof serialized !== "string") {
    throw new PackageStateError(
      "SessionInit.profileDocument must be a JSON document (it is not JSON-serializable)."
    );
  }
  return JSON.parse(serialized) as Record<string, unknown>;
}

// Resolve a profile's document + canonical hash + author sidecar from either an
// inline document (caller-supplied, e.g. a freshly published template) or the
// template resolver. Inline resolution uses sha256Prefixed — the SAME JCS
// canonicalization the registry, the dashboard-api template store, and the
// offline verifier use — so the hash is identical everywhere. Returns null only
// for a resolver miss; an inline document always resolves.
//
// `pin` controls resolver lookup:
//   - A hash (the V1/parameterized path passes ref.profile_hash): resolve
//     PINNED first, so the resolver skips any source that serves a different
//     document under this id (a stale mirror or a hostile source) and falls
//     through to the correctly-pinned bundled/cache copy — this is the
//     anti-substitution fallback the resolver exists to provide. Only if the pin
//     matches NO source do we resolve unpinned once more, purely to preserve the
//     precise diagnostic downstream: a document that exists under this id but
//     with a different hash yields the "hash mismatch" error (declared vs
//     computed), while a genuine absence yields "unknown profile".
//   - undefined (the V0 path passes the bundled-only resolver here): resolve
//     unpinned/best-effort, matching the legacy behavior — the V0 embedded
//     profile is not genesis-authenticated, so its hash is checked at finalize,
//     not at bind.
async function resolveProfileForBinding(
  ref: ProfileReference,
  inlineDocument: Record<string, unknown> | undefined,
  inlineAuthorSignature: ProfileSignatureSidecar | undefined,
  resolver: TemplateResolver,
  pin: string | undefined
): Promise<{
  profile: Record<string, unknown>;
  profileHash: string;
  authorSignature: ProfileSignatureSidecar | undefined;
} | null> {
  if (inlineDocument !== undefined) {
    // Snapshot the caller-owned document FIRST, then validate against the
    // snapshot. The session retains this value and re-evaluates it at finalize
    // against the committed profile_hash and the already-written profile.json;
    // if the caller mutated their original object in between, that retained
    // reference would drift and finalize would reject the session on a spurious
    // hash mismatch. A JSON round-trip (jsonSnapshot) isolates from caller
    // mutation, collapses the value to its exact written JSON form (so the
    // committed hash matches profile.json), and — importantly for the check
    // below — resolves any toJSON()/getter so the profile_id we validate is the
    // one actually embedded and hashed, not a pre-serialization value that
    // could differ. Freeze so caller-owned state cannot invalidate an
    // in-progress session — the same isolation bound parameter values get.
    const snapshot = deepFreeze(jsonSnapshot(inlineDocument));
    // The inline document must be the body of the reference it is supplied
    // against. A document whose own profile_id disagrees with the reference is
    // an invalid binding that evaluateMandate would otherwise only catch at
    // finalize — after work is recorded and a partial package exists. It is
    // knowable at bind time, so reject it here alongside the hash check, before
    // any package or witness side effect.
    const snapshotProfileId = (snapshot as { profile_id?: unknown }).profile_id;
    if (snapshotProfileId !== ref.profile_id) {
      throw new PackageStateError(
        `SessionInit.profileDocument.profile_id (${String(snapshotProfileId)}) does not match ` +
          `SessionInit.profile.profile_id (${ref.profile_id}). The inline document must be the ` +
          `body of the referenced profile.`
      );
    }
    return {
      profile: snapshot,
      profileHash: sha256Prefixed(snapshot),
      authorSignature: inlineAuthorSignature
    };
  }
  // Registry resolution (no inline document): go through the template resolver.
  if (pin !== undefined) {
    // Pinned first — see the `pin` contract above. A hit here has a
    // locally-recomputed hash equal to the pin, so the explicit check in
    // resolveGenesisBinding trivially passes; the anti-substitution fallback
    // (skip a mismatching source, use the pinned copy) has already happened
    // inside the resolver.
    const pinned = await resolver.resolveProfile(ref.profile_id, { expectedHash: pin });
    if (pinned) {
      return {
        profile: pinned.profile,
        profileHash: pinned.profileHash,
        authorSignature: pinned.authorSignature
      };
    }
    // No source matched the pin. Resolve unpinned only to diagnose: a document
    // under this id with a DIFFERENT hash surfaces as the precise "hash
    // mismatch" error via the explicit check; a true absence stays null ->
    // "unknown profile".
    const unpinned = await resolver.resolveProfile(ref.profile_id);
    if (!unpinned) return null;
    return {
      profile: unpinned.profile,
      profileHash: unpinned.profileHash,
      authorSignature: unpinned.authorSignature
    };
  }
  const loaded = await resolver.resolveProfile(ref.profile_id);
  if (!loaded) return null;
  return {
    profile: loaded.profile,
    profileHash: loaded.profileHash,
    authorSignature: loaded.authorSignature
  };
}

export interface GenesisBindingResult {
  // The profile reference to seal on the receipt: carries params_hash on the
  // parameterized (V1) path; a stray params_hash is stripped on the V0 path.
  profileRef: ProfileReference | undefined;
  // The chain genesis: SEQUESIGN_GENESIS_V1 when parameterized, else V0.
  initialChainState: string;
  // The bound parameter values (parameterized path only) so they can travel in
  // the package (params.json) and be restored on resume. Undefined on V0.
  boundParams: Record<string, unknown> | undefined;
  // Embed-first packaging (Phase 3): the resolved workflow profile document
  // for a profile_constrained session, so it can travel in the package
  // (profile.json) and let an offline verifier re-resolve the mandate's rules
  // and re-verify profile_hash without a registry. Undefined for a freeform
  // session, or when the profile_id is not in the registry (the session then
  // still fails at finalize via validateWorkflowProfile, as before).
  profileDocument: Record<string, unknown> | undefined;
  // Template system Phase 5: the template-author signature sidecar for the
  // resolved profile, so it can travel in the package (profile.sig.json) and let
  // an offline verifier grade template_authenticity. Populated ONLY on the
  // parameterized (V1) path — a V0 receipt's embedded profile is not
  // genesis-authenticated, so an author signature over it would not be evaluated
  // and is deliberately not embedded. Undefined when the profile is unsigned.
  profileAuthorSignature: ProfileSignatureSidecar | undefined;
}

// Resolve the chain genesis and the sealed profile reference for a session.
// Throws PackageStateError / ParameterBindingError on an invalid mandate,
// before any package or witness side effect, so a binding failure never leaves
// partial state behind.
export async function resolveGenesisBinding(
  args: GenesisBindingArgs
): Promise<GenesisBindingResult> {
  // The resolver used for the PARAMETERIZED (V1) path: a caller-supplied one
  // when present, else bundled-only (previous behavior). Discovery only — the
  // resolved document's hash is pinned/re-checked (see resolveProfileForBinding
  // and the explicit check below). The V0 path deliberately does NOT use this
  // and stays bundled-only (see its call site for why).
  const resolver = args.templateResolver ?? bundledOnlyResolver();
  // An inline profile document only makes sense as the concrete body of the
  // session's profile reference. Reject it without a reference rather than
  // silently ignoring it (which would produce a receipt bound to nothing).
  if (args.profileDocument !== undefined && !args.profile) {
    throw new PackageStateError(
      "SessionInit.profileDocument requires SessionInit.profile (the inline document is the body of that profile reference)."
    );
  }
  // An inline template must be parameterized. Only a parameterized session
  // commits profile_hash into the signed genesis (SEQUESIGN_GENESIS_V1), which
  // is what authenticates the embedded profile.json for offline verification.
  // Without params the session takes the V0 path, whose embedded profile is NOT
  // genesis-authenticated, so the verifier falls back to the bundled registry —
  // and for a template not shipped in the SDK (the whole point of an inline
  // document) that fallback misses and finalize fails as unknown_profile. Reject
  // it fail-fast here rather than after work is recorded.
  if (args.profileDocument !== undefined && args.params === undefined) {
    throw new PackageStateError(
      "SessionInit.profileDocument requires SessionInit.params: an inline template must be " +
        "parameterized so its hash is committed into the signed genesis and the embedded document " +
        "is verifiable offline. An unparameterized inline template is not genesis-authenticated and " +
        "cannot be verified (the verifier falls back to the registry, which does not have it). Bind " +
        "parameters, or register the template in the SDK and drop profileDocument."
    );
  }
  if (args.params !== undefined) {
    if (!args.profile) {
      throw new PackageStateError(
        "SessionInit.params requires SessionInit.profile (parameters bind to a profile)."
      );
    }
    const loaded = await resolveProfileForBinding(
      args.profile,
      args.profileDocument,
      args.profileAuthorSignature,
      resolver,
      args.profile.profile_hash
    );
    if (!loaded) {
      throw new ParameterBindingError(args.profile.profile_id, [
        `Unknown profile_id: ${args.profile.profile_id}`
      ]);
    }
    if (loaded.profileHash !== args.profile.profile_hash) {
      throw new ParameterBindingError(args.profile.profile_id, [
        `Profile hash mismatch. Declared ${args.profile.profile_hash}, ${args.profileDocument !== undefined ? "inline document" : "registry"} computed ${loaded.profileHash}.`
      ]);
    }
    const declarations = (loaded.profile as { parameters?: ParameterDeclarations }).parameters;
    // A session is parameterized (V1 genesis + params_hash + v2.1.0) only when
    // the profile's `parameters` is a non-array OBJECT with at least one declared
    // parameter. Everything else — missing, empty {}, or a malformed scalar/array
    // block like `"parameters": 0` — is not a valid parameterized template:
    // bindParameters(nonObject, {}) would otherwise see no Object.entries and
    // succeed with {}, emitting a spurious v2.1.0/V1 receipt committing hash({})
    // and breaking the byte-identical V0 path for genuinely unparameterized
    // profiles. Reject inapplicable params fail-closed here; a non-empty object
    // with bad INNER declarations still reaches bindParameters for its precise
    // per-declaration error.
    const declObject =
      declarations != null && typeof declarations === "object" && !Array.isArray(declarations)
        ? (declarations as ParameterDeclarations)
        : undefined;
    if (!declObject || Object.keys(declObject).length === 0) {
      throw new ParameterBindingError(args.profile.profile_id, [
        "Profile declares no usable parameters (its `parameters` block is missing, empty, or not a JSON object); SessionInit.params is not applicable. Omit params for a non-parameterized profile."
      ]);
    }
    const bound = bindParameters(declObject, args.params);
    if (!bound.ok) {
      throw new ParameterBindingError(args.profile.profile_id, bound.errors);
    }
    const boundParamsHash = paramsHash(bound.params);
    return {
      profileRef: { ...args.profile, params_hash: boundParamsHash },
      initialChainState: computeGenesisV1({
        chainId: args.chainId,
        taskId: args.taskId,
        delegatorId: args.delegatorId,
        agentId: args.agentId,
        profileHash: args.profile.profile_hash,
        paramsHash: boundParamsHash
      }),
      boundParams: bound.params,
      profileDocument: loaded.profile as Record<string, unknown>,
      profileAuthorSignature: loaded.authorSignature
    };
  }
  // No params bound this session -> V0 receipt. A params_hash on the caller's
  // ProfileReference (the public type allows it) is meaningless here — it was
  // not produced by binding — and would otherwise make the envelope emit a
  // v2.1.0 receipt whose V1 genesis recompute then fails. Strip it so a V0
  // receipt never carries params_hash.
  let profileRef = args.profile;
  if (profileRef?.params_hash) {
    const { params_hash: _strippedParamsHash, ...withoutParamsHash } = profileRef;
    profileRef = withoutParamsHash;
  }
  // Embed-first packaging (Phase 3): an unparameterized profile_constrained
  // session still carries workflow rules, so resolve the profile document for
  // profile.json. An inline document is used verbatim; otherwise this is
  // best-effort — an unknown profile_id yields undefined here and the session
  // fails later in evaluateMandate exactly as before, so this does not tighten
  // the V0 path's bind-time behavior. The embedded document's hash is checked
  // against profile_hash at finalize (evaluateMandate), so an inline document
  // that does not match its reference is caught there, not silently accepted.
  //
  // Resolve V0 from the BUNDLED-ONLY resolver, NOT any caller-supplied dynamic
  // resolver: a V0 receipt's embedded profile is not genesis-authenticated, so
  // the offline verifier distrusts it and falls back to the bundled registry.
  // Embedding a dynamically-resolved, non-bundled document here would therefore
  // produce a receipt that always fails offline verification (unknown_profile)
  // AFTER work and witness side effects — the exact hazard that makes inline
  // documents require params. Keeping V0 bundled-only both avoids that footgun
  // and preserves the legacy V0 contract byte-for-byte (dynamic resolution is
  // meaningfully a V1/parameterized-only capability).
  let profileDocument: Record<string, unknown> | undefined;
  if (profileRef) {
    const loaded = await resolveProfileForBinding(
      profileRef,
      args.profileDocument,
      undefined,
      bundledOnlyResolver(),
      undefined
    );
    profileDocument = loaded?.profile;
  }
  return {
    profileRef,
    initialChainState: computeGenesisV0(args.chainId),
    boundParams: undefined,
    profileDocument,
    // V0 path: the embedded profile is not genesis-authenticated, so no author
    // signature is embedded (it would not be evaluated by the verifier).
    profileAuthorSignature: undefined
  };
}
