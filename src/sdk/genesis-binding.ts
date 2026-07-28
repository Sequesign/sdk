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

import { loadProfileById } from "../lib/schema-registry.js";
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
  if (args.params !== undefined) {
    if (!args.profile) {
      throw new PackageStateError(
        "SessionInit.params requires SessionInit.profile (parameters bind to a profile)."
      );
    }
    const loaded = await loadProfileById(args.profile.profile_id);
    if (!loaded) {
      throw new ParameterBindingError(args.profile.profile_id, [
        `Unknown profile_id: ${args.profile.profile_id}`
      ]);
    }
    if (loaded.profileHash !== args.profile.profile_hash) {
      throw new ParameterBindingError(args.profile.profile_id, [
        `Profile hash mismatch. Declared ${args.profile.profile_hash}, registry computed ${loaded.profileHash}.`
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
  // profile.json. Best-effort — an unknown profile_id yields undefined here
  // and the session fails later in validateWorkflowProfile exactly as before,
  // so this does not tighten the V0 path's bind-time behavior.
  let profileDocument: Record<string, unknown> | undefined;
  if (profileRef) {
    const loaded = await loadProfileById(profileRef.profile_id);
    profileDocument = loaded?.profile as Record<string, unknown> | undefined;
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
