import type { ActionRecord, EvidenceBlob } from "./types.js";
import { loadProfileById } from "./schema-registry.js";
import { sha256Prefixed } from "./hash.js";
import { canonicalize } from "./canonicalize.js";
import { resolveSchemaParams, ParameterResolutionError } from "./mandate-params.js";
import {
  validateJsonSchema,
  collectUnenforceableSchema,
  type JsonSchema
} from "./schema-validation.js";

// Mandate evaluation splits into two axes (template system Phase 4):
//
//   HARD (integrity): the mandate's identity must be establishable and intact.
//   The profile document must resolve (embedded profile.json or the bundled
//   registry) and its hash must equal the committed profile_hash. A hard
//   failure means the receipt is not verifiable as the mandate it claims — the
//   verifier fails it (valid:false) and the seal path refuses.
//
//   SOFT (conformance): did the sealed WORK obey the mandate — allowed actions,
//   transitions, conditional requirements, and the parameterized
//   evidence_schemas ($param/$allowlist bound to the receipt's params)?
//   Nonconformant work still seals and still verifies as authentic
//   (valid:true), but with conformant:false and the specific violations
//   surfaced, so a consumer decides its own bar. This is the
//   "violation-preserving seal".
export type MandateEvaluationResult = {
  // HARD axis.
  resolved: boolean;
  resolvedFrom: "embedded" | "registry" | "none";
  profileHashVerified: boolean;
  hardErrors: string[];
  // SOFT axis. Only meaningful when resolved && profileHashVerified; a hard
  // failure leaves conformant=false with no violations enumerated (the mandate
  // could not be established to evaluate against).
  conformant: boolean;
  violations: string[];
  // The hash-verified profile document, when resolved with no hard error. The
  // caller (verify) uses it for the identity.min_assurance term, which it
  // evaluates (via evaluateIdentityTerm) only after resolving the trust-anchor-
  // relative assurance. Undefined on a hard-failed / unresolved mandate.
  resolvedProfile?: Record<string, unknown>;
};

// Assurance tiers, low -> high. A receipt's resolved assurance must rank >= the
// mandate's identity.min_assurance floor. Null-prototype so a lookup by an
// inherited name ("toString", "constructor", "__proto__") does not resolve to a
// Function/Object member and slip past the unrecognized-tier check.
const ASSURANCE_RANK: Record<string, number> = Object.assign(Object.create(null), {
  self_asserted: 0,
  registered: 1
});
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
// Protocol timestamps are ISO 8601, millisecond precision, UTC `Z` (spec §2.3,
// e.g. 2026-05-15T17:30:00.000Z). Validate the exact wire format before parsing:
// Date.parse accepts loose inputs ("0", "2026-01-01", "2026-01-01 00:00:00"),
// which would let a malformed timestamp yield a spurious duration instead of
// failing closed.
const ISO_MS_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

// Seal-time mandate terms (spec §4) that need signals the document-only
// conformance pass does not have. Split into two granular checks because the
// verifier learns identity assurance only after resolving the agent identity —
// later than it evaluates the mandate — whereas action timestamps are always in
// hand. Both are violation-preserving (return strings; the caller records them,
// they do not fail the receipt) and fail-closed on anything unsubstantiateable.

// identity.min_assurance: the receipt's assurance must rank at or above the
// floor. identityAssurance defaults to the lowest tier (self_asserted) when
// unknown, so an unresolved assurance cannot satisfy a higher floor. A present-
// but-malformed identity container or an unrecognized tier is itself a violation.
export function evaluateIdentityTerm(
  profileDoc: Record<string, unknown>,
  identityAssurance?: "self_asserted" | "registered"
): string[] {
  const identity = profileDoc.identity;
  if (identity === undefined) return [];
  if (!isPlainObject(identity))
    return [
      `The profile's identity must be a JSON object; the identity requirement cannot be substantiated.`
    ];
  const min = identity.min_assurance;
  if (min === undefined) return [];
  const assurance = identityAssurance ?? "self_asserted";
  if (typeof min !== "string" || !Object.prototype.hasOwnProperty.call(ASSURANCE_RANK, min))
    return [
      `The profile's identity.min_assurance "${String(min)}" is not a recognized assurance tier (self_asserted | registered); the requirement cannot be substantiated.`
    ];
  if (ASSURANCE_RANK[assurance] < ASSURANCE_RANK[min])
    return [`Identity assurance ${assurance} is below the mandate's minimum (${min}).`];
  return [];
}

// validity.max_session_duration_s: the span from the first to the last signed
// action timestamp must be within the cap. A present-but-malformed validity
// container, a non-positive cap, or an action timestamp that is not the exact
// protocol wire format (ISO 8601, millisecond, UTC Z) is a violation.
export function evaluateValidityTerm(
  profileDoc: Record<string, unknown>,
  actionTimestamps: string[]
): string[] {
  const validity = profileDoc.validity;
  if (validity === undefined) return [];
  if (!isPlainObject(validity))
    return [
      `The profile's validity must be a JSON object; the validity requirement cannot be substantiated.`
    ];
  const max = validity.max_session_duration_s;
  if (max === undefined) return [];
  if (typeof max !== "number" || !Number.isFinite(max) || max <= 0)
    return [
      `The profile's validity.max_session_duration_s must be a positive number of seconds; the constraint cannot be substantiated.`
    ];
  if (actionTimestamps.length === 0) return [];
  // Shape (regex) is necessary but not sufficient: Date.parse normalizes
  // impossible calendar dates (2026-02-30 -> Mar 2), which would yield a finite
  // duration. Require each timestamp to round-trip — new Date(ms).toISOString()
  // emits exactly the canonical ms-Z form, so equality proves both the exact
  // wire format AND a real calendar date.
  const ms = actionTimestamps.map((t) => (typeof t === "string" ? Date.parse(t) : NaN));
  const badFormat = actionTimestamps.some(
    (t, i) =>
      typeof t !== "string" ||
      !ISO_MS_UTC.test(t) ||
      !Number.isFinite(ms[i]) ||
      new Date(ms[i]).toISOString() !== t
  );
  if (badFormat)
    return [
      `Session duration cannot be evaluated: an action timestamp is not a valid ISO 8601 UTC (millisecond, Z) timestamp, so validity.max_session_duration_s cannot be substantiated.`
    ];
  // Compute the extrema iteratively rather than Math.max(...ms)/Math.min(...ms):
  // spreading a large array (a receipt can carry ~125k+ actions, and offline
  // packages have no action-count cap) overflows V8's argument limit and throws
  // RangeError, which would reject the whole verify promise instead of returning
  // a report.
  let minMs = ms[0];
  let maxMs = ms[0];
  for (const n of ms) {
    if (n < minMs) minMs = n;
    if (n > maxMs) maxMs = n;
  }
  const durationS = (maxMs - minMs) / 1000;
  if (durationS > max)
    return [`Session duration ${durationS.toFixed(3)}s exceeds the mandate's maximum (${max}s).`];
  return [];
}

// Traverse a dotted path requiring an OWN property at every segment. Evidence
// content is plain JSON, so a path naming an inherited member ("toString",
// "constructor.name") must resolve to undefined (absent) rather than walking the
// prototype chain — otherwise a bound field could read as "present" or match an
// inherited value across two objects and grade conformant with no real data.
function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce((acc: unknown, part: string) => {
    if (acc && typeof acc === "object" && Object.prototype.hasOwnProperty.call(acc, part))
      return (acc as Record<string, unknown>)[part];
    return undefined;
  }, obj);
}

// Evaluate a receipt's actions/evidence against its profile-constrained
// mandate. Phase 3 embed-first: when `embeddedProfile` (the package's
// profile.json) is provided it is used AND its hash is verified offline, so
// verification needs no registry; when absent we fall back to the bundled
// registry (back-compat for receipts that predate profile embedding).
export async function evaluateMandate(p: {
  profileId: string;
  profileHash: string;
  actions: ActionRecord[];
  evidence: EvidenceBlob[];
  // The receipt's bound parameters (params.json), needed to resolve the
  // profile's parameterized evidence_schemas. Absent for an unparameterized
  // profile_constrained receipt.
  boundParams?: Record<string, unknown>;
  // The embedded profile document (profile.json). null/undefined -> registry
  // fallback.
  embeddedProfile?: Record<string, unknown> | null;
  // The receipt's identity assurance, for the identity.min_assurance term. The
  // producer passes its self-assessment at seal (registered iff it holds a
  // platform identity proof); the verifier passes the RESOLVED assurance (a
  // platform proof that actually verifies against a trusted key). Both routes go
  // through here so the sealed conformance block and the verifier's
  // recomputation agree. Omitted -> treated as the lowest tier (self_asserted),
  // so an unknown assurance cannot satisfy a higher floor (fail-closed).
  identityAssurance?: "self_asserted" | "registered";
}): Promise<MandateEvaluationResult> {
  // 1. Resolve the profile document and verify its hash (HARD).
  let profileDoc: Record<string, unknown> | undefined;
  let resolvedFrom: MandateEvaluationResult["resolvedFrom"] = "none";
  let computedHash: string | undefined;
  // Track whether the embedded document could even be canonically hashed. JCS
  // throws on a value it cannot represent (e.g. a lone surrogate in a string);
  // a throw here would reject the whole verify promise instead of yielding the
  // intended profile_binding_invalid report, so treat it as unhashable.
  let hashComputable = true;
  if (p.embeddedProfile != null) {
    profileDoc = p.embeddedProfile;
    resolvedFrom = "embedded";
    // hashCanonical (via sha256Prefixed) canonicalizes, so the embedded
    // profile.json reproduces the registry's profile_hash regardless of
    // serialization key order.
    try {
      computedHash = sha256Prefixed(profileDoc);
    } catch {
      hashComputable = false;
    }
  } else {
    const loaded = await loadProfileById(p.profileId);
    if (loaded) {
      profileDoc = loaded.profile as Record<string, unknown>;
      resolvedFrom = "registry";
      computedHash = loaded.profileHash;
    }
  }
  if (!profileDoc) {
    return {
      resolved: false,
      resolvedFrom: "none",
      profileHashVerified: false,
      hardErrors: [
        `Unknown profile_id: ${p.profileId} (no embedded profile.json and not in the registry).`
      ],
      conformant: false,
      violations: []
    };
  }
  const profileHashVerified = hashComputable && computedHash === p.profileHash;
  const hardErrors: string[] = [];
  if (!hashComputable) {
    hardErrors.push(
      "The embedded profile.json contains a value that cannot be JCS-canonicalized, so its profile_hash cannot be verified."
    );
  } else if (!profileHashVerified) {
    hardErrors.push(
      `Profile hash mismatch. Expected ${p.profileHash}, computed ${computedHash}.` +
        (resolvedFrom === "embedded"
          ? " The embedded profile.json does not match the committed profile_hash."
          : "")
    );
  }
  // The embedded document's own profile_id is the authenticated identity (bound
  // by hash -> genesis for a V1 receipt). The receipt's claimed profile_id is
  // unsigned, so require it to match the embedded document — otherwise a
  // verification could attribute the receipt to one profile while evaluating a
  // different document. (The registry path resolves BY profile_id, so it
  // matches by construction.)
  if (resolvedFrom === "embedded") {
    const embeddedId =
      typeof (profileDoc as { profile_id?: unknown }).profile_id === "string"
        ? (profileDoc as { profile_id: string }).profile_id
        : undefined;
    if (embeddedId !== p.profileId) {
      hardErrors.push(
        `Embedded profile.json profile_id "${embeddedId ?? "(missing)"}" does not match the receipt's profile_id "${p.profileId}".`
      );
    }
  }

  // A hard binding failure means the mandate identity is broken. Stop here
  // rather than evaluating conformance against an untrusted/tampered document
  // whose fields may be the wrong container type (which would throw a TypeError
  // and reject the whole verify promise instead of returning the intended
  // profile_binding_invalid report).
  if (hardErrors.length > 0) {
    return {
      resolved: true,
      resolvedFrom,
      profileHashVerified,
      hardErrors,
      conformant: false,
      violations: []
    };
  }

  // 2. Conformance (SOFT): workflow shape + parameter constraints. Read each
  // structural field defensively — a document can be a valid JSON object yet
  // have a wrong-typed field; treat a non-array where an array is expected as
  // "empty" so evaluation degrades to violations rather than throwing.
  const violations: string[] = [];
  const asArray = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);
  const p_ = profileDoc as Record<string, unknown>;
  const allowedActions = asArray<string>(p_.allowed_actions);
  const requiredActions = asArray<string>(p_.required_actions);
  const allowedTransitions = asArray<unknown>(p_.allowed_transitions);
  const allowedFinalActions = Array.isArray(p_.allowed_final_actions)
    ? (p_.allowed_final_actions as string[])
    : undefined;
  const conditionalRequirements = asArray<{
    if_action?: string;
    field_path?: string;
    equals?: unknown;
    required_prior_to?: { action?: string; must_include?: string };
  }>(p_.conditional_requirements);
  const actionTypes = p.actions.map((a) => a.action_type);
  for (const a of actionTypes)
    if (!allowedActions.includes(a))
      violations.push(`Action ${a} is not allowed by profile ${p.profileId}.`);
  for (const r of requiredActions)
    if (!actionTypes.includes(r)) violations.push(`Required action missing: ${r}`);
  let previous = "START";
  const allowed = new Set(
    allowedTransitions.map((pair) =>
      Array.isArray(pair) ? `${pair[0]}->${pair[1]}` : `invalid_transition`
    )
  );
  for (const current of actionTypes) {
    if (!allowed.has(`${previous}->${current}`))
      violations.push(`Invalid workflow transition: ${previous} -> ${current}`);
    previous = current;
  }
  if (allowedFinalActions && !allowedFinalActions.includes(actionTypes[actionTypes.length - 1]))
    violations.push(`Invalid final action: ${actionTypes[actionTypes.length - 1]}`);
  const evidenceByActionType = new Map(p.evidence.map((item) => [item.action_type, item]));
  const evidenceByActionId = new Map(p.evidence.map((e) => [e.action_id, e]));
  // Action IDs must be unique. The action_id -> evidence join (used by the
  // per-action schema loop and the cross-action bindings) is 1:1; a reused id
  // collapses two actions onto one evidence blob in the Map, which would let a
  // binding be satisfied by pointing both the source and target action at a
  // single identical blob (and would evaluate a schema against the wrong blob).
  // A duplicate action_id is a malformed chain — fail closed.
  const dupActionIds = new Set<string>();
  for (const [label, ids] of [
    ["action", p.actions.map((a) => a.action_id)],
    ["evidence", p.evidence.map((e) => e.action_id)]
  ] as const) {
    const seen = new Set<string>();
    for (const id of ids) {
      if (seen.has(id) && !dupActionIds.has(id)) {
        dupActionIds.add(id);
        violations.push(
          `Duplicate ${label} action_id "${id}": action IDs must be unique; the evidence join cannot be substantiated.`
        );
      }
      seen.add(id);
    }
  }
  for (const rule of conditionalRequirements) {
    if (!rule || typeof rule !== "object" || !rule.required_prior_to) continue;
    const evidence = rule.if_action ? evidenceByActionType.get(rule.if_action) : undefined;
    if (!evidence || typeof rule.field_path !== "string") continue;
    const value = getPath(evidence, rule.field_path);
    if (value === rule.equals) {
      const targetIndex = actionTypes.indexOf(rule.required_prior_to.action ?? "");
      const requiredIndex = actionTypes.indexOf(rule.required_prior_to.must_include ?? "");
      if (targetIndex >= 0 && (requiredIndex < 0 || requiredIndex > targetIndex))
        violations.push(
          `Action ${rule.required_prior_to.must_include} is required before ${rule.required_prior_to.action}.`
        );
    }
  }

  // Parameter conformance (Phase 4): resolve the profile's parameterized
  // evidence_schemas against the receipt's bound params ($param / $allowlist)
  // and validate each action's evidence.content against the resolved schema.
  // This is the enforcement teeth of a parameterized mandate — e.g. a payment
  // amount <= the bound max_amount, a vendor within the bound allowlist. Only
  // action_types with a declared evidence schema are checked; others are
  // unconstrained here (registry action schemas still apply elsewhere).
  const evidenceSchemas = p_.evidence_schemas;
  // A present-but-non-object evidence_schemas container (e.g. `5`, `null`, or an
  // array) is a malformed mandate, not an absent one. Treating it as absent would
  // silently skip all parameter enforcement and return conformant:true — so fail
  // closed: a present container that is not a plain object is a conformance
  // violation. Only `undefined` (the field genuinely absent) skips this axis.
  if (
    evidenceSchemas !== undefined &&
    (evidenceSchemas === null ||
      typeof evidenceSchemas !== "object" ||
      Array.isArray(evidenceSchemas))
  ) {
    violations.push(
      `The profile's evidence_schemas is malformed (must be a JSON object mapping action_type to a JSON Schema); cannot evaluate parameter conformance.`
    );
  } else if (evidenceSchemas && typeof evidenceSchemas === "object") {
    // Anchor on the SIGNED actions and select each rule by the action record's
    // action_type — never the evidence blob's self-declared action_type, which
    // a producer can mislabel (while still signing a constrained action) to dodge
    // the constraint. The evidence is joined by the authenticated action_id
    // (both the action record's action_id and the evidence blob are covered by
    // signatures via evidence_hash).
    for (const a of p.actions) {
      const rawSchema = (evidenceSchemas as Record<string, unknown>)[a.action_type];
      if (rawSchema === undefined) continue;
      const ev = evidenceByActionId.get(a.action_id);
      // No evidence content to evaluate against (external / customer-held
      // custody, where neither the broker nor a third party holds the blob).
      // Skip rather than fabricate a violation — the party that DOES hold the
      // full package (the customer, offline) evaluates the constraint there.
      // Selecting by the signed action_type above already defeats a mislabeled
      // evidence blob, so a present-but-mislabeled blob is still evaluated.
      if (!ev) continue;
      let resolvedSchema: unknown;
      try {
        resolvedSchema = resolveSchemaParams(rawSchema, p.boundParams ?? {});
      } catch (err) {
        if (err instanceof ParameterResolutionError) {
          violations.push(
            `Cannot evaluate the parameterized mandate for ${a.action_type}: ${err.message}`
          );
          continue;
        }
        throw err;
      }
      // A resolved schema must be a JSON-Schema object. A scalar/null entry (or
      // one whose nested property schemas are malformed) would make
      // validateJsonSchema throw (it uses `"const" in schema` etc.). Guard the
      // top level and catch any deeper failure — a malformed mandate schema is a
      // conformance violation, never a thrown promise rejection.
      if (!resolvedSchema || typeof resolvedSchema !== "object" || Array.isArray(resolvedSchema)) {
        violations.push(
          `Action ${a.action_type}: the profile's evidence_schema is malformed (not a JSON Schema object); cannot evaluate conformance.`
        );
        continue;
      }
      // Fail closed on JSON Schema keywords the subset validator does not
      // enforce (pattern, oneOf, exclusiveMaximum, ...). Silently ignoring one
      // would drop a mandate constraint and report violating evidence as
      // conformant. Since this is the enforcement gate, an unenforceable
      // constraint is itself a conformance violation.
      const unenforceable = collectUnenforceableSchema(resolvedSchema);
      if (unenforceable.length > 0) {
        violations.push(
          `Action ${a.action_type}: the profile's evidence_schema uses constraint(s) this verifier cannot enforce [${unenforceable.join(", ")}]; the constraint cannot be substantiated.`
        );
        continue;
      }
      let result: { valid: boolean; errors: string[] };
      try {
        result = validateJsonSchema(ev.content, resolvedSchema as JsonSchema);
      } catch {
        violations.push(
          `Action ${a.action_type}: the profile's evidence_schema could not be evaluated (malformed schema).`
        );
        continue;
      }
      if (!result.valid)
        for (const e of result.errors)
          violations.push(`Action ${a.action_type} violates the parameterized mandate: ${e}`);
    }
  }

  // Cross-action evidence bindings (SOFT): fields that must carry identical
  // values across two action types, so a later action stays bound to the earlier
  // one it depends on. Without this the per-action schema loop above validates
  // each blob independently, so a chain could review report A and authorize an
  // unrelated report B (each blob valid on its own) and still grade conformant.
  // Anchored on SIGNED actions + joined by action_id (same substrate as the
  // schema loop). Every `to_action` occurrence must match SOME earlier
  // `from_action` occurrence on every listed field; a bound field missing on the
  // to_action side fails closed. When the needed evidence content is unavailable
  // (external custody), the check is delegated to the party holding the full
  // package — consistent with the per-action schema loop's custody handling.
  // A present-but-non-array evidence_bindings is a malformed mandate, not an
  // absent one — treating it as absent would silently drop the entire
  // cross-action constraint. Fail closed, exactly as evidence_schemas /
  // identity / validity do. Only `undefined` (genuinely absent) skips.
  if (p_.evidence_bindings !== undefined && !Array.isArray(p_.evidence_bindings)) {
    violations.push(
      `The profile's evidence_bindings is malformed (must be an array of {from_action, to_action, fields} rules); the cross-action binding cannot be substantiated.`
    );
  }
  const evidenceBindings = asArray<{
    from_action?: unknown;
    to_action?: unknown;
    fields?: unknown;
  }>(p_.evidence_bindings);
  for (const rule of evidenceBindings) {
    const fromType = rule && typeof rule.from_action === "string" ? rule.from_action : undefined;
    const toType = rule && typeof rule.to_action === "string" ? rule.to_action : undefined;
    const rawFields = asArray<unknown>(rule?.fields);
    const fields = rawFields.filter((f): f is string => typeof f === "string");
    if (!fromType || !toType || fields.length === 0 || fields.length !== rawFields.length) {
      violations.push(
        `Malformed evidence_binding (requires string from_action, to_action, and a non-empty array of string fields).`
      );
      continue;
    }
    // Single pass over the chain in order (O(F+T), not O(F×T)). As we walk, keep
    // the running state of PRECEDING from_action occurrences: how many exist at
    // all, how many have available evidence content, and the set of canonical
    // bound-field-value keys among those with content. Each to_action is judged
    // against that running state — which by construction covers only strictly-
    // earlier actions — so an adversarial large receipt (no action-count cap
    // offline) cannot drive quadratic work/allocation. A canonical key equals
    // another iff the bound field values are structurally equal (JCS), i.e. the
    // same test sameValue would make, but O(1) to look up.
    const keyOf = (content: unknown): string | undefined => {
      const vals = fields.map((f) => getPath(content, f));
      if (vals.some((v) => v === undefined)) return undefined;
      try {
        return canonicalize(vals);
      } catch {
        return undefined;
      }
    };
    let precedingFromCount = 0;
    let precedingFromWithContent = 0;
    const seenFromKeys = new Set<string>();
    for (const a of p.actions) {
      const ev = evidenceByActionId.get(a.action_id);
      if (a.action_type === toType) {
        // Judged against strictly-earlier from state (current action not yet folded in).
        if (precedingFromCount === 0) {
          violations.push(
            `Action ${toType} is not bound to a preceding ${fromType}: no ${fromType} occurs earlier in the chain to bind to.`
          );
        } else if (ev) {
          const missing = fields.filter((f) => getPath(ev.content, f) === undefined);
          if (missing.length > 0) {
            violations.push(
              `Action ${toType}: evidence_binding to ${fromType} cannot be substantiated — missing field(s) [${missing.join(", ")}].`
            );
          } else {
            const k = keyOf(ev.content);
            const matched = k !== undefined && seenFromKeys.has(k);
            // Only conclude "no preceding source matches" when EVERY preceding
            // from_action's evidence is available here. If some are externally
            // custodied (precedingFromWithContent < precedingFromCount), the
            // target might match one we can't see, so an unmatched target is
            // delegated to the full-package holder rather than flagged — the
            // same custody deferral the per-action schema loop makes. (When no
            // preceding source has content at all, this is delegated too.)
            if (!matched && precedingFromWithContent === precedingFromCount) {
              violations.push(
                `Action ${toType} is not bound to a preceding ${fromType}: field(s) [${fields.join(", ")}] match no prior ${fromType} (it must correspond to the earlier action, not an arbitrary one).`
              );
            }
          }
        }
        // ev absent (target externally custodied): structural check passed above;
        // the field comparison is delegated to the full-package holder.
      }
      if (a.action_type === fromType) {
        precedingFromCount++;
        if (ev) {
          precedingFromWithContent++;
          const k = keyOf(ev.content);
          if (k !== undefined) seenFromKeys.add(k);
        }
      }
    }
  }

  // Seal-time terms (spec §4). validity depends only on the signed action
  // timestamps, always in hand, so it is evaluated here for BOTH the producer
  // seal and the verifier (they both call evaluateMandate) — a duration
  // violation is thus recorded in the sealed conformance block, not only
  // re-derived at verify time. identity.min_assurance needs the identity
  // assurance: the producer supplies its self-assessment here (so it, too, is
  // sealed); the verifier omits it here and evaluates the identity floor
  // separately once it has resolved the authoritative assurance.
  violations.push(
    ...evaluateValidityTerm(
      p_,
      p.actions.map((a) => a.timestamp)
    )
  );
  if (p.identityAssurance !== undefined)
    violations.push(...evaluateIdentityTerm(p_, p.identityAssurance));

  return {
    resolved: true,
    resolvedFrom,
    profileHashVerified,
    hardErrors,
    conformant: hardErrors.length === 0 && violations.length === 0,
    violations,
    resolvedProfile: profileDoc
  };
}

// Back-compat shape (pre-Phase-4): a single boolean `valid` that conflates the
// hard and soft axes. Retained for callers not yet migrated to the graded
// model; new code should call evaluateMandate and treat the axes separately.
export type WorkflowValidationResult = {
  valid: boolean;
  profileHashVerified: boolean;
  errors: string[];
};

export async function validateWorkflowProfile(p: {
  profileId: string;
  profileHash: string;
  actions: ActionRecord[];
  evidence: EvidenceBlob[];
  boundParams?: Record<string, unknown>;
  embeddedProfile?: Record<string, unknown> | null;
}): Promise<WorkflowValidationResult> {
  const r = await evaluateMandate(p);
  return {
    valid: r.resolved && r.profileHashVerified && r.conformant,
    profileHashVerified: r.profileHashVerified,
    errors: [...r.hardErrors, ...r.violations]
  };
}
