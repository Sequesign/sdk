// A-priori single-action mandate check (template system, Phase 6).
//
// evaluateMandate (profile.ts) grades a WHOLE sealed chain after the fact:
// given the recorded actions + evidence, is the work conformant? checkAction is
// the complementary PRE-flight: before recording action X on a
// profile_constrained session, would X be permitted by the mandate, and — given
// the session's bound parameters — what evidence shape must X carry? It lets an
// agent (via the sequesign_check_action MCP tool) validate an action against the
// template before committing it, instead of discovering a violation only in the
// finalized receipt's conformance report.
//
// This is a PURE, offline, dependency-free function over the same substrate
// evaluateMandate uses (bindParameters, resolveSchemaParams,
// collectUnenforceableSchema, validateJsonSchema), so the pre-flight answer and
// the post-hoc conformance verdict cannot disagree about the same action. It
// checks a single prospective action, so it never inspects required_actions /
// allowed_final_actions / conditional_requirements (those are chain-completeness
// properties, only decidable once the chain is done — evaluateMandate owns them).

import { bindParameters, resolveSchemaParams, ParameterResolutionError } from "./mandate-params.js";
import type { ParameterDeclarations } from "./mandate-params.js";
import {
  validateJsonSchema,
  collectUnenforceableSchema,
  type JsonSchema
} from "./schema-validation.js";

export type CheckActionInput = {
  // The workflow profile document. The caller resolves it (registry
  // loadProfileById, or an embedded profile.json); checkAction does no I/O.
  profile: Record<string, unknown>;
  // The prospective action's type (e.g. "payment_instruction_created").
  actionType: string;
  // The session's provided parameter values, or omitted. Supplying params models
  // the parameterized (V1) session — they bind against the profile's `parameters`
  // block exactly as session start does, so $param / $allowlist in the action's
  // evidence_schema resolve to the concrete constraints the sealer will enforce
  // (and the profile must declare usable parameters, else it is inapplicable).
  // OMITTING params models an unparameterized V0 session — no binding, no
  // missing-required error — matching resolveGenesisBinding.
  params?: Record<string, unknown>;
  // The action types already recorded on the chain, in order. When supplied,
  // the transition <last-prior> -> actionType (START -> actionType for an empty
  // array) is checked against allowed_transitions. Omit (undefined) to skip the
  // transition check — the answer then reflects only the action-level rules.
  priorActionTypes?: string[];
  // Optional draft evidence content for the action. When supplied AND the
  // profile declares a (parameterized) evidence_schema for actionType, it is
  // resolved against the bound params and validated, so the agent learns
  // whether its evidence satisfies the mandate before recording.
  evidence?: unknown;
};

export type CheckActionResult = {
  // Overall gate: the action is permitted at this point AND (when checkable)
  // its evidence satisfies the mandate. A `null` sub-result (not checked) never
  // blocks; only a definite `false` does.
  allowed: boolean;
  // actionType is in the profile's allowed_actions.
  actionAllowed: boolean;
  // Transition <fromAction> -> actionType against allowed_transitions. null when
  // priorActionTypes was not supplied (transition not evaluated).
  transitionValid: boolean | null;
  // The transition source considered ("START", the last prior action), or null
  // when the transition was not evaluated.
  fromAction: string | null;
  // Parameter binding errors (unknown key, wrong type, missing required, ...).
  // Non-empty means the parameters are invalid, so a parameterized
  // evidence_schema could not be resolved — the action is not allowed.
  paramErrors: string[];
  // The concrete JSON Schema for this action's evidence after resolving
  // $param / $allowlist against the bound params, or null when the profile
  // declares no evidence_schema for actionType. Surfaced so an agent can see
  // the shape its evidence must satisfy.
  resolvedEvidenceSchema: unknown | null;
  // Evidence validation outcome: null when not evaluated (no evidence supplied,
  // or no schema declared); otherwise whether the supplied evidence validates.
  evidenceValid: boolean | null;
  // Human-readable reasons the action is blocked or the evidence fails. Empty
  // when allowed.
  reasons: string[];
};

const asArray = <T>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

// Evaluate a single prospective action against a profile's mandate. Pure and
// total: never throws for a malformed profile/evidence — a problem it cannot
// evaluate becomes a reason + a fail-closed (blocking) outcome, mirroring
// evaluateMandate's defensive reads.
export function checkAction(input: CheckActionInput): CheckActionResult {
  const profile = input.profile ?? {};
  const reasons: string[] = [];

  // 1. Bind parameters, mirroring resolveGenesisBinding (src/sdk/genesis-binding.ts)
  //    so the pre-flight models the session it will produce. Parameters bind only
  //    on the parameterized (V1) path, which the caller selects by SUPPLYING
  //    params:
  //      - params OMITTED -> an unparameterized V0 session. No binding, so a
  //        "missing required parameter" is NOT a violation (evaluateMandate
  //        reports none for a V0 receipt). boundParams stays {} — a profile that
  //        references $param in an evidence_schema is then unbound and fails
  //        closed below, exactly as a V0 receipt evaluates.
  //      - params SUPPLIED -> the V1 path, which requires the profile to declare
  //        usable parameters (a non-array object with >=1 key), exactly as
  //        session start does; otherwise the params are inapplicable (an error,
  //        matching "Profile declares no usable parameters ... Omit params").
  const rawDecls = profile.parameters;
  const declObject =
    rawDecls != null && typeof rawDecls === "object" && !Array.isArray(rawDecls)
      ? (rawDecls as ParameterDeclarations)
      : undefined;
  const paramErrors: string[] = [];
  let boundParams: Record<string, unknown> = {};
  if (input.params !== undefined) {
    if (!declObject || Object.keys(declObject).length === 0) {
      paramErrors.push(
        "Profile declares no usable parameters (its `parameters` block is missing, empty, or not a JSON object); params is not applicable — omit params for a non-parameterized profile."
      );
    } else {
      const bind = bindParameters(declObject, input.params);
      if (!bind.ok) paramErrors.push(...bind.errors);
      else boundParams = bind.params;
    }
  }
  if (paramErrors.length > 0) reasons.push(...paramErrors.map((e) => `Parameter error: ${e}`));

  // 2. Action-level allow check.
  const allowedActions = asArray<string>(profile.allowed_actions);
  const actionAllowed = allowedActions.includes(input.actionType);
  if (!actionAllowed)
    reasons.push(`Action "${input.actionType}" is not in the profile's allowed_actions.`);

  // 3. Transition check (only when prior context is supplied).
  let transitionValid: boolean | null = null;
  let fromAction: string | null = null;
  if (input.priorActionTypes !== undefined) {
    const prior = asArray<string>(input.priorActionTypes);
    fromAction = prior.length > 0 ? prior[prior.length - 1] : "START";
    const allowed = new Set(
      asArray<unknown>(profile.allowed_transitions).map((pair) =>
        Array.isArray(pair) ? `${pair[0]}->${pair[1]}` : "invalid_transition"
      )
    );
    transitionValid = allowed.has(`${fromAction}->${input.actionType}`);
    if (!transitionValid)
      reasons.push(`Transition "${fromAction}" -> "${input.actionType}" is not allowed.`);
  }

  // 4. Evidence schema: resolve the (parameterized) schema for this action, and
  //    validate supplied evidence against it. Mirrors evaluateMandate's
  //    fail-closed handling of unbound $param, malformed, and unenforceable
  //    schemas so the pre-flight verdict matches the post-hoc one.
  let resolvedEvidenceSchema: unknown | null = null;
  let evidenceValid: boolean | null = null;
  const evidenceSchemas = profile.evidence_schemas;
  if (
    evidenceSchemas !== undefined &&
    (evidenceSchemas === null ||
      typeof evidenceSchemas !== "object" ||
      Array.isArray(evidenceSchemas))
  ) {
    reasons.push(
      "The profile's evidence_schemas is malformed (must be a JSON object mapping action_type to a JSON Schema)."
    );
    evidenceValid = false;
  } else if (
    paramErrors.length === 0 &&
    evidenceSchemas &&
    typeof evidenceSchemas === "object" &&
    (evidenceSchemas as Record<string, unknown>)[input.actionType] !== undefined
  ) {
    const rawSchema = (evidenceSchemas as Record<string, unknown>)[input.actionType];
    let resolved: unknown;
    try {
      resolved = resolveSchemaParams(rawSchema, boundParams);
    } catch (err) {
      if (err instanceof ParameterResolutionError) {
        reasons.push(
          `Cannot resolve the parameterized evidence_schema for "${input.actionType}": ${err.message}`
        );
        evidenceValid = false;
        resolved = undefined;
      } else {
        throw err;
      }
    }
    if (resolved !== undefined) {
      if (!resolved || typeof resolved !== "object" || Array.isArray(resolved)) {
        reasons.push(
          `The profile's evidence_schema for "${input.actionType}" is malformed (not a JSON Schema object).`
        );
        evidenceValid = false;
      } else {
        const unenforceable = collectUnenforceableSchema(resolved);
        if (unenforceable.length > 0) {
          reasons.push(
            `The profile's evidence_schema for "${input.actionType}" uses constraint(s) this verifier cannot enforce [${unenforceable.join(", ")}].`
          );
          evidenceValid = false;
        } else {
          resolvedEvidenceSchema = resolved;
          if (input.evidence !== undefined) {
            let result: { valid: boolean; errors: string[] };
            try {
              result = validateJsonSchema(input.evidence, resolved as JsonSchema);
            } catch {
              reasons.push(
                `The profile's evidence_schema for "${input.actionType}" could not be evaluated (malformed schema).`
              );
              result = { valid: false, errors: [] };
            }
            evidenceValid = result.valid;
            if (!result.valid)
              for (const e of result.errors)
                reasons.push(`Evidence does not satisfy the mandate: ${e}`);
          }
        }
      }
    }
  }

  const allowed =
    paramErrors.length === 0 &&
    actionAllowed &&
    transitionValid !== false &&
    evidenceValid !== false;

  return {
    allowed,
    actionAllowed,
    transitionValid,
    fromAction,
    paramErrors,
    resolvedEvidenceSchema,
    evidenceValid,
    reasons
  };
}
