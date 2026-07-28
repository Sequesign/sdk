// Parameterized mandate support (template system, Phase 1).
//
// A workflow profile MAY declare a `parameters` block. A session binds
// concrete values to those parameters at start; the bound values are
// hashed (params_hash) and, from Phase 2 on, committed into the chain
// genesis alongside the profile_hash. This module is the pure substrate:
// binding + validation of parameter values, the params_hash construction,
// and the `$param` / `$allowlist` resolution that turns a parameterized
// evidence schema into a concrete JSON Schema before validation.
//
// WIRE CONTRACT. The behavior here is verifier-observable: an independent
// verifier (in any language) must reproduce identical bound-parameter
// bytes and identical resolved schemas, or offline conformance
// re-evaluation diverges from the sealer. The rules below are therefore
// specified in docs/protocol-spec.md section 2.7 and must not drift from
// it. Everything is deterministic and dependency-free (JCS via
// canonicalize.ts, SHA-256 via hash.ts).

import { sha256Prefixed } from "./hash.js";
import { canonicalize } from "./canonicalize.js";

// The JSON data model's value types, as usable for a parameter. Mirrors
// the `type` keyword of the evidence-schema validator so a declared
// parameter type and the schema that consumes it speak the same words.
export type ParameterType = "string" | "number" | "boolean" | "array" | "object";

// Runtime whitelist of the protocol's declaration types. A profile is loaded
// from JSON, so `decl.type` can be any string at runtime; a non-whitelisted
// type (e.g. "null", "integer") must be rejected rather than matched against
// jsonTypeOf, or the sealer would commit a params_hash for a declaration a
// spec-compliant offline verifier rejects.
const VALID_PARAMETER_TYPES: ReadonlySet<string> = new Set([
  "string",
  "number",
  "boolean",
  "array",
  "object"
]);

export type ParameterDeclaration = {
  type: ParameterType;
  // Absent or false: the parameter may be left unbound (a `$param`
  // reference to it is then an authoring error; a `$allowlist` reference
  // drops the constraint — see resolveSchemaParams).
  required?: boolean;
  // Applied when the caller does not provide the parameter. A default is
  // type-checked against `type` exactly like a provided value would be.
  default?: unknown;
};

export type ParameterDeclarations = Record<string, ParameterDeclaration>;

export type BindParametersResult =
  | { ok: true; params: Record<string, unknown> }
  | { ok: false; errors: string[] };

function jsonTypeOf(v: unknown): ParameterType | "null" | "undefined" {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  const t = typeof v;
  if (t === "object") return "object";
  if (t === "string" || t === "number" || t === "boolean") return t;
  // functions, symbols, bigint: not part of the JSON model.
  return "undefined";
}

function typeMatches(v: unknown, type: ParameterType): boolean {
  if (type === "number") return typeof v === "number" && Number.isFinite(v);
  return jsonTypeOf(v) === type;
}

// Assign an OWN enumerable data property, even when key === "__proto__".
// Plain `obj[key] = value` routes "__proto__" through the inherited accessor
// (mutating the prototype, or silently no-op'ing for a primitive) instead of
// creating an own member — so a parameter or schema key literally named
// "__proto__" (legal in JSON, and these are bytes we hash and commit) would be
// lost. defineProperty bypasses the accessor; the object keeps its normal
// prototype so canonicalize (Object.keys) and deep-equality are unchanged.
function setOwn(obj: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(obj, key, {
    value,
    writable: true,
    enumerable: true,
    configurable: true
  });
}

// A value is a "plain" JSON object iff its prototype is Object.prototype or
// null. A Date/Map/Set/RegExp/class instance is NOT: canonicalize would
// serialize only its enumerable own properties (usually none), so e.g. a
// Date collides with `{}` in the hash while the caller believes it bound a
// real value. Such instances must be rejected, not silently flattened.
function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// Path (or reason) of the first node in `value` that is not a faithfully
// JSON-representable value, or null if the whole value is clean. Rejects:
// undefined, non-finite numbers, functions/symbols/bigint, array holes, and
// non-plain object instances — at any nesting depth. This is stricter than
// canonicalize alone, which throws on some of these but silently drops others
// (an `undefined` object member) or misrepresents them (a Date -> `{}`).
function firstNonJsonPath(value: unknown, path: string, seen: Set<object>): string | null {
  const here = path || "value";
  if (value === null) return null;
  const t = typeof value;
  if (t === "boolean" || t === "string") return null;
  if (t === "number") return Number.isFinite(value) ? null : `non-finite number at ${here}`;
  if (t !== "object") return `unsupported ${t} at ${here}`; // function, symbol, bigint, undefined
  const obj = value as object;
  // Cycle guard: a value reachable from itself is not JSON-representable and
  // would otherwise recurse until the stack overflows. `seen` tracks the
  // current DFS path (added on entry, removed on exit below), so a genuine
  // back-edge is rejected while a shared but acyclic reference is not.
  if (seen.has(obj)) return `circular reference at ${here}`;
  seen.add(obj);
  try {
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        if (!(i in value)) return `array hole at ${path}[${i}]`;
        const r = firstNonJsonPath(value[i], `${path}[${i}]`, seen);
        if (r) return r;
      }
      return null;
    }
    if (!isPlainObject(obj)) {
      const name = obj.constructor?.name ?? "object";
      return `non-plain object (${name}) at ${here}`;
    }
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const child = `${path}${path ? "." : ""}${k}`;
      if (v === undefined) return `undefined value at ${child}`;
      const r = firstNonJsonPath(v, child, seen);
      if (r) return r;
    }
    return null;
  } finally {
    seen.delete(obj);
  }
}

// A bound parameter is committed via JCS canonicalization (paramsHash), so it
// must be a fully JSON-representable value. typeMatches only checks the
// top-level container; a value like `[Infinity]`, `{ x: undefined }`, or
// `{ cfg: new Date() }` passes that yet is not a stable/faithful JSON value.
// Reject at bind time: firstNonJsonPath rejects everything structurally
// non-JSON (including non-plain instances canonicalize would misrepresent),
// and a final canonicalize() guard catches anything left (e.g. lone
// surrogates in strings). Returns a reason or null.
function jsonBindError(value: unknown): string | null {
  const bad = firstNonJsonPath(value, "", new Set<object>());
  if (bad) return bad;
  try {
    canonicalize(value);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

// Deep-clone a validated JSON value into a fresh, deeply frozen tree, so the
// bound parameters are an immutable snapshot of the session binding. Without
// this the returned params would alias the caller's input: a mutation after
// paramsHash() but before resolveSchemaParams() would let the committed hash
// cover one value while resolution enforces another. Input is already
// validated JSON (jsonBindError), so only arrays and plain objects need
// structural copying; setOwn preserves an own "__proto__" key.
function snapshotJson(value: unknown): unknown {
  if (Array.isArray(value)) return Object.freeze(value.map(snapshotJson));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>))
      setOwn(out, k, snapshotJson(v));
    return Object.freeze(out);
  }
  return value;
}

// Bind caller-supplied values to a parameter declaration block.
//
// Rules (wire contract, spec 2.7.1):
//   1. Only declared parameters are accepted. An unknown provided key is
//      an error (fail-closed: a mandate must not carry values it never
//      declared, or params_hash would cover unreviewed input).
//   2. Per declaration: use the provided value if present; else the
//      declared `default`; else error if `required`; else the parameter
//      is left unbound (omitted from the result).
//   3. Provided values and defaults are both type-checked against `type`.
//      A non-finite number is rejected (consistent with JCS).
//   4. The result contains only parameters that resolved to a value.
//      "Omitted optional" and "not declared" both leave the key absent,
//      so params_hash is stable regardless of how the caller spelled an
//      absent optional.
export function bindParameters(
  declarations: ParameterDeclarations | undefined,
  provided: Record<string, unknown> | undefined
): BindParametersResult {
  const decls = declarations ?? {};
  const input = provided ?? {};
  const errors: string[] = [];

  for (const key of Object.keys(input)) {
    // Own-property check, NOT `key in decls`: `in` walks the prototype
    // chain, so a supplied `toString`/`constructor` would look declared,
    // skip this fail-closed guard, and never be covered by params_hash.
    if (!Object.prototype.hasOwnProperty.call(decls, key)) errors.push(`Unknown parameter: ${key}`);
  }

  const params: Record<string, unknown> = {};
  for (const [name, decl] of Object.entries(decls)) {
    // Fail closed on a malformed declaration (e.g. `{"limit": null}` or a
    // scalar from profile JSON) rather than throwing a TypeError on the
    // `.type` dereference below — a bad template must return validation
    // errors, not crash session start / offline verification.
    if (decl === null || typeof decl !== "object" || Array.isArray(decl)) {
      errors.push(`Parameter ${name}: declaration must be an object with a "type"`);
      continue;
    }
    // Reject a declaration type outside the protocol whitelist before any
    // value matching, so a JSON profile can't commit a params_hash for a
    // type (e.g. "null") that a spec-compliant verifier would reject.
    if (!VALID_PARAMETER_TYPES.has((decl as ParameterDeclaration).type as string)) {
      errors.push(
        `Parameter ${name}: unsupported declaration type ${JSON.stringify((decl as ParameterDeclaration).type)} (allowed: string, number, boolean, array, object)`
      );
      continue;
    }
    // Own-property presence only — NOT `&& input[name] !== undefined`. An
    // explicit `undefined` value (e.g. from config/form data) is a supplied
    // invalid value, not an omission: routing it through the value path makes
    // typeMatches reject it, rather than silently applying a default or
    // dropping an optional $allowlist constraint to "allow any".
    const hasProvided = Object.prototype.hasOwnProperty.call(input, name);
    if (hasProvided) {
      const value = input[name];
      if (!typeMatches(value, decl.type)) {
        errors.push(`Parameter ${name}: expected ${decl.type}, got ${jsonTypeOf(value)}`);
      } else {
        const bad = jsonBindError(value);
        if (bad) errors.push(`Parameter ${name}: ${bad}`);
        else setOwn(params, name, snapshotJson(value));
      }
      continue;
    }
    if (decl.default !== undefined) {
      if (!typeMatches(decl.default, decl.type)) {
        errors.push(`Parameter ${name}: default value is not a ${decl.type}`);
      } else {
        const bad = jsonBindError(decl.default);
        if (bad) errors.push(`Parameter ${name}: default ${bad}`);
        else setOwn(params, name, snapshotJson(decl.default));
      }
      continue;
    }
    if (decl.required) errors.push(`Missing required parameter: ${name}`);
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, params: Object.freeze(params) as Record<string, unknown> };
}

// params_hash is "sha256:" + SHA-256 over the JCS-canonical bytes of the
// bound parameters. Reuses the same construction as profile_hash /
// schema_hash (hash.ts), so it is order-independent and reproducible in
// any RFC 8785 implementation.
export function paramsHash(boundParams: Record<string, unknown>): string {
  return sha256Prefixed(boundParams);
}

function isMarker(node: unknown, key: "$param" | "$allowlist"): node is Record<string, string> {
  return (
    typeof node === "object" &&
    node !== null &&
    !Array.isArray(node) &&
    Object.keys(node).length === 1 &&
    // Own-property check, NOT `key in node`: an inherited `$param`/`$allowlist`
    // (e.g. from prototype pollution in the process) would otherwise make a
    // normal single-own-key schema like `{type:"number"}` look like a marker
    // and drop its constraint. The marker key must be the object's own key.
    Object.prototype.hasOwnProperty.call(node, key) &&
    // Spec 2.7.2: marker names are strings. A non-string value (e.g.
    // `{"$param": 0}`) is NOT a marker — treating it as one would let JS
    // coerce 0 -> "0" and resolve a schema a stricter verifier rejects.
    typeof (node as Record<string, unknown>)[key] === "string"
  );
}

export class ParameterResolutionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ParameterResolutionError";
  }
}

// Resolve `$param` / `$allowlist` markers in a (parameterized) JSON
// Schema against bound parameters, producing a concrete JSON Schema.
//
// Rules (wire contract, spec 2.7.2):
//   - Resolution ALWAYS precedes validation. The verifier resolves first,
//     then validates evidence against the concrete schema.
//   - `{"$param": "<name>"}` -> the bound value of <name>. If <name> is
//     not bound it is a ParameterResolutionError (fail-closed: a $param
//     marker is a constraint that must be enforced; silently dropping it
//     would weaken the mandate).
//   - `{"$allowlist": "<name>"}` -> `{"enum": <value>}` when <name> is
//     bound to an array; `{}` (no constraint) when <name> is UNBOUND.
//     This is the one deliberate drop-when-absent rule: an allowlist is
//     opt-in membership, and an unbound allowlist means "not restricted".
//     A bound-but-non-array value is an error.
//   - A marker is recognized only as an object with exactly one key that
//     is `$param` or `$allowlist`. Every other object/array is traversed
//     structurally and rebuilt. The transform is pure and deterministic;
//     object key order is irrelevant (the result is consumed by the
//     order-independent validator or hashed via JCS).
export function resolveSchemaParams(
  schema: unknown,
  boundParams: Record<string, unknown>
): unknown {
  if (isMarker(schema, "$param")) {
    const name = schema["$param"];
    if (!Object.prototype.hasOwnProperty.call(boundParams, name))
      throw new ParameterResolutionError(`$param references unbound parameter: ${name}`);
    return boundParams[name];
  }
  if (isMarker(schema, "$allowlist")) {
    const name = schema["$allowlist"];
    if (!Object.prototype.hasOwnProperty.call(boundParams, name)) return {};
    const value = boundParams[name];
    if (!Array.isArray(value))
      throw new ParameterResolutionError(
        `$allowlist parameter ${name} must be an array, got ${jsonTypeOf(value)}`
      );
    return { enum: value };
  }
  if (Array.isArray(schema)) return schema.map((item) => resolveSchemaParams(item, boundParams));
  if (typeof schema === "object" && schema !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(schema as Record<string, unknown>))
      setOwn(out, k, resolveSchemaParams(v, boundParams));
    return out;
  }
  return schema;
}

// Convenience: two bound-parameter sets are equivalent iff their JCS
// bytes match. Exposed for tests and for a future genesis/verify path
// that compares an embedded params.json against the committed hash.
export function boundParamsEqual(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  return canonicalize(a) === canonicalize(b);
}
