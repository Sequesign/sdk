import type { EvidenceBlob } from "./types.js";
import { loadSchemaById } from "./schema-registry.js";
import { canonicalize } from "./canonicalize.js";
export type SchemaValidationResult = { valid: boolean; errors: string[] };
// The subset of JSON Schema this hand-rolled validator supports. Kept
// deliberately small and dependency-free (no ajv) so an independent
// verifier in any language is a weekend port, not an ajv-compatibility
// project — the load-bearing property under "verify without us" (see
// docs/protocol-spec.md section 2.7). `maximum` and `const` were added
// for parameterized mandates: a `$param` bound value commonly resolves
// into `maximum` (spend ceilings) or `const` (fixed currency).
export type JsonSchema = {
  type?: string;
  required?: string[];
  properties?: Record<string, JsonSchema>;
  additionalProperties?: boolean;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  const?: unknown;
  items?: JsonSchema;
};
function typeOf(v: unknown): string {
  if (Array.isArray(v)) return "array";
  if (v === null) return "null";
  return typeof v;
}
// Equality by canonical JSON bytes, so `const` and `enum` work for any JSON
// value — including the object/array members an `$allowlist` parameter can
// carry. Reference equality (`Array.includes`) would fail to match evidence
// parsed as a distinct-but-equal object.
function jcsEqual(a: unknown, b: unknown): boolean {
  return canonicalize(a) === canonicalize(b);
}
function validateValue(v: unknown, s: JsonSchema, p: string): string[] {
  const errors: string[] = [];
  // `const` is checked before `type`: an exact-value constraint subsumes
  // type, and equality is by JCS bytes so it works for any JSON value
  // (string, number, or a resolved object/array).
  if ("const" in s && !jcsEqual(v, s.const)) {
    errors.push(`${p}: expected const ${canonicalize(s.const)}, got ${canonicalize(v)}`);
    return errors;
  }
  if (s.type && typeOf(v) !== s.type) {
    errors.push(`${p}: expected ${s.type}, got ${typeOf(v)}`);
    return errors;
  }
  if (s.enum && !s.enum.some((e) => jcsEqual(e, v)))
    errors.push(
      `${p}: expected one of ${s.enum.map((e) => canonicalize(e)).join(", ")}, got ${canonicalize(v)}`
    );
  // Numeric bounds fail closed: a resolved schema whose `minimum`/`maximum`
  // is present but not a number (e.g. a `$param` bound as "500") is rejected,
  // not silently skipped — otherwise an over-limit value would validate and a
  // spend ceiling would be unenforced.
  if ("minimum" in s) {
    if (typeof s.minimum !== "number")
      errors.push(`${p}: schema minimum must be a number, got ${typeOf(s.minimum)}`);
    else if (typeof v === "number" && v < s.minimum)
      errors.push(`${p}: expected >= ${s.minimum}, got ${v}`);
  }
  if ("maximum" in s) {
    if (typeof s.maximum !== "number")
      errors.push(`${p}: schema maximum must be a number, got ${typeOf(s.maximum)}`);
    else if (typeof v === "number" && v > s.maximum)
      errors.push(`${p}: expected <= ${s.maximum}, got ${v}`);
  }
  if (s.type === "object" && v && typeof v === "object" && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    // Presence/membership tests use hasOwnProperty, never `in`: `in` walks the
    // prototype chain, so an evidence key named "constructor" / "toString" /
    // "__proto__" would read as a declared property and slip past
    // additionalProperties:false (smuggling PHI or a payload), and a required
    // field named after a prototype member would read as present when absent.
    const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);
    for (const f of s.required ?? [])
      if (!has(obj, f)) errors.push(`${p}.${f}: missing required field`);
    const props = s.properties ?? {};
    for (const [k, c] of Object.entries(props))
      if (has(obj, k)) errors.push(...validateValue(obj[k], c, `${p}.${k}`));
    if (s.additionalProperties === false) {
      for (const k of Object.keys(obj))
        if (!has(props, k)) errors.push(`${p}.${k}: additional property not allowed`);
    }
  }
  if (s.type === "array" && Array.isArray(v) && s.items) {
    v.forEach((item, i) => errors.push(...validateValue(item, s.items!, `${p}[${i}]`)));
  }
  return errors;
}
// Validate any JSON value against a concrete (already parameter-resolved)
// JSON Schema. This is the shared core used both by registry-schema
// validation (below) and, for parameterized mandates, by conformance
// re-evaluation against an embedded profile's resolved evidence schema.
// The schema passed here must already have had `$param` / `$allowlist`
// resolved (see mandate-params.resolveSchemaParams); this function does
// not interpret markers.
export function validateJsonSchema(value: unknown, schema: JsonSchema): SchemaValidationResult {
  const errors = validateValue(value, schema, "content");
  return { valid: errors.length === 0, errors };
}

// The exact keyword set validateValue interprets. Anything else in a schema is
// silently ignored by the validator, which is fine for trusted registry
// schemas but NOT for a parameterized mandate's evidence_schemas, where a
// silently-dropped keyword (pattern, oneOf, exclusiveMaximum, ...) would let
// violating evidence read as conformant. The mandate path uses this to detect
// unsupported keywords and fail closed (record a conformance violation).
const SUPPORTED_SCHEMA_KEYWORDS = new Set([
  "type",
  "required",
  "properties",
  "additionalProperties",
  "enum",
  "minimum",
  "maximum",
  "const",
  "items"
]);

// Annotation / metadata keywords that do NOT constrain instance validity. They
// are harmless in an evidence_schema, so they must not be treated as
// unenforceable assertions (which would force a spurious v2.2.0 violation
// receipt). Note $ref / $defs / definitions are deliberately NOT here: they
// imply reference resolution the subset validator does not do, so they must
// still fail closed as unsupported assertions.
const ANNOTATION_SCHEMA_KEYWORDS = new Set([
  "$schema",
  "$id",
  "$anchor",
  "$comment",
  "title",
  "description",
  "default",
  "examples",
  "readOnly",
  "writeOnly",
  "deprecated"
]);

// Recursively collect any schema constraint the subset validator does not
// enforce — both unsupported keyword NAMES and recognized keywords used in a
// FORM validateValue silently ignores (e.g. `additionalProperties` as a
// subschema object, which validateValue only acts on when === false; `type` as
// an array of types; `items` as a tuple array). Walks into `properties.*` and
// `items`. Returns dotted paths naming each offending constraint. An empty
// array means every constraint in the (resolved) schema is actually enforced,
// so the mandate gate can trust a "valid" result.
export function collectUnenforceableSchema(schema: unknown, path = "content"): string[] {
  if (!schema || typeof schema !== "object" || Array.isArray(schema)) return [];
  const s = schema as Record<string, unknown>;
  const out: string[] = [];
  const isPlainObject = (v: unknown): boolean => !!v && typeof v === "object" && !Array.isArray(v);
  for (const key of Object.keys(s)) {
    // Annotation-only keywords do not affect validity; ignore them.
    if (ANNOTATION_SCHEMA_KEYWORDS.has(key)) continue;
    if (!SUPPORTED_SCHEMA_KEYWORDS.has(key)) {
      out.push(`${path}.${key}`);
      continue;
    }
    // Recognized keyword: confirm it appears in a form validateValue enforces.
    const val = s[key];
    switch (key) {
      case "type":
        if (typeof val !== "string") out.push(`${path}.type(non-string)`);
        break;
      case "enum":
        if (!Array.isArray(val)) out.push(`${path}.enum(non-array)`);
        break;
      case "required":
        if (!Array.isArray(val) || !val.every((x) => typeof x === "string"))
          out.push(`${path}.required(non-string-array)`);
        break;
      case "properties":
        if (!isPlainObject(val)) out.push(`${path}.properties(non-object)`);
        break;
      case "additionalProperties":
        // validateValue only enforces `additionalProperties === false`; a
        // subschema-object form is a real constraint it silently drops.
        if (typeof val !== "boolean") out.push(`${path}.additionalProperties(subschema-form)`);
        break;
      case "items":
        if (!isPlainObject(val)) out.push(`${path}.items(non-object)`);
        break;
      case "minimum":
      case "maximum":
        if (typeof val !== "number") out.push(`${path}.${key}(non-number)`);
        break;
      // `const` compares by JCS bytes, so any value is enforceable.
    }
  }
  // Object/array keywords are only evaluated when the schema declares the
  // matching instance type: validateValue runs `required` / `properties` /
  // `additionalProperties` only under `type === "object"`, and `items` only
  // under `type === "array"`. Without the matching type the constraint is
  // silently skipped, so a schema like {required:["amount"]} (no type) must be
  // treated as unenforceable rather than trusted.
  if (
    (s.required !== undefined ||
      s.properties !== undefined ||
      s.additionalProperties !== undefined) &&
    s.type !== "object"
  ) {
    out.push(`${path}.(object-constraints-require-type-object)`);
  }
  if (s.items !== undefined && s.type !== "array") {
    out.push(`${path}.(items-requires-type-array)`);
  }
  if (isPlainObject(s.properties)) {
    for (const [k, v] of Object.entries(s.properties as Record<string, unknown>)) {
      out.push(...collectUnenforceableSchema(v, `${path}.${k}`));
    }
  }
  if (isPlainObject(s.items)) out.push(...collectUnenforceableSchema(s.items, `${path}[]`));
  return out;
}
export async function validateEvidenceSchema(
  evidence: EvidenceBlob
): Promise<SchemaValidationResult> {
  if (!evidence.schema_id || !evidence.schema_hash)
    return { valid: false, errors: ["Evidence does not include schema_id and schema_hash."] };
  const loaded = await loadSchemaById(evidence.schema_id);
  if (!loaded) {
    // The "sandbox." namespace is reserved for schemas the Interactive
    // Sandbox generates on the fly (src/sandbox-runner.ts) into an
    // ephemeral, process-local registry. A saved sandbox receipt is a
    // developer-loop artifact: it verifies in the process that created it,
    // not independently in a fresh process (the schema files are
    // gitignored and the manifest entry lives only in a temp registry).
    // Report that explicitly rather than as a bare "Unknown schema_id",
    // which would read as a real failure instead of a by-design limit.
    if (evidence.schema_id.startsWith("sandbox.")) {
      return {
        valid: false,
        errors: [
          `Sandbox schema "${evidence.schema_id}" is not in the registry. Interactive Sandbox receipts are a local developer-loop tool: their schema is generated into an ephemeral registry and is not independently verifiable in a separate process. Regenerate it in the sandbox to inspect verification.`
        ]
      };
    }
    return { valid: false, errors: [`Unknown schema_id: ${evidence.schema_id}`] };
  }
  if (loaded.schemaHash !== evidence.schema_hash)
    return {
      valid: false,
      errors: [
        `Schema hash mismatch for ${evidence.schema_id}. Expected ${evidence.schema_hash}, computed ${loaded.schemaHash}.`
      ]
    };
  // Bind the schema to the claimed action_type (issue #218). Each registry
  // schema is registered against exactly one action_type; validating the
  // content shape alone would let a receipt claim one action_type while
  // supplying an unrelated schema's id + content and still report
  // schema_valid=true (a semantic-integrity bypass). Reject when the schema
  // the id resolves to is not the schema bound to the evidence's action_type.
  if (loaded.actionType !== evidence.action_type)
    return {
      valid: false,
      errors: [
        `Schema ${evidence.schema_id} is registered for action_type "${loaded.actionType}", but the evidence claims action_type "${evidence.action_type}".`
      ]
    };
  const errors = validateValue(evidence.content, loaded.schema as JsonSchema, "content");
  return { valid: errors.length === 0, errors };
}
