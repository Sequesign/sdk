import type { EvidenceBlob } from "./types.js";
import { loadSchemaById } from "./schema-registry.js";
export type SchemaValidationResult = { valid: boolean; errors: string[] };
type JsonSchema = {
  type?: string;
  required?: string[];
  properties?: Record<string, JsonSchema>;
  additionalProperties?: boolean;
  enum?: unknown[];
  minimum?: number;
  items?: JsonSchema;
};
function typeOf(v: unknown): string {
  if (Array.isArray(v)) return "array";
  if (v === null) return "null";
  return typeof v;
}
function validateValue(v: unknown, s: JsonSchema, p: string): string[] {
  const errors: string[] = [];
  if (s.type && typeOf(v) !== s.type) {
    errors.push(`${p}: expected ${s.type}, got ${typeOf(v)}`);
    return errors;
  }
  if (s.enum && !s.enum.includes(v))
    errors.push(`${p}: expected one of ${s.enum.join(", ")}, got ${String(v)}`);
  if (typeof v === "number" && typeof s.minimum === "number" && v < s.minimum)
    errors.push(`${p}: expected >= ${s.minimum}, got ${v}`);
  if (s.type === "object" && v && typeof v === "object" && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    for (const f of s.required ?? [])
      if (!(f in obj)) errors.push(`${p}.${f}: missing required field`);
    const props = s.properties ?? {};
    for (const [k, c] of Object.entries(props))
      if (k in obj) errors.push(...validateValue(obj[k], c, `${p}.${k}`));
    if (s.additionalProperties === false) {
      for (const k of Object.keys(obj))
        if (!(k in props)) errors.push(`${p}.${k}: additional property not allowed`);
    }
  }
  if (s.type === "array" && Array.isArray(v) && s.items) {
    v.forEach((item, i) => errors.push(...validateValue(item, s.items!, `${p}[${i}]`)));
  }
  return errors;
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
  const errors = validateValue(evidence.content, loaded.schema as JsonSchema, "content");
  return { valid: errors.length === 0, errors };
}
