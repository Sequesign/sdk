// §3.2 PR 3: shared client-side schema policy. Direct mode owned this
// logic privately in session.ts (applySchemaPolicy); managed mode now
// runs the identical client-side check so customer-visible behavior is
// identical across modes and tiers.
//
// Two flavors of policy, selected by session mode:
//
//   - schema_validated / profile_constrained: schemaId + schemaHash
//     are REQUIRED on every action. Hash must match the bundled
//     registry. Content is validated against the loaded schema.
//     Throws SchemaRequiredError, SchemaHashMismatchError, or
//     SchemaValidationError on the corresponding failure.
//
//   - freeform mode: schema fields are OPTIONAL. When both are
//     supplied, hash is verified against the registry; content is not
//     content-validated.
//
// On success the schema reference is added to SessionState so the
// finalize envelope's schema_references array reflects every schema
// the chain bound to.
//
// In managed-mode hosted tier, broker re-runs the schema gate
// server-side (PR 9), giving D6 / D7 defense-in-depth. In customer-
// evidence tiers, this client-side gate is the only check (broker has
// no content to validate).

import { loadSchemaById } from "../lib/schema-registry.js";
import { validateEvidenceSchema } from "../lib/schema-validation.js";
import type { EvidenceBlob } from "../lib/types.js";
import {
  SchemaHashMismatchError,
  SchemaRequiredError,
  SchemaValidationError
} from "./errors.js";
import type { SessionState } from "./state.js";
import type { RecordActionInput } from "./types.js";

export async function applySchemaPolicy(
  state: SessionState,
  input: RecordActionInput,
  evidenceBlob: EvidenceBlob
): Promise<void> {
  const modeRequiresValidation =
    state.mode === "schema_validated" || state.mode === "profile_constrained";

  if (!modeRequiresValidation) {
    if (input.schemaId && input.schemaHash) {
      const loaded = await loadSchemaById(input.schemaId);
      if (loaded && loaded.schemaHash !== input.schemaHash) {
        throw new SchemaHashMismatchError(
          input.schemaId,
          input.schemaHash,
          loaded.schemaHash
        );
      }
      state.addSchemaReference({
        schema_id: input.schemaId,
        schema_hash: input.schemaHash
      });
    }
    return;
  }

  if (!input.schemaId || !input.schemaHash) {
    throw new SchemaRequiredError(input.actionType);
  }
  const loaded = await loadSchemaById(input.schemaId);
  if (loaded && loaded.schemaHash !== input.schemaHash) {
    throw new SchemaHashMismatchError(
      input.schemaId,
      input.schemaHash,
      loaded.schemaHash
    );
  }
  const result = await validateEvidenceSchema(evidenceBlob);
  if (!result.valid) {
    throw new SchemaValidationError(input.schemaId, result.errors);
  }
  state.addSchemaReference({
    schema_id: input.schemaId,
    schema_hash: input.schemaHash
  });
}
