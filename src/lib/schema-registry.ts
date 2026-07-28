import { readJson } from "./io.js";
import { sha256Prefixed } from "./hash.js";
import { registryPath, resolveAsset } from "./paths.js";
import type { ActionType, ProfileSignatureSidecar } from "./types.js";

// Template system Phase 6: a template's trust/support tier — discovery
// metadata a consumer filters on when browsing the registry (via the
// sequesign_list_templates MCP tool). This is NOT a security control: the
// hard trust signals are the genesis hash binding (content) and the
// template_authenticity grade (author signature). The tier is curation:
//   - "official"     — authored by Sequesign; the canonical bundled templates.
//   - "verified"     — third-party author whose signature Sequesign recognizes
//                      (a template_authenticity "attested" author key).
//   - "community"    — contributed / unvetted. The default for an untagged entry.
//   - "experimental" — demo or unstable; not for production use.
export type TemplateTier = "official" | "verified" | "community" | "experimental";

export type RegistryManifest = {
  registry_version: string;
  schemas: Array<{ schema_id: string; action_type: ActionType; path: string; hash_alg: "sha256" }>;
  // Template system Phase 5: `signature_path` optionally points at the
  // template-author signature sidecar (profile.sig.json) co-located with the
  // profile. Absent for unsigned profiles (the mandate content is still
  // hash-bound; it is simply not author-vouched).
  //
  // Template system Phase 6: `tier` optionally classifies the template for
  // discovery. Absent is treated as "community" (see resolveTemplateTier).
  profiles: Array<{
    profile_id: string;
    path: string;
    hash_alg: "sha256";
    signature_path?: string;
    tier?: TemplateTier;
  }>;
};

// A manifest entry with no explicit tier is treated as "community" (contributed
// / unvetted) — the conservative default, so an untagged template never
// masquerades as official.
export function resolveTemplateTier(tier: TemplateTier | undefined): TemplateTier {
  return tier ?? "community";
}
export async function loadManifest(): Promise<RegistryManifest> {
  return readJson<RegistryManifest>(registryPath("manifest.json"));
}
export async function loadSchemaByActionType(actionType: ActionType) {
  const m = await loadManifest();
  const e = m.schemas.find((x) => x.action_type === actionType);
  if (!e) return null;
  const schema = await readJson<Record<string, unknown>>(resolveAsset(e.path));
  return { schemaId: e.schema_id, actionType, schema, schemaHash: sha256Prefixed(schema) };
}
export async function loadSchemaById(schemaId: string) {
  const m = await loadManifest();
  const e = m.schemas.find((x) => x.schema_id === schemaId);
  if (!e) return null;
  const schema = await readJson<Record<string, unknown>>(resolveAsset(e.path));
  return {
    schemaId: e.schema_id,
    actionType: e.action_type,
    schema,
    schemaHash: sha256Prefixed(schema)
  };
}
export async function loadProfileById(profileId: string) {
  const m = await loadManifest();
  const e = m.profiles.find((x) => x.profile_id === profileId);
  if (!e) return null;
  const profile = await readJson<Record<string, unknown>>(resolveAsset(e.path));
  // Template system Phase 5: load the co-located author signature sidecar when
  // the manifest declares one. A missing/unreadable sidecar is not fatal — the
  // profile is simply unsigned (author vouching is optional), so authorSignature
  // is undefined and the session embeds no profile.sig.json.
  let authorSignature: ProfileSignatureSidecar | undefined;
  if (e.signature_path) {
    try {
      const sidecar = await readJson<ProfileSignatureSidecar>(resolveAsset(e.signature_path));
      if (sidecar && typeof sidecar.cose_sign1_b64url === "string") {
        authorSignature = { cose_sign1_b64url: sidecar.cose_sign1_b64url };
      }
    } catch {
      authorSignature = undefined;
    }
  }
  return {
    profileId: e.profile_id,
    profile,
    profileHash: sha256Prefixed(profile),
    authorSignature,
    // Phase 6: the resolved discovery tier (absent -> "community").
    tier: resolveTemplateTier(e.tier)
  };
}
