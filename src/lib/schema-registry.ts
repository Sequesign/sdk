import { readJson } from "./io.js";
import { sha256Prefixed } from "./hash.js";
import { registryPath, resolveAsset } from "./paths.js";
import type { ActionType } from "./types.js";
export type RegistryManifest = {
  registry_version: string;
  schemas: Array<{ schema_id: string; action_type: ActionType; path: string; hash_alg: "sha256" }>;
  profiles: Array<{ profile_id: string; path: string; hash_alg: "sha256" }>;
};
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
  return { profileId: e.profile_id, profile, profileHash: sha256Prefixed(profile) };
}
