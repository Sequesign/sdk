import type { ActionRecord, EvidenceBlob } from "./types.js";
import { loadProfileById } from "./schema-registry.js";
export type WorkflowValidationResult = {
  valid: boolean;
  profileHashVerified: boolean;
  errors: string[];
};
function getPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce((acc: unknown, part: string) => {
    if (acc && typeof acc === "object" && part in (acc as Record<string, unknown>))
      return (acc as Record<string, unknown>)[part];
    return undefined;
  }, obj);
}
export async function validateWorkflowProfile(p: {
  profileId: string;
  profileHash: string;
  actions: ActionRecord[];
  evidence: EvidenceBlob[];
}): Promise<WorkflowValidationResult> {
  const loaded = await loadProfileById(p.profileId);
  if (!loaded)
    return {
      valid: false,
      profileHashVerified: false,
      errors: [`Unknown profile_id: ${p.profileId}`]
    };
  const errors: string[] = [];
  const profileHashVerified = loaded.profileHash === p.profileHash;
  if (!profileHashVerified)
    errors.push(
      `Profile hash mismatch. Expected ${p.profileHash}, computed ${loaded.profileHash}.`
    );
  const profile = loaded.profile as any;
  const actionTypes = p.actions.map((a) => a.action_type);
  for (const a of actionTypes)
    if (!profile.allowed_actions.includes(a))
      errors.push(`Action ${a} is not allowed by profile ${p.profileId}.`);
  for (const r of profile.required_actions ?? [])
    if (!actionTypes.includes(r)) errors.push(`Required action missing: ${r}`);
  let previous = "START";
  const allowed = new Set(
    (profile.allowed_transitions ?? []).map((pair: [string, string]) => `${pair[0]}->${pair[1]}`)
  );
  for (const current of actionTypes) {
    if (!allowed.has(`${previous}->${current}`))
      errors.push(`Invalid workflow transition: ${previous} -> ${current}`);
    previous = current;
  }
  if (
    profile.allowed_final_actions &&
    !profile.allowed_final_actions.includes(actionTypes[actionTypes.length - 1])
  )
    errors.push(`Invalid final action: ${actionTypes[actionTypes.length - 1]}`);
  const evidenceByActionType = new Map(p.evidence.map((item) => [item.action_type, item]));
  for (const rule of profile.conditional_requirements ?? []) {
    const evidence = evidenceByActionType.get(rule.if_action);
    if (!evidence) continue;
    const value = getPath(evidence, rule.field_path);
    if (value === rule.equals) {
      const targetIndex = actionTypes.indexOf(rule.required_prior_to.action);
      const requiredIndex = actionTypes.indexOf(rule.required_prior_to.must_include);
      if (targetIndex >= 0 && (requiredIndex < 0 || requiredIndex > targetIndex))
        errors.push(
          `Action ${rule.required_prior_to.must_include} is required before ${rule.required_prior_to.action}.`
        );
    }
  }
  return { valid: errors.length === 0 && profileHashVerified, profileHashVerified, errors };
}
