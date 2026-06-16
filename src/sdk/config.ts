import type {
  EnvelopeCustody,
  EvidenceCustody,
  SdkConfig,
  SdkMode,
  SdkTier
} from "./types.js";

// Internal, fully-resolved SDK configuration. Either a Direct or a
// Managed shape; the discriminant is `mode`. Built by
// `resolveSdkConfig` after validating the public SdkConfig surface.
export type ResolvedSdkConfig =
  | {
      mode: "direct";
      witness: SdkConfig["witness"];
    }
  | {
      mode: "managed";
      intermediary: NonNullable<SdkConfig["intermediary"]>;
      evidenceCustody: EvidenceCustody;
      envelopeCustody: EnvelopeCustody;
      tier?: SdkTier;
    };

const TIER_TO_CUSTODY: Record<
  SdkTier,
  { evidenceCustody: EvidenceCustody; envelopeCustody: EnvelopeCustody }
> = {
  hosted: { evidenceCustody: "both", envelopeCustody: "both" },
  "hash-only": { evidenceCustody: "customer", envelopeCustody: "both" },
  ephemeral: { evidenceCustody: "customer", envelopeCustody: "customer" }
};

export class SdkConfigError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "SdkConfigError";
    this.code = code;
  }
}

// Reject configurations that mix mode-specific options or omit
// required ones. The errors here are the customer's first interaction
// with the SDK; the messages are written to point at the right next
// step instead of just naming the problem.
export function resolveSdkConfig(input: SdkConfig | undefined): ResolvedSdkConfig {
  const cfg: SdkConfig = input ?? {};
  const mode: SdkMode = cfg.mode ?? "direct";

  // `broker` is the canonical managed-mode key; `intermediary` is the
  // deprecated alias. They are the same shape, so resolution collapses
  // them here and everything downstream sees one endpoint config.
  if (cfg.broker !== undefined && cfg.intermediary !== undefined) {
    throw new SdkConfigError(
      "broker_and_intermediary_both_set",
      "broker and intermediary are aliases for the same managed-mode endpoint config. Set broker (recommended) and remove intermediary."
    );
  }
  const managedEndpoint = cfg.broker ?? cfg.intermediary;

  if (cfg.evidenceEncryption !== undefined && cfg.evidenceEncryption !== "none") {
    if (cfg.evidenceEncryption === "client-side") {
      // hash-only and ephemeral never send evidence to Sequesign, so
      // encryption is incoherent in those tiers; surface that
      // specifically before falling through to the global rejection.
      if (cfg.tier === "hash-only" || cfg.tier === "ephemeral") {
        throw new SdkConfigError(
          "evidence_encryption_incoherent_with_tier",
          `evidenceEncryption has no effect when evidence is not sent to Sequesign (tier "${cfg.tier}"). Remove evidenceEncryption or pick a different tier.`
        );
      }
      throw new SdkConfigError(
        "evidence_encryption_not_implemented",
        'Encrypted evidence is reserved for a future release; tracked in GitHub issue #76. Set evidenceEncryption to "none" or omit it.'
      );
    }
    throw new SdkConfigError(
      "evidence_encryption_invalid",
      `evidenceEncryption must be "none" or "client-side"; got ${JSON.stringify(cfg.evidenceEncryption)}.`
    );
  }

  if (mode === "direct") {
    if (managedEndpoint !== undefined) {
      throw new SdkConfigError(
        "intermediary_not_allowed_in_direct_mode",
        'mode is "direct" (the default) but broker config was supplied. Set mode to "managed" to route through the Sequesign broker, or remove the broker config.'
      );
    }
    if (cfg.tier !== undefined) {
      throw new SdkConfigError(
        "tier_not_allowed_in_direct_mode",
        'mode is "direct" (the default) but tier was supplied. Set mode to "managed" to pick a tier ("hosted", "hash-only", or "ephemeral"), or remove the tier.'
      );
    }
    if (cfg.evidenceCustody !== undefined || cfg.envelopeCustody !== undefined) {
      throw new SdkConfigError(
        "custody_not_allowed_in_direct_mode",
        'evidenceCustody and envelopeCustody only apply in managed mode. Set mode to "managed", or remove these parameters.'
      );
    }
    return { mode: "direct", witness: cfg.witness };
  }

  // mode === "managed"
  if (cfg.witness !== undefined) {
    throw new SdkConfigError(
      "witness_not_allowed_in_managed_mode",
      'mode is "managed"; the SDK talks to the broker, not directly to the witness. Remove the witness config and supply broker instead.'
    );
  }
  if (!managedEndpoint) {
    throw new SdkConfigError(
      "intermediary_required_for_managed_mode",
      'mode is "managed" but no broker config was supplied. Pass broker: { baseUrl, apiKey } pointing at the Sequesign broker (https://broker.sequesign.com).'
    );
  }
  const hasRawCustody =
    cfg.evidenceCustody !== undefined || cfg.envelopeCustody !== undefined;
  if (cfg.tier === undefined && !hasRawCustody) {
    throw new SdkConfigError(
      "tier_required_for_managed_mode",
      [
        'mode is "managed" but no tier was supplied. Choose one of:',
        '  tier: "hosted"    : Sequesign stores receipt + evidence; you also keep both.',
        '  tier: "hash-only" : Sequesign stores receipt envelope only; you keep evidence.',
        '  tier: "ephemeral" : Sequesign signs and forgets; you keep both.',
        "Advanced callers may instead set evidenceCustody and envelopeCustody directly."
      ].join("\n")
    );
  }
  if (cfg.tier !== undefined && hasRawCustody) {
    throw new SdkConfigError(
      "tier_and_raw_custody_both_set",
      "specify either `tier` (recommended) OR the raw custody parameters (evidenceCustody/envelopeCustody), not both."
    );
  }

  const custody = cfg.tier
    ? TIER_TO_CUSTODY[cfg.tier]
    : {
        evidenceCustody: cfg.evidenceCustody as EvidenceCustody,
        envelopeCustody: cfg.envelopeCustody as EnvelopeCustody
      };

  return {
    mode: "managed",
    intermediary: managedEndpoint,
    evidenceCustody: custody.evidenceCustody,
    envelopeCustody: custody.envelopeCustody,
    tier: cfg.tier
  };
}
