// Public API surface for @sequesign/sdk, pinned at the v0.5 receipt
// schema freeze (PR 15-A). Everything re-exported here is part of the
// supported surface; adding to it is a deliberate act. The three
// historically low-confidence exports were audited at the freeze and
// kept because each is live on the public surface: NotImplementedError
// is thrown by public session methods, UnsupportedClaim is a field type
// on RecordActionInput, and WitnessConfigSummary is a field type on the
// resume/session summary. AgentIdentityAttestation is new in v0.5.

import { mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { tmpdir } from "node:os";

import { resolveSdkConfig, SdkConfigError } from "./config.js";
import { startManagedSessionImpl } from "./managed-session.js";
import { ResumeError } from "./errors.js";
import {
  resumeFromPackageImpl,
  resumeSessionImpl
} from "./resume.js";
import {
  submitApprovalSatelliteImpl,
  submitCounterpartySatelliteImpl
} from "./satellite.js";
import { startSessionImpl } from "./session.js";
import type {
  KeyMaterial,
  ResumeOptions,
  Sdk,
  SdkConfig,
  SdkDefaults,
  Session,
  SessionCheckpoint,
  SessionInit,
  SubmitApprovalSatelliteInput,
  SubmitCounterpartySatelliteInput,
  WitnessInput,
  WitnessResult
} from "./types.js";

export function createSequesign(options: SdkConfig = {}): Sdk {
  const resolved = resolveSdkConfig(options);

  if (resolved.mode === "direct") {
    const witnessDefaults = resolved.witness;
    return {
      async startSession(init: SessionInit): Promise<Session> {
        if (!init.package) {
          throw new ResumeError(
            "package_required",
            "Direct mode requires init.package. Pass { directory, ifExists } to write the receipt package to disk."
          );
        }
        return startSessionImpl(
          init as SessionInit & { package: NonNullable<SessionInit["package"]> },
          witnessDefaults
        );
      },
      async resumeSession(
        checkpoint: SessionCheckpoint,
        keypair: KeyMaterial,
        opts: ResumeOptions = {}
      ): Promise<Session> {
        return resumeSessionImpl({
          checkpoint,
          keypair,
          options: opts,
          sdkWitnessDefaults: witnessDefaults
        });
      },
      async resumeFromPackage(
        packageDirectory: string,
        keypair: KeyMaterial,
        opts: ResumeOptions = {}
      ): Promise<Session> {
        return resumeFromPackageImpl({
          packageDirectory,
          keypair,
          options: opts,
          sdkWitnessDefaults: witnessDefaults
        });
      },
      async witness(input: WitnessInput): Promise<WitnessResult> {
        return witnessOneShotDirect(input, witnessDefaults);
      },
      async submitApprovalSatellite(input: SubmitApprovalSatelliteInput) {
        return submitApprovalSatelliteImpl(input, resolved);
      },
      async submitCounterpartySatellite(input: SubmitCounterpartySatelliteInput) {
        return submitCounterpartySatelliteImpl(input, resolved);
      }
    };
  }

  // managed mode
  return {
    async startSession(init: SessionInit): Promise<Session> {
      return startManagedSessionImpl({ init, managed: resolved });
    },
    async resumeSession(): Promise<Session> {
      throw new ResumeError(
        "resume_not_supported_in_managed_mode",
        "Resuming a session is not supported in managed mode. Phase 4 multi-action chains are in-process only; cross-process resume requires server-side session state, which we will consider only if customers ask for it."
      );
    },
    async resumeFromPackage(): Promise<Session> {
      throw new ResumeError(
        "resume_not_supported_in_managed_mode",
        "Resuming a session is not supported in managed mode. Phase 4 multi-action chains are in-process only; cross-process resume requires server-side session state, which we will consider only if customers ask for it."
      );
    },
    async witness(input: WitnessInput): Promise<WitnessResult> {
      return witnessOneShotManaged(input, resolved);
    },
    async submitApprovalSatellite(input: SubmitApprovalSatelliteInput) {
      return submitApprovalSatelliteImpl(input, resolved);
    },
    async submitCounterpartySatellite(input: SubmitCounterpartySatelliteInput) {
      return submitCounterpartySatelliteImpl(input, resolved);
    }
  };
}

// One-shot convenience for direct mode: open a session against a
// temporary package directory, record a single action, finalize, and
// clean up. The caller gets the receipt object without seeing the
// temporary path.
async function witnessOneShotDirect(
  input: WitnessInput,
  witnessDefaults: SdkConfig["witness"]
): Promise<WitnessResult> {
  let packageDir: string;
  let ownsTemp: boolean;
  let ifExists: "fail" | "reset" | "resume";
  if (input.package) {
    packageDir = input.package.directory;
    ownsTemp = false;
    ifExists = input.package.ifExists ?? "fail";
  } else {
    packageDir = await mkdtemp(path.join(tmpdir(), "sequesign-witness-"));
    ownsTemp = true;
    // mkdtemp creates the directory, so "reset" is the only option that
    // does not throw on existing directory.
    ifExists = "reset";
  }
  try {
    const session = await startSessionImpl(
      {
        agent: input.agent,
        task: input.task,
        mode: input.mode,
        chainId: input.chainId,
        receiptId: input.receiptId,
        package: { directory: packageDir, ifExists }
      },
      witnessDefaults
    );
    await session.recordAction({
      actionType: input.actionType,
      evidence: input.evidence,
      verifiabilityClass: input.verifiabilityClass,
      schemaId: input.schemaId,
      schemaHash: input.schemaHash
    });
    const result = await session.finalize();
    return {
      receipt: result.receipt,
      receiptId: result.receiptId,
      chainId: session.chainId
    };
  } finally {
    if (ownsTemp) {
      await rm(packageDir, { recursive: true, force: true });
    }
  }
}

async function witnessOneShotManaged(
  input: WitnessInput,
  resolved: ReturnType<typeof resolveSdkConfig>
): Promise<WitnessResult> {
  if (resolved.mode !== "managed") {
    throw new Error("witnessOneShotManaged invoked with non-managed config");
  }
  const session = await startManagedSessionImpl({
    init: {
      agent: input.agent,
      task: input.task,
      mode: input.mode,
      chainId: input.chainId,
      receiptId: input.receiptId,
      package: input.package
    },
    managed: resolved
  });
  await session.recordAction({
    actionType: input.actionType,
    evidence: input.evidence,
    verifiabilityClass: input.verifiabilityClass,
    schemaId: input.schemaId,
    schemaHash: input.schemaHash
  });
  const result = await session.finalize();
  return {
    receipt: result.receipt,
    receiptId: result.receiptId,
    chainId: session.chainId,
    r2Key: result.r2Key,
    receiptUrl: result.receiptUrl
  };
}

export { serializeCheckpoint, parseCheckpoint } from "./resume.js";

export { SdkConfigError } from "./config.js";

export {
  NotImplementedError,
  WitnessUnavailableError,
  WitnessRequestFailedError,
  WitnessResponseMismatchError,
  WitnessSignatureMismatchError,
  WitnessKeyRotationLoopError,
  SessionStateError,
  PackageStateError,
  FinalizationError,
  SchemaValidationError,
  SchemaHashMismatchError,
  SchemaRequiredError,
  ResumeError,
  ApprovalError,
  PlanReferenceError,
  CounterpartyAttestationError,
  SatelliteError,
  ProfileValidationError,
  InclusionProofTimeoutError,
  SequesignSdkError
} from "./errors.js";

// BrokerRequestError is the canonical name (the managed-mode endpoint
// is the broker); IntermediaryRequestError is the legacy alias, kept so
// existing catch sites keep working. Same class, two names.
export {
  IntermediaryRequestError,
  IntermediaryRequestError as BrokerRequestError
} from "./intermediary-client.js";

export {
  PLAN_GENERATED_ACTION_TYPE,
  PLAN_STEP_EXECUTED_ACTION_TYPE,
  PLAN_DEVIATION_ACTION_TYPE
} from "./types.js";

export { formatInspectionReport } from "./inspect.js";

// v0.6 step #4.4 (vouching): the enrollment-side proof-of-possession helper. SDK
// consumers (the approver/counterparty enrolling a key) need this to produce the
// `subject_signature` that dashboard-api POST /registrations (#4.3) requires;
// re-export it from the SDK root so they don't reimplement the challenge encoding.
export { registrationChallengeSignature } from "../lib/registration.js";

export type {
  Sdk,
  SdkConfig,
  SdkDefaults,
  SdkMode,
  SdkTier,
  EvidenceCustody,
  EnvelopeCustody,
  EvidenceEncryption,
  BrokerConfig,
  IntermediaryConfig,
  WitnessInput,
  WitnessResult,
  Session,
  SessionInit,
  KeyMaterial,
  WitnessConfig,
  WitnessStaticKey,
  PackageConfig,
  RecordActionInput,
  RecordedAction,
  FinalizeOptions,
  FinalizeResult,
  FetchInclusionProofsOptions,
  FetchInclusionProofsResult,
  SessionStateSnapshot,
  UnsupportedClaim,
  ReceiptMode,
  VerifiabilityClass,
  AgentActionReceipt,
  AgentIdentityAttestation,
  BatchInclusionProof,
  VerificationReport,
  EvidenceReference,
  ProfileReference,
  SchemaReference,
  InspectionReport,
  InspectedAction,
  OutstandingRequirement,
  InspectionWarning,
  PartialVerificationReport,
  ToolWrapSpec,
  ToolWrapErrorMode,
  WrappedTool,
  SessionCheckpoint,
  WitnessConfigSummary,
  ResumeOptions,
  RecordApprovalInput,
  RecordPlanInput,
  RecordPlanStepInput,
  RecordCounterpartyAttestationInput,
  SubmitApprovalSatelliteInput,
  SubmitCounterpartySatelliteInput,
  ApprovalAttestation,
  ApprovalSatellite,
  CounterpartyAttestation,
  CounterpartySatellite,
  IdentityProof
} from "./types.js";
