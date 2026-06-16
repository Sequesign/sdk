export class SequesignSdkError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "SequesignSdkError";
    this.code = code;
  }
}

export class NotImplementedError extends SequesignSdkError {
  constructor(method: string) {
    super("not_implemented", `${method} is not implemented in this milestone.`);
    this.name = "NotImplementedError";
  }
}

export class WitnessUnavailableError extends SequesignSdkError {
  readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super("witness_unavailable", message);
    this.name = "WitnessUnavailableError";
    this.cause = cause;
  }
}

export class WitnessRequestFailedError extends SequesignSdkError {
  readonly status?: number;
  readonly attempts: number;
  readonly cause?: unknown;
  constructor(message: string, attempts: number, status?: number, cause?: unknown) {
    super("witness_request_failed", message);
    this.name = "WitnessRequestFailedError";
    this.attempts = attempts;
    this.status = status;
    this.cause = cause;
  }
}

export class WitnessResponseMismatchError extends SequesignSdkError {
  readonly field: string;
  constructor(field: string, expected: unknown, actual: unknown) {
    super(
      "witness_response_mismatch",
      `Witness response field "${field}" did not match the request: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}.`
    );
    this.name = "WitnessResponseMismatchError";
    this.field = field;
  }
}

export class WitnessSignatureMismatchError extends SequesignSdkError {
  readonly witnessKeyId: string;
  constructor(witnessKeyId: string) {
    super(
      "witness_signature_invalid",
      `Witness attestation signature did not verify against the discovered key (key_id=${witnessKeyId}).`
    );
    this.name = "WitnessSignatureMismatchError";
    this.witnessKeyId = witnessKeyId;
  }
}

export class WitnessKeyRotationLoopError extends SequesignSdkError {
  constructor() {
    super(
      "witness_key_rotation_loop",
      "Witness key rotated twice in succession without a verifying signature. Refusing to advance."
    );
    this.name = "WitnessKeyRotationLoopError";
  }
}

export class SessionStateError extends SequesignSdkError {
  constructor(message: string) {
    super("session_state", message);
    this.name = "SessionStateError";
  }
}

export class PackageStateError extends SequesignSdkError {
  constructor(message: string) {
    super("package_state", message);
    this.name = "PackageStateError";
  }
}

export class FinalizationError extends SequesignSdkError {
  constructor(message: string) {
    super("finalization_failed", message);
    this.name = "FinalizationError";
  }
}

export class SchemaValidationError extends SequesignSdkError {
  readonly schemaId: string;
  readonly errors: string[];
  constructor(schemaId: string, errors: string[]) {
    super(
      "schema_validation_failed",
      `Evidence did not validate against schema "${schemaId}": ${errors.join("; ")}`
    );
    this.name = "SchemaValidationError";
    this.schemaId = schemaId;
    this.errors = errors;
  }
}

export class SchemaHashMismatchError extends SequesignSdkError {
  readonly schemaId: string;
  readonly expected: string;
  readonly actual: string;
  constructor(schemaId: string, expected: string, actual: string) {
    super(
      "schema_hash_mismatch",
      `Schema "${schemaId}" hash did not match: expected ${expected}, computed ${actual}`
    );
    this.name = "SchemaHashMismatchError";
    this.schemaId = schemaId;
    this.expected = expected;
    this.actual = actual;
  }
}

export class SchemaRequiredError extends SequesignSdkError {
  constructor(actionType: string) {
    super(
      "schema_required",
      `Action "${actionType}" was recorded under schema_validated mode without schemaId and schemaHash. Provide both, or use freeform mode.`
    );
    this.name = "SchemaRequiredError";
  }
}

export class ResumeError extends SequesignSdkError {
  readonly detail?: unknown;
  constructor(code: string, message: string, detail?: unknown) {
    super(code, message);
    this.name = "ResumeError";
    this.detail = detail;
  }
}

export class ApprovalError extends SequesignSdkError {
  constructor(code: string, message: string) {
    super(code, message);
    this.name = "ApprovalError";
  }
}

export class PlanReferenceError extends SequesignSdkError {
  readonly planActionId?: string;
  constructor(message: string, planActionId?: string) {
    super("plan_reference_invalid", message);
    this.name = "PlanReferenceError";
    this.planActionId = planActionId;
  }
}

export class CounterpartyAttestationError extends SequesignSdkError {
  constructor(code: string, message: string) {
    super(code, message);
    this.name = "CounterpartyAttestationError";
  }
}

// v0.6 step #3b.3: a deferred-satellite submit failed. Binding failures
// (wrong task/action/content/chain) reuse ApprovalError /
// CounterpartyAttestationError with the SAME codes as the in-envelope
// recordApproval / recordCounterpartyAttestation paths, so a satellite is
// rejected for the same reason and with the same code whether it is born
// co-located or deferred. SatelliteError covers the satellite-specific
// failures: a seal whose signature does not self-verify, and a duplicate
// already present in the attestations.jsonl sidecar.
export class SatelliteError extends SequesignSdkError {
  constructor(code: string, message: string) {
    super(code, message);
    this.name = "SatelliteError";
  }
}

export class ProfileValidationError extends SequesignSdkError {
  readonly profileId: string;
  readonly errors: string[];
  constructor(profileId: string, errors: string[]) {
    super(
      "profile_validation_failed",
      `Receipt does not satisfy workflow profile "${profileId}": ${errors.join("; ")}`
    );
    this.name = "ProfileValidationError";
    this.profileId = profileId;
    this.errors = errors;
  }
}

export class InclusionProofTimeoutError extends SequesignSdkError {
  readonly position: number;
  readonly timeoutMs: number;
  constructor(position: number, timeoutMs: number) {
    super(
      "inclusion_proof_timeout",
      `Witness did not seal a batch containing log position ${position} within ${timeoutMs}ms.`
    );
    this.name = "InclusionProofTimeoutError";
    this.position = position;
    this.timeoutMs = timeoutMs;
  }
}
