import type { Session } from "./types.js";
import type {
  RecordActionInput,
  ToolWrapSpec,
  WrappedTool
} from "./types.js";

export function createWrappedTool<TArgs extends readonly unknown[], TResult>(
  session: Session,
  spec: ToolWrapSpec<TArgs, TResult>
): WrappedTool<TArgs, TResult> {
  const onError = spec.onError ?? "throw";
  return async (...args: TArgs): Promise<TResult> => {
    let result: TResult;
    try {
      result = await Promise.resolve(spec.handler(...args));
    } catch (err) {
      if (onError === "record_error_action") {
        const evidence = (spec.buildErrorEvidence ?? defaultBuildErrorEvidence)(args, err);
        const metadata = spec.buildMetadata
          ? safeBuildMetadataForError(spec, args, err)
          : undefined;
        // v0.4 dropped evidenceSource from RecordActionInput; the
        // "tool_captured" semantic is carried by verifiabilityClass.
        // The envelope's evidence_custody is derived from session
        // context and is not overridable per action.
        const errorRecordInput: RecordActionInput = {
          actionType: spec.actionType,
          evidence,
          verifiabilityClass: spec.verifiabilityClass ?? "tool_captured",
          schemaId: spec.schemaId,
          schemaHash: spec.schemaHash,
          metadata: mergeErrorMetadata(metadata, err)
        };
        await session.recordAction(errorRecordInput);
      }
      throw err;
    }
    const evidence = spec.buildEvidence(args, result);
    const metadata = spec.buildMetadata ? spec.buildMetadata(args, result) : undefined;
    const recordInput: RecordActionInput = {
      actionType: spec.actionType,
      evidence,
      verifiabilityClass: spec.verifiabilityClass ?? "tool_captured",
      schemaId: spec.schemaId,
      schemaHash: spec.schemaHash,
      metadata
    };
    await session.recordAction(recordInput);
    return result;
  };
}

function defaultBuildErrorEvidence(args: unknown, error: unknown): unknown {
  return {
    tool_error: {
      name: errorName(error),
      message: errorMessage(error)
    },
    tool_args_summary: summarizeArgs(args)
  };
}

function errorName(error: unknown): string {
  if (error instanceof Error) return error.name;
  return "Error";
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

function summarizeArgs(args: unknown): unknown {
  if (Array.isArray(args)) {
    return {
      count: args.length
    };
  }
  return { count: 0 };
}

function safeBuildMetadataForError<TArgs extends readonly unknown[], TResult>(
  spec: ToolWrapSpec<TArgs, TResult>,
  _args: TArgs,
  _err: unknown
): Record<string, unknown> | undefined {
  void spec;
  return undefined;
}

function mergeErrorMetadata(
  base: Record<string, unknown> | undefined,
  error: unknown
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...(base ?? {}) };
  merged.tool_invocation = "failed";
  merged.error_name = errorName(error);
  return merged;
}
