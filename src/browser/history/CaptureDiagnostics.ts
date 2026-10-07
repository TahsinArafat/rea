import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisCapabilityUnavailableError,
} from "../../domain/analysisErrorCore.js";
import { redactExplicitText } from "../../domain/explicitSensitiveValues.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../../domain/providerCleanupError.js";

/** Keep a real ancestor coordinate when a producer property identity is explicitly excluded. */
export const redactCapturePointer = (
  pointer: string,
  values: readonly string[],
): string => {
  let parent = "";
  for (const segment of pointer.split("/").slice(1)) {
    const decoded = segment.replaceAll("~1", "/").replaceAll("~0", "~");
    const child = `${parent}/${segment}`;
    if (
      values.some(
        (literal) => decoded.includes(literal) || child.includes(literal),
      )
    )
      return parent;
    parent = child;
  }
  return parent;
};

/** Exclude explicit literals at the failure boundary while preserving typed diagnostic meaning. */
export const redactCaptureFailure = (
  error: AnalysisError,
  values: readonly string[],
): AnalysisError => {
  if (values.length === 0) return error;
  const text = (value: string): string => redactExplicitText(value, values);
  const diagnostics = (
    value: Readonly<Record<string, JsonValue>>,
  ): Record<string, JsonValue> =>
    Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !values.some((literal) => key.includes(literal)))
        .map(([key, item]) => [key, visit(item)]),
    );
  const visit = (value: JsonValue): JsonValue => {
    if (typeof value === "string") return text(value);
    if (Array.isArray(value)) return value.map(visit);
    if (typeof value === "object" && value !== null) return diagnostics(value);
    return value;
  };
  if (error instanceof AnalysisAccessDeniedError)
    return new AnalysisAccessDeniedError(
      error.operation,
      text(error.path),
      error.systemCode,
      { cause: error },
    );
  if (error instanceof AnalysisInputError)
    return new AnalysisInputError(
      error.operation,
      { cause: error },
      error.issues.map((issue) => ({
        ...issue,
        path: issue.path.map((part) =>
          typeof part === "string" && part.startsWith("/")
            ? redactCapturePointer(part, values)
            : part,
        ),
        ...(issue.message === undefined
          ? {}
          : { message: text(issue.message) }),
        ...(issue.expected === undefined
          ? {}
          : { expected: visit(issue.expected) }),
      })),
    );
  if (error instanceof AnalysisOutputError)
    return new AnalysisOutputError(error.operation, text(error.reason), {
      cause: error,
    });
  if (error instanceof AnalysisCapabilityUnavailableError)
    return new AnalysisCapabilityUnavailableError(
      error.providerId,
      error.operation,
      text(error.reason),
      {
        cause: error,
        ...(error.userMessage === undefined
          ? {}
          : { userMessage: text(error.userMessage) }),
      },
    );
  if (error instanceof ProviderCleanupError)
    return new ProviderCleanupError(
      error.providerId,
      error.cleanupResources.map(text),
      diagnostics(error.diagnostics ?? {}),
      { operation: error.operation, cause: error },
    );
  if (error instanceof ProviderAdapterError)
    return new ProviderAdapterError(error.providerId, error.operation, {
      cause: error,
      ...(error.diagnostics === undefined
        ? {}
        : { diagnostics: diagnostics(error.diagnostics) }),
    });
  return error;
};
