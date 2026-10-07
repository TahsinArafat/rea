import { access, mkdtemp, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
import { HistoricalCaptureDecoder } from "../../../src/browser/history/HistoricalCaptureDecoder.js";
import { HAR_CAPTURE_PROVIDER_IDENTITY } from "../../../src/browser/history/CaptureRelease.js";
import {
  inspectWebNetworkCaptureInputSchema,
  WEB_NETWORK_CAPTURE_LIMITS,
} from "../../../src/domain/webNetworkCapture.js";
import { historicalHar } from "../../fixtures/historicalHar.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";

it("classifies an oversized selected capture before creating an owned decoder", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-limit-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, "");
  await truncate(path, WEB_NETWORK_CAPTURE_LIMITS.inputBytes + 1);
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        command: async () => {
          throw new Error("Oversized input must not launch decoding");
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Oversized input must fail");
  expect(result.error._tag).toBe("AnalysisInputError");
  expect(projectAnalysisError(result.error)).toMatchObject({
    category: "invalid_input",
    details: {
      issues: [
        {
          path: ["capture_path"],
          reason: "out_of_range",
          expected: {
            maximum_capture_bytes: WEB_NETWORK_CAPTURE_LIMITS.inputBytes,
          },
        },
      ],
    },
  });
});

it("does not misclassify decoder filesystem failures as missing selected input", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-command-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        command: async () => {
          throw Object.assign(
            new Error("Configured decoder command file missing"),
            { code: "ENOENT" },
          );
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Failed decoder command must fail");
  expect(result.error._tag).toBe("ProviderAdapterError");
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: {
      diagnostics: {
        phase: "decoder",
        reason: "Configured decoder command file missing",
      },
    },
  });
});

it.each(["missing-capture", "missing-reply", "failed-command"])(
  "redacts declared paths and diagnostics while preserving the %s failure",
  async (mode) => {
    const root = await mkdtemp(join(tmpdir(), "rea-historical-sensitive-"));
    onTestFinished(() => rm(root, { recursive: true, force: true }));
    const path = join(root, "explicit-private-value.har");
    if (mode !== "missing-capture")
      await writeFile(path, JSON.stringify(historicalHar()));
    const decoder = new HistoricalCaptureDecoder(
      [
        {
          format: "har",
          identity: HAR_CAPTURE_PROVIDER_IDENTITY,
          command: async () => ({
            command: process.execPath,
            arguments: [
              "-e",
              mode === "failed-command"
                ? 'process.stderr.write("explicit-private-value ordinary diagnostic"); process.exit(2)'
                : "process.exit(0)",
            ],
          }),
        },
      ],
      process.env,
    );
    const result = await decoder.inspect(
      inspectWebNetworkCaptureInputSchema.parse({
        capture_path: path,
        format: "har",
        sensitive_values: ["explicit-private-value", "REDACTED"],
      }),
    );
    if (result.ok) throw new Error("Failure required");
    const projected = projectAnalysisError(result.error);
    const serialized = JSON.stringify(projected);
    expect(serialized).not.toContain("explicit-private-value");
    expect(serialized).not.toContain("REDACTED");
    expect(result.error._tag).toBe(
      mode === "missing-capture"
        ? "AnalysisInputError"
        : mode === "missing-reply"
          ? "AnalysisOutputError"
          : "ProviderAdapterError",
    );
    if (mode === "missing-capture") expect(serialized).toContain("ENOENT");
    if (mode === "failed-command")
      expect(serialized).toContain('"exit_code":2');
  },
);

it("reports an absent owned reply as output failure and removes its private snapshot root", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-decoder-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  let privatePath: string | undefined;
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        command: async (_, runtimePath) => {
          privatePath = runtimePath;
          return {
            command: process.execPath,
            arguments: ["-e", "process.exit(0)"],
          };
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
    }),
  );
  if (result.ok) throw new Error("Owned reply is required");
  expect(result.error._tag).toBe("AnalysisOutputError");
  expect(result.error.message).toContain("ENOENT");
  if (privatePath === undefined)
    throw new Error("Private root was not acquired");
  await expect(access(privatePath)).rejects.toMatchObject({ code: "ENOENT" });
});

it("cancels after snapshot acquisition before launch and removes private input declarations", async () => {
  const root = await mkdtemp(join(tmpdir(), "rea-historical-cancel-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "input.har");
  await writeFile(path, JSON.stringify(historicalHar()));
  let privatePath: string | undefined;
  const controller = new AbortController();
  const decoder = new HistoricalCaptureDecoder(
    [
      {
        format: "har",
        identity: HAR_CAPTURE_PROVIDER_IDENTITY,
        command: async (_, runtimePath) => {
          privatePath = runtimePath;
          controller.abort();
          return {
            command: process.execPath,
            arguments: ["-e", "process.exit(3)"],
          };
        },
      },
    ],
    process.env,
  );
  const result = await decoder.inspect(
    inspectWebNetworkCaptureInputSchema.parse({
      capture_path: path,
      format: "har",
      sensitive_values: ["explicit-private-declaration"],
    }),
    { signal: controller.signal },
  );
  if (result.ok) throw new Error("Cancelled acquisition must fail");
  expect(result.error._tag).toBe("AnalysisCancelledError");
  if (privatePath === undefined)
    throw new Error("Private root was not acquired");
  await expect(access(privatePath)).rejects.toMatchObject({ code: "ENOENT" });
});
