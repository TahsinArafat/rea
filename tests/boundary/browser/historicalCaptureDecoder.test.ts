import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, onTestFinished } from "vitest";
import { HistoricalCaptureDecoder } from "../../../src/browser/history/HistoricalCaptureDecoder.js";
import { HAR_CAPTURE_PROVIDER_IDENTITY } from "../../../src/browser/history/CaptureRelease.js";
import { inspectWebNetworkCaptureInputSchema } from "../../../src/domain/webNetworkCapture.js";
import { historicalHar } from "../../fixtures/historicalHar.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";

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
