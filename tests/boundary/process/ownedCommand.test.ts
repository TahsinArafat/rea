import { randomUUID } from "node:crypto";
import { expect, it } from "vitest";
import { runOwnedCommand } from "../../../src/process/OwnedCommand.js";
import { spawnOwnedProviderProcess } from "../../../src/process/ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "../../../src/process/ProcessOwnership.js";
import { waitForProviderProcessReady } from "../../fixtures/providerProcess.js";

const command = (script: string) => ({
  command: process.execPath,
  arguments: ["-e", script],
  runId: `rea-owned-command-test-${randomUUID()}`,
});

it("collects a real owned command and verifies its exit before returning diagnostics", async () => {
  const result = await runOwnedCommand(
    command('process.stdout.write("observed-output")'),
    { timeoutMs: 2_000, diagnosticBytes: 1024 },
  );
  expect(result).toMatchObject({
    exitCode: 0,
    signal: null,
    stdout: { text: "observed-output", bytes: 15 },
  });
});

it("cancels a real acquired process and independently releases it", async () => {
  const controller = new AbortController();
  let pid: number | undefined;
  const result = runOwnedCommand(
    command(
      'process.stdout.write("ready\\n"); setInterval(() => undefined, 1000)',
    ),
    { timeoutMs: 5_000, diagnosticBytes: 1024 },
    {
      signal: controller.signal,
      launcher: async (input) => {
        const process = await spawnOwnedProviderProcess(input);
        pid = process.process.pid;
        await waitForProviderProcessReady(process.process);
        setImmediate(() => controller.abort());
        return process;
      },
    },
  );
  await expect(result).rejects.toMatchObject({
    reason: "cancelled",
    cleanupFailure: null,
  });
  if (pid === undefined) throw new Error("Process was not acquired");
  const acquiredPid = pid;
  expect(() => process.kill(acquiredPid, 0)).toThrow();
});

it("returns a timeout for a running process after independent cleanup", async () => {
  await expect(
    runOwnedCommand(command("setInterval(() => undefined, 1000)"), {
      timeoutMs: 50,
      diagnosticBytes: 1024,
    }),
  ).rejects.toMatchObject({ reason: "timeout", cleanupFailure: null });
});

it("honors cancellation during cleanup after a successful command", async () => {
  const controller = new AbortController();
  await expect(
    runOwnedCommand(
      command("process.exit(0)"),
      { timeoutMs: 2_000, diagnosticBytes: 1024 },
      {
        signal: controller.signal,
        launcher: async (input) => {
          const launched = await spawnOwnedProviderProcess(input);
          return {
            ...launched,
            cleanup: async () => {
              const result = await cleanupOwnedProcessGroup(launched.ownership);
              controller.abort();
              return result;
            },
          };
        },
      },
    ),
  ).rejects.toMatchObject({ reason: "cancelled", cleanupFailure: null });
});

it("rejects oversized diagnostics even when the child exits immediately", async () => {
  await expect(
    runOwnedCommand(command('process.stdout.write("x".repeat(2048))'), {
      timeoutMs: 2_000,
      diagnosticBytes: 1024,
    }),
  ).rejects.toMatchObject({ reason: "output-limit", cleanupFailure: null });
});

it("preserves original command failure together with failed cleanup resource identities", async () => {
  const request = command("process.exit(2)");
  await expect(
    runOwnedCommand(
      request,
      { timeoutMs: 2_000, diagnosticBytes: 1024 },
      {
        launcher: async (input) => {
          const process = await spawnOwnedProviderProcess(input);
          return {
            ...process,
            cleanup: async () => ({
              cleaned: false as const,
              reason: "synthetic cleanup could not be confirmed",
            }),
          };
        },
      },
    ),
  ).rejects.toMatchObject({
    reason: "process",
    cleanupFailure: "synthetic cleanup could not be confirmed",
    resources: expect.arrayContaining([request.runId]),
    snapshot: { exitCode: 2 },
  });
});
