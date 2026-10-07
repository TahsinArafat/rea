import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "./ProviderProcess.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "./ProviderProcess.js";
import { cleanupOwnedProcessGroup } from "./ProcessOwnership.js";
import { waitForAbortableDelay } from "./ProviderDeadline.js";

/** A short-lived command failed its lifecycle or complete-output contract. */
export class OwnedCommandFailure extends Error {
  constructor(
    readonly reason: "cancelled" | "timeout" | "output-limit" | "process",
    message: string,
    readonly snapshot: ProviderProcessSnapshot | null = null,
    readonly cleanupFailure: string | null = null,
    options?: ErrorOptions,
    readonly resources: readonly string[] = [],
  ) {
    super(message, options);
  }
}

/** Execute a single owned process with independent cleanup and bounded diagnostic retention. */
export const runOwnedCommand = async (
  spawn: OwnedProviderProcessSpawnOptions,
  limits: { readonly timeoutMs: number; readonly diagnosticBytes: number },
  options: {
    readonly signal?: AbortSignal;
    readonly launcher?: (
      input: OwnedProviderProcessSpawnOptions,
    ) => Promise<SpawnedOwnedProviderProcess>;
  } = {},
): Promise<ProviderProcessSnapshot> => {
  if (options.signal?.aborted)
    throw new OwnedCommandFailure(
      "cancelled",
      "Command cancelled before launch.",
    );
  const launched = await (options.launcher ?? spawnOwnedProviderProcess)(spawn);
  let exceeded = false;
  let processFailure: string | undefined;
  const supervisor = new ProviderProcessSupervisor(
    {
      ...launched,
      ownsProcessLifetime: true,
      cleanup:
        launched.cleanup ??
        (() => cleanupOwnedProcessGroup(launched.ownership)),
    },
    {
      onDiagnostic: (event) => {
        if (
          event.type === "output" &&
          event.totalBytes > limits.diagnosticBytes
        )
          exceeded = true;
        if (event.type === "error") processFailure = event.message;
      },
    },
  );
  const deadline = Date.now() + limits.timeoutMs;
  let failure: OwnedCommandFailure | undefined;
  try {
    while (!(await supervisor.waitForOutputClose(10))) {
      if (options.signal?.aborted)
        throw new OwnedCommandFailure("cancelled", "Command cancelled.");
      if (Date.now() >= deadline)
        throw new OwnedCommandFailure("timeout", "Command deadline elapsed.");
      if (exceeded)
        throw new OwnedCommandFailure(
          "output-limit",
          "Command diagnostic output exceeded its complete-output budget.",
        );
      if (processFailure !== undefined)
        throw new OwnedCommandFailure("process", processFailure);
      await waitForAbortableDelay(25, options.signal);
    }
    const snapshot = supervisor.snapshot();
    if (Date.now() >= deadline)
      throw new OwnedCommandFailure(
        "timeout",
        "Command deadline elapsed.",
        snapshot,
      );
    if (exceeded)
      throw new OwnedCommandFailure(
        "output-limit",
        "Command diagnostic output exceeded its complete-output budget.",
        snapshot,
      );
    if (options.signal?.aborted)
      throw new OwnedCommandFailure(
        "cancelled",
        "Command cancelled.",
        snapshot,
      );
    if (
      processFailure !== undefined ||
      snapshot.exitCode !== 0 ||
      snapshot.signal !== null
    )
      throw new OwnedCommandFailure(
        "process",
        processFailure ??
          "Command failed; inspect its exit status and diagnostics.",
        snapshot,
      );
  } catch (cause: unknown) {
    failure =
      cause instanceof OwnedCommandFailure
        ? cause
        : new OwnedCommandFailure(
            "process",
            "Command collection failed.",
            null,
            null,
            { cause },
          );
  }
  const stopped = await supervisor.stop();
  const snapshot = supervisor.snapshot();
  supervisor.dispose();
  if (stopped.status === "incomplete")
    throw new OwnedCommandFailure(
      failure?.reason ?? "process",
      failure?.message ?? "Command cleanup failed.",
      snapshot,
      stopped.reason,
      failure === undefined ? undefined : { cause: failure },
      [
        spawn.runId,
        ...(spawn.cwd === undefined ? [] : [spawn.cwd]),
        `pid:${launched.ownership.leaderPid}`,
        `process-group:${launched.ownership.processGroupId}`,
      ],
    );
  if (failure !== undefined) throw failure;
  return snapshot;
};
