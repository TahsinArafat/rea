import type { McpServer } from "@modelcontextprotocol/server";
import type { WebNetworkCaptureService } from "../application/WebNetworkCaptureService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "../logger.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import { toCallToolResult } from "./toolResult.js";

/** Bind historical inspection to its named contract and caller-owned Evidence writer. */
export const registerWebNetworkCaptureTool = (
  server: McpServer,
  service: WebNetworkCaptureService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
): void => {
  const contract = toolContract("inspect_web_network_capture");
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    async (input, context) => {
      const result = await logToolExecution(logger, contract.name, () =>
        service.inspect(input, { signal: context.mcpReq.signal }),
      );
      if (!result.ok) return toCallToolResult(result, contract);
      const recorded = recordEvidence?.(result.value);
      return recorded !== undefined && !recorded.ok
        ? toCallToolResult(recorded, contract)
        : toCallToolResult(result, contract);
    },
  );
};
