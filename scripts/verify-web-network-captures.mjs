#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { access, copyFile, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { PrivateRuntimeRoot } from "../dist/process/PrivateRuntimeRoot.js";
import { runOwnedCommand } from "../dist/process/OwnedCommand.js";
import { mcpTextValue } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

const executable = process.env.REA_MITMDUMP_COMMAND;
if (
  process.platform !== "linux" ||
  executable === undefined ||
  !isAbsolute(executable)
)
  throw new Error(
    "verify:web:network-captures requires Linux and absolute REA_MITMDUMP_COMMAND for caller-supplied mitmdump 12.2.3",
  );
await access(executable);
const entrypoint =
  process.argv[2] ?? fileURLToPath(new URL("./rea.mjs", import.meta.url));
const run = createVerifierRun();
const runtime = await PrivateRuntimeRoot.create({
  prefix: "rea-history-verifier-",
});
const environment = Object.fromEntries(
  Object.entries(process.env).filter(([, value]) => typeof value === "string"),
);
const client = new Client({
  name: "historical-web-capture-verifier",
  version: "1",
});
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env: environment,
  stderr: "pipe",
});
const failures = [];
let cases = 0;
try {
  await runOwnedCommand(
    {
      command: executable,
      arguments: [
        "--no-server",
        "-q",
        "--set",
        `confdir=${join(runtime.path, "config")}`,
        "--set",
        `rea_fixture_root=${runtime.path}`,
        "-s",
        fileURLToPath(
          new URL("./fixtures/generate-mitmproxy-capture.py", import.meta.url),
        ),
      ],
      cwd: runtime.path,
      runId: `rea-history-fixture-${randomUUID()}`,
      hostEnvironment: environment,
    },
    { timeoutMs: 30_000, diagnosticBytes: 1024 * 1024 },
  );
  await client.connect(transport);
  for (const format of ["har", "mitmproxy"]) {
    const path = join(
      runtime.path,
      format === "har" ? "producer.har" : "flows.mitm",
    );
    const raw = await readFile(path);
    const input = { capture_path: path, format, record_ordinals: [1, 0] };
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, input);
      assert.equal(value.total_records, 2);
      assert.deepEqual(
        value.records.map((record) => record.ordinal),
        [1, 0],
      );
      assert.equal(
        value.artifact.sha256,
        createHash("sha256").update(raw).digest("hex"),
      );
      assert.equal(value.runtime_attribution, "unknown");
      const first = value.records[1];
      if (format === "mitmproxy") {
        assert.equal(first.reported.id, "original-producer-id");
        assert.equal(value.records[0].reported.id, first.reported.id);
        assert.equal(first.location.offset, 0);
        assert.equal(
          value.records[0].location.offset + value.records[0].location.bytes,
          raw.length,
        );
        assert.equal(
          first.reported.request.path,
          "http://example.test/a?token=ordinary#fragment",
        );
        assertBinary(
          first,
          "/request/content",
          Buffer.from([0, 255, ...Buffer.from("body")]),
        );
        assertBinary(
          first,
          "/response/content",
          Buffer.from([0, 254, ...Buffer.from("answer")]),
        );
        assertBinary(
          first,
          "/websocket/messages/0/2",
          Buffer.from([0, 253, ...Buffer.from("message")]),
        );
        assert.equal(value.records[0].reported.request.content, null);
        assertBinary(value.records[0], "/response/content", Buffer.alloc(0));
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/big_integer" &&
              number.literal === "9007199254740993",
          ),
        );
        assert.ok(
          first.numeric_literals.some(
            (number) =>
              number.pointer === "/metadata/nonfinite" &&
              number.literal === "inf",
          ),
        );
        assert.equal(
          first.reported.metadata.response.headers[0][1],
          "ordinary-extension-credential-name",
        );
      } else {
        assert.equal(value.container.reported.log.creator.name, "mitmproxy");
        assert.equal(value.container.reported.log.creator.version, "12.2.3");
        assert.equal(value.records[0].reported.request.postData.text, null);
        assertBinary(
          first,
          "/response/content/text",
          Buffer.from([0, 255, 1, 254]),
        );
      }
      const text = JSON.stringify(value);
      for (const secret of [
        "native-transport-secret",
        "cookie-secret",
        "redirect-password",
        "user:password",
      ])
        assert.ok(
          !text.includes(secret),
          `Credential leaked through ${mode}/${format}`,
        );
      cases++;
    }
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "string-urls.mitm"),
      format: "mitmproxy",
    });
    const first = value.records[0];
    for (const state of [first.reported, first.reported.backup]) {
      assert.equal(state.request.path, "https://example.test/string-path");
      assert.equal(state.request.authority, "example.test");
      assert.deepEqual(
        state.request.headers.map((field) => field[1]),
        ["https://example.test/from", "//example.test"],
      );
      assert.equal(state.response.headers[0][1], "https://example.test/to");
    }
    assert.ok(!JSON.stringify(value).includes("password"));
    assert.ok(
      first.redactions.some(
        (redaction) =>
          redaction.pointer === "/backup/request/authority" &&
          redaction.reason === "transport-credential",
      ),
    );
    cases++;
  }
  for (const sensitive_values of [
    ["REDACTED", "["],
    ["secret", "REDACTED"],
  ]) {
    for (const format of ["har", "mitmproxy"]) {
      for (const mode of ["cli", "mcp"]) {
        const value = await inspect(mode, {
          capture_path: join(
            runtime.path,
            format === "har" ? "producer.har" : "string-urls.mitm",
          ),
          format,
          record_ordinals: [0],
          sensitive_values,
        });
        const first = value.records[0];
        const markers =
          format === "har"
            ? first.reported._markers
            : first.reported.metadata._markers;
        assert.equal(markers.sensitive, null);
        assert.equal(markers.ordinary, "unmarked");
        assert.equal(
          sensitive_values.includes("[") ? markers.bracket : markers.overlap,
          null,
        );
        if (format === "mitmproxy")
          assert.equal(first.reported.backup.metadata._markers.sensitive, null);
        cases++;
      }
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `malformed-${format}`);
    await writeFile(path, format === "har" ? "{invalid-json" : "999999999999:");
    for (const mode of ["cli", "mcp"]) {
      await inspect(mode, { capture_path: path, format }, "invalid_input");
      cases++;
    }
  }
  for (const format of ["har", "mitmproxy"]) {
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, {
        capture_path: join(
          runtime.path,
          format === "har" ? "producer.har" : "string-urls.mitm",
        ),
        format,
        sensitive_values: ["private-property"],
      });
      const record = value.records[0];
      const properties =
        format === "har"
          ? record.reported._private_properties
          : record.reported.metadata._private_properties;
      assert.deepEqual(properties, { kept: 7 });
      assert.ok(!JSON.stringify(value).includes("private-property"));
      assert.ok(
        record.redactions.some(
          (item) =>
            item.scope === "property-name" &&
            item.pointer ===
              (format === "har"
                ? "/_private_properties"
                : "/metadata/_private_properties"),
        ),
      );
      if (format === "mitmproxy")
        assert.deepEqual(record.reported.backup.metadata._private_properties, {
          kept: 7,
        });
      cases++;
    }
  }
  const privatePath = join(runtime.path, "REDACTED.har");
  await copyFile(join(runtime.path, "producer.har"), privatePath);
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: privatePath,
      format: "har",
      sensitive_values: ["REDACTED", "["],
    });
    assert.equal(value.artifact.path, "");
    assert.ok(!JSON.stringify(value).includes("REDACTED"));
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "private-property-absent.har"),
        format: "har",
        sensitive_values: ["private-property", "REDACTED"],
      },
      "invalid_input",
    );
    cases++;
    await inspect(
      mode,
      {
        capture_path: join(runtime.path, "invalid-private-key.mitm"),
        format: "mitmproxy",
        sensitive_values: ["private-property"],
      },
      "unsupported_provider",
    );
    cases++;
  }
  for (const mode of ["cli", "mcp"]) {
    const value = await inspect(mode, {
      capture_path: join(runtime.path, "flows.mitm"),
      format: "mitmproxy",
      record_ordinals: [0],
      sensitive_values: ["body"],
    });
    assert.equal(
      value.records[0].binary_fields.find(
        (field) => field.pointer === "/request/content",
      ).state,
      "redacted",
    );
    cases++;
  }
  for (const format of ["har", "mitmproxy"]) {
    const path = join(runtime.path, `empty-${format}`);
    await writeFile(
      path,
      format === "har"
        ? JSON.stringify({
            log: {
              version: "1.2",
              creator: { name: "source-owned-empty-fixture", version: "1" },
              entries: [],
            },
          })
        : "",
    );
    for (const mode of ["cli", "mcp"]) {
      const value = await inspect(mode, { capture_path: path, format });
      assert.equal(value.total_records, 0);
      cases++;
    }
  }
} catch (cause) {
  failures.push(cause);
} finally {
  for (const cleanup of [
    () => client.close(),
    () => transport.close(),
    () => runtime.close(),
  ]) {
    try {
      await cleanup();
    } catch (cause) {
      failures.push(cause);
    }
  }
}
const verifier = await completeVerifierRun(run);
try {
  assert.equal(verifier.process_lineage.status, "verified");
  assert.deepEqual(verifier.process_lineage.descendants, []);
} catch (cause) {
  failures.push(cause);
}
if (failures.length > 0) {
  console.error(
    JSON.stringify(
      { status: "failed", public_cases: cases, verifier },
      null,
      2,
    ),
  );
  throw new AggregateError(
    failures,
    "Historical capture verification failed; analysis and cleanup failures are retained.",
  );
}
console.log(
  JSON.stringify(
    {
      status: "passed",
      public_cases: cases,
      upstream: "mitmproxy 12.2.3 FlowWriter + SaveHar",
      offline: true,
      verifier,
    },
    null,
    2,
  ),
);

async function inspect(mode, input, errorCategory) {
  if (mode === "mcp") {
    const result = await client.callTool({
      name: "inspect_web_network_capture",
      arguments: input,
    });
    const value = JSON.parse(mcpTextValue(result));
    if (errorCategory !== undefined) {
      assert.equal(result.isError, true);
      assert.equal(value.error.category, errorCategory);
      for (const literal of input.sensitive_values ?? [])
        assert.ok(!JSON.stringify(value.error).includes(literal));
      return null;
    }
    assert.notEqual(result.isError, true, mcpTextValue(result));
    return value.result;
  }
  const args = [
    entrypoint,
    "inspect-web-network-capture",
    input.capture_path,
    input.format,
    "--json",
    ...(input.record_ordinals ?? []).flatMap((ordinal) => [
      "--record",
      String(ordinal),
    ]),
    ...(input.sensitive_values ?? []).flatMap((value) => [
      "--sensitive-value",
      value,
    ]),
  ];
  try {
    const result = await promisify(execFile)(process.execPath, args, {
      env: environment,
      timeout: 40_000,
      maxBuffer: 96 * 1024 * 1024,
    });
    assert.equal(
      errorCategory,
      undefined,
      "Expected malformed capture to fail",
    );
    return JSON.parse(result.stdout).normalized_result;
  } catch (cause) {
    if (errorCategory === undefined) throw cause;
    assert.equal(typeof cause.code, "number");
    const value = JSON.parse(cause.stdout);
    assert.equal(value.category, errorCategory);
    for (const literal of input.sensitive_values ?? [])
      assert.ok(!JSON.stringify(value).includes(literal));
    return null;
  }
}

function assertBinary(record, pointer, bytes) {
  const field = record.binary_fields.find((item) => item.pointer === pointer);
  assert.ok(field, `Missing native byte field ${pointer}`);
  assert.equal(field.state, "retained");
  assert.equal(field.content_base64, bytes.toString("base64"));
  assert.equal(field.bytes, bytes.length);
  assert.equal(field.sha256, createHash("sha256").update(bytes).digest("hex"));
}
