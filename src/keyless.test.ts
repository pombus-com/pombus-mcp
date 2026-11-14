// The stdio server WITHOUT a key (registries such as Glama boot it with no credential to introspect):
// it must come up, list the full catalog, refuse every call with the localized "set POMBUS_API_KEY"
// line, and touch the network NOT AT ALL. With a key, the key's scope still decides what is listed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CoreClient } from "./client.js";
import { humanMessage } from "./i18n.js";
import { buildServer } from "./server.js";
import { TOOL_TABLE } from "./tools.js";
import { FakeCore, authMeScoped } from "./testutil.js";

async function connect(server: Awaited<ReturnType<typeof buildServer>>): Promise<Client> {
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0" });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  return client;
}

test("no key: tools/list is the full catalog, tools/call is a localized isError, and NO fetch happens", async () => {
  const realFetch = globalThis.fetch;
  const prevLocale = process.env["POMBUS_LOCALE"];
  const fetched: string[] = [];
  globalThis.fetch = (async (url: unknown) => {
    fetched.push(String(url));
    throw new Error("network forbidden in keyless mode");
  }) as typeof fetch;
  try {
    const server = await buildServer(null);
    const client = await connect(server);

    const listed = await client.listTools();
    assert.deepEqual(
      listed.tools.map((t) => t.name).sort(),
      TOOL_TABLE.map((t) => t.name).sort(),
      "every REST tool is listed, as for an org master key",
    );
    assert.ok(listed.tools.every((t) => (t.description ?? "").length > 0), "normal descriptions");

    process.env["POMBUS_LOCALE"] = "pt-BR";
    const res = await client.callTool({ name: "list_inboxes", arguments: {} });
    assert.equal(res.isError, true);
    const content = res.content as Array<{ type: string; text: string }>;
    assert.equal(content[0]!.text, humanMessage("no_api_key", "pt-BR"));

    // Even a name outside the catalog gets the same answer: nothing is dispatched without a key.
    const unknown = await client.callTool({ name: "no_such_tool", arguments: {} });
    assert.equal(unknown.isError, true);

    assert.deepEqual(fetched, [], "keyless mode never calls the network");
    await client.close();
    await server.close();
  } finally {
    globalThis.fetch = realFetch;
    if (prevLocale === undefined) delete process.env["POMBUS_LOCALE"];
    else process.env["POMBUS_LOCALE"] = prevLocale;
  }
});

test("with a key: the key's scope still gates the catalog (keyless does not widen a scoped key)", async () => {
  const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeScoped({ message_read: true }));
  const core = new CoreClient({ apiKey: "pk_live_k", baseUrl: "https://core.test/v0", fetchImpl: fake.fetch });
  const server = await buildServer(core);
  const client = await connect(server);
  const names = (await client.listTools()).tools.map((t) => t.name);
  assert.ok(names.length > 0 && names.length < TOOL_TABLE.length, "scoped key sees a strict subset");
  assert.ok(!names.includes("send_message") && !names.includes("delete_inbox"));
  assert.equal(fake.requests.length, 1, "exactly the /auth/me boot call");
  await client.close();
  await server.close();
});

test("real stdio boot without POMBUS_API_KEY (what Glama runs): initialize + tools/list answer", async () => {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && k !== "POMBUS_API_KEY") env[k] = v;
  env["POMBUS_API_BASE"] = "http://127.0.0.1:9/v0"; // a stray call would fail, never reach a real core
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./bin.js", import.meta.url)), "mcp"],
    env,
    stderr: "pipe",
  });
  const client = new Client({ name: "glama-like", version: "0" });
  await client.connect(transport);
  try {
    assert.equal(client.getServerVersion()?.name, "pombus");
    const listed = await client.listTools();
    assert.equal(listed.tools.length, TOOL_TABLE.length);
    const res = await client.callTool({ name: "list_inboxes", arguments: {} });
    assert.equal(res.isError, true);
  } finally {
    await client.close();
  }
});
