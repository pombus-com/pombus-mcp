import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CoreClient, CoreError } from "./client.js";
import { ScopeBinding } from "./scope.js";
import { specByName, callTool, type ToolContext } from "./tools.js";
import { buildServer } from "./server.js";
import { FakeCore, authMeInbox, authMePod } from "./testutil.js";

const KEY = "pk_live_secret_do_not_log_abcdef";

async function ctxFor(fake: FakeCore): Promise<ToolContext> {
  const client = new CoreClient({ apiKey: KEY, baseUrl: "https://core.test/v0", fetchImpl: fake.fetch });
  const scope = await ScopeBinding.resolve(client);
  return { client, scope };
}

test("the API key rides ONLY in the Authorization header — never in a URL", async () => {
  const fake = new FakeCore()
    .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_x"))
    .on("GET", () => true, { json: { ok: true } });
  const ctx = await ctxFor(fake);
  await callTool(specByName("list_messages", ctx.scope)!, {}, ctx);
  await callTool(specByName("get_message", ctx.scope)!, { message_id: "m1" }, ctx);
  assert.ok(fake.requests.length >= 2);
  for (const r of fake.requests) {
    assert.ok(!r.url.includes(KEY), `key leaked into URL: ${r.url}`);
    assert.equal(r.headers["authorization"], `Bearer ${KEY}`);
    // No other header carries it.
    for (const [k, v] of Object.entries(r.headers)) {
      if (k !== "authorization") assert.ok(!v.includes(KEY), `key leaked into header ${k}`);
    }
  }
});

test("a transport error message never contains the key or the URL", async () => {
  const fetchImpl = async () => {
    throw new TypeError("fetch failed: connect ECONNREFUSED https://core.test/v0?api_key=" + KEY);
  };
  const client = new CoreClient({ apiKey: KEY, baseUrl: "https://core.test/v0", fetchImpl });
  await assert.rejects(
    () => client.get("/inboxes"),
    (e: unknown) => {
      assert.ok(e instanceof CoreError);
      assert.ok(!e.message.includes(KEY), "key must not appear in the error");
      assert.ok(!e.message.includes("core.test"), "URL must not appear in the error");
      assert.equal((e as CoreError).code, "network");
      return true;
    },
  );
});

test("auth failure does NOT reveal whether an inbox exists (403 and 404 collapse to not_found)", async () => {
  const forbidden = new FakeCore()
    .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod())
    .on("GET", (u) => /\/inboxes\/inb_q$/.test(u.pathname), { status: 403, json: { code: "forbidden" } });
  const missing = new FakeCore()
    .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod())
    .on("GET", (u) => /\/inboxes\/inb_q$/.test(u.pathname), { status: 404, json: { code: "not_found" } });

  const errOf = async (fake: FakeCore): Promise<string> => {
    const ctx = await ctxFor(fake);
    try {
      await callTool(specByName("get_thread", ctx.scope)!, { inbox_id: "inb_q", thread_id: "t1" }, ctx);
      return "no-error";
    } catch (e) {
      return (e as { code?: string }).code ?? "unknown";
    }
  };
  // A key denied the inbox (403) and a key facing a missing inbox (404) get the IDENTICAL answer, so
  // the model can never use the error to enumerate which inboxes exist.
  assert.equal(await errOf(forbidden), "not_found");
  assert.equal(await errOf(missing), "not_found");
});

test("end-to-end over MCP: list tools and call one through the real server adapter", async () => {
  const fake = new FakeCore()
    .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_e2e"))
    .on("GET", (u) => /\/inboxes\/inb_e2e\/threads$/.test(u.pathname), {
      json: { threads: [{ tid: "thr_1" }] },
    });
  const core = new CoreClient({ apiKey: KEY, baseUrl: "https://core.test/v0", fetchImpl: fake.fetch });
  const server = await buildServer(core);

  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0" });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);

  const listed = await client.listTools();
  assert.ok(listed.tools.some((t) => t.name === "list_threads"));
  // Single-inbox key: no tool exposes inbox_id.
  for (const t of listed.tools) {
    const props = (t.inputSchema?.properties ?? {}) as Record<string, unknown>;
    assert.ok(!("inbox_id" in props));
  }

  const res = await client.callTool({ name: "list_threads", arguments: {} });
  assert.equal(res.isError ?? false, false);
  const content = res.content as Array<{ type: string; text: string }>;
  const payload = JSON.parse(content[0]!.text) as { threads: Array<{ tid: string }> };
  assert.equal(payload.threads[0]!.tid, "thr_1");

  await client.close();
  await server.close();
});

test("end-to-end: a core error surfaces as an isError tool result with a stable code (no leak)", async () => {
  const fake = new FakeCore()
    .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_e2e"))
    .on("GET", () => true, { status: 404, json: { code: "not_found" } });
  const core = new CoreClient({ apiKey: KEY, baseUrl: "https://core.test/v0", fetchImpl: fake.fetch });
  const server = await buildServer(core);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0" });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);

  const res = await client.callTool({ name: "get_message", arguments: { message_id: "m_x" } });
  assert.equal(res.isError, true);
  const content = res.content as Array<{ type: string; text: string }>;
  assert.equal(content[0]!.text, "error: not_found");
  assert.ok(!content[0]!.text.includes(KEY));

  await client.close();
  await server.close();
});
