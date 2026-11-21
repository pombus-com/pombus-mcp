// R3 proof (worker layer) — the Worker fetch handler authenticates on TWO credential paths and serves
// the MCP endpoint. These cases pin the WORKER's contract:
//   - Bearer path: a valid access token resolves to the ACTIVE org's child key; the core sees that child
//     key (never the opaque token); tools/list carries the catalogue PLUS the two org tools.
//   - x-api-key path: the header IS the credential (one org); the org tools are NOT exposed.
//   - both headers at once → 400 invalid_request.
//   - fail-closed: no credential / an unknown token → 401, the core is NEVER called.
//   - the org tools: list_organizations lists only authorized orgs + marks the active one;
//     select_organization switches to an authorized org, and for one OUTSIDE the set returns
//     authorization_required + an authorize_url (NEVER a child-key fallback).
//
// The full delegating OAuth flow (GET /authorize 302, /authorize/return, /token redeem, anti-injection)
// is proven end-to-end in oauth.test.ts. Here the token-set is seeded directly so the worker's own
// behaviour is tested without re-running the dance.

import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { authorize, type WorkerEnv } from "./worker.js";
import { OAuthStore, validateAccessToken, type LiveToken } from "./oauth.js";
import { FakeCore, authMePod } from "../testutil.js";

const CHILD_A = "pk_live_child_alpha_do_not_log";
const CHILD_B = "pk_live_child_bravo_do_not_log";
const ACCESS = "opaque_access_token_43_chars_seeded_for_test_x";
const BASE = "https://core.test/v0";
const MCP_ACCEPT = "application/json, text/event-stream";
const ORG_A = "org_alpha";
const ORG_B = "org_bravo";
const OWNER = "ownerhash_alice_000";

/** A fake core answering /auth/me as a master pod key so buildServer exposes the full catalogue. */
function masterCore(): FakeCore {
  return new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod());
}

/** A token-set with one authorized org (ORG_A, active), the state /token leaves behind. */
function oneOrg(): LiveToken {
  const now = Date.now();
  return {
    activeOrg: ORG_A,
    orgs: { [ORG_A]: { childKey: CHILD_A, perms: ["message_read"], label: "Alpha", expiresAt: now + 60_000 } },
    owner: OWNER,
    tokenExp: now + 60_000,
  };
}

/** A token-set with TWO authorized orgs, ORG_A active. */
function twoOrgs(): LiveToken {
  const now = Date.now();
  return {
    activeOrg: ORG_A,
    orgs: {
      [ORG_A]: { childKey: CHILD_A, perms: [], label: "Alpha", expiresAt: now + 60_000 },
      [ORG_B]: { childKey: CHILD_B, perms: [], label: "Bravo", expiresAt: now + 60_000 },
    },
    owner: OWNER,
    tokenExp: now + 60_000,
  };
}

async function seededStore(set: LiveToken = oneOrg()): Promise<OAuthStore> {
  const s = new OAuthStore();
  await s.putToken(ACCESS, set);
  return s;
}

function env(core: FakeCore, store: OAuthStore): WorkerEnv {
  return { POMBUS_API_BASE: BASE, __coreFetch: core.fetch, __store: store };
}

/** POST one JSON-RPC message to the MCP endpoint. headers chosen by the caller (Bearer / x-api-key). */
function mcpPost(e: WorkerEnv, body: unknown, headers: Record<string, string>) {
  return worker.fetch(
    new Request("https://mcp.test/", {
      method: "POST",
      headers: { accept: MCP_ACCEPT, "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    }),
    e,
  );
}

const INITIALIZE = {
  jsonrpc: "2.0", id: 1, method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "r3-test", version: "0" } },
};

function parseJsonRpc(text: string): { result?: unknown; error?: unknown } {
  const trimmed = text.trim();
  if (trimmed.startsWith("{")) return JSON.parse(trimmed);
  const line = trimmed.split("\n").find((l) => l.startsWith("data:"));
  assert.ok(line, `expected a JSON or SSE data frame, got: ${trimmed.slice(0, 120)}`);
  return JSON.parse(line.slice("data:".length).trim());
}

async function listToolNames(e: WorkerEnv, headers: Record<string, string>): Promise<Set<string>> {
  await mcpPost(e, INITIALIZE, headers);
  const res = await mcpPost(e, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, headers);
  assert.equal(res.status, 200, "tools/list must succeed");
  const tools = (parseJsonRpc(await res.text()).result as { tools: { name: string }[] }).tools;
  return new Set(tools.map((t) => t.name));
}

/** Call a tool and return its parsed <pombus-data> JSON. */
async function callTool(e: WorkerEnv, headers: Record<string, string>, name: string, args: Record<string, unknown>): Promise<unknown> {
  await mcpPost(e, INITIALIZE, headers);
  const res = await mcpPost(e, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name, arguments: args } }, headers);
  assert.equal(res.status, 200);
  const result = parseJsonRpc(await res.text()).result as { content: { text: string }[]; isError?: boolean };
  assert.ok(!result.isError, `tool ${name} returned an error: ${result.content[0]?.text}`);
  const text = result.content[0]!.text;
  const m = /<pombus-data>\n([\s\S]*?)\n<\/pombus-data>/.exec(text);
  assert.ok(m, "the tool result must carry a pombus-data block");
  return JSON.parse(m[1]!);
}

// ===================================================================================================
// Bearer path — a valid access token resolves to the active org's child key; org tools are exposed.
// ===================================================================================================

test("Bearer: a valid access token lists the catalogue PLUS the two org tools; the core sees the child key", async () => {
  const core = masterCore();
  const e = env(core, await seededStore());
  const names = await listToolNames(e, { authorization: `Bearer ${ACCESS}` });
  assert.ok(names.has("list_organizations"), "list_organizations is exposed on the Bearer path");
  assert.ok(names.has("select_organization"), "select_organization is exposed on the Bearer path");
  assert.ok(names.has("list_inboxes"), "the REST catalogue is still exposed");
  assert.equal(names.size, 57, `master Bearer must expose 55 REST + 2 org tools = 57, got ${names.size}`);
  // The ACTIVE org's child key — not the opaque access token — is the credential the core sees.
  const authMe = core.requests.find((r) => r.url.endsWith("/auth/me"));
  assert.equal(authMe?.headers["authorization"], `Bearer ${CHILD_A}`, "the core must see the active org's child key");
  for (const r of core.requests) {
    assert.notEqual(r.headers["authorization"], `Bearer ${ACCESS}`, "the access token must never reach the core");
  }
});

// ===================================================================================================
// x-api-key path — the header IS the credential; org tools are NOT exposed.
// ===================================================================================================

test("x-api-key: the header is the credential (one org); org tools are NOT exposed", async () => {
  const core = masterCore();
  const e = env(core, await seededStore());
  const DIRECT_KEY = "pk_live_direct_pod_key_do_not_log";
  const names = await listToolNames(e, { "x-api-key": DIRECT_KEY });
  assert.ok(!names.has("list_organizations"), "org tools must be HIDDEN on the x-api-key path");
  assert.ok(!names.has("select_organization"), "org tools must be HIDDEN on the x-api-key path");
  assert.equal(names.size, 55, `master x-api-key must expose exactly 55 tools, got ${names.size}`);
  // The pod-key in the header is the credential sent to the core directly (no token-set lookup).
  const authMe = core.requests.find((r) => r.url.endsWith("/auth/me"));
  assert.equal(authMe?.headers["authorization"], `Bearer ${DIRECT_KEY}`, "the x-api-key value is the core credential");
});

test("x-api-key: calling an org tool (hidden on this path) is an unknown-tool error", async () => {
  const core = masterCore();
  const e = env(core, await seededStore());
  await mcpPost(e, INITIALIZE, { "x-api-key": "pk_live_direct_do_not_log" });
  const res = await mcpPost(e, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "list_organizations", arguments: {} } }, { "x-api-key": "pk_live_direct_do_not_log" });
  const result = parseJsonRpc(await res.text()).result as { isError?: boolean; content: { text: string }[] };
  assert.ok(result.isError, "an org tool must be unknown on the x-api-key path");
});

// ===================================================================================================
// Both headers → 400 invalid_request.
// ===================================================================================================

test("both authorization:Bearer and x-api-key present → 400 invalid_request, core untouched", async () => {
  const core = masterCore();
  const e = env(core, await seededStore());
  const res = await mcpPost(e, INITIALIZE, { authorization: `Bearer ${ACCESS}`, "x-api-key": "pk_live_direct" });
  assert.equal(res.status, 400);
  assert.equal((JSON.parse(await res.text()) as { error: string }).error, "invalid_request");
  assert.equal(core.requests.length, 0, "an ambiguous credential never reaches the core");
});

// ===================================================================================================
// Fail-closed — no credential and an unknown token.
// ===================================================================================================

test("fail-closed: no credential → 401 with the resource_metadata challenge, core never called", async () => {
  const core = masterCore();
  const res = await mcpPost(env(core, await seededStore()), INITIALIZE, {});
  assert.equal(res.status, 401);
  assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata="https:\/\/[^"]+\/\.well-known\/oauth-protected-resource"$/);
  assert.equal(core.requests.length, 0, "fail-closed: the Server is never built");
});

test("fail-closed: an unknown Bearer token → 401, core never called", async () => {
  const core = masterCore();
  const res = await mcpPost(env(core, await seededStore()), INITIALIZE, { authorization: "Bearer not_a_real_token" });
  assert.equal(res.status, 401);
  assert.equal(core.requests.length, 0);
});

test("authorize() resolves a Bearer to the active org's child key; validateAccessToken is its primitive", async () => {
  const store = await seededStore();
  const good = new Request("https://mcp.test/", { headers: { authorization: `Bearer ${ACCESS}` } });
  const unknown = new Request("https://mcp.test/", { headers: { authorization: "Bearer nope" } });
  const bare = new Request("https://mcp.test/", {});
  assert.equal(await authorize(good, { __store: store }), CHILD_A, "a known token resolves to the active child key");
  assert.equal(await authorize(unknown, { __store: store }), null);
  assert.equal(await authorize(bare, { __store: store }), null);
  assert.equal(await validateAccessToken(`Bearer ${ACCESS}`, store), CHILD_A);
  assert.equal(await validateAccessToken(null, store), null);
});

// ===================================================================================================
// The org tools (E) — list only authorized orgs; switch within the set; authorize_url outside it.
// ===================================================================================================

test("list_organizations lists ONLY the authorized orgs and marks the active one", async () => {
  const core = masterCore();
  const e = env(core, await seededStore(twoOrgs()));
  const out = (await callTool(e, { authorization: `Bearer ${ACCESS}` }, "list_organizations", {})) as {
    organizations: { orgId: string; label: string; active: boolean }[];
  };
  const byId = new Map(out.organizations.map((o) => [o.orgId, o]));
  assert.deepEqual([...byId.keys()].sort(), [ORG_A, ORG_B].sort(), "only the two authorized orgs appear");
  assert.equal(byId.get(ORG_A)!.active, true, "ORG_A is active");
  assert.equal(byId.get(ORG_B)!.active, false, "ORG_B is authorized but not active");
});

test("select_organization: an authorized org switches the active pointer instantly", async () => {
  const core = masterCore();
  const store = await seededStore(twoOrgs());
  const e = env(core, store);
  const out = (await callTool(e, { authorization: `Bearer ${ACCESS}` }, "select_organization", { organization: ORG_B })) as { status: string; orgId: string };
  assert.equal(out.status, "active");
  assert.equal(out.orgId, ORG_B);
  assert.equal((await store.getActiveChild(ACCESS))!.childKey, CHILD_B, "the active child key is now ORG_B's");
});

test("select_organization: an org OUTSIDE the set returns authorization_required + an authorize_url, never a fallback key", async () => {
  const core = masterCore();
  const store = await seededStore(oneOrg()); // only ORG_A authorized
  const e = env(core, store);
  const out = (await callTool(e, { authorization: `Bearer ${ACCESS}` }, "select_organization", { organization: "org_unauthorized" })) as {
    status: string; authorize_url: string; link_token: string;
  };
  assert.equal(out.status, "authorization_required", "an unauthorized org must NOT switch");
  assert.ok(out.authorize_url.startsWith("/authorize?link_token="), "an authorize_url carrying the link_token is returned");
  assert.ok(out.link_token, "a single-use link_token is minted");
  // The active org is UNCHANGED — no fallback to another org's child key (SEC4).
  assert.equal((await store.getActiveChild(ACCESS))!.childKey, CHILD_A, "the active child key is unchanged");
  // The link_token is tied to THIS access token and is single-use.
  assert.equal(await store.takeLink(out.link_token), ACCESS, "the link_token resolves to this access token");
});

test("rate limit: the public OAuth routes are keyed per IP+route; a refused call never reaches the store", async () => {
  const store = new OAuthStore();
  const keys: string[] = [];
  const RATE_LIMIT = { limit: async ({ key }: { key: string }) => { keys.push(key); return { success: false }; } };
  const e: WorkerEnv = { ...env(new FakeCore(), store), RATE_LIMIT };
  for (const [method, path] of [["POST", "/register"], ["GET", "/authorize"], ["POST", "/token"]] as const) {
    const res = await worker.fetch(new Request(`https://mcp.pombus.com${path}`, {
      method, headers: { "cf-connecting-ip": "203.0.113.7", "content-type": "application/json" },
      ...(method === "POST" ? { body: "{}" } : {}),
    }), e);
    assert.equal(res.status, 429, path);
    assert.equal(res.headers.get("retry-after"), "60");
  }
  assert.deepEqual(keys, ["203.0.113.7:/register", "203.0.113.7:/authorize", "203.0.113.7:/token"]);
  // the MCP endpoint itself and discovery are not on this limiter
  await worker.fetch(new Request("https://mcp.pombus.com/.well-known/oauth-authorization-server"), e);
  assert.equal(keys.length, 3);
  // IPv6: keyed by the /56 (ipBucket), so a rotating address inside it is the same caller
  keys.length = 0;
  for (const ip of ["2001:db8:a:b00::1", "2001:db8:a:bff:dead:beef:1:2"]) {
    await worker.fetch(new Request("https://mcp.pombus.com/register", {
      method: "POST", headers: { "cf-connecting-ip": ip, "content-type": "application/json" }, body: "{}" }), e);
  }
  assert.deepEqual(keys, ["2001:db8:a:b00::/56:/register", "2001:db8:a:b00::/56:/register"]);
  // under the limit, the route answers as usual (here: /register validates the body)
  const ok = { limit: async () => ({ success: true }) };
  const res = await worker.fetch(new Request("https://mcp.pombus.com/register", {
    method: "POST", headers: { "content-type": "application/json" }, body: "{}" }), { ...e, RATE_LIMIT: ok });
  assert.notEqual(res.status, 429);
});
