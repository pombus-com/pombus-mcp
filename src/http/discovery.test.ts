// R2d proof (end-to-end) — the three surfaces that let a client (Claude.ai) connect WITHOUT a
// pre-known client_id, exercised the way a Worker runtime does: real `Request` in, real `Response`
// out, the core faked via the FetchLike seam. Covers:
//
//   AC1  GET /.well-known/oauth-protected-resource → 200 JSON { resource, authorization_servers }
//        derived from the request origin.
//   AC2  GET /.well-known/oauth-authorization-server → 200 JSON with the origin-derived endpoints,
//        S256, response_type code, token_endpoint_auth_methods ["none"].
//   AC3  The MCP 401 now carries www-authenticate with resource_metadata="<origin>/.well-known/...".
//   AC4  POST /register (https redirect) → 201 with a client_id that then WORKS at /authorize; a
//        redirect_uri outside that client's registered set is rejected (exact-match preserved).
//   AC5  POST /register with a non-loopback http redirect (and data:/javascript:) → 400
//        invalid_redirect_uri (the anti-open-redirect anchor).
//   AC6  /register is stateless: the client_id is SIGNED and carries its redirect_uris — a flood writes
//        nothing; an unsigned/tampered id is invalid_client; one signed with the PREVIOUS secret still works.
//   AC7  Root page: GET / Accept text/html no Bearer → 200 branded HTML; POST / no Bearer → 401;
//        GET / Accept application/json no Bearer → 401 (neither becomes the page — fail-closed intact).
//
// The pre-existing invariants (AC8: fail-closed, PKCE, single-use, exact-match, draft-first, i18n,
// store-down 503) stay proven by oauth.test.ts and store-do.test.ts, untouched by this file.

import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { type WorkerEnv } from "./worker.js";
import { OAuthStore, STORE_CAP } from "./oauth.js";
import { ROOT_TEXT } from "./oauth-i18n.js";
import { spyOn, sealToken, FakeCore, type CapturedRequest, type ProgrammedReply } from "../testutil.js";

const BASE = "https://core.test/v0";
const ORIGIN = "https://mcp.test";
const MCP_ACCEPT = "application/json, text/event-stream";

/** A minimal core that answers /auth/me (never reached on these paths, but present so an accidental
 *  core hit would be visible). All ids invented (AGENTS.md §9). */
function core(): FakeCore {
  return new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), (): ProgrammedReply => ({
    json: { scope_type: "pod", scope_id: "pod_test", organization_id: "org_test", pod_id: "pod_test",
            inbox_id: null, api_key_id: "k", permissions: null },
  }));
}

// R3: /authorize now delegates to the webmail, so it needs the consent URL + the HMAC secret to 302.
const WEB_CONSENT = "https://mail.pombus.com/mcp/consent";
const SECRET = "test_hmac_secret_shared_with_the_webmail_000";
const STATE = "test_worker_only_state_secret_0000000000000";

function env(c: FakeCore, store: OAuthStore): WorkerEnv {
  return {
    POMBUS_API_BASE: BASE, __coreFetch: c.fetch, __store: store,
    WEB_CONSENT_URL: WEB_CONSENT, MCP_WEB_LINK_SECRET: SECRET, MCP_STATE_SECRET: STATE,
  };
}

function get(e: WorkerEnv, path: string, headers: Record<string, string> = {}): Promise<Response> {
  return worker.fetch(new Request(`${ORIGIN}${path}`, { method: "GET", headers }), e);
}

function registerPost(e: WorkerEnv, body: unknown): Promise<Response> {
  return worker.fetch(
    new Request(`${ORIGIN}/register`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: ORIGIN },
      body: typeof body === "string" ? body : JSON.stringify(body),
    }),
    e,
  );
}

async function json(res: Response): Promise<Record<string, unknown>> {
  return JSON.parse(await res.text()) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------------------------------
// AC1 / AC2 — discovery documents, origin-derived.
// ---------------------------------------------------------------------------------------------------

test("AC1: GET /.well-known/oauth-protected-resource returns resource + authorization_servers = origin", async () => {
  const res = await get(env(core(), new OAuthStore()), "/.well-known/oauth-protected-resource");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "application/json");
  const doc = await json(res);
  assert.equal(doc["resource"], ORIGIN, "resource must be the request origin");
  assert.deepEqual(doc["authorization_servers"], [ORIGIN], "AS list must be the request origin");
});

test("AC2: GET /.well-known/oauth-authorization-server returns origin-derived endpoints, S256, DCR", async () => {
  const res = await get(env(core(), new OAuthStore()), "/.well-known/oauth-authorization-server");
  assert.equal(res.status, 200);
  const doc = await json(res);
  assert.equal(doc["issuer"], ORIGIN);
  assert.equal(doc["authorization_endpoint"], `${ORIGIN}/authorize`);
  assert.equal(doc["token_endpoint"], `${ORIGIN}/token`);
  assert.equal(doc["registration_endpoint"], `${ORIGIN}/register`, "DCR endpoint must be advertised");
  assert.deepEqual(doc["response_types_supported"], ["code"]);
  assert.deepEqual(doc["grant_types_supported"], ["authorization_code"]);
  assert.deepEqual(doc["code_challenge_methods_supported"], ["S256"], "only S256");
  assert.deepEqual(doc["token_endpoint_auth_methods_supported"], ["none"], "public client");
});

test("AC2 (origin): the documents reflect the REQUEST origin, not a hardcoded host", async () => {
  // A request to a different origin (e.g. wrangler dev on localhost) must derive THAT origin.
  const e = env(core(), new OAuthStore());
  const res = await worker.fetch(
    new Request("http://localhost:8787/.well-known/oauth-authorization-server", { method: "GET" }),
    e,
  );
  assert.equal(res.status, 200);
  const doc = await json(res);
  assert.equal(doc["issuer"], "http://localhost:8787");
  assert.equal(doc["authorization_endpoint"], "http://localhost:8787/authorize");
});

test("discovery: a non-GET on a well-known is 405 (public metadata is read-only)", async () => {
  const e = env(core(), new OAuthStore());
  const res = await worker.fetch(new Request(`${ORIGIN}/.well-known/oauth-protected-resource`, {
    method: "POST", headers: { origin: ORIGIN }, body: "{}",
  }), e);
  assert.equal(res.status, 405);
});

// ---------------------------------------------------------------------------------------------------
// AC3 — the MCP 401 carries the resource_metadata pointer.
// ---------------------------------------------------------------------------------------------------

test("AC3: the MCP 401 www-authenticate carries resource_metadata pointing at our discovery document", async () => {
  const e = env(core(), new OAuthStore());
  const res = await worker.fetch(new Request(`${ORIGIN}/`, {
    method: "POST",
    headers: { accept: MCP_ACCEPT, "content-type": "application/json", origin: ORIGIN },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }), e);
  assert.equal(res.status, 401, "no Bearer => still fail-closed 401");
  const wa = res.headers.get("www-authenticate") ?? "";
  assert.match(wa, /^Bearer /, "still an RFC 6750 Bearer challenge");
  assert.ok(
    wa.includes(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource"`),
    `the challenge must point at the metadata document (got: ${wa})`,
  );
});

// ---------------------------------------------------------------------------------------------------
// AC4 — DCR issues a working client_id; exact-match is preserved against its own uris.
// ---------------------------------------------------------------------------------------------------

test("AC4: POST /register with an https redirect → 201, and the client_id then works at /authorize", async () => {
  const store = new OAuthStore();
  const e = env(core(), store);
  const REDIRECT = "https://claude.ai/api/mcp/auth_callback";

  const reg = await registerPost(e, { redirect_uris: [REDIRECT] });
  assert.equal(reg.status, 201, "a valid registration must be created");
  assert.equal(reg.headers.get("cache-control"), "no-store");
  const body = await json(reg);
  const clientId = body["client_id"] as string;
  assert.ok(clientId && clientId.length >= 40, "a high-entropy client_id must be issued");
  assert.equal(body["token_endpoint_auth_method"], "none");
  assert.deepEqual(body["redirect_uris"], [REDIRECT]);

  // The freshly registered client_id resolves at /authorize (findClient dynamic path).
  const u = new URL(`${ORIGIN}/authorize`);
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", REDIRECT);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("code_challenge", "a".repeat(43));
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("state", "st");
  const authRes = await worker.fetch(new Request(u.toString(), { method: "GET" }), e);
  // R3: a valid /authorize now 302s to the webmail consent URL (not a 200 HTML screen).
  assert.equal(authRes.status, 302, "the registered client is delegated to the webmail consent screen");
  const loc = new URL(authRes.headers.get("location")!);
  assert.equal(`${loc.origin}${loc.pathname}`, WEB_CONSENT, "the 302 points at the webmail consent URL");
});

test("AC4: a registered client cannot redirect to a uri it did NOT register (exact-match preserved)", async () => {
  const store = new OAuthStore();
  const e = env(core(), store);
  const reg = await registerPost(e, { redirect_uris: ["https://app.one/cb"] });
  const clientId = (await json(reg))["client_id"] as string;

  // Try /authorize with a DIFFERENT (also https, also valid-shaped) uri the client never registered.
  const u = new URL(`${ORIGIN}/authorize`);
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", "https://app.two/cb"); // not this client's
  u.searchParams.set("response_type", "code");
  u.searchParams.set("code_challenge", "a".repeat(43));
  u.searchParams.set("code_challenge_method", "S256");
  u.searchParams.set("state", "st");
  const res = await worker.fetch(new Request(u.toString(), { method: "GET" }), e);
  assert.equal(res.status, 400, "a uri outside the client's registered set must be rejected");
  assert.equal(res.headers.get("location"), null, "no redirect to the unregistered uri");
});

test("AC4: a loopback http redirect is accepted (the MCP Inspector / local clients)", async () => {
  const e = env(core(), new OAuthStore());
  const reg = await registerPost(e, {
    redirect_uris: ["http://127.0.0.1:6274/oauth/callback", "http://localhost:8080/cb"],
  });
  assert.equal(reg.status, 201, "loopback http is a legitimate dynamic client callback");
});

// ---------------------------------------------------------------------------------------------------
// AC5 — the anti-open-redirect anchor.
// ---------------------------------------------------------------------------------------------------

test("AC5: POST /register with a non-loopback http redirect → 400 invalid_redirect_uri", async () => {
  const e = env(core(), new OAuthStore());
  const res = await registerPost(e, { redirect_uris: ["http://evil.com/cb"] });
  assert.equal(res.status, 400);
  assert.equal((await json(res))["error"], "invalid_redirect_uri");
});

test("AC5: data: and javascript: redirect_uris are rejected (whole registration fails)", async () => {
  const e = env(core(), new OAuthStore());
  for (const bad of ["data:text/html,evil", "javascript:alert(1)", "file:///etc/passwd"]) {
    const res = await registerPost(e, { redirect_uris: ["https://ok.example/cb", bad] });
    assert.equal(res.status, 400, `${bad} must reject the registration`);
    assert.equal((await json(res))["error"], "invalid_redirect_uri");
  }
});

test("AC5: a missing / empty / non-array redirect_uris is invalid", async () => {
  const e = env(core(), new OAuthStore());
  assert.equal((await registerPost(e, {})).status, 400, "no redirect_uris");
  assert.equal((await registerPost(e, { redirect_uris: [] })).status, 400, "empty array");
  assert.equal((await registerPost(e, { redirect_uris: "https://x/cb" })).status, 400, "string, not array");
  // A non-JSON / oversized body is invalid_client_metadata.
  const notJson = await registerPost(e, "}{ not json");
  assert.equal(notJson.status, 400);
  assert.equal((await json(notJson))["error"], "invalid_client_metadata");
});

// ---------------------------------------------------------------------------------------------------
// AC6 — the register cap: a flood never grows the store unbounded.
// ---------------------------------------------------------------------------------------------------


function authorizeWith(e: WorkerEnv, clientId: string, redirect: string): Promise<Response> {
  const u = new URL(`${ORIGIN}/authorize`);
  for (const [k, v] of Object.entries({ client_id: clientId, redirect_uri: redirect, response_type: "code",
    code_challenge: "a".repeat(43), code_challenge_method: "S256", state: "st" })) u.searchParams.set(k, v);
  return worker.fetch(new Request(u.toString(), { method: "GET" }), e);
}

test("AC6: /register writes NOTHING — a flood fills no store; each client_id is signed and self-contained", async () => {
  const { spy: store, calls } = spyOn(new OAuthStore());
  const e = env(core(), store);
  for (let i = 0; i < 50; i++) assert.equal((await registerPost(e, { redirect_uris: [`https://x${i}.example/cb`] })).status, 201);
  assert.deepEqual(calls, [], "the store is never touched by /register");
  // a fresh Worker env (a deploy: a new, EMPTY store) still resolves a client_id registered before it
  const reg = await json(await registerPost(e, { redirect_uris: ["https://app.one/cb"] }));
  const after = env(core(), new OAuthStore());
  assert.equal((await authorizeWith(after, reg["client_id"] as string, "https://app.one/cb")).status, 302);
});

test("AC6: an unsigned or tampered client_id is invalid_client; one signed with MCP_STATE_SECRET_PREV still works", async () => {
  const e = env(core(), new OAuthStore());
  const id = (await json(await registerPost(e, { redirect_uris: ["https://app.one/cb"] })))["client_id"] as string;
  const [payload, sig] = id.split(".") as [string, string];
  // re-point the redirect inside the payload, keep the old signature
  const forgedPayload = btoa(JSON.stringify({ u: ["https://evil.example/cb"] })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  for (const bad of ["random_unsigned_client_id_0000000000000000", `${forgedPayload}.${sig}`, `${payload}.${sig.slice(0, -2)}AA`, `${payload}`]) {
    const res = await authorizeWith(e, bad, "https://evil.example/cb");
    assert.equal(res.status, 400, bad);
    assert.equal(await res.text(), "invalid_client", bad);
  }
  // rotation: the id was signed with STATE; the next deploy signs with a NEW secret and keeps STATE as PREV
  const rotated: WorkerEnv = { ...e, MCP_STATE_SECRET: "a_brand_new_state_secret_after_rotation_000", MCP_STATE_SECRET_PREV: STATE };
  assert.equal((await authorizeWith(rotated, id, "https://app.one/cb")).status, 302, "PREV still verifies");
  const dropped: WorkerEnv = { ...e, MCP_STATE_SECRET: "a_brand_new_state_secret_after_rotation_000" };
  assert.equal((await authorizeWith(dropped, id, "https://app.one/cb")).status, 400, "without PREV it is gone");
  // ...and during the rotation the Worker SIGNS with the new secret, never with PREV: an id registered under
  // [new, PREV] still resolves once PREV is dropped.
  const fresh = (await json(await registerPost(rotated, { redirect_uris: ["https://app.one/cb"] })))["client_id"] as string;
  assert.equal((await authorizeWith(dropped, fresh, "https://app.one/cb")).status, 302, "signed with the CURRENT secret");
});

test("redirect_uri is an EXACT match — near misses are refused, for a fixed AND a dynamic client", async () => {
  const e = env(core(), new OAuthStore());
  const dyn = (await json(await registerPost(e, { redirect_uris: ["https://app.one/cb"] })))["client_id"] as string;
  const fixedUri = "http://127.0.0.1:6274/oauth/callback";
  for (const [id, uri] of [["pombus-mcp", fixedUri], [dyn, "https://app.one/cb"]] as const) {
    assert.equal((await authorizeWith(e, id, uri)).status, 302, `${id}: the exact uri`);
    for (const near of [`${uri}x`, `${uri}/x`, `${uri}?a=b`, `${uri}.evil.com`, uri.toUpperCase()]) {
      const res = await authorizeWith(e, id, near);
      assert.equal(res.status, 400, `${id}: ${near}`);
    }
  }
});

test("a signed client_id carrying a uri /register would refuse (http non-loopback) is invalid_client", async () => {
  const e = env(core(), new OAuthStore());
  const forged = await sealToken(STATE, "mcp-client-v1", { u: ["http://evil.example/cb"] });
  const res = await authorizeWith(e, forged, "http://evil.example/cb");
  assert.equal(res.status, 400);
  assert.equal(await res.text(), "invalid_client");
});

test("AC6: /register caps the redirect_uris (count and size) and fails closed without the state secret", async () => {
  const e = env(core(), new OAuthStore());
  const many = Array.from({ length: 6 }, (_, i) => `https://a${i}.example/cb`);
  assert.equal((await registerPost(e, { redirect_uris: many })).status, 400);
  assert.equal((await registerPost(e, { redirect_uris: [`https://x.example/${"p".repeat(600)}`] })).status, 400);
  const noSecret: WorkerEnv = { ...e };
  delete noSecret.MCP_STATE_SECRET;
  assert.equal((await registerPost(noSecret, { redirect_uris: ["https://app.one/cb"] })).status, 503);
});

// ---------------------------------------------------------------------------------------------------
// AC7 — the friendly root page, and that it never becomes an auth bypass.
// ---------------------------------------------------------------------------------------------------

test("AC7: GET / with Accept text/html and no Bearer → 200 branded HTML (not a 401)", async () => {
  const e = env(core(), new OAuthStore());
  const res = await get(e, "/", { accept: "text/html" });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-type"), "text/html; charset=utf-8");
  const html = await res.text();
  assert.ok(html.includes(ROOT_TEXT["root_heading"]!["en-US"]), "the branded heading must render");
  assert.ok(/role="img" aria-label="Pombus"/.test(html), "the Pombus lockup must be present");
  assert.ok(!/<script/i.test(html), "the page carries no script (CSP-friendly, inline only)");
});

test("AC7: the root page honors Accept-Language (pt-BR → Portuguese copy)", async () => {
  const e = env(core(), new OAuthStore());
  const res = await get(e, "/", { accept: "text/html", "accept-language": "pt-BR" });
  const html = await res.text();
  assert.ok(html.includes(ROOT_TEXT["root_heading"]!["pt-BR"]), "pt-BR heading must render");
  assert.ok(!html.includes(ROOT_TEXT["root_heading"]!["en-US"]), "the en-US heading must not appear");
});

test("AC7 (fail-closed): a real MCP request never becomes the page", async () => {
  const e = env(core(), new OAuthStore());
  // POST (a real MCP client) with no Bearer → still the fail-closed 401, never the HTML page.
  const post = await worker.fetch(new Request(`${ORIGIN}/`, {
    method: "POST",
    headers: { accept: MCP_ACCEPT, "content-type": "application/json", origin: ORIGIN },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }), e);
  assert.equal(post.status, 401, "POST without Bearer stays 401 — not the page");
  assert.notEqual(post.headers.get("content-type"), "text/html; charset=utf-8");

  // GET with Accept application/json (MCP discovery-ish, no html) and no Bearer → 401, not the page.
  const getJson = await get(e, "/", { accept: "application/json" });
  assert.equal(getJson.status, 401, "GET asking for json stays 401 — not the page");

  // GET with Accept text/html but WITH a (bogus) Bearer → treated as MCP, 401, not the page.
  const getWithBearer = await get(e, "/", { accept: "text/html", authorization: "Bearer nope" });
  assert.equal(getWithBearer.status, 401, "a Bearer forces the MCP path even if html is asked");
});

test("AC7 (no core touch): none of the public R2d surfaces ever reach the core", async () => {
  const c = core();
  const e = env(c, new OAuthStore());
  await get(e, "/.well-known/oauth-protected-resource");
  await get(e, "/.well-known/oauth-authorization-server");
  await get(e, "/", { accept: "text/html" });
  await registerPost(e, { redirect_uris: ["https://ok.example/cb"] });
  assert.equal(c.requests.length, 0, "discovery / register / root page never touch the core");
});
