// R3 proof — the store-down envelope. Since R2c the OAuth store is a Durable Object reached by RPC, so
// every `await store.*` in worker.fetch can REJECT when the DO is unavailable. Such a throw must NOT
// escape as workerd's default 500 (which risks a stack AND distinguishes "infra down" from "credential
// invalid" — an availability oracle). The top-level try/catch collapses any throw into one content-free
// 503. These prove the envelope is uniform and content-free, the core is never reached, and the NORMAL
// 401 path is untouched.
//
// R3 removed the R2c sliding-window rate limiter (it guarded the old paste-key POST /authorize, which is
// gone — the human now authenticates on the webmail, not here), so there is no `hit` to test. What is
// NOT here, on purpose: the Durable Object shell (do-class.ts) and the DurableObjectStore→stub RPC —
// workerd-specific, 1:1 pass-throughs, reviewed by reading + the founder's `wrangler dev` smoke.

import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { type WorkerEnv } from "./worker.js";
import { OAuthStore, type OAuthStoreLike } from "./oauth.js";
import { FakeCore, hmacB64 as hmac, sealToken, type ProgrammedReply } from "../testutil.js";

const BASE = "https://core.test/v0";
const WEB_CONSENT = "https://mail.pombus.com/mcp/consent";
const SECRET = "test_hmac_secret_shared_with_the_webmail_000";
const STATE = "test_worker_only_state_secret_0000000000000";


function recordingCore(): FakeCore {
  return new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), (): ProgrammedReply => ({
    json: { scope_type: "pod", scope_id: "pod_test", organization_id: "org_test", pod_id: "pod_test",
            inbox_id: null, api_key_id: "k", permissions: null },
  }));
}

/** A store whose every method REJECTS — stands in for a Durable Object that is completely unavailable.
 *  It satisfies OAuthStoreLike so the Worker awaits it exactly as it would the real DO; the only thing
 *  that matters is that the awaited Promise rejects, which the top-level catch must absorb into a 503. */
function rejectingStore(): OAuthStoreLike {
  const down = (): Promise<never> => Promise.reject(new Error("DO unavailable: stack must never leak"));
  return {
    useRid: down,
    putCode: down,
    takeCode: down,
    tokenRoom: down,
    putToken: down,
    getToken: down,
    attachOrg: down,
    setActiveOrg: down,
    getActiveChild: down,
    putLink: down,
    takeLink: down,
    reset: down,
  };
}

test("worker: MCP request (Bearer) + store that rejects on getActiveChild → content-free 503, core untouched", async () => {
  const core = recordingCore();
  const e: WorkerEnv = { POMBUS_API_BASE: BASE, __coreFetch: core.fetch, __store: rejectingStore() };
  const res = await worker.fetch(
    new Request("https://mcp.test/", {
      method: "POST",
      headers: { origin: "https://mcp.test", authorization: "Bearer at_some_opaque_token", "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
    e,
  );
  assert.equal(res.status, 503, "a store failure on the MCP path must be a 503, not a 500");
  assert.equal(await res.text(), "", "the 503 carries no body — no stack, no .message can leak");
  assert.ok(res.headers.get("retry-after"), "a Retry-After must be set");
  assert.equal(core.requests.length, 0, "the core is never touched when the store is down");
});

test("worker: GET /authorize/return + store that rejects on useRid → the SAME content-free 503", async () => {
  const core = recordingCore();
  const e: WorkerEnv = {
    POMBUS_API_BASE: BASE, __coreFetch: core.fetch, __store: rejectingStore(),
    WEB_CONSENT_URL: WEB_CONSENT, MCP_WEB_LINK_SECRET: SECRET, MCP_STATE_SECRET: STATE,
  };
  // a VALID rid and a VALID webmail signature: the first store call (useRid) is what rejects
  const rid = await sealToken(STATE, "mcp-rid-v1", {
    c: "x", r: "http://127.0.0.1:6274/oauth/callback", s: "s", ch: "a".repeat(43), e: Date.now() + 60_000,
  });
  const u = new URL("https://mcp.test/authorize/return");
  u.searchParams.set("rid", rid);
  u.searchParams.set("handoff", "h");
  u.searchParams.set("sig", await hmac(SECRET, `mcp-complete.${rid}.h`));
  const res = await worker.fetch(new Request(u.toString(), { method: "GET" }), e);
  // useRid REJECTS → the throw hits the top-level catch → uniform 503.
  assert.equal(res.status, 503, "a store failure on /authorize/return must be the SAME uniform 503");
  assert.equal(await res.text(), "", "the 503 carries no body");
  assert.ok(res.headers.get("retry-after"), "a Retry-After must be set");
  assert.equal(core.requests.length, 0, "the core is never touched when the store is down");
});

test("worker: an unknown token with a WORKING store stays 401 (not 503) — the normal path is intact", async () => {
  const core = recordingCore();
  const e: WorkerEnv = { POMBUS_API_BASE: BASE, __coreFetch: core.fetch, __store: new OAuthStore() };
  const res = await worker.fetch(
    new Request("https://mcp.test/", {
      method: "POST",
      headers: { origin: "https://mcp.test", authorization: "Bearer at_unknown_but_well_formed", "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    }),
    e,
  );
  assert.equal(res.status, 401, "an unknown token with a healthy store is still a content-free 401");
  assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer resource_metadata="https:\/\/[^"]+\/\.well-known\/oauth-protected-resource"$/);
  assert.equal(core.requests.length, 0, "an unresolved token never reaches the core");
});
