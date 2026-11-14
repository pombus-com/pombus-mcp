// R3 proof (end-to-end) — the DELEGATING OAuth 2.1 AS and the multi-org token-set, exercised the way a
// Worker runtime does: real `Request` in, real `Response` out, the core faked via FetchLike and the
// webmail faked via a WEB service binding seam (nothing leaves the process). The human consent moved to
// the webmail; the Worker keeps PKCE/redirect/client/state and redeems a single-use handoff.
//
// Covers (each maps to a requirement / security invariant in the spec):
//   GET /authorize 302s to WEB_CONSENT_URL with a correct HMAC sig; no secret/url → 503 (no redirect).
//   GET /authorize/return validates the sig and emits an authorization code (bad sig → 400).
//   POST /token redeems via the fake WEB: success builds a 1-org token-set; a null redeem → invalid_grant;
//     a link_token + matching ownerHash attaches a second org; a MISMATCHED ownerHash → invalid_grant and
//     NO attach (anti-injection). No WEB binding → 503.
//   The token-set store: put/get/attachOrg(owner match & mismatch)/setActiveOrg/getActiveChild/expiry/cap.
//   validateAccessToken returns the ACTIVE org's child key.
//   Preserved invariants: PKCE S256 only (`plain` refused, wrong verifier → invalid_grant), single-use
//     code + rid, redirect exact-match (no open redirect), fail-closed 401 at the MCP endpoint.
//
// The org tools (list/select_organization) and path discrimination (Bearer vs x-api-key vs both) are
// proven in worker.test.ts, where the MCP endpoint is driven. All ids/keys invented (AGENTS.md §9).

import { test } from "node:test";
import assert from "node:assert/strict";
import worker, { type WorkerEnv } from "./worker.js";
import { OAuthStore, STORE_CAP, MAX_FORM_BYTES, type LiveToken, type RedeemedHandoff, type WebBinding } from "./oauth.js";
import { FakeCore } from "../testutil.js";

const BASE = "https://core.test/v0";
const CLIENT = "pombus-mcp";
const REDIRECT = "http://127.0.0.1:6274/oauth/callback";
const ORIGIN = "https://mcp.test";
const WEB_CONSENT = "https://mail.pombus.com/mcp/consent";
const SECRET = "test_hmac_secret_shared_with_the_webmail_000";

const ORG_A = "org_alpha";
const ORG_B = "org_bravo";
const OWNER = "ownerhash_alice_000";
const OWNER_OTHER = "ownerhash_mallory_999";
const CHILD_A = "pk_live_child_alpha_do_not_log";
const CHILD_B = "pk_live_child_bravo_do_not_log";

// A fixed PKCE pair; the challenge is its real S256, locked by the first test.
const VERIFIER = "pkce_verifier_dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";
let CHALLENGE = "";

async function s256(verifier: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let s = "";
  for (const b of new Uint8Array(d)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** HMAC-SHA256 → base64url, the same way the Worker signs the 302 hops — used to forge a correct (and
 *  an incorrect) `sig` for /authorize/return. */
async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  let s = "";
  for (const b of new Uint8Array(sig)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A fake WEB binding: a map of handoff → redeemed payload. An unknown handoff redeems to null (the
 *  real webmail's single-use/expired behaviour). */
function fakeWeb(table: Record<string, RedeemedHandoff>): WebBinding {
  return {
    async redeemMcpHandoff(handoff: string): Promise<RedeemedHandoff | null> {
      return table[handoff] ?? null;
    },
  };
}

/** Build a Worker env. `omit` drops a webmail seam so a test can prove the fail-closed path (no secret /
 *  no consent URL / no WEB binding) — `delete` rather than `= undefined` keeps exactOptionalPropertyTypes
 *  happy. */
function env(
  store: OAuthStore,
  web?: WebBinding,
  omit: { secret?: boolean; consentUrl?: boolean; web?: boolean } = {},
): WorkerEnv {
  const e: WorkerEnv = {
    POMBUS_API_BASE: BASE,
    __coreFetch: new FakeCore().fetch,
    __store: store,
    WEB_CONSENT_URL: WEB_CONSENT,
    MCP_WEB_LINK_SECRET: SECRET,
    ...(web ? { __web: web } : {}),
  };
  if (omit.secret) delete e.MCP_WEB_LINK_SECRET;
  if (omit.consentUrl) delete e.WEB_CONSENT_URL;
  if (omit.web) {
    delete e.__web;
    delete e.WEB;
  }
  return e;
}

function authorizeGet(e: WorkerEnv, params: Record<string, string>): Promise<Response> {
  const u = new URL(`${ORIGIN}/authorize`);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return worker.fetch(new Request(u.toString(), { method: "GET" }), e);
}

function authorizeReturn(e: WorkerEnv, params: Record<string, string>): Promise<Response> {
  const u = new URL(`${ORIGIN}/authorize/return`);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return worker.fetch(new Request(u.toString(), { method: "GET" }), e);
}

function tokenPost(e: WorkerEnv, fields: Record<string, string>): Promise<Response> {
  const fd = new FormData();
  for (const [k, v] of Object.entries(fields)) fd.set(k, v);
  return worker.fetch(new Request(`${ORIGIN}/token`, { method: "POST", body: fd }), e);
}

function baseParams(): Record<string, string> {
  return {
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: "code",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    state: "xyz-state-123",
    scope: "read_mail send",
  };
}

/** Drive GET /authorize → read the rid out of the 302 Location; return the rid (the single-use request
 *  id the Worker stashed). */
async function startAuthorize(e: WorkerEnv, params = baseParams()): Promise<string> {
  const res = await authorizeGet(e, params);
  assert.equal(res.status, 302, "GET /authorize must 302 to the webmail");
  const loc = new URL(res.headers.get("location") ?? "");
  assert.equal(`${loc.origin}${loc.pathname}`, WEB_CONSENT, "must 302 to the webmail consent URL");
  const rid = loc.searchParams.get("rid") ?? "";
  assert.ok(rid, "the 302 must carry a rid");
  return rid;
}

/** base64url-decode the signed ctx the Worker carries on the 302, parsed back to {scope, redirectHost}. */
function decodeCtx(ctx: string): { scope: string; redirectHost: string } {
  const b64 = ctx.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as { scope: string; redirectHost: string };
}

/** Simulate the webmail bounce-back with a correct signature, returning the Worker's /authorize/return
 *  response (a 302 to the agent's redirect_uri carrying ?code&state). */
async function completeAuthorize(e: WorkerEnv, rid: string, handoff: string): Promise<Response> {
  const sig = await hmac(SECRET, `mcp-complete.${rid}.${handoff}`);
  return authorizeReturn(e, { rid, handoff, sig });
}

/** Run the whole flow to a live access token for ORG_A, using a fresh fake WEB. Returns {token, store}. */
async function flowToToken(handoff = "handoff_a"): Promise<{ token: string; store: OAuthStore }> {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const web = fakeWeb({ [handoff]: { childKey: CHILD_A, orgId: ORG_A, perms: ["message_read"], label: "Alpha", ownerHash: OWNER } });
  const e = env(store, web);
  const rid = await startAuthorize(e);
  const ret = await completeAuthorize(e, rid, handoff);
  assert.equal(ret.status, 302);
  const code = new URL(ret.headers.get("location")!).searchParams.get("code")!;
  assert.ok(code, "the return must redirect with a code");
  const tok = await tokenPost(e, {
    grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT,
  });
  assert.equal(tok.status, 200, "token exchange must succeed");
  const body = JSON.parse(await tok.text()) as { access_token: string; token_type: string; scope?: unknown };
  assert.equal(body.token_type, "Bearer");
  assert.ok(!("scope" in body), "no fabricated scope in the token response");
  return { token: body.access_token, store };
}

// ---------------------------------------------------------------------------------------------------
test("fixture: the PKCE challenge is the real S256 of the verifier", async () => {
  CHALLENGE = await s256(VERIFIER);
  assert.match(CHALLENGE, /^[A-Za-z0-9\-_]{43}$/);
});

// ===================================================================================================
// A — GET /authorize delegates (302 to the webmail, signed); fail-closed without the webmail config.
// ===================================================================================================

test("A: GET /authorize 302s to WEB_CONSENT_URL with a correct HMAC sig and a rid — no HTML", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const res = await authorizeGet(e, baseParams());
  assert.equal(res.status, 302);
  assert.equal(res.headers.get("content-type"), null, "no HTML body — the Worker only redirects");
  const loc = new URL(res.headers.get("location")!);
  assert.equal(`${loc.origin}${loc.pathname}`, WEB_CONSENT);
  const rid = loc.searchParams.get("rid")!;
  const ctx = loc.searchParams.get("ctx")!;
  const sig = loc.searchParams.get("sig")!;
  assert.ok(rid && ctx && sig, "rid, ctx and sig must all be present");
  assert.equal(sig, await hmac(SECRET, `mcp-consent.${rid}.${ctx}`), "the sig must be HMAC(secret, 'mcp-consent.'+rid+'.'+ctx) — it covers the ctx");
  // The ctx carries ONLY scope + the agent's redirect host (not secrets): the webmail pre-checks the
  // toggles and shows who is asking from it. It is signed, so a tamper flips the sig.
  const decoded = decodeCtx(ctx);
  assert.equal(decoded.scope, "read_mail send", "scope travels inside the signed ctx");
  assert.equal(decoded.redirectHost, "127.0.0.1:6274", "the redirect host travels inside the signed ctx");
  // PKCE / redirect / client / state stay in the Worker — they must NOT be on the consent URL, NOR
  // may scope/redirect appear as RAW params (they live inside the signed ctx only).
  for (const leak of ["code_challenge", "redirect_uri", "client_id", "state", "scope"]) {
    assert.equal(loc.searchParams.get(leak), null, `${leak} must never travel as a raw param to the webmail`);
  }
});

test("A (fail-closed): no webmail secret/URL configured → 503, NO redirect", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const noSecret = env(store, fakeWeb({}), { secret: true });
  const r1 = await authorizeGet(noSecret, baseParams());
  assert.equal(r1.status, 503, "no secret → 503");
  assert.equal(r1.headers.get("location"), null, "no redirect without a signature");
  const noUrl = env(store, fakeWeb({}), { consentUrl: true });
  const r2 = await authorizeGet(noUrl, baseParams());
  assert.equal(r2.status, 503, "no consent URL → 503");
  assert.equal(r2.headers.get("location"), null);
});

test("A (invariant): PKCE `plain` is refused at /authorize; bad params 400 with no redirect", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  assert.equal((await authorizeGet(e, { ...baseParams(), code_challenge_method: "plain" })).status, 400);
  assert.equal((await authorizeGet(e, { ...baseParams(), response_type: "token" })).status, 400);
  const noState = await authorizeGet(e, { ...baseParams(), state: "" });
  assert.equal(noState.status, 400);
  assert.equal(noState.headers.get("location"), null);
});

test("A (invariant): an unknown client_id and a non-whitelisted redirect_uri are 400 with NO redirect", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const badClient = await authorizeGet(e, { ...baseParams(), client_id: "not-registered" });
  assert.equal(badClient.status, 400);
  assert.equal(badClient.headers.get("location"), null);
  const badRedirect = await authorizeGet(e, { ...baseParams(), redirect_uri: "https://evil.example/steal" });
  assert.equal(badRedirect.status, 400);
  assert.equal(badRedirect.headers.get("location"), null);
});

// ===================================================================================================
// B — GET /authorize/return validates the signature and emits an authorization code.
// ===================================================================================================

test("B: /authorize/return with a correct sig emits a code and 302s to the agent's redirect_uri", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const rid = await startAuthorize(e);
  const ret = await completeAuthorize(e, rid, "handoff_x");
  assert.equal(ret.status, 302);
  const loc = new URL(ret.headers.get("location")!);
  assert.equal(`${loc.origin}${loc.pathname}`, REDIRECT.replace(/\?.*$/, ""), "must bounce to the agent's exact redirect_uri");
  assert.ok(loc.searchParams.get("code"), "a code must be issued");
  assert.equal(loc.searchParams.get("state"), "xyz-state-123", "state must be echoed");
});

test("B (invariant): a FORGED signature on /authorize/return is 400, no code, no redirect", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const rid = await startAuthorize(e);
  const forged = await authorizeReturn(e, { rid, handoff: "handoff_x", sig: "wrong_signature_wrong_signature_wrong_000" });
  assert.equal(forged.status, 400, "a bad sig must be rejected");
  assert.equal(forged.headers.get("location"), null, "no redirect on a forged return");
});

test("B (invariant): the rid is single-use — a replayed /authorize/return finds nothing", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const rid = await startAuthorize(e);
  assert.equal((await completeAuthorize(e, rid, "h1")).status, 302, "first return succeeds");
  assert.equal((await completeAuthorize(e, rid, "h1")).status, 400, "a replayed rid is rejected");
});

// ===================================================================================================
// C — POST /token redeems the handoff via the WEB binding and builds the token-set.
// ===================================================================================================

test("C: /token redeem success → a one-org token-set; validateAccessToken yields the active child key", async () => {
  const { token, store } = await flowToToken();
  const active = await store.getActiveChild(token);
  assert.ok(active, "the token must resolve to an active org");
  assert.equal(active!.orgId, ORG_A);
  assert.equal(active!.childKey, CHILD_A, "the active org's child key is the credential the core will see");
});

test("C (invariant): a wrong PKCE verifier → invalid_grant", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const e = env(store, fakeWeb({ h: { childKey: CHILD_A, orgId: ORG_A, perms: [], label: "A", ownerHash: OWNER } }));
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "h")).headers.get("location")!).searchParams.get("code")!;
  const bad = await tokenPost(e, {
    grant_type: "authorization_code", code,
    code_verifier: "wrong_verifier_wrong_verifier_wrong_verifier_1234", redirect_uri: REDIRECT, client_id: CLIENT,
  });
  assert.equal(bad.status, 400);
  assert.equal((JSON.parse(await bad.text()) as { error: string }).error, "invalid_grant");
});

test("C (invariant): the authorization code is single-use — a replay is invalid_grant", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const e = env(store, fakeWeb({ h: { childKey: CHILD_A, orgId: ORG_A, perms: [], label: "A", ownerHash: OWNER } }));
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "h")).headers.get("location")!).searchParams.get("code")!;
  const first = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(first.status, 200);
  const replay = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(replay.status, 400);
  assert.equal((JSON.parse(await replay.text()) as { error: string }).error, "invalid_grant");
});

test("C: a NULL redeem (unknown/consumed handoff) → invalid_grant, no token-set created", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const e = env(store, fakeWeb({})); // the WEB binding knows no handoffs → every redeem is null
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "unknown_handoff")).headers.get("location")!).searchParams.get("code")!;
  const res = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(res.status, 400);
  assert.equal((JSON.parse(await res.text()) as { error: string }).error, "invalid_grant");
});

test("C (fail-closed): no WEB binding configured → /token is 503 (not invalid_grant)", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const e = env(store, undefined, { web: true }); // no __web and no WEB binding
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "h")).headers.get("location")!).searchParams.get("code")!;
  const res = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(res.status, 503, "without the WEB binding the Worker cannot mint — 503, not a bad grant");
});

test("C (binding): a code bound to one client/redirect is invalid for another", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const e = env(store, fakeWeb({ h: { childKey: CHILD_A, orgId: ORG_A, perms: [], label: "A", ownerHash: OWNER } }));
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "h")).headers.get("location")!).searchParams.get("code")!;
  const wrongRedirect = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: "http://localhost:6274/oauth/callback", client_id: CLIENT });
  assert.equal((JSON.parse(await wrongRedirect.text()) as { error: string }).error, "invalid_grant");
});

// ===================================================================================================
// C/E — add-org: link_token + ownerHash match attaches a second org; a MISMATCH never grafts.
// ===================================================================================================

test("add-org: a link_token with a MATCHING ownerHash attaches a second org to the SAME access token", async () => {
  const { token, store } = await flowToToken("handoff_a"); // token-set has ORG_A, owner = OWNER
  // select_organization(unauthorized) would mint a link_token tied to `token`; simulate that here.
  const linkToken = "lt_test_match";
  await store.putLink(linkToken, token);
  const web = fakeWeb({ handoff_b: { childKey: CHILD_B, orgId: ORG_B, perms: ["message_read"], label: "Bravo", ownerHash: OWNER } });
  const e = env(store, web);
  // Re-run /authorize WITH the link_token, then return + token.
  const rid = await startAuthorize(e, { ...baseParams(), link_token: linkToken });
  const code = new URL((await completeAuthorize(e, rid, "handoff_b")).headers.get("location")!).searchParams.get("code")!;
  const res = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(res.status, 200, "the add-org exchange must succeed");
  const back = JSON.parse(await res.text()) as { access_token: string };
  assert.equal(back.access_token, token, "the SAME access token is returned (the agent already holds it)");
  // Both orgs are now on the set, and the new one is active.
  const live = await store.getToken(token);
  assert.deepEqual(Object.keys(live!.orgs).sort(), [ORG_A, ORG_B].sort(), "both orgs are authorized");
  assert.equal(live!.activeOrg, ORG_B, "the newly added org becomes active");
  assert.equal((await store.getActiveChild(token))!.childKey, CHILD_B);
});

test("anti-injection: a link_token with a MISMATCHED ownerHash is invalid_grant and NEVER attaches", async () => {
  const { token, store } = await flowToToken("handoff_a"); // owner = OWNER
  const linkToken = "lt_test_mismatch";
  await store.putLink(linkToken, token);
  // The redeem returns a DIFFERENT ownerHash — an attacker's webmail session, not the token owner's.
  const web = fakeWeb({ handoff_b: { childKey: CHILD_B, orgId: ORG_B, perms: [], label: "Bravo", ownerHash: OWNER_OTHER } });
  const e = env(store, web);
  const rid = await startAuthorize(e, { ...baseParams(), link_token: linkToken });
  const code = new URL((await completeAuthorize(e, rid, "handoff_b")).headers.get("location")!).searchParams.get("code")!;
  const res = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(res.status, 400);
  assert.equal((JSON.parse(await res.text()) as { error: string }).error, "invalid_grant");
  // ORG_B must NOT have been grafted onto the set.
  const live = await store.getToken(token);
  assert.deepEqual(Object.keys(live!.orgs), [ORG_A], "the mismatched org must never be attached");
  assert.equal(live!.activeOrg, ORG_A, "the active org is unchanged");
});

// ===================================================================================================
// D — the token-set store unit behaviour (put/get/attachOrg/setActiveOrg/getActiveChild/expiry/cap).
// ===================================================================================================

function liveToken(over: Partial<LiveToken> = {}): LiveToken {
  const now = Date.now();
  return {
    activeOrg: ORG_A,
    orgs: { [ORG_A]: { childKey: CHILD_A, perms: ["message_read"], label: "Alpha", expiresAt: now + 60_000 } },
    owner: OWNER,
    tokenExp: now + 60_000,
    ...over,
  };
}

test("store: putToken/getToken, and getToken sweeps an expired token-set", async () => {
  const s = new OAuthStore();
  await s.putToken("at_live", liveToken());
  assert.ok(await s.getToken("at_live"));
  await s.putToken("at_dead", liveToken({ tokenExp: Date.now() - 1 }));
  assert.equal(await s.getToken("at_dead"), undefined, "an expired token-set is swept");
});

test("store: attachOrg requires owner match; setActiveOrg only for an authorized org", async () => {
  const s = new OAuthStore();
  await s.putToken("at", liveToken());
  const entry = { childKey: CHILD_B, perms: [], label: "Bravo", expiresAt: Date.now() + 60_000 };
  assert.equal(await s.attachOrg("at", ORG_B, entry, OWNER_OTHER), false, "owner mismatch must NOT attach");
  assert.deepEqual(Object.keys((await s.getToken("at"))!.orgs), [ORG_A]);
  assert.equal(await s.attachOrg("at", ORG_B, entry, OWNER), true, "owner match attaches");
  assert.deepEqual(Object.keys((await s.getToken("at"))!.orgs).sort(), [ORG_A, ORG_B].sort());
  assert.equal(await s.setActiveOrg("at", "org_not_in_set"), false, "cannot activate an unauthorized org");
  assert.equal(await s.setActiveOrg("at", ORG_B), true, "can activate an authorized org");
  assert.equal((await s.getToken("at"))!.activeOrg, ORG_B);
});

test("store: getActiveChild returns the active org's child key; an expired org entry → undefined", async () => {
  const s = new OAuthStore();
  await s.putToken("at", liveToken());
  const a = await s.getActiveChild("at");
  assert.equal(a!.childKey, CHILD_A);
  // Expire only the active org's entry (not the whole token-set): getActiveChild must refuse.
  await s.putToken("at2", liveToken({
    orgs: { [ORG_A]: { childKey: CHILD_A, perms: [], label: "A", expiresAt: Date.now() - 1 } },
  }));
  assert.equal(await s.getActiveChild("at2"), undefined, "an expired active entry yields no child key");
});

test("store: attachOrg/setActiveOrg/getActiveChild on an unknown token are safe (false/undefined)", async () => {
  const s = new OAuthStore();
  assert.equal(await s.attachOrg("nope", ORG_B, { childKey: "k", perms: [], label: "", expiresAt: Date.now() + 1000 }, OWNER), false);
  assert.equal(await s.setActiveOrg("nope", ORG_B), false);
  assert.equal(await s.getActiveChild("nope"), undefined);
});

test("store: putLink/takeLink is single-use", async () => {
  const s = new OAuthStore();
  await s.putLink("lt", "at_access");
  assert.equal(await s.takeLink("lt"), "at_access");
  assert.equal(await s.takeLink("lt"), undefined, "a link_token is consumed on use");
});

test("store: a full token store is refused BEFORE a redeem — no stranded child key", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const web: WebBinding = {
    async redeemMcpHandoff(): Promise<RedeemedHandoff> {
      throw new Error("redeem must not be called when the store is full");
    },
  };
  const e = env(store, web);
  const rid = await startAuthorize(e);
  const code = new URL((await completeAuthorize(e, rid, "h")).headers.get("location")!).searchParams.get("code")!;
  for (let i = 0; i < STORE_CAP; i++) await store.putToken(`t_${i}`, liveToken());
  const res = await tokenPost(e, { grant_type: "authorization_code", code, code_verifier: VERIFIER, redirect_uri: REDIRECT, client_id: CLIENT });
  assert.equal(res.status, 503, "a full token store must refuse before redeeming");
});

// ===================================================================================================
// Preserved hardening — foreign Origin fence, body cap, pending-request cap eviction.
// ===================================================================================================

test("hardening: a foreign browser Origin is 403 before the core on the OAuth surfaces", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const forged = await worker.fetch(new Request(`${ORIGIN}/token`, {
    method: "POST", headers: { origin: "https://evil.example" }, body: new FormData(),
  }), e);
  assert.equal(forged.status, 403, "the AS endpoints are fenced against a foreign origin");
});

test("hardening: POST bodies above MAX_FORM_BYTES are 413", async () => {
  CHALLENGE = await s256(VERIFIER);
  const e = env(new OAuthStore(), fakeWeb({}));
  const big = "x".repeat(MAX_FORM_BYTES + 1);
  assert.equal((await tokenPost(e, { grant_type: "authorization_code", code: big })).status, 413);
});

test("hardening: pending requests are capped by evicting the OLDEST — a GET flood can't lock humans out", async () => {
  CHALLENGE = await s256(VERIFIER);
  const store = new OAuthStore();
  const pending = () => ({
    clientId: CLIENT, redirectUri: REDIRECT, state: "s", codeChallenge: CHALLENGE, scope: "", expiresAt: Date.now() + 60_000,
  });
  for (let i = 0; i < STORE_CAP; i++) await store.putRequest(`flood_${i}`, pending());
  const e = env(store, fakeWeb({}));
  const res = await authorizeGet(e, baseParams());
  assert.equal(res.status, 302, "the human still gets a redirect");
  assert.equal(await store.takeRequest("flood_0"), undefined, "the oldest flood entry made room");
  assert.ok(await store.takeRequest("flood_1"), "the rest stays: the map never grows past the cap");
});
