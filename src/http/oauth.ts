// R3 — the hand-written OAuth 2.1 Authorization Server for the Pombus remote MCP endpoint, now a
// DELEGATING front-end (the "Sign in with the webmail" pattern). The HUMAN consent no longer happens
// here: it runs in the WEBMAIL (mail.pombus.com), the origin that holds the human's session cookie and
// renders the toggle-based consent screen. The Worker keeps everything that must NEVER leave it — PKCE,
// the redirect_uri whitelist, the client registry, state, the code — and delegates only the human
// decision, exactly as an OAuth client delegates to an identity provider.
//
// The three Worker surfaces:
//   - GET /authorize        : validate, stash a PendingRequest, 302 to the webmail consent URL (signed).
//   - GET /authorize/return : the webmail bounces back here (signed) with a single-use HANDOFF code; we
//                             mint OUR authorization code bound to that handoff and 302 to the agent.
//   - POST /token           : exchange code + PKCE verifier; REDEEM the handoff via the WEB service
//                             binding to get the child key, and build the token-set.
//
// Multi-org "Model D" (founder decision, final): one access token reaches ONLY the orgs explicitly
// authorized, never the human's whole org universe. The token is a SET of {org → child key}; the agent
// switches the active org with a tool, and adding an org re-runs consent for that org alone.
//
// Security invariants (audited black-box, AGENTS.md §5):
//   - Fail-closed everywhere. validateAccessToken returns null on anything off.
//   - PKCE S256 stays IN THE WORKER: the code_verifier is never sent to the webmail. `plain` is refused.
//   - Single-use: pending request (rid), handoff, authorization code — each consumed exactly once.
//   - redirect_uri exact-match against the client whitelist (no open redirect); state echoed.
//   - HMAC signs both 302 hops (mcp-consent.<rid>.<ctx> outbound, mcp-complete.<rid>.<handoff> inbound)
//     so a third party cannot forge a consent return NOR tamper with the signed ctx (scope + redirect
//     host) the webmail reads. The secret is shared with the webmail only.
//   - Anti-org-injection: attachOrg only when the redeem's ownerHash equals the token's owner — an
//     attacker holding the access token cannot graft an org without the owner's webmail session.
//   - Log hygiene: this module logs NOTHING — no child key, access token, handoff, verifier, ownerHash
//     or signature ever reaches a log line.

import type { FetchLike } from "../client.js";

// --- client registry ------------------------------------------------------------------------------
// Unchanged from R2d: a fixed first-party client plus RFC 7591 dynamically-registered clients, both
// resolved through resolveClient() and fenced by the SAME exact-match redirect whitelist.
export interface OAuthClient {
  clientId: string;
  redirectUris: readonly string[];
}

/** The registered clients. loopback + the MCP Inspector callback cover local use; claude.ai is hosted. */
export const DEFAULT_CLIENTS: readonly OAuthClient[] = [
  {
    clientId: "pombus-mcp",
    redirectUris: [
      "http://127.0.0.1:6274/oauth/callback",   // MCP Inspector default
      "http://localhost:6274/oauth/callback",
      "https://claude.ai/api/mcp/auth_callback", // a hosted MCP client's fixed callback
    ],
  },
];

// --- in-memory store ------------------------------------------------------------------------------
// In production this store lives inside ONE Durable Object (do-class.ts) every isolate reaches by RPC,
// so the OAuth hops (which land on different isolates) share state. The DO keeps everything in MEMORY
// on purpose, NOT ctx.storage: child keys and the owner hash must never touch disk at rest. Each map is
// capped (STORE_CAP). Methods are async so OAuthStore (in-process) and DurableObjectStore (across the
// DO boundary) share the ONE interface (OAuthStoreLike).

export interface PendingRequest {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  /** The agent's requested scope hint, carried through to the webmail via the rid's server state (the
   *  webmail reads it at redeem/consent-context, NOT off the URL). Back-compat / informational only. */
  scope: string;
  /** Present on the ADD-ORG flow: the link_token the agent carried to tie a new org to an EXISTING
   *  access token (select_organization). Absent on a first authorization. */
  linkToken?: string;
  expiresAt: number;
}

export interface IssuedCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  /** The single-use handoff the webmail minted; redeemed at /token for the child key. NOT the key. */
  handoffCode: string;
  /** Carried from the PendingRequest through the code so /token knows this is an add-org exchange. */
  linkToken?: string;
  expiresAt: number;
}

/** One authorized org inside a token-set: the minted child key for that org and its grant metadata. */
export interface OrgEntry {
  /** The minted, scoped, short-lived pod-key for THIS org. Opaque to the client; NEVER logged. */
  childKey: string;
  perms: string[];
  label: string;
  expiresAt: number;
}

/** The access token's value — a SET of orgs (Model D). `activeOrg` is the one the next core call uses;
 *  `owner` is the webmail-side owner hash that gates attachOrg (anti-injection); `tokenExp` bounds the
 *  whole set. Opaque to the client. NEVER logged. */
export interface LiveToken {
  activeOrg: string;
  orgs: Record<string, OrgEntry>;
  owner: string;
  tokenExp: number;
}

/** A dynamically-registered client (RFC 7591). Same shape every stored map uses so the cap's sweep +
 *  eviction works unchanged; the TTL only bounds growth, it is not a security timer. */
export interface RegisteredClient {
  redirectUris: readonly string[];
  expiresAt: number;
}

/** Ties a link_token to an existing access token (the ADD-ORG flow). Capped + single-use. Living in the
 *  store (not an HMAC of the access token) keeps it revocable and keeps the access token off the URL. */
export interface LinkRecord {
  accessToken: string;
  expiresAt: number;
}

/** Ceiling per map (sec audit). Pending requests + clients + links EVICT the oldest when full (a flood
 *  only rolls the window, never locks a human out); codes and tokens — which need a real credential —
 *  are refused instead, so no live grant is dropped. */
export const STORE_CAP = 1000;

function hasRoom<T extends { expiresAt: number }>(m: Map<string, T>): boolean {
  if (m.size < STORE_CAP) return true;
  const now = Date.now();
  for (const [k, v] of m) if (v.expiresAt < now) m.delete(k);
  return m.size < STORE_CAP;
}

/** The store contract, async on EVERY method so the in-process OAuthStore and the across-the-DO-boundary
 *  DurableObjectStore both satisfy it and the handlers await without knowing which side they are on. */
export interface OAuthStoreLike {
  putRequest(id: string, r: PendingRequest): Promise<void>;
  takeRequest(id: string): Promise<PendingRequest | undefined>;
  putCode(code: string, c: IssuedCode): Promise<boolean>;
  takeCode(code: string): Promise<IssuedCode | undefined>;
  tokenRoom(): Promise<boolean>;
  /** Create a token-set under an opaque access token. */
  putToken(token: string, t: LiveToken): Promise<void>;
  /** The whole token-set, or undefined when unknown/expired (swept by tokenExp). */
  getToken(token: string): Promise<LiveToken | undefined>;
  /** Attach/replace one org on an existing token-set — ONLY when ownerHash matches the token's owner
   *  (anti-injection). Returns false on owner mismatch or unknown/expired token. */
  attachOrg(token: string, orgId: string, entry: OrgEntry, ownerHash: string): Promise<boolean>;
  /** Point the token-set at `orgId` — only if it is an authorized org. Returns false otherwise. */
  setActiveOrg(token: string, orgId: string): Promise<boolean>;
  /** The active org's child key + grant, or undefined when the token/entry is gone or expired. The ONLY
   *  source of the credential a core call uses — org↔org isolation hinges on this being the sole path. */
  getActiveChild(token: string): Promise<{ orgId: string; childKey: string; perms: string[] } | undefined>;
  /** Tie a link_token to an access token (add-org flow). */
  putLink(linkToken: string, accessToken: string): Promise<boolean>;
  /** Resolve-and-consume a link_token → the access token it was tied to (single-use). */
  takeLink(linkToken: string): Promise<string | undefined>;
  putClient(clientId: string, redirectUris: readonly string[]): Promise<boolean>;
  getClient(clientId: string): Promise<readonly string[] | undefined>;
  reset(): Promise<void>;
}

export class OAuthStore implements OAuthStoreLike {
  private readonly requests = new Map<string, PendingRequest>();
  private readonly codes = new Map<string, IssuedCode>();
  private readonly tokens = new Map<string, LiveToken>();
  private readonly links = new Map<string, LinkRecord>();
  private readonly clients = new Map<string, RegisteredClient>();

  async putRequest(id: string, r: PendingRequest): Promise<void> {
    if (!hasRoom(this.requests)) this.requests.delete(this.requests.keys().next().value!);
    this.requests.set(id, r);
  }
  async takeRequest(id: string): Promise<PendingRequest | undefined> {
    const r = this.requests.get(id);
    if (!r) return undefined;
    this.requests.delete(id);
    if (r.expiresAt < Date.now()) return undefined;
    return r;
  }
  async putCode(code: string, c: IssuedCode): Promise<boolean> {
    if (!hasRoom(this.codes)) return false;
    this.codes.set(code, c);
    return true;
  }
  /** Single-use: take and DELETE. Inside a DO the input gate serializes this get-then-delete, so a
   *  replay racing the first exchange cannot both read the same code. */
  async takeCode(code: string): Promise<IssuedCode | undefined> {
    const c = this.codes.get(code);
    if (!c) return undefined;
    this.codes.delete(code);
    if (c.expiresAt < Date.now()) return undefined;
    return c;
  }
  /** Checked BEFORE /token builds a token-set, so a full store never strands a freshly redeemed key. The
   *  token map is keyed on `tokenExp` (not the shared `expiresAt`), so it sweeps its own expired sets
   *  before judging room — no eviction of a live grant (unlike pending requests, a token is refused when
   *  truly full, so nobody's active session is dropped). */
  async tokenRoom(): Promise<boolean> {
    if (this.tokens.size < STORE_CAP) return true;
    const now = Date.now();
    for (const [k, v] of this.tokens) if (v.tokenExp < now) this.tokens.delete(k);
    return this.tokens.size < STORE_CAP;
  }
  async putToken(token: string, t: LiveToken): Promise<void> {
    this.tokens.set(token, t);
  }
  async getToken(token: string): Promise<LiveToken | undefined> {
    const t = this.tokens.get(token);
    if (!t) return undefined;
    if (t.tokenExp < Date.now()) {
      this.tokens.delete(token);
      return undefined;
    }
    return t;
  }
  async attachOrg(token: string, orgId: string, entry: OrgEntry, ownerHash: string): Promise<boolean> {
    const t = await this.getToken(token);
    if (!t) return false;
    if (t.owner !== ownerHash) return false; // anti-injection: only the owner's webmail session may add
    t.orgs[orgId] = entry;
    return true;
  }
  async setActiveOrg(token: string, orgId: string): Promise<boolean> {
    const t = await this.getToken(token);
    if (!t) return false;
    if (!(orgId in t.orgs)) return false;
    t.activeOrg = orgId;
    return true;
  }
  async getActiveChild(
    token: string,
  ): Promise<{ orgId: string; childKey: string; perms: string[] } | undefined> {
    const t = await this.getToken(token);
    if (!t) return undefined;
    const entry = t.orgs[t.activeOrg];
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) return undefined; // the active org's key lapsed; re-authorize
    return { orgId: t.activeOrg, childKey: entry.childKey, perms: entry.perms };
  }
  async putLink(linkToken: string, accessToken: string): Promise<boolean> {
    if (!hasRoom(this.links)) this.links.delete(this.links.keys().next().value!);
    this.links.set(linkToken, { accessToken, expiresAt: Date.now() + REQUEST_TTL_MS });
    return true;
  }
  async takeLink(linkToken: string): Promise<string | undefined> {
    const l = this.links.get(linkToken);
    if (!l) return undefined;
    this.links.delete(linkToken);
    if (l.expiresAt < Date.now()) return undefined;
    return l.accessToken;
  }
  /** /register is PUBLIC — cap it like pending requests: sweep, then EVICT the oldest rather than refuse,
   *  so a flood only rolls the window. Never returns false in practice; the boolean keeps putCode's shape. */
  async putClient(clientId: string, redirectUris: readonly string[]): Promise<boolean> {
    if (!hasRoom(this.clients)) this.clients.delete(this.clients.keys().next().value!);
    this.clients.set(clientId, { redirectUris, expiresAt: Date.now() + REGISTER_TTL_MS });
    return true;
  }
  async getClient(clientId: string): Promise<readonly string[] | undefined> {
    const c = this.clients.get(clientId);
    if (!c) return undefined;
    if (c.expiresAt < Date.now()) {
      this.clients.delete(clientId);
      return undefined;
    }
    return c.redirectUris;
  }
  /** Test seam: wipe everything between cases. */
  async reset(): Promise<void> {
    this.requests.clear();
    this.codes.clear();
    this.tokens.clear();
    this.links.clear();
    this.clients.clear();
  }
}

/** The process-wide store the Worker uses when no Durable Object is bound (tests, `wrangler dev` before
 *  the DO migration). A test can construct its own OAuthStore instead. */
export const store = new OAuthStore();

// --- lifetimes ------------------------------------------------------------------------------------
const REQUEST_TTL_MS = 10 * 60 * 1000; // a human has 10 min to finish consent on the webmail
const CODE_TTL_MS = 60 * 1000;         // authorization code: 60s, single-use
const TOKEN_TTL_MS = 60 * 60 * 1000;   // access token + minted child keys: 1h
const REGISTER_TTL_MS = 30 * 24 * 60 * 60 * 1000; // a dynamic client registration (bounds growth only)

// --- crypto helpers (Web Crypto, present in Workers and Node >=20) --------------------------------

/** base64url WITHOUT padding (RFC 7636 §A). */
function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A cryptographically-random opaque token (32 bytes → 43 base64url chars). Unguessable: request ids,
 *  authorization codes, access tokens, link tokens. */
function randomToken(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b64url(b);
}

/** PKCE S256: BASE64URL(SHA-256(ASCII(code_verifier))). Compared (constant-time) against the stored
 *  challenge AT THE WORKER — the verifier never leaves this process to the webmail. */
async function s256(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return b64url(new Uint8Array(digest));
}

/** HMAC-SHA256(secret, message) → base64url. Signs both 302 hops so a third party cannot forge a
 *  consent return. stdlib Web Crypto, no dependency. */
async function hmac(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64url(new Uint8Array(sig));
}

/** Constant-time string compare (timing-oracle fence on code_challenge / signatures). Both operands are
 *  base64url, so byte length equals char length. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// --- helpers --------------------------------------------------------------------------------------

function findClient(clients: readonly OAuthClient[], clientId: string): OAuthClient | undefined {
  return clients.find((c) => c.clientId === clientId);
}

/** Resolve a client_id: the FIXED registry first, then a DYNAMICALLY-REGISTERED client (RFC 7591). A
 *  registered client is its stored redirect_uris in the same shape, so the exact-match fence runs
 *  identically. Unknown → undefined (fail-closed). */
async function resolveClient(deps: OAuthDeps, clientId: string): Promise<OAuthClient | undefined> {
  const fixed = findClient(deps.clients, clientId);
  if (fixed) return fixed;
  const uris = await deps.store.getClient(clientId);
  if (uris) return { clientId, redirectUris: uris };
  return undefined;
}

/** redirect_uri exact-match against the client's whitelist — byte-identical or rejected (open-redirect fence). */
function redirectAllowed(client: OAuthClient, redirectUri: string): boolean {
  return client.redirectUris.some((u) => u === redirectUri);
}

/** A content-free 400. OAuth errors on the AUTHORIZE side must not become an oracle; `detail` is a fixed
 *  non-sensitive string we choose (never caller input, never a secret). */
function badRequest(detail: string): Response {
  return new Response(detail, {
    status: 400,
    headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff" },
  });
}

/** Content-free 503 — the store is full, or a required binding/secret is missing (fail-closed). */
function unavailable(): Response {
  return new Response(null, { status: 503, headers: { "retry-after": "60" } });
}

/** Both POST bodies are a handful of short form fields. 8 KiB stops an arbitrary buffered body. */
export const MAX_FORM_BYTES = 8 * 1024;

async function readFormCapped(req: Request): Promise<FormData | null> {
  const chunks = await readBodyCapped(req);
  if (!chunks) return null;
  const headers = { "content-type": req.headers.get("content-type") ?? "" };
  try {
    return await new Response(new Blob(chunks), { headers }).formData();
  } catch {
    return null;
  }
}

/** Read at most MAX_FORM_BYTES, enforced on the bytes actually read (not a content-length the caller
 *  may omit or lie about). null = too large or unreadable. */
async function readBodyCapped(req: Request): Promise<Uint8Array[] | null> {
  if (Number(req.headers.get("content-length") ?? 0) > MAX_FORM_BYTES) return null;
  const reader = req.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_FORM_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  }
  return chunks;
}

async function readJsonCapped(req: Request): Promise<Record<string, unknown> | null> {
  const chunks = await readBodyCapped(req);
  if (!chunks) return null;
  try {
    const text = await new Response(new Blob(chunks)).text();
    const parsed = JSON.parse(text) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function tooLarge(): Response {
  return new Response(null, { status: 413 });
}

/** The RFC 6749 token error (coarse OAuth code only — never which part failed). */
function tokenError(error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** Build a 302 to the redirect_uri with code+state (or error+state). The redirect_uri was already proven
 *  an exact whitelist match, so this cannot be an open redirect. */
function oauthRedirect(redirectUri: string, params: Record<string, string>): Response {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return new Response(null, { status: 302, headers: { location: u.toString() } });
}

// --- the webmail service binding (contract R3 codes against; faked in tests) ----------------------

/** What the webmail returns when the Worker redeems a handoff: the minted child key for the org the
 *  human consented to, plus the grant metadata and the owner hash that gates attachOrg. null = the
 *  handoff is unknown/consumed/expired on the webmail side. */
export interface RedeemedHandoff {
  childKey: string;
  orgId: string;
  perms: string[];
  label: string;
  ownerHash: string;
}

/** The RPC surface of the WEB service binding (env.WEB). Single-use on the webmail side. */
export interface WebBinding {
  redeemMcpHandoff(handoffCode: string): Promise<RedeemedHandoff | null>;
}

// --- handler dependencies -------------------------------------------------------------------------

/** Options for the OAuth handlers: the client registry, the store, and the R3 webmail seams (consent
 *  URL, the HMAC secret shared with the webmail, and the WEB binding). The webmail ones are OPTIONAL so
 *  the fail-closed default holds when they are unset. The core seams (coreFetch/coreBaseUrl) survive for
 *  the MCP path's own wiring shape, which a test injects the same way. */
export interface OAuthDeps {
  clients: readonly OAuthClient[];
  store: OAuthStoreLike;
  coreFetch?: FetchLike;
  coreBaseUrl?: string;
  /** The webmail consent screen URL the Worker 302s to. Absent → /authorize cannot delegate → 503. */
  webConsentUrl?: string;
  /** The HMAC secret shared with the webmail. Absent → cannot sign/verify the 302 hops → fail-closed. */
  webLinkSecret?: string;
  /** The WEB service binding used to redeem a handoff at /token. Absent → /token cannot mint → 503. */
  web?: WebBinding;
}

// --- GET /authorize (delegating front-end) --------------------------------------------------------

/** Validate the authorization request and 302 to the WEBMAIL consent screen. Everything that must stay
 *  server-side — client, redirect_uri, PKCE challenge, state — is stashed in a single-use PendingRequest
 *  under a random `rid`; only `rid` + an HMAC signature travel to the webmail. Rejects (400, no redirect)
 *  when the client/redirect_uri is unknown; 400 for every other protocol error (the request never
 *  reached a trusted redirect). Fail-closed: no webmail secret/URL configured → 503, never a redirect. */
export async function handleAuthorizeGet(req: Request, deps: OAuthDeps): Promise<Response> {
  const u = new URL(req.url);
  const q = u.searchParams;
  const clientId = q.get("client_id") ?? "";
  const redirectUri = q.get("redirect_uri") ?? "";
  const responseType = q.get("response_type") ?? "";
  const codeChallenge = q.get("code_challenge") ?? "";
  const method = q.get("code_challenge_method") ?? "";
  const state = q.get("state") ?? "";
  const scope = q.get("scope") ?? "";
  const linkTokenRaw = q.get("link_token") ?? "";

  const client = await resolveClient(deps, clientId);
  if (!client) return badRequest("invalid_client");
  if (!redirectAllowed(client, redirectUri)) return badRequest("invalid_redirect_uri");
  if (responseType !== "code") return badRequest("unsupported_response_type");
  if (method !== "S256") return badRequest("invalid_pkce"); // plain is forbidden (OAuth 2.1)
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)) return badRequest("invalid_pkce");
  if (!state) return badRequest("invalid_state");

  // Fail-closed: without the webmail consent URL and the shared secret we cannot delegate OR sign the
  // hop — refuse rather than bounce somewhere unsigned. 503 is honest ("unavailable"), not an oracle.
  if (!deps.webConsentUrl || !deps.webLinkSecret) return unavailable();

  // The ADD-ORG flow (select_organization): if a valid link_token is present, consume it and carry the
  // tied access token into the PendingRequest so /token attaches the new org to the SAME access token.
  // An invalid/expired link_token is simply ignored (treated as a first authorization) — never an error
  // that would tell an attacker whether a link_token exists.
  let linkToken: string | undefined;
  if (linkTokenRaw) {
    const tied = await deps.store.takeLink(linkTokenRaw);
    if (tied) linkToken = tied;
  }

  const rid = randomToken();
  await deps.store.putRequest(rid, {
    clientId,
    redirectUri,
    state,
    codeChallenge,
    scope,
    ...(linkToken !== undefined ? { linkToken } : {}),
    expiresAt: Date.now() + REQUEST_TTL_MS,
  });

  // The webmail needs the scope (to pre-check the toggles) and the agent's host (to show "who is
  // asking") — and there is no reverse channel. We carry that context SIGNED on the 302: scope and
  // redirect host are not secrets (OAuth already puts scope/redirect on the authorize URL), and
  // folding the ctx into the HMAC input makes it tamper-evident. PKCE/redirect_uri/client/state stay
  // in the Worker's PendingRequest and never travel.
  const ctx = b64url(new TextEncoder().encode(JSON.stringify({ scope, redirectHost: new URL(redirectUri).host })));
  const sig = await hmac(deps.webLinkSecret, `mcp-consent.${rid}.${ctx}`);
  const consent = new URL(deps.webConsentUrl);
  consent.searchParams.set("rid", rid);
  consent.searchParams.set("ctx", ctx);
  consent.searchParams.set("sig", sig);
  return new Response(null, { status: 302, headers: { location: consent.toString() } });
}

// --- GET /authorize/return (webmail → worker) -----------------------------------------------------

/** The webmail bounces the human back here after consent, carrying the single-use `handoff` it minted,
 *  signed with mcp-complete.<rid>.<handoff>. We verify the signature, consume the PendingRequest (rid),
 *  and issue OUR authorization code bound to redirect_uri + PKCE challenge + the handoff. Then 302 to the
 *  agent's redirect_uri with ?code&state (exact-match already proven — no open redirect). A bad signature
 *  or unknown rid is a bare 400 (no redirect — we have nothing trusted to bounce to). */
export async function handleAuthorizeReturn(req: Request, deps: OAuthDeps): Promise<Response> {
  const q = new URL(req.url).searchParams;
  const rid = q.get("rid") ?? "";
  const handoff = q.get("handoff") ?? "";
  const sig = q.get("sig") ?? "";

  if (!deps.webLinkSecret) return unavailable(); // fail-closed: cannot verify the webmail's signature
  if (!rid || !handoff || !sig) return badRequest("invalid_request");

  const expected = await hmac(deps.webLinkSecret, `mcp-complete.${rid}.${handoff}`);
  if (!timingSafeEqual(sig, expected)) return badRequest("invalid_request"); // forged return

  const pending = await deps.store.takeRequest(rid); // single-use
  if (!pending) return badRequest("invalid_request");

  // Re-check the client/redirect defensively (fail-closed) before building any redirect.
  const client = await resolveClient(deps, pending.clientId);
  if (!client || !redirectAllowed(client, pending.redirectUri)) return badRequest("invalid_request");

  const code = randomToken();
  const ok = await deps.store.putCode(code, {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    handoffCode: handoff,
    ...(pending.linkToken !== undefined ? { linkToken: pending.linkToken } : {}),
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  if (!ok) return oauthRedirect(pending.redirectUri, { error: "temporarily_unavailable", state: pending.state });
  return oauthRedirect(pending.redirectUri, { code, state: pending.state });
}

// --- POST /token (redeem via the WEB service binding) ---------------------------------------------

/** Exchange authorization_code + code_verifier for an access token. Verifies PKCE S256 (IN THE WORKER),
 *  the bound redirect_uri + client, consumes the single-use code, then REDEEMS the handoff via the WEB
 *  binding to obtain the child key + org metadata. On a first authorization it builds a fresh token-set
 *  (one org); on an add-org exchange (link_token present) it attaches the org to the EXISTING token-set
 *  only if the redeem's ownerHash matches the token's owner (anti-injection). The child key and handoff
 *  are never placed in the response or a log. */
export async function handleToken(req: Request, deps: OAuthDeps): Promise<Response> {
  const form = await readFormCapped(req);
  if (!form) return tooLarge();
  const grantType = String(form.get("grant_type") ?? "");
  const code = String(form.get("code") ?? "");
  const verifier = String(form.get("code_verifier") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const clientId = String(form.get("client_id") ?? "");

  if (grantType !== "authorization_code") return tokenError("unsupported_grant_type");

  // Full token store: refuse BEFORE consuming the code (the client can retry) and BEFORE redeeming.
  if (!(await deps.store.tokenRoom())) return unavailable();
  const issued = await deps.store.takeCode(code); // single-use
  if (!issued) return tokenError("invalid_grant");
  if (issued.clientId !== clientId) return tokenError("invalid_grant");
  if (issued.redirectUri !== redirectUri) return tokenError("invalid_grant");
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return tokenError("invalid_grant");
  const computed = await s256(verifier);
  if (!timingSafeEqual(computed, issued.codeChallenge)) return tokenError("invalid_grant");

  // Fail-closed: no WEB binding configured → we cannot obtain a child key → 503 (not an invalid_grant,
  // which would wrongly blame the client). The code was already consumed; the client re-authorizes.
  if (!deps.web) return unavailable();

  let redeemed: RedeemedHandoff | null;
  try {
    redeemed = await deps.web.redeemMcpHandoff(issued.handoffCode);
  } catch {
    return unavailable(); // the webmail is unreachable — availability failure, not a bad grant
  }
  if (!redeemed) return tokenError("invalid_grant"); // unknown/consumed handoff

  const now = Date.now();
  const entry: OrgEntry = {
    childKey: redeemed.childKey,
    perms: redeemed.perms,
    label: redeemed.label,
    expiresAt: now + TOKEN_TTL_MS,
  };

  if (issued.linkToken === undefined) {
    // First authorization: a fresh token-set with exactly one org, pointed at it.
    const accessToken = randomToken();
    await deps.store.putToken(accessToken, {
      activeOrg: redeemed.orgId,
      orgs: { [redeemed.orgId]: entry },
      owner: redeemed.ownerHash,
      tokenExp: now + TOKEN_TTL_MS,
    });
    return tokenResponse(accessToken);
  }

  // Add-org: resolve the existing access token the link_token was tied to, and attach ONLY if the
  // redeem's ownerHash matches the token's owner. The link_token was already consumed at /authorize;
  // here we resolve it to the access token it carried through the PendingRequest → IssuedCode.
  const accessToken = issued.linkToken;
  const attached = await deps.store.attachOrg(accessToken, redeemed.orgId, entry, redeemed.ownerHash);
  if (!attached) return tokenError("invalid_grant"); // owner mismatch or token gone — never grafts
  await deps.store.setActiveOrg(accessToken, redeemed.orgId);
  // The agent already holds this access token; return it again (idempotent confirmation).
  return tokenResponse(accessToken);
}

/** The RFC 6749 §5.1 success body. No `scope`: we do not enumerate the grant (the child key is it). */
function tokenResponse(accessToken: string): Response {
  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(TOKEN_TTL_MS / 1000),
    }),
    { status: 200, headers: { "content-type": "application/json", "cache-control": "no-store" } },
  );
}

// --- POST /register (Dynamic Client Registration, RFC 7591) ---------------------------------------

function registerError(error: string): Response {
  return new Response(JSON.stringify({ error }), {
    status: 400,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

/** The ONLY redirect_uri shapes a dynamic client may register (anti-open-redirect anchor): https, or a
 *  loopback (127.0.0.1 / localhost) http callback. Anything else rejects the WHOLE registration. */
function isAllowedRedirectUri(raw: unknown): boolean {
  if (typeof raw !== "string" || raw.length === 0) return false;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:" && (u.hostname === "127.0.0.1" || u.hostname === "localhost")) return true;
  return false;
}

/** Handle POST /register. Validates redirect_uris, generates a random public client_id, stores the
 *  registration (capped), returns 201 with the RFC 7591 client-information fields. No secret issued —
 *  PKCE authenticates the exchange. Nothing is logged. */
export async function handleRegister(req: Request, deps: OAuthDeps): Promise<Response> {
  const body = await readJsonCapped(req);
  if (!body) return registerError("invalid_client_metadata");

  const redirectUris = body["redirect_uris"];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return registerError("invalid_redirect_uri");
  }
  for (const uri of redirectUris) {
    if (!isAllowedRedirectUri(uri)) return registerError("invalid_redirect_uri");
  }
  const uris = redirectUris as string[];

  const clientId = randomToken(); // public, high-entropy; no secret
  await deps.store.putClient(clientId, uris);

  return new Response(
    JSON.stringify({
      client_id: clientId,
      redirect_uris: uris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    }),
    { status: 201, headers: { "content-type": "application/json", "cache-control": "no-store" } },
  );
}

// --- Bearer resolution ----------------------------------------------------------------------------

/** Resolve a Bearer access token to the child key of its ACTIVE org (Model D), or null to refuse
 *  (fail-closed). getActiveChild is the ONLY source of the credential — org↔org isolation depends on no
 *  other path producing a child key. The returned value is the minted child key; NEVER log it. */
export async function validateAccessToken(
  authorizationHeader: string | null,
  store: OAuthStoreLike,
): Promise<string | null> {
  const m = /^Bearer (.+)$/.exec((authorizationHeader ?? "").trim());
  const token = m?.[1]?.trim();
  if (!token) return null;
  const active = await store.getActiveChild(token);
  return active ? active.childKey : null;
}
