// R3 — the hand-written OAuth 2.1 Authorization Server for the Pombus remote MCP endpoint, now a
// DELEGATING front-end (the "Sign in with the webmail" pattern). The HUMAN consent no longer happens
// here: it runs in the WEBMAIL (mail.pombus.com), the origin that holds the human's session cookie and
// renders the toggle-based consent screen. The Worker keeps everything that must NEVER leave it — PKCE,
// the redirect_uri whitelist, the client registry, state, the code — and delegates only the human
// decision, exactly as an OAuth client delegates to an identity provider.
//
// The three Worker surfaces:
//   - GET /authorize        : validate, sign the request into a stateless `rid`, 302 to the webmail consent URL.
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
//   - Single-use: rid (useRid), handoff, authorization code — each consumed exactly once.
//   - Nothing anonymous writes the store: the pending request (rid) and a dynamic client (client_id) are
//     tokens signed with MCP_STATE_SECRET (Worker-only; PREV verifies during a rotation), not store rows.
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

export interface IssuedCode {
  /** sha256 (base64url) of the client_id the request was authorized for — a stateless client_id can be ~1 KB,
   *  and the rid that carries this travels in URLs and the webmail's consent cookie. /token compares the hash. */
  clientIdHash: string;
  redirectUri: string;
  codeChallenge: string;
  /** The single-use handoff the webmail minted; redeemed at /token for the child key. NOT the key. */
  handoffCode: string;
  /** The access token a link_token tied to (resolved at /authorize/return) — /token's add-org exchange. */
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

/** Ties a link_token to an existing access token (the ADD-ORG flow). Capped + single-use. Living in the
 *  store (not an HMAC of the access token) keeps it revocable and keeps the access token off the URL. */
export interface LinkRecord {
  accessToken: string;
  expiresAt: number;
}

/** Ceiling per map (sec audit). Links and used rids EVICT the oldest when full; codes and tokens — which
 *  need a real credential — are refused instead, so no live grant is dropped. Nothing here is written by an
 *  anonymous request any more: pending requests and dynamic clients are signed tokens (no store), and every
 *  write left happens after a human consented on the webmail or holds a valid access token. */
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
  /** Mark a (hashed) rid as used; false when it already was — the rid is a signed token, single-use by this. */
  useRid(ridHash: string, expiresAt: number): Promise<boolean>;
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
  reset(): Promise<void>;
}

export class OAuthStore implements OAuthStoreLike {
  private readonly usedRids = new Map<string, { expiresAt: number }>();
  private readonly codes = new Map<string, IssuedCode>();
  private readonly tokens = new Map<string, LiveToken>();
  private readonly links = new Map<string, LinkRecord>();

  /** Written only by /authorize/return AFTER the webmail's signature checked (a human consented), so a flood
   *  cannot reach it; full → evict the oldest. An evicted rid's return URL could be replayed (the webmail's
   *  signature is deterministic) — what still contains that is the handoff, single-use on the webmail side
   *  (a second /token redeem finds nothing), plus PKCE: only the agent holding the verifier can exchange a code. */
  async useRid(ridHash: string, expiresAt: number): Promise<boolean> {
    if (this.usedRids.has(ridHash)) return false;
    if (!hasRoom(this.usedRids)) this.usedRids.delete(this.usedRids.keys().next().value!);
    this.usedRids.set(ridHash, { expiresAt });
    return true;
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
   *  before judging room — no eviction of a live grant (a token is refused when truly full, so nobody's
   *  active session is dropped). */
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
  /** Test seam: wipe everything between cases. */
  async reset(): Promise<void> {
    this.usedRids.clear();
    this.codes.clear();
    this.tokens.clear();
    this.links.clear();
  }
}

/** The process-wide store the Worker uses when no Durable Object is bound (tests, `wrangler dev` before
 *  the DO migration). A test can construct its own OAuthStore instead. */
export const store = new OAuthStore();

// --- lifetimes ------------------------------------------------------------------------------------
const REQUEST_TTL_MS = 10 * 60 * 1000; // a human has 10 min to finish consent on the webmail
const CODE_TTL_MS = 60 * 1000;         // authorization code: 60s, single-use
const TOKEN_TTL_MS = 60 * 60 * 1000;   // access token + minted child keys: 1h
// Caps that keep the signed rid small: it rides the consent URL, the return URL and the webmail's consent cookie.
const MAX_STATE = 256;
const MAX_SCOPE = 256;
const MAX_REDIRECT = 512;
const MAX_DCR_URIS = 5;
const MAX_DCR_JSON = 1024;   // the signed client_id carries its redirect_uris

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

function b64urlDecode(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** A signed stateless token: `b64url(JSON) . HMAC(HMAC(secret, label), payload)`. The label separates the
 *  rid from the client_id (a token minted as one never verifies as the other). Signed with the CURRENT secret
 *  (the first); verified against current and PREVIOUS, so a rotation never breaks an in-flight token. */
async function seal(secrets: readonly string[], label: string, obj: unknown): Promise<string> {
  const payload = b64url(new TextEncoder().encode(JSON.stringify(obj)));
  return `${payload}.${await hmac(await hmac(secrets[0] ?? "", label), payload)}`;
}

/** The object a seal() token carries, or null when malformed, unsigned or signed with an unknown key. */
async function unseal(secrets: readonly string[], label: string, token: string): Promise<Record<string, unknown> | null> {
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const [payload, sig] = parts as [string, string];
  let ok = false;
  for (const s of secrets) if (timingSafeEqual(sig, await hmac(await hmac(s, label), payload))) ok = true;
  if (!ok) return null;
  const bytes = b64urlDecode(payload);
  if (!bytes) return null;
  try {
    const o: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return o !== null && typeof o === "object" && !Array.isArray(o) ? (o as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const RID_LABEL = "mcp-rid-v1";
const CLIENT_LABEL = "mcp-client-v1";

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;

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

/** Resolve a client_id: the FIXED registry first, then a DYNAMIC client (RFC 7591), which is now the SIGNED
 *  client_id itself carrying its redirect_uris — nothing stored, so /register writes nothing and a
 *  registration survives deploys. Unsigned, tampered or unknown-key → undefined (fail-closed). */
async function resolveClient(deps: OAuthDeps, clientId: string): Promise<OAuthClient | undefined> {
  const fixed = findClient(deps.clients, clientId);
  if (fixed) return fixed;
  if (!deps.stateSecrets?.length) return undefined;
  const c = await unseal(deps.stateSecrets, CLIENT_LABEL, clientId);
  const u = c?.["u"];
  // the same redirect fence /register applied: a client_id can never carry a uri /register would refuse
  if (!Array.isArray(u) || u.length === 0 || !u.every(isAllowedRedirectUri)) return undefined;
  return { clientId, redirectUris: u as string[] };
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

/** The token request body, application/x-www-form-urlencoded ONLY (RFC 6749 §4.1.3) — the caller refuses
 *  any other content-type first. null = too large or unreadable. */
async function readFormCapped(req: Request): Promise<URLSearchParams | null> {
  const chunks = await readBodyCapped(req);
  if (!chunks) return null;
  return new URLSearchParams(await new Response(new Blob(chunks)).text());   // a lenient parser: never throws
}

/** RFC 6749 §4.1.3: the client sends the token request as application/x-www-form-urlencoded. multipart
 *  (or anything else) is refused before a byte is read: one body format, one parser. */
const isUrlEncoded = (req: Request): boolean =>
  /^application\/x-www-form-urlencoded\s*(;|$)/i.test(req.headers.get("content-type") ?? "");

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
  /** The Worker-only secrets that sign the stateless rid and client_id: [current, previous?]. Signs with the
   *  first, verifies with both (rotation). Empty/absent → /authorize and /register fail closed (503). */
  stateSecrets?: readonly string[];
  /** The WEB service binding used to redeem a handoff at /token. Absent → /token cannot mint → 503. */
  web?: WebBinding;
}

// --- GET /authorize (delegating front-end) --------------------------------------------------------

/** Validate the authorization request and 302 to the WEBMAIL consent screen. The request (client hash,
 *  redirect_uri, PKCE challenge, state, scope, link_token) travels as a SIGNED `rid` — nothing is written to
 *  the store, so an anonymous flood of /authorize has nothing to fill or evict. None of it is secret (all of
 *  it is on this very URL); the signature makes it tamper-evident, and /authorize/return makes it single-use. Rejects (400, no redirect)
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

  if (!deps.stateSecrets?.length) return unavailable();   // cannot verify a dynamic client_id nor sign a rid
  const client = await resolveClient(deps, clientId);
  if (!client) return badRequest("invalid_client");
  if (!redirectAllowed(client, redirectUri)) return badRequest("invalid_redirect_uri");
  if (responseType !== "code") return badRequest("unsupported_response_type");
  if (method !== "S256") return badRequest("invalid_pkce"); // plain is forbidden (OAuth 2.1)
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeChallenge)) return badRequest("invalid_pkce");
  // Caps in BYTES (UTF-8), not UTF-16 units: the rid rides the webmail's consent cookie (4 KB).
  if (!state || utf8Len(state) > MAX_STATE) return badRequest("invalid_state");
  if (utf8Len(scope) > MAX_SCOPE) return badRequest("invalid_scope");

  // Fail-closed: without the webmail consent URL and the shared secret we cannot delegate OR sign the
  // hop — refuse rather than bounce somewhere unsigned. 503 is honest ("unavailable"), not an oracle.
  if (!deps.webConsentUrl || !deps.webLinkSecret) return unavailable();

  // The ADD-ORG flow (select_organization): the RAW link_token rides the rid and is consumed at
  // /authorize/return — resolving it here would put the ACCESS token it ties to into a URL. Only a
  // well-formed one is carried (an odd one is dropped: treated as a first authorization, never an error).
  const linkToken = /^[A-Za-z0-9_-]{1,64}$/.test(linkTokenRaw) ? linkTokenRaw : undefined;   // minted: 43 b64url
  const rid = await seal(deps.stateSecrets, RID_LABEL, {
    c: await s256(clientId),
    r: redirectUri,
    s: state,
    ch: codeChallenge,
    ...(linkToken !== undefined ? { lt: linkToken } : {}),
    e: Date.now() + REQUEST_TTL_MS,
  });

  // The webmail needs the scope (to pre-check the toggles) and the agent's host (to show "who is
  // asking") — and there is no reverse channel. We carry that context SIGNED on the 302: scope and
  // redirect host are not secrets (OAuth already puts scope/redirect on the authorize URL), and
  // folding the ctx into the HMAC input makes it tamper-evident. The rid is opaque to the webmail.
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
 *  signed with mcp-complete.<rid>.<handoff>. We verify that signature AND the rid's own, consume the rid,
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

  // The rid is OUR signed request: the client and redirect_uri were checked at /authorize before it was
  // signed, so a valid signature is that check. Expired → refuse; a second use → refuse (useRid).
  if (!deps.stateSecrets?.length) return unavailable();
  const p = await unseal(deps.stateSecrets, RID_LABEL, rid);
  const [c, r, s, ch, e, lt] = [p?.["c"], p?.["r"], p?.["s"], p?.["ch"], p?.["e"], p?.["lt"]];
  if (typeof c !== "string" || typeof r !== "string" || typeof s !== "string" || typeof ch !== "string"
      || typeof e !== "number") {
    return badRequest("invalid_request");
  }
  if (e < Date.now()) return badRequest("invalid_request");
  if (!(await deps.store.useRid(await s256(rid), e))) return badRequest("invalid_request"); // single-use

  // ADD-ORG: consume the link_token now (single-use) → the access token it ties to. Unknown/expired is
  // treated as a first authorization, exactly as before (never an oracle on whether it existed).
  const linkToken = typeof lt === "string" ? await deps.store.takeLink(lt) : undefined;

  const code = randomToken();
  const ok = await deps.store.putCode(code, {
    clientIdHash: c,
    redirectUri: r,
    codeChallenge: ch,
    handoffCode: handoff,
    ...(linkToken !== undefined ? { linkToken } : {}),
    expiresAt: Date.now() + CODE_TTL_MS,
  });
  if (!ok) return oauthRedirect(r, { error: "temporarily_unavailable", state: s });
  return oauthRedirect(r, { code, state: s });
}

// --- POST /token (redeem via the WEB service binding) ---------------------------------------------

/** Exchange authorization_code + code_verifier for an access token. Verifies PKCE S256 (IN THE WORKER),
 *  the bound redirect_uri + client, consumes the single-use code, then REDEEMS the handoff via the WEB
 *  binding to obtain the child key + org metadata. On a first authorization it builds a fresh token-set
 *  (one org); on an add-org exchange (link_token present) it attaches the org to the EXISTING token-set
 *  only if the redeem's ownerHash matches the token's owner (anti-injection). The child key and handoff
 *  are never placed in the response or a log. */
export async function handleToken(req: Request, deps: OAuthDeps): Promise<Response> {
  if (!isUrlEncoded(req)) return tokenError("invalid_request");
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
  if (!timingSafeEqual(issued.clientIdHash, await s256(clientId))) return tokenError("invalid_grant");
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
  // redeem's ownerHash matches the token's owner. The link_token was consumed at /authorize/return, which
  // put the access token it tied to into the IssuedCode.
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

/** Handle POST /register. Validates redirect_uris and returns a SIGNED public client_id that carries them
 *  (RFC 7591 client-information fields, 201). Nothing is stored: a flood of /register fills nothing, and the
 *  registration survives deploys. No secret issued — PKCE authenticates the exchange. Nothing is logged. */
export async function handleRegister(req: Request, deps: OAuthDeps): Promise<Response> {
  if (!deps.stateSecrets?.length) return unavailable();
  const body = await readJsonCapped(req);
  if (!body) return registerError("invalid_client_metadata");

  const redirectUris = body["redirect_uris"];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || redirectUris.length > MAX_DCR_URIS) {
    return registerError("invalid_redirect_uri");
  }
  for (const uri of redirectUris) {
    if (!isAllowedRedirectUri(uri)) return registerError("invalid_redirect_uri");
  }
  const uris = redirectUris as string[];
  if (uris.some((u) => u.length > MAX_REDIRECT) || JSON.stringify(uris).length > MAX_DCR_JSON) {
    return registerError("invalid_redirect_uri");
  }

  const clientId = await seal(deps.stateSecrets, CLIENT_LABEL, { u: uris }); // public; no secret

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
