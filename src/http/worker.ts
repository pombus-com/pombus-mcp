// R3 — the Pombus MCP server over Streamable-HTTP in a Worker, behind a DELEGATING OAuth 2.1 front.
//
// The human consent no longer runs here: the Worker 302s to the WEBMAIL (mail.pombus.com) and the
// webmail — the origin that holds the human's session cookie and the toggle-based consent screen —
// mints the scoped child key and hands it back via a single-use handoff the Worker redeems over the WEB
// service binding. The agent never sees the child key; the Worker holds the opaque access token → child
// key mapping (oauth.ts, a per-org token-set: Model D multi-org).
//
// Two credential paths (AgentMail parity):
//   - `authorization: Bearer <access-token>`  → the OAuth/multi-org path: resolve the ACTIVE org's child
//     key from the token-set, expose the org tools (list/select_organization).
//   - `x-api-key: <pod-key>`                   → the key IS the credential (one org, stdio/Cursor/Windsurf
//     style); org tools are NOT exposed. No token-set, no multi-org.
//   - BOTH headers present                     → 400 invalid_request (ambiguous; refuse).
//
// OAuth surfaces (no Bearer required; they ISSUE/complete the Bearer): GET /authorize (302 to webmail),
// GET /authorize/return (webmail bounce-back), POST /token (redeem). Everything else is the MCP endpoint
// and is fail-closed: no valid credential → 401, the Server is never built, the core never touched.
//
// Transport: WebStandardStreamableHTTPServerTransport (SDK 1.32.1), stateless (one per request).
//
// Log hygiene (AGENTS.md §5): this worker logs NOTHING — no access token, child key, handoff, signature,
// mailbox content or URL.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { CoreClient } from "../client.js";
import { buildServer } from "../server.js";
import {
  store as defaultStore,
  validateAccessToken,
  handleAuthorizeGet,
  handleAuthorizeReturn,
  handleToken,
  handleRegister,
  DEFAULT_CLIENTS,
  type OAuthDeps,
  type OAuthStoreLike,
  type WebBinding,
} from "./oauth.js";
import { DurableObjectStore, type DurableObjectNamespace } from "./store-do.js";
import { renderRoot } from "./root.js";
import { ipBucket } from "./ipBucket.js";
import { pickLocale, parseAcceptLanguage } from "./oauth-i18n.js";
import type { FetchLike } from "../client.js";

/** The Worker environment (wrangler `env`). Everything is optional so the fail-closed default holds when
 *  NONE of it is set. `__coreFetch` + `__store` + `__web` are TEST-ONLY seams (a real wrangler env never
 *  carries them). */
export interface WorkerEnv {
  /** Core base URL override (client.ts reads POMBUS_API_BASE from process.env only in Node). */
  POMBUS_API_BASE?: string;
  /** The Durable Object namespace wrangler binds (store-do.ts) — the single shared OAuth store. */
  OAUTH_STORE?: DurableObjectNamespace;
  /** The webmail consent screen URL the Worker 302s a human to. A var/secret; absent → /authorize 503. */
  WEB_CONSENT_URL?: string;
  /** The HMAC secret shared with the webmail (signs both 302 hops). A secret; absent → fail-closed. */
  MCP_WEB_LINK_SECRET?: string;
  /** Worker-only secret that signs the stateless rid and client_id. Absent → /authorize + /register 503. */
  MCP_STATE_SECRET?: string;
  /** The PREVIOUS state secret during a rotation: still verifies, never signs. */
  MCP_STATE_SECRET_PREV?: string;
  /** The webmail service binding used to redeem a handoff at /token. Absent → /token 503. */
  WEB?: WebBinding;
  /** Cloudflare's native rate limiter (wrangler.toml [[ratelimits]]), keyed per client IP on the public
   *  OAuth surfaces. Absent (local dev, tests) → no limit. */
  RATE_LIMIT?: { limit(opts: { key: string }): Promise<{ success: boolean }> };
  /** TEST-ONLY fake core. Never present in a real Worker env. */
  __coreFetch?: FetchLike;
  /** TEST-ONLY isolated OAuth store. Typed as the INTERFACE so a test can inject a rejecting fake. */
  __store?: OAuthStoreLike;
  /** TEST-ONLY fake WEB binding (overrides env.WEB in tests). */
  __web?: WebBinding;
}

/** Resolve the OAuth store: the test seam first, else the bound Durable Object, else the module singleton. */
function resolveStore(env: WorkerEnv): OAuthStoreLike {
  if (env.__store) return env.__store;
  if (env.OAUTH_STORE) return new DurableObjectStore(env.OAUTH_STORE);
  return defaultStore;
}

/** Resolve the WEB service binding: the test seam first, else the wrangler binding (may be undefined —
 *  /token then fail-closes to 503). */
function resolveWeb(env: WorkerEnv): WebBinding | undefined {
  return env.__web ?? env.WEB;
}

/** Resolve the Bearer ACCESS TOKEN on an MCP request to the child key of its ACTIVE org, or null to
 *  refuse. The single fail-closed decision point for the Bearer path; the returned value is the minted
 *  child key (NEVER log it). getActiveChild (oauth.ts) is the only source — org↔org isolation hinges on it. */
export function authorize(req: Request, env: WorkerEnv): Promise<string | null> {
  return validateAccessToken(req.headers.get("authorization"), resolveStore(env));
}

/** 401 with the RFC 6750 challenge carrying the resource_metadata pointer (RFC 9728). Content-free. */
function unauthorized(origin: string): Response {
  return new Response(null, {
    status: 401,
    headers: {
      "www-authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`,
    },
  });
}

/** 200 JSON for a discovery metadata document. Public, short-cacheable, content-free of any secret. */
function metadata(doc: Record<string, unknown>): Response {
  return new Response(JSON.stringify(doc), {
    status: 200,
    headers: { "content-type": "application/json", "cache-control": "public, max-age=3600" },
  });
}

/** Assemble the OAuth handler dependencies from the Worker env: the fixed client registry, the store,
 *  the core seams, and the R3 webmail seams (consent URL, HMAC secret, WEB binding). */
function oauthDeps(env: WorkerEnv): OAuthDeps {
  const web = resolveWeb(env);
  return {
    clients: DEFAULT_CLIENTS,
    store: resolveStore(env),
    ...(env.__coreFetch !== undefined ? { coreFetch: env.__coreFetch } : {}),
    ...(env.POMBUS_API_BASE !== undefined ? { coreBaseUrl: env.POMBUS_API_BASE } : {}),
    ...(env.WEB_CONSENT_URL !== undefined ? { webConsentUrl: env.WEB_CONSENT_URL } : {}),
    ...(env.MCP_WEB_LINK_SECRET !== undefined ? { webLinkSecret: env.MCP_WEB_LINK_SECRET } : {}),
    ...(env.MCP_STATE_SECRET
      ? { stateSecrets: [env.MCP_STATE_SECRET, ...(env.MCP_STATE_SECRET_PREV ? [env.MCP_STATE_SECRET_PREV] : [])] }
      : {}),
    ...(web !== undefined ? { web } : {}),
  };
}

/** 503 with a Retry-After, no body — the last-resort envelope for ANY unexpected throw inside fetch (a
 *  store/DO RPC rejection is the real case). Collapsing every internal failure into one content-free 503
 *  denies an availability oracle: 503 is honestly "unavailable", NOT the 401/403 a caller uses to infer
 *  credential state, NOR the 200/302 of success. Nothing logged, no .message/.stack serialized. */
function unavailable(): Response {
  return new Response(null, { status: 503, headers: { "retry-after": "60" } });
}

/** Origins allowed to call this Worker from a browser: itself (the webmail return lands here as a
 *  top-level navigation, not a fetch, so it carries no Origin anyway) and the origins of the registered
 *  OAuth callbacks. The MCP Streamable-HTTP spec requires validating Origin (DNS-rebinding fence).
 *  Non-browser clients send no Origin and are judged by their credential alone. */
export function originAllowed(req: Request): boolean {
  const origin = req.headers.get("origin");
  if (origin === null) return true;
  if (origin === new URL(req.url).origin) return true;
  return DEFAULT_CLIENTS.some((c) => c.redirectUris.some((u) => new URL(u).origin === origin));
}

export default {
  async fetch(req: Request, env: WorkerEnv): Promise<Response> {
    // One top-level try/catch is the last line of defence: the store is a Durable Object reached by RPC,
    // so the `await`s below can REJECT when the DO is unavailable. The catch collapses any such throw
    // into one content-free 503 (see unavailable()). The NORMAL error paths (401/400/302/503) return in
    // their own flows and never fall through.
    try {
      const url = new URL(req.url);
      const path = url.pathname;

      // A foreign browser origin gets a content-free 403 before anything else (OAuth surfaces included).
      if (!originAllowed(req)) return new Response(null, { status: 403 });

      // /authorize, /register and /token are PUBLIC and each one writes to the shared store: without a
      // per-IP limit any client can churn it (registrations, pending requests) as fast as it can send.
      if (env.RATE_LIMIT && (path === "/authorize" || path === "/register" || path === "/token")) {
        // IPv6 by /56, IPv4 by /32 (ipBucket): a rotating address inside one /56 is still ONE caller — a fresh
        // bucket per address let a flood of /authorize evict real users' pending logins (STORE_CAP).
        const ip = ipBucket(req.headers.get("cf-connecting-ip"));
        if (!(await env.RATE_LIMIT.limit({ key: `${ip}:${path}` })).success) {
          return new Response(JSON.stringify({ error: "rate_limited" }), {
            status: 429, headers: { "content-type": "application/json", "retry-after": "60" },
          });
        }
      }

      // --- OAuth surfaces (no Bearer required; they issue/complete the Bearer). AWAIT them so a store
      // RPC rejection inside a handler lands in the top-level catch (→ one 503), not as an un-awaited
      // rejected promise that escapes this try. ---
      if (path === "/authorize") {
        if (req.method === "GET") return await handleAuthorizeGet(req, oauthDeps(env));
        // POST /authorize (the R2e paste-key approve) is GONE — the human decides on the webmail now.
        return new Response(null, { status: 405, headers: { allow: "GET" } });
      }
      if (path === "/authorize/return") {
        if (req.method === "GET") return await handleAuthorizeReturn(req, oauthDeps(env));
        return new Response(null, { status: 405, headers: { allow: "GET" } });
      }
      if (path === "/token") {
        if (req.method === "POST") return await handleToken(req, oauthDeps(env));
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }

      // --- Discovery (RFC 9728 + RFC 8414) — PUBLIC metadata, origin-derived, no secret. ---
      const origin = url.origin;
      if (path === "/.well-known/oauth-protected-resource") {
        if (req.method !== "GET") return new Response(null, { status: 405, headers: { allow: "GET" } });
        return metadata({ resource: origin, authorization_servers: [origin] });
      }
      if (path === "/.well-known/oauth-authorization-server") {
        if (req.method !== "GET") return new Response(null, { status: 405, headers: { allow: "GET" } });
        return metadata({
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          registration_endpoint: `${origin}/register`,
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code"],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
      }

      // --- Dynamic Client Registration (RFC 7591) — PUBLIC. ---
      if (path === "/register") {
        if (req.method === "POST") return await handleRegister(req, oauthDeps(env));
        return new Response(null, { status: 405, headers: { allow: "POST" } });
      }

      // --- Friendly root page — ONLY for a human browser (GET + Accept text/html + no credential). A
      // real MCP client POSTs with Accept json/event-stream and a credential, so it never matches. The
      // gate is deliberately narrow so it can never become an auth bypass. ---
      if (
        req.method === "GET" &&
        !req.headers.get("authorization") &&
        !req.headers.get("x-api-key") &&
        (req.headers.get("accept") ?? "").includes("text/html")
      ) {
        const locale = pickLocale([parseAcceptLanguage(req.headers.get("accept-language"))]);
        return new Response(renderRoot(locale), {
          status: 200,
          headers: {
            "content-type": "text/html; charset=utf-8",
            "x-content-type-options": "nosniff",
            "cache-control": "no-store",
          },
        });
      }

      // --- MCP endpoint (everything else) — requires a valid credential on exactly ONE of the two paths. ---
      const bearer = req.headers.get("authorization");
      const apiKeyHeader = req.headers.get("x-api-key");

      // Both credentials at once is ambiguous (which org/scope?) — refuse rather than pick (fail-closed).
      if (bearer && apiKeyHeader) {
        return new Response(JSON.stringify({ error: "invalid_request" }), {
          status: 400,
          headers: { "content-type": "application/json", "cache-control": "no-store" },
        });
      }

      // The credential the core will see, and whether this is the multi-org (Bearer) path.
      let apiKey: string | null;
      let orgTools: boolean;
      if (apiKeyHeader) {
        // x-api-key: the pod-key IS the credential (one org, stdio/Cursor style). No token-set lookup,
        // no org tools. A blank header is no credential.
        apiKey = apiKeyHeader.trim() || null;
        orgTools = false;
      } else {
        // Bearer: resolve the ACTIVE org's child key from the token-set. Org tools exposed.
        apiKey = await authorize(req, env);
        orgTools = true;
      }

      // Fail-closed: refuse BEFORE building the Server. No credential never resolves scope, never touches
      // the core, never learns whether any inbox exists — the 401 is content-free.
      if (!apiKey) return unauthorized(origin);

      const client = new CoreClient({
        apiKey,
        ...(env.POMBUS_API_BASE !== undefined ? { baseUrl: env.POMBUS_API_BASE } : {}),
        ...(env.__coreFetch !== undefined ? { fetchImpl: env.__coreFetch } : {}),
      });

      // On the Bearer path the org tools need the token-set: pass the store + the access token so
      // list/select_organization can read and re-point the set. The access token is parsed from the
      // Authorization header exactly as validateAccessToken did (kept tiny — no second source of truth).
      const orgSession = orgTools ? bearerOrgSession(bearer, resolveStore(env)) : undefined;

      let server: Server;
      try {
        server = await buildServer(client, orgSession ? { orgSession } : {});
      } catch {
        // buildServer's only outward call is /auth/me (scope resolve). A failure there → content-free 401
        // (the core's anti-enumeration rule; never distinguishes rejected key from unreachable core).
        return unauthorized(origin);
      }

      const transport = new WebStandardStreamableHTTPServerTransport({ enableJsonResponse: true });
      await server.connect(transport);
      return transport.handleRequest(req);
    } catch {
      return unavailable();
    }
  },
};

/** Build the org-session handle for the Bearer path: the store + the opaque access token the org tools
 *  operate on. Returns undefined when the header has no Bearer token (then no org tools). The access
 *  token is NEVER logged. */
function bearerOrgSession(
  authorizationHeader: string | null,
  store: OAuthStoreLike,
): { store: OAuthStoreLike; accessToken: string } | undefined {
  const m = /^Bearer (.+)$/.exec((authorizationHeader ?? "").trim());
  const token = m?.[1]?.trim();
  if (!token) return undefined;
  return { store, accessToken: token };
}
