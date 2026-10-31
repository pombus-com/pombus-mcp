// HTTP client for the Pombus REST core. The MCP server is a pure client: it never opens SQLite,
// never parses MIME. It holds the API key, signs every request with a Bearer header, and translates
// the core's HTTP contract into a shape the tool layer can hand back to the model.
//
// Security invariants enforced here (audited by pombus-sec):
//   - the key lives ONLY in the Authorization header; it is never placed in a URL, an argv, a log
//     line, or a thrown error message.
//   - an auth/permission failure (401/403) and a missing resource (404) collapse to ONE opaque
//     error for the model (`not_found`), so the server never confirms an inbox exists to a caller
//     that cannot reach it — the same anti-enumeration rule the core applies.
//   - network/transport errors report the failure TYPE only, never the request URL (which carries
//     query values) or the key.

const DEFAULT_BASE = "https://mail-api.pombus.com/v0";

export type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";

/** A failure the tool layer surfaces to the model. `code` is stable and locale-free; it maps to an
 *  i18n message only when a human sees it. Never carries the key, the URL, or a server detail that
 *  would distinguish "forbidden" from "not found". */
export class CoreError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CoreError";
    this.code = code;
  }
}

/** The minimal fetch surface we depend on — lets tests inject a fake without a live core. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface ClientOptions {
  apiKey: string;
  baseUrl?: string;
  fetchImpl?: FetchLike;
}

/** Resolve the core base URL from an explicit option or the environment, else the production default.
 *  Trailing slash trimmed so path joins never double up. */
export function resolveBaseUrl(explicit?: string): string {
  const raw = (explicit ?? process.env["POMBUS_API_BASE"] ?? DEFAULT_BASE).trim();
  return raw.replace(/\/+$/, "");
}

/** Read the API key from the environment. Returns null when absent — the caller decides how to fail
 *  (the server refuses to start without it). The value is never logged by this module. */
export function readApiKey(): string | null {
  const k = (process.env["POMBUS_API_KEY"] ?? "").trim();
  return k.length > 0 ? k : null;
}

export class CoreClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;

  constructor(opts: ClientOptions) {
    this.apiKey = opts.apiKey;
    this.baseUrl = resolveBaseUrl(opts.baseUrl);
    // Node >=20 ships a global fetch; the option exists only so tests can inject a fake core.
    this.fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
  }

  /** Build an absolute URL from a path and query params. Values are URL-encoded. The API key is
   *  NEVER a query param — it only ever rides in the Authorization header (keyHygiene). */
  private url(path: string, query?: Record<string, string | number | boolean | undefined>): string {
    const u = new URL(this.baseUrl + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") u.searchParams.set(k, String(v));
      }
    }
    return u.toString();
  }

  /** One request. On a non-2xx the core body is parsed for its stable `code`; 401/403/404 all map to
   *  `not_found` so the model can never tell "you may not" from "it does not exist". Other statuses
   *  keep their code for diagnostics but still never leak the key or the URL. */
  async request<T = unknown>(
    method: HttpMethod,
    path: string,
    opts: {
      query?: Record<string, string | number | boolean | undefined> | undefined;
      body?: unknown;
    } = {},
  ): Promise<T> {
    const url = this.url(path, opts.query);
    const init: RequestInit = {
      method,
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        accept: "application/json",
        ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
      },
    };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    // A corporate proxy is honoured by Node's own undici dispatcher (HTTPS_PROXY / NODE_USE_ENV_PROXY);
    // we do not re-implement it.

    let res: Response;
    try {
      res = await this.fetchImpl(url, init);
    } catch (e) {
      // Transport failure: report the TYPE, never the URL (it carries query values) or the key.
      throw new CoreError("network", `request failed: ${errName(e)}`);
    }

    if (res.ok) {
      if (res.status === 204) return undefined as T;
      const text = await res.text();
      if (!text) return undefined as T;
      try {
        return JSON.parse(text) as T;
      } catch {
        throw new CoreError("bad_response", "core returned a non-JSON body");
      }
    }

    // Anti-enumeration: do NOT distinguish "forbidden" from "not found" to the model.
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      throw new CoreError("not_found", "resource not found");
    }
    // Other errors: a stable code from the core body when present, else the status. The message is
    // generic; the body is read but only its `code`/`detail` string is used, never echoed verbatim
    // if it could carry caller input.
    const code = await safeCode(res);
    throw new CoreError(code, `core error (${res.status})`);
  }

  get<T = unknown>(path: string, query?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.request<T>("GET", path, { query });
  }
  post<T = unknown>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("POST", path, { body });
  }
  patch<T = unknown>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("PATCH", path, { body });
  }
  delete<T = unknown>(path: string, body?: unknown): Promise<T> {
    return this.request<T>("DELETE", path, { body });
  }
}

/** The error constructor name only — never the message, which could carry a URL or system path. */
function errName(e: unknown): string {
  if (e && typeof e === "object" && "name" in e && typeof (e as { name: unknown }).name === "string") {
    return (e as { name: string }).name;
  }
  return "Error";
}

/** Extract a stable short code from a core error body without echoing attacker-influenced text. */
async function safeCode(res: Response): Promise<string> {
  try {
    const text = await res.text();
    if (!text) return "core_error";
    const body = JSON.parse(text) as { code?: unknown; detail?: unknown };
    const raw = typeof body.code === "string" ? body.code : typeof body.detail === "string" ? body.detail : "";
    // Only accept a conservative identifier shape; anything else collapses to a generic code so a
    // reflected body can't smuggle content into our error.
    return /^[a-z][a-z0-9_]{0,39}$/.test(raw) ? raw : "core_error";
  } catch {
    return "core_error";
  }
}
