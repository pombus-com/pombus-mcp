// Test doubles — a fake core (a FetchLike that records every request and returns programmed replies)
// and a captured-request shape the tests assert against. Not a *.test.ts, so the test runner does not
// execute it as a suite. All fixtures are written from scratch (AGENTS.md §9): invented ids, no real
// data.

import type { FetchLike } from "./client.js";

export interface CapturedRequest {
  method: string;
  /** Full URL as the client built it (used to assert path + query + that the key is NOT in it). */
  url: string;
  /** The request headers as a lowercased map (used to assert the key rides ONLY in authorization). */
  headers: Record<string, string>;
  /** Parsed JSON body, when one was sent. */
  body: unknown;
}

export interface ProgrammedReply {
  status?: number;
  json?: unknown;
}

/** Match a request by method + a path predicate; returns the reply to send. */
export type Route = {
  method: string;
  match: (url: URL) => boolean;
  reply: ProgrammedReply | ((req: CapturedRequest, url: URL) => ProgrammedReply);
};

export class FakeCore {
  readonly requests: CapturedRequest[] = [];
  private readonly routes: Route[] = [];

  /** Register a route. Routes are matched in order; the first match wins. */
  on(method: string, match: (url: URL) => boolean, reply: Route["reply"]): this {
    this.routes.push({ method, match, reply });
    return this;
  }

  /** A FetchLike bound to this fake. Records the request, then returns the first matching route's
   *  reply, or a 404 when nothing matches (so an unexpected call fails closed, like the real core). */
  readonly fetch: FetchLike = async (rawUrl, init) => {
    const url = new URL(rawUrl);
    const headers = lowerHeaders(init.headers);
    let body: unknown;
    if (typeof init.body === "string" && init.body.length > 0) {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    const captured: CapturedRequest = { method: init.method ?? "GET", url: rawUrl, headers, body };
    this.requests.push(captured);

    const route = this.routes.find((r) => r.method === captured.method && r.match(url));
    const reply: ProgrammedReply = route
      ? typeof route.reply === "function"
        ? route.reply(captured, url)
        : route.reply
      : { status: 404, json: { code: "not_found" } };
    return makeResponse(reply);
  };
}

function lowerHeaders(h: RequestInit["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  if (h instanceof Headers) {
    h.forEach((v, k) => (out[k.toLowerCase()] = v));
  } else if (Array.isArray(h)) {
    for (const pair of h) {
      const k = pair[0];
      const v = pair[1];
      if (k !== undefined && v !== undefined) out[k.toLowerCase()] = v;
    }
  } else {
    for (const [k, v] of Object.entries(h)) out[k.toLowerCase()] = String(v);
  }
  return out;
}

function makeResponse(reply: ProgrammedReply): Response {
  const status = reply.status ?? 200;
  const hasBody = reply.json !== undefined;
  // A 204/205 MUST have a null body (undici throws on any body, even ""), matching the real core's
  // no-content replies (e.g. a DELETE).
  const nullBodyStatus = status === 204 || status === 205 || status === 304;
  const body = hasBody ? JSON.stringify(reply.json) : nullBodyStatus ? null : "";
  return new Response(body, {
    status,
    headers: hasBody ? { "content-type": "application/json" } : {},
  });
}

/** An /auth/me reply for an inbox-scoped key (single implied inbox). */
export function authMeInbox(inboxId: string): ProgrammedReply {
  return {
    json: {
      scope_type: "inbox",
      scope_id: inboxId,
      organization_id: "org_test",
      pod_id: "pod_test",
      inbox_id: inboxId,
      api_key_id: "key_test",
      permissions: null,
    },
  };
}

/** An /auth/me reply for a pod-scoped key (reaches many inboxes). */
export function authMePod(): ProgrammedReply {
  return {
    json: {
      scope_type: "pod",
      scope_id: "pod_test",
      organization_id: "org_test",
      pod_id: "pod_test",
      inbox_id: null,
      api_key_id: "key_test",
      permissions: null,
    },
  };
}

/** A POST /v0/inboxes reply (the shape the core returns: inbox_id + email). Invented ids only (§9). */
export function createdInbox(inboxId: string, email: string): ProgrammedReply {
  return { json: { inbox_id: inboxId, email } };
}

/** An /auth/me reply for a SCOPED pod key — a real permissions object drives the catalog gate. Pass
 *  the permissions the human granted the key; everything else uses invented ids (§9). */
export function authMeScoped(
  permissions: Record<string, boolean>,
  overrides: Partial<{ scope_type: string; inbox_id: string | null; pod_id: string | null }> = {},
): ProgrammedReply {
  return {
    json: {
      scope_type: overrides.scope_type ?? "pod",
      scope_id: "pod_test",
      organization_id: "org_test",
      pod_id: overrides.pod_id === undefined ? "pod_test" : overrides.pod_id,
      inbox_id: overrides.inbox_id ?? null,
      api_key_id: "key_test",
      permissions,
    },
  };
}
