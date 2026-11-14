// R2c — the Durable Object shell. This is the ONE place that imports cloudflare:workers, so it is the
// ONE file the `node --test` runner must never load: `cloudflare:workers` throws
// ERR_UNSUPPORTED_ESM_URL_SCHEME in Node. It is kept off the test import graph (only do-entry.ts, the
// wrangler main, pulls it) and off `tsc`'s unresolved-module error by the ambient declaration below.
//
// Why this exists: Cloudflare Workers do NOT pin the same isolate across the three hops of the OAuth
// flow, so an in-isolate OAuthStore loses the authorization code between POST /authorize and POST
// /token → `invalid_grant` in production. ONE Durable Object instance fixes it: every isolate reaches
// the same object (DurableObjectStore resolves it by a fixed name), and the DO's input gate serializes
// calls so single-use take-and-delete stays atomic.
//
// MEMORY, not ctx.storage (deliberate, do not "fix"): the store holds each token-set's minted childKeys
// (one per authorized org, inside every OrgEntry) and the ownerHash that gates attachOrg. Persisting
// them to ctx.storage would put those secrets on disk at rest — a worse security posture. In memory they
// never touch disk. The only cost is benign: if the DO is evicted after a long idle, live tokens vanish
// and the agent re-authorizes (a UX degradation, never a security failure). So this class does NOT touch
// ctx.storage at all.
//
// This shell carries NO logic and logs NOTHING: every method is a 1:1 pass-through to the in-memory
// OAuthStore it wraps. All behaviour under test (single-use, expiry, caps, PKCE, scope, rate-limit)
// lives in OAuthStore (oauth.ts), proven in node. The shell is workerd-specific and verified by reading
// plus the founder's `wrangler dev` smoke — it has no automated test, by design (no Miniflare is added;
// the package's stack is fixed, AGENTS.md §4).

// The runtime base class comes from `cloudflare:workers`, declared minimally in
// cloudflare-workers.d.ts (the npx package has no @cloudflare/workers-types; see that file).
import { DurableObject } from "cloudflare:workers";
import {
  OAuthStore,
  type OAuthStoreLike,
  type PendingRequest,
  type IssuedCode,
  type LiveToken,
  type OrgEntry,
} from "./oauth.js";

/** The singleton OAuth store as a Durable Object. Its public methods ARE the RPC surface the Worker's
 *  DurableObjectStore calls on the stub; each forwards straight to the wrapped in-memory OAuthStore. */
export class OAuthStoreDO extends DurableObject implements OAuthStoreLike {
  private readonly store = new OAuthStore();

  putRequest(id: string, r: PendingRequest): Promise<void> {
    return this.store.putRequest(id, r);
  }
  takeRequest(id: string): Promise<PendingRequest | undefined> {
    return this.store.takeRequest(id);
  }
  putCode(code: string, c: IssuedCode): Promise<boolean> {
    return this.store.putCode(code, c);
  }
  takeCode(code: string): Promise<IssuedCode | undefined> {
    return this.store.takeCode(code);
  }
  tokenRoom(): Promise<boolean> {
    return this.store.tokenRoom();
  }
  putToken(token: string, t: LiveToken): Promise<void> {
    return this.store.putToken(token, t);
  }
  getToken(token: string): Promise<LiveToken | undefined> {
    return this.store.getToken(token);
  }
  attachOrg(token: string, orgId: string, entry: OrgEntry, ownerHash: string): Promise<boolean> {
    return this.store.attachOrg(token, orgId, entry, ownerHash);
  }
  setActiveOrg(token: string, orgId: string): Promise<boolean> {
    return this.store.setActiveOrg(token, orgId);
  }
  getActiveChild(
    token: string,
  ): Promise<{ orgId: string; childKey: string; perms: string[] } | undefined> {
    return this.store.getActiveChild(token);
  }
  putLink(linkToken: string, accessToken: string): Promise<boolean> {
    return this.store.putLink(linkToken, accessToken);
  }
  takeLink(linkToken: string): Promise<string | undefined> {
    return this.store.takeLink(linkToken);
  }
  putClient(clientId: string, redirectUris: readonly string[]): Promise<boolean> {
    return this.store.putClient(clientId, redirectUris);
  }
  getClient(clientId: string): Promise<readonly string[] | undefined> {
    return this.store.getClient(clientId);
  }
  reset(): Promise<void> {
    return this.store.reset();
  }
}
