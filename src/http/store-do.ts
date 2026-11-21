// R2c — the client the Worker uses to reach the OAuth store, which in production lives inside ONE
// Durable Object (do-class.ts OAuthStoreDO). Every isolate resolves the SAME instance by name, so the
// three hops of the OAuth flow share state — the isolate-hop `invalid_grant` that blocked a deploy is
// gone. This file holds NO cloudflare:workers import: it only needs the shape of a DurableObjectNamespace
// and a stub, so it loads fine under `node --test` (the DO class itself, which does import the runtime,
// is isolated in do-class.ts and never on the test path). Types are a tiny local declaration because the
// npx package does not depend on @cloudflare/workers-types (its stack is fixed: tsc + node --test).

import type { OAuthStoreLike } from "./oauth.js";

// --- minimal Cloudflare types (only what this client touches) -------------------------------------
// A DurableObjectStub for an RPC-style DO exposes the DO class's public methods, each returning a
// Promise across the boundary — exactly OAuthStoreLike. So the stub IS an OAuthStoreLike and the
// delegation below is a straight pass-through with no casts in the method bodies.

/** An opaque DO id (from idFromName). */
export interface DurableObjectId {
  readonly name?: string;
}

/** The binding wrangler injects as env.OAUTH_STORE. idFromName("oauth") → always the same id → the
 *  SAME single DO instance, which is the whole point (one shared store, not one per isolate). */
export interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): OAuthStoreLike;
}

// --- the Worker-side client -----------------------------------------------------------------------

/** OAuthStoreLike backed by the singleton Durable Object. Each call is a one-line RPC delegation to the
 *  stub; all the logic (single-use, expiry, caps, rate-limit) stays in the OAuthStore the DO wraps, so
 *  nothing here needs a test of its own beyond the DO shell's by-reading review. */
export class DurableObjectStore implements OAuthStoreLike {
  private readonly stub: OAuthStoreLike;

  constructor(ns: DurableObjectNamespace) {
    // One fixed name → one DO instance for the whole Worker. Its input gate serializes every method, so
    // the store's check-then-write (takeCode/useRid) stays atomic across concurrent isolates.
    this.stub = ns.get(ns.idFromName("oauth"));
  }

  useRid(ridHash: string, expiresAt: number): Promise<boolean> {
    return this.stub.useRid(ridHash, expiresAt);
  }
  putCode(code: string, c: Parameters<OAuthStoreLike["putCode"]>[1]): Promise<boolean> {
    return this.stub.putCode(code, c);
  }
  takeCode(code: string): ReturnType<OAuthStoreLike["takeCode"]> {
    return this.stub.takeCode(code);
  }
  tokenRoom(): Promise<boolean> {
    return this.stub.tokenRoom();
  }
  putToken(token: string, t: Parameters<OAuthStoreLike["putToken"]>[1]): Promise<void> {
    return this.stub.putToken(token, t);
  }
  getToken(token: string): ReturnType<OAuthStoreLike["getToken"]> {
    return this.stub.getToken(token);
  }
  attachOrg(
    token: string,
    orgId: string,
    entry: Parameters<OAuthStoreLike["attachOrg"]>[2],
    ownerHash: string,
  ): Promise<boolean> {
    return this.stub.attachOrg(token, orgId, entry, ownerHash);
  }
  setActiveOrg(token: string, orgId: string): Promise<boolean> {
    return this.stub.setActiveOrg(token, orgId);
  }
  getActiveChild(token: string): ReturnType<OAuthStoreLike["getActiveChild"]> {
    return this.stub.getActiveChild(token);
  }
  putLink(linkToken: string, accessToken: string): Promise<boolean> {
    return this.stub.putLink(linkToken, accessToken);
  }
  takeLink(linkToken: string): ReturnType<OAuthStoreLike["takeLink"]> {
    return this.stub.takeLink(linkToken);
  }
  reset(): Promise<void> {
    return this.stub.reset();
  }
}
