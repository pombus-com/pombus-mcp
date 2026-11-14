import { test } from "node:test";
import assert from "node:assert/strict";
import { CoreClient } from "./client.js";

const KEY = "pk_live_secret_do_not_log_client";

/** A `this`-sensitive fetch that mimics the workerd native fetch: it demands `this === globalThis`
 *  and throws `TypeError: Illegal invocation` otherwise — exactly what Cloudflare Workers (production
 *  and `wrangler dev`) do. Node's own undici fetch ignores `this`, so this fake is the only way to
 *  reproduce the production failure inside node:test. Returns a stub 200 when called correctly. */
function workerdLikeFetch(host: unknown): (url: string, init: RequestInit) => Promise<Response> {
  return function (this: unknown): Promise<Response> {
    if (this !== host) throw new TypeError("Illegal invocation");
    return Promise.resolve(new Response("{}", { status: 200, headers: { "content-type": "application/json" } }));
  };
}

// Regression (prod bug 2026-11): the CoreClient default fetch must be bound to globalThis. With the
// unbound default (`globalThis.fetch as FetchLike`) the detached call reached workerd with the wrong
// `this`, threw Illegal invocation, collapsed to CoreError("network"), and every MCP->core request in
// production failed. If someone drops the `.bind(globalThis)`, the fake below throws and this fails.
test("default fetch is bound to globalThis — no Illegal invocation under a workerd-like host", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = workerdLikeFetch(globalThis) as typeof globalThis.fetch;
  try {
    // No fetchImpl injected: this exercises the real default `globalThis.fetch.bind(globalThis)`.
    const client = new CoreClient({ apiKey: KEY, baseUrl: "https://core.test/v0" });
    const body = await client.get<Record<string, unknown>>("/auth/me");
    assert.deepEqual(body, {}, "the bound default must reach the host with this===globalThis");
  } finally {
    globalThis.fetch = original;
  }
});

// Sanity: prove the fake really does reject a detached call, so the test above has teeth. A bare
// reference to the installed fetch (torn off globalThis) must throw — this is the exact failure the
// bind() prevents.
test("the workerd-like fake rejects a detached call — the fake has teeth", () => {
  const original = globalThis.fetch;
  globalThis.fetch = workerdLikeFetch(globalThis) as typeof globalThis.fetch;
  try {
    const detached = globalThis.fetch;
    assert.throws(() => detached("https://core.test/v0/auth/me", {}), /Illegal invocation/);
  } finally {
    globalThis.fetch = original;
  }
});
