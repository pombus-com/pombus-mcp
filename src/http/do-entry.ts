// R2c — the wrangler `main`. It exists so the Durable Object class is a named export of the deployed
// entry (wrangler requires the DO class to be exported from main) WITHOUT putting the toxic
// cloudflare:workers import on the test path: the tests import ./worker.js directly and never touch this
// file, so `node --test` never loads do-class.js. workerd loads this module and sees both the fetch
// handler and OAuthStoreDO.
//
// Keep this file a pure re-export — no logic. The worker's fetch handler stays in worker.ts (fully
// tested in node); the DO shell stays in do-class.ts (workerd-only).

export { default } from "./worker.js";
export { OAuthStoreDO } from "./do-class.js";
