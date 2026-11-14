// R2c — a minimal ambient declaration for the `cloudflare:workers` runtime module, just enough for
// `tsc` to resolve `extends DurableObject` in do-class.ts. The npx package does NOT depend on
// @cloudflare/workers-types (its stack is fixed: tsc + node --test, AGENTS.md §4), and only the DO shell
// needs the base class. workerd provides the real implementation at deploy time; `node --test` never
// loads do-class.js (the one file that imports this module), so this declaration never has to be real.
//
// This is a standalone ambient module declaration — NOT an augmentation — so it must live in a file with
// no top-level import/export (hence a .d.ts with none), or TS treats it as augmenting a module that
// doesn't exist (TS2664).

declare module "cloudflare:workers" {
  /** The Durable Object base class. The RPC-style DO only needs to extend it and expose public methods;
   *  this surface is the ctor the subclass's implicit super() satisfies. */
  export class DurableObject<Env = unknown> {
    protected ctx: unknown;
    protected env: Env;
    constructor(ctx: unknown, env: Env);
  }
}
