// Scope binding — the core of F4's access rule (strategy doc 4.2/4.3, adoption spec line 104):
// the model NEVER supplies a raw inbox_id that escapes the API key's scope.
//
// On boot the server calls GET /v0/auth/me and learns the key's scope:
//   - inbox / domain key  -> a single inbox is implied. The inbox_id is DERIVED from the scope and the
//     tools that need one do NOT accept it as an argument at all. The model cannot address any other
//     inbox because the parameter does not exist in the tool schema.
//   - pod / organization key -> the key can see many inboxes. `list_inboxes` enumerates the ones the
//     key may reach; a tool that needs an inbox_id accepts only an id the server has seen in that
//     enumeration, validated against the allowed set before any request leaves the process.
//
// The core already fences every route by scope (authz_inbox), so this layer is defense in depth plus
// an honest tool schema: the key's authority — not the model's argument — decides which inbox is read.

import type { CoreClient } from "./client.js";

export type ScopeType = "inbox" | "domain" | "pod" | "organization";

export interface AuthMe {
  scope_type: ScopeType;
  scope_id: string | null;
  organization_id: string;
  pod_id: string | null;
  inbox_id: string | null;
  api_key_id: string | null;
  // The key's granular permission set. null => master full-access key (no gate). A permissions object
  // => a scoped key: it may only do what the object grants. The catalog gate (gateAllows) reads this to
  // decide which tools to EXPOSE; the core enforces the same map server-side (api.py get_principal).
  permissions?: Record<string, boolean> | null;
}

/** The resolved binding the tool layer consults. `fixedInboxId` set => single-inbox key: tools drop
 *  the inbox_id parameter entirely. Otherwise => multi-inbox key: tools require a listed inbox_id,
 *  checked via `allows`. `permissions` drives the catalog gate; `podId` lets pod-scoped tools derive
 *  the pod from the key's own scope instead of taking it as a free model argument. */
export class ScopeBinding {
  readonly scopeType: ScopeType;
  readonly fixedInboxId: string | null;
  // The key's permission set, verbatim from /auth/me. null = master (full access); an object = scoped.
  readonly permissions: Record<string, boolean> | null;
  // The pod the key is bound to, when it is pod/inbox/domain-scoped. An org (master) key has none, so a
  // pod-scoped tool must then take a validated pod_id argument. Pod-scoped tools NEVER take a free
  // pod_id when this is set — the key's own pod is used, so the model can't address another tenant.
  readonly podId: string | null;
  // The set of inbox ids the key has been observed to reach, grown lazily by list_inboxes. A pod/org
  // key can reach ids not yet listed; `allows` therefore also confirms unknown ids against the core
  // (fail-closed) rather than rejecting them for being unseen.
  private readonly seen = new Set<string>();

  private constructor(
    scopeType: ScopeType,
    fixedInboxId: string | null,
    permissions: Record<string, boolean> | null,
    podId: string | null,
  ) {
    this.scopeType = scopeType;
    this.fixedInboxId = fixedInboxId;
    this.permissions = permissions;
    this.podId = podId;
  }

  /** True when the key binds exactly one inbox (inbox or domain... no: domain reaches many). Only an
   *  inbox-scoped key is truly single. A domain key reaches every inbox of its domain, so it is
   *  multi-inbox like a pod key. */
  get isSingleInbox(): boolean {
    return this.fixedInboxId !== null;
  }

  /** The catalog gate: does the key hold the permission a tool requires? A master key (permissions ===
   *  null) holds everything. A scoped key holds `perm` when its object has it true — with ONE mirror of
   *  the core's rule (api.py:1331-1334): message_send satisfies message_reply, so a key that can send
   *  can also reply. Tools whose gate is false are never REGISTERED (hidden, not registered-then-403). */
  gateAllows(requiredPerm: string | null): boolean {
    if (this.permissions === null) return true; // master key
    if (requiredPerm === null) return true; // a tool with no gated route (none scope)
    if (this.permissions[requiredPerm] === true) return true;
    if (requiredPerm === "message_reply" && this.permissions["message_send"] === true) return true;
    return false;
  }

  /** Call /v0/auth/me and build the binding. An inbox key yields a fixed inbox_id; every other scope
   *  is multi-inbox and the inbox_id must be supplied-and-validated per call. Captures the key's
   *  permissions (catalog gate) and pod_id (pod-scoped tools derive the pod from the scope). */
  static async resolve(client: CoreClient): Promise<ScopeBinding> {
    const me = await client.get<AuthMe>("/auth/me");
    const permissions = me.permissions ?? null;
    const podId = me.pod_id ?? null;
    if (me.scope_type === "inbox" && me.inbox_id) {
      return new ScopeBinding("inbox", me.inbox_id, permissions, podId);
    }
    // domain / pod / organization: no single implied inbox.
    return new ScopeBinding(me.scope_type, null, permissions, podId);
  }

  /** Record inbox ids returned by list_inboxes so later calls can validate against the enumeration. */
  remember(ids: Iterable<string>): void {
    for (const id of ids) this.seen.add(id);
  }

  /** Resolve the inbox_id a tool will act on. For a single-inbox key the model's argument (if any) is
   *  IGNORED and the fixed id is used — the model can never widen past its scope. For a multi-inbox
   *  key the argument is required and must be an id the key can reach: known from a prior list, or
   *  confirmed against the core (which fences by scope and 404s an inbox outside it). Returns the id,
   *  or throws a stable `not_found` (never distinguishing "unknown" from "forbidden"). */
  async resolveInboxId(client: CoreClient, requested: string | undefined): Promise<string> {
    if (this.fixedInboxId !== null) return this.fixedInboxId;
    const id = (requested ?? "").trim();
    if (!id) throw new ScopeError("inbox_required");
    if (this.seen.has(id)) return id;
    // Not seen yet. Confirm it against the core: get_inbox 404s (via not_found) for any inbox the key
    // may not reach, so a hostile id never turns into a cross-tenant read. On success, remember it.
    await client.get(`/inboxes/${encodeURIComponent(id)}`); // throws CoreError('not_found') if out of scope
    this.seen.add(id);
    return id;
  }

  /** Resolve the pod_id a pod-scoped tool acts on. Same discipline as resolveInboxId: when the key is
   *  itself pod/inbox/domain-scoped the model's argument is IGNORED and the key's own pod is used — it
   *  cannot address another tenant. Only a master (org) key, which binds no single pod, must supply a
   *  pod_id; it is then validated against the core (get_pod 404s -> not_found for an unknown pod) so a
   *  forged id never turns into a cross-tenant action. */
  async resolvePodId(client: CoreClient, requested: string | undefined): Promise<string> {
    if (this.podId !== null) return this.podId;
    const id = (requested ?? "").trim();
    if (!id) throw new ScopeError("pod_required");
    await client.get(`/pods/${encodeURIComponent(id)}`); // throws CoreError('not_found') if out of scope
    return id;
  }
}

/** A scope-layer failure the tool layer maps to an i18n message for a human. Locale-free, key-free. */
export class ScopeError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ScopeError";
    this.code = code;
  }
}
