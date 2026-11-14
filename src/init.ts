// `pombus init` — the one command. Reads a key, resolves its scope, optionally creates an inbox, and
// writes the MCP server block into the detected client's config (merge, atomic, 0600 — clients.ts),
// persisting EXACTLY the key the user provided. i18n throughout.
//
// This module is a THIN orchestrator: every piece with weight (the HTTP, the write) lives elsewhere
// and is reused. The function takes its side-effects as injected dependencies (key source, fetch,
// HOME, output sink) so a test drives the whole flow against a fake core and a temp HOME without
// ever touching real stdin/stdout/disk.

import { domainToASCII } from "node:url";
import { CoreClient, CoreError, type FetchLike } from "./client.js";
import { ScopeBinding } from "./scope.js";
import {
  clientTargets,
  printableCodexToml,
  printableJson,
  writeJsonConfig,
  ConfigWriteError,
  type ClientTarget,
} from "./clients.js";
import { humanMessage, resolveLocale, type Locale } from "./i18n.js";
import { homedir } from "node:os";

/** A placeholder shown in --print output instead of a real key, so a user can paste the block and fill
 *  the key in themselves without a secret ever reaching the terminal scrollback. */
const KEY_PLACEHOLDER = "<YOUR_POMBUS_API_KEY>";

export interface InitOptions {
  /** The raw API key, if already known (from POMBUS_API_KEY). When absent, `promptKey` is used. */
  apiKey?: string | undefined;
  /** Create an inbox during init (the --create-inbox flag or an interactive yes). */
  createInbox?: boolean;
  /** The VERIFIED own domain the new inbox is created on — required with createInbox: a user key can no
   *  longer create an inbox on the platform domain (the core answers 403 platform_inbox_not_allowed). */
  domain?: string | undefined;
  /** Dry run: print the block, write nothing. */
  print?: boolean;
  /** Which client to target by id; when absent, every writable detected client is written. */
  client?: string | undefined;
  /** Locale for human lines. Defaults to the environment. */
  locale?: Locale;
  /** HOME dir the client table resolves against (tests point this at a temp dir). */
  home?: string | undefined;
  /** Injected fetch (tests supply a fake core). */
  fetchImpl?: FetchLike | undefined;
  /** Core base URL override (tests). */
  baseUrl?: string | undefined;
  /** Line sink for human output (defaults to stderr; stdout stays clean). */
  out?: (line: string) => void;
  /** Interactive key prompt, used only when apiKey is absent and not in --print mode. */
  promptKey?: () => Promise<string>;
}

/** What init did — returned so tests (and the CLI) can assert the decisions without parsing output. */
export interface InitResult {
  printed: boolean;
  inboxId: string | null;
  inboxEmail: string | null;
  /** Client ids actually written to. */
  written: string[];
  /** Client ids that fell back to print (unknown detection / print-only format). */
  printedFor: string[];
}

/** POST /v0/inboxes response. */
interface CreatedInbox {
  inbox_id?: unknown;
  email?: unknown;
}

export async function runInit(opts: InitOptions): Promise<InitResult> {
  const locale: Locale = opts.locale ?? resolveLocale();
  const out = opts.out ?? ((l: string) => process.stderr.write(l + "\n"));
  const say = (code: string, suffix = ""): void => out(humanMessage(code, locale) + suffix);

  // --create-inbox needs --domain: an extra inbox only exists on a verified domain of your own. Refuse
  // BEFORE the key prompt and any request, with the rule spelled out (the core would answer a bare 403).
  const rawDomain = (opts.domain ?? "").trim();
  if (opts.createInbox && !rawDomain) {
    say("init_inbox_needs_domain");
    throw new InitAbort("init_inbox_needs_domain");
  }
  const domain = normalizeDomain(rawDomain);
  if (opts.createInbox && !looksLikeDomain(domain)) {
    say("init_inbox_bad_domain");
    throw new InitAbort("init_inbox_bad_domain");
  }

  // --print with no key: emit the placeholder block for every known client and stop. No network, no
  // disk. This is the "I just want the snippet" path and the safe landing for uncertain detection.
  const key = (opts.apiKey ?? "").trim() || (opts.print ? "" : await requireKey(opts));
  if (opts.print && !key) {
    printBlocks(KEY_PLACEHOLDER, opts, out, locale);
    return emptyPrintResult();
  }

  const client = new CoreClient({
    apiKey: key,
    ...(opts.baseUrl !== undefined ? { baseUrl: opts.baseUrl } : {}),
    ...(opts.fetchImpl !== undefined ? { fetchImpl: opts.fetchImpl } : {}),
  });
  const scope = await ScopeBinding.resolve(client); // throws CoreError on a bad key / unreachable core

  // Optionally create an inbox and show the address.
  let inboxId: string | null = scope.fixedInboxId;
  let inboxEmail: string | null = null;
  if (opts.createInbox) {
    let created: CreatedInbox;
    try {
      created = await client.post<CreatedInbox>("/inboxes", { domain });
    } catch (e) {
      // The refusals a person can act on (INBOX_REFUSALS) get their own line (the key was fine — /auth/me passed
      // above). Anything else rethrows to the CLI's generic handler.
      const why = e instanceof CoreError ? (e.coreCode ?? e.code) : "";
      const human = INBOX_REFUSALS[why];
      if (human) {
        say(human);
        throw new InitAbort(human);
      }
      throw e;
    }
    inboxId = typeof created.inbox_id === "string" ? created.inbox_id : inboxId;
    inboxEmail = typeof created.email === "string" ? created.email : null;
    if (inboxEmail) say("init_inbox_created", inboxEmail);
  }

  // The key that lands on disk is exactly the one the user provided (env or prompt) — the agent is the
  // account's full operator, so it runs with the key the user chose to give it.

  // --print mode: show the real-target block(s) and write nothing.
  if (opts.print) {
    printBlocks(key, opts, out, locale);
    say("init_key_power"); // the REAL key was just printed for paste (the placeholder path above isn't)
    return {
      printed: true,
      inboxId,
      inboxEmail,
      written: [],
      printedFor: targetsFor(opts).map((t) => t.id),
    };
  }

  // Write to each targeted client. A write that fails safely (corrupt/outside-home) becomes a print
  // fallback for THAT client, never an aborted install.
  const written: string[] = [];
  const printedFor: string[] = [];
  const targets = targetsFor(opts);
  for (const t of targets) {
    if (t.mode === "print") {
      say("init_print_only_client");
      out(blockFor(t, key));
      printedFor.push(t.id);
      continue;
    }
    try {
      writeJsonConfig(t.path, homeOf(opts), key);
      say("init_config_written", t.label);
      written.push(t.id);
    } catch (e) {
      if (e instanceof ConfigWriteError) {
        say("init_print_only_client");
        out(blockFor(t, key));
        printedFor.push(t.id);
      } else {
        throw e;
      }
    }
  }

  if (written.length === 0 && printedFor.length === 0) {
    // No target at all resolved — detection was too uncertain to touch anything: print for everyone.
    say("init_no_client");
    out(printableJson(key));
  }
  // Whether written or printed for paste, the real key now sits in a config: say what it can do.
  say("init_key_power");
  if (written.length > 0) {
    say("init_restart_client");
    say("init_done");
  }

  return {
    printed: false,
    inboxId,
    inboxEmail,
    written,
    printedFor,
  };
}

/** The client targets for this run: one by id, or all known clients. */
function targetsFor(opts: InitOptions): ClientTarget[] {
  const all = clientTargets(homeOf(opts));
  if (!opts.client) return all;
  const one = all.find((t) => t.id === opts.client);
  return one ? [one] : [];
}

// The CLI passes no home: it MUST be the user's real HOME. An empty string here resolved every client
// path against the cwd and wrote the key in plain text into the project the user ran init from (0.1.0).
function homeOf(opts: InitOptions): string {
  return opts.home || homedir();
}

/** Print the MCP block for each targeted client in its own format (JSON for most, TOML for Codex). */
function printBlocks(
  key: string,
  opts: InitOptions,
  out: (l: string) => void,
  locale: Locale,
): void {
  const targets = targetsFor(opts);
  if (targets.length === 0) {
    out(humanMessage("init_no_client", locale));
    out(printableJson(key));
    return;
  }
  for (const t of targets) out(blockFor(t, key));
}

/** The pasteable block for one client in its native format. */
function blockFor(t: ClientTarget, key: string): string {
  return t.id === "codex" ? printableCodexToml(key) : printableJson(key);
}

/** Obtain the key when none was in the environment: the prompt (interactive) must be supplied. */
async function requireKey(opts: InitOptions): Promise<string> {
  if (!opts.promptKey) {
    // No key and no way to ask: fail closed with the same code the server uses for a missing key.
    const locale = opts.locale ?? resolveLocale();
    (opts.out ?? ((l: string) => process.stderr.write(l + "\n")))(
      humanMessage("no_api_key", locale),
    );
    throw new InitAbort("no_api_key");
  }
  return (await opts.promptKey()).trim();
}

function emptyPrintResult(): InitResult {
  return {
    printed: true,
    inboxId: null,
    inboxEmail: null,
    written: [],
    printedFor: [],
  };
}

/** The core's create-inbox refusals a person can act on -> their human line. `platform_inbox_not_allowed`,
 *  `inbox_limit` and `missing_permission` arrive as a 403 (collapsed to not_found, real code in coreCode);
 *  `domain_not_verified` as a 422. */
const INBOX_REFUSALS: Record<string, string> = {
  platform_inbox_not_allowed: "init_inbox_platform_domain",
  domain_not_verified: "init_inbox_domain_not_verified",
  inbox_limit: "init_inbox_limit",
  missing_permission: "init_inbox_missing_permission",
};

/** `--domain` as the core stores it: lowercase, no trailing dot, IDN in punycode (`café.com` ->
 *  `xn--caf-dma.com`). ASCII is restricted to letters/digits/dot/hyphen BEFORE the conversion, because
 *  `domainToASCII` parses a URL host and would silently cut `acme.com/x` down to `acme.com`. The caller
 *  passes it already trimmed. */
export function normalizeDomain(raw: string): string {
  const d = raw.toLowerCase();
  if (!/^[a-z0-9.\-\u{80}-\u{10ffff}]+$/u.test(d)) return "";
  return domainToASCII(d).replace(/\.$/, "");
}

/** A basic domain-name shape (labels of letters/digits/hyphens, a dot, a TLD) — catches a typo or a flag
 *  swallowed as the value BEFORE any request. The core is the authority on whether it is verified. */
function looksLikeDomain(d: string): boolean {
  return d.length <= 253 && /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(d);
}

/** A clean, key-free abort for a missing prerequisite (the CLI turns it into exit code 1). */
export class InitAbort extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "InitAbort";
    this.code = code;
  }
}
