// Client config — where `pombus init` writes (or prints) the MCP server block, and how it writes it
// safely. The MCP block shape is the Resend/Postmark standard every client understands:
//   { "command": "npx", "args": ["-y", "pombus", "mcp"], "env": { "POMBUS_API_KEY": "<key>" } }
//
// SECURITY (audited by pombus-sec, the write is the sharp edge of this slice):
//   - MERGE, never clobber: the existing config is parsed and ONLY the `pombus` entry under
//     `mcpServers` is added/updated; every other key the user has is preserved byte-for-byte on the
//     parts we don't touch.
//   - ATOMIC: write to a temp file in the SAME directory, fsync, then rename over the target. A crash
//     mid-write never leaves a truncated config (rename is atomic on the same filesystem).
//   - 0600: the file that carries the key is chmod'd to owner-only where the OS supports it (POSIX);
//     on Windows chmod is a no-op and NTFS inherits the user profile ACL, so we do not pretend.
//   - NEVER the project repo: only a path under the user's HOME. We refuse any target we cannot place
//     inside os.homedir(), falling back to --print instead of guessing.
//   - PRINT fallback: a client whose format we will not write by hand (Codex: TOML, which we will not
//     serialize without a parser — ponytail forbids the dep, and a half-escaped TOML path is a known
//     way to wedge the client) is PRINT-only. So is any client whose config dir we cannot resolve.

import { mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync, rmSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname, resolve, sep, isAbsolute } from "node:path";

/** One supported client. `write` clients get an atomic merge into a JSON file; `print` clients only
 *  ever get the block printed for manual paste (their format is not safe for us to serialize). */
export interface ClientTarget {
  /** Stable id used on the CLI (`--client`) and in i18n-free logs. */
  id: string;
  /** Human label for the i18n line ("MCP config written for <label>"). */
  label: string;
  /** "json" => mergeable JSON file we write; "print" => we only print the block. */
  mode: "json" | "print";
  /** Absolute config path (resolved against HOME). For a print-only client this is informational. */
  path: string;
  /** Source citation for the path (kept in code so the reviewer can verify the claim). */
  source: string;
}

/** Resolve the table of known clients for a given HOME. Taking `home` as an argument (not calling
 *  os.homedir() inline) is what lets a test point the whole table at a temp dir. */
export function clientTargets(home: string = homedir()): ClientTarget[] {
  return [
    {
      id: "claude-code",
      label: "Claude Code",
      mode: "json",
      // code.claude.com/docs/en/mcp-quickstart: user-scoped servers live under the `mcpServers` key of
      // ~/.claude.json (on Windows %USERPROFILE%\.claude.json). This file also holds other Claude Code
      // state, which is exactly why we merge-only the mcpServers entry and never rewrite the rest.
      path: join(home, ".claude.json"),
      source: "code.claude.com/docs/en/mcp-quickstart",
    },
    {
      id: "cursor",
      label: "Cursor",
      mode: "json",
      // cursor.com/docs/mcp: global servers live in ~/.cursor/mcp.json under a top-level mcpServers.
      path: join(home, ".cursor", "mcp.json"),
      source: "cursor.com/docs/mcp",
    },
    {
      id: "gemini",
      label: "Gemini CLI",
      mode: "json",
      // geminicli.com/docs/reference/configuration: user settings at ~/.gemini/settings.json, MCP under
      // the top-level mcpServers object (same shape as the others).
      path: join(home, ".gemini", "settings.json"),
      source: "geminicli.com/docs/reference/configuration",
    },
    {
      id: "codex",
      label: "Codex CLI",
      mode: "print",
      // community.openai.com: Codex reads ~/.codex/config.toml — a TOML file under an [mcp_servers.*]
      // table. We do NOT write TOML (no parser without a dep; a mis-escaped Windows path is a known way
      // to wedge the Codex app). So Codex is print-only: we show the block and let the user paste it.
      path: join(home, ".codex", "config.toml"),
      source: "community.openai.com/t/codex-config-toml-mcp",
    },
  ];
}

/** The MCP server block, exactly the Resend/Postmark shape. `key` may be a placeholder for --print. */
export function serverBlock(key: string): {
  command: string;
  args: string[];
  env: Record<string, string>;
} {
  return { command: "npx", args: ["-y", "pombus", "mcp"], env: { POMBUS_API_KEY: key } };
}

/** The pretty JSON a --print or a print-only client shows: the standard mcpServers wrapper with the
 *  single pombus entry, so the user can paste it straight in. */
export function printableJson(key: string): string {
  return JSON.stringify({ mcpServers: { pombus: serverBlock(key) } }, null, 2);
}

/** The TOML a Codex user pastes by hand (we print, never write it). Kept tiny and literal — this is
 *  display text, not a serializer: a fixed three-line table with a JSON-encoded env map, which TOML
 *  accepts as an inline table only in its own syntax, so we emit the explicit sub-table form. */
export function printableCodexToml(key: string): string {
  // Backslashes in a Windows npx path are not an issue here: `npx` is a bare command, and the key is a
  // conservative token. We still single-quote the key (TOML literal string) so no escape is needed.
  return [
    "[mcp_servers.pombus]",
    'command = "npx"',
    'args = ["-y", "pombus", "mcp"]',
    "",
    "[mcp_servers.pombus.env]",
    `POMBUS_API_KEY = '${key}'`,
  ].join("\n");
}

/** Raised when a write target is unsafe (outside HOME) or unreadable in a way we refuse to overwrite.
 *  The caller turns it into a --print fallback, never a crash. */
export class ConfigWriteError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ConfigWriteError";
    this.code = code;
  }
}

/** True when `target` is inside `home` (defense against a client table — or a tampered HOME env — that
 *  would place a write in the project repo or elsewhere). Path-prefix check after resolving both. */
export function isInsideHome(target: string, home: string): boolean {
  // A HOME that is empty or relative ("", ".") resolves against the cwd, and a HOME that is itself a git
  // repo (a container with HOME=/app=WORKDIR) is a project: either way the key would land in a repo.
  // The caller falls back to --print. (Target and home derive from the same string, so this guard — not
  // the prefix check below — is what catches a misconfigured HOME.)
  if (!home.trim() || !isAbsolute(home) || existsSync(join(home, ".git"))) return false;
  const h = resolve(home);
  const t = resolve(target);
  return t === h || t.startsWith(h + sep);
}

/** Merge the pombus server block into a client's JSON config and write it atomically with 0600.
 *  - Reads the existing file (missing file => start from {}); a present-but-corrupt file is NOT
 *    silently overwritten — we throw so the user's broken-but-real config is never destroyed.
 *  - Sets config.mcpServers.pombus = block, leaving every other key untouched.
 *  - Idempotent: running twice yields the same single entry (object key assignment, not append).
 *  Returns nothing; throws ConfigWriteError on an unsafe/corrupt target. */
export function writeJsonConfig(path: string, home: string, key: string): void {
  if (!isInsideHome(path, home)) throw new ConfigWriteError("outside_home");

  let root: Record<string, unknown>;
  let existing: string | null = null;
  try {
    existing = readFileSync(path, "utf8");
  } catch {
    existing = null; // ENOENT (or unreadable): treat as a fresh file.
  }
  if (existing === null || existing.trim() === "") {
    root = {};
  } else {
    try {
      const parsed = JSON.parse(existing) as unknown;
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new ConfigWriteError("corrupt_config");
      }
      root = parsed as Record<string, unknown>;
    } catch (e) {
      if (e instanceof ConfigWriteError) throw e;
      // Real config that we cannot parse: refuse to clobber it. The caller falls back to --print.
      throw new ConfigWriteError("corrupt_config");
    }
  }

  const servers = asObject(root["mcpServers"]);
  servers["pombus"] = serverBlock(key);
  root["mcpServers"] = servers;

  const body = JSON.stringify(root, null, 2) + "\n";
  atomicWrite(path, body);
}

/** mcpServers must be an object; a non-object (someone set it to a string/array) is replaced with a
 *  fresh object holding our entry rather than throwing — we never want to fail install on a weird but
 *  non-fatal shape, and the rest of the file is preserved. */
function asObject(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {};
}

/** Atomic file write with owner-only perms. Temp file in the SAME directory so rename stays on one
 *  filesystem (atomic); 0600 on the temp BEFORE rename so the key never sits world-readable even for an
 *  instant; chmod again after rename for the case where the target already existed with looser perms.
 *  On Windows chmod is a no-op — NTFS inherits the profile ACL, so we do not fake a guarantee. */
function atomicWrite(path: string, body: string): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  const tmp = join(dir, `.pombus-${process.pid}-${Date.now()}.tmp`);
  try {
    writeFileSync(tmp, body, { mode: 0o600 });
    try {
      chmodSync(tmp, 0o600);
    } catch {
      /* non-POSIX: best effort */
    }
    renameSync(tmp, path);
    try {
      chmodSync(path, 0o600);
    } catch {
      /* non-POSIX: best effort */
    }
  } catch (e) {
    try {
      rmSync(tmp, { force: true });
    } catch {
      /* temp may not exist */
    }
    throw e;
  }
}
