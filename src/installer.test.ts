import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInit } from "./init.js";
import { runDoctor } from "./doctor.js";
import {
  clientTargets,
  writeJsonConfig,
  isInsideHome,
  printableJson,
  printableCodexToml,
  ConfigWriteError,
} from "./clients.js";
import { FakeCore, authMeInbox, authMePod, createdInbox } from "./testutil.js";

// Obviously-fake tokens — never a real secret (AGENTS.md §9).
const BROAD_KEY = "pk_test_broad_pod_scope_FAKE";
const BASE = "https://core.test/v0";

/** A temp HOME, cleaned up after each use. */
function tempHome(): { home: string; cleanup: () => void } {
  const home = mkdtempSync(join(tmpdir(), "pombus-home-"));
  return { home, cleanup: () => rmSync(home, { recursive: true, force: true }) };
}

/** A line sink that records init/doctor human output for assertions. */
function sink(): { lines: string[]; out: (l: string) => void } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l) };
}

// ---------------------------------------------------------------------------------------------------
// clients.ts — the write is the sharp edge: merge, idempotent, atomic-ish, 0600, never outside HOME.
// ---------------------------------------------------------------------------------------------------

test("writeJsonConfig MERGES — preserves every existing key, adds only mcpServers.pombus", () => {
  const { home, cleanup } = tempHome();
  try {
    const path = join(home, ".claude.json");
    writeFileSync(
      path,
      JSON.stringify({
        projects: { "/some/proj": { history: [1, 2, 3] } },
        theme: "dark",
        mcpServers: { other: { command: "node", args: ["x.js"] } },
      }),
    );
    writeJsonConfig(path, home, BROAD_KEY);
    const after = JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;
    // Untouched keys survive byte-for-value.
    assert.deepEqual(after["projects"], { "/some/proj": { history: [1, 2, 3] } });
    assert.equal(after["theme"], "dark");
    // The pre-existing OTHER server survives; ours is added alongside.
    assert.deepEqual(after["mcpServers"]["other"], { command: "node", args: ["x.js"] });
    assert.deepEqual(after["mcpServers"]["pombus"], {
      command: "npx",
      args: ["-y", "pombus", "mcp"],
      env: { POMBUS_API_KEY: BROAD_KEY },
    });
  } finally {
    cleanup();
  }
});

test("writeJsonConfig is IDEMPOTENT — running twice yields exactly one pombus entry", () => {
  const { home, cleanup } = tempHome();
  try {
    const path = join(home, ".cursor", "mcp.json");
    writeJsonConfig(path, home, BROAD_KEY);
    writeJsonConfig(path, home, BROAD_KEY);
    const after = JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;
    const servers = after["mcpServers"] as Record<string, unknown>;
    assert.deepEqual(Object.keys(servers), ["pombus"]);
  } finally {
    cleanup();
  }
});

test("writeJsonConfig creates a fresh file when none exists (and its parent dir)", () => {
  const { home, cleanup } = tempHome();
  try {
    const path = join(home, ".gemini", "settings.json");
    writeJsonConfig(path, home, BROAD_KEY);
    const after = JSON.parse(readFileSync(path, "utf8")) as Record<string, any>;
    assert.equal(after["mcpServers"]["pombus"]["env"]["POMBUS_API_KEY"], BROAD_KEY);
  } finally {
    cleanup();
  }
});

test("writeJsonConfig REFUSES to clobber a corrupt existing config (never destroys real state)", () => {
  const { home, cleanup } = tempHome();
  try {
    const path = join(home, ".claude.json");
    writeFileSync(path, "{ this is not valid json ");
    assert.throws(
      () => writeJsonConfig(path, home, BROAD_KEY),
      (e: unknown) => e instanceof ConfigWriteError && e.code === "corrupt_config",
    );
    // The broken file is left exactly as it was — not overwritten.
    assert.equal(readFileSync(path, "utf8"), "{ this is not valid json ");
  } finally {
    cleanup();
  }
});

test("writeJsonConfig REFUSES a target outside HOME (never writes into a project repo)", () => {
  const { home, cleanup } = tempHome();
  try {
    const outside = join(tmpdir(), "not-home-" + process.pid, "mcp.json");
    assert.throws(
      () => writeJsonConfig(outside, home, BROAD_KEY),
      (e: unknown) => e instanceof ConfigWriteError && e.code === "outside_home",
    );
  } finally {
    cleanup();
  }
});

test("isInsideHome accepts HOME and children, rejects siblings and the project tree", () => {
  const home = join(tmpdir(), "h");
  assert.ok(isInsideHome(join(home, ".cursor", "mcp.json"), home));
  assert.ok(isInsideHome(home, home));
  assert.ok(!isInsideHome(join(tmpdir(), "hother", "x.json"), home));
  assert.ok(!isInsideHome("/etc/mcp.json", home));
});

test("the config file carrying the key is 0600 on POSIX (owner-only)", { skip: process.platform === "win32" }, () => {
  const { home, cleanup } = tempHome();
  try {
    const path = join(home, ".cursor", "mcp.json");
    writeJsonConfig(path, home, BROAD_KEY);
    const mode = statSync(path).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600, got ${mode.toString(8)}`);
  } finally {
    cleanup();
  }
});

test("the client table: claude-code/cursor/gemini are WRITE (json), codex is PRINT (toml)", () => {
  const home = join(tmpdir(), "h");
  const t = clientTargets(home);
  const by = Object.fromEntries(t.map((c) => [c.id, c]));
  assert.equal(by["claude-code"]!.mode, "json");
  assert.equal(by["cursor"]!.mode, "json");
  assert.equal(by["gemini"]!.mode, "json");
  assert.equal(by["codex"]!.mode, "print");
  // Every target carries a cited source and a path under HOME.
  for (const c of t) {
    assert.ok(c.source.length > 0, `${c.id} missing source`);
    assert.ok(isInsideHome(c.path, home), `${c.id} path escapes HOME`);
  }
});

test("printable blocks: JSON has the standard mcpServers wrapper; Codex TOML is a [mcp_servers.pombus] table", () => {
  const j = JSON.parse(printableJson("<KEY>")) as any;
  assert.deepEqual(j.mcpServers.pombus, {
    command: "npx",
    args: ["-y", "pombus", "mcp"],
    env: { POMBUS_API_KEY: "<KEY>" },
  });
  const toml = printableCodexToml("<KEY>");
  assert.ok(toml.includes("[mcp_servers.pombus]"));
  assert.ok(toml.includes('command = "npx"'));
  assert.ok(toml.includes("POMBUS_API_KEY = '<KEY>'"));
});

// ---------------------------------------------------------------------------------------------------
// runInit key contract (option A): the key the user provided is persisted verbatim — no mint, no
// narrowing. The agent is the account's full operator and runs with the key the user chose to give.
// ---------------------------------------------------------------------------------------------------

test("init persists EXACTLY the provided key — never mints a new one (no POST /api-keys)", async () => {
  const { home, cleanup } = tempHome();
  try {
    // --create-inbox on a pod key: an inbox is created, but the key written is still the given one.
    const fake = new FakeCore()
      .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod())
      .on("POST", (u) => u.pathname.endsWith("/inboxes"), createdInbox("inb_new", "agent@pombus.com"));
    const { out } = sink();
    const res = await runInit({
      apiKey: BROAD_KEY,
      createInbox: true,
      client: "cursor",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "en-US",
      out,
    });
    assert.deepEqual(res.written, ["cursor"]);
    assert.equal(res.inboxId, "inb_new"); // --create-inbox still works, independent of the key

    const cfg = JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8")) as any;
    assert.equal(cfg.mcpServers.pombus.env.POMBUS_API_KEY, BROAD_KEY, "the provided key is persisted as-is");

    // No key was minted — the installer never hits POST /api-keys.
    assert.ok(!fake.requests.some((r) => r.method === "POST" && r.url.includes("/api-keys")));
  } finally {
    cleanup();
  }
});

// 0.1.0 critical: the CLI calls runInit WITHOUT `home`, and the key landed in plain text in the cwd
// (the user's repo) instead of HOME. Drive the exact CLI shape: no `home`, HOME env and cwd apart.
test("init with no `home` writes into os.homedir(), never into the cwd", async () => {
  const { home, cleanup } = tempHome();
  const cwd = mkdtempSync(join(tmpdir(), "pombus-repo-"));
  const saved = { HOME: process.env["HOME"], USERPROFILE: process.env["USERPROFILE"], cwd: process.cwd() };
  process.env["HOME"] = home;
  process.env["USERPROFILE"] = home;
  process.chdir(cwd);
  try {
    const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod());
    const { lines, out } = sink();
    const res = await runInit({ apiKey: BROAD_KEY, client: "cursor", baseUrl: BASE, fetchImpl: fake.fetch, locale: "en-US", out });
    assert.deepEqual(res.written, ["cursor"]);
    assert.equal(
      (JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8")) as any).mcpServers.pombus.env.POMBUS_API_KEY,
      BROAD_KEY,
    );
    assert.throws(() => statSync(join(cwd, ".cursor", "mcp.json")), "nothing may be written into the cwd");
    assert.ok(lines.some((l) => l.includes("everything this key can")), "init declares the key's power");
  } finally {
    process.chdir(saved.cwd);
    for (const k of ["HOME", "USERPROFILE"] as const) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(cwd, { recursive: true, force: true });
    cleanup();
  }
});

// Every path that leaves the REAL key in front of the user says once what it can do; the placeholder
// print (no key) does not, since nothing powerful was handed out.
test("the key-power notice: once on write (before restart), once on --print with a real key, never on placeholder", async () => {
  const notice = "everything this key can";
  const { home, cleanup } = tempHome();
  try {
    const fake = () => new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod());
    const w = sink();
    await runInit({ apiKey: BROAD_KEY, client: "cursor", home, baseUrl: BASE, fetchImpl: fake().fetch, locale: "en-US", out: w.out });
    const at = w.lines.findIndex((l) => l.includes(notice));
    assert.equal(w.lines.filter((l) => l.includes(notice)).length, 1);
    assert.ok(at >= 0 && at < w.lines.findIndex((l) => l.includes("Restart your client")));

    const p = sink();
    await runInit({ apiKey: BROAD_KEY, print: true, client: "cursor", home, baseUrl: BASE, fetchImpl: fake().fetch, locale: "en-US", out: p.out });
    assert.ok(p.lines.some((l) => l.includes(BROAD_KEY)), "the real key was printed");
    assert.equal(p.lines.filter((l) => l.includes(notice)).length, 1);

    const ph = sink();
    await runInit({ print: true, client: "cursor", home, locale: "en-US", out: ph.out });
    assert.ok(!ph.lines.some((l) => l.includes(notice)));
  } finally {
    cleanup();
  }
});

test("isInsideHome refuses an empty, relative or git-repo HOME (all of them mean 'a project')", () => {
  assert.ok(!isInsideHome(join(process.cwd(), ".claude.json"), ""));
  assert.ok(!isInsideHome(".claude.json", "  "));
  assert.ok(!isInsideHome(".claude.json", ".")); // HOME=. on POSIX: os.homedir() returns "." verbatim
  const { home, cleanup } = tempHome();
  try {
    assert.ok(isInsideHome(join(home, ".cursor", "mcp.json"), home));
    mkdirSync(join(home, ".git")); // a container whose HOME is the app repo (HOME=/app=WORKDIR)
    assert.ok(!isInsideHome(join(home, ".cursor", "mcp.json"), home));
  } finally {
    cleanup();
  }
});

test("init with an inbox-scoped key persists it as-is (no /api-keys call)", async () => {
  const { home, cleanup } = tempHome();
  try {
    const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_fixed"));
    const { out } = sink();
    const res = await runInit({
      apiKey: BROAD_KEY, // the value is opaque to init; it is written verbatim
      client: "cursor",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "en-US",
      out,
    });
    assert.deepEqual(res.written, ["cursor"]);
    assert.ok(!fake.requests.some((r) => r.url.includes("/api-keys")));
    const cfg = JSON.parse(readFileSync(join(home, ".cursor", "mcp.json"), "utf8")) as any;
    assert.equal(cfg.mcpServers.pombus.env.POMBUS_API_KEY, BROAD_KEY);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------------------------------
// --print writes NOTHING.
// ---------------------------------------------------------------------------------------------------

test("init --print writes NO file and emits the block", async () => {
  const { home, cleanup } = tempHome();
  try {
    const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_fixed"));
    const { lines, out } = sink();
    const res = await runInit({
      apiKey: BROAD_KEY,
      print: true,
      client: "cursor",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "en-US",
      out,
    });
    assert.equal(res.printed, true);
    assert.deepEqual(res.written, []);
    // No config file was created.
    assert.throws(() => readFileSync(join(home, ".cursor", "mcp.json"), "utf8"));
    assert.ok(lines.some((l) => l.includes('"pombus"')));
  } finally {
    cleanup();
  }
});

test("init --print with NO key emits a placeholder block, makes no network call, writes nothing", async () => {
  const { home, cleanup } = tempHome();
  try {
    const fake = new FakeCore().on("GET", () => true, { json: {} });
    const { lines, out } = sink();
    const res = await runInit({
      print: true,
      client: "cursor",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "en-US",
      out,
    });
    assert.equal(res.printed, true);
    assert.equal(fake.requests.length, 0, "no network call without a key");
    assert.ok(lines.some((l) => l.includes("<YOUR_POMBUS_API_KEY>")));
  } finally {
    cleanup();
  }
});

test("init on a PRINT-only client (codex) prints TOML and writes no file", async () => {
  const { home, cleanup } = tempHome();
  try {
    const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMeInbox("inb_fixed"));
    const { lines, out } = sink();
    const res = await runInit({
      apiKey: BROAD_KEY,
      client: "codex",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "en-US",
      out,
    });
    assert.deepEqual(res.written, []);
    assert.deepEqual(res.printedFor, ["codex"]);
    assert.throws(() => readFileSync(join(home, ".codex", "config.toml"), "utf8"));
    assert.ok(lines.some((l) => l.includes("[mcp_servers.pombus]")));
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------------------------------
// doctor — reports scope / errors, read-only.
// ---------------------------------------------------------------------------------------------------

test("doctor reports the scope of a valid key", async () => {
  const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod());
  const { lines, out } = sink();
  const res = await runDoctor({ apiKey: BROAD_KEY, baseUrl: BASE, fetchImpl: fake.fetch, locale: "en-US", out });
  assert.equal(res.ok, true);
  assert.equal(res.scope, "pod");
  assert.ok(lines.some((l) => l.includes("pod")));
  // Read-only: the single request was the /auth/me GET.
  assert.equal(fake.requests.length, 1);
  assert.equal(fake.requests[0]!.method, "GET");
});

test("doctor with no key reports no_api_key and makes no network call", async () => {
  const fake = new FakeCore().on("GET", () => true, { json: {} });
  const { out } = sink();
  const res = await runDoctor({ baseUrl: BASE, fetchImpl: fake.fetch, locale: "en-US", out });
  assert.equal(res.ok, false);
  assert.equal(res.code, "no_api_key");
  assert.equal(fake.requests.length, 0);
});

test("doctor with an invalid key reports auth_failed (401/403/404 collapse to not_found -> auth_failed)", async () => {
  const fake = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), { status: 401, json: { code: "unauthorized" } });
  const { out } = sink();
  const res = await runDoctor({ apiKey: "pk_test_bad_FAKE", baseUrl: BASE, fetchImpl: fake.fetch, locale: "en-US", out });
  assert.equal(res.ok, false);
  assert.equal(res.code, "auth_failed");
});

test("doctor with an unreachable core reports network", async () => {
  const fetchImpl = async () => {
    throw new TypeError("fetch failed");
  };
  const { out } = sink();
  const res = await runDoctor({ apiKey: "pk_test_x_FAKE", baseUrl: BASE, fetchImpl, locale: "en-US", out });
  assert.equal(res.ok, false);
  assert.equal(res.code, "network");
});

// ---------------------------------------------------------------------------------------------------
// the key never leaks into human output (log hygiene, AGENTS.md §5).
// ---------------------------------------------------------------------------------------------------

test("no human line printed by init or doctor ever contains the BROAD key", async () => {
  const { home, cleanup } = tempHome();
  try {
    const fake = new FakeCore()
      .on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod())
      .on("POST", (u) => u.pathname.endsWith("/inboxes"), createdInbox("inb_new", "agent@pombus.com"));
    const initSink = sink();
    await runInit({
      apiKey: BROAD_KEY,
      createInbox: true,
      client: "cursor",
      home,
      baseUrl: BASE,
      fetchImpl: fake.fetch,
      locale: "pt-BR",
      out: initSink.out,
    });
    for (const l of initSink.lines) assert.ok(!l.includes(BROAD_KEY), `broad key leaked: ${l}`);

    const docSink = sink();
    const fake2 = new FakeCore().on("GET", (u) => u.pathname.endsWith("/auth/me"), authMePod());
    await runDoctor({ apiKey: BROAD_KEY, baseUrl: BASE, fetchImpl: fake2.fetch, locale: "es-419", out: docSink.out });
    for (const l of docSink.lines) assert.ok(!l.includes(BROAD_KEY), `broad key leaked (doctor): ${l}`);
  } finally {
    cleanup();
  }
});
