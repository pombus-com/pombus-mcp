import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "./bin.js";

test("parseArgs: command + flags", () => {
  const a = parseArgs(["init", "--create-inbox", "--print"]);
  assert.equal(a.cmd, "init");
  assert.equal(a.createInbox, true);
  assert.equal(a.print, true);
});

test("parseArgs: --dry-run is an alias for --print", () => {
  assert.equal(parseArgs(["init", "--dry-run"]).print, true);
});

test("parseArgs: --locale with a space or an = ", () => {
  assert.equal(parseArgs(["init", "--locale", "pt-BR"]).locale, "pt-BR");
  assert.equal(parseArgs(["init", "--locale=es-419"]).locale, "es-419");
});

test("parseArgs: an invalid locale is dropped (falls back to env detection)", () => {
  assert.equal(parseArgs(["init", "--locale", "klingon"]).locale, undefined);
});

test("parseArgs: --client selects one target", () => {
  assert.equal(parseArgs(["init", "--client", "cursor"]).client, "cursor");
  assert.equal(parseArgs(["init", "--client=codex"]).client, "codex");
});

test("parseArgs: --help, and no command", () => {
  assert.equal(parseArgs(["--help"]).help, true);
  assert.equal(parseArgs(["doctor", "-h"]).help, true);
  assert.equal(parseArgs([]).cmd, undefined);
});

test("parseArgs: an unknown flag is ignored, not fatal", () => {
  const a = parseArgs(["init", "--some-future-flag", "--print"]);
  assert.equal(a.cmd, "init");
  assert.equal(a.print, true);
});
