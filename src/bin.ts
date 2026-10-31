#!/usr/bin/env node
// The `pombus` CLI entrypoint. Three subcommands:
//   - `pombus mcp`    — the stdio MCP server a client invokes (F4).
//   - `pombus init`   — the installer: read key, (opt) create inbox, write MCP config (F5).
//   - `pombus doctor` — validate the key and report its scope (F5).
// Flag parsing is a tiny manual argv walk (ponytail: no commander/yargs). `--help` prints usage.
//
// parseArgs is exported and pure; main() runs ONLY when this file is the process entrypoint (guarded
// at the bottom), so a test can import parseArgs without the CLI firing.

import { createInterface } from "node:readline";
import { argv } from "node:process";
import { fileURLToPath } from "node:url";
import { CoreError, readApiKey } from "./client.js";
import { runMcpServer } from "./server.js";
import { runInit, InitAbort } from "./init.js";
import { runDoctor } from "./doctor.js";
import { humanCodeForBoot, humanMessage, resolveLocale, type Locale } from "./i18n.js";

/** The parsed CLI surface. Kept small and pure so a test can assert the parse without a process. */
export interface ParsedArgs {
  cmd: string | undefined;
  createInbox: boolean;
  print: boolean;
  help: boolean;
  locale: Locale | undefined;
  client: string | undefined;
}

const VALID_LOCALES: readonly Locale[] = ["en-US", "pt-BR", "es-419"];

/** Parse argv (the slice AFTER `node bin.js`). Unknown flags are ignored rather than fatal — a thin
 *  installer should not reject a future client's extra flag. `--locale`/`--client` take the next arg
 *  or an `=value`. An invalid locale is dropped (falls back to env detection). */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const out: ParsedArgs = {
    cmd: undefined,
    createInbox: false,
    print: false,
    help: false,
    locale: undefined,
    client: undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!out.cmd && !a.startsWith("-")) {
      out.cmd = a;
      continue;
    }
    if (a === "--create-inbox") out.createInbox = true;
    else if (a === "--print" || a === "--dry-run") out.print = true;
    else if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--locale" || a.startsWith("--locale=")) {
      const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[++i];
      if (v && (VALID_LOCALES as readonly string[]).includes(v)) out.locale = v as Locale;
    } else if (a === "--client" || a.startsWith("--client=")) {
      const v = a.includes("=") ? a.slice(a.indexOf("=") + 1) : argv[++i];
      if (v) out.client = v;
    }
  }
  return out;
}

const USAGE = [
  "usage: pombus <command> [options]",
  "",
  "commands:",
  "  mcp       run the stdio MCP server (invoked by your client)",
  "  init      write the Pombus MCP config into your client",
  "  doctor    check your API key and report its scope",
  "",
  "init options:",
  "  --create-inbox     create a new inbox and bind the config to it",
  "  --print            print the config block instead of writing it",
  "  --client <id>      target one client (claude-code|cursor|gemini|codex)",
  "  --locale <loc>     en-US | pt-BR | es-419",
].join("\n");

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || !args.cmd) {
    process.stdout.write(USAGE + "\n");
    process.exitCode = args.cmd ? 0 : 2;
    return;
  }

  if (args.cmd === "mcp") {
    await runMcpServer();
    return;
  }

  if (args.cmd === "init") {
    await runInit({
      apiKey: readApiKey() ?? undefined,
      createInbox: args.createInbox,
      print: args.print,
      ...(args.client !== undefined ? { client: args.client } : {}),
      ...(args.locale !== undefined ? { locale: args.locale } : {}),
      home: undefined, // init.ts homeOf() falls back to os.homedir(); clients.ts refuses an unsafe HOME
      promptKey: promptKeyHidden,
    });
    return;
  }

  if (args.cmd === "doctor") {
    const res = await runDoctor({
      apiKey: readApiKey() ?? undefined,
      ...(args.locale !== undefined ? { locale: args.locale } : {}),
    });
    process.exitCode = res.ok ? 0 : 1;
    return;
  }

  process.stderr.write(`unknown command: ${args.cmd}\n` + USAGE + "\n");
  process.exitCode = 2;
}

/** Read a key from the TTY without echoing it. readline writes the prompt; we mute the output stream
 *  while the user types so the secret never lands in the terminal scrollback. The prompt text itself
 *  is written before muting so the user still sees it. Falls back to a normal (echoing) read when
 *  stdin is not a TTY (piped input) — there is nothing to hide there. */
async function promptKeyHidden(): Promise<string> {
  const locale = resolveLocale();
  const prompt = humanMessage("init_prompt_key", locale);
  const input = process.stdin;
  const output = process.stdout;

  const rl = createInterface({ input, output, terminal: true });
  // Mute: replace the interface's write of typed characters with nothing, but keep the initial prompt.
  output.write(prompt);
  const rlAny = rl as unknown as { _writeToOutput?: (s: string) => void };
  const originalWrite = rlAny._writeToOutput;
  rlAny._writeToOutput = () => {
    /* swallow keystroke echo */
  };
  try {
    const answer = await new Promise<string>((res) => rl.question("", res));
    output.write("\n");
    return answer;
  } finally {
    if (originalWrite) rlAny._writeToOutput = originalWrite;
    rl.close();
  }
}

/** True when this module is the process entrypoint (run as `node bin.js` / the `pombus` bin), as
 *  opposed to being imported by a test. Compares the resolved module path to argv[1]. */
function isEntrypoint(): boolean {
  const invoked = argv[1];
  if (!invoked) return false;
  try {
    return fileURLToPath(import.meta.url) === invoked;
  } catch {
    return false;
  }
}

if (isEntrypoint()) {
  main().catch((e: unknown) => {
    // Last-resort guard: never print the key or a stack that could carry one. Localize the REAL cause
    // when it is a CoreError (a human ran us); a clean InitAbort already printed its own line.
    if (e instanceof InitAbort) {
      process.exitCode = 1;
      return;
    }
    const code = e instanceof CoreError ? humanCodeForBoot(e.code) : "unknown";
    process.stderr.write(humanMessage(code) + "\n");
    process.exitCode = 1;
  });
}
