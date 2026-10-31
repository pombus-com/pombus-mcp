// The MCP server — a thin stdio adapter over the tool catalog. It registers the tools the scope
// allows, dispatches CallTool to the matching handler, and translates failures into a tool error the
// model can read. It never reimplements core logic; every call is one REST request.
//
// Log hygiene (AGENTS.md §5, audited by pombus-sec): the stdio stream IS the MCP channel, so nothing
// but protocol frames may touch stdout. Diagnostics go to stderr, and NOTHING we print ever includes
// the API key — the key lives only in the client's Authorization header, never in an argument, a URL,
// or an error message surfaced here.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { CoreClient, CoreError, readApiKey } from "./client.js";
import { ScopeBinding, ScopeError } from "./scope.js";
import { specByName, toolDescriptors, callTool, ToolArgError } from "./tools.js";

const SERVER_NAME = "pombus";
const SERVER_VERSION = "0.1.0";

/** Build and connect the MCP server over stdio. Fails fast (before connecting) when the key is absent,
 *  so a misconfigured client sees a clear stderr line instead of a server that answers every tool with
 *  an auth error. */
export async function runMcpServer(): Promise<void> {
  const { humanMessage, humanCodeForBoot } = await import("./i18n.js");
  const apiKey = readApiKey();
  if (!apiKey) {
    // Human-facing, localized, to stderr — never stdout (would corrupt the MCP stream).
    process.stderr.write(humanMessage("no_api_key") + "\n");
    process.exitCode = 1;
    return;
  }
  const client = new CoreClient({ apiKey });
  let server: Server;
  try {
    // buildServer resolves the key's scope (one /v0/auth/me call). A human runs the server, so a boot
    // failure here is human-facing: localize the REAL cause — a rejected key (auth_failed) or an
    // unreachable core (network) — instead of a generic line. CoreError already carries only a safe,
    // key-free code.
    server = await buildServer(client);
  } catch (e) {
    const code = e instanceof CoreError ? humanCodeForBoot(e.code) : "unknown";
    process.stderr.write(humanMessage(code) + "\n");
    process.exitCode = 1;
    return;
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

/** Build the Server bound to a given core client. Exposed so tests drive it with a fake core and
 *  without a real stdio transport. Resolves the key's scope up front (one /v0/auth/me call) so the
 *  tool schemas can omit inbox_id for a single-inbox key. */
export async function buildServer(client: CoreClient): Promise<Server> {
  const scope = await ScopeBinding.resolve(client);
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolDescriptors(scope),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
    // specByName honours the gate: a tool the key may not use is "unknown" here, exactly as it is
    // absent from ListTools — the model can neither see nor call a tool outside its permissions.
    const spec = specByName(req.params.name, scope);
    if (!spec) return toolError(`unknown tool: ${req.params.name}`);
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    try {
      const value = await callTool(spec, args, { client, scope });
      return { content: [{ type: "text", text: toText(value) }] };
    } catch (e) {
      return toolError(modelError(e));
    }
  });

  return server;
}

/** Serialize a handler result for the model. undefined (e.g. a 204) becomes an explicit ok marker. */
function toText(value: unknown): string {
  if (value === undefined) return JSON.stringify({ ok: true });
  return JSON.stringify(value);
}

/** A CallTool result flagged as an error (isError), carrying model-facing en-US text. */
function toolError(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

/** Map a thrown error to a stable, locale-free string for the model. Never leaks the key or a URL:
 *  CoreError/ScopeError/ToolArgError already carry only a safe code; anything else collapses to a
 *  generic message so an unexpected throw can't smuggle a secret into the tool output. */
function modelError(e: unknown): string {
  if (e instanceof CoreError) return `error: ${e.code}`;
  if (e instanceof ScopeError) return `error: ${e.code}`;
  if (e instanceof ToolArgError) return `error: ${e.code}`;
  return "error: internal";
}
