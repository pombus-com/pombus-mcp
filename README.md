# Pombus MCP server

Email boxes for AI agents — the opposite of a webmail client. Pombus gives a
person and their AI agents their own mailboxes; the agent operates the mailbox
over the [Model Context Protocol](https://modelcontextprotocol.io) while the
human stays in the loop.

This package is the MCP server: a thin stdio translator between a client's MCP
tool calls and the Pombus REST API. It holds no mail and no logic of its own —
every read, draft and send is a call to the Pombus core. Learn more at
[pombus.com](https://pombus.com).

<!-- mcp-name: com.pombus/pombus -->

## Install

One command wires Pombus into your MCP client:

```sh
npx pombus init
```

`init` reads your API key, detects your client, and writes the MCP server block
into its config (merging, never clobbering the rest of the file). Detected
clients: **Claude Code**, **Cursor**, **Gemini CLI**, and **Codex CLI** (Codex
uses TOML, so `init` prints the block for you to paste).

```sh
npx pombus init --print                 # print the config block, write nothing
npx pombus init --client cursor         # target one client
npx pombus init --create-inbox          # create an inbox during setup
```

## Commands

| Command         | What it does                                                        |
| --------------- | ------------------------------------------------------------------- |
| `pombus mcp`    | Run the stdio MCP server. Your client invokes this; you rarely do.  |
| `pombus init`   | Write the Pombus MCP config into your client.                       |
| `pombus doctor` | Validate your API key and report its scope. Read-only, one request. |

## Authentication

Set `POMBUS_API_KEY` in the environment. `init` writes it into the MCP server
block for you; the key never lands in your terminal scrollback. Get a key at
[pombus.com](https://pombus.com).

```json
{
  "mcpServers": {
    "pombus": {
      "command": "npx",
      "args": ["-y", "pombus", "mcp"],
      "env": { "POMBUS_API_KEY": "<YOUR_POMBUS_API_KEY>" }
    }
  }
}
```

## The tools are gated by your key

The server exposes a catalog of 53 tools — list and read threads, search, label,
compose and send drafts, manage lists, read metrics. But **your API key decides
what the agent actually sees.** A tool is only registered when the key holds the
permission that tool needs; a key without send permission never sees a send
tool, so the agent cannot call it. The same key also fixes the scope: an
inbox-scoped key binds a single inbox, and tools drop the `inbox_id` argument
entirely — the agent physically cannot address another inbox.

**Draft-first is the default write path.** Composing a message creates a draft
(`create_draft`) for a human to review; sending is a separate, explicit step
(`send_draft`). Direct, unreviewed send exists only for keys that explicitly
hold send permission — most keys stay draft-only.

Run `pombus doctor` to see exactly which scope your key resolves to.

## License

[MIT](./LICENSE) © Runaki
