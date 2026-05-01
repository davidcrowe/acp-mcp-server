# ACP Governance MCP Server

> Model Context Protocol server that lets Claude, ChatGPT, Cursor, Lovable, and any MCP client check tool calls against [Agentic Control Plane](https://agenticcontrolplane.com) governance — policy decisions, rate limits, audit logs, identity attribution.

**One sentence:** before your AI agent runs a sensitive tool, it asks ACP whether the call is allowed. ACP says yes, no, or asks for confirmation, and writes an audit row attributable to the human behind the agent.

## What it exposes

Two tools, callable via MCP:

| Tool | What it does |
|---|---|
| `acp_check` | Ask ACP whether a tool call should be allowed. Returns `allow` / `deny` / `ask` plus a reason. |
| `acp_status` | Verify the connection and your workspace identity. |

That's the whole surface. Everything else — policies, audit logs, scope intersection, delegation chains — runs server-side at `api.agenticcontrolplane.com`. This MCP server is just the bridge.

## Install (hosted — recommended)

The server is hosted at **`https://mcp.agenticcontrolplane.com/mcp`**. Add it as a connector in your MCP client:

**Claude Desktop / Claude.ai connector:**
```
URL: https://mcp.agenticcontrolplane.com/mcp
Auth: OAuth (sign in with Google through ACP)
```

**ChatGPT, Cursor, Lovable, Cline:**
Same URL, same OAuth flow. Most clients have a one-click "Add MCP Server" UI.

**Programmatic clients** (your own agent code):
```http
POST https://mcp.agenticcontrolplane.com/mcp
Authorization: Bearer gsk_<your-acp-api-key>
Content-Type: application/json
```

You'll need an ACP workspace. The free tier is unlimited tool-call logging — sign up at [cloud.agenticcontrolplane.com/login](https://cloud.agenticcontrolplane.com/login).

## Install (self-host)

If you want to run the bridge yourself — for air-gapped deployments, or to point at a self-hosted ACP gateway — clone and run:

```bash
git clone https://github.com/davidcrowe/acp-mcp-server
cd acp-mcp-server
npm install
npm run build

# Point at the ACP API (default: https://api.agenticcontrolplane.com)
export ACP_API_BASE=https://your-acp-gateway.example.com

# Optional: service-level API key for OAuth users (ChatGPT, Claude.ai)
# whose JWTs aren't directly usable as ACP tokens
export ACP_SERVICE_KEY=gsk_workspace_...

npm start
# → MCP endpoint: POST http://0.0.0.0:3000/mcp
# → OAuth discovery: GET /.well-known/oauth-protected-resource
```

The bridge speaks streamable-HTTP MCP and proxies to ACP's `/govern/tool-use` endpoint.

## How it fits

```
your AI client            this MCP server          ACP gateway
─────────────            ─────────────────         ───────────
Claude / ChatGPT  ──►  mcp.agenticcontrolplane  ──►  api.agenticcontrolplane
Cursor / Lovable    POST /mcp (acp_check)         POST /govern/tool-use
                                                      ↓
                                                   policy + audit + identity
                                                      ↓
                                                   allow / deny / ask
```

Every call writes an audit row attributable to the human identity behind the OAuth session — so you get a complete log of every governed tool call across every MCP client your team uses, in one workspace.

## Auth model

The server supports two authentication paths:

1. **OAuth (recommended for human-driven clients)** — Claude.ai, ChatGPT, etc. complete an OAuth flow against ACP's identity provider; the resulting Auth0 JWT identifies the human. The bridge uses an `ACP_SERVICE_KEY` to authorize the underlying governance call on the human's behalf.
2. **Bearer `gsk_` API key (recommended for programmatic clients)** — pass an ACP API key directly as `Authorization: Bearer gsk_...`. The key's identity is the ACP-side actor. Skip OAuth.

OAuth discovery metadata is served at `/.well-known/oauth-protected-resource` per the MCP authorization spec.

## Local development

```bash
npm install
npm run dev        # tsx-based hot reload
```

Tools are defined in `src/tools/tools.ts`. The MCP JSON-RPC handler is in `src/handlers/mcpHandler.ts`. The Express entry point and rate limits are in `src/server/expressServer.ts`.

## License

MIT — see [LICENSE](LICENSE).

## Links

- [ACP — full product](https://agenticcontrolplane.com)
- [Sign up (free tier)](https://cloud.agenticcontrolplane.com/login)
- [Governance benchmark](https://github.com/agentic-control-plane/agentgovbench)
- [Issues / questions](https://github.com/davidcrowe/acp-mcp-server/issues)
