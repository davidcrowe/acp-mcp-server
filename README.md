# Agentic Control Plane — MCP Server

Pre-tool-use governance for AI agents. Call `acp_check` before any sensitive tool invocation to get an allow, deny, or ask decision backed by your workspace policies, PII redaction, per-tier rate limits, and structured audit logging.

**Live endpoint:** `https://mcp.agenticcontrolplane.com/mcp`
**Website:** https://agenticcontrolplane.com
**Dashboard:** https://cloud.agenticcontrolplane.com

## Connecting from Claude, ChatGPT, Cursor, and other MCP clients

Add the MCP server URL to your client:

```
https://mcp.agenticcontrolplane.com/mcp
```

On first connection, your client will walk you through an OAuth sign-in (Google). A workspace is auto-provisioned for your account if you don't have one yet. Subsequent tool calls are attributed to you automatically.

**Claude Desktop:** Settings → Connectors → Add custom connector → paste the URL.
**ChatGPT:** Settings → Connectors → Add → paste the URL.
**MCP Inspector:** `npx @modelcontextprotocol/inspector` → paste URL, click "Connect".

## Tools

### `acp_check`

Check whether a proposed tool call is allowed. Call this before executing any sensitive action.

| Param | Type | Required | Description |
|---|---|---|---|
| `tool_name` | string | ✅ | Name of the tool about to be called (e.g. `notion.readPage`, `Bash`) |
| `tool_input` | string | ✅ | JSON string of the tool arguments |
| `client_name` | string | — | Overridden by OAuth key tag |
| `agent_tier` | string | — | `interactive` \| `subagent` \| `background` \| `api` |

Returns: `{ decision: "allow" | "deny" | "ask", reason: string, tool: string }`

Annotations: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`.

### `acp_status`

Check ACP governance connectivity and policy mode. Takes no arguments.

Returns: `"ACP: Connected. Mode: audit-only. Dashboard: https://cloud.agenticcontrolplane.com"`

Annotations: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`.

## Security model

- **OAuth 2.1** with PKCE (S256) + Dynamic Client Registration per RFC 7591.
- **Per-user API keys** minted at `/token` exchange — each user's tool calls land in their own workspace, never a shared one.
- **Client attribution** — the DCR `client_name` (Claude, ChatGPT, Cursor, etc.) is tagged onto each key at mint time and surfaces in audit logs.
- **Rate limiting** — 30 req/min on OAuth endpoints, 100 req/min global.
- **No third-party data sharing** — tool calls proxy only to `api.agenticcontrolplane.com`.
- **HTTPS only** — no plaintext transport.

## Debugging

**Can't complete OAuth?**
- Clear any cached registration in your MCP client and retry
- Claude Code: `security delete-generic-password -s "Claude Code-credentials" && rm ~/.claude/mcp-needs-auth-cache.json`

**Not seeing tool calls in the audit log?**
- Check https://cloud.agenticcontrolplane.com → Activity Log, filter by your workspace
- Confirm the right Google account is signed in (the OAuth popup account determines the workspace)

**`gsk_` key not working?**
- Keys issued via MCP OAuth are scoped to that client install. Revoke in dashboard → API keys, then re-run the OAuth flow.

## Support

Email: **hello@agenticcontrolplane.com**
Issues: https://github.com/davidcrowe/acp-mcp-server/issues

## License

MIT. See `LICENSE`.
