# MCP Directory Submission Pack

Materials for submitting `acp-mcp-server` to the Anthropic and OpenAI directories.

## Server basics

| Field | Value |
|---|---|
| Server name | Agentic Control Plane |
| MCP endpoint | `https://mcp.agenticcontrolplane.com/mcp` |
| Transport | Streamable HTTP |
| Auth | OAuth 2.1 / DCR / PKCE (Firebase Google sign-in) |
| Website | https://agenticcontrolplane.com |
| Dashboard | https://cloud.agenticcontrolplane.com |
| Privacy | https://agenticcontrolplane.com/privacy |
| Terms | https://agenticcontrolplane.com/terms |
| Support | support@agenticcontrolplane.com |
| Repository | https://github.com/davidcrowe/acp-mcp-server |

## One-line pitch

Pre-tool-use governance for AI agents. Call `acp_check` before any sensitive action to get an allow/deny decision backed by per-workspace policies, PII transforms, per-tier rate limits, and structured audit logging.

## Short description (Claude / ChatGPT directory blurb)

Agentic Control Plane (ACP) is a governance layer for AI tool calls. Agents call `acp_check` before executing any sensitive tool — reading data, writing data, running shell commands — and ACP returns an `allow`, `deny`, or `ask` decision based on policies the user has configured in their workspace. Every call is logged with per-user identity, tool name, input preview, PII findings, and decision rationale, giving teams a real audit trail and a policy kill-switch for agent actions.

Use cases:
- CISOs who need visibility and control over Claude / ChatGPT agent activity inside their org.
- Developers building autonomous agents who want per-agent-tier rate limits and kill-switches.
- Teams that need PII redaction in flight before tool calls hit external APIs.

## Tools exposed

**`acp_check`** — Check if a proposed tool call is allowed.

Input:
- `tool_name` (string, required) — the tool about to be invoked, e.g. `notion.readPage`
- `tool_input` (string, required) — JSON string of the tool arguments
- `client_name` (string, optional) — overridden by OAuth key tag
- `agent_tier` (string, optional) — `interactive` | `subagent` | `background` | `api`

Output: `{ decision: "allow"|"deny"|"ask", reason: string, tool: string }`

Annotations: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`.

**`acp_status`** — Check governance connectivity and mode.

Input: none

Output: `"ACP: Connected. Mode: audit-only. Dashboard: https://cloud.agenticcontrolplane.com"`

Annotations: `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`.

---

## Three concrete usage examples (required by Claude directory)

### Example 1 — Agent checks before reading a sensitive Notion page

User: "Read the 2027 comp band doc from Notion and summarise it."

Agent flow:
1. Agent receives the request and identifies the tool it needs: `notion.readPage`.
2. Before executing, agent calls:
   ```json
   {
     "name": "acp_check",
     "arguments": {
       "tool_name": "notion.readPage",
       "tool_input": "{\"page_id\":\"d1f2...comp-band-2027\"}",
       "agent_tier": "interactive"
     }
   }
   ```
3. ACP returns:
   ```json
   {"decision": "ask", "reason": "flagged: page_id matches 'comp-band' policy", "tool": "notion.readPage"}
   ```
4. Agent surfaces the ask to the user before proceeding.

### Example 2 — Background subagent attempts a write during a sensitive window

User: Long-running research subagent is on the last step of its plan.

Agent flow:
1. Subagent wants to call `slack.postMessage` to a public channel.
2. It calls `acp_check` with `agent_tier: "subagent"`.
3. ACP returns `{"decision": "deny", "reason": "rate-limited: subagent tier (11/10 per minute)", ...}`.
4. Subagent backs off, surfaces the decision to the orchestrator, and the user sees a clean audit log entry instead of a silent rate-limit failure.

### Example 3 — New user confirms their setup

User just signed into their ACP workspace via OAuth.

Agent flow:
1. They ask the agent "Is governance working?"
2. Agent calls `acp_status`.
3. ACP returns `"ACP: Connected. Mode: audit-only. Dashboard: https://cloud.agenticcontrolplane.com"`.
4. User clicks through to their dashboard and sees the call they just made in the audit log, tagged with their workspace and the calling client (Claude / ChatGPT / etc.).

---

## Security & privacy notes for reviewers

- Multi-tenant, per-user OAuth via Firebase Google sign-in. No shared service credentials after the OAuth flow completes.
- Each signed-in user gets their own `gsk_` API key minted at `/token` exchange. Keys are scoped to that user's workspace and stored in Firestore as SHA-256 hashes only.
- MCP client identity is bound to each key at registration (from DCR `client_name`), so audit logs correctly attribute calls to Claude / ChatGPT / Cursor / etc.
- No agent content is stored beyond a truncated 2000-char input preview (further redacted if the workspace has PII policies enabled).
- All requests over HTTPS. OAuth 2.1 + PKCE + DCR.

## Callback URIs allowlisted

- `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback`
- `https://chatgpt.com/*`, `https://chat.openai.com/*`
- `http://localhost:*` (Claude Desktop, MCP Inspector)

## Test account

Reviewers may sign in with any Google account — a workspace is auto-provisioned on first login at no cost. No MFA required on test accounts.
