// src/tools/tools.ts
// ACP Governance tools — exposed via MCP for Claude, ChatGPT, Lovable, etc.

const ACP_API = process.env.ACP_API_BASE || "https://api.agenticcontrolplane.com";

// For OAuth users (ChatGPT, Claude), their Auth0 JWT can't be used
// directly with the governance API. Use a service-level API key as fallback.
const ACP_SERVICE_KEY = process.env.ACP_SERVICE_KEY || "";

// ── Scope mapping (governance tools require no special scopes) ──────
export const TOOL_SCOPES: Record<string, string[]> = {
  acp_check: [],
  acp_status: [],
};

export const REQUIRED_SCOPES = Array.from(
  new Set(Object.values(TOOL_SCOPES).flat())
).sort();

// ── Tool descriptors for MCP tools/list ─────────────────────────────
export function mcpToolDescriptors() {
  return [
    {
      name: "acp_check",
      description:
        "Check whether a tool call is allowed by ACP governance policies. " +
        "Call this before executing any sensitive action. Returns allow/deny decision.",
      inputSchema: {
        type: "object" as const,
        properties: {
          tool_name: {
            type: "string",
            description: "Name of the tool being called (e.g., 'notion.readPage', 'jira.createIssue')",
          },
          tool_input: {
            type: "string",
            description: "JSON string of the tool input/arguments",
          },
          client_name: {
            type: "string",
            description: "Name of the calling client (e.g., 'Lovable', 'ChatGPT', 'Claude')",
          },
          agent_tier: {
            type: "string",
            description: "Agent autonomy tier: 'interactive' (human supervising), 'subagent', 'background' (autonomous), or 'api'. Defaults to 'interactive'.",
          },
        },
        required: ["tool_name", "tool_input"],
        additionalProperties: false,
      },
    },
    {
      name: "acp_status",
      description: "Check ACP governance status and connectivity for your workspace.",
      inputSchema: {
        type: "object" as const,
        properties: {},
        additionalProperties: false,
      },
    },
  ];
}

// ── Tool execution ──────────────────────────────────────────────────

export async function executeGovernanceTool(
  toolName: string,
  args: Record<string, unknown>,
  bearerToken: string
): Promise<{ ok: boolean; result: string }> {
  // Use gsk_ key directly if provided, otherwise fall back to service key
  const governToken = bearerToken.startsWith("gsk_") ? bearerToken : (ACP_SERVICE_KEY || bearerToken);
  if (toolName === "acp_check") {
    return acpCheck(args, governToken);
  }
  if (toolName === "acp_status") {
    return acpStatus(governToken);
  }
  return { ok: false, result: `Unknown tool: ${toolName}` };
}

async function acpCheck(
  args: Record<string, unknown>,
  bearerToken: string
): Promise<{ ok: boolean; result: string }> {
  const toolName = String(args.tool_name || "");
  const toolInput = String(args.tool_input || "{}");
  const clientName = String(args.client_name || "MCP Client");

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(`${ACP_API}/govern/tool-use`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${bearerToken}`,
        "Content-Type": "application/json",
        "X-GS-Client": `${clientName.toLowerCase().replace(/\s+/g, "-")}-mcp/0.1.0`,
      },
      body: JSON.stringify({
        tool_name: toolName,
        tool_input: toolInput,
        agent_tier: String(args.agent_tier || "interactive"),
        client: { name: clientName, version: "0.1.0" },
      }),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!res.ok) {
      return { ok: true, result: JSON.stringify({ decision: "allow", reason: "acp-http-error", tool: toolName }) };
    }

    const data = (await res.json()) as { decision: string; reason?: string };
    return {
      ok: true,
      result: JSON.stringify({ decision: data.decision, reason: data.reason || data.decision, tool: toolName }),
    };
  } catch {
    return { ok: true, result: JSON.stringify({ decision: "allow", reason: "acp-network-error", tool: toolName }) };
  } finally {
    clearTimeout(timeout);
  }
}

async function acpStatus(bearerToken: string): Promise<{ ok: boolean; result: string }> {
  try {
    const res = await fetch(`${ACP_API}/govern/health`);
    const data = (await res.json()) as { mode?: string };
    return {
      ok: true,
      result: `ACP: Connected. Mode: ${data.mode || "unknown"}. Dashboard: https://cloud.agenticcontrolplane.com`,
    };
  } catch {
    return { ok: false, result: "ACP: Cannot reach governance API" };
  }
}

// ── Tool result summarizer ──────────────────────────────────────────
export function summarizeToolResult(name: string, payload: any): string {
  if (name === "acp_check") {
    try {
      const d = typeof payload === "string" ? JSON.parse(payload) : payload;
      return `ACP governance: ${d.decision} (${d.reason}) for tool ${d.tool}`;
    } catch {
      return String(payload);
    }
  }
  if (name === "acp_status") {
    return String(payload);
  }
  return JSON.stringify(payload);
}
