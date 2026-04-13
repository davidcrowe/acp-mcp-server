// src/handlers/mcpHandler.ts
import type { Request, Response } from "express";

import {
  TOOL_SCOPES,
  summarizeToolResult,
  mcpToolDescriptors,
  executeGovernanceTool,
} from "../tools/tools.js";
import {
  verifyBearer,
  buildWwwAuthenticate,
  readAuth,
  verifyBearerAndScopes,
  logAuthShape,
} from "./authHelpers.js";
import { setCorsHeaders } from "./httpHelpers.js";

type JsonRpcReq = {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: any;
};

type JsonRpcRes =
  | { jsonrpc: "2.0"; id: string | number | null; result: any }
  | { jsonrpc: "2.0"; id: string | number | null; error: { code: number; message: string; data?: any } };

function jsonRpcResult(id: any, result: any): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function jsonRpcError(id: any, code: number, message: string, data?: any): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
}

export function looksLikeJsonRpc(body: any): boolean {
  try {
    const b = typeof body === "string" ? JSON.parse(body) : body;
    return b && b.jsonrpc === "2.0" && typeof b.method === "string";
  } catch {
    return false;
  }
}

function getBearerToken(req: Request): string {
  const auth = req.header("authorization") || "";
  if (!auth.startsWith("Bearer ")) return "";
  return auth.slice(7);
}

function detectClient(req: Request): string {
  const ua = req.header("user-agent") || "";
  if (ua.includes("Claude-User") || ua.includes("python-httpx")) return "Claude";
  if (ua.includes("aiohttp") || ua.includes("OpenAI")) return "ChatGPT";
  const token = getBearerToken(req);
  if (token.startsWith("gsk_")) return "Lovable";
  return "MCP Client";
}

const DEBUG = !!process.env.DEBUG;

export async function handleMcp(req: Request, res: Response) {
  setCorsHeaders(res, true);
  if (DEBUG) console.log("[mcp:req]", { path: (req as any).path ?? req.url, method: req.method });

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: { code: "METHOD_NOT_ALLOWED" } });
    return;
  }

  let rpc: JsonRpcReq;
  try {
    rpc = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    res.status(400).json(jsonRpcError(null, -32700, "Parse error"));
    return;
  }

  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    res.status(400).json(jsonRpcError(rpc?.id ?? null, -32600, "Invalid Request"));
    return;
  }

  // initialize — no auth required
  if (rpc.method === "initialize") {
    const result = {
      protocolVersion: "2024-11-05",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "acp-governance", version: "1.0.0" },
    };
    res.status(200).json(jsonRpcResult(rpc.id ?? null, result));
    return;
  }

  if (rpc.method === "notifications/initialized") {
    res.status(202).end();
    return;
  }

  // tools/list — return tools without auth (auth required on tools/call)
  if (rpc.method === "tools/list") {
    res.status(200).json(jsonRpcResult(rpc.id ?? null, { tools: mcpToolDescriptors() }));
    return;
  }

  // tools/call — requires valid JWT + scopes
  if (rpc.method === "tools/call") {
    const name = rpc.params?.name;
    const args = rpc.params?.arguments ?? {};

    logAuthShape("mcp.tools/call", req);

    if (typeof name !== "string" || !TOOL_SCOPES[name]) {
      res.status(404).json(jsonRpcError(rpc.id ?? null, -32601, `Unknown tool: ${name}`));
      return;
    }

    // Prompt OAuth if token is missing or not an accepted shape.
    // Accepted shapes: JWT (Firebase/Auth0) or opaque ACP `gsk_` API key.
    {
      const { hasAuth, token, tokenShape } = readAuth(req);
      const isAcpKey = token.startsWith("gsk_");
      if (!hasAuth || (tokenShape !== "jwt" && !isAcpKey)) {
        res.setHeader("WWW-Authenticate", buildWwwAuthenticate(req) + ', error="invalid_token"');
        res.status(401).json(jsonRpcError(rpc.id ?? null, -32001, "Unauthorized"));
        return;
      }
    }

    try {
      await verifyBearerAndScopes(req, name);
    } catch (e: any) {
      res.setHeader("WWW-Authenticate", e?.www || buildWwwAuthenticate(req));
      res
        .status(Number(e?.status) || 401)
        .json(jsonRpcError(rpc.id ?? null, -32001, e?.message || "Unauthorized"));
      return;
    }

    const accessToken = getBearerToken(req);
    const clientName = detectClient(req);

    // Override client_name with detected client if not provided
    if (!args.client_name) args.client_name = clientName;

    // Execute governance tool directly (no Proxyabl — tools call ACP API)
    try {
      const { ok, result } = await executeGovernanceTool(name, args, accessToken);

      const summaryText = summarizeToolResult(name, result);

      const baseResult: any = {
        isError: !ok,
        content: [{ type: "text" as const, text: summaryText || result }],
      };

      res.status(200).json(jsonRpcResult(rpc.id ?? null, baseResult));
    } catch (e: any) {
      res.status(200).json(jsonRpcResult(rpc.id ?? null, {
        isError: true,
        content: [{ type: "text" as const, text: `Tool ${name} failed: ${e?.message || e}` }],
      }));
    }
    return;
  }

  res.status(400).json(jsonRpcError(rpc.id ?? null, -32601, `Method not found: ${rpc.method}`));
}
