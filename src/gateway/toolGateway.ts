// src/gateway/toolGateway.ts
// ACP Governance MCP Server — main request handler
// Based on gatewaystack-chatgpt-starter patterns

import type { Request, Response } from "express";

import { createIdentifiablVerifier } from "@gatewaystack/identifiabl";
import crypto from "crypto";

import { looksLikeJsonRpc, handleMcp } from "../handlers/mcpHandler.js";
import { buildWwwAuthenticate, verifyFirebaseIdToken } from "../handlers/authHelpers.js";
import { wellKnownOauthProtectedResourcev2 } from "../handlers/wellKnown.js";
import {
  setCorsHeaders,
  fetchJsonWithRetry,
} from "../handlers/httpHelpers.js";
import {
  OAUTH_ISSUER,
  OAUTH_AUDIENCE,
  OAUTH_SCOPES,
  JWKS_URI_FALLBACK,
  OIDC_DISCOVERY,
} from "../handlers/oauthConfig.js";

const DEBUG = !!process.env.DEBUG;

export { OAUTH_ISSUER, OAUTH_AUDIENCE, OAUTH_SCOPES };

// ---- Identifiabl verifier (still used for Auth0 JWTs if any) ----
export const identifiablVerifier = createIdentifiablVerifier({
  issuer: OAUTH_ISSUER,
  audience: OAUTH_AUDIENCE || "",
  jwksUri: JWKS_URI_FALLBACK,
});

// ---- Firebase Auth config (set via env in deployment) ----
// Firebase web API keys are public by design, but we still load them from env
// so this source can live in a public repo without baked-in identifiers.
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || "";
const FIREBASE_AUTH_DOMAIN = process.env.FIREBASE_AUTH_DOMAIN || "";
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";

// Temporary auth code → Firebase ID token mapping (in-memory, expires in 5 min)
const authCodes = new Map<string, { idToken: string; expiresAt: number }>();
setInterval(() => {
  const now = Date.now();
  for (const [code, entry] of authCodes) {
    if (now > entry.expiresAt) authCodes.delete(code);
  }
}, 60_000);

// ---- Public base URL from request headers ----
function getPublicBaseUrl(req: Request): string {
  const rawProto = req.get("x-forwarded-proto") || (req as any).protocol || "https";
  const proto = rawProto.split(",")[0].trim();
  const host = req.get("x-forwarded-host") || req.get("host") || "localhost";
  return `${proto}://${host}`;
}

// ---- redirect_uri allowlist for /authorize ----
const ALLOWED_REDIRECT_ORIGINS = new Set<string>([
  "https://claude.ai",
  "https://claude.com",
  "https://chatgpt.com",
  "https://chat.openai.com",
  "https://lovable.dev",
]);

function isAllowedRedirect(uri: string): boolean {
  if (!uri) return false;
  try {
    const u = new URL(uri);
    if (
      u.protocol === "http:" &&
      (u.hostname === "localhost" || u.hostname === "127.0.0.1")
    ) {
      return true;
    }
    return u.protocol === "https:" && ALLOWED_REDIRECT_ORIGINS.has(u.origin);
  } catch {
    return false;
  }
}

// =============== Main handler ===============
export async function toolGatewayImpl(req: Request, res: Response) {
  const method = req.method.toUpperCase();
  const path = (req as any).path ?? req.url ?? "/";

  if (DEBUG) console.log("[gw]", method, path);

  // ---- CORS preflight ----
  if (method === "OPTIONS") {
    setCorsHeaders(res, false);
    res.status(204).end();
    return;
  }

  // ---- MCP (JSON-RPC over POST /mcp or POST /) ----
  if (method === "POST" && (path === "/mcp" || path === "/")) {
    if (looksLikeJsonRpc(req.body)) {
      return handleMcp(req, res);
    }
    // If it looks like JSON-RPC but on /, also handle it
    if (path === "/" && req.body?.jsonrpc) {
      return handleMcp(req, res);
    }
  }

  // ---- Protocol discovery (HEAD /) ----
  if (method === "HEAD" && (path === "/" || path === "/mcp")) {
    setCorsHeaders(res, false);
    res.setHeader("MCP-Protocol-Version", "2025-06-18");
    res.status(200).end();
    return;
  }

  // ---- Health / info ----
  if (method === "GET" && path === "/") {
    setCorsHeaders(res, true);
    const base = getPublicBaseUrl(req);
    res.status(200).json({
      ok: true,
      server: "acp-governance-mcp",
      version: "1.0.0",
      links: {
        mcp: `${base}/mcp`,
        health: `${base}/`,
        oauth_protected_resource: `${base}/.well-known/oauth-protected-resource`,
        oauth_authorization_server: `${base}/.well-known/oauth-authorization-server`,
      },
    });
    return;
  }

  if (method === "GET" && path === "/health") {
    setCorsHeaders(res, true);
    res.status(200).json({ ok: true, server: "acp-governance-mcp" });
    return;
  }

  // ---- OAuth discovery ----
  if (method === "GET" && path.startsWith("/.well-known/oauth-protected-resource")) {
    setCorsHeaders(res, true);
    return wellKnownOauthProtectedResourcev2(req, res);
  }

  // ---- DCR: return shared OAuth client ----
  if (method === "POST" && path === "/register") {
    setCorsHeaders(res, true);
    // Return the pre-existing Auth0 client for all MCP clients
    res.status(200).json({
      client_id: process.env.ACP_OAUTH_CLIENT_ID || "",
      client_secret: process.env.ACP_OAUTH_CLIENT_SECRET || "",
      token_endpoint_auth_method: "client_secret_post",
    });
    return;
  }

  if (method === "GET" && path === "/.well-known/oauth-authorization-server") {
    setCorsHeaders(res, true);
    const base = getPublicBaseUrl(req);
    res.status(200).json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
    });
    return;
  }

  // Proxy JWKS from Auth0 (Claude can't reach Auth0 directly due to Cloudflare)
  if (method === "GET" && path === "/.well-known/jwks.json") {
    setCorsHeaders(res, true);
    try {
      const doc = await fetchJsonWithRetry(`${OAUTH_ISSUER}/.well-known/jwks.json`);
      res.status(200).json(doc);
    } catch (e: any) {
      console.error("[wk:jwks] proxy failed:", e?.message);
      res.status(502).json({ error: "jwks_proxy_failed" });
    }
    return;
  }

  if (method === "GET" && path === "/.well-known/openid-configuration") {
    setCorsHeaders(res, true);
    const base = getPublicBaseUrl(req);
    // Serve rewritten OIDC config with all endpoints on our server
    res.status(200).json({
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      jwks_uri: `${base}/.well-known/jwks.json`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post"],
      scopes_supported: ["openid", "email", "profile"],
    });
    return;
  }

  // ---- OAuth: Firebase Auth login page ----
  if (method === "GET" && path === "/authorize") {
    const qs = new URL(req.url || "/", `https://${req.headers.host}`).searchParams;
    const redirectUri = qs.get("redirect_uri") || "";
    const state = qs.get("state") || "";
    const codeChallenge = qs.get("code_challenge") || "";

    if (!isAllowedRedirect(redirectUri)) {
      console.warn("[oauth:authorize] rejected redirect_uri", { redirectUri });
      res
        .status(400)
        .set("Content-Type", "text/html; charset=utf-8")
        .send(
          `<!doctype html><meta charset="utf-8"><title>Invalid request</title>` +
            `<body style="font-family:-apple-system,sans-serif;padding:40px;max-width:560px;margin:auto">` +
            `<h1 style="font-size:20px">Invalid redirect_uri</h1>` +
            `<p>This MCP server does not recognize the redirect_uri provided by your client. ` +
            `If you reached this page from a legitimate MCP client, please contact support so we can add it to the allowlist.</p>` +
            `</body>`
        );
      return;
    }

    // Pre-escape values for safe interpolation into the JS context below.
    // JSON.stringify quotes the string and escapes \" \\ etc., but does NOT
    // escape < > or U+2028/2029 — those would let an injected </script>
    // close the surrounding script element. Escape them explicitly.
    const jsString = (s: string): string =>
      JSON.stringify(String(s ?? ""))
        .replace(/</g, "\\u003c")
        .replace(/>/g, "\\u003e")
        .replace(/\u2028/g, "\\u2028")
        .replace(/\u2029/g, "\\u2029");
    const safeRedirect = jsString(redirectUri);
    const safeState = jsString(state);
    const safeChallenge = jsString(codeChallenge);

    // Serve a login page with Firebase Auth
    const html = `<!DOCTYPE html>
<html><head><title>ACP Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; background: #f8f8fc; }
  .card { background: #fff; border-radius: 16px; padding: 40px; max-width: 400px; width: 90%; box-shadow: 0 2px 12px rgba(0,0,0,0.08); text-align: center; }
  h1 { font-size: 22px; color: #1a1a2e; margin: 0 0 8px; }
  p { color: #6b7280; font-size: 14px; margin: 0 0 24px; }
  .btn { display: flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 12px; font-size: 15px; font-weight: 600; border: 2px solid #d0d0e8; border-radius: 10px; background: #fff; cursor: pointer; color: #1a1a2e; }
  .btn:hover { border-color: #5b5bd6; }
  .status { margin-top: 16px; font-size: 13px; color: #6b7280; }
</style>
</head><body>
<div class="card">
  <h1>Agentic Control Plane</h1>
  <p>Sign in to connect your ACP workspace</p>
  <button class="btn" id="googleBtn" onclick="signIn()">
    <svg width="18" height="18" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18A10.96 10.96 0 0 0 1 12c0 1.77.42 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
    Continue with Google
  </button>
  <div class="status" id="status"></div>
</div>
<script src="https://www.gstatic.com/firebasejs/11.0.0/firebase-app-compat.js"></script>
<script src="https://www.gstatic.com/firebasejs/11.0.0/firebase-auth-compat.js"></script>
<script>
  firebase.initializeApp({
    apiKey: "${FIREBASE_API_KEY}",
    authDomain: "${FIREBASE_AUTH_DOMAIN}",
    projectId: "${FIREBASE_PROJECT_ID}"
  });

  async function signIn() {
    document.getElementById("status").textContent = "Signing in...";
    try {
      const provider = new firebase.auth.GoogleAuthProvider();
      const result = await firebase.auth().signInWithPopup(provider);
      const idToken = await result.user.getIdToken();

      // Send ID token to our server to get an auth code
      const resp = await fetch("/auth/code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id_token: idToken,
          code_challenge: ${safeChallenge},
          state: ${safeState}
        })
      });
      const data = await resp.json();

      if (data.code) {
        // Redirect back to the MCP client with the auth code
        const url = new URL(${safeRedirect});
        url.searchParams.set("code", data.code);
        url.searchParams.set("state", ${safeState});
        window.location.href = url.toString();
      } else {
        document.getElementById("status").textContent = "Error: " + (data.error || "Unknown error");
      }
    } catch (e) {
      document.getElementById("status").textContent = "Error: " + e.message;
    }
  }
</script>
</body></html>`;

    res.status(200).set("Content-Type", "text/html").send(html);
    return;
  }

  // ---- OAuth: auth code generation (called from login page) ----
  if (method === "POST" && path === "/auth/code") {
    setCorsHeaders(res, true);
    const { id_token } = req.body || {};
    if (!id_token || typeof id_token !== "string") {
      res.status(400).json({ error: "missing id_token" });
      return;
    }

    // Verify the Firebase ID token signature before trusting it
    try {
      const verified = await verifyFirebaseIdToken(id_token);
      console.log("[oauth:code] Firebase ID token verified", { sub: verified.sub });
    } catch (verr: any) {
      console.warn("[oauth:code] Firebase verify failed", { message: verr?.message });
      res.status(401).json({ error: "invalid_id_token", error_description: verr?.message || "verify failed" });
      return;
    }

    // Generate a random auth code and store the mapping
    const code = crypto.randomBytes(32).toString("hex");
    authCodes.set(code, {
      idToken: id_token,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
    });

    console.log("[oauth:code] Auth code generated", { codeLen: code.length });
    res.status(200).json({ code });
    return;
  }

  // ---- OAuth: token exchange ----
  if (method === "POST" && (path === "/oauth/token" || path === "/token")) {
    setCorsHeaders(res, true);

    // Parse body (could be JSON or form-urlencoded)
    let grantType = "", code = "", clientId = "", clientSecret = "";
    if (typeof req.body === "object" && req.body !== null) {
      grantType = req.body.grant_type || "";
      code = req.body.code || "";
      clientId = req.body.client_id || "";
      clientSecret = req.body.client_secret || "";
    } else if (typeof req.body === "string") {
      const params = new URLSearchParams(req.body);
      grantType = params.get("grant_type") || "";
      code = params.get("code") || "";
      clientId = params.get("client_id") || "";
      clientSecret = params.get("client_secret") || "";
    }

    console.log("[oauth:token]", { grantType, hasCode: !!code, clientId: clientId.slice(0, 10) });

    if (grantType !== "authorization_code" || !code) {
      res.status(400).json({ error: "invalid_request", error_description: "Expected grant_type=authorization_code with code" });
      return;
    }

    const entry = authCodes.get(code);
    if (!entry || Date.now() > entry.expiresAt) {
      authCodes.delete(code);
      res.status(400).json({ error: "invalid_grant", error_description: "Code expired or invalid" });
      return;
    }

    // Single use — delete immediately
    authCodes.delete(code);

    // Return the Firebase ID token as the access token
    res.status(200).json({
      access_token: entry.idToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
    return;
  }

  // ---- Favicon ----
  if (method === "GET" && path.startsWith("/favicon")) {
    res.status(204).end();
    return;
  }

  // ---- Catch-all ----
  setCorsHeaders(res, true);
  res.status(405).json({ error: "Method not allowed", path, method });
}
