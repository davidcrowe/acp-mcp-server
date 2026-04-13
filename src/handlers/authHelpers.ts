// src/handlers/authHelpers.ts
import type { Request } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { updateGatewayContext } from "@gatewaystack/request-context";
import { REQUIRED_SCOPES, TOOL_SCOPES } from "../tools/tools.js";
import { identifiablVerifier } from "../gateway/toolGateway.js";
import { OAUTH_SCOPES, OAUTH_AUDIENCE } from "./oauthConfig.js";

const DEBUG = !!process.env.DEBUG;

// ----------------- Firebase ID token verifier -----------------
const FIREBASE_PROJECT_ID =
  process.env.FIREBASE_PROJECT_ID || "gatewaystack-connect";

const firebaseJwks = createRemoteJWKSet(
  new URL(
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/securetoken@system.gserviceaccount.com"
  )
);

export async function verifyFirebaseIdToken(token: string) {
  const { payload } = await jwtVerify(token, firebaseJwks, {
    issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
    audience: FIREBASE_PROJECT_ID,
    algorithms: ["RS256"],
  });
  return payload;
}

// ----------------- Small helpers -----------------
export function readAuth(req: Request) {
  const auth = req.header("authorization") || "";
  const hasAuth = auth.startsWith("Bearer ");
  const token = hasAuth ? auth.slice(7) : "";
  const tokenShape = token.includes(".") ? "jwt" : (token ? "opaque" : "none");
  return { hasAuth, token, tokenShape, len: token.length };
}

export function logAuthShape(prefix: string, req: Request) {
  if (!DEBUG) return;
  const { hasAuth, tokenShape, len } = readAuth(req);
  console.log(
    `[auth:${prefix}] hasAuth=%s tokenShape=%s len=%d path=%s method=%s`,
    hasAuth,
    tokenShape,
    len,
    (req as any).path ?? req.url,
    req.method
  );
}

export function logTokenScopes(prefix: string, payload: any) {
  if (!DEBUG) return;
  const scopeStr = typeof payload.scope === "string" ? payload.scope : "";
  const permissions = Array.isArray((payload as any).permissions)
    ? (payload as any).permissions
    : [];
  const scopes = Array.from(
    new Set([
      ...scopeStr.split(" ").filter(Boolean),
      ...permissions,
    ])
  );

  console.log(`[auth:${prefix}]`, { scopeStr, permissions, scopes });
}

export function b64urlDecodeToJson(s: string) {
  try {
    s += "=".repeat((4 - (s.length % 4)) % 4);
    const buf = Buffer.from(
      s.replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    );
    return JSON.parse(buf.toString("utf8"));
  } catch {
    return undefined;
  }
}

export function requireScopes(have: string[], need: string[]) {
  const ok = need.every((s) => have.includes(s));
  if (!ok) {
    console.warn("[auth:insufficient_scope]", { have, need });
    const err: any = new Error("insufficient_scope");
    err.status = 403;
    err.code = "INSUFFICIENT_SCOPE";
    throw err;
  }
}

export async function subjectToUid(sub: string, _email?: string): Promise<string> {
  return `auth0:${sub}`;
}

// ----------------- WWW-Authenticate builder -----------------
export function buildWwwAuthenticate(req: Request): string {
  const xfProto = req.get("x-forwarded-proto") || (req as any).protocol || "https";
  const xfHost = req.get("x-forwarded-host") || req.get("host");
  const base = `${xfProto}://${xfHost}`;

  const metaUrl = `${base}/.well-known/oauth-protected-resource`;

  const scopeParam = (
    REQUIRED_SCOPES.length
      ? REQUIRED_SCOPES
      : OAUTH_SCOPES.split(" ").filter(Boolean)
  ).join(" ");

  const resourceParam = OAUTH_AUDIENCE ? `, resource="${OAUTH_AUDIENCE}"` : "";

  return `Bearer resource_metadata="${metaUrl}", scope="${scopeParam}"${resourceParam}`;
}

// ----------------- Core verify helpers -----------------
export async function verifyBearer(req: Request) {
  logAuthShape("verifyBearer", req);

  const auth = req.header("authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    const err: any = new Error("NO_AUTH");
    err.status = 401;
    err.www = buildWwwAuthenticate(req) + ', error="invalid_token"';
    throw err;
  }

  const accessToken = auth.slice(7);

  // ACP `gsk_` API keys are the primary token type after the OAuth /token
  // exchange is rewired to call /plugin/mcp-provision. Accept them directly:
  // the ACP governance API routes per tenant from the key prefix, so this
  // server doesn't need to do any identity work beyond confirming the shape.
  if (accessToken.startsWith("gsk_")) {
    const parts = accessToken.split("_");
    const slug = parts[1] || "unknown";
    const identity = {
      sub: `acp:${slug}`,
      issuer: "acp",
      source: "acp-key" as const,
    };
    updateGatewayContext({ identity: { ...identity, raw: { sub: identity.sub } } });
    if (DEBUG) console.log("[auth:acp-key] accepted", { slug });
    return { sub: identity.sub, scope: "", permissions: [] } as any;
  }

  const segments = accessToken.split(".");
  const header = segments[0] ? b64urlDecodeToJson(segments[0]) : undefined;
  if (DEBUG) console.log(
    "[auth:token] segments=%d header.alg=%s header.typ=%s",
    segments.length,
    header?.alg,
    header?.typ
  );

  if (segments.length !== 3) {
    const e: any = new Error(
      segments.length === 5
        ? "ACCESS_TOKEN_IS_ENCRYPTED_JWE"
        : "ACCESS_TOKEN_NOT_JWS"
    );
    e.status = 401;
    e.www = buildWwwAuthenticate(req) + ', error="invalid_token"';
    throw e;
  }

  // Try identifiabl (Auth0 JWT) first
  const result = await identifiablVerifier(accessToken);

  let identity: any;
  let payload: any;

  if (!result.ok) {
    // Fallback: verify Firebase ID tokens via Google's JWKS
    const claims = b64urlDecodeToJson(segments[1]);
    const iss = claims?.iss || "";
    if (iss.startsWith("https://securetoken.google.com/")) {
      try {
        const verified = await verifyFirebaseIdToken(accessToken);
        if (DEBUG) console.log("[auth:firebase-token] verified", { sub: verified.sub, iss: verified.iss });
        identity = {
          sub: String(verified.sub || ""),
          issuer: String(verified.iss || ""),
          source: "firebase",
          email: typeof (verified as any).email === "string" ? (verified as any).email : undefined,
        };
        payload = verified;
      } catch (verr: any) {
        console.error("[auth:firebase-verify-failed]", { message: verr?.message });
        const e: any = new Error("FIREBASE_VERIFY_FAILED");
        e.status = 401;
        e.www = buildWwwAuthenticate(req) + ', error="invalid_token"';
        throw e;
      }
    } else {
      console.error("[auth:identifiabl:error]", {
        error: (result as any).error,
        detail: (result as any).detail,
      });
      const e: any = new Error("JWT_VERIFY_FAILED");
      e.status = 401;
      e.www = buildWwwAuthenticate(req) + ', error="invalid_token"';
      throw e;
    }
  } else {
    identity = result.identity;
    payload = result.payload;
  }

  if (DEBUG) console.log("[auth:postVerify]", {
    sub: identity.sub,
    issuer: identity.issuer,
    tenantId: identity.tenantId,
    roles: identity.roles,
    scopes: identity.scopes,
    plan: identity.plan,
    source: identity.source,
  });

  updateGatewayContext({
    identity: {
      ...identity,
      raw: identity.raw ?? payload,
    },
  });

  logTokenScopes("postVerify", payload as any);

  return payload;
}

export async function verifyBearerAndScopes(req: Request, toolName: string) {
  const payload = await verifyBearer(req);

  const sub = String(payload.sub || "");
  if (!sub) {
    const err: any = new Error("TOKEN_NO_SUB");
    err.status = 401;
    err.www = buildWwwAuthenticate(req) + ', error="invalid_token"';
    throw err;
  }

  const email =
    typeof (payload as any).email === "string"
      ? ((payload as any).email as string)
      : undefined;

  const scopeStr =
    typeof (payload as any).scope === "string"
      ? ((payload as any).scope as string)
      : "";
  const permissions = Array.isArray((payload as any).permissions)
    ? ((payload as any).permissions as string[])
    : [];

  const scopes = Array.from(
    new Set([
      ...scopeStr.split(" ").filter(Boolean),
      ...permissions,
    ])
  );

  const need = TOOL_SCOPES[toolName] || [];
  if (need.length) requireScopes(scopes, need);

  const uid = await subjectToUid(sub, email);
  return { uid, scopes, payload };
}
