// src/server/expressServer.ts
import express from "express";
import rateLimit from "express-rate-limit";
import { toolGatewayImpl } from "../gateway/toolGateway.js";

const PORT = parseInt(process.env.PORT || "3000", 10);

const app = express();

// Body parsing
app.use(express.json({ limit: "2mb" }));
app.use(
  express.text({
    type: (req) => {
      const ct = req.headers["content-type"] || "";
      return !ct.includes("application/json");
    },
    limit: "2mb",
  })
);

// Rate limiting: 100 req/min per IP (global)
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 100,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

// Stricter rate limit on the OAuth/auth surface
const authLimiter = rateLimit({
  windowMs: 60_000,
  max: 30, // generous: legitimate clients do 1-2 exchanges per connection
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
app.use(
  ["/authorize", "/auth/code", "/token", "/oauth/token", "/register"],
  authLimiter
);

// Favicon
app.get("/favicon.*", (_, res) => res.status(204).end());

// Everything → tool gateway
app.all("*", (req, res) => toolGatewayImpl(req, res));

app.listen(PORT, () => {
  console.log(`ACP Governance MCP Server listening on http://0.0.0.0:${PORT}`);
  console.log(`MCP endpoint: POST /mcp`);
  console.log(`OAuth discovery: GET /.well-known/oauth-protected-resource`);
});
