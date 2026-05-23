/**
 * @file index.ts
 * @notice Aegis MCP Bridge — Stateless Cloudflare Worker.
 *
 * Implements the MCP HTTP transport (JSON-RPC 2.0 over HTTP POST).
 * All requests arrive at a single endpoint: POST /mcp
 *
 * Supported methods:
 *   - initialize          : Returns server capabilities (no-op, stateless).
 *   - tools/list          : Returns the Aegis tool manifest.
 *   - tools/call          : Dispatches to the IronClaw Shade Agent.
 *
 * Architecture:
 *   Cursor / Claude Desktop / VS Code
 *       │  POST /mcp (JSON-RPC 2.0)
 *       ▼
 *   [This Worker — stateless, no persistent connection]
 *       │  POST /vault/read | /vault/write | /skills/execute
 *       │  Authorization: Bearer <IRONCLAW_AGENT_API_KEY>
 *       ▼
 *   [IronClaw Shade Agent — Rust/Axum inside NEAR TEE Network (Intel TDX / AMD SEV-SNP)]
 *
 * Transport: HTTP (not SSE).
 * Rationale: Cloudflare Workers cannot hold SSE connections without Durable
 * Objects. HTTP transport is fully supported by all major MCP clients and maps
 * cleanly to the Worker's request/response model.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { verify } from "@noble/ed25519";
import type { Env, JsonRpcRequest, JsonRpcResponse, McpToolCallParams } from "./types.js";
import { TOOLS } from "./tools.js";
import {
  handleAgentHealth,
  handleVaultWrite,
  handleVaultRead,
  handleZdrCheck,
} from "./dispatcher.js";

/* //////////////////////////////////////////////////////////////
                    CRYPTO & ENCODING HELPERS
//////////////////////////////////////////////////////////////*/

const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Decode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);
  const bytes = [0];
  for (let i = 0; i < str.length; i++) {
    const c = str.charAt(i);
    let value = B58_ALPHABET.indexOf(c);
    if (value < 0) throw new Error("Invalid base58 character");
    for (let j = 0; j < bytes.length; j++) {
      const b = bytes[j];
      if (b === undefined) continue;
      value += b * 58;
      bytes[j] = value & 0xff;
      value >>= 8;
    }
    while (value > 0) {
      bytes.push(value & 0xff);
      value >>= 8;
    }
  }
  // count leading '1's
  let zeroCount = 0;
  while (zeroCount < str.length && str.charAt(zeroCount) === "1") {
    zeroCount++;
  }
  const result = new Uint8Array(zeroCount + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[bytes.length - 1 - i];
    result[zeroCount + i] = b !== undefined ? b : 0;
  }
  return result;
}

function arrayBufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (byte !== undefined) {
      binary += String.fromCharCode(byte);
    }
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToUint8Array(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function decodePublicKey(pubKeyStr: string): Uint8Array {
  const clean = pubKeyStr.replace("ed25519:", "");
  
  // Try base58 first
  try {
    const b58 = base58Decode(clean);
    if (b58.length === 32) {
      return b58;
    }
  } catch (e) {
    // Ignore and try base64
  }

  // Try base64
  try {
    const b64 = base64UrlToUint8Array(clean);
    if (b64.length === 32) {
      return b64;
    }
  } catch (e) {
    // Ignore
  }

  throw new Error("Could not decode Ed25519 public key (invalid base58 or base64 length/format)");
}

/* //////////////////////////////////////////////////////////////
                        JSON-RPC HELPERS
//////////////////////////////////////////////////////////////*/

const JSONRPC = "2.0" as const;

function success<T>(id: string | number, result: T): JsonRpcResponse<T> {
  return { jsonrpc: JSONRPC, id, result };
}

function rpcError(
  id: string | number | null,
  code: number,
  message: string,
): JsonRpcResponse {
  return { jsonrpc: JSONRPC, id, error: { code, message } };
}

// Standard JSON-RPC error codes
const RPC_METHOD_NOT_FOUND = -32601;
const RPC_INVALID_PARAMS = -32602;
const RPC_INTERNAL_ERROR = -32603;

/* //////////////////////////////////////////////////////////////
                       HONO APPLICATION
//////////////////////////////////////////////////////////////*/

const app = new Hono<{ Bindings: Env; Variables: { nearAccountId?: string } }>();

// CORS — allows any MCP client to reach the bridge.
// Tighten this to specific origins for enterprise deployments.
app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["POST", "GET", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  }),
);

/* //////////////////////////////////////////////////////////////
                      MCP ENDPOINT: POST /mcp
//////////////////////////////////////////////////////////////*/

app.post("/mcp", async (c) => {
  let req: JsonRpcRequest;

  try {
    req = await c.req.json<JsonRpcRequest>();
  } catch {
    return c.json(rpcError(null, -32700, "Parse error: invalid JSON"), 400);
  }

  const { id, method, params } = req;

  // ─── initialize ───────────────────────────────────────────────────────────
  // MCP clients send this on first connection. We return minimal capabilities
  // and do not store any session state — pure stateless response.
  if (method === "initialize") {
    return c.json(
      success(id, {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "aegis-mcp-bridge", version: "0.1.0" },
        capabilities: { tools: {} },
      }),
    );
  }

  // Session enforcement for protected methods: tools/list and tools/call
  if (method === "tools/list" || method === "tools/call") {
    const authHeader = c.req.header("Authorization");
    const xSessionId = c.req.header("x-session-id");
    let sessionId = "";
    if (authHeader && authHeader.startsWith("Bearer ")) {
      sessionId = authHeader.substring(7);
    } else if (xSessionId) {
      sessionId = xSessionId;
    }

    if (!sessionId) {
      return c.json(rpcError(id, -32001, "SESSION_MISSING"), 401);
    }

    const sessionStr = await c.env.SESSIONS_KV.get(`session:${sessionId}`);
    if (!sessionStr) {
      return c.json(rpcError(id, -32002, "SESSION_EXPIRED"), 401);
    }

    const session = JSON.parse(sessionStr) as { nearAccountId: string; expiresAt: number };
    if (Date.now() > session.expiresAt) {
      await c.env.SESSIONS_KV.delete(`session:${sessionId}`);
      return c.json(rpcError(id, -32002, "SESSION_EXPIRED"), 401);
    }

    c.set("nearAccountId", session.nearAccountId);
  }

  // ─── tools/list ───────────────────────────────────────────────────────────
  if (method === "tools/list") {
    return c.json(success(id, { tools: TOOLS }));
  }

  // ─── tools/call ───────────────────────────────────────────────────────────
  if (method === "tools/call") {
    const toolParams = params as McpToolCallParams | undefined;

    if (!toolParams?.name || typeof toolParams.name !== "string") {
      return c.json(rpcError(id, RPC_INVALID_PARAMS, "tools/call requires params.name"), 400);
    }

    const toolArgs = toolParams.arguments ?? {};
    const env = c.env;

    // Validate env — refuse to forward calls if secrets are missing.
    if (!env.IRONCLAW_AGENT_API_KEY) {
      return c.json(
        rpcError(id, RPC_INTERNAL_ERROR, "IRONCLAW_AGENT_API_KEY is not configured in this Worker. " +
          "Set it via: wrangler secret put IRONCLAW_AGENT_API_KEY"),
        500,
      );
    }
    if (!env.IRONCLAW_AGENT_BASE_URL) {
      return c.json(
        rpcError(id, RPC_INTERNAL_ERROR, "IRONCLAW_AGENT_BASE_URL is not configured."),
        500,
      );
    }

    // Boundary check: Enforce cross-user tenant isolation!
    const authenticatedAccountId = c.get("nearAccountId");
    if (!authenticatedAccountId) {
      return c.json(rpcError(id, -32001, "SESSION_MISSING"), 401);
    }

    if (toolArgs.nearAccountId && toolArgs.nearAccountId !== authenticatedAccountId) {
      return c.json(
        rpcError(
          id,
          RPC_INVALID_PARAMS,
          `Unauthorized: nearAccountId in arguments (${toolArgs.nearAccountId}) does not match authenticated session account (${authenticatedAccountId})`
        ),
        403
      );
    }

    try {
      let toolResult;

      switch (toolParams.name) {
        case "agent_health":
          toolResult = await handleAgentHealth(env);
          break;
        case "vault_write":
          toolResult = await handleVaultWrite(env, toolArgs);
          break;
        case "vault_read":
          toolResult = await handleVaultRead(env, toolArgs);
          break;
        case "zdr_check":
          toolResult = await handleZdrCheck(env, toolArgs);
          break;
        default:
          return c.json(
            rpcError(id, RPC_METHOD_NOT_FOUND, `Unknown tool: ${toolParams.name}`),
            404,
          );
      }

      return c.json(success(id, toolResult));
    } catch (e) {
      return c.json(
        rpcError(id, RPC_INTERNAL_ERROR, `Internal bridge error: ${String(e)}`),
        500,
      );
    }
  }

  // ─── Unknown method ───────────────────────────────────────────────────────
  return c.json(rpcError(id, RPC_METHOD_NOT_FOUND, `Method not found: ${method}`), 404);
});

/* //////////////////////////////////////////////////////////////
                    AUTHENTICATION ENDPOINTS
//////////////////////////////////////////////////////////////*/

app.post("/auth/challenge", async (c) => {
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = arrayBufferToBase64Url(nonceBytes.buffer);

  // Store in CHALLENGES_KV (key: challenge:${nonce}, TTL: 60s)
  await c.env.CHALLENGES_KV.put(`challenge:${nonce}`, "unused", { expirationTtl: 60 });

  return c.json({ nonce });
});

app.post("/auth/unlock", async (c) => {
  let body: {
    nearAccountId?: string;
    publicKey?: string;
    signature?: string;
    challenge?: string;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "INVALID_JSON" }, 400);
  }

  const { nearAccountId, publicKey, signature, challenge } = body;

  if (!nearAccountId || !publicKey || !signature || !challenge) {
    return c.json({ error: "MISSING_PARAMS" }, 400);
  }

  // 1. Unconditionally delete challenge from KV
  const challengeKey = `challenge:${challenge}`;
  const challengeExists = await c.env.CHALLENGES_KV.get(challengeKey);
  if (!challengeExists) {
    return c.json({ error: "CHALLENGE_NOT_FOUND" }, 401);
  }
  await c.env.CHALLENGES_KV.delete(challengeKey);

  // 2. Fetch active keys from NEAR RPC
  const nearRpcUrl = c.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";
  
  let keysResponse: any;
  try {
    const rpcRes = await fetch(nearRpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "aegis-auth",
        method: "query",
        params: {
          request_type: "view_access_keys",
          finality: "final",
          account_id: nearAccountId,
        },
      }),
    });
    
    if (!rpcRes.ok) {
      return c.json({ error: "NEAR_RPC_ERROR" }, 500);
    }
    
    keysResponse = await rpcRes.json();
  } catch (rpcErr) {
    return c.json({ error: "NEAR_RPC_UNREACHABLE", detail: String(rpcErr) }, 500);
  }

  if (keysResponse.error) {
    return c.json({ error: "NEAR_ACCOUNT_NOT_FOUND" }, 401);
  }

  const keys = keysResponse.result?.keys || [];
  
  // 3. Verify public key exists on-chain
  const keyExists = keys.some((k: any) => k.public_key === publicKey);
  if (!keyExists) {
    return c.json({ error: "PUBLIC_KEY_NOT_REGISTERED" }, 401);
  }

  // 4. Verify Ed25519 signature
  try {
    const nonceBytes = base64UrlToUint8Array(challenge);
    const sigBytes = base64UrlToUint8Array(signature);
    const pubKeyBytes = decodePublicKey(publicKey);
    
    const isValid = await verify(sigBytes, nonceBytes, pubKeyBytes);
    
    if (!isValid) {
      return c.json({ error: "INVALID_SIGNATURE" }, 401);
    }
  } catch (err) {
    return c.json({ error: "INVALID_SIGNATURE", detail: String(err) }, 401);
  }

  // 5. Check gateway function call key delegation
  let delegationRequired = false;
  if (c.env.GATEWAY_FUNCKEY_PUBKEY) {
    const gatewayKeyExists = keys.some((k: any) => k.public_key === c.env.GATEWAY_FUNCKEY_PUBKEY);
    delegationRequired = !gatewayKeyExists;
  }

  // 6. Generate session
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 3600 * 1000; // 1 hour TTL standard

  const sessionObj = {
    nearAccountId,
    createdAt: Date.now(),
    expiresAt,
  };

  await c.env.SESSIONS_KV.put(`session:${sessionId}`, JSON.stringify(sessionObj), {
    expirationTtl: 3600,
  });

  return c.json({
    sessionId,
    expiresAt,
    delegationRequired,
  });
});

app.post("/auth/logout", async (c) => {
  const authHeader = c.req.header("Authorization");
  const xSessionId = c.req.header("x-session-id");
  let sessionId = "";
  if (authHeader && authHeader.startsWith("Bearer ")) {
    sessionId = authHeader.substring(7);
  } else if (xSessionId) {
    sessionId = xSessionId;
  }

  if (sessionId) {
    await c.env.SESSIONS_KV.delete(`session:${sessionId}`);
  }

  return c.json({ ok: true });
});

/* //////////////////////////////////////////////////////////////
                   HEALTH & DISCOVERY ENDPOINTS
//////////////////////////////////////////////////////////////*/

/** Bridge-level health check — does not call the Shade Agent. */
app.get("/health", (c) =>
  c.json({ success: true, service: "aegis-mcp-bridge", version: "0.1.0" }),
);

/** MCP well-known discovery endpoint. */
app.get("/.well-known/mcp", (c) =>
  c.json({
    mcpEndpoint: "/mcp",
    transport: "http",
    protocolVersion: "2024-11-05",
    serverName: "aegis-mcp-bridge",
    tools: TOOLS.map((t) => t.name),
  }),
);

export default app;
