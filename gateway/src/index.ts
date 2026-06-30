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

import { Hono, type Context } from "hono";
import { cors } from "hono/cors";
import { verify } from "@noble/ed25519";
import type { Env, JsonRpcRequest, JsonRpcResponse, McpToolCallParams, Permission } from "./types.js";
import { TOOLS } from "./tools.js";
import {
  handleAgentHealth,
  handleVaultWrite,
  handleVaultRead,
  handleZdrCheck,
} from "./dispatcher.js";
import {
  handleTeamVaultWrite,
  handleTeamVaultRead,
  handleTeamManage,
} from "./team_handlers.js";

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

const app = new Hono<{ Bindings: Env; Variables: { nearAccountId?: string; teamId?: string; teamPermission?: Permission } }>();

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

  // ─── Team Verification Helpers ────────────────────────────────────────────

  /**
   * @notice Verifies if the authenticated user is a member of the specified team.
   * @param c Context with nearAccountId set in variables
   * @param teamId The team ID to check membership for
   * @returns Promise<boolean> True if user is a member, false otherwise
   */
  async function verify_team_membership(c: Context, teamId: string): Promise<boolean> {
    // Team membership now lives in D1 (NEAR contract retirement, Phase 2.5).
    const nearAccountId = c.get("nearAccountId");
    if (!nearAccountId || !c.env.DB) {
      return false;
    }
    return dbIsTeamMember(c.env.DB, teamId, nearAccountId);
  }

  /**
   * @notice Gets the permission level of the authenticated user in the specified team.
   * @param c Context with nearAccountId set in variables
   * @param teamId The team ID to check permission for
   * @returns Promise<Permission | null> Permission if member, null otherwise
   */
  async function get_team_permission(c: Context, teamId: string): Promise<Permission | null> {
    // Team permissions now live in D1 (NEAR contract retirement, Phase 2.5).
    const nearAccountId = c.get("nearAccountId");
    if (!nearAccountId || !c.env.DB) {
      return null;
    }
    return dbGetTeamPermission(c.env.DB, teamId, nearAccountId);
  }

  /**
   * @notice Verifies if the authenticated user has write permission in the specified team.
   * @param c Context with nearAccountId set in variables
   * @param teamId The team ID to check write permission for
   * @returns Promise<boolean> True if user has write or admin permission
   */
  async function verify_team_write_permission(c: Context, teamId: string): Promise<boolean> {
    const permission = await get_team_permission(c, teamId);
    return permission === "write" || permission === "admin";
  }

  /**
   * @notice Verifies if the authenticated user has admin permission in the specified team.
   * @param c Context with nearAccountId set in variables
   * @param teamId The team ID to check admin permission for
   * @returns Promise<boolean> True if user has admin permission
   */
  async function verify_team_admin_permission(c: Context, teamId: string): Promise<boolean> {
    const permission = await get_team_permission(c, teamId);
    return permission === "admin";
  }

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

    let authenticatedAccountId = "";

    // 1. Try SESSIONS_KV session lookup
    const sessionStr = await c.env.SESSIONS_KV.get(`session:${sessionId}`);
    if (sessionStr) {
      const session = JSON.parse(sessionStr) as { nearAccountId: string; expiresAt: number };
      if (Date.now() <= session.expiresAt) {
        authenticatedAccountId = session.nearAccountId;
      } else {
        await c.env.SESSIONS_KV.delete(`session:${sessionId}`);
      }
    }

    // 2. Try D1 API key database lookup if session is not active
    if (!authenticatedAccountId && c.env.DB) {
      try {
        const userRow = await c.env.DB.prepare(
          "SELECT near_account_id FROM users WHERE api_key = ?"
        ).bind(sessionId).first<{ near_account_id: string }>();
        if (userRow && userRow.near_account_id) {
          authenticatedAccountId = userRow.near_account_id;
        }
      } catch (dbErr) {
        console.warn("D1 database lookup for API key failed, falling back:", dbErr);
      }
    }

    if (!authenticatedAccountId) {
      return c.json(rpcError(id, -32002, "SESSION_EXPIRED"), 401);
    }

    c.set("nearAccountId", authenticatedAccountId);
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
    const toolName = toolParams.name;

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

    // Team context verification
    const teamId = typeof toolArgs.teamId === "string" ? toolArgs.teamId : undefined;
    if (teamId) {
      // Verify team membership
      const isMember = await verify_team_membership(c, teamId);
      if (!isMember) {
        return c.json(
          rpcError(
            id,
            -32003, // TEAM_MEMBER_REQUIRED
            `TEAM_MEMBER_REQUIRED: Account ${authenticatedAccountId} is not a member of team ${teamId}`
          ),
          403
        );
      }

      // Get and store team permission
      const permission = await get_team_permission(c, teamId);
      if (permission) {
        c.set("teamId", teamId);
        c.set("teamPermission", permission);
      }
    }

    try {
      let toolResult;

      // Dynamic multi-tenant routing based on authenticated account TEE endpoint
      let agentBaseUrl = env.IRONCLAW_AGENT_BASE_URL;
      if (env.DB) {
        try {
          const userRow = await env.DB.prepare(
            "SELECT tee_endpoint FROM users WHERE near_account_id = ?"
          ).bind(authenticatedAccountId).first<{ tee_endpoint: string }>();
          if (userRow && userRow.tee_endpoint) {
            agentBaseUrl = userRow.tee_endpoint;
          }
        } catch (dbErr) {
          // Fallback to default configured agent base URL if D1 query fails or DB is not bound (e.g. testing)
        }
      }

      const routedEnv = {
        ...env,
        IRONCLAW_AGENT_BASE_URL: agentBaseUrl,
      };

      switch (toolParams.name) {
        case "agent_health":
          toolResult = await handleAgentHealth(routedEnv);
          break;
        case "vault_write": {
          // SAAS: Check storage quota before allowing the write
          if (env.DB) {
            try {
              const quotaRow = await env.DB.prepare(
                "SELECT storage_used_bytes, storage_limit_bytes FROM users WHERE near_account_id = ?"
              ).bind(authenticatedAccountId).first<{ storage_used_bytes: number; storage_limit_bytes: number }>();
              if (quotaRow && quotaRow.storage_used_bytes >= quotaRow.storage_limit_bytes) {
                return c.json(
                  rpcError(id, -32006, `QUOTA_EXCEEDED: Storage limit reached (${quotaRow.storage_used_bytes}/${quotaRow.storage_limit_bytes} bytes). Upgrade your plan to continue writing.`),
                  403
                );
              }
            } catch { /* proceed if DB check fails — fail-open for availability */ }
          }
          toolResult = await handleVaultWrite(routedEnv, toolArgs);
          // SAAS: Increment storage usage after successful write
          if (env.DB && toolResult && !toolResult.isError) {
            try {
              const resultText = toolResult.content?.[0]?.text;
              if (resultText) {
                const parsed = JSON.parse(resultText) as { blobSizeBytes?: number };
                if (typeof parsed.blobSizeBytes === "number" && parsed.blobSizeBytes > 0) {
                  await env.DB.prepare(
                    "UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE near_account_id = ?"
                  ).bind(parsed.blobSizeBytes, authenticatedAccountId).run();
                }
              }
            } catch { /* metering is best-effort — don't break the write */ }
          }
          break;
        }
        case "vault_read":
          toolResult = await handleVaultRead(routedEnv, toolArgs);
          break;
        case "zdr_check":
          toolResult = await handleZdrCheck(routedEnv, toolArgs);
          break;
        case "team_vault_write":
          // Verify write permission for team vault operations
          if (typeof toolArgs.teamId === "string" && !await verify_team_write_permission(c, toolArgs.teamId)) {
            return c.json(
              rpcError(id, -32004, "TEAM_PERMISSION_DENIED: Write permission required"),
              403
            );
          }
          toolResult = await handleTeamVaultWrite(routedEnv, toolArgs);
          // SAAS: Increment storage usage for team writes (billed to requesting user)
          if (env.DB && toolResult && !toolResult.isError) {
            try {
              const resultText = toolResult.content?.[0]?.text;
              if (resultText) {
                const parsed = JSON.parse(resultText) as { blobSizeBytes?: number };
                if (typeof parsed.blobSizeBytes === "number" && parsed.blobSizeBytes > 0) {
                  await env.DB.prepare(
                    "UPDATE users SET storage_used_bytes = storage_used_bytes + ? WHERE near_account_id = ?"
                  ).bind(parsed.blobSizeBytes, authenticatedAccountId).run();
                }
              }
            } catch { /* metering is best-effort */ }
          }
          break;
        case "team_vault_read":
          // Verify membership for team vault read operations
          if (typeof toolArgs.teamId === "string" && !await verify_team_membership(c, toolArgs.teamId)) {
            return c.json(
              rpcError(id, -32003, "TEAM_MEMBER_REQUIRED: Membership required"),
              403
            );
          }
          toolResult = await handleTeamVaultRead(routedEnv, toolArgs);
          break;
        case "team_manage":
          // Verify admin permission for team management
          if (typeof toolArgs.teamId === "string" && !await verify_team_admin_permission(c, toolArgs.teamId)) {
            return c.json(
              rpcError(id, -32005, "TEAM_PERMISSION_DENIED: Admin permission required"),
              403
            );
          }
          toolResult = await handleTeamManage(routedEnv, toolArgs);
          break;
        default:
          return c.json(
            rpcError(id, RPC_METHOD_NOT_FOUND, `Unknown tool: ${toolName}`),
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
                   TEAM AUTHENTICATION ENDPOINTS
//////////////////////////////////////////////////////////////*/

app.post("/auth/team/challenge", async (c) => {
  let body: { teamId?: string };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "INVALID_JSON" }, 400);
  }

  const { teamId } = body;

  if (!teamId) {
    return c.json({ error: "MISSING_TEAM_ID" }, 400);
  }

  // Generate nonce and store in CHALLENGES_KV
  const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
  const nonce = arrayBufferToBase64Url(nonceBytes.buffer);

  // Store with team-specific key format
  await c.env.CHALLENGES_KV.put(`team_challenge:${teamId}:${nonce}`, "unused", { expirationTtl: 60 });

  return c.json({ nonce, teamId });
});

app.post("/auth/team/unlock", async (c) => {
  let body: {
    teamId?: string;
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

  const { teamId, nearAccountId, publicKey, signature, challenge } = body;

  if (!teamId || !nearAccountId || !publicKey || !signature || !challenge) {
    return c.json({ error: "MISSING_PARAMS" }, 400);
  }

  // 1. Verify challenge exists in KV
  const challengeKey = `team_challenge:${teamId}:${challenge}`;
  const challengeExists = await c.env.CHALLENGES_KV.get(challengeKey);
  if (!challengeExists) {
    return c.json({ error: "CHALLENGE_NOT_FOUND" }, 401);
  }
  await c.env.CHALLENGES_KV.delete(challengeKey);

  // 2. Verify Ed25519 signature
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

  // 3. Verify team membership via D1 (NEAR contract retired — Phase 2.5).
  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }
  if (!(await dbIsTeamMember(c.env.DB, teamId, nearAccountId))) {
    return c.json({ error: "TEAM_MEMBER_REQUIRED" }, 403);
  }

  // 4. Generate team session
  const sessionId = crypto.randomUUID();
  const expiresAt = Date.now() + 3600 * 1000; // 1 hour TTL

  const sessionObj = {
    teamId,
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
    teamId,
  });
});

app.post("/auth/team/logout", async (c) => {
  let body: { teamId?: string };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "INVALID_JSON" }, 400);
  }

  const { teamId } = body;
  const authHeader = c.req.header("Authorization");
  const xSessionId = c.req.header("x-session-id");
  let sessionId = "";

  if (authHeader && authHeader.startsWith("Bearer ")) {
    sessionId = authHeader.substring(7);
  } else if (xSessionId) {
    sessionId = xSessionId;
  }

  if (!teamId || !sessionId) {
    return c.json({ error: "MISSING_TEAM_ID_OR_SESSION" }, 400);
  }

  // Delete session from KV
  await c.env.SESSIONS_KV.delete(`session:${sessionId}`);

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

/* //////////////////////////////////////////////////////////////
                   MANAGED SAAS CONTROL PLANE ROUTER
//////////////////////////////////////////////////////////////*/

async function getAuthenticatedUser(c: Context<any>): Promise<string | null> {
  const authHeader = c.req.header("Authorization");
  const xSessionId = c.req.header("x-session-id");
  let sessionId = "";
  if (authHeader && authHeader.startsWith("Bearer ")) {
    sessionId = authHeader.substring(7);
  } else if (xSessionId) {
    sessionId = xSessionId;
  }

  if (!sessionId) return null;

  const sessionStr = await c.env.SESSIONS_KV.get(`session:${sessionId}`);
  if (sessionStr) {
    const session = JSON.parse(sessionStr) as { nearAccountId: string; expiresAt: number };
    if (Date.now() <= session.expiresAt) {
      return session.nearAccountId;
    }
  }

  if (c.env.DB) {
    try {
      const userRow = (await c.env.DB.prepare(
        "SELECT near_account_id FROM users WHERE api_key = ?"
      ).bind(sessionId).first()) as { near_account_id: string } | null;
      if (userRow) {
        return userRow.near_account_id;
      }
    } catch (dbErr) {
      // Ignore
    }
  }

  return null;
}

// ─── Team data-plane helpers (D1) ──────────────────────────────────────────────
// Backing store for team membership/permissions after the NEAR contract retirement
// (Phase 2.5). Shared by the /mcp authorization closures and the /api/team routes.
// Permission values are lowercase ("read" | "write" | "admin"), matching `Permission`.

async function dbIsTeamMember(db: D1Database, teamId: string, accountId: string): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS ok FROM team_members WHERE team_id = ? AND account_id = ?")
    .bind(teamId, accountId)
    .first();
  return !!row;
}

async function dbGetTeamPermission(db: D1Database, teamId: string, accountId: string): Promise<Permission | null> {
  const row = await db
    .prepare("SELECT permission FROM team_members WHERE team_id = ? AND account_id = ?")
    .bind(teamId, accountId)
    .first<{ permission: Permission }>();
  return row?.permission ?? null;
}

// ─── Team management (D1-backed; replaces the NEAR contract — Phase 2.5) ────────

app.post("/api/team/create", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as { teamId?: string; name?: string };
  const teamId = typeof body.teamId === "string" ? body.teamId.trim() : "";
  const name = typeof body.name === "string" ? body.name.trim() : "";
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(teamId)) {
    return c.json({ error: "INVALID_TEAM_ID", detail: "teamId must be 1-64 chars of [a-zA-Z0-9_-]" }, 400);
  }
  if (!name || name.length > 128) {
    return c.json({ error: "INVALID_NAME", detail: "name must be 1-128 chars" }, 400);
  }

  try {
    const existing = await c.env.DB.prepare("SELECT 1 AS ok FROM teams WHERE team_id = ?").bind(teamId).first();
    if (existing) return c.json({ error: "TEAM_EXISTS" }, 409);

    const now = Date.now();
    // Create the team and add the creator as the first admin member, atomically.
    await c.env.DB.batch([
      c.env.DB.prepare("INSERT INTO teams (team_id, name, creator_account_id, created_at) VALUES (?, ?, ?, ?)")
        .bind(teamId, name, accountId, now),
      c.env.DB.prepare("INSERT INTO team_members (team_id, account_id, permission, added_by, joined_at) VALUES (?, ?, 'admin', ?, ?)")
        .bind(teamId, accountId, accountId, now),
    ]);
    return c.json({ success: true, teamId });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.post("/api/team/add_member", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as { teamId?: string; memberAccountId?: string; permission?: string };
  const teamId = typeof body.teamId === "string" ? body.teamId : "";
  const memberAccountId = typeof body.memberAccountId === "string" ? body.memberAccountId.trim() : "";
  const permission = body.permission;
  if (!teamId || !memberAccountId) return c.json({ error: "INVALID_ARGS" }, 400);
  if (permission !== "read" && permission !== "write" && permission !== "admin") {
    return c.json({ error: "INVALID_PERMISSION", detail: "permission must be read|write|admin" }, 400);
  }
  // Only a team admin may add members.
  if ((await dbGetTeamPermission(c.env.DB, teamId, accountId)) !== "admin") {
    return c.json({ error: "FORBIDDEN", detail: "admin permission required" }, 403);
  }

  try {
    await c.env.DB.prepare(
      "INSERT INTO team_members (team_id, account_id, permission, added_by, joined_at) VALUES (?, ?, ?, ?, ?) " +
      "ON CONFLICT(team_id, account_id) DO UPDATE SET permission = excluded.permission"
    ).bind(teamId, memberAccountId, permission, accountId, Date.now()).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.post("/api/team/update_permission", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as { teamId?: string; memberAccountId?: string; permission?: string };
  const teamId = typeof body.teamId === "string" ? body.teamId : "";
  const memberAccountId = typeof body.memberAccountId === "string" ? body.memberAccountId.trim() : "";
  const permission = body.permission;
  if (!teamId || !memberAccountId) return c.json({ error: "INVALID_ARGS" }, 400);
  if (permission !== "read" && permission !== "write" && permission !== "admin") {
    return c.json({ error: "INVALID_PERMISSION", detail: "permission must be read|write|admin" }, 400);
  }
  if ((await dbGetTeamPermission(c.env.DB, teamId, accountId)) !== "admin") {
    return c.json({ error: "FORBIDDEN", detail: "admin permission required" }, 403);
  }
  // Member must already exist to update.
  if ((await dbGetTeamPermission(c.env.DB, teamId, memberAccountId)) === null) {
    return c.json({ error: "MEMBER_NOT_FOUND" }, 404);
  }

  try {
    await c.env.DB.prepare("UPDATE team_members SET permission = ? WHERE team_id = ? AND account_id = ?")
      .bind(permission, teamId, memberAccountId).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.post("/api/team/remove_member", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as { teamId?: string; memberAccountId?: string };
  const teamId = typeof body.teamId === "string" ? body.teamId : "";
  const memberAccountId = typeof body.memberAccountId === "string" ? body.memberAccountId.trim() : "";
  if (!teamId || !memberAccountId) return c.json({ error: "INVALID_ARGS" }, 400);
  if ((await dbGetTeamPermission(c.env.DB, teamId, accountId)) !== "admin") {
    return c.json({ error: "FORBIDDEN", detail: "admin permission required" }, 403);
  }

  try {
    // Don't orphan the team: refuse to remove the only remaining admin.
    if ((await dbGetTeamPermission(c.env.DB, teamId, memberAccountId)) === "admin") {
      const admins = await c.env.DB.prepare(
        "SELECT COUNT(*) AS n FROM team_members WHERE team_id = ? AND permission = 'admin'"
      ).bind(teamId).first<{ n: number }>();
      if ((admins?.n ?? 0) <= 1) {
        return c.json({ error: "LAST_ADMIN", detail: "cannot remove the only admin" }, 409);
      }
    }
    await c.env.DB.prepare("DELETE FROM team_members WHERE team_id = ? AND account_id = ?")
      .bind(teamId, memberAccountId).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.get("/api/team/members", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const teamId = c.req.query("teamId") || "";
  if (!teamId) return c.json({ error: "INVALID_ARGS", detail: "teamId required" }, 400);
  // Only members may view the roster.
  if (!(await dbIsTeamMember(c.env.DB, teamId, accountId))) {
    return c.json({ error: "FORBIDDEN", detail: "membership required" }, 403);
  }

  try {
    const rows = await c.env.DB.prepare(
      "SELECT account_id, permission, joined_at FROM team_members WHERE team_id = ? ORDER BY joined_at ASC"
    ).bind(teamId).all<{ account_id: string; permission: string; joined_at: number }>();
    const members = (rows.results ?? []).map((r) => ({
      accountId: r.account_id,
      permission: r.permission,
      joinedAt: r.joined_at,
    }));
    return c.json({ members });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

// ─── Pointer index (D1-backed; replaces the NEAR contract — Phase 2.5) ──────────
// Per-user wiki/skill pointers: which encrypted blob belongs to which
// {account, entryType, identifier}. Owner is always the authenticated session user.

function isEntryType(t: unknown): t is "wiki" | "skill" {
  return t === "wiki" || t === "skill";
}

app.post("/api/pointers/set", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as {
    entryType?: string; identifier?: string; blobId?: string; contentSha256?: string;
  };
  const { entryType, identifier, blobId, contentSha256 } = body;
  if (!isEntryType(entryType)) return c.json({ error: "INVALID_ENTRY_TYPE" }, 400);
  if (typeof identifier !== "string" || !identifier || identifier.length > 128) {
    return c.json({ error: "INVALID_IDENTIFIER" }, 400);
  }
  if (typeof blobId !== "string" || typeof contentSha256 !== "string") {
    return c.json({ error: "INVALID_ARGS" }, 400);
  }

  try {
    await c.env.DB.prepare(
      "INSERT INTO pointers (owner_type, owner_id, entry_type, identifier, blob_id, content_sha256, updated_at) " +
      "VALUES ('user', ?, ?, ?, ?, ?, ?) " +
      "ON CONFLICT(owner_type, owner_id, entry_type, identifier) DO UPDATE SET " +
      "blob_id = excluded.blob_id, content_sha256 = excluded.content_sha256, updated_at = excluded.updated_at"
    ).bind(accountId, entryType, identifier, blobId, contentSha256, Date.now()).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.post("/api/pointers/remove", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const body = (await c.req.json().catch(() => ({}))) as { entryType?: string; identifier?: string };
  if (!isEntryType(body.entryType)) return c.json({ error: "INVALID_ENTRY_TYPE" }, 400);
  if (typeof body.identifier !== "string" || !body.identifier) {
    return c.json({ error: "INVALID_IDENTIFIER" }, 400);
  }
  try {
    await c.env.DB.prepare(
      "DELETE FROM pointers WHERE owner_type = 'user' AND owner_id = ? AND entry_type = ? AND identifier = ?"
    ).bind(accountId, body.entryType, body.identifier).run();
    return c.json({ success: true });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.get("/api/pointers/list", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const entryType = c.req.query("entryType");
  if (!isEntryType(entryType)) return c.json({ error: "INVALID_ENTRY_TYPE" }, 400);
  try {
    const rows = await c.env.DB.prepare(
      "SELECT identifier FROM pointers WHERE owner_type = 'user' AND owner_id = ? AND entry_type = ? ORDER BY identifier ASC"
    ).bind(accountId, entryType).all<{ identifier: string }>();
    return c.json({ identifiers: (rows.results ?? []).map((r) => r.identifier) });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.get("/api/pointers/get", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) return c.json({ error: "UNAUTHORIZED" }, 401);
  if (!c.env.DB) return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);

  const entryType = c.req.query("entryType");
  const identifier = c.req.query("identifier") || "";
  if (!isEntryType(entryType)) return c.json({ error: "INVALID_ENTRY_TYPE" }, 400);
  if (!identifier) return c.json({ error: "INVALID_IDENTIFIER" }, 400);
  try {
    const row = await c.env.DB.prepare(
      "SELECT blob_id, content_sha256, updated_at FROM pointers WHERE owner_type = 'user' AND owner_id = ? AND entry_type = ? AND identifier = ?"
    ).bind(accountId, entryType, identifier).first<{ blob_id: string; content_sha256: string; updated_at: number }>();
    if (!row) return c.json({ pointer: null });
    return c.json({
      pointer: { blob_id: row.blob_id, content_sha256: row.content_sha256, updated_at_ms: row.updated_at },
    });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.get("/api/user", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) {
    return c.json({ error: "UNAUTHORIZED" }, 401);
  }

  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }

  try {
    const user = await c.env.DB.prepare(
      "SELECT near_account_id, api_key, tee_endpoint, subscription_status, storage_used_bytes, storage_limit_bytes FROM users WHERE near_account_id = ?"
    ).bind(accountId).first<{
      near_account_id: string;
      api_key: string;
      tee_endpoint: string;
      subscription_status: string;
      storage_used_bytes: number;
      storage_limit_bytes: number;
    }>();

    if (!user) {
      return c.json({ error: "USER_NOT_REGISTERED" }, 404);
    }

    return c.json({
      success: true,
      nearAccountId: user.near_account_id,
      apiKey: user.api_key,
      teeEndpoint: user.tee_endpoint,
      subscriptionStatus: user.subscription_status,
      storageUsedBytes: user.storage_used_bytes || 0,
      storageLimitBytes: user.storage_limit_bytes || 10485760,
    });
  } catch (err) {
    return c.json({ error: "DB_ERROR", detail: String(err) }, 500);
  }
});

app.post("/api/register", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) {
    return c.json({ error: "UNAUTHORIZED" }, 401);
  }

  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }

  let body: { teeEndpoint?: string } = {};
  try {
    body = await c.req.json().catch(() => ({}));
  } catch {
    // Ignore
  }

  try {
    const existingUser = await c.env.DB.prepare(
      "SELECT near_account_id, api_key, tee_endpoint, subscription_status, storage_used_bytes, storage_limit_bytes FROM users WHERE near_account_id = ?"
    ).bind(accountId).first<{
      near_account_id: string;
      api_key: string;
      tee_endpoint: string;
      subscription_status: string;
      storage_used_bytes: number;
      storage_limit_bytes: number;
    }>();

    if (existingUser) {
      return c.json({
        success: true,
        nearAccountId: existingUser.near_account_id,
        apiKey: existingUser.api_key,
        teeEndpoint: existingUser.tee_endpoint,
        subscriptionStatus: existingUser.subscription_status,
        storageUsedBytes: existingUser.storage_used_bytes || 0,
        storageLimitBytes: existingUser.storage_limit_bytes || 10485760,
      });
    }

    const apiKey = "ak_aegis_" + arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(24)).buffer);
    // SAAS: Default to the shared TEE pool (IRONCLAW_AGENT_BASE_URL) instead of
    // a per-user subdomain that doesn't exist. Enterprise users can override later.
    const teeEndpoint = body.teeEndpoint || c.env.IRONCLAW_AGENT_BASE_URL || "https://api.aipassports.xyz";

    await c.env.DB.prepare(
      "INSERT INTO users (near_account_id, api_key, tee_endpoint, subscription_status, storage_used_bytes, storage_limit_bytes, created_at) VALUES (?, ?, ?, 'free', 0, 10485760, ?)"
    ).bind(accountId, apiKey, teeEndpoint, Date.now()).run();

    return c.json({
      success: true,
      nearAccountId: accountId,
      apiKey,
      teeEndpoint,
      subscriptionStatus: "free",
      storageUsedBytes: 0,
      storageLimitBytes: 10485760,
    });
  } catch (err) {
    return c.json({ error: "REGISTRATION_FAILED", detail: String(err) }, 500);
  }
});

app.post("/api/keys/generate", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) {
    return c.json({ error: "UNAUTHORIZED" }, 401);
  }

  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }

  try {
    const apiKey = "ak_aegis_" + arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(24)).buffer);
    await c.env.DB.prepare(
      "UPDATE users SET api_key = ? WHERE near_account_id = ?"
    ).bind(apiKey, accountId).run();

    return c.json({
      success: true,
      apiKey,
    });
  } catch (err) {
    return c.json({ error: "KEY_GENERATION_FAILED", detail: String(err) }, 500);
  }
});

app.post("/api/billing/subscribe", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) {
    return c.json({ error: "UNAUTHORIZED" }, 401);
  }

  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }

  let body: { tier?: "free" | "developer" | "team" };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "INVALID_JSON" }, 400);
  }

  const { tier } = body;
  if (!tier || !["free", "developer", "team"].includes(tier)) {
    return c.json({ error: "INVALID_TIER" }, 400);
  }

  let limit = 10485760; // 10MB Free
  if (tier === "developer") {
    limit = 524288000; // 500MB
  } else if (tier === "team") {
    limit = 2147483648; // 2GB
  }

  try {
    await c.env.DB.prepare(
      "UPDATE users SET subscription_status = ?, storage_limit_bytes = ? WHERE near_account_id = ?"
    ).bind(tier, limit, accountId).run();

    return c.json({
      success: true,
      subscriptionStatus: tier,
      storageLimitBytes: limit,
    });
  } catch (err) {
    return c.json({ error: "SUBSCRIPTION_UPDATE_FAILED", detail: String(err) }, 500);
  }
});

app.get("/api/logs", async (c) => {
  const accountId = await getAuthenticatedUser(c);
  if (!accountId) {
    return c.json({ error: "UNAUTHORIZED" }, 401);
  }

  if (!c.env.DB) {
    return c.json({ error: "DATABASE_NOT_CONFIGURED" }, 500);
  }

  try {
    const { results } = await c.env.DB.prepare(
      "SELECT timestamp, skill_name, destination, rule_triggered, marker_detected FROM firewall_audit_logs WHERE near_account_id = ? ORDER BY timestamp DESC LIMIT 50"
    ).bind(accountId).all();

    return c.json({
      success: true,
      logs: results,
    });
  } catch (err) {
    return c.json({ error: "LOGS_QUERY_FAILED", detail: String(err) }, 500);
  }
});

export default app;
