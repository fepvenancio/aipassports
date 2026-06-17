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
    // Get nearAccountId from context variables
    const nearAccountId = c.get("nearAccountId");
    if (!nearAccountId) {
      return false;
    }

    // Call NEAR contract method is_team_member
    const nearRpcUrl = c.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";
    
    try {
      const rpcRes = await fetch(nearRpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "team-membership-check",
          method: "query",
          params: {
            request_type: "call_function",
            finality: "final",
            account_id: c.env.AEGIS_CONTRACT_ID || "aegis.testnet",
            method_name: "is_team_member",
            args_base64: btoa(JSON.stringify({
              team_id: teamId,
              account_id: nearAccountId
            }))
          },
        }),
      });
      
      if (!rpcRes.ok) {
        return false;
      }
      
      const json = await rpcRes.json<{ result: boolean }>();
      return !!json.result; // Returns true if member exists
    } catch (error) {
      console.error("Team membership verification failed:", error);
      return false;
    }
  }

  /**
   * @notice Gets the permission level of the authenticated user in the specified team.
   * @param c Context with nearAccountId set in variables
   * @param teamId The team ID to check permission for
   * @returns Promise<Permission | null> Permission if member, null otherwise
   */
  async function get_team_permission(c: Context, teamId: string): Promise<Permission | null> {
    // Get nearAccountId from context variables
    const nearAccountId = c.get("nearAccountId");
    if (!nearAccountId) {
      return null;
    }

    // Call NEAR contract method get_team_member
    const nearRpcUrl = c.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";
    
    try {
      const rpcRes = await fetch(nearRpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "team-permission-check",
          method: "query",
          params: {
            request_type: "call_function",
            finality: "final",
            account_id: c.env.AEGIS_CONTRACT_ID || "aegis.testnet",
            method_name: "get_team_member",
            args_base64: btoa(JSON.stringify({
              team_id: teamId,
              account_id: nearAccountId
            }))
          },
        }),
      });
      
      if (!rpcRes.ok) {
        return null;
      }
      
      const json = await rpcRes.json<{ result: { permission: Permission } | null }>();
      const member = json.result;
      return member?.permission || null;
    } catch (error) {
      console.error("Team permission check failed:", error);
      return null;
    }
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
        case "vault_write":
          toolResult = await handleVaultWrite(routedEnv, toolArgs);
          break;
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

  // 3. Verify team membership via NEAR contract
  const nearRpcUrl = c.env.NEAR_RPC_URL || "https://rpc.testnet.near.org";

  try {
    const rpcRes = await fetch(nearRpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "team-auth",
        method: "query",
        params: {
          request_type: "call_function",
          finality: "final",
          account_id: c.env.AEGIS_CONTRACT_ID || "aegis.testnet",
          method_name: "is_team_member",
          args_base64: btoa(JSON.stringify({
            team_id: teamId,
            account_id: nearAccountId
          }))
        },
      }),
    });

    if (!rpcRes.ok) {
      return c.json({ error: "NEAR_RPC_ERROR" }, 500);
    }

    const json = await rpcRes.json() as { result?: boolean };
    if (!json.result) {
      return c.json({ error: "TEAM_MEMBER_REQUIRED" }, 403);
    }
  } catch (rpcErr) {
    return c.json({ error: "NEAR_RPC_UNREACHABLE", detail: String(rpcErr) }, 500);
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
    const teeEndpoint = body.teeEndpoint || `https://${accountId}.aegis-tee.near.ai`;

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
