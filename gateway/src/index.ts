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
 *   [IronClaw Shade Agent — Rust/Axum inside Azure ACI Confidential TEE]
 *
 * Transport: HTTP (not SSE).
 * Rationale: Cloudflare Workers cannot hold SSE connections without Durable
 * Objects. HTTP transport is fully supported by all major MCP clients and maps
 * cleanly to the Worker's request/response model.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Env, JsonRpcRequest, JsonRpcResponse, McpToolCallParams } from "./types.js";
import { TOOLS } from "./tools.js";
import {
  handleAgentHealth,
  handleVaultWrite,
  handleVaultRead,
  handleZdrCheck,
} from "./dispatcher.js";

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

const app = new Hono<{ Bindings: Env }>();

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
