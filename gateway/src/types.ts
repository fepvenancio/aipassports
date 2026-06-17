/**
 * @file types.ts
 * @notice MCP protocol types (HTTP transport, 2024-11-05 spec subset).
 *
 * We implement only the tool-calling surface of MCP — `tools/list` and
 * `tools/call`. We deliberately do NOT implement SSE transport because:
 *   1. Cloudflare Workers cannot hold persistent connections without Durable Objects.
 *   2. HTTP transport is fully supported by Cursor, VS Code, and Claude Desktop.
 *   3. Stateless HTTP maps cleanly to the Worker's request/response model.
 */

// ─── JSON-RPC 2.0 Base ────────────────────────────────────────────────────────

export interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id: string | number;
  readonly method: string;
  readonly params?: unknown;
}

export interface JsonRpcSuccess<T = unknown> {
  readonly jsonrpc: "2.0";
  readonly id: string | number;
  readonly result: T;
}

export interface JsonRpcError {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly error: {
    readonly code: number;
    readonly message: string;
    readonly data?: unknown;
  };
}

export type JsonRpcResponse<T = unknown> = JsonRpcSuccess<T> | JsonRpcError;

// ─── MCP Tool Types ───────────────────────────────────────────────────────────

export interface McpToolInputSchema {
  readonly type: "object";
  readonly properties: Record<string, McpSchemaProperty>;
  readonly required: readonly string[];
}

export interface McpSchemaProperty {
  readonly type: string;
  readonly description: string;
  readonly default?: unknown;
  readonly enum?: readonly unknown[];
}

export interface McpTool {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: McpToolInputSchema;
}

export interface McpToolsListResult {
  readonly tools: readonly McpTool[];
}

// Extended McpToolCallParams with all tool types including team tools
export type McpToolCallParams =
  | {
      readonly name: "agent_health";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "vault_write";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "vault_read";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "zdr_check";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "team_vault_write";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "team_vault_read";
      readonly arguments: Record<string, unknown>;
    }
  | {
      readonly name: "team_manage";
      readonly arguments: Record<string, unknown>;
    };

export interface McpTextContent {
  readonly type: "text";
  readonly text: string;
}

export interface McpToolCallResult {
  readonly content: readonly McpTextContent[];
  readonly isError?: boolean;
}

// ─── Team Types ───────────────────────────────────────────────────────────────

/** Team metadata stored on-chain */
export interface TeamMetadata {
  readonly teamId: string;
  readonly name: string;
  readonly createdAt: number;
  readonly createdBy: string;
}

/** Permission level for team members */
export type Permission = "read" | "write" | "admin";

/** Team member record with permissions and metadata */
export interface TeamMember {
  readonly accountId: string;
  readonly permission: Permission;
  readonly joinedAt: number;
  readonly addedBy: string;
}

// ─── Worker Env ───────────────────────────────────────────────────────────────

export interface Env {
  /** Bearer token for the IronClaw Shade Agent. Injected as a Worker secret. */
  readonly IRONCLAW_AGENT_API_KEY: string;
  /** Base URL of the Shade Agent (e.g. https://api.aipassports.xyz or http://localhost:8080). */
  readonly IRONCLAW_AGENT_BASE_URL: string;
  /** Cloudflare KV for storing temporary challenges/nonces */
  readonly CHALLENGES_KV: KVNamespace;
  /** Cloudflare KV for storing active user sessions */
  readonly SESSIONS_KV: KVNamespace;
  /** Optional gateway function call key public key for delegation checks */
  readonly GATEWAY_FUNCKEY_PUBKEY?: string;
  /** Optional NEAR RPC URL override */
  readonly NEAR_RPC_URL?: string;
  /** Optional Cloudflare KV for storing team memberships */
  readonly TEAMS_KV?: KVNamespace;
  /** NEAR contract ID for Aegis smart contract */
  readonly AEGIS_CONTRACT_ID?: string;
  /** Cloudflare D1 Database for mapping multi-tenant users to endpoints */
  readonly DB: D1Database;
}
