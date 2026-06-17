/**
 * @file dispatcher.ts
 * @notice Pure, stateless dispatcher that routes `tools/call` MCP requests
 *         to the IronClaw Shade Agent HTTP endpoints.
 *
 * Design decisions:
 *   - Every function is pure: takes (env, args) → returns McpToolCallResult.
 *   - No global state, no module-level caches — safe for Cloudflare Workers.
 *   - All Shade Agent calls use a shared `callShadeAgent` helper that:
 *       1. Injects the Bearer token from the Worker secret.
 *       2. Propagates HTTP errors as structured MCP error content.
 *       3. Never leaks the API key in error messages.
 */

import type { Env, McpToolCallResult } from "./types.js";

/* //////////////////////////////////////////////////////////////
                         SHADE AGENT CLIENT
//////////////////////////////////////////////////////////////*/

export interface ShadeAgentCallOptions {
  readonly env: Env;
  readonly path: string;
  readonly body?: unknown;
  /** If true, sends GET with no body. Default: false (POST). */
  readonly method?: "GET" | "POST";
}

/**
 * @notice Forwards a request to the IronClaw Shade Agent.
 * @dev Injects `Authorization: Bearer <IRONCLAW_AGENT_API_KEY>` on every call.
 *      Returns the parsed JSON response body or throws a structured error string.
 *      Exported so team_handlers.ts can share this implementation (AUDIT-I3).
 */
export async function callShadeAgent({ env, path, body, method = "POST" }: ShadeAgentCallOptions): Promise<unknown> {
  const url = `${env.IRONCLAW_AGENT_BASE_URL}${path}`;

  const init: RequestInit = {
    method,
    headers: {
      "Authorization": `Bearer ${env.IRONCLAW_AGENT_API_KEY}`,
      "Content-Type": "application/json",
    },
    ...(method === "POST" && body !== undefined
      ? { body: JSON.stringify(body) }
      : {}),
  };

  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (networkError) {
    // Network-level failure — agent unreachable.
    throw `Network error reaching Shade Agent at ${env.IRONCLAW_AGENT_BASE_URL}: ${String(networkError)}`;
  }

  const json = await response.json().catch(() => ({ success: false, message: "Non-JSON response from Shade Agent" }));

  if (!response.ok) {
    const errorBody = json as { errorCode?: string; message?: string };
    throw `Shade Agent returned ${response.status}: [${errorBody.errorCode ?? "UNKNOWN"}] ${errorBody.message ?? "No message"}`;
  }

  return json;
}

/* //////////////////////////////////////////////////////////////
                         TOOL HANDLERS
//////////////////////////////////////////////////////////////*/

/**
 * @notice Pre-flight health check. No auth required — the /health endpoint
 *         is intentionally unauthenticated on the Shade Agent.
 */
export async function handleAgentHealth(env: Env): Promise<McpToolCallResult> {
  try {
    // Health endpoint is unauthenticated — use a plain fetch, not callShadeAgent.
    const response = await fetch(`${env.IRONCLAW_AGENT_BASE_URL}/health`);
    const json = await response.json() as { success?: boolean; status?: string };

    if (response.ok && json.success === true) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ healthy: true, status: json.status ?? "healthy", agentUrl: env.IRONCLAW_AGENT_BASE_URL }),
        }],
      };
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({ healthy: false, statusCode: response.status, agentUrl: env.IRONCLAW_AGENT_BASE_URL }),
      }],
      isError: true,
    };
  } catch (e) {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ healthy: false, error: `Cannot reach agent at ${env.IRONCLAW_AGENT_BASE_URL}: ${String(e)}` }),
      }],
      isError: true,
    };
  }
}

/**
 * @notice Encrypt and persist plaintext to Walrus under a NEAR identity.
 */
export async function handleVaultWrite(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { nearAccountId, entryType, identifier, plaintext, epochs } = args;

  if (typeof nearAccountId !== "string" || typeof plaintext !== "string") {
    return errorResult("INVALID_ARGS", "nearAccountId and plaintext must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/vault/write",
      body: {
        nearAccountId,
        entryType: typeof entryType === "string" ? entryType : "wiki",
        identifier: typeof identifier === "string" ? identifier : "home",
        plaintext,
        epochs: typeof epochs === "number" ? epochs : 26,
      },
    }) as { blobId: string; contentSha256: string };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          blobId: result.blobId,
          contentSha256: result.contentSha256,
          note: "Save blobId and contentSha256 together — both are required to read back this vault entry.",
        }),
      }],
    };
  } catch (e) {
    return errorResult("VAULT_WRITE_FAILED", String(e));
  }
}

/**
 * @notice Download and decrypt a vault entry from Walrus.
 */
export async function handleVaultRead(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { nearAccountId, entryType, identifier, blobId, expectedSha256 } = args;

  if (
    typeof nearAccountId !== "string" ||
    typeof blobId !== "string" ||
    typeof expectedSha256 !== "string"
  ) {
    return errorResult("INVALID_ARGS", "nearAccountId, blobId, and expectedSha256 must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/vault/read",
      body: {
        nearAccountId,
        entryType: typeof entryType === "string" ? entryType : "wiki",
        identifier: typeof identifier === "string" ? identifier : "home",
        blobId,
        expectedSha256,
      },
    }) as { plaintext: string };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({ success: true, plaintext: result.plaintext }),
      }],
    };
  } catch (e) {
    return errorResult("VAULT_READ_FAILED", String(e));
  }
}

/**
 * @notice Execute an AI skill through the ZDR egress firewall.
 */
export async function handleZdrCheck(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { nearAccountId, skillName, prompt, model, destination } = args;

  if (
    typeof nearAccountId !== "string" ||
    typeof skillName !== "string" ||
    typeof prompt !== "string" ||
    typeof destination !== "string"
  ) {
    return errorResult("INVALID_ARGS", "nearAccountId, skillName, prompt, and destination must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/skills/execute",
      body: {
        nearAccountId,
        skillName,
        prompt,
        model: typeof model === "string" ? model : "gpt-4o",
        destination,
      },
    });

    return {
      content: [{ type: "text", text: JSON.stringify(result) }],
    };
  } catch (e) {
    // Surface firewall blocks clearly so the caller understands the rejection reason.
    const msg = String(e);
    const isFirewallBlock =
      msg.includes("FIREWALL_ERROR_DESTINATION_BLOCKED") ||
      msg.includes("FIREWALL_ERROR_SENSITIVE_CONTENT");

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: false,
          firewallBlock: isFirewallBlock,
          error: msg,
        }),
      }],
      isError: true,
    };
  }
}



/* //////////////////////////////////////////////////////////////
                         HELPERS
//////////////////////////////////////////////////////////////*/

function errorResult(code: string, detail: string): McpToolCallResult {
  return {
    content: [{
      type: "text",
      text: JSON.stringify({ success: false, errorCode: code, detail }),
    }],
    isError: true,
  };
}
