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
import { mintCapabilityToken } from "./capability.js";

/* //////////////////////////////////////////////////////////////
                         SHADE AGENT CLIENT
//////////////////////////////////////////////////////////////*/

export interface ShadeAgentCallOptions {
  readonly env: Env;
  readonly path: string;
  readonly body?: unknown;
  /** If true, sends GET with no body. Default: false (POST). */
  readonly method?: "GET" | "POST";
  /**
   * Authenticated NEAR account this request acts as. When set (and a gateway
   * signing key is configured), a short-lived Ed25519 capability token binding
   * this subject is attached as `X-Aegis-Capability`, so the agent can verify the
   * account cryptographically instead of trusting the body's `nearAccountId`.
   * The caller MUST have already validated `subject` against the session identity.
   */
  readonly subject?: string;
}

/**
 * @notice Forwards a request to the IronClaw Shade Agent.
 * @dev Injects `Authorization: Bearer <IRONCLAW_AGENT_API_KEY>` on every call.
 *      Returns the parsed JSON response body or throws a structured error string.
 *      Exported so team_handlers.ts can share this implementation (AUDIT-I3).
 */
export async function callShadeAgent({ env, path, body, method = "POST", subject }: ShadeAgentCallOptions): Promise<unknown> {
  const url = `${env.IRONCLAW_AGENT_BASE_URL}${path}`;

  const headers: Record<string, string> = {
    "Authorization": `Bearer ${env.IRONCLAW_AGENT_API_KEY}`,
    "Content-Type": "application/json",
  };

  // Capability binding: attach a gateway-signed token asserting the authenticated
  // subject. No-op (empty token) when no signing key is configured (legacy mode).
  if (subject) {
    const capabilityToken = await mintCapabilityToken(env, subject);
    if (capabilityToken) headers["X-Aegis-Capability"] = capabilityToken;
  }

  const init: RequestInit = {
    method,
    headers,
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
      let attestation: any = { status: "UNKNOWN", error: "Not checked" };
      try {
        const attestResponse = await fetch(`${env.IRONCLAW_AGENT_BASE_URL}/attest`);
        const attestJson = await attestResponse.json() as any;
        attestation = {
          success: attestJson.success || false,
          status: attestJson.attestation_status || "UNKNOWN",
          platform: attestJson.tee_platform || "Unknown",
          message: attestJson.message || "",
          quote: attestJson.tdx_quote || null,
          errorCode: attestJson.error_code || null,
          statusCode: attestResponse.status
        };
      } catch (attestError) {
        attestation = {
          success: false,
          status: "UNREACHABLE",
          error: String(attestError)
        };
      }

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            healthy: true,
            status: json.status ?? "healthy",
            agentUrl: env.IRONCLAW_AGENT_BASE_URL,
            attestation
          }),
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
      subject: nearAccountId,
      body: {
        nearAccountId,
        entryType: typeof entryType === "string" ? entryType : "wiki",
        identifier: typeof identifier === "string" ? identifier : "home",
        plaintext,
        epochs: typeof epochs === "number" ? epochs : 26,
      },
    }) as { blobId: string; contentSha256: string; blobSizeBytes?: number };

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          blobId: result.blobId,
          contentSha256: result.contentSha256,
          blobSizeBytes: result.blobSizeBytes ?? 0,
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
      subject: nearAccountId,
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
 * Extract the assistant text from a provider's raw chat-completion JSON.
 * Best-effort across OpenAI-compatible (choices[0].message.content) and
 * Anthropic (content[].text) shapes. Returns "" if no text field is found;
 * the raw response is always passed through alongside for clients that need it.
 */
function extractAssistantText(raw: unknown): string {
  if (!raw || typeof raw !== "object") return "";
  const r = raw as Record<string, any>;
  const openai = r?.choices?.[0]?.message?.content;
  if (typeof openai === "string") return openai;
  if (Array.isArray(r?.content)) {
    const block = r.content.find((b: any) => b?.type === "text" && typeof b?.text === "string");
    if (block) return block.text as string;
  }
  return "";
}

/**
 * @notice Execute a stored skill through the ZDR egress firewall.
 * @dev Canonical contract matches the agent's `ExecuteRequest`
 *      ({ nearAccountId, blobId, expectedSha256, userInput }). The model and the
 *      egress destination live inside the encrypted skill config in the enclave and
 *      are NOT caller-supplied. The agent returns the provider's raw response, which
 *      we normalize to { output, zdrBlocked } for clients.
 */
export async function handleZdrCheck(
  env: Env,
  args: Record<string, unknown>,
): Promise<McpToolCallResult> {
  const { nearAccountId, blobId, expectedSha256, userInput } = args;

  if (
    typeof nearAccountId !== "string" ||
    typeof blobId !== "string" ||
    typeof expectedSha256 !== "string" ||
    typeof userInput !== "string"
  ) {
    return errorResult("INVALID_ARGS", "nearAccountId, blobId, expectedSha256, and userInput must be strings.");
  }

  try {
    const result = await callShadeAgent({
      env,
      path: "/skills/execute",
      subject: nearAccountId,
      body: { nearAccountId, blobId, expectedSha256, userInput },
    });

    // Agent returns the provider's raw JSON; normalize to a stable client shape.
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          zdrBlocked: false,
          output: extractAssistantText(result),
          raw: result,
        }),
      }],
    };
  } catch (e) {
    const msg = String(e);
    const isFirewallBlock =
      msg.includes("FIREWALL_ERROR_DESTINATION_BLOCKED") ||
      msg.includes("FIREWALL_ERROR_SENSITIVE_CONTENT");

    if (!isFirewallBlock) {
      // Genuine failure (e.g. blob not found, provider error) — surface as an error.
      return errorResult("ZDR_CHECK_FAILED", msg);
    }

    // Firewall block: classify, audit, and return a structured (non-error) result so
    // clients can render the block instead of catching an exception.
    let ruleTriggered = "UNKNOWN";
    let markerDetected: string | null = null;
    if (msg.includes("FIREWALL_ERROR_DESTINATION_BLOCKED")) {
      ruleTriggered = "DESTINATION_BLOCKED";
    } else if (msg.includes("FIREWALL_ERROR_SENSITIVE_CONTENT")) {
      ruleTriggered = "SENSITIVE_CONTENT_BLOCKED";
      const match = msg.match(/sensitive word: ([A-Z_]+)/i) || msg.match(/contained marker (\w+)/);
      if (match) markerDetected = match[1] ?? null;
    }

    if (env.DB) {
      try {
        // The real egress destination lives in the enclave skill config and is not
        // visible to the gateway; we log the skill blobId and an enclave-config marker.
        await env.DB.prepare(
          "INSERT INTO firewall_audit_logs (near_account_id, timestamp, skill_name, destination, rule_triggered, marker_detected) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(
          nearAccountId,
          Date.now(),
          blobId,
          "enclave-config",
          ruleTriggered,
          markerDetected
        ).run();
      } catch {
        // Best-effort logging — never break the client response.
      }
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          success: true,
          zdrBlocked: true,
          zdrMarker: markerDetected,
          ruleTriggered,
        }),
      }],
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
