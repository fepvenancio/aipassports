// ─────────────────────────────────────────────────────────────────────────────
// mcpClient — Gateway MCP transport for the web app (Phase 1: close the browser gap)
//
// The web app no longer talks to the TEE agent directly with a shared key.
// All data-plane operations (memory read/write, skill execution) go through the
// gateway's MCP endpoint (`/mcp`, JSON-RPC tools/call), authenticated with the
// user's NEAR/SSO **session token**. The gateway validates the session, enforces
// that the account matches, and mints a short-lived capability token for the agent.
//
// This eliminates VITE_AGENT_API_KEY from the browser and makes every call
// attributed and capability-bound. See docs/ROADMAP_AUTH_TO_ZK.md (Phase 1).
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Resolve the gateway base URL. Mirrors the existing MCP-endpoint logic used by
 * Dashboard/McpSetupPanel: dev → local Worker, prod → same origin as the app.
 * Override with VITE_GATEWAY_URL when the gateway is on a different host.
 */
export function getGatewayBase(): string {
  const override = (import.meta.env.VITE_GATEWAY_URL as string | undefined)?.trim();
  if (override) return override.replace(/\/$/, '');
  return import.meta.env.DEV ? 'http://localhost:8787' : window.location.origin;
}

interface McpTextContent {
  type: 'text';
  text: string;
}

interface McpRpcResponse {
  jsonrpc: '2.0';
  id: number | string;
  result?: { content?: McpTextContent[]; isError?: boolean };
  error?: { code: number; message: string };
}

let rpcId = 0;

/**
 * Call a gateway MCP tool and return the parsed tool payload.
 *
 * @throws Error on missing session, network failure, JSON-RPC error, or a tool
 *         result whose payload has `success === false`.
 */
export async function callMcpTool<T = Record<string, unknown>>(
  name: string,
  args: Record<string, unknown>,
  signal?: AbortSignal,
): Promise<T> {
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  if (!sessionToken) {
    throw new Error('Not signed in: no active session. Please sign in again.');
  }

  const res = await fetch(`${getGatewayBase()}/mcp`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${sessionToken}`,
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: ++rpcId,
      method: 'tools/call',
      params: { name, arguments: args },
    }),
    signal,
  });

  // Transport / auth-level failures (e.g. 401 SESSION_EXPIRED) come back as HTTP errors.
  const json = (await res.json().catch(() => null)) as McpRpcResponse | null;
  if (!res.ok || !json) {
    const msg = json?.error?.message ?? `Gateway error: HTTP ${res.status}`;
    throw new Error(msg);
  }
  if (json.error) {
    throw new Error(json.error.message || `MCP error ${json.error.code}`);
  }

  const text = json.result?.content?.[0]?.text;
  if (typeof text !== 'string') {
    throw new Error('Malformed MCP response: missing tool result.');
  }

  // Tool payloads are JSON strings. Tool-level failures carry { success: false }.
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error('Malformed MCP tool payload (not JSON).');
  }
  if (payload.success === false) {
    const message =
      (payload.message as string | undefined) ??
      (payload.errorCode as string | undefined) ??
      'Tool call failed.';
    throw new Error(message);
  }

  return payload as T;
}
