// ─────────────────────────────────────────────────────────────────────────────
// AegisApiClient — Aegis web app API surface
//
// Data plane (memory read/write, skill execution): routed through the GATEWAY MCP
// endpoint under the user's session via ./mcpClient. The browser holds NO shared
// agent key (Phase 1 — see docs/ROADMAP_AUTH_TO_ZK.md). The gateway authenticates
// the session, enforces the account, and mints a capability token for the agent;
// all encryption/decryption happens inside the TEE.
//
// Control plane (/api/*, /auth/*): session-authenticated calls to the gateway.
// `getAgentBase()` is retained for unauthenticated health checks and the existing
// /api/* control-plane calls (which already carry the session token).
//
// Security history:
//   NEW-05 — VITE_AGENT_URL validated to https:// (or http://localhost for dev).
// ─────────────────────────────────────────────────────────────────────────────

import { callMcpTool } from './mcpClient';

// Read custom agent URL from localStorage if set, else fallback to Vite environment default
export function getAgentBase(): string {
  const custom = localStorage.getItem('AEGIS_CUSTOM_AGENT_URL');
  if (custom) {
    return validateAndResolveAgentBase(custom);
  }
  // In development, route to proxy. In production, connect directly to the live secure enclave.
  const defaultUrl = import.meta.env.DEV ? '/api' : 'https://api.aipassports.xyz';
  const raw = (import.meta.env.VITE_AGENT_URL as string | undefined) ?? defaultUrl;
  return validateAndResolveAgentBase(raw);
}

// Write or remove custom agent URL in localStorage
export function setCustomAgentUrl(url: string | null): void {
  if (url) {
    // Validate first before storing
    validateAndResolveAgentBase(url);
    localStorage.setItem('AEGIS_CUSTOM_AGENT_URL', url);
  } else {
    localStorage.removeItem('AEGIS_CUSTOM_AGENT_URL');
  }
}

// NEW-05: Validate VITE_AGENT_URL scheme at module load time.
// Prevents URL injection: if an attacker compromises the build pipeline and
// sets VITE_AGENT_URL to http://attacker.com, all vault reads go to the attacker.
// Allowed: https:// in production, http://localhost or /api (proxy) in dev.
function validateAndResolveAgentBase(raw: string): string {
  // Relative path (Vite dev proxy) — safe, no validation needed
  if (raw.startsWith('/')) return raw;

  try {
    const url = new URL(raw);
    const isHttps = url.protocol === 'https:';
    const isLocalHttp =
      url.protocol === 'http:' &&
      (url.hostname === 'localhost' || url.hostname === '127.0.0.1');

    if (!isHttps && !isLocalHttp) {
      throw new Error(
        `VITE_AGENT_URL must be https:// in production (got "${raw}"). ` +
        `For local dev, use http://localhost only.`
      );
    }
    return raw;
  } catch (e) {
    // URL parse failure or our own validation error
    throw new Error(`VITE_AGENT_URL is not a valid URL: "${raw}". Error: ${(e as Error).message}`);
  }
}

/** Whether we're in production mode (IronClaw agent, no local proxy) */
export const IS_PROD_AGENT = () => {
  const base = getAgentBase();
  return !base.startsWith('/') && !base.includes('localhost') && !base.includes('127.0.0.1');
};

// ─── Data plane ───────────────────────────────────────────────────────────────
//
// Phase 1: the browser no longer holds a shared agent key (VITE_AGENT_API_KEY is
// removed). All memory/skill operations go through the gateway MCP endpoint under
// the user's session via `callMcpTool` (see ./mcpClient). The gateway authenticates
// the session, enforces the account, and mints a capability token for the agent.
// `getAgentBase()` above is retained only for unauthenticated health checks and the
// control-plane `/api/*` calls (which already use the session token).

// ─── Vault Write ──────────────────────────────────────────────────────────────

/**
 * Encrypts plaintext inside the TEE and persists the ciphertext blob.
 * Returns the blobId and SHA-256 integrity hash for NEAR contract registration.
 *
 * Phase 1: routed through the gateway MCP `vault_write` tool under the user's
 * session (not directly to the agent with a shared key). The gateway enforces the
 * account and mints a capability token the agent verifies.
 */
export async function vaultWrite(
  nearAccountId: string,
  entryType: 'wiki' | 'skill',
  identifier: string,
  plaintext: string,
  signal?: AbortSignal,
): Promise<{ blobId: string; contentSha256: string }> {
  return callMcpTool<{ blobId: string; contentSha256: string }>('vault_write', {
    nearAccountId,
    entryType,
    identifier,
    plaintext,
  }, signal);
}

// ─── Vault Read ───────────────────────────────────────────────────────────────

/**
 * Downloads the encrypted blob, verifies SHA-256 integrity, and decrypts inside
 * the TEE. Returns the raw plaintext to the browser.
 *
 * Phase 1: routed through the gateway MCP `vault_read` tool under the user's
 * session. Note the MCP tool expects `expectedSha256` (mapped from contentSha256).
 */
export async function vaultRead(
  nearAccountId: string,
  entryType: 'wiki' | 'skill',
  identifier: string,
  blobId: string,
  contentSha256: string,
  signal?: AbortSignal,
): Promise<{ plaintext: string; metadata: Record<string, unknown> }> {
  return callMcpTool<{ plaintext: string; metadata: Record<string, unknown> }>('vault_read', {
    nearAccountId,
    entryType,
    identifier,
    blobId,
    expectedSha256: contentSha256,
  }, signal);
}

// ─── Skill Execute ────────────────────────────────────────────────────────────

/**
 * Executes a stored skill through the ZDR egress firewall in the TEE.
 *
 * Routed through the gateway MCP `zdr_check` tool under the user's session (no shared
 * agent key in the browser). The contract matches the agent's `ExecuteRequest`:
 * the skill's model and egress destination live in its encrypted config inside the
 * enclave, so only the skill blob + integrity hash + user input are sent. The gateway
 * normalizes the provider response to `{ output, zdrBlocked, zdrMarker }`.
 */
export async function skillsExecute(
  nearAccountId: string,
  skillBlobId: string,
  skillContentSha256: string,
  userPrompt: string,
  signal?: AbortSignal,
): Promise<{ output: string; zdrBlocked: boolean; zdrMarker?: string }> {
  return callMcpTool<{ output: string; zdrBlocked: boolean; zdrMarker?: string }>(
    'zdr_check',
    {
      nearAccountId,
      blobId: skillBlobId,
      expectedSha256: skillContentSha256,
      userInput: userPrompt,
    },
    signal,
  );
}

// ─── Health ───────────────────────────────────────────────────────────────────

/** Returns true if the TEE agent is reachable. */
export async function pingAgent(): Promise<boolean> {
  try {
    const base = getAgentBase();
    const res = await fetch(`${base}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Fetches the user profile from the SaaS control plane.
 */
export async function getUserProfile(signal?: AbortSignal): Promise<{
  nearAccountId: string;
  apiKey: string;
  teeEndpoint: string;
  subscriptionStatus: 'free' | 'developer' | 'team';
  storageUsedBytes: number;
  storageLimitBytes: number;
}> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/user`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  return res.json() as Promise<any>;
}

/**
 * Registers/onboards the user on the SaaS control plane.
 */
export async function registerUser(teeEndpoint?: string, signal?: AbortSignal): Promise<{
  nearAccountId: string;
  apiKey: string;
  teeEndpoint: string;
  subscriptionStatus: 'free' | 'developer' | 'team';
  storageUsedBytes: number;
  storageLimitBytes: number;
}> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/register`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    body: JSON.stringify({ teeEndpoint }),
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  return res.json() as Promise<any>;
}

/**
 * Regenerates the user's primary API key on the SaaS control plane.
 */
export async function regenerateApiKey(signal?: AbortSignal): Promise<{ apiKey: string }> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/keys/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  return res.json() as Promise<any>;
}

/**
 * Subscribes to a pricing tier (Free / Developer / Team) on the SaaS control plane.
 */
export async function subscribeTier(tier: 'free' | 'developer' | 'team', signal?: AbortSignal): Promise<{
  subscriptionStatus: 'free' | 'developer' | 'team';
  storageLimitBytes: number;
}> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/billing/subscribe`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    body: JSON.stringify({ tier }),
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  return res.json() as Promise<any>;
}

/**
 * Fetches ZDR firewall block audit logs for the user.
 */
export async function getFirewallLogs(signal?: AbortSignal): Promise<Array<{
  timestamp: number;
  skill_name: string;
  destination: string;
  rule_triggered: string;
  marker_detected: string | null;
}>> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/logs`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  const data = await res.json() as { logs: any[] };
  return data.logs;
}

// ─── Team Management ─────────────────────────────────────────────────────────

/**
 * Helper for session-authenticated POST requests to the SaaS control plane.
 * Mirrors the pattern used by registerUser, subscribeTier, etc.
 */
async function gatewayPost<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  return res.json() as Promise<T>;
}

/**
 * Creates a new team on the SaaS control plane.
 * The gateway generates a UUID for the team and registers it on the NEAR contract.
 */
export async function createTeam(
  name: string,
  signal?: AbortSignal,
): Promise<{ teamId: string }> {
  const teamId = crypto.randomUUID();
  await gatewayPost<{ success: boolean }>('/api/team/create', { teamId, name }, signal);
  return { teamId };
}

/**
 * Adds a NEAR account as a member to an existing team with the given permission level.
 * The gateway verifies team ownership via the NEAR contract before adding.
 */
export async function addTeamMember(
  teamId: string,
  memberAccountId: string,
  permission: 'read' | 'write' | 'admin',
  signal?: AbortSignal,
): Promise<{ success: boolean }> {
  return gatewayPost<{ success: boolean }>(
    '/api/team/add_member',
    { teamId, memberAccountId, permission },
    signal,
  );
}

/**
 * Removes a member from a team. Requires admin permission on the team.
 */
export async function removeTeamMember(
  teamId: string,
  memberAccountId: string,
  signal?: AbortSignal,
): Promise<{ success: boolean }> {
  return gatewayPost<{ success: boolean }>(
    '/api/team/remove_member',
    { teamId, memberAccountId },
    signal,
  );
}

/**
 * Updates the permission level for an existing team member.
 * Requires admin permission on the team.
 */
export async function updateTeamPermission(
  teamId: string,
  memberAccountId: string,
  permission: 'read' | 'write' | 'admin',
  signal?: AbortSignal,
): Promise<{ success: boolean }> {
  return gatewayPost<{ success: boolean }>(
    '/api/team/update_permission',
    { teamId, memberAccountId, permission },
    signal,
  );
}

/**
 * Lists all members of a team with their permission levels and join timestamps.
 */
export async function listTeamMembers(
  teamId: string,
  signal?: AbortSignal,
): Promise<Array<{ accountId: string; permission: string; joinedAt: number }>> {
  const base = getAgentBase();
  const sessionToken = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  const res = await fetch(`${base}/api/team/members?teamId=${encodeURIComponent(teamId)}`, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(sessionToken ? { Authorization: `Bearer ${sessionToken}` } : {}),
    },
    signal,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }

  const data = await res.json() as { members: Array<{ accountId: string; permission: string; joinedAt: number }> };
  return data.members;
}
