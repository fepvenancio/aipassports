// ─────────────────────────────────────────────────────────────────────────────
// AegisApiClient — TEE Agent HTTP Interface
//
// Targets the Rust TEE Shade Agent (IronClaw / local dev at localhost:8080).
//
// Dev  (VITE_AGENT_URL unset): Vite proxies /api → http://localhost:8080
// Prod (VITE_AGENT_URL set):   Direct fetch to the IronClaw agent URL
//
// All encryption, decryption, Walrus I/O, and LLM calls are performed
// inside the TEE. The browser never receives or sends plaintext keys.
//
// Security hardening applied (audit cycle 2026-05-22 round 2):
//   CRITICAL-R1  — Authorization: Bearer header added to all agentPost() calls.
//   NEW-05       — VITE_AGENT_URL validated to be https:// (or http://localhost
//                  for dev) at module initialization. Fails fast if invalid.
//   NEW-01       — agentPost() accepts an AbortSignal for cancellation/cleanup.
// ─────────────────────────────────────────────────────────────────────────────

const RAW_AGENT_URL = (import.meta.env.VITE_AGENT_URL as string | undefined) ?? '/api';

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

const AGENT_BASE = validateAndResolveAgentBase(RAW_AGENT_URL);

/** Whether we're in production mode (IronClaw agent, no local proxy) */
export const IS_PROD_AGENT = Boolean(import.meta.env.VITE_AGENT_URL);

// ─── Agent API Key ────────────────────────────────────────────────────────────

// CRITICAL-R1: The agent now requires Bearer token authentication (C-01 server fix).
// Without this header, every protected route returns 401 and the app is broken.
// Key is loaded from VITE_AGENT_API_KEY — this is the public-facing API key,
// NOT the TEE master secret (which never leaves the enclave).
const AGENT_API_KEY = (import.meta.env.VITE_AGENT_API_KEY as string | undefined) ?? '';

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * POST to the TEE agent with:
 *  - Content-Type: application/json
 *  - Authorization: Bearer <VITE_AGENT_API_KEY>  (CRITICAL-R1)
 *  - AbortSignal for timeout/unmount cleanup     (NEW-01)
 */
async function agentPost<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${AGENT_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // CRITICAL-R1: Send Bearer token on every agent request.
      // Without this, C-01 middleware rejects all calls with 401.
      ...(AGENT_API_KEY ? { Authorization: `Bearer ${AGENT_API_KEY}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` })) as { error?: string };
    throw new Error(err.error ?? `Agent error: HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ─── Vault Write ──────────────────────────────────────────────────────────────

/**
 * Encrypts plaintext inside the TEE and uploads the ciphertext blob to Walrus.
 * Returns the blobId and SHA-256 integrity hash for NEAR contract registration.
 * Spec: ARCH.md §4.1 — POST /vault/write
 */
export async function vaultWrite(
  nearAccountId: string,
  entryType: 'wiki' | 'skill',
  identifier: string,
  plaintext: string,
  signal?: AbortSignal,
): Promise<{ blobId: string; contentSha256: string }> {
  return agentPost<{ blobId: string; contentSha256: string }>('/vault/write', {
    nearAccountId,
    entryType,
    identifier,
    plaintext,
  }, signal);
}

// ─── Vault Read ───────────────────────────────────────────────────────────────

/**
 * Downloads the encrypted blob from Walrus, verifies SHA-256 integrity,
 * and decrypts inside the TEE. Returns the raw plaintext to the browser.
 * Spec: ARCH.md §4.2 — POST /vault/read
 */
export async function vaultRead(
  nearAccountId: string,
  blobId: string,
  contentSha256: string,
  signal?: AbortSignal,
): Promise<{ plaintext: string; metadata: Record<string, unknown> }> {
  return agentPost<{ plaintext: string; metadata: Record<string, unknown> }>('/vault/read', {
    nearAccountId,
    blobId,
    contentSha256,
  }, signal);
}

// ─── Skill Execute ────────────────────────────────────────────────────────────

/**
 * Loads the skill config from Walrus, applies ZDR firewall rules,
 * calls the LLM provider, and returns the assistant output.
 *
 * CRITICAL-R6: llmApiKey parameter removed — the key now lives in the agent's
 * AppState (loaded at startup from LLM_API_KEY env var). It is never accepted
 * in HTTP request bodies.
 * Spec: ARCH.md §7.3 — POST /skills/execute
 */
export async function skillsExecute(
  nearAccountId: string,
  skillBlobId: string,
  skillContentSha256: string,
  userPrompt: string,
  signal?: AbortSignal,
): Promise<{ output: string; zdrBlocked: boolean; zdrMarker?: string }> {
  return agentPost<{ output: string; zdrBlocked: boolean; zdrMarker?: string }>(
    '/skills/execute',
    {
      nearAccountId,
      skillBlobId,
      skillContentSha256,
      userPrompt,
      // NOTE: llmApiKey intentionally omitted — loaded from server env (CRITICAL-R6)
    },
    signal,
  );
}

// ─── Health ───────────────────────────────────────────────────────────────────

/** Returns true if the TEE agent is reachable. */
export async function pingAgent(): Promise<boolean> {
  try {
    const res = await fetch(`${AGENT_BASE}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
