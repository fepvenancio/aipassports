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
// ─────────────────────────────────────────────────────────────────────────────

const AGENT_BASE = (import.meta.env.VITE_AGENT_URL as string | undefined) ?? '/api';

/** Whether we're in production mode (IronClaw agent, no local proxy) */
export const IS_PROD_AGENT = Boolean(import.meta.env.VITE_AGENT_URL);

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function agentPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${AGENT_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
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
): Promise<{ blobId: string; contentSha256: string }> {
  return agentPost<{ blobId: string; contentSha256: string }>('/vault/write', {
    nearAccountId,
    entryType,
    identifier,
    plaintext,
  });
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
): Promise<{ plaintext: string; metadata: Record<string, unknown> }> {
  return agentPost<{ plaintext: string; metadata: Record<string, unknown> }>('/vault/read', {
    nearAccountId,
    blobId,
    contentSha256,
  });
}

// ─── Skill Execute ────────────────────────────────────────────────────────────

/**
 * Loads the skill config from Walrus, applies ZDR firewall rules,
 * calls the LLM provider, and returns the assistant output.
 *
 * llmApiKey: In-memory only. Only sent in dev mode (local agent).
 *            In production the key lives in IronClaw TEE secrets.
 * Spec: ARCH.md §7.3 — POST /skills/execute
 */
export async function skillsExecute(
  nearAccountId: string,
  skillBlobId: string,
  skillContentSha256: string,
  userPrompt: string,
  llmApiKey?: string,
): Promise<{ output: string; zdrBlocked: boolean; zdrMarker?: string }> {
  return agentPost<{ output: string; zdrBlocked: boolean; zdrMarker?: string }>(
    '/skills/execute',
    {
      nearAccountId,
      skillBlobId,
      skillContentSha256,
      userPrompt,
      ...(llmApiKey ? { llmApiKey } : {}),
    },
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
