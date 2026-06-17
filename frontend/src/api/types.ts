// ─── Vault / Contract Types ───────────────────────────────────────────────────

export interface VaultPointer {
  blob_id: string;          // Walrus blobId (opaque address)
  content_sha256: string;   // SHA-256 of plaintext BEFORE encryption
  updated_at_ms: number;    // Unix ms — block_timestamp_ms() from NEAR
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

/**
 * Phase 3 session: dashboard-mode only.
 * Auth = wallet connect. No gateway session required.
 * Identity IS the NEAR accountId.
 */
export interface AuthSession {
  nearAccountId: string;
  sessionId?: string;
}

// ─── Wiki ─────────────────────────────────────────────────────────────────────

export interface WikiEntry {
  slug: string;
  pointer: VaultPointer | null;
  content?: string;           // Populated after vault/read decryption
  metadata?: Record<string, unknown>;
}

// ─── Skills ──────────────────────────────────────────────────────────────────

export interface SkillConfig {
  name: string;
  description: string;
  provider?: string;          // e.g. 'openai', 'anthropic'
  model?: string;
}

export interface SkillEntry {
  id: string;
  pointer: VaultPointer | null;
  config?: SkillConfig;       // Populated after vault/read decryption
}

// ─── ZDR Firewall ─────────────────────────────────────────────────────────────

/**
 * Sensitive markers from zdr_firewall.rs (client-side UX feedback only).
 * Real enforcement happens server-side in the TEE agent — FIREWALL.md §2.
 */
export const ZDR_MARKERS = [
  'PRIVATE_KEY', 'MNEMONIC', 'SECRET_TOKEN', 'SECRET_KEY',
  'PASSWORD', 'API_KEY', 'PASSPHRASE', 'SEED_PHRASE',
] as const;

export type ZdrMarker = typeof ZDR_MARKERS[number];

export function detectZdrViolation(text: string): ZdrMarker | null {
  const upper = text.toUpperCase();
  for (const marker of ZDR_MARKERS) {
    if (upper.includes(marker)) return marker;
  }
  return null;
}
