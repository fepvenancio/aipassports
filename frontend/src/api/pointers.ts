// ─────────────────────────────────────────────────────────────────────────────
// pointers — Pointer index client (gateway/D1-backed)
//
// Replaces api/nearRpc.ts (on-chain reads) and the wallet pointer mutations
// (on-chain writes) as part of retiring the NEAR contract (Phase 2.5). Every call
// is session-authenticated against the gateway; the owner is the authenticated user.
// Signatures mirror the old nearRpc/wallet functions so hook call-sites barely change.
// ─────────────────────────────────────────────────────────────────────────────

import { getAgentBase } from './gateway';
import type { VaultPointer } from './types';

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('AEGIS_SESSION_TOKEN') || '';
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function gwGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(`${getAgentBase()}${path}`, { method: 'GET', headers: authHeaders(), signal });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({ error: `HTTP ${res.status}` }))) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function gwPost(path: string, body: unknown, signal?: AbortSignal): Promise<void> {
  const res = await fetch(`${getAgentBase()}${path}`, {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({ error: `HTTP ${res.status}` }))) as { error?: string };
    throw new Error(err.error ?? `API error: HTTP ${res.status}`);
  }
}

// ── Reads (replaces nearRpc) ───────────────────────────────────────────────────
// The nearAccountId argument is retained for signature compatibility; the gateway
// derives the owner from the session, so it is intentionally unused.

export async function listWikiSlugs(_nearAccountId?: string): Promise<string[]> {
  const { identifiers } = await gwGet<{ identifiers: string[] }>('/api/pointers/list?entryType=wiki');
  return identifiers;
}

export async function getWikiPointer(_nearAccountId: string, slug: string): Promise<VaultPointer | null> {
  const { pointer } = await gwGet<{ pointer: VaultPointer | null }>(
    `/api/pointers/get?entryType=wiki&identifier=${encodeURIComponent(slug)}`,
  );
  return pointer;
}

export async function listSkillIds(_nearAccountId?: string): Promise<string[]> {
  const { identifiers } = await gwGet<{ identifiers: string[] }>('/api/pointers/list?entryType=skill');
  return identifiers;
}

export async function getSkillPointer(_nearAccountId: string, id: string): Promise<VaultPointer | null> {
  const { pointer } = await gwGet<{ pointer: VaultPointer | null }>(
    `/api/pointers/get?entryType=skill&identifier=${encodeURIComponent(id)}`,
  );
  return pointer;
}

// ── Writes (replaces wallet pointer mutations) ─────────────────────────────────

export async function updateWikiPointer(slug: string, blobId: string, contentSha256: string): Promise<void> {
  await gwPost('/api/pointers/set', { entryType: 'wiki', identifier: slug, blobId, contentSha256 });
}

export async function removeWikiPointer(slug: string): Promise<void> {
  await gwPost('/api/pointers/remove', { entryType: 'wiki', identifier: slug });
}

export async function updateSkillPointer(id: string, blobId: string, contentSha256: string): Promise<void> {
  await gwPost('/api/pointers/set', { entryType: 'skill', identifier: id, blobId, contentSha256 });
}

export async function removeSkillPointer(id: string): Promise<void> {
  await gwPost('/api/pointers/remove', { entryType: 'skill', identifier: id });
}
