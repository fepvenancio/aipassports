import type { VaultPointer } from './types';

// ─────────────────────────────────────────────────────────────────────────────
// Stateless NEAR RPC View Client
//
// Calls NEAR contract view methods directly via the public NEAR JSON-RPC.
// No wallet connection required — these are unauthenticated read-only calls.
// Spec: ARCH.md §4.2 — view methods do not mutate state.
//
// Response decoding: NEAR RPC returns result.result as an array of ASCII byte
// values. We decode: Uint8Array → UTF-8 string → JSON.parse.
// ─────────────────────────────────────────────────────────────────────────────

const NEAR_RPC = (import.meta.env.VITE_NEAR_RPC_URL as string | undefined)
  ?? 'https://rpc.testnet.near.org';

const CONTRACT_ID = (import.meta.env.VITE_NEAR_CONTRACT_ID as string | undefined)
  ?? 'aegis-vault.testnet';

// ─── Core RPC driver ─────────────────────────────────────────────────────────

async function viewCall<T>(methodName: string, args: Record<string, unknown>): Promise<T> {
  const argsBase64 = btoa(JSON.stringify(args));

  const res = await fetch(NEAR_RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'query',
      params: {
        request_type: 'call_function',
        finality: 'final',
        account_id: CONTRACT_ID,
        method_name: methodName,
        args_base64: argsBase64,
      },
    }),
  });

  if (!res.ok) throw new Error(`NEAR RPC HTTP error: ${res.status}`);

  const json = await res.json() as {
    result?: { result: number[] };
    error?: { message: string; data?: string };
  };

  if (json.error) {
    throw new Error(json.error.data ?? json.error.message ?? 'NEAR RPC error');
  }

  if (!json.result?.result) throw new Error('NEAR RPC: empty result');

  // Decode byte array → UTF-8 → JSON
  const bytes = new Uint8Array(json.result.result);
  const text = new TextDecoder('utf-8').decode(bytes);
  return JSON.parse(text) as T;
}

// ─── View Methods ─────────────────────────────────────────────────────────────

/** Returns a paginated list of wiki slugs owned by accountId. */
export function listWikiSlugs(
  accountId: string,
  fromIndex = 0,
  limit = 100,
): Promise<string[]> {
  return viewCall<string[]>('list_wiki_slugs', {
    account_id: accountId,
    from_index: fromIndex,
    limit,
  });
}

/** Returns the VaultPointer for a specific wiki slug, or null if not found. */
export function getWikiPointer(
  accountId: string,
  slug: string,
): Promise<VaultPointer | null> {
  return viewCall<VaultPointer | null>('get_wiki_pointer', {
    account_id: accountId,
    slug,
  });
}

/** Returns a paginated list of skill IDs owned by accountId. */
export function listSkillIds(
  accountId: string,
  fromIndex = 0,
  limit = 100,
): Promise<string[]> {
  return viewCall<string[]>('list_skill_ids', {
    account_id: accountId,
    from_index: fromIndex,
    limit,
  });
}

/** Returns the VaultPointer for a specific skill, or null if not found. */
export function getSkillPointer(
  accountId: string,
  skillId: string,
): Promise<VaultPointer | null> {
  return viewCall<VaultPointer | null>('get_skill_pointer', {
    account_id: accountId,
    skill_id: skillId,
  });
}
