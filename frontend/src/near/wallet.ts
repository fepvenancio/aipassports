import type { WalletSelector } from '@near-wallet-selector/core';
import { setupWalletSelector } from '@near-wallet-selector/core';
import { setupMyNearWallet } from '@near-wallet-selector/my-near-wallet';

// ─────────────────────────────────────────────────────────────────────────────
// NEAR Wallet Service — Phase 3
//
// Responsibilities:
//  1. Wallet connect / disconnect (NEAR Wallet Selector)
//  2. NEAR contract mutations via signAndSendTransaction
//     (update/remove wiki and skill pointers)
//
// All args match the Rust contract exactly (snake_case, 100 Tgas, 0.01 NEAR deposit).
// NEAR.md §4 — method signatures and storage deposit math.
// ─────────────────────────────────────────────────────────────────────────────

const NEAR_NETWORK = (import.meta.env.VITE_NEAR_NETWORK as 'testnet' | 'mainnet' | undefined)
  ?? 'testnet';

const CONTRACT_ID = (import.meta.env.VITE_NEAR_CONTRACT_ID as string | undefined)
  ?? 'aegis-vault.testnet';

const GAS = '100000000000000';                    // 100 Tgas
const STORAGE_DEPOSIT = '10000000000000000000000'; // 0.01 NEAR (excess auto-refunded)

let _selector: WalletSelector | null = null;

async function getSelector(): Promise<WalletSelector> {
  if (_selector) return _selector;
  _selector = await setupWalletSelector({
    network: NEAR_NETWORK,
    modules: [setupMyNearWallet()],
  });
  return _selector;
}

// ─── Wallet Connect / Disconnect ──────────────────────────────────────────────

/**
 * Opens the NEAR wallet connection modal and returns the connected accountId.
 * Phase 3 auth: this is the ONLY auth step for dashboard mode.
 */
export async function connectWallet(): Promise<string> {
  const selector = await getSelector();
  const { setupModal } = await import('@near-wallet-selector/modal-ui');
  const modal = setupModal(selector, {
    contractId: CONTRACT_ID,
    methodNames: [
      'update_wiki_pointer',
      'remove_wiki_pointer',
      'update_skill_pointer',
      'remove_skill_pointer',
    ],
  });
  modal.show();

  return new Promise((resolve, reject) => {
    // Already signed in
    const existing = selector.store.getState().accounts[0]?.accountId;
    if (existing) { resolve(existing); return; }

    const sub = selector.store.observable.subscribe((state) => {
      const account = state.accounts[0]?.accountId;
      if (account) { sub.unsubscribe(); resolve(account); }
    });
    setTimeout(() => { sub.unsubscribe(); reject(new Error('Wallet connection timed out')); }, 300_000);
  });
}

/** Returns the connected NEAR accountId, or null if not connected. */
export async function getConnectedAccountId(): Promise<string | null> {
  try {
    const selector = await getSelector();
    return selector.store.getState().accounts[0]?.accountId ?? null;
  } catch {
    return null;
  }
}

/** Signs out of the NEAR wallet. */
export async function disconnectWallet(): Promise<void> {
  try {
    const selector = await getSelector();
    const wallet = await selector.wallet();
    await wallet.signOut();
  } catch { /* best-effort */ }
}

// ─── Internal: sign and broadcast a FunctionCall ─────────────────────────────

async function functionCall(
  methodName: string,
  args: Record<string, string>,
  withDeposit = false,
): Promise<void> {
  const selector = await getSelector();
  const wallet = await selector.wallet();
  // Wallet selector v8: action shape uses params sub-object
  await (wallet as any).signAndSendTransaction({
    receiverId: CONTRACT_ID,
    actions: [{
      type: 'FunctionCall',
      params: {
        methodName,
        args,
        gas: GAS,
        deposit: withDeposit ? STORAGE_DEPOSIT : '0',
      },
    }],
  });
}

// ─── Wiki Mutations ───────────────────────────────────────────────────────────

/**
 * Broadcasts update_wiki_pointer to the NEAR contract.
 * Attaches 0.01 NEAR storage deposit (refunded if unused — NEAR.md §4.2).
 * Args are snake_case to match Rust borsh deserialization.
 */
export function updateWikiPointer(
  slug: string,
  blobId: string,
  contentSha256: string,
): Promise<void> {
  return functionCall(
    'update_wiki_pointer',
    { slug, blob_id: blobId, content_sha256: contentSha256 },
    true,
  );
}

/** Broadcasts remove_wiki_pointer. No deposit required. */
export function removeWikiPointer(slug: string): Promise<void> {
  return functionCall('remove_wiki_pointer', { slug }, false);
}

// ─── Skill Mutations ──────────────────────────────────────────────────────────

/** Broadcasts update_skill_pointer with storage deposit. */
export function updateSkillPointer(
  skillId: string,
  blobId: string,
  contentSha256: string,
): Promise<void> {
  return functionCall(
    'update_skill_pointer',
    { skill_id: skillId, blob_id: blobId, content_sha256: contentSha256 },
    true,
  );
}

/** Broadcasts remove_skill_pointer. */
export function removeSkillPointer(skillId: string): Promise<void> {
  return functionCall('remove_skill_pointer', { skill_id: skillId }, false);
}
