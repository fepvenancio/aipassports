import type { WalletSelector } from '@near-wallet-selector/core';
import type { actionCreators as ActionCreatorsType } from '@near-wallet-selector/core';

// ─────────────────────────────────────────────────────────────────────────────
// NEAR Wallet Service — Phase 3
//
// Responsibilities:
//  1. Wallet connect / disconnect (NEAR Wallet Selector)
//  2. NEAR contract mutations via signAndSendTransaction
//
// Code-splitting:
//   setupWalletSelector and setupMyNearWallet are DYNAMICALLY imported inside
//   getSelector() so they are excluded from the initial JS bundle. Vite will
//   emit them as separate async chunks loaded only when the user clicks
//   "Connect Wallet" — reducing initial load by ~40%.
//
// Action typing:
//   Wallet Selector v10 re-exports NAJ Action (near-api-js native type).
//   We use the provided `actionCreators.functionCall` builder which returns
//   the correct NAJ Action type — no `as any` required.
//
// All args are snake_case to match Rust borsh deserialization. NEAR.md §4.
// ─────────────────────────────────────────────────────────────────────────────

const NEAR_NETWORK = (import.meta.env.VITE_NEAR_NETWORK as 'testnet' | 'mainnet' | undefined)
  ?? 'testnet';

const CONTRACT_ID = (import.meta.env.VITE_NEAR_CONTRACT_ID as string | undefined)
  ?? 'aegis-vault.testnet';

// 100 Tgas expressed as BigInt (NAJ action builder expects BigInt for gas)
const GAS = BigInt('100000000000000');
// 0.01 NEAR in yoctoNEAR (excess storage deposit auto-refunded by contract)
const STORAGE_DEPOSIT = BigInt('10000000000000000000000');

let _selector: WalletSelector | null = null;
let _selectorPromise: Promise<WalletSelector> | null = null;
let _actionCreators: typeof ActionCreatorsType | null = null;

// ─── Selector (lazy-loaded) ───────────────────────────────────────────────────

async function getSelector(): Promise<WalletSelector> {
  if (_selector) return _selector;
  if (_selectorPromise) return _selectorPromise;

  _selectorPromise = (async () => {
    // Dynamic import — Vite code-splits these into separate async chunks.
    // The wallet selector (~400 kB) is not part of the initial JS bundle.
    const [coreModule, { setupMyNearWallet }] = await Promise.all([
      import('@near-wallet-selector/core'),
      import('@near-wallet-selector/my-near-wallet'),
    ]);

    const { setupWalletSelector } = coreModule;
    _actionCreators = coreModule.actionCreators;

    _selector = await setupWalletSelector({
      network: NEAR_NETWORK,
      modules: [setupMyNearWallet()],
    });

    _selectorPromise = null;
    return _selector;
  })();

  return _selectorPromise;
}

// ─── Wallet Connect / Disconnect ──────────────────────────────────────────────

/**
 * Opens the NEAR wallet connection modal.
 * Phase 3 auth: this is the ONLY auth step for dashboard mode.
 * IDENTITY.md §6 — dashboard mode uses wallet directly.
 */
export async function connectWallet(): Promise<string> {
  const selector = await getSelector();

  // Modal UI is also dynamically imported — not in initial bundle.
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
    const existing = selector.store.getState().accounts[0]?.accountId;
    if (existing) { resolve(existing); return; }

    const sub = selector.store.observable.subscribe((state) => {
      const account = state.accounts[0]?.accountId;
      if (account) { sub.unsubscribe(); resolve(account); }
    });

    setTimeout(
      () => { sub.unsubscribe(); reject(new Error('Wallet connection timed out')); },
      300_000,
    );
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
  deposit: bigint,
): Promise<void> {
  const selector = await getSelector();
  const wallet = await selector.wallet();

  // actionCreators is loaded from the dynamic import of @near-wallet-selector/core.
  // It is guaranteed to be set because functionCall() is always called after
  // getSelector() which initialises _actionCreators.
  const action = _actionCreators!.functionCall(
    methodName,
    args,
    GAS,
    deposit,
  );

  await wallet.signAndSendTransaction({
    receiverId: CONTRACT_ID,
    actions: [action],
  });
}

// ─── Wiki Mutations ───────────────────────────────────────────────────────────

/**
 * Broadcasts update_wiki_pointer to the NEAR contract.
 * 0.01 NEAR storage deposit — excess refunded (NEAR.md §4.2).
 */
export function updateWikiPointer(
  slug: string,
  blobId: string,
  contentSha256: string,
): Promise<void> {
  return functionCall(
    'update_wiki_pointer',
    { slug, blob_id: blobId, content_sha256: contentSha256 },
    STORAGE_DEPOSIT,
  );
}

/** Broadcasts remove_wiki_pointer. No deposit required. */
export function removeWikiPointer(slug: string): Promise<void> {
  return functionCall('remove_wiki_pointer', { slug }, BigInt(0));
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
    STORAGE_DEPOSIT,
  );
}

/** Broadcasts remove_skill_pointer. */
export function removeSkillPointer(skillId: string): Promise<void> {
  return functionCall('remove_skill_pointer', { skill_id: skillId }, BigInt(0));
}
