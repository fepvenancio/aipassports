import type { WalletSelector } from '@near-wallet-selector/core';

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

let _selector: WalletSelector | null = null;
let _selectorPromise: Promise<WalletSelector> | null = null;

// ─── Selector (lazy-loaded) ───────────────────────────────────────────────────

async function getSelector(): Promise<WalletSelector> {
  if (_selector) return _selector;
  if (_selectorPromise) return _selectorPromise;

  _selectorPromise = (async () => {
    // Dynamic import — Vite code-splits these into separate async chunks.
    // The wallet selector (~400 kB) is not part of the initial JS bundle.
    const [coreModule, { setupMyNearWallet }, { setupSender }] = await Promise.all([
      import('@near-wallet-selector/core'),
      import('@near-wallet-selector/my-near-wallet'),
      import('@near-wallet-selector/sender'),
    ]);

    const { setupWalletSelector } = coreModule;

    _selector = await setupWalletSelector({
      network: NEAR_NETWORK,
      modules: [
        setupMyNearWallet(),
        setupSender(),
      ],
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

// Pointer mutations were removed with the NEAR contract retirement (Phase 2.5).
// Pointers now live in D1 and are written via the gateway — see api/pointers.ts.
// This module retains only NEAR-wallet login (NEP-413 signing) until SSO lands.

/** Signs a challenge nonce using the connected wallet. */
export async function signChallengeMessage(challenge: string): Promise<{ publicKey: string; signature: string }> {
  const selector = await getSelector();
  const wallet = await selector.wallet();
  const accounts = selector.store.getState().accounts;
  const activeAccount = accounts[0];
  if (!activeAccount) {
    throw new Error('No active account connected');
  }

  // Decode challenge base64url to Uint8Array
  const base64 = challenge.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const nonce = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    nonce[i] = binary.charCodeAt(i);
  }

  const response = await wallet.signMessage({
    message: "Authenticate with Aegis Dashboard",
    recipient: CONTRACT_ID,
    nonce: nonce as any,
  });

  if (!response) {
    throw new Error("Message signing failed or was rejected by the wallet.");
  }

  // Encode signature to base64url
  let signatureBase64Url = '';
  if (typeof response.signature === 'string') {
    // Standardize base64 to base64url
    signatureBase64Url = response.signature
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  } else {
    const sigBytes = new Uint8Array(response.signature as any);
    let sigBinary = '';
    for (let i = 0; i < sigBytes.length; i++) {
      sigBinary += String.fromCharCode(sigBytes[i]);
    }
    signatureBase64Url = btoa(sigBinary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  return {
    publicKey: response.publicKey,
    signature: signatureBase64Url,
  };
}
