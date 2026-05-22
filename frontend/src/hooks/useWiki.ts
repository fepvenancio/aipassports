import { useState, useEffect, useCallback, useRef } from 'react';
import * as nearRpc from '../api/nearRpc';
import * as agent from '../api/gateway';
import * as wallet from '../near/wallet';
import type { VaultPointer } from '../api/types';

// ─── State Machine ────────────────────────────────────────────────────────────

export type WikiStatus =
  | 'idle'
  | 'fetching-slugs'
  | 'fetching-pointer'
  | 'decrypting-tee'
  | 'saving-walrus'
  | 'committing-near'
  | 'deleting'
  | 'error';

export interface WikiState {
  status: WikiStatus;
  errorMessage: string | null;
  slugs: string[];
  selectedSlug: string | null;
  content: string;            // Current editor content
  savedContent: string;       // Last persisted content (diff detection)
  pointer: VaultPointer | null;
  isNewPage: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// useWiki
// Encapsulates all async state machine logic for wiki page CRUD.
// Reads: NEAR RPC (no auth) → TEE agent decryption
// Writes: TEE agent encryption → Walrus upload → NEAR wallet transaction
//
// Security hardening applied (audit cycle 2026-05-22 round 2):
//   NEW-03 — savePage has a function-level concurrency guard using a ref.
//             Previously, the guard only existed as a UI `disabled` prop.
//             Two concurrent calls (keyboard shortcut + button click) would
//             produce two Walrus blobs and two NEAR transactions.
//   NEW-01 — AbortController cleanup on all async operations via useRef.
//             Prevents setState-after-unmount on long-running TEE operations.
// ─────────────────────────────────────────────────────────────────────────────
export function useWiki(nearAccountId: string) {
  const [state, setState] = useState<WikiState>({
    status: 'idle',
    errorMessage: null,
    slugs: [],
    selectedSlug: null,
    content: '',
    savedContent: '',
    pointer: null,
    isNewPage: false,
  });

  // NEW-03: Synchronous lock for savePage — prevents double-upload/double-tx
  const savingRef = useRef(false);

  // NEW-01: AbortController for active vault read/write operations
  const abortRef = useRef<AbortController | null>(null);

  // NEW-01: Cancel in-flight requests on unmount
  useEffect(() => {
    return () => {
      abortRef.current?.abort();
    };
  }, []);

  // ── Helpers ────────────────────────────────────────────────────────────────

  function setStatus(status: WikiStatus) {
    setState((s) => ({ ...s, status, errorMessage: null }));
  }

  function setError(message: string) {
    setState((s) => ({ ...s, status: 'error', errorMessage: message }));
  }

  // ── List slugs ─────────────────────────────────────────────────────────────

  const listSlugs = useCallback(async () => {
    setStatus('fetching-slugs');
    try {
      const slugs = await nearRpc.listWikiSlugs(nearAccountId);
      setState((s) => ({ ...s, status: 'idle', slugs }));
    } catch (e) {
      setError((e as Error).message);
    }
  }, [nearAccountId]);

  useEffect(() => { listSlugs(); }, [listSlugs]);

  // ── Select / read a page ───────────────────────────────────────────────────

  async function selectPage(slug: string) {
    // Cancel any previous in-flight read
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setState((s) => ({
      ...s, status: 'fetching-pointer', selectedSlug: slug,
      isNewPage: false, content: '', savedContent: '', pointer: null,
    }));
    try {
      const pointer = await nearRpc.getWikiPointer(nearAccountId, slug);
      if (!pointer) throw new Error(`No pointer found for slug "${slug}"`);

      if (controller.signal.aborted) return;
      setState((s) => ({ ...s, status: 'decrypting-tee', pointer }));

      const { plaintext } = await agent.vaultRead(
        nearAccountId,
        'wiki',
        slug,
        pointer.blob_id,
        pointer.content_sha256,
        controller.signal,
      );

      if (controller.signal.aborted) return;
      setState((s) => ({
        ...s, status: 'idle', content: plaintext, savedContent: plaintext,
      }));
    } catch (e) {
      if (controller.signal.aborted) return;
      setError((e as Error).message);
    }
  }

  // ── Start new page ─────────────────────────────────────────────────────────

  function startNewPage() {
    abortRef.current?.abort();
    setState((s) => ({
      ...s, status: 'idle', selectedSlug: null, isNewPage: true,
      content: '', savedContent: '', pointer: null, errorMessage: null,
    }));
  }

  // ── Save (create or update) ────────────────────────────────────────────────

  async function savePage(slug: string) {
    // NEW-03: Function-level concurrency guard.
    // UI disabled prop alone is not enough — keyboard shortcuts or programmatic
    // calls can bypass it. Two concurrent saves = two Walrus blobs + two NEAR txns.
    if (savingRef.current) return;
    savingRef.current = true;

    // Cancel any stale vault-read abort controller to avoid conflicts
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    // Capture content at call-time, not after async gaps (stale closure prevention)
    const currentContent = state.content;

    setState((s) => ({ ...s, status: 'saving-walrus', errorMessage: null }));
    try {
      // 1. Encrypt + upload to Walrus via TEE agent
      const { blobId, contentSha256 } = await agent.vaultWrite(
        nearAccountId, 'wiki', slug, currentContent, controller.signal,
      );

      if (controller.signal.aborted) return;

      // 2. Commit pointer to NEAR contract
      setState((s) => ({ ...s, status: 'committing-near' }));
      await wallet.updateWikiPointer(slug, blobId, contentSha256);

      if (controller.signal.aborted) return;

      // 3. Update local state
      const pointer: VaultPointer = {
        blob_id: blobId,
        content_sha256: contentSha256,
        updated_at_ms: Date.now(),
      };

      setState((s) => ({
        ...s, status: 'idle', selectedSlug: slug, isNewPage: false,
        pointer, savedContent: currentContent,
        slugs: s.slugs.includes(slug) ? s.slugs : [...s.slugs, slug],
      }));
    } catch (e) {
      if (controller.signal.aborted) return;
      setError((e as Error).message);
    } finally {
      savingRef.current = false;
    }
  }

  // ── Delete ─────────────────────────────────────────────────────────────────

  async function deletePage(slug: string) {
    setState((s) => ({ ...s, status: 'deleting' }));
    try {
      await wallet.removeWikiPointer(slug);
      setState((s) => ({
        ...s, status: 'idle',
        slugs: s.slugs.filter((x) => x !== slug),
        selectedSlug: s.selectedSlug === slug ? null : s.selectedSlug,
        content: s.selectedSlug === slug ? '' : s.content,
        savedContent: s.selectedSlug === slug ? '' : s.savedContent,
        pointer: s.selectedSlug === slug ? null : s.pointer,
        isNewPage: false,
      }));
    } catch (e) {
      setError((e as Error).message);
    }
  }

  // ── Update editor content ──────────────────────────────────────────────────

  function setContent(content: string) {
    setState((s) => ({ ...s, content }));
  }

  const hasUnsavedChanges = state.content !== state.savedContent;

  return {
    state,
    hasUnsavedChanges,
    listSlugs,
    selectPage,
    startNewPage,
    savePage,
    deletePage,
    setContent,
  };
}
