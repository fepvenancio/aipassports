import { useState, useEffect, useCallback } from 'react';
import * as nearRpc from '../api/nearRpc';
import * as agent from '../api/gateway';
import * as wallet from '../near/wallet';
import type { SkillEntry, SkillConfig, VaultPointer } from '../api/types';

// ─── State Machine ────────────────────────────────────────────────────────────

export type SkillsStatus =
  | 'idle'
  | 'fetching'
  | 'registering'
  | 'removing'
  | 'error';

// ─────────────────────────────────────────────────────────────────────────────
// useSkills
// Manages skill registry state and all async skill CRUD operations.
// ─────────────────────────────────────────────────────────────────────────────
export function useSkills(nearAccountId: string) {
  const [skills, setSkills] = useState<SkillEntry[]>([]);
  const [status, setStatus] = useState<SkillsStatus>('idle');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // ── List skills ────────────────────────────────────────────────────────────

  const listSkills = useCallback(async () => {
    setStatus('fetching');
    setErrorMessage(null);
    try {
      const ids = await nearRpc.listSkillIds(nearAccountId);

      // Fetch all pointers in parallel
      const entries = await Promise.all(
        ids.map(async (id): Promise<SkillEntry> => {
          try {
            const pointer = await nearRpc.getSkillPointer(nearAccountId, id);
            let config: SkillConfig | undefined;

            // Best-effort: decrypt skill config to get name/description
            if (pointer) {
              try {
                const { plaintext } = await agent.vaultRead(
                  nearAccountId, pointer.blob_id, pointer.content_sha256,
                );
                config = JSON.parse(plaintext) as SkillConfig;
              } catch {
                // Decryption failed (agent offline) — show id only
              }
            }
            return { id, pointer, config };
          } catch {
            return { id, pointer: null };
          }
        }),
      );

      setSkills(entries);
      setStatus('idle');
    } catch (e) {
      setStatus('error');
      setErrorMessage((e as Error).message);
    }
  }, [nearAccountId]);

  useEffect(() => { listSkills(); }, [listSkills]);

  // ── Register ───────────────────────────────────────────────────────────────

  async function registerSkill(id: string, config: SkillConfig): Promise<void> {
    setStatus('registering');
    setErrorMessage(null);
    try {
      // Serialize config JSON as plaintext for TEE encryption
      const plaintext = JSON.stringify(config);

      // Upload encrypted blob to Walrus via agent
      const { blobId, contentSha256 } = await agent.vaultWrite(
        nearAccountId, 'skill', id, plaintext,
      );

      // Register pointer on NEAR contract via wallet transaction
      await wallet.updateSkillPointer(id, blobId, contentSha256);

      const pointer: VaultPointer = {
        blob_id: blobId,
        content_sha256: contentSha256,
        updated_at_ms: Date.now(),
      };

      setSkills((prev) => [
        ...prev.filter((s) => s.id !== id),
        { id, pointer, config },
      ]);
      setStatus('idle');
    } catch (e) {
      setStatus('error');
      setErrorMessage((e as Error).message);
    }
  }

  // ── Remove ─────────────────────────────────────────────────────────────────

  async function removeSkill(id: string): Promise<void> {
    setStatus('removing');
    setErrorMessage(null);
    try {
      await wallet.removeSkillPointer(id);
      setSkills((prev) => prev.filter((s) => s.id !== id));
      setStatus('idle');
    } catch (e) {
      setStatus('error');
      setErrorMessage((e as Error).message);
    }
  }

  return {
    skills,
    status,
    errorMessage,
    listSkills,
    registerSkill,
    removeSkill,
  };
}
