import { useState, useCallback } from 'react';
import * as agent from '../api/gateway';
import { detectZdrViolation, type ZdrMarker } from '../api/types';

// ─── State Machine ────────────────────────────────────────────────────────────

export type ExecutorStatus =
  | 'idle'
  | 'zdr-blocked'
  | 'executing'
  | 'completed'
  | 'error';

export interface ExecutorState {
  status: ExecutorStatus;
  zdrMarker: ZdrMarker | null;     // Which marker triggered the block
  output: string | null;           // Agent response
  errorMessage: string | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// useSkillExecutor
//
// State machine for the Skill Execution Console.
//
// ZDR scanning runs on every keystroke (client-side feedback only).
// Server-side enforcement is in the TEE agent's zdr_firewall::is_compliant().
// FIREWALL.md §2 — the agent will reject even if the client doesn't flag.
//
// llmApiKey:
//   Dev  (local agent):    Accepted — agent needs it to call LLM provider.
//   Prod (IronClaw):       Key lives in TEE secrets. This field is ignored.
// ─────────────────────────────────────────────────────────────────────────────
export function useSkillExecutor(nearAccountId: string) {
  const [prompt, setPromptRaw] = useState('');
  const [llmApiKey, setLlmApiKey] = useState('');
  const [state, setState] = useState<ExecutorState>({
    status: 'idle',
    zdrMarker: null,
    output: null,
    errorMessage: null,
  });

  // ── Real-time ZDR scanning ─────────────────────────────────────────────────

  const handlePromptChange = useCallback((value: string) => {
    setPromptRaw(value);
    const marker = detectZdrViolation(value);

    if (marker) {
      setState({
        status: 'zdr-blocked',
        zdrMarker: marker,
        output: null,
        errorMessage: null,
      });
    } else {
      setState((prev) =>
        prev.status === 'zdr-blocked'
          ? { status: 'idle', zdrMarker: null, output: null, errorMessage: null }
          : prev,
      );
    }
  }, []);

  // ── Execute ────────────────────────────────────────────────────────────────

  const execute = useCallback(async (
    skillBlobId: string,
    skillContentSha256: string,
  ) => {
    if (state.status === 'zdr-blocked') return;
    if (!prompt.trim()) return;

    setState({ status: 'executing', zdrMarker: null, output: null, errorMessage: null });

    try {
      const result = await agent.skillsExecute(
        nearAccountId,
        skillBlobId,
        skillContentSha256,
        prompt,
        llmApiKey || undefined,
      );

      // Agent may also enforce ZDR server-side
      if (result.zdrBlocked) {
        setState({
          status: 'zdr-blocked',
          zdrMarker: (result.zdrMarker as ZdrMarker) ?? null,
          output: null,
          errorMessage: null,
        });
      } else {
        setState({ status: 'completed', zdrMarker: null, output: result.output, errorMessage: null });
      }
    } catch (e) {
      setState({
        status: 'error',
        zdrMarker: null,
        output: null,
        errorMessage: (e as Error).message,
      });
    }
  }, [nearAccountId, prompt, llmApiKey, state.status]);

  // ── Reset ──────────────────────────────────────────────────────────────────

  const reset = useCallback(() => {
    setPromptRaw('');
    setState({ status: 'idle', zdrMarker: null, output: null, errorMessage: null });
  }, []);

  return {
    prompt,
    llmApiKey,
    state,
    handlePromptChange,
    setLlmApiKey,
    execute,
    reset,
  };
}
