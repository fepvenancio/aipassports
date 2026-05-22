import { useState, useCallback, useRef, useEffect } from 'react';
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
// Security hardening applied (audit cycle 2026-05-22 round 2):
//   NEW-02 — Double-submission race fixed with useRef synchronous lock.
//             Previously: useCallback closed over stale `state.status`, allowing
//             two rapid clicks to both see 'idle' and both call skillsExecute().
//             Fix: inFlightRef.current is a synchronous guard checked before
//             any async work. It cannot be stale because refs are not closed over.
//   NEW-01 — AbortController cleanup: if the component unmounts while a skill
//             is executing, the in-flight fetch is cancelled. No more "setState
//             on unmounted component" and no zombie LLM requests.
//   CRITICAL-R6 — llmApiKey removed from hook (no longer sent in request body).
// ─────────────────────────────────────────────────────────────────────────────
export function useSkillExecutor(nearAccountId: string) {
  const [prompt, setPromptRaw] = useState('');
  const [state, setState] = useState<ExecutorState>({
    status: 'idle',
    zdrMarker: null,
    output: null,
    errorMessage: null,
  });

  // NEW-02: Synchronous in-flight lock — cannot be stale (ref vs closure)
  const inFlightRef = useRef(false);

  // NEW-01: AbortController for the active skill execution fetch
  const abortControllerRef = useRef<AbortController | null>(null);

  // NEW-01: Cancel any in-flight request on unmount
  useEffect(() => {
    return () => {
      abortControllerRef.current?.abort();
    };
  }, []);

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
    // NEW-02: Synchronous lock — prevents double-submission race.
    // Reading state.status from a useCallback closure is stale; inFlightRef is not.
    if (inFlightRef.current) return;
    if (!prompt.trim()) return;

    // Check ZDR state without relying on stale closure — read ref value instead
    // (ZDR marker is checked client-side as UX feedback; server enforces regardless)
    const marker = detectZdrViolation(prompt);
    if (marker) return;

    // Set synchronous lock before any await
    inFlightRef.current = true;

    // NEW-01: Create fresh AbortController for this execution
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setState({ status: 'executing', zdrMarker: null, output: null, errorMessage: null });

    try {
      const result = await agent.skillsExecute(
        nearAccountId,
        skillBlobId,
        skillContentSha256,
        prompt,
        controller.signal,
      );

      // Guard against state update after unmount (controller.signal.aborted)
      if (controller.signal.aborted) return;

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
      if (controller.signal.aborted) return; // Unmount cleanup — don't set state
      setState({
        status: 'error',
        zdrMarker: null,
        output: null,
        errorMessage: (e as Error).message,
      });
    } finally {
      inFlightRef.current = false;
    }
  // Only nearAccountId and prompt needed — inFlightRef is stable (ref), not a dep
  }, [nearAccountId, prompt]);

  // ── Reset ──────────────────────────────────────────────────────────────────

  const reset = useCallback(() => {
    abortControllerRef.current?.abort();
    inFlightRef.current = false;
    setPromptRaw('');
    setState({ status: 'idle', zdrMarker: null, output: null, errorMessage: null });
  }, []);

  return {
    prompt,
    state,
    handlePromptChange,
    execute,
    reset,
  };
}
