import { useState, useRef, useEffect } from 'react';
import { useSkillExecutor } from '../../../hooks/useSkillExecutor';
import { useSkills } from '../../../hooks/useSkills';
import { ZdrAlertBanner } from '../../UI/ZdrAlertBanner';
import { IS_PROD_AGENT } from '../../../api/gateway';

export default function SkillConsole({ nearAccountId }: { nearAccountId: string }) {
  const { skills } = useSkills(nearAccountId);
  const { prompt, llmApiKey, state, handlePromptChange, setLlmApiKey, execute, reset } = useSkillExecutor(nearAccountId);
  const [skillId, setSkillId] = useState<string>('');
  const outputRef = useRef<HTMLDivElement>(null);

  // Pre-select first skill when skills load
  useEffect(() => {
    if (skills.length > 0 && !skillId) setSkillId(skills[0].id);
  }, [skills, skillId]);

  // Auto-scroll terminal output
  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [state]);

  const selectedSkill = skills.find((s) => s.id === skillId);
  const isBlocked  = state.status === 'zdr-blocked';
  const isExecuting = state.status === 'executing';
  const canExecute = Boolean(selectedSkill?.pointer) && prompt.trim().length > 0 && !isBlocked && !isExecuting;

  async function handleExecute() {
    if (!selectedSkill?.pointer) return;
    await execute(selectedSkill.pointer.blob_id, selectedSkill.pointer.content_sha256);
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 0 }}>

      {/* Console title bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '0 0 16px',
        borderBottom: '1px solid var(--color-border)', marginBottom: 16, flexShrink: 0,
      }}>
        <div>
          <h2 style={{ margin: '0 0 3px', fontSize: 15, fontWeight: 600 }}>Execution Console</h2>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--color-text-3)' }}>
            Run registered skills through the IronClaw TEE · ZDR enforced at agent boundary
          </p>
        </div>
        <div style={{ flex: 1 }} />
        {(state.status === 'completed' || state.status === 'error') && (
          <button className="btn btn-ghost btn-sm" onClick={reset}>Clear</button>
        )}
      </div>

      {/* Dual-column workspace */}
      <div style={{ flex: 1, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, minHeight: 0 }}>

        {/* ── LEFT: Input ────────────────────────────────────────────────── */}
        <div className="glass" style={{ borderRadius: 12, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

          {/* Panel header */}
          <div style={{ padding: '11px 16px', borderBottom: '1px solid var(--color-border)', flexShrink: 0 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--color-text-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              SKILL INPUT
            </span>
          </div>

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 14, padding: 16, overflowY: 'auto' }}>

            {/* Skill selector */}
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 6 }}>Select Skill</label>
              {skills.length === 0 ? (
                <div style={{ fontSize: 12, color: 'var(--color-text-3)', padding: '8px 0' }}>
                  No skills registered. Go to the Skills tab first.
                </div>
              ) : (
                <select
                  id="select-skill"
                  className="input input-mono"
                  value={skillId}
                  onChange={(e) => setSkillId(e.target.value)}
                  style={{ cursor: 'pointer' }}
                >
                  {skills.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.config?.name ?? s.id}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Prompt input with real-time ZDR scanning */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)' }}>
                Prompt
                {isBlocked && (
                  <span className="badge badge-alert" style={{ marginLeft: 8 }}>ZDR BLOCKED</span>
                )}
              </label>
              <textarea
                id="console-prompt-input"
                className={`input textarea input-mono ${isBlocked ? 'zdr-active' : ''}`}
                value={prompt}
                onChange={(e) => handlePromptChange(e.target.value)}
                placeholder={`Enter your prompt here…\n\nThe ZDR Firewall scans every keystroke.\nSensitive markers (PRIVATE_KEY, MNEMONIC, etc.) are blocked immediately.`}
                style={{ flex: 1, resize: 'none', minHeight: 160, fontSize: 12, lineHeight: 1.7 }}
                disabled={isExecuting}
              />
            </div>

            {/* ZDR Alert Banner — shows when marker detected */}
            <ZdrAlertBanner
              marker={state.zdrMarker}
              serverSide={state.status === 'error' && Boolean(state.zdrMarker)}
              onDismiss={state.status === 'zdr-blocked' ? reset : undefined}
            />

            {/* LLM API key — dev mode only, never shown in production */}
            {!IS_PROD_AGENT && (
              <div>
                <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 6 }}>
                  LLM API Key
                  <span className="badge badge-amber" style={{ marginLeft: 8, fontSize: 9 }}>DEV ONLY · IN-MEMORY</span>
                </label>
                <input
                  id="console-llm-key"
                  type="password"
                  className="input input-mono"
                  placeholder="sk-… (transient, never persisted or logged)"
                  value={llmApiKey}
                  onChange={(e) => setLlmApiKey(e.target.value)}
                  style={{ fontSize: 12 }}
                  autoComplete="off"
                  spellCheck={false}
                />
                <p style={{ margin: '5px 0 0', fontSize: 10, color: 'var(--color-text-3)', lineHeight: 1.5 }}>
                  Production (IronClaw): key lives in TEE secrets. This field is hidden.
                </p>
              </div>
            )}

            {/* Execute button */}
            <button
              id="btn-execute-skill"
              className="btn btn-accent"
              style={{ width: '100%', padding: 12, fontSize: 13, fontWeight: 600, justifyContent: 'center' }}
              onClick={handleExecute}
              disabled={!canExecute}
            >
              {isExecuting
                ? <><span className="spinner" style={{ borderTopColor: '#03040a', borderColor: 'rgba(0,0,0,0.2)' }} /> Executing in TEE…</>
                : isBlocked
                  ? '⛔ Blocked by ZDR Firewall'
                  : '▶ Execute Skill'}
            </button>
          </div>
        </div>

        {/* ── RIGHT: Terminal output ─────────────────────────────────────── */}
        <div
          className="terminal-scanline"
          style={{
            borderRadius: 12,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            background: '#02030a',
            border: `1px solid ${isBlocked ? 'rgba(255,59,92,0.35)' : 'rgba(0,240,255,0.12)'}`,
            boxShadow: isBlocked ? '0 0 24px rgba(255,59,92,0.08)' : '0 0 20px rgba(0,240,255,0.05)',
            transition: 'border-color 0.3s, box-shadow 0.3s',
            position: 'relative',
          }}
        >
          {/* Terminal title bar */}
          <div style={{
            padding: '9px 14px',
            borderBottom: `1px solid ${isBlocked ? 'rgba(255,59,92,0.2)' : 'rgba(0,240,255,0.1)'}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            flexShrink: 0, background: 'rgba(0,240,255,0.02)',
          }}>
            <span style={{
              fontSize: 10, fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.12em',
              color: isBlocked ? 'var(--color-alert)' : 'var(--color-accent)',
            }}>
              {isBlocked ? '⛔ ZDR FIREWALL — BLOCKED' : '⌨ ENCLAVE OUTPUT'}
            </span>
            {/* macOS traffic lights */}
            <div style={{ display: 'flex', gap: 5 }}>
              {['#ff5f56', '#ffbd2e', '#27c93f'].map((c) => (
                <div key={c} style={{ width: 8, height: 8, borderRadius: 99, background: c }} />
              ))}
            </div>
          </div>

          {/* Output body */}
          <div
            ref={outputRef}
            style={{ flex: 1, overflowY: 'auto', padding: '18px 20px', fontFamily: 'var(--font-mono)', fontSize: 12, lineHeight: 1.85 }}
          >
            {state.status === 'idle' && (
              <span style={{ color: 'var(--color-text-3)' }}>
                $ aegis-tee ready<br />
                $ awaiting skill execution<span className="terminal-cursor" />
              </span>
            )}

            {state.status === 'executing' && (
              <div style={{ color: 'var(--color-accent)', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div>$ executing skill: <strong>{skillId}</strong></div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5 }} />
                  Processing inside TEE enclave…
                </div>
              </div>
            )}

            {state.status === 'completed' && state.output && (
              <div className="animate-fade-in">
                <div style={{ color: 'var(--color-text-3)', fontSize: 11, marginBottom: 10 }}>
                  $ skill={skillId} status=completed
                </div>
                <div style={{ color: 'var(--color-accent)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {state.output}
                </div>
                <div style={{ color: 'var(--color-text-3)', marginTop: 10, fontSize: 11 }}>
                  $ exit 0<span className="terminal-cursor" />
                </div>
              </div>
            )}

            {isBlocked && (
              <div className="animate-fade-in" style={{ color: 'var(--color-alert)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div>$ zdr-firewall: PAYLOAD INTERCEPTED</div>
                {state.zdrMarker && <div>$ marker detected: <strong>{state.zdrMarker}</strong></div>}
                <div>$ action: TRANSMISSION BLOCKED</div>
                <div style={{ marginTop: 8, color: 'rgba(255,59,92,0.6)', fontSize: 11, lineHeight: 1.6 }}>
                  Remove the sensitive content from your prompt.<br />
                  Zero Data Retention enforced. FIREWALL.md §2
                </div>
              </div>
            )}

            {state.status === 'error' && (
              <div className="animate-fade-in" style={{ color: 'var(--color-alert)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div>$ error: {state.errorMessage}</div>
                <div style={{ color: 'var(--color-text-3)', fontSize: 11 }}>$ exit 1</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
