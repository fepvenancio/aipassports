import { useState, useRef, useEffect } from 'react';
import { useSkillExecutor } from '../../../hooks/useSkillExecutor';
import { useSkills } from '../../../hooks/useSkills';
import { ZdrAlertBanner } from '../../UI/ZdrAlertBanner';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Button from '../../UI/Button';
import Select from '../../UI/Select';
import Badge from '../../UI/Badge';

export default function SkillConsole({ nearAccountId }: { nearAccountId: string }) {
  const { skills } = useSkills(nearAccountId);
  const { prompt, state, handlePromptChange, execute, reset } = useSkillExecutor(nearAccountId);

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
    <div className="h-full flex flex-col gap-0 overflow-hidden animate-fade-in pr-1">

      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4 shrink-0 gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Execution Console</h2>
          <p className="text-xs text-slate-400 mt-0.5 font-sans">
            Run registered prompt environments inside the secure IronClaw TEE, protected by ZDR audits.
          </p>
        </div>
        {(state.status === 'completed' || state.status === 'error') && (
          <Button
            variant="outline"
            size="sm"
            onClick={reset}
            className="shrink-0"
          >
            Clear Output
          </Button>
        )}
      </div>

      {/* Workspace Split */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-4 min-h-0 pb-2">

        {/* ── LEFT COLUMN: Input Control Panel ───────────────────────────── */}
        <Card className="flex flex-col overflow-hidden">
          {/* Header */}
          <CardHeader className="py-2.5">
            <CardTitle>SKILL RUNNER</CardTitle>
          </CardHeader>

          <CardContent className="flex-grow overflow-y-auto p-4 flex flex-col gap-4">
            {/* Selector */}
            <div>
              <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">SELECT REGISTERED SKILL</label>
              {skills.length === 0 ? (
                <div className="text-xs text-slate-500 font-mono py-1">
                  No skills registered. Please register a skill first.
                </div>
              ) : (
                <Select
                  id="select-skill"
                  mono
                  value={skillId}
                  onChange={(e) => setSkillId(e.target.value)}
                >
                  {skills.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.config?.name ?? s.id} ({s.id})
                    </option>
                  ))}
                </Select>
              )}
            </div>

            {/* Prompt input */}
            <div className="flex-1 flex flex-col gap-1.5 min-h-[140px]">
              <label className="block text-[10px] font-semibold text-slate-400 flex items-center justify-between font-mono">
                <span>PROMPT INPUT</span>
                {isBlocked && (
                  <Badge variant="destructive" className="font-bold text-[9px] px-2 py-0.5">
                    ZDR BLOCKED
                  </Badge>
                )}
              </label>
              <textarea
                id="console-prompt-input"
                className={`flex-grow w-full bg-slate-950 border text-slate-100 rounded-lg px-3 py-2 text-xs font-mono outline-none transition-all resize-none leading-relaxed ${
                  isBlocked
                    ? 'border-rose-500 focus:border-rose-500'
                    : 'border-slate-800 focus:border-cyan-500/50'
                }`}
                value={prompt}
                onChange={(e) => handlePromptChange(e.target.value)}
                placeholder={`Enter prompt input...\n\nThe Zero Data Retention (ZDR) firewall scans prompts in real-time. Private key patterns or seed phrases are blocked instantly.`}
                disabled={isExecuting}
              />
            </div>

            {/* ZDR alert banner */}
            <ZdrAlertBanner
              marker={state.zdrMarker}
              serverSide={state.status === 'error' && Boolean(state.zdrMarker)}
              onDismiss={state.status === 'zdr-blocked' ? reset : undefined}
            />

            {/* Execute Button */}
            <Button
              id="btn-execute-skill"
              variant="default"
              onClick={handleExecute}
              disabled={!canExecute}
              className="w-full py-2.5 font-semibold shadow-inner"
            >
              {isExecuting ? (
                <>
                  <span className="w-3.5 h-3.5 rounded-full border border-slate-950/20 border-t-slate-950 animate-spin" />
                  Executing inside TEE Enclave...
                </>
              ) : isBlocked ? (
                '⛔ Firewall Block Active'
              ) : (
                '▶ Run Enclave Task'
              )}
            </Button>
          </CardContent>
        </Card>

        {/* ── RIGHT COLUMN: Classic Terminal Output ───────────────────────── */}
        <div className={`bg-slate-950 border rounded-xl flex flex-col overflow-hidden shadow-inner transition-all duration-300 relative ${
          isBlocked ? 'border-rose-900/60 shadow-rose-950/5' : 'border-slate-800/80 shadow-slate-950/10'
        }`}>
          {/* Header */}
          <div className={`px-4 py-2 border-b flex items-center justify-between shrink-0 select-none ${
            isBlocked ? 'bg-rose-950/10 border-rose-900/40' : 'bg-slate-900/30 border-slate-800/60'
          }`}>
            <Badge
              variant={isBlocked ? 'destructive' : 'default'}
              className="font-bold text-[9px] px-2.5 py-0.5"
            >
              {isBlocked ? 'ZDR INTERCEPT ACTIVE' : 'SECURE ENCLAVE OUTPUT'}
            </Badge>
            {/* macOS traffic lights styling */}
            <div className="flex gap-1.5">
              {['bg-rose-500', 'bg-amber-500', 'bg-emerald-500'].map((c) => (
                <div key={c} className={`w-2 h-2 rounded-full ${c} opacity-75`} />
              ))}
            </div>
          </div>

          {/* Terminal Logs Body */}
          <div
            ref={outputRef}
            className="flex-grow overflow-y-auto p-5 font-mono text-xs leading-relaxed text-slate-300"
          >
            {state.status === 'idle' && (
              <span className="text-slate-500">
                $ aegis-enclave init ok<br />
                $ awaiting pipeline invocation...<span className="terminal-cursor" />
              </span>
            )}

            {state.status === 'executing' && (
              <div className="text-cyan-400 flex flex-col gap-2">
                <div>$ aegis-enclave run --skill={skillId}</div>
                <div className="flex items-center gap-2 text-slate-400">
                  <span className="w-3.5 h-3.5 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
                  Decrypting payload & executing inference inside enclaved memory...
                </div>
              </div>
            )}

            {state.status === 'completed' && state.output && (
              <div className="animate-fade-in">
                <div className="text-slate-500 text-[10px] mb-2 font-semibold">
                  $ exit_code=0 status=completed
                </div>
                <div className="text-cyan-300 whitespace-pre-wrap break-all leading-relaxed bg-slate-900/40 border border-slate-800/40 rounded-lg p-3">
                  {state.output}
                </div>
                <div className="text-slate-500 mt-3">
                  $ ready<span className="terminal-cursor" />
                </div>
              </div>
            )}

            {isBlocked && (
              <div className="animate-fade-in text-rose-400 flex flex-col gap-2.5">
                <div className="font-bold">$ zdr-firewall: POLICY EXCLUSION DETECTED</div>
                {state.zdrMarker && <div>$ sensitive token key category: <strong>{state.zdrMarker}</strong></div>}
                <div>$ action: EGRESS DENIED & TRANSIENT MEMORY SHREDDED</div>
                <div className="mt-2 text-rose-400/60 leading-relaxed text-[11px]">
                  Outbound pipeline aborted. Prompts containing cryptographically sensitive credentials cannot be dispatched to public LLM services.
                </div>
              </div>
            )}

            {state.status === 'error' && (
              <div className="animate-fade-in text-rose-400 flex flex-col gap-1.5">
                <div>$ task failed: {state.errorMessage}</div>
                <div className="text-slate-500">$ exit_code=1</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
