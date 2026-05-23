import { useState } from 'react';
import { useSkills } from '../../../hooks/useSkills';
import { SkeletonCard } from '../../UI/CustomSkeleton';
import type { SkillConfig, SkillEntry } from '../../../api/types';
import { Card, CardHeader, CardTitle } from '../../UI/Card';
import Button from '../../UI/Button';
import Input from '../../UI/Input';
import Select from '../../UI/Select';
import Badge from '../../UI/Badge';

const EMPTY_FORM: SkillConfig = { name: '', description: '', provider: 'openai', model: 'gpt-4o' };

export default function SkillsPanel({ nearAccountId }: { nearAccountId: string }) {
  const { skills, status, errorMessage, registerSkill, removeSkill } = useSkills(nearAccountId);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<SkillConfig & { id: string }>({ id: '', ...EMPTY_FORM });

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault();
    await registerSkill(form.id, { name: form.name, description: form.description, provider: form.provider, model: form.model });
    setShowForm(false);
    setForm({ id: '', ...EMPTY_FORM });
  }

  return (
    <div className="h-full flex flex-col gap-5 overflow-hidden animate-fade-in pr-1.5 pb-2">
      
      {/* Panel Header */}
      <div className="flex items-start justify-between shrink-0">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">Skill Registry</h2>
          <p className="text-xs text-slate-400 mt-0.5 font-sans">
            Encrypted tools stored as Walrus blobs and registered in the NEAR contract index.
          </p>
        </div>
        <Button
          variant={showForm ? 'outline' : 'default'}
          size="sm"
          onClick={() => setShowForm((v) => !v)}
          disabled={status === 'registering'}
        >
          {showForm ? '✕ Cancel' : '+ Register Skill'}
        </Button>
      </div>

      {/* Error Panel */}
      {status === 'error' && errorMessage && (
        <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg px-4 py-2.5 text-xs text-rose-400 font-mono animate-fade-in shrink-0">
          ⚠ {errorMessage}
        </div>
      )}

      {/* Registration Form */}
      {showForm && (
        <Card className="p-5 md:p-6 flex flex-col gap-4 animate-fade-in shrink-0 shadow-md">
          <CardHeader className="p-0 border-b-0 bg-transparent flex items-start shrink-0">
            <CardTitle>REGISTER NEW SKILL</CardTitle>
          </CardHeader>

          <form onSubmit={handleRegister} className="flex flex-col gap-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">SKILL ID *</label>
                <Input
                  id="input-skill-id"
                  type="text"
                  mono
                  placeholder="security-scanner"
                  value={form.id}
                  onChange={(e) => setForm({ ...form, id: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '') })}
                  required
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">DISPLAY NAME *</label>
                <Input
                  id="input-skill-name"
                  type="text"
                  placeholder="Security Scanner"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  required
                />
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">LLM PROVIDER</label>
                <Select
                  value={form.provider}
                  onChange={(e) => setForm({ ...form, provider: e.target.value })}
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="gemini">Google Gemini</option>
                </Select>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">MODEL</label>
                <Input
                  type="text"
                  mono
                  placeholder="gpt-4o"
                  value={form.model}
                  onChange={(e) => setForm({ ...form, model: e.target.value })}
                />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-semibold text-slate-400 mb-1.5 font-mono">SYSTEM PROMPT / DESCRIPTION *</label>
              <textarea
                id="input-skill-description"
                className="w-full bg-slate-950 border border-slate-800 focus:border-cyan-500/50 text-slate-100 rounded-lg px-3 py-2 text-xs font-mono outline-none transition-all resize-none min-h-[80px]"
                placeholder="Audit Solidity contracts for reentrancy, access control, and integer overflow vulnerabilities..."
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                required
              />
            </div>

            <div className="flex justify-end gap-2 shrink-0">
              <Button type="button" variant="outline" size="sm" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button
                id="btn-submit-skill"
                type="submit"
                variant="default"
                size="sm"
                disabled={status === 'registering'}
              >
                {status === 'registering' ? (
                  <span className="flex items-center gap-1.5">
                    <span className="w-3.5 h-3.5 rounded-full border border-slate-950/20 border-t-slate-950 animate-spin" />
                    Registering...
                  </span>
                ) : (
                  'Register Skill'
                )}
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Grid Container */}
      <div className="flex-1 overflow-y-auto pr-1">
        {status === 'fetching' ? (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 animate-fade-in">
            {Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}
          </div>
        ) : skills.length === 0 ? (
          <EmptySkills onAdd={() => setShowForm(true)} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {skills.map((skill) => (
              <SkillCard
                key={skill.id}
                skill={skill}
                onRemove={() => { if (confirm(`Remove skill "${skill.id}"?`)) removeSkill(skill.id); }}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SkillCard({ skill, onRemove }: { skill: SkillEntry; onRemove: () => void }) {
  return (
    <Card className="flex flex-col gap-3.5 p-5 animate-fade-in hover:border-slate-700/80 transition-all duration-150 group">
      {/* Card Header */}
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-sm shrink-0 shadow-inner">
          ⚡
        </div>
        <div className="flex-grow overflow-hidden">
          <div className="text-xs font-semibold text-slate-200 truncate group-hover:text-slate-100 transition-colors">
            {skill.config?.name ?? skill.id}
          </div>
          <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">
            {skill.id}
          </div>
        </div>
        <Badge variant="default" className="shrink-0 font-bold text-[9px] px-2 py-0.5">
          ACTIVE
        </Badge>
      </div>

      {/* Description */}
      {skill.config?.description && (
        <p className="text-xs text-slate-400 leading-relaxed break-words line-clamp-3">
          {skill.config.description}
        </p>
      )}

      {/* Meta tags */}
      {skill.config && (
        <div className="flex gap-1.5 flex-wrap">
          {skill.config.provider && (
            <Badge variant="secondary" className="px-2 py-0.5 text-[9px]">
              {skill.config.provider}
            </Badge>
          )}
          {skill.config.model && (
            <Badge variant="secondary" className="px-2 py-0.5 text-[9px]">
              {skill.config.model}
            </Badge>
          )}
        </div>
      )}

      {/* Pointer locator */}
      {skill.pointer && (
        <div className="px-3 py-1.5 bg-slate-950 border border-slate-800/40 rounded-lg font-mono text-[9px] text-slate-500 break-all select-none leading-normal">
          blob: {skill.pointer.blob_id.slice(0, 24)}...
        </div>
      )}

      {/* Actions */}
      <div className="flex justify-end shrink-0 pt-1">
        <Button
          variant="destructive"
          size="xs"
          onClick={onRemove}
        >
          Remove
        </Button>
      </div>
    </Card>
  );
}

function EmptySkills({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 text-slate-500 select-none py-20">
      <span className="text-5xl">⚡</span>
      <div className="text-center flex flex-col gap-1">
        <p className="text-xs font-semibold text-slate-400">No skills registered</p>
        <p className="text-[11px] text-slate-500">Register custom LLM prompt environments to expand your memory skills</p>
      </div>
      <Button variant="outline" size="sm" onClick={onAdd}>
        + Register First Skill
      </Button>
    </div>
  );
}
