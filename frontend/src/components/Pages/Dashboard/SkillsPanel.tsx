import { useState } from 'react';
import { useSkills } from '../../../hooks/useSkills';
import { SkeletonCard } from '../../UI/CustomSkeleton';
import type { SkillConfig, SkillEntry } from '../../../api/types';

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
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 18 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2 style={{ margin: '0 0 4px', fontSize: 15, fontWeight: 600 }}>Skill Registry</h2>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--color-text-3)' }}>
            LLM tools encrypted as Walrus blobs, indexed on NEAR
          </p>
        </div>
        <button className="btn btn-accent btn-sm" onClick={() => setShowForm((v) => !v)} disabled={status === 'registering'}>
          {showForm ? '✕ Cancel' : '+ Register Skill'}
        </button>
      </div>

      {/* Error */}
      {status === 'error' && errorMessage && (
        <div className="animate-fade-in" style={{ background: 'var(--color-alert-dim)', border: '1px solid rgba(255,59,92,0.2)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--color-alert)', fontFamily: 'var(--font-mono)' }}>
          {errorMessage}
        </div>
      )}

      {/* Registration form */}
      {showForm && (
        <form onSubmit={handleRegister} className="glass animate-fade-in" style={{ borderRadius: 12, padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--color-accent)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Register New Skill
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 5 }}>Skill ID *</label>
              <input
                id="input-skill-id"
                className="input input-mono"
                placeholder="security-scanner"
                value={form.id}
                onChange={(e) => setForm({ ...form, id: e.target.value.toLowerCase().replace(/[^a-z0-9_-]/g, '') })}
                required
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 5 }}>Display Name *</label>
              <input
                id="input-skill-name"
                className="input"
                placeholder="Security Scanner"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                required
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 5 }}>Provider</label>
              <select
                className="input"
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value })}
                style={{ cursor: 'pointer' }}
              >
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="gemini">Google Gemini</option>
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 5 }}>Model</label>
              <input
                className="input input-mono"
                placeholder="gpt-4o"
                value={form.model}
                onChange={(e) => setForm({ ...form, model: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 11, color: 'var(--color-text-3)', marginBottom: 5 }}>Description / System Prompt *</label>
            <textarea
              id="input-skill-description"
              className="input textarea input-mono"
              placeholder="Audit Solidity contracts for reentrancy, access control, and integer overflow vulnerabilities…"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              required
              style={{ minHeight: 90 }}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowForm(false)}>Cancel</button>
            <button id="btn-submit-skill" type="submit" className="btn btn-accent btn-sm" disabled={status === 'registering'}>
              {status === 'registering' ? <><span className="spinner" style={{ width: 12, height: 12, borderWidth: 1.5, borderTopColor: '#03040a', borderColor: 'rgba(0,0,0,0.2)' }} /> Registering…</> : 'Register'}
            </button>
          </div>
        </form>
      )}

      {/* Grid */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {status === 'fetching' ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px,1fr))', gap: 16 }}>
            {Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}
          </div>
        ) : skills.length === 0 ? (
          <EmptySkills onAdd={() => setShowForm(true)} />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(270px,1fr))', gap: 16 }}>
            {skills.map((skill) => (
              <SkillCard key={skill.id} skill={skill} onRemove={() => { if (confirm(`Remove skill "${skill.id}"?`)) removeSkill(skill.id); }} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SkillCard({ skill, onRemove }: { skill: SkillEntry; onRemove: () => void }) {
  return (
    <div
      className="glass animate-fade-in"
      style={{ borderRadius: 12, padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 12, transition: 'border-color 0.15s' }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = 'rgba(0,240,255,0.2)'; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--color-border)'; }}
    >
      {/* Card header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ width: 34, height: 34, borderRadius: 9, flexShrink: 0, background: 'var(--color-primary)', border: '1px solid rgba(0,240,255,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>
          ⚡
        </div>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {skill.config?.name ?? skill.id}
          </div>
          <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-3)', marginTop: 1 }}>
            {skill.id}
          </div>
        </div>
        <span className="badge badge-accent" style={{ flexShrink: 0 }}>Active</span>
      </div>

      {/* Description */}
      {skill.config?.description && (
        <p style={{ margin: 0, fontSize: 12, color: 'var(--color-text-2)', lineHeight: 1.55 }}>
          {skill.config.description.length > 120 ? skill.config.description.slice(0, 120) + '…' : skill.config.description}
        </p>
      )}

      {/* TEE schema */}
      {skill.config && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {skill.config.provider && <span className="badge badge-navy" style={{ fontFamily: 'var(--font-mono)' }}>{skill.config.provider}</span>}
          {skill.config.model && <span className="badge badge-navy" style={{ fontFamily: 'var(--font-mono)' }}>{skill.config.model}</span>}
        </div>
      )}

      {/* Pointer */}
      {skill.pointer && (
        <div style={{ padding: '7px 10px', background: 'rgba(0,0,0,0.2)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--color-text-3)' }}>
          blob: {skill.pointer.blob_id.slice(0, 22)}…
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn btn-alert btn-xs" onClick={onRemove}>Remove</button>
      </div>
    </div>
  );
}

function EmptySkills({ onAdd }: { onAdd: () => void }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: 280, gap: 14, color: 'var(--color-text-3)' }}>
      <div style={{ fontSize: 46 }}>⚡</div>
      <div style={{ textAlign: 'center' }}>
        <p style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 500 }}>No skills registered</p>
        <p style={{ margin: 0, fontSize: 12 }}>Register custom LLM tools to extend your AI context</p>
      </div>
      <button className="btn btn-ghost btn-sm" onClick={onAdd}>+ Register First Skill</button>
    </div>
  );
}
