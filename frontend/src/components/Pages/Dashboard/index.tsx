import { useState, useEffect } from 'react';
import DashboardSidebar, { type DashTab } from './DashboardSidebar';
import DashboardHeader from './DashboardHeader';
import WikiPanel from './WikiPanel';
import SkillsPanel from './SkillsPanel';
import SkillConsole from './SkillConsole';
import { pingAgent } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';

interface Props {
  session: AuthSession;
  onLock: () => void;
}

export default function Dashboard({ session, onLock }: Props) {
  const [tab, setTab] = useState<DashTab>('wiki');
  const [collapsed, setCollapsed] = useState(false);
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);

  useEffect(() => {
    pingAgent().then(setAgentOnline);
    const interval = setInterval(() => pingAgent().then(setAgentOnline), 30_000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ height: '100vh', display: 'flex', background: 'var(--color-bg)' }}>
      <DashboardSidebar
        session={session}
        activeTab={tab}
        collapsed={collapsed}
        onTabChange={setTab}
        onToggle={() => setCollapsed((v) => !v)}
        onLock={onLock}
      />

      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <DashboardHeader
          activeTab={tab}
          nearAccountId={session.nearAccountId}
          agentOnline={agentOnline}
        />

        <div
          className="grid-bg"
          style={{ flex: 1, padding: 20, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}
        >
          {tab === 'wiki'     && <WikiPanel     nearAccountId={session.nearAccountId} />}
          {tab === 'skills'   && <SkillsPanel   nearAccountId={session.nearAccountId} />}
          {tab === 'console'  && <SkillConsole  nearAccountId={session.nearAccountId} />}
          {tab === 'settings' && <SettingsPanel session={session} agentOnline={agentOnline} />}
        </div>
      </main>
    </div>
  );
}

// ─── Settings Panel ───────────────────────────────────────────────────────────
function SettingsPanel({ session, agentOnline }: { session: AuthSession; agentOnline: boolean | null }) {
  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: 18, maxWidth: 540, overflowY: 'auto' }}>
      <Section title="IDENTITY">
        <Row label="NEAR Account" value={session.nearAccountId} mono />
        <Row label="Auth Model"   value="Wallet-only · Dashboard mode (Phase 3)" />
        <Row label="Identity"     value="Ed25519 NEAR key · IDENTITY.md §6" />
      </Section>
      <Section title="ARCHITECTURE">
        <Row label="Reads"       value="Direct NEAR RPC (stateless, no auth)" />
        <Row label="Writes"      value="NEAR Wallet Selector signAndSendTransaction" />
        <Row label="Encryption"  value="AES-256-GCM · IronClaw TEE" />
        <Row label="Storage"     value="Walrus Protocol (per-entry blobs)" />
        <Row label="Index"       value="NEAR Smart Contract (shared, composite key)" />
      </Section>
      <Section title="AGENT">
        <Row
          label="Status"
          value={agentOnline === null ? 'Probing…' : agentOnline ? 'Online' : 'Offline'}
          accent={agentOnline === true}
          alert={agentOnline === false}
        />
        <Row label="Mode"      value={import.meta.env.VITE_AGENT_URL ? 'Production (IronClaw)' : 'Development (localhost:8080)'} />
        <Row label="ZDR"       value="zdr_firewall::is_compliant() · FIREWALL.md §2" />
      </Section>
      <Section title="DOCS">
        {['ARCH.md','IDENTITY.md','NEAR.md','WALRUS.md','SYNC.md','FIREWALL.md','DEPLOYMENT.md'].map((doc) => (
          <a key={doc} href={`https://github.com/fepvenancio/aipassports/blob/main/docs/${doc}`}
            target="_blank" rel="noopener noreferrer"
            style={{ display: 'block', fontSize: 12, color: 'var(--color-accent)', textDecoration: 'none', padding: '5px 16px', fontFamily: 'var(--font-mono)', borderBottom: '1px solid var(--color-border)' }}
          >
            ↗ {doc}
          </a>
        ))}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="glass" style={{ borderRadius: 12, overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--color-border)', fontSize: 10, fontWeight: 700, color: 'var(--color-text-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        {title}
      </div>
      <div>{children}</div>
    </div>
  );
}

function Row({ label, value, mono, accent, alert }: { label: string; value: string; mono?: boolean; accent?: boolean; alert?: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 16px', borderBottom: '1px solid var(--color-border)', gap: 16 }}>
      <span style={{ fontSize: 12, color: 'var(--color-text-2)', flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 12, fontFamily: mono ? 'var(--font-mono)' : 'var(--font-sans)', color: accent ? 'var(--color-accent)' : alert ? 'var(--color-alert)' : 'var(--color-text-1)', textAlign: 'right', wordBreak: 'break-all' }}>
        {value}
      </span>
    </div>
  );
}
