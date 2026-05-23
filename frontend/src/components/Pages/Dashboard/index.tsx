import { useState, useEffect } from 'react';
import DashboardSidebar, { type DashTab } from './DashboardSidebar';
import DashboardHeader from './DashboardHeader';
import WikiPanel from './WikiPanel';
import SkillsPanel from './SkillsPanel';
import SkillConsole from './SkillConsole';
import { pingAgent, getAgentBase, setCustomAgentUrl } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Button from '../../UI/Button';
import Input from '../../UI/Input';
import Badge from '../../UI/Badge';

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
    <div className="h-screen w-full flex bg-slate-950 text-slate-100 overflow-hidden font-sans">
      <DashboardSidebar
        session={session}
        activeTab={tab}
        collapsed={collapsed}
        onTabChange={setTab}
        onToggle={() => setCollapsed((v) => !v)}
        onLock={onLock}
      />

      <main className="flex-1 flex flex-col overflow-hidden min-w-0">
        <DashboardHeader
          activeTab={tab}
          nearAccountId={session.nearAccountId}
          agentOnline={agentOnline}
        />

        <div className="flex-1 p-6 overflow-hidden flex flex-col bg-slate-950">
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
  const [customUrl, setCustomUrl] = useState(localStorage.getItem('AEGIS_CUSTOM_AGENT_URL') || '');
  const [error, setError] = useState<string | null>(null);

  const activeUrl = getAgentBase();

  function handleSaveUrl(val: string) {
    setError(null);
    try {
      if (val.trim() === '') {
        setCustomAgentUrl(null);
        window.location.reload();
      } else {
        setCustomAgentUrl(val.trim());
        window.location.reload();
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="animate-fade-in flex flex-col gap-6 max-w-xl overflow-y-auto flex-1 min-h-0 pr-1.5 pb-8">
      
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
      
      <Section title="TEE COMPUTE AGENT">
        <Row
          label="Attestation Status"
          value={agentOnline === null ? 'Probing...' : agentOnline ? 'Online' : 'Offline'}
          accent={agentOnline === true}
          alert={agentOnline === false}
        />
        <div className="flex flex-col px-4 py-3 border-b border-slate-800/60 last:border-0 gap-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1.5">
            <span className="text-xs text-slate-400 font-medium">Active Endpoint</span>
            <span className="text-xs font-mono text-cyan-400 break-all text-left sm:text-right">{activeUrl}</span>
          </div>
          <div className="flex gap-2 w-full">
            <div className="flex-1 min-w-0">
              <Input
                type="text"
                mono
                placeholder="https://custom-agent-url (empty to reset)"
                value={customUrl}
                onChange={(e) => setCustomUrl(e.target.value)}
              />
            </div>
            <Button
              variant="default"
              size="sm"
              onClick={() => handleSaveUrl(customUrl)}
              className="shrink-0"
            >
              Apply
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => handleSaveUrl('')}
              className="shrink-0"
            >
              Reset
            </Button>
          </div>
          {error && (
            <div className="text-[10px] text-rose-400 font-mono">
              &times; {error}
            </div>
          )}
        </div>
        <Row label="ZDR Firewall" value="zdr_firewall::is_compliant() · FIREWALL.md §2" />
      </Section>
      
      <Section title="DOCUMENTATION REFERENCES">
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2 p-4">
          {['ARCH.md','IDENTITY.md','NEAR.md','WALRUS.md','SYNC.md','FIREWALL.md','DEPLOYMENT.md'].map((doc) => (
            <a key={doc} href={`https://github.com/fepvenancio/aipassports/blob/main/docs/${doc}`}
              target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-mono px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg hover:border-slate-700 transition-all"
            >
              <span className="text-[10px]">↗</span> {doc}
            </a>
          ))}
        </div>
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader className="py-2.5">
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="p-0 gap-0">{children}</CardContent>
    </Card>
  );
}

function Row({ label, value, mono, accent, alert }: { label: string; value: string; mono?: boolean; accent?: boolean; alert?: boolean }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between px-4 py-3 border-b border-slate-800/60 last:border-0 gap-1.5 sm:gap-4">
      <span className="text-xs text-slate-400 font-medium shrink-0">{label}</span>
      {accent || alert ? (
        <Badge variant={accent ? 'success' : 'destructive'} className="font-semibold select-none shrink-0 text-[9px] px-2 py-0.5 self-start sm:self-auto">
          {value.toUpperCase()}
        </Badge>
      ) : (
        <span className={`text-xs ${mono ? 'font-mono' : 'font-sans'} text-slate-200 text-left sm:text-right break-all max-w-full sm:max-w-[70%]`}>
          {value}
        </span>
      )}
    </div>
  );
}
