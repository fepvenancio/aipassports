import { useState, useEffect } from 'react';
import DashboardSidebar, { type DashTab } from './DashboardSidebar';
import DashboardHeader from './DashboardHeader';
import WikiPanel from './WikiPanel';
import SkillsPanel from './SkillsPanel';
import SkillConsole from './SkillConsole';
import LogsPanel from './LogsPanel';
import BillingPanel from './BillingPanel';
import TeamsPanel from './TeamsPanel';
import McpSetupPanel from './McpSetupPanel';
import { pingAgent, getAgentBase, setCustomAgentUrl, getUserProfile, registerUser } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '../../UI/Card';
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

  // SaaS state
  const [notRegistered, setNotRegistered] = useState(false);
  const [checkingRegistration, setCheckingRegistration] = useState(true);
  const [provisioning, setProvisioning] = useState(false);
  const [provisionStep, setProvisionStep] = useState<number>(0);
  const [provisionedApiKey, setProvisionedApiKey] = useState<string | null>(null);
  const [apiKeyCopied, setApiKeyCopied] = useState(false);
  const [mcpCopied, setMcpCopied] = useState(false);

  useEffect(() => {
    async function checkProfile() {
      try {
        setCheckingRegistration(true);
        const data = await getUserProfile();
        if (data && data.apiKey) {
          setProvisionedApiKey(data.apiKey);
        }
        setNotRegistered(false);
      } catch (err: any) {
        if (err.message && err.message.includes('USER_NOT_REGISTERED')) {
          setNotRegistered(true);
        } else {
          console.error('Failed to load user profile:', err);
        }
      } finally {
        setCheckingRegistration(false);
      }
    }
    checkProfile();
  }, []);

  useEffect(() => {
    pingAgent().then(setAgentOnline);
    const interval = setInterval(() => pingAgent().then(setAgentOnline), 30_000);
    return () => clearInterval(interval);
  }, []);

  async function handleProvision() {
    setProvisioning(true);
    setProvisionStep(1); // Allocation
    await new Promise((r) => setTimeout(r, 1000));
    setProvisionStep(2); // Attestation
    await new Promise((r) => setTimeout(r, 1200));
    setProvisionStep(3); // Sealing
    try {
      const result = await registerUser();
      await new Promise((r) => setTimeout(r, 800));
      setProvisionedApiKey(result.apiKey);
      setProvisionStep(4); // Complete
    } catch (e) {
      console.error(e);
      setProvisionStep(-1); // Error
      setProvisioning(false);
    }
  }

  if (checkingRegistration) {
    return (
      <div className="h-screen w-full flex flex-col items-center justify-center bg-slate-950 text-slate-100 font-mono text-xs gap-3">
        <div className="w-6 h-6 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
        <span>&rsaquo; Restoring secure TEE session...</span>
      </div>
    );
  }

  if (notRegistered) {
    const gatewayUrl = import.meta.env.DEV
      ? 'http://localhost:8787/mcp'
      : `${window.location.origin}/mcp`;

    const mcpConfig = JSON.stringify({
      mcpServers: {
        "aegis-memory": {
          command: "npx",
          args: [
            "-y",
            "@modelcontextprotocol/server-http",
            "--url",
            gatewayUrl,
            "--header",
            `Authorization: Bearer ${provisionedApiKey || 'ak_aegis_YOUR_API_KEY'}`
          ]
        }
      }
    }, null, 2);

    return (
      <OnboardingWizard
        provisioning={provisioning}
        provisionStep={provisionStep}
        provisionedApiKey={provisionedApiKey}
        apiKeyCopied={apiKeyCopied}
        mcpCopied={mcpCopied}
        mcpConfigStr={mcpConfig}
        onProvision={handleProvision}
        onCopyApiKey={() => {
          if (provisionedApiKey) {
            navigator.clipboard.writeText(provisionedApiKey);
            setApiKeyCopied(true);
            setTimeout(() => setApiKeyCopied(false), 2000);
          }
        }}
        onCopyMcp={() => {
          navigator.clipboard.writeText(mcpConfig);
          setMcpCopied(true);
          setTimeout(() => setMcpCopied(false), 2000);
        }}
        onEnterWorkspace={() => setNotRegistered(false)}
      />
    );
  }

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
          {tab === 'teams'    && <TeamsPanel    session={session} />}
          {tab === 'console'  && <SkillConsole  nearAccountId={session.nearAccountId} />}
          {tab === 'logs'     && <LogsPanel />}
          {tab === 'mcp'      && <McpSetupPanel session={session} />}
          {tab === 'billing'  && <BillingPanel />}
          {tab === 'settings' && (
            <SettingsPanel
              session={session}
              agentOnline={agentOnline}
              apiKey={provisionedApiKey}
            />
          )}
        </div>
      </main>
    </div>
  );
}

// ─── Settings Panel ───────────────────────────────────────────────────────────
function SettingsPanel({
  session,
  agentOnline,
  apiKey,
}: {
  session: AuthSession;
  agentOnline: boolean | null;
  apiKey: string | null;
}) {
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
        {apiKey && (
          <div className="flex flex-col px-4 py-3 border-b border-slate-800/60 last:border-0 gap-1.5">
            <span className="text-xs text-slate-400 font-medium">Vault API Key</span>
            <div className="flex gap-2">
              <span className="text-xs font-mono text-cyan-400 truncate flex-1 select-all">{apiKey}</span>
              <button 
                onClick={() => {
                  navigator.clipboard.writeText(apiKey);
                  alert("API key copied!");
                }}
                className="text-[10px] text-slate-400 hover:text-cyan-400 font-mono px-1.5 py-0.5 border border-slate-800 bg-slate-950 rounded transition-all"
              >
                Copy
              </button>
            </div>
          </div>
        )}
        <Row label="Auth Model"   value="Managed SaaS · Zero-Knowledge TEE Gateway" />
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
          {['simplified_arch.md','IDENTITY.md','NEAR.md','WALRUS.md','SYNC.md','FIREWALL.md'].map((doc) => (
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

// ─── Onboarding Wizard Component ─────────────────────────────────────────────
interface OnboardingProps {
  provisioning: boolean;
  provisionStep: number;
  provisionedApiKey: string | null;
  apiKeyCopied: boolean;
  mcpCopied: boolean;
  mcpConfigStr: string;
  onProvision: () => void;
  onCopyApiKey: () => void;
  onCopyMcp: () => void;
  onEnterWorkspace: () => void;
}

function OnboardingWizard({
  provisioning,
  provisionStep,
  provisionedApiKey,
  apiKeyCopied,
  mcpCopied,
  mcpConfigStr,
  onProvision,
  onCopyApiKey,
  onCopyMcp,
  onEnterWorkspace,
}: OnboardingProps) {
  return (
    <div className="h-screen w-full flex items-center justify-center p-6 bg-slate-950 relative overflow-hidden select-none">
      {/* Decorative top grid lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35" />

      <Card className="w-full max-w-xl relative animate-fade-in shadow-2xl z-10 border border-slate-800 bg-slate-900/80 backdrop-blur-md">
        {/* Subtle accent border top */}
        <div className="absolute top-0 left-8 right-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />

        <CardHeader className="flex flex-col items-center text-center pt-8 pb-4">
          <div className="w-12 h-12 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-center text-xl mb-4 shadow-inner select-none">
            🛡️
          </div>
          <CardTitle className="text-2xl font-bold tracking-tight text-slate-50">
            Provision Sovereign Vault
          </CardTitle>
          <CardDescription className="text-xs text-slate-400 mt-1 font-medium max-w-sm">
            Let's spin up your personal, hardware-isolated AI Memory vault on NEAR AI Cloud enclaves.
          </CardDescription>
        </CardHeader>

        <CardContent className="px-8 pb-8 md:px-10 flex flex-col gap-5 select-text">
          {/* STEP 1: INITIAL STATE */}
          {provisionStep === 0 && (
            <div className="flex flex-col gap-4 text-slate-300 text-xs leading-relaxed font-sans">
              <p>
                Aegis leverages Intel TDX secure enclaves to keep your memory files fully encrypted. 
                Even the hosting cloud provider cannot inspect your wiki entries, custom skills, or API keys.
              </p>
              <div className="border border-slate-800 bg-slate-950/50 p-4 rounded-lg flex flex-col gap-2 font-mono text-[10px]">
                <div className="text-cyan-400 font-semibold uppercase tracking-wider mb-1">Vault Node Spec</div>
                <div>&rsaquo; CPU Architecture: Intel TDX (Trust Domain Extensions)</div>
                <div>&rsaquo; Storage Engine: Walrus Protocol (Distributed Blobs)</div>
                <div>&rsaquo; Egress Protection: Zero Data Runaway (ZDR) Firewall</div>
                <div>&rsaquo; Registry Index: NEAR Shared Smart Contract</div>
              </div>
              <Button
                variant="default"
                onClick={onProvision}
                className="w-full py-3 mt-2 font-semibold justify-center text-sm"
              >
                Provision Secure Enclave
              </Button>
            </div>
          )}

          {/* STEP 2: PROVISIONING PROCESS */}
          {provisioning && provisionStep > 0 && provisionStep < 4 && (
            <div className="flex flex-col gap-4 py-4">
              <div className="flex items-center justify-center gap-3">
                <div className="w-5 h-5 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
                <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-bold">
                  ENCLAVE ALLOCATION IN PROGRESS...
                </span>
              </div>
              
              <div className="border border-slate-800 bg-slate-950 p-4 rounded-lg font-mono text-[10px] text-slate-400 leading-normal h-32 flex flex-col gap-1 justify-start">
                <div className={provisionStep >= 1 ? "text-slate-200" : "opacity-45"}>
                  {provisionStep >= 1 ? "✔" : "›"} [1/3] Requesting secure node on NEAR AI Cloud...
                </div>
                <div className={provisionStep >= 2 ? "text-slate-200" : "opacity-45"}>
                  {provisionStep >= 2 ? "✔ [ATTESTED]" : "›"} [2/3] Allocating Intel TDX hardware-isolated enclave...
                </div>
                <div className={provisionStep >= 3 ? "text-slate-200" : "opacity-45"}>
                  {provisionStep >= 3 ? "✔ [SEALED]" : "›"} [3/3] Generating zero-knowledge encryption Master Keys...
                </div>
                {provisionStep === 3 && (
                  <div className="text-cyan-400 animate-pulse mt-1 select-none">
                    &rsaquo; Finalizing secure credentials...
                  </div>
                )}
              </div>
            </div>
          )}

          {/* STEP 3: SUCCESS & CONFIG REVEAL */}
          {provisionStep === 4 && (
            <div className="flex flex-col gap-4 py-2 animate-fade-in">
              <div className="bg-emerald-950/20 border border-emerald-900/30 text-emerald-400 rounded-lg p-3 text-xs flex items-center gap-2.5 font-medium select-none">
                <span>✔</span>
                <span>Confidential Enclave provisioned successfully!</span>
              </div>

              {/* API Key Reveal */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                  Personal Vault API Key (Do not share)
                </span>
                <div className="flex gap-2">
                  <div className="flex-1 bg-slate-950 border border-slate-800 px-3 py-2 rounded-lg font-mono text-xs text-cyan-400 select-all truncate">
                    {provisionedApiKey}
                  </div>
                  <Button variant="outline" size="sm" onClick={onCopyApiKey} className="shrink-0 text-xs">
                    {apiKeyCopied ? 'Copied' : 'Copy'}
                  </Button>
                </div>
              </div>

              {/* MCP Copy Card */}
              <div className="flex flex-col gap-1.5 mt-2">
                <div className="flex justify-between items-center select-none">
                  <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                    Cursor / Claude Desktop Config
                  </span>
                  <Button variant="ghost" size="xs" onClick={onCopyMcp} className="text-[10px] hover:text-cyan-400">
                    {mcpCopied ? 'Copied Configuration!' : 'Copy Config'}
                  </Button>
                </div>
                <pre className="bg-slate-950 border border-slate-800 p-3 rounded-lg font-mono text-[10px] text-cyan-400/90 overflow-x-auto select-all max-h-40 leading-relaxed shadow-inner">
                  {mcpConfigStr}
                </pre>
              </div>

              <Button
                variant="default"
                onClick={onEnterWorkspace}
                className="w-full py-3 mt-4 font-bold justify-center text-sm select-none"
              >
                Enter Memory Workspace
              </Button>
            </div>
          )}

          {/* ERROR STATE */}
          {provisionStep === -1 && (
            <div className="flex flex-col gap-4 py-2 animate-fade-in select-none">
              <div className="bg-rose-950/20 border border-rose-900/30 text-rose-400 rounded-lg p-4 text-xs flex flex-col gap-2 font-medium">
                <span className="font-semibold text-sm">Provisioning Error</span>
                <span>Secure enclave registration failed. Please ensure the network connection is active.</span>
              </div>
              <Button
                variant="outline"
                onClick={onProvision}
                className="w-full py-2.5 mt-2 text-xs"
              >
                &larr; Try Again
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
