// ─────────────────────────────────────────────────────────────────────────────
// McpSetupPanel — MCP Client Configuration & Connection Status
//
// Guides the user through connecting external MCP clients (Cursor, Claude
// Desktop, VS Code) to the Aegis TEE gateway. Displays:
//   - Live connection status via pingAgent()
//   - API key management (show/hide, copy, regenerate via regenerateApiKey())
//   - Per-client JSON config snippets with copy-to-clipboard
//
// The MCP endpoint is the gateway URL + /mcp, authenticated via Bearer token.
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useEffect, useCallback } from 'react';
import { pingAgent, getAgentBase, regenerateApiKey, getUserProfile } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Button from '../../UI/Button';
import Badge from '../../UI/Badge';

/* //////////////////////////////////////////////////////////////
                             TYPES
////////////////////////////////////////////////////////////// */

type McpClient = 'cursor' | 'claude' | 'vscode';

interface Props {
  session: AuthSession;
}

/* //////////////////////////////////////////////////////////////
                           CONSTANTS
////////////////////////////////////////////////////////////// */

const CLIENT_META: Record<McpClient, { label: string; icon: string; configPath: string }> = {
  cursor: {
    label: 'Cursor',
    icon: '⌨️',
    configPath: '.cursor/mcp.json',
  },
  claude: {
    label: 'Claude Desktop',
    icon: '🤖',
    configPath: 'claude_desktop_config.json',
  },
  vscode: {
    label: 'VS Code',
    icon: '💻',
    configPath: '.vscode/mcp.json',
  },
};

const CLIENT_KEYS: McpClient[] = ['cursor', 'claude', 'vscode'];

/* //////////////////////////////////////////////////////////////
                          COMPONENT
////////////////////////////////////////////////////////////// */

export default function McpSetupPanel({ session }: Props) {
  // ── State ──────────────────────────────────────────────────────────────────
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);
  const [checking, setChecking] = useState(false);
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [showApiKey, setShowApiKey] = useState(false);
  const [apiKeyCopied, setApiKeyCopied] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [activeClient, setActiveClient] = useState<McpClient>('cursor');
  const [configCopied, setConfigCopied] = useState(false);
  const [endpointCopied, setEndpointCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ── Derived ────────────────────────────────────────────────────────────────

  const gatewayUrl = (() => {
    const base = getAgentBase();
    // In dev, build full URL; in prod the base is already absolute
    if (base.startsWith('/')) {
      return `${window.location.origin}${base}`;
    }
    return base;
  })();

  const mcpEndpoint = `${gatewayUrl}/mcp`;

  const sessionToken = apiKey || localStorage.getItem('AEGIS_SESSION_TOKEN') || 'YOUR_API_KEY';

  // ── Effects ────────────────────────────────────────────────────────────────

  useEffect(() => {
    checkConnection();
    loadApiKey();
  }, []);

  // Poll connection status every 30s
  useEffect(() => {
    const interval = setInterval(checkConnection, 30_000);
    return () => clearInterval(interval);
  }, []);

  // ── Connection Check ───────────────────────────────────────────────────────

  async function checkConnection() {
    setChecking(true);
    const online = await pingAgent();
    setAgentOnline(online);
    setChecking(false);
  }

  // ── Load API Key ───────────────────────────────────────────────────────────

  async function loadApiKey() {
    try {
      const profile = await getUserProfile();
      if (profile?.apiKey) {
        setApiKey(profile.apiKey);
      }
    } catch {
      // Silently fail — key will show placeholder
    }
  }

  // ── Regenerate API Key ─────────────────────────────────────────────────────

  const handleRegenerate = useCallback(async () => {
    if (!confirm('Regenerate your API key? All existing MCP connections will need updating.')) return;
    setRegenerating(true);
    setError(null);
    try {
      const result = await regenerateApiKey();
      setApiKey(result.apiKey);
      setShowApiKey(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRegenerating(false);
    }
  }, []);

  // ── Copy Helpers ───────────────────────────────────────────────────────────

  function copyApiKey() {
    if (!apiKey) return;
    navigator.clipboard.writeText(apiKey);
    setApiKeyCopied(true);
    setTimeout(() => setApiKeyCopied(false), 2000);
  }

  function copyEndpoint() {
    navigator.clipboard.writeText(mcpEndpoint);
    setEndpointCopied(true);
    setTimeout(() => setEndpointCopied(false), 2000);
  }

  function copyConfig() {
    navigator.clipboard.writeText(getConfigJson());
    setConfigCopied(true);
    setTimeout(() => setConfigCopied(false), 2000);
  }

  // ── Config Generator ───────────────────────────────────────────────────────

  function getConfigJson(): string {
    const config = {
      mcpServers: {
        aegis: {
          url: mcpEndpoint,
          headers: {
            Authorization: `Bearer ${sessionToken}`,
          },
        },
      },
    };
    return JSON.stringify(config, null, 2);
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in flex flex-col gap-6 overflow-y-auto flex-1 min-h-0 pr-1.5 pb-8 max-w-4xl">

      {/* ── Error Banner ────────────────────────────────────────────────────── */}
      {error && (
        <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-xs text-rose-400 font-mono animate-fade-in">
          &times; {error}
        </div>
      )}

      {/* ── Connection Status ───────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>MCP CONNECTION STATUS</CardTitle>
          <div className="flex items-center gap-2">
            {checking && (
              <span className="w-3 h-3 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
            )}
            <Badge
              variant={agentOnline === null ? 'secondary' : agentOnline ? 'success' : 'destructive'}
              className="font-semibold text-[9px] px-2 py-0.5"
            >
              {agentOnline === null ? 'CHECKING…' : agentOnline ? '● CONNECTED' : '● OFFLINE'}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 py-4">
          {/* Endpoint URL */}
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              MCP Endpoint URL
            </span>
            <div className="flex gap-2">
              <div className="flex-1 bg-slate-950 border border-slate-800 px-3 py-2.5 rounded-lg font-mono text-xs text-cyan-400 select-all truncate">
                {mcpEndpoint}
              </div>
              <Button variant="outline" size="sm" onClick={copyEndpoint} className="shrink-0">
                {endpointCopied ? '✔ Copied' : 'Copy'}
              </Button>
            </div>
          </div>

          {/* Connection info */}
          <div className="border border-slate-800/60 bg-slate-950/50 rounded-lg p-3 flex flex-col gap-1.5 text-[10px] font-mono text-slate-400">
            <div>› Protocol: <span className="text-slate-200">HTTP Streamable MCP (JSON-RPC 2.0)</span></div>
            <div>› Auth: <span className="text-slate-200">Bearer Token (API Key)</span></div>
            <div>› Encryption: <span className="text-slate-200">AES-256-GCM in TEE Enclave</span></div>
            <div>› Account: <span className="text-cyan-400">{session.nearAccountId}</span></div>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={checkConnection}
            disabled={checking}
            className="self-start"
          >
            {checking ? (
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
                Testing…
              </span>
            ) : (
              '🔍 Test Connection'
            )}
          </Button>
        </CardContent>
      </Card>

      {/* ── API Key Management ──────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>API KEY</CardTitle>
          <Badge variant="warning" className="text-[9px] px-2 py-0.5 font-semibold">
            SENSITIVE
          </Badge>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 py-4">
          {/* Key display */}
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              Vault API Key (Bearer Token)
            </span>
            <div className="flex gap-2">
              <div className="flex-1 bg-slate-950 border border-slate-800 px-3 py-2.5 rounded-lg font-mono text-xs truncate select-all transition-colors">
                {apiKey ? (
                  <span className={showApiKey ? 'text-cyan-400' : 'text-slate-600'}>
                    {showApiKey ? apiKey : '•'.repeat(Math.min(apiKey.length, 40))}
                  </span>
                ) : (
                  <span className="text-slate-600 italic">No API key loaded</span>
                )}
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowApiKey(!showApiKey)}
                disabled={!apiKey}
                className="shrink-0"
                title={showApiKey ? 'Hide key' : 'Reveal key'}
              >
                {showApiKey ? '🙈' : '👁️'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={copyApiKey}
                disabled={!apiKey}
                className="shrink-0"
              >
                {apiKeyCopied ? '✔ Copied' : 'Copy'}
              </Button>
            </div>
          </div>

          {/* Regenerate */}
          <div className="flex items-center gap-3">
            <Button
              variant="destructive"
              size="sm"
              onClick={handleRegenerate}
              disabled={regenerating}
            >
              {regenerating ? (
                <span className="flex items-center gap-1.5">
                  <span className="w-3 h-3 rounded-full border border-rose-400/30 border-t-rose-400 animate-spin" />
                  Regenerating…
                </span>
              ) : (
                '🔄 Regenerate Key'
              )}
            </Button>
            <span className="text-[10px] text-slate-500">
              Warning: existing connections will be invalidated.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* ── Client Setup Instructions ───────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>CLIENT SETUP</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-0 p-0">
          {/* Client Tabs */}
          <div className="flex border-b border-slate-800/80">
            {CLIENT_KEYS.map((key) => {
              const meta = CLIENT_META[key];
              const active = activeClient === key;
              return (
                <button
                  key={key}
                  onClick={() => {
                    setActiveClient(key);
                    setConfigCopied(false);
                  }}
                  className={`flex items-center gap-2 px-5 py-3 text-xs font-medium transition-all cursor-pointer border-b-2 select-none ${
                    active
                      ? 'text-cyan-400 border-cyan-400 bg-slate-950/50'
                      : 'text-slate-500 border-transparent hover:text-slate-300 hover:bg-slate-800/30'
                  }`}
                >
                  <span className="text-sm">{meta.icon}</span>
                  <span>{meta.label}</span>
                </button>
              );
            })}
          </div>

          {/* Active Client Config */}
          <div className="p-5 flex flex-col gap-4 animate-fade-in" key={activeClient}>
            {/* Step-by-step instructions */}
            <div className="flex flex-col gap-3">
              <StepItem
                step={1}
                title={`Open ${CLIENT_META[activeClient].configPath}`}
                description={getStepOneDescription(activeClient)}
              />
              <StepItem
                step={2}
                title="Paste the configuration below"
                description="Copy the JSON configuration and paste it into the file. Replace or merge with existing mcpServers entries."
              />
              <StepItem
                step={3}
                title={`Restart ${CLIENT_META[activeClient].label}`}
                description={`After saving the config, restart ${CLIENT_META[activeClient].label} to activate the Aegis MCP connection.`}
              />
            </div>

            {/* Config JSON */}
            <div className="flex flex-col gap-1.5">
              <div className="flex justify-between items-center">
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
                  {CLIENT_META[activeClient].configPath}
                </span>
                <Button variant="default" size="xs" onClick={copyConfig}>
                  {configCopied ? '✔ Copied!' : '📋 Copy Config'}
                </Button>
              </div>
              <pre className="bg-slate-950 border border-slate-800 p-4 rounded-lg font-mono text-[11px] text-cyan-400/90 overflow-x-auto select-all leading-relaxed shadow-inner">
                {getConfigJson()}
              </pre>
            </div>

            {/* Verification */}
            <div className="border border-slate-800/60 bg-slate-950/50 rounded-lg p-3 text-[10px] font-mono text-slate-400">
              <span className="text-cyan-400 font-semibold uppercase tracking-wider">Verification: </span>
              {getVerificationHint(activeClient)}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* //////////////////////////////////////////////////////////////
                       SUB-COMPONENTS
////////////////////////////////////////////////////////////// */

// ── Step Item ────────────────────────────────────────────────────────────────

function StepItem({ step, title, description }: { step: number; title: string; description: string }) {
  return (
    <div className="flex gap-3">
      <div className="w-6 h-6 rounded-full bg-slate-950 border border-slate-800 flex items-center justify-center text-[10px] font-mono font-bold text-cyan-400 shrink-0 shadow-inner select-none">
        {step}
      </div>
      <div className="flex flex-col gap-0.5 min-w-0">
        <span className="text-xs font-semibold text-slate-200">{title}</span>
        <span className="text-[10px] text-slate-500 leading-relaxed">{description}</span>
      </div>
    </div>
  );
}

/* //////////////////////////////////////////////////////////////
                          HELPERS
////////////////////////////////////////////////////////////// */

function getStepOneDescription(client: McpClient): string {
  switch (client) {
    case 'cursor':
      return 'In your project root, create or open .cursor/mcp.json. This file tells Cursor which MCP servers to connect to.';
    case 'claude':
      return 'Open Claude Desktop settings and navigate to the MCP configuration file (claude_desktop_config.json) in your app data directory.';
    case 'vscode':
      return 'In your project root, create or open .vscode/mcp.json. VS Code reads MCP server configurations from this file.';
  }
}

function getVerificationHint(client: McpClient): string {
  switch (client) {
    case 'cursor':
      return 'After restarting, open Cursor Settings → MCP and verify "aegis" shows a green connected indicator.';
    case 'claude':
      return 'After restarting Claude Desktop, the Aegis tools should appear in the tool picker (hammer icon) in a new conversation.';
    case 'vscode':
      return 'After restarting, open the VS Code Command Palette (Cmd+Shift+P) and search "MCP" to verify the aegis server is listed.';
  }
}
