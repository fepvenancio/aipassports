import { useState, useEffect } from 'react';
import { connectWallet, getConnectedAccountId } from '../../../near/wallet';
import { pingAgent } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';
import Button from '../../UI/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../../UI/Card';
import Badge from '../../UI/Badge';

type Step = 'idle' | 'connecting' | 'error';

interface Props {
  onSuccess: (session: AuthSession) => void;
}

export default function AuthGate({ onSuccess }: Props) {
  const [step, setStep] = useState<Step>('idle');
  const [error, setError] = useState<string | null>(null);
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  // Check if wallet already connected and session exists
  useEffect(() => {
    getConnectedAccountId()
      .then((id: string | null) => {
        const token = localStorage.getItem('AEGIS_SESSION_TOKEN');
        if (id && token) {
          onSuccess({ nearAccountId: id, sessionId: token });
        }
      })
      .finally(() => {
        setLoading(false);
      });
  }, [onSuccess]);

  // Probe agent health
  useEffect(() => {
    pingAgent().then(setAgentOnline);
  }, []);

  async function handleConnect() {
    setStep('connecting');
    setError(null);
    try {
      const nearAccountId = await connectWallet();

      // 1. Fetch challenge nonce from gateway
      const base = import.meta.env.DEV ? '/api' : 'https://api.aipassports.xyz';
      const challengeRes = await fetch(`${base}/auth/challenge`, {
        method: 'POST',
      });
      if (!challengeRes.ok) {
        throw new Error(`Challenge fetch failed: HTTP ${challengeRes.status}`);
      }
      const challengeJson = await challengeRes.json() as { nonce: string };
      const challenge = challengeJson.nonce;

      // 2. Request user signature via Wallet Selector (NEP-413)
      const { signChallengeMessage } = await import('../../../near/wallet');
      const { publicKey, signature } = await signChallengeMessage(challenge);

      // 3. Submit signature to unlock session
      const unlockRes = await fetch(`${base}/auth/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nearAccountId,
          publicKey,
          signature,
          challenge
        }),
      });

      if (!unlockRes.ok) {
        const errJson = await unlockRes.json().catch(() => ({ error: `HTTP ${unlockRes.status}` })) as { error?: string };
        throw new Error(errJson.error ?? `Unlock failed: HTTP ${unlockRes.status}`);
      }

      const unlockJson = await unlockRes.json() as { sessionId: string };
      const sessionId = unlockJson.sessionId;

      localStorage.setItem('AEGIS_SESSION_TOKEN', sessionId);
      onSuccess({ nearAccountId, sessionId });
    } catch (e) {
      setStep('error');
      setError((e as Error).message);
    }
  }

  const busy = step === 'connecting';

  if (loading) {
    return (
      <div id="auth-gate" className="h-screen w-full flex items-center justify-center p-6 bg-slate-950">
        <Card className="w-full max-w-md p-10 text-center animate-fade-in shadow-xl">
          <div className="w-8 h-8 rounded-full border-2 border-slate-700 border-t-cyan-400 animate-spin mx-auto mb-6" />
          <h2 className="text-sm font-mono text-slate-400 tracking-wide">
            &rsaquo; Restoring secure session...
          </h2>
        </Card>
      </div>
    );
  }

  return (
    <div id="auth-gate" className="h-screen w-full flex items-center justify-center p-6 bg-slate-950 relative overflow-hidden">
      {/* Decorative top grid lines */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0f172a_1px,transparent_1px),linear-gradient(to_bottom,#0f172a_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-35" />

      {/* Main card */}
      <Card className="w-full max-w-md relative animate-fade-in shadow-2xl z-10">
        {/* Subtle accent border top */}
        <div className="absolute top-0 left-8 right-8 h-[1px] bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />

        <CardHeader className="flex flex-col items-center text-center pt-8 pb-6 border-b-0 bg-transparent">
          <div className="w-12 h-12 bg-slate-950 border border-slate-800 rounded-lg flex items-center justify-center text-xl mb-4 shadow-inner">
            🛡️
          </div>
          <CardTitle className="text-2xl font-bold tracking-tight text-slate-50 lowercase normal-case">
            Project Aegis
          </CardTitle>
          <CardDescription className="text-xs text-slate-400 mt-1 font-medium">
            Sovereign AI Memory Vault
          </CardDescription>
        </CardHeader>
 
        <CardContent className="px-8 pb-4 md:px-10 flex flex-col gap-6">
          {/* Feature tags */}
          <div className="flex flex-wrap gap-1.5 justify-center">
            {['AES-256-GCM', 'Intel TDX TEE', 'Walrus Storage', 'NEAR ID'].map((f) => (
              <Badge key={f} variant="secondary">
                {f}
              </Badge>
            ))}
          </div>
 
          {/* Agent status */}
          {agentOnline === false && (
            <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg px-4 py-2.5 text-xs text-rose-400 flex items-center gap-2.5 animate-fade-in font-medium">
              <span className="text-base select-none">⚠️</span>
              <span>TEE Agent offline &mdash; start the agent at localhost:8080</span>
            </div>
          )}
          {agentOnline === true && (
            <div className="bg-cyan-950/20 border border-cyan-900/30 rounded-lg px-4 py-2.5 text-xs text-cyan-400 flex items-center gap-2.5 animate-fade-in font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse-dot" />
              <span>Confidential TEE Agent online</span>
            </div>
          )}
 
          {/* Status prompt */}
          <p className="text-center text-xs min-h-[16px] text-slate-400 font-medium">
            {busy ? 'Opening NEAR wallet selector...' : 'Connect your NEAR wallet to access your private memory vault'}
          </p>

          {/* Connect button */}
          {step !== 'error' && (
            <Button
              id="btn-connect-wallet"
              variant="default"
              className="w-full py-3 text-sm font-semibold justify-center"
              onClick={handleConnect}
              disabled={busy}
            >
              {busy ? (
                <>
                  <span className="w-4 h-4 rounded-full border border-slate-950/20 border-t-slate-950 animate-spin" />
                  Connecting...
                </>
              ) : (
                <>
                  <NearIcon />
                  Connect NEAR Wallet
                </>
              )}
            </Button>
          )}

          {/* Error panel */}
          {step === 'error' && error && (
            <div className="animate-fade-in">
              <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 mb-4 text-xs text-rose-400 font-mono leading-relaxed break-all">
                {error}
              </div>
              <Button
                variant="outline"
                className="w-full py-2.5 text-sm"
                onClick={() => { setStep('idle'); setError(null); }}
              >
                &larr; Try Again
              </Button>
            </div>
          )}
        </CardContent>

        {/* Footer info */}
        <CardFooter className="justify-center border-t border-slate-800/40 py-6 bg-slate-950/20">
          <p className="text-center text-[10px] text-slate-500 leading-relaxed font-mono">
            No passwords. Your NEAR keys cryptographically sign session state.
            <br />
            <span className="opacity-60">IDENTITY.md &sect;6 &bull; Decentralized Dashboard Mode</span>
          </p>
        </CardFooter>
      </Card>
    </div>
  );
}

function NearIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" className="flex-shrink-0">
      <path d="M10.5 2.5L6.5 8.5H10.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M5.5 13.5L9.5 7.5H5.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}
