import { useState, useEffect } from 'react';
import { connectWallet, getConnectedAccountId } from '../../../near/wallet';
import { pingAgent } from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';

// ─── Auth Step ────────────────────────────────────────────────────────────────
type Step = 'idle' | 'connecting' | 'error';

interface Props {
  onSuccess: (session: AuthSession) => void;
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthGate — Phase 3
//
// Auth model: wallet connect only (no gateway session).
// Identity = connected NEAR accountId.
// Spec: IDENTITY.md §6 — dashboard mode uses wallet directly.
// ─────────────────────────────────────────────────────────────────────────────
export default function AuthGate({ onSuccess }: Props) {
  const [step, setStep] = useState<Step>('idle');
  const [error, setError] = useState<string | null>(null);
  const [agentOnline, setAgentOnline] = useState<boolean | null>(null);

  // Check if wallet already connected (page refresh)
  useEffect(() => {
    getConnectedAccountId().then((id: string | null) => {
      if (id) onSuccess({ nearAccountId: id });
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
      onSuccess({ nearAccountId });
    } catch (e) {
      setStep('error');
      setError((e as Error).message);
    }
  }

  const busy = step === 'connecting';

  return (
    <div
      id="auth-gate"
      className="grid-bg"
      style={{
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
        position: 'relative',
        overflow: 'hidden',
        background: 'var(--color-bg)',
      }}
    >
      {/* Ambient glows */}
      <div style={{ position: 'absolute', top: '15%', left: '10%', width: 500, height: 500, background: 'radial-gradient(circle, rgba(0,240,255,0.04) 0%, transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '10%', right: '8%', width: 400, height: 400, background: 'radial-gradient(circle, rgba(167,139,250,0.04) 0%, transparent 70%)', pointerEvents: 'none' }} />

      {/* Main card */}
      <div
        className="glass-hi animate-fade-in"
        style={{
          width: '100%',
          maxWidth: 460,
          borderRadius: 16,
          padding: '52px 44px',
          position: 'relative',
          border: '1px solid rgba(30,41,59,0.9)',
        }}
      >
        {/* Cyan top accent line */}
        <div style={{
          position: 'absolute', top: 0, left: '20%', right: '20%', height: 1,
          background: 'linear-gradient(90deg, transparent, var(--color-accent), transparent)',
          borderRadius: 99,
        }} />

        {/* Logo block */}
        <div style={{ textAlign: 'center', marginBottom: 44 }}>
          <div style={{
            width: 60, height: 60,
            background: 'var(--color-primary)',
            border: '1px solid rgba(0,240,255,0.2)',
            borderRadius: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 26, margin: '0 auto 24px',
            boxShadow: '0 0 24px rgba(0,240,255,0.12)',
          }}>
            🛡
          </div>
          <h1 style={{ margin: '0 0 8px', fontSize: 28, fontWeight: 700, letterSpacing: '-0.5px' }}>
            <span className="gradient-text">Project Aegis</span>
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: 'var(--color-text-2)', lineHeight: 1.5 }}>
            Sovereign AI Memory Layer
          </p>
        </div>

        {/* Feature tags */}
        <div style={{ display: 'flex', gap: 7, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 40 }}>
          {['AES-256-GCM', 'IronClaw TEE', 'Walrus Storage', 'NEAR Identity'].map((f) => (
            <span key={f} className="badge badge-navy" style={{ fontFamily: 'var(--font-mono)', fontSize: 10 }}>
              {f}
            </span>
          ))}
        </div>

        {/* Agent status */}
        {agentOnline === false && (
          <div className="animate-fade-in" style={{
            background: 'rgba(255,59,92,0.07)',
            border: '1px solid rgba(255,59,92,0.2)',
            borderRadius: 8, padding: '10px 14px', marginBottom: 16,
            fontSize: 12, color: 'rgba(255,59,92,0.8)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span>⚠</span>
            TEE Agent offline — start the Rust agent at localhost:8080
          </div>
        )}
        {agentOnline === true && (
          <div className="animate-fade-in" style={{
            background: 'var(--color-accent-dim)',
            border: '1px solid rgba(0,240,255,0.15)',
            borderRadius: 8, padding: '10px 14px', marginBottom: 16,
            fontSize: 12, color: 'var(--color-accent)',
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span className="animate-pulse">●</span> TEE Agent online
          </div>
        )}

        {/* Status */}
        <p style={{
          textAlign: 'center', fontSize: 12, minHeight: 16, marginBottom: 20,
          color: busy ? 'var(--color-accent)' : 'var(--color-text-3)',
          fontFamily: busy ? 'var(--font-mono)' : 'var(--font-sans)',
          transition: 'color 0.2s',
        }}>
          {busy ? '› Opening NEAR wallet selector…' : 'Connect your NEAR wallet to access your vault'}
        </p>

        {/* Connect button */}
        {step !== 'error' && (
          <button
            id="btn-connect-wallet"
            className="btn btn-accent"
            style={{ width: '100%', padding: '14px 20px', fontSize: 14, fontWeight: 600, justifyContent: 'center' }}
            onClick={handleConnect}
            disabled={busy}
          >
            {busy ? (
              <><span className="spinner" style={{ borderTopColor: '#03040a', borderColor: 'rgba(0,0,0,0.2)' }} /> Connecting…</>
            ) : (
              <><NearIcon /> Connect NEAR Wallet</>
            )}
          </button>
        )}

        {/* Error */}
        {step === 'error' && error && (
          <div className="animate-fade-in">
            <div style={{
              background: 'var(--color-alert-dim)',
              border: '1px solid rgba(255,59,92,0.25)',
              borderRadius: 8, padding: '12px 14px', marginBottom: 14,
              fontSize: 12, color: 'var(--color-alert)',
              fontFamily: 'var(--font-mono)', lineHeight: 1.5, wordBreak: 'break-word',
            }}>
              {error}
            </div>
            <button className="btn btn-ghost" style={{ width: '100%' }} onClick={() => { setStep('idle'); setError(null); }}>
              ↩ Try Again
            </button>
          </div>
        )}

        {/* Footer */}
        <p style={{
          textAlign: 'center', fontSize: 11, color: 'var(--color-text-3)',
          marginTop: 36, marginBottom: 0, lineHeight: 1.6,
        }}>
          No passwords. Your NEAR key IS the identity.
          <br />
          <span style={{ opacity: 0.5 }}>IDENTITY.md §6 · Dashboard auth model</span>
        </p>
      </div>
    </div>
  );
}

function NearIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none">
      <path d="M10.5 2.5L6.5 8.5H10.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      <path d="M5.5 13.5L9.5 7.5H5.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}
