import type { ZdrMarker } from '../../api/types';

// ─────────────────────────────────────────────────────────────────────────────
// ZdrAlertBanner
// Pulsating crimson warning card that activates when the ZDR firewall
// intercepts a sensitive marker in the prompt input.
//
// Visual spec: ZDR Crimson (#ff3b5c) with pulsating box-shadow glow.
// The banner mirrors the marker that triggered the block.
// ─────────────────────────────────────────────────────────────────────────────

interface ZdrAlertBannerProps {
  marker: ZdrMarker | null;
  /** If true, the alert displays as "server-side enforcement triggered" */
  serverSide?: boolean;
  onDismiss?: () => void;
}

export function ZdrAlertBanner({ marker, serverSide = false, onDismiss }: ZdrAlertBannerProps) {
  if (!marker) return null;

  return (
    <div
      className="zdr-glow animate-fade-in"
      role="alert"
      aria-live="assertive"
      style={{
        background: 'var(--color-alert-dim)',
        borderRadius: 10,
        padding: '14px 16px',
        display: 'flex',
        gap: 12,
        alignItems: 'flex-start',
      }}
    >
      {/* Icon */}
      <div style={{
        flexShrink: 0,
        width: 32, height: 32,
        background: 'rgba(255,59,92,0.15)',
        border: '1px solid rgba(255,59,92,0.3)',
        borderRadius: 8,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 16,
      }}>
        🛑
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: 12,
          fontWeight: 700,
          color: 'var(--color-alert)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          marginBottom: 4,
        }}>
          {serverSide ? '▶ ZDR FIREWALL — PAYLOAD INTERCEPTED' : '▶ ZDR FIREWALL — INPUT BLOCKED'}
        </div>
        <div style={{ fontSize: 12, color: 'rgba(255,59,92,0.8)', lineHeight: 1.5 }}>
          {serverSide
            ? `The agent rejected this payload. Sensitive marker detected: `
            : `Sensitive data detected in prompt: `}
          <code style={{
            fontFamily: 'var(--font-mono)',
            background: 'rgba(255,59,92,0.15)',
            padding: '1px 6px',
            borderRadius: 4,
            color: 'var(--color-alert)',
            fontSize: 11,
          }}>
            {marker}
          </code>
        </div>
        <div style={{ fontSize: 11, color: 'var(--color-text-3)', marginTop: 6 }}>
          Remove the sensitive content before dispatching. FIREWALL.md §2 — Zero Data Retention.
        </div>
      </div>

      {/* Dismiss */}
      {onDismiss && (
        <button
          onClick={onDismiss}
          style={{
            flexShrink: 0,
            background: 'none',
            border: 'none',
            color: 'var(--color-text-3)',
            cursor: 'pointer',
            fontSize: 16,
            padding: 0,
            lineHeight: 1,
          }}
          aria-label="Dismiss ZDR alert"
        >
          ✕
        </button>
      )}
    </div>
  );
}
