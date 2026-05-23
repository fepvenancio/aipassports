// NEW-07: React ErrorBoundary to catch render-time errors before they blank the entire app.
// Without this, any null.property access during render (e.g. pointer.blob_id.slice() when
// blob_id is null) causes React to unmount the ENTIRE application — blank white screen,
// full stack trace in DevTools (information leak), no recovery path.
//
// Attack scenario: attacker-controlled NEAR RPC returns VaultPointer with blob_id: null →
// WikiPanel crashes → ErrorBoundary catches → user sees informative error, not blank screen.

import React from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import '@near-wallet-selector/modal-ui/styles.css';
import App from './App.tsx';

// ─── Error Boundary ───────────────────────────────────────────────────────────

interface ErrorBoundaryState {
  hasError: boolean;
  errorMessage: string;
}

class AppErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    // Sanitize error message — avoid leaking internal paths or stack frames to the UI
    const safe = error?.message?.slice(0, 200) ?? 'An unexpected error occurred';
    return { hasError: true, errorMessage: safe };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Log full detail to console for devs, but never expose in the DOM
    console.error('[AppErrorBoundary] Render error caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100vh',
            background: '#06070a',
            color: '#e2e8f0',
            fontFamily: 'system-ui, sans-serif',
            gap: '16px',
            padding: '24px',
            textAlign: 'center',
          }}
        >
          <h1 style={{ fontSize: '1.5rem', color: '#f87171' }}>Something went wrong</h1>
          <p style={{ maxWidth: '480px', color: '#94a3b8', fontSize: '0.9rem' }}>
            {this.state.errorMessage}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, errorMessage: '' })}
            style={{
              padding: '8px 20px',
              background: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#e2e8f0',
              cursor: 'pointer',
            }}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─── Entry Point ──────────────────────────────────────────────────────────────

// NEW-12: Guard against missing root element (misconfigured CDN/build stripping the div)
const rootEl = document.getElementById('root');
if (!rootEl) {
  document.body.innerHTML = '<div style="color:red;padding:24px">Fatal: #root element not found. Check index.html.</div>';
  throw new Error('Fatal: #root element not found in index.html');
}

createRoot(rootEl).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
);
