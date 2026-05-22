import type { DashTab } from './DashboardSidebar';

const TAB_LABEL: Record<DashTab, string> = {
  wiki:     'Wiki Memory',
  skills:   'Skill Registry',
  console:  'Execution Console',
  settings: 'Settings',
};

interface Props {
  activeTab: DashTab;
  nearAccountId: string;
  agentOnline: boolean | null;
}

export default function DashboardHeader({ activeTab, nearAccountId, agentOnline }: Props) {
  const accountShort = nearAccountId.length > 22
    ? `${nearAccountId.slice(0, 10)}…${nearAccountId.slice(-8)}`
    : nearAccountId;

  return (
    <header style={{
      height: 56,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      background: 'var(--color-surface)',
      borderBottom: '1px solid var(--color-border)',
      flexShrink: 0,
    }}>
      {/* Left: page title */}
      <h1 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: 'var(--color-text-1)' }}>
        {TAB_LABEL[activeTab]}
      </h1>

      {/* Right: status indicators */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        {/* Agent status */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 10px', borderRadius: 99,
          background: agentOnline === true
            ? 'var(--color-accent-dim)'
            : agentOnline === false
            ? 'var(--color-alert-dim)'
            : 'rgba(255,255,255,0.04)',
          border: `1px solid ${
            agentOnline === true ? 'rgba(0,240,255,0.15)' :
            agentOnline === false ? 'rgba(255,59,92,0.15)' :
            'var(--color-border)'
          }`,
          fontSize: 11,
          color: agentOnline === true
            ? 'var(--color-accent)'
            : agentOnline === false
            ? 'var(--color-alert)'
            : 'var(--color-text-3)',
        }}>
          <span className={agentOnline === true ? 'animate-pulse' : ''}>
            {agentOnline === null ? '○' : agentOnline ? '●' : '●'}
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 500 }}>
            {agentOnline === null ? 'PROBING…' : agentOnline ? 'ENCLAVE ONLINE' : 'ENCLAVE OFFLINE'}
          </span>
        </div>

        {/* Account pill */}
        <div style={{
          padding: '4px 10px', borderRadius: 99,
          background: 'var(--color-primary)',
          border: '1px solid var(--color-border)',
          fontSize: 11,
          fontFamily: 'var(--font-mono)',
          color: 'var(--color-text-2)',
        }}>
          {accountShort}
        </div>
      </div>
    </header>
  );
}
