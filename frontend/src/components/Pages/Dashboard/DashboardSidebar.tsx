import { disconnectWallet } from '../../../near/wallet';
import type { AuthSession } from '../../../api/types';

// ─── Navigation ───────────────────────────────────────────────────────────────
export type DashTab = 'wiki' | 'skills' | 'console' | 'settings';

const NAV: Array<{ id: DashTab; icon: string; label: string }> = [
  { id: 'wiki',     icon: '📄', label: 'Wiki'    },
  { id: 'skills',  icon: '⚡', label: 'Skills'  },
  { id: 'console', icon: '⌨',  label: 'Console'  },
  { id: 'settings',icon: '⚙',  label: 'Settings' },
];

interface Props {
  session: AuthSession;
  activeTab: DashTab;
  collapsed: boolean;
  onTabChange: (tab: DashTab) => void;
  onToggle: () => void;
  onLock: () => void;
}

export default function DashboardSidebar({
  session, activeTab, collapsed, onTabChange, onToggle, onLock,
}: Props) {
  const w = collapsed ? 64 : 224;

  async function handleLock() {
    await disconnectWallet();
    onLock();
  }

  return (
    <aside style={{
      width: w,
      flexShrink: 0,
      display: 'flex',
      flexDirection: 'column',
      background: 'var(--color-surface)',
      borderRight: '1px solid var(--color-border)',
      transition: 'width 0.22s cubic-bezier(0.4,0,0.2,1)',
      overflow: 'hidden',
    }}>
      {/* Logo row */}
      <div style={{
        height: 56,
        display: 'flex',
        alignItems: 'center',
        justifyContent: collapsed ? 'center' : 'space-between',
        padding: collapsed ? 0 : '0 14px',
        borderBottom: '1px solid var(--color-border)',
        flexShrink: 0,
      }}>
        {!collapsed && (
          <span style={{ fontSize: 15, fontWeight: 700 }}>
            <span className="gradient-text">Aegis</span>
          </span>
        )}
        <button
          className="btn btn-ghost btn-icon"
          onClick={onToggle}
          style={{ border: 'none', color: 'var(--color-text-3)', padding: 6 }}
          title={collapsed ? 'Expand' : 'Collapse'}
        >
          <span style={{ fontSize: 14 }}>{collapsed ? '▶' : '◀'}</span>
        </button>
      </div>

      {/* Account badge */}
      <div style={{
        padding: collapsed ? '10px 0' : '12px 14px',
        borderBottom: '1px solid var(--color-border)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: collapsed ? 'center' : 'flex-start',
        gap: 10,
        flexShrink: 0,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8, flexShrink: 0,
          background: 'linear-gradient(135deg, var(--color-accent-dim), var(--color-purple-dim))',
          border: '1px solid rgba(0,240,255,0.15)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, color: 'var(--color-accent)',
          fontFamily: 'var(--font-mono)',
        }}>
          N
        </div>
        {!collapsed && (
          <div style={{ overflow: 'hidden' }}>
            <div style={{
              fontSize: 11, fontWeight: 600,
              color: 'var(--color-text-1)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              maxWidth: 140,
            }}>
              {session.nearAccountId}
            </div>
            <div style={{ fontSize: 10, color: 'var(--color-accent)', marginTop: 1 }}>
              <span className="animate-pulse" style={{ marginRight: 4 }}>●</span>
              Vault Active
            </div>
          </div>
        )}
      </div>

      {/* Nav items */}
      <nav style={{ flex: 1, padding: '10px 6px', display: 'flex', flexDirection: 'column', gap: 3 }}>
        {NAV.map(({ id, icon, label }) => {
          const active = activeTab === id;
          return (
            <button
              key={id}
              id={`nav-${id}`}
              onClick={() => onTabChange(id)}
              className="btn btn-ghost"
              style={{
                width: '100%',
                justifyContent: collapsed ? 'center' : 'flex-start',
                padding: collapsed ? '10px 0' : '9px 12px',
                gap: 10, fontSize: 13,
                background: active ? 'var(--color-accent-dim)' : 'transparent',
                borderColor: active ? 'rgba(0,240,255,0.18)' : 'transparent',
                color: active ? 'var(--color-accent)' : 'var(--color-text-2)',
                fontWeight: active ? 600 : 400,
                borderLeft: active ? '2px solid var(--color-accent)' : '2px solid transparent',
                borderRadius: active ? '0 var(--radius-md) var(--radius-md) 0' : 'var(--radius-md)',
                transition: 'all 0.14s',
              }}
              title={collapsed ? label : undefined}
            >
              <span style={{ fontSize: 15, flexShrink: 0 }}>{icon}</span>
              {!collapsed && label}
            </button>
          );
        })}
      </nav>

      {/* Lock */}
      <div style={{ padding: '10px 6px', borderTop: '1px solid var(--color-border)', flexShrink: 0 }}>
        <button
          id="btn-lock-vault"
          className="btn btn-alert"
          onClick={handleLock}
          style={{
            width: '100%',
            justifyContent: collapsed ? 'center' : 'flex-start',
            padding: collapsed ? '10px 0' : '9px 12px',
            gap: 10, fontSize: 13, borderColor: 'transparent',
          }}
          title={collapsed ? 'Lock Vault' : undefined}
        >
          <span style={{ fontSize: 15 }}>🔒</span>
          {!collapsed && 'Lock Vault'}
        </button>
      </div>
    </aside>
  );
}
