import { disconnectWallet } from '../../../near/wallet';
import type { AuthSession } from '../../../api/types';
import Button from '../../UI/Button';

export type DashTab = 'wiki' | 'skills' | 'console' | 'settings';

const NAV: Array<{ id: DashTab; icon: string; label: string }> = [
  { id: 'wiki',     icon: '📄', label: 'Wiki Pages'   },
  { id: 'skills',  icon: '⚡', label: 'Skill Registry' },
  { id: 'console', icon: '⌨️', label: 'Console'      },
  { id: 'settings',icon: '⚙️', label: 'Settings'     },
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
  async function handleLock() {
    await disconnectWallet();
    onLock();
  }

  return (
    <aside className={`h-full shrink-0 flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-300 ${
      collapsed ? 'w-16' : 'w-56'
    }`}>
      {/* Logo row */}
      <div className={`h-14 flex items-center border-b border-slate-800 shrink-0 ${
        collapsed ? 'justify-center px-0' : 'justify-between px-4'
      }`}>
        {!collapsed && (
          <span className="text-xs font-bold tracking-wider text-slate-100 uppercase select-none">
            Aegis <span className="text-cyan-400">Vault</span>
          </span>
        )}
        <Button
          variant="outline"
          size="icon"
          onClick={onToggle}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          className="w-7 h-7 flex items-center justify-center"
        >
          <span className="text-[10px] font-mono leading-none select-none">
            {collapsed ? '→' : '←'}
          </span>
        </Button>
      </div>

      {/* Account Profile Block */}
      <div className={`flex items-center gap-3 border-b border-slate-800/80 shrink-0 ${
        collapsed ? 'justify-center py-4 px-0' : 'justify-start py-4 px-4'
      }`}>
        <div className="w-8 h-8 rounded-lg shrink-0 bg-slate-950 border border-slate-800 flex items-center justify-center text-xs font-mono font-bold text-cyan-400 select-none shadow-inner">
          N
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <div className="text-xs font-semibold text-slate-200 truncate max-w-[130px] font-mono leading-none">
              {session.nearAccountId}
            </div>
            <div className="text-[9px] text-cyan-400 mt-1 font-mono uppercase tracking-wider flex items-center gap-1 leading-none select-none">
              <span className="w-1 h-1 rounded-full bg-cyan-400 animate-pulse-dot" />
              Active
            </div>
          </div>
        )}
      </div>

      {/* Nav items */}
      <nav className="flex-grow p-2 flex flex-col gap-1 overflow-y-auto">
        {NAV.map(({ id, icon, label }) => {
          const active = activeTab === id;
          return (
            <Button
              key={id}
              id={`nav-${id}`}
              onClick={() => onTabChange(id)}
              variant={active ? 'secondary' : 'ghost'}
              className={`w-full text-xs shrink-0 ${
                collapsed ? 'justify-center px-0' : 'justify-start px-3'
              } ${
                active ? 'text-cyan-400 font-semibold border-slate-700 bg-slate-950 shadow-inner' : ''
              }`}
              title={collapsed ? label : undefined}
            >
              <span className="text-sm shrink-0">{icon}</span>
              {!collapsed && <span>{label}</span>}
            </Button>
          );
        })}
      </nav>

      {/* Lock */}
      <div className="p-2 border-t border-slate-800/80 shrink-0">
        <Button
          id="btn-lock-vault"
          variant="destructive"
          onClick={handleLock}
          className={`w-full text-xs font-semibold ${
            collapsed ? 'justify-center px-0' : 'justify-start px-3'
          }`}
          title={collapsed ? 'Lock Vault' : undefined}
        >
          <span className="text-sm shrink-0">🔒</span>
          {!collapsed && <span>Lock Vault</span>}
        </Button>
      </div>
    </aside>
  );
}
