import type { DashTab } from './DashboardSidebar';
import Badge from '../../UI/Badge';

const TAB_LABEL: Record<DashTab, string> = {
  wiki:     'Wiki Memory',
  skills:   'Skill Registry',
  console:  'Execution Console',
  logs:     'Firewall Compliance Logs',
  billing:  'Billing & Subscription',
  settings: 'Settings',
  teams:    'Team Management',
  mcp:      'MCP Setup',
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
    <header className="h-14 flex items-center justify-between px-6 bg-slate-900 border-b border-slate-800 shrink-0">
      {/* Left: page title */}
      <h1 className="text-sm font-semibold text-slate-100">
        {TAB_LABEL[activeTab]}
      </h1>

      {/* Right: status indicators */}
      <div className="flex items-center gap-2">
        {/* Agent status */}
        <Badge
          variant={
            agentOnline === true ? 'success' :
            agentOnline === false ? 'destructive' :
            'secondary'
          }
          className="font-semibold select-none text-[9px] px-2.5 py-0.5"
        >
          <span className={`w-1 h-1 rounded-full ${
            agentOnline === true ? 'bg-emerald-400 animate-pulse-dot' :
            agentOnline === false ? 'bg-rose-500' :
            'bg-slate-500'
          }`} />
          <span>
            {agentOnline === null ? 'PROBING ENCLAVE...' : agentOnline ? 'ENCLAVE ONLINE' : 'ENCLAVE OFFLINE'}
          </span>
        </Badge>

        {/* Account pill */}
        <Badge variant="secondary" className="px-2.5 py-0.5 text-[9px] hover:border-slate-700 transition-colors">
          {accountShort}
        </Badge>
      </div>
    </header>
  );
}
