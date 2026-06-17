import { useState, useEffect } from 'react';
import { getFirewallLogs } from '../../../api/gateway';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Badge from '../../UI/Badge';

interface AuditLog {
  timestamp: number;
  skill_name: string;
  destination: string;
  rule_triggered: string;
  marker_detected: string | null;
}

export default function LogsPanel() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchLogs();
  }, []);

  async function fetchLogs() {
    try {
      setLoading(true);
      setError(null);
      const data = await getFirewallLogs();
      setLogs(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="flex-grow flex items-center justify-center p-12 text-slate-400 text-xs font-mono">
        &rsaquo; Retrieving firewall compliance logs...
      </div>
    );
  }

  return (
    <div className="animate-fade-in flex flex-col gap-6 overflow-y-auto flex-1 min-h-0 pr-1.5 pb-8">
      {error && (
        <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-xs text-rose-400 font-mono">
          &times; {error}
        </div>
      )}

      <Card className="flex flex-col flex-1 min-h-0">
        <CardHeader className="py-3 shrink-0 flex flex-row items-center justify-between">
          <CardTitle>ZDR EGRESS FIREWALL COMPLIANCE LOGS</CardTitle>
          <button
            onClick={fetchLogs}
            className="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono bg-slate-900 border border-slate-800 px-2.5 py-1 rounded hover:border-slate-700 transition-all shrink-0"
          >
            ↻ Refresh Feed
          </button>
        </CardHeader>
        <CardContent className="flex-1 overflow-y-auto p-0 gap-0 min-h-0">
          {logs.length === 0 ? (
            <div className="py-24 text-center text-slate-500 text-xs flex flex-col items-center gap-3">
              <span className="text-4xl select-none">🛡️</span>
              <span className="font-semibold text-slate-400">No security events triggered</span>
              <p className="max-w-xs text-[10px] text-slate-500 font-mono">
                Outbound prompt requests sent to OpenAI, Anthropic, or Vertex AI are running in full zero-knowledge compliance.
              </p>
            </div>
          ) : (
            <div className="w-full flex flex-col font-mono text-xs text-slate-300">
              {/* Header Row */}
              <div className="flex bg-slate-900 border-b border-slate-800/80 px-4 py-2 text-slate-400 font-semibold select-none text-[10px] shrink-0">
                <span className="w-40 shrink-0">TIMESTAMP</span>
                <span className="w-32 shrink-0">SKILL</span>
                <span className="w-48 shrink-0">DESTINATION</span>
                <span className="w-44 shrink-0">RULE TRIGGERED</span>
                <span className="flex-1 min-w-0">FLAGGED PARAMETER</span>
              </div>
              {/* Data Rows */}
              <div className="flex-1 overflow-y-auto flex flex-col">
                {logs.map((log, index) => {
                  const date = new Date(log.timestamp).toLocaleString();
                  const destHost = log.destination.replace('https://', '').split('/')[0] || log.destination;
                  return (
                    <div
                      key={index}
                      className="flex border-b border-slate-800/40 hover:bg-slate-900/20 px-4 py-3 items-center"
                    >
                      <span className="w-40 shrink-0 text-slate-400 select-none text-[11px]">{date}</span>
                      <span className="w-32 shrink-0 text-slate-200 font-semibold">{log.skill_name}</span>
                      <span className="w-48 shrink-0 text-cyan-400 truncate pr-4" title={log.destination}>
                        {destHost}
                      </span>
                      <span className="w-44 shrink-0">
                        <Badge
                          variant={log.rule_triggered === 'DESTINATION_BLOCKED' ? 'destructive' : 'warning'}
                          className="text-[9px] px-2 py-0.5"
                        >
                          {log.rule_triggered.replace('_', ' ')}
                        </Badge>
                      </span>
                      <span className="flex-1 min-w-0 text-rose-400 font-semibold truncate">
                        {log.marker_detected ? `[${log.marker_detected}]` : 'N/A'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
