import { useState, useEffect } from 'react';
import { getUserProfile, subscribeTier } from '../../../api/gateway';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Button from '../../UI/Button';
import Badge from '../../UI/Badge';

interface Profile {
  nearAccountId: string;
  subscriptionStatus: 'free' | 'developer' | 'team';
  storageUsedBytes: number;
  storageLimitBytes: number;
}

export default function BillingPanel() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    fetchProfile();
  }, []);

  async function fetchProfile() {
    try {
      setLoading(true);
      setError(null);
      const data = await getUserProfile();
      setProfile(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  async function handleUpgrade(tier: 'free' | 'developer' | 'team') {
    if (!profile) return;
    try {
      setUpdating(true);
      setError(null);
      const res = await subscribeTier(tier);
      setProfile({
        ...profile,
        subscriptionStatus: res.subscriptionStatus,
        storageLimitBytes: res.storageLimitBytes,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setUpdating(false);
    }
  }

  if (loading) {
    return (
      <div className="flex-grow flex items-center justify-center p-12 text-slate-400 text-xs font-mono">
        &rsaquo; Loading billing profile...
      </div>
    );
  }

  const usedMB = ((profile?.storageUsedBytes || 0) / (1024 * 1024)).toFixed(2);
  const limitMB = ((profile?.storageLimitBytes || 10485760) / (1024 * 1024)).toFixed(0);
  const percentUsed = Math.min(
    100,
    Math.round(((profile?.storageUsedBytes || 0) / (profile?.storageLimitBytes || 10485760)) * 100)
  );

  return (
    <div className="animate-fade-in flex flex-col gap-6 overflow-y-auto flex-1 min-h-0 pr-1.5 pb-8 max-w-4xl">
      {error && (
        <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-xs text-rose-400 font-mono">
          &times; {error}
        </div>
      )}

      {/* Storage Utilization Card */}
      <Card>
        <CardHeader>
          <CardTitle>VAULT STORAGE UTILIZATION</CardTitle>
          {profile && (
            <Badge variant={profile.subscriptionStatus === 'free' ? 'secondary' : 'success'}>
              {profile.subscriptionStatus.toUpperCase()} TIER
            </Badge>
          )}
        </CardHeader>
        <CardContent className="flex flex-col gap-4 py-4">
          <div className="flex justify-between items-center text-xs font-mono text-slate-400">
            <span>Used: <strong className="text-slate-100">{usedMB} MB</strong></span>
            <span>Capacity: <strong className="text-slate-100">{limitMB} MB</strong></span>
          </div>
          <div className="w-full bg-slate-900 border border-slate-800 rounded-full h-3.5 overflow-hidden p-[1px]">
            <div
              className="bg-gradient-to-r from-cyan-500 to-cyan-400 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(34,211,238,0.3)]"
              style={{ width: `${percentUsed}%` }}
            />
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {percentUsed}% capacity utilized. All blockchain transaction gas and storage staking are completely managed and abstracted by the operator.
          </div>
        </CardContent>
      </Card>

      {/* Tiers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Free Tier */}
        <Card className={profile?.subscriptionStatus === 'free' ? 'border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.05)]' : ''}>
          <CardHeader className="flex flex-col gap-1">
            <CardTitle>FREE TIER</CardTitle>
            <div className="text-xl font-bold font-mono text-slate-100">$0 <span className="text-[10px] text-slate-500 font-normal">/ month</span></div>
          </CardHeader>
          <CardContent className="text-xs flex flex-col gap-3 py-4 text-slate-400">
            <ul className="flex flex-col gap-2 list-none p-0 m-0">
              <li>📄 10MB Sovereign Storage</li>
              <li>🔒 Zero-Knowledge TEE Encryption</li>
              <li>⚡ Egress ZDR Prompt Firewall</li>
              <li>🛡️ Limited Firewall Logs</li>
            </ul>
            <Button
              variant={profile?.subscriptionStatus === 'free' ? 'secondary' : 'outline'}
              disabled={profile?.subscriptionStatus === 'free' || updating}
              onClick={() => handleUpgrade('free')}
              className="mt-4 justify-center"
            >
              {profile?.subscriptionStatus === 'free' ? 'Active Plan' : 'Select Free'}
            </Button>
          </CardContent>
        </Card>

        {/* Developer Tier */}
        <Card className={profile?.subscriptionStatus === 'developer' ? 'border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.05)]' : ''}>
          <CardHeader className="flex flex-col gap-1">
            <CardTitle>DEVELOPER TIER</CardTitle>
            <div className="text-xl font-bold font-mono text-cyan-400">$5 <span className="text-[10px] text-slate-500 font-normal">/ month</span></div>
          </CardHeader>
          <CardContent className="text-xs flex flex-col gap-3 py-4 text-slate-400">
            <ul className="flex flex-col gap-2 list-none p-0 m-0">
              <li>📄 500MB Sovereign Storage</li>
              <li>🔒 Zero-Knowledge TEE Encryption</li>
              <li>⚡ Egress ZDR Prompt Firewall</li>
              <li>🛡️ Full Audit Logging & Viewer</li>
            </ul>
            <Button
              variant={profile?.subscriptionStatus === 'developer' ? 'secondary' : 'default'}
              disabled={profile?.subscriptionStatus === 'developer' || updating}
              onClick={() => handleUpgrade('developer')}
              className="mt-4 justify-center"
            >
              {profile?.subscriptionStatus === 'developer' ? 'Active Plan' : 'Upgrade Plan'}
            </Button>
          </CardContent>
        </Card>

        {/* Team Tier */}
        <Card className={profile?.subscriptionStatus === 'team' ? 'border-cyan-500/50 shadow-[0_0_12px_rgba(6,182,212,0.05)]' : ''}>
          <CardHeader className="flex flex-col gap-1">
            <CardTitle>TEAM TIER</CardTitle>
            <div className="text-xl font-bold font-mono text-cyan-400">$15 <span className="text-[10px] text-slate-500 font-normal">/ month</span></div>
          </CardHeader>
          <CardContent className="text-xs flex flex-col gap-3 py-4 text-slate-400">
            <ul className="flex flex-col gap-2 list-none p-0 m-0">
              <li>📄 2GB Sovereign Storage</li>
              <li>👥 Cryptographic Team Key Sharing</li>
              <li>🔑 Multi-User ECDH Access Controls</li>
              <li>🛡️ Enterprise Security Dashboard</li>
            </ul>
            <Button
              variant={profile?.subscriptionStatus === 'team' ? 'secondary' : 'default'}
              disabled={profile?.subscriptionStatus === 'team' || updating}
              onClick={() => handleUpgrade('team')}
              className="mt-4 justify-center"
            >
              {profile?.subscriptionStatus === 'team' ? 'Active Plan' : 'Upgrade Plan'}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
