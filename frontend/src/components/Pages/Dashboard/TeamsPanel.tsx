// ─────────────────────────────────────────────────────────────────────────────
// TeamsPanel — Cryptographic Team Key Management
//
// Manages team creation, member invitations, and ECDH permission delegation.
// Teams enable multi-user access to shared encrypted vault entries via the
// NEAR contract's team access control layer.
//
// Local state is used for the team list since we don't have a list-my-teams
// endpoint yet — users manage teams by ID with full CRUD operations.
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useCallback } from 'react';
import {
  createTeam,
  addTeamMember,
  removeTeamMember,
  updateTeamPermission,
  listTeamMembers,
} from '../../../api/gateway';
import type { AuthSession } from '../../../api/types';
import { Card, CardHeader, CardTitle, CardContent } from '../../UI/Card';
import Button from '../../UI/Button';
import Input from '../../UI/Input';
import Badge from '../../UI/Badge';

/* //////////////////////////////////////////////////////////////
                             TYPES
////////////////////////////////////////////////////////////// */

type Permission = 'read' | 'write' | 'admin';

interface TeamMember {
  accountId: string;
  permission: string;
  joinedAt: number;
}

interface Team {
  id: string;
  name: string;
  members: TeamMember[];
  expanded: boolean;
  loading: boolean;
}

interface Props {
  session: AuthSession;
}

/* //////////////////////////////////////////////////////////////
                         CONSTANTS
////////////////////////////////////////////////////////////// */


const PERMISSION_OPTIONS: Permission[] = ['read', 'write', 'admin'];

/* //////////////////////////////////////////////////////////////
                        COMPONENT
////////////////////////////////////////////////////////////// */

export default function TeamsPanel({ session }: Props) {
  // ── State ──────────────────────────────────────────────────────────────────
  const [teams, setTeams] = useState<Team[]>([]);
  const [createName, setCreateName] = useState('');
  const [joinTeamId, setJoinTeamId] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Per-team add-member form state
  const [addMemberForms, setAddMemberForms] = useState<
    Record<string, { accountId: string; permission: Permission }>
  >({});

  // ── Helpers ────────────────────────────────────────────────────────────────

  function flashSuccess(msg: string) {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 3000);
  }

  function flashError(msg: string) {
    setError(msg);
    setTimeout(() => setError(null), 5000);
  }

  // ── Create Team ────────────────────────────────────────────────────────────

  const handleCreate = useCallback(async () => {
    if (!createName.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const { teamId } = await createTeam(createName.trim());
      setTeams((prev) => [
        ...prev,
        { id: teamId, name: createName.trim(), members: [], expanded: true, loading: false },
      ]);
      setCreateName('');
      flashSuccess(`Team "${createName.trim()}" created successfully.`);
    } catch (err) {
      flashError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreating(false);
    }
  }, [createName]);

  // ── Load Team By ID (Join / Import) ────────────────────────────────────────

  const handleJoinTeam = useCallback(async () => {
    const id = joinTeamId.trim();
    if (!id) return;
    if (teams.some((t) => t.id === id)) {
      flashError('Team already added.');
      return;
    }
    setError(null);
    const stub: Team = { id, name: id.slice(0, 8) + '…', members: [], expanded: true, loading: true };
    setTeams((prev) => [...prev, stub]);
    try {
      const members = await listTeamMembers(id);
      setTeams((prev) =>
        prev.map((t) => (t.id === id ? { ...t, members, loading: false } : t)),
      );
      setJoinTeamId('');
      flashSuccess('Team loaded.');
    } catch (err) {
      setTeams((prev) => prev.filter((t) => t.id !== id));
      flashError(err instanceof Error ? err.message : String(err));
    }
  }, [joinTeamId, teams]);

  // ── Toggle Expand ──────────────────────────────────────────────────────────

  const toggleExpand = useCallback(async (teamId: string) => {
    setTeams((prev) =>
      prev.map((t) => {
        if (t.id !== teamId) return t;
        const willExpand = !t.expanded;
        if (willExpand && t.members.length === 0) {
          // Lazy-load members on first expand
          refreshMembers(teamId);
        }
        return { ...t, expanded: willExpand };
      }),
    );
  }, []);

  // ── Refresh Members ────────────────────────────────────────────────────────

  async function refreshMembers(teamId: string) {
    setTeams((prev) => prev.map((t) => (t.id === teamId ? { ...t, loading: true } : t)));
    try {
      const members = await listTeamMembers(teamId);
      setTeams((prev) => prev.map((t) => (t.id === teamId ? { ...t, members, loading: false } : t)));
    } catch (err) {
      setTeams((prev) => prev.map((t) => (t.id === teamId ? { ...t, loading: false } : t)));
      flashError(err instanceof Error ? err.message : String(err));
    }
  }

  // ── Add Member ─────────────────────────────────────────────────────────────

  async function handleAddMember(teamId: string) {
    const form = addMemberForms[teamId];
    if (!form?.accountId.trim()) return;
    setError(null);
    try {
      await addTeamMember(teamId, form.accountId.trim(), form.permission);
      // Refresh members list
      await refreshMembers(teamId);
      // Reset form
      setAddMemberForms((prev) => ({
        ...prev,
        [teamId]: { accountId: '', permission: 'read' },
      }));
      flashSuccess(`${form.accountId.trim()} added as ${form.permission}.`);
    } catch (err) {
      flashError(err instanceof Error ? err.message : String(err));
    }
  }

  // ── Remove Member ──────────────────────────────────────────────────────────

  async function handleRemoveMember(teamId: string, memberAccountId: string) {
    if (!confirm(`Remove "${memberAccountId}" from this team?`)) return;
    setError(null);
    try {
      await removeTeamMember(teamId, memberAccountId);
      setTeams((prev) =>
        prev.map((t) =>
          t.id === teamId
            ? { ...t, members: t.members.filter((m) => m.accountId !== memberAccountId) }
            : t,
        ),
      );
      flashSuccess(`${memberAccountId} removed.`);
    } catch (err) {
      flashError(err instanceof Error ? err.message : String(err));
    }
  }

  // ── Update Permission ──────────────────────────────────────────────────────

  async function handleUpdatePermission(teamId: string, memberAccountId: string, newPerm: Permission) {
    setError(null);
    try {
      await updateTeamPermission(teamId, memberAccountId, newPerm);
      setTeams((prev) =>
        prev.map((t) =>
          t.id === teamId
            ? {
                ...t,
                members: t.members.map((m) =>
                  m.accountId === memberAccountId ? { ...m, permission: newPerm } : m,
                ),
              }
            : t,
        ),
      );
      flashSuccess(`${memberAccountId} updated to ${newPerm}.`);
    } catch (err) {
      flashError(err instanceof Error ? err.message : String(err));
    }
  }

  // ── Remove Team (local only) ───────────────────────────────────────────────

  function handleDismissTeam(teamId: string) {
    setTeams((prev) => prev.filter((t) => t.id !== teamId));
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="animate-fade-in flex flex-col gap-6 overflow-y-auto flex-1 min-h-0 pr-1.5 pb-8 max-w-4xl">

      {/* ── Status Messages ─────────────────────────────────────────────────── */}
      {error && (
        <div className="bg-rose-950/20 border border-rose-900/30 rounded-lg p-3 text-xs text-rose-400 font-mono animate-fade-in">
          &times; {error}
        </div>
      )}
      {successMsg && (
        <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-3 text-xs text-emerald-400 font-mono animate-fade-in flex items-center gap-2">
          <span>✔</span> {successMsg}
        </div>
      )}

      {/* ── Create / Join Header ────────────────────────────────────────────── */}
      <Card>
        <CardHeader>
          <CardTitle>TEAM MANAGEMENT</CardTitle>
          <Badge variant="default" className="text-[9px] px-2 py-0.5 font-semibold">
            {teams.length} TEAM{teams.length !== 1 ? 'S' : ''}
          </Badge>
        </CardHeader>
        <CardContent className="flex flex-col gap-4 py-4">
          {/* Create new team */}
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              Create New Team
            </span>
            <div className="flex gap-2">
              <div className="flex-1 min-w-0">
                <Input
                  type="text"
                  placeholder="Team name (e.g. engineering-core)"
                  value={createName}
                  onChange={(e) => setCreateName(e.target.value)}
                />
              </div>
              <Button
                variant="default"
                size="sm"
                onClick={handleCreate}
                disabled={creating || !createName.trim()}
                className="shrink-0"
              >
                {creating ? (
                  <span className="flex items-center gap-1.5">
                    <span className="w-3 h-3 rounded-full border border-slate-950/20 border-t-slate-950 animate-spin" />
                    Creating…
                  </span>
                ) : (
                  '+ Create Team'
                )}
              </Button>
            </div>
          </div>

          {/* Join existing team by ID */}
          <div className="flex flex-col gap-1.5">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              Import Team by ID
            </span>
            <div className="flex gap-2">
              <div className="flex-1 min-w-0">
                <Input
                  type="text"
                  mono
                  placeholder="Paste team UUID"
                  value={joinTeamId}
                  onChange={(e) => setJoinTeamId(e.target.value)}
                />
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={handleJoinTeam}
                disabled={!joinTeamId.trim()}
                className="shrink-0"
              >
                Load Team
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* ── Teams List ──────────────────────────────────────────────────────── */}
      {teams.length === 0 ? (
        <EmptyTeams />
      ) : (
        teams.map((team) => (
          <TeamCard
            key={team.id}
            team={team}
            currentAccount={session.nearAccountId}
            addMemberForm={addMemberForms[team.id] || { accountId: '', permission: 'read' as Permission }}
            onToggleExpand={() => toggleExpand(team.id)}
            onDismiss={() => handleDismissTeam(team.id)}
            onRefresh={() => refreshMembers(team.id)}
            onAddMember={() => handleAddMember(team.id)}
            onRemoveMember={(acct) => handleRemoveMember(team.id, acct)}
            onUpdatePermission={(acct, perm) => handleUpdatePermission(team.id, acct, perm)}
            onFormChange={(patch) =>
              setAddMemberForms((prev) => ({
                ...prev,
                [team.id]: { ...(prev[team.id] || { accountId: '', permission: 'read' }), ...patch },
              }))
            }
          />
        ))
      )}
    </div>
  );
}

/* //////////////////////////////////////////////////////////////
                       SUB-COMPONENTS
////////////////////////////////////////////////////////////// */

// ── Empty State ──────────────────────────────────────────────────────────────

function EmptyTeams() {
  return (
    <Card>
      <CardContent className="py-16">
        <div className="flex flex-col items-center justify-center gap-4 text-slate-500 select-none">
          <span className="text-5xl">👥</span>
          <p className="text-xs font-semibold text-slate-400">No teams yet</p>
          <p className="text-[10px] text-slate-500 max-w-xs text-center leading-relaxed">
            Create a team to enable cryptographic key sharing with other NEAR accounts.
            Members gain encrypted access to shared vault entries based on their permission level.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Team Card ────────────────────────────────────────────────────────────────

interface TeamCardProps {
  team: Team;
  currentAccount: string;
  addMemberForm: { accountId: string; permission: Permission };
  onToggleExpand: () => void;
  onDismiss: () => void;
  onRefresh: () => void;
  onAddMember: () => void;
  onRemoveMember: (accountId: string) => void;
  onUpdatePermission: (accountId: string, perm: Permission) => void;
  onFormChange: (patch: Partial<{ accountId: string; permission: Permission }>) => void;
}

function TeamCard({
  team,
  currentAccount,
  addMemberForm,
  onToggleExpand,
  onDismiss,
  onRefresh,
  onAddMember,
  onRemoveMember,
  onUpdatePermission,
  onFormChange,
}: TeamCardProps) {
  const [showId, setShowId] = useState(false);

  return (
    <Card className="animate-fade-in transition-all duration-200">
      {/* Team Header */}
      <CardHeader className="py-2.5 cursor-pointer group" onClick={onToggleExpand}>
        <div className="flex items-center gap-3">
          <span className="text-sm select-none transition-transform duration-200" style={{
            display: 'inline-block',
            transform: team.expanded ? 'rotate(90deg)' : 'rotate(0deg)',
          }}>
            ▶
          </span>
          <CardTitle className="text-slate-200 text-xs font-bold tracking-wide">
            {team.name}
          </CardTitle>
          <Badge variant="secondary" className="text-[9px] px-2 py-0.5">
            {team.members.length} MEMBER{team.members.length !== 1 ? 'S' : ''}
          </Badge>
        </div>

        <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
          <Button
            variant="ghost"
            size="xs"
            onClick={() => setShowId(!showId)}
            title="Show Team ID"
          >
            🔑
          </Button>
          <Button variant="ghost" size="xs" onClick={onRefresh} title="Refresh Members">
            🔄
          </Button>
          <Button variant="destructive" size="xs" onClick={onDismiss} title="Dismiss Team">
            ✕
          </Button>
        </div>
      </CardHeader>

      {/* Team ID Reveal */}
      {showId && (
        <div className="px-4 py-2 bg-slate-950/50 border-b border-slate-800/60 flex items-center gap-2 animate-fade-in">
          <span className="text-[10px] text-slate-500 font-mono shrink-0">Team ID:</span>
          <span className="text-[10px] text-cyan-400 font-mono truncate select-all flex-1">{team.id}</span>
          <Button
            variant="ghost"
            size="xs"
            onClick={() => {
              navigator.clipboard.writeText(team.id);
            }}
          >
            Copy
          </Button>
        </div>
      )}

      {/* Expanded Content */}
      <div
        className="overflow-hidden transition-all duration-300 ease-in-out"
        style={{
          maxHeight: team.expanded ? '1000px' : '0px',
          opacity: team.expanded ? 1 : 0,
        }}
      >
        <CardContent className="flex flex-col gap-4 py-4">
          {/* Loading */}
          {team.loading && (
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono py-4 justify-center">
              <span className="w-4 h-4 rounded-full border border-slate-800 border-t-cyan-400 animate-spin" />
              Loading members…
            </div>
          )}

          {/* Members List */}
          {!team.loading && team.members.length === 0 && (
            <div className="text-center text-xs text-slate-500 py-4 select-none">
              No members yet. Add team members below.
            </div>
          )}

          {!team.loading && team.members.length > 0 && (
            <div className="flex flex-col gap-0.5">
              {team.members.map((member) => (
                <MemberRow
                  key={member.accountId}
                  member={member}
                  isCurrentUser={member.accountId === currentAccount}
                  onRemove={() => onRemoveMember(member.accountId)}
                  onUpdatePermission={(perm) => onUpdatePermission(member.accountId, perm)}
                />
              ))}
            </div>
          )}

          {/* Add Member Form */}
          <div className="border-t border-slate-800/60 pt-4 flex flex-col gap-2">
            <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider font-semibold">
              Add Member
            </span>
            <div className="flex gap-2 flex-wrap">
              <div className="flex-1 min-w-[200px]">
                <Input
                  type="text"
                  mono
                  placeholder="member.near"
                  value={addMemberForm.accountId}
                  onChange={(e) => onFormChange({ accountId: e.target.value })}
                />
              </div>
              <select
                className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-3 py-2 text-xs outline-none font-mono cursor-pointer hover:border-slate-700 transition-colors focus:border-cyan-500/55"
                value={addMemberForm.permission}
                onChange={(e) => onFormChange({ permission: e.target.value as Permission })}
              >
                {PERMISSION_OPTIONS.map((p) => (
                  <option key={p} value={p}>
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                  </option>
                ))}
              </select>
              <Button
                variant="default"
                size="sm"
                onClick={onAddMember}
                disabled={!addMemberForm.accountId.trim()}
              >
                + Add
              </Button>
            </div>
          </div>
        </CardContent>
      </div>
    </Card>
  );
}

// ── Member Row ───────────────────────────────────────────────────────────────

interface MemberRowProps {
  member: TeamMember;
  isCurrentUser: boolean;
  onRemove: () => void;
  onUpdatePermission: (perm: Permission) => void;
}

function MemberRow({ member, isCurrentUser, onRemove, onUpdatePermission }: MemberRowProps) {
  return (
    <div className="flex items-center justify-between px-4 py-2.5 rounded-lg hover:bg-slate-800/30 transition-colors group animate-fade-in">
      <div className="flex items-center gap-3 min-w-0 flex-1">
        {/* Avatar */}
        <div className="w-7 h-7 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-center text-[10px] font-mono font-bold text-cyan-400 select-none shrink-0 shadow-inner">
          {member.accountId.charAt(0).toUpperCase()}
        </div>
        {/* Account ID */}
        <span className="text-xs font-mono text-slate-200 truncate">
          {member.accountId}
          {isCurrentUser && (
            <span className="text-[9px] text-slate-500 ml-1.5">(you)</span>
          )}
        </span>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {/* Permission Badge / Selector */}
        <select
          className="bg-transparent border-0 text-[10px] font-mono font-semibold cursor-pointer outline-none uppercase tracking-wider px-1 py-0.5 rounded hover:bg-slate-800/50 transition-colors"
          style={{
            color:
              member.permission === 'admin'
                ? '#10b981'
                : member.permission === 'write'
                ? '#f59e0b'
                : '#22d3ee',
          }}
          value={member.permission}
          onChange={(e) => onUpdatePermission(e.target.value as Permission)}
        >
          {PERMISSION_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p.toUpperCase()}
            </option>
          ))}
        </select>

        {/* Joined date */}
        <span className="text-[9px] text-slate-600 font-mono hidden sm:inline">
          {new Date(member.joinedAt).toLocaleDateString()}
        </span>

        {/* Remove button */}
        <Button
          variant="destructive"
          size="xs"
          onClick={onRemove}
          className="opacity-0 group-hover:opacity-100 transition-opacity"
          title={`Remove ${member.accountId}`}
        >
          ✕
        </Button>
      </div>
    </div>
  );
}
