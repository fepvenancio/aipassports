-- D1 Database Schema for Aegis Gateway Users
CREATE TABLE IF NOT EXISTS users (
    near_account_id TEXT PRIMARY KEY,
    api_key TEXT UNIQUE NOT NULL,
    tee_endpoint TEXT NOT NULL,
    subscription_status TEXT DEFAULT 'free',
    storage_used_bytes INTEGER DEFAULT 0,
    storage_limit_bytes INTEGER DEFAULT 10485760, -- 10MB default
    created_at INTEGER NOT NULL
);

-- D1 Database Schema for Aegis Gateway Firewall Audit Logs
CREATE TABLE IF NOT EXISTS firewall_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    near_account_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    skill_name TEXT NOT NULL,
    destination TEXT NOT NULL,
    rule_triggered TEXT NOT NULL,
    marker_detected TEXT,
    FOREIGN KEY(near_account_id) REFERENCES users(near_account_id)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- NEAR-contract retirement (Phase 2.5, Step 1): mirror the on-chain team + pointer
-- index in D1 so the contract can be retired. ADDITIVE ONLY — nothing reads these
-- tables yet (Step 2 swaps the gateway's NEAR RPC reads over to them). Mirrors the
-- contract data model in backend/src/lib.rs (TeamMetadata, TeamMember, pointers).
-- ─────────────────────────────────────────────────────────────────────────────

-- Teams (was: contract TeamMetadata).
CREATE TABLE IF NOT EXISTS teams (
    team_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    creator_account_id TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Team members + permissions (was: contract TeamMember). Permission values are
-- lowercase to match the gateway's `Permission` type ("read" | "write" | "admin").
CREATE TABLE IF NOT EXISTS team_members (
    team_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    permission TEXT NOT NULL CHECK (permission IN ('read', 'write', 'admin')),
    added_by TEXT,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (team_id, account_id),
    FOREIGN KEY (team_id) REFERENCES teams(team_id)
);

-- Index for "is this account a member / what permission" lookups
-- (replaces the contract's is_team_member / get_team_member view calls).
CREATE INDEX IF NOT EXISTS idx_team_members_account ON team_members(account_id);

-- Pointer index (was: contract per-account and per-team wiki/skill pointers, keyed by
-- composite "{owner}:{identifier}"). owner_type distinguishes user vs team ownership.
CREATE TABLE IF NOT EXISTS pointers (
    owner_type TEXT NOT NULL CHECK (owner_type IN ('user', 'team')),
    owner_id TEXT NOT NULL,            -- account_id (user) or team_id (team)
    entry_type TEXT NOT NULL CHECK (entry_type IN ('wiki', 'skill')),
    identifier TEXT NOT NULL,          -- slug (wiki) or skill id
    blob_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (owner_type, owner_id, entry_type, identifier)
);

-- Index for enumerating an owner's entries of a given type.
CREATE INDEX IF NOT EXISTS idx_pointers_owner ON pointers(owner_type, owner_id, entry_type);

