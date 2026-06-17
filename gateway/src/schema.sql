-- D1 Database Schema for Aegis Gateway Users
CREATE TABLE IF NOT EXISTS users (
    near_account_id TEXT PRIMARY KEY,
    api_key TEXT UNIQUE NOT NULL,
    tee_endpoint TEXT NOT NULL,
    subscription_status TEXT DEFAULT 'free',
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

