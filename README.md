# Project Aegis: The Sovereign AI Passport

[![Security: IronClaw TEE](https://img.shields.io/badge/Security-IronClaw_TEE-blueviolet)](docs/simplified_arch.md)
[![Storage: Walrus Protocol](https://img.shields.io/badge/Storage-Walrus_Protocol-blue)](docs/WALRUS.md)
[![Identity: NEAR Protocol](https://img.shields.io/badge/Identity-NEAR_Protocol-green)](docs/NEAR.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-gray.svg)](LICENSE)

Project Aegis is a sovereign, decentralized AI memory and skill layer. It gives users one encrypted, user-owned context vault — wiki pages, skills, and preferences — accessible by every AI tool that supports the Model Context Protocol (MCP). No AI company owns your data. No monthly server bill.

---

## How It Works

```
Cursor / Claude Code / VS Code
        │ MCP (stdio or SSE)
        ▼
MCP Gateway (Hono / Cloudflare Workers)  ← stateless, holds no data
        │
        ├──► NEAR Contract     ← on-chain index: who owns what blob ID
        │
        └──► IronClaw TEE Agent ← hardware enclave: derives keys, decrypts, runs LLM
                    │
                    └──► Walrus Protocol ← per-entry encrypted blobs, decentralized storage
```

Your vault entries are encrypted inside a hardware TEE before they ever touch the network. The NEAR smart contract holds only a pointer index — blob IDs and content hashes, no content. The Walrus decentralized network stores the encrypted blobs. No single party has your data.

---

## Architecture

| Layer | Technology | Role |
|---|---|---|
| **Identity & Index** | NEAR Smart Contract (Rust) | Maps your NEAR account to per-entry Walrus blob pointers |
| **MCP Gateway** | Hono on Cloudflare Workers | Stateless MCP bridge. Holds zero vault data. |
| **Compute & Encryption** | IronClaw Shade Agent (TEE) | Derives DEKs, encrypts/decrypts, executes LLM skills with ZDR firewall |
| **Blob Storage** | Walrus Protocol | Per-entry AES-256-GCM encrypted blobs, erasure-coded |

### Team Data Flow

```
Team Collaboration Layer
        │
        ▼
NEAR Contract (Team Metadata)
        │
        ├──► Team Master Secret (Sealed in TEE)
        │
        └──► Team DEKs (Derived per-team)
                    │
                    ├──► Member DEKs (Per-user)
                    │
                    └──► Encrypted Team DEKs (Per-member)
                                │
                                └──► Team Vault Entries (Shared blobs)
```

### Key Properties

| Property | Implementation |
|---|---|
| **Encryption** | AES-256-GCM with per-user DEK derived via HKDF inside IronClaw TEE |
| **Crypto-shredding** | Revoking the agent master secret renders all blobs permanently unrecoverable (GDPR Art. 17) |
| **Identity** | NEAR account signatures — no passwords, no JWT, no database |
| **ZDR Firewall** | All LLM calls enforced inside TEE — only verified providers, ZDR headers injected |
| **Integrity** | SHA-256(plaintext) stored on NEAR; verified against decrypted output on every read |
| **Zero lock-in** | MCP-native. Works with Claude, Cursor, VS Code, and any MCP-compatible tool |
| **Rate limiting** | 5/min on `/auth/unlock`, 100/min on `/mcp/messages` (Cloudflare KV) |

---

## MCP Tools

Every AI tool that connects to Aegis gets these built-in tools plus any user-defined skills:

| Tool | Parameters | Description |
|---|---|---|
| `wiki/create` | `slug`, `content`, `metadata?` | Encrypt + upload entry to Walrus, write pointer to NEAR |
| `wiki/update` | `slug`, `content`, `metadata?` | Re-encrypt, re-upload, update NEAR pointer |
| `wiki/read` | `slug` | Fetch from Walrus, decrypt in TEE, return plaintext |
| `skill/register` | `id`, `name`, `description`, `schema?` | Register a skill pointer |
| `skill/remove` | `id` | Remove skill pointer from NEAR |

Wiki pages are also exposed as `wiki://{slug}` MCP resources.

---

## Team Support

Project Aegis now includes comprehensive team collaboration features, allowing multiple users to securely share vault entries and manage permissions.

### Team Functionality Overview

| Feature | Description |
|---|---|
| **Team Creation** | Create shared workspaces with unique team IDs |
| **Member Management** | Add/remove members with granular permissions |
| **Shared Vault** | Collaborative wiki entries accessible to team members |
| **Permission Levels** | Read, Write, and Admin roles for fine-grained access control |
| **Encryption Isolation** | Each team has unique encryption keys for security isolation |

### Creating a Team

```typescript
// MCP Tool Call
const teamId = "engineering-team";
const teamName = "Engineering Department";

const response = await mcp.tools.call("create_team", {
    teamId,
    name: teamName
});

// Returns: TeamMetadata with creation timestamp
```

### Adding Team Members

```typescript
// Add member with specific permission
const memberAccount = "alice.near";
const permission = "write"; // or "read", "admin"

const response = await mcp.tools.call("add_team_member", {
    teamId,
    accountId: memberAccount,
    permission
});
```

### Permission Levels

| Permission | Capabilities |
|---|---|
| **read** | View team wiki entries, list team members |
| **write** | Create/update team wiki entries, add members with read permission |
| **admin** | Full access including member management and team settings |

### Team Vault Operations

Team vault entries work like personal wiki entries but are accessible to authorized team members:

```typescript
// Write to team vault
const result = await mcp.tools.call("team_vault_write", {
    teamId: "engineering-team",
    slug: "architecture-decision",
    content: "# Architecture Decision Record...",
    metadata: { author: "alice.near", tags: ["architecture"] }
});

// Returns: { blobId, contentSha256 }

// Read from team vault
const content = await mcp.tools.call("team_vault_read", {
    teamId: "engineering-team",
    slug: "architecture-decision"
});

// Returns: { content, metadata }
```

### Team Management

```typescript
// List all team members
const members = await mcp.tools.call("list_team_members", {
    teamId: "engineering-team"
});

// Update member permission
const response = await mcp.tools.call("update_team_member_permission", {
    teamId: "engineering-team",
    accountId: "alice.near",
    permission: "admin"
});

// Remove team member
const response = await mcp.tools.call("remove_team_member", {
    teamId: "engineering-team",
    accountId: "alice.near"
});
```

### Example: Full Team Workflow

```typescript
// 1. Create team
const team = await mcp.tools.call("create_team", {
    teamId: "product-team",
    name: "Product Development"
});

// 2. Add team members
await mcp.tools.call("add_team_member", {
    teamId: "product-team",
    accountId: "bob.near",
    permission: "write"
});

await mcp.tools.call("add_team_member", {
    teamId: "product-team",
    accountId: "carol.near",
    permission: "read"
});

// 3. Collaborate on shared documents
await mcp.tools.call("team_vault_write", {
    teamId: "product-team",
    slug: "roadmap-q3",
    content: "# Q3 Roadmap..."
});

// 4. Read shared documents (any team member)
const roadmap = await mcp.tools.call("team_vault_read", {
    teamId: "product-team",
    slug: "roadmap-q3"
});
```

---

## Gateway Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/auth/challenge` | POST | None | Issue a single-use cryptographic nonce |
| `/auth/unlock` | POST | NEAR signature | Verify signature, create session in CF KV |
| `/auth/logout` | POST | Session | Invalidate session |
| `/mcp/sse` | GET | Session | Establish MCP streamable connection |
| `/mcp/messages` | POST | Session | Send JSON-RPC MCP messages |
| `/health` | GET | None | Health check |

---

## Repository Structure

```
aipassport/
├── backend/        # NEAR smart contract (Rust, near-sdk 5.6)
│   └── src/
│       ├── lib.rs          # AegisContract entry point + team methods
│       ├── vault.rs        # VaultAggregate + VaultPointer + team validation
│       └── zdr_firewall.rs # ZDR compliance (ported to agent)
├── gateway/        # Hono MCP gateway (TypeScript, Cloudflare Workers)
│   └── src/
│       ├── team_handlers.ts  # Team-specific MCP tool handlers
│       └── index.test.ts      # Integration tests including team auth
├── agent/          # IronClaw Shade Agent (Rust, TEE)
│   └── src/
│       ├── team_key_manager.rs # Team encryption key management
│       └── team_key_manager_tests.rs # Team key manager unit tests
├── frontend/       # Vite React dashboard
├── infra/          # Deployment manifests
└── docs/
    ├── simplified_arch.md # Simplified multi-tenant SaaS architecture
    ├── IDENTITY.md     # NEAR signature auth & session management
    ├── SYNC.md         # Per-entry Walrus write/read path
    ├── FIREWALL.md     # ZDR enforcement & audit logging
    ├── NEAR.md         # Smart contract spec & NEAR CLI reference
    └── WALRUS.md       # Blob storage spec & REST API
```

---

## Documentation

- [**Architecture**](docs/simplified_arch.md) — Simplified multi-tenant SaaS architecture.
- [**Identity**](docs/IDENTITY.md) — NEAR signature auth, FastAuth, session management.
- [**Storage & Sync**](docs/SYNC.md) — Per-entry write/read path, blob format, key derivation.
- [**ZDR Firewall**](docs/FIREWALL.md) — Egress enforcement, payload scanning, audit logging.
- [**NEAR Contract**](docs/NEAR.md) — On-chain data model, storage staking, CLI reference.
- [**Walrus Storage**](docs/WALRUS.md) — Blob architecture, encryption format, epoch lifecycle.

---

## Security

Project Aegis operates with a Zero-Trust posture across all layers:

- **All encryption happens inside a hardware TEE** (IronClaw, Intel TDX / NVIDIA Confidential Compute). Keys never exist outside the enclave.
- **All outbound LLM calls** pass through the ZDR firewall inside the TEE — only `api.openai.com`, `api.anthropic.com`, and `aiplatform.googleapis.com` are permitted.
- **NEAR contract enforces ownership** via `predecessor_account_id()` — no external auth layer can override this.
- **Content integrity** is verified on every read via `SHA-256(plaintext)` stored on-chain.
- **Crypto-shredding** (GDPR Article 17): revoking the agent master secret permanently destroys all user data without touching individual files.

---

*"Sovereignty through silicon physics."*