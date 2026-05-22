# Project Aegis: The Sovereign AI Passport

[![Security: IronClaw TEE](https://img.shields.io/badge/Security-IronClaw_TEE-blueviolet)](docs/ARCH.md)
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
│       ├── lib.rs          # AegisContract entry point
│       ├── vault.rs        # VaultAggregate + VaultPointer
│       └── zdr_firewall.rs # ZDR compliance (ported to agent)
├── gateway/        # Hono MCP gateway (TypeScript, Cloudflare Workers)
├── agent/          # IronClaw Shade Agent (Rust, TEE)
├── frontend/       # Vite React dashboard
├── infra/          # Deployment manifests
└── docs/
    ├── ARCH.md         # System architecture & topology
    ├── IDENTITY.md     # NEAR signature auth & session management
    ├── SYNC.md         # Per-entry Walrus write/read path
    ├── FIREWALL.md     # ZDR enforcement & audit logging
    ├── DEPLOYMENT.md   # All four layers deployment guide
    ├── NEAR.md         # Smart contract spec & NEAR CLI reference
    └── WALRUS.md       # Blob storage spec & REST API
```

---

## Documentation

- [**Architecture**](docs/ARCH.md) — Four-layer topology, key management, MCP tool contract.
- [**Identity**](docs/IDENTITY.md) — NEAR signature auth, FastAuth, session management.
- [**Storage & Sync**](docs/SYNC.md) — Per-entry write/read path, blob format, key derivation.
- [**ZDR Firewall**](docs/FIREWALL.md) — Egress enforcement, payload scanning, audit logging.
- [**Deployment**](docs/DEPLOYMENT.md) — NEAR, Cloudflare Workers, IronClaw, Walrus setup.
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