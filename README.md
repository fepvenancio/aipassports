# Project Aegis: The Sovereign AI Passport

[![Security: TEE-Shielded](https://img.shields.io/badge/Security-TEE--Shielded-blueviolet)](https://github.com/fepvenancio/aipassports)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture: DDD](https://img.shields.io/badge/Architecture-DDD-green)](docs/ARCH.md)

Project Aegis is a decoupled, provider-agnostic context layer that abstracts a user's long-term memory, skills, and configurations away from proprietary AI vendor silos. It establishes a hardware-enforced, zero-trust boundary for agentic intelligence.

---

## Architecture

Project Aegis is built on **Domain-Driven Design (DDD)** principles with strict layer isolation:

- **Domain Layer** — `Vault`, `Skill`, `WikiPage`, `EncryptedBlob`, `Credential`, `ComplianceRegistry`
- **Application Layer** — `SyncService`, `ExecuteToolUseCase`, `SyncVaultUseCase`; Ports (`ICryptoEngine`, `ISyncProvider`, `IIdentityVerifier`, `IOutboundProxy`, `IVaultRepository`)
- **Infrastructure Layer** — `AESGCMEngine`, `JwtAssertionVerifier`, `LocalFileSystemAdapter`, `CloudflareR2Adapter`, `VaultRepository`, `McpStdioServer`, `McpSseServer`, `ZdrProxyClient`, `SessionManager`, `RateLimiter`

### Key architectural properties

| Property | Implementation |
|---|---|
| State isolation | Each SSE session gets its own `Vault` and `MCP.Server` instance via `SessionManager` |
| Stateless domain | Domain objects (`Vault`, `Skill`, `WikiPage`) are pure ES modules with no I/O |
| ZDR firewall | All outbound requests pass through `ComplianceRegistry` — exact-hostname match only, unverified endpoints are dropped with 403 |
| Auth | JWT assertion verification with algorithm negotiation; session-based enforcement on all protected routes |
| Crypto | AES-256-GCM with optional per-operation DEK; master key zeroization (`nuke()`) for GDPR Article 17 |
| Sync | Immediate (fire-and-forget) + debounced (30s sliding window) with graceful shutdown flush |
| Rate limiting | Per-IP sliding window: 5/min on `/auth/unlock`, 100/min on `/mcp/messages` |

---

## Quick Start (Local Alpha)

### 1. Requirements
- Node.js 22+
- pnpm 10+

### 2. Installation
```bash
pnpm install
```

### 3. Running Stdio Server
```bash
pnpm start:stdio
# or: node src/main.js --transport=stdio
```

### 4. Running Streamable HTTP Gateway
```bash
pnpm start:sse
# or: node src/main.js --transport=sse
```

### 5. Running Tests
```bash
pnpm test                # All three suites
pnpm test:smoke          # Crypto round-trip + storage
pnpm test:debounce       # Sync sliding-window validation
pnpm test:firewall       # ZDR compliance audit
```

---

## Transport Modes

| Mode | Transport | Auth | Use Case |
|---|---|---|---|
| `stdio` | JSON-RPC 2.0 over stdin/stdout | None (local) | IDE integration (Cursor, VS Code) |
| `sse` | Streamable HTTP (MCP SDK v1.29+) | JWT assertion + session | Multi-user cloud deployment |

### SSE Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/auth/challenge` | POST | None | Generate WebAuthn challenge |
| `/auth/unlock` | POST | JWT | Authenticate and create session |
| `/mcp/sse` | GET | Session | Establish streamable connection |
| `/mcp/messages` | POST | Session | Send JSON-RPC messages |
| `/health` | GET | None | Health check (session count, uptime) |

---

## Configuration

| Environment Variable | Required | Description |
|---|---|---|
| `OWNER_ID` | No (stdio) | Vault owner identifier for local mode. Defaults to `local-user`. |
| `R2_ACCOUNT_ID` | SSE only | Cloudflare R2 account ID. Switches storage from local filesystem to R2. |
| `R2_ACCESS_KEY_ID` | SSE + R2 | R2 access key. |
| `R2_SECRET_ACCESS_KEY` | SSE + R2 | R2 secret key. |
| `R2_BUCKET_NAME` | SSE + R2 | R2 bucket name. |
| `CORS_ORIGINS` | No | Comma-seperated list of allowed origins for SSE mode. |
| `LOCAL_VAULT_PATH` | No | Override local storage path. Defaults to `~/.ai-passport`. |

---

## Documentation

Detailed technical specifications following **RFC 2119** are in the `/docs` directory:

- [**Architecture Overview**](docs/ARCH.md) — System-wide design and layer boundaries.
- [**Identity Specification**](docs/IDENTITY.md) — JWT assertion verification and session management.
- [**Sync Engine Specification**](docs/SYNC.md) — Hybrid write-behind and debounce strategies.
- [**Firewall Specification**](docs/FIREWALL.md) — ZDR enforcement and compliance registry.
- [**Deployment Specification**](docs/DEPLOYMENT.md) — TEE staging, TCB measurement, and Docker.

---

## Security

Project Aegis assumes a **Zero-Trust** posture:

- All stored data is encrypted client-side using **AES-256-GCM** with authenticated encryption.
- All outbound LLM traffic passes through the **ZDR Firewall** — only whitelisted exact hostnames are allowed.
- The `ComplianceRegistry` uses **exact hostname matching** — substring spoofing is blocked.
- Master key can be cryptographically shredded (`nuke()`) for GDPR Article 17 compliance.
- Session management enforces 1-hour TTL with periodic eviction.
- Rate limiting prevents brute-force auth attempts (5/min).

---

*“Sovereignty through silicon physics.”*