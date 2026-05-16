# Project Aegis: The Sovereign AI Passport

[![Security: TEE-Shielded](https://img.shields.io/badge/Security-TEE--Shielded-blueviolet)](https://github.com/fepvenancio/aipassports)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Architecture: DDD](https://img.shields.io/badge/Architecture-DDD-green)](docs/ARCH.md)

Project Aegis is a decoupled, provider-agnostic context layer that abstracts a user's long-term memory, skills, and configurations away from proprietary AI vendor silos. It establishes a hardware-enforced, zero-trust boundary for agentic intelligence.

---

## Architecture

Project Aegis is built on **Domain-Driven Design (DDD)** principles with strict layer isolation:

- **Domain Layer** — `Vault`, `Skill`, `WikiPage`, `EncryptedBlob`, `Credential`, `ComplianceRegistry`
- **Application Layer** — `SyncService`, `ExecuteToolUseCase`, `SyncVaultUseCase`, `SkillExecutor`; Ports (`ICryptoEngine`, `ISyncProvider`, `IIdentityVerifier`, `IOutboundProxy`, `IVaultRepository`)
- **Infrastructure Layer** — `AESGCMEngine`, `KeyDerivation`, `JwtAssertionVerifier`, `LocalFileSystemAdapter`, `CloudflareR2Adapter`, `VaultRepository`, `McpStdioServer`, `McpSseServer`, `ZdrProxyClient`, `SessionManager`, `RateLimiter`

### Key architectural properties

| Property | Implementation |
|---|---|
| **Persistent encryption** | Per-user DEK derived via HKDF from server pepper + ownerId. Same user on same server = same DEK every boot. |
| **State isolation** | Each SSE session gets its own `Vault` and `MCP.Server` instance via `SessionManager` |
| **Write-back MCP tools** | `wiki/create`, `wiki/update`, `wiki/read`, `skill/register`, `skill/remove` — vault is fully writable over MCP |
| **LLM execution** | Skill calls route through `ZdrProxyClient` → `ComplianceRegistry` to verified LLM endpoints |
| **ZDR firewall** | All outbound requests pass through `ComplianceRegistry` — exact-hostname match only |
| **Auth** | JWT assertion verification with algorithm negotiation; session-based enforcement on all protected routes |
| **Crypto** | AES-256-GCM with per-user DEK; master key zeroization (`nuke()`) for GDPR Article 17 |
| **Sync** | Immediate (fire-and-forget) + debounced (30s sliding window) with graceful shutdown flush |
| **Rate limiting** | Per-IP sliding window: 5/min on `/auth/unlock`, 100/min on `/mcp/messages` |

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

## MCP Tools

The server exposes built-in management tools plus any user-defined skills:

### Built-in Tools

| Tool | Description |
|---|---|
| `wiki/create` | Create a new wiki page (`slug`, `content`, optional `metadata`) |
| `wiki/update` | Update an existing wiki page (`slug`, `content`, optional `metadata`) |
| `wiki/read` | Read a wiki page by slug |
| `skill/register` | Register a new skill (`id`, `name`, `description`, optional `schema`) |
| `skill/remove` | Remove a skill by ID |

### User-Defined Skills

Skills defined in the vault are also exposed as MCP tools. If `LLM_ENDPOINT_URL` is configured, skill invocations route through the ZDR proxy to the configured LLM endpoint.

### MCP Resources

Wiki pages are exposed as `wiki://{slug}` resources for reading via `resources/list` and `resources/read`.

---

## Key Management

**Critical**: The server uses an HKDF-derived per-user Data Encryption Key (DEK).

1. On first boot, a 32-byte server pepper is generated and stored at `~/.ai-passport/pepper.key` (or `PEPPER_KEY` env var for TEE deployment).
2. Each user's DEK is derived via `HKDF-SHA256(pepper, ownerId, "aipassport-dek-v1", 32)`.
3. Same user + same server = same DEK. Data encrypted on boot N is decryptable on boot N+1.
4. On TEE deployment, set `PEPPER_KEY` as a secure environment variable. Loss of the pepper = loss of all encrypted data.

**For the crypto-shredding use case (GDPR Article 17)**: deleting the pepper renders all user data cryptographically unrecoverable. No per-file deletion needed.

---

## Transport Modes

| Mode | Transport | Auth | Use Case |
|---|---|---|---|
| `stdio` | JSON-RPC 2.0 over stdin/stdout | None (local) | IDE integration (Cursor, VS Code, Claude Code) |
| `sse` | Streamable HTTP (MCP SDK v1.29+) | JWT assertion + session | Multi-user cloud deployment |

### SSE Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/auth/challenge` | POST | None | Generate cryptographic challenge |
| `/auth/unlock` | POST | JWT | Authenticate and create session |
| `/mcp/sse` | GET | Session | Establish streamable connection |
| `/mcp/messages` | POST | Session | Send JSON-RPC messages |
| `/health` | GET | None | Health check (session count, uptime) |

---

## Configuration

| Environment Variable | Required | Description |
|---|---|---|
| `OWNER_ID` | No (stdio) | Vault owner ID for local mode. Defaults to `local-user`. |
| `PEPPER_KEY` | No | Hex-encoded 32-byte server pepper. If not set, auto-generated and stored at `~/.ai-passport/pepper.key`. |
| `LLM_ENDPOINT_URL` | No | LLM API endpoint for skill execution. Must be a ZDR-verified hostname. Defaults to `https://api.openai.com/v1/chat/completions`. |
| `LLM_MODEL` | No | Model name for LLM calls. Defaults to `gpt-4o-mini`. |
| `LLM_MAX_TOKENS` | No | Max response tokens. Defaults to `1024`. |
| `R2_ACCOUNT_ID` | SSE only | Cloudflare R2 account ID. Switches storage from local to R2. |
| `R2_ACCESS_KEY_ID` | SSE + R2 | R2 access key. |
| `R2_SECRET_ACCESS_KEY` | SSE + R2 | R2 secret key. |
| `R2_BUCKET_NAME` | SSE + R2 | R2 bucket name. |
| `CORS_ORIGINS` | No | Comma-separated allowed origins for SSE mode. |
| `LOCAL_VAULT_PATH` | No | Override local storage path. Defaults to `~/.ai-passport`. |

---

## Documentation

- [**Architecture Overview**](docs/ARCH.md) — System-wide design and layer boundaries.
- [**Identity Specification**](docs/IDENTITY.md) — JWT assertion verification and session management.
- [**Sync Engine Specification**](docs/SYNC.md) — Hybrid write-behind and debounce strategies.
- [**Firewall Specification**](docs/FIREWALL.md) — ZDR enforcement and compliance registry.
- [**Deployment Specification**](docs/DEPLOYMENT.md) — TEE staging, TCB measurement, and Docker.

---

## Security

Project Aegis assumes a **Zero-Trust** posture:

- All stored data is encrypted using **AES-256-GCM** with per-user HKDF-derived DEKs.
- All outbound LLM traffic passes through the **ZDR Firewall** — only `api.openai.com`, `api.anthropic.com`, and `aiplatform.googleapis.com` are whitelisted via exact hostname match.
- Master key can be cryptographically shredded (`nuke()`) for GDPR Article 17 compliance. Deletion of the pepper file has the same effect.
- Sessions expire after 1 hour with 60-second periodic cleanup.
- Rate limiting: 5/min on `/auth/unlock`, 100/min on `/mcp/messages`.

---

*“Sovereignty through silicon physics.”*