# ARCH-003: Architecture Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. System Overview

Project Aegis SHALL implement a Domain-Driven Design (DDD) architectural pattern. The system MUST maintain strict separation between Domain, Application, and Infrastructure layers.

## 2. Key Management

### 2.1 Server Pepper
- A 32-byte server pepper SHALL be generated on first boot and stored at `~/.ai-passport/pepper.key`.
- In TEE deployment, the pepper SHALL be injected via the `PEPPER_KEY` environment variable (hex-encoded).
- Loss of the pepper SHALL render all encrypted data unrecoverable (crypto-shredding).

### 2.2 Per-User DEK Derivation
- Each user's Data Encryption Key (DEK) MUST be derived via `HKDF-SHA256(pepper, ownerId, 'aipassport-dek-v1', 32)`.
- The same `(ownerId, pepper)` pair MUST always produce the same DEK.
- Different `ownerId` values MUST produce different DEKs.
- The DEK is passed to `VaultRepository` and `SyncService` for per-user encryption.

### 2.3 Crypto-Shredding
- Calling `AESGCMEngine.nuke()` zero-fills the master key in memory.
- Deleting the pepper file has the same effect cryptographically — all data becomes unrecoverable.

## 3. Layering Constraints

### 3.1 Domain Layer (`src/Domain/`)
- The Domain layer MUST NOT have any dependencies on external frameworks or infrastructure-specific modules.
- Domain logic SHALL be implemented using pure ES Modules with private fields (`#`).
- `Vault` MUST support `addSkill`, `removeSkill`, `getSkill`, `createWikiPage`, `updateWikiPage`, `getWikiPage`, `ingestWikiPage`, `fromJSON`, `toJSON`.
- `ComplianceRegistry` MUST use exact hostname matching via `new URL(url).hostname` — substring matching is PROHIBITED.

### 3.2 Application Layer (`src/Application/`)
- `ExecuteToolUseCase` MUST route built-in skills (`wiki/create`, `wiki/update`, `wiki/read`, `skill/register`, `skill/remove`) directly and external skills through `SkillExecutor`.
- `SkillExecutor` MUST route LLM calls through `ZdrProxyClient.fetch()` — direct calls to LLM APIs are PROHIBITED.
- `SkillExecutor` MUST verify the LLM endpoint is in `ComplianceRegistry` before making the call.
- `SyncService` MUST NOT register its own process signal handlers. Lifecycle management SHALL be owned by `main.js`.

### 3.3 Infrastructure Layer (`src/Infrastructure/`)
- `AESGCMEngine` MUST validate DEK length (32 bytes) when provided and throw `INFRA_ERROR_INVALID_MASTER_KEY_SIZE_EXPECTED_32_BYTES` if invalid.
- `AESGCMEngine` MUST throw `INFRA_ERROR_KEY_DESTROYED` if `encrypt` or `decrypt` is called after `nuke()`.
- `KeyDerivation` MUST use `crypto.hkdfSync('sha256', pepper, ownerId, 'aipassport-dek-v1', 32)`.
- `JwtAssertionVerifier` MUST read the `alg` header from the JWT and reject unsupported algorithms.

## 4. MCP Tools

### 4.1 Built-in Tools
The server MUST expose the following built-in MCP tools regardless of vault contents:

| Tool | Parameters | Description |
|---|---|---|
| `wiki/create` | `slug` (required), `content` (required), `metadata` (optional) | Create a new wiki page |
| `wiki/update` | `slug` (required), `content` (required), `metadata` (optional) | Update an existing wiki page |
| `wiki/read` | `slug` (required) | Read a wiki page |
| `skill/register` | `id` (required), `name` (required), `description` (required), `schema` (optional) | Register a new skill |
| `skill/remove` | `id` (required) | Remove a skill |

### 4.2 External Skills
- User-defined skills from the vault MUST also be exposed as MCP tools.
- If `LLM_ENDPOINT_URL` is configured, skill invocations MUST route through `SkillExecutor` → `ZdrProxyClient`.
- If `LLM_ENDPOINT_URL` is NOT configured (local-only mode), skill invocations MUST return a placeholder response indicating no LLM routing is available.

### 4.3 Persistence
- Any mutation tool (`wiki/create`, `wiki/update`, `skill/register`, `skill/remove`) MUST trigger `SyncService.immediateSync()` after the operation completes.

## 5. Communication Protocol

### 5.1 Model Context Protocol (MCP)
- The system MUST expose capabilities via MCP v1.0.
- Stdio transport SHALL use `StdioServerTransport`.
- HTTP transport SHALL use `StreamableHTTPServerTransport` (MCP SDK v1.29+).

### 5.2 Session Management
- Each SSE connection MUST be associated with an authenticated session via `SessionManager`.
- Sessions MUST have a configurable TTL (default: 1 hour).
- Each session MUST have its own `Vault` instance and its own `MCP.Server` instance.

## 6. Security Model

- The system SHALL follow a Zero-Trust architecture.
- `ownerId` MUST be extracted from the JWT `sub` or `iss` claim. If neither is present, the request MUST be rejected with 401.
- Rate limiting MUST be enforced: 5/min on `/auth/unlock`, 100/min on `/mcp/messages`.
- Request body size MUST be limited to 100KB.

## 7. Dependency Graph

```
main.js
├── Domain (Vault, Skill, WikiPage, EncryptedBlob, ComplianceRegistry, Credential)
├── Application
│   ├── Ports (ICryptoEngine, ISyncProvider, IIdentityVerifier, IOutboundProxy, IVaultRepository)
│   ├── Services (SyncService, SkillExecutor)
│   └── UseCases (ExecuteToolUseCase, SyncVaultUseCase)
└── Infrastructure
    ├── Crypto (AESGCMEngine, KeyDerivation, JwtAssertionVerifier)
    ├── Storage (LocalFileSystemAdapter, CloudflareR2Adapter, VaultRepository)
    └── Transport (McpStdioServer, McpSseServer, SessionManager, RateLimiter, ZdrProxyClient)
```