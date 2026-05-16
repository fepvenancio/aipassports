# ARCH-002: Architecture Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. System Overview

Project Aegis SHALL implement a Domain-Driven Design (DDD) architectural pattern. The system MUST maintain strict separation between Domain, Application, and Infrastructure layers.

## 2. Layering Constraints

### 2.1 Domain Layer (`src/Domain/`)
- The Domain layer MUST NOT have any dependencies on external frameworks or infrastructure-specific modules.
- Domain logic SHALL be implemented using pure ES Modules with private fields (`#`).
- Aggregates (`Vault`) MUST encapsulate business invariants and coordinate state transitions.
- Entities (`Skill`, `WikiPage`) MUST be identity-based with immutable value semantics.
- Value Objects (`EncryptedBlob`, `Credential`, `ComplianceRegistry`) MUST be immutable and validated on construction.
- `ComplianceRegistry` MUST use exact hostname matching via `new URL(url).hostname` — substring matching is PROHIBITED.

### 2.2 Application Layer (`src/Application/`)
- The Application layer SHALL coordinate domain objects and invoke infrastructure through Ports (Abstract Interfaces).
- Use Cases (`ExecuteToolUseCase`, `SyncVaultUseCase`) MUST represent distinct business operations.
- `SyncService` MUST support two strategies: immediate (fire-and-forget) and debounced (sliding-window, default 30s).
- `SyncService` MUST provide a `destroy()` method that clears all timers and pending state. Lifecycle management SHALL be owned by `main.js`, not by `SyncService` itself.
- `IVaultRepository` MUST be the sole interface for loading and persisting vaults per user.

### 2.3 Infrastructure Layer (`src/Infrastructure/`)
- All I/O operations (Filesystem, Network, Crypto) MUST be implemented in the Infrastructure layer.
- Infrastructure adapters MUST implement the corresponding Port interfaces defined in the Application layer.
- `AESGCMEngine` MUST validate the DEK parameter (if provided) is a 32-byte Buffer.
- `AESGCMEngine` MUST throw `INFRA_ERROR_KEY_DESTROYED` if `encrypt` or `decrypt` is called after `nuke()`.
- `JwtAssertionVerifier` MUST read the `alg` header from the JWT and reject unsupported algorithms.

## 3. Communication Protocol

### 3.1 Model Context Protocol (MCP)
- The system MUST expose capabilities via the Model Context Protocol (MCP) v1.0.
- Stdio transport SHALL use `StdioServerTransport`.
- HTTP transport SHALL use `StreamableHTTPServerTransport` (MCP SDK v1.29+).
- JSON-RPC 2.0 MUST be used for all MCP communication.

### 3.2 Session Management
- Each SSE connection MUST be associated with an authenticated session via `SessionManager`.
- Sessions MUST have a configurable TTL (default: 1 hour).
- Sessions MUST be evicted periodically (every 60 seconds).
- `SessionManager` MUST enforce a maximum session count (default: 1024).
- Each session MUST have its own `Vault` instance and its own `MCP.Server` instance.

## 4. Security Model

- The system SHALL follow a Zero-Trust architecture.
- All persistent data MUST be client-side encrypted using AES-256-GCM.
- Outbound LLM calls MUST pass through the ZDR compliance proxy.
- Rate limiting MUST be enforced: 5 requests/min on `/auth/unlock`, 100 requests/min on `/mcp/messages`.
- Security headers MUST be set: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`.
- Request body size MUST be limited to 100KB via `express.json({ limit: '100kb' })`.

## 5. Dependency Graph

```
main.js
├── Domain (Vault, Skill, WikiPage, ...)
├── Application
│   ├── Ports (ICryptoEngine, ISyncProvider, IIdentityVerifier, IOutboundProxy, IVaultRepository)
│   ├── Services (SyncService)
│   └── UseCases (ExecuteToolUseCase, SyncVaultUseCase)
└── Infrastructure
    ├── Crypto (AESGCMEngine, JwtAssertionVerifier)
    ├── Storage (LocalFileSystemAdapter, CloudflareR2Adapter, VaultRepository)
    └── Transport (McpStdioServer, McpSseServer, SessionManager, RateLimiter, ZdrProxyClient)
```

Domain MUST NOT import from Application or Infrastructure. Application MUST NOT import from Infrastructure (only Ports).