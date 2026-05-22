# ARCH-005: Architecture Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. System Overview

Project Aegis is a sovereign, decentralized AI memory and skill layer. It gives users a single, provider-agnostic context vault — wiki pages, skills, and preferences — that any AI tool supporting the Model Context Protocol (MCP) can read and write. All data is user-owned, hardware-encrypted, and stored on decentralized infrastructure. No AI company silos the user's data. No persistent centralized server holds content.

The system is composed of four distinct, independently deployable layers:

| Layer | Technology | Role |
|---|---|---|
| **Identity & Index** | NEAR Smart Contract (Rust, shared deployment) | Maps NEAR account IDs to per-entry Walrus blob pointers. The authoritative on-chain index. |
| **MCP Gateway** | Hono on Cloudflare Workers | Stateless MCP protocol bridge. Auth via NEAR signatures. Sessions in CF KV. Holds zero vault content. |
| **Compute & Encryption** | IronClaw Shade Agent (TEE) | Derives DEKs inside hardware enclave. Encrypts/decrypts vault entries. Executes LLM skill calls with ZDR enforcement. |
| **Blob Storage** | Walrus Protocol | Stores per-entry AES-256-GCM encrypted blobs addressed by `blobId`. Erasure-coded, decentralized. |

## 2. Key Management

### 2.1 IronClaw Agent Master Secret
- The IronClaw Shade Agent holds a 32-byte master secret sealed to the TEE's hardware attestation measurement (PCR registers / TDX MRTD).
- The master secret is generated on first agent boot by the TEE's internal CSPRNG, then sealed. It cannot be exported or read outside the enclave.
- The master secret persists across agent restarts on the same hardware with the same TEE measurement. A code change → new measurement → new secret → all existing blobs unrecoverable (crypto-shredding / GDPR Article 17).
- Planned key rotation: decrypt all blobs under old secret → re-encrypt under new secret → redeploy with new measurement. This is a migration, not an automatic operation.

### 2.2 Per-User DEK Derivation
- Each user's Data Encryption Key (DEK) MUST be derived inside the IronClaw agent via:
  ```
  DEK = HKDF-SHA256(
    ikm  = master_secret,          // 32 bytes
    salt = near_account_id_bytes,  // UTF-8 bytes of the user's NEAR account ID
    info = b"aipassport-dek-v1",   // 17 bytes, fixed
    len  = 32                      // output length in bytes
  )
  ```
- Same `(nearAccountId, masterSecret)` → always same DEK.
- Different `nearAccountId` values → different DEKs (HKDF guarantee).
- The DEK MUST NOT leave the TEE enclave in plaintext. It is derived on-demand per request and zeroed after use.

### 2.3 Content Integrity
- Before encrypting a vault entry, the agent MUST compute `SHA-256(plaintext_bytes)` (raw bytes, not hex string) and store the hex digest as `content_sha256` in the NEAR contract alongside the `blobId`.
- After decrypting a blob, the agent MUST recompute `SHA-256(decrypted_bytes)` and compare it byte-by-byte to the stored hex digest. A mismatch MUST abort the read with `VAULT_ERROR_INTEGRITY_MISMATCH`.
- Walrus `blobId` values are opaque addresses — they are NOT content hashes. The `content_sha256` field is the sole integrity verification mechanism.

## 3. Trust Model

It is critical to understand what each layer is trusted to see:

| Component | Sees Plaintext? | Trusted For |
|---|---|---|
| Cloudflare Workers (gateway) | **Yes — in transit** | Routing, session management. Cloudflare can observe plaintext content as it passes through. Considered trusted for transport, not storage. |
| IronClaw TEE Agent | **Yes — inside enclave** | Key derivation, encryption, decryption, ZDR enforcement. TEE hardware attestation is the trust root. |
| NEAR blockchain | **No** | Pointer index (blobId + hash only). All data is public — security relies on Walrus blobs being encrypted. |
| Walrus Protocol | **No** | Storing ciphertext blobs. Walrus never receives plaintext — blobs are pre-encrypted before upload. |

**Explicit guarantee:** No single external party (Cloudflare, NEAR, Walrus) holds both the ciphertext AND the decryption key. The IronClaw TEE holds the key; Walrus holds the ciphertext. The TEE hardware attestation provides the trust anchor.

**Non-guarantee:** Cloudflare CAN observe plaintext content in transit between the MCP client and the IronClaw agent (through the Workers gateway). This is an acceptable trade-off for the current product stage. A future upgrade could eliminate this by having MCP clients encrypt content directly to the IronClaw agent's TEE public key before sending.

## 4. Layering Constraints

### 4.1 NEAR Smart Contract (`backend/src/`)
- The contract is a **shared, single deployment** serving all users. See NEAR.md §2 for the architectural decision.
- The contract MUST store `VaultPointer` structs only — it MUST NOT store plaintext or encrypted vault content.
- Access control is enforced by composite key construction: `predecessor_account_id()` constructs the key prefix `{accountId}:` for all mutations. Users can only affect their own entries.
- `PanicOnDefault` MUST be derived — the contract MUST NOT be callable in an uninitialised state.
- The contract MUST be initialised with `new()` immediately after deployment via `with-init-call`. See DEPLOYMENT.md §2.

### 4.2 MCP Gateway (`gateway/src/`)
- The gateway MUST be stateless — it MUST NOT store vault content, encryption material, or NEAR keys (except the delegated function call access key in CF KV, see NEAR.md §7.4).
- Sessions MUST be stored in Cloudflare KV with a configurable TTL (default: 1 hour). Session records contain only `nearAccountId`, `createdAt`, `expiresAt`.
- The gateway MUST verify NEAR account signatures for all authenticated requests. Full protocol in IDENTITY.md §2.
- MCP tool execution (wiki/create, wiki/update, wiki/read, skill invocations) MUST be delegated to the IronClaw agent via its HTTP API. The gateway MUST NOT perform encryption, decryption, or LLM calls directly.
- Read operations (get_wiki_pointer, list_wiki_slugs) MUST use NEAR RPC view calls — no NEAR transaction signature required.
- Write operations (update_wiki_pointer, remove_wiki_pointer) MUST be submitted as NEAR transactions signed with the delegated function call access key.
- Rate limiting MUST be enforced: 5/min on `/auth/unlock`, 100/min on `/mcp/messages`, per IP.

### 4.3 IronClaw Agent (`agent/src/`)
- The agent MUST execute entirely within a hardware TEE (Intel TDX or NVIDIA Confidential Compute).
- All DEK derivation, encryption, and decryption MUST occur inside the enclave. These operations MUST NOT be offloaded to the gateway.
- The agent MUST enforce the ZDR firewall (FIREWALL.md) for ALL outbound LLM API calls.
- The agent MUST NOT expose the master secret, derived DEKs, or plaintext vault content via its HTTP API response bodies or logs.
- The agent MAY expose plaintext content to the gateway in its HTTP API response — this is necessary for the MCP client to receive the content. The trust model accepts Cloudflare can see this in transit.

### 4.4 Walrus Storage
- Each vault entry (wiki page, skill) MUST be stored as a separate encrypted blob on Walrus.
- Blobs MUST be AES-256-GCM encrypted with the per-user DEK before upload. The gateway MUST NOT upload unencrypted content to Walrus.
- The encrypted blob format MUST be `[12-byte IV][16-byte auth tag][ciphertext]` — see WALRUS.md §3.
- The `blobId` returned by Walrus and the `content_sha256` are written to the NEAR contract as two **sequential** network operations (NOT atomic). See SYNC.md §2 for orphaned blob handling.

## 5. MCP Tools

### 5.1 Built-in Tools
The gateway MUST expose the following built-in MCP tools regardless of vault contents:

| Tool | Parameters | Description |
|---|---|---|
| `wiki/create` | `slug` (required), `content` (required), `metadata` (optional) | Sends to agent for encryption + Walrus upload; gateway writes NEAR pointer. |
| `wiki/update` | `slug` (required), `content` (required), `metadata` (optional) | Re-encrypts and re-uploads blob; gateway updates NEAR pointer. |
| `wiki/read` | `slug` (required) | Gateway reads pointer from NEAR; agent fetches blob from Walrus and decrypts. |
| `skill/register` | `id` (required), `name` (required), `description` (required), `schema` (optional) | Encrypts skill config; gateway writes NEAR pointer. |
| `skill/remove` | `id` (required) | Gateway removes NEAR pointer. Walrus blob expires naturally. |

### 5.2 External Skills (Dynamic Tools)
- User-defined skills from the NEAR vault index MUST also be exposed as MCP tools.
- At session start, the gateway calls `list_skill_ids` via NEAR RPC view and registers each skill as an MCP tool.
- Skill invocations MUST route: gateway → IronClaw agent → (read skill config from Walrus) → ZDR firewall → LLM API.
- If the agent has no `LLM_ENDPOINT_URL` configured, skill invocations MUST return: `{ "error": "SKILL_ERROR_NO_LLM_CONFIGURED" }`.

### 5.3 Persistence Contract
- Any mutation tool MUST complete the full write path — agent encrypt → Walrus upload → NEAR pointer update — before returning success to the MCP client.
- Partial writes (Walrus upload succeeded, NEAR update failed) MUST be treated as failures and surfaced with `{ "error": "VAULT_ERROR_POINTER_UPDATE_FAILED", "blobId": "..." }` so the orphaned blob ID is visible for debugging.

### 5.4 MCP Resources
- Wiki pages MUST be exposed as `wiki://{slug}` MCP resources via `resources/list` and `resources/read`.
- Resource reads follow the identical code path as `wiki/read`.

## 6. Communication Protocol

### 6.1 MCP Transport
- The gateway MUST expose MCP capabilities via MCP v1.0 (JSON-RPC 2.0 framing).
- **SSE (primary)**: `StreamableHTTPServerTransport` over HTTPS. Client sends requests to `/mcp/messages`, receives events from `/mcp/sse`. Used by browser dashboard AND IDE clients.
- **stdio (future, local bridge)**: `StdioServerTransport` for a potential local CLI bridge. NOT the primary path and NOT deployed on Cloudflare Workers (Workers cannot run as a stdio process). The local bridge would forward to the cloud SSE gateway.

### 6.2 IDE Configuration (SSE Mode)
For Cursor/Claude Code/VS Code, users add the following to their MCP config:
```json
{
  "mcpServers": {
    "aegis": {
      "url": "https://aegis-gateway.<subdomain>.workers.dev/mcp/sse",
      "headers": {
        "x-session-id": "<sessionId from /auth/unlock>"
      }
    }
  }
}
```

### 6.3 Session Management
- Each authenticated connection MUST be associated with a session in Cloudflare KV.
- Session records: `{ nearAccountId, createdAt, expiresAt }` — no vault data.
- TTL: configurable via `SESSION_TTL_SECONDS` (default: 3600).
- `/mcp/sse` and `/mcp/messages` MUST require a valid `x-session-id` header.

## 7. Gateway–Agent HTTP API Protocol

The gateway communicates with the IronClaw agent over HTTPS. All requests MUST include `Authorization: Bearer {IRONCLAW_AGENT_API_KEY}` (the shared secret between gateway and agent).

### 7.1 Encrypt and Upload (write path)
```
POST {IRONCLAW_AGENT_URL}/vault/write
Authorization: Bearer {IRONCLAW_AGENT_API_KEY}
Content-Type: application/json

{
  "nearAccountId": "alice.near",
  "entryType": "wiki" | "skill",
  "slug": "my-notes",           // or "skillId" for skills
  "plaintext": "...",           // UTF-8 content to encrypt
  "metadata": {}                // optional, also encrypted
}

Response 200:
{
  "blobId": "abc123xyz...",
  "contentSha256": "deadbeef...64chars"
}

Response 4xx/5xx:
{
  "error": "AGENT_ERROR_CODE",
  "message": "Human-readable description"
}
```

### 7.2 Decrypt and Return (read path)
```
POST {IRONCLAW_AGENT_URL}/vault/read
Authorization: Bearer {IRONCLAW_AGENT_API_KEY}
Content-Type: application/json

{
  "nearAccountId": "alice.near",
  "blobId": "abc123xyz...",
  "contentSha256": "deadbeef...64chars"
}

Response 200:
{
  "plaintext": "...",
  "metadata": {}
}

Response 4xx/5xx:
{
  "error": "AGENT_ERROR_CODE",
  "message": "Human-readable description"
}
```

### 7.3 Execute Skill (LLM invocation path)
```
POST {IRONCLAW_AGENT_URL}/skills/execute
Authorization: Bearer {IRONCLAW_AGENT_API_KEY}
Content-Type: application/json

{
  "nearAccountId": "alice.near",
  "skillBlobId": "skill-blob-id...",
  "skillContentSha256": "...",
  "userInput": "..."
}

Response 200:
{
  "output": "..."
}
```

### 7.4 Agent Error Codes

| Error Code | Meaning |
|---|---|
| `AGENT_ERROR_DECRYPTION_FAILED` | AES-GCM auth tag verification failed |
| `AGENT_ERROR_INTEGRITY_MISMATCH` | SHA-256 mismatch after decryption |
| `AGENT_ERROR_WALRUS_DOWNLOAD_FAILED` | Blob not found or network error |
| `AGENT_ERROR_WALRUS_UPLOAD_FAILED` | Upload failed (insufficient WAL, network) |
| `AGENT_ERROR_ZDR_VIOLATION` | Outbound request blocked by ZDR firewall |
| `AGENT_ERROR_NO_LLM_CONFIGURED` | `LLM_ENDPOINT_URL` not set in agent env |

## 8. Security Model

- **Zero-Trust**: no component implicitly trusts another — every call is authenticated.
- **Gateway auth**: NEAR account signature verification for session creation.
- **Agent auth**: shared API key (`IRONCLAW_AGENT_API_KEY`) between gateway and agent.
- **Contract auth**: `predecessor_account_id()` — cryptographically enforced by NEAR protocol.
- **Rate limiting**: 5/min on `/auth/unlock`, 100/min on `/mcp/messages` (CF KV sliding window).
- **Security headers** (all gateway responses): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'`.
- **Request body limit**: 100 KB enforced at gateway middleware layer.

## 9. Runtime Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                          CLIENTS                                     │
│  Cursor / Claude Code / VS Code         Browser Dashboard            │
│  (SSE MCP over HTTPS, x-session-id)     (Vite React, SSE MCP)       │
└──────────────────┬──────────────────────────────────┬───────────────┘
                   │ HTTPS + MCP SSE                  │ HTTPS
                   ▼                                  ▼
┌─────────────────────────────────────────────────────────────────────┐
│              MCP GATEWAY  (Hono / Cloudflare Workers)                │
│  Stateless. Auth: NEAR Ed25519 signatures. Sessions: CF KV.          │
│  Reads NEAR index via RPC view calls (no key required).              │
│  Submits NEAR mutations via function call access key.                 │
│  Routes encrypt/decrypt/execute → IronClaw agent.                    │
│                                                                      │
│  /auth/challenge    /auth/unlock    /auth/logout                     │
│  /mcp/sse           /mcp/messages   /health                          │
└──────────────┬───────────────────────────────────┬──────────────────┘
               │ NEAR RPC (view calls, tx submit)   │ HTTPS + Bearer token
               ▼                                   ▼
┌──────────────────────┐             ┌──────────────────────────────┐
│  NEAR CONTRACT        │             │  IRONCLW SHADE AGENT         │
│  (Shared Vault Index) │             │  (IronClaw TEE Network)      │
│                       │             │                              │
│  AegisContract {      │◄────────────┤  Writes pointer after        │
│   wiki_pointers:      │  NEAR tx    │  successful Walrus upload    │
│    LookupMap<         │             │                              │
│     "alice:slug",     │             │  master_secret: sealed TEE   │
│     VaultPointer>     │             │  DEK: derived per-request    │
│   skill_pointers:     │             │  ZDR: enforced on LLM calls  │
│    LookupMap<...>     │             │                              │
│   wiki_slug_lists:    │             │  /vault/write                │
│    LookupMap<         │             │  /vault/read                 │
│     AccountId,        │             │  /skills/execute             │
│     Vec<String>>      │             └───────────────┬──────────────┘
│  }                    │                             │ Encrypted blobs
└──────────────────────┘                             ▼
                                       ┌──────────────────────────────┐
                                       │  WALRUS PROTOCOL              │
                                       │  (Decentralized Blob Storage) │
                                       │                              │
                                       │  Per-entry blobs:            │
                                       │  blobId → [IV|tag|ciphertext]│
                                       │  Erasure-coded, no plaintext │
                                       └──────────────────────────────┘
```

## 10. Dependency Graph

```
gateway/ (Hono on Cloudflare Workers — TypeScript)
├── middleware/
│   ├── auth.ts         (NearSignatureVerifier → @noble/ed25519 + NEAR RPC)
│   ├── rateLimit.ts    (sliding window via CF KV)
│   └── security.ts     (response headers, body size limit)
├── routes/
│   ├── auth.ts         (challenge/unlock/logout → CF KV: SESSIONS_KV, CHALLENGES_KV)
│   └── mcp.ts          (sse + messages → IronClawClient)
├── near/
│   └── rpc.ts          (view_access_keys, get_wiki_pointer, list_wiki_slugs → NEAR RPC)
└── agent/
    └── client.ts       (IronClawClient: /vault/write, /vault/read, /skills/execute)

backend/ (NEAR Smart Contract — Rust, near-sdk 5.6)
├── lib.rs              (AegisContract: #[near(contract_state)], #[init] new())
├── vault.rs            (VaultPointer struct, AegisContract mutations + views)
└── zdr_firewall.rs     (OutboundPayload, is_compliant — reference impl, ported to agent)

agent/ (IronClaw Shade Agent — Rust)
├── main.rs             (HTTP server, route handlers)
├── vault_writer.rs     (DEK derivation, AES-GCM encrypt, Walrus PUT)
├── vault_reader.rs     (Walrus GET, AES-GCM decrypt, SHA-256 verify)
├── skill_executor.rs   (skill config decrypt, ZDR enforce, LLM call)
├── zdr_firewall.rs     (ported from backend/src/zdr_firewall.rs)
└── key_derivation.rs   (HKDF-SHA256, master secret management)

frontend/ (Vite + React — TypeScript)
├── services/
│   ├── NearWalletService.ts    (@near-wallet-selector)
│   └── GatewayApiService.ts   (auth flow, MCP calls)
└── pages/
    ├── Dashboard.tsx           (wiki + skill management)
    └── Auth.tsx                (NEAR wallet connect + challenge-response)
```