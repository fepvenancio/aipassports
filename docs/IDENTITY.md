# ID-005: Identity & Authentication Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Authentication Strategy

Project Aegis SHALL implement a passwordless, database-free authentication model built on NEAR Protocol account cryptography. A user's identity IS their NEAR account — a cryptographic key pair managed by their wallet or FastAuth. The gateway verifies a signed challenge to establish a session. No username/password database exists anywhere in the system.

### 1.1 Identity Layers

| User Type | Onboarding Flow | Identity Primitive |
|---|---|---|
| Developer / CLI | `near-cli` account or NEAR wallet (MyNearWallet, Meteor) | Ed25519 keypair, self-custodied |
| Non-technical user | FastAuth (email + device passkey) | MPC-backed NEAR account, no seed phrase required |

FastAuth wraps a NEAR account behind an email address and device passkey. From the protocol's perspective, both flows produce the same thing: a valid `nearAccountId` (e.g., `alice.near`) with a corresponding Ed25519 signing key. The gateway treats them identically.

### 1.2 Transport Mode and Auth Scope

| Mode | Transport | Auth Required | Use Case |
|---|---|---|---|
| SSE (cloud) | HTTPS + MCP SSE | NEAR signature + session | Browser dashboard, IDE via cloud gateway |
| stdio (local bridge) | JSON-RPC 2.0 over stdin/stdout | None (local process, user-trusted) | Future local CLI; NOT the primary path |

**Primary transport is SSE.** Modern MCP clients (Cursor, Claude Code, VS Code Copilot Chat) support connecting to an HTTPS MCP SSE endpoint directly. No local stdio binary is needed. Users configure their IDE to point at `https://aegis-gateway.<subdomain>.workers.dev/mcp/sse` with the session token in the header.

## 2. Signature-Based Verification

### 2.1 Challenge-Response Flow

```
Client                          Gateway                     NEAR RPC
  │                               │                             │
  │  POST /auth/challenge          │                             │
  │──────────────────────────────►│                             │
  │  ← { nonce: base64url(32B) }  │                             │
  │                               │                             │
  │  [sign nonce with NEAR key]   │                             │
  │                               │                             │
  │  POST /auth/unlock             │                             │
  │  { nearAccountId,             │                             │
  │    publicKey,                 │                             │
  │    signature: base64url }     │                             │
  │──────────────────────────────►│                             │
  │                               │  view_access_keys(accountId)│
  │                               │────────────────────────────►│
  │                               │  ← [{ public_key, ... }]   │
  │                               │                             │
  │                               │  [verify Ed25519 signature] │
  │                               │                             │
  │  ← { sessionId: uuid-v4 }     │                             │
  │                               │                             │
```

### 2.2 Exact Signed Message Format

The signature MUST be computed over the following exact byte sequence:

```
signed_bytes = nonce_bytes (raw 32 bytes, NOT base64-encoded)
```

- The gateway issues the nonce as Base64URL for transport.
- The client MUST decode the Base64URL nonce back to its raw 32 bytes before signing.
- The Ed25519 signature is computed over these 32 raw bytes — no hashing, no wrapping, no JSON encoding.
- This matches how NEAR's native `SignMessage` works for off-chain challenges.
- The signature MUST be returned as Base64URL in the `/auth/unlock` request body.

**Client-side signing (TypeScript example using NEAR Wallet Selector):**
```typescript
// nonce is the base64url string from /auth/challenge
const nonceBytes = Buffer.from(nonce, 'base64url');  // 32 bytes
// keyPair is the user's Ed25519 key from NEAR Wallet Selector
const { signature } = keyPair.sign(nonceBytes);
const signatureBase64 = Buffer.from(signature).toString('base64url');
```

**Verification (gateway side, TypeScript using @noble/ed25519):**
```typescript
import { verify } from '@noble/ed25519';
const nonceBytes = Buffer.from(storedNonce, 'base64url');           // 32 raw bytes
const sigBytes   = Buffer.from(req.body.signature, 'base64url');    // 64 bytes
const pubKeyBytes = Buffer.from(req.body.publicKey.replace('ed25519:', ''), 'base64'); // 32 bytes
const isValid = await verify(sigBytes, nonceBytes, pubKeyBytes);
```

### 2.3 Challenge Requirements
- Challenges MUST be generated using the Web Crypto API: `crypto.getRandomValues(new Uint8Array(32))`.
- Challenges MUST be exactly 32 bytes, encoded as Base64URL for transport.
- Challenges MUST be stored in Cloudflare KV with key `challenge:{nonce_base64url}` and a TTL of 60 seconds (env: `AUTH_CHALLENGE_TTL_SECONDS`, default: `60`).
- Challenges MUST be single-use: the gateway MUST delete the challenge from KV immediately upon first consumption, whether verification succeeds or fails. Deletion is unconditional.
- Replay of a consumed challenge MUST be rejected with HTTP 401 `{ "error": "CHALLENGE_ALREADY_USED" }`.

### 2.4 Signature Verification Requirements
- The gateway MUST fetch the account's active access keys from NEAR RPC:
  ```
  POST {NEAR_RPC_URL}
  { "jsonrpc": "2.0", "method": "query",
    "params": { "request_type": "view_access_keys", "finality": "final", "account_id": "{nearAccountId}" },
    "id": 1 }
  ```
- The returned key list contains objects with `public_key` in format `"ed25519:{base64_pubkey}"`.
- The gateway MUST verify that `req.body.publicKey` exactly matches one of the returned keys.
- Signature verification MUST use Ed25519 (library: `@noble/ed25519` — pure TypeScript, no Node.js crypto dependency, compatible with Cloudflare Workers).
- If the NEAR account does not exist, NEAR RPC returns an error — reject with HTTP 401 `{ "error": "NEAR_ACCOUNT_NOT_FOUND" }`.
- If the public key is not in the account's key set, reject with HTTP 401 `{ "error": "PUBLIC_KEY_NOT_REGISTERED" }`.
- If the signature is invalid, reject with HTTP 401 `{ "error": "INVALID_SIGNATURE" }`.
- The `nearAccountId` from the verified challenge BECOMES the `ownerId` used for all session operations. It MUST NOT be substituted or defaulted.

## 3. Session Management

- Each successful `/auth/unlock` MUST return `{ "sessionId": "<uuid-v4>", "expiresAt": <unix_ms> }`.
- Sessions MUST be stored in Cloudflare KV under key `session:{sessionId}`.
- Session record schema:
  ```json
  {
    "nearAccountId": "alice.near",
    "createdAt": 1716000000000,
    "expiresAt": 1716003600000
  }
  ```
- Session TTL MUST be configurable (env: `SESSION_TTL_SECONDS`, default: `3600`).
- Cloudflare KV's native TTL (the `expirationTtl` option on `kv.put()`) MUST be used for automatic expiry — no manual sweep is needed.
- `/mcp/sse` and `/mcp/messages` MUST require a valid `x-session-id` header.
- Missing session: HTTP 401 `{ "error": "SESSION_MISSING" }`.
- Expired session: HTTP 401 `{ "error": "SESSION_EXPIRED" }`.

## 4. Gateway Auth Endpoints

| Endpoint | Method | Auth | Request Body | Response |
|---|---|---|---|---|
| `/auth/challenge` | POST | None | `{}` | `{ "nonce": "<base64url_32B>" }` |
| `/auth/unlock` | POST | None | `{ nearAccountId, publicKey, signature }` | `{ sessionId, expiresAt }` |
| `/auth/logout` | POST | Session header | `{}` | `{ "ok": true }` |

## 5. On-Chain Identity Enforcement (Redundant Layer)

The NEAR smart contract enforces ownership independently from the gateway:
- `env::predecessor_account_id()` in the contract equals the NEAR account that cryptographically signed the transaction.
- This is enforced by the NEAR protocol itself — no middleware can fake it.
- **Implication:** Even if the gateway is compromised, an attacker cannot write to another user's vault entries without that user's NEAR private key OR a valid function call access key granted by that user.
- The gateway auth (challenge-response) and the NEAR contract auth (transaction signing) are two independent layers. Both must pass for a mutation to succeed.

## 6. Function Call Key Delegation

For MCP flows (Cursor, Claude Code), the gateway submits NEAR transactions on the user's behalf using NEAR's native Function Call Access Keys. Full specification in [NEAR.md §7](NEAR.md).

**Summary for implementation:**
1. During dashboard onboarding, the user's NEAR wallet creates a function call access key scoped to the Aegis contract's mutation methods.
2. The gateway holds the corresponding private key in Cloudflare Workers secrets (one shared gateway key — users register THIS specific public key during onboarding).
3. At session creation, the gateway confirms the function call key exists on the user's NEAR account by checking the `view_access_keys` response for the gateway's public key.
4. If the function call key is NOT found, the gateway flags `"delegationRequired": true` in the session response — the client MUST prompt the user to grant delegation via the dashboard before MCP mutations will work.
5. Read operations (wiki/read, list) work without delegation — they use NEAR RPC view calls which require no signature.

## 7. Key Derivation (Inside TEE — Reference Only)

The per-user DEK is derived exclusively inside the IronClaw Shade Agent:
- `DEK = HKDF-SHA256(master_secret, near_account_id_bytes, info: b"aipassport-dek-v1", length: 32)`
- The `nearAccountId` string is UTF-8 encoded to bytes and used as the HKDF salt.
- The master secret MUST be sealed to the TEE hardware attestation — it is inaccessible outside the enclave.
- The DEK is derived on-demand per request and zeroed after use. It is never cached, logged, or transmitted.
- The gateway does NOT derive or hold DEKs. This section is informational for protocol verification.

## 8. Error Code Registry (Auth Layer)

| HTTP Status | Error Code | Meaning |
|---|---|---|
| 401 | `CHALLENGE_NOT_FOUND` | Nonce not in KV (expired or never issued) |
| 401 | `CHALLENGE_ALREADY_USED` | Nonce was already consumed |
| 401 | `NEAR_ACCOUNT_NOT_FOUND` | Account does not exist on NEAR |
| 401 | `PUBLIC_KEY_NOT_REGISTERED` | Provided public key not on the account |
| 401 | `INVALID_SIGNATURE` | Ed25519 signature verification failed |
| 401 | `SESSION_MISSING` | `x-session-id` header absent |
| 401 | `SESSION_EXPIRED` | Session TTL elapsed |
| 401 | `DELEGATION_REVOKED` | Function call key no longer on user's account |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests (see FIREWALL.md §6) |