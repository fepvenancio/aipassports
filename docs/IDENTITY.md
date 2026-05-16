# ID-003: Identity & Authentication Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Authentication Strategy

Project Aegis SHALL implement a passwordless, database-free authentication model. The client-side WebAuthn/Passkey ceremony produces a signed JWT assertion. The server validates this assertion — it does NOT perform WebAuthn verification itself.

## 2. Assertion Verification

### 2.1 JWT Structure
- The system MUST accept identity assertions in the form of JSON Web Tokens (JWT).
- JWTs SHOULD utilize the RS256, RS384, RS512, ES256, ES384, or ES512 signing algorithms.

### 2.2 Verification Logic
- The `JwtAssertionVerifier` MUST parse the JWT into Header, Payload, and Signature components.
- The verifier MUST read the `alg` field from the JWT header and validate it against supported algorithms via `_mapAlgToNodeCrypto()`.
- The verifier MUST reject JWTs with unsupported `alg` values.
- The verifier MUST check the `exp` claim. If expired, the request MUST be rejected.
- Signature verification SHALL be performed using the native Node.js `crypto` module.

### 2.3 Owner Identity
- The `ownerId` MUST be extracted from the JWT `sub` claim, falling back to `iss`.
- If neither `sub` nor `iss` is present, the request MUST be rejected with 401 and `INVALID_TOKEN: missing sub or iss claim`.
- The `ownerId` MUST NOT default to `'unknown'` or any other fallback value.

## 3. Session Management

- Each successful `/auth/unlock` MUST return a `sessionId` (UUID v4).
- Sessions MUST be stored in `SessionManager` with a configurable TTL (default: 1 hour).
- Sessions MUST be periodically swept for expiry (every 60 seconds).
- `/mcp/sse` and `/mcp/messages` MUST require a valid `x-session-id` header.

## 4. Challenge Generation

- The `/auth/challenge` endpoint MUST generate a cryptographically random 32-byte challenge encoded as Base64URL.
- The endpoint MUST NOT return mock or placeholder data.
- The challenge MUST have a configurable timeout (default: 60 seconds).

## 5. Key Derivation

- The per-user DEK MUST be derived via `HKDF-SHA256(pepper, ownerId, 'aipassport-dek-v1', 32)`.
- The pepper MUST be loaded from `~/.ai-passport/pepper.key` (local) or `PEPPER_KEY` env var (TEE).
- If no pepper exists, a new 32-byte pepper MUST be generated and persisted.