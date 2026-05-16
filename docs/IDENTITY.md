# ID-002: Identity & Authentication Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Authentication Strategy

Project Aegis SHALL implement a passwordless, database-free authentication model. The client-side WebAuthn/Passkey ceremony produces a signed JWT assertion. The server validates this assertion — it does NOT perform WebAuthn verification itself.

## 2. Assertion Verification

### 2.1 JWT Structure
- The system MUST accept identity assertions in the form of JSON Web Tokens (JWT).
- JWTs SHOULD utilize the RS256, RS384, RS512, ES256, ES384, or ES512 signing algorithms.

### 2.2 Verification Logic
- The `JwtAssertionVerifier` MUST parse the JWT into Header, Payload, and Signature components (dot-separated Base64URL segments).
- The verifier MUST read the `alg` field from the JWT header and map it to a Node.js crypto hash algorithm via `_mapAlgToNodeCrypto()`.
- The verifier MUST reject JWTs with unsupported `alg` values by throwing `INFRA_ERROR_IDENTITY_UNSUPPORTED_ALG`.
- The verifier MUST check the `exp` (Expiration) claim. If the current time is greater than `exp`, the system MUST reject the assertion with `INFRA_ERROR_IDENTITY_TOKEN_EXPIRED`.
- Signature verification SHALL be performed using the native Node.js `crypto` module's `createVerify()`.

## 3. Session Management

- The system SHALL only "unlock" a user's vault and create a session upon successful identity assertion.
- Each successful `/auth/unlock` call MUST return a `sessionId` (UUID v4) that identifies the session.
- Sessions MUST be stored in a `SessionManager` with a configurable TTL (default: 1 hour).
- Sessions MUST be periodically swept for expiry (every 60 seconds).
- Failed assertions MUST result in an `UNAUTHORIZED_IDENTITY_ASSERTION_FAILED` (401) or `RATE_LIMIT_EXCEEDED` (429) response.
- The `/auth/unlock` endpoint MUST be rate-limited to 5 requests per minute per IP.

## 4. Access Enforcement

- The `/mcp/sse` and `/mcp/messages` endpoints MUST require a valid `x-session-id` header.
- Requests without a valid session MUST receive a 401 response.
- The `/health` endpoint MUST NOT require authentication.
- The `/auth/challenge` endpoint MUST NOT require authentication.