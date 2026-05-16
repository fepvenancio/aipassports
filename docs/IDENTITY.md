# ID-001: Identity & Authentication Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Authentication Strategy

Project Aegis SHALL implement a passwordless, database-free authentication model based on WebAuthn/Passkeys.

## 2. Assertion Verification

### 2.1 JWT Structure
- The system MUST accept identity assertions in the form of JSON Web Tokens (JWT).
- JWTs SHOULD utilize the RS256 signing algorithm.

### 2.2 Verification Logic
- The `JwtAssertionVerifier` MUST parse the JWT into Header, Payload, and Signature components.
- The verifier MUST check the `exp` (Expiration) claim. If the current time is greater than `exp`, the system MUST reject the assertion.
- The verifier MUST determine the signing algorithm from the JWT `alg` header and reject unsupported algorithms.
- Signature verification SHALL be performed using the native Node.js `crypto` module.

## 3. Access Control

- The system SHALL only "unlock" the vault and initialize transport handlers upon a successful identity assertion.
- Failed assertions MUST result in an `UNAUTHORIZED_IDENTITY_ASSERTION_FAILED` error.
