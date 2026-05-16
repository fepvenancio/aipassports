# DEPLOY-003: Confidential Deployment Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Runtime Environment

Project Aegis SHALL be deployed within a serverless Trusted Execution Environment (TEE) (e.g., Azure ACI with AMD SEV-SNP).

## 2. Key Management in Production

### 2.1 Pepper Injection
- In TEE deployment, the `PEPPER_KEY` environment variable MUST be set as a hex-encoded 32-byte value.
- The pepper MUST be injected as a `secureValue` parameter in the deployment manifest, decryptable only within the hardware enclave after successful attestation.
- The `~/.ai-passport/pepper.key` file MUST NOT be used in production — always use `PEPPER_KEY` env var.

### 2.2 Crypto-Shredding
- Deleting the `PEPPER_KEY` (or revoking the secureValue) SHALL render all user data cryptographically unrecoverable.
- `AESGCMEngine.nuke()` zero-fills the in-memory master key as defense-in-depth.

## 3. Environment Variables

| Variable | Mode | Description |
|---|---|---|
| `PEPPER_KEY` | All | Hex-encoded 32-byte server pepper (required for persistence across restarts) |
| `LLM_ENDPOINT_URL` | All | LLM API endpoint (must be ZDR-verified) |
| `LLM_MODEL` | All | Model name (default: `gpt-4o-mini`) |
| `LLM_MAX_TOKENS` | All | Max response tokens (default: `1024`) |
| `OWNER_ID` | stdio | Vault owner for local mode (default: `local-user`) |
| `R2_ACCOUNT_ID` | SSE | Cloudflare R2 account ID |
| `R2_ACCESS_KEY_ID` | SSE | R2 access key |
| `R2_SECRET_ACCESS_KEY` | SSE | R2 secret key |
| `R2_BUCKET_NAME` | SSE | R2 bucket name |
| `CORS_ORIGINS` | SSE | Comma-separated allowed origins |
| `LOCAL_VAULT_PATH` | stdio | Override local storage path |

## 4. Container Hardening

### 4.1 Privilege Isolation
- The container MUST run as a non-root user (`aegisuser`).
- The data directory MUST be at `/home/aegisuser/.ai-passport` with correct ownership.

### 4.2 Security Headers
- `X-Content-Type-Options: nosniff` MUST be set on all responses.
- `X-Frame-Options: DENY` MUST be set on all responses.
- `Cache-Control: no-store` MUST be set on all responses.
- Request body size MUST be limited to 100KB.

## 5. Graceful Shutdown

- The application MUST register coordinated SIGTERM and SIGINT handlers in `main.js`.
- Shutdown sequence: `SyncService.flush()` → `SyncService.destroy()` → `SessionManager.shutdown()` → `McpSseServer.shutdown()` → exit.
- No individual component SHALL register its own signal handlers.