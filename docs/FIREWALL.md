# FIRE-004: ZDR Security Firewall Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Scope

The ZDR (Zero Data Retention) firewall runs exclusively inside the IronClaw Shade Agent TEE. It intercepts all outbound network requests from the agent to LLM provider APIs. The gateway does NOT perform LLM calls and is NOT subject to this firewall — it only routes MCP protocol traffic.

The `zdr_firewall.rs` module in `backend/src/` contains the reference implementation. The same module MUST be ported to `agent/src/zdr_firewall.rs` and used there.

## 2. Compliance Verification

### 2.1 Allowed Destination Registry
- The agent MUST maintain a static, compile-time `ComplianceRegistry` of verified LLM provider endpoints.
- Registry entries MUST be exact, full base URLs (scheme + hostname + path prefix). Substring matching is PROHIBITED.
- The current registry MUST contain exactly these entries:

| Provider | Allowed Base URL |
|---|---|
| OpenAI | `https://api.openai.com/v1/chat/completions` |
| Anthropic | `https://api.anthropic.com/v1/messages` |
| Google Vertex AI | `https://aiplatform.googleapis.com/v1/` |

- To add a provider, a new entry MUST be added to the registry in source code, reviewed, and the agent redeployed with a new attestation measurement. Registry entries MUST NOT be configurable at runtime via environment variables.

### 2.2 Egress Policy
- Before any outbound LLM request, the agent MUST check the target URL against the registry using `allowed_destinations.contains(&destination)` — exact string match.
- If the destination is not in the registry, the agent MUST reject the request with `SKILL_ERROR_LLM_ENDPOINT_NOT_VERIFIED` and log the blocked attempt.
- If the destination is in the registry, the agent MUST apply the provider-specific ZDR transformation (§3) before transmitting.

## 3. ZDR Transformations

Every outbound LLM request MUST have the following transformations applied based on the target provider:

### 3.1 Provider Actions

| Provider | ZDR Transformation |
|---|---|
| OpenAI (`api.openai.com`) | Inject `"store": false` into the JSON request body |
| Anthropic (`api.anthropic.com`) | Add headers: `anthropic-beta: zero-retention-2025-04-01` and `x-anthropic-zdr: true` |
| Google Vertex AI (`aiplatform.googleapis.com`) | Inject `"data_retention": "none"` into the JSON request body |

### 3.2 Enforcement
- The `LlmExecutor` MUST call `ZdrFirewall::validate_and_transform(payload)` before transmitting any request.
- If the transformation step fails (e.g., malformed JSON body), the request MUST be aborted — it MUST NOT be sent untransformed.
- If the ZDR transformation for a provider is unknown (new provider added without corresponding action), the request MUST be rejected.

## 4. Payload Content Scanning

Before transmitting any payload to an LLM provider, the agent MUST scan the serialised request body for sensitive data markers. The scan MUST be case-insensitive (convert to uppercase before checking).

### 4.1 Blocked Markers (exhaustive list)

| Marker | Rationale |
|---|---|
| `PRIVATE_KEY` | Private key material |
| `SECRET_KEY` | Private key material |
| `MNEMONIC` | Seed phrase |
| `PASSPHRASE` | Seed phrase variant |
| `SEED_PHRASE` | Seed phrase |
| `SECRET_TOKEN` | API or service token |
| `API_KEY` | API credential |
| `PASSWORD` | Password credential |
| `BEARER` | Bearer token |
| `AUTH_TOKEN` | Authentication token |
| `WALLET_SECRET` | Wallet private material |

- If any marker is found in the payload, the request MUST be rejected with `SKILL_ERROR_SENSITIVE_DATA_DETECTED`.
- The blocked payload MUST be logged (redacted — log only the matched marker, not the surrounding context).
- False positives (legitimate uses of these strings in non-sensitive context) are accepted as the cost of the security guarantee. Users SHOULD use alternative phrasing if needed.

## 5. Fallback Behaviour

- If a ZDR transformation fails (e.g., the provider changed their API schema), the request MUST be blocked. It MUST NOT be sent without the transformation.
- There is no "pass-through" mode. An untransformed request to a ZDR provider is a compliance violation.
- The agent MUST surface a structured error to the gateway: `{ "error": "ZDR_TRANSFORM_FAILED", "provider": "openai" }`.

## 6. Rate Limiting (Gateway Layer)

Rate limiting is enforced at the Hono gateway, not inside the agent:

- `/auth/unlock`: MUST be rate-limited to 5 requests per minute per IP.
- `/mcp/messages`: MUST be rate-limited to 100 requests per minute per IP.
- Rate limit responses MUST include `Retry-After` (seconds until limit resets) and `X-RateLimit-Remaining` headers.
- Rate limit state MUST be stored in Cloudflare KV (key: `ratelimit:{ip}:{endpoint}`).

## 7. Audit Logging

All ZDR-related events MUST be logged as structured JSON to the agent's stdout (which IronClaw routes to its audit log system).

### 7.1 Log Schema
```json
{
  "timestamp": "2026-05-22T16:00:00Z",
  "event": "ZDR_BLOCKED | ZDR_TRANSFORMED | ZDR_CONTENT_BLOCKED",
  "near_account_id": "alice.near",
  "destination": "https://api.openai.com/v1/chat/completions",
  "provider": "openai",
  "matched_marker": "API_KEY"
}
```

- `near_account_id` MUST always be present to associate the event with a user.
- `matched_marker` MUST only be present for `ZDR_CONTENT_BLOCKED` events.
- Logs MUST NOT contain plaintext vault content, DEK material, or full payloads.