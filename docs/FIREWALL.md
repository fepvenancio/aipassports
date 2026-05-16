# FIRE-003: ZDR Security Firewall Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Outbound Interception

The `ZdrProxyClient` MUST intercept all outbound network requests originating from within the Project Aegis runtime. The `SkillExecutor` MUST use `ZdrProxyClient.fetch()` for all LLM calls — direct calls to LLM APIs are PROHIBITED.

## 2. Compliance Verification

### 2.1 Endpoint Registry
- The system MUST maintain an immutable `ComplianceRegistry` of verified providers.
- Registry keys MUST be exact hostnames (`api.openai.com`, `api.anthropic.com`, `aiplatform.googleapis.com`).
- All destination URLs MUST be checked by extracting `new URL(url).hostname` and performing an exact match.
- Substring matching (e.g., `url.includes()`) is PROHIBITED.

### 2.2 Egress Policy
- If an outbound URL's hostname does not exactly match a registry key, the proxy MUST return 403.
- If a match is found, the proxy MUST apply the provider-specific ZDR transformation.

## 3. ZDR Transformation

### 3.1 Provider Actions
| Provider | Hostname | ZDR Action |
|---|---|---|
| OpenAI | `api.openai.com` | Inject `store: false` into request body |
| Anthropic | `api.anthropic.com` | Append `anthropic-beta: zero-retention-2025` and `x-anthropic-zdr: true` headers |
| Google Vertex AI | `aiplatform.googleapis.com` | Inject `data_retention: "none"` into request body |

### 3.2 SkillExecutor Enforcement
- `SkillExecutor.executeLLMSkill()` MUST verify the LLM endpoint against `ComplianceRegistry.isVerified()` before making any network call.
- If the endpoint is not verified, `SkillExecutor` MUST throw `SKILL_ERROR_LLM_ENDPOINT_NOT_VERIFIED`.
- The `LLM_ENDPOINT_URL` environment variable (default: `https://api.openai.com/v1/chat/completions`) configures the target LLM.

## 4. Audit Logging

- All blocked egress attempts MUST be logged with the target URL.
- All enforced ZDR transformations MUST be logged with the provider name.

## 5. Rate Limiting

- The `/auth/unlock` endpoint MUST be rate-limited to 5 requests per minute per IP.
- The `/mcp/messages` endpoint MUST be rate-limited to 100 requests per minute per IP.
- Rate limit responses MUST include `Retry-After` and `X-RateLimit-Remaining` headers.