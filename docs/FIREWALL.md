# FIRE-002: ZDR Security Firewall Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Outbound Interception

The `ZdrProxyClient` MUST intercept all outbound network requests originating from within the Project Aegis runtime.

## 2. Compliance Verification

### 2.1 Endpoint Registry
- The system MUST maintain an immutable `ComplianceRegistry` of verified providers.
- Registry keys MUST be exact hostnames (e.g., `api.openai.com`, `api.anthropic.com`, `aiplatform.googleapis.com`).
- All destination URLs MUST be checked against the registry by extracting `new URL(url).hostname` and performing an exact match.
- Substring matching (e.g., `url.includes()`) is PROHIBITED — it enables bypass attacks (e.g., `api.anthropic.com.evil.com`).

### 2.2 Egress Policy
- If an outbound URL's hostname does not exactly match a registry key, the proxy MUST drop the request and return a 403 Forbidden response.
- If an exact match is found, the proxy MUST apply the provider-specific ZDR (Zero Data Retention) transformation.

## 3. ZDR Transformation

### 3.1 Parameter Injection
- For OpenAI (`api.openai.com`), the proxy MUST inject `store: false` into the request body.
- For Anthropic (`api.anthropic.com`), the proxy MUST append `anthropic-beta: zero-retention-2025` and `x-anthropic-zdr: true` headers.
- For Google Vertex AI (`aiplatform.googleapis.com`), the proxy MUST inject `data_retention: "none"` into the request body.

### 3.2 Body Parsing
- If the request body is a string, the ZDR action MUST parse it as JSON before modification and re-serialize after.
- If the request body is an object, modifications MUST be applied directly and the body MUST be re-serialized to a JSON string.

## 4. Audit Logging

- All blocked egress attempts MUST be logged to stderr with the target URL.
- All enforced ZDR transformations MUST be logged to stderr with the provider name.
- The log format MUST be: `[SECURITY_FIREWALL] Blocked non-compliant egress to: {url}` or `[SECURITY_FIREWALL] Enforcing ZDR for verified provider: {provider}`.

## 5. Rate Limiting

- The `/auth/unlock` endpoint MUST be rate-limited to 5 requests per minute per IP.
- The `/mcp/messages` endpoint MUST be rate-limited to 100 requests per minute per IP.
- Rate limit responses MUST include `Retry-After` header and `X-RateLimit-Remaining` header.
- Rate limiting MUST be implemented via a sliding-window algorithm (no external dependencies).