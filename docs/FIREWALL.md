# FIRE-001: ZDR Security Firewall Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Outbound Interception

The `ZdrProxyClient` MUST intercept all outbound network requests originating from within the Project Aegis runtime.

## 2. Compliance Verification

### 2.1 Endpoint Registry
- The system MUST maintain an immutable `ComplianceRegistry` of verified providers.
- All destination URLs MUST be checked against the registry before egress.

### 2.2 Egress Policy
- If an outbound URL does not match a verified provider in the registry, the proxy MUST drop the request and return a 403 Forbidden response.
- If a match is found, the proxy MUST apply the provider-specific ZDR (Zero Data Retention) transformation.

## 3. ZDR Transformation

### 3.1 Parameter Injection
- For compliant providers, the proxy MUST inject mandatory non-retention parameters (e.g., `store: false` for OpenAI).
- For providers requiring specific headers, the proxy MUST append the necessary security/compliance headers.

## 4. Audit Logging

- All blocked egress attempts SHOULD be logged to the security audit stream with the target URL and policy violation details.
