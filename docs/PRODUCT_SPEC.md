# Confidential AI Memory — Product & Build Spec

> Enterprise-only product. This spec supersedes the ZK roadmap for product direction.
> ZK, anonymous auth, NEAR-as-login, and Walrus-as-identity are **out of scope** (see §9).
> Working product name: **Aegis** (rename freely).

---

## 1. What we're building

**Aegis is confidential, attested memory for enterprise AI.** It gives a company's
AI assistants and agents a persistent, encrypted context store that the company fully
controls, with cryptographic proof that no AI vendor retains the data and a complete,
attributable audit trail of every access.

The buyer's problem: employees and AI agents want to use frontier models (ChatGPT,
Claude, Copilot, Cursor) on sensitive internal data, and security/compliance can't
allow it because they can't control or prove what happens to that data. Aegis is the
control layer that turns the CISO's "no" into a provable "yes."

### The claim — scoped honestly (this is what we sell, exactly)
We make three precise guarantees. We never blur them, because enterprise security
reviewers will test each one:

1. **No retention.** Context lives in our enclave-encrypted store; model providers are
   used only under enterprise zero-retention terms and retain nothing. (Contractual + technical.)
2. **Tamper-proof control + full audit.** Access policy, DLP, and audit run inside a TEE
   that neither we (the operator) nor the cloud provider can read or alter — and we can
   *prove* it via hardware attestation. Every access is attributed to a user/agent.
3. **Confidential memory.** Vault keys are derived and used only inside the enclave; the
   browser, the gateway, and the host never see plaintext keys.

What we **do not** claim in v1: that the model provider never *sees* a prompt. Today the
enclave decrypts context and sends it to the provider under ZDR terms — the provider
processes it but does not retain it. End-to-end "the model never sees plaintext" is a
later premium tier (confidential inference, §9).

---

## 2. Who it's for

| Persona | Role | What they need from Aegis |
|---|---|---|
| **CISO / Security buyer** | Economic buyer | Proof (attestation, audit, compliance posture) that AI use is safe; deploys in their cloud. |
| **Platform / Security admin** | Operator | Deploy enclaves, configure SSO, set DLP/egress policy, manage keys, export audit to SIEM. |
| **Team lead** | Manager | Create teams, manage members & roles, oversee their team's memories. |
| **Member (employee)** | Daily user | Store/retrieve memories; connect their AI tool (MCP) and use it safely. |
| **AI tool / agent** | Machine client | Read/write memory via MCP under the member's attributed, capability-bound session. |

Primary verticals: regulated industries (finance, healthcare, legal, defense, pharma)
where "we can prove the data handling" is a purchase requirement, not a nice-to-have.

---

## 3. Architecture (grounded in the current stack)

```
┌────────────┐   SSO (OIDC/SAML)     ┌──────────────────┐   capability token   ┌────────────────────────┐
│  Browser    │ ───── session ─────▶ │  Gateway (Worker) │ ──── + Bearer ─────▶ │  TEE Agent (Rust/Axum) │
│  Console +  │                      │  authN/Z, mint    │                      │  - vault encrypt/decrypt│
│  Landing    │ ◀──── trust report ─ │  audit, policy    │ ◀──── attested ───── │  - DLP egress firewall  │
└────────────┘                       └────────┬─────────┘                       │  - HKDF per-tenant keys │
       ▲                                       │                                └───────────┬────────────┘
       │ MCP tools/call (Claude/Cursor/...)    │ audit → SIEM                                │
┌──────┴───────┐                       ┌───────▼────────┐                          ┌─────────▼─────────┐
│  AI tools /  │                       │  Audit store   │                          │ Pluggable storage │
│  agents      │                       │  + RBAC/teams  │                          │ (S3/Blob; BYOK)   │
└──────────────┘                       └────────────────┘                          └───────────────────┘
                                              │
                                       ┌──────▼───────┐
                                       │ Model providers (ZDR terms): OpenAI/Anthropic/Azure/Bedrock/Vertex │
                                       └──────────────────────────────────────────────────────────────────┘
```

Reused from today: the Rust TEE agent (`agent/`), the gateway MCP bridge (`gateway/`),
per-tenant HKDF key derivation, the ZDR egress firewall (`zdr_firewall.rs`), the
capability-token binding (`capability.rs`/`capability.ts`), teams/RBAC in the contract.

Enterprise changes (what's new): SSO/SCIM replaces wallet login; **real attestation**
(C-04) becomes the trust keystone; pluggable storage + BYOK replaces Walrus-as-identity;
tamper-evident audit export; per-tenant/BYOC deployment; the web app routes through the
gateway (no shared key in the browser).

---

## 4. Core concepts (glossary used across UI + docs)

- **Memory** — a single encrypted context entry (note, doc, fact, skill/prompt). The
  product noun replacing "wiki/skill entry."
- **Vault** — a namespace of memories owned by a user or a team; the unit of access control.
- **Team** — a group with Read/Write/Admin roles; provisioned via SCIM.
- **Connector** — an AI tool connected over MCP (Claude, Cursor, VS Code/Copilot).
- **Capability token** — short-lived gateway-signed proof binding a request to a NEAR/SSO
  identity (already built); the agent enforces `sub == account`.
- **Attestation / Trust report** — the hardware proof (DCAP quote) that the enclave is
  genuine, plus a human-readable summary the customer hands to auditors.
- **Audit record** — an attributed, tamper-evident log line for every memory access and
  admin action; exportable to the customer's SIEM.
- **Policy** — DLP/egress rules (PII redaction, blocked destinations, per-role limits).

---

## 5. User flows (step by step)

### F1 — Org onboarding & deployment
1. Buyer signs up, creates an **Organization**.
2. Chooses deployment model:
   - **Managed (multi-tenant)** — fastest; runs in our cloud, per-tenant key isolation.
   - **BYOC / dedicated enclave** — runs in the customer's Azure Confidential VM / GCP
     Confidential / AWS Nitro, inside their boundary. (Premium.)
3. Aegis provisions the enclave(s) and the gateway, derives the per-org keys inside the TEE.
4. Onboarding completes by showing the **Trust Report**: live attestation result +
   policy summary the admin can download for their auditors.
- **Acceptance:** org exists, enclave attests as genuine, trust report downloadable.

### F2 — SSO login
1. Admin configures the org's IdP (OIDC/SAML: Okta, Entra, Google).
2. Users log in via SSO; the gateway verifies the IdP assertion, creates a session, and
   maps the user to org/team/roles (SCIM-provisioned).
3. The gateway mints capability tokens from the **session identity** (not a body field).
- **Acceptance:** no passwords; identity, org, and roles come from the IdP; sessions expire.

### F3 — Connect an AI tool (Connector / MCP)
1. Member opens **Connectors**, picks their tool (Claude / Cursor / VS Code).
2. Aegis shows the MCP config (endpoint = gateway `/mcp`, auth = provisioned per-user key
   or session) and copy-paste setup per tool.
3. The tool now calls `vault_read` / `vault_write` over MCP, session-authenticated and
   capability-bound.
- **Acceptance:** the AI tool reads/writes the member's memories with full attribution;
  no shared agent key in the client.

### F4 — Teams & members
1. Team lead creates a **Team**, adds members (or SCIM auto-provisions from IdP groups).
2. Assigns roles: Read / Write / Admin (existing contract `Permission` enum).
3. Members get access to the team **Vault**.
- **Acceptance:** role changes take effect immediately; removal revokes access without
  rotating anyone else's keys.

### F5 — Create / read / write memories
1. From the **Console** or from a connected AI tool, the user writes a memory →
   encrypted in the enclave, stored as ciphertext in pluggable storage, pointer recorded.
2. Reads decrypt inside the enclave and return plaintext only to the authenticated user.
3. Search/browse memories by vault, tag, and time.
- **Acceptance:** plaintext never appears outside the enclave except to the authorized
  caller; every read/write produces an audit record.

### F6 — Policy / DLP
1. Admin sets egress policy: PII/secret redaction, blocked destinations, per-role limits
   (extends the ZDR firewall).
2. Policy is enforced inside the enclave on every model call.
- **Acceptance:** a prompt containing a blocked secret is redacted/blocked and logged.

### F7 — Audit & compliance
1. Admin views the **Audit** screen: who accessed which memory, when, from which tool,
   under which policy decision.
2. Exports to SIEM (Splunk/Sentinel) via stream or download.
3. Re-runs **attestation** on demand and downloads an updated trust report.
- **Acceptance:** audit is attributable, tamper-evident, and exportable; attestation is
  verifiable by a third party.

### F8 — Billing & usage
1. Per-seat and/or per-usage metering (reuse existing quota/metering work).
2. Admin views usage, manages plan.
- **Acceptance:** usage is accurate and tied to org/team/user.

### F9 — Key management
1. Admin can rotate the gateway capability key (dual-key, zero-downtime) and revoke
   per-user/per-team access.
- **Acceptance:** rotation causes no outage; revocation is immediate and scoped.

---

## 6. Build plan (sequenced, enterprise)

Each phase is independently shippable and leaves the system correct.

- **Phase 1 — Close the browser gap (now).** Route the web app's memory calls through the
  gateway `/mcp` (already exposes `vault_write`/`vault_read`/`zdr_check`); delete
  `VITE_AGENT_API_KEY` + `agentPost`; enable capability enforcement; lock agent ingress to
  the gateway. *Acceptance:* no shared secret in the browser; all data-plane traffic is
  session-authenticated and capability-bound.
- **Phase 2 — SSO + SCIM.** Add OIDC/SAML login and SCIM provisioning; mint capability
  tokens from the SSO session; map org/team/roles from the IdP. Retire wallet login.
- **Phase 3 — Attestation + Trust Report (keystone).** Make `/attest` return a real DCAP
  quote; build the customer-facing trust report and on-demand re-attestation. *Nothing we
  sell is provable until this ships.*
- **Phase 4 — Audit + DLP.** Tamper-evident, attributed audit with SIEM export; extend the
  ZDR firewall into PII/secret redaction and per-role egress policy.
- **Phase 5 — Pluggable storage + BYOK + BYOC deploy.** Storage interface (S3/Blob), CMK/
  BYOK, and dedicated-enclave deployment in the customer's cloud.
- **Phase 6 — Compliance + billing hardening.** SOC 2 Type II program, data residency,
  per-seat/usage billing, key rotation runbook.

Do **not** start any new cryptographic subsystem before Phases 1–3 are in production.

---

## 7. Data model (sketch)

- **Organization** (id, name, deployment_model, sso_config, plan).
- **User** (id, org_id, idp_subject, email, status).
- **Team** (id, org_id, name) — maps to contract team.
- **Membership** (user_id, team_id, role: Read|Write|Admin).
- **Vault** (id, owner: user|team, org_id).
- **Memory pointer** (vault_id, identifier, storage_ref, content_sha256, created_at).
- **Connector** (user_id, tool, provisioned_key_id, created_at).
- **AuditRecord** (org_id, actor, action, object, policy_decision, tool, ts, signature).
- **Session / API key** (subject, scopes, expiry).

(Encrypted blobs live in pluggable storage; only pointers + metadata live in the index.)

---

## 8. Non-goals (v1)

- No ZK / anonymous auth — enterprise requires **attribution** (see ZK assessment).
- No confidential inference yet — provider sees prompts under ZDR terms (premium tier later).
- No general LLM gateway/proxy product — that lane is crowded; we are the memory + control layer.
- No consumer / crypto-native features (wallet login, decentralized-storage-as-identity).

---

## 9. Future (architect for, don't build now)

- **Confidential inference** tier (TEE/confidential-GPU) → upgrades claim to "provider
  never sees plaintext." Architect the broker to route to such a backend without redesign.
- **Confidential credential broker for agents** — same enclave engine extended from memory
  to secrets/actions (the code already leans here: server-side key loading, egress secret
  scanning). High-value, low-competition follow-on.
- **Cross-org agent federation** — the *only* place ZK/selective-disclosure earns its keep;
  a separate, later product with a real privacy boundary.
