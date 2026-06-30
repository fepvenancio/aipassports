# Frontend Spec — Landing + Console

Companion to `PRODUCT_SPEC.md`. Defines the two frontend surfaces: a **marketing
landing page** (sells the product on security/trust) and the **Console** (login + the
app where customers deploy, and manage teams, vaults, memories, connectors, audit).

Build order: spec (this doc) → landing → console. Reuse the existing React app where
noted; today it is a bare `App.tsx` shell (`AuthGate` ↔ `Dashboard`) with no router and
no landing page.

---

## A. Information architecture & routes

Add a router (`react-router`). Three zones:

```
Public (marketing)            Auth                         Console (authenticated)
/                  landing    /login      SSO sign-in      /app                overview
/security          trust/how  /login/sso  IdP callback     /app/memories       vaults + memories
/compliance        proof      /onboard    deploy wizard    /app/teams          teams + roles
/pricing                                                   /app/connectors     MCP / AI tools
/docs (or link)                                            /app/policies       DLP / egress
                                                           /app/audit          audit + trust report
                                                           /app/billing        usage + plan
                                                           /app/settings       SSO, keys, deployment
```

Guard `/app/*` behind an authenticated session; guard `/onboard` until org is created;
show a persistent **"Not attested"** banner across `/app/*` until Phase 3 attestation is
live and green.

---

## B. Landing page (`/`) — selling on security

Audience: a CISO or platform/security lead evaluating whether AI can be allowed on
sensitive data. Tone: calm, precise, evidence-led — not hype. Every claim links to proof.
Reuse `frontend/src/assets/hero.png`'s slot but with new visuals.

### B1. Hero
- **Headline:** "Let your people use AI on sensitive data — and prove it's safe."
- **Subhead:** "Confidential, attested memory for enterprise AI. Frontier models, zero
  retention, full audit — deployed in your cloud."
- **Primary CTA:** "Book a security review" · **Secondary:** "See the trust report"
- Trust strip under the fold: "Runs in confidential hardware · Zero data retention ·
  SSO + full audit · Deploy in your own cloud."

### B2. The problem (qualify the buyer)
"Your teams want ChatGPT, Claude, and Copilot on real data. Security can't say yes
because you can't control or prove what happens to it." Three pain bullets: shadow AI,
data leakage to providers, no audit trail.

### B3. How it works (3 steps, diagrammatic)
1. **Connect** your AI tools over MCP (Claude, Cursor, Copilot).
2. **Confidential memory** stores context encrypted in a TEE — keys never leave hardware.
3. **Prove it** — hardware attestation + full audit you can hand to your auditors.

### B4. Security & trust (the core selling section)
Three cards mapping exactly to the §1 scoped claims (do not over-claim):
- **No retention** — providers used only under zero-retention terms; nothing is kept.
- **Tamper-proof control** — policy, DLP, and audit run in a TEE neither we nor the cloud
  can read or alter — proven by hardware attestation.
- **Confidential memory** — vault keys are derived and used only inside the enclave.
- Include an **honest scope note** ("what we mean by no retention") — turns security
  reviewers into allies instead of skeptics.

### B5. Proof / attestation
Show a sample **Trust Report**: live attestation status, enclave measurement, policy
summary, "download for your auditor." This is the differentiator — lead with evidence.

### B6. Compliance
Logos/roadmap: SOC 2 Type II, data residency, HIPAA/BAA path. "Deploy in your own cloud
(Azure Confidential / GCP Confidential / AWS Nitro)."

### B7. Use cases / verticals
Finance, healthcare, legal, defense — one line each on the sensitive-data scenario.

### B8. Integrations
MCP-compatible tools (Claude, Cursor, VS Code/Copilot) + model providers (OpenAI,
Anthropic, Azure OpenAI, Bedrock, Vertex) under ZDR terms.

### B9. Pricing teaser + CTA
Per-seat and dedicated-enclave tiers; CTA "Book a security review."

### B10. Footer
Security/trust center link, docs, contact, legal.

---

## C. Console (`/app/*`) — the user area

Evolve the existing `Dashboard` (sidebar + panels). Keep `DashboardSidebar` /
`DashboardHeader`; re-label nav to the routes in §A. Header shows org name, attestation
status pill (green = attested), user/SSO identity, and team switcher.

### C1. Auth (`/login`) — evolve `AuthGate`
Replace NEP-413 wallet connect with **SSO**: "Sign in with your company SSO" → IdP →
callback → session. Keep the secure-session messaging; drop wallet UI. Show org picker if
the user belongs to multiple orgs.

### C2. Onboarding / Deploy wizard (`/onboard`) — new
Stepper: (1) Create org → (2) Choose deployment (Managed vs BYOC/dedicated enclave) →
(3) Provision (progress + what's happening in the enclave) → (4) **Trust Report** shown,
download enabled → (5) "Invite your team / configure SSO." Gate the rest of the console
until provisioning + first attestation succeed.

### C3. Overview (`/app`) — new/light
At-a-glance: attestation status + last verified time, # memories, # active connectors,
recent audit highlights, policy summary, quota usage. Primary CTAs: "Connect a tool,"
"Invite members," "View trust report."

### C4. Memories (`/app/memories`) — evolve `WikiPanel` (+ `SkillConsole`)
Rename "Wiki/Skills" → **Memories**. Browse by vault (personal/team), search/filter by
tag+time, view/create/edit a memory, see per-memory access history. Encryption happens
in the enclave; UI only handles plaintext for the authorized user. Empty state: "No
memories yet — write one, or let your AI tool create them."

### C5. Teams (`/app/teams`) — evolve `TeamsPanel`
List teams, members, roles (Read/Write/Admin). Add member (manual or show SCIM-synced
status from IdP groups). Role change and removal are immediate; surface "removal revokes
access without rotating others' keys."

### C6. Connectors (`/app/connectors`) — evolve `McpSetupPanel`
Per-tool setup (Claude / Cursor / VS Code) showing the gateway `/mcp` endpoint and the
per-user auth, with copy-paste config. Status: connected/last-seen. This replaces any
"paste the agent API key" flow — the browser/tool never holds a shared agent key.

### C7. Policies / DLP (`/app/policies`) — new
Configure egress policy (PII/secret redaction, blocked destinations, per-role limits) —
the UI over the ZDR firewall. Show a test box: paste sample text → preview redaction.

### C8. Audit + Trust Report (`/app/audit`) — evolve `LogsPanel`
Attributed, filterable log (actor, action, object, tool, policy decision, time). Export
to SIEM/CSV. Tab for the **Trust Report**: current attestation, re-attest button,
download. This screen is the compliance team's home.

### C9. Billing & usage (`/app/billing`) — evolve `BillingPanel`
Per-seat/usage metering, plan management, invoices. Tie usage to org/team/user.

### C10. Settings (`/app/settings`) — new
SSO/IdP config, SCIM, capability key rotation (dual-key, zero-downtime), deployment
details (managed/BYOC), storage/BYOK config, data residency region.

---

## D. Existing component → new mapping

| Today | Becomes | Action |
|---|---|---|
| `App.tsx` (no router) | Router + public/auth/console zones | Add `react-router`, landing + guards |
| `AuthGate` (wallet) | `/login` SSO | Replace NEP-413 with OIDC/SAML |
| `Dashboard` + `DashboardSidebar` | Console shell | Re-label nav to §A routes |
| `WikiPanel` (+ `SkillConsole`) | `MemoriesPanel` | Rename concept to Memories/Vaults |
| `SkillsPanel` | folded into Memories or Policies | Decide: skills = a memory type |
| `TeamsPanel` | `TeamsPanel` | Add SCIM status, immediate revoke UX |
| `McpSetupPanel` | `ConnectorsPanel` | Remove shared-key flow; per-user MCP auth |
| `LogsPanel` | `AuditPanel` + Trust Report tab | Add attribution, export, attestation |
| `BillingPanel` | `BillingPanel` | Keep; tie to org/seat/usage |
| `api/gateway.ts` `agentPost` | `api/mcpClient.ts` | Route memory ops through gateway `/mcp` |
| `near/wallet.ts` | removed/optional | SSO replaces wallet identity |

New components: `LandingPage/*`, `OnboardDeployWizard`, `OverviewPanel`, `PoliciesPanel`,
`SettingsPanel`, `TrustReport`, `AttestationPill`.

---

## E. Design / brand direction

Security-forward and credible: restrained palette, strong typography (the existing Inter/
Fira), evidence over adjectives. Recurring **trust signals**: attestation pill, "verified
hardware" badge, trust-report download. Avoid crypto/web3 visual language entirely — the
buyer is an enterprise CISO, not a token holder. Accessibility and clarity over flourish.

---

## F. UI states to handle everywhere

- **Loading / provisioning** — especially the deploy wizard (enclave spin-up can take time).
- **Empty** — no memories / no teams / no connectors, each with a clear first action.
- **Error** — auth failure, attestation failure, policy block (show the policy reason).
- **Not attested** — global banner until attestation is green; block sensitive actions or
  clearly mark the environment as unverified.
- **Revoked / expired session** — clean redirect to `/login`.

---

## G. Acceptance for the frontend milestone

A CISO can: hit the landing page and understand the security model; sign in via SSO;
complete the deploy wizard and download a trust report; connect Claude/Cursor and have it
read/write memories with full attribution; invite a team with roles; view and export an
attributed audit log — with **no shared secret in the browser** and a visible attestation
status throughout.
