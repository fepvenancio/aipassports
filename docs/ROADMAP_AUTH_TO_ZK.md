# Roadmap: From Capability Binding to Zero-Knowledge Auth

This is the sequenced, repo-grounded plan to (1) finish the auth-binding work so it
actually protects the web app, and (2) carry it through to the ZK layer. Each phase
lists concrete files, changes, and acceptance criteria. Do the phases in order — each
is a prerequisite for the next.

---

## Where we are (Phase 0 — done)

Capability binding is shipped for the **gateway → agent** hop:

- `agent/src/capability.rs` verifies gateway-signed Ed25519 tokens and enforces
  `capability.sub == nearAccountId` on `/vault/write`, `/vault/read`, `/skills/execute`.
- `gateway/src/capability.ts` mints those tokens inside `callShadeAgent`.
- Gated by `AEGIS_GATEWAY_CAP_PUBKEY` (agent) / `AEGIS_CAP_SIGNING_KEY` (gateway).

**The gap:** the web app does **not** use that hop. `frontend/src/api/gateway.ts`
`agentPost()` calls the agent **directly** (`https://api.aipassports.xyz`) with
`VITE_AGENT_API_KEY` — a shared key shipped in every browser bundle. So vault ops
bypass the gateway, the capability check, and the NEAR-session identity. This is the
most exposed surface and Phase 1 closes it.

Good news: the gateway's `/mcp` endpoint **already** exposes `vault_write`,
`vault_read`, and `zdr_check` as session-authenticated tools that dispatch through
`callShadeAgent` (see `gateway/src/index.ts` `tools/call` switch and
`gateway/src/dispatcher.ts`). Phase 1 is mostly client-side rewiring onto an
existing, already-secured path.

---

## Phase 1 — Close the browser gap (finish now)

Goal: every web-app vault/skill call goes through the gateway under the user's NEAR
session; the shared agent key leaves the browser; agent enforcement is turned on.

### 1.1 Add a gateway MCP client in the frontend
- **File:** new `frontend/src/api/mcpClient.ts`.
- Implement `callMcpTool(name, args, signal)` that POSTs JSON-RPC `tools/call` to
  `${gatewayBase}/mcp` with `Authorization: Bearer ${localStorage['AEGIS_SESSION_TOKEN']}`.
- Parse the MCP result envelope (`result.content[0].text` → JSON) and surface errors.
- Reuse the gateway base already computed for MCP setup
  (`Dashboard/index.tsx` uses `window.location.origin + '/mcp'` in prod,
  `http://localhost:8787/mcp` in dev).
- **Acceptance:** a unit/manual call to `agent_health` via the gateway returns healthy
  using only the session token (no agent key).

### 1.2 Migrate vault/skill calls off the direct path
- **File:** `frontend/src/api/gateway.ts`.
- Reimplement `vaultWrite` → `callMcpTool('vault_write', {...})`,
  `vaultRead` → `callMcpTool('vault_read', {...})`,
  skill execution → `callMcpTool('zdr_check', {...})`.
- Update callers if signatures change: `hooks/useWiki.ts`, `hooks/useSkills.ts`,
  `hooks/useSkillExecutor.ts`.
- Delete `agentPost()`, `AGENT_API_KEY`, and the direct `getAgentBase()` usage for
  these ops. Keep a gateway-routed health/attest check if the UI needs it (or call
  `agent_health` via MCP).
- **Acceptance:** the app reads and writes a vault entry end-to-end with the dev
  server proxying to the gateway, not the agent.

### 1.3 Retire the public agent key
- Remove `VITE_AGENT_API_KEY` and `VITE_AGENT_URL` (for vault ops) from
  `frontend/.env*`, `frontend/vite.config.ts` proxy notes, and any docs.
- Grep to confirm zero references remain: `grep -rn "VITE_AGENT_API_KEY\|agentPost" frontend/src`.
- **Acceptance:** a production build (`pnpm -C frontend build`) contains no agent
  bearer token (`grep -r "VITE_AGENT_API_KEY" frontend/dist` → empty).

### 1.4 Generate keys and enable enforcement
- Generate the keypair (command in `docs/CAPABILITY_BINDING.md`).
- Gateway: `wrangler secret put AEGIS_CAP_SIGNING_KEY`.
- Agent: set `AEGIS_GATEWAY_CAP_PUBKEY` (docker-compose env / `ironclaw secret put`).
- **Acceptance:** agent logs `Capability binding ENABLED` at startup.

### 1.5 Lock the agent to the gateway
- With enforcement on, the agent rejects any caller without a valid capability token.
- Belt-and-suspenders: restrict agent ingress at the network layer to the gateway
  Worker (allowlist / mTLS / private networking) so the agent is not directly
  reachable from the public internet.
- **Acceptance:** a direct `curl` to `/vault/read` with only the bearer returns
  `401 AGENT_ERROR_CAPABILITY_MISSING`; the same op via the web app succeeds.

### 1.6 End-to-end verification
- Login (NEP-413) → write entry → read entry → run a skill, all through the gateway.
- Confirm cross-account spoofing fails: tamper `nearAccountId` in a proxied request →
  gateway rejects at session check (`index.ts:416`); a forged direct call →
  agent rejects (`AGENT_ERROR_SUBJECT_MISMATCH` / capability invalid).
- **Exit criteria for Phase 1:** no shared secret in the browser; all data-plane
  traffic is NEAR-session-authenticated and capability-bound.

---

## Phase 2 — Extend capability binding to team vaults

Currently `/vault/team/*` is not capability-bound: `gateway/src/team_handlers.ts`
calls `callShadeAgent` **without** a `subject`, and the agent's team handlers don't
call `enforce_capability_subject`.

- **Gateway:** pass `subject: <authenticated session account>` (and the
  `requestingAccountId` in the body) for `handleTeamVaultWrite` / `handleTeamVaultRead`.
- **Agent:** add `claims: Option<Extension<CapabilityClaims>>` to
  `team_vault_write_handler` / `team_vault_read_handler` and call
  `enforce_capability_subject(&claims, &req.requesting_account_id)`.
- Keep the existing gateway membership check (NEAR RPC) as the authorization layer;
  capability binding adds the actor-identity layer.
- **Acceptance:** team vault read/write require a valid token whose subject is the
  requesting member; mismatches return 403.

---

## Phase 3 — Harden the capability layer (pre-ZK)

These make the token layer production-grade and are reused by the ZK layer.

- **3.1 Replay cache (optional):** persist `jti` in a short-TTL KV/Durable Object and
  reject reuse within the window. Today the 120s `exp` bounds replay; a nullifier-style
  cache tightens it and mirrors the ZK design.
- **3.2 Key rotation runbook:** support two active gateway public keys on the agent
  (`AEGIS_GATEWAY_CAP_PUBKEY` + `..._NEXT`) for zero-downtime rotation; document the
  procedure.
- **3.3 Attestation (C-04):** wire the real DCAP TDX quote in `/attest` so clients can
  verify they're talking to a genuine enclave. **This — not ZK — is what defends
  against a malicious host.** Track it independently.
- **3.4 Rate limiting / abuse controls** at the gateway per session and per account.
- **Exit criteria:** rotation tested, attestation returns a verifiable quote, replay
  window enforced.

---

## Phase 4 — Zero-knowledge auth layer (the updated idea)

Now the substrate exists: a single verification seam (`CapabilityVerifier::verify`)
and a single enforcement seam (`enforce_capability_subject`). ZK replaces *what the
agent verifies*, not the plumbing around it.

### 4.0 Decision point — identity vs. anonymity (resolve first)
This is the crux and must be decided before any circuit work. Today the TEE derives
the per-user vault key from `nearAccountId` (`key_derivation::derive_dek`, account ID
as HKDF salt). If a ZK proof hides *which* account is calling, **the TEE can no longer
salt by `nearAccountId`.** Options:
- **(a) Pseudonymous key:** derive the DEK from a stable per-credential pseudonym /
  commitment carried in the proof's public inputs. Preserves anonymity; requires a
  migration/derivation story for existing vaults.
- **(b) Authorized-but-attributed:** the proof asserts membership + tier and *also*
  binds the account (revealed to the TEE, hidden from the host/provider). Keeps current
  key derivation; weaker privacy but trivial migration.
- Pick (a) for true privacy-first positioning, (b) for the fastest enterprise path.
  Everything below assumes the choice is made.

### 4.1 Registry & credential model
- Define the authorized-set commitment (Merkle root of credential leaves; leaf =
  hash(secret, tier, ...)). Decide where it lives: a NEAR contract view, or a manifest
  the TEE syncs (`docs/SYNC.md` pattern).
- Choose the proof system: **Semaphore v4** (bundled trusted setup, nullifiers,
  membership — recommended) or **Circom + Groth16** (smallest proof, but per-circuit
  ceremony). Avoid zkVM here — overkill for access predicates.

### 4.2 Circuit
- Statement: "I know a secret whose leaf is in the tree under `root`, my `tier`
  satisfies the requested op, and `nullifier = H(secret, epoch)`."
- Public inputs: `root`, `nullifier`, `epoch/timestamp`, `tier`, and (option b) the
  bound account or (option a) the pseudonym commitment.
- Deliverable: circuit + verifying key, checked into `circuits/`.

### 4.3 Client-side prover (frontend)
- **File:** new `frontend/src/zk/prover.ts` using snarkjs/wasm (or Semaphore JS).
- On session start (or per request), generate the proof + nullifier from the user's
  secret credential, locally. The secret never leaves the browser.
- Replace the session bearer with (or carry alongside) the proof in the
  `X-Aegis-Capability` slot — keep the same header so the agent seam is unchanged.
- **Acceptance:** sub-second proof generation; proof + public inputs sent to gateway.

### 4.4 Agent-side verifier kernel
- **File:** swap the body of `CapabilityVerifier::verify` (or add a sibling
  `ZkCredentialVerifier`) to: fetch/validate current `root`, run the compiled Groth16/
  Semaphore verifier, check `nullifier` unseen (reuse Phase 3.1 cache), enforce `tier`.
- `enforce_capability_subject` becomes `enforce_authorization` — for option (a) it maps
  the proof's pseudonym to the DEK salt; for option (b) it keeps `sub == nearAccountId`.
- Keep the enclave footprint small (Groth16 verify is ~ms); no new egress if the root
  is synced rather than fetched per request.
- **Acceptance:** valid proof → access; replayed nullifier → reject; stale root →
  reject; tier too low → reject.

### 4.5 Revocation
- Maintain a revocation accumulator; add a non-membership check to the circuit (or a
  separate revocation root the verifier checks). Revoking one credential leaves others
  untouched — the operational win over key rotation.

### 4.6 Tiered ZDR policy (ties back to the original idea)
- Carry `tier` from the verified proof into the ZDR firewall so egress policy is
  per-tier (e.g. free → no external calls, enterprise → allow + log nullifier).
  Hook in `agent/src/zdr_firewall.rs`.

### 4.7 Portable attestation receipt (optional, novel)
- Wrap the TEE attestation (Phase 3.3) into a verifiable receipt a user can show a
  third party ("this result came from verified hardware") without revealing the query.

### 4.8 Migration & coexistence
- Run capability tokens and ZK proofs in parallel behind a feature flag; verify both
  at the seam; cut over per tier/cohort; then retire the Ed25519 token path.
- **Exit criteria:** anonymous-but-authorized access works end-to-end, revocation is
  per-credential, ZDR enforces per-tier, and the legacy token path is removed.

---

## Sequencing summary

1. **Phase 1** (now): web app → gateway, kill `VITE_AGENT_API_KEY`, enforce. *Closes the live gap.*
2. **Phase 2**: team vault coverage.
3. **Phase 3**: replay cache, key rotation, **C-04 attestation** (host defense), rate limits.
4. **Phase 4**: ZK — decide identity model (4.0) first, then registry → circuit → prover → verifier → revocation → tiered ZDR → migration.

Each phase is independently shippable and leaves the system in a correct state. Do not
start Phase 4 before Phase 1 is enforced in production and C-04 (3.3) is real — ZK adds
privacy on top of authenticated, attested infrastructure; it does not substitute for
either.
