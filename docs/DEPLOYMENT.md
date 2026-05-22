# DEPLOY-005: Deployment Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Runtime Environment

Project Aegis is deployed across four independent, decentralized infrastructure layers. No single cloud provider holds user vault content or is a single point of failure.

| Layer | Runtime | Provider | Data Held |
|---|---|---|---|
| Vault Index | NEAR Smart Contract | NEAR Blockchain | Storage pointers only (blobId + sha256). No content. |
| MCP Gateway | Hono on Cloudflare Workers | Cloudflare (free tier sufficient) | Sessions in CF KV only. No vault content. |
| Compute / Encryption | IronClaw Shade Agent | NEAR IronClaw TEE Network | Master secret sealed to hardware. No persistent user data. |
| Blob Storage | Walrus Protocol | Walrus Decentralized Network | AES-256-GCM encrypted blobs only. |

## 2. Pre-Deployment Checklist

Complete these steps IN ORDER before any code is deployed. Some have lead times.

```
[ ] 2.1 Create NEAR testnet account (aegis-vault.testnet) — 5 minutes, free
[ ] 2.2 Apply for IronClaw developer access — ⚠ MAY REQUIRE WAITLIST (apply first)
[ ] 2.3 Create Cloudflare account + Workers + KV namespaces — 10 minutes, free
[ ] 2.4 Install toolchain (Rust, near-cli-rs, wrangler) — 20 minutes
[ ] 2.5 Set up Walrus testnet access — 5 minutes, free (no WAL tokens needed on testnet)
[ ] 2.6 Deploy NEAR contract (testnet)
[ ] 2.7 Deploy IronClaw agent (testnet/devnet)
[ ] 2.8 Deploy Hono gateway (Cloudflare Workers)
[ ] 2.9 Deploy frontend (Cloudflare Pages)
[ ] 2.10 Run end-to-end test: create wiki page → verify pointer on NEAR → verify blob on Walrus
```

> [!WARNING]
> **IronClaw developer access may require a waitlist.** As of 2026, IronClaw is in early access. Apply at ironclaw.com BEFORE building the agent. This is the longest unblocking item. All other layers can be developed and tested (with a mock agent) while waiting for IronClaw access.

## 3. Layer 1: NEAR Contract Deployment

### 3.1 Toolchain Installation
```bash
# Rust + wasm32 target
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add wasm32-unknown-unknown

# NEAR CLI RS (the modern Rust-based CLI — NOT the deprecated JS near-cli)
cargo install near-cli-rs
```

### 3.2 Build
```bash
cd backend/
cargo build --target wasm32-unknown-unknown --release
# Output: target/wasm32-unknown-unknown/release/backend.wasm
# Verify it compiled: ls -lh target/wasm32-unknown-unknown/release/backend.wasm
```

### 3.3 Testnet Deployment (First Time)

> [!IMPORTANT]
> First deployment MUST use `with-init-call new` to initialise the shared contract state.
> A contract deployed `without-init-call` will have uninitialised LookupMaps.
> Calling any method on an uninitialised contract with `PanicOnDefault` will panic.

```bash
# Step 1: Create testnet account (if not already created)
near account create-account sponsor-by-faucet-service aegis-vault.testnet \
  autogenerate-new-keypair save-to-keychain \
  network-config testnet

# Step 2: Deploy WITH init call
near contract deploy aegis-vault.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config testnet sign-with-keychain send

# Step 3: Verify contract state is initialised (should return '[]', not panic)
near contract call-function as-read-only aegis-vault.testnet \
  list_wiki_slugs \
  json-args '{"account_id": "any-account.testnet", "from_index": 0, "limit": 10}' \
  network-config testnet now
```

### 3.4 Testnet Re-Deployment (Upgrade)

> [!IMPORTANT]
> Re-deployment preserves existing on-chain state (LookupMap entries survive).
> Do NOT call `new()` again on re-deploy — it will fail because `PanicOnDefault` prevents re-initialisation.
> Use `without-init-call` for upgrades.

```bash
# Rebuild first
cargo build --target wasm32-unknown-unknown --release

# Re-deploy WITHOUT init call
near contract deploy aegis-vault.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  without-init-call \
  network-config testnet sign-with-keychain send
```

### 3.5 Mainnet Deployment (First Time)
```bash
# Fund the account first — minimum balance for contract + storage
# Estimate: 5 NEAR minimum balance + 1 NEAR per 100KB expected state
near contract deploy aegis-vault.near \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0 NEAR' \
  network-config mainnet sign-with-keychain send
```

### 3.6 Contract Account Key Management
- The contract account's full-access keypair MUST be stored in a hardware wallet (Ledger) for mainnet.
- The contract account MUST maintain a NEAR balance sufficient to cover storage staking for all current entries plus a 20% buffer.
- Monitor balance: `near account view-account-summary aegis-vault.near network-config mainnet now`.
- Top up before balance drops below 10 NEAR.

## 4. Layer 2: Hono Gateway Deployment (Cloudflare Workers)

### 4.1 Toolchain and Project Setup
```bash
# Install wrangler (Cloudflare CLI)
pnpm add -g wrangler
wrangler login

# Create KV namespaces (run once per environment)
wrangler kv namespace create SESSIONS_KV
wrangler kv namespace create CHALLENGES_KV
wrangler kv namespace create RATELIMIT_KV
# Note the IDs output by each command — paste into wrangler.toml
```

### 4.2 wrangler.toml
```toml
name = "aegis-gateway"
main = "src/index.ts"
compatibility_date = "2025-01-01"
compatibility_flags = ["nodejs_compat"]

[vars]
SESSION_TTL_SECONDS = "3600"
AUTH_CHALLENGE_TTL_SECONDS = "60"
RATE_LIMIT_AUTH_PER_MIN = "5"
RATE_LIMIT_MCP_PER_MIN = "100"
MAX_BODY_SIZE_BYTES = "102400"
NEAR_NETWORK = "testnet"       # or "mainnet"

[[kv_namespaces]]
binding = "SESSIONS_KV"
id = "<paste-sessions-kv-id>"

[[kv_namespaces]]
binding = "CHALLENGES_KV"
id = "<paste-challenges-kv-id>"

[[kv_namespaces]]
binding = "RATELIMIT_KV"
id = "<paste-ratelimit-kv-id>"
```

### 4.3 Secrets (set via wrangler — never commit to source control)
```bash
# Required secrets
wrangler secret put NEAR_CONTRACT_ID           # e.g. "aegis-vault.testnet"
wrangler secret put NEAR_RPC_URL               # e.g. "https://rpc.testnet.near.org"
wrangler secret put IRONCLAW_AGENT_URL         # e.g. "https://agent-xyz.ironclaw.dev"
wrangler secret put IRONCLAW_AGENT_API_KEY     # Shared bearer token with the agent
wrangler secret put GATEWAY_FUNCKEY_PRIVKEY    # The Ed25519 private key whose public key
                                               # users register as a function call access key
                                               # during dashboard onboarding
wrangler secret put CORS_ORIGINS               # e.g. "https://aegis.app,http://localhost:5173"
```

**About `GATEWAY_FUNCKEY_PRIVKEY`:**
- This is a single Ed25519 keypair generated once for the gateway.
- The **public key** is hardcoded in the frontend and presented to users during onboarding.
- Users register this public key as a function call access key on their NEAR account (see NEAR.md §7).
- The **private key** is stored as a Workers secret. Cloudflare can access it but cannot call the NEAR contract without knowing which user's account has granted access.
- Generate the keypair: `near generate-key gateway-funckey --save-to-keychain`.

### 4.4 Security Headers (Hono middleware — enforced on ALL responses)
```typescript
// gateway/src/middleware/security.ts
app.use('*', (c, next) => {
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('X-Frame-Options', 'DENY');
  c.header('Cache-Control', 'no-store');
  c.header('Content-Security-Policy', "default-src 'none'");
  c.header('Referrer-Policy', 'no-referrer');
  return next();
});
```

### 4.5 Deploy
```bash
cd gateway/
pnpm install
wrangler deploy
# Gateway URL: https://aegis-gateway.<your-subdomain>.workers.dev
```

### 4.6 Local Development
```bash
wrangler dev
# Runs at http://localhost:8787
# Uses --local KV (in-memory, data not persisted between restarts)
```

## 5. Layer 3: IronClaw Agent Deployment

> [!CAUTION]
> **Apply for IronClaw developer access FIRST** before building the agent. This is the critical path blocker. While waiting, build and test with a mock agent server that accepts the same HTTP API but skips actual TEE encryption.

### 5.1 Mock Agent (For Development Without IronClaw Access)
```typescript
// mock-agent/src/index.ts
// Implements the same HTTP API as the real IronClaw agent
// WITHOUT any real encryption — for development ONLY

// POST /vault/write → encrypt with PBKDF2 + AES-GCM (dev key) → upload to Walrus testnet
// POST /vault/read  → download from Walrus testnet → decrypt
// POST /skills/execute → forward to LLM directly (no ZDR enforcement in mock)
```
Deploy this mock on any server (e.g., a local `npx` process or Cloudflare Worker) to unblock gateway and frontend development.

### 5.2 Real Agent Prerequisites
```
- IronClaw developer account (apply: ironclaw.com)
- ironclaw CLI installed (per official docs)
- Approved agent deployment slot
```

### 5.3 Agent Manifest (`agent/agent.toml`)
```toml
name = "aegis-vault-agent"
runtime = "rust"
tee = "intel-tdx"    # or "nvidia-cc" depending on available IronClaw hardware

[resources]
memory_mb = 512
max_concurrent_requests = 50

[secrets]
# AGENT_MASTER_SECRET is auto-generated and sealed to TEE on first boot.
# Do NOT set this manually — the agent generates it internally.
LLM_API_KEY = { source = "env" }   # LLM provider API key (set via ironclaw env)

[env]
LLM_ENDPOINT_URL = "https://api.openai.com/v1/chat/completions"
LLM_MODEL = "gpt-4o-mini"
LLM_MAX_TOKENS = "2048"
WALRUS_PUBLISHER_URL = "https://publisher.walrus-testnet.walrus.space"  # testnet
WALRUS_AGGREGATOR_URL = "https://aggregator.walrus-testnet.walrus.space"
WALRUS_STORAGE_EPOCHS = "5"
```

### 5.4 Master Secret Lifecycle
- **First boot**: agent generates 32 bytes using TEE CSPRNG. Seals to TEE measurement. Logs `"Master secret initialised. Measurement: {hex}"`.
- **Subsequent boots (same binary)**: agent unseals the same 32 bytes. Same DEKs. All blobs accessible.
- **After code change (new binary = new measurement)**: agent generates NEW 32 bytes. Old DEKs are GONE. All existing blobs are UNRECOVERABLE.
- **Pre-upgrade migration requirement**: before deploying a new agent binary to mainnet, run the migration script to re-encrypt all blobs:
  ```bash
  # agent/scripts/migrate_blobs.sh
  # 1. Stand up old agent (old binary, old measurement, old secret) in parallel
  # 2. For each (accountId, slug) in NEAR contract: read via old agent, re-write via new agent
  # 3. Verify all pointers updated with new blobIds
  # 4. Decommission old agent
  ```

### 5.5 Deploy
```bash
cd agent/
ironclaw deploy --manifest agent.toml --network testnet
# Copy the assigned HTTPS endpoint → set as IRONCLAW_AGENT_URL in gateway secrets
```

### 5.6 Authentication Between Gateway and Agent
- The gateway authenticates to the agent with a shared bearer token: `IRONCLAW_AGENT_API_KEY`.
- Generate a cryptographically random 32-byte token: `openssl rand -hex 32`.
- Set the same token in both the gateway (`wrangler secret put IRONCLAW_AGENT_API_KEY`) and the agent's IronClaw environment.
- The agent MUST reject all requests without a valid `Authorization: Bearer <token>` header.

## 6. Layer 4: Walrus Storage Setup

### 6.1 Testnet (Free — No WAL Tokens Required)
```
Publisher URL: https://publisher.walrus-testnet.walrus.space
Aggregator URL: https://aggregator.walrus-testnet.walrus.space
No account or funding required.
Blobs stored for a limited number of test epochs — data is not permanent.
```

### 6.2 Mainnet (Requires WAL Tokens)
```
Publisher URL: https://publisher.walrus.space
Aggregator URL: https://aggregator.walrus.space
```
- Create a Sui wallet (Sui is the underlying L1 for Walrus).
- Acquire WAL tokens (purchased via SUI on-chain or through Walrus ecosystem participants).
- Fund the wallet associated with the IronClaw agent's Sui address before the agent begins uploading.
- Monitor WAL balance via Walrus explorer. Refill before it reaches zero.
- Expected cost: fractions of a cent per vault entry per year. See WALRUS.md §6.3.

### 6.3 Storage Epoch Configuration
- Set `WALRUS_STORAGE_EPOCHS` in the agent env (default: `5`, ≈ 10 weeks).
- For production, consider 26 epochs (≈ 1 year) for typical vault entries.
- The agent's renewal job handles epoch extension. See SYNC.md §7.2.

## 7. Layer 5: Frontend Deployment (Vite Dashboard)

```bash
cd frontend/
pnpm install

# Create frontend/.env with real values
cat > .env.production << EOF
VITE_GATEWAY_URL=https://aegis-gateway.<subdomain>.workers.dev
VITE_NEAR_NETWORK=testnet
VITE_NEAR_CONTRACT_ID=aegis-vault.testnet
VITE_GATEWAY_FUNCKEY_PUBKEY=ed25519:<base64-public-key>
EOF

pnpm build
# Output: dist/

# Deploy to Cloudflare Pages
wrangler pages deploy dist/ --project-name aegis-dashboard
# Dashboard URL: https://aegis-dashboard.pages.dev
```

**`VITE_GATEWAY_FUNCKEY_PUBKEY`**: the public key of the gateway's function call access keypair. This is embedded in the frontend so it can be presented to users during the onboarding delegation step (wallet signIn call).

## 8. Deployment Order

Deploy in this exact order — each layer depends on the previous:

```
Step 1: NEAR Contract
  → Output: contract address (e.g., "aegis-vault.testnet")

Step 2: Walrus
  → Testnet: nothing to configure. Mainnet: provision WAL balance.

Step 3: IronClaw Agent
  → Needs: WALRUS_PUBLISHER_URL, WALRUS_AGGREGATOR_URL, NEAR_RPC_URL
  → Output: agent HTTPS endpoint URL

Step 4: Hono Gateway
  → Needs: NEAR_CONTRACT_ID, NEAR_RPC_URL, IRONCLAW_AGENT_URL, IRONCLAW_AGENT_API_KEY
  → Output: gateway URL (e.g., "https://aegis-gateway.xxx.workers.dev")

Step 5: Frontend
  → Needs: VITE_GATEWAY_URL, VITE_NEAR_CONTRACT_ID, VITE_GATEWAY_FUNCKEY_PUBKEY
  → Output: dashboard URL
```

## 9. Environment Variable Summary

### Gateway (Cloudflare Workers)

| Variable | Type | Description |
|---|---|---|
| `NEAR_CONTRACT_ID` | Secret | Deployed contract address |
| `NEAR_RPC_URL` | Secret | NEAR JSON-RPC endpoint |
| `IRONCLAW_AGENT_URL` | Secret | IronClaw agent HTTPS base URL |
| `IRONCLAW_AGENT_API_KEY` | Secret | Shared bearer token |
| `GATEWAY_FUNCKEY_PRIVKEY` | Secret | Gateway's Ed25519 private key for NEAR tx signing |
| `CORS_ORIGINS` | Secret | Allowed dashboard origin(s) |
| `SESSION_TTL_SECONDS` | Var | Default: `3600` |
| `AUTH_CHALLENGE_TTL_SECONDS` | Var | Default: `60` |
| `RATE_LIMIT_AUTH_PER_MIN` | Var | Default: `5` |
| `RATE_LIMIT_MCP_PER_MIN` | Var | Default: `100` |
| `MAX_BODY_SIZE_BYTES` | Var | Default: `102400` |
| `NEAR_NETWORK` | Var | `testnet` or `mainnet` |

### IronClaw Agent

| Variable | Source | Description |
|---|---|---|
| `LLM_API_KEY` | IronClaw secret | LLM provider API key (OpenAI etc.) |
| `LLM_ENDPOINT_URL` | Env | Default: `https://api.openai.com/v1/chat/completions` |
| `LLM_MODEL` | Env | Default: `gpt-4o-mini` |
| `LLM_MAX_TOKENS` | Env | Default: `2048` |
| `WALRUS_PUBLISHER_URL` | Env | Publisher endpoint |
| `WALRUS_AGGREGATOR_URL` | Env | Aggregator endpoint |
| `WALRUS_STORAGE_EPOCHS` | Env | Default: `5` |

### Frontend

| Variable | Description |
|---|---|
| `VITE_GATEWAY_URL` | Gateway HTTPS URL |
| `VITE_NEAR_NETWORK` | `testnet` or `mainnet` |
| `VITE_NEAR_CONTRACT_ID` | Contract address |
| `VITE_GATEWAY_FUNCKEY_PUBKEY` | Gateway's Ed25519 public key for wallet delegation |

## 10. Rollback Procedure

| Layer | Rollback | Risk |
|---|---|---|
| NEAR Contract | Re-deploy previous WASM with `without-init-call`. State preserved. | Low |
| Gateway | `wrangler rollback` — CF keeps previous versions. | None |
| IronClaw Agent | `ironclaw rollback`. If TEE measurement differs from current sealed secret → blobs unrecoverable until migration. | **HIGH — verify measurement parity first** |
| Frontend | `wrangler pages rollback`. | None |

> [!CAUTION]
> Never roll back the IronClaw agent without verifying that the rollback target binary has the SAME TEE measurement as the currently sealed master secret. If measurements differ, all vault blobs become unrecoverable. Contact IronClaw support if unsure.