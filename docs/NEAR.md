# NEAR-002: Smart Contract Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Overview

The NEAR smart contract is the **on-chain vault index** for Project Aegis. It is the authoritative source of truth for:
- Which NEAR account owns which vault entries.
- Where each entry's encrypted blob lives on Walrus (the `blobId`).
- The SHA-256 integrity hash of each entry's plaintext (for tamper detection after decryption).

The contract stores NO plaintext, NO encrypted content, and NO keys. It is a pure, access-controlled pointer registry serving ALL users — one shared contract deployment for the entire product.

## 2. Architectural Decision: Shared Contract (Multi-User)

**The contract is a single shared deployment.** One operator account deploys it once. All users register their vault pointers in this single contract. This is the standard NEAR dApp pattern.

**Why not one-contract-per-user?**
- Requires every user to deploy a contract and pay the minimum contract balance (~5 NEAR).
- Terrible UX for non-technical users (FastAuth path).
- Complicates the gateway which would need to track per-user contract addresses.

**Implication for access control:** There is no single `owner_id` field. Instead, mutations are gated by `env::predecessor_account_id()`. Each user can only write to the entries indexed under their own `AccountId`. View methods are intentionally public — the pointers (blobId + hash) are not sensitive; only the blobs on Walrus are sensitive (and always encrypted before upload).

## 3. On-Chain Data Model

### 3.1 VaultPointer
```rust
/// @notice Pointer to an AES-256-GCM encrypted blob stored on Walrus Protocol.
/// @dev The contract stores only the locator and integrity hash — never content.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct VaultPointer {
    /// @notice Walrus blobId — opaque string address on the Walrus network.
    /// Maximum 128 characters. Must be non-empty.
    pub blob_id: String,

    /// @notice SHA-256 hex digest of the plaintext bytes BEFORE encryption.
    /// Used by the IronClaw agent to verify data integrity after decryption.
    /// Always 64 lowercase hex characters.
    pub content_sha256: String,

    /// @notice Unix timestamp in milliseconds of the last successful write.
    /// Set by the contract to env::block_timestamp_ms() at write time.
    pub updated_at_ms: u64,
}
```

### 3.2 AegisContract (Shared Multi-User State)
```rust
/// @notice Shared vault index for all Project Aegis users.
/// @dev Uses composite string keys to partition per-user data within shared LookupMaps.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AegisContract {
    /// @notice Wiki page pointer lookup.
    /// Key format: "{account_id}:{slug}" — colon is the separator.
    /// AccountIds are validated by NEAR (lowercase alphanumeric, dot, dash, underscore — no colons).
    /// Slugs are validated to [a-z0-9_-] by this contract (no colons allowed).
    /// LookupMap storage prefix: b"wp"
    wiki_pointers: LookupMap<String, VaultPointer>,

    /// @notice Skill pointer lookup.
    /// Key format: "{account_id}:{skill_id}" — same separator rules.
    /// LookupMap storage prefix: b"sp"
    skill_pointers: LookupMap<String, VaultPointer>,

    /// @notice Per-user list of wiki slugs for enumeration (e.g., building MCP tool list).
    /// Key: AccountId. Value: Vec<String> of slugs owned by that account.
    /// LookupMap storage prefix: b"wl"
    /// @dev Vec<String> is serialised as a single borsh blob per user entry.
    ///      Acceptable for typical vault sizes (<1000 entries per user, ~30-50KB per list).
    wiki_slug_lists: LookupMap<AccountId, Vec<String>>,

    /// @notice Per-user list of skill IDs for enumeration.
    /// LookupMap storage prefix: b"sl"
    skill_id_lists: LookupMap<AccountId, Vec<String>>,
}
```

### 3.3 Key Format Specification
- **Separator**: single colon `:` character.
- **AccountId side**: any valid NEAR AccountId. NEAR protocol enforces its own format (lowercase alphanumeric + `_`, `-`, `.`, max 64 chars). Colons are NOT valid in NEAR AccountIds by protocol rules.
- **Slug/ID side**: MUST match regex `^[a-z0-9][a-z0-9_-]{0,127}$` — lowercase alphanumeric, hyphens, underscores; must start with alphanumeric; max 128 chars total. Colons are explicitly PROHIBITED. Validation panics with `VAULT_ERROR_INVALID_IDENTIFIER` on violation.
- **Composite key construction**: `format!("{}:{}", account_id.as_str(), slug)` — this is unambiguous because the slug cannot contain colons, and the separator is exactly one colon.

## 4. Contract Methods

### 4.1 Initialization

```rust
/// @notice Initializes the shared contract. Called once by the operator at deployment.
/// @dev MUST be called immediately after deployment via `--init-call new '{}'`.
///      PanicOnDefault ensures no method can be called on an uninitialised contract.
#[init]
pub fn new() -> Self
```

Deployment command MUST use `with-init-call`:
```bash
near contract deploy aegis-vault.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  network-config testnet sign-with-keychain send
```

### 4.2 Mutation Methods (write — require caller's signature)

All mutation methods use `env::predecessor_account_id()` as the authoritative user identity. The caller IS their identity — no parameter is accepted for `account_id` in mutations (to prevent impersonation). The `predecessor_account_id()` is the NEAR account that cryptographically signed the transaction.

| Method | Parameters | Description |
|---|---|---|
| `update_wiki_pointer` | `slug: String, blob_id: String, content_sha256: String` | Upsert a wiki page pointer. Creates if new, overwrites if exists. |
| `remove_wiki_pointer` | `slug: String` | Delete a wiki page pointer and release its storage stake. |
| `update_skill_pointer` | `skill_id: String, blob_id: String, content_sha256: String` | Upsert a skill pointer. |
| `remove_skill_pointer` | `skill_id: String` | Delete a skill pointer and release its storage stake. |

**Storage deposit requirement:**
- Creating a NEW entry requires an attached deposit covering storage cost.
- Minimum deposit for `update_*` when creating: `env::storage_byte_cost() * estimated_bytes`.
- Estimated bytes per entry: `len(account_id) + 1 + len(slug) + ~180 bytes` (borsh-serialised VaultPointer).
- The contract MUST refund excess deposit: `Promise::new(caller).transfer(excess)`.
- Updating an EXISTING entry (same composite key, new pointer values) does NOT require a deposit — the storage slot is already paid for.
- On delete: the contract MUST refund the original storage stake via `Promise::new(caller).transfer(released_stake)`. This refund is an async `Promise` and may fail if the caller account no longer exists — this is acceptable (best-effort refund). Failures are logged but do not revert the deletion.

### 4.3 View Methods (read-only — no gas cost, callable by anyone)

| Method | Parameters | Returns | Description |
|---|---|---|---|
| `get_wiki_pointer` | `account_id: AccountId, slug: String` | `Option<VaultPointer>` | Fetch a single pointer. Returns `null` if not found. |
| `get_skill_pointer` | `account_id: AccountId, skill_id: String` | `Option<VaultPointer>` | Fetch a single pointer. Returns `null` if not found. |
| `list_wiki_slugs` | `account_id: AccountId, from_index: u64, limit: u64` | `Vec<String>` | Paginated list of wiki slugs for this account. |
| `list_skill_ids` | `account_id: AccountId, from_index: u64, limit: u64` | `Vec<String>` | Paginated list of skill IDs for this account. |

- `limit` MUST be capped at 100. If `limit > 100`, the contract MUST use 100 silently (NOT panic).
- `from_index` beyond the list length MUST return an empty `Vec` (NOT panic).
- Both view methods are used by the Hono gateway at session start to build the user's dynamic MCP tool list.
- View methods expose pointer data (blobId + hash) publicly. This is intentional — content is encrypted at the Walrus layer. The blobId and SHA-256 hash are not sensitive.

## 5. Validation Rules

All slugs and skill IDs MUST satisfy:
```
Regex: ^[a-z0-9][a-z0-9_-]{0,127}$
Rules:
  - Start with [a-z0-9] (lowercase alphanumeric only)
  - Subsequent chars: [a-z0-9_-] (lowercase alphanumeric, hyphen, underscore)
  - Total length: 1–128 characters
  - Colons (:) PROHIBITED — they are the composite key separator
  - Whitespace PROHIBITED
  - Uppercase PROHIBITED
On violation: panic with "VAULT_ERROR_INVALID_IDENTIFIER"
```

`blob_id` MUST satisfy:
```
  - Non-empty
  - Maximum 128 characters
  - Must contain only printable ASCII (no null bytes, no control chars)
On violation: panic with "VAULT_ERROR_INVALID_BLOB_ID"
```

`content_sha256` MUST satisfy:
```
  - Exactly 64 characters
  - All characters must be [0-9a-f] (lowercase hex only)
On violation: panic with "VAULT_ERROR_INVALID_HASH"
```

## 6. Access Control Model

```
User (NEAR AccountId) ──signs──► NEAR Transaction
                                       │
                                       ▼
                               AegisContract
                                       │
                    env::predecessor_account_id() → "alice.near"
                                       │
                    Composite key: "alice.near:my-notes"
                                       │
                    Only modifies entries under "alice.near:*"
                                       │
                    Cannot access "bob.near:*" — different key prefix
```

No explicit `assert_owner()` needed. The access control IS the composite key: a user can only affect entries whose composite key starts with their account ID, because `predecessor_account_id()` is the cryptographically signed identity and is used directly to construct the key.

## 7. Function Call Key Delegation (For Gateway MCP Flow)

When users interact via MCP tools (Cursor, Claude Code), the Hono gateway submits NEAR transactions on their behalf. This uses NEAR's native **Function Call Access Keys**:

### 7.1 What a Function Call Access Key Is
- A scoped private key on the USER's NEAR account (NOT the gateway's account).
- It can ONLY call specific methods on a specific contract.
- It CANNOT transfer NEAR tokens (full access is NOT granted).
- `predecessor_account_id()` in the contract is still the USER's account ID — the delegation is transparent to the contract.

### 7.2 Key Scope
```json
{
  "permission": {
    "FunctionCall": {
      "allowance": "250000000000000000000000",
      "receiver_id": "aegis-vault.near",
      "method_names": [
        "update_wiki_pointer",
        "remove_wiki_pointer",
        "update_skill_pointer",
        "remove_skill_pointer"
      ]
    }
  }
}
```
- `allowance`: 0.25 NEAR (≈ 2,500 pointer writes at 100 Tgas each ≈ many years of usage). User can replenish.
- `receiver_id`: the deployed Aegis contract address — calls to other contracts are PROHIBITED.
- `method_names`: only the four mutation methods. Read-only (view) calls require no key.

### 7.3 Key Grant Flow (Dashboard Onboarding)
1. User signs into the dashboard.
2. Dashboard calls `nearWallet.signIn({ contractId: 'aegis-vault.near', methodNames: [...] })`.
3. The NEAR wallet prompts the user: "Allow Aegis to call these methods on your behalf?"
4. User approves — wallet creates the function call access key and registers it on the user's NEAR account.
5. The wallet stores the corresponding private key in the browser's local storage (NEAR Wallet Selector handles this).
6. The gateway uses this private key (passed during session establishment) to sign NEAR transactions for MCP calls.

### 7.4 Key Storage in the Gateway
- During session creation (`/auth/unlock`), the client sends the function call access key private key to the gateway.
- The gateway encrypts it with its own master key and stores it in Cloudflare KV: `funckey:{nearAccountId}` → encrypted private key.
- TTL: same as the session TTL (key is purged when session expires).
- The gateway MUST zero-fill the key from memory immediately after storing to KV.
- If the session expires and a new one is created, the client MUST re-supply the key.

### 7.5 Key Revocation
- The user can revoke the function call access key at any time via the NEAR dashboard or CLI.
- After revocation, MCP mutations fail with a NEAR authentication error — the gateway surfaces this as a structured error: `VAULT_ERROR_DELEGATION_REVOKED`.
- Data already written to Walrus and NEAR is unaffected. New writes require re-delegation.

## 8. Error Code Registry

All panics produce a string error code. Reference implementation:

| Error Code | Trigger | Recoverable? |
|---|---|---|
| `VAULT_ERROR_INVALID_IDENTIFIER` | Slug/ID fails regex validation | Yes — fix the slug |
| `VAULT_ERROR_INVALID_BLOB_ID` | `blob_id` is empty or >128 chars | Yes — fix the blob_id |
| `VAULT_ERROR_INVALID_HASH` | `content_sha256` is not 64 lowercase hex chars | Yes — fix the hash |
| `VAULT_ERROR_INSUFFICIENT_DEPOSIT` | New entry without sufficient attached NEAR | Yes — attach more NEAR |
| `VAULT_ERROR_NOT_FOUND` | `remove_*` called on non-existent slug | Yes — check slug exists first |

## 9. Storage Economics

- NEAR storage staking: ~1 NEAR per 100 KB of on-chain state.
- Staked NEAR is locked but NOT burned — recovered on deletion.

Per-entry breakdown:
| Component | Approximate Size |
|---|---|
| Composite key (`account_id` + `:` + `slug`) | 10–200 bytes |
| `blob_id` (Walrus blobId) | ~60 bytes |
| `content_sha256` | 64 bytes |
| `updated_at_ms` | 8 bytes |
| Borsh framing overhead | ~20 bytes |
| **Total per entry** | **~162–352 bytes** |

Practical cost: 1 NEAR supports ~285–617 entries. For 1,000 entries per user, expect ~2–4 NEAR locked in storage staking (not spent — recoverable).

The `wiki_slug_lists` and `skill_id_lists` add ~`num_entries * avg_slug_length` bytes per user (one borsh blob per user). For 100 entries averaging 15 chars: ~1.5 KB per user for the list.

## 10. NEAR CLI Reference

```bash
# Deploy (first time — MUST include init call)
near contract deploy aegis-vault.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  with-init-call new json-args '{}' \
  prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' \
  network-config testnet sign-with-keychain send

# Re-deploy (upgrade — state is preserved, init NOT called again)
near contract deploy aegis-vault.testnet \
  use-file target/wasm32-unknown-unknown/release/backend.wasm \
  without-init-call \
  network-config testnet sign-with-keychain send

# Read a wiki pointer (free, no gas)
near contract call-function as-read-only aegis-vault.testnet \
  get_wiki_pointer \
  json-args '{"account_id": "alice.near", "slug": "my-notes"}' \
  network-config testnet now

# Write a wiki pointer (costs gas + storage deposit for new entries)
near contract call-function as-transaction aegis-vault.testnet \
  update_wiki_pointer \
  json-args '{"slug": "my-notes", "blob_id": "abc123xyz...", "content_sha256": "deadbeef...64chars"}' \
  prepaid-gas '100.0 Tgas' \
  attached-deposit '0.01 NEAR' \
  sign-as alice.near \
  network-config testnet sign-with-keychain send

# List wiki slugs (free, paginated)
near contract call-function as-read-only aegis-vault.testnet \
  list_wiki_slugs \
  json-args '{"account_id": "alice.near", "from_index": 0, "limit": 50}' \
  network-config testnet now

# Delete a pointer (refunds storage stake)
near contract call-function as-transaction aegis-vault.testnet \
  remove_wiki_pointer \
  json-args '{"slug": "my-notes"}' \
  prepaid-gas '50.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as alice.near \
  network-config testnet sign-with-keychain send
```
