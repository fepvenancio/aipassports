# SYNC-005: Storage & Persistence Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Overview

Project Aegis uses a **per-entry pointer model**. Each vault entry (wiki page, skill) is an independent encrypted blob stored on Walrus Protocol. The NEAR smart contract holds a pointer index — a pair of `LookupMap`s of composite key → `VaultPointer`. There is no monolithic vault blob, no write-behind sync queue, and no stale-cache problem.

Every mutation follows a strict sequential write path:
```
encrypt (TEE) → upload (Walrus) → point (NEAR)
```
And every read follows the inverse:
```
lookup (NEAR) → download (Walrus) → decrypt (TEE) → verify (SHA-256)
```

## 2. Write Path (Mutation)

Every vault mutation MUST follow this exact seven-step sequence. The entire operation MUST be treated as failed if any step errors — success is only returned to the MCP client after step 7 confirms the NEAR transaction.

```
MCP Client → Gateway → IronClaw Agent
                             │
                             ├─ Step 1: Derive per-user DEK
                             │          HKDF-SHA256(master_secret, near_account_id_bytes,
                             │                      b"aipassport-dek-v1", 32)
                             │
                             ├─ Step 2: Serialize entry to JSON payload
                             │          { "version": 1, "content": "...", "metadata": {} }
                             │          → UTF-8 bytes
                             │
                             ├─ Step 3: Compute integrity hash
                             │          content_sha256 = hex(SHA-256(plaintext_bytes))
                             │          ⚠ Computed BEFORE encryption (hash of plaintext, not ciphertext)
                             │
                             ├─ Step 4: Generate random IV
                             │          iv = CSPRNG(12 bytes)  ← fresh per write, never reused
                             │
                             ├─ Step 5: AES-256-GCM encrypt
                             │          (ciphertext, auth_tag) = AES_256_GCM_Encrypt(
                             │            key=DEK, iv=iv, plaintext=payload_bytes)
                             │          blob = iv || auth_tag || ciphertext  (28 + N bytes)
                             │
                             ├─ Step 6: Upload to Walrus
                             │          PUT {WALRUS_PUBLISHER_URL}/v1/blobs?epochs={N}
                             │          Body: blob bytes
                             │          ← blobId (from response JSON)
                             │          ⚠ Log blobId to audit log BEFORE step 7
                             │            (orphan detection if step 7 fails)
                             │
                             └─ Step 7: Update NEAR pointer
                                        Gateway submits NEAR transaction:
                                        update_wiki_pointer(slug, blobId, content_sha256)
                                        Signed with function call access key
                                        ← NEAR confirms transaction hash
```

**Steps 6 and 7 are NOT atomic** — they are two sequential network operations across different systems. If step 7 fails after step 6 succeeds, the blob exists on Walrus without a NEAR pointer. This is an **orphaned blob**. Orphaned blobs:
- Are inaccessible to users (no NEAR pointer to find them).
- Are NOT a security risk (they are encrypted with the per-user DEK).
- Expire naturally when their Walrus storage epoch ends.
- Can be identified from the pre-step-7 audit log for manual cleanup if needed.

**Rollback on step 7 failure:** Return error to MCP client with `VAULT_ERROR_POINTER_UPDATE_FAILED` and include the `blobId` in the error response so the operator can log it. Do NOT retry step 6 — the same plaintext will produce a different ciphertext (different IV) so re-uploading creates a new blob with a new blobId.

## 3. Read Path

```
MCP Client (wiki/read) → Gateway → IronClaw Agent
                                         │
                                         ├─ Step 1: NEAR RPC view call
                                         │          get_wiki_pointer(account_id, slug)
                                         │          → { blob_id, content_sha256, updated_at_ms }
                                         │          → If null: return VAULT_ERROR_NOT_FOUND
                                         │
                                         ├─ Step 2: Download from Walrus
                                         │          GET {WALRUS_AGGREGATOR_URL}/v1/blobs/{blob_id}
                                         │          → raw encrypted bytes
                                         │          → If 404: return VAULT_ERROR_BLOB_NOT_FOUND
                                         │            (blob may have expired — epoch ended)
                                         │
                                         ├─ Step 3: Parse blob format
                                         │          iv       = bytes[0..12]
                                         │          auth_tag = bytes[12..28]
                                         │          ciphertext = bytes[28..]
                                         │
                                         ├─ Step 4: Derive per-user DEK
                                         │          (same as write path Step 1)
                                         │
                                         ├─ Step 5: AES-256-GCM decrypt
                                         │          plaintext_bytes = AES_256_GCM_Decrypt(
                                         │            key=DEK, iv=iv,
                                         │            ciphertext=ciphertext, tag=auth_tag)
                                         │          → If tag verification fails:
                                         │            VAULT_ERROR_DECRYPTION_FAILED
                                         │            (indicates tampering or corruption)
                                         │
                                         ├─ Step 6: Verify integrity
                                         │          computed = hex(SHA-256(plaintext_bytes))
                                         │          stored   = content_sha256 from NEAR
                                         │          → If mismatch: VAULT_ERROR_INTEGRITY_MISMATCH
                                         │            (should not happen if AES-GCM tag passed —
                                         │             defence-in-depth)
                                         │
                                         └─ Step 7: Parse and return
                                                    entry = JSON.parse(plaintext_bytes)
                                                    return { content: entry.content,
                                                             metadata: entry.metadata }
```

## 4. Vault Entry JSON Schema (The Plaintext Payload)

The JSON payload encrypted in every Walrus blob MUST conform to this schema:

```json
{
  "$schema": "aegis-vault-entry/v1",
  "version": 1,
  "type": "wiki" | "skill",
  "content": "<string>",
  "metadata": {
    "createdAt": 1716000000000,
    "updatedAt": 1716003600000,
    "tags": ["optional", "array", "of", "strings"]
  }
}
```

**Field rules:**
- `version`: always `1` for this schema version. Must be present. Future versions increment this.
- `type`: `"wiki"` for wiki pages, `"skill"` for skill configurations.
- `content`: the raw markdown or text content for wiki; JSON-serialised skill config for skills.
- `metadata.createdAt`: Unix ms of first creation. Set once, never updated.
- `metadata.updatedAt`: Unix ms of this write. Updated on every mutation.
- `metadata.tags`: optional array of lowercase alphanumeric strings.

**Skill `content` sub-schema:**
```json
{
  "name": "Security Scanner",
  "description": "Audit Solidity contracts for common vulnerabilities",
  "llmEndpointUrl": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4o",
  "systemPrompt": "You are a Solidity security expert...",
  "maxTokens": 2048,
  "schema": {
    "input": { "type": "string", "description": "Solidity source code" }
  }
}
```

## 5. Encrypted Blob Format

All Walrus blobs MUST use the following binary layout:

```
Offset  Size     Field
──────  ──────   ─────────────────────────────────────────────────
0       12 B     IV (nonce): cryptographically random per write
12      16 B     AES-256-GCM authentication tag
28      N bytes  Ciphertext (AES-256-GCM encrypted JSON payload)
──────  ──────
Total: 28 + N bytes (N = len(plaintext_bytes))
```

- **IV generation**: `crypto_secure_random(12)` — must be fresh for EVERY write, even if content is unchanged from a previous write.
- **IV reuse**: PROHIBITED. Reusing an IV with the same key (DEK) catastrophically breaks AES-GCM security — the keystream becomes recoverable.
- **Auth tag verification**: the 16-byte auth tag MUST be verified during every decryption. A tag failure MUST abort immediately — it indicates ciphertext tampering.
- **Blob size**: for typical wiki pages (100–10,000 chars), expect 128–10,028 byte blobs — negligible Walrus cost.

## 6. NEAR Contract Storage

### 6.1 VaultPointer Structure
```
VaultPointer {
  blob_id:        String  // Walrus blobId, max 128 chars, printable ASCII
  content_sha256: String  // exactly 64 lowercase hex chars (SHA-256 of plaintext)
  updated_at_ms:  u64     // set by contract to env::block_timestamp_ms() at write time
}
```

### 6.2 Storage Staking
- NEAR requires ~1 NEAR staked per 100 KB of on-chain state.
- Each `VaultPointer` entry: ~162–352 bytes (see NEAR.md §9).
- Staked NEAR is locked but recoverable on deletion.
- The contract REQUIRES a storage deposit for NEW entries. See NEAR.md §4.2.

### 6.3 Concurrent Write Ordering
- NEAR's transaction processing guarantees sequential ordering of transactions from the same account.
- Multiple in-flight write requests from the same `nearAccountId` will be processed by NEAR in transaction submission order.
- **No gateway-level queueing is required.** The NEAR protocol handles this natively.
- Concurrent writes from DIFFERENT users are fully independent — no locking needed at any level.
- Edge case: if two MCP clients for the same user submit writes to the same slug simultaneously, NEAR will process them in order. The last-confirmed transaction wins — the intermediate state is committed then overwritten. This is acceptable; true multi-client concurrent editing is not a v1 concern.

## 7. Walrus Blob Lifecycle

### 7.1 Epochs
- Walrus stores blobs for a configurable number of epochs (agent env: `WALRUS_STORAGE_EPOCHS`, default: `5`).
- Each epoch ≈ 2 weeks on Walrus mainnet. 5 epochs ≈ 10 weeks of guaranteed availability.
- After the epoch expires, the blob is deleted by Walrus — it is no longer retrievable.
- The NEAR pointer continues to exist after epoch expiry — reads will return `VAULT_ERROR_BLOB_NOT_FOUND`.

### 7.2 Renewal Strategy
- The IronClaw agent SHOULD run a background renewal job (weekly cron) to extend epoch durations.
- Renewal process: `list_wiki_slugs` + `list_skill_ids` → for each entry with `updated_at_ms` suggesting expiry within 14 days → re-upload same blob with new epoch count → update NEAR pointer.
- Renewal is an upsert write — same content but new blobId and updated `updated_at_ms`.
- Renewal is best-effort; if it fails, users lose access to expired entries (they can re-upload from their local copy if available).

### 7.3 Deletion Behaviour
- `remove_wiki_pointer` / `remove_skill_pointer` removes the NEAR pointer and releases the storage stake.
- The Walrus blob is NOT explicitly deleted — Walrus does not support early deletion of certified blobs.
- A blob with no NEAR pointer is effectively invisible — no user or system component can locate it.
- Deleted entries: NEAR pointer gone → storage stake refunded → Walrus blob expires naturally.

## 8. Key Derivation Reference

### 8.1 Master Secret Lifecycle
1. **First boot**: agent uses TEE CSPRNG to generate 32 random bytes.
2. **Sealing**: bytes are sealed to the TEE measurement (Intel TDX: seal to MRTD register; NVIDIA CC: equivalent measurement).
3. **Restarts**: same binary + same hardware → same measurement → same sealed secret → same master secret → same DEKs → all blobs remain accessible.
4. **Code update**: new binary → new measurement → new sealed secret → NEW DEKs → all old blobs UNRECOVERABLE.
5. **Migration plan before code update**: decrypt all user blobs under old secret → re-encrypt under new secret → update NEAR pointers → then redeploy. This must be scripted and tested before any agent code update in production.

### 8.2 Per-User DEK
```
HKDF-SHA256:
  IKM  = master_secret                     (32 bytes, sealed to TEE)
  Salt = UTF-8(near_account_id)            (e.g. b"alice.near")
  Info = b"aipassport-dek-v1"              (17 bytes, fixed)
  L    = 32                                (output length in bytes)
```
- Deterministic: same inputs → same 32-byte DEK.
- The DEK MUST be zeroed from memory immediately after the encryption/decryption operation completes.
- The DEK MUST NOT be cached across requests, written to disk, included in logs, or returned in any API response.