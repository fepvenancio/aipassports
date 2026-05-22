# WALRUS-001: Decentralized Blob Storage Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Overview

Walrus Protocol is the blob storage layer for Project Aegis. Each vault entry (wiki page, skill) is stored as an independent encrypted blob on Walrus. The Walrus `blobId` returned after upload is the sole locator for that blob — it is stored on the NEAR contract as a `VaultPointer`.

Walrus provides:
- **Erasure-coded redundancy**: data survives up to 2/3 of storage nodes going offline.
- **No full replication**: 4–5x replication factor vs. network-wide for Arweave — cost-efficient.
- **Mutable lifecycle**: blobs can be allowed to expire and re-uploaded with updated content.
- **Fast retrieval**: optimised for active, frequently-accessed data (AI context use case).

## 2. Architecture: Per-Entry Blobs

Every vault entry is stored as a SEPARATE Walrus blob. The vault is NOT a single monolithic blob.

```
NEAR Contract (VaultIndex)
├── wiki_pages:
│   ├── "my-notes"     → { blob_id: "Abc...1", content_sha256: "abc...def" }
│   ├── "erc4626-spec" → { blob_id: "Xyz...2", content_sha256: "123...456" }
│   └── "coding-rules" → { blob_id: "Def...3", content_sha256: "789...abc" }
└── skills:
    └── "security-scan" → { blob_id: "Ghi...4", content_sha256: "fed...cba" }

Walrus Network
├── blob "Abc...1" → [IV][tag][AES-GCM ciphertext of "my-notes" content]
├── blob "Xyz...2" → [IV][tag][AES-GCM ciphertext of "erc4626-spec" content]
├── blob "Def...3" → [IV][tag][AES-GCM ciphertext of "coding-rules" content]
└── blob "Ghi...4" → [IV][tag][AES-GCM ciphertext of skill config JSON]
```

**Why per-entry?**
- Editing one wiki page uploads only that entry (~KB), not the entire vault (~GB).
- Different entries can have different epoch lengths (e.g., keep skills for 2 years, drafts for 3 months).
- Deletion of one entry does not affect others.
- Upload failures affect one entry, not the whole vault.

## 3. Encrypted Blob Format

Before upload, the IronClaw agent MUST produce blobs in this exact binary format:

```
Offset  Size  Field
──────  ────  ─────────────────────────────────────────────────────
0       12    IV (nonce): cryptographically random, unique per blob
12      16    AES-GCM authentication tag
28      N     Ciphertext (AES-256-GCM encrypted JSON payload)
──────  ────
Total: 28 + N bytes
```

- The IV MUST be generated fresh for every encryption operation. Reusing an IV with the same DEK is a critical security violation that breaks AES-GCM confidentiality.
- The authentication tag MUST be verified during decryption. A verification failure MUST abort the read — it indicates tampering or corruption.
- The JSON payload before encryption MUST include a `version` field for future schema migrations: `{ "version": 1, "content": "...", "metadata": {} }`.

## 4. Content Integrity

Walrus `blobId` values are addresses, NOT content hashes. They do not self-verify the data's integrity.

The integrity chain is:
```
plaintext bytes
    → SHA-256(plaintext) = content_sha256          [stored in NEAR contract]
    → AES-256-GCM encrypt(plaintext, DEK, IV)      [auth tag verifies ciphertext]
    → upload to Walrus → blobId                    [stored in NEAR contract]

On read:
    blobId → Walrus download → ciphertext
    → AES-256-GCM decrypt (auth tag fail = reject) → plaintext
    → SHA-256(plaintext) vs stored content_sha256  (mismatch = reject)
```

Two independent integrity checks:
1. **AES-GCM tag**: verifies ciphertext was not modified in transit or at rest.
2. **SHA-256 comparison**: verifies the decrypted plaintext matches the originally encrypted data.

## 5. Walrus REST API

The IronClaw agent MUST use the Walrus REST API (no Sui SDK required).

### 5.1 Upload (PUT)
```
PUT {WALRUS_PUBLISHER_URL}/v1/blobs?epochs={N}
Content-Type: application/octet-stream
Body: [raw encrypted bytes — 28 + N bytes]

Response 200 (new upload):
{
  "newlyCreated": {
    "blobObject": {
      "blobId": "abc123...",
      "registeredEpoch": 42,
      "certifiedEpoch": 43
    }
  }
}

Response 200 (already certified — identical bytes uploaded before):
{
  "alreadyCertified": {
    "blobId": "abc123...",
    "event": { ... }
  }
}
```

The agent MUST handle both response shapes and extract `blobId` from either.

**Cross-user safety of `alreadyCertified`:** An `alreadyCertified` response means Walrus has seen identical bytes before. This is safe because AES-256-GCM uses a per-write random IV combined with a per-user DEK. Two users with identical plaintext will produce different ciphertexts (different DEKs → different keystreams). Two writes of the same user with identical plaintext will also produce different ciphertexts (different IVs → different keystreams). Therefore, an `alreadyCertified` response can ONLY occur if the exact same encrypted bytes were uploaded before — which in practice means a retry of a previous failed write, not a cross-user collision.

### 5.2 Download (GET)
```
GET {WALRUS_AGGREGATOR_URL}/v1/blobs/{blobId}
Response: raw encrypted bytes (binary)
```

### 5.3 Endpoints

| Network | Publisher | Aggregator |
|---|---|---|
| Testnet | `https://publisher.walrus-testnet.walrus.space` | `https://aggregator.walrus-testnet.walrus.space` |
| Mainnet | `https://publisher.walrus.space` | `https://aggregator.walrus.space` |

### 5.4 Error Handling
- HTTP 404 on download: blob not found or expired. Surface as `VAULT_ERROR_BLOB_NOT_FOUND`.
- HTTP 402 on upload: insufficient WAL balance. Surface as `WALRUS_ERROR_INSUFFICIENT_BALANCE`.
- HTTP 5xx: transient Walrus network error. Retry up to 3 times with exponential backoff (1s, 2s, 4s) before failing.

## 6. Storage Epochs & Cost

### 6.1 Epoch Duration
- Each Walrus epoch is approximately 2 weeks on mainnet (subject to network governance).
- The default storage duration is 5 epochs (~10 weeks).
- For persistent data (e.g., permanent coding standards), use 26 epochs (~1 year).

### 6.2 Renewal
- Walrus does NOT auto-renew. The IronClaw agent MUST implement a background renewal job.
- Renewal: re-upload the same encrypted bytes (if content unchanged) or new encrypted bytes (if content changed) with a fresh epoch count. Update the NEAR pointer's `updated_at_ms`.
- The renewal job SHOULD run weekly and renew any entry expiring within 14 days.

### 6.3 Approximate Cost (Mainnet — subject to change)
- Walrus mainnet pricing: TBD at general availability (testnet is free).
- Estimated range based on Sui/Walrus economics: $0.001–$0.01 per MB per epoch.
- For typical vault entries (1–50 KB each), cost per entry per year is fractions of a cent.

### 6.4 Dual-Token Dependency (WAL + SUI)
- Walrus is a Sui ecosystem protocol. Storage payments are denominated in **WAL tokens**.
- WAL is purchased on the Sui network using SUI (the L1 token).
- This adds a second token dependency beyond NEAR. The IronClaw agent must have a funded Sui wallet with WAL.
- On **testnet**: no WAL required — Walrus testnet is free and permissionless.
- On **mainnet**: provision WAL in the agent's Sui address before any writes are attempted. Write failures due to insufficient WAL will surface as `WALRUS_ERROR_INSUFFICIENT_BALANCE` (HTTP 402 from Walrus).
- Monitor WAL balance proactively. An empty balance causes ALL wiki/create and wiki/update calls to fail until replenished.

## 7. Frontend Direct Upload

For the Vite dashboard, the frontend MAY upload blobs directly to Walrus (bypassing the IronClaw agent) if the encryption is performed client-side. However, the recommended architecture is:
- **Client → Gateway → IronClaw Agent → Walrus**: agent handles encryption and upload; gateway then submits the NEAR pointer write as a sequential step (see SYNC.md §2 for the full write path and orphaned blob handling).
- Client-side encryption is an advanced option for users who want maximum custody of their DEK, at the cost of not being able to use the IronClaw agent for AI skill execution on their data.

Direct upload from the browser (agent-bypassed mode):
```typescript
const response = await fetch(
  `${WALRUS_PUBLISHER_URL}/v1/blobs?epochs=5`,
  {
    method: "PUT",
    headers: { "Content-Type": "application/octet-stream" },
    body: encryptedBytes,  // Must be pre-encrypted by client
  }
);
const result = await response.json();
const blobId = result.newlyCreated?.blobObject?.blobId
            ?? result.alreadyCertified?.blobId;
```
