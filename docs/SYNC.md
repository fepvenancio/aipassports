# SYNC-003: Hybrid Synchronization Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Synchronization Overview

The `SyncService` SHALL manage state persistence between the in-memory `Vault` aggregate and the `ISyncProvider` storage. The `VaultRepository` SHALL manage per-user vault hydration with an LRU cache. Per-user Data Encryption Keys (DEKs) derived via HKDF SHALL be used for all encryption operations.

## 2. Write-Behind Strategies

### 2.1 Immediate Synchronization
- All vault mutations (wiki create/update, skill register/remove, unlock) MUST trigger an immediate asynchronous synchronization via `SyncService.immediateSync()`.
- Immediate sync operations SHOULD NOT block the primary application thread (fire-and-forget with error logging).

### 2.2 Debounced Synchronization
- High-frequency state changes SHOULD use `SyncService.queueDebouncedSync()` with a configurable debounce window (default: 30 seconds).

## 3. Key Derivation

### 3.1 Server Pepper
- A 32-byte server pepper MUST be stored at `~/.ai-passport/pepper.key` (local mode) or injected via `PEPPER_KEY` env var (TEE mode).
- On first boot with no existing pepper, a new one MUST be generated and persisted.
- Loss of the pepper SHALL render all encrypted data unrecoverable — this is the crypto-shredding mechanism for GDPR Article 17.

### 3.2 Per-User DEK
- Each user's DEK MUST be derived via `HKDF-SHA256(pepper, ownerId, 'aipassport-dek-v1', 32)`.
- `KeyDerivation.deriveDEK(ownerId)` MUST be deterministic: same inputs always produce the same 32-byte key.
- The DEK MUST be passed to `VaultRepository` for per-user encrypt/decrypt operations.

## 4. Vault Repository

### 4.1 Caching
- `VaultRepository` MUST cache recently-used vaults in an LRU map with a configurable TTL (default: 15 minutes, max: 256 entries).
- Cache entries that exceed the TTL MUST be evicted on next access or via the `evictExpired()` method.

### 4.2 Persistence
- `VaultRepository.load(ownerId)` MUST derive the per-user DEK and use it for decryption.
- `VaultRepository.save(ownerId, state)` MUST derive the per-user DEK and use it for encryption.
- If a vault does not exist for a given `ownerId`, `load()` MUST return an empty `Vault`.

## 5. Storage Format

- All persisted data MUST be serialized as JSON and encrypted using AES-256-GCM with the per-user DEK.
- Encrypted payloads MUST contain the ciphertext, a unique IV (nonce), and an authentication tag.
- Local storage MUST use atomic write-then-rename.

## 6. Graceful Shutdown

- `SyncService` MUST provide `flush()` and `destroy()` methods.
- Process lifecycle management (SIGTERM/SIGINT handlers) SHALL be owned by `main.js`.
- The shutdown sequence MUST be: `flush()` → `destroy()` → `shutdown session manager` → `exit`.