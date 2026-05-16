# SYNC-002: Hybrid Synchronization Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Synchronization Overview

The `SyncService` SHALL manage state persistence between the in-memory `Vault` aggregate and the `ISyncProvider` storage. The `VaultRepository` SHALL manage per-user vault hydration with an LRU cache.

## 2. Write-Behind Strategies

### 2.1 Immediate Synchronization
- Critical state changes (e.g., Skill registration, Master Key Shredding) MUST trigger an immediate, asynchronous synchronization via `SyncService.immediateSync()`.
- Immediate sync operations SHOULD NOT block the primary application thread (fire-and-forget with error logging).

### 2.2 Debounced Synchronization
- High-frequency state changes (e.g., Wiki edits) MUST utilize a sliding-window debounce strategy via `SyncService.queueDebouncedSync()`.
- The default debounce threshold SHALL be 30 seconds (configurable via `options.debounceMs`).
- Multiple updates within the debounce window MUST be aggregated into a single atomic write.
- The system MUST ensure that the final state captured at the end of the window is the one persisted to the storage provider.

### 2.3 Graceful Shutdown
- `SyncService` MUST provide a `flush()` method that persists all pending debounce states immediately.
- `SyncService` MUST provide a `destroy()` method that clears all timers and pending state without persisting.
- Process lifecycle management (SIGTERM/SIGINT handlers) SHALL be owned by `main.js`, which MUST call `syncService.flush()` before `syncService.destroy()`.
- `SyncService` SHALL NOT register its own process signal handlers.

## 3. Vault Repository

### 3.1 Caching
- `VaultRepository` MUST cache recently-used vaults in an LRU map with a configurable TTL (default: 15 minutes).
- Cache entries that exceed the TTL MUST be evicted on next access or via the `evictExpired()` method.
- Maximum cache entries SHALL default to 256.

### 3.2 Hydration
- `VaultRepository.load(ownerId)` MUST attempt to pull and decrypt the vault from the storage provider.
- If the vault does not exist (new user), `load()` MUST return an empty `Vault` for that owner.
- `VaultRepository.save(ownerId, state)` MUST encrypt and push the serialized state, then update the cache.

## 4. Storage Format

- All persisted data MUST be serialized as JSON and encrypted using AES-256-GCM before transmission to the sync provider.
- Encrypted payloads MUST contain the ciphertext, a unique IV (nonce), and an authentication tag.
- Local storage MUST use atomic write-then-rename (`file.tmp.RANDOM_HEX` → `file`).

## 5. Fault Tolerance

- Synchronization failures SHALL NOT crash the application process.
- Failed operations MUST be logged to the diagnostic stream (`stderr`).
- R2 `nuke()` MUST paginate with `ContinuationToken` to handle buckets with >1000 objects.