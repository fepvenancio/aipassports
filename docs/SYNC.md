# SYNC-001: Hybrid Synchronization Specification

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

## 1. Synchronization Overview

The `SyncService` SHALL manage state persistence between the in-memory `Vault` aggregate and the `ISyncProvider` storage.

## 2. Write-Behind Strategies

### 2.1 Immediate Synchronization
- Critical state changes (e.g., Skill registration, Master Key Shredding) MUST trigger an immediate, asynchronous synchronization.
- Immediate sync operations SHOULD NOT block the primary application thread.

### 2.2 Debounced Synchronization
- High-frequency state changes (e.g., Wiki edits) MUST utilize a sliding-window debounce strategy.
- The default debounce threshold SHALL be 30 seconds.
- Multiple updates within the debounce window MUST be aggregated into a single atomic write.
- The system MUST ensure that the final state captured at the end of the window is the one persisted to the storage provider.

## 3. Storage Format

- All persisted data MUST be serialized as JSON and encrypted using AES-256-GCM before transmission to the sync provider.
- Encrypted payloads MUST contain the ciphertext, a unique IV (nonce), and an authentication tag.

## 4. Fault Tolerance

- Synchronization failures SHALL NOT crash the application process.
- Failed operations MUST be logged to the diagnostic stream (`stderr`).
