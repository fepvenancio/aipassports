/**
 * @title SyncService
 * @notice Orchestrates the Hybrid Write-Behind Synchronization Engine.
 * @dev Manages immediate async pushes and debounced batch updates to Cloudflare R2.
 */

/* //////////////////////////////////////////////////////////////
                            SYNC SERVICE
//////////////////////////////////////////////////////////////*/

export class SyncService {
  _syncProvider;
  _cryptoEngine;
  _timers;
  _pendingStates;
  _debounceMs;

  /**
   * @param {ISyncProvider} syncProvider - Concrete storage adapter (e.g., CloudflareR2Adapter).
   * @param {ICryptoEngine} cryptoEngine - Concrete crypto adapter (e.g., AESGCMEngine).
   * @param {object} [options] - Optional configuration.
   * @param {number} [options.debounceMs=30000] - Debounce window in milliseconds.
   */
  constructor(syncProvider, cryptoEngine, options = {}) {
    this._syncProvider = syncProvider;
    this._cryptoEngine = cryptoEngine;
    this._timers = new Map(); // vaultId -> timeoutId
    this._pendingStates = new Map(); // vaultId -> { state, dek }
    this._debounceMs = options.debounceMs ?? 30000;
  }

  /* //////////////////////////////////////////////////////////////
                          SYNC STRATEGIES
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Executes an immediate, non-blocking asynchronous push to the provider.
   * @dev Fire-and-forget implementation to safeguard the <5ms latency budget.
   * @param {string} vaultId - Unique identifier for the vault storage key.
   * @param {object} aggregateState - The raw JS object representing the vault state.
   * @param {Buffer} dek - The Data Encryption Key.
   */
  immediateSync(vaultId, aggregateState, dek) {
    this._performSync(vaultId, aggregateState, dek).catch((error) => {
      console.error(`[SYNC_SERVICE_CRITICAL_FAILURE] ${vaultId}:`, error.message);
    });
  }

  /**
   * @notice Queues a debounced synchronization task.
   * @dev Batches high-frequency updates into a single encrypted upload after an idle window.
   * @param {string} vaultId - Unique identifier for the vault storage key.
   * @param {object} aggregateState - The raw JS object representing the vault state.
   * @param {Buffer} dek - The Data Encryption Key.
   */
  queueDebouncedSync(vaultId, aggregateState, dek) {
    this._pendingStates.set(vaultId, { state: aggregateState, dek });

    if (this._timers.has(vaultId)) {
      clearTimeout(this._timers.get(vaultId));
    }

    const timeoutId = setTimeout(() => {
      const pending = this._pendingStates.get(vaultId);
      if (pending) {
        this._performSync(vaultId, pending.state, pending.dek)
          .then(() => {
            this._pendingStates.delete(vaultId);
            this._timers.delete(vaultId);
          })
          .catch((error) => {
            console.error(`[SYNC_SERVICE_DEBOUNCE_FAILURE] ${vaultId}:`, error.message);
          });
      }
    }, this._debounceMs);

    this._timers.set(vaultId, timeoutId);
  }

  /* //////////////////////////////////////////////////////////////
                          LIFECYCLE
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Flushes all pending debounce states immediately.
   * @dev Called during graceful shutdown to prevent data loss.
   * @returns {Promise<void>}
   */
  async flush() {
    const pendingIds = [...this._pendingStates.keys()];
    for (const vaultId of pendingIds) {
      const pending = this._pendingStates.get(vaultId);
      if (pending) {
        if (this._timers.has(vaultId)) {
          clearTimeout(this._timers.get(vaultId));
        }
        try {
          await this._performSync(vaultId, pending.state, pending.dek);
        } catch (error) {
          console.error(`[SYNC_SERVICE_FLUSH_FAILURE] ${vaultId}:`, error.message);
        }
        this._pendingStates.delete(vaultId);
        this._timers.delete(vaultId);
      }
    }
  }

  /**
   * @notice Tears down the service: clears timers and pending state.
   * @dev Call flush() before destroy() if you want to persist pending data.
   */
  destroy() {
    for (const [, timeoutId] of this._timers) {
      clearTimeout(timeoutId);
    }
    this._timers.clear();
    this._pendingStates.clear();
  }

  /* //////////////////////////////////////////////////////////////
                          INTERNAL LOGIC
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Internal helper to encrypt and push data.
   * @dev Fault-tolerant wrapper for storage operations.
   */
  async _performSync(vaultId, state, dek) {
    try {
      const plaintext = JSON.stringify(state);
      const encryptedBlob = await this._cryptoEngine.encrypt(plaintext, dek);
      await this._syncProvider.push(`${vaultId}/vault.json`, encryptedBlob);
      console.error(`[SYNC_SERVICE] Successfully persisted ${vaultId} to cloud.`);
    } catch (error) {
      throw new Error(`PERFORM_SYNC_FAILED: ${error.message}`);
    }
  }
}