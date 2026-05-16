import { ISyncProvider } from '../../Application/Ports/ISyncProvider.js';
import { ICryptoEngine } from '../../Application/Ports/ICryptoEngine.js';
import { IVaultRepository } from '../../Application/Ports/IVaultRepository.js';
import { Vault } from '../../Domain/Aggregates/Vault.js';

/**
 * @title VaultRepository
 * @notice Implements IVaultRepository with LRU cache and encrypted storage.
 * @dev Caches recently-used vaults to avoid redundant decrypt/IO cycles.
 */

/* //////////////////////////////////////////////////////////////
                        VAULT REPOSITORY
//////////////////////////////////////////////////////////////*/

const DEFAULT_TTL_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_MAX_ENTRIES = 256;

export class VaultRepository extends IVaultRepository {
  #syncProvider;
  #cryptoEngine;
  #cache;
  #maxEntries;
  #ttlMs;

  /**
   * @param {ISyncProvider} syncProvider - Storage adapter (R2 or local).
   * @param {ICryptoEngine} cryptoEngine - Encryption engine.
   * @param {object} [options]
   * @param {number} [options.maxEntries=256] - Maximum cached vaults.
   * @param {number} [options.ttlMs=900000] - Cache entry TTL in milliseconds (default 15min).
   */
  constructor(syncProvider, cryptoEngine, options = {}) {
    super();
    this.#syncProvider = syncProvider;
    this.#cryptoEngine = cryptoEngine;
    this.#maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#cache = new Map(); // ownerId -> { vault, accessedAt }
  }

  /**
   * @notice Loads a vault from storage or cache.
   * @param {string} ownerId
   * @returns {Promise<Vault>}
   */
  async load(ownerId) {
    const cached = this.#cache.get(ownerId);
    if (cached && (Date.now() - cached.accessedAt) < this.#ttlMs) {
      return cached.vault;
    }

    try {
      const encryptedBlob = await this.#syncProvider.pull(`${ownerId}/vault.json`);
      const decryptedData = await this.#cryptoEngine.decrypt(encryptedBlob);
      const data = JSON.parse(decryptedData);
      const vault = Vault.fromJSON({ ...data, ownerId });
      this.#touch(ownerId, vault);
      return vault;
    } catch (error) {
      if (error.message.includes('RESOURCE_NOT_FOUND') || error.message.includes('NOT_FOUND')) {
        // New user — return empty vault
        const vault = new Vault(ownerId, [], []);
        this.#touch(ownerId, vault);
        return vault;
      }
      throw new Error(`VAULT_REPOSITORY_LOAD_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Encrypts and persists vault state, updates cache.
   * @param {string} ownerId
   * @param {object} state - Serialized vault state (from vault.toJSON()).
   * @returns {Promise<void>}
   */
  async save(ownerId, state) {
    const plaintext = JSON.stringify(state);
    const encryptedBlob = await this.#cryptoEngine.encrypt(plaintext);
    await this.#syncProvider.push(`${ownerId}/vault.json`, encryptedBlob);
    const vault = Vault.fromJSON({ ...state, ownerId });
    this.#touch(ownerId, vault);
  }

  /**
   * @notice Evicts all expired entries from the cache.
   * @returns {number} Number of entries evicted.
   */
  evictExpired() {
    const now = Date.now();
    let evicted = 0;
    for (const [ownerId, entry] of this.#cache) {
      if (now - entry.accessedAt >= this.#ttlMs) {
        this.#cache.delete(ownerId);
        evicted++;
      }
    }
    return evicted;
  }

  /**
   * @notice Returns the number of cached vaults.
   */
  get cacheSize() {
    return this.#cache.size;
  }

  /* //////////////////////////////////////////////////////////////
                            INTERNALS
  //////////////////////////////////////////////////////////////*/

  #touch(ownerId, vault) {
    // Evict oldest if at capacity
    if (this.#cache.size >= this.#maxEntries) {
      const oldestKey = this.#cache.keys().next().value;
      this.#cache.delete(oldestKey);
    }
    this.#cache.set(ownerId, { vault, accessedAt: Date.now() });
  }
}