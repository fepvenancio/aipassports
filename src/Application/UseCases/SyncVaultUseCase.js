import { Vault } from '../../Domain/Aggregates/Vault.js';

/**
 * @title SyncVaultUseCase
 * @notice Coordinates the synchronization and decryption of the AI Passport.
 */

/* //////////////////////////////////////////////////////////////
                        SYNC VAULT USE CASE
//////////////////////////////////////////////////////////////*/

export class SyncVaultUseCase {
  #cryptoEngine;
  #syncProvider;

  /**
   * @param {ICryptoEngine} cryptoEngine 
   * @param {ISyncProvider} syncProvider 
   */
  constructor(cryptoEngine, syncProvider) {
    this.#cryptoEngine = cryptoEngine;
    this.#syncProvider = syncProvider;
  }

  /**
   * @notice Synchronizes the vault for a given user.
   * @param {string} ownerId 
   * @returns {Promise<Vault>}
   */
  async execute(ownerId) {
    try {
      /* //////////////////////////////////////////////////////////////
                                PULL DATA
      //////////////////////////////////////////////////////////////*/
      const encryptedBlob = await this.#syncProvider.pull(`${ownerId}/vault.json`);
      
      /* //////////////////////////////////////////////////////////////
                                DECRYPT DATA
      //////////////////////////////////////////////////////////////*/
      const decryptedData = await this.#cryptoEngine.decrypt(encryptedBlob);
      const data = JSON.parse(decryptedData);

      /* //////////////////////////////////////////////////////////////
                                HYDRATE VAULT
      //////////////////////////////////////////////////////////////*/
      // Note: In a full implementation, we'd map data to Entity instances
      return new Vault(ownerId, data.skills || [], data.wikiPages || []);
    } catch (error) {
      console.error('USE_CASE_ERROR_SYNC_FAILED', error);
      throw new Error('USE_CASE_ERROR_SYNC_FAILED');
    }
  }
}
