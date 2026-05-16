import { Vault } from '../../Domain/Aggregates/Vault.js';
import { Skill } from '../../Domain/Entities/Skill.js';
import { WikiPage } from '../../Domain/Entities/WikiPage.js';

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
  #keyDerivation;

  /**
   * @param {ICryptoEngine} cryptoEngine 
   * @param {ISyncProvider} syncProvider 
   * @param {KeyDerivation} [keyDerivation]
   */
  constructor(cryptoEngine, syncProvider, keyDerivation = null) {
    this.#cryptoEngine = cryptoEngine;
    this.#syncProvider = syncProvider;
    this.#keyDerivation = keyDerivation;
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
      const dek = this.#keyDerivation ? this.#keyDerivation.deriveDEK(ownerId) : undefined;
      const decryptedData = await this.#cryptoEngine.decrypt(encryptedBlob, dek);
      const data = JSON.parse(decryptedData);

      /* //////////////////////////////////////////////////////////////
                                HYDRATE VAULT
      //////////////////////////////////////////////////////////////*/
      const skills = (data.skills || []).map(s =>
        new Skill(s.id, s.name, s.description, s.schema)
      );
      const wikiPages = (data.wikiPages || []).map(p =>
        new WikiPage(p.slug, p.content, p.metadata)
      );

      return new Vault(ownerId, skills, wikiPages);
    } catch (error) {
      console.error('USE_CASE_ERROR_SYNC_FAILED', error);
      throw new Error('USE_CASE_ERROR_SYNC_FAILED');
    }
  }
}
