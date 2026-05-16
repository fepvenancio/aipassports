/**
 * @title ISyncProvider Port
 * @notice Abstract interface for storage synchronization.
 * @dev Bridges local filesystem and Cloudflare R2.
 */

/* //////////////////////////////////////////////////////////////
                          SYNC PROVIDER
//////////////////////////////////////////////////////////////*/

export class ISyncProvider {
  /**
   * @notice Pushes an encrypted blob to the storage provider.
   * @param {string} key 
   * @param {EncryptedBlob} blob 
   */
  async push(key, blob) { throw new Error('NOT_IMPLEMENTED'); }

  /**
   * @notice Pulls an encrypted blob from the storage provider.
   * @param {string} key 
   * @returns {Promise<EncryptedBlob>}
   */
  async pull(key) { throw new Error('NOT_IMPLEMENTED'); }

  /**
   * @notice Permanently deletes all blocks (GDPR Article 17).
   */
  async nuke() { throw new Error('NOT_IMPLEMENTED'); }
}
