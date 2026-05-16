/**
 * @title IVaultRepository Port
 * @notice Abstract interface for vault persistence and hydration.
 * @dev Bridges transport layers to storage/crypto infrastructure.
 */

/* //////////////////////////////////////////////////////////////
                        VAULT REPOSITORY
//////////////////////////////////////////////////////////////*/

export class IVaultRepository {
  /**
   * @notice Loads and decrypts a vault for the given owner.
   * @param {string} ownerId - The vault owner's public key hash.
   * @returns {Promise<Vault>} The hydrated vault aggregate, or a new empty vault if none exists.
   */
  async load(ownerId) { throw new Error('NOT_IMPLEMENTED'); }

  /**
   * @notice Encrypts and persists the vault state for the given owner.
   * @param {string} ownerId - The vault owner's public key hash.
   * @param {object} state - The serialized vault state.
   * @returns {Promise<void>}
   */
  async save(ownerId, state) { throw new Error('NOT_IMPLEMENTED'); }
}