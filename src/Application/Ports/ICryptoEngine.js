/**
 * @title ICryptoEngine Port
 * @notice Abstract interface for cryptographic operations.
 * @dev Enforces hardware-backed security or local emulation.
 */

/* //////////////////////////////////////////////////////////////
                          CRYPTO ENGINE
//////////////////////////////////////////////////////////////*/

export class ICryptoEngine {
  /**
   * @notice Encrypts data using AES-256-GCM.
   * @param {string} plaintext - The raw string to encrypt.
   * @param {Buffer} [dek] - Optional Data Encryption Key. Falls back to master key.
   * @returns {Promise<EncryptedBlob>}
   */
  async encrypt(plaintext, dek) { throw new Error('NOT_IMPLEMENTED'); }

  /**
   * @notice Decrypts an EncryptedBlob.
   * @param {EncryptedBlob} blob - The authenticated ciphertext packet.
   * @param {Buffer} [dek] - Optional Data Encryption Key. Falls back to master key.
   * @returns {Promise<string>}
   */
  async decrypt(blob, dek) { throw new Error('NOT_IMPLEMENTED'); }

  /**
   * @notice Shreds the master KEK (Right to Forgotten).
   * @returns {Promise<void>}
   */
  async nuke() { throw new Error('NOT_IMPLEMENTED'); }
}
