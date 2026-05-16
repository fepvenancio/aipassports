import crypto from 'crypto';
import { ICryptoEngine } from '../../Application/Ports/ICryptoEngine.js';
import { EncryptedBlob } from '../../Domain/ValueObjects/EncryptedBlob.js';

/**
 * @title AESGCMEngine
 * @notice Production-grade implementation of AES-256-GCM encryption.
 * @dev Utilizes native Node.js crypto with authenticated encryption and secure key disposal.
 */

/* //////////////////////////////////////////////////////////////
                            AES GCM ENGINE
//////////////////////////////////////////////////////////////*/

export class AESGCMEngine extends ICryptoEngine {
  #masterKey;

  /**
   * @param {Buffer} masterKey - 32-byte (256-bit) cryptographically strong Buffer.
   */
  constructor(masterKey) {
    super();
    this._validateKey(masterKey);
    this.#masterKey = masterKey;
  }

  /* //////////////////////////////////////////////////////////////
                          ENCRYPTION LOGIC
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Encrypts plaintext using AES-256-GCM with automated IV derivation.
   * @param {string} plaintext - The raw string to encrypt.
   * @returns {Promise<EncryptedBlob>}
   */
  async encrypt(plaintext) {
    if (typeof plaintext !== 'string') {
      throw new Error('INFRA_ERROR_CRYPTO_INVALID_PLAINTEXT_TYPE');
    }

    try {
      // 1. Derive unique 12-byte initialization vector (nonce)
      const iv = crypto.randomBytes(12);

      // 2. Initialize cipher with GCM mode
      const cipher = crypto.createCipheriv('aes-256-gcm', this.#masterKey, iv);
      
      // 3. Perform encryption
      let ciphertext = cipher.update(plaintext, 'utf8', 'base64');
      ciphertext += cipher.final('base64');
      
      // 4. Extract 16-byte authentication tag
      const tag = cipher.getAuthTag().toString('base64');

      return new EncryptedBlob(
        ciphertext,
        iv.toString('base64'),
        tag
      );
    } catch (error) {
      throw new Error(`INFRA_ERROR_ENCRYPTION_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Decrypts an EncryptedBlob and verifies its authenticity tag.
   * @param {EncryptedBlob} blob - The authenticated ciphertext packet.
   * @returns {Promise<string>}
   */
  async decrypt(blob) {
    try {
      const iv = Buffer.from(blob.nonce, 'base64');
      const tag = Buffer.from(blob.tag, 'base64');

      // 1. Initialize decipher
      const decipher = crypto.createDecipheriv('aes-256-gcm', this.#masterKey, iv);
      
      // 2. Set expected authentication tag
      decipher.setAuthTag(tag);
      
      // 3. Perform decryption and verification
      let plaintext = decipher.update(blob.ciphertext, 'base64', 'utf8');
      plaintext += decipher.final('utf8');
      
      return plaintext;
    } catch (error) {
      throw new Error('INFRA_ERROR_DECRYPTION_FAILED_OR_TAMPERED');
    }
  }

  /* //////////////////////////////////////////////////////////////
                            MAINTENANCE
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Securely shreds the master key from memory.
   * @dev Implements Right to Forgotten by zero-filling the underlying buffer.
   */
  async nuke() {
    if (this.#masterKey) {
      // Overwrite memory with zeros before release
      this.#masterKey.fill(0);
      this.#masterKey = null;
    }
    console.warn('[SECURITY] Master key shredded from volatile memory.');
  }

  /* //////////////////////////////////////////////////////////////
                            VALIDATION
  //////////////////////////////////////////////////////////////*/

  _validateKey(key) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new Error('INFRA_ERROR_INVALID_MASTER_KEY_SIZE_EXPECTED_32_BYTES');
    }
  }
}
