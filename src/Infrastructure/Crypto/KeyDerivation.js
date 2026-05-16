import crypto from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';

/**
 * @title KeyDerivation
 * @notice Derives per-user Data Encryption Keys from a server pepper.
 * @dev Uses HKDF-SHA256 to deterministically derive 32-byte DEKs.
 *      Same (pepper, ownerId) always produces the same DEK.
 *      The pepper is generated once and stored at ~/.ai-passport/pepper.key
 *      or loaded from the PEPPER_KEY env var (hex-encoded).
 */

/* //////////////////////////////////////////////////////////////
                        KEY DERIVATION
//////////////////////////////////////////////////////////////*/

const PEPPER_FILE = 'pepper.key';
const HKDF_INFO = 'aipassport-dek-v1';

export class KeyDerivation {
  #pepper;

  /**
   * @param {Buffer} pepper - 32-byte server pepper.
   */
  constructor(pepper) {
    if (!Buffer.isBuffer(pepper) || pepper.length !== 32) {
      throw new Error('INFRA_ERROR_INVALID_PEPPER_SIZE_EXPECTED_32_BYTES');
    }
    this.#pepper = pepper;
  }

  /**
   * @notice Derives a per-user Data Encryption Key.
   * @param {string} ownerId - The user's identity (e.g., JWT sub claim).
   * @returns {Buffer} 32-byte DEK.
   */
  deriveDEK(ownerId) {
    return Buffer.from(
      crypto.hkdfSync('sha256', this.#pepper, ownerId, HKDF_INFO, 32)
    );
  }

  /**
   * @notice Returns the pepper (for testing only).
   */
  get pepper() {
    return this.#pepper;
  }

  /**
   * @notice Loads or generates the server pepper.
   * If PEPPER_KEY env var is set (hex), uses that.
   * Otherwise loads from or creates ~/.ai-passport/pepper.key.
   * @param {string} [basePath] - Override storage path (for testing).
   * @returns {Promise<Buffer>} 32-byte pepper.
   */
  static async loadOrGenerate(basePath) {
    // 1. Check env var first (for TEE deployment where pepper is injected)
    const envPepper = process.env.PEPPER_KEY;
    if (envPepper) {
      const pepper = Buffer.from(envPepper, 'hex');
      if (pepper.length !== 32) {
        throw new Error('INFRA_ERROR_ENV_PEPPER_WRONG_LENGTH');
      }
      return pepper;
    }

    // 2. Load from or create file
    const dir = basePath ?? process.env.LOCAL_VAULT_PATH ?? path.join(os.homedir(), '.ai-passport');
    const pepperPath = path.join(dir, PEPPER_FILE);

    try {
      const hex = await fs.readFile(pepperPath, 'utf-8');
      const pepper = Buffer.from(hex.trim(), 'hex');
      if (pepper.length !== 32) {
        throw new Error(`INFRA_ERROR_PEPPER_FILE_CORRUPT: expected 32 bytes, got ${pepper.length}`);
      }
      return pepper;
    } catch (error) {
      if (error.code === 'ENOENT' || error.message.includes('CORRUPT')) {
        // Generate new pepper
        const pepper = crypto.randomBytes(32);
        await fs.mkdir(dir, { recursive: true });
        await fs.writeFile(pepperPath, pepper.toString('hex'), 'utf-8');
        console.error(`[KEY_DERIVATION] Generated new pepper at ${pepperPath}`);
        return pepper;
      }
      throw error;
    }
  }
}