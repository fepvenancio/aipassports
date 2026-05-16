import crypto from 'crypto';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { ISyncProvider } from '../../Application/Ports/ISyncProvider.js';
import { EncryptedBlob } from '../../Domain/ValueObjects/EncryptedBlob.js';

/**
 * @title LocalFileSystemAdapter
 * @notice Sovereign storage implementation for the Free Tier AI Passport.
 * @dev Manages encrypted payloads inside ~/.ai-passport (or LOCAL_VAULT_PATH).
 */

/* //////////////////////////////////////////////////////////////
                      LOCAL FILE SYSTEM ADAPTER
//////////////////////////////////////////////////////////////*/

export class LocalFileSystemAdapter extends ISyncProvider {
  #basePath;

  /**
   * @param {string} [basePath] - The root sovereign directory.
   * Defaults to LOCAL_VAULT_PATH env var, then ~/.ai-passport.
   */
  constructor(basePath) {
    super();
    this.#basePath = basePath ?? process.env.LOCAL_VAULT_PATH ?? path.join(os.homedir(), '.ai-passport');
  }

  /* //////////////////////////////////////////////////////////////
                          STORAGE OPERATIONS
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Persists an encrypted payload safely to disk using atomic write-then-rename.
   * @param {string} key - The relative path/filename.
   * @param {EncryptedBlob} blob - The encrypted data packet.
   */
  async push(key, blob) {
    const destination = this._resolvePath(key);
    
    try {
      // 1. Ensure parent directory exists
      await fs.mkdir(path.dirname(destination), { recursive: true });

      // 2. Prepare serialized chunk payload
      const payload = JSON.stringify({
        ciphertext: blob.ciphertext,
        nonce: blob.nonce,
        tag: blob.tag,
        version: '1.0',
        timestamp: Date.now()
      }, null, 2);

      // 3. Atomic write: write to temp file, then rename
      const tmpFile = destination + '.tmp.' + crypto.randomBytes(6).toString('hex');
      await fs.writeFile(tmpFile, payload, 'utf-8');
      await fs.rename(tmpFile, destination);
    } catch (error) {
      throw new Error(`INFRA_ERROR_STORAGE_WRITE_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Retrieves and hydrates an encrypted payload from disk.
   * @param {string} key - The relative path/filename.
   * @returns {Promise<EncryptedBlob>}
   */
  async pull(key) {
    const source = this._resolvePath(key);

    try {
      const rawData = await fs.readFile(source, 'utf-8');
      const { ciphertext, nonce, tag } = JSON.parse(rawData);

      return new EncryptedBlob(ciphertext, nonce, tag);
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new Error(`INFRA_ERROR_RESOURCE_NOT_FOUND: ${key}`);
      }
      throw new Error(`INFRA_ERROR_STORAGE_READ_FAILED: ${error.message}`);
    }
  }

  /**
   * @notice Permanently erases the entire sovereign directory.
   * @dev GDPR Article 17 compliance.
   */
  async nuke() {
    try {
      await fs.rm(this.#basePath, { recursive: true, force: true });
      console.warn('[STORAGE] Sovereign data volume wiped.');
    } catch (error) {
      throw new Error(`INFRA_ERROR_NUKE_FAILED: ${error.message}`);
    }
  }

  /* //////////////////////////////////////////////////////////////
                            HELPERS
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Prevents directory traversal attacks by resolving paths strictly.
   * @param {string} key 
   * @returns {string}
   */
  _resolvePath(key) {
    const resolved = path.resolve(this.#basePath, key);
    const expectedPrefix = path.resolve(this.#basePath);
    
    // Ensure it either perfectly matches the directory or is securely nested inside it.
    if (!resolved.startsWith(expectedPrefix + path.sep) && resolved !== expectedPrefix) {
      throw new Error('SECURITY_ERROR_DIRECTORY_TRAVERSAL_DETECTED');
    }
    return resolved;
  }
}