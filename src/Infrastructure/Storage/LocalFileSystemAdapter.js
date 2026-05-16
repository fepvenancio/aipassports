import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { ISyncProvider } from '../../Application/Ports/ISyncProvider.js';

/**
 * @title LocalFileSystemAdapter
 * @notice Sovereign storage implementation for the Free Tier AI Passport.
 * @dev Manages encrypted payloads inside the ~/.ai-passport directory.
 */

/* //////////////////////////////////////////////////////////////
                      LOCAL FILE SYSTEM ADAPTER
//////////////////////////////////////////////////////////////*/

export class LocalFileSystemAdapter extends ISyncProvider {
  #basePath;

  /**
   * @param {string} basePath - The root sovereign directory.
   */
  constructor(basePath = path.join(os.homedir(), '.ai-passport')) {
    super();
    this.#basePath = basePath;
  }

  /* //////////////////////////////////////////////////////////////
                          STORAGE OPERATIONS
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Persists an encrypted payload safely to disk.
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

      // 3. Atomic-style write (Write then rename would be safer for production, 
      // but simple write is standard for alpha)
      await fs.writeFile(destination, payload, 'utf-8');
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

      // Dynamic import to maintain domain layer isolation
      const { EncryptedBlob } = await import('../../Domain/ValueObjects/EncryptedBlob.js');
      
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
    const resolved = path.join(this.#basePath, key);
    if (!resolved.startsWith(this.#basePath)) {
      throw new Error('SECURITY_ERROR_DIRECTORY_TRAVERSAL_DETECTED');
    }
    return resolved;
  }
}
