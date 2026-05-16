/**
 * @title EncryptedBlob Value Object
 * @notice Represents a client-side encrypted data packet.
 * @dev Enforces AES-256-GCM envelope structure (ciphertext + nonce + tag).
 */

/* //////////////////////////////////////////////////////////////
                          ENCRYPTED BLOB
//////////////////////////////////////////////////////////////*/

export class EncryptedBlob {
  #ciphertext;
  #nonce;
  #tag;

  /**
   * @param {string} ciphertext - Base64 encoded ciphertext.
   * @param {string} nonce - Base64 encoded initialization vector.
   * @param {string} tag - Base64 encoded auth tag.
   */
  constructor(ciphertext, nonce, tag) {
    this.#ciphertext = this._validate(ciphertext, 'ciphertext');
    this.#nonce = this._validate(nonce, 'nonce');
    this.#tag = this._validate(tag, 'tag');
    Object.freeze(this);
  }

  get ciphertext() { return this.#ciphertext; }
  get nonce() { return this.#nonce; }
  get tag() { return this.#tag; }

  /* //////////////////////////////////////////////////////////////
                            VALIDATION
  //////////////////////////////////////////////////////////////*/

  _validate(val, field) {
    if (!val || typeof val !== 'string') {
      throw new Error(`DOMAIN_ERROR_INVALID_BLOB_${field.toUpperCase()}`);
    }
    return val;
  }
}
