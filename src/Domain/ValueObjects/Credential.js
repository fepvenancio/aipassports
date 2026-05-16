/**
 * @title Credential Value Object
 * @notice Represents an authenticated credential (e.g., JWT, Public Key).
 * @dev Immutable value object.
 */

/* //////////////////////////////////////////////////////////////
                            CREDENTIAL
//////////////////////////////////////////////////////////////*/

export class Credential {
  #type;
  #value;

  /**
   * @param {string} type - The type of credential (e.g., 'JWT', 'PubKey').
   * @param {string} value - The raw credential value.
   */
  constructor(type, value) {
    this.#type = this._validateType(type);
    this.#value = this._validateValue(value);
    Object.freeze(this);
  }

  get type() { return this.#type; }
  get value() { return this.#value; }

  /* //////////////////////////////////////////////////////////////
                            VALIDATION
  //////////////////////////////////////////////////////////////*/

  _validateType(type) {
    if (!type || typeof type !== 'string') {
      throw new Error('DOMAIN_ERROR_INVALID_CREDENTIAL_TYPE');
    }
    return type;
  }

  _validateValue(value) {
    if (!value || typeof value !== 'string') {
      throw new Error('DOMAIN_ERROR_INVALID_CREDENTIAL_VALUE');
    }
    return value;
  }

  /**
   * @notice Checks equality with another credential.
   * @param {Credential} other
   * @returns {boolean}
   */
  equals(other) {
    return other instanceof Credential && 
           this.#type === other.type && 
           this.#value === other.value;
  }
}
