/**
 * @title IIdentityVerifier Port
 * @notice Abstract interface for identity validation.
 * @dev Enforces seed-phrase-free authentication via WebAuthn/Passkey assertions.
 */

/* //////////////////////////////////////////////////////////////
                        IDENTITY VERIFIER
//////////////////////////////////////////////////////////////*/

export class IIdentityVerifier {
  /**
   * @notice Verifies a cryptographic assertion (e.g., JWT).
   * @param {string} token - The signed assertion.
   * @param {string|Buffer} publicKey - The public key to verify against.
   * @returns {Promise<boolean>}
   */
  async verifyAssertion(token, publicKey) { throw new Error('NOT_IMPLEMENTED'); }
}
