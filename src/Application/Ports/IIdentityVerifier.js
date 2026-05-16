/**
 * @title IIdentityVerifier Port
 * @notice Abstract interface for identity validation.
 * @dev Verifies JWT assertions derived from WebAuthn/Passkey authentication ceremonies.
 *      The Passkey ceremony itself happens client-side; this port validates the resulting
 *      signed JWT token server-side.
 */

/* //////////////////////////////////////////////////////////////
                        IDENTITY VERIFIER
//////////////////////////////////////////////////////////////*/

export class IIdentityVerifier {
  /**
   * @notice Verifies a JWT assertion signature and expiration.
   * @param {string} token - The signed JWT assertion.
   * @param {string|Buffer} publicKey - The PEM-encoded public key to verify against.
   * @returns {Promise<boolean>}
   */
  async verifyAssertion(token, publicKey) { throw new Error('NOT_IMPLEMENTED'); }
}