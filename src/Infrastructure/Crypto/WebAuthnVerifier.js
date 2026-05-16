import crypto from 'crypto';
import { IIdentityVerifier } from '../../Application/Ports/IIdentityVerifier.js';

/**
 * @title WebAuthnVerifier
 * @notice Implements identity verification using native Node.js crypto.
 * @dev Parses JWT assertions and verifies signatures against a public key.
 */

/* //////////////////////////////////////////////////////////////
                        WEBAUTHN VERIFIER
//////////////////////////////////////////////////////////////*/

export class WebAuthnVerifier extends IIdentityVerifier {
  /**
   * @notice Verifies a JWT assertion signature and expiration.
   * @param {string} token - The Base64Url encoded JWT.
   * @param {string} publicKey - The PEM encoded public key.
   * @returns {Promise<boolean>}
   */
  async verifyAssertion(token, publicKey) {
    try {
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      if (!headerB64 || !payloadB64 || !signatureB64) {
        throw new Error('INFRA_ERROR_IDENTITY_INVALID_JWT_FORMAT');
      }

      // 1. Check Expiration
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      const now = Math.floor(Date.now() / 1000);
      
      if (payload.exp && payload.exp < now) {
        throw new Error('INFRA_ERROR_IDENTITY_TOKEN_EXPIRED');
      }

      // 2. Verify Signature
      const verifier = crypto.createVerify('sha256');
      verifier.update(`${headerB64}.${payloadB64}`);
      
      const signature = Buffer.from(signatureB64, 'base64url');
      const isValid = verifier.verify(publicKey, signature);

      if (!isValid) {
        throw new Error('INFRA_ERROR_IDENTITY_INVALID_SIGNATURE');
      }

      return true;
    } catch (error) {
      console.error('[IDENTITY_VERIFICATION_FAILED]', error.message);
      return false;
    }
  }
}
