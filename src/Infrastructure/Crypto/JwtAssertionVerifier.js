import crypto from 'crypto';
import { IIdentityVerifier } from '../../Application/Ports/IIdentityVerifier.js';

/**
 * @title JwtAssertionVerifier
 * @notice Verifies JWT assertions (e.g., Private Key JWT from Passkey flow) using Node.js crypto.
 * @dev This implements the server-side verification of JWT tokens produced by the
 *      WebAuthn/Passkey authentication flow. The Passkey ceremony itself happens client-side;
 *      this verifier validates the resulting JWT assertion signed by the user's private key.
 */

/* //////////////////////////////////////////////////////////////
                      JWT ASSERTION VERIFIER
//////////////////////////////////////////////////////////////*/

export class JwtAssertionVerifier extends IIdentityVerifier {
  /**
   * @notice Verifies a JWT assertion signature and expiration.
   * @param {string} token - The Base64Url encoded JWT.
   * @param {string|Buffer} publicKey - The PEM-encoded public key or certificate.
   * @returns {Promise<boolean>}
   */
  async verifyAssertion(token, publicKey) {
    try {
      const [headerB64, payloadB64, signatureB64] = token.split('.');
      if (!headerB64 || !payloadB64 || !signatureB64) {
        throw new Error('INFRA_ERROR_IDENTITY_INVALID_JWT_FORMAT');
      }

      // 1. Determine algorithm from JWT header
      const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
      const algorithm = this._mapAlgToNodeCrypto(header.alg);

      // 2. Check Expiration
      const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      const now = Math.floor(Date.now() / 1000);

      if (payload.exp && payload.exp < now) {
        throw new Error('INFRA_ERROR_IDENTITY_TOKEN_EXPIRED');
      }

      // 3. Verify Signature
      const verifier = crypto.createVerify(algorithm.hashAlgo);
      verifier.update(`${headerB64}.${payloadB64}`);

      const signature = Buffer.from(signatureB64, 'base64url');
      const isValid = verifier.verify(publicKey, signature);

      if (!isValid) {
        throw new Error('INFRA_ERROR_IDENTITY_INVALID_SIGNATURE');
      }

      return true;
    } catch (error) {
      if (error.message.startsWith('INFRA_ERROR_IDENTITY')) {
        console.error('[IDENTITY_VERIFICATION_FAILED]', error.message);
      } else {
        console.error('[IDENTITY_VERIFICATION_FAILED] Unexpected error:', error.message);
      }
      return false;
    }
  }

  /**
   * @notice Maps JWT "alg" header to Node.js crypto algorithm name.
   * @param {string} alg - JWT algorithm identifier (e.g., "RS256", "ES256").
   * @returns {{ hashAlgo: string }}
   */
  _mapAlgToNodeCrypto(alg) {
    const algMap = {
      'RS256': { hashAlgo: 'sha256' },
      'RS384': { hashAlgo: 'sha384' },
      'RS512': { hashAlgo: 'sha512' },
      'ES256': { hashAlgo: 'sha256' },
      'ES384': { hashAlgo: 'sha384' },
      'ES512': { hashAlgo: 'sha512' },
    };

    if (!algMap[alg]) {
      throw new Error(`INFRA_ERROR_IDENTITY_UNSUPPORTED_ALG: ${alg}`);
    }

    return algMap[alg];
  }
}