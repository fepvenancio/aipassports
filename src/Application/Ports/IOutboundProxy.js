/**
 * @title IOutboundProxy Port
 * @notice Abstract interface for secure outbound network routing.
 * @dev Enforces a gateway between the TEE and the public internet.
 */

/* //////////////////////////////////////////////////////////////
                        OUTBOUND PROXY
//////////////////////////////////////////////////////////////*/

export class IOutboundProxy {
  /**
   * @notice Dispatches a secure, proxied network request.
   * @param {string} url 
   * @param {object} options 
   * @returns {Promise<Response>}
   */
  async fetch(url, options) { throw new Error('NOT_IMPLEMENTED'); }
}
