import { IOutboundProxy } from "../../Application/Ports/IOutboundProxy.js";
import { ComplianceRegistry } from "../../Domain/ValueObjects/ComplianceRegistry.js";

/**
 * @title ZdrProxyClient
 * @notice Implementation of IOutboundProxy that enforces Zero Data Retention.
 * @dev Intercepts, validates, and modifies outgoing LLM payloads.
 */

/* //////////////////////////////////////////////////////////////
                          ZDR PROXY CLIENT
//////////////////////////////////////////////////////////////*/

export class ZdrProxyClient extends IOutboundProxy {
  /**
   * @notice Secure fetch wrapper that enforces compliance policies.
   * @param {string} url 
   * @param {object} options 
   * @returns {Promise<Response>}
   */
  async fetch(url, options = {}) {
    try {
      /* //////////////////////////////////////////////////////////////
                            POLICY EVALUATION
      //////////////////////////////////////////////////////////////*/
      const policy = ComplianceRegistry.getPolicy(url);

      if (!policy) {
        // FR-5.3: Drop connection to unverified consumer endpoints
        console.error(`[SECURITY_FIREWALL] Blocked non-compliant egress to: ${url}`);
        return new Response(
          JSON.stringify({
            error: "SECURITY_POLICY_VIOLATION",
            message: "The destination endpoint lacks ZDR safety guarantees. Connection dropped.",
            target: url
          }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }

      /* //////////////////////////////////////////////////////////////
                            ZDR ENFORCEMENT
      //////////////////////////////////////////////////////////////*/
      console.error(`[SECURITY_FIREWALL] Enforcing ZDR for verified provider: ${policy.provider}`);
      
      const { body, headers } = policy.zdrAction(options.body, options.headers || {});
      
      const secureOptions = {
        ...options,
        body,
        headers
      };

      /* //////////////////////////////////////////////////////////////
                            EGRESS ROUTING
      //////////////////////////////////////////////////////////////*/
      // Native fetch execution
      return await globalThis.fetch(url, secureOptions);
    } catch (error) {
      console.error(`[PROXY_CLIENT_ERROR] ${error.message}`);
      throw new Error(`INFRA_ERROR_PROXY_DISPATCH_FAILED: ${error.message}`);
    }
  }
}
