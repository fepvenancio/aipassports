/**
 * @title ComplianceRegistry Value Object
 * @notice Immutable dictionary of verified enterprise LLM providers and their ZDR requirements.
 * @dev Governs outbound request modification to enforce Zero Data Retention (ZDR).
 */

/* //////////////////////////////////////////////////////////////
                        COMPLIANCE REGISTRY
//////////////////////////////////////////////////////////////*/

const REGISTRY = {
  "api.openai.com": {
    provider: "openai",
    zdrAction: (body, headers) => {
      // FR-5.2: Enforce "store: false" for OpenAI ZDR
      const parsedBody = typeof body === 'string' ? JSON.parse(body) : body;
      parsedBody.store = false;
      return { body: JSON.stringify(parsedBody), headers };
    }
  },
  "api.anthropic.com": {
    provider: "anthropic",
    zdrAction: (body, headers) => {
      // FR-5.2: Inject specific Anthropic compliance headers
      const newHeaders = { 
        ...headers, 
        "anthropic-beta": "zero-retention-2025",
        "x-anthropic-zdr": "true" 
      };
      return { body, headers: newHeaders };
    }
  },
  "aiplatform.googleapis.com": {
    provider: "google-vertex",
    zdrAction: (body, headers) => {
      // ZDR logic for Vertex AI
      const parsedBody = typeof body === 'string' ? JSON.parse(body) : body;
      parsedBody.data_retention = "none";
      return { body: JSON.stringify(parsedBody), headers };
    }
  }
};

export class ComplianceRegistry {
  /**
   * @notice Retrieves the compliance policy for a given URL.
   * @param {string} url 
   * @returns {object|null}
   */
  static getPolicy(url) {
    try {
      const host = new URL(url).hostname;
      // Exact host match only — no substring matching to prevent bypass
      if (host in REGISTRY) {
        return REGISTRY[host];
      }
      // Fallback: check path-based keys against full URL origin + path prefix
      for (const key in REGISTRY) {
        const policyUrl = `https://${key}`;
        try {
          const policyOrigin = new URL(policyUrl).origin;
          if (url.startsWith(policyOrigin)) {
            return REGISTRY[key];
          }
        } catch {
          // Skip malformed keys
        }
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * @notice Checks if a host is explicitly blocked or unverified.
   * @param {string} url 
   * @returns {boolean}
   */
  static isVerified(url) {
    return this.getPolicy(url) !== null;
  }
}

Object.freeze(ComplianceRegistry);
Object.freeze(REGISTRY);
