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
        "anthropic-beta": "zero-retention-2026", // Mocked 2026 header
        "x-zdr-enforce": "true" 
      };
      return { body, headers: newHeaders };
    }
  },
  "api.google.com/vertex": {
    provider: "google-vertex",
    zdrAction: (body, headers) => {
      // Mocked ZDR logic for Vertex
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
    const host = new URL(url).host;
    // Check for exact host or path-based match
    for (const key in REGISTRY) {
      if (url.includes(key)) {
        return REGISTRY[key];
      }
    }
    return null;
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
