import { ComplianceRegistry } from '../../Domain/ValueObjects/ComplianceRegistry.js';

/**
 * @title SkillExecutor
 * @notice Executes skill invocations by routing LLM calls through the ZDR proxy.
 * @dev For skills that require LLM execution, the request passes through
 *      ComplianceRegistry-verified endpoints only. Internal skills (wiki, vault ops)
 *      are handled directly without LLM calls.
 */

/* //////////////////////////////////////////////////////////////
                        SKILL EXECUTOR
//////////////////////////////////////////////////////////////*/

const DEFAULT_LLM_CONFIG = {
  url: process.env.LLM_ENDPOINT_URL || 'https://api.openai.com/v1/chat/completions',
  model: process.env.LLM_MODEL || 'gpt-4o-mini',
  maxTokens: parseInt(process.env.LLM_MAX_TOKENS || '1024', 10),
};

export class SkillExecutor {
  #proxyClient;
  #llmConfig;

  /**
   * @param {IOutboundProxy} proxyClient - ZDR-proxied fetch client.
   * @param {object} [llmConfig] - Override default LLM configuration.
   * @param {string} [llmConfig.url] - LLM API endpoint.
   * @param {string} [llmConfig.model] - Model name.
   * @param {number} [llmConfig.maxTokens] - Max response tokens.
   */
  constructor(proxyClient, llmConfig = {}) {
    this.#proxyClient = proxyClient;
    this.#llmConfig = { ...DEFAULT_LLM_CONFIG, ...llmConfig };
  }

  /**
   * @notice Executes an LLM-backed skill by routing through the ZDR proxy.
   * @param {Skill} skill - The skill to execute.
   * @param {object} params - The validated parameters.
   * @returns {Promise<string>} The LLM response text.
   */
  async executeLLMSkill(skill, params) {
    const { url, model, maxTokens } = this.#llmConfig;

    // Verify the LLM endpoint is ZDR-compliant before making the call
    if (!ComplianceRegistry.isVerified(url)) {
      throw new Error(`SKILL_ERROR_LLM_ENDPOINT_NOT_VERIFIED: ${url}`);
    }

    const systemPrompt = skill.description;
    const userMessage = JSON.stringify(params);

    const body = JSON.stringify({
      model,
      max_tokens: maxTokens,
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userMessage }
      ]
    });

    const response = await this.#proxyClient.fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`SKILL_ERROR_LLM_CALL_FAILED: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    // Extract content from response (works for OpenAI and Anthropic formats)
    if (data.choices?.[0]?.message?.content) {
      return data.choices[0].message.content;
    }
    if (data.content?.[0]?.text) {
      return data.content[0].text;
    }

    return JSON.stringify(data);
  }
}