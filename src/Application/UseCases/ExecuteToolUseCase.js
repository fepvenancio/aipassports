/**
 * @title ExecuteToolUseCase
 * @notice Orchestrates the lookup and preparation of a skill execution.
 */

/* //////////////////////////////////////////////////////////////
                      EXECUTE TOOL USE CASE
//////////////////////////////////////////////////////////////*/

export class ExecuteToolUseCase {
  /**
   * @notice Prepares a tool call by validating the skill exists in the vault.
   * @param {Vault} vault 
   * @param {string} skillId 
   * @param {object} params 
   * @returns {Promise<object>} The prepared execution context.
   */
  async execute(vault, skillId, params) {
    const skill = vault.skills.find(s => s.id === skillId);
    
    if (!skill) {
      throw new Error('USE_CASE_ERROR_SKILL_NOT_FOUND');
    }

    /* //////////////////////////////////////////////////////////////
                            VALIDATE PARAMS
    //////////////////////////////////////////////////////////////*/
    // TODO: Implement JSON Schema validation against skill.schema
    // using a library like ajv for production-grade validation.

    return {
      skillId: skill.id,
      skillName: skill.name,
      params,
      timestamp: Date.now()
    };
  }
}
