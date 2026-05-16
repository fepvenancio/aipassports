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
   * @returns {object} The prepared execution context.
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

    return {
      skill,
      params,
      timestamp: Date.now()
    };
  }
}
