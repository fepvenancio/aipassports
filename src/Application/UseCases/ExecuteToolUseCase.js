import Ajv from 'ajv';
import { Skill } from '../../Domain/Entities/Skill.js';
import { SkillExecutor } from '../Services/SkillExecutor.js';

/**
 * @title ExecuteToolUseCase
 * @notice Orchestrates skill execution: LLM-backed skills route through the ZDR proxy,
 *         internal skills (wiki, vault ops) are handled directly.
 */

/* //////////////////////////////////////////////////////////////
                      EXECUTE TOOL USE CASE
//////////////////////////////////////////////////////////////*/

const ajv = new Ajv({ strict: false });

export class ExecuteToolUseCase {
  #skillExecutor;

  /**
   * @param {SkillExecutor} skillExecutor - Routes LLM-backed skill calls through ZDR proxy.
   *          Pass null to disable LLM execution (local-only mode).
   */
  constructor(skillExecutor) {
    this.#skillExecutor = skillExecutor;
  }

  /**
   * @notice Executes a tool call: validates params, routes to internal handler or LLM.
   * @param {Vault} vault - The user's vault (mutated for internal skills).
   * @param {string} skillId - The skill identifier.
   * @param {object} params - The parameters for the skill.
   * @returns {Promise<object>} The execution result.
   */
  async execute(vault, skillId, params) {
    // Handle internal vault operations directly
    switch (skillId) {
      case 'wiki/create':
        return this._handleWikiCreate(vault, params);
      case 'wiki/update':
        return this._handleWikiUpdate(vault, params);
      case 'wiki/read':
        return this._handleWikiRead(vault, params);
      case 'skill/register':
        return this._handleSkillRegister(vault, params);
      case 'skill/remove':
        return this._handleSkillRemove(vault, params);
    }

    // External skills: find in vault and execute via LLM proxy
    const skill = vault.getSkill(skillId);
    if (!skill) {
      throw new Error('USE_CASE_ERROR_SKILL_NOT_FOUND');
    }

    // Validate params against the skill's JSON Schema
    if (skill.schema) {
      const validate = ajv.compile(skill.schema);
      if (!validate(params)) {
        throw new Error(`USE_CASE_ERROR_INVALID_PARAMS: ${JSON.stringify(validate.errors)}`);
      }
    }

    if (!this.#skillExecutor) {
      // Local-only mode: no LLM routing
      return {
        skillId: skill.id,
        skillName: skill.name,
        result: `Skill "${skill.name}" invoked locally (no LLM routing configured).`,
        timestamp: Date.now()
      };
    }

    const result = await this.#skillExecutor.executeLLMSkill(skill, params);
    return { skillId: skill.id, skillName: skill.name, result, timestamp: Date.now() };
  }

  /* //////////////////////////////////////////////////////////////
                    INTERNAL SKILL HANDLERS
  //////////////////////////////////////////////////////////////*/

  _handleWikiCreate(vault, params) {
    const { slug, content, metadata } = params;
    if (!slug || !content) {
      throw new Error('USE_CASE_ERROR_MISSING_PARAMS: slug and content are required');
    }
    vault.createWikiPage(slug, content, metadata || {});
    return { skillId: 'wiki/create', skillName: 'Create Wiki Page', result: `Wiki page "${slug}" created.`, timestamp: Date.now() };
  }

  _handleWikiUpdate(vault, params) {
    const { slug, content, metadata } = params;
    if (!slug || !content) {
      throw new Error('USE_CASE_ERROR_MISSING_PARAMS: slug and content are required');
    }
    vault.updateWikiPage(slug, content, metadata);
    return { skillId: 'wiki/update', skillName: 'Update Wiki Page', result: `Wiki page "${slug}" updated.`, timestamp: Date.now() };
  }

  _handleWikiRead(vault, params) {
    const { slug } = params;
    if (!slug) {
      throw new Error('USE_CASE_ERROR_MISSING_PARAMS: slug is required');
    }
    const page = vault.getWikiPage(slug);
    if (!page) {
      throw new Error(`USE_CASE_ERROR_WIKI_PAGE_NOT_FOUND: ${slug}`);
    }
    return { skillId: 'wiki/read', skillName: 'Read Wiki Page', result: page.content, timestamp: Date.now() };
  }

  _handleSkillRegister(vault, params) {
    const { id, name, description, schema } = params;
    if (!id || !name || !description) {
      throw new Error('USE_CASE_ERROR_MISSING_PARAMS: id, name, and description are required');
    }
    vault.addSkill(new Skill(id, name, description, schema || { type: 'object', properties: {} }));
    return { skillId: 'skill/register', skillName: 'Register Skill', result: `Skill "${name}" registered.`, timestamp: Date.now() };
  }

  _handleSkillRemove(vault, params) {
    const { id } = params;
    if (!id) {
      throw new Error('USE_CASE_ERROR_MISSING_PARAMS: id is required');
    }
    const removed = vault.removeSkill(id);
    if (!removed) {
      throw new Error(`USE_CASE_ERROR_SKILL_NOT_FOUND: ${id}`);
    }
    return { skillId: 'skill/remove', skillName: 'Remove Skill', result: `Skill "${id}" removed.`, timestamp: Date.now() };
  }
}