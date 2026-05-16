/**
 * @title Skill Entity
 * @notice Represents an AgentSkills capability.
 * @dev Governed by agentskills.io specification.
 */

/* //////////////////////////////////////////////////////////////
                              SKILL
//////////////////////////////////////////////////////////////*/

export class Skill {
  #id;
  #name;
  #description;
  #schema;

  /**
   * @param {string} id - Unique skill identifier (directory name).
   * @param {string} name - Human readable name.
   * @param {string} description - Intent description for LLM.
   * @param {object} schema - JSON Schema for parameters.
   */
  constructor(id, name, description, schema) {
    this.#id = id;
    this.#name = name;
    this.#description = description;
    this.#schema = schema;
  }

  get id() { return this.#id; }
  get name() { return this.#name; }
  get description() { return this.#description; }
  get schema() { return this.#schema; }
}
