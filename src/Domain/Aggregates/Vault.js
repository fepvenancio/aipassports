/**
 * @title Vault Aggregate
 * @notice Coordinates business invariants for the Sovereign AI Passport.
 * @dev Stateless coordinator for memory, skills, and credentials.
 */

/* //////////////////////////////////////////////////////////////
                            VAULT
//////////////////////////////////////////////////////////////*/

export class Vault {
  #ownerId;
  #skills;
  #wikiPages;

  /**
   * @param {string} ownerId - Public Key hash of the owner.
   * @param {Skill[]} skills - Loaded capabilities.
   * @param {WikiPage[]} wikiPages - Knowledge pages.
   */
  constructor(ownerId, skills = [], wikiPages = []) {
    this.#ownerId = ownerId;
    this.#skills = skills;
    this.#wikiPages = wikiPages;
  }

  get ownerId() { return this.#ownerId; }
  get skills() { return [...this.#skills]; }
  get wikiPages() { return [...this.#wikiPages]; }

  /**
   * @notice Serializes the vault state for synchronization.
   * @returns {object}
   */
  toJSON() {
    return {
      ownerId: this.#ownerId,
      skills: this.#skills.map(s => ({ id: s.id, name: s.name, description: s.description, schema: s.schema })),
      wikiPages: this.#wikiPages.map(p => ({ slug: p.slug, content: p.content, metadata: p.metadata }))
    };
  }

  /* //////////////////////////////////////////////////////////////
                          BUSINESS LOGIC
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Adds a new skill to the vault.
   * @param {Skill} skill 
   */
  addSkill(skill) {
    if (this.#skills.find(s => s.id === skill.id)) {
      throw new Error('DOMAIN_ERROR_SKILL_ALREADY_EXISTS');
    }
    this.#skills.push(skill);
  }

  /**
   * @notice Ingests a wiki page, ensuring memory consistency.
   * @param {WikiPage} page 
   */
  ingestWikiPage(page) {
    const existing = this.#wikiPages.find(p => p.slug === page.slug);
    if (existing) {
      // In a real implementation, this would trigger contradiction mitigation logic
      this._mitigateContradiction(existing, page);
    } else {
      this.#wikiPages.push(page);
    }
  }

  _mitigateContradiction(existing, incoming) {
    // TODO: Implement contradiction mitigation (FR-3.2)
    console.log(`Mitigating contradiction for ${existing.slug}`);
  }
}
