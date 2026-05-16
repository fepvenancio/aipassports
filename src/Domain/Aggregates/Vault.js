import { WikiPage } from '../Entities/WikiPage.js';
import { Skill } from '../Entities/Skill.js';

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
   * @notice Deserializes a vault from its JSON representation.
   * @dev Reconstitutes Skill and WikiPage entities from plain objects.
   * @param {object} json - The JSON object from toJSON().
   * @returns {Vault}
   */
  static fromJSON(json) {
    const skills = (json.skills || []).map(s =>
      new Skill(s.id, s.name, s.description, s.schema)
    );
    const wikiPages = (json.wikiPages || []).map(p =>
      new WikiPage(p.slug, p.content, p.metadata)
    );
    return new Vault(json.ownerId, skills, wikiPages);
  }

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
                          SKILL MANAGEMENT
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
   * @notice Removes a skill from the vault by ID.
   * @param {string} skillId
   * @returns {boolean} True if removed, false if not found.
   */
  removeSkill(skillId) {
    const index = this.#skills.findIndex(s => s.id === skillId);
    if (index === -1) return false;
    this.#skills.splice(index, 1);
    return true;
  }

  /**
   * @notice Finds a skill by ID.
   * @param {string} skillId
   * @returns {Skill|undefined}
   */
  getSkill(skillId) {
    return this.#skills.find(s => s.id === skillId);
  }

  /* //////////////////////////////////////////////////////////////
                          WIKI MANAGEMENT
  //////////////////////////////////////////////////////////////*/

  /**
   * @notice Creates a new wiki page. Rejects if slug already exists.
   * @param {string} slug
   * @param {string} content
   * @param {object} [metadata]
   */
  createWikiPage(slug, content, metadata = {}) {
    if (this.#wikiPages.find(p => p.slug === slug)) {
      throw new Error('DOMAIN_ERROR_WIKI_PAGE_ALREADY_EXISTS');
    }
    this.#wikiPages.push(new WikiPage(slug, content, metadata));
  }

  /**
   * @notice Updates an existing wiki page's content and/or metadata.
   * @param {string} slug
   * @param {string} content
   * @param {object} [metadata]
   */
  updateWikiPage(slug, content, metadata) {
    const page = this.#wikiPages.find(p => p.slug === slug);
    if (!page) {
      throw new Error('DOMAIN_ERROR_WIKI_PAGE_NOT_FOUND');
    }
    page.updateContent(content);
    if (metadata !== undefined) {
      page.updateMetadata(metadata);
    }
  }

  /**
   * @notice Ingests a wiki page, ensuring memory consistency.
   * Creates if new, mitigates contradiction if existing.
   * @param {WikiPage|object} page - WikiPage entity or plain object { slug, content, metadata }.
   */
  ingestWikiPage(page) {
    const slug = page instanceof WikiPage ? page.slug : page.slug;
    const existing = this.#wikiPages.find(p => p.slug === slug);
    if (existing) {
      this._mitigateContradiction(existing, page);
    } else {
      const wikiPage = page instanceof WikiPage ? page : new WikiPage(page.slug, page.content, page.metadata);
      this.#wikiPages.push(wikiPage);
    }
  }

  /**
   * @notice Gets a wiki page by slug.
   * @param {string} slug
   * @returns {WikiPage|undefined}
   */
  getWikiPage(slug) {
    return this.#wikiPages.find(p => p.slug === slug);
  }

  _mitigateContradiction(existing, incoming) {
    const incomingPage = incoming instanceof WikiPage ? incoming : new WikiPage(incoming.slug, incoming.content, incoming.metadata);
    const incomingConfidence = incomingPage.metadata?.confidence ?? 0.5;
    const existingConfidence = existing.metadata?.confidence ?? 1.0;

    existing.updateConfidence(existingConfidence * 0.8);
    console.log(`[CONTRADICTION] ${existing.slug}: confidence reduced to ${existingConfidence * 0.8} due to conflicting update (incoming confidence: ${incomingConfidence})`);
  }
}