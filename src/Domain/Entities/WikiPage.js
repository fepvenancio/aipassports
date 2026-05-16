/**
 * @title WikiPage Entity
 * @notice Represents a unit of long-term memory.
 * @dev Governed by LLM Wiki v2 specification.
 */

/* //////////////////////////////////////////////////////////////
                            WIKI PAGE
//////////////////////////////////////////////////////////////*/

export class WikiPage {
  #slug;
  #content;
  #metadata;

  /**
   * @param {string} slug - Unique page identifier ([[wiki-link]]).
   * @param {string} content - Markdown body.
   * @param {object} metadata - YAML frontmatter including confidence metrics.
   */
  constructor(slug, content, metadata = {}) {
    this.#slug = slug;
    this.#content = content;
    this.#metadata = metadata;
  }

  get slug() { return this.#slug; }
  get content() { return this.#content; }
  get metadata() { return this.#metadata; }

  /**
   * @notice Updates page confidence based on contradiction analysis.
   * @param {number} newConfidence 
   */
  updateConfidence(newConfidence) {
    this.#metadata.confidence = newConfidence;
  }
}
