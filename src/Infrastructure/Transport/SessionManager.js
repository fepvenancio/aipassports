import crypto from 'crypto';

/**
 * @title SessionManager
 * @notice Manages per-user authenticated sessions with TTL-based expiry.
 * @dev Each session holds its own Vault, MCP Server, and transport.
 *      Sessions expire after a configurable TTL and are cleaned up periodically.
 */

/* //////////////////////////////////////////////////////////////
                        SESSION MANAGER
//////////////////////////////////////////////////////////////*/

const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1 hour
const DEFAULT_MAX_SESSIONS = 1024;
const SWEEP_INTERVAL_MS = 60 * 1000; // 1 minute

export class SessionManager {
  #sessions;
  #ttlMs;
  #maxSessions;
  #sweepTimer;
  #onExpired;

  /**
   * @param {object} [options]
   * @param {number} [options.ttlMs=3600000] - Session TTL in milliseconds (default 1 hour).
   * @param {number} [options.maxSessions=1024] - Maximum concurrent sessions.
   * @param {function} [options.onExpired] - Callback fired when a session expires. Receives (session).
   */
  constructor(options = {}) {
    this.#sessions = new Map();
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    this.#maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS;
    this.#onExpired = options.onExpired ?? null;

    // Periodic sweep of expired sessions
    this.#sweepTimer = setInterval(() => this.sweep(), SWEEP_INTERVAL_MS);
    // Don't prevent process exit
    if (this.#sweepTimer.unref) {
      this.#sweepTimer.unref();
    }
  }

  /**
   * @notice Creates a new authenticated session.
   * @param {string} ownerId - The vault owner identifier.
   * @param {Vault} vault - The hydrated vault for this user.
   * @returns {string} sessionId
   */
  create(ownerId, vault) {
    // Evict oldest if at capacity
    if (this.#sessions.size >= this.#maxSessions) {
      const oldestKey = this.#sessions.keys().next().value;
      this.destroy(oldestKey);
    }

    const sessionId = crypto.randomUUID();
    this.#sessions.set(sessionId, {
      ownerId,
      vault,
      server: null,
      transport: null,
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
    });

    return sessionId;
  }

  /**
   * @notice Retrieves a session by ID. Returns null if expired or missing.
   * @param {string} sessionId
   * @returns {object|null}
   */
  get(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) return null;

    // Check expiry
    if (Date.now() - session.lastActivityAt > this.#ttlMs) {
      this.destroy(sessionId);
      return null;
    }

    // Touch activity
    session.lastActivityAt = Date.now();
    return session;
  }

  /**
   * @notice Destroys a session, cleaning up its MCP server and transport.
   * @param {string} sessionId
   */
  destroy(sessionId) {
    const session = this.#sessions.get(sessionId);
    if (!session) return;

    // Close MCP server if connected
    if (session.server) {
      try { session.server.close(); } catch { /* best effort */ }
    }

    this.#sessions.delete(sessionId);
  }

  /**
   * @notice Sweeps all expired sessions.
   * @returns {number} Number of sessions evicted.
   */
  sweep() {
    const now = Date.now();
    let evicted = 0;

    for (const [sessionId, session] of this.#sessions) {
      if (now - session.lastActivityAt > this.#ttlMs) {
        if (this.#onExpired) {
          this.#onExpired(session);
        }
        this.destroy(sessionId);
        evicted++;
      }
    }

    return evicted;
  }

  /**
   * @notice Returns the number of active sessions.
   */
  get size() {
    return this.#sessions.size;
  }

  /**
   * @notice Shuts down the session manager, destroying all sessions.
   */
  shutdown() {
    clearInterval(this.#sweepTimer);
    for (const sessionId of this.#sessions.keys()) {
      this.destroy(sessionId);
    }
  }
}