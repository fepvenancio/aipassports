/**
 * @title RateLimiter
 * @notice Sliding-window rate limiter per client IP.
 * @dev No external dependencies. Tracks request counts in-memory with periodic cleanup.
 */

/* //////////////////////////////////////////////////////////////
                          RATE LIMITER
//////////////////////////////////////////////////////////////*/

export class RateLimiter {
  #windows;
  #maxRequests;
  #windowMs;
  #cleanupInterval;
  #cleanupTimer;

  /**
   * @param {object} [options]
   * @param {number} [options.maxRequests=100] - Maximum requests per window.
   * @param {number} [options.windowMs=60000] - Window duration in milliseconds (default 1 min).
   * @param {number} [options.cleanupIntervalMs=120000] - How often to purge expired entries.
   */
  constructor(options = {}) {
    this.#maxRequests = options.maxRequests ?? 100;
    this.#windowMs = options.windowMs ?? 60_000;
    this.#cleanupInterval = options.cleanupIntervalMs ?? 120_000;
    this.#windows = new Map(); // ip -> { count, startTime }

    // Periodic cleanup of stale entries
    this.#cleanupTimer = setInterval(() => this.#cleanup(), this.#cleanupInterval);
    if (this.#cleanupTimer.unref) {
      this.#cleanupTimer.unref();
    }
  }

  /**
   * @notice Checks if a request from the given IP is within rate limits.
   * @param {string} ip - The client IP address.
   * @returns {{ allowed: boolean, retryAfterMs: number, remaining: number }}
   */
  check(ip) {
    const now = Date.now();
    let entry = this.#windows.get(ip);

    // Reset window if expired or missing
    if (!entry || (now - entry.startTime) >= this.#windowMs) {
      entry = { count: 0, startTime: now };
      this.#windows.set(ip, entry);
    }

    entry.count++;

    const remaining = Math.max(0, this.#maxRequests - entry.count);
    const retryAfterMs = Math.max(0, this.#windowMs - (now - entry.startTime));

    if (entry.count > this.#maxRequests) {
      return { allowed: false, retryAfterMs, remaining: 0 };
    }

    return { allowed: true, retryAfterMs: 0, remaining };
  }

  /**
   * @notice Returns an Express-compatible middleware function.
   * @returns {function}
   */
  middleware() {
    return (req, res, next) => {
      const ip = req.ip || req.connection?.remoteAddress || 'unknown';
      const result = this.check(ip);

      res.setHeader('X-RateLimit-Remaining', result.remaining.toString());

      if (!result.allowed) {
        res.setHeader('Retry-After', Math.ceil(result.retryAfterMs / 1000).toString());
        return res.status(429).json({
          error: "RATE_LIMIT_EXCEEDED",
          message: "Too many requests. Please try again later.",
          retryAfterMs: result.retryAfterMs
        });
      }

      next();
    };
  }

  /**
   * @notice Removes stale entries older than the window.
   */
  #cleanup() {
    const now = Date.now();
    for (const [ip, entry] of this.#windows) {
      if (now - entry.startTime >= this.#windowMs * 2) {
        this.#windows.delete(ip);
      }
    }
  }

  /**
   * @notice Stops the cleanup timer.
   */
  destroy() {
    clearInterval(this.#cleanupTimer);
    this.#windows.clear();
  }
}