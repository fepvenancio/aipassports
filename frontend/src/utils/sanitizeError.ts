// ─────────────────────────────────────────────────────────────────────────────
// sanitizeError — MEDIUM-P2-2
//
// Raw Error.message values from external API calls can contain:
//   - Full stack traces (leaks source paths and dependency versions)
//   - Internal host names, port numbers, or IP addresses
//   - Raw HTTP response bodies from NEAR RPC or the agent (may include
//     internal service details the user should not see)
//
// This utility strips or truncates sensitive fragments before the message
// is surfaced in the UI. It does NOT swallow errors — the full detail is
// always available in the browser DevTools console for developers.
// ─────────────────────────────────────────────────────────────────────────────

/** Maximum character length of an error string shown in the UI. */
const MAX_ERROR_LEN = 120;

/**
 * Patterns that likely contain internal detail that should not be surfaced.
 * Each entry is replaced with the substitution string.
 */
const REDACTION_RULES: Array<[RegExp, string]> = [
  // Stack-trace lines (  at Function.name (/path/file.ts:12:34))
  [/\s+at\s+\S+\s+\([^)]+\)/g, ''],
  // Localhost / private IP addresses
  [/https?:\/\/(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(:\d+)?/gi, '[agent]'],
  // File system paths (Unix-style and Windows-style)
  [/(?:\/[a-z0-9_.-]+){3,}/gi, '[path]'],
  [/[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*/g, '[path]'],
];

/**
 * Sanitizes an error for safe display in the UI.
 *
 * @param err - The error object or unknown thrown value.
 * @returns A sanitized, human-readable string safe for rendering.
 */
export function sanitizeError(err: unknown): string {
  let message: string;

  if (err instanceof Error) {
    message = err.message;
  } else if (typeof err === 'string') {
    message = err;
  } else {
    message = 'An unexpected error occurred.';
  }

  // Apply redaction rules
  for (const [pattern, replacement] of REDACTION_RULES) {
    message = message.replace(pattern, replacement);
  }

  // Collapse multiple whitespace introduced by redaction
  message = message.replace(/\s{2,}/g, ' ').trim();

  // Cap length
  if (message.length > MAX_ERROR_LEN) {
    message = message.slice(0, MAX_ERROR_LEN) + '…';
  }

  return message || 'An unexpected error occurred.';
}
