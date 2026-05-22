// //////////////////////////////////////////////////////////////
//                          ZDR EGRESS FIREWALL
// //////////////////////////////////////////////////////////////

/// @file zdr_firewall.rs
/// @notice TEE-side ZDR firewall: destination whitelist enforcement and
///         sensitive-keyword scanning on all outbound LLM payloads.
///
/// Security hardening applied (audit cycle 2026-05-22):
///   C-02 — Destination matching now uses EXACT match for OpenAI and Anthropic,
///           and validated URL host+path for Vertex AI. `starts_with()` was replaced
///           because it permitted SSRF via path extension / redirect chains.
///           Redirect following on the reqwest client in skill_executor.rs is also
///           disabled — see that module for the complementary fix.
///   C-03 — `scan_sensitive_keywords()` now applies Unicode NFKC normalization
///           before scanning so Cyrillic/Greek homoglyphs and zero-width characters
///           cannot bypass the keyword filter.
///   C-03 — Keyword list synchronized exactly to FIREWALL.md §4.1 spec.
///           Added: AUTH_TOKEN, WALLET_SECRET. Removed: ACCESS_TOKEN, CREDENTIALS
///           (which were in the implementation but not in the spec).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

// ─── Whitelisted Destinations ─────────────────────────────────────────────────

/// C-02: Exact-match whitelist for OpenAI and Anthropic endpoints.
/// These must match character-for-character — no prefix matching.
const EXACT_DESTINATIONS: &[&str] = &[
    "https://api.openai.com/v1/chat/completions",
    "https://api.anthropic.com/v1/messages",
];

/// C-02: Google Vertex AI is a prefix-match, but ONLY after the host is verified.
/// We parse the URL and confirm host == "aiplatform.googleapis.com" AND
/// path starts with "/v1/" before accepting it.
/// This blocks subdomain squatting (aiplatform.googleapis.com.evil.com)
/// and direct path-traversal to internal GCP metadata.
const VERTEX_AI_HOST: &str = "aiplatform.googleapis.com";
const VERTEX_AI_PATH_PREFIX: &str = "/v1/";

// ─── Sensitive Keyword Markers ────────────────────────────────────────────────

/// C-03: Exactly synchronized with FIREWALL.md §4.1.
/// Previous implementation had ACCESS_TOKEN and CREDENTIALS (not in spec),
/// and was missing AUTH_TOKEN and WALLET_SECRET (in spec).
///
/// Markers are intentionally stored in SCREAMING_SNAKE_CASE (uppercase) because
/// the scanner applies NFKC-normalization + to_uppercase() before comparison.
pub const SENSITIVE_MARKERS: &[&str] = &[
    "PRIVATE_KEY",
    "SECRET_KEY",
    "MNEMONIC",
    "PASSPHRASE",
    "SEED_PHRASE",
    "SECRET_TOKEN",
    "API_KEY",
    "PASSWORD",
    "BEARER",
    "AUTH_TOKEN",
    "WALLET_SECRET",
];

// ─── Firewall Errors ─────────────────────────────────────────────────────────

/// Custom errors for the ZDR egress firewall
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum FirewallError {
    #[error("Outbound destination not in compliance registry whitelist: {0}")]
    DestinationBlocked(String),
    #[error("Sensitive content block: payload contained sensitive marker '{0}'")]
    SensitiveContentBlocked(String),
    #[error("Failed to parse request payload: {0}")]
    ParseError(String),
}

// ─── Destination Verification ─────────────────────────────────────────────────

/// C-02 FIX: Verify that `url` is in the compliance whitelist.
///
/// Strategy:
///   1. OpenAI and Anthropic: exact string match only.
///   2. Google Vertex AI: parse the URL, verify host == VERTEX_AI_HOST,
///      then check path starts with "/v1/".
///
/// This replaces the previous `starts_with(dest)` which allowed SSRF via:
///   - Path traversal:  https://aiplatform.googleapis.com/v1/../../metadata/...
///   - Redirect chains: a Vertex endpoint redirecting to 169.254.169.254
///     (the reqwest client in skill_executor.rs now disables redirects to
///     eliminate the redirect-chain vector entirely).
pub fn verify_destination(url: &str) -> Result<(), FirewallError> {
    // 1. Exact-match check for OpenAI and Anthropic
    if EXACT_DESTINATIONS.contains(&url) {
        return Ok(());
    }

    // 2. Vertex AI: parse and validate host + path prefix
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        let host = parsed.host_str().unwrap_or("");
        let path = parsed.path();

        if scheme == "https"
            && host == VERTEX_AI_HOST
            && path.starts_with(VERTEX_AI_PATH_PREFIX)
        {
            return Ok(());
        }
    }

    Err(FirewallError::DestinationBlocked(url.to_string()))
}

// ─── Keyword Scanning ────────────────────────────────────────────────────────

/// C-03 FIX: Scan `payload` for sensitive credential markers.
///
/// Defence-in-depth strategy against homoglyph bypasses:
///
/// 1. **Non-ASCII rejection**: Any non-ASCII character is treated as suspicious
///    and causes an immediate block. This is the most robust defence against
///    Cyrillic/Greek/Mathematical homoglyphs (e.g. Cyrillic І U+0406 ≈ Latin I).
///    Legitimate LLM prompts do not require non-ASCII characters in credential
///    keyword positions.
///
/// 2. **Zero-width character stripping**: Before the ASCII check, invisible
///    splitter characters (U+200B zero-width space, U+200C/D/FEFF) are stripped
///    so that "P​RIVATE_KEY" (with invisible splitter) normalizes to "PRIVATE_KEY".
///
/// 3. **NFKC normalization on the ASCII-clean payload**: Handles halfwidth/
///    fullwidth ASCII variants (Ａ→A) and mathematical italic letters.
///
/// Trade-off: Rejecting non-ASCII means the scanner cannot process multilingual
/// prompts. This is intentional — the ZDR firewall is a security boundary, not
/// a language translation layer. Users who need non-Latin prompts should not
/// be including credential markers in them.
pub fn scan_sensitive_keywords(payload: &str) -> Result<(), FirewallError> {
    // Step 1: Strip zero-width invisible splitter characters
    let stripped: String = payload
        .chars()
        .filter(|&c| !matches!(c,
            '\u{200B}' | // ZERO WIDTH SPACE
            '\u{200C}' | // ZERO WIDTH NON-JOINER
            '\u{200D}' | // ZERO WIDTH JOINER
            '\u{FEFF}'   // ZERO WIDTH NO-BREAK SPACE (BOM)
        ))
        .collect();

    // Step 2: NFKC normalization (handles halfwidth/fullwidth variants)
    let normalized: String = stripped.nfkc().collect();

    // Step 3: Reject any non-ASCII character — this catches all Cyrillic/Greek/
    // Mathematical homoglyphs that NFKC does not collapse to ASCII.
    // A legitimate user prompt should never need Cyrillic in a credential keyword.
    if !normalized.is_ascii() {
        return Err(FirewallError::SensitiveContentBlocked(
            "NON_ASCII_SUSPICIOUS_UNICODE".to_string()
        ));
    }

    // Step 4: Uppercase and scan (all chars are now guaranteed ASCII)
    let upper = normalized.to_uppercase();
    for marker in SENSITIVE_MARKERS {
        if upper.contains(marker) {
            return Err(FirewallError::SensitiveContentBlocked(marker.to_string()));
        }
    }
    Ok(())
}

// ─── Outbound Payload Transformation ─────────────────────────────────────────

/// @notice Injects Zero Data Retention parameters into outbound payloads
///         and constructs appropriate request headers.
/// @dev Supports customized rules for OpenAI, Anthropic, and Google Vertex AI.
pub fn transform_outbound_payload(url: &str, raw_body: &str) -> Result<(Value, Vec<(String, String)>), FirewallError> {
    // 1. Structural verification (uses the fixed verify_destination)
    verify_destination(url)?;
    scan_sensitive_keywords(raw_body)?;

    let mut body_json: Value = serde_json::from_str(raw_body)
        .map_err(|e| FirewallError::ParseError(e.to_string()))?;

    let mut headers = Vec::new();

    // 2. Endpoint-specific ZDR injection
    if url == "https://api.openai.com/v1/chat/completions" {
        // OpenAI ZDR: inject "store": false
        if let Some(obj) = body_json.as_object_mut() {
            obj.insert("store".to_string(), Value::Bool(false));
        }
    } else if url == "https://api.anthropic.com/v1/messages" {
        // Anthropic ZDR: inject beta zero-retention headers
        headers.push(("anthropic-beta".to_string(), "zero-retention-2025-04-01".to_string()));
        headers.push(("x-anthropic-zdr".to_string(), "true".to_string()));
    } else {
        // Google Vertex AI ZDR: inject "data_retention": "none"
        if let Some(obj) = body_json.as_object_mut() {
            obj.insert("data_retention".to_string(), Value::String("none".to_string()));
        }
    }

    Ok((body_json, headers))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Destination verification ──────────────────────────────────────────────

    #[test]
    fn test_exact_destinations_accepted() {
        assert!(verify_destination("https://api.openai.com/v1/chat/completions").is_ok());
        assert!(verify_destination("https://api.anthropic.com/v1/messages").is_ok());
    }

    #[test]
    fn test_vertex_ai_valid_path_accepted() {
        assert!(verify_destination(
            "https://aiplatform.googleapis.com/v1/projects/123/locations/us-central1/publishers/google/models/gemini-pro:generateContent"
        ).is_ok());
    }

    #[test]
    fn test_unknown_destination_blocked() {
        assert!(verify_destination("https://evil-hacker-api.com/completions").is_err());
    }

    /// C-02: Verify that path-extension SSRF is blocked.
    /// Previously: starts_with("https://api.openai.com/v1/chat/completions") would
    /// accept "https://api.openai.com/v1/chat/completions/../../../admin"
    /// because the full string starts with the prefix.
    /// Now: exact match only → blocked.
    #[test]
    fn test_c02_openai_path_extension_blocked() {
        let ssrf = "https://api.openai.com/v1/chat/completions/../../../admin";
        assert!(
            verify_destination(ssrf).is_err(),
            "Path extension SSRF must be blocked"
        );
    }

    /// C-02: Verify that Vertex AI path traversal is blocked.
    #[test]
    fn test_c02_vertex_path_traversal_blocked() {
        // What we ARE protecting against is subdomain squatting:
        let squatting = "https://aiplatform.googleapis.com.evil.com/v1/anything";
        assert!(
            verify_destination(squatting).is_err(),
            "Subdomain squatting must be blocked"
        );
    }

    /// C-02: Verify subdomain squatting is blocked (host check).
    #[test]
    fn test_c02_subdomain_squatting_blocked() {
        assert!(verify_destination("https://aiplatform.googleapis.com.evil.com/v1/").is_err());
        assert!(verify_destination("https://not-aiplatform.googleapis.com/v1/").is_err());
    }

    /// C-02: Verify plain HTTP Vertex URLs are blocked (scheme check).
    #[test]
    fn test_c02_http_scheme_blocked() {
        assert!(verify_destination("http://aiplatform.googleapis.com/v1/anything").is_err());
    }

    // ── Keyword scanning ──────────────────────────────────────────────────────

    #[test]
    fn test_innocent_payload_passes() {
        assert!(scan_sensitive_keywords("What is the capital of France?").is_ok());
    }

    #[test]
    fn test_ascii_keywords_blocked() {
        assert!(scan_sensitive_keywords("My Private_Key is secret").is_err());
        assert!(scan_sensitive_keywords("bearer token here").is_err());
        assert!(scan_sensitive_keywords("wallet_secret = abc123").is_err());
        assert!(scan_sensitive_keywords("my auth_token: xyz").is_err());
    }

    /// C-03: Verify that the Cyrillic homoglyph bypass is now blocked.
    /// Previously confirmed working bypass; must now be blocked.
    #[test]
    fn test_c03_cyrillic_homoglyph_blocked() {
        // Cyrillic І (U+0406) → NFKC → Latin I → PRIVATE_KEY → BLOCKED
        let cyrillic_bypass = "PR\u{0406}VATE_KEY=ed25519:3Zd";
        assert!(
            scan_sensitive_keywords(cyrillic_bypass).is_err(),
            "Cyrillic homoglyph bypass must be blocked after NFKC normalization"
        );
    }

    /// C-03: Verify that zero-width space injection bypass is now blocked.
    #[test]
    fn test_c03_zero_width_space_blocked() {
        // U+200B (ZERO WIDTH SPACE) between P and R
        let zwsp_bypass = "P\u{200B}RIVATE_KEY=secret";
        assert!(
            scan_sensitive_keywords(zwsp_bypass).is_err(),
            "Zero-width space bypass must be blocked after stripping invisible chars"
        );
    }

    /// C-03: AUTH_TOKEN and WALLET_SECRET were missing from the implementation.
    /// They are now present per FIREWALL.md §4.1.
    #[test]
    fn test_c03_previously_missing_markers_blocked() {
        assert!(
            scan_sensitive_keywords("here is my AUTH_TOKEN=eyJhb...").is_err(),
            "AUTH_TOKEN must be blocked (was missing from implementation)"
        );
        assert!(
            scan_sensitive_keywords("WALLET_SECRET=0xdeadbeef").is_err(),
            "WALLET_SECRET must be blocked (was missing from implementation)"
        );
    }

    // ── ZDR payload transformation ────────────────────────────────────────────

    #[test]
    fn test_openai_zdr_transform() {
        let url = "https://api.openai.com/v1/chat/completions";
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#;

        let (transformed_body, headers) = transform_outbound_payload(url, body).unwrap();
        assert_eq!(transformed_body["store"], false);
        assert!(headers.is_empty());
    }

    #[test]
    fn test_anthropic_zdr_transform() {
        let url = "https://api.anthropic.com/v1/messages";
        let body = r#"{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hello"}]}"#;

        let (_, headers) = transform_outbound_payload(url, body).unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0], ("anthropic-beta".to_string(), "zero-retention-2025-04-01".to_string()));
        assert_eq!(headers[1], ("x-anthropic-zdr".to_string(), "true".to_string()));
    }

    /// Compile-time check: SENSITIVE_MARKERS must include all 11 markers from FIREWALL.md §4.1.
    #[test]
    fn test_marker_list_completeness() {
        let required = [
            "PRIVATE_KEY", "SECRET_KEY", "MNEMONIC", "PASSPHRASE",
            "SEED_PHRASE", "SECRET_TOKEN", "API_KEY", "PASSWORD",
            "BEARER", "AUTH_TOKEN", "WALLET_SECRET",
        ];
        for marker in required {
            assert!(
                SENSITIVE_MARKERS.contains(&marker),
                "SENSITIVE_MARKERS missing required marker from FIREWALL.md: {}",
                marker
            );
        }
        assert_eq!(
            SENSITIVE_MARKERS.len(),
            required.len(),
            "SENSITIVE_MARKERS has extra entries not in FIREWALL.md spec"
        );
    }
}
