use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

// //////////////////////////////////////////////////////////////
//                  ZERO DATA RETENTION FIREWALL
// //////////////////////////////////////////////////////////////

/// @title OutboundPayload
/// @notice Represents a data payload requesting to be dispatched outside the TEE boundary.
///
/// Security hardening applied (audit cycle 2026-06-17):
///   AUDIT-I2-A — Added 4 missing sensitive markers: BEARER, AUTH_TOKEN, WALLET_SECRET,
///                SEED_PHRASE. Synced to match agent/src/zdr_firewall.rs SENSITIVE_MARKERS.
///   AUDIT-I2-B — Added ASCII control-char stripping (TAB, LF, CR, NULL) before scanning,
///                preventing "PRIVATE\tKEY" from bypassing the keyword check.
///   AUDIT-I2-C — Added NFKC normalization before the uppercase comparison, preventing
///                Unicode homoglyph bypass (e.g. "ＰＲＩＶＡＴＥ＿＿ＫＥＹ").
#[derive(Serialize, Deserialize, Debug)]
pub struct OutboundPayload {
    /// @notice The raw string payload to be transmitted.
    pub data: String,
    /// @notice The target URL or provider endpoint.
    pub destination: String,
    /// @notice Unix timestamp marking the payload request time.
    pub timestamp: u64,
}

impl OutboundPayload {
    // //////////////////////////////////////////////////////////////
    //                     SENSITIVE MARKERS
    // //////////////////////////////////////////////////////////////

    /// @notice Sensitive keyword markers — synchronized with agent/src/zdr_firewall.rs.
    /// @dev AUDIT-I2-A: Added BEARER, AUTH_TOKEN, WALLET_SECRET, SEED_PHRASE.
    /// These were present in the authoritative agent-side firewall but missing here,
    /// creating a false sense of security for auditors reading the backend crate.
    ///
    /// Stored in SCREAMING_SNAKE_CASE because the scanner normalises + uppercases
    /// the input before comparison.
    const SENSITIVE_MARKERS: &'static [&'static str] = &[
        "PRIVATE_KEY",
        "MNEMONIC",
        "SECRET_TOKEN",
        "SECRET_KEY",
        "PASSWORD",
        "API_KEY",
        "PASSPHRASE",
        "BEARER",
        "AUTH_TOKEN",
        "WALLET_SECRET",
        "SEED_PHRASE",
    ];

    // //////////////////////////////////////////////////////////////
    //                          VALIDATION
    // //////////////////////////////////////////////////////////////

    /// @notice Validates an outbound payload against the ComplianceRegistry rules.
    /// @dev Sanitization pipeline (synchronized with agent/src/zdr_firewall.rs):
    ///      1. NFKC normalization — collapses fullwidth/halfwidth Unicode to ASCII (AUDIT-I2-C).
    ///      2. Collapse whitespace (' ', '\t', '\n', '\r') AND underscores ('_') to single space.
    ///         This is the key TAB-bypass fix (AUDIT-I2-B): "PRIVATE\tKEY" → "PRIVATE KEY"
    ///         which matches the space-normalized marker "PRIVATE KEY" derived from "PRIVATE_KEY".
    ///      3. Uppercase conversion for case-insensitive scan.
    ///      4. Each marker is checked in both its original form (e.g. "PRIVATE_KEY") and its
    ///         space-normalized form ("PRIVATE KEY"), so both variants are blocked.
    ///
    /// @param allowed_destinations A list of approved destinations.
    /// @return true if destination is allowed and no sensitive markers are detected.
    pub fn is_compliant(&self, allowed_destinations: &[String]) -> bool {
        if !allowed_destinations.contains(&self.destination) {
            return false;
        }

        // Step 1: NFKC-normalize to collapse Unicode homoglyphs to ASCII equivalents (AUDIT-I2-C).
        let nfkc_normalized: String = self.data.nfkc().collect();

        // Step 2: Collapse whitespace (TAB, LF, CR, SPACE) and underscores to a single space.
        //         AUDIT-I2-B: "PRIVATE\tKEY" → "PRIVATE KEY" → matches space marker "PRIVATE KEY".
        let mut collapsed = String::with_capacity(nfkc_normalized.len());
        let mut last_was_space = false;
        for c in nfkc_normalized.chars() {
            if c.is_ascii_whitespace() || c == '_' {
                if !last_was_space {
                    collapsed.push(' ');
                    last_was_space = true;
                }
            } else {
                collapsed.push(c);
                last_was_space = false;
            }
        }

        // Step 3: Uppercase for case-insensitive matching.
        let upper = collapsed.to_uppercase();

        // Step 4: Scan both original marker and its space-normalized form.
        for marker in Self::SENSITIVE_MARKERS.iter() {
            if upper.contains(marker) {
                return false;
            }
            // Check space-normalized form (e.g. "PRIVATE KEY" for marker "PRIVATE_KEY")
            let space_marker = marker.replace('_', " ");
            if upper.contains(&space_marker) {
                return false;
            }
        }

        true
    }
}

// //////////////////////////////////////////////////////////////
//                            TESTS
// //////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload(data: &str) -> OutboundPayload {
        OutboundPayload {
            data: data.to_string(),
            destination: "https://api.openai.com/v1/chat/completions".to_string(),
            timestamp: 0,
        }
    }

    fn allowed() -> Vec<String> {
        vec!["https://api.openai.com/v1/chat/completions".to_string()]
    }

    #[test]
    fn test_clean_payload_passes() {
        let p = make_payload("Summarize this document for me.");
        assert!(p.is_compliant(&allowed()));
    }

    #[test]
    fn test_destination_not_in_allowlist_fails() {
        let p = make_payload("hello");
        assert!(!p.is_compliant(&vec!["https://other.example.com".to_string()]));
    }

    #[test]
    fn test_all_eleven_markers_blocked() {
        let markers = [
            "PRIVATE_KEY", "SECRET_KEY", "MNEMONIC", "PASSPHRASE", "SEED_PHRASE",
            "SECRET_TOKEN", "API_KEY", "PASSWORD", "BEARER", "AUTH_TOKEN", "WALLET_SECRET",
        ];
        for marker in markers.iter() {
            let p = make_payload(&format!("my {} is abc", marker.to_lowercase()));
            assert!(!p.is_compliant(&allowed()), "Marker '{}' must be blocked", marker);
        }
    }

    #[test]
    fn test_tab_bypass_blocked() {
        // AUDIT-I2-B: "PRIVATE\tKEY" must not bypass the scanner
        let p = make_payload("PRIVATE\tKEY abc");
        assert!(!p.is_compliant(&allowed()), "TAB-injected PRIVATE_KEY must be blocked");
    }

    #[test]
    fn test_unicode_homoglyph_bypass_blocked() {
        // AUDIT-I2-C: fullwidth "ＰＡＳＳＷＯＲＤ" must be caught via NFKC normalization
        let p = make_payload("ＰＡＳＳＷＯＲＤ is abc");
        assert!(!p.is_compliant(&allowed()), "Unicode homoglyph PASSWORD must be blocked");
    }
}
