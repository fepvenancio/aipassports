// //////////////////////////////////////////////////////////////
//                          ZDR EGRESS FIREWALL
// //////////////////////////////////////////////////////////////

/// @file zdr_firewall.rs
/// @notice Port and extension of the contract-validated ZDR firewall for high-performance TEE egress enforcement.
/// @dev Intercepts outbound LLM prompts to verify destination endpoints, scrub credentials, and inject zero-retention parameters.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Strict whitelist of allowed AI endpoints
pub const ALLOWED_DESTINATIONS: &[&str] = &[
    "https://api.openai.com/v1/chat/completions",
    "https://api.anthropic.com/v1/messages",
    "https://aiplatform.googleapis.com/v1/",
];

/// Eleven high-risk sensitive strings representing credentials, secrets, or keys
pub const SENSITIVE_MARKERS: &[&str] = &[
    "PRIVATE_KEY",
    "MNEMONIC",
    "SECRET_TOKEN",
    "SECRET_KEY",
    "PASSWORD",
    "API_KEY",
    "PASSPHRASE",
    "SEED_PHRASE",
    "ACCESS_TOKEN",
    "BEARER",
    "CREDENTIALS",
];

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

/// @notice Asserts that the destination URL is compliance-certified.
/// @dev Destination match is a prefix match to allow path expansions for Google Vertex and sub-resources.
pub fn verify_destination(url: &str) -> Result<(), FirewallError> {
    for dest in ALLOWED_DESTINATIONS {
        if url.starts_with(dest) {
            return Ok(());
        }
    }
    Err(FirewallError::DestinationBlocked(url.to_string()))
}

/// @notice Scans arbitrary string payloads case-insensitively for the 11 forbidden keys.
pub fn scan_sensitive_keywords(payload: &str) -> Result<(), FirewallError> {
    let payload_upper = payload.to_uppercase();
    for marker in SENSITIVE_MARKERS {
        if payload_upper.contains(marker) {
            return Err(FirewallError::SensitiveContentBlocked(marker.to_string()));
        }
    }
    Ok(())
}

/// @notice Injects Zero Data Retention parameters into outbound payloads and constructs appropriate request headers.
/// @dev Supports customized rules for OpenAI, Anthropic, and Google Vertex AI.
pub fn transform_outbound_payload(url: &str, raw_body: &str) -> Result<(Value, Vec<(String, String)>), FirewallError> {
    // 1. Structural Verification
    verify_destination(url)?;
    scan_sensitive_keywords(raw_body)?;

    let mut body_json: Value = serde_json::from_str(raw_body)
        .map_err(|e| FirewallError::ParseError(e.to_string()))?;
    
    let mut headers = Vec::new();

    // 2. Endpoint-specific ZDR injection
    if url.starts_with("https://api.openai.com") {
        // OpenAI ZDR Transformation: inject "store": false
        if let Some(obj) = body_json.as_object_mut() {
            obj.insert("store".to_string(), Value::Bool(false));
        }
    } else if url.starts_with("https://api.anthropic.com") {
        // Anthropic ZDR Transformation: inject beta zero-retention headers
        headers.push(("anthropic-beta".to_string(), "zero-retention-2025-04-01".to_string()));
        headers.push(("x-anthropic-zdr".to_string(), "true".to_string()));
    } else if url.starts_with("https://aiplatform.googleapis.com") {
        // Google Vertex AI ZDR Transformation: inject "data_retention": "none"
        if let Some(obj) = body_json.as_object_mut() {
            obj.insert("data_retention".to_string(), Value::String("none".to_string()));
        }
    }

    Ok((body_json, headers))
}

// //////////////////////////////////////////////////////////////
//                              TESTS
// //////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_destination() {
        assert!(verify_destination("https://api.openai.com/v1/chat/completions").is_ok());
        assert!(verify_destination("https://api.anthropic.com/v1/messages").is_ok());
        assert!(verify_destination("https://aiplatform.googleapis.com/v1/projects/123/locations/us-central1/publishers/google/models/gemini").is_ok());
        
        let blocked = verify_destination("https://evil-hacker-api.com/completions");
        assert!(blocked.is_err());
        if let Err(FirewallError::DestinationBlocked(url)) = blocked {
            assert_eq!(url, "https://evil-hacker-api.com/completions");
        }
    }

    #[test]
    fn test_sensitive_keyword_scanner() {
        assert!(scan_sensitive_keywords("What is the capital of France?").is_ok());
        
        // Assert case-insensitive match
        let blocked1 = scan_sensitive_keywords("My Private_Key is extremely secret");
        assert!(blocked1.is_err());
        
        let blocked2 = scan_sensitive_keywords("bearer token secret value");
        assert!(blocked2.is_err());
        if let Err(FirewallError::SensitiveContentBlocked(marker)) = blocked2 {
            assert_eq!(marker, "BEARER");
        }
    }

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
}
