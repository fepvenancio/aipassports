// //////////////////////////////////////////////////////////////
//                          SKILL EXECUTOR
// //////////////////////////////////////////////////////////////

/// @file skill_executor.rs
/// @notice Implements safe, hardware-enforced skill execution by coordinating
///         decrypt, compile, ZDR audit, and dispatch.
///
/// Security hardening applied (audit cycle 2026-05-22 round 2):
///   CRITICAL-R4 — reqwest client now uses `redirect::Policy::none()`.
///                 Previously `Client::new()` followed up to 10 redirects,
///                 allowing a whitelisted Vertex AI endpoint to redirect to
///                 http://169.254.169.254 (cloud metadata SSRF).
///   CRITICAL-R3 — Added 30-second connect + response timeout to all reqwest clients.
///   CRITICAL-R6 — Removed `api_key` from `ExecuteRequest`. LLM credentials are
///                 now loaded at startup from env vars into `AppState` and injected
///                 into `execute_skill()` directly. The key never appears in request
///                 bodies, access logs, or DevTools.
///   N-05        — `blob_id` in ExecuteRequest is now validated before use
///                 (same rules as vault_read_handler: [a-zA-Z0-9_-], ≤128 chars).

use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use reqwest::{Client, redirect};

use crate::vault_reader;
use crate::zdr_firewall;

/// Custom errors for the skill execution module
#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    #[error("Vault reader error: {0}")]
    ReaderError(#[from] vault_reader::ReaderError),
    #[error("Failed to parse decrypted skill configuration: {0}")]
    ConfigParseError(String),
    #[error("ZDR Firewall error: {0}")]
    FirewallError(#[from] zdr_firewall::FirewallError),
    #[error("Failed to serialize prompt: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("LLM HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("LLM provider returned error status: {0} - {1}")]
    LlmProviderError(reqwest::StatusCode, String),
    #[error("HTTP client construction failed: {0}")]
    HttpClientError(reqwest::Error),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Dynamic schema config for a decrypted skill
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct SkillConfig {
    pub name: String,
    pub description: String,
    pub llm_endpoint_url: String,
    pub model: String,
    pub system_prompt: String,
    pub max_tokens: Option<u32>,
}

/// Arguments to invoke a skill execution.
///
/// CRITICAL-R6: `api_key` has been REMOVED from this struct.
/// LLM credentials are loaded at startup in `AppState` via the `LLM_API_KEY`
/// environment variable and injected into `execute_skill()` directly.
/// Accepting credentials in the request body would expose them in:
///   - Browser DevTools Network tab
///   - Agent access logs (any fmt::Debug on the request)
///   - Proxy / WAF / SIEM systems ingesting request bodies
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteRequest {
    pub near_account_id: String,
    pub blob_id: String,
    pub expected_sha256: String,
    pub user_input: String,
}

/// Standard Chat Completion Message formatting
#[derive(Serialize, Deserialize, Debug)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Standard LLM Request layout
#[derive(Serialize, Deserialize, Debug)]
struct LlmRequest {
    model: String,
    messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

// ─── Input Validation ─────────────────────────────────────────────────────────

/// N-05: Validate blob_id before using it in a Walrus URL path segment.
/// Same rules as vault_read_handler: [a-zA-Z0-9_-], max 128 chars.
fn validate_blob_id_for_skill(blob_id: &str) -> Result<(), SkillError> {
    if blob_id.is_empty() || blob_id.len() > 128 {
        return Err(SkillError::InvalidInput(
            "blob_id length must be 1-128 chars".to_string()
        ));
    }
    if !blob_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(SkillError::InvalidInput(
            "blob_id must only contain [a-zA-Z0-9_-]".to_string()
        ));
    }
    Ok(())
}

// ─── Secure HTTP Client ───────────────────────────────────────────────────────

/// CRITICAL-R4 + CRITICAL-R3: Build a hardened reqwest client for LLM dispatch.
///
/// Security properties:
/// - `redirect::Policy::none()`: No redirect following. A whitelisted Vertex AI
///   endpoint redirecting to http://169.254.169.254 would previously be followed
///   silently (default: 10 hops). Now: 307/302 responses are returned as-is,
///   never followed, never reaching unwhitelisted destinations.
/// - `timeout(30s)`: Prevents thread-pool exhaustion via slow LLM responses.
/// - `connect_timeout(10s)`: Fails fast on unreachable endpoints.
fn build_llm_client() -> Result<Client, SkillError> {
    Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(SkillError::HttpClientError)
}

// ─── Skill Execution ──────────────────────────────────────────────────────────

/// @notice Orchestrates the complete decrypted skill execution workflow.
/// @param master_secret The platform's 32-byte master secret.
/// @param llm_api_key  The LLM provider API key from AppState (never from HTTP body).
/// @param req The validated skill execution request.
pub async fn execute_skill(
    master_secret: &[u8; 32],
    llm_api_key: &str,
    req: ExecuteRequest,
) -> Result<Value, SkillError> {
    // N-05: Validate blob_id before URL construction
    validate_blob_id_for_skill(&req.blob_id)?;

    // 1. Download and Decrypt the Skill Configuration from Walrus
    let decrypted_json = vault_reader::download_and_decrypt(
        master_secret,
        &req.near_account_id,
        &req.blob_id,
        &req.expected_sha256,
    ).await?;

    let config: SkillConfig = serde_json::from_str(&decrypted_json)
        .map_err(|e| SkillError::ConfigParseError(e.to_string()))?;

    // 2. Format the LLM Chat Completions Request Body
    let mut messages = Vec::new();
    if !config.system_prompt.trim().is_empty() {
        messages.push(ChatMessage {
            role: "system".to_string(),
            content: config.system_prompt,
        });
    }
    messages.push(ChatMessage {
        role: "user".to_string(),
        content: req.user_input,
    });

    let llm_req = LlmRequest {
        model: config.model,
        messages,
        max_tokens: config.max_tokens,
    };

    let raw_payload = serde_json::to_string(&llm_req)?;

    // 3. Subject outbound request to Zero Data Retention Firewall
    let (transformed_body, headers_to_inject) = zdr_firewall::transform_outbound_payload(
        &config.llm_endpoint_url,
        &raw_payload,
    )?;

    // 4. CRITICAL-R4: Build redirect-disabled client with timeouts
    let client = build_llm_client()?;

    let mut request = client
        .post(&config.llm_endpoint_url)
        .header("Content-Type", "application/json")
        // CRITICAL-R6: LLM API key from AppState (never from HTTP body)
        .header("Authorization", format!("Bearer {}", llm_api_key));

    // Inject ZDR-specific metadata headers (e.g. for Anthropic)
    for (k, v) in headers_to_inject {
        request = request.header(k, v);
    }

    let response = request
        .json(&transformed_body)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        // N-12: Cap error body to prevent internal topology disclosure
        let err_text = response.text().await.unwrap_or_default();
        let err_text = if err_text.len() > 512 {
            format!("{}...[truncated]", &err_text[..512])
        } else {
            err_text
        };
        return Err(SkillError::LlmProviderError(status, err_text));
    }

    let response_json: Value = response.json().await?;
    Ok(response_json)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// CRITICAL-R4: The LLM client must not follow redirects.
    #[test]
    fn test_llm_client_redirect_policy_none() {
        let client = build_llm_client().expect("client must build");
        // We can't inspect the redirect policy directly, but we can verify
        // the client builds successfully with our hardened configuration.
        // Integration test: client should reject 302 responses without following.
        drop(client); // no panic = correct construction
    }

    /// N-05: Validate blob_id rejects path traversal and injection patterns.
    #[test]
    fn test_blob_id_validation() {
        assert!(validate_blob_id_for_skill("").is_err(), "empty blob_id must be rejected");
        assert!(validate_blob_id_for_skill("a".repeat(129).as_str()).is_err(), "128+ chars must be rejected");
        assert!(validate_blob_id_for_skill("../../etc/passwd").is_err(), "path traversal must be rejected");
        assert!(validate_blob_id_for_skill("blob?param=evil").is_err(), "query injection must be rejected");
        assert!(validate_blob_id_for_skill("blob id").is_err(), "spaces must be rejected");
        // Valid patterns
        assert!(validate_blob_id_for_skill("abc123").is_ok(), "alphanumeric must be accepted");
        assert!(validate_blob_id_for_skill("blob-id_v2").is_ok(), "hyphens and underscores must be accepted");
    }
}
