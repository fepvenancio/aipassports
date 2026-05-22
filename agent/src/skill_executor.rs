// //////////////////////////////////////////////////////////////
//                          SKILL EXECUTOR
// //////////////////////////////////////////////////////////////

/// @file skill_executor.rs
/// @notice Implements safe, hardware-enforced skill execution by coordinating decrypt, compile, ZDR audit, and dispatch.
/// @dev Decrypts the target skill schema, formats the message context, runs the egress firewall, and queries the LLM.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use reqwest::Client;

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

/// Arguments to invoke a skill execution
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteRequest {
    pub near_account_id: String,
    pub blob_id: String,
    pub expected_sha256: String,
    pub user_input: String,
    pub api_key: String,
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

/// @notice Orchestrates the complete decrypted skill execution workflow.
pub async fn execute_skill(
    master_secret: &[u8; 32],
    req: ExecuteRequest,
) -> Result<Value, SkillError> {
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

    // 4. Dispatch transformed payload to compliant LLM endpoint inside TEE boundary
    let client = Client::new();
    let mut request = client
        .post(&config.llm_endpoint_url)
        .header("Content-Type", "application/json");

    // Inject provider authorization
    if config.llm_endpoint_url.starts_with("https://aiplatform.googleapis.com") {
        request = request.header("Authorization", format!("Bearer {}", req.api_key));
    } else {
        request = request.header("Authorization", format!("Bearer {}", req.api_key));
    }

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
        let err_text = response.text().await.unwrap_or_default();
        return Err(SkillError::LlmProviderError(status, err_text));
    }

    let response_json: Value = response.json().await?;
    Ok(response_json)
}
