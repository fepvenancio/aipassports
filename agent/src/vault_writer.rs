// //////////////////////////////////////////////////////////////
//                          VAULT WRITER
// //////////////////////////////////////////////////////////////

/// @file vault_writer.rs
/// @notice Handles the secure write pipeline: AES-256-GCM encryption and Walrus storage publishing.
/// @dev Implements the binary packing invariant: `[12-byte IV][16-byte GCM tag][ciphertext]`.
///
/// Security hardening applied (audit cycle 2026-05-22 round 2):
///   CRITICAL-R3 — Added 30-second response + 10-second connect timeout.
///   HIGH-R6     — `WALRUS_PUBLISHER_URL` validated to be https:// at call time.
///   HIGH-R7     — DEK is wrapped in `Zeroizing` so it is scrubbed from memory
///                 immediately when it goes out of scope (even on panic).
///   P2-4        — Added maximum epoch cap (52 epochs ≈ 1 year) to prevent
///                 storage quota exhaustion via epochs=u64::MAX.

use std::time::Duration;
use serde::{Deserialize, Serialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use reqwest::Client;
use zeroize::Zeroizing;

use crate::key_derivation;

/// Maximum storage duration allowed (52 epochs ≈ 1 year on Walrus mainnet).
/// Prevents storage quota exhaustion via epochs=u64::MAX (P2-4 fix).
pub const MAX_EPOCHS: u64 = 52;

/// Custom errors for the vault writer
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("Key derivation error: {0}")]
    KeyError(#[from] key_derivation::KeyError),
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Walrus publishing request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("Walrus returned error status: {0} - {1}")]
    WalrusError(reqwest::StatusCode, String),
    #[error("Failed to parse Walrus upload response: {0}")]
    ParseError(String),
    #[error("Walrus publisher URL is not https:// — SSRF prevention: {0}")]
    InvalidPublisherUrl(String),
    #[error("HTTP client construction failed: {0}")]
    HttpClientError(reqwest::Error),
    #[error("epochs value {0} exceeds maximum allowed {1}")]
    EpochsTooLarge(u64, u64),
}

/// JSON payload structure for Walrus upload responses
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct NewlyCreated {
    blob_object: BlobObject,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BlobObject {
    blob_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct AlreadyCertified {
    blob_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WalrusUploadResponse {
    newly_created: Option<NewlyCreated>,
    already_certified: Option<AlreadyCertified>,
}

/// Output of a successful vault write operation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WriteResult {
    pub blob_id: String,
    pub content_sha256: String,
}

// ─── Input Validation ─────────────────────────────────────────────────────────

/// HIGH-R6: Validate that the Walrus publisher URL uses https:// scheme.
fn validate_publisher_url(url: &str) -> Result<(), WriterError> {
    match url::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" => Ok(()),
        Ok(parsed) if parsed.scheme() == "http"
            && parsed.host_str().map_or(false, |h| h == "localhost" || h == "127.0.0.1") =>
        {
            Ok(()) // http://localhost allowed for local dev
        }
        _ => Err(WriterError::InvalidPublisherUrl(url.to_string())),
    }
}

// ─── Secure HTTP Client ───────────────────────────────────────────────────────

fn build_writer_client() -> Result<Client, WriterError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(WriterError::HttpClientError)
}

// ─── Vault Writer ─────────────────────────────────────────────────────────────

/// @notice Encrypts plaintext JSON, packs it into the binary envelope, and publishes it to Walrus.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID.
/// @param plaintext The raw UTF-8 string to be encrypted (Wiki content or Skill JSON).
/// @param epochs Storage duration in epochs (max 52 ≈ 1 year).
pub async fn encrypt_and_publish(
    master_secret: &[u8; 32],
    near_account_id: &str,
    plaintext: &str,
    epochs: u64,
) -> Result<WriteResult, WriterError> {
    // P2-4: Cap epochs to prevent storage quota exhaustion
    if epochs > MAX_EPOCHS {
        return Err(WriterError::EpochsTooLarge(epochs, MAX_EPOCHS));
    }

    // 1. HIGH-R7: Derive User's Data Encryption Key (DEK) — wrapped in Zeroizing
    let dek = Zeroizing::new(key_derivation::derive_dek(master_secret, near_account_id)?);

    // 2. Generate cryptographically secure random 12-byte IV
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // 3. Encrypt via AES-256-GCM
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*dek));
    let encrypted_bytes = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| WriterError::EncryptionFailed)?;

    // Split out tag and ciphertext. Standard encrypt returns [ciphertext][16-byte tag]
    if encrypted_bytes.len() < 16 {
        return Err(WriterError::EncryptionFailed);
    }
    let tag_start = encrypted_bytes.len() - 16;
    let ciphertext = &encrypted_bytes[..tag_start];
    let tag = &encrypted_bytes[tag_start..];

    // 4. Pack into Binary Envelope: [12-byte IV][16-byte tag][ciphertext]
    let mut packed_payload = Vec::with_capacity(12 + 16 + ciphertext.len());
    packed_payload.extend_from_slice(&iv);
    packed_payload.extend_from_slice(tag);
    packed_payload.extend_from_slice(ciphertext);

    // 5. Compute SHA-256 hash of the original plaintext for NEAR contract integrity verification
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let content_sha256 = hex::encode(hasher.finalize());

    // 6. HIGH-R6: Build and validate Walrus Publisher URL
    let publisher_url = std::env::var("WALRUS_PUBLISHER_URL")
        .unwrap_or_else(|_| "http://localhost:31600".to_string());

    validate_publisher_url(&publisher_url)?;

    // CRITICAL-R3: Hardened client with timeouts and no redirects
    let client = build_writer_client()?;
    let url = format!("{}/v1/blobs?epochs={}", publisher_url, epochs);

    let response = client
        .put(&url)
        .header("Content-Type", "application/octet-stream")
        .body(packed_payload)
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
        return Err(WriterError::WalrusError(status, err_text));
    }

    // 7. Parse the Walrus Response and extract blobId
    let body_text = response.text().await?;
    let upload_resp: WalrusUploadResponse = serde_json::from_str(&body_text)
        .map_err(|e| WriterError::ParseError(format!("{}: body_len={}", e, body_text.len())))?;

    let blob_id = if let Some(newly) = upload_resp.newly_created {
        newly.blob_object.blob_id
    } else if let Some(certified) = upload_resp.already_certified {
        certified.blob_id
    } else {
        return Err(WriterError::ParseError(
            "Missing blobId field in Walrus response (neither newly_created nor already_certified)".to_string()
        ));
    };

    Ok(WriteResult {
        blob_id,
        content_sha256,
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// HIGH-R6: Publisher URL must be https:// or http://localhost only.
    #[test]
    fn test_publisher_url_validation() {
        assert!(validate_publisher_url("https://publisher.walrus.example.com").is_ok());
        assert!(validate_publisher_url("http://localhost:31600").is_ok());
        assert!(validate_publisher_url("http://127.0.0.1:31600").is_ok());
        assert!(validate_publisher_url("http://169.254.169.254").is_err(), "metadata SSRF must be blocked");
        assert!(validate_publisher_url("http://evil.com").is_err());
        assert!(validate_publisher_url("file:///etc/passwd").is_err());
    }

    /// P2-4: epochs must be capped at MAX_EPOCHS.
    #[tokio::test]
    async fn test_epochs_cap_rejected() {
        let master = [0u8; 32];
        let result = encrypt_and_publish(&master, "alice.near", "test", u64::MAX).await;
        assert!(matches!(result, Err(WriterError::EpochsTooLarge(_, _))), "u64::MAX epochs must be rejected");

        let result2 = encrypt_and_publish(&master, "alice.near", "test", 53).await;
        assert!(matches!(result2, Err(WriterError::EpochsTooLarge(53, 52))), "53 epochs must be rejected");
    }
}
