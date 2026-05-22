// //////////////////////////////////////////////////////////////
//                          VAULT WRITER
// //////////////////////////////////////////////////////////////

/// @file vault_writer.rs
/// @notice Handles the secure write pipeline: AES-256-GCM encryption and Walrus storage publishing.
/// @dev Implements the binary packing invariant: `[12-byte IV][16-byte GCM tag][ciphertext]`.

use serde::{Deserialize, Serialize};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use reqwest::Client;

use crate::key_derivation;

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

/// @notice Encrypts plaintext JSON, packs it into the binary envelope, and publishes it to Walrus.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID.
/// @param plaintext The raw UTF-8 string to be encrypted (Wiki content or Skill JSON).
/// @param epochs Storage duration in epochs.
pub async fn encrypt_and_publish(
    master_secret: &[u8; 32],
    near_account_id: &str,
    plaintext: &str,
    epochs: u64,
) -> Result<WriteResult, WriterError> {
    // 1. Derive User's Data Encryption Key (DEK)
    let dek = key_derivation::derive_dek(master_secret, near_account_id)?;

    // 2. Generate cryptographically secure random 12-byte IV
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);

    // 3. Encrypt via AES-256-GCM
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
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

    // 6. Upload to Walrus Publisher REST API
    let publisher_url = std::env::var("WALRUS_PUBLISHER_URL")
        .unwrap_or_else(|_| "http://localhost:31600".to_string());
    
    let client = Client::new();
    let url = format!("{}/v1/blobs?epochs={}", publisher_url, epochs);

    let response = client
        .put(&url)
        .header("Content-Type", "application/octet-stream")
        .body(packed_payload)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let err_text = response.text().await.unwrap_or_default();
        return Err(WriterError::WalrusError(status, err_text));
    }

    // 7. Parse the Walrus Response and extract blobId
    let body_text = response.text().await?;
    let upload_resp: WalrusUploadResponse = serde_json::from_str(&body_text)
        .map_err(|e| WriterError::ParseError(format!("{}: {}", e, body_text)))?;

    let blob_id = if let Some(newly) = upload_resp.newly_created {
        newly.blob_object.blob_id
    } else if let Some(certified) = upload_resp.already_certified {
        certified.blob_id
    } else {
        return Err(WriterError::ParseError(format!(
            "Missing blobId in Walrus response: {}",
            body_text
        )));
    };

    Ok(WriteResult {
        blob_id,
        content_sha256,
    })
}
