// //////////////////////////////////////////////////////////////
//                          VAULT READER
// //////////////////////////////////////////////////////////////

/// @file vault_reader.rs
/// @notice Handles the secure read pipeline: Walrus blob download, parsing, AES-GCM decryption, and SHA-256 integrity assertion.
/// @dev Enforces the binary packing invariant parsing and defends against at-rest data tampering.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use sha2::{Digest, Sha256};
use reqwest::Client;

use crate::key_derivation;

/// Custom errors for the vault reader
#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error("Key derivation error: {0}")]
    KeyError(#[from] key_derivation::KeyError),
    #[error("Packed payload envelope is invalid or too small")]
    EnvelopeTooSmall,
    #[error("Decryption failed (GCM authentication tag mismatch)")]
    DecryptionFailed,
    #[error("Integrity check failed: decrypted data hash does not match stored content_sha256")]
    IntegrityMismatch { expected: String, computed: String },
    #[error("Walrus retrieval request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("Blob not found on Walrus (transient or expired): {0}")]
    BlobNotFound(String),
    #[error("Walrus aggregator returned error status: {0}")]
    AggregatorError(reqwest::StatusCode),
}

/// @notice Downloads, validates, decrypts, and asserts SHA-256 integrity for a Walrus blob.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID.
/// @param blob_id The locator identifier for the blob on Walrus.
/// @param expected_sha256 The expected SHA-256 hash stored on NEAR (used for defense-in-depth verification).
pub async fn download_and_decrypt(
    master_secret: &[u8; 32],
    near_account_id: &str,
    blob_id: &str,
    expected_sha256: &str,
) -> Result<String, ReaderError> {
    // 1. Download packed binary payload from Walrus Aggregator REST API
    let aggregator_url = std::env::var("WALRUS_AGGREGATOR_URL")
        .unwrap_or_else(|_| "http://localhost:31601".to_string());
    
    let client = Client::new();
    let url = format!("{}/v1/blobs/{}", aggregator_url, blob_id);

    let response = client.get(&url).send().await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ReaderError::BlobNotFound(blob_id.to_string()));
    } else if !response.status().is_success() {
        return Err(ReaderError::AggregatorError(response.status()));
    }

    let packed_payload = response.bytes().await?;

    // 2. Parse Binary Envelope: [12-byte IV][16-byte tag][ciphertext]
    if packed_payload.len() < 12 + 16 {
        return Err(ReaderError::EnvelopeTooSmall);
    }

    let iv = &packed_payload[..12];
    let tag = &packed_payload[12..28];
    let ciphertext = &packed_payload[28..];

    // 3. Derive User's Data Encryption Key (DEK)
    let dek = key_derivation::derive_dek(master_secret, near_account_id)?;

    // 4. Decrypt via AES-256-GCM. Reconstruct [ciphertext][16-byte tag] for standard AEAD decryption
    let nonce = Nonce::from_slice(iv);
    let mut decrypt_payload = Vec::with_capacity(ciphertext.len() + 16);
    decrypt_payload.extend_from_slice(ciphertext);
    decrypt_payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek));
    let decrypted_bytes = cipher
        .decrypt(nonce, decrypt_payload.as_slice())
        .map_err(|_| ReaderError::DecryptionFailed)?;

    let plaintext = String::from_utf8(decrypted_bytes)
        .map_err(|_| ReaderError::DecryptionFailed)?;

    // 5. Defence-in-Depth Integrity Check: Verify that SHA-256(plaintext) == expected_sha256
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let computed_sha256 = hex::encode(hasher.finalize());

    if computed_sha256 != expected_sha256 {
        return Err(ReaderError::IntegrityMismatch {
            expected: expected_sha256.to_string(),
            computed: computed_sha256,
        });
    }

    Ok(plaintext)
}
