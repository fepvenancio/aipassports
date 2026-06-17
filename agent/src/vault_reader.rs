// //////////////////////////////////////////////////////////////
//                          VAULT READER
// //////////////////////////////////////////////////////////////

/// @file vault_reader.rs
/// @notice Handles the secure read pipeline: Walrus blob download, parsing,
///         AES-GCM decryption, and SHA-256 integrity assertion.
///
/// Security hardening applied (audit cycle 2026-05-22 round 2):
///   CRITICAL-R3 — Added 30-second response + 10-second connect timeout.
///   HIGH-R6     — `WALRUS_AGGREGATOR_URL` validated to be https:// at call time.
///   HIGH-R7     — DEK is wrapped in `Zeroizing` so it is scrubbed from memory
///                 immediately when it goes out of scope (even on panic).
///   HIGH-R8     — `expected_sha256` is now validated to be exactly 64 lowercase
///                 hex chars before use, preventing garbage comparisons.
///                 Hash comparison uses `subtle::ConstantTimeEq` to prevent
///                 timing oracle attacks on the hash prefix.

use std::time::Duration;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use sha2::{Digest, Sha256};
use reqwest::Client;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::key_derivation;
use crate::team_key_manager::TeamKeyManager;

/// Type alias for NEAR AccountId (using String for simplicity in agent context)
type AccountId = String;

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
    #[error("Invalid SHA-256 hash format: must be exactly 64 lowercase hex chars")]
    InvalidHashFormat,
    #[error("Walrus aggregator URL is not https:// — SSRF prevention: {0}")]
    InvalidAggregatorUrl(String),
    #[error("HTTP client construction failed: {0}")]
    HttpClientError(reqwest::Error),
}

// ─── Input Validation ─────────────────────────────────────────────────────────

/// HIGH-R8: Validate that `hash` is exactly 64 lowercase hex characters.
/// Rejects empty strings, wrong-length strings, and non-hex characters.
/// Prevents the hash comparison from operating on garbage input.
fn validate_sha256_format(hash: &str) -> Result<(), ReaderError> {
    if hash.len() != 64 {
        return Err(ReaderError::InvalidHashFormat);
    }
    if !hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return Err(ReaderError::InvalidHashFormat);
    }
    Ok(())
}

/// HIGH-R6: Validate that the Walrus aggregator URL uses https:// scheme.
/// Prevents SSRF via operator misconfiguration:
///   WALRUS_AGGREGATOR_URL=http://169.254.169.254 → metadata API access
///   WALRUS_AGGREGATOR_URL=file:///etc/passwd     → file read (reqwest rejects, but validate early)
fn validate_walrus_url(url: &str) -> Result<(), ReaderError> {
    match url::Url::parse(url) {
        Ok(parsed) if parsed.scheme() == "https" => Ok(()),
        Ok(parsed) if parsed.scheme() == "http"
            && parsed.host_str().map_or(false, |h| h == "localhost" || h == "127.0.0.1") =>
        {
            // Allow http://localhost only for local development
            Ok(())
        }
        _ => Err(ReaderError::InvalidAggregatorUrl(url.to_string())),
    }
}

// ─── Secure HTTP Client ───────────────────────────────────────────────────────

fn build_reader_client() -> Result<Client, ReaderError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(ReaderError::HttpClientError)
}

// ─── Vault Reader ─────────────────────────────────────────────────────────────

/// @notice Downloads, validates, decrypts, and asserts SHA-256 integrity for a Walrus blob.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID.
/// @param entry_type The category of the vault entry (e.g. "wiki" or "skill").
/// @param identifier The specific record identifier (e.g. page slug or skill name).
/// @param blob_id The locator identifier for the blob on Walrus.
/// @param expected_sha256 The expected SHA-256 hash stored on NEAR (64 lowercase hex chars).
pub async fn download_and_decrypt(
    master_secret: &[u8; 32],
    near_account_id: &str,
    entry_type: &str,
    identifier: &str,
    blob_id: &str,
    expected_sha256: &str,
) -> Result<String, ReaderError> {
    // HIGH-R8: Validate hash format before any processing
    validate_sha256_format(expected_sha256)?;

    // 1. Build and validate Walrus Aggregator URL
    let aggregator_url = std::env::var("WALRUS_AGGREGATOR_URL")
        .unwrap_or_else(|_| "http://localhost:31601".to_string());

    // HIGH-R6: Validate scheme (https:// required in production; http://localhost allowed for dev)
    validate_walrus_url(&aggregator_url)?;

    // CRITICAL-R3: Hardened client with timeouts and no redirects
    let client = build_reader_client()?;
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

    // 3. HIGH-R7: Derive User's Data Encryption Key (DEK) — wrapped in Zeroizing
    // Zeroizing ensures the DEK bytes are scrubbed from stack/heap when it drops,
    // even on panic or early return. Without this, the DEK remains in memory until
    // the allocator reclaims the page — accessible via core dumps or /proc/mem.
    let dek = Zeroizing::new(key_derivation::derive_dek(master_secret, near_account_id, entry_type, identifier)?);

    // 4. Decrypt via AES-256-GCM. Reconstruct [ciphertext][16-byte tag] for standard AEAD decryption
    let nonce = Nonce::from_slice(iv);
    let mut decrypt_payload = Vec::with_capacity(ciphertext.len() + 16);
    decrypt_payload.extend_from_slice(ciphertext);
    decrypt_payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*dek));
    let decrypted_bytes = cipher
        .decrypt(nonce, decrypt_payload.as_slice())
        .map_err(|_| ReaderError::DecryptionFailed)?;

    let plaintext = String::from_utf8(decrypted_bytes)
        .map_err(|_| ReaderError::DecryptionFailed)?;

    // 5. HIGH-R8: Constant-time SHA-256 integrity check
    // Using subtle::ConstantTimeEq to prevent timing oracle attacks.
    // Without this, a timing side-channel could reveal the expected hash byte-by-byte.
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let computed_sha256 = hex::encode(hasher.finalize());

    // Both strings are 64-char hex — guaranteed same length — safe for constant-time compare
    let hashes_match: bool = computed_sha256.as_bytes()
        .ct_eq(expected_sha256.as_bytes())
        .into();

    if !hashes_match {
        return Err(ReaderError::IntegrityMismatch {
            expected: expected_sha256.to_string(),
            computed: computed_sha256,
        });
    }

    Ok(plaintext)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// HIGH-R8: SHA-256 format validation must reject garbage inputs.
    #[test]
    fn test_sha256_format_validation() {
        // Must pass
        assert!(validate_sha256_format("a".repeat(64).as_str()).is_ok());
        assert!(validate_sha256_format("0123456789abcdef".repeat(4).as_str()).is_ok());
        // Must fail
        assert!(validate_sha256_format("").is_err(), "empty hash must be rejected");
        assert!(validate_sha256_format("abc").is_err(), "short hash must be rejected");
        assert!(validate_sha256_format("A".repeat(64).as_str()).is_err(), "uppercase hex must be rejected");
        assert!(validate_sha256_format("g".repeat(64).as_str()).is_err(), "non-hex char must be rejected");
        assert!(validate_sha256_format(&"a".repeat(65)).is_err(), "65-char hash must be rejected");
        // Empty string was the confirmed bypass (previously accepted, caused empty != computed mismatch)
        assert!(validate_sha256_format("").is_err(), "empty string timing oracle must be blocked");
    }

    /// HIGH-R6: Walrus URL must be https:// or http://localhost only.
    #[test]
    fn test_walrus_url_validation() {
        assert!(validate_walrus_url("https://aggregator.walrus.example.com").is_ok());
        assert!(validate_walrus_url("http://localhost:31601").is_ok());
        assert!(validate_walrus_url("http://127.0.0.1:31601").is_ok());
        // Must fail
        assert!(validate_walrus_url("http://169.254.169.254").is_err(), "metadata SSRF must be blocked");
        assert!(validate_walrus_url("http://evil.com").is_err(), "plain http must be blocked");
        assert!(validate_walrus_url("file:///etc/passwd").is_err(), "file:// must be blocked");
        assert!(validate_walrus_url("ftp://attacker.com").is_err(), "ftp:// must be blocked");
    }
}

// ///////////////////////////////////////////////////////////////
//                          TEAM VAULT READER
// ///////////////////////////////////////////////////////////////

/// @notice Reads a team vault entry from Walrus and decrypts it using the team DEK.
/// @dev Full team vault read pipeline:
///      1. Downloads encrypted blob from Walrus aggregator
///      2. Parses binary envelope: [12-byte IV][16-byte GCM tag][ciphertext]
///      3. Derives the team DEK directly from the platform master secret
///         (HKDF-SHA256 via get_or_generate_team_dek — same derivation as the write path)
///      4. Decrypts blob with AES-256-GCM
///      5. Verifies SHA-256 integrity via constant-time comparison
///
/// Access control note: The gateway verifies team membership via NEAR RPC before
/// forwarding the request to this endpoint. The agent trusts this gate and does
/// not re-verify on-chain. The TEE is the cryptographic boundary; the NEAR contract
/// is the access-control boundary.
///
/// AUDIT-FIX (read path): The previous implementation attempted to look up a
/// per-member `encrypted_team_dek` from an in-memory cache that was never populated.
/// This caused every team vault read to fail with `ReaderError::DecryptionFailed`.
/// The correct approach is to derive the team DEK deterministically from the master
/// secret — identical to what write_team_vault_entry does. No cache population step
/// is needed because the derivation is stateless and restart-safe.
///
/// @param master_secret Platform master secret — source of all key material.
/// @param team_id The team that owns the vault entry.
/// @param slug Unique identifier for the wiki page (used in logging only).
/// @param requesting_account_id NEAR account ID of the requesting member (logged).
/// @param team_key_manager Mutable reference for DEK derivation + caching.
/// @param blob_id Walrus blob ID to fetch.
/// @param expected_sha256 Expected SHA-256 hex digest of the plaintext.
/// @return Decrypted plaintext as UTF-8 string.
pub async fn read_team_vault_entry(
    master_secret: &[u8; 32],
    team_id: &str,
    slug: &str,
    requesting_account_id: &AccountId,
    team_key_manager: &mut TeamKeyManager,
    blob_id: &str,
    expected_sha256: &str,
) -> Result<String, ReaderError> {
    let _ = slug; // used for logging context; derivation is team-scoped only

    // HIGH-R8: Validate hash format before any processing
    validate_sha256_format(expected_sha256)?;

    // 1. Build and validate Walrus Aggregator URL
    let aggregator_url = std::env::var("WALRUS_AGGREGATOR_URL")
        .unwrap_or_else(|_| "http://localhost:31601".to_string());

    // HIGH-R6: Validate scheme (https:// required in production; http://localhost allowed for dev)
    validate_walrus_url(&aggregator_url)?;

    // CRITICAL-R3: Hardened client with timeouts and no redirects
    let client = build_reader_client()?;
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

    // 3. Derive team DEK directly from platform master secret.
    //    AUDIT-FIX: The old code called get_encrypted_team_dek() which looked up a
    //    per-member wrapped DEK from an in-memory HashMap — but that cache was never
    //    populated anywhere in the codebase, so it always returned None and every read
    //    failed. The correct path matches the write side: derive the team DEK via
    //    get_or_generate_team_dek() which uses HKDF(master, team_id). The TEE is the
    //    trusted executor; access control is enforced upstream by the gateway.
    let team_dek_vec = team_key_manager
        .get_or_generate_team_dek(master_secret, team_id)
        .map_err(|_| ReaderError::DecryptionFailed)?;

    if team_dek_vec.len() != 32 {
        return Err(ReaderError::DecryptionFailed);
    }

    let mut team_dek_array = [0u8; 32];
    team_dek_array.copy_from_slice(&team_dek_vec);
    let team_dek = Zeroizing::new(team_dek_array);

    // 4. Decrypt blob using team DEK
    let nonce = Nonce::from_slice(iv);
    let mut decrypt_payload = Vec::with_capacity(ciphertext.len() + 16);
    decrypt_payload.extend_from_slice(ciphertext);
    decrypt_payload.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*team_dek));
    let decrypted_bytes = cipher
        .decrypt(nonce, decrypt_payload.as_slice())
        .map_err(|_| ReaderError::DecryptionFailed)?;

    let plaintext = String::from_utf8(decrypted_bytes)
        .map_err(|_| ReaderError::DecryptionFailed)?;

    // 5. HIGH-R8: Constant-time SHA-256 integrity check
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let computed_sha256 = hex::encode(hasher.finalize());

    // Both strings are 64-char hex — guaranteed same length — safe for constant-time compare
    let hashes_match: bool = computed_sha256.as_bytes()
        .ct_eq(expected_sha256.as_bytes())
        .into();

    if !hashes_match {
        return Err(ReaderError::IntegrityMismatch {
            expected: expected_sha256.to_string(),
            computed: computed_sha256,
        });
    }

    let _ = requesting_account_id; // validated upstream; retained for future audit logging
    Ok(plaintext)
}
