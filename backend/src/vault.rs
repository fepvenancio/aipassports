use near_sdk::{env, near};

// //////////////////////////////////////////////////////////////
//                          DATA MODEL
// //////////////////////////////////////////////////////////////

/// @title VaultPointer
/// @notice Represents a pointer to an encrypted blob stored on Walrus Protocol.
/// @dev The contract stores only this lightweight metadata — never the encrypted payload itself.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct VaultPointer {
    /// @notice The opaque Walrus blobId address locating the encrypted blob on Walrus.
    pub blob_id: String,

    /// @notice The SHA-256 integrity hash of the raw plaintext before encryption.
    /// @dev Used by the client to guarantee no tampering has occurred after decryption.
    pub content_sha256: String,

    /// @notice Unix timestamp in milliseconds when the pointer was last updated.
    pub updated_at_ms: u64,
}

// //////////////////////////////////////////////////////////////
//                      VALIDATION HELPERS
// //////////////////////////////////////////////////////////////

/// @notice Validates a page slug or skill ID according to strict structural rules.
/// @dev Rule: ^[a-z0-9][a-z0-9_-]{0,127}$
///      Start with [a-z0-9] (lowercase alphanumeric).
///      Subsequent characters must be [a-z0-9_-].
///      Total length must be between 1 and 128 characters.
///      Panics with "VAULT_ERROR_INVALID_IDENTIFIER" on failure.
pub fn validate_identifier(id: &str) {
    let len = id.len();
    if len == 0 || len > 128 {
        env::panic_str("VAULT_ERROR_INVALID_IDENTIFIER");
    }
    
    let mut chars = id.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        env::panic_str("VAULT_ERROR_INVALID_IDENTIFIER");
    }
    
    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' && c != '_' {
            env::panic_str("VAULT_ERROR_INVALID_IDENTIFIER");
        }
    }
}

/// @notice Validates that a Walrus blob_id is structurally safe and non-empty.
/// @dev Rule: Must be non-empty, max 128 characters, and contain only printable ASCII.
///      Panics with "VAULT_ERROR_INVALID_BLOB_ID" on failure.
pub fn validate_blob_id(blob_id: &str) {
    let len = blob_id.len();
    if len == 0 || len > 128 {
        env::panic_str("VAULT_ERROR_INVALID_BLOB_ID");
    }
    
    for c in blob_id.chars() {
        if !c.is_ascii() || c.is_ascii_control() {
            env::panic_str("VAULT_ERROR_INVALID_BLOB_ID");
        }
    }
}

/// @notice Validates that a content hash is a valid 64-character lowercase hex digest.
/// @dev Rule: Exactly 64 characters, lowercase hex only [0-9a-f].
///      Panics with "VAULT_ERROR_INVALID_HASH" on failure.
pub fn validate_content_sha256(hash: &str) {
    if hash.len() != 64 {
        env::panic_str("VAULT_ERROR_INVALID_HASH");
    }
    
    for c in hash.chars() {
        if !c.is_ascii_hexdigit() || (c.is_ascii_alphabetic() && !c.is_ascii_lowercase()) {
            env::panic_str("VAULT_ERROR_INVALID_HASH");
        }
    }
}
