use near_sdk::{env, near};

// Re-export Permission enum from parent module for use in validation
use super::Permission;

// //////////////////////////////////////////////////////////////
//                          DATA MODEL
// //////////////////////////////////////////////////////////////

/// @title VaultPointer
/// @notice Represents a pointer to an encrypted blob stored on Walrus Protocol.
/// @dev The contract stores only this lightweight metadata — never the encrypted payload itself.
///
/// Borsh serialization field order is FIXED and append-only. Never reorder existing fields.
/// New fields must be added at the END and be Option<T> for backwards compatibility.
/// The `version` field (P3-6) is stored first to allow future schema migrations.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct VaultPointer {
    /// @notice Schema version. Current: 1. Increment when fields are added.
    /// @dev First field in Borsh layout — allows future readers to branch on version
    ///      without re-reading or re-interpreting subsequent bytes.
    pub version: u8,

    /// @notice The opaque Walrus blobId address locating the encrypted blob on Walrus.
    pub blob_id: String,

    /// @notice The SHA-256 integrity hash of the raw plaintext before encryption.
    /// @dev Used by the client to guarantee no tampering has occurred after decryption.
    pub content_sha256: String,

    /// @notice Unix timestamp in milliseconds when the pointer was last updated.
    pub updated_at_ms: u64,
}

impl VaultPointer {
    /// @notice Calculates the Borsh-serialized size of this VaultPointer.
    pub fn serialized_size(&self) -> u64 {
        // version (1) + blob_id (4 + len) + content_sha256 (4 + len) + updated_at_ms (8)
        1 + 4 + self.blob_id.len() as u64 + 4 + self.content_sha256.len() as u64 + 8
    }
}

// //////////////////////////////////////////////////////////////
//                      VALIDATION HELPERS
// //////////////////////////////////////////////////////////////

/// Maximum number of entries (wiki slugs or skill IDs) any single user can register.
/// F-02 FIX: Prevents unbounded Vec growth via repeated update_wiki_pointer calls.
/// Without this cap, an attacker could register 10^6 entries, causing:
///   - list_wiki_slugs() to iterate millions of entries → gas exhaustion DoS
///   - NEAR storage to be filled with an attacker's junk (storage staking attack)
pub const MAX_ENTRIES_PER_USER: usize = 1_000;

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

/// @notice Validates that a Walrus blob_id conforms to URL-safe Base64 format.
/// @dev P3-7 CORRECTION: Walrus blob IDs are NOT Base58 — they are 256-bit hashes encoded
///      as URL-safe Base64 (RFC 4648 §5) WITHOUT padding, producing a 43-character string.
///
/// ```text
/// Correct Walrus blob ID format:
///   - Alphabet: [A-Za-z0-9_-] (URL-safe Base64: '-' and '_' instead of '+' and '/')
///   - Typical length: exactly 43 characters (32 bytes * 4/3 rounded up, no '=' padding)
///   - We allow 1-64 chars to be forward-compatible with any future hash size changes
///
/// Examples of valid real Walrus blob IDs:
///   oehkoh0352bRGNPjuwcy0nye3OLKT649K62imdNAlXg (43 chars)
///   M4hsZGQ1oCktdzegB6HnI6Mi28S2nqOPHxK-W7_4BUk (43 chars, contains - and _)
///
/// The previous Base58 alphabet was INCORRECT - it rejected:
///   - '0' (valid in Base64, invalid in Base58)
///   - '-' and '_' (URL-safe Base64 substitutes for '+' and '/')
///   - 'O', 'I', 'l' (valid in Base64, excluded in Base58 for visual ambiguity)
/// ```
///
/// Panics with "VAULT_ERROR_INVALID_BLOB_ID" on failure.
pub fn validate_blob_id(blob_id: &str) {
    let len = blob_id.len();
    // Walrus blob IDs are 43 chars for a 256-bit hash; allow up to 64 for future flexibility.
    if len == 0 || len > 64 {
        env::panic_str("VAULT_ERROR_INVALID_BLOB_ID");
    }

    // URL-safe Base64 alphabet (RFC 4648 §5): A-Z, a-z, 0-9, hyphen (-), underscore (_).
    // Note: NO padding character ('=') — Walrus omits padding.
    for c in blob_id.chars() {
        if !matches!(c,
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_'
        ) {
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

/// Maximum number of members any single team can have.
/// Prevents unbounded Vec growth and storage staking attacks.
pub const MAX_TEAM_MEMBERS: usize = 100;

/// @notice Validates a team ID according to the same rules as identifiers.
/// @dev Reuses validate_identifier logic for consistency.
///      Rule: ^[a-z0-9][a-z0-9_-]{0,127}$
///      Panics with "VAULT_ERROR_INVALID_IDENTIFIER" on failure.
pub fn validate_team_id(team_id: &str) {
    validate_identifier(team_id);
}

/// @notice Validates that a Permission enum variant is valid.
/// @dev The enum definition already ensures type safety, but this provides
///      a consistent validation interface for callers.
pub fn validate_permission(permission: &Permission) {
    // Enum variants are validated by the type system
    let _ = permission;
}
