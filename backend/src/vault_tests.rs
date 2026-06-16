//! Comprehensive unit tests for the vault.rs module
//! 
//! Tests cover:
//! - VaultPointer struct creation and serialization
//! - Identifier validation (validate_identifier)
//! - Blob ID validation (validate_blob_id)
//! - Content SHA-256 validation (validate_content_sha256)

use super::vault::{
    VaultPointer, validate_blob_id, validate_content_sha256, validate_identifier,
    MAX_ENTRIES_PER_USER,
};
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId};
use near_sdk::borsh::{BorshSerialize, BorshDeserialize};

// Helper context for tests that need NEAR environment
fn get_context(predecessor: AccountId) -> near_sdk::VMContext {
    VMContextBuilder::new()
        .predecessor_account_id(predecessor)
        .build()
}

// ============================================================================
// VAULT POINTER STRUCT TESTS
// ============================================================================

#[test]
fn test_vault_pointer_creation() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "validBlobId123".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1234567890,
    };

    assert_eq!(pointer.version, 1);
    assert_eq!(pointer.blob_id, "validBlobId123");
    assert_eq!(
        pointer.content_sha256,
        "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939"
    );
    assert_eq!(pointer.updated_at_ms, 1234567890);
}

#[test]
fn test_vault_pointer_serialized_size() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "abc".to_string(), // 3 chars
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1234567890,
    };

    // Expected: version(1) + blob_id(4 + len) + content_sha256(4 + len) + updated_at_ms(8)
    let expected_size = 1 + 4 + 3 + 4 + 64 + 8;
    assert_eq!(pointer.serialized_size(), expected_size);
}

#[test]
fn test_vault_pointer_serialized_size_empty_strings() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "".to_string(),
        content_sha256: "".to_string(),
        updated_at_ms: 0,
    };

    let expected_size = 1 + 4 + 0 + 4 + 0 + 8;
    assert_eq!(pointer.serialized_size(), expected_size);
}

#[test]
fn test_vault_pointer_serialized_size_long_strings() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "a".repeat(64),
        content_sha256: "a".repeat(64),
        updated_at_ms: u64::MAX,
    };

    let expected_size = 1 + 4 + 64 + 4 + 64 + 8;
    assert_eq!(pointer.serialized_size(), expected_size);
}

#[test]
fn test_vault_pointer_clone() {
    let original = VaultPointer {
        version: 1,
        blob_id: "test".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1000,
    };

    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn test_vault_pointer_partial_eq() {
    let pointer1 = VaultPointer {
        version: 1,
        blob_id: "test".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1000,
    };

    let pointer2 = VaultPointer {
        version: 1,
        blob_id: "test".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1000,
    };

    let pointer3 = VaultPointer {
        version: 2,
        blob_id: "test".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1000,
    };

    assert_eq!(pointer1, pointer2);
    assert_ne!(pointer1, pointer3);
}

#[test]
fn test_vault_pointer_debug() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "test".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1000,
    };

    let debug_str = format!("{:?}", pointer);
    assert!(debug_str.contains("VaultPointer"));
    assert!(debug_str.contains("version: 1"));
    assert!(debug_str.contains("blob_id: \"test\""));
}

// ============================================================================
// VAULT POINTER SERIALIZATION TESTS
// ============================================================================

#[test]
fn test_vault_pointer_borsh_serialization() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "test_blob".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1234567890,
    };

    let serialized = pointer.try_to_vec().unwrap();
    let deserialized: VaultPointer = BorshDeserialize::try_from_slice(&serialized).unwrap();
    assert_eq!(pointer, deserialized);
}

#[test]
fn test_vault_pointer_json_serialization() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "test_blob".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1234567890,
    };

    let json_str = serde_json::to_string(&pointer).unwrap();
    let deserialized: VaultPointer = serde_json::from_str(&json_str).unwrap();
    assert_eq!(pointer, deserialized);
}

#[test]
fn test_vault_pointer_json_structure() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "test_blob".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1234567890,
    };

    let json_str = serde_json::to_string(&pointer).unwrap();
    assert!(json_str.contains("\"version\":1"));
    assert!(json_str.contains("\"blob_id\":\"test_blob\""));
    assert!(json_str.contains("\"content_sha256\":\"d6e330a1"));
    assert!(json_str.contains("\"updated_at_ms\":1234567890"));
}

// ============================================================================
// IDENTIFIER VALIDATION TESTS (validate_identifier)
// ============================================================================

#[test]
fn test_validate_identifier_valid_single_lowercase() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("a");
}

#[test]
fn test_validate_identifier_valid_single_digit() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("0");
}

#[test]
fn test_validate_identifier_valid_min_length() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("a");
}

#[test]
fn test_validate_identifier_valid_max_length() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let id = "a".repeat(128);
    validate_identifier(&id);
}

#[test]
fn test_validate_identifier_valid_with_all_allowed_chars() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abc123xyz_123-test");
}

#[test]
fn test_validate_identifier_valid_starting_with_digit() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("123abc");
}

#[test]
fn test_validate_identifier_valid_with_underscores_and_hyphens() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("my_test-123_valid");
}

#[test]
fn test_validate_identifier_valid_wiki_slug_example() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("erc4626-standard");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_empty() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_too_long() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let id = "a".repeat(129);
    validate_identifier(&id);
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_starting_with_uppercase() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("Abc123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_starting_with_underscore() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("_abc123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_starting_with_hyphen() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("-abc123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_with_spaces() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abc 123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_with_special_chars() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abc!@#$%");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_with_period() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abc.123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_with_comma() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abc,123");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_with_uppercase_in_middle() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abcDef");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_IDENTIFIER")]
fn test_validate_identifier_non_ascii() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_identifier("abcÄ123");
}

// ============================================================================
// BLOB ID VALIDATION TESTS (validate_blob_id)
// ============================================================================

#[test]
fn test_validate_blob_id_valid_min_length() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("1");
}

#[test]
fn test_validate_blob_id_valid_max_length() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let blob_id = "1".repeat(64);
    validate_blob_id(&blob_id);
}

#[test]
fn test_validate_blob_id_valid_base58_chars() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
}

#[test]
fn test_validate_blob_id_valid_walrus_example() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("CertfedBdBHashBase58Ab");
}

#[test]
fn test_validate_blob_id_valid_43_chars() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let blob_id = "1".repeat(43);
    validate_blob_id(&blob_id);
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_empty() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_too_long() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let blob_id = "1".repeat(65);
    validate_blob_id(&blob_id);
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_zero() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc0def");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_capital_o() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abcOdef");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_capital_i() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abcIdef");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_lowercase_l() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abcldef");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_space() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc def");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_slash() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc/def");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_question_mark() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc?def");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_plus() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc+def");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_BLOB_ID")]
fn test_validate_blob_id_contains_equals() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_blob_id("abc=def");
}

// ============================================================================
// CONTENT SHA-256 VALIDATION TESTS (validate_content_sha256)
// ============================================================================

#[test]
fn test_validate_content_sha256_valid() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939");
}

#[test]
fn test_validate_content_sha256_valid_all_zeros() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let hash = "0".repeat(64);
    validate_content_sha256(&hash);
}

#[test]
fn test_validate_content_sha256_valid_all_f() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let hash = "f".repeat(64);
    validate_content_sha256(&hash);
}

#[test]
fn test_validate_content_sha256_valid_mixed_hex() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_empty() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_too_short() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_too_long() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let hash = "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a39391234";
    validate_content_sha256(&hash);
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_uppercase() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("D6E330A1C1D9333A39393A646C26A1C1D9333A39393A646C26A1C1D9333A3939");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_mixed_case() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6E330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_contains_non_hex() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a39g9");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_contains_special_chars() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3-39");
}

#[test]
#[should_panic(expected = "VAULT_ERROR_INVALID_HASH")]
fn test_validate_content_sha256_contains_space() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    validate_content_sha256("d6e330a1c1d9333a 39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939");
}

// ============================================================================
// CONSTANT TESTS
// ============================================================================

#[test]
fn test_max_entries_per_user_constant() {
    assert_eq!(MAX_ENTRIES_PER_USER, 1_000);
}

// ============================================================================
// EDGE CASE AND INTEGRATION TESTS
// ============================================================================

#[test]
fn test_vault_pointer_with_real_world_data() {
    let pointer = VaultPointer {
        version: 1,
        blob_id: "CertfedBdBHashBase58Ab".to_string(),
        content_sha256: "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939".to_string(),
        updated_at_ms: 1716435600000,
    };

    assert_eq!(pointer.version, 1);
    assert!(pointer.serialized_size() > 0);
    
    let serialized = pointer.try_to_vec().unwrap();
    let deserialized: VaultPointer = BorshDeserialize::try_from_slice(&serialized).unwrap();
    assert_eq!(pointer, deserialized);
}

#[test]
fn test_all_validation_functions_with_valid_data() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    
    validate_identifier("valid-slug_123");
    validate_blob_id("CertfedBdBHashBase58Ab");
    validate_content_sha256("d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939");
}

#[test]
fn test_validation_functions_are_independent() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    
    validate_identifier("valid-identifier");
    
    let result = std::panic::catch_unwind(|| {
        testing_env!(get_context(AccountId::new("test.near".to_string())));
        validate_blob_id("invalid/blob");
    });
    assert!(result.is_err());
}

// ============================================================================
// PROPERTY-BASED TESTING HELPERS
// ============================================================================

fn generate_valid_identifier(length: usize) -> String {
    assert!(length >= 1 && length <= 128, "Identifier length must be 1-128");
    let mut id = String::with_capacity(length);
    if length > 0 {
        id.push('a');
    }
    for _ in 1..length {
        id.push('a');
    }
    id
}

fn generate_valid_blob_id(length: usize) -> String {
    assert!(length >= 1 && length <= 64, "Blob ID length must be 1-64");
    "1".repeat(length)
}

fn generate_valid_sha256() -> String {
    "0".repeat(64)
}

#[test]
fn test_generated_valid_identifier() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    
    for length in [1, 2, 10, 50, 100, 128] {
        let id = generate_valid_identifier(length);
        validate_identifier(&id);
    }
}

#[test]
fn test_generated_valid_blob_id() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    
    for length in [1, 2, 10, 43, 44, 64] {
        let blob_id = generate_valid_blob_id(length);
        validate_blob_id(&blob_id);
    }
}

#[test]
fn test_generated_valid_sha256() {
    testing_env!(get_context(AccountId::new("test.near".to_string())));
    let hash = generate_valid_sha256();
    validate_content_sha256(&hash);
}
