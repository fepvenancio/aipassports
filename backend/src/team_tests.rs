//! Comprehensive unit tests for team functionality
//!
//! Tests cover:
//! - Team creation and validation
//! - Team member management
//! - Team vault operations
//! - Permission enforcement
//!
//! CORRECTIONS applied (2026-06-17):
//!   TEST-FIX-1 — `AccountId::new_unvalidated()` is deprecated since nearcore#4440.
//!                Replaced with `"account.near".parse::<AccountId>().unwrap()` throughout.
//!   TEST-FIX-2 — `VMContextBuilder::new()` defaults `block_timestamp` to 0 (nanoseconds).
//!                `env::block_timestamp_ms()` returns 0/1_000_000 = 0, so `created_at > 0`
//!                and `joined_at > 0` assertions fail. Fixed by setting a non-zero timestamp
//!                of 1_700_000_000_000_000_000 ns (≈ Nov 2023 in nanoseconds).
//!   TEST-FIX-3 — `get_team_metadata()` returns `Option<TeamMetadata>`, not a panic.
//!                Tests expecting `#[should_panic(expected = "TEAM_NOT_FOUND")]` were wrong.
//!                Fixed to assert `None` is returned for non-existent teams.
//!   TEST-FIX-4 — `validate_blob_id` now uses URL-safe Base64 [A-Za-z0-9_-], not Base58.
//!                Test fixtures updated to use real Walrus-style blob IDs.
//!   TEST-FIX-5 — `test_validate_content_sha256_valid_mixed_hex` had a 62-char hex string.
//!                SHA-256 is exactly 64 hex chars. Fixed.

use super::*;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId};

// ─── Test Helpers ─────────────────────────────────────────────────────────────

/// Returns a VMContext with the caller set as both predecessor and signer,
/// a non-zero block timestamp so `env::block_timestamp_ms() > 0`, and a
/// sufficient attached deposit for storage costs.
///
/// TEST-FIX-2: `VMContextBuilder::new()` defaults block_timestamp to 0 (nanoseconds).
/// `env::block_timestamp_ms()` = block_timestamp / 1_000_000, so it also returns 0.
/// Contract code stores `env::block_timestamp_ms()` into `created_at` and `joined_at`,
/// causing `assert!(field > 0)` to fail. We set 1_700_000_000_000_000_000 ns (Nov 2023).
///
/// DEPOSIT: The contract's `_reconcile_storage_deposit` requires yoctoNEAR proportional to
/// new bytes stored. `add_team_member` and `update_team_wiki_pointer` are `#[payable]` and
/// will panic with VAULT_ERROR_INSUFFICIENT_DEPOSIT if no deposit is attached.
/// Using 100_000_000_000_000_000_000_000 yoctoNEAR (= 0.1 NEAR) — same as lib.rs tests.
fn get_context(predecessor: AccountId) -> near_sdk::VMContext {
    VMContextBuilder::new()
        .predecessor_account_id(predecessor.clone())
        .signer_account_id(predecessor)
        .block_timestamp(1_700_000_000_000_000_000u64) // TEST-FIX-2: non-zero → ms > 0
        .attached_deposit(near_sdk::NearToken::from_yoctonear(100_000_000_000_000_000_000_000))
        .build()
}

/// A valid Walrus-style blob ID (URL-safe Base64, 43 chars).
/// TEST-FIX-4: Real Walrus blob IDs use [A-Za-z0-9_-] alphabet, NOT Base58.
const VALID_BLOB_ID: &str = "M4hsZGQ1oCktdzegB6HnI6Mi28S2nqOPHxK-W7-4BUk";

/// A valid 64-character lowercase SHA-256 hex digest.
const VALID_SHA256: &str = "d6e330a1c1d9333a39393a646c26a1c1d9333a39393a646c26a1c1d9333a3939";

fn get_contract() -> AegisContract {
    AegisContract::new()
}

// ============================================================================
// TEAM CREATION TESTS
// ============================================================================

#[test]
fn test_create_team() {
    let mut contract = get_contract();
    // TEST-FIX-1: use .parse().unwrap() instead of deprecated new_unvalidated()
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    let name = "Test Team".to_string();

    // Create team
    contract.create_team(team_id.clone(), name.clone());

    // Verify team exists
    let metadata = contract.get_team_metadata(team_id.clone()).expect("Team should exist");
    assert_eq!(metadata.team_id, team_id);
    assert_eq!(metadata.name, name);
    // TEST-FIX-2: block_timestamp is now non-zero, so block_timestamp_ms() > 0
    assert!(metadata.created_at > 0, "created_at must be > 0; check block_timestamp in get_context()");
    assert_eq!(metadata.created_by, admin);

    // Verify admin is added as member
    let members = contract.list_team_members(team_id.clone());
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].account_id, admin);
    assert_eq!(members[0].permission, Permission::Admin);
    // TEST-FIX-2: same fix — joined_at comes from env::block_timestamp_ms()
    assert!(members[0].joined_at > 0, "joined_at must be > 0; check block_timestamp in get_context()");
    assert_eq!(members[0].added_by, admin);
}

#[test]
#[should_panic(expected = "TEAM_ALREADY_EXISTS")]
fn test_create_team_duplicate() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    let name = "Test Team".to_string();

    // Create team twice
    contract.create_team(team_id.clone(), name.clone());
    contract.create_team(team_id, name); // Should panic with TEAM_ALREADY_EXISTS
}

// ============================================================================
// TEAM MEMBER MANAGEMENT TESTS
// ============================================================================

#[test]
fn test_add_team_member() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let member: AccountId = "member.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    // Add member with Write permission
    contract.add_team_member(team_id.clone(), member.clone(), Permission::Write);

    // Verify member was added
    let members = contract.list_team_members(team_id.clone());
    assert_eq!(members.len(), 2);

    let member_record = members.iter().find(|m| m.account_id == member).expect("Member should exist");
    assert_eq!(member_record.permission, Permission::Write);
    // TEST-FIX-2: non-zero timestamp required
    assert!(member_record.joined_at > 0, "joined_at must be > 0");
    assert_eq!(member_record.added_by, admin);
}

#[test]
#[should_panic(expected = "TEAM_PERMISSION_DENIED")]
fn test_add_team_member_non_admin() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let member: AccountId = "member.near".parse().unwrap();
    let non_admin: AccountId = "nonadmin.near".parse().unwrap();

    testing_env!(get_context(admin.clone()));
    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    // Add member with Read permission
    contract.add_team_member(team_id.clone(), member.clone(), Permission::Read);

    // Try to add another member from non-admin account — should panic
    testing_env!(get_context(non_admin.clone()));
    contract.add_team_member(team_id, "new.near".parse().unwrap(), Permission::Write);
}

#[test]
fn test_remove_team_member() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let member: AccountId = "member.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());
    contract.add_team_member(team_id.clone(), member.clone(), Permission::Write);

    // Verify member exists
    let members_before = contract.list_team_members(team_id.clone());
    assert_eq!(members_before.len(), 2);

    // Remove member
    contract.remove_team_member(team_id.clone(), member.clone());

    // Verify member was removed
    let members_after = contract.list_team_members(team_id);
    assert_eq!(members_after.len(), 1);
    assert_eq!(members_after[0].account_id, admin);
}

// ============================================================================
// TEAM VAULT OPERATIONS TESTS
// ============================================================================

#[test]
fn test_update_team_wiki_pointer() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    let slug = "test-slug".to_string();
    // TEST-FIX-4: Use URL-safe Base64 blob ID (Walrus format), not Base58
    let blob_id = VALID_BLOB_ID.to_string();
    let content_sha256 = VALID_SHA256.to_string();

    // Add wiki pointer
    contract.update_team_wiki_pointer(team_id.clone(), slug.clone(), blob_id.clone(), content_sha256.clone());

    // Verify pointer was stored
    let pointer = contract.get_team_wiki_pointer(team_id.clone(), slug.clone())
        .expect("Pointer should exist");
    assert_eq!(pointer.blob_id, blob_id);
    assert_eq!(pointer.content_sha256, content_sha256);

    // Verify slug was added to list
    let slugs = contract.list_team_wiki_slugs(team_id);
    assert_eq!(slugs.len(), 1);
    assert_eq!(slugs[0], slug);
}

#[test]
fn test_get_team_wiki_pointer() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    let slug = "test-slug".to_string();
    // TEST-FIX-4: Use URL-safe Base64 blob ID
    let blob_id = VALID_BLOB_ID.to_string();
    let content_sha256 = VALID_SHA256.to_string();

    // Add wiki pointer
    contract.update_team_wiki_pointer(team_id.clone(), slug.clone(), blob_id.clone(), content_sha256.clone());

    // Retrieve pointer
    let retrieved_pointer = contract.get_team_wiki_pointer(team_id, slug)
        .expect("Pointer should exist");

    // Verify it matches
    assert_eq!(retrieved_pointer.blob_id, blob_id);
    assert_eq!(retrieved_pointer.content_sha256, content_sha256);
}

// ============================================================================
// PERMISSION ENFORCEMENT TESTS
// ============================================================================

#[test]
#[should_panic(expected = "TEAM_PERMISSION_DENIED")]
fn test_team_permission_enforcement() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let read_only_member: AccountId = "readonly.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    // Add read-only member
    contract.add_team_member(team_id.clone(), read_only_member.clone(), Permission::Read);

    // Try to write wiki pointer as read-only member — should panic with TEAM_PERMISSION_DENIED
    testing_env!(get_context(read_only_member.clone()));
    contract.update_team_wiki_pointer(
        team_id,
        "test-slug".to_string(),
        VALID_BLOB_ID.to_string(),
        VALID_SHA256.to_string(),
    );
}

#[test]
fn test_team_member_permission_update() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let member: AccountId = "member.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());
    contract.add_team_member(team_id.clone(), member.clone(), Permission::Read);

    // Verify initial permission
    let members = contract.list_team_members(team_id.clone());
    let member_record = members.iter().find(|m| m.account_id == member).expect("Member should exist");
    assert_eq!(member_record.permission, Permission::Read);

    // Update permission to Write
    contract.update_team_member_permission(team_id.clone(), member.clone(), Permission::Write);

    // Verify permission was updated
    let members_after = contract.list_team_members(team_id);
    let updated_member = members_after.iter().find(|m| m.account_id == member).expect("Member should exist");
    assert_eq!(updated_member.permission, Permission::Write);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

#[test]
fn test_get_nonexistent_team() {
    // TEST-FIX-3: get_team_metadata() returns Option<TeamMetadata>, NOT a panic.
    // The contract has no testing_env set, so we need one for the NEAR SDK to initialise.
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin));

    let contract = get_contract();
    let result = contract.get_team_metadata("nonexistent-team".to_string());

    // Correct assertion: function returns None for missing team, does not panic
    assert!(result.is_none(), "get_team_metadata should return None for a non-existent team");
}

#[test]
#[should_panic(expected = "TEAM_MEMBER_REQUIRED")]
fn test_remove_nonexistent_member() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    let team_id = "test-team".to_string();
    contract.create_team(team_id.clone(), "Test Team".to_string());

    let nonexistent_member: AccountId = "nonexistent.near".parse().unwrap();

    // Try to remove member that doesn't exist — should panic with TEAM_MEMBER_REQUIRED
    contract.remove_team_member(team_id, nonexistent_member);
}

#[test]
fn test_team_creation_with_max_length_id() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    // Create team with maximum length ID (128 chars)
    let team_id = "a".repeat(128);
    let name = "Test Team".to_string();

    contract.create_team(team_id.clone(), name);

    // Verify team was created
    let metadata = contract.get_team_metadata(team_id.clone()).expect("Team should exist");
    assert_eq!(metadata.team_id, team_id);
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_full_team_workflow() {
    let mut contract = get_contract();
    let admin: AccountId = "admin.near".parse().unwrap();
    let member1: AccountId = "member1.near".parse().unwrap();
    let member2: AccountId = "member2.near".parse().unwrap();
    testing_env!(get_context(admin.clone()));

    // 1. Create team
    let team_id = "workflow-team".to_string();
    contract.create_team(team_id.clone(), "Workflow Test Team".to_string());

    // 2. Add members with different permissions
    contract.add_team_member(team_id.clone(), member1.clone(), Permission::Write);
    contract.add_team_member(team_id.clone(), member2.clone(), Permission::Read);

    // 3. Verify all members exist
    let members = contract.list_team_members(team_id.clone());
    assert_eq!(members.len(), 3);

    // 4. Add wiki entry as admin
    // TEST-FIX-4: Use URL-safe Base64 blob ID
    contract.update_team_wiki_pointer(
        team_id.clone(),
        "doc1".to_string(),
        VALID_BLOB_ID.to_string(),
        VALID_SHA256.to_string(),
    );

    // 5. Verify wiki entry exists
    let slugs = contract.list_team_wiki_slugs(team_id.clone());
    assert_eq!(slugs.len(), 1);
    assert_eq!(slugs[0], "doc1");

    // 6. Update member1 to admin
    contract.update_team_member_permission(team_id.clone(), member1.clone(), Permission::Admin);

    // 7. Verify permission update
    let updated_members = contract.list_team_members(team_id.clone());
    let member1_record = updated_members.iter().find(|m| m.account_id == member1).expect("Member1 should exist");
    assert_eq!(member1_record.permission, Permission::Admin);

    // 8. Remove member2
    contract.remove_team_member(team_id.clone(), member2.clone());

    // 9. Verify final state
    let final_members = contract.list_team_members(team_id);
    assert_eq!(final_members.len(), 2);
    assert!(final_members.iter().any(|m| m.account_id == admin));
    assert!(final_members.iter().any(|m| m.account_id == member1));
    assert!(!final_members.iter().any(|m| m.account_id == member2));
}