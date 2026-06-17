//! Comprehensive unit tests for TeamKeyManager
//!
//! Tests cover:
//! - Team DEK generation and determinism
//! - Team DEK encryption/decryption
//! - Security properties (wrong key fails)
//! - Cache operations
//!
//! AUDIT-I1 (2026-06-17): Updated for new deterministic key derivation API.
//!   - Removed `store_team_master_secret` / `get_team_master_secret` / `team_exists` tests
//!     (those methods no longer exist — team secrets are derived from platform master secret).
//!   - Updated `get_or_generate_team_dek` calls to accept `platform_master: &[u8; 32]`.

use super::team_key_manager::TeamKeyManager;

// ============================================================================
// TEAM DEK GENERATION TESTS
// ============================================================================

#[test]
fn test_generate_team_dek() {
    let manager = TeamKeyManager::new();

    let team_id = "test-team";
    let master_secret = [42u8; 32]; // 32-byte team master secret

    // Generate team DEK
    let dek = manager.generate_team_dek(team_id, &master_secret);

    // Verify it's 32 bytes
    assert_eq!(dek.len(), 32, "Team DEK should be 32 bytes");

    // Verify deterministic: same inputs produce same output
    let dek2 = manager.generate_team_dek(team_id, &master_secret);
    assert_eq!(*dek, *dek2, "Team DEK generation should be deterministic");

    // Verify different team IDs produce different DEKs
    let dek3 = manager.generate_team_dek("different-team", &master_secret);
    assert_ne!(*dek, *dek3, "Different team IDs should produce different DEKs");

    // Verify different master secrets produce different DEKs
    let different_master = [43u8; 32];
    let dek4 = manager.generate_team_dek(team_id, &different_master);
    assert_ne!(*dek, *dek4, "Different master secrets should produce different DEKs");
}

#[test]
fn test_get_or_generate_team_dek_determinism() {
    let mut manager = TeamKeyManager::new();

    let platform_master = [1u8; 32];
    let team_id = "cached-team";

    // First call: cache miss — derives and caches
    let dek1 = manager.get_or_generate_team_dek(&platform_master, team_id)
        .expect("Should derive DEK successfully");

    // Second call: cache hit — returns same DEK
    let dek2 = manager.get_or_generate_team_dek(&platform_master, team_id)
        .expect("Should return cached DEK successfully");

    assert_eq!(*dek1, *dek2, "Cached DEK must match derived DEK");
}

#[test]
fn test_get_or_generate_team_dek_cross_restart_consistency() {
    // Simulates a "restart": create a fresh manager with the same platform master secret.
    // The derived DEK must be identical, proving no data loss on restart.
    let platform_master = [77u8; 32];
    let team_id = "my-team";

    let dek_before = {
        let mut manager = TeamKeyManager::new();
        manager.get_or_generate_team_dek(&platform_master, team_id)
            .expect("DEK derivation should succeed")
    };

    let dek_after = {
        let mut manager = TeamKeyManager::new(); // fresh instance = simulated restart
        manager.get_or_generate_team_dek(&platform_master, team_id)
            .expect("DEK derivation should succeed after restart")
    };

    assert_eq!(
        *dek_before, *dek_after,
        "AUDIT-I1: Team DEK must be identical across restarts (deterministic derivation)"
    );
}

#[test]
fn test_get_or_generate_team_dek_isolation() {
    let mut manager = TeamKeyManager::new();
    let platform_master = [1u8; 32];

    let dek_a = manager.get_or_generate_team_dek(&platform_master, "team-alpha")
        .expect("DEK derivation should succeed");
    let dek_b = manager.get_or_generate_team_dek(&platform_master, "team-beta")
        .expect("DEK derivation should succeed");

    assert_ne!(*dek_a, *dek_b, "Different teams must get different DEKs");
}

// ============================================================================
// TEAM DEK ENCRYPTION/DECRYPTION TESTS
// ============================================================================

#[test]
fn test_encrypt_decrypt_team_dek() {
    let manager = TeamKeyManager::new();

    // Setup: team DEK and member DEK
    let team_dek = vec![1u8; 32];
    let member_dek = [2u8; 32];
    let member_account = "alice.near".to_string();

    // Encrypt team DEK for member
    let encrypted = manager.encrypt_team_dek_for_member(&team_dek, &member_account, &member_dek);

    // Verify encrypted data has nonce + ciphertext
    assert!(encrypted.len() > 12, "Encrypted data should include 12-byte nonce + ciphertext");

    // Decrypt with same member DEK and correct member account (AAD)
    let decrypted = manager.decrypt_team_dek_for_member(&encrypted, &member_dek, &member_account);

    // Verify decryption succeeded
    assert!(decrypted.is_some(), "Decryption should succeed with correct key and AAD");
    assert_eq!(decrypted.unwrap(), team_dek, "Decrypted DEK should match original");
}

#[test]
fn test_encrypt_decrypt_fails_with_wrong_key() {
    let manager = TeamKeyManager::new();

    // Setup: team DEK and two different member DEKs
    let team_dek = vec![1u8; 32];
    let member1_dek = [2u8; 32];
    let member2_dek = [3u8; 32];
    let member_account = "alice.near".to_string();

    // Encrypt with member1 DEK
    let encrypted = manager.encrypt_team_dek_for_member(&team_dek, &member_account, &member1_dek);

    // Try to decrypt with member2 DEK (wrong key) — AAD matches but key is wrong
    let decrypted = manager.decrypt_team_dek_for_member(&encrypted, &member2_dek, &member_account);

    // Should fail (return None)
    assert!(decrypted.is_none(), "Decryption should fail with wrong key");
}

#[test]
fn test_encrypt_decrypt_different_accounts() {
    let manager = TeamKeyManager::new();

    let team_dek = vec![1u8; 32];
    let member_dek = [2u8; 32];

    // Encrypt for two different accounts
    let encrypted1 = manager.encrypt_team_dek_for_member(&team_dek, &"alice.near".to_string(), &member_dek);
    let encrypted2 = manager.encrypt_team_dek_for_member(&team_dek, &"bob.near".to_string(), &member_dek);

    // Should produce different ciphertexts due to different nonces
    assert_ne!(encrypted1, encrypted2, "Different accounts should get different encrypted DEKs");

    // Both should decrypt with the correct AAD (own account ID) and same member DEK
    let decrypted1 = manager.decrypt_team_dek_for_member(&encrypted1, &member_dek, "alice.near");
    let decrypted2 = manager.decrypt_team_dek_for_member(&encrypted2, &member_dek, "bob.near");

    assert_eq!(decrypted1.unwrap(), decrypted2.unwrap(), "Both should decrypt to same team DEK");

    // AUDIT-H2: Cross-account decryption must fail — using alice's ciphertext with bob's AAD
    let cross_decrypt = manager.decrypt_team_dek_for_member(&encrypted1, &member_dek, "bob.near");
    assert!(cross_decrypt.is_none(), "Cross-account decryption must fail due to AAD mismatch");
}

// ============================================================================
// CACHE OPERATIONS TESTS
// ============================================================================

#[test]
fn test_store_and_retrieve_encrypted_dek() {
    let mut manager = TeamKeyManager::new();

    let team_id = "test-team";
    let member_account = "alice.near";
    let encrypted_dek = vec![1, 2, 3, 4, 5]; // Mock encrypted data

    // Store encrypted DEK
    manager.store_encrypted_team_dek(
        team_id.to_string(),
        member_account.to_string(),
        encrypted_dek.clone()
    );

    // Retrieve it
    let retrieved = manager.get_encrypted_team_dek(team_id, &member_account.to_string());

    // Verify retrieval succeeded
    assert!(retrieved.is_some(), "Retrieved encrypted DEK should exist");
    assert_eq!(*retrieved.unwrap(), encrypted_dek, "Retrieved DEK should match stored DEK");
}

#[test]
fn test_delete_encrypted_dek() {
    let mut manager = TeamKeyManager::new();

    let team_id = "test-team";
    let member_account = "alice.near";
    let encrypted_dek = vec![1, 2, 3, 4, 5];

    // Store and verify
    manager.store_encrypted_team_dek(
        team_id.to_string(),
        member_account.to_string(),
        encrypted_dek.clone()
    );
    assert!(manager.get_encrypted_team_dek(team_id, &member_account.to_string()).is_some());

    // Delete
    manager.delete_encrypted_team_dek(team_id, &member_account.to_string());

    // Verify deletion
    let deleted = manager.get_encrypted_team_dek(team_id, &member_account.to_string());
    assert!(deleted.is_none(), "Deleted DEK should not exist");
}

#[test]
fn test_encrypted_dek_cache_isolation() {
    let mut manager = TeamKeyManager::new();

    let team1 = "team1";
    let team2 = "team2";
    let member1 = "alice";
    let member2 = "bob";

    // Store different DEKs for different teams/members
    manager.store_encrypted_team_dek(team1.to_string(), member1.to_string(), vec![1, 1, 1]);
    manager.store_encrypted_team_dek(team1.to_string(), member2.to_string(), vec![2, 2, 2]);
    manager.store_encrypted_team_dek(team2.to_string(), member1.to_string(), vec![3, 3, 3]);

    // Verify isolation
    assert_eq!(*manager.get_encrypted_team_dek(team1, &member1.to_string()).unwrap(), vec![1, 1, 1]);
    assert_eq!(*manager.get_encrypted_team_dek(team1, &member2.to_string()).unwrap(), vec![2, 2, 2]);
    assert_eq!(*manager.get_encrypted_team_dek(team2, &member1.to_string()).unwrap(), vec![3, 3, 3]);

    // Verify non-existent combinations return None
    assert!(manager.get_encrypted_team_dek(team2, &member2.to_string()).is_none());
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================

#[test]
fn test_full_team_key_lifecycle() {
    let mut manager = TeamKeyManager::new();

    // 1. Derive team DEK from platform master secret (AUDIT-I1: no store_team_master_secret needed)
    let platform_master = [1u8; 32];
    let team_id = "lifecycle-team";
    let team_dek = manager.get_or_generate_team_dek(&platform_master, team_id)
        .expect("DEK derivation should succeed");
    assert_eq!(team_dek.len(), 32);

    // 2. Add two members
    let member1_dek = [2u8; 32];
    let member2_dek = [3u8; 32];
    let member1 = "alice.near";
    let member2 = "bob.near";

    let encrypted_for_member1 = manager.encrypt_team_dek_for_member(&team_dek, &member1.to_string(), &member1_dek);
    let encrypted_for_member2 = manager.encrypt_team_dek_for_member(&team_dek, &member2.to_string(), &member2_dek);

    // 3. Store encrypted DEKs
    manager.store_encrypted_team_dek(team_id.to_string(), member1.to_string(), encrypted_for_member1);
    manager.store_encrypted_team_dek(team_id.to_string(), member2.to_string(), encrypted_for_member2);

    // 4. Verify member1 can decrypt with their own AAD
    let decrypted1 = manager.decrypt_team_dek_for_member(
        manager.get_encrypted_team_dek(team_id, &member1.to_string()).unwrap(),
        &member1_dek,
        member1,
    );
    assert_eq!(decrypted1.unwrap(), *team_dek);

    // 5. Verify member2 can decrypt with their own AAD
    let decrypted2 = manager.decrypt_team_dek_for_member(
        manager.get_encrypted_team_dek(team_id, &member2.to_string()).unwrap(),
        &member2_dek,
        member2,
    );
    assert_eq!(decrypted2.unwrap(), *team_dek);

    // 6. Verify cross-decryption fails: member2_dek + member1's AAD → should fail
    let cross_decrypt = manager.decrypt_team_dek_for_member(
        manager.get_encrypted_team_dek(team_id, &member1.to_string()).unwrap(),
        &member2_dek,
        member1, // member1's AAD but member2's key — should fail
    );
    assert!(cross_decrypt.is_none());

    // Also verify: member2_dek with wrong AAD (member2) on member1's ciphertext
    let cross_decrypt2 = manager.decrypt_team_dek_for_member(
        manager.get_encrypted_team_dek(team_id, &member1.to_string()).unwrap(),
        &member2_dek,
        member2, // wrong AAD too
    );
    assert!(cross_decrypt2.is_none());

    // 7. Remove member1
    manager.delete_encrypted_team_dek(team_id, &member1.to_string());
    assert!(manager.get_encrypted_team_dek(team_id, &member1.to_string()).is_none());

    // 8. Verify member2 still has access
    assert!(manager.get_encrypted_team_dek(team_id, &member2.to_string()).is_some());

    // 9. AUDIT-I1: Verify DEK is still derivable after "restart" (fresh manager, same master)
    let mut fresh_manager = TeamKeyManager::new();
    let team_dek_after_restart = fresh_manager
        .get_or_generate_team_dek(&platform_master, team_id)
        .expect("DEK must be re-derivable after restart");
    assert_eq!(
        *team_dek, *team_dek_after_restart,
        "Team DEK must survive a simulated restart"
    );
}