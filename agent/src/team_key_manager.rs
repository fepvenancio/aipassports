// ///////////////////////////////////////////////////////////////
//                          TEAM KEY MANAGER
// ///////////////////////////////////////////////////////////////

/// @file team_key_manager.rs
/// @notice Manages team encryption keys and member access.
/// @dev Team master secrets are derived deterministically from the platform master secret
///      using HKDF-SHA256 — they are NEVER stored in-memory or on-disk.
///
/// Security hardening applied (audit cycle 2026-06-17):
///   AUDIT-I1-A — Removed `team_master_secrets: HashMap<String, [u8; 32]>`.
///                Previously, random team master secrets were stored in a HashMap in AppState.
///                This caused two critical issues:
///                  1. DATA LOSS: HashMap cleared on every agent restart →
///                     all team vault blobs permanently undecryptable after restart.
///                  2. SECRET LEAKAGE: Raw 32-byte secrets in heap memory, never scrubbed,
///                     exposed to core dumps and /proc/mem reads.
///                Fix: derive team master secrets on-demand from the platform master secret
///                via derive_team_master_secret() — deterministic, zero-storage, restart-safe.
///
///   AUDIT-I1-B — DEK cache values are now `Zeroizing<Vec<u8>>` instead of `Vec<u8>`,
///                ensuring cached DEKs are scrubbed from memory when the cache entry is dropped.

use std::collections::HashMap;
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;
use rand::RngCore;

use crate::key_derivation;

/// Type alias for NEAR AccountId (using String for simplicity in agent context)
type AccountId = String;

// ─────────────────────────────────────────────────────────────────────────────
//                          TEAM KEY MANAGER
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Manages team encryption keys and member access.
/// @dev The `team_dek_cache` is a performance optimisation only — its contents are never
///      the source of truth. Any cached DEK can be re-derived from the platform master
///      secret at any time via `derive_team_master_secret` + `generate_team_dek`.
#[derive(Debug, Default)]
pub struct TeamKeyManager {
    /// @notice Caches team_id → team DEK (32-byte key, memory-scrubbed on drop).
    /// @dev This is a performance cache only. The DEK is re-derived from the platform
    ///      master secret if not present. Do NOT treat absence as "team does not exist".
    team_dek_cache: HashMap<String, Zeroizing<Vec<u8>>>,

    /// @notice Maps team_id → member AccountId → encrypted team DEK.
    /// @dev Encrypted DEK format: [12-byte nonce][ciphertext].
    ///      This stores per-member access grants. An entry here means the member has
    ///      been granted access to the team vault.
    encrypted_team_dek_cache: HashMap<String, HashMap<AccountId, Vec<u8>>>,
}

impl TeamKeyManager {
    /// @notice Creates a new TeamKeyManager with empty caches.
    pub fn new() -> Self {
        Self {
            team_dek_cache: HashMap::new(),
            encrypted_team_dek_cache: HashMap::new(),
        }
    }

// ─────────────────────────────────────────────────────────────────────────────
//                       TEAM DEK GENERATION
// ─────────────────────────────────────────────────────────────────────────────

    /// @notice Generates a team DEK from the team master secret.
    /// @dev Uses HKDF-SHA256 with info = "team_dek:{team_id}".
    ///      The team master secret is itself derived from the platform master secret —
    ///      see `key_derivation::derive_team_master_secret`.
    /// @param team_id Unique team identifier.
    /// @param team_master_secret 32-byte team master secret (derived, not stored).
    /// @return 32-byte team DEK (memory-scrubbed via Zeroizing wrapper).
    pub fn generate_team_dek(&self, team_id: &str, team_master_secret: &[u8; 32]) -> Zeroizing<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let info = format!("team_dek:{}", team_id);
        let hk = Hkdf::<Sha256>::new(None, team_master_secret);

        let mut okm = vec![0u8; 32];
        hk.expand(info.as_bytes(), &mut okm)
            .expect("HKDF expansion should not fail for valid inputs");

        Zeroizing::new(okm)
    }

    /// @notice Gets or generates a team DEK, deriving it from the platform master secret.
    /// @dev AUDIT-I1-A FIX: This function now accepts the platform master secret directly
    ///      instead of looking it up from the (now-removed) `team_master_secrets` HashMap.
    ///      The team master secret is derived on-demand — no persistent state required.
    ///
    ///      Cache hit path  : O(1) HashMap lookup → return Zeroizing<Vec<u8>> clone.
    ///      Cache miss path : derive_team_master_secret() → generate_team_dek() → insert cache.
    ///
    /// @param platform_master The platform's 32-byte master secret (from AppState).
    /// @param team_id Unique team identifier.
    /// @return The 32-byte team DEK wrapped in Zeroizing.
    pub fn get_or_generate_team_dek(
        &mut self,
        platform_master: &[u8; 32],
        team_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, key_derivation::KeyError> {
        // Return cached DEK if available (performance fast path)
        if let Some(cached_dek) = self.team_dek_cache.get(team_id) {
            return Ok(Zeroizing::new(cached_dek.to_vec()));
        }

        // Derive team master secret on-demand — deterministic, no HashMap lookup needed
        let team_master = key_derivation::derive_team_master_secret(platform_master, team_id)?;

        // Generate team DEK from the derived team master secret
        let dek = self.generate_team_dek(team_id, &team_master);

        // Cache for subsequent calls in this process lifetime
        self.team_dek_cache.insert(team_id.to_string(), Zeroizing::new(dek.to_vec()));

        Ok(dek)
    }

    // ─────────────────────────────────────────────────────────────────────────
    //                MEMBER DEK ENCRYPTION / DECRYPTION
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Encrypts a team DEK for a specific member using their personal DEK.
    /// @dev Uses AES-256-GCM with a random 12-byte nonce and the member's NEAR account ID
    ///      bound as Additional Authenticated Data (AAD). The AAD commitment means any
    ///      substitution of this ciphertext under a different member's identity will fail
    ///      GCM tag verification — closing the cross-member ciphertext swap attack.
    ///
    ///      AUDIT-H2 FIX: `_member_account_id` is now fully bound as AAD.
    ///      Previous code left the parameter unused (prefixed with `_`), so the GCM tag
    ///      was computed only over the ciphertext. An attacker who controls the in-memory
    ///      cache could swap Alice's entry under Bob's slot and the tag would still pass.
    ///      With AAD = member_account_id.as_bytes(), the tag is bound to the identity.
    ///
    /// @param team_dek 32-byte team DEK to encrypt.
    /// @param member_account_id NEAR account ID of the member — bound as GCM AAD.
    /// @param member_dek 32-byte member personal DEK used as the encryption key.
    /// @return Encrypted team DEK: [12-byte nonce][ciphertext+tag].
    pub fn encrypt_team_dek_for_member(
        &self,
        team_dek: &[u8],
        member_account_id: &AccountId,
        member_dek: &[u8; 32],
    ) -> Vec<u8> {
        let cipher = Aes256Gcm::new(member_dek.into());
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // AUDIT-H2: Bind member identity as AAD so the GCM tag commits to this specific member.
        let ciphertext = cipher
            .encrypt(nonce, Payload {
                msg: team_dek,
                aad: member_account_id.as_bytes(),
            })
            .expect("AES-GCM encryption should not fail with valid inputs");

        // Return nonce + ciphertext+tag
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        result
    }

    /// @notice Decrypts a team DEK for a specific member using their personal DEK.
    /// @dev Extracts nonce from the first 12 bytes, decrypts the remainder.
    ///      The member_account_id MUST match the one used during encryption (AAD check).
    ///      Returns None on any decryption failure (wrong key, wrong AAD, corrupted data).
    ///
    ///      AUDIT-H2 FIX: Now requires `member_account_id` for AAD verification.
    ///      GCM authentication will reject any ciphertext that was encrypted for a
    ///      different member, even if the member_dek is correct.
    ///
    /// @param encrypted_team_dek Encrypted DEK: [12-byte nonce][ciphertext+tag].
    /// @param member_dek 32-byte member personal DEK used as the decryption key.
    /// @param member_account_id NEAR account ID — must match AAD used during encryption.
    /// @return Some(plaintext team DEK) on success, None on any failure.
    pub fn decrypt_team_dek_for_member(
        &self,
        encrypted_team_dek: &[u8],
        member_dek: &[u8; 32],
        member_account_id: &str,
    ) -> Option<Vec<u8>> {
        if encrypted_team_dek.len() < 12 {
            return None;
        }

        let nonce = Nonce::from_slice(&encrypted_team_dek[..12]);
        let ciphertext = &encrypted_team_dek[12..];

        let cipher = Aes256Gcm::new(member_dek.into());

        // AUDIT-H2: Verify AAD — if the ciphertext was encrypted for a different member,
        // GCM tag verification will fail here and return None.
        cipher.decrypt(nonce, Payload {
            msg: ciphertext,
            aad: member_account_id.as_bytes(),
        }).ok()
    }

    // ─────────────────────────────────────────────────────────────────────────
    //               ENCRYPTED TEAM DEK CACHE OPERATIONS
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Stores an encrypted team DEK for a member.
    /// @dev Used when granting member access to team resources.
    ///      The encrypted DEK format is [12-byte nonce][ciphertext] as produced by
    ///      `encrypt_team_dek_for_member`.
    /// @param team_id Unique team identifier.
    /// @param member_account_id NEAR account ID of the member.
    /// @param encrypted_team_dek Encrypted DEK to store.
    pub fn store_encrypted_team_dek(
        &mut self,
        team_id: String,
        member_account_id: AccountId,
        encrypted_team_dek: Vec<u8>,
    ) {
        self.encrypted_team_dek_cache
            .entry(team_id)
            .or_default()
            .insert(member_account_id, encrypted_team_dek);
    }

    /// @notice Retrieves an encrypted team DEK for a member.
    /// @dev Returns None if the team or member does not exist in the cache.
    ///      Absence does NOT imply the team doesn't exist — the team DEK can always
    ///      be re-derived from the platform master secret.
    /// @param team_id Unique team identifier.
    /// @param member_account_id NEAR account ID of the member.
    /// @return Optional reference to the encrypted team DEK bytes.
    pub fn get_encrypted_team_dek(
        &self,
        team_id: &str,
        member_account_id: &AccountId,
    ) -> Option<&Vec<u8>> {
        self.encrypted_team_dek_cache
            .get(team_id)
            .and_then(|members: &HashMap<AccountId, Vec<u8>>| members.get(member_account_id))
    }

    /// @notice Deletes an encrypted team DEK for a member.
    /// @dev Used when revoking member access to team resources.
    ///      Also cleans up the parent team entry if no members remain.
    /// @param team_id Unique team identifier.
    /// @param member_account_id NEAR account ID of the member.
    pub fn delete_encrypted_team_dek(&mut self, team_id: &str, member_account_id: &AccountId) {
        if let Some(members) = self.encrypted_team_dek_cache.get_mut(team_id) {
            members.remove(member_account_id);

            // Clean up empty team entries to avoid unbounded map growth
            if members.is_empty() {
                self.encrypted_team_dek_cache.remove(team_id);
            }
        }
    }
}

// ///////////////////////////////////////////////////////////////
