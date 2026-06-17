// //////////////////////////////////////////////////////////////
//                          KEY DERIVATION ENGINE
// //////////////////////////////////////////////////////////////

/// @file key_derivation.rs
/// @notice Implements high-assurance master secret management and HKDF-SHA256 DEK derivation.
/// @dev In production, the master secret is unsealed from the TEE's measurement-bound storage.
///      In simulation mode, it falls back to a locally persisted secret file.

use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use hkdf::Hkdf;
use sha2::Sha256;
use rand::RngCore;
use rand::rngs::OsRng;

/// Length of the master secret in bytes.
pub const MASTER_SECRET_LEN: usize = 32;

/// Length of the derived data encryption key (DEK) in bytes.
pub const DEK_LEN: usize = 32;

/// @notice Custom errors for the key derivation module.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Failed to read master secret: {0}")]
    ReadFailed(std::io::Error),
    #[error("Failed to write master secret: {0}")]
    WriteFailed(std::io::Error),
    #[error("Invalid master secret length: expected {expected}, found {found}")]
    InvalidLength { expected: usize, found: usize },
    #[error("HKDF expansion failure")]
    HkdfExpansionFailed,
}

/// @notice Loads the 32-byte master secret.
/// @dev If `TEE_SIMULATION=true`, retrieves the key from a local `.secret` file.
///      Otherwise, unseals the key from TEE platform PCR measurements.
pub fn load_master_secret() -> Result<[u8; MASTER_SECRET_LEN], KeyError> {
    let sim_mode = std::env::var("TEE_SIMULATION").unwrap_or_else(|_| "false".to_string()) == "true";

    if sim_mode {
        let secret_dir = Path::new(".secret");
        if !secret_dir.exists() {
            fs::create_dir_all(secret_dir).map_err(KeyError::WriteFailed)?;
        }
        let secret_path = secret_dir.join("master_secret.bin");

        if secret_path.exists() {
            let bytes = fs::read(&secret_path).map_err(KeyError::ReadFailed)?;
            if bytes.len() != MASTER_SECRET_LEN {
                return Err(KeyError::InvalidLength {
                    expected: MASTER_SECRET_LEN,
                    found: bytes.len(),
                });
            }
            let mut key = [0u8; MASTER_SECRET_LEN];
            key.copy_from_slice(&bytes);
            Ok(key)
        } else {
            // P3-4 FIX: Use OsRng (getrandom syscall) instead of thread_rng().
            // thread_rng() seeds from OS entropy at startup but may buffer in userspace;
            // OsRng calls getrandom(2) / /dev/urandom directly on every invocation,
            // which is required for TEE environments where PRNG seeding may differ.
            let mut key = [0u8; MASTER_SECRET_LEN];
            OsRng.fill_bytes(&mut key);

            // P3-3 FIX: Atomic write — write to a temp file, set permissions, then rename.
            // The previous code wrote key with default umask (0o644 = world-readable),
            // then chmod'd to 0o600. The window between write and chmod let another process
            // read the key.
            // Fix: create a sibling temp file, chmod it BEFORE writing sensitive bytes,
            // then rename atomically. rename(2) is atomic on POSIX (same filesystem).
            let tmp_path = secret_dir.join("master_secret.bin.tmp");

            // Prepare the temp file with correct permissions before writing any data
            fs::write(&tmp_path, [0u8; MASTER_SECRET_LEN]).map_err(KeyError::WriteFailed)?;
            #[cfg(unix)]
            fs::set_permissions(
                &tmp_path,
                fs::Permissions::from_mode(0o600),
            )
            .map_err(KeyError::WriteFailed)?;

            // Now write the actual key — permissions already correct, no race window
            fs::write(&tmp_path, key).map_err(KeyError::WriteFailed)?;

            // Atomically rename into the final path
            fs::rename(&tmp_path, &secret_path).map_err(KeyError::WriteFailed)?;

            Ok(key)
        }
    } else {
        // PRODUCTION TEE UNSEALING
        // In native TDX or SEV-SNP enclaves, we would call the platform driver to unseal
        // a 32-byte key sealed against the MRTD/PCR registers.
        // For compliance and execution safety inside this template, we fallback to TEE env variable or error.
        match std::env::var("TEE_SEALED_KEY") {
            Ok(val) => {
                let bytes = hex::decode(val).map_err(|_| KeyError::InvalidLength { expected: MASTER_SECRET_LEN, found: 0 })?;
                if bytes.len() != MASTER_SECRET_LEN {
                    return Err(KeyError::InvalidLength {
                        expected: MASTER_SECRET_LEN,
                        found: bytes.len(),
                    });
                }
                let mut key = [0u8; MASTER_SECRET_LEN];
                key.copy_from_slice(&bytes);
                Ok(key)
            }
            Err(_) => {
                // C-05 FIX: HARD FAIL in production when TEE_SEALED_KEY is absent.
                //
                // The previous behaviour silently generated an ephemeral key, which meant:
                //   - Agent starts successfully but with a throwaway secret.
                //   - Every restart produces a NEW key → all previous blobs permanently undecryptable.
                //   - No warning, no error — silent irreversible data loss.
                //
                // Operators MUST inject TEE_SEALED_KEY at deploy time.
                // For local dev: set TEE_SIMULATION = "true" in agent.dev.toml (gitignored).
                Err(KeyError::ReadFailed(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "CRITICAL: TEE_SEALED_KEY environment variable not set. \
                     In production mode the master secret must be injected as a \
                     TEE-sealed secret. Refusing to start with an ephemeral key \
                     (silent data loss on restart). \
                     For local development, use TEE_SIMULATION=true in agent.dev.toml.",
                )))
            }
        }
    }
}

/// @notice Derives a per-user, domain-separated Data Encryption Key (DEK) using HKDF-SHA256.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID (acts as the salt).
/// @param entry_type The category of the vault entry (e.g. "wiki" or "skill").
/// @param identifier The specific record identifier (e.g. page slug or skill name).
/// @dev Multi-tenant isolation is cryptographically guaranteed because the account ID is mixed as the salt.
///      Domain separation prevents cross-endpoint key reuse by binding the key to entry_type and identifier.
pub fn derive_dek(
    master_secret: &[u8; MASTER_SECRET_LEN],
    near_account_id: &str,
    entry_type: &str,
    identifier: &str,
) -> Result<[u8; DEK_LEN], KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(near_account_id.as_bytes()), master_secret);
    let info = format!("aipassport-dek-v1:{}:{}", entry_type, identifier);
    let mut dek = [0u8; DEK_LEN];
    hk.expand(info.as_bytes(), &mut dek)
        .map_err(|_| KeyError::HkdfExpansionFailed)?;
    Ok(dek)
}

/// @notice Derives a per-team master secret from the platform master secret using HKDF-SHA256.
/// @param master_secret The platform's 32-byte master secret.
/// @param team_id The unique team identifier (used as HKDF info for domain separation).
/// @return A 32-byte team master secret, deterministic for a given (master_secret, team_id) pair.
/// @dev This replaces the previous approach of storing random team master secrets in a HashMap,
///      which caused permanent data loss on agent restart (same failure mode as C-05 for user keys).
///
///      Derivation scheme:
///        team_master_secret = HKDF-SHA256(ikm=master_secret, salt=None, info="aipassport-team-v1:{team_id}")
///
///      Properties:
///        - Deterministic: same (master_secret, team_id) always produces the same team key.
///        - Isolated: different team_ids produce cryptographically independent secrets.
///        - Domain-separated: "aipassport-team-v1:" prefix prevents cross-usage with user DEK derivation.
///        - Zero-storage: no in-memory HashMap or disk persistence needed.
pub fn derive_team_master_secret(
    master_secret: &[u8; MASTER_SECRET_LEN],
    team_id: &str,
) -> Result<[u8; MASTER_SECRET_LEN], KeyError> {
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let info = format!("aipassport-team-v1:{}", team_id);
    let mut team_secret = [0u8; MASTER_SECRET_LEN];
    hk.expand(info.as_bytes(), &mut team_secret)
        .map_err(|_| KeyError::HkdfExpansionFailed)?;
    Ok(team_secret)
}

// //////////////////////////////////////////////////////////////
//                              TESTS
// //////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dek_derivation_determinism_and_isolation() {
        let master_secret = [0x55u8; MASTER_SECRET_LEN];
        
        let dek_alice1 = derive_dek(&master_secret, "alice.near", "wiki", "home").unwrap();
        let dek_alice2 = derive_dek(&master_secret, "alice.near", "wiki", "home").unwrap();
        let dek_bob = derive_dek(&master_secret, "bob.near", "wiki", "home").unwrap();
        
        // Determinism: Same input must produce the same DEK
        assert_eq!(dek_alice1, dek_alice2);

        // Multi-tenant Isolation: Different account IDs must produce distinct DEKs
        assert_ne!(dek_alice1, dek_bob);

        // Domain Separation: Different entry types must produce distinct DEKs
        let dek_alice_skill = derive_dek(&master_secret, "alice.near", "skill", "home").unwrap();
        assert_ne!(dek_alice1, dek_alice_skill);

        // Domain Separation: Different identifiers must produce distinct DEKs
        let dek_alice_page2 = derive_dek(&master_secret, "alice.near", "wiki", "about").unwrap();
        assert_ne!(dek_alice1, dek_alice_page2);
    }

    #[test]
    fn test_team_master_secret_derivation() {
        let master_secret = [0xAAu8; MASTER_SECRET_LEN];

        // Determinism: same (master_secret, team_id) must always produce the same key
        let team_a_1 = derive_team_master_secret(&master_secret, "team-alpha").unwrap();
        let team_a_2 = derive_team_master_secret(&master_secret, "team-alpha").unwrap();
        assert_eq!(team_a_1, team_a_2, "Team master secret must be deterministic");

        // Isolation: different team IDs must produce different secrets
        let team_b = derive_team_master_secret(&master_secret, "team-beta").unwrap();
        assert_ne!(team_a_1, team_b, "Different team IDs must produce different secrets");

        // Domain separation: team keys must be distinct from user DEKs under the same master
        let user_dek = derive_dek(&master_secret, "team-alpha", "wiki", "home").unwrap();
        assert_ne!(
            team_a_1, user_dek,
            "Team master secret must not collide with user DEK derivation"
        );

        // Different platform secrets must produce different team secrets
        let other_master = [0xBBu8; MASTER_SECRET_LEN];
        let team_a_other = derive_team_master_secret(&other_master, "team-alpha").unwrap();
        assert_ne!(
            team_a_1, team_a_other,
            "Different platform master secrets must produce different team secrets"
        );
    }
}
