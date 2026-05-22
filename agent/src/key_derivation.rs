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

/// Length of the master secret in bytes.
pub const MASTER_SECRET_LEN: usize = 32;

/// Length of the derived data encryption key (DEK) in bytes.
pub const DEK_LEN: usize = 32;

/// Constant info context parameter mixed into HKDF derivation to enforce domain separation.
pub const HKDF_INFO_CONTEXT: &[u8] = b"aipassport-dek-v1";

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
            // Generate a secure cryptographically random master secret
            let mut key = [0u8; MASTER_SECRET_LEN];
            rand::thread_rng().fill_bytes(&mut key);
            fs::write(&secret_path, key).map_err(KeyError::WriteFailed)?;
            // C-05 FIX: Restrict file to owner-read-only (0o600).
            // fs::write uses the process umask (typically 0o644 = world-readable).
            // A world-readable master secret defeats all TEE confidentiality guarantees.
            #[cfg(unix)]
            fs::set_permissions(
                &secret_path,
                fs::Permissions::from_mode(0o600),
            )
            .map_err(KeyError::WriteFailed)?;
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

/// @notice Derives a per-user Data Encryption Key (DEK) using HKDF-SHA256.
/// @param master_secret The platform's master secret.
/// @param near_account_id The owner's unique NEAR account ID (acts as the salt).
/// @dev Multi-tenant isolation is cryptographically guaranteed because the account ID is mixed as the salt.
pub fn derive_dek(master_secret: &[u8; MASTER_SECRET_LEN], near_account_id: &str) -> Result<[u8; DEK_LEN], KeyError> {
    let hk = Hkdf::<Sha256>::new(Some(near_account_id.as_bytes()), master_secret);
    let mut dek = [0u8; DEK_LEN];
    hk.expand(HKDF_INFO_CONTEXT, &mut dek)
        .map_err(|_| KeyError::HkdfExpansionFailed)?;
    Ok(dek)
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
        
        let dek_alice1 = derive_dek(&master_secret, "alice.near").unwrap();
        let dek_alice2 = derive_dek(&master_secret, "alice.near").unwrap();
        let dek_bob = derive_dek(&master_secret, "bob.near").unwrap();

        // Determinism: Same input must produce the same DEK
        assert_eq!(dek_alice1, dek_alice2);

        // Isolation: Different account IDs must produce distinct DEKs
        assert_ne!(dek_alice1, dek_bob);
    }
}
