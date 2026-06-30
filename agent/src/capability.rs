//! @file capability.rs
//! @notice Gateway-issued capability-token verification (defense-in-depth auth binding).
//!
//! ## Why this exists
//! The agent's Bearer token (`IRONCLAW_AGENT_API_KEY`) authenticates the *caller*
//! (the gateway) but says nothing about the *subject* of the request. Before this
//! module, the `nearAccountId` in a request body was **self-asserted**: anyone
//! holding the shared Bearer token — a leaked secret, or any path that can reach
//! the agent directly — could read or write ANY account's vault simply by setting
//! that field, because the TEE derives the per-user DEK from `nearAccountId`
//! (see `key_derivation::derive_dek`, which mixes the account ID as the HKDF salt).
//!
//! ## What this fixes
//! The gateway now signs a short-lived Ed25519 "capability token" that binds the
//! authenticated NEAR account (`sub`). The agent verifies that signature against a
//! configured gateway public key (`AEGIS_GATEWAY_CAP_PUBKEY`) and the protected
//! handlers enforce `sub == nearAccountId`. A leaked Bearer token alone no longer
//! suffices to spoof an account: an attacker would also need the gateway's Ed25519
//! signing key, which never leaves the gateway Worker secret store.
//!
//! This is the minimal, TEE-offline (no NEAR RPC egress, no ZDR-firewall change)
//! auth-binding fix. It is also the exact seam at which a zero-knowledge credential
//! proof can later replace the signed token: swap `CapabilityVerifier::verify` for a
//! proof verifier and the rest of the agent is unchanged.
//!
//! ## Token format (compact, JWS-like, but minimal)
//! ```text
//!   token        = base64url(payload_json) "." base64url(ed25519_sig)
//!   signed bytes = the ASCII bytes of the first segment, base64url(payload_json)
//!   payload_json = {"sub","team","perm","iat","exp","jti"}   // iat/exp in epoch ms
//! ```
//! Signing over the already-encoded first segment (rather than re-serialising the
//! JSON) avoids any canonicalisation ambiguity between signer and verifier.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// Hard cap on accepted token length — bounds work before any crypto/parse.
const MAX_TOKEN_BYTES: usize = 4096;

/// Clock-skew tolerance between the gateway (signer) and the agent (verifier).
const DEFAULT_LEEWAY_MS: u64 = 5_000;

/// Environment variable holding the gateway's Ed25519 public key (hex, 32 bytes).
/// When unset, capability binding is DISABLED (legacy bearer-only behaviour) and a
/// prominent warning is emitted at startup.
pub const PUBKEY_ENV: &str = "AEGIS_GATEWAY_CAP_PUBKEY";

/// Verified claims carried by a capability token. `Clone` so it can be stored in
/// request extensions and read by handlers via `Extension<CapabilityClaims>`.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityClaims {
    /// Subject: the authenticated NEAR account this request is permitted to act as.
    pub sub: String,
    /// Optional team context (reserved for future per-team enforcement).
    #[serde(default)]
    pub team: Option<String>,
    /// Optional access tier / permission hint (reserved; not yet load-bearing).
    #[serde(default)]
    pub perm: Option<String>,
    /// Issued-at, epoch milliseconds.
    pub iat: u64,
    /// Expiry, epoch milliseconds.
    pub exp: u64,
    /// Unique token id (nonce). Carried for auditability; replay defence is
    /// primarily provided by the short `exp` window.
    #[serde(default)]
    pub jti: String,
}

/// Why a capability token was rejected. Mapped to a stable error code for clients.
#[derive(Debug, PartialEq, Eq)]
pub enum CapabilityError {
    /// No token supplied while binding is enabled.
    Missing,
    /// Structurally invalid (segments, base64, JSON, or field shape).
    Malformed,
    /// Signature did not verify under the configured gateway key.
    BadSignature,
    /// `exp` is in the past (beyond leeway).
    Expired,
    /// `iat` is in the future (beyond leeway) — likely a clock or forgery issue.
    NotYetValid,
}

impl CapabilityError {
    /// Stable, machine-readable error code surfaced to adapters.
    pub fn code(&self) -> &'static str {
        match self {
            CapabilityError::Missing => "AGENT_ERROR_CAPABILITY_MISSING",
            CapabilityError::Malformed => "AGENT_ERROR_CAPABILITY_MALFORMED",
            CapabilityError::BadSignature => "AGENT_ERROR_CAPABILITY_BAD_SIGNATURE",
            CapabilityError::Expired => "AGENT_ERROR_CAPABILITY_EXPIRED",
            CapabilityError::NotYetValid => "AGENT_ERROR_CAPABILITY_NOT_YET_VALID",
        }
    }
}

/// Verifies gateway-signed capability tokens against a fixed Ed25519 public key.
#[derive(Clone)]
pub struct CapabilityVerifier {
    verifying_key: VerifyingKey,
    leeway_ms: u64,
}

impl CapabilityVerifier {
    /// Construct a verifier from a raw 32-byte Ed25519 public key.
    pub fn new(verifying_key: VerifyingKey, leeway_ms: u64) -> Self {
        Self { verifying_key, leeway_ms }
    }

    /// Build a verifier from the `AEGIS_GATEWAY_CAP_PUBKEY` env var (hex, 32 bytes).
    ///
    /// Returns `None` when the variable is unset/empty (binding disabled) or `None`
    /// when the value is present but malformed — the caller logs the distinction.
    /// To make a malformed-but-present key fail loudly rather than silently disable
    /// security, callers should treat a present-but-unparseable value as fatal; see
    /// `from_env_checked`.
    pub fn from_env() -> Option<Self> {
        Self::from_env_checked().ok().flatten()
    }

    /// Like `from_env`, but distinguishes "unset" (`Ok(None)`, binding disabled)
    /// from "set but invalid" (`Err`, a misconfiguration that must fail hard).
    pub fn from_env_checked() -> Result<Option<Self>, String> {
        let raw = match std::env::var(PUBKEY_ENV) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let bytes = hex::decode(trimmed)
            .map_err(|_| format!("{PUBKEY_ENV} is not valid hex"))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("{PUBKEY_ENV} must decode to exactly 32 bytes"))?;
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|_| format!("{PUBKEY_ENV} is not a valid Ed25519 public key"))?;
        Ok(Some(Self::new(vk, DEFAULT_LEEWAY_MS)))
    }

    /// Verify a token string at the given wall-clock time (epoch ms) and return its
    /// claims. Performs, in order: length bound, segment split, signature check over
    /// the encoded payload, payload decode/parse, then temporal validity.
    pub fn verify(&self, token: &str, now_ms: u64) -> Result<CapabilityClaims, CapabilityError> {
        if token.is_empty() {
            return Err(CapabilityError::Missing);
        }
        if token.len() > MAX_TOKEN_BYTES {
            return Err(CapabilityError::Malformed);
        }

        let mut parts = token.split('.');
        let payload_b64 = parts.next().ok_or(CapabilityError::Malformed)?;
        let sig_b64 = parts.next().ok_or(CapabilityError::Malformed)?;
        if parts.next().is_some() || payload_b64.is_empty() || sig_b64.is_empty() {
            return Err(CapabilityError::Malformed);
        }

        // Decode and check the signature BEFORE trusting any payload bytes.
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| CapabilityError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CapabilityError::Malformed)?;
        let signature = Signature::from_bytes(&sig_arr);
        // verify_strict rejects non-canonical / small-order public keys and
        // malleable signatures — stronger than the basic Verifier::verify.
        self.verifying_key
            .verify_strict(payload_b64.as_bytes(), &signature)
            .map_err(|_| CapabilityError::BadSignature)?;

        // Signature is valid; now the payload bytes can be trusted to parse.
        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| CapabilityError::Malformed)?;
        let claims: CapabilityClaims =
            serde_json::from_slice(&payload_json).map_err(|_| CapabilityError::Malformed)?;

        if now_ms > claims.exp.saturating_add(self.leeway_ms) {
            return Err(CapabilityError::Expired);
        }
        if claims.iat > now_ms.saturating_add(self.leeway_ms) {
            return Err(CapabilityError::NotYetValid);
        }

        Ok(claims)
    }
}

/// Current wall-clock time in epoch milliseconds. Saturates to 0 on the
/// (practically impossible) pre-epoch clock, never panics.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic signing key for tests (fixed 32-byte seed).
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Mint a token exactly as the gateway does: sign over base64url(payload).
    fn mint(signing: &SigningKey, sub: &str, iat: u64, exp: u64) -> String {
        let payload = format!(
            r#"{{"sub":"{sub}","team":null,"perm":null,"iat":{iat},"exp":{exp},"jti":"test-nonce"}}"#
        );
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let sig = signing.sign(payload_b64.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{payload_b64}.{sig_b64}")
    }

    fn verifier_for(signing: &SigningKey) -> CapabilityVerifier {
        CapabilityVerifier::new(signing.verifying_key(), DEFAULT_LEEWAY_MS)
    }

    #[test]
    fn accepts_valid_token_and_extracts_subject() {
        let sk = test_signing_key();
        let v = verifier_for(&sk);
        let now = 1_000_000;
        let token = mint(&sk, "alice.near", now, now + 120_000);
        let claims = v.verify(&token, now).expect("valid token");
        assert_eq!(claims.sub, "alice.near");
        assert_eq!(claims.jti, "test-nonce");
    }

    #[test]
    fn rejects_expired_token() {
        let sk = test_signing_key();
        let v = verifier_for(&sk);
        let iat = 1_000_000;
        let exp = iat + 100;
        let token = mint(&sk, "alice.near", iat, exp);
        // now well past exp + leeway
        let err = v.verify(&token, exp + DEFAULT_LEEWAY_MS + 1).unwrap_err();
        assert_eq!(err, CapabilityError::Expired);
    }

    #[test]
    fn rejects_future_iat() {
        let sk = test_signing_key();
        let v = verifier_for(&sk);
        let now = 1_000_000;
        let iat = now + DEFAULT_LEEWAY_MS + 10_000;
        let token = mint(&sk, "alice.near", iat, iat + 120_000);
        let err = v.verify(&token, now).unwrap_err();
        assert_eq!(err, CapabilityError::NotYetValid);
    }

    #[test]
    fn rejects_signature_from_wrong_key() {
        let signer = test_signing_key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        // Verifier trusts `signer`, but token is signed by `attacker`.
        let v = verifier_for(&signer);
        let now = 1_000_000;
        let token = mint(&attacker, "alice.near", now, now + 120_000);
        let err = v.verify(&token, now).unwrap_err();
        assert_eq!(err, CapabilityError::BadSignature);
    }

    #[test]
    fn rejects_tampered_payload() {
        let sk = test_signing_key();
        let v = verifier_for(&sk);
        let now = 1_000_000;
        let token = mint(&sk, "alice.near", now, now + 120_000);
        // Forge: replace the payload segment with a different subject, keep the sig.
        let forged_payload = URL_SAFE_NO_PAD.encode(
            format!(
                r#"{{"sub":"bob.near","team":null,"perm":null,"iat":{now},"exp":{},"jti":"x"}}"#,
                now + 120_000
            )
            .as_bytes(),
        );
        let sig_seg = token.split('.').nth(1).unwrap();
        let forged = format!("{forged_payload}.{sig_seg}");
        let err = v.verify(&forged, now).unwrap_err();
        assert_eq!(err, CapabilityError::BadSignature);
    }

    #[test]
    fn rejects_malformed_tokens() {
        let sk = test_signing_key();
        let v = verifier_for(&sk);
        let now = 1_000_000;
        assert_eq!(v.verify("", now).unwrap_err(), CapabilityError::Missing);
        assert_eq!(v.verify("only-one-segment", now).unwrap_err(), CapabilityError::Malformed);
        assert_eq!(v.verify("a.b.c", now).unwrap_err(), CapabilityError::Malformed);
        assert_eq!(v.verify("!!!.@@@", now).unwrap_err(), CapabilityError::Malformed);
    }
}
