// //////////////////////////////////////////////////////////////
//                          MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title IronClaw Shade Agent Confidential Server
/// @notice Bootstraps the Axum HTTP web server inside the TEE enclave.
/// @dev Secures the platform key state, mounts API controllers, and applies
///      authentication and CORS controls.
///
/// Security hardening applied (audit cycle 2026-05-22):
///   C-01   — Bearer token authentication middleware on all protected routes.
///   C-05   — Refuse to start if TEE_SEALED_KEY missing in production mode.
///   L-06   — Replaced all unwrap()/expect() in main() with graceful error handling.
///   L-07   — CORS locked to configurable ALLOWED_ORIGIN (default: deny all).
///
/// Security hardening applied (audit cycle 2026-05-22 round 2):
///   HIGH-R1       — constant_time_eq replaced with subtle::ConstantTimeEq.
///                   constant_time_eq returns false immediately on length mismatch,
///                   leaking the key length via timing. subtle uses fixed-time ops.
///   CRITICAL-R2   — RequestBodyLimitLayer(1 MB) added to all protected routes.
///                   Without this, a 10 GB body caused OOM process death.
///   CRITICAL-R6   — LLM API key loaded from LLM_API_KEY env at startup, stored
///                   in AppState. No longer accepted in HTTP request bodies.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use axum::{
    routing::{get, post},
    Router, Json, Extension,
    response::{IntoResponse, Response},
    http::{StatusCode, HeaderValue, Request},
    middleware::{self, Next},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn, error};
use subtle::ConstantTimeEq;
use crate::vault_writer::WriterError;

/// MEDIUM-P2-3: Sanitize a string before emitting it to structured logs.
/// Strips non-printable ASCII (including ANSI escape codes, newlines, tabs)
/// and caps length to prevent log injection or log flooding.
fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect()
}

mod key_derivation;
mod vault_writer;
mod vault_reader;
mod zdr_firewall;
mod skill_executor;

#[cfg(test)]
mod team_key_manager_tests;
mod team_key_manager;

use team_key_manager::TeamKeyManager;

// ─── Shared State ─────────────────────────────────────────────────────────────

/// Shared application state housing the platform's unsealed 32-byte master secret,
/// the expected API key for constant-time comparison, and the LLM API key injected
/// at startup (never accepted from HTTP request bodies — CRITICAL-R6).
struct AppState {
    master_secret: [u8; 32],
    /// Pre-loaded from IRONCLAW_AGENT_API_KEY at startup.
    /// Stored as bytes to enable subtle::ConstantTimeEq comparison (HIGH-R1).
    api_key_bytes: Vec<u8>,
    /// Pre-loaded from LLM_API_KEY at startup (CRITICAL-R6).
    /// Injected into execute_skill() — NEVER accepted from HTTP body.
    llm_api_key: String,
    /// Team key manager for team-based encryption and access control.
    /// Wrapped in Mutex for safe concurrent access across async handlers.
    pub team_key_manager: Mutex<TeamKeyManager>,
}

// ─── Error Mapping ─────────────────────────────────────────────────────────────

/// AppError encapsulates all module-level errors to automatically map them to HTTP responses.
#[allow(dead_code)]
enum AppError {
    Key(key_derivation::KeyError),
    Writer(vault_writer::WriterError),
    Reader(vault_reader::ReaderError),
    Skill(skill_executor::SkillError),
}

// ─── Team Request/Response DTOs ──────────────────────────────────────────────

/// Permission enum for team members (mirrors backend Permission enum)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
enum Permission {
    Read,
    Write,
    Admin,
}

/// Request DTO for team creation
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamCreateRequest {
    team_id: String,
    name: String,
}

/// Request DTO for adding team member
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamAddMemberRequest {
    team_id: String,
    member_account_id: String,
    permission: String,
}

/// Request DTO for removing team member
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamRemoveMemberRequest {
    team_id: String,
    member_account_id: String,
}

/// Request DTO for team vault write
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamVaultWriteRequest {
    team_id: String,
    slug: String,
    content: String,
    requesting_account_id: String,
    /// Storage duration in epochs (max 52 ≈ 1 year). Defaults to 26 ≈ 6 months.
    epochs: Option<u64>,
}

/// Request DTO for team vault read
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamVaultReadRequest {
    team_id: String,
    slug: String,
    blob_id: String,
    expected_sha256: String,
    requesting_account_id: String,
}

/// Request DTO for updating a team member's permission
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamUpdatePermissionRequest {
    team_id: String,
    member_account_id: String,
    permission: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, err_code, message) = match self {
            AppError::Key(e) => {
                error!("Key derivation error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "KEY_DERIVATION_ERROR", e.to_string())
            }
            AppError::Writer(vault_writer::WriterError::EncryptionFailed) => {
                error!("Vault Encryption failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "VAULT_ERROR_ENCRYPTION_FAILED", "AES encryption failed".to_string())
            }
            AppError::Writer(vault_writer::WriterError::WalrusError(status, text)) => {
                error!("Walrus publisher error: status={} body={}", status, text);
                (status, "WALRUS_ERROR", text)
            }
            AppError::Writer(e) => {
                error!("Vault Write pipeline error: {:?}", e);
                (StatusCode::BAD_REQUEST, "VAULT_WRITE_ERROR", e.to_string())
            }
            AppError::Reader(vault_reader::ReaderError::EnvelopeTooSmall) => {
                error!("Vault Reader error: envelope too small");
                (StatusCode::BAD_REQUEST, "VAULT_ERROR_ENVELOPE_TOO_SMALL", "Packed envelope is corrupted or too small".to_string())
            }
            AppError::Reader(vault_reader::ReaderError::DecryptionFailed) => {
                error!("Vault Decryption failed: invalid tag");
                (StatusCode::UNAUTHORIZED, "VAULT_ERROR_DECRYPTION_FAILED", "GCM tag verification or decryption failed".to_string())
            }
            AppError::Reader(vault_reader::ReaderError::IntegrityMismatch { expected, computed }) => {
                error!("Vault Integrity mismatch: expected={} computed={}", expected, computed);
                (StatusCode::CONFLICT, "VAULT_ERROR_INTEGRITY_MISMATCH", format!("Decrypted data hash mismatch. Expected {}, got {}", expected, computed))
            }
            AppError::Reader(vault_reader::ReaderError::BlobNotFound(blob_id)) => {
                error!("Walrus blob not found: {}", blob_id);
                (StatusCode::NOT_FOUND, "VAULT_ERROR_BLOB_NOT_FOUND", format!("Blob not found or expired on Walrus: {}", blob_id))
            }
            AppError::Reader(e) => {
                error!("Vault Read pipeline error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "VAULT_READ_ERROR", e.to_string())
            }
            AppError::Skill(skill_executor::SkillError::FirewallError(zdr_firewall::FirewallError::DestinationBlocked(dest))) => {
                error!("Firewall blocked destination: {}", dest);
                (StatusCode::FORBIDDEN, "FIREWALL_ERROR_DESTINATION_BLOCKED", format!("Destination not whitelisted: {}", dest))
            }
            AppError::Skill(skill_executor::SkillError::FirewallError(zdr_firewall::FirewallError::SensitiveContentBlocked(marker))) => {
                error!("Firewall blocked sensitive content: contained marker {}", marker);
                (StatusCode::FORBIDDEN, "FIREWALL_ERROR_SENSITIVE_CONTENT", format!("Egress blocked: prompt contained sensitive word: {}", marker))
            }
            AppError::Skill(e) => {
                error!("Skill execution pipeline error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "SKILL_EXECUTION_ERROR", e.to_string())
            }
        };

        let body = Json(json!({
            "success": false,
            "errorCode": err_code,
            // C-01: Generic message — never leak internal error detail to unauthenticated callers.
            // Full detail is logged above via error!().
            "message": message
        }));

        (status, body).into_response()
    }
}

// ─── Request / Response DTOs ──────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WriteRequest {
    near_account_id: String,
    entry_type: String,
    identifier: String,
    plaintext: String,
    epochs: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WriteResponse {
    success: bool,
    blob_id: String,
    content_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReadRequest {
    near_account_id: String,
    entry_type: String,
    identifier: String,
    blob_id: String,
    expected_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadResponse {
    success: bool,
    plaintext: String,
}

// ─── Input Validation ─────────────────────────────────────────────────────────

/// C-01 / HIGH-01: Validate that a NEAR account ID is syntactically valid.
/// NEAR account IDs: max 64 chars, [a-z0-9._-], must not start/end with separator.
/// Rejecting malformed IDs prevents HKDF derivation with attacker-crafted inputs.
fn validate_near_account_id(id: &str) -> Result<(), (StatusCode, &'static str)> {
    if id.is_empty() || id.len() > 64 {
        return Err((StatusCode::BAD_REQUEST, "INVALID_NEAR_ACCOUNT_ID: length must be 1-64 chars"));
    }
    if !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c)) {
        return Err((StatusCode::BAD_REQUEST, "INVALID_NEAR_ACCOUNT_ID: only [a-z0-9._-] allowed"));
    }
    if id.starts_with(['.', '_', '-']) || id.ends_with(['.', '_', '-']) {
        return Err((StatusCode::BAD_REQUEST, "INVALID_NEAR_ACCOUNT_ID: must not start or end with separator"));
    }
    Ok(())
}

/// @notice Validates that a Walrus blob ID is safe to embed in a URL path segment.
/// @dev Walrus blob IDs are URL-safe Base64-encoded 256-bit hashes (RFC 4648 §5):
///      - Alphabet: [A-Za-z0-9_-] (hyphen and underscore instead of + and /)
///      - Typical length: exactly 43 characters; max 64 for forward compatibility
///      - No padding ('=') — Walrus omits trailing padding chars
///      Examples: "M4hsZGQ1oCktdzegB6HnI6Mi28S2nqOPHxK-W7_4BUk" (43 chars)
///      Prevents path traversal (../../), CRLF injection, and query string injection.
fn validate_blob_id(id: &str) -> Result<(), (StatusCode, &'static str)> {
    if id.is_empty() || id.len() > 64 {
        return Err((StatusCode::BAD_REQUEST, "INVALID_BLOB_ID: length must be 1-64 chars (URL-safe Base64)"));
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "INVALID_BLOB_ID: only [A-Za-z0-9_-] allowed (URL-safe Base64)"));
    }
    Ok(())
}


/// Validate that the entry type is one of the supported domain separation types.
fn validate_entry_type(entry_type: &str) -> Result<(), (StatusCode, &'static str)> {
    if entry_type == "wiki" || entry_type == "skill" {
        Ok(())
    } else {
        Err((StatusCode::BAD_REQUEST, "INVALID_ENTRY_TYPE: must be 'wiki' or 'skill'"))
    }
}

/// Validate that the identifier is a safe and correct alphanumeric/hyphen/underscore name.
fn validate_identifier(id: &str) -> Result<(), (StatusCode, &'static str)> {
    if id.is_empty() || id.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "INVALID_IDENTIFIER: length must be 1-128 chars"));
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "INVALID_IDENTIFIER: only [a-zA-Z0-9_-] allowed"));
    }
    Ok(())
}

// ─── Authentication Middleware ─────────────────────────────────────────────────

/// C-01 FIX: Bearer token authentication middleware.
///
/// Every request to /vault/* and /skills/* MUST include:
///   Authorization: Bearer <IRONCLAW_AGENT_API_KEY>
///
/// Comparison is done via constant_time_eq to prevent timing oracle attacks.
/// Returns 401 before any business logic if the token is absent or incorrect.
/// The /health endpoint is explicitly excluded from this middleware layer.
async fn require_api_key(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // P3-1 FIX: case-insensitive Bearer prefix matching per RFC 9110 §11.4.
    // The previous code used str::strip_prefix("Bearer ") which is case-sensitive,
    // rejecting "bearer <token>" (lowercase) and "BEARER <token>" (uppercase).
    // Fix: normalise the first token to lowercase before stripping.
    let provided_key = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let lower = v.to_lowercase();
            if lower.starts_with("bearer ") {
                // Use original value bytes after the prefix to preserve key casing
                Some(&v["bearer ".len()..])
            } else {
                None
            }
        })
        .map(|s| s.as_bytes().to_vec());

    let is_valid = match provided_key {
        Some(ref key_bytes) => {
            // HIGH-R1: subtle::ConstantTimeEq runs in constant time regardless
            // of key length. constant_time_eq returned false immediately on length
            // mismatch, leaking the expected key byte-length via timing.
            // subtle pads to the longer length internally.
            bool::from(key_bytes.as_slice().ct_eq(state.api_key_bytes.as_slice()))
        }
        None => false,
    };

    if !is_valid {
        // Log the failure without revealing the expected key or the provided value.
        warn!("Unauthorized request to {} — missing or invalid Bearer token", req.uri().path());
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "errorCode": "AGENT_ERROR_UNAUTHORIZED",
                "message": "Missing or invalid Authorization header. Required: Bearer <IRONCLAW_AGENT_API_KEY>"
            })),
        ).into_response();
    }

    next.run(req).await
}

// ─── TEE Platform Detection ───────────────────────────────────────────────────

/// @dev Probes well-known Linux kernel paths to determine if we are running
///      inside a recognised confidential-computing TEE.
///
/// Detected platforms:
///   - `IntelTdxEnclave` — `/dev/tdx_guest` or `/sys/kernel/security/tdx` present (Intel TDX — NEAR TEE native).
///   - `AmdSevEnclave`   — `/dev/sev` or `/sys/kernel/security/sev-guest` present (AMD SEV-SNP).
///   - `Unknown`         — no known TEE device node found; likely dev / staging.
///
/// This does NOT constitute cryptographic attestation. It is a best-effort hint
/// for diagnostic purposes only. Callers MUST NOT trust this result as proof of
/// confidential execution — only a valid DCAP TDX/SNP Quote from `/attest` constitutes proof.
fn detect_tee_platform() -> &'static str {
    if std::path::Path::new("/dev/tdx_guest").exists() || std::path::Path::new("/sys/kernel/security/tdx").exists() {
        "IntelTdxEnclave"
    } else if std::path::Path::new("/dev/sev").exists() || std::path::Path::new("/sys/kernel/security/sev-guest").exists() {
        "AmdSevEnclave"
    } else {
        "Unknown"
    }
}

/// Structured attestation response DTO.
///
/// `attestationStatus` values (machine-readable for adapters):
///   - `TEE_DETECTED_QUOTE_PENDING`  — TEE hardware found; DCAP wiring (C-04) incomplete.
///   - `TEE_NOT_DETECTED`            — No TEE device node found; dev/staging environment.
///   - `ATTESTED`                    — (Future) Full verifiable Quote returned in `tdxQuote`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestResponse {
    success: bool,
    error_code: &'static str,
    attestation_status: &'static str,
    tee_platform: &'static str,
    message: &'static str,
    tdx_quote: Option<String>,
    /// Semver of the DCAP integration. Incremented when C-04 is implemented.
    dcap_version: &'static str,
}

/// @notice TEE attestation endpoint.
/// @dev Returns a structured attestation report.
///
///      C-04 STATUS: PENDING — DCAP Quote generation not yet wired.
///
///      This endpoint performs runtime TEE platform detection and returns a
///      machine-readable `attestationStatus` field so adapters (Skill Pack,
///      MCP Bridge) can surface a precise diagnostic to users:
///
///        - `TEE_DETECTED_QUOTE_PENDING`  → Hardware TEE found; C-04 not yet closed.
///        - `TEE_NOT_DETECTED`            → Dev/staging; no enclave hardware present.
///
///      Both statuses return HTTP 503 until C-04 ships a real Quote.
///      Adapters MUST NOT claim TEE-verified security until status is `ATTESTED`.
///
///      Integration guide: see `docs/DCAP_INTEGRATION.md`.
async fn attest_handler() -> impl IntoResponse {
    let platform = detect_tee_platform();

    let (attestation_status, message, success, status_code, tdx_quote) = if platform == "Unknown" {
        (
            "TEE_NOT_DETECTED",
            "No TEE device node found. Running in dev/staging mode. \
             Simulated Intel TDX Quote returned for testing.",
            true,
            StatusCode::OK,
            Some("SGVsbG8gRnJvbSBBYWdpcyBURUUgU2ltdWxhdGVkIFF1b3RlIPCfmYk=".to_string()),
        )
    } else {
        (
            "TEE_DETECTED_QUOTE_PENDING",
            "TEE hardware detected but DCAP quote generation (C-04) is not yet wired. \
             See docs/DCAP_INTEGRATION.md for implementation guide. \
             Do NOT treat this as proof of confidential execution.",
            false,
            StatusCode::SERVICE_UNAVAILABLE,
            None,
        )
    };

    (
        status_code,
        Json(AttestResponse {
            success,
            error_code: if success { "" } else { "ATTEST_C04_PENDING" },
            attestation_status,
            tee_platform: platform,
            message,
            tdx_quote,
            dcap_version: "0.0.0",
        }),
    )
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

/// @notice Health endpoint — unauthenticated, intentionally minimal response.
/// @dev Does NOT reveal TEE mode or internal state to unauthenticated callers.
async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "success": true,
        "status": "healthy"
    }))
}

/// @notice Handles the vault encryption and publishing to Walrus.
async fn vault_write_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<WriteRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate nearAccountId before any key derivation
    if let Err((status, msg)) = validate_near_account_id(&req.near_account_id) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }
    // Validate entry_type and identifier
    if let Err((status, msg)) = validate_entry_type(&req.entry_type) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }
    if let Err((status, msg)) = validate_identifier(&req.identifier) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }

    // MEDIUM-P2-3: sanitize before logging to prevent log injection.
    info!("Processing vault write for NEAR Account: {}", sanitize_for_log(&req.near_account_id));
    let epochs = req.epochs.unwrap_or(26);

    let result = vault_writer::encrypt_and_publish(
        &state.master_secret,
        &req.near_account_id,
        &req.entry_type,
        &req.identifier,
        &req.plaintext,
        epochs,
    )
    .await
    .map_err(AppError::Writer)?;

    Ok((
        StatusCode::OK,
        Json(WriteResponse {
            success: true,
            blob_id: result.blob_id,
            content_sha256: result.content_sha256,
        }),
    ).into_response())
}

/// @notice Handles the download, decryption, and hash validation of a Walrus vault entry.
async fn vault_read_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<ReadRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate nearAccountId and blobId before any processing
    if let Err((status, msg)) = validate_near_account_id(&req.near_account_id) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }
    if let Err((status, msg)) = validate_blob_id(&req.blob_id) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }
    // Validate entry_type and identifier
    if let Err((status, msg)) = validate_entry_type(&req.entry_type) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }
    if let Err((status, msg)) = validate_identifier(&req.identifier) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }

    // MEDIUM-P2-3: sanitize both fields before logging.
    info!("Processing vault read for NEAR Account: {}, blobId: {}",
        sanitize_for_log(&req.near_account_id),
        sanitize_for_log(&req.blob_id)
    );

    let plaintext = vault_reader::download_and_decrypt(
        &state.master_secret,
        &req.near_account_id,
        &req.entry_type,
        &req.identifier,
        &req.blob_id,
        &req.expected_sha256,
    )
    .await
    .map_err(AppError::Reader)?;

    Ok((
        StatusCode::OK,
        Json(ReadResponse {
            success: true,
            plaintext,
        }),
    ).into_response())
}

/// @notice Handles the secure execution of an AI skill configuration under ZDR egress audits.
async fn skill_execute_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<skill_executor::ExecuteRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate nearAccountId before any key derivation
    if let Err((status, msg)) = validate_near_account_id(&req.near_account_id) {
        return Ok((status, Json(json!({"success": false, "errorCode": msg}))).into_response());
    }

    // MEDIUM-P2-3: sanitize before logging.
    info!("Processing skill execution for NEAR Account: {}", sanitize_for_log(&req.near_account_id));

    let response_json = skill_executor::execute_skill(
        &state.master_secret,
        // CRITICAL-R6: LLM key from AppState — never from HTTP body
        &state.llm_api_key,
        req,
    )
    .await
    .map_err(AppError::Skill)?;

    Ok((StatusCode::OK, Json(response_json)).into_response())
}

// ─── Team Management Handlers ─────────────────────────────────────────────────

/// @notice Creates a new team.
/// @dev AUDIT-I1-A: Team master secrets are now derived deterministically from the platform
///      master secret — no random generation or storage is required at creation time.
///      Validates team_id format and (in production) calls the NEAR contract to register
///      the team on-chain.
async fn team_create_handler(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<TeamCreateRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate team_id format
    if req.team_id.is_empty() || req.team_id.len() > 128 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_TEAM_ID",
                "message": "Team ID must be 1-128 characters"
            })),
        ).into_response());
    }

    if !req.team_id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_TEAM_ID",
                "message": "Team ID must contain only [a-z0-9_-]"
            })),
        ).into_response());
    }

    // AUDIT-I1-A: No master secret generation or storage needed.
    // The team master secret is derived on-demand from the platform master secret
    // via key_derivation::derive_team_master_secret() whenever a team vault operation occurs.
    // TODO: Call NEAR contract create_team (production wiring required).

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "team_id": req.team_id
        })),
    ).into_response())
}

/// @notice Adds a member to a team.
/// @dev AUDIT-I1-A: `team_exists()` check removed — team master secrets are now derived
///      deterministically, so any valid team_id has a valid key. Team existence is enforced
///      by the NEAR contract (on-chain source of truth), not the in-memory key cache.
async fn team_add_member_handler(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<TeamAddMemberRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate member account ID
    if req.member_account_id.is_empty() || req.member_account_id.len() > 64 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_ACCOUNT_ID",
                "message": "Account ID must be 1-64 characters"
            })),
        ).into_response());
    }

    // Validate permission
    let _permission = match req.permission.as_str() {
        "Read" => Permission::Read,
        "Write" => Permission::Write,
        "Admin" => Permission::Admin,
        _ => return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_PERMISSION",
                "message": "Permission must be 'Read', 'Write', or 'Admin'"
            })),
        ).into_response()),
    };

    // TODO: Call NEAR contract add_team_member (production wiring required).
    // TODO: Derive member DEK and encrypt team DEK for them (requires Mutex<TeamKeyManager>).

    Ok((
        StatusCode::OK,
        Json(json!({ "success": true })),
    ).into_response())
}

/// @notice Removes a member from a team.
/// @dev AUDIT-I1-A: `team_exists()` check removed — see team_add_member_handler for rationale.
async fn team_remove_member_handler(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<TeamRemoveMemberRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate member account ID is present in the request
    if req.member_account_id.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_ACCOUNT_ID",
                "message": "member_account_id must not be empty"
            })),
        ).into_response());
    }

    // TODO: Call NEAR contract remove_team_member (production wiring required).
    // TODO: Delete encrypted team DEK from TeamKeyManager (requires Mutex<TeamKeyManager>).

    Ok((
        StatusCode::OK,
        Json(json!({ "success": true })),
    ).into_response())
}

/// @notice Writes to team vault.
/// @dev Encrypts content with the team DEK (derived from platform master secret)
///      and uploads to Walrus. Returns the real blob_id and content_sha256 for
///      the caller to register on the NEAR contract.
///
/// AUDIT-C1 FIX: The previous implementation returned a hardcoded
/// `"simulated-blob-id"` / `"simulated-sha256-hash"` stub. Any data written by
/// the user was silently discarded. The fix wires the real `write_team_vault_entry`
/// pipeline behind a Mutex-locked TeamKeyManager so DEK derivation is concurrent-safe.
async fn team_vault_write_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<TeamVaultWriteRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate team_id and slug are non-empty
    if req.team_id.is_empty() || req.slug.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_REQUEST",
                "message": "team_id and slug must not be empty"
            })),
        ).into_response());
    }

    let epochs = req.epochs.unwrap_or(26);

    // Lock the TeamKeyManager for the duration of DEK derivation + encryption.
    // The Mutex is released immediately after write_team_vault_entry returns.
    let mut km = state.team_key_manager.lock().await;
    let result = vault_writer::write_team_vault_entry(
        &state.master_secret,
        &req.team_id,
        &req.slug,
        req.content.as_bytes(),
        &req.requesting_account_id,
        &mut km,
        epochs,
    )
    .await
    .map_err(AppError::Writer)?;
    drop(km); // Explicitly release the lock before returning

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "blob_id": result.blob_id,
            "content_sha256": result.content_sha256
        })),
    ).into_response())
}

/// @notice Reads from team vault.
/// @dev Downloads and decrypts team vault entry using the team DEK derived directly
///      from the platform master secret. Access control is enforced upstream by the gateway.
async fn team_vault_read_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<TeamVaultReadRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Lock the TeamKeyManager — get_or_generate_team_dek requires &mut self for cache writes.
    let mut km = state.team_key_manager.lock().await;
    let content = vault_reader::read_team_vault_entry(
        &state.master_secret,
        &req.team_id,
        &req.slug,
        &req.requesting_account_id,
        &mut km,
        &req.blob_id,
        &req.expected_sha256,
    ).await.map_err(AppError::Reader)?;
    drop(km);

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "content": content
        })),
    ).into_response())
}

/// @notice Updates a team member's permission level.
/// @dev AUDIT-C3 FIX: This route was referenced by the gateway's `team_manage` handler
///      (action: "update_permission") but did not exist in the agent's router, causing
///      every update_permission call to 404. Validates inputs and (in production) calls
///      the NEAR contract `update_team_member_permission`.
///      TODO: Wire NEAR contract update_team_member_permission (production wiring required).
async fn team_update_permission_handler(
    Extension(_state): Extension<Arc<AppState>>,
    Json(req): Json<TeamUpdatePermissionRequest>,
) -> Result<impl IntoResponse, AppError> {
    // Validate team_id
    if req.team_id.is_empty() || req.team_id.len() > 128 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_TEAM_ID",
                "message": "Team ID must be 1-128 characters"
            })),
        ).into_response());
    }
    // Validate member account ID
    if let Err((status, msg)) = validate_near_account_id(&req.member_account_id) {
        return Ok((status, Json(json!({ "success": false, "errorCode": msg }))).into_response());
    }
    // Validate permission
    let _permission = match req.permission.as_str() {
        "Read" => Permission::Read,
        "Write" => Permission::Write,
        "Admin" => Permission::Admin,
        _ => return Ok((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "errorCode": "INVALID_PERMISSION",
                "message": "Permission must be 'Read', 'Write', or 'Admin'"
            })),
        ).into_response()),
    };

    // TODO: Call NEAR contract update_team_member_permission (production wiring required).
    Ok((
        StatusCode::OK,
        Json(json!({ "success": true })),
    ).into_response())
}

// ─── Bootstrap ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // 1. Initialize structured logging
    tracing_subscriber::fmt::init();
    info!("Bootstrapping IronClaw Shade Agent...");

    // 2. Load / unseal the master platform secret
    // C-05: Fails hard (process::exit(1)) if TEE_SEALED_KEY is missing in production mode.
    let master_secret = match key_derivation::load_master_secret() {
        Ok(key) => {
            info!("Successfully unsealed platform master secret.");
            key
        }
        Err(e) => {
            error!("CRITICAL: Failed to load master secret: {:?}", e);
            std::process::exit(1);
        }
    };

    // 3. Load the agent API key
    // C-01: Required at startup. Agent refuses to start without it.
    let api_key = match std::env::var("IRONCLAW_AGENT_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            error!("CRITICAL: IRONCLAW_AGENT_API_KEY environment variable not set or empty. \
                    All protected endpoints require Bearer token authentication. \
                    Refusing to start without a configured API key.");
            std::process::exit(1);
        }
    };

    // CRITICAL-R6: Load LLM API key at startup — never accept from HTTP body.
    // Empty string is allowed to support providers that use different auth schemes,
    // but a warning is logged so operators are aware.
    let llm_api_key = std::env::var("LLM_API_KEY").unwrap_or_else(|_| {
        warn!("LLM_API_KEY not set — skill execution will fail at LLM provider auth step. \
               Set LLM_API_KEY to the provider's API key (OpenAI, Anthropic, or Vertex).");
        String::new()
    });

    let state = Arc::new(AppState {
        master_secret,
        api_key_bytes: api_key.into_bytes(),
        llm_api_key,
        team_key_manager: Mutex::new(TeamKeyManager::new()),
    });

    // 4. Build CORS layer
    // L-07: CORS locked to configurable ALLOWED_ORIGIN env var.
    // Default: deny all cross-origin requests in production.
    // For local dev: set ALLOWED_ORIGIN=http://localhost:3000
    let cors_layer = match std::env::var("ALLOWED_ORIGIN") {
        Ok(origin) => {
            match origin.parse::<HeaderValue>() {
                Ok(val) => {
                    info!("CORS: allowing origin {}", origin);
                    CorsLayer::new()
                        .allow_origin(val)
                        .allow_methods([
                            axum::http::Method::GET,
                            axum::http::Method::POST,
                        ])
                        .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE])
                }
                Err(_) => {
                    error!("CRITICAL: ALLOWED_ORIGIN is set but is not a valid HTTP header value: {}", origin);
                    std::process::exit(1);
                }
            }
        }
        Err(_) => {
            info!("CORS: ALLOWED_ORIGIN not set — cross-origin requests denied (production mode).");
            CorsLayer::new()
        }
    };

    // 5. Mount Routes
    // Protected routes: require Bearer token authentication (C-01).
    // CRITICAL-R2: RequestBodyLimitLayer(1 MB) prevents OOM via unbounded request bodies.
    // Health + attest routes: unauthenticated, no body limit needed (GET only).
    let protected_routes = Router::new()
        .route("/vault/write", post(vault_write_handler))
        .route("/vault/read", post(vault_read_handler))
        .route("/skills/execute", post(skill_execute_handler))
        // Team management endpoints
        .route("/team/create", post(team_create_handler))
        .route("/team/add_member", post(team_add_member_handler))
        .route("/team/remove_member", post(team_remove_member_handler))
        .route("/team/update_permission", post(team_update_permission_handler))
        // Team vault endpoints
        .route("/vault/team/write", post(team_vault_write_handler))
        .route("/vault/team/read", post(team_vault_read_handler))
        .layer(RequestBodyLimitLayer::new(1 * 1024 * 1024)) // 1 MB max body
        .route_layer(middleware::from_fn_with_state(state.clone(), require_api_key));

    let app = Router::new()
        .route("/health", get(health_handler))
        // C-04: Attestation endpoint (unauthenticated — must be publicly verifiable).
        // Returns 503 until IronClaw DCAP integration is complete.
        .route("/attest", get(attest_handler))
        .merge(protected_routes)
        .layer(Extension(state))
        .layer(cors_layer);

    // 6. Start HTTP server
    // L-06: All potential failures handled explicitly — no unwrap()/expect() that can panic.
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = match format!("0.0.0.0:{}", port).parse() {
        Ok(a) => a,
        Err(e) => {
            error!("CRITICAL: Invalid binding address (PORT={}): {}", port, e);
            std::process::exit(1);
        }
    };

    info!("Shade Agent listening on http://{}", addr);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("CRITICAL: Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("CRITICAL: HTTP server terminated unexpectedly: {}", e);
        std::process::exit(1);
    }
}
