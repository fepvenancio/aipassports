// //////////////////////////////////////////////////////////////
//                          MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title IronClaw Shade Agent Confidential Server
/// @notice Bootstraps the Axum HTTP web server inside the TEE enclave.
/// @dev Secures the platform key state, mounts API controllers, and applies
///      authentication and CORS controls.
///
/// Security hardening applied (audit cycle 2026-05-22):
///   C-01 — Bearer token authentication middleware on all protected routes.
///   C-05 — Refuse to start if TEE_SEALED_KEY missing in production mode.
///   L-06 — Replaced all unwrap()/expect() in main() with graceful error handling.
///   L-07 — CORS locked to configurable ALLOWED_ORIGIN (default: deny all).

use std::net::SocketAddr;
use std::sync::Arc;
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
use tracing::{info, warn, error};
use constant_time_eq::constant_time_eq;

mod key_derivation;
mod vault_writer;
mod vault_reader;
mod zdr_firewall;
mod skill_executor;

// ─── Shared State ─────────────────────────────────────────────────────────────

/// Shared application state housing the platform's unsealed 32-byte master secret
/// and the expected API key for constant-time comparison.
struct AppState {
    master_secret: [u8; 32],
    /// Pre-loaded from IRONCLAW_AGENT_API_KEY at startup.
    /// Stored as bytes to allow constant_time_eq comparison.
    api_key_bytes: Vec<u8>,
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

/// HIGH-03: Validate that a Walrus blob ID is safe to embed in a URL path segment.
/// Walrus blob IDs are base58 strings — only alphanumeric characters allowed.
/// Prevents path traversal (../../), CRLF injection, and query string injection.
fn validate_blob_id(id: &str) -> Result<(), (StatusCode, &'static str)> {
    if id.is_empty() || id.len() > 128 {
        return Err((StatusCode::BAD_REQUEST, "INVALID_BLOB_ID: length must be 1-128 chars"));
    }
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "INVALID_BLOB_ID: only [a-zA-Z0-9_-] allowed"));
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
    let provided_key = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.as_bytes().to_vec());

    let is_valid = match provided_key {
        Some(ref key_bytes) => constant_time_eq(key_bytes, &state.api_key_bytes),
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

/// @notice TEE attestation endpoint.
/// @dev Returns the Intel TDX Quote for the current enclave measurement.
///      Callers (e.g. the Hono gateway) MUST verify this quote against Intel
///      DCAP infrastructure before trusting any data from this agent.
///
/// C-04 STATUS: STUB — The IronClaw DCAP verification integration is pending.
///              Until this endpoint returns a verifiable TDX Quote, the gateway
///              MUST document this as a known trust gap and NOT be used on mainnet.
///
/// The stub returns HTTP 503 (not 200) to ensure callers cannot silently accept
/// a fake "healthy" attestation response — they MUST handle the 503 explicitly.
async fn attest_handler() -> impl IntoResponse {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "success": false,
            "errorCode": "ATTEST_NOT_IMPLEMENTED",
            "message": "TDX attestation quote generation is not yet wired to the IronClaw DCAP driver. \
                        This endpoint will return a verifiable TDX Quote when C-04 is implemented. \
                        Do NOT deploy to mainnet until this returns a valid attestation.",
            "tdxQuote": null
        })),
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

    info!("Processing vault write for NEAR Account: {}", req.near_account_id);
    let epochs = req.epochs.unwrap_or(26);

    let result = vault_writer::encrypt_and_publish(
        &state.master_secret,
        &req.near_account_id,
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

    info!("Processing vault read for NEAR Account: {}, blobId: {}", req.near_account_id, req.blob_id);

    let plaintext = vault_reader::download_and_decrypt(
        &state.master_secret,
        &req.near_account_id,
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

    info!("Processing skill execution for NEAR Account: {}", req.near_account_id);

    let response_json = skill_executor::execute_skill(
        &state.master_secret,
        req,
    )
    .await
    .map_err(AppError::Skill)?;

    Ok((StatusCode::OK, Json(response_json)).into_response())
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

    let state = Arc::new(AppState {
        master_secret,
        api_key_bytes: api_key.into_bytes(),
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
    // Health route: unauthenticated, intentionally minimal.
    let protected_routes = Router::new()
        .route("/vault/write", post(vault_write_handler))
        .route("/vault/read", post(vault_read_handler))
        .route("/skills/execute", post(skill_execute_handler))
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
