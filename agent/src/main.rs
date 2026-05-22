// //////////////////////////////////////////////////////////////
//                          MAIN ENTRY POINT
// //////////////////////////////////////////////////////////////

/// @title IronClaw Shade Agent Confidential Server
/// @notice Bootstraps the Axum HTTP web server inside the TEE enclave.
/// @dev Secures the platform key state, mounts API controllers, and applies CORS controls.

use std::net::SocketAddr;
use std::sync::Arc;
use axum::{
    routing::{get, post},
    Router, Json, Extension,
    response::{IntoResponse, Response},
    http::StatusCode
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::{CorsLayer, Any};
use tracing::{info, error};

mod key_derivation;
mod vault_writer;
mod vault_reader;
mod zdr_firewall;
mod skill_executor;

/// Shared application state housing the platform's unsealed 32-byte master secret
struct AppState {
    master_secret: [u8; 32],
}

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
            "message": message
        }));

        (status, body).into_response()
    }
}

// Request and response DTO definitions

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WriteRequest {
    near_account_id: String,
    plaintext: String,
    epochs: Option<u64>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct WriteResponse {
    success: bool,
    blob_id: String,
    content_sha256: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ReadRequest {
    near_account_id: String,
    blob_id: String,
    expected_sha256: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ReadResponse {
    success: bool,
    plaintext: String,
}

// //////////////////////////////////////////////////////////////
//                        ROUTE HANDLERS
// //////////////////////////////////////////////////////////////

/// @notice Health endpoint to verify that the Shade Agent is up and running.
async fn health_handler() -> impl IntoResponse {
    Json(json!({
        "success": true,
        "status": "healthy",
        "tee": std::env::var("TEE_SIMULATION").unwrap_or_else(|_| "false".to_string()) == "true"
    }))
}

/// @notice Handles the vault encryption and publishing to Walrus.
async fn vault_write_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<WriteRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Processing vault write for NEAR Account: {}", req.near_account_id);
    let epochs = req.epochs.unwrap_or(5);

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
    ))
}

/// @notice Handles the download, decryption, and hash validation of a Walrus vault entry.
async fn vault_read_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<ReadRequest>,
) -> Result<impl IntoResponse, AppError> {
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
    ))
}

/// @notice Handles the secure execution of an AI skill configuration under ZDR egress audits.
async fn skill_execute_handler(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<skill_executor::ExecuteRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Processing skill execution for NEAR Account: {}", req.near_account_id);

    let response_json = skill_executor::execute_skill(
        &state.master_secret,
        req,
    )
    .await
    .map_err(AppError::Skill)?;

    Ok((StatusCode::OK, Json(response_json)))
}

// //////////////////////////////////////////////////////////////
//                        BOOTSTRAPPING
// //////////////////////////////////////////////////////////////

#[tokio::main]
async fn main() {
    // 1. Initialize logging
    tracing_subscriber::fmt::init();
    info!("Bootstraping IronClaw Shade Agent...");

    // 2. Load / unseal the master platform secret
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

    let state = Arc::new(AppState { master_secret });

    // 3. Mount Routes
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/vault/write", post(vault_write_handler))
        .route("/vault/read", post(vault_read_handler))
        .route("/skills/execute", post(skill_execute_handler))
        .layer(Extension(state))
        // Apply lax CORS for development (CORS can be locked down in production config)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // 4. Start HTTP Server
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Invalid binding address");

    info!("Shade Agent listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
