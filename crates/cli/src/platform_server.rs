use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Multipart, Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    routing::{delete, get, post, put},
    Json, Router,
};
use hb_zayfer_core::{
    passgen, AppInfo, AuditLogger, Contact, KeyMetadata, KeyStore, WorkspaceSummary,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
struct ServerState {
    info: AppInfo,
}

#[derive(Debug, Serialize)]
struct KeyMetadataOut {
    fingerprint: String,
    algorithm: String,
    label: String,
    created_at: String,
    has_private: bool,
    has_public: bool,
}

impl From<&KeyMetadata> for KeyMetadataOut {
    fn from(value: &KeyMetadata) -> Self {
        Self {
            fingerprint: value.fingerprint.clone(),
            algorithm: value.algorithm.to_string(),
            label: value.label.clone(),
            created_at: value.created_at.to_rfc3339(),
            has_private: value.has_private,
            has_public: value.has_public,
        }
    }
}

#[derive(Debug, Serialize)]
struct ContactOut {
    name: String,
    email: Option<String>,
    key_fingerprints: Vec<String>,
    notes: Option<String>,
    created_at: String,
}

impl From<&Contact> for ContactOut {
    fn from(value: &Contact) -> Self {
        Self {
            name: value.name.clone(),
            email: value.email.clone(),
            key_fingerprints: value.key_fingerprints.clone(),
            notes: value.notes.clone(),
            created_at: value.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditEntryOut {
    timestamp: String,
    operation: String,
    prev_hash: Option<String>,
    entry_hash: String,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PassgenRequest {
    length: Option<usize>,
    words: Option<usize>,
    separator: Option<String>,
    exclude: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EncryptTextRequest {
    plaintext: String,
    passphrase: String,
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DecryptTextRequest {
    ciphertext_b64: String,
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct KeygenRequest {
    algorithm: String,
    label: String,
    passphrase: String,
    user_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct KeygenResponse {
    fingerprint: String,
    algorithm: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct SignRequest {
    message_b64: String,
    fingerprint: String,
    passphrase: String,
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    message_b64: String,
    signature_b64: String,
    fingerprint: String,
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContactRequest {
    name: String,
    email: Option<String>,
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LinkKeyRequest {
    contact_name: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct FileActionQuery {
    passphrase: String,
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BackupRequest {
    output_path: String,
    passphrase: String,
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    backup_path: String,
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdateRequest {
    value: serde_json::Value,
}

const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

pub fn serve(host: &str, port: u16) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("Invalid host/port combination")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build async runtime")?;

    runtime.block_on(async move {
        let router = build_platform_router()?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind {}", addr))?;
        println!("Starting Rust web platform on http://{}", addr);
        axum::serve(listener, router)
            .await
            .context("Rust web server failed")?;
        Ok(())
    })
}

pub fn build_platform_router() -> Result<Router> {
    let state = ServerState {
        info: AppInfo::current(),
    };

    let mut router = Router::new()
        .route("/health", get(health_handler))
        .route("/api/version", get(api_version_handler))
        .route("/api/status", get(api_status_handler))
        .route("/api/keys", get(api_keys_handler))
        .route("/api/keys/:fingerprint", delete(api_delete_key_handler))
        .route("/api/keys/:fingerprint/public", get(api_public_key_handler))
        .route(
            "/api/contacts",
            get(api_contacts_handler).post(api_add_contact_handler),
        )
        .route("/api/contacts/:name", delete(api_remove_contact_handler))
        .route("/api/contacts/link", post(api_link_contact_handler))
        .route("/api/config", get(api_config_handler))
        .route("/api/audit/count", get(api_audit_count_handler))
        .route("/api/audit/recent", get(api_audit_recent_handler))
        .route("/api/audit/verify", get(api_audit_verify_handler))
        .route("/api/passgen", post(api_passgen_handler))
        .route("/api/encrypt/text", post(api_encrypt_text_handler))
        .route("/api/encrypt/file", post(api_encrypt_file_handler))
        .route("/api/decrypt/text", post(api_decrypt_text_handler))
        .route("/api/decrypt/file", post(api_decrypt_file_handler))
        .route("/api/keygen", post(api_keygen_handler))
        .route("/api/sign", post(api_sign_handler))
        .route("/api/verify", post(api_verify_handler))
        .route("/api/backup/create", post(api_backup_create_handler))
        .route("/api/backup/verify", post(api_backup_verify_handler))
        .route("/api/backup/restore", post(api_backup_restore_handler))
        .route("/api/config/:key", put(api_set_config_handler))
        .with_state(state);

    let static_dir = std::env::current_dir()?
        .join("python")
        .join("hb_zayfer")
        .join("web")
        .join("static");

    if static_dir.exists() {
        router = router
            .nest_service("/static", ServeDir::new(static_dir.clone()))
            .fallback_service(ServeFile::new(static_dir.join("index.html")));
    }

    Ok(router)
}

async fn health_handler(State(state): State<ServerState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "brand_name": state.info.brand_name,
        "version": state.info.version,
    }))
}

async fn api_version_handler(State(state): State<ServerState>) -> Json<serde_json::Value> {
    Json(json!({
        "version": state.info.version,
        "brand_name": state.info.brand_name,
    }))
}

async fn api_status_handler() -> Result<Json<WorkspaceSummary>, (StatusCode, String)> {
    WorkspaceSummary::collect().map(Json).map_err(internal_err)
}

async fn api_keys_handler() -> Result<Json<Vec<KeyMetadataOut>>, (StatusCode, String)> {
    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let keys = keystore
        .list_keys()
        .into_iter()
        .map(KeyMetadataOut::from)
        .collect();
    Ok(Json(keys))
}

async fn api_contacts_handler() -> Result<Json<Vec<ContactOut>>, (StatusCode, String)> {
    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let contacts = keystore
        .list_contacts()
        .into_iter()
        .map(ContactOut::from)
        .collect();
    Ok(Json(contacts))
}

async fn api_config_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let config = hb_zayfer_core::services::load_web_config().map_err(internal_err)?;
    Ok(Json(json!({
        "cipher": config.cipher,
        "kdf": config.kdf,
        "chunk_size": config.chunk_size,
        "audit_enabled": config.audit_enabled,
        "dark_mode": config.dark_mode,
        "clipboard_auto_clear": config.clipboard_auto_clear,
    })))
}

async fn api_audit_count_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let logger = AuditLogger::default_location().map_err(internal_err)?;
    Ok(Json(
        json!({ "count": logger.entry_count().map_err(internal_err)? }),
    ))
}

async fn api_audit_recent_handler() -> Result<Json<Vec<AuditEntryOut>>, (StatusCode, String)> {
    let logger = AuditLogger::default_location().map_err(internal_err)?;
    let entries = logger.recent_entries(20).map_err(internal_err)?;
    let out = entries
        .into_iter()
        .map(|e| AuditEntryOut {
            timestamp: e.timestamp.to_rfc3339(),
            operation: format!("{:?}", e.operation),
            prev_hash: e.prev_hash,
            entry_hash: e.entry_hash,
            note: e.note,
        })
        .collect();
    Ok(Json(out))
}

async fn api_audit_verify_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let logger = AuditLogger::default_location().map_err(internal_err)?;
    Ok(Json(
        json!({ "valid": logger.verify_integrity().map_err(internal_err)? }),
    ))
}

async fn api_passgen_handler(
    Json(req): Json<PassgenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(words) = req.words {
        let separator = req.separator.unwrap_or_else(|| "-".to_string());
        let value = passgen::generate_passphrase(words, &separator);
        let entropy = passgen::passphrase_entropy(words);
        Ok(Json(json!({
            "type": "passphrase",
            "value": value,
            "entropy_bits": entropy,
        })))
    } else {
        let length = req.length.unwrap_or(20);
        let exclude = req.exclude.unwrap_or_default();
        let policy = passgen::PasswordPolicy {
            length,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude,
        };
        let value = passgen::generate_password(&policy);
        let entropy = passgen::estimate_entropy(&policy);
        Ok(Json(json!({
            "type": "password",
            "value": value,
            "entropy_bits": entropy,
        })))
    }
}

async fn api_encrypt_text_handler(
    Json(req): Json<EncryptTextRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let algorithm = req.algorithm.unwrap_or_else(|| "aes".to_string());
    let encrypted =
        hb_zayfer_core::services::encrypt_text_payload(&req.plaintext, &req.passphrase, &algorithm)
            .map_err(bad_request_err)?;
    Ok(Json(json!({ "ciphertext_b64": encrypted })))
}

async fn api_decrypt_text_handler(
    Json(req): Json<DecryptTextRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let plaintext =
        hb_zayfer_core::services::decrypt_text_payload(&req.ciphertext_b64, &req.passphrase)
            .map_err(bad_request_err)?;
    Ok(Json(json!({ "plaintext": plaintext })))
}

async fn api_encrypt_file_handler(
    Query(query): Query<FileActionQuery>,
    multipart: Multipart,
) -> Result<Response, (StatusCode, String)> {
    if query.passphrase.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "passphrase is required".to_string(),
        ));
    }

    let (filename, contents) = read_uploaded_file(multipart).await?;
    let (download_name, encrypted) = hb_zayfer_core::services::encrypt_file_payload(
        Some(&filename),
        &contents,
        &query.passphrase,
        query.algorithm.as_deref().unwrap_or("aes"),
    )
    .map_err(bad_request_err)?;

    Ok(attachment_response(&download_name, encrypted))
}

async fn api_decrypt_file_handler(
    Query(query): Query<FileActionQuery>,
    multipart: Multipart,
) -> Result<Response, (StatusCode, String)> {
    if query.passphrase.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "passphrase is required".to_string(),
        ));
    }

    let (filename, contents) = read_uploaded_file(multipart).await?;
    let (download_name, plaintext) = hb_zayfer_core::services::decrypt_file_payload(
        Some(&filename),
        &contents,
        &query.passphrase,
    )
    .map_err(bad_request_err)?;

    Ok(attachment_response(&download_name, plaintext))
}

async fn api_keygen_handler(
    Json(req): Json<KeygenRequest>,
) -> Result<Json<KeygenResponse>, (StatusCode, String)> {
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    let created = hb_zayfer_core::services::generate_and_store_key(
        &mut keystore,
        &req.algorithm,
        &req.label,
        &req.passphrase,
        req.user_id.as_deref(),
    )
    .map_err(bad_request_err)?;
    Ok(Json(KeygenResponse {
        fingerprint: created.fingerprint,
        algorithm: created.algorithm,
        label: created.label,
    }))
}

async fn api_sign_handler(
    Json(req): Json<SignRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let algorithm = req.algorithm.unwrap_or_else(|| "ed25519".to_string());
    let signature_b64 = hb_zayfer_core::services::sign_message_payload(
        &keystore,
        &req.message_b64,
        &req.fingerprint,
        &req.passphrase,
        &algorithm,
    )
    .map_err(bad_request_err)?;
    Ok(Json(json!({ "signature_b64": signature_b64 })))
}

async fn api_verify_handler(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let algorithm = req.algorithm.unwrap_or_else(|| "ed25519".to_string());
    let valid = hb_zayfer_core::services::verify_message_payload(
        &keystore,
        &req.message_b64,
        &req.signature_b64,
        &req.fingerprint,
        &algorithm,
    )
    .map_err(bad_request_err)?;
    Ok(Json(json!({ "valid": valid })))
}

async fn api_delete_key_handler(
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore.delete_key(&fingerprint).map_err(bad_request_err)?;
    Ok(Json(
        json!({ "status": "deleted", "fingerprint": fingerprint }),
    ))
}

async fn api_public_key_handler(
    Path(fingerprint): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let public_key = keystore
        .load_public_key(&fingerprint)
        .map_err(bad_request_err)?;
    Ok(Json(json!({
        "fingerprint": fingerprint,
        "public_key_b64": BASE64.encode(public_key),
    })))
}

async fn api_add_contact_handler(
    Json(req): Json<ContactRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore
        .add_contact(&req.name, req.email.as_deref(), req.notes.as_deref())
        .map_err(bad_request_err)?;
    Ok(Json(json!({ "status": "created", "name": req.name })))
}

async fn api_remove_contact_handler(
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore.remove_contact(&name).map_err(bad_request_err)?;
    Ok(Json(json!({ "status": "deleted", "name": name })))
}

async fn api_link_contact_handler(
    Json(req): Json<LinkKeyRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore
        .associate_key_with_contact(&req.contact_name, &req.fingerprint)
        .map_err(bad_request_err)?;
    Ok(Json(json!({ "status": "linked" })))
}

async fn api_backup_create_handler(
    Json(req): Json<BackupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let manifest = hb_zayfer_core::services::create_backup_archive(
        &req.output_path,
        &req.passphrase,
        req.label.as_deref(),
    )
    .map_err(bad_request_err)?;
    Ok(Json(backup_manifest_json(&manifest)))
}

async fn api_backup_verify_handler(
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let manifest =
        hb_zayfer_core::services::verify_backup_archive(&req.backup_path, &req.passphrase)
            .map_err(bad_request_err)?;
    Ok(Json(backup_manifest_json(&manifest)))
}

async fn api_backup_restore_handler(
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let manifest =
        hb_zayfer_core::services::restore_backup_archive(&req.backup_path, &req.passphrase)
            .map_err(bad_request_err)?;
    Ok(Json(backup_manifest_json(&manifest)))
}

async fn api_set_config_handler(
    Path(key): Path<String>,
    Json(req): Json<ConfigUpdateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let value = req
        .value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| req.value.to_string());
    let saved =
        hb_zayfer_core::services::update_web_config(&key, &value).map_err(bad_request_err)?;
    Ok(Json(json!({ "key": key, "value": saved })))
}

async fn read_uploaded_file(
    mut multipart: Multipart,
) -> Result<(String, Vec<u8>), (StatusCode, String)> {
    while let Some(field) = multipart.next_field().await.map_err(internal_err)? {
        if field.name() == Some("file") {
            let filename = sanitize_filename(field.file_name(), "upload");
            let data = field.bytes().await.map_err(internal_err)?;
            if data.len() > MAX_UPLOAD_BYTES {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "File too large (max {} MiB)",
                        MAX_UPLOAD_BYTES / (1024 * 1024)
                    ),
                ));
            }
            return Ok((filename, data.to_vec()));
        }
    }

    Err((StatusCode::BAD_REQUEST, "file is required".to_string()))
}

fn sanitize_filename(name: Option<&str>, fallback: &str) -> String {
    use std::path::Path;

    let base = name
        .and_then(|value| Path::new(value).file_name().and_then(|item| item.to_str()))
        .unwrap_or(fallback);
    let cleaned: String = base
        .chars()
        .map(|ch| {
            if ch.is_control() || matches!(ch, '"' | '\\' | '/') {
                '_'
            } else {
                ch
            }
        })
        .collect();
    if cleaned.is_empty() {
        fallback.to_string()
    } else {
        cleaned
    }
}

fn attachment_response(filename: &str, bytes: Vec<u8>) -> Response {
    let disposition = format!(
        "attachment; filename=\"{}\"",
        sanitize_filename(Some(filename), "download.bin")
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(bytes))
        .expect("valid attachment response")
}

fn backup_manifest_json(manifest: &hb_zayfer_core::BackupManifest) -> serde_json::Value {
    json!({
        "created_at": manifest.created_at.to_rfc3339(),
        "private_key_count": manifest.private_key_count,
        "public_key_count": manifest.public_key_count,
        "contact_count": manifest.contact_count,
        "version": manifest.version,
        "label": manifest.label,
        "integrity_hash": manifest.integrity_hash,
    })
}

fn internal_err<E: ToString>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn bad_request_err<E: ToString>(err: E) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::sync::{Mutex, OnceLock};
    use tempfile::TempDir;
    use tower::util::ServiceExt;

    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    async fn json_response(router: Router, request: Request<Body>) -> Value {
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn version_endpoint_returns_metadata() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/version")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let data = json_response(router, request).await;
        assert_eq!(data["brand_name"], "Zayfer Vault");
        assert!(data["version"].as_str().unwrap().starts_with("1."));
    }

    #[tokio::test]
    async fn passgen_endpoint_returns_password() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/passgen")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"length":16}"#))
            .unwrap();

        let data = json_response(router, request).await;
        assert_eq!(data["type"], "password");
        assert!(data["value"].as_str().unwrap().len() >= 16);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn encrypt_and_decrypt_text_roundtrip() {
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = TempDir::new().unwrap();
        std::env::set_var("HB_ZAYFER_HOME", temp.path());

        let router = build_platform_router().unwrap();
        let encrypt_request = Request::builder()
            .uri("/api/encrypt/text")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"plaintext":"hello rust","passphrase":"secret","algorithm":"aes"}"#,
            ))
            .unwrap();
        let encrypted = json_response(router.clone(), encrypt_request).await;
        let ciphertext = encrypted["ciphertext_b64"].as_str().unwrap();

        let decrypt_request = Request::builder()
            .uri("/api/decrypt/text")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"ciphertext_b64":"{}","passphrase":"secret"}}"#,
                ciphertext
            )))
            .unwrap();
        let decrypted = json_response(router, decrypt_request).await;
        assert_eq!(decrypted["plaintext"], "hello rust");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn keygen_endpoint_creates_key() {
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = TempDir::new().unwrap();
        std::env::set_var("HB_ZAYFER_HOME", temp.path());

        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/keygen")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"algorithm":"ed25519","label":"web-key","passphrase":"secret"}"#,
            ))
            .unwrap();

        let data = json_response(router, request).await;
        assert_eq!(data["algorithm"], "ed25519");
        assert_eq!(data["label"], "web-key");
        assert!(data["fingerprint"].as_str().unwrap().len() > 8);
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn config_endpoint_updates_cipher() {
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = TempDir::new().unwrap();
        std::env::set_var("HB_ZAYFER_HOME", temp.path());

        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/config/cipher")
            .method(Method::PUT)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"value":"ChaCha20"}"#))
            .unwrap();

        let data = json_response(router, request).await;
        assert_eq!(data["key"], "cipher");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn backup_endpoints_create_and_verify_backup() {
        let _guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = TempDir::new().unwrap();
        std::env::set_var("HB_ZAYFER_HOME", temp.path());

        let router = build_platform_router().unwrap();
        let output_path = temp.path().join("native-web-backup.hbzf");
        let create_request = Request::builder()
            .uri("/api/backup/create")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"output_path":"{}","passphrase":"backup-secret","label":"native"}}"#,
                output_path.display()
            )))
            .unwrap();

        let created = json_response(router.clone(), create_request).await;
        assert_eq!(created["label"], "native");

        let verify_request = Request::builder()
            .uri("/api/backup/verify")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"backup_path":"{}","passphrase":"backup-secret"}}"#,
                output_path.display()
            )))
            .unwrap();

        let verified = json_response(router, verify_request).await;
        assert_eq!(verified["integrity_hash"], created["integrity_hash"]);
    }
}
