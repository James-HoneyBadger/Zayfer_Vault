use std::net::SocketAddr;
use std::path::{Component, Path as FsPath};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::{header, Request as HttpRequest, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        Response,
    },
    routing::{delete, get, post, put},
    Json, Router,
};
use hb_zayfer_core::{
    passgen, AppInfo, AuditLogger, Contact, KeyMetadata, KeyStore, WorkspaceSummary,
};
use rand::RngCore;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Semaphore;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

/// Maximum number of concurrent expensive keypair generations (RSA-4096 etc.).
/// Bounding this prevents an authenticated client from exhausting CPU by
/// flooding the keygen endpoint.
const KEYGEN_CONCURRENCY: usize = 2;

fn keygen_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(KEYGEN_CONCURRENCY))
}

/// Filesystem locations that should never be a target for read/write
/// operations issued through the web API, even if the caller is authenticated.
/// This is defence-in-depth on top of OS-level permissions.
const FORBIDDEN_PATH_PREFIXES: &[&str] = &[
    "/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var/log",
];

/// Validate a user-supplied filesystem path that will be written to (or read
/// from) by a privileged service call. Rejects:
/// - empty paths
/// - paths containing NUL bytes (defense against C-string truncation)
/// - paths whose components include `..` (no parent traversal in inputs)
/// - paths under well-known sensitive system roots
///
/// Note: this does not canonicalise the path (which may not exist yet). It
/// is a syntactic check intended to catch obvious abuse, not a substitute for
/// the OS permission model.
fn validate_user_path(raw: &str) -> Result<(), (StatusCode, String)> {
    if raw.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "path must not be empty".into()));
    }
    if raw.as_bytes().contains(&0u8) {
        return Err((
            StatusCode::BAD_REQUEST,
            "path must not contain NUL bytes".into(),
        ));
    }
    let p = FsPath::new(raw);
    for comp in p.components() {
        if matches!(comp, Component::ParentDir) {
            return Err((
                StatusCode::BAD_REQUEST,
                "path must not contain '..' components".into(),
            ));
        }
    }
    // Block well-known system locations. Compare on the lexical form so we
    // don't follow symlinks during validation.
    if let Some(s) = p.to_str() {
        for prefix in FORBIDDEN_PATH_PREFIXES {
            if s == *prefix || s.starts_with(&format!("{}/", prefix)) {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("path under {} is not permitted", prefix),
                ));
            }
        }
    }
    Ok(())
}

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

#[derive(Debug, Deserialize)]
struct KeyExpiryRequest {
    /// RFC 3339 timestamp; pass `null` to remove the expiry.
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KeyUsageRequest {
    /// List of allowed usages (e.g. ["sign", "encrypt"]); pass `null` or an
    /// empty list to clear all usage constraints.
    usages: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AuditExportRequest {
    destination: String,
}

const MAX_UPLOAD_BYTES: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
//
// The platform server defaults to *token-based* authentication, modelled on
// Jupyter Notebook: a random token is generated at launch and printed once
// in the startup banner. Clients must include it in either:
//
//   * the `Authorization: Bearer <token>` header, or
//   * the `?token=<value>` query parameter (intended only for the initial
//     browser hand-off; the URL is otherwise replaced by header-based auth).
//
// `/health` and `/static/*` are intentionally exempt — `/health` so that
// reverse proxies and container orchestrators can probe liveness without
// credentials, and the static asset bundle so the SPA can boot before the
// user authenticates.

/// Generate a fresh 32-byte URL-safe random token.
pub fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Wait for the conventional shutdown signals: Ctrl+C on every platform, and
/// SIGTERM additionally on Unix. Returns once either fires so callers can
/// initiate a graceful drain.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Initialise tracing for the web platform.
///
/// Reads the `RUST_LOG` env var (default: `hb_zayfer=info,tower_http=info`),
/// emits structured logs to stderr, and is safe to call multiple times —
/// subsequent calls are no-ops once a global subscriber is installed.
fn init_tracing() {
    use std::sync::Once;
    use tracing_subscriber::{fmt, EnvFilter};
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("hb_zayfer=info,tower_http=info"));
        let _ = fmt()
            .with_env_filter(filter)
            .with_target(false)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

/// Ensure a self-signed certificate exists under the Zayfer config
/// directory and return `(cert_path, key_path)` suitable for passing to
/// [`serve_with_auth`].
///
/// The cert is created on first call and reused thereafter. The certificate
/// includes Subject Alternative Names for `localhost`, `127.0.0.1`, `::1`,
/// and the bind host (when not already covered). The private key file is
/// created with `0600` permissions on Unix.
///
/// This is intended for **local development only** — browsers will warn
/// until the certificate is added to the trust store.
pub fn ensure_self_signed_cert(host: &str) -> Result<(String, String)> {
    use std::fs;
    use std::path::PathBuf;

    let base: PathBuf = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not resolve home directory for self-signed cert"))?
        .join(".hb_zayfer")
        .join("tls");
    fs::create_dir_all(&base)
        .with_context(|| format!("Failed to create TLS directory {}", base.display()))?;
    let cert_path = base.join("self-signed.cert.pem");
    let key_path = base.join("self-signed.key.pem");

    if cert_path.exists() && key_path.exists() {
        return Ok((
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        ));
    }

    let mut sans = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if !sans.iter().any(|s| s == host) {
        sans.push(host.to_string());
    }
    let cert = rcgen::generate_simple_self_signed(sans)
        .context("Failed to generate self-signed certificate")?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("Failed to write {}", cert_path.display()))?;
    fs::write(&key_path, &key_pem)
        .with_context(|| format!("Failed to write {}", key_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to chmod {}", key_path.display()))?;
        fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("Failed to chmod {}", cert_path.display()))?;
    }

    eprintln!(
        "[hb-zayfer] Generated self-signed TLS certificate at {} (valid for localhost, 127.0.0.1, ::1, {})",
        base.display(),
        host
    );

    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

#[derive(Clone)]
struct AuthState {
    token: String,
}

async fn token_auth_middleware(
    State(auth): State<AuthState>,
    request: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Header check
    if let Some(value) = request.headers().get(header::AUTHORIZATION) {
        if let Ok(text) = value.to_str() {
            if let Some(stripped) = text.strip_prefix("Bearer ") {
                if subtle_eq(stripped.trim(), &auth.token) {
                    return Ok(next.run(request).await);
                }
            }
            // Also accept the bare token for compatibility with curl one-liners.
            if subtle_eq(text.trim(), &auth.token) {
                return Ok(next.run(request).await);
            }
        }
    }
    // Query-parameter fallback (?token=...)
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("token=") {
                let decoded = percent_decode(value).unwrap_or_else(|| value.to_string());
                if subtle_eq(&decoded, &auth.token) {
                    return Ok(next.run(request).await);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Constant-time string comparison to avoid timing attacks on the token.
fn subtle_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Minimal percent-decoding sufficient for typical token query parameters.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16)?;
                let lo = (bytes[i + 2] as char).to_digit(16)?;
                out.push(((hi << 4) | lo) as u8);
                i += 2;
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// Convenience entry point: serve with a freshly generated token.
#[allow(dead_code)]
pub fn serve(host: &str, port: u16) -> Result<()> {
    serve_with_auth(host, port, Some(generate_token()), None)
}

/// Serve with an explicit auth token (or ``None`` to disable auth entirely).
/// When ``token`` is ``Some``, the value is required on every ``/api/*`` call.
/// When ``None``, the server runs unauthenticated and prints a prominent
/// warning. The default ``serve()`` entry point always supplies a freshly
/// generated token; the unauthenticated mode must be opted into explicitly
/// by the CLI (typically via ``--no-auth``).
///
/// When ``tls`` is ``Some((cert_path, key_path))``, both files must be
/// PEM-encoded; the server then accepts only HTTPS connections.
pub fn serve_with_auth(
    host: &str,
    port: u16,
    token: Option<String>,
    tls: Option<(String, String)>,
) -> Result<()> {
    init_tracing();
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .context("Invalid host/port combination")?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to build async runtime")?;

    runtime.block_on(async move {
        let mut router = match token.as_ref() {
            Some(t) => build_authed_router(t.clone())?,
            None => build_platform_router()?,
        };
        let scheme = if tls.is_some() { "https" } else { "http" };
        if tls.is_some() {
            router = router.layer(middleware::from_fn(hsts_middleware));
        }
        print_startup_banner(addr, token.as_deref(), scheme);
        match tls {
            Some((cert_path, key_path)) => {
                // Install the ring-based crypto provider once. Idempotent:
                // a second call returns Err(()), which we ignore — that just
                // means another part of the process already installed one.
                let _ = rustls::crypto::ring::default_provider().install_default();
                let config =
                    axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                        .await
                        .with_context(|| {
                            format!("Failed to load TLS cert={cert_path} key={key_path}")
                        })?;
                let handle = axum_server::Handle::new();
                let shutdown_handle = handle.clone();
                tokio::spawn(async move {
                    shutdown_signal().await;
                    eprintln!("[hb-zayfer] shutdown signal received, draining connections...");
                    shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
                });
                axum_server::bind_rustls(addr, config)
                    .handle(handle)
                    .serve(router.into_make_service())
                    .await
                    .context("Rust web server (TLS) failed")?;
            }
            None => {
                let listener = tokio::net::TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("Failed to bind {}", addr))?;
                axum::serve(listener, router)
                    .with_graceful_shutdown(shutdown_signal())
                    .await
                    .context("Rust web server failed")?;
            }
        }
        Ok(())
    })
}

fn print_startup_banner(addr: SocketAddr, token: Option<&str>, scheme: &str) {
    println!("Starting Rust web platform on {}://{}", scheme, addr);
    match token {
        Some(t) => {
            println!();
            println!("    To access, use this URL (the token grants full API access):");
            println!("        {}://{}/?token={}", scheme, addr, t);
            println!();
            println!("    Or send the token via header:");
            println!("        Authorization: Bearer {}", t);
            println!();
        }
        None => {
            eprintln!();
            eprintln!("WARNING: authentication is DISABLED for this session.");
            eprintln!(
                "         Anyone able to reach {} can perform privileged",
                addr
            );
            eprintln!("         cryptographic operations. Use --no-auth only on a");
            eprintln!("         trusted host bound to a loopback interface.");
            eprintln!();
        }
    }
}

/// Build the platform router with token authentication enforced on every
/// `/api/*` route. `/health`, the SPA fallback, and `/static/*` remain
/// unauthenticated so that liveness probes and the initial asset bundle
/// can load before the user signs in.
pub fn build_authed_router(token: String) -> Result<Router> {
    let base = build_platform_router()?;
    // We can't easily split a built router; instead, we attach the auth layer
    // to a copy of every /api route. The cleanest approach is to apply
    // middleware at the top level and short-circuit non-/api requests.
    let auth_state = AuthState { token };
    Ok(base.layer(middleware::from_fn_with_state(auth_state, api_only_auth)))
}

async fn api_only_auth(
    State(auth): State<AuthState>,
    request: HttpRequest<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    if path.starts_with("/api/") {
        return token_auth_middleware(State(auth), request, next).await;
    }
    Ok(next.run(request).await)
}

pub fn build_platform_router() -> Result<Router> {
    let state = ServerState {
        info: AppInfo::current(),
    };

    let mut router = Router::new()
        .route("/health", get(health_handler))
        .route("/healthz", get(healthz_handler))
        .route("/readyz", get(readyz_handler))
        .route("/api/version", get(api_version_handler))
        .route("/api/status", get(api_status_handler))
        .route("/api/keys", get(api_keys_handler))
        .route("/api/keys/:fingerprint", delete(api_delete_key_handler))
        .route("/api/keys/:fingerprint/public", get(api_public_key_handler))
        .route(
            "/api/keys/:fingerprint/expiry",
            put(api_set_key_expiry_handler),
        )
        .route(
            "/api/keys/:fingerprint/usage",
            put(api_set_key_usage_handler),
        )
        .route("/api/keys/expiring", get(api_expiring_keys_handler))
        .route(
            "/api/contacts",
            get(api_contacts_handler).post(api_add_contact_handler),
        )
        .route("/api/contacts/:name", delete(api_remove_contact_handler))
        .route("/api/contacts/link", post(api_link_contact_handler))
        .route("/api/config", get(api_config_handler))
        .route("/api/audit/count", get(api_audit_count_handler))
        .route("/api/audit/recent", get(api_audit_recent_handler))
        .route("/api/audit/stream", get(api_audit_stream_handler))
        .route("/api/audit/verify", get(api_audit_verify_handler))
        .route("/api/audit/export", post(api_audit_export_handler))
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

    Ok(router
        .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES + 1024 * 1024))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        ))
}

/// Apply a small set of conservative security headers to every response.
///
/// - `X-Content-Type-Options: nosniff` — block MIME sniffing.
/// - `X-Frame-Options: DENY` — refuse framing.
/// - `Referrer-Policy: no-referrer` — never leak the URL on outbound clicks.
/// - `Cross-Origin-Opener-Policy: same-origin` — isolate the SPA.
/// - `Permissions-Policy` — deny powerful APIs we don't need.
async fn security_headers_middleware(request: HttpRequest<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    use axum::http::HeaderValue;
    headers
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry(header::X_FRAME_OPTIONS)
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("cross-origin-opener-policy")
        .or_insert(HeaderValue::from_static("same-origin"));
    headers
        .entry("permissions-policy")
        .or_insert(HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        ));
    response
}

/// Strict-Transport-Security: only ever applied when the server is bound over
/// TLS. Browsers must never receive HSTS over plaintext, and we don't want to
/// pin clients to HTTPS when the operator hasn't configured a certificate.
async fn hsts_middleware(request: HttpRequest<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    use axum::http::HeaderValue;
    response
        .headers_mut()
        .entry(header::STRICT_TRANSPORT_SECURITY)
        .or_insert(HeaderValue::from_static(
            "max-age=31536000; includeSubDomains",
        ));
    response
}

async fn health_handler(State(state): State<ServerState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "brand_name": state.info.brand_name,
        "version": state.info.version,
    }))
}

/// Lightweight liveness probe. Returns `200 OK` with the literal body
/// `ok` so orchestrators (systemd, Kubernetes, Docker healthchecks) can
/// check the process without parsing JSON. Intentionally does no I/O.
async fn healthz_handler() -> &'static str {
    "ok"
}

/// Readiness probe. Verifies the on-disk keystore is reachable so the
/// server only reports "ready" once it can actually serve key-backed
/// API calls. Returns `200 OK` with body `ready` on success, or
/// `503 Service Unavailable` with the underlying error message.
async fn readyz_handler() -> Result<&'static str, (StatusCode, String)> {
    match KeyStore::open_default() {
        Ok(_) => Ok("ready"),
        Err(e) => Err((StatusCode::SERVICE_UNAVAILABLE, e.to_string())),
    }
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

/// Server-Sent Events stream of new audit entries.
///
/// On connect, the server sends the most recent 20 entries as a backlog so
/// clients have immediate context, then polls the audit log on a fixed
/// cadence and emits any entry whose `entry_hash` it has not already sent.
/// Each SSE event has `event: audit` and a JSON payload matching the shape
/// of `/api/audit/recent`. A keep-alive comment is sent every 15 seconds.
async fn api_audit_stream_handler() -> Result<
    Sse<impl futures_util::Stream<Item = Result<Event, std::convert::Infallible>>>,
    (StatusCode, String),
> {
    use std::collections::HashSet;
    use std::time::Duration;
    // Validate up-front so the client gets a clean error rather than a
    // half-open SSE connection that immediately dies.
    let _ = AuditLogger::default_location().map_err(internal_err)?;

    let stream = async_stream::stream! {
        let mut seen: HashSet<String> = HashSet::new();
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        // First tick fires immediately so the backlog ships without delay.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut bootstrapped = false;
        loop {
            interval.tick().await;
            let logger = match AuditLogger::default_location() {
                Ok(l) => l,
                Err(_) => continue,
            };
            // On first iteration, fetch a backlog of 20; subsequently poll
            // a slightly larger window to catch bursts between ticks.
            let n = if bootstrapped { 50 } else { 20 };
            let entries = match logger.recent_entries(n) {
                Ok(e) => e,
                Err(_) => continue,
            };
            bootstrapped = true;
            for e in entries {
                if !seen.insert(e.entry_hash.clone()) {
                    continue;
                }
                let payload = serde_json::json!({
                    "timestamp": e.timestamp.to_rfc3339(),
                    "operation": format!("{:?}", e.operation),
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                    "note": e.note,
                });
                let event = Event::default()
                    .event("audit")
                    .json_data(payload)
                    .unwrap_or_else(|_| Event::default().event("audit").data("{}"));
                yield Ok::<_, std::convert::Infallible>(event);
            }
            // Bound memory: forget hashes once we've tracked many entries.
            // The append-only log guarantees we won't re-emit in practice
            // because we only consider the most recent N on each tick.
            if seen.len() > 1024 {
                seen.clear();
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
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
    // Cap concurrent expensive keygen operations to protect the host CPU.
    let _permit = keygen_semaphore().try_acquire().map_err(|_| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            "keygen is busy; retry shortly".to_string(),
        )
    })?;
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

async fn api_set_key_expiry_handler(
    Path(fingerprint): Path<String>,
    Json(req): Json<KeyExpiryRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use chrono::{DateTime, Utc};
    let parsed: Option<DateTime<Utc>> = match req.expires_at.as_deref() {
        None | Some("") => None,
        Some(ts) => Some(
            DateTime::parse_from_rfc3339(ts)
                .map_err(|e| {
                    (
                        StatusCode::BAD_REQUEST,
                        format!("invalid RFC 3339 timestamp: {e}"),
                    )
                })?
                .with_timezone(&Utc),
        ),
    };
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore
        .set_key_expiry(&fingerprint, parsed)
        .map_err(bad_request_err)?;
    Ok(Json(json!({
        "status": "ok",
        "fingerprint": fingerprint,
        "expires_at": req.expires_at,
    })))
}

async fn api_set_key_usage_handler(
    Path(fingerprint): Path<String>,
    Json(req): Json<KeyUsageRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use hb_zayfer_core::keystore::KeyUsage;
    fn parse_usage(s: &str) -> Result<KeyUsage, (StatusCode, String)> {
        match s {
            "encrypt" => Ok(KeyUsage::Encrypt),
            "decrypt" => Ok(KeyUsage::Decrypt),
            "sign" => Ok(KeyUsage::Sign),
            "verify" => Ok(KeyUsage::Verify),
            "key_agreement" | "key-agreement" => Ok(KeyUsage::KeyAgreement),
            other => Err((
                StatusCode::BAD_REQUEST,
                format!("unknown key usage: {other}"),
            )),
        }
    }
    let usages: Option<Vec<KeyUsage>> = match req.usages {
        None => None,
        Some(list) if list.is_empty() => None,
        Some(list) => Some(
            list.iter()
                .map(|s| parse_usage(s))
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };
    let mut keystore = KeyStore::open_default().map_err(internal_err)?;
    keystore
        .set_key_usage(&fingerprint, usages)
        .map_err(bad_request_err)?;
    Ok(Json(json!({ "status": "ok", "fingerprint": fingerprint })))
}

#[derive(Debug, Deserialize)]
struct ExpiringKeysQuery {
    /// Warning horizon in days; defaults to 30.
    days: Option<u32>,
}

async fn api_expiring_keys_handler(
    axum::extract::Query(q): axum::extract::Query<ExpiringKeysQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use hb_zayfer_core::keystore::KeyExpiryStatus;
    let keystore = KeyStore::open_default().map_err(internal_err)?;
    let warning_days = q.days.unwrap_or(30);
    let results = keystore.check_expiring_keys(warning_days);
    let out: Vec<serde_json::Value> = results
        .into_iter()
        .map(|(meta, status)| {
            let (state, days_left) = match status {
                KeyExpiryStatus::Expired => ("expired", None),
                KeyExpiryStatus::ExpiringSoon { days_left } => ("expiring_soon", Some(days_left)),
            };
            json!({
                "fingerprint": meta.fingerprint,
                "label": meta.label,
                "algorithm": meta.algorithm,
                "expires_at": meta.expires_at.map(|d| d.to_rfc3339()),
                "state": state,
                "days_left": days_left,
            })
        })
        .collect();
    Ok(Json(json!({ "warning_days": warning_days, "keys": out })))
}

async fn api_audit_export_handler(
    Json(req): Json<AuditExportRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    validate_user_path(&req.destination)?;
    let logger = AuditLogger::default_location().map_err(internal_err)?;
    logger
        .export(std::path::Path::new(&req.destination))
        .map_err(internal_err)?;
    Ok(Json(
        json!({ "status": "exported", "destination": req.destination }),
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
    validate_user_path(&req.output_path)?;
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
    validate_user_path(&req.backup_path)?;
    let manifest =
        hb_zayfer_core::services::verify_backup_archive(&req.backup_path, &req.passphrase)
            .map_err(bad_request_err)?;
    Ok(Json(backup_manifest_json(&manifest)))
}

async fn api_backup_restore_handler(
    Json(req): Json<RestoreRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    validate_user_path(&req.backup_path)?;
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
    async fn oversize_request_is_rejected() {
        // Send a body larger than MAX_UPLOAD_BYTES + headroom; axum should
        // reject it via the DefaultBodyLimit layer with 413 Payload Too Large.
        let router = build_platform_router().unwrap();
        let oversize = vec![0u8; MAX_UPLOAD_BYTES + 2 * 1024 * 1024];
        let request = Request::builder()
            .uri("/api/encrypt/text")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(oversize))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn version_endpoint_includes_security_headers() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/version")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let h = response.headers();
        assert_eq!(
            h.get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            h.get("x-frame-options").and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            h.get("referrer-policy").and_then(|v| v.to_str().ok()),
            Some("no-referrer")
        );
    }

    #[tokio::test]
    async fn audit_stream_returns_event_stream() {
        // Verify the endpoint negotiates the SSE content-type and responds
        // OK. We don't read the body to avoid blocking on the long-lived
        // stream.
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/audit/stream")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.starts_with("text/event-stream"),
            "expected SSE content-type, got: {ct}"
        );
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

    // -------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn authed_router_rejects_missing_token() {
        let router = build_authed_router("test-token-abc".into()).unwrap();
        let request = Request::builder()
            .uri("/api/version")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authed_router_rejects_wrong_token() {
        let router = build_authed_router("expected".into()).unwrap();
        let request = Request::builder()
            .uri("/api/version")
            .header("authorization", "Bearer wrong")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn authed_router_accepts_bearer_header() {
        let router = build_authed_router("good-token".into()).unwrap();
        let request = Request::builder()
            .uri("/api/version")
            .header("authorization", "Bearer good-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authed_router_accepts_query_token() {
        let router = build_authed_router("good-token".into()).unwrap();
        let request = Request::builder()
            .uri("/api/version?token=good-token")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authed_router_allows_health_unauthenticated() {
        let router = build_authed_router("anything".into()).unwrap();
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authed_router_allows_healthz_unauthenticated() {
        let router = build_authed_router("anything".into()).unwrap();
        let request = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_returns_plain_ok_body() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"ok");
    }

    #[test]
    fn generate_token_yields_unique_hex() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn subtle_eq_constant_time_basic_equality() {
        assert!(subtle_eq("abc", "abc"));
        assert!(!subtle_eq("abc", "abd"));
        assert!(!subtle_eq("abc", "ab"));
        assert!(!subtle_eq("", "x"));
    }

    // -------------------------------------------------------------------
    // Path validation (defence-in-depth against traversal)
    // -------------------------------------------------------------------

    #[test]
    fn validate_user_path_accepts_normal_paths() {
        assert!(validate_user_path("/tmp/zayfer/backup.hbzf").is_ok());
        assert!(validate_user_path("relative/sub/file.hbzf").is_ok());
        assert!(validate_user_path("/home/alice/backups/2026.hbzf").is_ok());
    }

    #[test]
    fn validate_user_path_rejects_empty() {
        let err = validate_user_path("").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_user_path_rejects_null_byte() {
        let err = validate_user_path("/tmp/foo\0.hbzf").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_user_path_rejects_parent_traversal() {
        let err = validate_user_path("/tmp/../etc/passwd").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let err = validate_user_path("backups/../../secret").unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_user_path_rejects_sensitive_roots() {
        for bad in [
            "/etc/passwd",
            "/proc/self/mem",
            "/sys/kernel",
            "/dev/sda",
            "/root/.ssh/id_rsa",
            "/boot/grub.cfg",
            "/var/log/syslog",
        ] {
            let err = validate_user_path(bad).unwrap_err();
            assert_eq!(err.0, StatusCode::FORBIDDEN, "expected 403 for {}", bad);
        }
    }

    #[tokio::test]
    async fn backup_create_rejects_traversal_path() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/backup/create")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"output_path":"/etc/zayfer.hbzf","passphrase":"x"}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn backup_create_rejects_traversal_path_async() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/backup/create")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"output_path":"/tmp/../etc/x.hbzf","passphrase":"x"}"#,
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // -------------------------------------------------------------------
    // Key lifecycle endpoints
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn set_key_expiry_rejects_invalid_timestamp() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/keys/deadbeef/expiry")
            .method(Method::PUT)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"expires_at":"not-a-date"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn set_key_usage_rejects_unknown_usage() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/keys/deadbeef/usage")
            .method(Method::PUT)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"usages":["bogus"]}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn expiring_keys_returns_object_with_warning_window() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/keys/expiring?days=7")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["warning_days"], 7);
        assert!(json["keys"].is_array());
    }

    #[tokio::test]
    async fn audit_export_rejects_traversal() {
        let router = build_platform_router().unwrap();
        let request = Request::builder()
            .uri("/api/audit/export")
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"destination":"/etc/zayfer-audit.json"}"#))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
