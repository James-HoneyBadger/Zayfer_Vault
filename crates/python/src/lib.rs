//! PyO3 bindings for the HB_Zayfer encryption suite.
//!
//! Exposes all core cryptographic operations to Python via the `hb_zayfer._native` module.
//! Key interchange format:
//! - RSA / Ed25519 keys: PEM strings
//! - X25519 keys: raw 32-byte `bytes`
//! - PGP keys: ASCII-armored strings
//!
//! Heavy crypto operations release the GIL via `py.detach()`.

use std::io::Cursor;
use std::path::PathBuf;

use pyo3::exceptions::{
    PyFileNotFoundError, PyOSError, PyPermissionError, PyRuntimeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use hb_zayfer_core::{
    aes_gcm, audit, chacha20, ed25519 as ed, error::HbError, format, kdf, keystore, openpgp,
    passgen, qr, rsa as hrsa, shamir, shred, stego, x25519 as x,
};

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map core `HbError` variants to semantically appropriate Python exceptions.
fn to_py(e: HbError) -> PyErr {
    match &e {
        // Wrong passphrase / auth failure → PermissionError
        HbError::InvalidPassphrase | HbError::AuthenticationFailed => {
            PyPermissionError::new_err(e.to_string())
        }
        // Key / contact not found → FileNotFoundError (lookup miss)
        HbError::KeyNotFound(_) | HbError::ContactNotFound(_) => {
            PyFileNotFoundError::new_err(e.to_string())
        }
        // I/O errors → OSError
        HbError::Io(_) => PyOSError::new_err(e.to_string()),
        // Invalid input data → ValueError
        HbError::InvalidKeyFormat(_)
        | HbError::InvalidFormat(_)
        | HbError::UnsupportedVersion(_)
        | HbError::UnsupportedAlgorithm(_)
        | HbError::PassphraseRequired
        | HbError::KeyAlreadyExists(_)
        | HbError::ContactAlreadyExists(_)
        | HbError::Config(_)
        | HbError::Serialization(_) => PyValueError::new_err(e.to_string()),
        // Crypto-internal failures → RuntimeError
        _ => PyRuntimeError::new_err(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Symmetric encryption: AES-256-GCM
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt. Returns (nonce, ciphertext) as bytes.
#[pyfunction]
fn aes_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let k = key.to_vec();
    let p = plaintext.to_vec();
    let a = aad.to_vec();
    let (nonce, ct) = py.detach(|| aes_gcm::encrypt(&k, &p, &a)).map_err(to_py)?;
    Ok((PyBytes::new(py, &nonce), PyBytes::new(py, &ct)))
}

/// AES-256-GCM decrypt. Returns plaintext bytes.
#[pyfunction]
fn aes_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let k = key.to_vec();
    let n = nonce.to_vec();
    let c = ciphertext.to_vec();
    let a = aad.to_vec();
    let pt = py
        .detach(|| aes_gcm::decrypt(&k, &n, &c, &a))
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &pt))
}

// ---------------------------------------------------------------------------
// Symmetric encryption: ChaCha20-Poly1305
// ---------------------------------------------------------------------------

/// ChaCha20-Poly1305 encrypt. Returns (nonce, ciphertext) as bytes.
#[pyfunction]
fn chacha_encrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let k = key.to_vec();
    let p = plaintext.to_vec();
    let a = aad.to_vec();
    let (nonce, ct) = py.detach(|| chacha20::encrypt(&k, &p, &a)).map_err(to_py)?;
    Ok((PyBytes::new(py, &nonce), PyBytes::new(py, &ct)))
}

/// ChaCha20-Poly1305 decrypt. Returns plaintext bytes.
#[pyfunction]
fn chacha_decrypt<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let k = key.to_vec();
    let n = nonce.to_vec();
    let c = ciphertext.to_vec();
    let a = aad.to_vec();
    let pt = py
        .detach(|| chacha20::decrypt(&k, &n, &c, &a))
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &pt))
}

// ---------------------------------------------------------------------------
// Key Derivation
// ---------------------------------------------------------------------------

/// Generate a random salt of the given length.
#[pyfunction]
fn generate_salt<'py>(py: Python<'py>, length: usize) -> Bound<'py, PyBytes> {
    let s = kdf::generate_salt(length);
    PyBytes::new(py, &s)
}

/// Derive a 32-byte key via Argon2id.
#[pyfunction]
#[pyo3(signature = (passphrase, salt, m_cost=65536, t_cost=3, p_cost=1))]
fn derive_key_argon2<'py>(
    py: Python<'py>,
    passphrase: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let pw = passphrase.to_vec();
    let s = salt.to_vec();
    let params = kdf::KdfParams::Argon2id(kdf::Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    });
    let key = py
        .detach(move || kdf::derive_key(&pw, &s, &params))
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &key))
}

/// Derive a 32-byte key via scrypt.
#[pyfunction]
#[pyo3(signature = (passphrase, salt, log_n=15, r=8, p=1))]
fn derive_key_scrypt<'py>(
    py: Python<'py>,
    passphrase: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> PyResult<Bound<'py, PyBytes>> {
    let pw = passphrase.to_vec();
    let s = salt.to_vec();
    let params = kdf::KdfParams::Scrypt(kdf::ScryptParams { log_n, r, p });
    let key = py
        .detach(move || kdf::derive_key(&pw, &s, &params))
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &key))
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// Generate an RSA key pair. Returns (private_pem, public_pem).
#[pyfunction]
fn rsa_generate(py: Python<'_>, bits: usize) -> PyResult<(String, String)> {
    let size = match bits {
        2048 => hrsa::RsaKeySize::Rsa2048,
        4096 => hrsa::RsaKeySize::Rsa4096,
        _ => return Err(PyValueError::new_err("bits must be 2048 or 4096")),
    };
    let kp = py.detach(|| hrsa::generate_keypair(size)).map_err(to_py)?;
    let priv_pem = hrsa::export_private_key_pem(&kp.private_key).map_err(to_py)?;
    let pub_pem = hrsa::export_public_key_pem(&kp.public_key).map_err(to_py)?;
    Ok((priv_pem, pub_pem))
}

/// RSA-OAEP encrypt (SHA-256). Input & output are bytes.
#[pyfunction]
fn rsa_encrypt<'py>(
    py: Python<'py>,
    public_pem: &str,
    plaintext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let pk = hrsa::import_public_key_pem(public_pem).map_err(to_py)?;
    let pt = plaintext.to_vec();
    let ct = py.detach(move || hrsa::encrypt(&pk, &pt)).map_err(to_py)?;
    Ok(PyBytes::new(py, &ct))
}

/// RSA-OAEP decrypt (SHA-256). Returns plaintext bytes.
#[pyfunction]
fn rsa_decrypt<'py>(
    py: Python<'py>,
    private_pem: &str,
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = hrsa::import_private_key_pem(private_pem).map_err(to_py)?;
    let ct = ciphertext.to_vec();
    let pt = py.detach(move || hrsa::decrypt(&sk, &ct)).map_err(to_py)?;
    Ok(PyBytes::new(py, &pt))
}

/// RSA PKCS#1 v1.5 sign (SHA-256). Returns signature bytes.
#[pyfunction]
fn rsa_sign<'py>(
    py: Python<'py>,
    private_pem: &str,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = hrsa::import_private_key_pem(private_pem).map_err(to_py)?;
    let msg = message.to_vec();
    let sig = py.detach(move || hrsa::sign(&sk, &msg)).map_err(to_py)?;
    Ok(PyBytes::new(py, &sig))
}

/// RSA PKCS#1 v1.5 verify. Returns True if valid.
#[pyfunction]
fn rsa_verify(
    py: Python<'_>,
    public_pem: &str,
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    let pk = hrsa::import_public_key_pem(public_pem).map_err(to_py)?;
    let msg = message.to_vec();
    let sig = signature.to_vec();
    py.detach(move || hrsa::verify(&pk, &msg, &sig))
        .map_err(to_py)
}

/// Compute RSA public key fingerprint (SHA-256 hex).
#[pyfunction]
fn rsa_fingerprint(public_pem: &str) -> PyResult<String> {
    let pk = hrsa::import_public_key_pem(public_pem).map_err(to_py)?;
    hrsa::fingerprint(&pk).map_err(to_py)
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Generate an Ed25519 key pair. Returns (signing_pem, verifying_pem).
#[pyfunction]
fn ed25519_generate() -> PyResult<(String, String)> {
    let kp = ed::generate_keypair();
    let sk_pem = ed::export_signing_key_pem(&kp.signing_key).map_err(to_py)?;
    let vk_pem = ed::export_verifying_key_pem(&kp.verifying_key).map_err(to_py)?;
    Ok((sk_pem, vk_pem))
}

/// Ed25519 sign. Returns 64-byte signature.
#[pyfunction]
fn ed25519_sign<'py>(
    py: Python<'py>,
    signing_pem: &str,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = ed::import_signing_key_pem(signing_pem).map_err(to_py)?;
    let sig = ed::sign(&sk, message);
    Ok(PyBytes::new(py, &sig))
}

/// Ed25519 verify. Returns True if valid.
#[pyfunction]
fn ed25519_verify(verifying_pem: &str, message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let vk = ed::import_verifying_key_pem(verifying_pem).map_err(to_py)?;
    ed::verify(&vk, message, signature).map_err(to_py)
}

/// Compute Ed25519 public key fingerprint (SHA-256 hex).
#[pyfunction]
fn ed25519_fingerprint(verifying_pem: &str) -> PyResult<String> {
    let vk = ed::import_verifying_key_pem(verifying_pem).map_err(to_py)?;
    Ok(ed::fingerprint(&vk))
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

/// Generate an X25519 key pair. Returns (secret_raw_32, public_raw_32).
#[pyfunction]
fn x25519_generate<'py>(py: Python<'py>) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
    let kp = x::generate_keypair();
    let sk = x::export_secret_key_raw(&kp.secret_key);
    let pk = x::export_public_key_raw(&kp.public_key);
    (PyBytes::new(py, &sk), PyBytes::new(py, &pk))
}

/// X25519 encrypt-side key agreement.
/// Returns (ephemeral_public_32, symmetric_key_32).
#[pyfunction]
fn x25519_encrypt_key_agreement<'py>(
    py: Python<'py>,
    their_public: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let pk = x::import_public_key_raw(their_public).map_err(to_py)?;
    let (eph, sym) = x::encrypt_key_agreement(&pk).map_err(to_py)?;
    let eph_bytes = x::export_public_key_raw(&eph);
    Ok((PyBytes::new(py, &eph_bytes), PyBytes::new(py, &sym)))
}

/// X25519 decrypt-side key agreement.
/// Returns 32-byte symmetric key.
#[pyfunction]
fn x25519_decrypt_key_agreement<'py>(
    py: Python<'py>,
    secret_raw: &[u8],
    ephemeral_public: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sk = x::import_secret_key_raw(secret_raw).map_err(to_py)?;
    let eph = x::import_public_key_raw(ephemeral_public).map_err(to_py)?;
    let sym = x::decrypt_key_agreement(&sk, &eph).map_err(to_py)?;
    Ok(PyBytes::new(py, &sym))
}

/// X25519 public key fingerprint.
#[pyfunction]
fn x25519_fingerprint(public_raw: &[u8]) -> PyResult<String> {
    let pk = x::import_public_key_raw(public_raw).map_err(to_py)?;
    Ok(x::fingerprint(&pk))
}

// ---------------------------------------------------------------------------
// OpenPGP
// ---------------------------------------------------------------------------

/// Generate a PGP certificate. Returns (public_armored, secret_armored).
#[pyfunction]
fn pgp_generate(py: Python<'_>, user_id: &str) -> PyResult<(String, String)> {
    let uid = user_id.to_string();
    let cert = py
        .detach(move || openpgp::generate_cert(&uid))
        .map_err(to_py)?;
    let pub_armor = openpgp::export_public_key(&cert).map_err(to_py)?;
    let sec_armor = openpgp::export_secret_key(&cert).map_err(to_py)?;
    Ok((pub_armor, sec_armor))
}

/// PGP encrypt a message to one or more recipients.
/// `recipient_public_keys` is a list of ASCII-armored public keys.
#[pyfunction]
fn pgp_encrypt<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    recipient_public_keys: Vec<String>,
) -> PyResult<Bound<'py, PyBytes>> {
    let pt = plaintext.to_vec();
    let ct = py
        .detach(move || {
            let certs: Vec<_> = recipient_public_keys
                .iter()
                .map(|k| openpgp::import_cert(k))
                .collect::<Result<Vec<_>, _>>()?;
            let cert_refs: Vec<&_> = certs.iter().collect();
            openpgp::encrypt_message(&pt, &cert_refs)
        })
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &ct))
}

/// PGP decrypt a message with a secret key.
#[pyfunction]
fn pgp_decrypt<'py>(
    py: Python<'py>,
    ciphertext: &[u8],
    secret_key_armored: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let ct = ciphertext.to_vec();
    let sk = secret_key_armored.to_string();
    let pt = py
        .detach(move || {
            let cert = openpgp::import_cert(&sk)?;
            openpgp::decrypt_message(&ct, &[cert])
        })
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &pt))
}

/// PGP sign a message. Returns signed message bytes.
#[pyfunction]
fn pgp_sign<'py>(
    py: Python<'py>,
    message: &[u8],
    secret_key_armored: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let msg = message.to_vec();
    let sk = secret_key_armored.to_string();
    let signed = py
        .detach(move || {
            let cert = openpgp::import_cert(&sk)?;
            openpgp::sign_message(&msg, &cert)
        })
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &signed))
}

/// PGP verify a signed message. Returns (message, valid).
#[pyfunction]
fn pgp_verify<'py>(
    py: Python<'py>,
    signed_message: &[u8],
    public_key_armored: &str,
) -> PyResult<(Bound<'py, PyBytes>, bool)> {
    let sm = signed_message.to_vec();
    let pk = public_key_armored.to_string();
    let (msg, valid) = py
        .detach(move || {
            let cert = openpgp::import_cert(&pk)?;
            openpgp::verify_message(&sm, &[cert])
        })
        .map_err(to_py)?;
    Ok((PyBytes::new(py, &msg), valid))
}

/// PGP certificate fingerprint.
#[pyfunction]
fn pgp_fingerprint(armored_key: &str) -> PyResult<String> {
    let cert = openpgp::import_cert(armored_key).map_err(to_py)?;
    Ok(openpgp::cert_fingerprint(&cert))
}

/// PGP certificate user ID.
#[pyfunction]
fn pgp_user_id(armored_key: &str) -> PyResult<Option<String>> {
    let cert = openpgp::import_cert(armored_key).map_err(to_py)?;
    Ok(openpgp::cert_user_id(&cert))
}

// ---------------------------------------------------------------------------
// HBZF file encryption / decryption helpers
// ---------------------------------------------------------------------------

/// Encrypt data in-memory using the HBZF streaming format.
///
/// `algorithm`: "aes" or "chacha"
/// `wrapping`: "password", "rsa", or "x25519"
///
/// For password mode: provide `passphrase`.
/// For RSA mode: provide `recipient_public_pem`.
/// For X25519 mode: provide `recipient_public_raw` (32 bytes).
///
/// Returns the encrypted HBZF blob.
/// Build KDF parameters from the Python-facing keyword arguments.
fn build_kdf_params(
    kdf: &str,
    kdf_memory_kib: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_log_n: Option<u8>,
    kdf_r: Option<u32>,
    kdf_p: Option<u32>,
) -> PyResult<kdf::KdfParams> {
    match kdf {
        "argon2id" | "argon2" => {
            let mem = kdf_memory_kib.unwrap_or(64 * 1024);
            if mem < 8 * 1024 {
                return Err(PyValueError::new_err(
                    "kdf_memory_kib must be at least 8192 (8 MiB) for Argon2id",
                ));
            }
            let iters = kdf_iterations.unwrap_or(3);
            if iters < 1 {
                return Err(PyValueError::new_err("kdf_iterations must be at least 1"));
            }
            Ok(kdf::KdfParams::argon2id(mem, iters, 1))
        }
        "scrypt" => {
            let log_n = kdf_log_n.unwrap_or(15);
            if log_n < 14 {
                return Err(PyValueError::new_err(
                    "kdf_log_n must be at least 14 for scrypt",
                ));
            }
            let r = kdf_r.unwrap_or(8);
            let p = kdf_p.unwrap_or(1);
            Ok(kdf::KdfParams::scrypt(log_n, r, p))
        }
        _ => Err(PyValueError::new_err("kdf must be 'argon2id' or 'scrypt'")),
    }
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    plaintext,
    algorithm = "aes",
    wrapping = "password",
    passphrase = None,
    recipient_public_pem = None,
    recipient_public_raw = None,
    kdf = "argon2id",
    kdf_memory_kib = None,
    kdf_iterations = None,
    kdf_log_n = None,
    kdf_r = None,
    kdf_p = None,
))]
fn encrypt_data<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    algorithm: &str,
    wrapping: &str,
    passphrase: Option<&[u8]>,
    recipient_public_pem: Option<&str>,
    recipient_public_raw: Option<&[u8]>,
    kdf: &str,
    kdf_memory_kib: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_log_n: Option<u8>,
    kdf_r: Option<u32>,
    kdf_p: Option<u32>,
) -> PyResult<Bound<'py, PyBytes>> {
    let algo = match algorithm {
        "aes" => format::SymmetricAlgorithm::Aes256Gcm,
        "chacha" => format::SymmetricAlgorithm::ChaCha20Poly1305,
        _ => return Err(PyValueError::new_err("algorithm must be 'aes' or 'chacha'")),
    };

    let pt = plaintext.to_vec();

    // Build EncryptParams based on wrapping mode
    let params = match wrapping {
        "password" => {
            let pw = passphrase
                .ok_or_else(|| PyValueError::new_err("passphrase required for password mode"))?;
            let kdf_params =
                build_kdf_params(kdf, kdf_memory_kib, kdf_iterations, kdf_log_n, kdf_r, kdf_p)?;
            let salt = kdf::generate_salt(16);
            let key = kdf::derive_key(pw, &salt, &kdf_params).map_err(to_py)?;
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::Password,
                symmetric_key: key,
                kdf_params: Some(kdf_params),
                kdf_salt: Some(salt),
                wrapped_key: None,
                ephemeral_public: None,
                chunk_size: None,
                compress: false,
            }
        }
        "rsa" => {
            let pem = recipient_public_pem.ok_or_else(|| {
                PyValueError::new_err("recipient_public_pem required for RSA mode")
            })?;
            let pk = hrsa::import_public_key_pem(pem).map_err(to_py)?;
            // Generate random symmetric key, wrap it with RSA-OAEP
            let sym_key = kdf::generate_salt(32); // random 32 bytes
            let wrapped = hrsa::encrypt(&pk, &sym_key).map_err(to_py)?;
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::RsaOaep,
                symmetric_key: sym_key,
                kdf_params: None,
                kdf_salt: None,
                wrapped_key: Some(wrapped),
                ephemeral_public: None,
                chunk_size: None,
                compress: false,
            }
        }
        "x25519" => {
            let raw = recipient_public_raw.ok_or_else(|| {
                PyValueError::new_err("recipient_public_raw required for X25519 mode")
            })?;
            let pk = x::import_public_key_raw(raw).map_err(to_py)?;
            let (eph, sym_key) = x::encrypt_key_agreement(&pk).map_err(to_py)?;
            let eph_bytes = x::export_public_key_raw(&eph);
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::X25519Ecdh,
                symmetric_key: sym_key.to_vec(),
                kdf_params: None,
                kdf_salt: None,
                wrapped_key: None,
                ephemeral_public: Some(eph_bytes),
                chunk_size: None,
                compress: false,
            }
        }
        _ => {
            return Err(PyValueError::new_err(
                "wrapping must be 'password', 'rsa', or 'x25519'",
            ))
        }
    };

    let result = py
        .detach(move || {
            let mut out = Vec::new();
            let mut reader = Cursor::new(&pt);
            format::encrypt_stream(&mut reader, &mut out, &params, pt.len() as u64, None)?;
            Ok::<_, HbError>(out)
        })
        .map_err(to_py)?;

    Ok(PyBytes::new(py, &result))
}

/// Decrypt an HBZF blob in memory.
///
/// Provide the appropriate key material for the wrapping mode stored in the header:
/// - password: `passphrase`
/// - rsa: `private_pem`
/// - x25519: `secret_raw` (32 bytes)
///
/// Returns plaintext bytes.
#[pyfunction]
#[pyo3(signature = (
    data,
    passphrase = None,
    private_pem = None,
    secret_raw = None,
))]
fn decrypt_data<'py>(
    py: Python<'py>,
    data: &[u8],
    passphrase: Option<&[u8]>,
    private_pem: Option<&str>,
    secret_raw: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    let blob = data.to_vec();
    let pw = passphrase.map(|b| b.to_vec());
    let pem = private_pem.map(|s| s.to_string());
    let sr = secret_raw.map(|b| b.to_vec());

    let result = py
        .detach(move || {
            let mut cursor = Cursor::new(&blob);
            let header = format::read_header(&mut cursor)?;

            // Recover symmetric key based on wrapping mode
            let sym_key = match header.wrapping {
                format::KeyWrapping::Password => {
                    let pw = pw.ok_or(HbError::PassphraseRequired)?;
                    let kdf_params = header
                        .kdf_params
                        .as_ref()
                        .ok_or_else(|| HbError::InvalidFormat("Missing KDF params".into()))?;
                    let salt = header
                        .kdf_salt
                        .as_ref()
                        .ok_or_else(|| HbError::InvalidFormat("Missing KDF salt".into()))?;
                    kdf::derive_key(&pw, salt, kdf_params)?
                }
                format::KeyWrapping::RsaOaep => {
                    let pem = pem.ok_or_else(|| {
                        HbError::InvalidFormat("private_pem required for RSA mode".into())
                    })?;
                    let sk = hrsa::import_private_key_pem(&pem)?;
                    let wrapped = header.wrapped_key.as_ref().ok_or_else(|| {
                        HbError::InvalidFormat("Missing wrapped key in header".into())
                    })?;
                    hrsa::decrypt(&sk, wrapped)?
                }
                format::KeyWrapping::X25519Ecdh => {
                    let sr = sr.ok_or_else(|| {
                        HbError::InvalidFormat("secret_raw required for X25519 mode".into())
                    })?;
                    let sk = x::import_secret_key_raw(&sr)?;
                    let eph_bytes = header.ephemeral_public.as_ref().ok_or_else(|| {
                        HbError::InvalidFormat("Missing ephemeral public key".into())
                    })?;
                    let eph = x::import_public_key_raw(eph_bytes)?;
                    let sym = x::decrypt_key_agreement(&sk, &eph)?;
                    sym.to_vec()
                }
            };

            let mut plaintext = Vec::new();
            format::decrypt_stream(&mut cursor, &mut plaintext, &header, &sym_key, None)?;
            Ok::<_, HbError>(plaintext)
        })
        .map_err(to_py)?;

    Ok(PyBytes::new(py, &result))
}

/// Encrypt a file on disk using the HBZF format.
///
/// Same parameter semantics as `encrypt_data` but operates on file paths.
/// Returns the number of bytes written.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
#[pyo3(signature = (
    input_path,
    output_path,
    algorithm = "aes",
    wrapping = "password",
    passphrase = None,
    recipient_public_pem = None,
    recipient_public_raw = None,
    kdf = "argon2id",
    kdf_memory_kib = None,
    kdf_iterations = None,
    kdf_log_n = None,
    kdf_r = None,
    kdf_p = None,
))]
fn encrypt_file(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    algorithm: &str,
    wrapping: &str,
    passphrase: Option<&[u8]>,
    recipient_public_pem: Option<&str>,
    recipient_public_raw: Option<&[u8]>,
    kdf: &str,
    kdf_memory_kib: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_log_n: Option<u8>,
    kdf_r: Option<u32>,
    kdf_p: Option<u32>,
) -> PyResult<u64> {
    let algo = match algorithm {
        "aes" => format::SymmetricAlgorithm::Aes256Gcm,
        "chacha" => format::SymmetricAlgorithm::ChaCha20Poly1305,
        _ => return Err(PyValueError::new_err("algorithm must be 'aes' or 'chacha'")),
    };

    let params = match wrapping {
        "password" => {
            let pw = passphrase
                .ok_or_else(|| PyValueError::new_err("passphrase required for password mode"))?;
            let kdf_params =
                build_kdf_params(kdf, kdf_memory_kib, kdf_iterations, kdf_log_n, kdf_r, kdf_p)?;
            let salt = kdf::generate_salt(16);
            let key = kdf::derive_key(pw, &salt, &kdf_params).map_err(to_py)?;
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::Password,
                symmetric_key: key,
                kdf_params: Some(kdf_params),
                kdf_salt: Some(salt),
                wrapped_key: None,
                ephemeral_public: None,
                chunk_size: None,
                compress: false,
            }
        }
        "rsa" => {
            let pem = recipient_public_pem.ok_or_else(|| {
                PyValueError::new_err("recipient_public_pem required for RSA mode")
            })?;
            let pk = hrsa::import_public_key_pem(pem).map_err(to_py)?;
            let sym_key = kdf::generate_salt(32);
            let wrapped = hrsa::encrypt(&pk, &sym_key).map_err(to_py)?;
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::RsaOaep,
                symmetric_key: sym_key,
                kdf_params: None,
                kdf_salt: None,
                wrapped_key: Some(wrapped),
                ephemeral_public: None,
                chunk_size: None,
                compress: false,
            }
        }
        "x25519" => {
            let raw = recipient_public_raw.ok_or_else(|| {
                PyValueError::new_err("recipient_public_raw required for X25519 mode")
            })?;
            let pk = x::import_public_key_raw(raw).map_err(to_py)?;
            let (eph, sym_key) = x::encrypt_key_agreement(&pk).map_err(to_py)?;
            let eph_bytes = x::export_public_key_raw(&eph);
            format::EncryptParams {
                algorithm: algo,
                wrapping: format::KeyWrapping::X25519Ecdh,
                symmetric_key: sym_key.to_vec(),
                kdf_params: None,
                kdf_salt: None,
                wrapped_key: None,
                ephemeral_public: Some(eph_bytes),
                chunk_size: None,
                compress: false,
            }
        }
        _ => {
            return Err(PyValueError::new_err(
                "wrapping must be 'password', 'rsa', or 'x25519'",
            ))
        }
    };

    let inp = input_path.to_string();
    let outp = output_path.to_string();

    py.detach(move || {
        let metadata = std::fs::metadata(&inp).map_err(|e| HbError::Io(e.to_string()))?;
        let file_len = metadata.len();
        let mut reader = std::fs::File::open(&inp)?;
        let mut writer = std::fs::File::create(&outp)?;
        format::encrypt_stream(&mut reader, &mut writer, &params, file_len, None)?;
        let out_len = std::fs::metadata(&outp)?.len();
        Ok::<_, HbError>(out_len)
    })
    .map_err(to_py)
}

/// Decrypt an HBZF file on disk.
///
/// Returns the number of plaintext bytes written.
#[pyfunction]
#[pyo3(signature = (
    input_path,
    output_path,
    passphrase = None,
    private_pem = None,
    secret_raw = None,
))]
fn decrypt_file(
    py: Python<'_>,
    input_path: &str,
    output_path: &str,
    passphrase: Option<&[u8]>,
    private_pem: Option<&str>,
    secret_raw: Option<&[u8]>,
) -> PyResult<u64> {
    let pw = passphrase.map(|b| b.to_vec());
    let pem = private_pem.map(|s| s.to_string());
    let sr = secret_raw.map(|b| b.to_vec());
    let inp = input_path.to_string();
    let outp = output_path.to_string();

    py.detach(move || {
        let mut reader = std::fs::File::open(&inp)?;
        let header = format::read_header(&mut reader)?;

        let sym_key = match header.wrapping {
            format::KeyWrapping::Password => {
                let pw = pw.ok_or(HbError::PassphraseRequired)?;
                let kdf_params = header
                    .kdf_params
                    .as_ref()
                    .ok_or_else(|| HbError::InvalidFormat("Missing KDF params".into()))?;
                let salt = header
                    .kdf_salt
                    .as_ref()
                    .ok_or_else(|| HbError::InvalidFormat("Missing KDF salt".into()))?;
                kdf::derive_key(&pw, salt, kdf_params)?
            }
            format::KeyWrapping::RsaOaep => {
                let pem = pem.ok_or_else(|| {
                    HbError::InvalidFormat("private_pem required for RSA mode".into())
                })?;
                let sk = hrsa::import_private_key_pem(&pem)?;
                let wrapped = header.wrapped_key.as_ref().ok_or_else(|| {
                    HbError::InvalidFormat("Missing wrapped key in header".into())
                })?;
                hrsa::decrypt(&sk, wrapped)?
            }
            format::KeyWrapping::X25519Ecdh => {
                let sr = sr.ok_or_else(|| {
                    HbError::InvalidFormat("secret_raw required for X25519 mode".into())
                })?;
                let sk = x::import_secret_key_raw(&sr)?;
                let eph_bytes = header
                    .ephemeral_public
                    .as_ref()
                    .ok_or_else(|| HbError::InvalidFormat("Missing ephemeral public key".into()))?;
                let eph = x::import_public_key_raw(eph_bytes)?;
                let sym = x::decrypt_key_agreement(&sk, &eph)?;
                sym.to_vec()
            }
        };

        let mut writer = std::fs::File::create(&outp)?;
        format::decrypt_stream(&mut reader, &mut writer, &header, &sym_key, None)?;
        let out_len = std::fs::metadata(&outp)?.len();
        Ok::<_, HbError>(out_len)
    })
    .map_err(to_py)
}

// ---------------------------------------------------------------------------
// KeyStore Python wrapper
// ---------------------------------------------------------------------------

/// Python wrapper for the HB_Zayfer key store.
#[pyclass(name = "KeyStore")]
struct PyKeyStore {
    inner: keystore::KeyStore,
}

#[pymethods]
impl PyKeyStore {
    /// Open the default key store at ~/.hb_zayfer/
    #[new]
    #[pyo3(signature = (path = None))]
    fn new(path: Option<&str>) -> PyResult<Self> {
        let ks = match path {
            Some(p) => keystore::KeyStore::open(PathBuf::from(p)).map_err(to_py)?,
            None => keystore::KeyStore::open_default().map_err(to_py)?,
        };
        Ok(Self { inner: ks })
    }

    /// Get the base path of the key store.
    #[getter]
    fn base_path(&self) -> String {
        self.inner.base_path().to_string_lossy().to_string()
    }

    /// Store a private key (encrypted with passphrase).
    fn store_private_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        passphrase: &[u8],
        algorithm: &str,
        label: &str,
    ) -> PyResult<()> {
        let algo = parse_key_algorithm(algorithm)?;
        self.inner
            .store_private_key(fingerprint, key_bytes, passphrase, algo, label)
            .map_err(to_py)
    }

    /// Store a public key.
    fn store_public_key(
        &mut self,
        fingerprint: &str,
        key_bytes: &[u8],
        algorithm: &str,
        label: &str,
    ) -> PyResult<()> {
        let algo = parse_key_algorithm(algorithm)?;
        self.inner
            .store_public_key(fingerprint, key_bytes, algo, label)
            .map_err(to_py)
    }

    /// Load and decrypt a private key.
    fn load_private_key<'py>(
        &self,
        py: Python<'py>,
        fingerprint: &str,
        passphrase: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self
            .inner
            .load_private_key(fingerprint, passphrase)
            .map_err(to_py)?;
        Ok(PyBytes::new(py, &data))
    }

    /// Load a public key.
    fn load_public_key<'py>(
        &self,
        py: Python<'py>,
        fingerprint: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self.inner.load_public_key(fingerprint).map_err(to_py)?;
        Ok(PyBytes::new(py, &data))
    }

    /// List all keys in the keyring.
    fn list_keys(&self) -> Vec<PyKeyMetadata> {
        self.inner
            .list_keys()
            .into_iter()
            .map(PyKeyMetadata::from_meta)
            .collect()
    }

    /// Get metadata for a specific key.
    fn get_key_metadata(&self, fingerprint: &str) -> Option<PyKeyMetadata> {
        self.inner
            .get_key_metadata(fingerprint)
            .map(PyKeyMetadata::from_meta)
    }

    /// Search keys by label substring.
    fn find_keys_by_label(&self, query: &str) -> Vec<PyKeyMetadata> {
        self.inner
            .find_keys_by_label(query)
            .into_iter()
            .map(PyKeyMetadata::from_meta)
            .collect()
    }

    /// Delete a key by fingerprint.
    fn delete_key(&mut self, fingerprint: &str) -> PyResult<()> {
        self.inner.delete_key(fingerprint).map_err(to_py)
    }

    /// Add a contact.
    #[pyo3(signature = (name, email = None, notes = None))]
    fn add_contact(
        &mut self,
        name: &str,
        email: Option<&str>,
        notes: Option<&str>,
    ) -> PyResult<()> {
        self.inner.add_contact(name, email, notes).map_err(to_py)
    }

    /// Associate a key fingerprint with a contact.
    fn associate_key_with_contact(
        &mut self,
        contact_name: &str,
        fingerprint: &str,
    ) -> PyResult<()> {
        self.inner
            .associate_key_with_contact(contact_name, fingerprint)
            .map_err(to_py)
    }

    /// Get a contact by name.
    fn get_contact(&self, name: &str) -> Option<PyContact> {
        self.inner.get_contact(name).map(PyContact::from_contact)
    }

    /// List all contacts.
    fn list_contacts(&self) -> Vec<PyContact> {
        self.inner
            .list_contacts()
            .into_iter()
            .map(PyContact::from_contact)
            .collect()
    }

    /// Remove a contact.
    fn remove_contact(&mut self, name: &str) -> PyResult<()> {
        self.inner.remove_contact(name).map_err(to_py)
    }

    /// Update a contact's email and/or notes.
    ///
    /// Pass a string to set a new value, or omit to leave unchanged.
    /// Python callers cannot clear a field to `None` via this method –
    /// remove and re-add the contact if that is needed.
    #[pyo3(signature = (name, email = None, notes = None))]
    fn update_contact(
        &mut self,
        name: &str,
        email: Option<&str>,
        notes: Option<&str>,
    ) -> PyResult<()> {
        self.inner
            .update_contact(name, email.map(Some), notes.map(Some))
            .map_err(to_py)
    }

    /// Resolve a contact name or fingerprint prefix to key fingerprints.
    fn resolve_recipient(&self, name_or_fp: &str) -> Vec<String> {
        self.inner.resolve_recipient(name_or_fp)
    }

    /// Create an encrypted backup of the keystore.
    #[pyo3(signature = (output_path, passphrase, label = None))]
    fn create_backup(
        &self,
        output_path: &str,
        passphrase: &[u8],
        label: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .create_backup(&PathBuf::from(output_path), passphrase, label)
            .map_err(to_py)
    }

    /// Restore keystore from backup into this keystore path.
    fn restore_backup(&self, backup_path: &str, passphrase: &[u8]) -> PyResult<PyBackupManifest> {
        let manifest = keystore::KeyStore::restore_backup(
            &PathBuf::from(backup_path),
            passphrase,
            self.inner.base_path(),
        )
        .map_err(to_py)?;
        Ok(PyBackupManifest::from_manifest(&manifest))
    }

    /// Verify a backup file with passphrase.
    fn verify_backup(&self, backup_path: &str, passphrase: &[u8]) -> PyResult<PyBackupManifest> {
        let manifest = keystore::KeyStore::verify_backup(&PathBuf::from(backup_path), passphrase)
            .map_err(to_py)?;
        Ok(PyBackupManifest::from_manifest(&manifest))
    }
}

/// Python representation of backup manifest.
#[pyclass(name = "BackupManifest", from_py_object)]
#[derive(Clone)]
struct PyBackupManifest {
    #[pyo3(get)]
    created_at: String,
    #[pyo3(get)]
    private_key_count: usize,
    #[pyo3(get)]
    public_key_count: usize,
    #[pyo3(get)]
    contact_count: usize,
    #[pyo3(get)]
    version: u8,
    #[pyo3(get)]
    label: Option<String>,
    #[pyo3(get)]
    integrity_hash: String,
}

impl PyBackupManifest {
    fn from_manifest(m: &hb_zayfer_core::BackupManifest) -> Self {
        Self {
            created_at: m.created_at.to_rfc3339(),
            private_key_count: m.private_key_count,
            public_key_count: m.public_key_count,
            contact_count: m.contact_count,
            version: m.version,
            label: m.label.clone(),
            integrity_hash: m.integrity_hash.clone(),
        }
    }
}

/// Python representation of an audit log entry.
#[pyclass(name = "AuditEntry", from_py_object)]
#[derive(Clone)]
struct PyAuditEntry {
    #[pyo3(get)]
    timestamp: String,
    #[pyo3(get)]
    operation: String,
    #[pyo3(get)]
    prev_hash: Option<String>,
    #[pyo3(get)]
    entry_hash: String,
    #[pyo3(get)]
    note: Option<String>,
}

impl PyAuditEntry {
    fn from_entry(e: &audit::AuditEntry) -> Self {
        Self {
            timestamp: e.timestamp.to_rfc3339(),
            operation: format!("{:?}", e.operation),
            prev_hash: e.prev_hash.clone(),
            entry_hash: e.entry_hash.clone(),
            note: e.note.clone(),
        }
    }
}

/// Python wrapper around audit logger.
#[pyclass(name = "AuditLogger")]
struct PyAuditLogger {
    inner: audit::AuditLogger,
}

#[pymethods]
impl PyAuditLogger {
    /// Create audit logger (default path if not provided).
    #[new]
    #[pyo3(signature = (path = None))]
    fn new(path: Option<&str>) -> PyResult<Self> {
        let inner = match path {
            Some(p) => audit::AuditLogger::new(PathBuf::from(p)),
            None => audit::AuditLogger::default_location().map_err(to_py)?,
        };
        Ok(Self { inner })
    }

    /// Return recent audit entries.
    #[pyo3(signature = (limit = 20))]
    fn recent_entries(&self, limit: usize) -> PyResult<Vec<PyAuditEntry>> {
        let entries = self.inner.recent_entries(limit).map_err(to_py)?;
        Ok(entries.iter().map(PyAuditEntry::from_entry).collect())
    }

    /// Verify audit log integrity chain.
    fn verify_integrity(&self) -> PyResult<bool> {
        self.inner.verify_integrity().map_err(to_py)
    }

    /// Export audit log to destination path.
    fn export(&self, destination: &str) -> PyResult<()> {
        self.inner
            .export(&PathBuf::from(destination))
            .map_err(to_py)
    }

    /// Return total number of audit entries.
    fn entry_count(&self) -> PyResult<usize> {
        self.inner.entry_count().map_err(to_py)
    }
}

// ---------------------------------------------------------------------------
// Key metadata Python wrapper
// ---------------------------------------------------------------------------

/// Python representation of key metadata.
#[pyclass(name = "KeyMetadata", from_py_object)]
#[derive(Clone)]
struct PyKeyMetadata {
    #[pyo3(get)]
    fingerprint: String,
    #[pyo3(get)]
    algorithm: String,
    #[pyo3(get)]
    label: String,
    #[pyo3(get)]
    created_at: String,
    #[pyo3(get)]
    has_private: bool,
    #[pyo3(get)]
    has_public: bool,
}

impl PyKeyMetadata {
    fn from_meta(m: &keystore::KeyMetadata) -> Self {
        Self {
            fingerprint: m.fingerprint.clone(),
            algorithm: m.algorithm.to_string(),
            label: m.label.clone(),
            created_at: m.created_at.to_rfc3339(),
            has_private: m.has_private,
            has_public: m.has_public,
        }
    }
}

#[pymethods]
impl PyKeyMetadata {
    fn __repr__(&self) -> String {
        format!(
            "KeyMetadata(fp='{}..', algo={}, label='{}')",
            &self.fingerprint[..std::cmp::min(16, self.fingerprint.len())],
            self.algorithm,
            self.label,
        )
    }
}

// ---------------------------------------------------------------------------
// Contact Python wrapper
// ---------------------------------------------------------------------------

/// Python representation of a contact.
#[pyclass(name = "Contact", from_py_object)]
#[derive(Clone)]
struct PyContact {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    email: Option<String>,
    #[pyo3(get)]
    key_fingerprints: Vec<String>,
    #[pyo3(get)]
    notes: Option<String>,
    #[pyo3(get)]
    created_at: String,
}

impl PyContact {
    fn from_contact(c: &keystore::Contact) -> Self {
        Self {
            name: c.name.clone(),
            email: c.email.clone(),
            key_fingerprints: c.key_fingerprints.clone(),
            notes: c.notes.clone(),
            created_at: c.created_at.to_rfc3339(),
        }
    }
}

#[pymethods]
impl PyContact {
    fn __repr__(&self) -> String {
        format!(
            "Contact(name='{}', keys={})",
            self.name,
            self.key_fingerprints.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn parse_key_algorithm(s: &str) -> PyResult<keystore::KeyAlgorithm> {
    match s.to_lowercase().as_str() {
        "rsa2048" | "rsa-2048" => Ok(keystore::KeyAlgorithm::Rsa2048),
        "rsa4096" | "rsa-4096" => Ok(keystore::KeyAlgorithm::Rsa4096),
        "ed25519" => Ok(keystore::KeyAlgorithm::Ed25519),
        "x25519" => Ok(keystore::KeyAlgorithm::X25519),
        "pgp" => Ok(keystore::KeyAlgorithm::Pgp),
        _ => Err(PyValueError::new_err(format!(
            "Unknown algorithm '{}'. Use: rsa2048, rsa4096, ed25519, x25519, pgp",
            s
        ))),
    }
}

/// Compute a SHA-256 fingerprint of arbitrary public key bytes.
#[pyfunction]
fn compute_fingerprint(public_key_bytes: &[u8]) -> String {
    keystore::compute_fingerprint(public_key_bytes)
}

/// Detect key format from raw data. Returns one of: "pkcs8_pem", "pkcs1_pem", "der", "openpgp", "openssh".
#[pyfunction]
fn detect_key_format(data: &[u8]) -> &'static str {
    match keystore::detect_key_format(data) {
        keystore::KeyFormat::Pkcs8Pem => "pkcs8_pem",
        keystore::KeyFormat::Pkcs1Pem => "pkcs1_pem",
        keystore::KeyFormat::Der => "der",
        keystore::KeyFormat::OpenPgpArmor => "openpgp",
        keystore::KeyFormat::OpenSsh => "openssh",
    }
}

#[pyfunction]
#[pyo3(signature = (algorithm, fingerprint, note = None))]
fn audit_log_key_generated(algorithm: &str, fingerprint: &str, note: Option<&str>) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::KeyGenerated {
                algorithm: algorithm.to_string(),
                fingerprint: fingerprint.to_string(),
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (algorithm, filename = None, size_bytes = None, note = None))]
fn audit_log_file_encrypted(
    algorithm: &str,
    filename: Option<&str>,
    size_bytes: Option<u64>,
    note: Option<&str>,
) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::FileEncrypted {
                algorithm: algorithm.to_string(),
                filename: filename.map(|s| s.to_string()),
                size_bytes,
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (algorithm, filename = None, size_bytes = None, note = None))]
fn audit_log_file_decrypted(
    algorithm: &str,
    filename: Option<&str>,
    size_bytes: Option<u64>,
    note: Option<&str>,
) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::FileDecrypted {
                algorithm: algorithm.to_string(),
                filename: filename.map(|s| s.to_string()),
                size_bytes,
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (algorithm, fingerprint, note = None))]
fn audit_log_data_signed(algorithm: &str, fingerprint: &str, note: Option<&str>) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::DataSigned {
                algorithm: algorithm.to_string(),
                fingerprint: fingerprint.to_string(),
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (algorithm, fingerprint, valid, note = None))]
fn audit_log_signature_verified(
    algorithm: &str,
    fingerprint: &str,
    valid: bool,
    note: Option<&str>,
) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::SignatureVerified {
                algorithm: algorithm.to_string(),
                fingerprint: fingerprint.to_string(),
                valid,
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (name, note = None))]
fn audit_log_contact_added(name: &str, note: Option<&str>) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::ContactAdded {
                name: name.to_string(),
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (name, note = None))]
fn audit_log_contact_deleted(name: &str, note: Option<&str>) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::ContactDeleted {
                name: name.to_string(),
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

#[pyfunction]
#[pyo3(signature = (fingerprint, note = None))]
fn audit_log_key_deleted(fingerprint: &str, note: Option<&str>) -> PyResult<()> {
    let logger = audit::AuditLogger::default_location().map_err(to_py)?;
    logger
        .log(
            audit::AuditOperation::KeyDeleted {
                fingerprint: fingerprint.to_string(),
            },
            note.map(|n| n.to_string()),
        )
        .map_err(to_py)
}

// ---------------------------------------------------------------------------
// Password / passphrase generation
// ---------------------------------------------------------------------------

/// Generate a random password.
#[pyfunction]
#[pyo3(signature = (length=20, uppercase=true, lowercase=true, digits=true, symbols=true, exclude=""))]
fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
    exclude: &str,
) -> String {
    let policy = passgen::PasswordPolicy {
        length,
        uppercase,
        lowercase,
        digits,
        symbols,
        exclude: exclude.to_string(),
    };
    passgen::generate_password(&policy)
}

/// Generate a diceware-style passphrase from a built-in word list.
#[pyfunction]
#[pyo3(signature = (words=6, separator="-"))]
fn generate_passphrase(words: usize, separator: &str) -> String {
    passgen::generate_passphrase(words, separator)
}

/// Estimate the entropy in bits of a password with the given policy.
#[pyfunction]
#[pyo3(signature = (length=20, uppercase=true, lowercase=true, digits=true, symbols=true))]
fn password_entropy(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
) -> f64 {
    let policy = passgen::PasswordPolicy {
        length,
        uppercase,
        lowercase,
        digits,
        symbols,
        exclude: String::new(),
    };
    passgen::estimate_entropy(&policy)
}

/// Estimate the entropy in bits of a diceware passphrase.
#[pyfunction]
#[pyo3(signature = (word_count=6))]
fn passphrase_entropy(word_count: usize) -> f64 {
    passgen::passphrase_entropy(word_count)
}

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing
// ---------------------------------------------------------------------------

/// Split a secret into `n` shares requiring `k` to reconstruct.
///
/// Returns a list of hex-encoded share strings.
#[pyfunction]
fn shamir_split(py: Python<'_>, secret: &[u8], n: u8, k: u8) -> PyResult<Vec<String>> {
    let secret_owned = secret.to_vec();
    let shares = py
        .detach(move || shamir::split(&secret_owned, n, k))
        .map_err(to_py)?;
    Ok(shares
        .iter()
        .map(|s| hex::encode(shamir::encode_share(s)))
        .collect())
}

/// Combine hex-encoded shares to reconstruct the secret.
#[pyfunction]
fn shamir_combine(py: Python<'_>, shares_hex: Vec<String>) -> PyResult<Py<PyBytes>> {
    let shares: Vec<shamir::Share> = shares_hex
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).map_err(|e| HbError::InvalidFormat(e.to_string()))?;
            shamir::decode_share(&bytes)
        })
        .collect::<Result<_, _>>()
        .map_err(to_py)?;
    let secret = py.detach(move || shamir::combine(&shares)).map_err(to_py)?;
    Ok(PyBytes::new(py, &secret).unbind())
}

// ---------------------------------------------------------------------------
// Steganography
// ---------------------------------------------------------------------------

/// Embed a payload into pixel data using LSB encoding.
///
/// `pixels` is a mutable copy of raw pixel bytes (e.g. RGBA).
/// Returns the modified pixel bytes.
#[pyfunction]
fn stego_embed(py: Python<'_>, pixels: &[u8], payload: &[u8]) -> PyResult<Py<PyBytes>> {
    let mut px = pixels.to_vec();
    let payload_owned = payload.to_vec();
    px = py
        .detach(move || -> Result<Vec<u8>, HbError> {
            stego::embed_in_pixels(&mut px, &payload_owned)?;
            Ok(px)
        })
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &px).unbind())
}

/// Extract a previously embedded payload from pixel data.
#[pyfunction]
fn stego_extract(py: Python<'_>, pixels: &[u8]) -> PyResult<Py<PyBytes>> {
    let px = pixels.to_vec();
    let data = py
        .detach(move || stego::extract_from_pixels(&px))
        .map_err(to_py)?;
    Ok(PyBytes::new(py, &data).unbind())
}

/// Return the maximum embeddable payload size for the given pixel buffer length.
#[pyfunction]
fn stego_capacity(pixel_len: usize) -> usize {
    stego::capacity(pixel_len)
}

// ---------------------------------------------------------------------------
// Secure file shredding
// ---------------------------------------------------------------------------

/// Securely shred (overwrite + delete) a single file.
#[pyfunction]
#[pyo3(signature = (path, passes=3))]
fn shred_file(py: Python<'_>, path: &str, passes: u32) -> PyResult<()> {
    let p = std::path::PathBuf::from(path);
    py.detach(move || shred::shred_file(&p, passes))
        .map_err(to_py)
}

/// Securely shred all files in a directory recursively. Returns count of files shredded.
#[pyfunction]
#[pyo3(signature = (path, passes=3))]
fn shred_directory(py: Python<'_>, path: &str, passes: u32) -> PyResult<usize> {
    let p = std::path::PathBuf::from(path);
    py.detach(move || shred::shred_directory(&p, passes))
        .map_err(to_py)
}

// ---------------------------------------------------------------------------
// QR key exchange URIs
// ---------------------------------------------------------------------------

/// Encode a public key as a `hbzf-key://` URI suitable for QR codes.
#[pyfunction]
#[pyo3(signature = (algorithm, public_key, label=None))]
fn qr_encode_key_uri(algorithm: &str, public_key: &[u8], label: Option<&str>) -> String {
    qr::encode_key_uri(algorithm, public_key, label)
}

/// Decode a `hbzf-key://` URI into (algorithm, public_key_bytes, label).
#[pyfunction]
fn qr_decode_key_uri(py: Python<'_>, uri: &str) -> PyResult<(String, Py<PyBytes>, Option<String>)> {
    let (algo, data, label) = qr::decode_key_uri(uri).map_err(to_py)?;
    Ok((algo, PyBytes::new(py, &data).unbind(), label))
}

/// Return the library version string.
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

/// HB_Zayfer native cryptographic operations.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Version
    m.add_function(wrap_pyfunction!(version, m)?)?;

    // Symmetric
    m.add_function(wrap_pyfunction!(aes_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(aes_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(chacha_decrypt, m)?)?;

    // KDF
    m.add_function(wrap_pyfunction!(generate_salt, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_argon2, m)?)?;
    m.add_function(wrap_pyfunction!(derive_key_scrypt, m)?)?;

    // RSA
    m.add_function(wrap_pyfunction!(rsa_generate, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_sign, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_verify, m)?)?;
    m.add_function(wrap_pyfunction!(rsa_fingerprint, m)?)?;

    // Ed25519
    m.add_function(wrap_pyfunction!(ed25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_fingerprint, m)?)?;

    // X25519
    m.add_function(wrap_pyfunction!(x25519_generate, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_encrypt_key_agreement, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_decrypt_key_agreement, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_fingerprint, m)?)?;

    // OpenPGP
    m.add_function(wrap_pyfunction!(pgp_generate, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_sign, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_verify, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(pgp_user_id, m)?)?;

    // HBZF file format
    m.add_function(wrap_pyfunction!(encrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_data, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_file, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_file, m)?)?;

    // Utilities
    m.add_function(wrap_pyfunction!(compute_fingerprint, m)?)?;
    m.add_function(wrap_pyfunction!(detect_key_format, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_key_generated, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_file_encrypted, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_file_decrypted, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_data_signed, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_signature_verified, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_contact_added, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_contact_deleted, m)?)?;
    m.add_function(wrap_pyfunction!(audit_log_key_deleted, m)?)?;

    // Password generation
    m.add_function(wrap_pyfunction!(generate_password, m)?)?;
    m.add_function(wrap_pyfunction!(generate_passphrase, m)?)?;
    m.add_function(wrap_pyfunction!(password_entropy, m)?)?;
    m.add_function(wrap_pyfunction!(passphrase_entropy, m)?)?;

    // Shamir's Secret Sharing
    m.add_function(wrap_pyfunction!(shamir_split, m)?)?;
    m.add_function(wrap_pyfunction!(shamir_combine, m)?)?;

    // Steganography
    m.add_function(wrap_pyfunction!(stego_embed, m)?)?;
    m.add_function(wrap_pyfunction!(stego_extract, m)?)?;
    m.add_function(wrap_pyfunction!(stego_capacity, m)?)?;

    // Secure file shredding
    m.add_function(wrap_pyfunction!(shred_file, m)?)?;
    m.add_function(wrap_pyfunction!(shred_directory, m)?)?;

    // QR key exchange
    m.add_function(wrap_pyfunction!(qr_encode_key_uri, m)?)?;
    m.add_function(wrap_pyfunction!(qr_decode_key_uri, m)?)?;

    // Classes
    m.add_class::<PyKeyStore>()?;
    m.add_class::<PyKeyMetadata>()?;
    m.add_class::<PyContact>()?;
    m.add_class::<PyBackupManifest>()?;
    m.add_class::<PyAuditEntry>()?;
    m.add_class::<PyAuditLogger>()?;

    Ok(())
}
