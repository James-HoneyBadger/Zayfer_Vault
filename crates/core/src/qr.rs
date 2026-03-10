//! QR-code–friendly key exchange helpers.
//!
//! Provides functions for encoding and decoding public keys into compact
//! URI strings suitable for QR code transmission.
//!
//! ```
//! use hb_zayfer_core::qr::{encode_key_uri, decode_key_uri};
//!
//! let uri = encode_key_uri("ed25519", &[0xAB; 32], Some("alice"));
//! assert!(uri.starts_with("hbzf-key://ed25519/"));
//! let (algo, data, label) = decode_key_uri(&uri).unwrap();
//! assert_eq!(algo, "ed25519");
//! assert_eq!(data.len(), 32);
//! assert_eq!(label, Some("alice".to_string()));
//! ```

use crate::error::HbError;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// URI scheme used for key exchange.
const SCHEME: &str = "hbzf-key://";

/// Encode a public key as a URI: `hbzf-key://<algo>/<base64url>?label=<label>`
///
/// The algorithm should be a lowercase identifier such as `ed25519`, `x25519`,
/// `rsa-2048`, etc.
pub fn encode_key_uri(algorithm: &str, public_key: &[u8], label: Option<&str>) -> String {
    let b64 = URL_SAFE_NO_PAD.encode(public_key);
    let mut uri = format!("{}{}/{}", SCHEME, algorithm, b64);
    if let Some(l) = label {
        uri.push_str("?label=");
        // Percent-encode spaces and special characters in label
        for ch in l.chars() {
            match ch {
                ' ' => uri.push_str("%20"),
                '&' => uri.push_str("%26"),
                '=' => uri.push_str("%3D"),
                '?' => uri.push_str("%3F"),
                _ => uri.push(ch),
            }
        }
    }
    uri
}

/// Decode a `hbzf-key://` URI back into (algorithm, public_key_bytes, label).
pub fn decode_key_uri(uri: &str) -> Result<(String, Vec<u8>, Option<String>), HbError> {
    if !uri.starts_with(SCHEME) {
        return Err(HbError::InvalidFormat(format!(
            "invalid key URI scheme: expected {}",
            SCHEME
        )));
    }

    let rest = &uri[SCHEME.len()..];

    // Split off query string
    let (path, query) = match rest.find('?') {
        Some(i) => (&rest[..i], Some(&rest[i + 1..])),
        None => (rest, None),
    };

    // path = "algo/base64data"
    let slash = path
        .find('/')
        .ok_or_else(|| HbError::InvalidFormat("missing / in key URI path".into()))?;

    let algorithm = &path[..slash];
    let b64 = &path[slash + 1..];

    let public_key = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| HbError::InvalidFormat(format!("bad base64 in key URI: {e}")))?;

    // Parse label from query string
    let label = query.and_then(|q| {
        for param in q.split('&') {
            if let Some(val) = param.strip_prefix("label=") {
                return Some(percent_decode(val));
            }
        }
        None
    });

    Ok((algorithm.to_string(), public_key, label))
}

/// Simple percent-decode for label values.
fn percent_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_no_label() {
        let key = vec![1u8; 32];
        let uri = encode_key_uri("x25519", &key, None);
        let (algo, data, label) = decode_key_uri(&uri).unwrap();
        assert_eq!(algo, "x25519");
        assert_eq!(data, key);
        assert!(label.is_none());
    }

    #[test]
    fn roundtrip_with_label() {
        let key = vec![0xAB; 48];
        let uri = encode_key_uri("rsa-2048", &key, Some("Bob Smith"));
        let (algo, data, label) = decode_key_uri(&uri).unwrap();
        assert_eq!(algo, "rsa-2048");
        assert_eq!(data, key);
        assert_eq!(label, Some("Bob Smith".to_string()));
    }

    #[test]
    fn bad_scheme() {
        let err = decode_key_uri("https://example.com").unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }

    #[test]
    fn missing_slash() {
        let err = decode_key_uri("hbzf-key://ed25519").unwrap_err();
        assert!(err.to_string().contains("/"));
    }

    #[test]
    fn encode_is_deterministic() {
        let key = &[9u8; 16];
        let a = encode_key_uri("ed25519", key, Some("test"));
        let b = encode_key_uri("ed25519", key, Some("test"));
        assert_eq!(a, b);
    }
}
