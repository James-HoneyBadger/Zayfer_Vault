//! Optional compression layer for data before encryption.
//!
//! Provides transparent deflate compression that can be applied to plaintext
//! before encryption. A 1-byte magic prefix distinguishes compressed data so
//! the decompression path can detect and handle it automatically.
//!
//! # Wire format
//! ```text
//! [1B] 0x00 = uncompressed | 0x01 = deflate-compressed
//! [...] payload (raw or deflate stream)
//! ```
//!
//! # Usage
//! ```rust
//! use hb_zayfer_core::compression;
//!
//! let original = b"Hello, world! ".repeat(100);
//! let compressed = compression::compress(&original).unwrap();
//! assert!(compressed.len() < original.len());
//!
//! let decompressed = compression::decompress(&compressed).unwrap();
//! assert_eq!(decompressed, original);
//! ```

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::error::{HbError, HbResult};

/// Magic byte for compressed payloads.
const COMPRESSED_MAGIC: u8 = 0x01;
/// Magic byte for uncompressed payloads.
const UNCOMPRESSED_MAGIC: u8 = 0x00;

/// Compress `data` using deflate.
///
/// Returns a buffer with a 1-byte header (`0x01`) followed by the compressed payload.
/// If compression doesn't reduce size, returns the original with header (`0x00`).
pub fn compress(data: &[u8]) -> HbResult<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(data)
        .map_err(|e| HbError::Io(format!("Compression write failed: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| HbError::Io(format!("Compression finish failed: {e}")))?;

    // Only use compressed form if it's actually smaller
    if compressed.len() < data.len() {
        let mut out = Vec::with_capacity(1 + compressed.len());
        out.push(COMPRESSED_MAGIC);
        out.extend_from_slice(&compressed);
        Ok(out)
    } else {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(UNCOMPRESSED_MAGIC);
        out.extend_from_slice(data);
        Ok(out)
    }
}

/// Decompress data produced by [`compress`].
///
/// Reads the 1-byte header to determine whether the payload is compressed.
pub fn decompress(data: &[u8]) -> HbResult<Vec<u8>> {
    if data.is_empty() {
        return Err(HbError::InvalidFormat("Empty compressed payload".into()));
    }

    match data[0] {
        UNCOMPRESSED_MAGIC => Ok(data[1..].to_vec()),
        COMPRESSED_MAGIC => {
            let mut decoder = DeflateDecoder::new(&data[1..]);
            let mut decompressed = Vec::new();
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| HbError::Io(format!("Decompression failed: {e}")))?;
            Ok(decompressed)
        }
        other => Err(HbError::InvalidFormat(format!(
            "Unknown compression header byte: 0x{other:02x}"
        ))),
    }
}

/// Check if data should be compressed based on threshold.
///
/// Returns `true` if the data length exceeds the threshold, indicating
/// compression may be beneficial.
pub fn should_compress(data_len: u64, threshold: Option<u64>) -> bool {
    match threshold {
        Some(t) => data_len >= t,
        None => false,
    }
}

/// Compress data only if it exceeds the threshold.
///
/// Returns the (possibly compressed) data. The result is always decompressible
/// via [`decompress`] regardless of whether compression was applied.
pub fn maybe_compress(data: &[u8], threshold: Option<u64>) -> HbResult<Vec<u8>> {
    if should_compress(data.len() as u64, threshold) {
        compress(data)
    } else {
        // Still prefix with uncompressed magic for consistent decompression
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(UNCOMPRESSED_MAGIC);
        out.extend_from_slice(data);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_roundtrip() {
        let data = b"Hello, HB_Zayfer! ".repeat(100);
        let compressed = compress(&data).unwrap();
        // Should be smaller than original (highly compressible repeated data)
        assert!(compressed.len() < data.len());
        assert_eq!(compressed[0], COMPRESSED_MAGIC);

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_incompressible_data_stays_uncompressed() {
        // Random-looking data that won't compress well
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let result = compress(&data).unwrap();
        // Header should indicate uncompressed since deflate overhead > savings
        assert_eq!(result[0], UNCOMPRESSED_MAGIC);
        assert_eq!(&result[1..], &data[..]);

        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_maybe_compress_below_threshold() {
        let data = b"short data";
        let result = maybe_compress(data, Some(1024)).unwrap();
        assert_eq!(result[0], UNCOMPRESSED_MAGIC);
        assert_eq!(&result[1..], data);

        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_maybe_compress_above_threshold() {
        let data = b"repeating content! ".repeat(200);
        let result = maybe_compress(&data, Some(100)).unwrap();
        assert_eq!(result[0], COMPRESSED_MAGIC);

        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_maybe_compress_no_threshold() {
        let data = b"no compression configured";
        let result = maybe_compress(data, None).unwrap();
        assert_eq!(result[0], UNCOMPRESSED_MAGIC);

        let decompressed = decompress(&result).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_decompress_empty_fails() {
        assert!(decompress(&[]).is_err());
    }

    #[test]
    fn test_decompress_bad_header_fails() {
        assert!(decompress(&[0xFF, 0x01, 0x02]).is_err());
    }

    #[test]
    fn test_should_compress() {
        assert!(!should_compress(100, None));
        assert!(!should_compress(100, Some(200)));
        assert!(should_compress(200, Some(200)));
        assert!(should_compress(300, Some(200)));
    }
}
