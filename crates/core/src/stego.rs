//! Steganography — hide data in images using LSB (Least Significant Bit)
//! encoding.
//!
//! Currently supports raw pixel data (RGBA) for embedding.  The caller is
//! responsible for loading/saving image files (e.g., via the `image` crate on
//! the CLI or Pillow on the Python side).
//!
//! Format:
//! ```text
//! [4 bytes]  Magic: "STEG"
//! [4 bytes]  Payload length (little-endian u32)
//! [N bytes]  Payload data
//! ```
//!
//! Each bit of the above byte-stream is written into the LSB of one pixel
//! channel value.  With RGBA (4 channels), each pixel stores 4 bits.
//!
//! # Example
//! ```
//! use hb_zayfer_core::stego::{embed_in_pixels, extract_from_pixels, capacity};
//!
//! let mut pixels = vec![128u8; 1000]; // 250 RGBA pixels
//! let secret = b"hidden msg";
//! let cap = capacity(pixels.len());
//! assert!(secret.len() <= cap);
//!
//! embed_in_pixels(&mut pixels, secret).unwrap();
//! let recovered = extract_from_pixels(&pixels).unwrap();
//! assert_eq!(&recovered, secret);
//! ```

use crate::error::{HbError, HbResult};

const MAGIC: &[u8; 4] = b"STEG";
/// Header size: 4 bytes magic + 4 bytes length
const HEADER_SIZE: usize = 8;

/// Return the maximum payload size (in bytes) that can be hidden in `pixel_len`
/// raw pixel bytes using single-bit LSB encoding.
pub fn capacity(pixel_len: usize) -> usize {
    // Each pixel byte stores 1 bit → pixel_len / 8 total bytes
    // Minus the 8-byte header
    if pixel_len / 8 > HEADER_SIZE {
        pixel_len / 8 - HEADER_SIZE
    } else {
        0
    }
}

/// Embed `payload` into the LSBs of `pixels` (in-place).
///
/// `pixels` is the raw pixel data (e.g., RGBA bytes).  Its length must be at
/// least `(payload.len() + 8) * 8` to hold the header + data.
pub fn embed_in_pixels(pixels: &mut [u8], payload: &[u8]) -> HbResult<()> {
    let needed_bits = (HEADER_SIZE + payload.len()) * 8;
    if needed_bits > pixels.len() {
        return Err(HbError::InvalidFormat(format!(
            "Payload ({} bytes) too large for image ({} pixel bytes, capacity {} bytes)",
            payload.len(),
            pixels.len(),
            capacity(pixels.len()),
        )));
    }
    if payload.len() > u32::MAX as usize {
        return Err(HbError::InvalidFormat("Payload too large".into()));
    }

    // Build the byte-stream: MAGIC + len(LE) + payload
    let mut stream = Vec::with_capacity(HEADER_SIZE + payload.len());
    stream.extend_from_slice(MAGIC);
    stream.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.extend_from_slice(payload);

    // Write each bit into the LSB of successive pixel bytes
    let mut bit_idx = 0usize;
    for byte in &stream {
        for bit_pos in (0..8).rev() {
            let bit = (*byte >> bit_pos) & 1;
            pixels[bit_idx] = (pixels[bit_idx] & 0xFE) | bit;
            bit_idx += 1;
        }
    }

    Ok(())
}

/// Extract the hidden payload from `pixels`.
///
/// Returns `Err` if no valid steganographic header is found.
pub fn extract_from_pixels(pixels: &[u8]) -> HbResult<Vec<u8>> {
    if pixels.len() < HEADER_SIZE * 8 {
        return Err(HbError::InvalidFormat("Image too small for stego header".into()));
    }

    // Read the header
    let header = read_bits(pixels, 0, HEADER_SIZE);
    if &header[..4] != MAGIC {
        return Err(HbError::InvalidFormat("No steganographic data found".into()));
    }

    let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let total_bits = (HEADER_SIZE + len) * 8;
    if total_bits > pixels.len() {
        return Err(HbError::InvalidFormat(format!(
            "Stego header claims {} bytes but image only has room for {}",
            len,
            capacity(pixels.len()),
        )));
    }

    let payload = read_bits(pixels, HEADER_SIZE * 8, len);
    Ok(payload)
}

/// Read `count` bytes from the LSBs of `pixels` starting at `start_bit`.
fn read_bits(pixels: &[u8], start_bit: usize, count: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(count);
    let mut bit_idx = start_bit;
    for _ in 0..count {
        let mut byte = 0u8;
        for bit_pos in (0..8).rev() {
            let bit = pixels[bit_idx] & 1;
            byte |= bit << bit_pos;
            bit_idx += 1;
        }
        result.push(byte);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embed_extract_roundtrip() {
        let mut pixels = vec![0xAA; 8000]; // 1000 RGBA pixels
        let payload = b"Hello, steganography!";
        embed_in_pixels(&mut pixels, payload).unwrap();
        let recovered = extract_from_pixels(&pixels).unwrap();
        assert_eq!(&recovered, payload);
    }

    #[test]
    fn test_capacity() {
        // 800 pixel bytes → 100 bytes total → 92 payload bytes
        assert_eq!(capacity(800), 92);
        // Too small
        assert_eq!(capacity(63), 0);
    }

    #[test]
    fn test_payload_too_large() {
        let mut pixels = vec![0; 100]; // 12 bytes capacity - 8 header = 4 payload max
        let payload = vec![0; 10];
        assert!(embed_in_pixels(&mut pixels, &payload).is_err());
    }

    #[test]
    fn test_no_stego_data() {
        let pixels = vec![0xFF; 1000]; // all 1s → magic won't match
        assert!(extract_from_pixels(&pixels).is_err());
    }

    #[test]
    fn test_empty_payload() {
        let mut pixels = vec![0x80; 200];
        embed_in_pixels(&mut pixels, b"").unwrap();
        let recovered = extract_from_pixels(&pixels).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_pixel_values_barely_changed() {
        let mut pixels: Vec<u8> = (0..=255).cycle().take(8000).collect();
        let original = pixels.clone();
        let payload = b"test data 12345";
        embed_in_pixels(&mut pixels, payload).unwrap();

        // Each pixel should differ by at most 1 (LSB flip)
        for (orig, modified) in original.iter().zip(pixels.iter()) {
            let diff = (*orig as i16 - *modified as i16).unsigned_abs();
            assert!(diff <= 1, "Pixel changed by {diff}");
        }
    }
}
