//! Shamir's Secret Sharing — split a secret into `n` shares requiring `k` to
//! reconstruct.
//!
//! Uses GF(2^8) arithmetic (the same finite field as AES) for byte-level
//! operations.  Secrets of arbitrary length are split byte-by-byte; each share
//! is the same length as the original secret plus a 1-byte x-coordinate header.
//!
//! # Examples
//! ```
//! use hb_zayfer_core::shamir::{split, combine};
//!
//! let secret = b"super secret passphrase";
//! let shares = split(secret, 5, 3).expect("split failed");
//! assert_eq!(shares.len(), 5);
//!
//! // Any 3 shares can reconstruct
//! let recovered = combine(&shares[..3]).expect("combine failed");
//! assert_eq!(&recovered, secret);
//! ```

use crate::error::{HbError, HbResult};
use rand::RngCore;
use rand_core::OsRng;

// ─────────────── GF(2^8) arithmetic (same field as AES) ──────────────

/// GF(2^8) addition is XOR.
fn gf_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// GF(2^8) multiplication via the Russian-peasant algorithm with
/// irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11B).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1B; // reduce modulo x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    result
}

/// Precomputed GF(2^8) multiplicative inverse lookup table.
/// Entry `i` = inverse of `i` in GF(2^8), with `gf_inv(0) = 0` by convention.
/// This is significantly faster than the Fermat exponentiation approach.
const GF_INV_TABLE: [u8; 256] = {
    let mut table = [0u8; 256];
    // Build using Fermat's little theorem: a^254 = a^(-1) in GF(2^8)
    let mut i: usize = 1;
    while i < 256 {
        let a = i as u8;
        let mut power = a;
        let mut acc: u8 = 1;
        let mut exp: u32 = 254;
        while exp > 0 {
            if exp & 1 != 0 {
                // acc = gf_mul(acc, power) inlined for const context
                let mut r: u8 = 0;
                let mut aa = acc;
                let mut bb = power;
                let mut j = 0;
                while j < 8 {
                    if bb & 1 != 0 { r ^= aa; }
                    let high = aa & 0x80;
                    aa <<= 1;
                    if high != 0 { aa ^= 0x1B; }
                    bb >>= 1;
                    j += 1;
                }
                acc = r;
            }
            // power = gf_mul(power, power) inlined for const context
            {
                let mut r: u8 = 0;
                let mut aa = power;
                let mut bb = power;
                let mut j = 0;
                while j < 8 {
                    if bb & 1 != 0 { r ^= aa; }
                    let high = aa & 0x80;
                    aa <<= 1;
                    if high != 0 { aa ^= 0x1B; }
                    bb >>= 1;
                    j += 1;
                }
                power = r;
            }
            exp >>= 1;
        }
        table[i] = acc;
        i += 1;
    }
    table
};

/// GF(2^8) multiplicative inverse via precomputed lookup table.
/// Returns 0 for input 0 by convention.
fn gf_inv(a: u8) -> u8 {
    GF_INV_TABLE[a as usize]
}

/// Evaluate polynomial at point `x` in GF(2^8).
/// `coeffs[0]` is the constant term (the secret byte).
fn eval_poly(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf_add(gf_mul(result, x), c);
    }
    result
}

// ─────────────── Public API ──────────────────────────────────────────

/// A single share: `(x, data)` where `x` is the share's distinct non-zero
/// x-coordinate and `data` is the evaluated polynomial at `x` for each
/// byte of the secret.
#[derive(Debug, Clone)]
pub struct Share {
    /// The x-coordinate of this share (1..=255).
    pub x: u8,
    /// The share data (same length as the original secret).
    pub data: Vec<u8>,
}

/// Split `secret` into `n` shares, requiring any `k` shares to reconstruct.
///
/// # Constraints
/// - `2 <= k <= n <= 255`
/// - `secret` must not be empty
pub fn split(secret: &[u8], n: u8, k: u8) -> HbResult<Vec<Share>> {
    if secret.is_empty() {
        return Err(HbError::InvalidFormat("Secret must not be empty".into()));
    }
    if k < 2 || n < k {
        return Err(HbError::InvalidFormat(
            format!("Invalid parameters: need 2 <= k <= n <= 255, got k={k}, n={n}"),
        ));
    }

    let mut rng = OsRng;
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share { x, data: Vec::with_capacity(secret.len()) })
        .collect();

    // For each byte of the secret, generate a random polynomial of degree k-1
    // with the secret byte as the constant term, then evaluate at each share's x.
    let mut coeffs = vec![0u8; k as usize];

    for &secret_byte in secret {
        coeffs[0] = secret_byte;
        // Random coefficients for degrees 1..k-1
        rng.fill_bytes(&mut coeffs[1..]);

        for share in shares.iter_mut() {
            share.data.push(eval_poly(&coeffs, share.x));
        }
    }

    Ok(shares)
}

/// Reconstruct the secret from `k` or more shares using Lagrange interpolation.
///
/// The first `shares[0].data.len()` bytes are reconstructed; all shares must
/// have the same data length.
pub fn combine(shares: &[Share]) -> HbResult<Vec<u8>> {
    if shares.is_empty() {
        return Err(HbError::InvalidFormat("No shares provided".into()));
    }
    let len = shares[0].data.len();
    if shares.iter().any(|s| s.data.len() != len) {
        return Err(HbError::InvalidFormat("All shares must have the same length".into()));
    }

    // Check for duplicate x-coordinates
    let mut xs: Vec<u8> = shares.iter().map(|s| s.x).collect();
    xs.sort();
    xs.dedup();
    if xs.len() != shares.len() {
        return Err(HbError::InvalidFormat("Duplicate share x-coordinates".into()));
    }

    let mut secret = Vec::with_capacity(len);
    let k = shares.len();

    for byte_idx in 0..len {
        // Lagrange interpolation at x = 0
        let mut value = 0u8;
        for i in 0..k {
            let xi = shares[i].x;
            let yi = shares[i].data[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            let mut basis = 1u8;
            for j in 0..k {
                if i == j { continue; }
                let xj = shares[j].x;
                // L_i(0) = prod(0 - xj) / (xi - xj) = prod(xj) / prod(xi ^ xj)
                // In GF(2^8): 0 - xj = xj, and xi - xj = xi ^ xj
                let num = xj;
                let den = gf_add(xi, xj);
                basis = gf_mul(basis, gf_mul(num, gf_inv(den)));
            }
            value = gf_add(value, gf_mul(yi, basis));
        }
        secret.push(value);
    }

    Ok(secret)
}

/// Encode a share into portable bytes: `[x][data...]`
pub fn encode_share(share: &Share) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + share.data.len());
    out.push(share.x);
    out.extend_from_slice(&share.data);
    out
}

/// Decode a share from its portable byte representation.
pub fn decode_share(bytes: &[u8]) -> HbResult<Share> {
    if bytes.len() < 2 {
        return Err(HbError::InvalidFormat("Share too short".into()));
    }
    Ok(Share {
        x: bytes[0],
        data: bytes[1..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_identity() {
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
        }
    }

    #[test]
    fn test_gf_inv_roundtrip() {
        for a in 1..=255u8 {
            let inv = gf_inv(a);
            assert_eq!(gf_mul(a, inv), 1, "a={a}, inv={inv}");
        }
    }

    #[test]
    fn test_split_combine_basic() {
        let secret = b"hello world";
        let shares = split(secret, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);
        // Any 3 shares should reconstruct
        let recovered = combine(&shares[0..3]).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_split_combine_all_subsets() {
        let secret = b"test123";
        let shares = split(secret, 4, 3).unwrap();

        // All 4-choose-3 subsets should work
        let subsets = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 2, 3],
            vec![1, 2, 3],
        ];
        for sub in subsets {
            let selected: Vec<Share> = sub.iter().map(|&i| shares[i].clone()).collect();
            let recovered = combine(&selected).unwrap();
            assert_eq!(&recovered, secret, "Failed with subset {:?}", sub);
        }
    }

    #[test]
    fn test_two_shares_insufficient_for_threshold_3() {
        let secret = b"secret";
        let shares = split(secret, 5, 3).unwrap();
        // 2 shares should NOT reconstruct correctly (probabilistically)
        let recovered = combine(&shares[0..2]).unwrap();
        // Very unlikely to match by chance for multi-byte secrets
        assert_ne!(&recovered, secret);
    }

    #[test]
    fn test_split_combine_large() {
        let secret: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let shares = split(&secret, 10, 5).unwrap();
        let recovered = combine(&shares[2..7]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_encode_decode_share() {
        let secret = b"abc";
        let shares = split(secret, 3, 2).unwrap();
        let encoded = encode_share(&shares[0]);
        let decoded = decode_share(&encoded).unwrap();
        assert_eq!(decoded.x, shares[0].x);
        assert_eq!(decoded.data, shares[0].data);
    }

    #[test]
    fn test_invalid_params() {
        assert!(split(b"hi", 1, 2).is_err()); // n < k
        assert!(split(b"hi", 3, 1).is_err()); // k < 2
        assert!(split(b"", 3, 2).is_err());   // empty secret
    }
}
