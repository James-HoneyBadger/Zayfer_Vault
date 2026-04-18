//! Secure memory utilities for protecting sensitive key material.
//!
//! Provides [`SecureBytes`], a wrapper around `Vec<u8>` that:
//! - Locks the backing memory with `mlock(2)` to prevent swapping to disk
//! - Zeroizes the buffer on drop via [`zeroize::Zeroize`]
//! - Unlocks the memory after zeroization
//!
//! # Platform notes
//! - On Unix: uses `libc::mlock` / `libc::munlock`.
//! - On other platforms: falls back to zeroize-only (no mlock).

use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// A secure byte buffer that is locked in physical memory and zeroized on drop.
///
/// Use this for storing symmetric keys, passphrases, and other sensitive
/// material that should never be written to swap.
///
/// # Example
/// ```
/// use hb_zayfer_core::secure_mem::SecureBytes;
///
/// let key = SecureBytes::new(vec![0xAA; 32]);
/// assert_eq!(key.len(), 32);
/// // Memory is mlocked and will be zeroized when `key` is dropped.
/// ```
pub struct SecureBytes {
    inner: Vec<u8>,
    locked: bool,
}

impl SecureBytes {
    /// Create a new `SecureBytes` by taking ownership of `data` and locking it.
    pub fn new(data: Vec<u8>) -> Self {
        let locked = mlock_buf(&data);
        Self {
            inner: data,
            locked,
        }
    }

    /// Create a zero-filled `SecureBytes` of the given length, already locked.
    pub fn zeroed(len: usize) -> Self {
        Self::new(vec![0u8; len])
    }

    /// Consume self and return the inner bytes **without** zeroizing.
    ///
    /// The caller takes responsibility for the plaintext material.
    pub fn into_inner(mut self) -> Vec<u8> {
        // Unlock before transferring ownership
        if self.locked {
            munlock_buf(&self.inner);
            self.locked = false;
        }
        let v = std::mem::take(&mut self.inner);
        // Prevent the Drop impl from zeroizing the now-empty vec
        std::mem::forget(self);
        v
    }
}

impl Deref for SecureBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zeroize the buffer contents before freeing
        self.inner.zeroize();
        // Unlock the memory region
        if self.locked {
            munlock_buf(&self.inner);
        }
    }
}

impl Clone for SecureBytes {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBytes")
            .field("len", &self.inner.len())
            .field("locked", &self.locked)
            .finish()
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

// ---------------------------------------------------------------------------
// Platform-specific mlock / munlock
// ---------------------------------------------------------------------------

/// Attempt to lock a buffer's memory pages from being swapped.
/// Returns `true` if successful.
#[cfg(unix)]
fn mlock_buf(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    // SAFETY: buf is a valid, allocated region; mlock is safe on owned memory.
    unsafe { libc::mlock(buf.as_ptr() as *const libc::c_void, buf.len()) == 0 }
}

/// Unlock previously locked memory pages.
#[cfg(unix)]
fn munlock_buf(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: same region that was mlocked.
    unsafe {
        libc::munlock(buf.as_ptr() as *const libc::c_void, buf.len());
    }
}

#[cfg(not(unix))]
fn mlock_buf(_buf: &[u8]) -> bool {
    false // no-op on non-Unix
}

#[cfg(not(unix))]
fn munlock_buf(_buf: &[u8]) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes_new_and_drop() {
        let data = vec![0xAB; 64];
        let sb = SecureBytes::new(data);
        assert_eq!(sb.len(), 64);
        assert_eq!(sb[0], 0xAB);
        // Drop happens implicitly — just verify no panic
    }

    #[test]
    fn test_secure_bytes_zeroed() {
        let sb = SecureBytes::zeroed(32);
        assert_eq!(sb.len(), 32);
        assert!(sb.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_bytes_into_inner() {
        let original = vec![1, 2, 3, 4, 5];
        let sb = SecureBytes::new(original.clone());
        let recovered = sb.into_inner();
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_secure_bytes_deref() {
        let sb = SecureBytes::new(vec![10, 20, 30]);
        let slice: &[u8] = &sb;
        assert_eq!(slice, &[10, 20, 30]);
    }

    #[test]
    fn test_secure_bytes_deref_mut() {
        let mut sb = SecureBytes::new(vec![0u8; 4]);
        sb[0] = 0xFF;
        sb[3] = 0x01;
        assert_eq!(&*sb, &[0xFF, 0, 0, 0x01]);
    }

    #[test]
    fn test_secure_bytes_clone() {
        let sb = SecureBytes::new(vec![42; 16]);
        let sb2 = sb.clone();
        assert_eq!(&*sb, &*sb2);
    }
}
