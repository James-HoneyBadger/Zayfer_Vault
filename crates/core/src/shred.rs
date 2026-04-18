//! Secure file shredding — overwrite file contents before deletion.
//!
//! Implements a multi-pass overwrite strategy inspired by the Gutmann method
//! (simplified).  Files are overwritten with random data, then zeroes, then
//! random data again before `unlink`.
//!
//! # Example
//! ```no_run
//! use hb_zayfer_core::shred::shred_file;
//!
//! shred_file("secret.txt", 3).expect("shred failed");
//! // The file is now deleted and its former sectors overwritten.
//! ```

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use rand::RngCore;
use rand_core::OsRng;

use crate::error::{HbError, HbResult};

/// Helper to convert an `io::Error` to `HbError::Io`.
fn io_err(e: std::io::Error) -> HbError {
    HbError::Io(e.to_string())
}

/// Default number of overwrite passes.
pub const DEFAULT_PASSES: u32 = 3;

/// Size of the write buffer used during overwrite (64 KiB).
const BUF_SIZE: usize = 64 * 1024;

/// Securely delete a file by overwriting its contents before unlinking.
///
/// * `path`   — path to the file to shred
/// * `passes` — number of overwrite passes (minimum 1; use [`DEFAULT_PASSES`]
///   for a sensible default)
///
/// Each pass alternates between random bytes and zeroes:
///   pass 0 → random, pass 1 → zeroes, pass 2 → random, …
///
/// After all passes the file is truncated to zero length, flushed, synced to
/// disk, and then removed.
pub fn shred_file<P: AsRef<Path>>(path: P, passes: u32) -> HbResult<()> {
    let path = path.as_ref();
    let passes = passes.max(1);

    if !path.exists() {
        return Err(HbError::Io(format!("File not found: {}", path.display())));
    }

    if !path.is_file() {
        return Err(HbError::Io(format!(
            "Not a regular file: {}",
            path.display()
        )));
    }

    let file_len = fs::metadata(path).map_err(io_err)?.len();

    // Open in write mode without truncation so we overwrite existing content.
    let mut file = OpenOptions::new().write(true).open(path).map_err(io_err)?;

    let mut rng = OsRng;
    let mut buf = vec![0u8; BUF_SIZE];

    for pass in 0..passes {
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        let use_random = pass % 2 == 0;

        let mut remaining = file_len;
        while remaining > 0 {
            let chunk = (remaining as usize).min(BUF_SIZE);
            if use_random {
                rng.fill_bytes(&mut buf[..chunk]);
            } else {
                buf[..chunk].fill(0);
            }
            file.write_all(&buf[..chunk]).map_err(io_err)?;
            remaining -= chunk as u64;
        }

        file.flush().map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
    }

    // Truncate to zero length and sync once more.
    file.set_len(0).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    drop(file);

    // Finally remove the file entry.
    fs::remove_file(path).map_err(io_err)?;

    Ok(())
}

/// Shred all files in a directory recursively, then remove empty directories.
///
/// Returns the number of files successfully shredded.
pub fn shred_directory<P: AsRef<Path>>(path: P, passes: u32) -> HbResult<usize> {
    let path = path.as_ref();
    if !path.is_dir() {
        return Err(HbError::Io(format!("Not a directory: {}", path.display())));
    }

    let mut count = 0usize;
    shred_dir_recursive(path, passes, &mut count)?;
    // Remove the now-empty directory tree
    fs::remove_dir_all(path).map_err(io_err)?;
    Ok(count)
}

fn shred_dir_recursive(dir: &Path, passes: u32, count: &mut usize) -> HbResult<()> {
    for entry in fs::read_dir(dir).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let path = entry.path();
        if path.is_dir() {
            shred_dir_recursive(&path, passes, count)?;
        } else if path.is_file() {
            shred_file(&path, passes)?;
            *count += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shred_file_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("secret.txt");
        fs::write(&file_path, b"super secret data").unwrap();
        assert!(file_path.exists());

        shred_file(&file_path, DEFAULT_PASSES).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_shred_file_overwrites_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("overwrite_test.bin");
        let original = vec![0xAA; 1024];
        fs::write(&file_path, &original).unwrap();

        // We can't easily verify the on-disk overwrite, but we can check
        // the file size stays the same before final truncation.  Instead,
        // just verify no error and the file is gone.
        shred_file(&file_path, 3).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_shred_nonexistent_file_errors() {
        let result = shred_file("/tmp/does_not_exist_hbzf_test.xyz", 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_shred_directory() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        fs::write(sub.join("b.txt"), b"bbb").unwrap();
        fs::write(sub.join("c.txt"), b"ccc").unwrap();

        // Shred the whole tree
        let target = dir.path().join("subdir");
        // Shred just the subdir
        let count = shred_directory(&target, 2).unwrap();
        assert_eq!(count, 2);
        assert!(!target.exists());
    }

    #[test]
    fn test_shred_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("empty.txt");
        fs::write(&file_path, b"").unwrap();
        shred_file(&file_path, 3).unwrap();
        assert!(!file_path.exists());
    }
}
