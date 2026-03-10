# Breaking Changes Log

**Project**: HB_Zayfer  
**Refactoring**: v0.1.0 → v0.2.0  
**Status**: Planning Phase

---

## How to Use This Document

This document tracks all breaking changes introduced during the refactoring. Each entry includes:
- **Change description** - What changed
- **Rationale** - Why we made this change
- **Impact** - Who is affected
- **Migration** - How to update your code
- **Introduced in** - Which phase/task

---

## Summary

*This section will be updated as refactoring progresses*

**Total Breaking Changes**: 0 (Planning phase)

### By Category
- **Rust API**: 0 changes
- **Python API**: 0 changes
- **CLI**: 0 changes
- **Web API**: 0 changes
- **File Format**: 0 changes
- **Configuration**: 0 changes

---

## Rust API Changes

### Error Type Restructuring

**Status**: 🟡 Planned for Phase 1, Task 1.2

**Change**:
```rust
// OLD (v0.1.0)
pub enum HbError {
    Rsa(String),
    AesGcm(String),
    Ed25519(String),
    // ... string-based errors
}

// NEW (v0.2.0)
pub enum HbError {
    Crypto(CryptoError),
    Storage(StorageError),
    Format(FormatError),
    // ... structured errors
}

pub enum CryptoError {
    KeyGenerationFailed { algorithm: String, source: Box<dyn Error> },
    EncryptionFailed { reason: String },
    InvalidKeySize { expected: usize, got: usize },
    // ... specific error variants
}
```

**Rationale**: String-based errors lose type information and context when crossing language boundaries. Structured errors provide better debugging and allow proper exception mapping in Python.

**Impact**: 
- **High** - Affects all error handling code
- **Rust crate users** - Must update error matching patterns
- **Python users** - Mostly transparent (exception types change)

**Migration**:
```rust
// Before
match result {
    Err(HbError::Rsa(msg)) => eprintln!("RSA error: {}", msg),
    // ...
}

// After
match result {
    Err(HbError::Crypto(CryptoError::KeyGenerationFailed { algorithm, .. })) => {
        eprintln!("Failed to generate {} key", algorithm)
    }
    // ...
}
```

**Deprecation Period**: N/A (error types must change immediately)

---

### Cipher API Trait-Based Refactor

**Status**: 🟡 Planned for Phase 2, Task 2.2-2.3

**Change**:
```rust
// OLD (v0.1.0)
use hb_zayfer_core::aes_gcm;
let (nonce, ciphertext) = aes_gcm::encrypt(key, plaintext, aad)?;

// NEW (v0.2.0)
use hb_zayfer_core::crypto::{Cipher, AesGcmCipher};
let cipher = AesGcmCipher::new();
let encrypted = cipher.encrypt(key, plaintext, aad)?;
```

**Rationale**: Direct function calls prevent algorithm polymorphism. Trait-based design allows algorithm selection at runtime and easier extension.

**Impact**:
- **Medium** - Affects direct crypto library users
- **Internal only** - Most users go through higher-level APIs

**Migration**: Use `Cipher` trait instead of direct functions. See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for details.

**Deprecation Period**: Old functions deprecated in v0.2.0, removed in v0.3.0

---

### Keystore API Abstraction

**Status**: 🟡 Planned for Phase 2, Task 2.6

**Change**:
```rust
// OLD (v0.1.0)
use hb_zayfer_core::keystore::FileKeyStore;
let mut ks = FileKeyStore::new(path)?;
ks.store_private_key(fingerprint, key_data, ...)?;

// NEW (v0.2.0)
use hb_zayfer_core::storage::{KeyStore, FileKeyStore};
let mut ks: Box<dyn KeyStore> = Box::new(FileKeyStore::new(path)?);
let entry = KeyEntry { /* ... */ };
ks.store_key(entry)?;
```

**Rationale**: Concrete type prevents backend flexibility. Trait-based design allows memory, SQLite, or remote storage backends.

**Impact**:
- **Low** - Most users go through `KeyManager` service
- **Direct keystore users** - Must use `KeyEntry` struct

**Migration**: Use `KeyStore` trait and `KeyEntry` struct. See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for details.

**Deprecation Period**: Old methods deprecated in v0.2.0, removed in v0.3.0

---

## Python API Changes

### KeyManager Service Introduction

**Status**: 🟡 Planned for Phase 3, Task 3.1

**Change**:
```python
# OLD (v0.1.0)
import hb_zayfer as hbz

priv, pub = hbz.ed25519_generate()
fp = hbz.ed25519_fingerprint(pub)
ks = hbz.KeyStore()
ks.store_private_key(fp, priv, passphrase, "Ed25519", "My Key")

# NEW (v0.2.0) - Preferred
import hb_zayfer as hbz

key_mgr = hbz.KeyManager()
metadata = key_mgr.generate_key("ed25519", "My Key", passphrase)
```

**Rationale**: Eliminates duplication across interfaces. One service handles all key operations consistently.

**Impact**:
- **Low** - Old API still works (deprecated)
- **Recommended** - New code should use `KeyManager`

**Migration**: See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for migration examples.

**Deprecation Period**: Old functions deprecated in v0.2.0, removed in v0.3.0

---

### Python Exception Hierarchy

**Status**: 🟡 Planned for Phase 1, Task 1.2

**Change**:
```python
# OLD (v0.1.0)
try:
    hbz.encrypt_file(...)
except ValueError as e:  # All errors are ValueError
    print(f"Error: {e}")

# NEW (v0.2.0)
try:
    hbz.encrypt_file(...)
except hbz.CryptoError as e:  # Specific exception types
    print(f"Crypto error: {e}")
except hbz.StorageError as e:
    print(f"Storage error: {e}")
```

**Rationale**: Generic `ValueError` hides error type. Specific exceptions allow proper error handling.

**Impact**:
- **Medium** - Affects exception handling code
- **Backward compatible** - All exceptions still inherit from `HbZayferError`

**Migration**: Update exception handlers to catch specific types. Generic handlers still work.

**Deprecation Period**: N/A (old exceptions still raised, new hierarchy added)

---

## CLI Changes

### No Breaking CLI Changes

**Status**: ✅ Confirmed

The CLI interface will remain **100% backward compatible**. Commands, flags, and behaviors are unchanged. Internal implementation uses new services layer, but user-facing interface is stable.

---

## Web API Changes

### No Breaking API Changes (v1)

**Status**: ✅ Confirmed

The Web API v1 endpoints remain **fully backward compatible**. Response formats and behaviors are unchanged. Internal implementation uses new services layer.

**New Features** (Non-Breaking):
- Better error response format (more detailed)
- Rate limiting (configurable)
- Security improvements (HTTPS enforcement)

These are additive and don't break existing clients.

---

## File Format Changes

### No Format Changes

**Status**: ✅ Confirmed

The HBZF file format specification remains **completely unchanged**. Files encrypted with v0.1.0 can be decrypted with v0.2.0 and vice versa.

---

## Configuration Changes

### New Config Options (Non-Breaking)

**Status**: 🟡 Planned for Phase 2

**New options**:
```toml
# New in v0.2.0 (all optional, have sensible defaults)
[crypto]
default_cipher = "aes256gcm"  # or "chacha20poly1305"

[storage]
backend = "file"  # or "memory", "sqlite" (future)

[web]
rate_limiting_enabled = false
max_requests_per_minute = 60
```

**Impact**: **None** - All existing configs still work. New options are optional with defaults.

---

## Build & Dependencies

### New Dependencies

**Status**: 🟡 Planned for Phase 1

**New Rust dependencies**:
- `thiserror` - Error handling
- Additional testing crates (dev-only)

**New Python dependencies**:
- `pytest-qt` - GUI testing (dev-only)
- `httpx` - Web API testing (dev-only)

**Impact**: 
- **User**: None (only installs runtime dependencies)
- **Developer**: Must install new dev dependencies

---

## Tracking

### Change Identifier Format

Format: `BC-{PHASE}{TASK}-{NUMBER}`

Example: `BC-2.2-001` = Breaking Change in Phase 2, Task 2, first change

### Status Legend

- 🔴 **Not Yet Implemented** - Planned but not started
- 🟡 **In Progress** - Currently being implemented
- 🟢 **Completed** - Implemented and merged
- ✅ **Confirmed** - Decision confirmed (no change)

---

## Review History

| Date | Reviewer | Notes |
|------|----------|-------|
| 2026-03-08 | Planning Team | Initial document created |

---

**Last Updated**: March 8, 2026  
**Next Review**: After Phase 1 completion
