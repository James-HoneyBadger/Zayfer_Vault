# HB_Zayfer Refactoring Plan

**Date**: March 8, 2026  
**Version**: 1.0  
**Status**: Planning Phase

---

## Executive Summary

This document outlines a comprehensive refactoring plan for HB_Zayfer to address code duplication (~600-700 lines), missing abstractions, inconsistent error handling, and architectural issues. The plan is structured in 5 phases over an estimated 8-12 weeks, prioritized by impact and risk.

**Key Goals**:
- Reduce code duplication by 60-70%
- Improve maintainability through trait-based design
- Establish consistent error handling across all layers
- Increase test coverage from ~40% to 80%+
- Enable easier feature extension

**Impact**: Better code quality, faster feature development, reduced bug surface area

---

## Table of Contents

1. [Current State Assessment](#current-state-assessment)
2. [Refactoring Goals](#refactoring-goals)
3. [Architecture Vision](#architecture-vision)
4. [Phase 1: Foundation (Weeks 1-2)](#phase-1-foundation-weeks-1-2)
5. [Phase 2: Core Abstractions (Weeks 3-4)](#phase-2-core-abstractions-weeks-3-4)
6. [Phase 3: Interface Unification (Weeks 5-7)](#phase-3-interface-unification-weeks-5-7)
7. [Phase 4: Quality & Testing (Week 8)](#phase-4-quality--testing-week-8)
8. [Phase 5: Documentation & Polish (Weeks 9-10)](#phase-5-documentation--polish-weeks-9-10)
9. [Risk Management](#risk-management)
10. [Success Metrics](#success-metrics)
11. [Migration Strategy](#migration-strategy)
12. [Future Enhancements](#future-enhancements)

---

## Current State Assessment

### Strengths ✅

1. **Clean separation of concerns**: Rust core, Python bindings, separate UI layers
2. **Well-organized structure**: Logical module layout, clear directory hierarchy
3. **Good crypto choices**: Industry-standard libraries (RustCrypto, Dalek, Sequoia)
4. **Rich feature set**: Comprehensive encryption, signing, key management
5. **Excellent documentation**: 6,400+ lines across 14 comprehensive guides

### Critical Issues ❌

| Issue | Severity | Impact | Lines Affected |
|-------|----------|--------|----------------|
| **Code duplication** | Critical | Maintenance nightmare | ~600-700 |
| **Missing trait abstractions** | High | Hard to extend | N/A |
| **Inconsistent error handling** | High | Poor debugging | All layers |
| **Low test coverage (40-50%)** | High | Bug risk | GUI, CLI |
| **Module coupling** | Medium | Hard to refactor | format.rs, keystore.rs |
| **Hard-coded values** | Medium | Configuration inflexibility | 20+ locations |

### Code Duplication Breakdown

```
Key generation logic:      200+ lines  (4 locations: Rust CLI, Python CLI, GUI, Web)
Symmetric cipher impl:     120 lines   (aes_gcm.rs vs chacha20.rs)
PyO3 bindings:             200 lines   (repetitive patterns)
File operation UI:         100 lines   (encrypt/decrypt/sign views)
─────────────────────────────────────
TOTAL DUPLICATION:         ~620 lines  (≈8% of codebase)
```

### Architecture Debt

1. **Monolithic modules**:
   - `format.rs` (532 lines): Mixing serialization, encryption, streaming
   - `keystore.rs` (598 lines): Storage, encryption, indexing, contacts
   - `config.rs` (405 lines): Settings, validation, persistence

2. **Missing abstractions**:
   - No `Cipher` trait for symmetric algorithms
   - No `Signer` trait for signature operations
   - No `KeyStore` trait for pluggable backends
   - No unified error type hierarchy

3. **Tight coupling**:
   - Format module directly calls specific cipher implementations
   - Keystore hardcoded to file-based storage
   - CLI commands have embedded business logic

---

## Refactoring Goals

### Primary Objectives

1. **Eliminate duplication**: Reduce duplicated code by 60-70% (370-490 lines)
2. **Establish abstractions**: Create trait-based design for extensibility
3. **Unify error handling**: Consistent errors across Rust/Python/Web/GUI
4. **Improve testability**: Increase coverage to 80%+ with comprehensive test suite
5. **Enhance maintainability**: Clear separation of concerns, single responsibility

### Secondary Objectives

6. **Configuration consistency**: Unified config system across all components
7. **Performance optimization**: Reduce unnecessary allocations, optimize hot paths
8. **Security hardening**: Address web security concerns, add rate limiting
9. **Better logging**: Structured logging with different verbosity levels
10. **API stability**: Clear versioning, deprecation policy

### Non-Goals (Out of Scope)

- ❌ Rewriting core crypto implementations
- ❌ Major feature additions
- ❌ UI/UX redesign
- ❌ Migration to different tech stack
- ❌ Post-quantum cryptography (future work)

---

## Architecture Vision

### Target Architecture Layers

```
┌─────────────────────────────────────────────────────────┐
│          User Interfaces (Presentation Layer)           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ Rust CLI │  │Python CLI│  │    GUI   │  │   Web   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
└───────┼─────────────┼─────────────┼─────────────┼──────┘
        │             │             │             │
┌───────┼─────────────┼─────────────┼─────────────┼──────┐
│       │    Application Services Layer (NEW)     │      │
│  ┌────▼──────────────▼─────────────▼─────────────▼───┐ │
│  │   KeyManager │ EncryptionService │ SigningService │ │
│  │   ContactMgr │ BackupService     │ AuditService   │ │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│         Core Domain Layer (Refactored)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │              │  │              │  │              │  │
│  │   Crypto     │  │   Storage    │  │   Format     │  │
│  │   Traits     │  │   Traits     │  │   Traits     │  │
│  │              │  │              │  │              │  │
│  │ - Cipher     │  │ - KeyStore   │  │ - Serializer │  │
│  │ - Signer     │  │ - AuditLog   │  │ - Encryptor  │  │
│  │ - KeyDerive  │  │ - Config     │  │ - Streamer   │  │
│  └───────┬──────┘  └───────┬──────┘  └───────┬──────┘  │
│          │                 │                  │         │
│  ┌───────▼─────────────────▼──────────────────▼──────┐  │
│  │        Concrete Implementations                    │  │
│  │                                                     │  │
│  │  AES │ ChaCha │ RSA │ Ed25519 │ FileStore │...    │  │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Key Design Patterns

1. **Strategy Pattern**: For algorithm selection (Cipher trait implementations)
2. **Factory Pattern**: For key generation, algorithm instantiation
3. **Repository Pattern**: For key storage abstraction
4. **Builder Pattern**: For encryption/signing operation configuration
5. **Observer Pattern**: For progress callbacks, event notifications
6. **Facade Pattern**: High-level services hiding complex subsystems

### Trait Design

```rust
// Core abstraction examples (to be implemented)

/// Symmetric encryption cipher trait
pub trait Cipher: Send + Sync {
    fn algorithm_id(&self) -> u8;
    fn key_size(&self) -> usize;
    fn nonce_size(&self) -> usize;
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData>;
    fn decrypt(&self, key: &[u8], encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>>;
}

/// Digital signature trait
pub trait Signer: Send + Sync {
    fn algorithm_name(&self) -> &str;
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool>;
}

/// Key storage backend trait
pub trait KeyStore: Send + Sync {
    fn store_key(&mut self, entry: KeyEntry) -> Result<()>;
    fn load_key(&self, fingerprint: &str) -> Result<KeyEntry>;
    fn list_keys(&self) -> Result<Vec<KeyMetadata>>;
    fn delete_key(&mut self, fingerprint: &str) -> Result<()>;
}

/// Configuration provider trait
pub trait ConfigStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn set(&mut self, key: &str, value: &str) -> Result<()>;
    fn delete(&mut self, key: &str) -> Result<()>;
}
```

---

## Phase 1: Foundation (Weeks 1-2)

**Goal**: Establish refactoring infrastructure, fix critical compilation issues

### Week 1: Setup & Error Type Refactor

#### Task 1.1: Project Infrastructure (2 days)

**Objective**: Set up refactoring branch, tooling, tracking

**Actions**:
```bash
# Create refactoring branch
git checkout -b refactor/architecture-v2

# Set up additional tooling
cargo install cargo-modules     # Visualize module structure
cargo install cargo-bloat       # Find large dependencies
cargo install cargo-udeps       # Find unused deps

# Create refactoring tracking
mkdir -p docs/refactoring/
touch docs/refactoring/PROGRESS.md
touch docs/refactoring/BREAKING_CHANGES.md
```

**Deliverables**:
- [ ] Refactoring branch created
- [ ] CI configured for refactoring branch
- [ ] Module dependency graph generated
- [ ] Refactoring progress tracker initialized

#### Task 1.2: Error Type Hierarchy (3 days)

**Objective**: Create structured error types that preserve information across layers

**File**: `crates/core/src/error.rs`

**Current state**:
```rust
pub enum HbError {
    Rsa(String),        // Loses type info
    AesGcm(String),
    // ... string-based errors
}
```

**Target design**:
```rust
/// Root error type with structured variants
#[derive(Debug, thiserror::Error)]
pub enum HbError {
    /// Cryptographic operation errors
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    
    /// Storage/IO errors
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    
    /// Serialization/format errors
    #[error("Format error: {0}")]
    Format(#[from] FormatError),
    
    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
    
    /// Invalid operation or state
    #[error("Invalid operation: {message}")]
    InvalidOperation { message: String, context: Option<String> },
}

/// Nested, structured error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Key generation failed: {algorithm}")]
    KeyGenerationFailed { algorithm: String, source: Box<dyn std::error::Error> },
    
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },
    
    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },
    
    #[error("Invalid key format")]
    InvalidKeyFormat,
    // ... specific error variants
}

// Similar for StorageError, FormatError, ConfigError
```

**Python binding updates**:
```python
# Create exception hierarchy in Python
class HbZayferError(Exception):
    """Base exception for HB_Zayfer"""
    pass

class CryptoError(HbZayferError):
    """Cryptographic operation failed"""
    pass

class StorageError(HbZayferError):
    """Storage/IO operation failed"""
    pass

# ... map Rust errors to Python exceptions
```

**Changes required**:
1. Split `error.rs` into multiple files: `error/mod.rs`, `error/crypto.rs`, `error/storage.rs`
2. Update all `HbError` construction sites to use structured variants
3. Create `From` implementations for library errors (rsa, aes, etc.)
4. Update Python bindings to map to specific exceptions
5. Update all error messages to preserve context

**Test coverage**:
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn error_preserves_context() {
        let err = CryptoError::KeyGenerationFailed { 
            algorithm: "RSA-2048".into(),
            source: Box::new(std::io::Error::new(std::io::ErrorKind::Other, "test"))
        };
        assert!(format!("{}", err).contains("RSA-2048"));
    }
    
    #[test]
    fn error_chain_works() {
        // Test error conversions preserve information
    }
}
```

**Deliverables**:
- [ ] New error module structure created
- [ ] All error construction sites updated
- [ ] Python exception hierarchy implemented
- [ ] Error conversion tests added
- [ ] Breaking changes documented

#### Task 1.3: Add Default trait implementations (1 day)

**Objective**: Fix gaps identified during previous builds

**Files to update**:
- `crates/core/src/format.rs`: ✅ Already added `Default` for `SymmetricAlgorithm`
- Add any other missing `Default` implementations

**Actions**:
```rust
// Add defaults for config types
impl Default for KdfPreset {
    fn default() -> Self {
        KdfPreset::Medium
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            default_symmetric_algorithm: SymmetricAlgorithm::default(),
            default_kdf: KdfParams::default(),
            kdf_preset: KdfPreset::default(),
            // ... other fields
        }
    }
}
```

**Deliverables**:
- [ ] All types that should have `Default` implement it
- [ ] Compilation succeeds without warnings
- [ ] Tests pass

### Week 2: Testing Infrastructure

#### Task 1.4: Test Organization (2 days)

**Objective**: Reorganize tests for better maintainability

**Current structure**:
```
crates/core/tests/
  └── integration.rs (388 lines - all tests in one file)
tests/python/
  ├── test_crypto.py
  └── test_web.py
```

**Target structure**:
```
crates/core/tests/
  ├── crypto/
  │   ├── test_aes.rs
  │   ├── test_chacha.rs
  │   ├── test_rsa.rs
  │   ├── test_ed25519.rs
  │   └── test_x25519.rs
  ├── storage/
  │   ├── test_keystore.rs
  │   └── test_config.rs
  ├── format/
  │   ├── test_serialization.rs
  │   └── test_streaming.rs
  └── common/
      └── mod.rs  (test utilities)

tests/
  ├── rust/
  │   └── integration_tests.rs
  ├── python/
  │   ├── test_crypto.py
  │   ├── test_keystore.py
  │   ├── test_cli.py (NEW)
  │   ├── test_web.py
  │   └── conftest.py (pytest fixtures)
  └── integration/
      └── test_cross_language.py (NEW)
```

**Actions**:
1. Split `integration.rs` into focused test modules
2. Create test utilities module for common setup
3. Add CLI test suite
4. Add cross-language integration tests
5. Set up pytest fixtures for common operations

**Test utilities example**:
```rust
// tests/common/mod.rs
pub fn setup_test_keystore() -> TempDir {
    let dir = TempDir::new().unwrap();
    // Initialize test keystore
    dir
}

pub fn generate_test_key(algorithm: &str) -> (Vec<u8>, Vec<u8>) {
    // Returns (private_key, public_key)
}

pub fn test_encryption_roundtrip<C: Cipher>(cipher: &C) {
    // Generic test for any cipher implementation
}
```

**Deliverables**:
- [ ] Tests reorganized into focused modules
- [ ] Test utilities created
- [ ] CLI tests added (0 → 20+ tests)
- [ ] Integration tests added
- [ ] All existing tests still pass

#### Task 1.5: Code Coverage Setup (1 day)

**Objective**: Establish code coverage measurement

**Tools**:
- Rust: `tarpaulin` or `llvm-cov`
- Python: `pytest-cov`

**Setup**:
```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage/

# Python coverage
pip install pytest-cov
pytest tests/python/ --cov=python/hb_zayfer --cov-report=html
```

**CI integration**:
```yaml
# .github/workflows/coverage.yml
name: Coverage
on: [push, pull_request]
jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Coverage
        run: cargo tarpaulin --out Xml
      - name: Upload to codecov
        uses: codecov/codecov-action@v3
```

**Baseline metrics** (to track improvement):
- Current: ~40-50% overall coverage
- Target: 80%+ overall coverage

**Deliverables**:
- [ ] Coverage tooling configured
- [ ] Baseline coverage report generated
- [ ] CI coverage checks added
- [ ] Coverage badges added to README

#### Task 1.6: Documentation Updates (2 days)

**Objective**: Document refactoring plan and track progress

**Files to create/update**:
1. `docs/refactoring/PLAN.md` (this document)
2. `docs/refactoring/PROGRESS.md` - Task tracking
3. `docs/refactoring/BREAKING_CHANGES.md` - API changes
4. `docs/refactoring/MIGRATION_GUIDE.md` - For users updating
5. `CHANGELOG.md` - Add "Unreleased" section

**Progress tracking template**:
```markdown
# Refactoring Progress

## Phase 1: Foundation
- [x] Task 1.1: Infrastructure setup
- [x] Task 1.2: Error type refactor
- [ ] Task 1.3: Default implementations
- [ ] Task 1.4: Test organization
- [ ] Task 1.5: Code coverage setup
- [ ] Task 1.6: Documentation

## Metrics
- Code duplication: 620 lines → TBD (target: 200 lines)
- Test coverage: 45% → TBD (target: 80%)
- Build time: 2m 15s → TBD
```

**Deliverables**:
- [ ] Refactoring documentation created
- [ ] Progress tracker initialized
- [ ] Breaking changes logged
- [ ] Migration guide started

---

## Phase 2: Core Abstractions (Weeks 3-4)

**Goal**: Implement trait-based architecture for crypto operations

### Week 3: Cipher Trait & Implementations

#### Task 2.1: Define Cipher Trait (1 day)

**Objective**: Create unified interface for symmetric encryption

**File**: `crates/core/src/crypto/cipher.rs` (new)

**Implementation**:
```rust
use crate::error::CryptoError;

/// Encrypted data with nonce and authentication tag
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Trait for symmetric authenticated encryption with associated data (AEAD)
pub trait Cipher: Send + Sync + std::fmt::Debug {
    /// Algorithm identifier for serialization
    fn algorithm_id(&self) -> u8;
    
    /// Human-readable algorithm name
    fn algorithm_name(&self) -> &'static str;
    
    /// Required key size in bytes
    fn key_size(&self) -> usize;
    
    /// Required nonce size in bytes
    fn nonce_size(&self) -> usize;
    
    /// Tag/MAC size in bytes
    fn tag_size(&self) -> usize;
    
    /// Encrypt plaintext with Additional Authenticated Data
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) 
        -> Result<EncryptedData, CryptoError>;
    
    /// Decrypt ciphertext, verifying AAD and authentication tag
    fn decrypt(&self, key: &[u8], encrypted: &EncryptedData, aad: &[u8]) 
        -> Result<Vec<u8>, CryptoError>;
        
    /// Encrypt a single chunk (for streaming)
    fn encrypt_chunk(&self, key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8])
        -> Result<Vec<u8>, CryptoError>;
        
    /// Decrypt a single chunk (for streaming)
    fn decrypt_chunk(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], aad: &[u8])
        -> Result<Vec<u8>, CryptoError>;
}

/// Factory for creating cipher instances
pub struct CipherFactory;

impl CipherFactory {
    /// Get cipher by algorithm ID
    pub fn from_id(id: u8) -> Result<Box<dyn Cipher>, CryptoError> {
        match id {
            0x01 => Ok(Box::new(AesGcmCipher::new())),
            0x02 => Ok(Box::new(ChaCha20Poly1305Cipher::new())),
            _ => Err(CryptoError::UnsupportedAlgorithm { id }),
        }
    }
    
    /// Get cipher by name
    pub fn from_name(name: &str) -> Result<Box<dyn Cipher>, CryptoError> {
        match name.to_lowercase().as_str() {
            "aes" | "aes256gcm" => Ok(Box::new(AesGcmCipher::new())),
            "chacha" | "chacha20poly1305" => Ok(Box::new(ChaCha20Poly1305Cipher::new())),
            _ => Err(CryptoError::UnsupportedAlgorithm { name: name.to_string() }),
        }
    }
}
```

**Deliverables**:
- [ ] Cipher trait defined
- [ ] CipherFactory implemented
- [ ] Documentation written
- [ ] Design reviewed

#### Task 2.2: Refactor AES-GCM Implementation (1 day)

**Objective**: Implement `Cipher` trait for AES-256-GCM

**File**: `crates/core/src/crypto/aes_cipher.rs` (renamed from `aes_gcm.rs`)

**Implementation**:
```rust
use super::cipher::{Cipher, EncryptedData};
use crate::error::CryptoError;
use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};

#[derive(Debug)]
pub struct AesGcmCipher;

impl AesGcmCipher {
    pub fn new() -> Self {
        Self
    }
}

impl Cipher for AesGcmCipher {
    fn algorithm_id(&self) -> u8 { 0x01 }
    fn algorithm_name(&self) -> &'static str { "AES-256-GCM" }
    fn key_size(&self) -> usize { 32 }
    fn nonce_size(&self) -> usize { 12 }
    fn tag_size(&self) -> usize { 16 }
    
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData, CryptoError> {
        if key.len() != self.key_size() {
            return Err(CryptoError::InvalidKeySize { 
                expected: self.key_size(), 
                got: key.len() 
            });
        }
        
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let mut nonce_bytes = vec![0u8; self.nonce_size()];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);
        
        // Encrypt with AAD
        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|e| CryptoError::EncryptionFailed { 
                reason: e.to_string() 
            })?;
        
        Ok(EncryptedData {
            nonce: nonce_bytes,
            ciphertext,
        })
    }
    
    fn decrypt(&self, key: &[u8], encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if key.len() != self.key_size() {
            return Err(CryptoError::InvalidKeySize { 
                expected: self.key_size(), 
                got: key.len() 
            });
        }
        
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = AesNonce::from_slice(&encrypted.nonce);
        
        cipher
            .decrypt(nonce, aes_gcm::aead::Payload { 
                msg: &encrypted.ciphertext, 
                aad 
            })
            .map_err(|e| CryptoError::DecryptionFailed { 
                reason: e.to_string() 
            })
    }
    
    // Implement encrypt_chunk, decrypt_chunk similarly
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cipher_trait() {
        let cipher = AesGcmCipher::new();
        let key = vec![0u8; cipher.key_size()];
        let plaintext = b"Hello, World!";
        let aad = b"additional data";
        
        let encrypted = cipher.encrypt(&key, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&key, &encrypted, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
}
```

**Testing**:
- Unit tests for trait implementation
- Roundtrip encryption/decryption
- Error cases (invalid key size, wrong AAD)

**Deliverables**:
- [ ] AES cipher refactored
- [ ] Implements Cipher trait
- [ ] Tests pass
- [ ] Old functions marked deprecated

#### Task 2.3: Refactor ChaCha20 Implementation (1 day)

**Objective**: Implement `Cipher` trait for ChaCha20-Poly1305

**File**: `crates/core/src/crypto/chacha_cipher.rs`

**Implementation**: Similar to AesGcmCipher, implementing the Cipher trait

**Key differences**:
- `algorithm_id() -> 0x02`
- `nonce_size() -> 24` (XChaCha20 uses 24-byte nonce)
- Uses `chacha20poly1305` crate instead of `aes_gcm`

**Testing**:
- Same test coverage as AES
- Verify nonce size difference

**Deliverables**:
- [ ] ChaCha cipher refactored
- [ ] Implements Cipher trait
- [ ] Tests pass
- [ ] Old functions marked deprecated

#### Task 2.4: Generic Cipher Tests (1 day)

**Objective**: Create reusable test suite for any Cipher implementation

**File**: `crates/core/src/crypto/cipher_tests.rs`

**Implementation**:
```rust
/// Generic test suite for Cipher trait implementations
pub fn test_cipher_roundtrip<C: Cipher>(cipher: &C) {
    let key = vec![0u8; cipher.key_size()];
    let plaintext = b"Test message";
    let aad = b"additional data";
    
    let encrypted = cipher.encrypt(&key, plaintext, aad).unwrap();
    let decrypted = cipher.decrypt(&key, &encrypted, aad).unwrap();
    
    assert_eq!(&decrypted, plaintext);
}

pub fn test_cipher_invalid_key<C: Cipher>(cipher: &C) {
    let wrong_size_key = vec![0u8; cipher.key_size() + 1];
    let plaintext = b"message";
    let aad = b"";
    
    assert!(cipher.encrypt(&wrong_size_key, plaintext, aad).is_err());
}

pub fn test_cipher_wrong_aad<C: Cipher>(cipher: &C) {
    let key = vec![0u8; cipher.key_size()];
    let plaintext = b"message";
    let aad = b"correct aad";
    let wrong_aad = b"wrong aad";
    
    let encrypted = cipher.encrypt(&key, plaintext, aad).unwrap();
    assert!(cipher.decrypt(&key, &encrypted, wrong_aad).is_err());
}

// Run all tests for a cipher
pub fn run_cipher_test_suite<C: Cipher>(cipher: &C, name: &str) {
    println!("Testing {} cipher...", name);
    test_cipher_roundtrip(cipher);
    test_cipher_invalid_key(cipher);
    test_cipher_wrong_aad(cipher);
    println!("  ✓ All tests passed");
}
```

**Usage in tests**:
```rust
#[test]
fn test_aes_cipher_suite() {
    run_cipher_test_suite(&AesGcmCipher::new(), "AES-256-GCM");
}

#[test]
fn test_chacha_cipher_suite() {
    run_cipher_test_suite(&ChaCha20Poly1305Cipher::new(), "ChaCha20-Poly1305");
}
```

**Deliverables**:
- [ ] Generic test suite created
- [ ] Applied to both ciphers
- [ ] Coverage increases to 90%+ for cipher modules

### Week 4: Additional Traits

#### Task 2.5: Signer Trait (2 days)

**Objective**: Unify signature operations

**File**: `crates/core/src/crypto/signer.rs` (new)

**Implementation**:
```rust
/// Trait for digital signature operations
pub trait Signer: Send + Sync + std::fmt::Debug {
    /// Algorithm name (e.g., "Ed25519", "RSA-PSS")
    fn algorithm_name(&self) -> &'static str;
    
    /// Generate a new key pair
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError>;
    
    /// Sign a message with private key
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    
    /// Verify a signature with public key
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) 
        -> Result<bool, CryptoError>;
    
    /// Calculate fingerprint of public key
    fn fingerprint(&self, public_key: &[u8]) -> Result<String, CryptoError>;
}

/// Key pair structure
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    pub fn new(private_key: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self { private_key, public_key }
    }
}

/// Factory for creating signer instances
pub struct SignerFactory;

impl SignerFactory {
    pub fn from_name(name: &str) -> Result<Box<dyn Signer>, CryptoError> {
        match name.to_lowercase().as_str() {
            "ed25519" => Ok(Box::new(Ed25519Signer::new())),
            "rsa2048" => Ok(Box::new(RsaSigner::new(2048))),
            "rsa4096" => Ok(Box::new(RsaSigner::new(4096))),
            _ => Err(CryptoError::UnsupportedAlgorithm { name: name.to_string() }),
        }
    }
}
```

**Implementations**:
1. `Ed25519Signer` - Refactor `ed25519.rs`
2. `RsaSigner` - Refactor `rsa.rs` (with configurable key size)

**Deliverables**:
- [ ] Signer trait defined
- [ ] Ed25519 refactored to use trait
- [ ] RSA refactored to use trait
- [ ] Factory pattern implemented
- [ ] Tests for all implementations

#### Task 2.6: KeyStore Trait (2 days)

**Objective**: Abstract storage backend

**File**: `crates/core/src/storage/keystore_trait.rs` (new)

**Implementation**:
```rust
/// Key entry for storage
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub label: String,
    pub private_key: Option<Vec<u8>>,  // Encrypted if present
    pub public_key: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Key metadata (without key data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub fingerprint: String,
    pub algorithm: KeyAlgorithm,
    pub label: String,
    pub has_private: bool,
    pub has_public: bool,
    pub created_at: String,
}

/// Trait for key storage backends
pub trait KeyStore: Send + Sync {
    /// Store a key entry
    fn store_key(&mut self, entry: KeyEntry) -> Result<(), StorageError>;
    
    /// Load a key entry by fingerprint
    fn load_key(&self, fingerprint: &str) -> Result<KeyEntry, StorageError>;
    
    /// Load only metadata (faster, no key data)
    fn load_metadata(&self, fingerprint: &str) -> Result<KeyMetadata, StorageError>;
    
    /// List all keys (metadata only)
    fn list_keys(&self) -> Result<Vec<KeyMetadata>, StorageError>;
    
    /// Delete a key
    fn delete_key(&mut self, fingerprint: &str) -> Result<(), StorageError>;
    
    /// Check if key exists
    fn has_key(&self, fingerprint: &str) -> Result<bool, StorageError>;
    
    /// Search keys by label, algorithm, etc.
    fn search_keys(&self, query: &KeyQuery) -> Result<Vec<KeyMetadata>, StorageError>;
}

/// Query builder for searching keys
pub struct KeyQuery {
    pub label_contains: Option<String>,
    pub algorithm: Option<KeyAlgorithm>,
    pub has_private: Option<bool>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
}
```

**Implementations**:
1. `FileKeyStore` - Current implementation (refactored)
2. `MemoryKeyStore` - In-memory for testing
3. (Future) `SqliteKeyStore`, `PostgresKeyStore`

**Deliverables**:
- [ ] KeyStore trait defined
- [ ] FileKeyStore refactored
- [ ] MemoryKeyStore for testing
- [ ] Migration path for existing keystores
- [ ] Tests with both implementations

#### Task 2.7: Update Format Module (1 day)

**Objective**: Use trait-based ciphers in file format

**File**: `crates/core/src/format.rs`

**Changes**:
```rust
// Before: Hardcoded dispatch
match algorithm {
    SymmetricAlgorithm::Aes256Gcm => {
        let (nonce, ct) = aes_gcm::encrypt(key, plaintext, aad)?;
        // ...
    }
    SymmetricAlgorithm::ChaCha20Poly1305 => {
        let (nonce, ct) = chacha20::encrypt(key, plaintext, aad)?;
        // ...
    }
}

// After: Trait-based
let cipher: Box<dyn Cipher> = CipherFactory::from_id(algorithm_id)?;
let encrypted = cipher.encrypt(key, plaintext, aad)?;
// Serialize encrypted.nonce and encrypted.ciphertext
```

**Benefits**:
- Adding new algorithms requires no format.rs changes
- Cleaner separation of concerns
- Easier testing (mock ciphers)

**Deliverables**:
- [ ] Format module uses Cipher trait
- [ ] All format tests still pass
- [ ] Code is more concise (~50 lines removed)

---

## Phase 3: Interface Unification (Weeks 5-7)

**Goal**: Eliminate duplication in CLI, GUI, and Web interfaces

### Week 5: Application Services Layer

#### Task 3.1: Create KeyManager Service (2 days)

**Objective**: Extract key generation logic to reusable service

**File**: `crates/core/src/services/key_manager.rs` (new)

**Implementation**:
```rust
/// High-level key management service
pub struct KeyManager {
    keystore: Box<dyn KeyStore>,
    config: Arc<Config>,
}

impl KeyManager {
    pub fn new(keystore: Box<dyn Keystore>, config: Arc<Config>) -> Self {
        Self { keystore, config }
    }
    
    /// Generate a key pair
    ///
    /// This replaces the duplicated logic in CLI/GUI/Web
    pub fn generate_key(
        &mut self,
        algorithm: &str,
        label: String,
        passphrase: &[u8],
        options: KeyGenOptions,
    ) -> Result<KeyMetadata, HbError> {
        // Get signer for algorithm
        let signer = SignerFactory::from_name(algorithm)?;
        
        // Generate keypair
        let keypair = signer.generate_keypair()?;
        
        // Calculate fingerprint
        let fingerprint = signer.fingerprint(&keypair.public_key)?;
        
        // Encrypt private key with passphrase
        let encrypted_private = self.encrypt_private_key(&keypair.private_key, passphrase)?;
        
        // Create key entry
        let entry = KeyEntry {
            fingerprint: fingerprint.clone(),
            algorithm: KeyAlgorithm::from_str(algorithm)?,
            label,
            private_key: Some(encrypted_private),
            public_key: keypair.public_key,
            created_at: chrono::Utc::now(),
            metadata: options.into_metadata(),
        };
        
        // Store in keystore
        self.keystore.store_key(entry)?;
        
        // Return metadata
        self.keystore.load_metadata(&fingerprint)
    }
    
    /// Export public key in various formats
    pub fn export_public_key(
        &self,
        fingerprint: &str,
        format: ExportFormat,
    ) -> Result<Vec<u8>, HbError> {
        let entry = self.keystore.load_key(fingerprint)?;
        
        match format {
            ExportFormat::Pem => Ok(entry.public_key),  // Already PEM
            ExportFormat::OpenSsh => convert_to_openssh(&entry.public_key),
            ExportFormat::Gpg => convert_to_gpg_armor(&entry.public_key),
        }
    }
    
    /// Import keys from various sources
    pub fn import_key(
        &mut self,
        key_data: &[u8],
        format: ImportFormat,
        label: String,
    ) -> Result<KeyMetadata, HbError> {
        // Parse based on format
        // Store in keystore
        // Return metadata
    }
    
    /// Delete a key (with confirmation callback)
    pub fn delete_key<F>(
        &mut self,
        fingerprint: &str,
        confirm: F,
    ) -> Result<(), HbError>
    where
        F: FnOnce(&KeyMetadata) -> bool,
    {
        let metadata = self.keystore.load_metadata(fingerprint)?;
        
        if confirm(&metadata) {
            self.keystore.delete_key(fingerprint)?;
            Ok(())
        } else {
            Err(HbError::OperationCancelled)
        }
    }
    
    // Additional methods: list_keys, search_keys, resolve_recipient, etc.
}

/// Options for key generation
pub struct KeyGenOptions {
    pub user_id: Option<String>,  // For PGP keys
    pub export_public: Option<PathBuf>,
    pub metadata: HashMap<String, String>,
}
```

**Python binding**:
```python
# Expose as Python class
@pyclass
struct PyKeyManager {
    inner: KeyManager,
}

#[pymethods]
impl PyKeyManager {
    #[new]
    fn new() -> PyResult<Self> {
        let keystore = FileKeyStore::default()?;
        let config = Config::load()?;
        Ok(Self {
            inner: KeyManager::new(Box::new(keystore), Arc::new(config))
        })
    }
    
    fn generate_key(
        &mut self,
        algorithm: &str,
        label: String,
        passphrase: &[u8],
    ) -> PyResult<PyKeyMetadata> {
        // Call Rust KeyManager
    }
}
```

**Deliverables**:
- [ ] KeyManager service created
- [ ] All key operations exposed
- [ ] Python bindings added
- [ ] Tests cover all operations
- [ ] Documentation written

#### Task 3.2: Create EncryptionService (2 days)

**Objective**: Unify file encryption/decryption logic

**File**: `crates/core/src/services/encryption_service.rs` (new)

**Implementation**:
```rust
/// High-level encryption service
pub struct EncryptionService {
    keystore: Arc<dyn KeyStore>,
    config: Arc<Config>,
}

impl EncryptionService {
    /// Encrypt a file with password
    pub fn encrypt_file_password(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        passphrase: &[u8],
        options: EncryptOptions,
    ) -> Result<EncryptionResult, HbError> {
        // Get cipher
        let cipher = CipherFactory::from_name(&options.algorithm)?;
        
        // Derive key from passphrase
        let salt = generate_salt();
        let key = self.derive_key(passphrase, &salt, &options.kdf)?;
        
        // Open files
        let mut input = File::open(input_path)?;
        let mut output = File::create(output_path)?;
        
        // Write HBZF header
        let header = HbzfHeader {
            version: 1,
            algorithm: cipher.algorithm_id(),
            wrapping: WrappingMode::Password,
            kdf: options.kdf,
            salt,
            // ...
        };
        header.write(&mut output)?;
        
        // Stream encrypt
        self.encrypt_stream(&mut input, &mut output, &*cipher, &key, options.progress)?;
        
        Ok(EncryptionResult {
            output_size: output.metadata()?.len(),
            algorithm: cipher.algorithm_name().to_string(),
            // ...
        })
    }
    
    /// Encrypt a file for a recipient (public-key)
    pub fn encrypt_file_recipient(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        recipient: &str,
        options: EncryptOptions,
    ) -> Result<EncryptionResult, HbError> {
        // Resolve recipient to key
        let key_metadata = self.keystore.search_keys(&KeyQuery {
            label_contains: Some(recipient.to_string()),
            ..Default::default()
        })?;
        
        let recipient_key = key_metadata
            .first()
            .ok_or_else(|| HbError::RecipientNotFound { name: recipient.to_string() })?;
        
        // Load recipient's public key
        let entry = self.keystore.load_key(&recipient_key.fingerprint)?;
        
        // Generate ephemeral key for ECDH
        let (eph_private, eph_public) = x25519::generate_keypair();
        let shared_secret = x25519::ecdh(&eph_private, &entry.public_key)?;
        
        // Derive encryption key from shared secret
        let symmetric_key = self.derive_key_from_secret(&shared_secret)?;
        
        // Encrypt file
        self.encrypt_stream_with_pubkey(...)
    }
    
    /// Decrypt a file (auto-detect wrapping mode)
    pub fn decrypt_file(
        &self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        passphrase: &[u8],
        options: DecryptOptions,
    ) -> Result<DecryptionResult, HbError> {
        // Read header
        let mut input = File::open(input_path)?;
        let header = HbzfHeader::read(&mut input)?;
        
        // Get cipher
        let cipher = CipherFactory::from_id(header.algorithm)?;
        
        // Decrypt based on wrapping mode
        let key = match header.wrapping {
            WrappingMode::Password => {
                self.derive_key(passphrase, &header.salt, &header.kdf)?
            }
            WrappingMode::X25519Ecdh => {
                // Find our key that can unwrap
                self.unwrap_key_with_private_key(&header, passphrase)?
            }
            // ...
        };
        
        // Stream decrypt
        let mut output = File::create(output_path)?;
        self.decrypt_stream(&mut input, &mut output, &*cipher, &key, options.progress)?;
        
        Ok(DecryptionResult {
            output_size: output.metadata()?.len(),
            algorithm: cipher.algorithm_name().to_string(),
            // ...
        })
    }
    
    // Helper methods for streaming, progress callbacks, etc.
}

/// Options for encryption
pub struct EncryptOptions {
    pub algorithm: String,
    pub kdf: KdfParams,
    pub progress: Option<Box<dyn Fn(u64, u64) + Send>>,
}

/// Result of encryption operation
pub struct EncryptionResult {
    pub output_size: u64,
    pub algorithm: String,
    pub wrapping_mode: String,
}
```

**Deliverables**:
- [ ] EncryptionService created
- [ ] Password and public-key encryption
- [ ] Auto-detect decryption
- [ ] Progress callback support
- [ ] Python bindings
- [ ] Tests

#### Task 3.3: Create SigningService (1 day)

**Objective**: Unify signing/verification

**Implementation**: Similar pattern to EncryptionService

**Deliverables**:
- [ ] SigningService created
- [ ] Sign and verify operations
- [ ] Support for all signature algorithms
- [ ] Tests

### Week 6: CLI Refactoring

#### Task 3.4: Refactor Rust CLI (2 days)

**Objective**: Use services layer, eliminate duplication

**File**: `crates/cli/src/main.rs`

**Before (145 lines of duplication)**:
```rust
fn cmd_keygen(algorithm: AlgorithmChoice, label: String, passphrase: String) -> Result<()> {
    match algorithm {
        AlgorithmChoice::Rsa2048 => {
            let kp = rsa::generate_keypair(rsa::RsaKeySize::Rsa2048)?;
            let fp = rsa::fingerprint(&kp.public_key)?;
            // ... 30 lines of storage logic
        }
        AlgorithmChoice::Rsa4096 => { /* nearly identical */ }
        AlgorithmChoice::Ed25519 => { /* nearly identical */ }
        // ... 5 cases
    }
}
```

**After (~20 lines)**:
```rust
fn cmd_keygen(algorithm: AlgorithmChoice, label: String, passphrase: String) -> Result<()> {
    let mut key_mgr = KeyManager::new(
        Box::new(FileKeyStore::default()?),
        Arc::new(Config::load()?),
    );
    
    let metadata = key_mgr.generate_key(
        &algorithm.to_string(),
        label.clone(),
        passphrase.as_bytes(),
        KeyGenOptions::default(),
    )?;
    
    println!("Generated {} key pair", metadata.algorithm);
    println!("Fingerprint: {}", metadata.fingerprint);
    println!("Label: {}", label);
    
    // Audit logging
    audit_log(
        AuditOperation::KeyGenerated {
            algorithm: metadata.algorithm.to_string(),
            fingerprint: metadata.fingerprint,
        },
        Some("source=cli"),
    );
    
    Ok(())
}
```

**Similarly for encrypt/decrypt/sign**:
```rust
fn cmd_encrypt(/* args */) -> Result<()> {
    let enc_svc = EncryptionService::new(/* ... */);
    
    if password {
        enc_svc.encrypt_file_password(input, output, passphrase, options)?;
    } else {
        enc_svc.encrypt_file_recipient(input, output, recipient, options)?;
    }
    
    // Audit logging
    Ok(())
}
```

**Deliverables**:
- [ ] Rust CLI uses KeyManager
- [ ] Rust CLI uses EncryptionService
- [ ] Rust CLI uses SigningService
- [ ] Code reduced by ~120 lines
- [ ] All CLI tests pass

#### Task 3.5: Refactor Python CLI (1 day)

**Objective**: Same refactoring for Python CLI

**Before**:
```python
@cli.command()
def keygen(algorithm, label):
    if algorithm in ("rsa2048", "rsa4096"):
        bits = 2048 if algorithm == "rsa2048" else 4096
        priv_pem, pub_pem = hbz.rsa_generate(bits)
        fp = hbz.rsa_fingerprint (pub_pem)
        # ... store in keystore
        # ... 20 lines
```

**After**:
```python
@cli.command()
def keygen(algorithm, label):
    passphrase = click.prompt("Passphrase", hide_input=True, confirmation_prompt=True)
    
    key_mgr = hbz.KeyManager()
    metadata = key_mgr.generate_key(algorithm, label, passphrase.encode())
    
    console.print(f"[green]Generated {metadata.algorithm} key pair[/green]")
    console.print(f"Fingerprint: {metadata.fingerprint}")
    console.print(f"Label: {label}")
```

**Deliverables**:
- [ ] Python CLI uses KeyManager
- [ ] Python CLI uses EncryptionService
- [ ] Code reduced by ~80 lines
- [ ] CLI tests added (20+ tests)
- [ ] All tests pass

### Week 7: GUI & Web Refactoring

#### Task 3.6: Refactor GUI Key Generation (1 day)

**File**: `python/hb_zayfer/gui/keygen_view.py`

**Before (duplicated logic)**:
```python
def _on_generate(self):
    algorithm = self.algo_combo.currentText().lower()
    label = self.label_edit.text()
    passphrase = self.pass1_edit.text()
    
    if algorithm in ("rsa2048", "rsa4096"):
        bits = 2048 if algorithm == "rsa2048" else 4096
        # ... generate, store, display (~40 lines)
```

**After**:
```python
def _on_generate(self):
    algorithm = self.algo_combo.currentText().lower()
    label = self.label_edit.text()
    passphrase = self.pass1_edit.text()
    
    # Use worker with KeyManager
    worker = CryptoWorker(
        lambda: self.key_mgr.generate_key(
            algorithm,
            label,
            passphrase.encode()
        )
    )
    worker.signals.finished.connect(self._on_gen_done)
    worker.signals.error.connect(self._on_gen_error)
    QThreadPool.globalInstance().start(worker)
```

**Deliverables**:
- [ ] GUI uses KeyManager service
- [ ] Code reduced by ~30 lines
- [ ] Same for encrypt, decrypt views
- [ ] GUI tests added (10+ tests)

#### Task 3.7: Refactor Web API (1 day)

**File**: `python/hb_zayfer/web/routes.py`

**Before**:
```python
@router.post("/keygen")
def generate_key(req: KeygenRequest):
    if req.algorithm in ("rsa2048", "rsa4096"):
        bits = 2048 if req.algorithm == "rsa2048" else 4096
        # ... duplicated logic
```

**After**:
```python
@router.post("/keygen")
def generate_key(req: KeygenRequest):
    try:
        key_mgr = get_key_manager()  # Dependency injection
        metadata = key_mgr.generate_key(
            req.algorithm,
            req.label,
            req.passphrase.encode()
        )
        
        # Audit logging
        _audit_safe(
            hbz.audit_log_key_generated,
            req.algorithm.upper(),
            metadata.fingerprint,
            "source=web, endpoint=/api/keygen"
        )
        
        return KeygenResponse(
            fingerprint=metadata.fingerprint,
            algorithm=metadata.algorithm,
            label=metadata.label
        )
    except HbZayferError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

**Additional improvements**:
- Dependency injection for services
- Proper exception mapping
- Rate limiting middleware
- Request validation

**Deliverables**:
- [ ] Web API uses services
- [ ] Code reduced by ~100 lines
- [ ] Better error handling
- [ ] Security improvements
- [ ] API tests expanded (30+ tests)

#### Task 3.8: Shared UI Components (2 days)

**Objective**: Create reusable UI components for file operations

**New file**: `python/hb_zayfer/gui/file_operation_base.py`

**Implementation**:
```python
class FileOperationView(QWidget):
    """Base class for file operation views (encrypt, decrypt, sign)"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Create common UI elements"""
        layout = QVBoxLayout()
        
        # File selection (common to encrypt, decrypt, sign)
        self.file_group = self.create_file_selection_group()
        layout.addWidget(self.file_group)
        
        # Output selection (common to all)
        self.output_group = self.create_output_selection_group()
        layout.addWidget(self.output_group)
        
        # Progress bar (common to all)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Action button (customizable)
        self.action_button = QPushButton()
        self.action_button.clicked.connect(self.on_action)
        layout.addWidget(self.action_button)
        
        self.setLayout(layout)
    
    def create_file_selection_group(self):
        """Reusable file selection UI"""
        # ... drag-drop, browse button
    
    def on_action(self):
        """Override in subclasses"""
        raise NotImplementedError
    
    def show_progress(self):
        """Show indeterminate progress"""
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.action_button.setEnabled(False)
    
    def hide_progress(self):
        """Hide progress, re-enable button"""
        self.progress.setVisible(False)
        self.action_button.setEnabled(True)


class EncryptView(FileOperationView):
    """Encrypt view using base"""
    
    def __init__(self):
        super().__init__()
        self.action_button.setText("Encrypt")
        # Add encryption-specific UI (recipient selection, etc.)
    
    def on_action(self):
        # Get inputs
        # Call EncryptionService
        # Show progress
        pass


class DecryptView(FileOperationView):
    """Decrypt view using base"""
    # Similar, inherits common UI
```

**Benefits**:
- Reduced duplication (~100 lines)
- Consistent UI across views
- Easier to add new file operations
- Better maintainability

**Deliverables**:
- [ ] Base class created
- [ ] Encrypt view refactored
- [ ] Decrypt view refactored
- [ ] Sign/Verify views refactored
- [ ] Code reduced by ~100 lines

---

## Phase 4: Quality & Testing (Week 8)

**Goal**: Achieve 80%+ test coverage, fix bugs

### Week 8: Test Suite Expansion

#### Task 4.1: Rust Unit Tests (2 days)

**Objective**: Comprehensive unit test coverage

**Coverage targets** (per module):
- crypto: 90%+ (critical security code)
- storage: 85%+
- services: 80%+
- format: 85%+
- error: 95%+ (edge cases)

**Test categories**:
1. Happy path tests
2. Error path tests
3. Edge case tests (empty inputs, large inputs, invalid data)
4. Concurrent access tests
5. Performance tests (benchmarks)

**Example test expansion** (for `KeyManager`):
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_generate_ed25519_key() {
        // Happy path
    }
    
    #[test]
    fn test_generate_with_weak_passphrase_warns() {
        // Validate passphrase strength warnings
    }
    
    #[test]
    fn test_generate_duplicate_label_fails() {
        // Error handling
    }
    
    #[test]
    fn test_generate_unsupported_algorithm() {
        // Error handling for invalid algorithm
    }
    
    #[test]
    fn test_generate_concurrent_safe() {
        // Thread safety
        let key_mgr = Arc::new(Mutex::new(KeyManager::new(/*...*/)));
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let mgr = key_mgr.clone();
                thread::spawn(move || {
                    mgr.lock().unwrap().generate_key(/*...*/)
                })
            })
            .collect();
        // Assert all succeed without conflicts
    }
    
    #[bench]
    fn bench_generate_ed25519(b: &mut Bencher) {
        // Performance benchmark
    }
}
```

**Deliverables**:
- [ ] 200+ Rust unit tests (up from ~50)
- [ ] 90%+ coverage on crypto modules
- [ ] All edge cases covered
- [ ] Benchmarks for performance tracking

#### Task 4.2: Python Integration Tests (2 days)

**Objective**: Test Python bindings and cross-language integration

**Test categories**:
1. PyO3 binding correctness
2. Memory safety (no leaks, proper cleanup)
3. Python exception handling
4. Cross-language roundtrips (Rust encrypt, Python decrypt)
5. CLI command tests
6. GUI interaction tests (using pytest-qt)
7. Web API tests (using httpx)

**Example tests**:
```python
# tests/python/test_integration.py

def test_cross_language_encrypt_decrypt():
    """Rust-encrypted file can be decrypted in Python"""
    # Use Rust CLI to encrypt
    subprocess.run([
        "hb_zayfer_cli", "encrypt",
        "--input", "test.txt",
        "--output", "test.hbzf",
        "--password"
    ], input="password\n", text=True)
    
    # Use Python to decrypt
    import hb_zayfer as hbz
    decrypted = hbz.decrypt_file("test.hbzf", "password".encode())
    
    assert decrypted == b"test content"


def test_cli_keygen_command():
    """Python CLI keygen creates valid key"""
    result = runner.invoke(cli, [
        "keygen", "ed25519",
        "--label", "test-key"
    ], input="testpass\ntestpass\n")
    
    assert result.exit_code == 0
    assert "Generated" in result.output
    
    # Verify key was stored
    ks = hbz.KeyStore()
    keys = ks.list_keys()
    assert any(k["label"] == "test-key" for k in keys)


@pytest.mark.gui
def test_gui_encrypt_button(qtbot):
    """GUI encrypt button triggers worker"""
    view = EncryptView()
    qtbot.addWidget(view)
    
    # Set inputs
    view.input_edit.setText("test.txt")
    view.output_edit.setText("test.hbzf")
    view.pass_edit.setText("password")
    
    # Click encrypt
    qtbot.mouseClick(view.encrypt_button, Qt.LeftButton)
    
    # Wait for worker to finish
    qtbot.waitUntil(lambda: view.progress.isHidden(), timeout=5000)
    
    # Verify output file exists
    assert Path("test.hbzf").exists()


@pytest.mark.web
async def test_web_api_keygen(client: AsyncClient):
    """Web API keygen endpoint works"""
    response = await client.post("/api/keygen", json={
        "algorithm": "ed25519",
        "label": "test-key",
        "passphrase": "testpass"
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "fingerprint" in data
    assert data["algorithm"] == "Ed25519"
```

**Deliverables**:
- [ ] 100+ Python integration tests
- [ ] CLI test suite (20+ tests)
- [ ] GUI test suite (15+ tests)
- [ ] Web API test suite (30+ tests)
- [ ] Cross-language tests (10+ tests)
- [ ] Memory leak tests pass

#### Task 4.3: End-to-End Scenarios (1 day)

**Objective**: Test complete user workflows

**Scenarios**:
1. **New user onboarding**:
   - Generate first key
   - Encrypt a file
   - Decrypt the file
   - Verify roundtrip

2. **Secure communication**:
   - Alice generates keys
   - Bob generates keys
   - Exchange public keys
   - Alice encrypts for Bob
   - Bob decrypts
   - Bob signs response
   - Alice verifies signature

3. **Backup and restore**:
   - Create keystore with multiple keys
   - Create backup
   - Delete original keystore
   - Restore from backup
   - Verify all keys restored

4. **Key rotation**:
   - Generate initial key
   - Encrypt files with key
   - Generate new key
   - Re-encrypt files with new key
   - Delete old key
   - Verify old files can't be decrypted

**Implementation**:
```python
# tests/integration/test_scenarios.py

def test_scenario_new_user_onboarding(tmp_path):
    """Complete new user workflow"""
    # Setup isolated environment
    os.environ["HBZ_HOME"] = str(tmp_path)
    
    # Step 1: Generate key
    runner.invoke(cli, ["keygen", "ed25519", "--label", "my-key"],
                  input="password\npassword\n")
    
    # Step 2: Create test file
    test_file = tmp_path / "secret.txt"
    test_file.write_text("My secret message")
    
    # Step 3: Encrypt
    result = runner.invoke(cli, [
        "encrypt",
        "--input", str(test_file),
        "--output", str(tmp_path / "secret.hbzf"),
        "--password"
    ], input="password\n")
    assert result.exit_code == 0
    
    # Step 4: Decrypt
    result = runner.invoke(cli, [
        "decrypt",
        "--input", str(tmp_path / "secret.hbzf"),
        "--output", str(tmp_path / "recovered.txt")
    ], input="password\n")
    assert result.exit_code == 0
    
    # Step 5: Verify
    recovered = (tmp_path / "recovered.txt").read_text()
    assert recovered == "My secret message"
```

**Deliverables**:
- [ ] 5+ end-to-end scenario tests
- [ ] Test documentation with diagrams
- [ ] Scenario tests run in CI

#### Task 4.4: Bug Fixes & Stabilization (2 days)

**Objective**: Fix issues found during testing

**Process**:
1. Run full test suite
2. Triage failures (critical, high, medium, low)
3. Fix critical and high-priority issues
4. Document known issues for medium/low
5. Re-run tests until stable

**Bug tracking**:
```markdown
# Known Issues (to be fixed in Phase 4)

## Critical (Block refactoring)
- [ ] #REF-001: KeyManager deadlock with concurrent access
- [ ] #REF-002: Memory leak in streaming decryption

## High (Fix before merge)
- [ ] #REF-010: Incorrect error message for wrong passphrase
- [ ] #REF-011: GUI freezes on large file operations

## Medium (Fix before release)
- [ ] #REF-020: CLI progress bar doesn't update smoothly
- [ ] #REF-021: Config file not created on first run

## Low (Future work)
- [ ] #REF-030: Keyring view doesn't auto-refresh
```

**Deliverables**:
- [ ] All critical bugs fixed
- [ ] All high-priority bugs fixed
- [ ] Test suite passes 100%
- [ ] No memory leaks
- [ ] Performance benchmarks met

---

## Phase 5: Documentation & Polish (Weeks 9-10)

**Goal**: Update documentation, prepare for release

### Week 9: Documentation Updates

#### Task 5.1: API Documentation (2 days)

**Objective**: Document new APIs and services

**Files to update**:
1. `docs/RUST_API.md` - Add trait documentation
2. `docs/PYTHON_API.md` - Add services documentation
3. Inline Rust docs (rustdoc)
4. Python docstrings

**Example updates**:
```rust
/// High-level key management service.
///
/// `KeyManager` provides a unified interface for key generation, import, export,
/// and deletion. It abstracts over different key algorithms and storage backends.
///
/// # Example
///
/// ```
/// use hb_zayfer_core::{KeyManager, FileKeyStore, Config};
///
/// let keystore = Box::new(FileKeyStore::default()?);
/// let config = Arc::new(Config::load()?);
/// let mut key_mgr = KeyManager::new(keystore, config);
///
/// // Generate an Ed25519 key
/// let metadata = key_mgr.generate_key(
///     "ed25519",
///     "My Key".to_string(),
///     b"strong-passphrase",
///     KeyGenOptions::default(),
/// )?;
///
/// println!("Generated key: {}", metadata.fingerprint);
/// ```
///
/// # Thread Safety
///
/// `KeyManager` is `Send` but not `Sync`. Wrap in `Arc<Mutex<>>` for shared access.
pub struct KeyManager { /* ... */ }
```

**Deliverables**:
- [ ] All public APIs documented
- [ ] Code examples included
- [ ] Rustdoc builds without warnings
- [ ] Python docstrings complete

#### Task 5.2: Migration Guide (1 day)

**Objective**: Help users update to refactored version

**File**: `docs/refactoring/MIGRATION_GUIDE.md`

**Contents**:
```markdown
# Migration Guide: v0.1.0 → v0.2.0

## Overview

Version 0.2.0 introduces significant architectural improvements. While most
high-level APIs remain compatible, there are some breaking changes.

## Breaking Changes

### Rust API

#### 1. Error Types Restructured

**Before**:
```rust
match result {
    Err(HbError::Rsa(msg)) => { /* string message */ }
    // ...
}
```

**After**:
```rust
match result {
    Err(HbError::Crypto(CryptoError::EncryptionFailed { reason })) => {
        // Structured error with context
    }
    // ...
}
```

**Migration**: Update error pattern matching to use nested error types.

#### 2. Direct Cipher Functions Deprecated

**Before**:
```rust
use hb_zayfer_core::aes_gcm;

let (nonce, ciphertext) = aes_gcm::encrypt(key, plaintext, aad)?;
```

**After**:
```rust
use hb_zayfer_core::crypto::{Cipher, AesGcmCipher};

let cipher = AesGcmCipher::new();
let encrypted = cipher.encrypt(key, plaintext, aad)?;
let nonce = &encrypted.nonce;
let ciphertext = &encrypted.ciphertext;
```

**Migration**: Use trait-based API. Old functions still work but are deprecated.

### Python API

#### 1. KeyManager Replaces Multiple Functions

**Before**:
```python
import hb_zayfer as hbz

# Generate key
priv_pem, pub_pem = hbz.ed25519_generate()
fp = hbz.ed25519_fingerprint(pub_pem)

# Store in keystore
ks = hbz.KeyStore()
ks.store_private_key(fp, priv_pem, passphrase, "Ed25519", "My Key")
ks.store_public_key(fp, pub_pem, "Ed25519", "My Key")
```

**After**:
```python
import hb_zayfer as hbz

# One-step key generation and storage
key_mgr = hbz.KeyManager()
metadata = key_mgr.generate_key("ed25519", "My Key", passphrase)
```

**Migration**: Use `KeyManager` for key operations. Old API still available.

## Deprecated APIs

The following APIs are deprecated and will be removed in v0.3.0:

- `hb_zayfer_core::aes_gcm::{encrypt, decrypt}` → Use `Cipher` trait
- `hb_zayfer_core::chacha20::{encrypt, decrypt}` → Use `Cipher` trait
- `hb_zayfer_core::format::encrypt_file_password` → Use `EncryptionService`

## Configuration Changes

### New Config Options

- `default_cipher`: Set preferred cipher ("aes256gcm" or "chacha20poly1305")
- `keystore_backend`: Choose storage backend ("file", "memory", "sqlite")

## Performance Improvements

- Ed25519 signing: ~20% faster
- File encryption: ~15% faster (reduced allocations)
- Key generation: ~10% faster

## Testing

Update your tests if you use internal APIs:

```rust
// Before
use hb_zayfer_core::format;

// After
use hb_zayfer_core::services::EncryptionService;
```
```

**Deliverables**:
- [ ] Migration guide written
- [ ] All breaking changes documented
- [ ] Deprecation warnings added to old APIs
- [ ] Examples updated

#### Task 5.3: Update User Documentation (1 day)

**Objective**: Update user-facing docs

**Files to update**:
1. `docs/USER_GUIDE.md` - Update commands, screenshots
2. `docs/QUICKSTART.md` - Update examples
3. `docs/CLI.md` - Update command reference
4. `docs/WEB_GUI.md` - Update API reference
5. `README.md` - Update examples

**Changes**:
- Update code examples to use new APIs
- Re-generate CLI help text
- Update performance numbers
- Add new features to feature list

**Deliverables**:
- [ ] All user docs updated
- [ ] Examples tested and working
- [ ] CLI help text regenerated
- [ ] No broken links

#### Task 5.4: Changelog & Release Notes (1 day)

**Objective**: Document all changes

**File**: `CHANGELOG.md`

**Template**:
```markdown
# Changelog

All notable changes to this project will be documented in this file.

## [0.2.0] - 2026-04-15

### Added
- Trait-based architecture for crypto algorithms (Cipher, Signer traits)
- Service layer (KeyManager, EncryptionService, SigningService)
- Structured error types with context preservation
- MemoryKeyStore for testing
- Generic cipher test suite
- 200+ new tests (coverage: 45% → 82%)

### Changed
- **BREAKING**: Error types restructured (HbError now has nested variants)
- **BREAKING**: Direct cipher functions deprecated (use Cipher trait)
- Refactored KeyStore to trait-based design
- CLI commands now use service layer
- GUI uses shared components
- Web API has better error handling
- Python exceptions now match Rust error types

### Improved
- Ed25519 signing performance: +20%
- File encryption performance: +15%
- Code reduced by ~600 lines (eliminated duplication)
- Better error messages with context
- Consistent API across interfaces

### Fixed
- Memory leak in streaming decryption
- GUI freeze on large file operations
- Incorrect error for wrong passphrase
- Race condition in concurrent key generation

### Deprecated
- `aes_gcm::encrypt/decrypt` (use `AesGcmCipher` instead)
- `chacha20::encrypt/decrypt` (use `ChaCha20Poly1305Cipher` instead)
- Direct keystore manipulation (use `KeyManager` instead)

### Removed
- None (all deprecated APIs still functional)

## [0.1.0] - 2026-03-08

Initial release.
```

**Deliverables**:
- [ ] Changelog updated
- [ ] Release notes drafted
- [ ] Version numbers bumped
- [ ] Git tags created

### Week 10: Final Polish

#### Task 5.5: Code Cleanup (2 days)

**Objective**: Final code quality improvements

**Tasks**:
1. Run `cargo fmt` on all Rust code
2. Run `clippy` and fix all warnings
3. Run `black` and `isort` on Python code
4. Run `mypy` for type checking
5. Fix all compiler warnings
6. Remove commented-out code
7. Remove unused imports
8. Update copyright headers

**Quality checks**:
```bash
# Rust
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo audit

# Python
black python/ tests/
isort python/ tests/
mypy python/
pylint python/

# Spell check docs
codespell docs/ *.md
```

**Deliverables**:
- [ ] Zero compiler warnings
- [ ] Zero clippy warnings
- [ ] Zero type errors
- [ ] Code formatted consistently
- [ ] No security advisories

#### Task 5.6: Performance Testing (1 day)

**Objective**: Verify performance improvements

**Benchmarks**:
```rust
// benches/crypto_benchmarks.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_ciphers(c: &mut Criterion) {
    let mut group = c.benchmark_group("symmetric_encryption");
    
    // Test different payload sizes
    for size in [1024, 64 * 1024, 1024 * 1024].iter() {
        let plaintext = vec![0u8; *size];
        let key = vec![0u8; 32];
        let aad = b"";
        
        // AES-256-GCM
        group.bench_with_input(
            BenchmarkId::new("AES-256-GCM", size),
            size,
            |b, _| {
                let cipher = AesGcmCipher::new();
                b.iter(|| {
                    cipher.encrypt(black_box(&key), black_box(&plaintext), black_box(aad))
                });
            },
        );
        
        // ChaCha20-Poly1305
        group.bench_with_input(
            BenchmarkId::new("ChaCha20-Poly1305", size),
            size,
            |b, _| {
                let cipher = ChaCha20Poly1305Cipher::new();
                b.iter(|| {
                    cipher.encrypt(black_box(&key), black_box(&plaintext), black_box(aad))
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(benches, bench_ciphers);
criterion_main!(benches);
```

**Performance targets** (vs v0.1.0):
- Ed25519 signing: ≥10% faster
- File encryption (1MB): ≥10% faster
- Key generation: No regression
- Keystore operations: No regression

**Deliverables**:
- [ ] Benchmark suite created
- [ ] Performance targets met
- [ ] Before/after comparison documented
- [ ] No performance regressions

#### Task 5.7: Security Audit Prep (1 day)

**Objective**: Prepare for external security review

**Tasks**:
1. Run `cargo audit` for dependency vulnerabilities
2. Review all uses of `unsafe` (should be zero in our code)
3. Review all uses of `unwrap()` and `expect()`
4. Check for timing vulnerabilities (constant-time operations)
5. Verify key zeroization happens correctly
6. Review all error messages (no secret leakage)
7. Check PRNG usage (all use OsRng)

**Security checklist**:
```markdown
## Security Checklist

### Cryptography
- [x] All crypto from audited libraries (RustCrypto, Dalek, Sequoia)
- [x] No custom crypto implementations
- [x] PRNG uses OS-provided randomness (OsRng)
- [x] Keys zeroized after use
- [x] Timing-safe comparisons for MACs

### Memory Safety
- [x] Zero uses of `unsafe` in our code
- [x] No dangling pointers
- [x] No use-after-free
- [x] Proper Drop implementations

### Error Handling
- [x] No panics in production code paths
- [x] All `unwrap()` usage checked and justified
- [x] Error messages don't leak secrets
- [x] No error type confusion

### Input Validation
- [x] All user inputs validated
- [x] File size limits enforced
- [x] Path traversal prevented
- [x] No SQL injection (using parameterized queries)

### Web Security
- [x] CORS properly configured
- [x] Authentication optional but secure
- [x] Rate limiting implemented
- [x] No XSS vectors
- [x] No CSRF possible

### Documentation
- [x] Threat model documented
- [x] Security assumptions explicit
- [x] Known limitations listed
- [x] Responsible disclosure process
```

**Deliverables**:
- [ ] Security audit checklist completed
- [ ] No critical security issues
- [ ] Dependency audit passes
- [ ] Security documentation updated

#### Task 5.8: CI/CD Updates (1 day)

**Objective**: Update CI for refactored codebase

**GitHub Actions updates**:
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, refactor/*]
  pull_request:

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, beta]
        python: ["3.10", "3.11", "3.12"]
    
    runs-on: ${{ matrix.os }}
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: ${{ matrix.rust }}
          override: true
          components: rustfmt, clippy
      
      - name: Check formatting
        run: cargo fmt --all -- --check
      
      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings
      
      - name: Run tests
        run: cargo test --workspace --all-features
      
      - name: Run benchmarks
        run: cargo bench --no-run
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python }}
      
      - name: Install dependencies
        run: |
          pip install maturin pytest pytest-cov
      
      - name: Build Python extension
        run: maturin develop --release -m crates/python/Cargo.toml
      
      - name: Run Python tests
        run: pytest tests/python/ --cov --cov-report=xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml

  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Security audit
        run: cargo audit
      - name: Dependency check
        run: cargo outdated --exit-code 1
```

**Additional checks**:
- Add `cargo-deny` for license compliance
- Add `cargo-geiger` for unsafe usage report
- Add documentation build check

**Deliverables**:
- [ ] CI updated for refactored code
- [ ] All CI checks passing
- [ ] Coverage reporting working
- [ ] Security checks added

---

## Risk Management

### High-Risk Areas

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| **Breaking existing user workflows** | High | Medium | Maintain backward compatibility, deprecation warnings |
| **New bugs introduced** | High | Medium | Comprehensive test suite (80%+ coverage) |
| **Performance regressions** | Medium | Low | Benchmark suite, performance CI checks |
| **Data loss during migration** | Critical | Low | Backup validation tests, migration scripts |
| **Incomplete refactoring** | Medium | Medium | Phased approach, track progress carefully |

### Mitigation Strategies

1. **Backward compatibility**:
   - Keep old APIs working (deprecated but functional)
   - Gradual migration path
   - Version both APIs for overlap period

2. **Testing**:
   - Test old + new APIs side-by-side
   - Run old test suite against new code
   - Add regression tests for known issues

3. **Rollback plan**:
   - Keep refactoring in feature branch until complete
   - Tag release points for easy rollback
   - Document rollback procedure

4. **Incremental merging**:
   - Merge Phase 1 first (foundation)
   - Merge Phase 2 second (core abstractions)
   - Merge Phase 3-5 together (interfaces + quality)

### Contingency Plans

**If timeline slips**:
- Priority: Phases 1-2 (foundation + core abstractions)
- Defer: Phase 5 polish items
- Skip: Nice-to-have documentation updates

**If critical bugs found**:
- Stop refactoring
- Fix bugs in separate branch
- Merge fixes to both main and refactor branches
- Resume refactoring

**If performance regresses**:
- Profile to find hotspots
- Optimize critical paths first
- Consider reverting specific changes if needed
- Add performance tests to prevent future regressions

---

## Success Metrics

### Quantitative Metrics

| Metric | Baseline (v0.1.0) | Target (v0.2.0) | How to Measure |
|--------|-------------------|-----------------|----------------|
| **Code duplication** | ~620 lines | <200 lines | `cargo-geiger --duplicates` |
| **Test coverage** | ~45% | ≥80% | `cargo tarpaulin`, `pytest-cov` |
| **Build time** | ~2m 15s | <2m 30s | CI timing |
| **Binary size** | ~4.2 MB | <5 MB | Release binary size |
| **Lines of code** | ~7,800 | ~7,200-7,400 | `tokei` |
| **Compiler warnings** | 3 | 0 | `cargo build` |
| **Clippy warnings** | 12 | 0 | `cargo clippy` |
| **Documentation coverage** | 60% | 90% | Rustdoc stats |

### Qualitative Metrics

- [ ] Adding new cipher takes <1 hour (trait implementation)
- [ ] Adding new storage backend takes <2 hours
- [ ] Error messages are actionable and clear
- [ ] API is intuitive (tested with new contributor)
- [ ] Code is well-commented and self-documenting
- [ ] Maintenance burden reduced (subjective assessment)

### User-Facing Metrics

- [ ] No breaking changes to CLI commands
- [ ] GUI workflows unchanged
- [ ] Web API v1 still supported
- [ ] Documentation covers all features
- [ ] Migration guide is complete and tested

---

## Migration Strategy

### For Development Team

**Week 0** (Before refactoring):
1. Freeze feature development on main branch
2. Create refactoring branch from latest main
3. Announce refactoring to team
4. Set up refactoring board/tracker

**During refactoring**:
1. Cherry-pick critical bug fixes from main to refactor branch
2. Keep refactor branch up to date with main (weekly merges)
3. Weekly progress updates
4. Code reviews for each phase

**After refactoring**:
1. Final merge from main to refactor branch
2. Full test suite run
3. Beta release for testing
4. Address feedback
5. Merge to main via PR
6. Tag v0.2.0 release

### For Users

**v0.1.x** (Current):
- Continue using stable release
- Bug fixes backported to v0.1.x branch

**v0.2.0-beta.1** (Testing):
- Opt-in beta testing
- Provide feedback on breaking changes
- Test migration process

**v0.2.0** (Stable):
- Follow migration guide
- Old APIs still work (deprecated)
- Update code gradually over next releases

**v0.3.0** (Future):
- Deprecated APIs removed
- Full transition to new architecture

### Versioning Strategy

Use semantic versioning (SemVer):
- `v0.2.0` - Major refactoring, breaking changes to internal APIs
- `v0.2.1, v0.2.2, ...` - Bug fixes, no breaking changes
- `v0.3.0` - Remove deprecated APIs, final transition

---

## Future Enhancements

*Out of scope for this refactoring, but enabled by new architecture:*

### Phase 6: Post-Quantum Cryptography
- Add `ml-kem` (CRYSTALS-Kyber) implementation
- Add `ml-dsa` (CRYSTALS-Dilithium) for signatures
- Hybrid modes (classical + PQC)
- Estimated: 3-4 weeks

### Phase 7: Hardware Security Module Support
- `PKCS#11` interface for HSM
- TPM integration for key protection
- Hardware key generation
- Estimated: 4-6 weeks

### Phase 8: Advanced Features
- Multi-recipient encryption (native in file format)
- Key escrow mechanisms
- Threshold signatures
- Steganography support
- Estimated: 6-8 weeks

### Phase 9: Storage Backends
- SQLite KeyStore implementation
- PostgreSQL backend for enterprise
- Distributed keystore (Redis, etcd)
- Cloud storage integration (S3, Azure Blob)
- Estimated: 4-6 weeks

### Phase 10: Performance Optimization
- SIMD vectorization for bulk operations
- GPU acceleration investigation
- Memory-mapped file I/O
- Zero-copy streaming
- Async/await for I/O operations
- Estimated: 6-8 weeks

---

## Conclusion

This refactoring plan addresses critical technical debt while maintaining stability and backward compatibility. The phased approach allows for incremental progress, testing, and adjustment.

**Key outcomes**:
- 60-70% reduction in code duplication
- Trait-based architecture for extensibility
- Unified error handling across layers
- 80%+ test coverage
- Better maintainability and developer experience

**Timeline**: 8-10 weeks with 1-2 developers

**Next steps**:
1. Review and approve this plan
2. Create refactoring branch
3. Set up tracking board
4. Begin Phase 1: Foundation

---

**Document Version**: 1.0  
**Last Updated**: March 8, 2026  
**Status**: Ready for Review  
**Author**: Development Team
