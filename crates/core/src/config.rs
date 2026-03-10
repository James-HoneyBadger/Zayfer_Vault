//! Configuration management for HB_Zayfer.
//!
//! Provides persistent configuration storage at `~/.hb_zayfer/config.toml`
//! with support for setting defaults and user preferences.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{HbError, HbResult};
use crate::format::SymmetricAlgorithm;
use crate::kdf::KdfParams;

/// Application configuration with user preferences and defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default symmetric encryption algorithm
    #[serde(default)]
    pub default_symmetric_algorithm: SymmetricAlgorithm,
    
    /// Default KDF parameters for key encryption
    #[serde(default)]
    pub default_kdf: KdfParams,
    
    /// Default KDF preset level (low, medium, high, paranoid)
    #[serde(default = "default_kdf_preset")]
    pub kdf_preset: KdfPreset,
    
    /// Default chunk size for file encryption (in bytes)
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
    
    /// Default output directory for encrypted files
    pub default_output_dir: Option<PathBuf>,
    
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enable_audit_log: bool,
    
    /// Enable compression before encryption for files larger than this size (bytes)
    pub auto_compress_threshold: Option<u64>,
    
    /// GUI preferences
    #[serde(default)]
    pub gui: GuiConfig,
    
    /// CLI preferences
    #[serde(default)]
    pub cli: CliConfig,
}

/// KDF preset levels with predefined security/performance trade-offs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfPreset {
    /// Fast operations, minimal security (testing only)
    Low,
    /// Balanced for interactive use (default)
    Medium,
    /// Higher security for sensitive keys
    High,
    /// Maximum security for critical keys
    Paranoid,
}

impl KdfPreset {
    /// Get KDF parameters for this preset.
    pub fn params(&self) -> KdfParams {
        match self {
            KdfPreset::Low => KdfParams::argon2id(16 * 1024, 2, 1),      // 16 MB, 2 iterations
            KdfPreset::Medium => KdfParams::argon2id(64 * 1024, 3, 1),   // 64 MB, 3 iterations (default)
            KdfPreset::High => KdfParams::argon2id(256 * 1024, 4, 1),    // 256 MB, 4 iterations
            KdfPreset::Paranoid => KdfParams::argon2id(1024 * 1024, 5, 2), // 1 GB, 5 iterations, 2 threads
        }
    }
}

impl Default for KdfPreset {
    fn default() -> Self {
        KdfPreset::Medium
    }
}

/// GUI-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    /// Use dark theme
    #[serde(default)]
    pub dark_mode: bool,
    
    /// Recent files list (max 10)
    #[serde(default)]
    pub recent_files: Vec<PathBuf>,
    
    /// Show password strength indicator
    #[serde(default = "default_true")]
    pub show_password_strength: bool,
    
    /// Window geometry (x, y, width, height)
    pub window_geometry: Option<(i32, i32, i32, i32)>,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            dark_mode: false,
            recent_files: Vec::new(),
            show_password_strength: true,
            window_geometry: None,
        }
    }
}

/// CLI-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Enable colored output
    #[serde(default = "default_true")]
    pub color: bool,
    
    /// Show progress bars for long operations
    #[serde(default = "default_true")]
    pub progress: bool,
    
    /// Verbosity level (0 = quiet, 1 = normal, 2 = verbose)
    #[serde(default = "default_verbosity")]
    pub verbosity: u8,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            color: true,
            progress: true,
            verbosity: 1,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let kdf_preset = KdfPreset::default();
        Self {
            default_symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
            default_kdf: kdf_preset.params(),
            kdf_preset,
            chunk_size: default_chunk_size(),
            default_output_dir: None,
            enable_audit_log: true,
            auto_compress_threshold: None,
            gui: GuiConfig::default(),
            cli: CliConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from the default location (~/.hb_zayfer/config.toml).
    pub fn load_default() -> HbResult<Self> {
        let config_path = Self::default_path()?;
        if config_path.exists() {
            Self::load(&config_path)
        } else {
            Ok(Self::default())
        }
    }
    
    /// Load configuration from a specific path.
    pub fn load(path: &Path) -> HbResult<Self> {
        let contents = fs::read_to_string(path)
            .map_err(|e| HbError::Config(format!("Failed to read config file: {}", e)))?;
        
        let mut config: Config = toml::from_str(&contents)
            .map_err(|e| HbError::Config(format!("Failed to parse config file: {}", e)))?;
        
        // Clamp chunk_size to valid range
        const MIN_CHUNK: usize = 4 * 1024;
        const MAX_CHUNK: usize = 16 * 1024 * 1024;
        if config.chunk_size < MIN_CHUNK {
            config.chunk_size = MIN_CHUNK;
        } else if config.chunk_size > MAX_CHUNK {
            config.chunk_size = MAX_CHUNK;
        }
        
        Ok(config)
    }
    
    /// Save configuration to the default location.
    pub fn save_default(&self) -> HbResult<()> {
        let config_path = Self::default_path()?;
        self.save(&config_path)
    }
    
    /// Save configuration to a specific path.
    pub fn save(&self, path: &Path) -> HbResult<()> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| HbError::Config(format!("Failed to create config directory: {}", e)))?;
        }
        
        let contents = toml::to_string_pretty(self)
            .map_err(|e| HbError::Config(format!("Failed to serialize config: {}", e)))?;
        
        // Write atomically
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, contents)
            .map_err(|e| HbError::Config(format!("Failed to write config file: {}", e)))?;
        fs::rename(&tmp, path)
            .map_err(|e| HbError::Config(format!("Failed to save config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Get the default config path (~/.hb_zayfer/config.toml).
    pub fn default_path() -> HbResult<PathBuf> {
        let home = dirs::home_dir()
            .ok_or_else(|| HbError::Config("Could not determine home directory".into()))?;
        Ok(home.join(".hb_zayfer").join("config.toml"))
    }
    
    /// Set a configuration value by key.
    pub fn set(&mut self, key: &str, value: &str) -> HbResult<()> {
        match key {
            "default-algorithm" | "default_algorithm" => {
                self.default_symmetric_algorithm = match value.to_lowercase().as_str() {
                    "aes" | "aes-256-gcm" | "aes256gcm" => SymmetricAlgorithm::Aes256Gcm,
                    "chacha" | "chacha20" | "chacha20-poly1305" => SymmetricAlgorithm::ChaCha20Poly1305,
                    _ => return Err(HbError::Config(format!("Invalid algorithm: {}", value))),
                };
            }
            "kdf-preset" | "kdf_preset" => {
                self.kdf_preset = match value.to_lowercase().as_str() {
                    "low" => KdfPreset::Low,
                    "medium" => KdfPreset::Medium,
                    "high" => KdfPreset::High,
                    "paranoid" => KdfPreset::Paranoid,
                    _ => return Err(HbError::Config(format!("Invalid KDF preset: {}", value))),
                };
                self.default_kdf = self.kdf_preset.params();
            }
            "chunk-size" | "chunk_size" => {
                let size: usize = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid chunk size: {}", value)))?;
                const MIN_CHUNK: usize = 4 * 1024;        // 4 KiB
                const MAX_CHUNK: usize = 16 * 1024 * 1024; // 16 MiB
                if size < MIN_CHUNK || size > MAX_CHUNK {
                    return Err(HbError::Config(format!(
                        "Chunk size must be between {} and {} bytes, got {}",
                        MIN_CHUNK, MAX_CHUNK, size
                    )));
                }
                self.chunk_size = size;
            }
            "audit-log" | "audit_log" | "enable-audit-log" | "enable_audit_log" => {
                self.enable_audit_log = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid boolean: {}", value)))?;
            }
            "dark-mode" | "dark_mode" => {
                self.gui.dark_mode = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid boolean: {}", value)))?;
            }
            "color" => {
                self.cli.color = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid boolean: {}", value)))?;
            }
            "progress" => {
                self.cli.progress = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid boolean: {}", value)))?;
            }
            "verbosity" => {
                self.cli.verbosity = value.parse()
                    .map_err(|_| HbError::Config(format!("Invalid verbosity: {}", value)))?;
            }
            _ => return Err(HbError::Config(format!("Unknown config key: {}", key))),
        }
        Ok(())
    }
    
    /// Get a configuration value by key as a string.
    pub fn get(&self, key: &str) -> HbResult<String> {
        match key {
            "default-algorithm" | "default_algorithm" => {
                Ok(format!("{:?}", self.default_symmetric_algorithm))
            }
            "kdf-preset" | "kdf_preset" => {
                Ok(format!("{:?}", self.kdf_preset))
            }
            "chunk-size" | "chunk_size" => {
                Ok(self.chunk_size.to_string())
            }
            "audit-log" | "audit_log" | "enable-audit-log" | "enable_audit_log" => {
                Ok(self.enable_audit_log.to_string())
            }
            "dark-mode" | "dark_mode" => {
                Ok(self.gui.dark_mode.to_string())
            }
            "color" => {
                Ok(self.cli.color.to_string())
            }
            "progress" => {
                Ok(self.cli.progress.to_string())
            }
            "verbosity" => {
                Ok(self.cli.verbosity.to_string())
            }
            _ => Err(HbError::Config(format!("Unknown config key: {}", key))),
        }
    }
    
    /// Add a file to recent files list (GUI).
    pub fn add_recent_file(&mut self, path: PathBuf) {
        // Remove if already in list
        self.gui.recent_files.retain(|p| p != &path);
        
        // Add to front
        self.gui.recent_files.insert(0, path);
        
        // Keep only last 10
        if self.gui.recent_files.len() > 10 {
            self.gui.recent_files.truncate(10);
        }
    }
}

// Helper functions for serde defaults
fn default_chunk_size() -> usize {
    65536 // 64 KiB
}

fn default_true() -> bool {
    true
}

fn default_verbosity() -> u8 {
    1
}

fn default_kdf_preset() -> KdfPreset {
    KdfPreset::Medium
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.default_symmetric_algorithm, SymmetricAlgorithm::Aes256Gcm);
        assert_eq!(config.kdf_preset, KdfPreset::Medium);
        assert_eq!(config.chunk_size, 65536);
        assert!(config.enable_audit_log);
    }
    
    #[test]
    fn test_config_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        
        let mut config = Config::default();
        config.default_symmetric_algorithm = SymmetricAlgorithm::ChaCha20Poly1305;
        config.kdf_preset = KdfPreset::High;
        config.gui.dark_mode = true;
        
        config.save(&config_path).unwrap();
        
        let loaded = Config::load(&config_path).unwrap();
        assert_eq!(loaded.default_symmetric_algorithm, SymmetricAlgorithm::ChaCha20Poly1305);
        assert_eq!(loaded.kdf_preset, KdfPreset::High);
        assert!(loaded.gui.dark_mode);
    }
    
    #[test]
    fn test_config_set_get() {
        let mut config = Config::default();
        
        config.set("default-algorithm", "chacha").unwrap();
        assert_eq!(config.default_symmetric_algorithm, SymmetricAlgorithm::ChaCha20Poly1305);
        
        config.set("kdf-preset", "high").unwrap();
        assert_eq!(config.kdf_preset, KdfPreset::High);
        
        config.set("dark-mode", "true").unwrap();
        assert!(config.gui.dark_mode);
        
        assert_eq!(config.get("verbosity").unwrap(), "1");
    }
    
    #[test]
    fn test_recent_files() {
        let mut config = Config::default();
        
        for i in 0..15 {
            config.add_recent_file(PathBuf::from(format!("/tmp/file{}.txt", i)));
        }
        
        // Should keep only last 10
        assert_eq!(config.gui.recent_files.len(), 10);
        
        // Most recent should be first
        assert_eq!(config.gui.recent_files[0], PathBuf::from("/tmp/file14.txt"));
    }
    
    #[test]
    fn test_kdf_presets() {
        match KdfPreset::Low.params() {
            KdfParams::Argon2id(p) => assert_eq!(p.m_cost, 16 * 1024),
            _ => panic!("Expected Argon2id params"),
        }
        match KdfPreset::Paranoid.params() {
            KdfParams::Argon2id(p) => {
                assert_eq!(p.m_cost, 1024 * 1024);
                assert_eq!(p.t_cost, 5);
                assert_eq!(p.p_cost, 2);
            }
            _ => panic!("Expected Argon2id params"),
        }
    }
}
