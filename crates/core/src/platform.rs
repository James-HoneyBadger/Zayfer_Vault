//! Shared platform metadata and path resolution.
//!
//! These types provide a single Rust-native source of truth for application
//! identity and filesystem layout so CLI, server, and future desktop targets
//! can all use the same conventions.

use std::path::PathBuf;

use crate::{HbError, HbResult};

/// Application identity shared across all Rust entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub brand_name: &'static str,
    pub binary_name: &'static str,
    pub package_name: &'static str,
    pub version: &'static str,
}

impl AppInfo {
    /// Return the current application identity.
    pub fn current() -> Self {
        Self {
            brand_name: "Zayfer Vault",
            binary_name: "hb-zayfer",
            package_name: "hb_zayfer",
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    /// Human-friendly application title.
    pub fn window_title(&self) -> String {
        format!("{} v{}", self.brand_name, self.version)
    }
}

/// Standardized application storage locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub user_home: PathBuf,
    pub app_home: PathBuf,
    pub config_path: PathBuf,
    pub audit_path: PathBuf,
}

impl AppPaths {
    /// Resolve the current user-home and app-home paths.
    pub fn current() -> HbResult<Self> {
        let user_home = dirs::home_dir()
            .ok_or_else(|| HbError::Config("Could not determine home directory".into()))?;

        let app_home = std::env::var("HB_ZAYFER_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| user_home.join(".hb_zayfer"));

        Ok(Self {
            user_home,
            config_path: app_home.join("config.toml"),
            audit_path: app_home.join("audit.log"),
            app_home,
        })
    }

    /// Resolve a user-supplied path and ensure it remains within the real home directory.
    pub fn resolve_user_path(&self, raw_path: &str, field_name: &str) -> HbResult<PathBuf> {
        let resolved = PathBuf::from(raw_path)
            .expand_home()
            .ok_or_else(|| HbError::Config(format!("Invalid {}: {}", field_name, raw_path)))?
            .canonical_or_self();

        if !resolved.starts_with(&self.user_home) && !resolved.starts_with(&self.app_home) {
            return Err(HbError::Config(format!(
                "{} must be within the configured application or user home directory",
                field_name
            )));
        }

        Ok(resolved)
    }
}

trait PathExt {
    fn expand_home(self) -> Option<PathBuf>;
    fn canonical_or_self(self) -> PathBuf;
}

impl PathExt for PathBuf {
    fn expand_home(self) -> Option<PathBuf> {
        let path = self;
        if let Ok(stripped) = path.strip_prefix("~") {
            let home = dirs::home_dir()?;
            Some(home.join(stripped))
        } else {
            Some(path)
        }
    }

    fn canonical_or_self(self) -> PathBuf {
        self.canonicalize().unwrap_or(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_info_is_consistent() {
        let info = AppInfo::current();
        assert_eq!(info.brand_name, "Zayfer Vault");
        assert!(info.window_title().contains(info.version));
    }

    #[test]
    fn app_paths_have_expected_suffixes() {
        let paths = AppPaths::current().unwrap();
        assert!(paths.config_path.ends_with("config.toml"));
        assert!(paths.audit_path.ends_with("audit.log"));
    }
}
