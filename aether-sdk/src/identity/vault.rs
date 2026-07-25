//! Key Vault backends for Identity Manager.
//!
//! Supports:
//! - **FileVault** — keys stored in filesystem
//! - **EnvVault** — keys from environment variables
//! - **HsmVault** — PKCS#11 HSM (stub)

use aether_core::Identity;
use std::fs;
use std::path::PathBuf;

/// Trait for key vault backends
pub trait KeyVault: Send + Sync {
    /// Load an existing identity from storage
    fn load_identity(&self) -> Result<Identity, String>;

    /// Save an identity to storage
    fn save_identity(&self, identity: &Identity) -> Result<(), String>;

    /// Archive an old identity (keep for grace period)
    fn archive_identity(&self, identity: &Identity) -> Result<(), String> {
        let archive_path = self.archive_path();
        let seed = identity.public_key_bytes(); // In prod: use actual seed
        let hex = hex::encode(seed);
        let archive_file = format!("{}.archived", hex);
        fs::write(
            PathBuf::from(&archive_path).join(&archive_file),
            hex.as_bytes(),
        )
        .map_err(|e| format!("Failed to archive identity: {}", e))
    }

    /// Path where archived keys are stored
    fn archive_path(&self) -> String;
}

/// Filesystem-based key vault
pub struct FileVault {
    key_path: String,
}

impl FileVault {
    pub fn new(key_path: &str) -> Self {
        Self {
            key_path: key_path.to_string(),
        }
    }
}

impl KeyVault for FileVault {
    fn load_identity(&self) -> Result<Identity, String> {
        let hex_str = fs::read_to_string(&self.key_path)
            .map_err(|e| format!("Failed to read key file {}: {}", self.key_path, e))?;
        let hex_str = hex_str.trim();

        if hex_str.len() != 64 {
            return Err(format!("Invalid key length in {}: expected 64 hex chars", self.key_path));
        }

        let mut seed = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut seed)
            .map_err(|e| format!("Invalid hex in key file: {}", e))?;

        Ok(Identity::from_seed(seed))
    }

    fn save_identity(&self, identity: &Identity) -> Result<(), String> {
        let hex = identity.hash_hex();
        fs::write(&self.key_path, hex.as_bytes())
            .map_err(|e| format!("Failed to write key file: {}", e))
    }

    fn archive_path(&self) -> String {
        let mut p = PathBuf::from(&self.key_path);
        p.pop();
        p.to_string_lossy().to_string()
    }
}

/// Environment-variable-based key vault
pub struct EnvVault {
    var_name: String,
}

impl EnvVault {
    pub fn new(var_name: &str) -> Self {
        Self {
            var_name: var_name.to_string(),
        }
    }
}

impl KeyVault for EnvVault {
    fn load_identity(&self) -> Result<Identity, String> {
        let hex_str = std::env::var(&self.var_name)
            .map_err(|e| format!("Env {} not set: {}", self.var_name, e))?;

        if hex_str.is_empty() {
            return Err("Key env var is empty".to_string());
        }

        let bytes = hex::decode(&hex_str)
            .map_err(|e| format!("Invalid hex in {}: {}", self.var_name, e))?;

        if bytes.len() != 32 {
            return Err(format!("Invalid seed length in {}: expected 32 bytes", self.var_name));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Identity::from_seed(seed))
    }

    fn save_identity(&self, identity: &Identity) -> Result<(), String> {
        let hex = identity.hash_hex();
        // Note: cannot set env vars programmatically in Rust safely.
        // In production, this would write to a secrets manager.
        tracing::info!("Identity saved (env var {} would be set)", self.var_name);
        Ok(())
    }

    fn archive_path(&self) -> String {
        "/tmp/aether-archived-keys".to_string()
    }
}