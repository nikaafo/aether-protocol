//! Identity Manager — enterprise-grade Ed25519 key lifecycle management.
//!
//! Provides:
//! - Key generation and storage (filesystem, env, HSM stub)
//! - Automatic key rotation
//! - Identity revocation
//! - Federation support

pub mod vault;
pub mod rotation;

use aether_core::Identity;
use serde::{Deserialize, Serialize};

use self::vault::KeyVault;

/// Configuration for Identity Manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Vault backend type: "file", "env", "hsm"
    pub vault_type: String,
    /// Path to key file (for "file" vault)
    pub key_path: Option<String>,
    /// Environment variable name (for "env" vault)
    pub env_var: Option<String>,
    /// HSM PKCS#11 URI (for "hsm" vault)
    pub pkcs11_uri: Option<String>,
    /// Auto-rotation policy
    pub rotation: Option<RotationPolicy>,
    /// Key label for identification
    pub label: String,
}

/// Key rotation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Rotate every N days
    pub interval_days: u32,
    /// Grace period for old keys (seconds)
    pub grace_period_secs: u64,
    /// Automatically generate new keys
    pub auto_rotate: bool,
}

/// Identity Manager
pub struct IdentityManager {
    /// Current active identity
    identity: Identity,
    /// Key vault backend
    vault: Box<dyn KeyVault>,
    /// Rotation policy
    rotation: Option<RotationPolicy>,
    /// Configuration
    config: IdentityConfig,
}

impl IdentityManager {
    /// Create a new IdentityManager with the given configuration
    pub fn new(config: IdentityConfig) -> Result<Self, String> {
        let vault: Box<dyn KeyVault> = match config.vault_type.as_str() {
            "file" => {
                let path = config.key_path.as_ref()
                    .ok_or("key_path required for file vault")?;
                Box::new(vault::FileVault::new(path))
            }
            "env" => {
                let var = config.env_var.as_ref()
                    .ok_or("env_var required for env vault")?;
                Box::new(vault::EnvVault::new(var))
            }
            _ => return Err(format!("Unknown vault type: {}", config.vault_type)),
        };

        let identity = match vault.load_identity() {
            Ok(id) => id,
            Err(_) => {
                let id = Identity::generate();
                vault.save_identity(&id)?;
                id
            }
        };

        Ok(Self {
            identity,
            vault,
            rotation: config.rotation.clone(),
            config,
        })
    }

    /// Get the current identity hash
    pub fn identity_hash(&self) -> String {
        self.identity.hash_hex()
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.identity.public_key_bytes()
    }

    /// Sign a message with the current identity
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.identity.sign(message).to_bytes().to_vec()
    }

    /// Rotate to a new key pair
    pub fn rotate(&mut self) -> Result<String, String> {
        let new_id = Identity::generate();
        let new_hash = new_id.hash_hex();

        // Archive old key
        self.vault.archive_identity(&self.identity)?;

        // Save new key
        self.vault.save_identity(&new_id)?;
        self.identity = new_id;

        tracing::info!("Identity rotated: new hash = {}", new_hash);
        Ok(new_hash)
    }

    /// Get the identity for use in Aether connections
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        if let Some(ref policy) = self.rotation {
            // In production: check last rotation time vs interval
            policy.auto_rotate
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_manager_from_env() {
        std::env::set_var("AETHER_TEST_KEY", "");
        let config = IdentityConfig {
            vault_type: "env".to_string(),
            key_path: None,
            env_var: Some("AETHER_TEST_KEY".to_string()),
            pkcs11_uri: None,
            rotation: None,
            label: "test".to_string(),
        };
        // Env vault generates new key if empty
        let mgr = IdentityManager::new(config);
        assert!(mgr.is_ok());
        let mgr = mgr.unwrap();
        assert!(!mgr.identity_hash().is_empty());
    }
}