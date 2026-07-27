//! Automatic key rotation for Aether identities.
//!
//! Handles periodic key rotation with configurable intervals,
//! grace periods for old keys, and automatic or manual triggers.

use serde::{Deserialize, Serialize};

/// Policy for automatic key rotation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Rotate every N days
    pub interval_days: u32,
    /// Grace period for old keys (seconds)
    pub grace_period_secs: u64,
    /// Automatically generate new keys
    pub auto_rotate: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            interval_days: 30,
            grace_period_secs: 3600,
            auto_rotate: true,
        }
    }
}