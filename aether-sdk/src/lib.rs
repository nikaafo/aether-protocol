//! # Aether Enterprise SDK
//!
//! Production-ready SDK for Aether Protocol with:
//! - **Identity Manager** — HSM/Vault/KMS key storage, auto-rotation, federation
//! - **Monitoring** — Prometheus metrics, OpenTelemetry tracing, Grafana dashboards
//! - **SLA Enforcer** — QoS policies, bandwidth quotas, latency guarantees

pub mod identity;
pub mod monitoring;
pub mod sla;

pub use identity::IdentityManager;
pub use monitoring::AetherMetrics;
pub use sla::SlaPolicy;