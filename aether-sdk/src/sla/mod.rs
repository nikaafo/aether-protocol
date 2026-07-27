//! SLA Enforcer — Quality of Service policies for Aether connections.
//!
//! Supports:
//! - YAML/JSON policy definitions
//! - Bandwidth quotas and latency guarantees  
//! - Stream priority QoS
//! - SLA violation alerts

use serde::{Deserialize, Serialize};

/// SLA Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaPolicy {
    /// Policy version
    pub version: String,
    /// Provider identifier
    pub provider: String,
    /// SLA guarantees
    pub guarantees: SlaGuarantees,
    /// QoS stream priorities
    pub qos: Option<QosConfig>,
    /// Alert thresholds
    pub alerts: Option<Vec<SlaAlert>>,
}

/// SLA guarantees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaGuarantees {
    /// Maximum handshake latency (p99, milliseconds)
    pub handshake_latency_p99_ms: u64,
    /// Minimum throughput (Mbps)
    pub throughput_min_mbps: u64,
    /// Availability percentage (e.g. 99.99)
    pub availability_pct: f64,
    /// Maximum concurrent streams
    pub max_concurrent_streams: u32,
    /// Maximum packet loss percentage
    pub max_packet_loss_pct: f64,
}

/// QoS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosConfig {
    /// Default stream priority (0-7, 0=background, 7=critical)
    pub default_priority: u8,
    /// Enable priority-based queueing
    pub priority_queueing: bool,
}

/// SLA alert threshold
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaAlert {
    /// Metric name to monitor
    pub metric: String,
    /// Threshold value
    pub threshold: f64,
    /// Alert action
    pub action: String,
}

impl SlaPolicy {
    /// Load SLA policy from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, String> {
        serde_yaml::from_str(yaml)
            .map_err(|e| format!("Failed to parse SLA policy: {}", e))
    }

    /// Load SLA policy from JSON string
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Failed to parse SLA policy: {}", e))
    }

    /// Check if the given metrics satisfy the SLA guarantees
    pub fn check_compliance(
        &self,
        handshake_p99_ms: u64,
        throughput_mbps: u64,
        packet_loss_pct: f64,
    ) -> SlaCompliance {
        let mut violations = Vec::new();

        if handshake_p99_ms > self.guarantees.handshake_latency_p99_ms {
            violations.push(format!(
                "Handshake latency p99 {}ms exceeds limit {}ms",
                handshake_p99_ms, self.guarantees.handshake_latency_p99_ms
            ));
        }

        if throughput_mbps < self.guarantees.throughput_min_mbps {
            violations.push(format!(
                "Throughput {}Mbps below minimum {}Mbps",
                throughput_mbps, self.guarantees.throughput_min_mbps
            ));
        }

        if packet_loss_pct > self.guarantees.max_packet_loss_pct {
            violations.push(format!(
                "Packet loss {}% exceeds limit {}%",
                packet_loss_pct, self.guarantees.max_packet_loss_pct
            ));
        }

        SlaCompliance {
            compliant: violations.is_empty(),
            violations,
        }
    }
}

/// SLA compliance check result
#[derive(Debug, Clone)]
pub struct SlaCompliance {
    /// Is the SLA satisfied?
    pub compliant: bool,
    /// List of violations (if any)
    pub violations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sla_policy_from_yaml() {
        let yaml = r#"
version: "1.0"
provider: "test-provider"
guarantees:
  handshake_latency_p99_ms: 100
  throughput_min_mbps: 100
  availability_pct: 99.99
  max_concurrent_streams: 10000
  max_packet_loss_pct: 0.01
"#;
        let policy = SlaPolicy::from_yaml(yaml).unwrap();
        assert_eq!(policy.guarantees.handshake_latency_p99_ms, 100);
        assert_eq!(policy.guarantees.throughput_min_mbps, 100);
    }

    #[test]
    fn test_sla_compliance_pass() {
        let policy = SlaPolicy {
            version: "1.0".into(),
            provider: "test".into(),
            guarantees: SlaGuarantees {
                handshake_latency_p99_ms: 100,
                throughput_min_mbps: 50,
                availability_pct: 99.9,
                max_concurrent_streams: 1000,
                max_packet_loss_pct: 0.01,
            },
            qos: None,
            alerts: None,
        };

        let result = policy.check_compliance(80, 60, 0.005);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_sla_compliance_fail() {
        let policy = SlaPolicy {
            version: "1.0".into(),
            provider: "test".into(),
            guarantees: SlaGuarantees {
                handshake_latency_p99_ms: 100,
                throughput_min_mbps: 50,
                availability_pct: 99.9,
                max_concurrent_streams: 1000,
                max_packet_loss_pct: 0.01,
            },
            qos: None,
            alerts: None,
        };

        let result = policy.check_compliance(150, 30, 0.02);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 3);
    }
}