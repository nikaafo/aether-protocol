//! Monitoring & Observability for Aether Protocol.
//!
//! Provides Prometheus metrics and OpenTelemetry tracing for:
//! - Connection lifecycle (active, duration, handshake latency)
//! - Stream statistics (bytes sent/received, flow control blocks)
//! - Multi-path (path migrations, RTT per path)
//! - Crypto operations (key rotations, decrypt errors)

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use std::time::Instant;

/// Register all Aether metrics descriptions (call once at startup)
pub fn register_metrics() {
    describe_gauge!("aether_connections_active", "Active Aether connections");
    describe_counter!("aether_connections_total", "Total connections opened");
    describe_counter!("aether_handshake_success_total", "Successful handshakes");
    describe_counter!("aether_handshake_failure_total", "Failed handshakes");
    describe_histogram!("aether_handshake_duration_seconds", "Handshake duration in seconds");

    describe_counter!("aether_streams_opened_total", "Total streams opened");
    describe_counter!("aether_streams_closed_total", "Total streams closed");
    describe_counter!("aether_stream_bytes_sent_total", "Total bytes sent");
    describe_counter!("aether_stream_bytes_received_total", "Total bytes received");

    describe_counter!("aether_path_migrations_total", "Total path migrations");
    describe_histogram!("aether_path_rtt_microseconds", "Path RTT in microseconds");

    describe_counter!("aether_key_rotations_total", "Total key rotations");
    describe_counter!("aether_decrypt_errors_total", "Total decrypt errors");
}

/// Aether metrics registry
pub struct AetherMetrics {
    start_time: Instant,
}

impl AetherMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        register_metrics();
        Self {
            start_time: Instant::now(),
        }
    }

    /// Record a new connection
    pub fn connection_opened(&self) {
        gauge!("aether_connections_active").increment(1.0);
        counter!("aether_connections_total").increment(1);
    }

    /// Record a closed connection
    pub fn connection_closed(&self) {
        gauge!("aether_connections_active").decrement(1.0);
    }

    /// Record handshake result
    pub fn handshake_completed(&self, success: bool, duration_ms: u64) {
        if success {
            counter!("aether_handshake_success_total").increment(1);
        } else {
            counter!("aether_handshake_failure_total").increment(1);
        }
        histogram!("aether_handshake_duration_seconds").record(duration_ms as f64 / 1000.0);
    }

    /// Record stream opened
    pub fn stream_opened(&self) {
        counter!("aether_streams_opened_total").increment(1);
    }

    /// Record stream closed
    pub fn stream_closed(&self) {
        counter!("aether_streams_closed_total").increment(1);
    }

    /// Record bytes sent on a stream
    pub fn bytes_sent(&self, count: u64) {
        counter!("aether_stream_bytes_sent_total").increment(count);
    }

    /// Record bytes received on a stream
    pub fn bytes_received(&self, count: u64) {
        counter!("aether_stream_bytes_received_total").increment(count);
    }

    /// Record path migration
    pub fn path_migrated(&self) {
        counter!("aether_path_migrations_total").increment(1);
    }

    /// Record path RTT
    pub fn path_rtt(&self, rtt_us: u64) {
        histogram!("aether_path_rtt_microseconds").record(rtt_us as f64);
    }

    /// Record key rotation
    pub fn key_rotated(&self) {
        counter!("aether_key_rotations_total").increment(1);
    }

    /// Record decrypt error
    pub fn decrypt_error(&self) {
        counter!("aether_decrypt_errors_total").increment(1);
    }

    /// Uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }
}

impl Default for AetherMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_basics() {
        let m = AetherMetrics::new();

        m.connection_opened();
        m.connection_opened();
        m.connection_closed();

        m.handshake_completed(true, 50);
        m.handshake_completed(false, 500);

        m.stream_opened();
        m.bytes_sent(1024);
        m.bytes_received(512);

        assert!(m.uptime_secs() < 5);
    }
}