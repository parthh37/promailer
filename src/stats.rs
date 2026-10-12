//! Lock-free counters exposed via the API (`/api/v1/stats`) and Prometheus (`/metrics`).

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub auth_success: AtomicU64,
    pub auth_failure: AtomicU64,
    pub messages_received: AtomicU64,
    pub messages_rejected: AtomicU64,
    pub bytes_received: AtomicU64,
    pub recipients_delivered: AtomicU64,
    pub recipients_deferred: AtomicU64,
    pub recipients_bounced: AtomicU64,
    pub ndr_generated: AtomicU64,
    pub badmail: AtomicU64,
    pub pickup_processed: AtomicU64,
    pub api_messages: AtomicU64,
}

#[derive(Serialize)]
pub struct StatsSnapshot {
    pub uptime_seconds: u64,
    pub connections_active: usize,
    pub connections_total: u64,
    pub connections_rejected: u64,
    pub auth_success: u64,
    pub auth_failure: u64,
    pub messages_received: u64,
    pub messages_rejected: u64,
    pub bytes_received: u64,
    pub recipients_delivered: u64,
    pub recipients_deferred: u64,
    pub recipients_bounced: u64,
    pub ndr_generated: u64,
    pub badmail: u64,
    pub pickup_processed: u64,
    pub api_messages: u64,
    pub queue_size: usize,
    pub deliveries_in_flight: usize,
}

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }

    pub fn snapshot(&self, uptime: u64, active: usize, queue_size: usize, in_flight: usize) -> StatsSnapshot {
        let g = |c: &AtomicU64| c.load(Relaxed);
        StatsSnapshot {
            uptime_seconds: uptime,
            connections_active: active,
            connections_total: g(&self.connections_total),
            connections_rejected: g(&self.connections_rejected),
            auth_success: g(&self.auth_success),
            auth_failure: g(&self.auth_failure),
            messages_received: g(&self.messages_received),
            messages_rejected: g(&self.messages_rejected),
            bytes_received: g(&self.bytes_received),
            recipients_delivered: g(&self.recipients_delivered),
            recipients_deferred: g(&self.recipients_deferred),
            recipients_bounced: g(&self.recipients_bounced),
            ndr_generated: g(&self.ndr_generated),
            badmail: g(&self.badmail),
            pickup_processed: g(&self.pickup_processed),
            api_messages: g(&self.api_messages),
            queue_size,
            deliveries_in_flight: in_flight,
        }
    }
}

impl StatsSnapshot {
    pub fn to_prometheus(&self) -> String {
        let v = serde_json::to_value(self).unwrap_or_default();
        let mut out = String::new();
        if let Some(map) = v.as_object() {
            for (k, val) in map {
                let kind = if k.ends_with("_total")
                    || matches!(
                        k.as_str(),
                        "connections_rejected"
                            | "auth_success"
                            | "auth_failure"
                            | "messages_received"
                            | "messages_rejected"
                            | "bytes_received"
                            | "recipients_delivered"
                            | "recipients_deferred"
                            | "recipients_bounced"
                            | "ndr_generated"
                            | "badmail"
                            | "pickup_processed"
                            | "api_messages"
                    ) {
                    "counter"
                } else {
                    "gauge"
                };
                out.push_str(&format!("# TYPE promailer_{k} {kind}\npromailer_{k} {val}\n"));
            }
        }
        out
    }
}
