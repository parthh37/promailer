//! IP access control, connection accounting and rate limiting.

use crate::config::{AccessConfig, DefaultPolicy};
use ipnet::IpNet;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Normalise IPv4-mapped IPv6 (`::ffff:1.2.3.4`) so v4 rules match dual-stack sockets.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub fn in_list(list: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    list.iter().any(|net| net.contains(&ip))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectDecision {
    Allow,
    Deny,
}

/// IIS "Connection control" semantics: deny list always wins; then the allow list;
/// then the default policy.
pub fn connection_allowed(cfg: &AccessConfig, ip: IpAddr) -> ConnectDecision {
    if in_list(&cfg.deny, ip) {
        return ConnectDecision::Deny;
    }
    if in_list(&cfg.allow, ip) {
        return ConnectDecision::Allow;
    }
    match cfg.default {
        DefaultPolicy::Allow => ConnectDecision::Allow,
        DefaultPolicy::Deny => ConnectDecision::Deny,
    }
}

// ---------------------------------------------------------------------------
// Connection tracker (global + per-IP concurrent connections)
// ---------------------------------------------------------------------------

pub struct ConnectionTracker {
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    total: Mutex<usize>,
}

/// RAII slot; dropping it releases the connection count.
pub struct ConnectionSlot {
    tracker: Arc<ConnectionTracker>,
    ip: IpAddr,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut per_ip = self.tracker.per_ip.lock();
        if let Some(n) = per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&self.ip);
            }
        }
        drop(per_ip);
        *self.tracker.total.lock() -= 1;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SlotError {
    TooManyTotal,
    TooManyFromIp,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { per_ip: Mutex::new(HashMap::new()), total: Mutex::new(0) })
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
        max_total: usize,
        max_per_ip: usize,
    ) -> Result<ConnectionSlot, SlotError> {
        let ip = canonical_ip(ip);
        let mut total = self.total.lock();
        if max_total > 0 && *total >= max_total {
            return Err(SlotError::TooManyTotal);
        }
        let mut per_ip = self.per_ip.lock();
        let n = per_ip.entry(ip).or_insert(0);
        if max_per_ip > 0 && *n >= max_per_ip {
            if *n == 0 {
                per_ip.remove(&ip);
            }
            return Err(SlotError::TooManyFromIp);
        }
        *n += 1;
        *total += 1;
        Ok(ConnectionSlot { tracker: self.clone(), ip })
    }

    pub fn active(&self) -> usize {
        *self.total.lock()
    }
}

// ---------------------------------------------------------------------------
// Token-bucket rate limiter keyed by IP / username / API key
// ---------------------------------------------------------------------------

struct Bucket {
    tokens: f64,
    last: Instant,
}

pub struct RateLimiter<K> {
    buckets: Mutex<HashMap<K, Bucket>>,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    pub fn new() -> Self {
        Self { buckets: Mutex::new(HashMap::new()) }
    }

    /// Consume one token from a bucket that refills at `per_minute` tokens/minute
    /// with burst = `per_minute`. `per_minute == 0` means unlimited.
    pub fn check(&self, key: &K, per_minute: u32) -> bool {
        if per_minute == 0 {
            return true;
        }
        let cap = per_minute as f64;
        let rate = cap / 60.0;
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let bucket = map.entry(key.clone()).or_insert(Bucket { tokens: cap, last: now });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(cap);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop buckets idle long enough to be full again (bounded memory).
    pub fn cleanup(&self, idle_secs: u64) {
        let now = Instant::now();
        self.buckets.lock().retain(|_, b| now.duration_since(b.last).as_secs() < idle_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn deny_wins_over_allow() {
        let cfg = AccessConfig {
            default: DefaultPolicy::Deny,
            allow: vec![IpNet::from_str("10.0.0.0/8").unwrap()],
            deny: vec![IpNet::from_str("10.0.0.5/32").unwrap()],
            ..Default::default()
        };
        assert_eq!(connection_allowed(&cfg, "10.1.1.1".parse().unwrap()), ConnectDecision::Allow);
        assert_eq!(connection_allowed(&cfg, "10.0.0.5".parse().unwrap()), ConnectDecision::Deny);
        assert_eq!(connection_allowed(&cfg, "8.8.8.8".parse().unwrap()), ConnectDecision::Deny);
    }

    #[test]
    fn mapped_ipv6_matches_v4_rule() {
        let list = vec![IpNet::from_str("127.0.0.1/32").unwrap()];
        assert!(in_list(&list, "::ffff:127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn tracker_limits() {
        let t = ConnectionTracker::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let a = t.try_acquire(ip, 10, 2).unwrap();
        let _b = t.try_acquire(ip, 10, 2).unwrap();
        assert_eq!(t.try_acquire(ip, 10, 2).err(), Some(SlotError::TooManyFromIp));
        drop(a);
        assert!(t.try_acquire(ip, 10, 2).is_ok());
    }

    #[test]
    fn rate_limiter_bursts_then_blocks() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            assert!(rl.check(&"k", 5));
        }
        assert!(!rl.check(&"k", 5));
        assert!(rl.check(&"k", 0));
    }
}
