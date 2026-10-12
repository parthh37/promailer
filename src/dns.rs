//! DNS resolution with TTL-respecting caches.
//!
//! A single `mail_auth::MessageAuthenticator` (hickory resolver using the
//! Windows/OS resolver configuration) is shared by delivery (MX/A/AAAA), the
//! inbound reverse-DNS lookup and the SPF/DKIM/DMARC diagnostics.

use mail_auth::{MessageAuthenticator, RecordSet, ResolverCache, MX};
use parking_lot::Mutex;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Upper bound for cached entries so a hostile/large workload can't grow memory unbounded.
const MAX_ENTRIES: usize = 50_000;
/// Clamp TTLs: never cache longer than an hour or shorter than 30 seconds.
const MAX_TTL: Duration = Duration::from_secs(3600);
const MIN_TTL: Duration = Duration::from_secs(30);

pub struct TtlCache<K, V> {
    inner: Mutex<HashMap<K, (V, Instant)>>,
}

impl<K: Hash + Eq, V: Clone> TtlCache<K, V> {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    fn purge_expired(map: &mut HashMap<K, (V, Instant)>) {
        let now = Instant::now();
        map.retain(|_, (_, exp)| *exp > now);
    }
}

impl<K: Hash + Eq, V: Clone> ResolverCache<K, V> for TtlCache<K, V> {
    fn get<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let map = self.inner.lock();
        map.get(name).filter(|(_, exp)| *exp > Instant::now()).map(|(v, _)| v.clone())
    }

    fn remove<Q>(&self, name: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.lock().remove(name).map(|(v, _)| v)
    }

    fn insert(&self, key: K, value: V, valid_until: Instant) {
        let now = Instant::now();
        let ttl = valid_until.saturating_duration_since(now).clamp(MIN_TTL, MAX_TTL);
        let mut map = self.inner.lock();
        if map.len() >= MAX_ENTRIES {
            Self::purge_expired(&mut map);
            if map.len() >= MAX_ENTRIES {
                map.clear();
            }
        }
        map.insert(key, (value, now + ttl));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsFailure {
    /// Authoritative "does not exist" / empty answer.
    NotFound,
    /// Timeout, SERVFAIL, network error - retry later.
    Temporary(String),
}

impl std::fmt::Display for DnsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsFailure::NotFound => write!(f, "no such record"),
            DnsFailure::Temporary(e) => write!(f, "DNS lookup failed: {e}"),
        }
    }
}

fn classify(err: mail_auth::Error) -> DnsFailure {
    match err {
        mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(_)) => DnsFailure::NotFound,
        other => DnsFailure::Temporary(other.to_string()),
    }
}

pub struct Dns {
    auth: MessageAuthenticator,
    mx: TtlCache<Box<str>, RecordSet<MX>>,
    v4: TtlCache<Box<str>, RecordSet<Ipv4Addr>>,
    v6: TtlCache<Box<str>, RecordSet<Ipv6Addr>>,
    ptr: TtlCache<IpAddr, RecordSet<Box<str>>>,
    txt: TtlCache<Box<str>, mail_auth::Txt>,
}

impl Dns {
    pub fn new() -> anyhow::Result<Self> {
        let auth = MessageAuthenticator::new_system_conf().or_else(|e| {
            tracing::warn!(error = %e, "could not read system DNS configuration; falling back to public resolvers");
            MessageAuthenticator::new_cloudflare()
        })?;
        Ok(Self {
            auth,
            mx: TtlCache::new(),
            v4: TtlCache::new(),
            v6: TtlCache::new(),
            ptr: TtlCache::new(),
            txt: TtlCache::new(),
        })
    }

    pub async fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsFailure> {
        let set = self.auth.mx_lookup(domain, Some(&self.mx)).await.map_err(classify)?;
        let mut out = Vec::new();
        for mx in set.rrset.iter() {
            for host in mx.exchanges.iter() {
                out.push((mx.preference, host.trim_end_matches('.').to_string()));
            }
        }
        if out.is_empty() {
            return Err(DnsFailure::NotFound);
        }
        Ok(out)
    }

    pub async fn ipv4(&self, host: &str) -> Result<Vec<IpAddr>, DnsFailure> {
        let set = self.auth.ipv4_lookup(host, Some(&self.v4)).await.map_err(classify)?;
        Ok(set.rrset.iter().map(|a| IpAddr::V4(*a)).collect())
    }

    pub async fn ipv6(&self, host: &str) -> Result<Vec<IpAddr>, DnsFailure> {
        let set = self.auth.ipv6_lookup(host, Some(&self.v6)).await.map_err(classify)?;
        Ok(set.rrset.iter().map(|a| IpAddr::V6(*a)).collect())
    }

    /// A + (optionally) AAAA. Returns NotFound only if both are authoritatively empty.
    pub async fn ips(&self, host: &str, ipv6: bool) -> Result<Vec<IpAddr>, DnsFailure> {
        let v4 = self.ipv4(host).await;
        let v6 = if ipv6 { self.ipv6(host).await } else { Err(DnsFailure::NotFound) };
        match (v4, v6) {
            (Ok(mut a), Ok(b)) => {
                a.extend(b);
                Ok(a)
            }
            (Ok(a), Err(_)) | (Err(_), Ok(a)) if !a.is_empty() => Ok(a),
            (Err(DnsFailure::Temporary(e)), _) | (_, Err(DnsFailure::Temporary(e))) => Err(DnsFailure::Temporary(e)),
            _ => Err(DnsFailure::NotFound),
        }
    }

    pub async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsFailure> {
        let set = self.auth.ptr_lookup(ip, Some(&self.ptr)).await.map_err(classify)?;
        let names: Vec<String> = set.rrset.iter().map(|n| n.trim_end_matches('.').to_string()).collect();
        if names.is_empty() {
            return Err(DnsFailure::NotFound);
        }
        Ok(names)
    }

    /// Forward-confirmed reverse DNS: returns the PTR name whose A/AAAA records
    /// include `ip`, or None.
    pub async fn fcrdns(&self, ip: IpAddr) -> Result<Option<String>, DnsFailure> {
        let names = self.ptr(ip).await?;
        for name in names {
            if let Ok(addrs) = self.ips(&name, ip.is_ipv6()).await {
                if addrs.contains(&ip) {
                    return Ok(Some(name));
                }
            }
        }
        Ok(None)
    }

    /// Raw TXT strings (each record's character-strings concatenated).
    pub async fn txt(&self, name: &str) -> Result<Vec<String>, DnsFailure> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let lookup = self.auth.resolver().lookup(name, RecordType::TXT).await.map_err(|e| classify(e.into()))?;
        let out: Vec<String> = lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(txt) => {
                    Some(txt.txt_data.iter().map(|p| String::from_utf8_lossy(p).into_owned()).collect::<String>())
                }
                _ => None,
            })
            .collect();
        if out.is_empty() {
            return Err(DnsFailure::NotFound);
        }
        Ok(out)
    }

    pub async fn spf_check(&self, ip: IpAddr, helo: &str, host: &str, sender: &str) -> mail_auth::SpfOutput {
        let params =
            mail_auth::Parameters::new(mail_auth::spf::verify::SpfParameters::verify_mail_from(ip, helo, host, sender))
                .with_txt_cache(&self.txt)
                .with_mx_cache(&self.mx)
                .with_ipv4_cache(&self.v4)
                .with_ipv6_cache(&self.v6)
                .with_ptr_cache(&self.ptr);
        self.auth.verify_spf(params).await
    }
}
