//! Routing and delivery of one message to one destination domain.

use crate::app::App;
use crate::config::{Config, OutboundTls, SmarthostConfig, SmarthostTls};
use crate::dns::DnsFailure;
use crate::smtp::client::{ClientError, ConnectParams, SmtpClient, Stage, TlsMode};
use crate::smtp::Reply;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::debug;

/// Maximum MX hosts tried per attempt, and addresses tried per host.
const MAX_MX_HOSTS: usize = 5;
const MAX_IPS_PER_HOST: usize = 2;

#[derive(Debug, Clone)]
pub enum Outcome {
    Delivered { host: String, response: String },
    Permanent { host: Option<String>, response: String },
    Transient { host: Option<String>, response: String },
}

impl Outcome {
    pub fn parts(&self) -> (Option<String>, String) {
        match self {
            Outcome::Delivered { host, response } => (Some(host.clone()), response.clone()),
            Outcome::Permanent { host, response } | Outcome::Transient { host, response } => {
                (host.clone(), response.clone())
            }
        }
    }
    fn is_transient(&self) -> bool {
        matches!(self, Outcome::Transient { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Retry later.
    Transient,
    /// Give up now and send an NDR.
    Permanent,
}

/// Decide whether a negative SMTP reply should bounce now or be retried.
///
/// The RFC rule is simple (4xx = retry, 5xx = bounce), but real-world receivers
/// don't always follow it. Big providers sometimes use 5xx codes for conditions
/// that are really temporary (IP reputation blocks, "try again later" throttling),
/// and bouncing those immediately loses mail that would get through an hour later.
///
/// TODO(you): refine this policy for your sending profile. Things to consider:
///   * Enhanced code 5.7.x (policy/reputation) — e.g. Microsoft "5.7.606 banned
///     sending IP", Gmail "5.7.1 ... unsolicited" — retry, or bounce fast?
///   * Text hints such as "try again later", "temporarily", "greylist" in a 5xx.
///   * 5.1.1 / 5.1.10 (no such user / null MX) are always truly permanent;
///     retrying those hurts your reputation.
///   * The trade-off: retrying more saves mail during a block, but delays NDRs
///     for genuinely bad addresses until `delivery.expire_after`.
pub fn classify_failure(reply: &Reply) -> FailureKind {
    if reply.is_permanent() {
        FailureKind::Permanent
    } else {
        FailureKind::Transient
    }
}

fn outcome_from_reply(host: &str, stage: Stage, reply: &Reply) -> Outcome {
    let response = format!("{} (in reply to {stage})", reply.text());
    match classify_failure(reply) {
        FailureKind::Permanent => Outcome::Permanent { host: Some(host.to_string()), response },
        FailureKind::Transient => Outcome::Transient { host: Some(host.to_string()), response },
    }
}

// ---------------------------------------------------------------------------
// Shared routing state: connection limits, source IP rotation, connection pool
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    route: String,
    addr: SocketAddr,
    source: Option<IpAddr>,
}

#[derive(Default)]
pub struct Routes {
    global: OnceLock<Arc<Semaphore>>,
    per_domain: Mutex<HashMap<String, (usize, Arc<Semaphore>)>>,
    pool: Mutex<HashMap<PoolKey, Vec<SmtpClient>>>,
    rr: AtomicUsize,
}

impl Routes {
    fn global(&self, size: usize) -> Arc<Semaphore> {
        self.global.get_or_init(|| Arc::new(Semaphore::new(size))).clone()
    }

    fn domain(&self, key: &str, size: usize) -> Arc<Semaphore> {
        let mut map = self.per_domain.lock();
        match map.get(key) {
            Some((sz, s)) if *sz == size => s.clone(),
            _ => {
                // New domain, or the limit changed after a config reload.
                let s = Arc::new(Semaphore::new(size));
                map.insert(key.to_string(), (size, s.clone()));
                s
            }
        }
    }

    fn take_pooled(&self, key: &PoolKey, idle: Duration) -> Option<SmtpClient> {
        let mut pool = self.pool.lock();
        let list = pool.get_mut(key)?;
        while let Some(c) = list.pop() {
            if c.last_used.elapsed() < idle {
                return Some(c);
            }
        }
        None
    }

    fn put_pooled(&self, key: PoolKey, client: SmtpClient) {
        let mut pool = self.pool.lock();
        let list = pool.entry(key).or_default();
        if list.len() < 4 {
            list.push(client);
        }
    }

    /// Close idle pooled connections and forget idle per-domain semaphores.
    pub async fn housekeeping(&self, idle: Duration) {
        let expired: Vec<SmtpClient> = {
            let mut pool = self.pool.lock();
            let mut out = Vec::new();
            for list in pool.values_mut() {
                let (keep, old): (Vec<_>, Vec<_>) = list.drain(..).partition(|c| c.last_used.elapsed() < idle);
                *list = keep;
                out.extend(old);
            }
            pool.retain(|_, l| !l.is_empty());
            out
        };
        for mut c in expired {
            let _ = c.quit().await;
        }
        self.per_domain.lock().retain(|_, (size, s)| Arc::strong_count(s) > 1 || s.available_permits() != *size);
    }

    fn pick_source(&self, cfg: &Config, pool: Option<&str>) -> Option<(IpAddr, String)> {
        let name = pool.unwrap_or("default");
        let candidates: Vec<_> = cfg.outbound_ips.iter().filter(|i| i.pool == name).collect();
        let list: Vec<_> = if candidates.is_empty() { cfg.outbound_ips.iter().collect() } else { candidates };
        if list.is_empty() {
            return None;
        }
        let i = self.rr.fetch_add(1, Ordering::Relaxed) % list.len();
        let ip = &list[i];
        Some((ip.address, ip.helo.clone().unwrap_or_else(|| cfg.server.hostname.clone())))
    }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

struct Ctx<'a> {
    app: &'a Arc<App>,
    cfg: &'a Config,
    sender: &'a str,
    data: &'a [u8],
    source: Option<IpAddr>,
    helo: String,
}

fn masquerade(sender: &str, cfg: &Config) -> String {
    match (&cfg.server.masquerade_domain, sender.rsplit_once('@')) {
        (Some(dom), Some((local, _))) if !dom.is_empty() => format!("{local}@{dom}"),
        _ => sender.to_string(),
    }
}

fn all(rcpts: &[String], o: Outcome) -> Vec<(String, Outcome)> {
    rcpts.iter().map(|r| (r.clone(), o.clone())).collect()
}

pub async fn deliver_domain(
    app: &Arc<App>,
    id: &str,
    sender: &str,
    domain: &str,
    rcpts: &[String],
    data: &[u8],
    pool: Option<&str>,
) -> Vec<(String, Outcome)> {
    let cfg = app.cfg();
    let rule = cfg.domain_rule(domain);
    let sender = masquerade(sender, &cfg);
    let per_domain = rule.and_then(|r| r.max_connections).unwrap_or(cfg.delivery.max_connections_per_domain).max(1);
    let routes = &app.queue.routes;

    let dom_sem = routes.domain(domain, per_domain);
    let Ok(_dp) = dom_sem.acquire_owned().await else {
        return all(rcpts, Outcome::Transient { host: None, response: "internal: domain limiter closed".into() });
    };
    let global = routes.global(cfg.delivery.max_connections);
    let Ok(_gp) = global.acquire_owned().await else {
        return all(rcpts, Outcome::Transient { host: None, response: "internal: connection limiter closed".into() });
    };

    let pool = pool.or(rule.and_then(|r| r.pool.as_deref()));
    let (source, helo) = match routes.pick_source(&cfg, pool) {
        Some((ip, helo)) => (Some(ip), helo),
        None => (None, cfg.server.hostname.clone()),
    };
    let ctx = Ctx { app, cfg: &cfg, sender: &sender, data, source, helo };
    debug!(%id, %domain, rcpts = rcpts.len(), source = ?source, "delivering");

    let tls_policy = rule.and_then(|r| r.tls).unwrap_or(cfg.delivery.tls);
    if let Some(sh) = rule.and_then(|r| r.smarthost.as_ref()) {
        return via_smarthost(&ctx, sh, rcpts).await;
    }
    match &cfg.delivery.smarthost {
        Some(sh) if cfg.delivery.attempt_direct_before_smarthost => {
            let mut results = via_mx(&ctx, domain, rcpts, tls_policy).await;
            let retry: Vec<String> = results.iter().filter(|(_, o)| o.is_transient()).map(|(r, _)| r.clone()).collect();
            if !retry.is_empty() {
                results.retain(|(_, o)| !o.is_transient());
                results.extend(via_smarthost(&ctx, sh, &retry).await);
            }
            results
        }
        Some(sh) => via_smarthost(&ctx, sh, rcpts).await,
        None => via_mx(&ctx, domain, rcpts, tls_policy).await,
    }
}

async fn via_mx(ctx: &Ctx<'_>, domain: &str, rcpts: &[String], policy: OutboundTls) -> Vec<(String, Outcome)> {
    let dns = &ctx.app.dns;
    let (hosts, implicit) = match dns.mx(domain).await {
        Ok(mut mx) => {
            // RFC 7505 null MX: "MX 0 ." means the domain accepts no mail.
            if mx.len() == 1 && (mx[0].1.is_empty() || mx[0].1 == ".") {
                return all(
                    rcpts,
                    Outcome::Permanent {
                        host: None,
                        response: "556 5.1.10 Recipient domain does not accept mail (null MX)".into(),
                    },
                );
            }
            mx.sort_by_key(|(p, _)| *p);
            // Shuffle hosts of equal preference for load distribution (RFC 5321 §5.1).
            let mut out: Vec<String> = Vec::new();
            let mut i = 0;
            while i < mx.len() {
                let p = mx[i].0;
                let mut same: Vec<String> =
                    mx[i..].iter().take_while(|(q, _)| *q == p).map(|(_, h)| h.clone()).collect();
                i += same.len();
                same.shuffle(&mut rand::thread_rng());
                out.extend(same);
            }
            (out, false)
        }
        Err(DnsFailure::NotFound) => (vec![domain.to_string()], true),
        Err(DnsFailure::Temporary(e)) => {
            return all(
                rcpts,
                Outcome::Transient { host: None, response: format!("451 4.4.3 MX lookup for {domain} failed: {e}") },
            );
        }
    };

    let mode = match policy {
        OutboundTls::Disabled => TlsMode::Disabled,
        OutboundTls::Opportunistic => TlsMode::Opportunistic,
        OutboundTls::Required => TlsMode::Required,
    };
    let connector =
        if ctx.cfg.delivery.verify_certificates { &ctx.app.client_tls.verifying } else { &ctx.app.client_tls.insecure };
    let want_v6 = ctx.cfg.delivery.ipv6 && !matches!(ctx.source, Some(IpAddr::V4(_)));
    let want_v4 = !matches!(ctx.source, Some(IpAddr::V6(_)));

    let mut last_err = format!("451 4.4.1 No reachable mail servers for {domain}");
    for host in hosts.iter().take(MAX_MX_HOSTS) {
        let ips = match dns.ips(host, want_v6).await {
            Ok(ips) => ips,
            Err(DnsFailure::NotFound) if implicit => {
                return all(
                    rcpts,
                    Outcome::Permanent {
                        host: None,
                        response: format!("550 5.1.2 Recipient domain {domain} has no MX or address records"),
                    },
                );
            }
            Err(e) => {
                last_err = format!("451 4.4.3 Cannot resolve MX host {host}: {e}");
                continue;
            }
        };
        let ips: Vec<IpAddr> =
            ips.into_iter().filter(|ip| (ip.is_ipv4() && want_v4) || (ip.is_ipv6() && want_v6)).collect();
        if ips.is_empty() {
            last_err = format!("451 4.4.4 MX host {host} has no usable addresses for this source IP family");
            continue;
        }
        for ip in ips.into_iter().take(MAX_IPS_PER_HOST) {
            let params = ConnectParams {
                addr: SocketAddr::new(ip, 25),
                source: ctx.source,
                tls_name: host,
                helo: &ctx.helo,
                tls: mode,
                connector,
                connect_timeout: ctx.cfg.delivery.connect_timeout,
                command_timeout: ctx.cfg.delivery.command_timeout,
                data_timeout: ctx.cfg.delivery.data_timeout,
                auth: None,
            };
            match transact(ctx, host, &params, rcpts).await {
                Attempt::Done(outcomes) => return outcomes,
                Attempt::TryNext(err) => last_err = err,
            }
        }
    }
    all(rcpts, Outcome::Transient { host: None, response: last_err })
}

async fn via_smarthost(ctx: &Ctx<'_>, sh: &SmarthostConfig, rcpts: &[String]) -> Vec<(String, Outcome)> {
    let ips: Vec<IpAddr> = match sh.host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => match ctx.app.dns.ips(&sh.host, true).await {
            Ok(v) => v,
            Err(e) => {
                return all(
                    rcpts,
                    Outcome::Transient {
                        host: Some(sh.host.clone()),
                        response: format!("451 4.4.3 Cannot resolve smarthost {}: {e}", sh.host),
                    },
                )
            }
        },
    };
    let mode = match sh.tls {
        SmarthostTls::None => TlsMode::Disabled,
        // Credentials must never travel in clear text: STARTTLS is mandatory here.
        SmarthostTls::Starttls => TlsMode::Required,
        SmarthostTls::Implicit => TlsMode::Implicit,
    };
    let connector = if sh.verify_certificate { &ctx.app.client_tls.verifying } else { &ctx.app.client_tls.insecure };
    let auth = match (&sh.username, &sh.password) {
        (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
        _ => None,
    };
    let mut last_err = format!("451 4.4.1 Smarthost {} unreachable", sh.host);
    for ip in ips.into_iter().filter(|ip| !(ctx.source.is_some_and(|s| s.is_ipv4() != ip.is_ipv4()))).take(3) {
        let params = ConnectParams {
            addr: SocketAddr::new(ip, sh.port),
            source: ctx.source,
            tls_name: &sh.host,
            helo: &ctx.helo,
            tls: mode,
            connector,
            connect_timeout: ctx.cfg.delivery.connect_timeout,
            command_timeout: ctx.cfg.delivery.command_timeout,
            data_timeout: ctx.cfg.delivery.data_timeout,
            auth,
        };
        match transact(ctx, &sh.host, &params, rcpts).await {
            Attempt::Done(o) => return o,
            Attempt::TryNext(e) => last_err = e,
        }
    }
    all(rcpts, Outcome::Transient { host: Some(sh.host.clone()), response: last_err })
}

enum Attempt {
    Done(Vec<(String, Outcome)>),
    TryNext(String),
}

async fn connect_with_fallback(params: &ConnectParams<'_>) -> Result<SmtpClient, ClientError> {
    match SmtpClient::connect(params).await {
        // Broken TLS stacks are common on small MTAs: opportunistic TLS falls back to plain text.
        Err(ClientError::Tls(e)) if params.tls == TlsMode::Opportunistic => {
            debug!(addr = %params.addr, error = %e, "TLS failed; retrying without TLS");
            let plain = ConnectParams { tls: TlsMode::Disabled, ..*params };
            SmtpClient::connect(&plain).await
        }
        other => other,
    }
}

async fn transact(ctx: &Ctx<'_>, host: &str, params: &ConnectParams<'_>, rcpts: &[String]) -> Attempt {
    let key = PoolKey { route: host.to_string(), addr: params.addr, source: params.source };
    let routes = &ctx.app.queue.routes;
    let idle = ctx.cfg.delivery.connection_idle_timeout;
    let label = format!("{host} [{}]", params.addr.ip());

    let mut reused = false;
    let mut client = None;
    if !idle.is_zero() {
        if let Some(mut c) = routes.take_pooled(&key, idle) {
            if c.reset().await {
                reused = true;
                client = Some(c);
            }
        }
    }
    let mut client = match client {
        Some(c) => c,
        None => match connect_with_fallback(params).await {
            Ok(c) => c,
            Err(e) => return connect_error(&label, rcpts, e),
        },
    };

    let mut result = client.send(ctx.sender, rcpts, ctx.data).await;
    // A pooled connection may have been closed by the remote while idle: retry once on a fresh one.
    if reused {
        if let Err(ClientError::Io(stage, _)) = &result {
            if matches!(stage, Stage::MailFrom | Stage::RcptTo) {
                client = match connect_with_fallback(params).await {
                    Ok(c) => c,
                    Err(e) => return connect_error(&label, rcpts, e),
                };
                result = client.send(ctx.sender, rcpts, ctx.data).await;
            }
        }
    }

    let outcomes = match result {
        Ok(tx) => {
            let mut out = Vec::with_capacity(rcpts.len());
            for (r, rep) in &tx.rejected {
                out.push((r.clone(), outcome_from_reply(&label, Stage::RcptTo, rep)));
            }
            if let Some(dr) = &tx.data_reply {
                let o = if dr.is_positive() {
                    Outcome::Delivered { host: label.clone(), response: dr.text() }
                } else {
                    outcome_from_reply(&label, Stage::Message, dr)
                };
                for (r, _) in &tx.accepted {
                    out.push((r.clone(), o.clone()));
                }
            }
            let reusable = tx.data_reply.as_ref().is_none_or(|r| r.is_positive());
            if reusable
                && !idle.is_zero()
                && client.messages_sent < ctx.cfg.delivery.max_messages_per_outbound_connection
            {
                routes.put_pooled(key, client);
            } else {
                let _ = client.quit().await;
            }
            return Attempt::Done(out);
        }
        Err(ClientError::Reply(stage, rep)) => {
            let _ = client.quit().await;
            all(rcpts, outcome_from_reply(&label, stage, &rep))
        }
        Err(e @ (ClientError::TooLarge(_) | ClientError::Utf8Unsupported)) => {
            let _ = client.quit().await;
            all(rcpts, Outcome::Permanent { host: Some(label.clone()), response: e.to_string() })
        }
        Err(e) => {
            // Connection dropped mid-transaction. Retrying may in rare cases duplicate a
            // message the remote already accepted, which RFC 5321 §6.1 prefers to losing it.
            return Attempt::TryNext(format!("451 4.4.2 {label}: {e}"));
        }
    };
    Attempt::Done(outcomes)
}

fn connect_error(label: &str, rcpts: &[String], e: ClientError) -> Attempt {
    match e {
        // A permanent rejection at greeting/EHLO is host-specific (often a blocklist);
        // other MX hosts may accept, so keep trying and only retry later if none do.
        ClientError::Reply(stage @ (Stage::Greeting | Stage::Ehlo), rep) => {
            Attempt::TryNext(format!("{} from {label} (in reply to {stage})", rep.text()))
        }
        ClientError::Reply(Stage::Auth, rep) => Attempt::Done(all(
            rcpts,
            Outcome::Transient {
                host: Some(label.to_string()),
                response: format!("smarthost authentication failed: {}", rep.text()),
            },
        )),
        other => Attempt::TryNext(format!("451 4.4.1 {label}: {other}")),
    }
}
