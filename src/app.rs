//! Shared application context passed (as `Arc<App>`) to every subsystem.

use crate::access::{ConnectionTracker, RateLimiter};
use crate::auth::AuthCache;
use crate::config::Config;
use crate::dkim::DkimRegistry;
use crate::dns::Dns;
use crate::events::EventLog;
use crate::queue::Queue;
use crate::stats::{Stats, StatsHistory};
use crate::tls::ClientTls;
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

pub struct App {
    /// Hot-reloadable settings. Listener binds, data_dir and logging require a restart.
    pub config: ArcSwap<Config>,
    pub config_path: PathBuf,
    pub dkim: ArcSwap<DkimRegistry>,
    pub tls_acceptor: ArcSwap<Option<TlsAcceptor>>,
    pub dns: Arc<Dns>,
    pub queue: Arc<Queue>,
    pub stats: Stats,
    pub stats_history: StatsHistory,
    pub events: EventLog,
    pub connections: Arc<ConnectionTracker>,
    pub rate_ip: RateLimiter<IpAddr>,
    pub rate_conn: RateLimiter<IpAddr>,
    pub rate_user: RateLimiter<String>,
    pub auth_cache: AuthCache,
    pub client_tls: ClientTls,
    pub started: Instant,
    shutdown_tx: watch::Sender<bool>,
}

impl App {
    pub fn new(config: Config, config_path: PathBuf, dns: Arc<Dns>, queue: Arc<Queue>) -> Result<Arc<Self>> {
        let dkim = DkimRegistry::load(&config.dkim).context("loading DKIM keys")?;
        let acceptor = load_acceptor(&config)?;
        let (shutdown_tx, _) = watch::channel(false);
        let events = EventLog::new(config.history.memory_events);
        Ok(Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            config_path,
            dkim: ArcSwap::from_pointee(dkim),
            tls_acceptor: ArcSwap::from_pointee(acceptor),
            dns,
            queue,
            stats: Stats::default(),
            stats_history: StatsHistory::default(),
            events,
            connections: ConnectionTracker::new(),
            rate_ip: RateLimiter::new(),
            rate_conn: RateLimiter::new(),
            rate_user: RateLimiter::new(),
            auth_cache: AuthCache::new(Duration::from_secs(300)),
            client_tls: ClientTls::new()?,
            started: Instant::now(),
            shutdown_tx,
        }))
    }

    pub fn cfg(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_tx.borrow()
    }

    pub fn trigger_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Re-read the config file and atomically swap policy (access lists, users,
    /// limits, delivery rules, DKIM keys, TLS certificate). On any error the
    /// running configuration is left untouched.
    pub fn reload(&self) -> Result<Vec<String>> {
        let new = Config::load(&self.config_path)?;
        let warnings = restart_required(&self.cfg(), &new);
        let dkim = DkimRegistry::load(&new.dkim)?;
        let acceptor = load_acceptor(&new)?;
        self.dkim.store(Arc::new(dkim));
        self.tls_acceptor.store(Arc::new(acceptor));
        self.config.store(Arc::new(new));
        tracing::info!(warnings = ?warnings, "configuration reloaded");
        Ok(warnings)
    }

    /// Periodic housekeeping for in-memory limiter state.
    pub fn housekeeping(&self) {
        self.rate_ip.cleanup(120);
        self.rate_conn.cleanup(120);
        self.rate_user.cleanup(120);
    }
}

/// Settings that are only read at start-up and differ between `old` and `new`.
pub fn restart_required(old: &Config, new: &Config) -> Vec<String> {
    fn json<T: serde::Serialize>(v: &T) -> Option<String> {
        serde_json::to_string(v).ok()
    }
    let mut w = Vec::new();
    if json(&new.listeners) != json(&old.listeners) {
        w.push("listener changes require a service restart".into());
    }
    if new.server.data_dir != old.server.data_dir {
        w.push("server.data_dir changes require a service restart".into());
    }
    if json(&new.logging) != json(&old.logging) {
        w.push("logging changes require a service restart".into());
    }
    if new.api.bind != old.api.bind || new.api.enabled != old.api.enabled {
        w.push("api.bind / api.enabled changes require a service restart".into());
    }
    if new.history.memory_events != old.history.memory_events {
        w.push("history.memory_events changes require a service restart".into());
    }
    if new.delivery.max_concurrent_messages != old.delivery.max_concurrent_messages {
        w.push("delivery.max_concurrent_messages changes require a service restart".into());
    }
    w
}

/// Validate everything `reload` would load (DKIM keys, TLS certificate) without applying it.
pub fn deep_validate(cfg: &Config) -> Result<()> {
    DkimRegistry::load(&cfg.dkim).context("loading DKIM keys")?;
    load_acceptor(cfg).context("loading TLS certificate")?;
    Ok(())
}

fn load_acceptor(cfg: &Config) -> Result<Option<TlsAcceptor>> {
    match &cfg.tls {
        Some(t) => Ok(Some(crate::tls::acceptor(crate::tls::load_server_config(&t.cert, &t.key)?))),
        None => Ok(None),
    }
}
