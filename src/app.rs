//! Shared application context passed (as `Arc<App>`) to every subsystem.

use crate::access::{ConnectionTracker, RateLimiter};
use crate::auth::AuthCache;
use crate::config::Config;
use crate::dkim::DkimRegistry;
use crate::dns::Dns;
use crate::eventlog::id as event_id;
use crate::queue::Queue;
use crate::stats::Stats;
use crate::tls::{CertHealth, CertInfo, ClientTls, ServerCert};
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
    /// The certificate behind `tls_acceptor`.
    pub tls_cert: ArcSwap<Option<CertInfo>>,
    pub dns: Arc<Dns>,
    pub queue: Arc<Queue>,
    pub stats: Stats,
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
        let cert = load_tls(&config)?;
        let (shutdown_tx, _) = watch::channel(false);
        Ok(Arc::new(Self {
            config: ArcSwap::from_pointee(config),
            config_path,
            dkim: ArcSwap::from_pointee(dkim),
            tls_acceptor: ArcSwap::from_pointee(cert.as_ref().map(|c| crate::tls::acceptor(c.config.clone()))),
            tls_cert: ArcSwap::from_pointee(cert.map(|c| c.info)),
            dns,
            queue,
            stats: Stats::default(),
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
        let old = self.cfg();
        let mut warnings = Vec::new();
        let listeners_changed =
            serde_json::to_string(&new.listeners).ok() != serde_json::to_string(&old.listeners).ok();
        if listeners_changed {
            warnings.push("listener changes require a service restart".into());
        }
        if new.server.data_dir != old.server.data_dir {
            warnings.push("server.data_dir changes require a service restart".into());
        }
        if serde_json::to_string(&new.logging).ok() != serde_json::to_string(&old.logging).ok() {
            warnings.push("logging changes require a service restart".into());
        }
        if new.api.bind != old.api.bind || new.api.enabled != old.api.enabled {
            warnings.push("api.bind / api.enabled changes require a service restart".into());
        }
        let dkim = DkimRegistry::load(&new.dkim)?;
        let cert = load_tls(&new)?;
        self.dkim.store(Arc::new(dkim));
        self.install_cert(cert);
        self.config.store(Arc::new(new));
        tracing::info!(event_id = event_id::RELOADED, warnings = ?warnings, "configuration reloaded");
        Ok(warnings)
    }

    /// Swap in a server certificate (or none); logs when it differs from the current one.
    pub fn install_cert(&self, cert: Option<ServerCert>) {
        let old = self.tls_cert.load_full();
        let new = cert.as_ref().map(|c| c.info.clone());
        if let (Some(old), Some(new)) = (old.as_ref(), new.as_ref()) {
            if old.thumbprint != new.thumbprint {
                tracing::info!(
                    event_id = event_id::CERT_CHANGED,
                    previous = %old.thumbprint,
                    thumbprint = %new.thumbprint,
                    subject = %new.subject,
                    expires = %new.not_after.format("%Y-%m-%d"),
                    "TLS certificate changed"
                );
            }
        }
        self.tls_acceptor.store(Arc::new(cert.map(|c| crate::tls::acceptor(c.config))));
        self.tls_cert.store(Arc::new(new));
    }

    /// Periodic housekeeping for in-memory limiter state.
    pub fn housekeeping(&self) {
        self.rate_ip.cleanup(120);
        self.rate_conn.cleanup(120);
        self.rate_user.cleanup(120);
    }
}

/// Load the configured server certificate and apply the validity policy: rejected
/// certificates fail the load, warnings are logged (and reach the Event Log).
pub fn load_tls(cfg: &Config) -> Result<Option<ServerCert>> {
    let Some(tls) = &cfg.tls else { return Ok(None) };
    let cert = crate::tls::load_server(tls).context("loading TLS certificate")?;
    apply_cert_policy(&cert.info)?;
    Ok(Some(cert))
}

pub fn apply_cert_policy(info: &CertInfo) -> Result<()> {
    match info.health(chrono::Utc::now()) {
        CertHealth::Healthy => Ok(()),
        CertHealth::Warn(msg) => {
            log_cert_warning(info, &msg);
            Ok(())
        }
        CertHealth::Reject(msg) => anyhow::bail!("TLS certificate {} rejected: {msg}", info.thumbprint),
    }
}

pub fn log_cert_warning(info: &CertInfo, msg: &str) {
    tracing::warn!(
        event_id = event_id::CERT_EXPIRING,
        thumbprint = %info.thumbprint,
        subject = %info.subject,
        source = %info.source,
        expires = %info.not_after.format("%Y-%m-%d %H:%M UTC"),
        "{msg}"
    );
}
