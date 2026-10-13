//! Process bootstrap: load config, bind sockets, start subsystems, run until told to stop.

use crate::app::App;
use crate::config::Config;
use crate::dns::Dns;
use crate::eventlog::id as event_id;
use crate::queue::{store::Store, Queue};
use crate::tls::CertHealth;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(not(windows), allow(dead_code))]
pub enum Control {
    Stop,
    Reload,
}

async fn bind(addr: std::net::SocketAddr, what: &str) -> Result<TcpListener> {
    TcpListener::bind(addr).await.with_context(|| {
        let hint = if addr.port() == 25 {
            " — is another SMTP server running? Stop the IIS SMTP service with `sc stop SMTPSVC` and `sc config SMTPSVC start= disabled`"
        } else {
            ""
        };
        format!("cannot bind {what} on {addr}{hint}")
    })
}

/// Run the server. `on_ready` is called once every socket is bound and all
/// subsystems are started (the Windows service reports RUNNING at that point).
pub async fn run(
    config_path: &Path,
    console: bool,
    mut control: mpsc::UnboundedReceiver<Control>,
    on_ready: impl FnOnce(),
) -> Result<()> {
    let config = Config::load(config_path)?;
    let _log_guards =
        crate::logging::init(&config.logging, console && config.logging.console, !console && config.logging.event_log)?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        hostname = %config.server.hostname,
        data_dir = %config.server.data_dir.display(),
        "Promailer starting"
    );

    let result = run_inner(config, config_path, console, &mut control, on_ready).await;
    if let Err(e) = &result {
        error!(event_id = event_id::FATAL, error = format!("{e:#}"), "Promailer stopped because of an error");
    }
    info!(event_id = event_id::STOPPED, "Promailer stopped");
    result
}

async fn run_inner(
    config: Config,
    config_path: &Path,
    console: bool,
    control: &mut mpsc::UnboundedReceiver<Control>,
    on_ready: impl FnOnce(),
) -> Result<()> {
    std::fs::create_dir_all(&config.server.data_dir)
        .with_context(|| format!("creating data directory {}", config.server.data_dir.display()))?;
    if config.pickup.enabled {
        std::fs::create_dir_all(&config.pickup.dir)
            .with_context(|| format!("creating pickup directory {}", config.pickup.dir.display()))?;
    }
    let store = Store::open(config.queue_dir(), config.badmail_dir(), config.drop_dir(), config.server.durable_writes)?;
    let queue = Queue::open(store)?;
    let dns = Arc::new(Dns::new()?);

    // Bind everything before reporting ready so misconfiguration fails the start loudly.
    let mut smtp = Vec::new();
    for l in &config.listeners {
        smtp.push((bind(l.bind, &format!("SMTP listener '{}'", l.name)).await?, l.clone()));
    }
    let api_listener = if config.api.enabled { Some(bind(config.api.bind, "HTTP API").await?) } else { None };
    if config.api.enabled && config.api.keys.is_empty() {
        warn!("HTTP API enabled but no [[api.keys]] configured; only /health and /metrics are usable");
    }

    let pickup_enabled = config.pickup.enabled;
    let app = App::new(config, config_path.to_path_buf(), dns, queue)?;

    let mut tasks = Vec::new();
    for (listener, lcfg) in smtp {
        tasks.push(tokio::spawn(crate::smtp::server::serve(app.clone(), listener, lcfg)));
    }
    if let Some(l) = api_listener {
        tasks.push(tokio::spawn(crate::api::serve(app.clone(), l)));
    }
    if pickup_enabled {
        tasks.push(tokio::spawn(crate::pickup::run(app.clone())));
    }
    let scheduler = tokio::spawn(crate::queue::run(app.clone()));
    tasks.push(tokio::spawn(housekeeping(app.clone())));
    tasks.push(tokio::spawn(cert_monitor(app.clone())));

    let cfg = app.cfg();
    info!(
        event_id = event_id::STARTED,
        version = env!("CARGO_PKG_VERSION"),
        hostname = %cfg.server.hostname,
        listeners = %cfg.listeners.iter().map(|l| format!("{} {}", l.name, l.bind)).collect::<Vec<_>>().join(", "),
        tls_certificate = %app.tls_cert.load().as_ref().as_ref().map_or("none".into(), |c| format!("{} ({})", c.thumbprint, c.subject)),
        queued = app.queue.len(),
        "Promailer started"
    );
    drop(cfg);
    on_ready();

    // Ctrl+C only applies to console mode. If the handler can't be registered (e.g. no
    // console under the SCM) the future must never resolve, or we'd shut down at once.
    let ctrl_c = async move {
        if console && tokio::signal::ctrl_c().await.is_ok() {
            return;
        }
        std::future::pending::<()>().await
    };
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            msg = control.recv() => match msg {
                Some(Control::Reload) => {
                    if let Err(e) = app.reload() {
                        error!(
                            event_id = event_id::RELOAD_FAILED,
                            error = format!("{e:#}"),
                            "configuration reload failed; keeping current configuration"
                        );
                    }
                }
                Some(Control::Stop) | None => break,
            },
            _ = &mut ctrl_c => {
                info!("Ctrl+C received");
                break;
            }
        }
    }

    info!("shutting down");
    app.trigger_shutdown();
    let grace = app.cfg().server.shutdown_grace + Duration::from_secs(5);
    if tokio::time::timeout(grace, scheduler).await.is_err() {
        warn!("delivery scheduler did not stop in time");
    }
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }
    Ok(())
}

async fn housekeeping(app: Arc<App>) {
    let mut shutdown = app.shutdown_rx();
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                app.housekeeping();
                app.queue.routes.housekeeping(app.cfg().delivery.connection_idle_timeout).await;
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Picks up renewed certificates without a restart (win-acme rewriting the PEM files,
/// AD CS auto-enrollment renewing a store certificate) and re-checks validity daily.
async fn cert_monitor(app: Arc<App>) {
    const RELOAD_EVERY: Duration = Duration::from_secs(3600);
    const REPORT_EVERY: Duration = Duration::from_secs(86400);
    let mut shutdown = app.shutdown_rx();
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + RELOAD_EVERY, RELOAD_EVERY);
    // Start-up already applied the policy to the current certificate.
    let mut last_report = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => break,
        }
        let Some(tls) = app.cfg().tls.clone() else { continue };
        // Reading PEM files or the certificate store blocks; keep it off the async workers.
        match tokio::task::spawn_blocking(move || crate::tls::load_server(&tls)).await {
            Ok(Ok(cert)) => {
                let current = app.tls_cert.load_full();
                if current.as_ref().as_ref().map(|c| &c.thumbprint) != Some(&cert.info.thumbprint) {
                    match crate::app::apply_cert_policy(&cert.info) {
                        Ok(()) => {
                            app.install_cert(Some(cert));
                            last_report = std::time::Instant::now();
                        }
                        Err(e) => error!(error = format!("{e:#}"), "new TLS certificate found but not used"),
                    }
                }
            }
            Ok(Err(e)) => {
                warn!(error = format!("{e:#}"), "cannot re-read the TLS certificate; keeping the current one")
            }
            Err(e) => warn!(error = %e, "TLS certificate check failed"),
        }
        if last_report.elapsed() >= REPORT_EVERY {
            last_report = std::time::Instant::now();
            if let Some(info) = app.tls_cert.load_full().as_ref() {
                match info.health(chrono::Utc::now()) {
                    CertHealth::Healthy => {}
                    CertHealth::Warn(msg) => crate::app::log_cert_warning(info, &msg),
                    CertHealth::Reject(msg) => error!(
                        event_id = event_id::CERT_INVALID,
                        thumbprint = %info.thumbprint,
                        subject = %info.subject,
                        source = %info.source,
                        expires = %info.not_after.format("%Y-%m-%d %H:%M UTC"),
                        "TLS certificate in use is not valid: {msg}"
                    ),
                }
            }
        }
    }
}
