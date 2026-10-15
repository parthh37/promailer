//! Process bootstrap: load config, bind sockets, start subsystems, run until told to stop.

use crate::app::App;
use crate::config::Config;
use crate::dns::Dns;
use crate::eventlog::id as event_id;
use crate::queue::{store::Store, Queue};
use crate::supervisor::{Supervisor, Watchdog};
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
    if config.crash_reports.enabled {
        install_crash_hook(&config);
    }

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

    // Every subsystem runs until shutdown; one that ends early stops the server with an
    // error so the SCM restarts the process instead of leaving it running half-dead.
    let (supervisor, mut faults) = Supervisor::new(app.shutdown_rx());
    let mut tasks = Vec::new();
    for (listener, lcfg) in smtp {
        let name = format!("SMTP listener '{}'", lcfg.name);
        tasks.push(supervisor.spawn(name, crate::smtp::server::serve(app.clone(), listener, lcfg)));
    }
    if let Some(l) = api_listener {
        tasks.push(supervisor.spawn("HTTP API", crate::api::serve(app.clone(), l)));
    }
    if pickup_enabled {
        tasks.push(supervisor.spawn("pickup directory watcher", crate::pickup::run(app.clone())));
    }
    let (history_tx, history_rx) = mpsc::channel(10_000);
    app.events.attach_history(history_tx);
    let history = supervisor.spawn("history writer", crate::events::run_writer(app.clone(), history_rx));
    let scheduler = supervisor.spawn("delivery scheduler", crate::queue::run(app.clone()));
    tasks.push(supervisor.spawn("housekeeping", housekeeping(app.clone())));
    tasks.push(supervisor.spawn("certificate monitor", cert_monitor(app.clone())));
    tasks.push(supervisor.spawn("statistics sampler", sample_stats(app.clone())));
    tasks.push(supervisor.spawn("crash report uploader", crash_uploader(app.clone())));

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

    // Armed only under the SCM: in console mode nothing would restart the process.
    let watchdog = if console {
        None
    } else {
        match Watchdog::start(app.clone()) {
            Ok(w) => Some(w),
            Err(e) => {
                warn!(error = %e, "cannot start the watchdog thread; hang detection is off");
                None
            }
        }
    };

    // Ctrl+C only applies to console mode. If the handler can't be registered (e.g. no
    // console under the SCM) the future must never resolve, or we'd shut down at once.
    let ctrl_c = async move {
        if console && tokio::signal::ctrl_c().await.is_ok() {
            return;
        }
        std::future::pending::<()>().await
    };
    tokio::pin!(ctrl_c);

    let mut failure = None;
    loop {
        tokio::select! {
            Some(fault) = faults.recv() => {
                failure = Some(fault);
                break;
            }
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

    // Disarm first: ending the process during a requested stop would look like a crash,
    // and the SCM would restart a service the administrator just stopped.
    drop(watchdog);
    info!("shutting down");
    app.trigger_shutdown();
    let grace = app.cfg().server.shutdown_grace + Duration::from_secs(5);
    if tokio::time::timeout(grace, scheduler).await.is_err() {
        warn!("delivery scheduler did not stop in time");
    }
    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }
    // Last, so events from the final deliveries are flushed to history.
    let _ = tokio::time::timeout(Duration::from_secs(5), history).await;
    // Shut down gracefully (in-flight deliveries finish or are re-queued) before reporting
    // the failure: the non-zero exit code is what makes the SCM restart the service.
    match failure {
        Some(fault) => Err(anyhow::anyhow!(fault)),
        None => Ok(()),
    }
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

/// Save a crash report for every distinct panic. Runs before the hook from
/// `supervisor::install_panic_hook`, which still logs every panic (rate-limited);
/// this one adds a tagged Event Log entry only when it saved a new report, so at
/// most once per distinct bug and a few times per process.
fn install_crash_hook(config: &Config) {
    promailer_crash::install_with(
        "promailer",
        config.crash_dir(),
        vec![config.server.hostname.clone()],
        Some(Box::new(|report, saved| {
            let Some(path) = saved else { return };
            error!(
                event_id = event_id::CRASH,
                location = %report.location,
                fingerprint = %report.fingerprint,
                report = %path.display(),
                "Promailer hit an internal error: {}. A crash report was saved; report it from Promailer \
                 Manager (Help > Crash Reports) or set [crash_reports] github_token to file reports automatically.",
                report.message
            );
        })),
    );
}

/// File pending crash reports on GitHub when the operator configured a token.
async fn crash_uploader(app: Arc<App>) {
    const EVERY: Duration = Duration::from_secs(600);
    let mut shutdown = app.shutdown_rx();
    // The first pass soon after start-up files the report of a crash that stopped the service.
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(30), EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => break,
        }
        let cfg = app.cfg();
        let c = &cfg.crash_reports;
        if !c.enabled || c.github_token.trim().is_empty() {
            continue;
        }
        let (dir, repo, token) = (cfg.crash_dir(), c.github_repo.clone(), c.github_token.clone());
        drop(cfg);
        match tokio::task::spawn_blocking(move || file_crash_reports(&dir, &repo, &token)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!(error = %e, "could not file crash reports on GitHub; will retry"),
            Err(e) => warn!(error = %e, "crash report upload task failed"),
        }
    }
}

/// Oldest first, a few per pass; stops at the first failure (token or network problem).
fn file_crash_reports(dir: &Path, repo: &str, token: &str) -> std::result::Result<usize, String> {
    const PER_PASS: usize = 5;
    let mut filed = 0;
    for report in promailer_crash::pending(dir).into_iter().rev().take(PER_PASS) {
        let url = promailer_crash::github::upload(repo, token, &report)?;
        promailer_crash::mark_reported(dir, &report, &url).map_err(|e| e.to_string())?;
        info!(issue = %url, fingerprint = %report.fingerprint, "crash report filed on GitHub");
        filed += 1;
    }
    Ok(filed)
}

/// Feed the dashboard's throughput / queue-size time series.
async fn sample_stats(app: Arc<App>) {
    let mut shutdown = app.shutdown_rx();
    let mut tick = tokio::time::interval(Duration::from_secs(crate::stats::SAMPLE_INTERVAL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let snap = crate::api::snapshot(&app);
                app.stats_history.push(snap.sample(chrono::Utc::now().timestamp()));
            }
            _ = shutdown.changed() => break,
        }
    }
}
