//! Process bootstrap: load config, bind sockets, start subsystems, run until told to stop.

use crate::app::App;
use crate::config::Config;
use crate::dns::Dns;
use crate::queue::{store::Store, Queue};
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
    let _log_guards = crate::logging::init(&config.logging, console && config.logging.console)?;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        hostname = %config.server.hostname,
        data_dir = %config.server.data_dir.display(),
        "Promailer starting"
    );

    let result = run_inner(config, config_path, console, &mut control, on_ready).await;
    if let Err(e) = &result {
        error!(error = format!("{e:#}"), "fatal error");
    }
    info!("Promailer stopped");
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
    let (history_tx, history_rx) = mpsc::channel(10_000);
    app.events.attach_history(history_tx);
    let history = tokio::spawn(crate::events::run_writer(app.clone(), history_rx));
    let scheduler = tokio::spawn(crate::queue::run(app.clone()));
    tasks.push(tokio::spawn(housekeeping(app.clone())));
    tasks.push(tokio::spawn(sample_stats(app.clone())));

    info!(queued = app.queue.len(), "Promailer ready");
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
                        error!(error = format!("{e:#}"), "configuration reload failed; keeping current configuration");
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
    // Last, so events from the final deliveries are flushed to history.
    let _ = tokio::time::timeout(Duration::from_secs(5), history).await;
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
