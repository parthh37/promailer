//! Logging setup.
//!
//! Three independent, rotated streams are written under `logging.dir`:
//!
//! * `promailer.log` – service events (startup, errors, warnings)
//! * `smtp.log`      – SMTP protocol transcript (IIS "Enable logging" equivalent)
//! * `delivery.log`  – one line per delivery attempt / final outcome
//!
//! Protocol and delivery lines are emitted with the `smtp_protocol` and
//! `delivery` tracing targets and routed by per-layer filters. Writers are
//! non-blocking: a slow disk never stalls an SMTP session.

use crate::config::{LogFormat, LogRotation, LoggingConfig};
use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{filter_fn, EnvFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Layer};

pub const PROTOCOL_TARGET: &str = "smtp_protocol";
pub const DELIVERY_TARGET: &str = "delivery";

/// Keep alive for the lifetime of the process; dropping flushes buffered logs.
pub struct LogGuards(#[allow(dead_code)] Vec<WorkerGuard>);

fn appender(cfg: &LoggingConfig, prefix: &str) -> Result<RollingFileAppender> {
    let rotation = match cfg.rotation {
        LogRotation::Hourly => Rotation::HOURLY,
        LogRotation::Daily => Rotation::DAILY,
    };
    RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix(prefix)
        .filename_suffix("log")
        .max_log_files(cfg.max_files.max(1))
        .build(&cfg.dir)
        .with_context(|| format!("creating log appender in {}", cfg.dir.display()))
}

pub fn init(cfg: &LoggingConfig, console: bool) -> Result<LogGuards> {
    std::fs::create_dir_all(&cfg.dir).with_context(|| format!("creating log directory {}", cfg.dir.display()))?;

    let mut guards = Vec::new();
    let is_special = |t: &str| t == PROTOCOL_TARGET || t == DELIVERY_TARGET;

    // Main service log.
    let (main_writer, g) = tracing_appender::non_blocking(appender(cfg, "promailer")?);
    guards.push(g);
    let env_filter =
        EnvFilter::try_new(&cfg.level).with_context(|| format!("invalid logging.level '{}'", cfg.level))?;

    let main_layer = match cfg.format {
        LogFormat::Json => fmt::layer().json().with_writer(main_writer).with_ansi(false).boxed(),
        LogFormat::Text => fmt::layer().with_writer(main_writer).with_ansi(false).boxed(),
    }
    .with_filter(env_filter)
    .with_filter(filter_fn(move |m| !is_special(m.target())));

    let console_layer = console.then(|| {
        let f = EnvFilter::try_new(&cfg.level).unwrap_or_else(|_| EnvFilter::new("info"));
        fmt::layer()
            .with_writer(std::io::stdout)
            .with_filter(f)
            .with_filter(filter_fn(move |m| !is_special(m.target())))
    });

    // Protocol transcript: compact lines, no level/target noise.
    let protocol_layer = if cfg.protocol_log {
        let (w, g) = tracing_appender::non_blocking(appender(cfg, "smtp")?);
        guards.push(g);
        Some(
            fmt::layer()
                .with_writer(w)
                .with_ansi(false)
                .with_level(false)
                .with_target(false)
                .with_filter(filter_fn(|m| m.target() == PROTOCOL_TARGET)),
        )
    } else {
        None
    };

    let delivery_layer = if cfg.delivery_log {
        let (w, g) = tracing_appender::non_blocking(appender(cfg, "delivery")?);
        guards.push(g);
        let layer = match cfg.format {
            LogFormat::Json => fmt::layer().json().with_writer(w).boxed(),
            LogFormat::Text => fmt::layer().with_writer(w).with_ansi(false).with_target(false).boxed(),
        };
        Some(layer.with_filter(filter_fn(|m| m.target() == DELIVERY_TARGET)))
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(main_layer)
        .with(console_layer)
        .with(protocol_layer)
        .with(delivery_layer)
        .try_init()
        .context("initialising logging")?;

    Ok(LogGuards(guards))
}

/// Minimal stdout logging for CLI sub-commands.
pub fn init_cli() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_target(false)
        .try_init();
}
