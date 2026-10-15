//! Promailer - production-grade outbound SMTP server for Windows.

mod access;
mod api;
mod app;
mod auth;
mod certstore;
mod checks;
mod config;
mod dkim;
mod dns;
#[cfg_attr(not(windows), allow(dead_code))]
mod eventlog;
mod events;
mod logging;
mod message;
mod pickup;
mod queue;
mod server;
#[cfg_attr(not(windows), allow(dead_code))]
mod service;
mod smtp;
mod stats;
mod supervisor;
mod tls;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::PathBuf;

const EXAMPLE_CONFIG: &str = include_str!("../config/promailer.example.toml");

#[derive(Parser)]
#[command(name = "promailer", version, about = "Production-grade outbound SMTP server for Windows")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

fn default_config() -> PathBuf {
    if let Ok(p) = std::env::var("PROMAILER_CONFIG") {
        return PathBuf::from(p);
    }
    if cfg!(windows) {
        config::default_data_dir().join("promailer.toml")
    } else {
        PathBuf::from("promailer.toml")
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Run in the foreground (console mode). Ctrl+C stops gracefully.
    Run {
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
    },
    /// Manage the Windows service.
    Service {
        #[command(subcommand)]
        action: ServiceCmd,
    },
    /// Configuration utilities.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// DKIM key management.
    Dkim {
        #[command(subcommand)]
        action: DkimCmd,
    },
    /// Check deliverability DNS for a sending domain: rDNS, SPF, DKIM, DMARC, MX.
    Check {
        /// Sending domain (the From: domain).
        #[arg(short, long)]
        domain: String,
        /// Public sending IP(s) to test; defaults to [[outbound_ip]] or the detected local IP.
        #[arg(long, value_delimiter = ',')]
        ip: Vec<std::net::IpAddr>,
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
        /// Output JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// SMTP AUTH user helpers.
    User {
        #[command(subcommand)]
        action: UserCmd,
    },
    /// HTTP API key helpers.
    ApiKey {
        #[command(subcommand)]
        action: ApiKeyCmd,
    },
    /// Inspect the queue (read-only; use the API to retry/delete).
    Queue {
        #[command(subcommand)]
        action: QueueCmd,
    },
    /// Windows certificate store helpers.
    Cert {
        #[command(subcommand)]
        action: CertCmd,
    },
}

#[derive(Subcommand)]
enum CertCmd {
    /// List certificates in LocalMachine\<store> with the thumbprints [tls] thumbprint expects.
    List {
        /// Store name, e.g. My (Personal) or WebHosting.
        #[arg(long, default_value = "My")]
        store: String,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Install as an auto-start Windows service (run as Administrator).
    Install {
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
        /// Run as this account (default LocalSystem), e.g. "NT AUTHORITY\\NetworkService".
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        password: Option<String>,
    },
    Uninstall,
    Start,
    Stop,
    /// Stop the service (if running) and start it again.
    Restart,
    /// Ask the running service to reload its configuration.
    Reload,
    /// Apply recovery and start-up settings to an installed service (used by the MSI).
    #[command(hide = true)]
    Configure,
    /// Entry point used by the Service Control Manager.
    #[command(hide = true)]
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Validate a configuration file (also loads TLS and DKIM keys).
    Check {
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
    },
    /// Write an annotated example configuration.
    Init {
        #[arg(short, long, default_value_os_t = default_config())]
        output: PathBuf,
        #[arg(long)]
        force: bool,
        /// Leave an existing file untouched and succeed (used by the MSI).
        #[arg(long, conflicts_with = "force")]
        keep_existing: bool,
        /// Server host name to write into the new configuration.
        #[arg(long)]
        hostname: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Alg {
    Rsa,
    Ed25519,
}

#[derive(Subcommand)]
enum DkimCmd {
    /// Generate a DKIM key pair and print the DNS TXT record to publish.
    Generate {
        #[arg(short, long)]
        domain: String,
        #[arg(short, long, default_value = "s1")]
        selector: String,
        #[arg(short, long, value_enum, default_value = "rsa")]
        algorithm: Alg,
        #[arg(long, default_value_t = 2048)]
        bits: usize,
        /// Directory for the private key file.
        #[arg(short, long, default_value = "dkim")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Hash a password for [[user]] password_hash (reads from stdin if not given).
    HashPassword {
        #[arg(long)]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum ApiKeyCmd {
    /// Generate a new API key and its config entry.
    Generate {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
enum QueueCmd {
    List {
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
    },
    Show {
        id: String,
        #[arg(short, long, default_value_os_t = default_config())]
        config: PathBuf,
    },
}

fn main() {
    supervisor::install_panic_hook();
    let cli = Cli::parse();
    if let Err(e) = dispatch(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("promailer")
        .build()
        .context("starting async runtime")
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Run { config } => {
            let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
            runtime()?.block_on(server::run(&config, true, rx, || {
                println!("Promailer is running. Press Ctrl+C to stop.");
            }))
        }
        Cmd::Service { action } => match action {
            ServiceCmd::Install { config, account, password } => service::install(&config, account, password),
            ServiceCmd::Uninstall => service::uninstall(),
            ServiceCmd::Start => service::start(),
            ServiceCmd::Stop => service::stop(),
            ServiceCmd::Restart => {
                // Already stopped is fine; the start below reports real problems.
                if let Err(e) = service::stop() {
                    eprintln!("note: {e:#}");
                }
                service::start()
            }
            ServiceCmd::Reload => service::reload(),
            ServiceCmd::Configure => service::configure(),
            ServiceCmd::Run { config } => service::run_dispatcher(config),
        },
        Cmd::Config { action } => match action {
            ConfigCmd::Check { config } => {
                logging::init_cli();
                let cfg = config::Config::load(&config)?;
                dkim::DkimRegistry::load(&cfg.dkim)?;
                let cert = app::load_tls(&cfg)?;
                println!("Configuration OK: {}", config.display());
                println!("  hostname     : {}", cfg.server.hostname);
                if let Some(c) = cert.map(|c| c.info) {
                    println!("  tls cert     : {} ({})", c.subject, c.source);
                    println!("  thumbprint   : {}", c.thumbprint);
                    println!(
                        "  valid        : {} to {}",
                        c.not_before.format("%Y-%m-%d"),
                        c.not_after.format("%Y-%m-%d")
                    );
                }
                println!("  data_dir     : {}", cfg.server.data_dir.display());
                for l in &cfg.listeners {
                    println!(
                        "  listener     : {} on {} (tls={:?}, auth required={})",
                        l.name, l.bind, l.tls, l.require_auth
                    );
                }
                println!("  users        : {}", cfg.users.len());
                println!(
                    "  dkim domains : {}",
                    cfg.dkim.iter().map(|d| d.domain.as_str()).collect::<Vec<_>>().join(", ")
                );
                println!(
                    "  api          : {}",
                    if cfg.api.enabled { cfg.api.bind.to_string() } else { "disabled".into() }
                );
                Ok(())
            }
            ConfigCmd::Init { output, force, keep_existing, hostname } => {
                if output.exists() {
                    if keep_existing {
                        println!("{} already exists; left unchanged", output.display());
                        return Ok(());
                    }
                    if !force {
                        anyhow::bail!("{} already exists (use --force to overwrite)", output.display());
                    }
                }
                let text = example_config(hostname.as_deref())?;
                if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&output, text)?;
                println!("Wrote {}", output.display());
                Ok(())
            }
        },
        Cmd::Dkim { action: DkimCmd::Generate { domain, selector, algorithm, bits, out } } => {
            let alg = match algorithm {
                Alg::Rsa => config::DkimAlgorithm::RsaSha256,
                Alg::Ed25519 => config::DkimAlgorithm::Ed25519Sha256,
            };
            let domain = domain.to_lowercase();
            let g = dkim::generate(&domain, &selector, alg, bits)?;
            std::fs::create_dir_all(&out)?;
            let path = out.join(format!("{domain}.{selector}.pem"));
            if path.exists() {
                anyhow::bail!("{} already exists; refusing to overwrite a live key", path.display());
            }
            std::fs::write(&path, &g.private_pem)?;
            println!("Private key written to {}\n", path.display());
            println!("1) Publish this DNS TXT record:\n");
            println!("   Name : {}", g.dns_name);
            println!("   Value: {}\n", g.dns_value);
            println!("   (Long values must be split into 255-character strings by some DNS providers.)\n");
            println!("2) Add to promailer.toml:\n");
            println!(
                "[[dkim]]\ndomain = \"{domain}\"\nselector = \"{selector}\"\nprivate_key = '{}'\nalgorithm = \"{}\"\n",
                path.display(),
                match alg {
                    config::DkimAlgorithm::RsaSha256 => "rsa-sha256",
                    config::DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
                }
            );
            if matches!(alg, config::DkimAlgorithm::Ed25519Sha256) {
                println!(
                    "Note: some receivers don't verify Ed25519 yet; configure an RSA key for the same domain too."
                );
            }
            println!("3) Verify with: promailer check --domain {domain}");
            Ok(())
        }
        Cmd::Check { domain, ip, config, json } => {
            logging::init_cli();
            let cfg = if config.exists() {
                config::Config::load(&config)?
            } else {
                eprintln!("note: {} not found, using defaults (DKIM keys can't be verified)", config.display());
                toml::from_str("")?
            };
            let reg = dkim::DkimRegistry::load(&cfg.dkim).unwrap_or_else(|_| dkim::DkimRegistry::empty());
            let report = runtime()?.block_on(async {
                let dns = dns::Dns::new()?;
                anyhow::Ok(checks::run(&dns, &cfg, &reg, &domain, &ip).await)
            })?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                checks::print(&report);
            }
            if report.failed() {
                std::process::exit(2);
            }
            Ok(())
        }
        Cmd::User { action: UserCmd::HashPassword { password } } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    eprint!("Password: ");
                    std::io::stderr().flush()?;
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            if pw.len() < 8 {
                anyhow::bail!("use at least 8 characters");
            }
            println!("{}", auth::hash_password(&pw)?);
            Ok(())
        }
        Cmd::ApiKey { action: ApiKeyCmd::Generate { name } } => {
            let key = auth::generate_api_key();
            println!("API key (shown once, store it securely):\n\n  {key}\n");
            println!("Add to promailer.toml:\n");
            println!(
                "[[api.keys]]\nname = \"{name}\"\nkey_sha256 = \"{}\"\npermissions = [\"send\"]",
                auth::sha256_hex(key.as_bytes())
            );
            Ok(())
        }
        Cmd::Cert { action: CertCmd::List { store } } => {
            let now = chrono::Utc::now();
            let mut certs = certstore::list(&store)?;
            certs.sort_by_key(|c| std::cmp::Reverse(c.info.not_after));
            println!("{:<40}  {:<10}  {:<13}  {:<3}  subject", "thumbprint", "expires", "status", "key");
            for c in &certs {
                let status = if c.archived {
                    "archived"
                } else if c.info.not_after < now {
                    "expired"
                } else if c.info.not_before > now {
                    "not yet valid"
                } else {
                    "valid"
                };
                println!(
                    "{:<40}  {:<10}  {:<13}  {:<3}  {}",
                    c.info.thumbprint,
                    c.info.not_after.format("%Y-%m-%d"),
                    status,
                    if c.has_key { "yes" } else { "no" },
                    c.info.subject
                );
            }
            println!("\n{} certificate(s) in LocalMachine\\{store}", certs.len());
            println!("Use one with a private key (key = yes) in promailer.toml:  [tls] thumbprint = \"...\"");
            Ok(())
        }
        Cmd::Queue { action } => {
            let (config, id) = match action {
                QueueCmd::List { config } => (config, None),
                QueueCmd::Show { id, config } => (config, Some(id)),
            };
            let cfg = config::Config::load(&config)?;
            let store = queue::store::Store::open(cfg.queue_dir(), cfg.badmail_dir(), cfg.drop_dir(), false)?;
            match id {
                Some(id) => println!("{}", serde_json::to_string_pretty(&store.load_meta(&id)?)?),
                None => {
                    let ids = store.list_ids();
                    println!(
                        "{:<28} {:<20} {:>5} {:>8}  {:<30} next attempt",
                        "ID", "created", "rcpt", "size", "sender"
                    );
                    for id in &ids {
                        if let Ok(m) = store.load_meta(id) {
                            let pending = m.pending().count();
                            println!(
                                "{:<28} {:<20} {:>2}/{:<2} {:>8}  {:<30} {}",
                                m.id,
                                m.created.format("%Y-%m-%d %H:%M:%S"),
                                pending,
                                m.recipients.len(),
                                m.size,
                                if m.sender.is_empty() { "<>" } else { &m.sender },
                                m.next_attempt.format("%Y-%m-%d %H:%M:%S")
                            );
                        }
                    }
                    println!("\n{} message(s) in queue", ids.len());
                }
            }
            Ok(())
        }
    }
}

/// The example configuration, optionally with `server.hostname` filled in.
fn example_config(hostname: Option<&str>) -> Result<String> {
    const PLACEHOLDER: &str = "hostname = \"mail.example.com\"";
    let Some(host) = hostname.map(|h| h.trim().to_lowercase()).filter(|h| !h.is_empty()) else {
        return Ok(EXAMPLE_CONFIG.to_string());
    };
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        anyhow::bail!("invalid host name '{host}'");
    }
    Ok(EXAMPLE_CONFIG.replacen(PLACEHOLDER, &format!("hostname = \"{host}\""), 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_hostname_is_personalised() {
        let text = example_config(Some(" Mail.Contoso.COM ")).unwrap();
        let cfg: config::Config = toml::from_str(&text).unwrap();
        assert_eq!(cfg.server.hostname, "mail.contoso.com");
        assert_eq!(example_config(None).unwrap(), EXAMPLE_CONFIG);
        assert_eq!(example_config(Some("")).unwrap(), EXAMPLE_CONFIG);
        assert!(example_config(Some("evil\"\n[api]")).is_err());
    }
}
