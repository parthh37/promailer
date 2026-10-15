//! Configuration model.
//!
//! The layout intentionally mirrors the IIS6 SMTP virtual server property pages so
//! administrators migrating from IIS can find every familiar knob:
//!
//! | IIS6 page                     | Promailer section                         |
//! |-------------------------------|-------------------------------------------|
//! | General (IP, connections, log)| `[[listener]]`, `[limits]`, `[logging]`   |
//! | Access > Authentication       | `[[listener]]` auth flags, `[[user]]`     |
//! | Access > Connection control   | `[access] allow/deny`                     |
//! | Access > Relay restrictions   | `[access] relay_*`                        |
//! | Messages                      | `[limits]`, `[delivery] ndr_*`, badmail   |
//! | Delivery (retry, expiry)      | `[delivery]`                              |
//! | Delivery > Outbound security  | `[delivery.smarthost]`, `[delivery] tls`  |
//! | Delivery > Advanced           | `[server] hostname/masquerade/max_hops`   |
//! | Domains (remote/local)        | `[[domain]]`, `[server] local_domains`    |

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default, rename = "listener")]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub access: AccessConfig,
    #[serde(default, rename = "user")]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default, rename = "outbound_ip")]
    pub outbound_ips: Vec<OutboundIp>,
    #[serde(default, rename = "domain")]
    pub domains: Vec<DomainRule>,
    #[serde(default)]
    pub dkim: Vec<DkimConfig>,
    #[serde(default)]
    pub pickup: PickupConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub history: HistoryConfig,
    #[serde(default)]
    pub crash_reports: CrashReportsConfig,
}

// ---------------------------------------------------------------------------
// [server]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    /// Fully-qualified host name used in the banner, EHLO and Received headers.
    /// Should match the PTR record of your outbound IP(s).
    pub hostname: String,
    /// Root directory for queue, pickup, badmail, drop and logs.
    pub data_dir: PathBuf,
    /// IIS "Masquerade domain": replaces the domain of the envelope sender on outbound mail.
    pub masquerade_domain: Option<String>,
    /// IIS "Maximum hop count": messages with more Received headers are rejected.
    pub max_hop_count: usize,
    /// Domains considered local. Mail for them is written to the Drop directory.
    pub local_domains: Vec<String>,
    /// Time allowed for in-flight work to finish on shutdown.
    #[serde(with = "humantime_serde")]
    pub shutdown_grace: Duration,
    /// Postmaster address used as From: on NDRs.
    pub postmaster: Option<String>,
    /// fsync queue files before acknowledging a message (250 OK). Disabling it
    /// roughly doubles enqueue throughput but risks losing accepted mail on power loss.
    pub durable_writes: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: default_hostname(),
            data_dir: default_data_dir(),
            masquerade_domain: None,
            max_hop_count: 30,
            local_domains: vec![],
            shutdown_grace: Duration::from_secs(30),
            postmaster: None,
            durable_writes: true,
        }
    }
}

fn default_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".into())
        .to_lowercase()
}

pub fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        PathBuf::from(base).join("Promailer")
    } else {
        PathBuf::from("./data")
    }
}

// ---------------------------------------------------------------------------
// [logging]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    Hourly,
    Daily,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Log directory; relative paths are resolved against `server.data_dir`.
    pub dir: PathBuf,
    /// tracing filter, e.g. "info" or "info,promailer::smtp=debug".
    pub level: String,
    pub format: LogFormat,
    pub rotation: LogRotation,
    /// Number of rotated files to keep per log stream.
    pub max_files: usize,
    /// SMTP command/response transcript log (IIS "Enable logging").
    pub protocol_log: bool,
    /// One line per delivery attempt with remote host and response.
    pub delivery_log: bool,
    /// Also log to stdout (ignored when running as a Windows service).
    pub console: bool,
    /// Write start/stop, reload, certificate and error events to the Windows Application
    /// log (source "Promailer") when running as a service.
    pub event_log: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("logs"),
            level: "info".into(),
            format: LogFormat::Text,
            rotation: LogRotation::Daily,
            max_files: 30,
            protocol_log: true,
            delivery_log: true,
            console: true,
            event_log: true,
        }
    }
}

// ---------------------------------------------------------------------------
// [[listener]]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ListenerTls {
    /// Plain text only.
    None,
    /// Advertise STARTTLS (needs `[tls]`).
    Starttls,
    /// TLS from the first byte, e.g. port 465 (needs `[tls]`).
    Implicit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    #[serde(default = "default_listener_name")]
    pub name: String,
    pub bind: SocketAddr,
    #[serde(default = "default_listener_tls")]
    pub tls: ListenerTls,
    /// Refuse MAIL FROM until STARTTLS completed.
    #[serde(default)]
    pub require_tls: bool,
    /// Refuse MAIL FROM until AUTH succeeded (IIS: uncheck "Anonymous access").
    #[serde(default)]
    pub require_auth: bool,
    /// Offer AUTH on unencrypted connections (IIS "Basic authentication" without TLS).
    #[serde(default)]
    pub allow_plaintext_auth: bool,
    /// Custom text after "220 <hostname>" in the greeting.
    #[serde(default)]
    pub banner: Option<String>,
}

fn default_listener_name() -> String {
    "smtp".into()
}
fn default_listener_tls() -> ListenerTls {
    ListenerTls::None
}

// ---------------------------------------------------------------------------
// [tls]
// ---------------------------------------------------------------------------

/// Server certificate: either PEM files (`cert` + `key`) or, on Windows, a certificate
/// in the LocalMachine certificate store selected by `thumbprint`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain (leaf first).
    #[serde(default)]
    pub cert: Option<PathBuf>,
    /// PEM private key (PKCS#8, PKCS#1 or SEC1).
    #[serde(default)]
    pub key: Option<PathBuf>,
    /// SHA-1 thumbprint of a certificate in `LocalMachine\<store>`, as shown by
    /// certlm.msc or `Get-ChildItem Cert:\LocalMachine\My`.
    #[serde(default)]
    pub thumbprint: Option<String>,
    /// LocalMachine store name: "My" (Personal, default) or e.g. "WebHosting".
    #[serde(default)]
    pub store: Option<String>,
}

/// Where the server certificate comes from, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsSource<'a> {
    Files { cert: &'a Path, key: &'a Path },
    Store { store: &'a str, thumbprint: &'a str },
}

impl TlsConfig {
    pub fn source(&self) -> Result<TlsSource<'_>> {
        match (&self.cert, &self.key, &self.thumbprint) {
            (Some(cert), Some(key), None) => {
                if self.store.is_some() {
                    bail!("[tls] store only applies to thumbprint");
                }
                Ok(TlsSource::Files { cert, key })
            }
            (None, None, Some(thumbprint)) => {
                Ok(TlsSource::Store { store: self.store.as_deref().unwrap_or("My"), thumbprint })
            }
            (_, _, Some(_)) => bail!("[tls] use either thumbprint or cert/key, not both"),
            (Some(_), None, None) => bail!("[tls] cert is set but key is missing"),
            (None, Some(_), None) => bail!("[tls] key is set but cert is missing"),
            (None, None, None) => {
                bail!("[tls] needs cert and key (PEM files) or thumbprint (Windows certificate store)")
            }
        }
    }
}

/// Normalise a thumbprint pasted from the Windows certificate dialog: drop spaces, colons
/// and the invisible U+200E mark that certmgr prepends when copying, then upper-case.
pub fn normalize_thumbprint(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_uppercase()
}

// ---------------------------------------------------------------------------
// [limits]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    /// IIS "Limit number of connections to".
    pub max_connections: usize,
    pub max_connections_per_ip: usize,
    /// IIS "Connection time-out" (idle time between commands).
    #[serde(with = "humantime_serde")]
    pub command_timeout: Duration,
    /// Maximum time to receive the DATA payload.
    #[serde(with = "humantime_serde")]
    pub data_timeout: Duration,
    /// Hard cap for a whole SMTP session.
    #[serde(with = "humantime_serde")]
    pub session_timeout: Duration,
    /// IIS "Limit message size to".
    pub max_message_size: ByteSize,
    /// IIS "Limit session size to".
    pub max_session_size: ByteSize,
    /// IIS "Limit number of messages per connection to".
    pub max_messages_per_connection: usize,
    /// IIS "Limit number of recipients per message to".
    pub max_recipients_per_message: usize,
    /// Disconnect after this many bad commands.
    pub max_errors_per_session: usize,
    /// Accepted messages per minute per client IP (0 = unlimited).
    pub messages_per_minute_per_ip: u32,
    /// Accepted messages per minute per authenticated user (0 = unlimited).
    pub messages_per_minute_per_user: u32,
    /// New connections per minute per client IP (0 = unlimited).
    pub connections_per_minute_per_ip: u32,
    /// Stop accepting mail (451) when this many messages are queued (0 = unlimited).
    pub max_queue_size: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            max_connections_per_ip: 100,
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(600),
            session_timeout: Duration::from_secs(3600),
            max_message_size: ByteSize(25 * 1024 * 1024),
            max_session_size: ByteSize(500 * 1024 * 1024),
            max_messages_per_connection: 100,
            max_recipients_per_message: 1000,
            max_errors_per_session: 10,
            messages_per_minute_per_ip: 0,
            messages_per_minute_per_user: 0,
            connections_per_minute_per_ip: 0,
            max_queue_size: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// [access]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccessConfig {
    /// IIS "All except the list below" (allow) vs "Only the list below" (deny).
    pub default: DefaultPolicy,
    /// Always allowed to connect (IPs or CIDR networks).
    pub allow: Vec<IpNet>,
    /// Never allowed to connect. Deny wins over allow.
    pub deny: Vec<IpNet>,
    /// IIS relay restrictions: clients allowed to relay to any domain.
    pub relay_allow: Vec<IpNet>,
    /// IIS "Allow all computers which successfully authenticate to relay".
    pub relay_authenticated: bool,
    /// IIS "Perform reverse DNS lookup on incoming messages".
    pub reverse_dns_lookup: bool,
    /// Reject clients whose IP has no PTR record (only used if reverse_dns_lookup).
    pub require_reverse_dns: bool,
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            default: DefaultPolicy::Allow,
            allow: vec![],
            deny: vec![],
            relay_allow: vec![IpNet::from_str("127.0.0.1/32").unwrap(), IpNet::from_str("::1/128").unwrap()],
            relay_authenticated: true,
            reverse_dns_lookup: false,
            require_reverse_dns: false,
        }
    }
}

// ---------------------------------------------------------------------------
// [[user]]  (SMTP AUTH accounts)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub username: String,
    /// Argon2 PHC string; generate with `promailer user hash-password`.
    pub password_hash: String,
    /// If non-empty, MAIL FROM must be in one of these domains.
    #[serde(default)]
    pub allowed_sender_domains: Vec<String>,
    /// If non-empty, the user may only log in from these networks.
    #[serde(default)]
    pub allowed_ips: Vec<IpNet>,
    /// Per-user override of `limits.messages_per_minute_per_user`.
    #[serde(default)]
    pub messages_per_minute: Option<u32>,
    #[serde(default)]
    pub disabled: bool,
}

// ---------------------------------------------------------------------------
// [delivery]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutboundTls {
    /// Use STARTTLS when offered, fall back to plain text.
    Opportunistic,
    /// Fail (temporarily) if the remote does not offer STARTTLS.
    Required,
    /// Never use TLS.
    Disabled,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SmarthostTls {
    None,
    Starttls,
    Implicit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmarthostConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default = "default_smarthost_tls")]
    pub tls: SmarthostTls,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Validate the smarthost certificate against public roots.
    #[serde(default = "default_true")]
    pub verify_certificate: bool,
}

fn default_smtp_port() -> u16 {
    25
}
fn default_smarthost_tls() -> SmarthostTls {
    SmarthostTls::Starttls
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeliveryConfig {
    /// Concurrent outbound SMTP connections (IIS "Limit number of connections to").
    pub max_connections: usize,
    /// Concurrent connections per destination domain (IIS "Limit connections per domain").
    pub max_connections_per_domain: usize,
    /// Messages processed concurrently by the queue (bounds memory).
    pub max_concurrent_messages: usize,
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub command_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub data_timeout: Duration,
    /// IIS first/second/third/subsequent retry intervals. The last value repeats.
    #[serde(with = "humantime_serde_vec")]
    pub retry_intervals: Vec<Duration>,
    /// IIS "Expiration timeout": give up and send an NDR after this long.
    #[serde(with = "humantime_serde")]
    pub expire_after: Duration,
    /// IIS "Delay notification": warn the sender once after this long (0 = never).
    #[serde(with = "humantime_serde")]
    pub delay_notification_after: Duration,
    /// Generate non-delivery reports to the sender.
    pub send_ndr: bool,
    /// IIS "Send copy of Non-Delivery Report to".
    pub ndr_copy_to: Option<String>,
    pub tls: OutboundTls,
    /// Verify remote certificates on direct MX delivery (most MTAs do not).
    pub verify_certificates: bool,
    /// Deliver to IPv6 MX addresses.
    pub ipv6: bool,
    pub smarthost: Option<SmarthostConfig>,
    /// IIS "Attempt direct delivery before sending to smart host".
    pub attempt_direct_before_smarthost: bool,
    /// Keep idle outbound connections for reuse.
    #[serde(with = "humantime_serde")]
    pub connection_idle_timeout: Duration,
    /// Messages sent over one cached connection before it is closed.
    pub max_messages_per_outbound_connection: usize,
    /// How often the queue is scanned for due messages.
    #[serde(with = "humantime_serde")]
    pub queue_scan_interval: Duration,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_connections: 500,
            max_connections_per_domain: 20,
            max_concurrent_messages: 2000,
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(300),
            data_timeout: Duration::from_secs(600),
            retry_intervals: vec![
                Duration::from_secs(10 * 60),
                Duration::from_secs(10 * 60),
                Duration::from_secs(10 * 60),
                Duration::from_secs(15 * 60),
                Duration::from_secs(30 * 60),
                Duration::from_secs(60 * 60),
            ],
            expire_after: Duration::from_secs(2 * 24 * 3600),
            delay_notification_after: Duration::from_secs(12 * 3600),
            send_ndr: true,
            ndr_copy_to: None,
            tls: OutboundTls::Opportunistic,
            verify_certificates: false,
            ipv6: false,
            smarthost: None,
            attempt_direct_before_smarthost: false,
            connection_idle_timeout: Duration::from_secs(30),
            max_messages_per_outbound_connection: 100,
            queue_scan_interval: Duration::from_secs(1),
        }
    }
}

mod humantime_serde_vec {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Duration>, D::Error> {
        let raw = Vec::<String>::deserialize(d)?;
        raw.iter().map(|s| humantime::parse_duration(s).map_err(serde::de::Error::custom)).collect()
    }

    pub fn serialize<S: Serializer>(v: &[Duration], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|d| humantime::format_duration(*d).to_string()))
    }
}

// ---------------------------------------------------------------------------
// [[outbound_ip]]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundIp {
    /// Local address to bind outgoing connections to. Must be assigned to this server.
    pub address: IpAddr,
    /// EHLO name for this IP; should equal the PTR record. Defaults to server.hostname.
    #[serde(default)]
    pub helo: Option<String>,
    /// Pool name, referenced by `[[domain]] pool` and the API `pool` field.
    #[serde(default = "default_pool")]
    pub pool: String,
}

fn default_pool() -> String {
    "default".into()
}

// ---------------------------------------------------------------------------
// [[domain]]  (IIS remote domains)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRule {
    /// Destination domain; "*.example.com" matches all subdomains.
    pub name: String,
    #[serde(default)]
    pub smarthost: Option<SmarthostConfig>,
    #[serde(default)]
    pub tls: Option<OutboundTls>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    /// Outbound IP pool to use for this destination.
    #[serde(default)]
    pub pool: Option<String>,
}

// ---------------------------------------------------------------------------
// [[dkim]]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DkimAlgorithm {
    RsaSha256,
    Ed25519Sha256,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DkimConfig {
    /// Signing domain (d=). Messages whose From: domain matches are signed.
    pub domain: String,
    pub selector: String,
    /// PEM private key; generate with `promailer dkim generate`.
    pub private_key: PathBuf,
    #[serde(default = "default_dkim_alg")]
    pub algorithm: DkimAlgorithm,
    /// Headers to sign. Defaults to a safe, widely-used set.
    #[serde(default = "default_dkim_headers")]
    pub headers: Vec<String>,
    /// Also sign mail from subdomains of `domain`.
    #[serde(default)]
    pub include_subdomains: bool,
    /// Signature expiry (x=). Unset = no expiry.
    #[serde(default, with = "humantime_serde")]
    pub expire: Option<Duration>,
}

fn default_dkim_alg() -> DkimAlgorithm {
    DkimAlgorithm::RsaSha256
}

pub fn default_dkim_headers() -> Vec<String> {
    [
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-ID",
        "Reply-To",
        "In-Reply-To",
        "References",
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "List-Unsubscribe",
        "List-Unsubscribe-Post",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// ---------------------------------------------------------------------------
// [pickup]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct PickupConfig {
    pub enabled: bool,
    /// Relative to data_dir unless absolute.
    pub dir: PathBuf,
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Files must be unmodified for this long before pickup (writer finished).
    #[serde(with = "humantime_serde")]
    pub settle_time: Duration,
}

impl Default for PickupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: PathBuf::from("pickup"),
            poll_interval: Duration::from_secs(2),
            settle_time: Duration::from_millis(500),
        }
    }
}

// ---------------------------------------------------------------------------
// [api]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ApiPermission {
    Send,
    Queue,
    Admin,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    pub name: String,
    /// SHA-256 hex of the key; generate with `promailer api-key generate`.
    pub key_sha256: String,
    pub permissions: Vec<ApiPermission>,
    /// If non-empty, `from` must be in one of these domains.
    #[serde(default)]
    pub allowed_sender_domains: Vec<String>,
    #[serde(default)]
    pub messages_per_minute: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    /// Networks allowed to call the API at all.
    pub allow: Vec<IpNet>,
    pub keys: Vec<ApiKeyConfig>,
    pub max_body_size: ByteSize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:8025".parse().unwrap(),
            allow: vec![IpNet::from_str("127.0.0.1/32").unwrap(), IpNet::from_str("::1/128").unwrap()],
            keys: vec![],
            max_body_size: ByteSize(35 * 1024 * 1024),
        }
    }
}

// ---------------------------------------------------------------------------
// [history]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct HistoryConfig {
    /// Record queue/delivery events as JSON lines under `<data_dir>/history`,
    /// searchable from the API and Promailer Manager.
    pub enabled: bool,
    /// Days of history files to keep.
    pub retention_days: u32,
    /// Recent events kept in memory for the live delivery log.
    pub memory_events: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self { enabled: true, retention_days: 30, memory_events: 10_000 }
    }
}

// ---------------------------------------------------------------------------
// [crash_reports]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CrashReportsConfig {
    /// Save a report under `<data_dir>/crashes` when Promailer hits an internal error
    /// (panic): version, message and code location, with addresses and names removed.
    pub enabled: bool,
    /// GitHub repository (`owner/name`) that receives reports.
    pub github_repo: String,
    /// Fine-grained token with "Issues: read and write" on `github_repo`. When set,
    /// reports are filed automatically (one issue per distinct bug; repeats add a
    /// comment). Empty: report them from Promailer Manager instead.
    pub github_token: String,
}

impl Default for CrashReportsConfig {
    fn default() -> Self {
        Self { enabled: true, github_repo: promailer_crash::github::DEFAULT_REPO.into(), github_token: String::new() }
    }
}

// ---------------------------------------------------------------------------
// ByteSize: accepts 1048576, "1048576", "512KB", "25MB", "1GB"
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn as_usize(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

impl FromStr for ByteSize {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let n: u64 = num.parse().map_err(|_| format!("invalid size '{s}'"))?;
        let mult = match unit.trim().to_ascii_uppercase().as_str() {
            "" | "B" => 1,
            "K" | "KB" | "KIB" => 1024,
            "M" | "MB" | "MIB" => 1024 * 1024,
            "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
            other => return Err(format!("unknown size unit '{other}'")),
        };
        n.checked_mul(mult).map(ByteSize).ok_or_else(|| "size overflow".into())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u64),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(ByteSize(n)),
            Raw::S(s) => s.parse().map_err(serde::de::Error::custom),
        }
    }
}

// ---------------------------------------------------------------------------
// Loading & validation
// ---------------------------------------------------------------------------

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading config file {}", path.display()))?;
        Self::parse(&text, path).map_err(|e| match e {
            ConfigError::Syntax(e) => anyhow::Error::new(e).context(format!("parsing {}", path.display())),
            ConfigError::Invalid(e) => e,
        })
    }

    /// Parse and validate config text as if it were stored at `path` (relative
    /// paths resolve against its directory). Used by `load` and the config editor.
    pub fn parse(text: &str, path: &Path) -> std::result::Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(ConfigError::Syntax)?;
        let base = path.parent().unwrap_or(Path::new("."));
        cfg.resolve_paths(base);
        cfg.normalize();
        cfg.validate().map_err(ConfigError::Invalid)?;
        Ok(cfg)
    }

    /// Non-fatal problems worth showing to an administrator.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if !self.hostname_is_fqdn() {
            w.push(format!(
                "server.hostname '{}' is not a fully-qualified domain name; receivers may reject mail",
                self.server.hostname
            ));
        }
        if self.api.enabled && self.api.keys.is_empty() {
            w.push("HTTP API enabled but no [[api.keys]] configured; only /health and /metrics are usable".into());
        }
        if self.api.enabled && self.api.allow.is_empty() {
            w.push("api.allow is empty: the HTTP API accepts connections from any address".into());
        }
        w
    }

    fn hostname_is_fqdn(&self) -> bool {
        !self.server.hostname.is_empty() && self.server.hostname.contains('.')
    }

    /// Make every relative path absolute so the service is independent of its
    /// working directory (services start in C:\Windows\System32).
    fn resolve_paths(&mut self, config_dir: &Path) {
        let abs = |p: &Path, base: &Path| -> PathBuf {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };
        self.server.data_dir = abs(&self.server.data_dir, config_dir);
        let data = self.server.data_dir.clone();
        self.logging.dir = abs(&self.logging.dir, &data);
        self.pickup.dir = abs(&self.pickup.dir, &data);
        if let Some(tls) = &mut self.tls {
            tls.cert = tls.cert.as_deref().map(|p| abs(p, config_dir));
            tls.key = tls.key.as_deref().map(|p| abs(p, config_dir));
        }
        for d in &mut self.dkim {
            d.private_key = abs(&d.private_key, config_dir);
        }
    }

    fn normalize(&mut self) {
        self.server.hostname = self.server.hostname.trim().to_lowercase();
        for d in &mut self.server.local_domains {
            *d = d.trim().to_lowercase();
        }
        for d in &mut self.domains {
            d.name = d.name.trim().to_lowercase();
        }
        for d in &mut self.dkim {
            d.domain = d.domain.trim().to_lowercase();
        }
        for k in &mut self.api.keys {
            k.key_sha256 = k.key_sha256.trim().to_lowercase();
        }
        if let Some(tls) = &mut self.tls {
            tls.thumbprint = tls.thumbprint.as_deref().map(normalize_thumbprint);
            tls.store = tls.store.as_deref().map(|s| s.trim().to_string());
        }
        if self.listeners.is_empty() {
            self.listeners.push(ListenerConfig {
                name: "smtp".into(),
                bind: "0.0.0.0:25".parse().unwrap(),
                tls: ListenerTls::None,
                require_tls: false,
                require_auth: false,
                allow_plaintext_auth: false,
                banner: None,
            });
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.hostname_is_fqdn() {
            tracing::warn!(
                hostname = %self.server.hostname,
                "server.hostname is not a fully-qualified domain name; receivers may reject mail"
            );
        }
        for l in &self.listeners {
            if matches!(l.tls, ListenerTls::Starttls | ListenerTls::Implicit) && self.tls.is_none() {
                bail!("listener '{}' uses TLS but no [tls] section is configured", l.name);
            }
            if l.require_tls && l.tls == ListenerTls::None {
                bail!("listener '{}' has require_tls but tls = \"none\"", l.name);
            }
        }
        let mut binds = std::collections::HashSet::new();
        for l in &self.listeners {
            if !binds.insert(l.bind) {
                bail!("duplicate listener bind address {}", l.bind);
            }
        }
        if self.delivery.retry_intervals.is_empty() {
            bail!("delivery.retry_intervals must contain at least one interval");
        }
        if self.delivery.max_connections == 0 || self.delivery.max_connections_per_domain == 0 {
            bail!("delivery connection limits must be greater than zero");
        }
        if self.delivery.max_concurrent_messages == 0 {
            bail!("delivery.max_concurrent_messages must be greater than zero");
        }
        for u in &self.users {
            if !u.password_hash.starts_with("$argon2") {
                bail!(
                    "user '{}': password_hash must be an argon2 hash (use `promailer user hash-password`)",
                    u.username
                );
            }
        }
        let mut names = std::collections::HashSet::new();
        for u in &self.users {
            if !names.insert(u.username.to_lowercase()) {
                bail!("duplicate user '{}'", u.username);
            }
        }
        if !promailer_crash::github::valid_repo(&self.crash_reports.github_repo) {
            bail!("crash_reports.github_repo must look like owner/name");
        }
        for k in &self.api.keys {
            if k.key_sha256.len() != 64 || !k.key_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("api key '{}': key_sha256 must be 64 hex characters", k.name);
            }
        }
        for d in &self.dkim {
            if !d.private_key.exists() {
                bail!("dkim key for {} (selector {}) not found: {}", d.domain, d.selector, d.private_key.display());
            }
        }
        let pools: std::collections::HashSet<&str> = self.outbound_ips.iter().map(|i| i.pool.as_str()).collect();
        for d in &self.domains {
            if let Some(p) = &d.pool {
                if !pools.contains(p.as_str()) {
                    bail!("domain rule '{}' references unknown outbound pool '{}'", d.name, p);
                }
            }
        }
        if let Some(tls) = &self.tls {
            match tls.source()? {
                TlsSource::Files { cert, key } => {
                    if !cert.exists() {
                        bail!("TLS certificate not found: {}", cert.display());
                    }
                    if !key.exists() {
                        bail!("TLS key not found: {}", key.display());
                    }
                }
                TlsSource::Store { store, thumbprint } => {
                    if !cfg!(windows) {
                        bail!("[tls] thumbprint (Windows certificate store) is only supported on Windows");
                    }
                    if thumbprint.len() != 40 {
                        bail!("[tls] thumbprint must be 40 hex characters (SHA-1), got {}", thumbprint.len());
                    }
                    if store.is_empty() || store.contains('\\') {
                        bail!("[tls] store must be a LocalMachine store name such as \"My\" or \"WebHosting\"");
                    }
                }
            }
        }
        Ok(())
    }

    /// Find the most specific remote-domain rule for `domain`.
    pub fn domain_rule(&self, domain: &str) -> Option<&DomainRule> {
        let mut best: Option<&DomainRule> = None;
        for rule in &self.domains {
            let matches = if let Some(suffix) = rule.name.strip_prefix("*.") {
                domain == suffix || domain.ends_with(&format!(".{suffix}"))
            } else {
                rule.name == domain
            };
            if matches && best.is_none_or(|b| rule.name.len() > b.name.len()) {
                best = Some(rule);
            }
        }
        best
    }

    pub fn is_local_domain(&self, domain: &str) -> bool {
        self.server.local_domains.iter().any(|d| d == domain)
    }

    pub fn postmaster(&self) -> String {
        self.server.postmaster.clone().unwrap_or_else(|| format!("postmaster@{}", self.server.hostname))
    }

    pub fn queue_dir(&self) -> PathBuf {
        self.server.data_dir.join("queue")
    }
    pub fn badmail_dir(&self) -> PathBuf {
        self.server.data_dir.join("badmail")
    }
    pub fn drop_dir(&self) -> PathBuf {
        self.server.data_dir.join("drop")
    }
    pub fn history_dir(&self) -> PathBuf {
        self.server.data_dir.join("history")
    }
    pub fn crash_dir(&self) -> PathBuf {
        self.server.data_dir.join("crashes")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// TOML syntax or schema error (carries a source span).
    #[error(transparent)]
    Syntax(toml::de::Error),
    /// Semantic validation failure.
    #[error("{0:#}")]
    Invalid(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytesize_parsing() {
        assert_eq!("1024".parse::<ByteSize>().unwrap().0, 1024);
        assert_eq!("10MB".parse::<ByteSize>().unwrap().0, 10 * 1024 * 1024);
        assert_eq!("512 kb".parse::<ByteSize>().unwrap().0, 512 * 1024);
        assert!("10XB".parse::<ByteSize>().is_err());
    }

    #[test]
    fn domain_rule_most_specific_wins() {
        let mut cfg: Config = toml::from_str(
            r#"
            [[domain]]
            name = "*.example.com"
            max_connections = 1
            [[domain]]
            name = "mail.example.com"
            max_connections = 2
            "#,
        )
        .unwrap();
        cfg.normalize();
        assert_eq!(cfg.domain_rule("mail.example.com").unwrap().max_connections, Some(2));
        assert_eq!(cfg.domain_rule("x.example.com").unwrap().max_connections, Some(1));
        assert_eq!(cfg.domain_rule("example.com").unwrap().max_connections, Some(1));
        assert!(cfg.domain_rule("example.org").is_none());
    }

    #[test]
    fn thumbprint_pasted_from_certmgr_is_normalised() {
        // certmgr's Details tab copies with a leading U+200E and spaces between byte pairs.
        let pasted = "\u{200e}3a 1f 00 b2 c4 d5 e6 f7 08 19 2a 3b 4c 5d 6e 7f 80 91 a2 b3";
        assert_eq!(normalize_thumbprint(pasted), "3A1F00B2C4D5E6F708192A3B4C5D6E7F8091A2B3");
        assert_eq!(normalize_thumbprint("3A:1F:00"), "3A1F00");
    }

    #[test]
    fn tls_source_selection() {
        let tls = |toml_text: &str| -> TlsConfig { toml::from_str(toml_text).unwrap() };
        let files = tls("cert = 'c.pem'\nkey = 'k.pem'");
        assert!(matches!(files.source().unwrap(), TlsSource::Files { .. }));
        let store = tls("thumbprint = 'AB'");
        assert_eq!(store.source().unwrap(), TlsSource::Store { store: "My", thumbprint: "AB" });
        let hosting = tls("thumbprint = 'AB'\nstore = 'WebHosting'");
        assert_eq!(hosting.source().unwrap(), TlsSource::Store { store: "WebHosting", thumbprint: "AB" });
        assert!(tls("cert = 'c.pem'\nkey = 'k.pem'\nthumbprint = 'AB'").source().is_err());
        assert!(tls("cert = 'c.pem'").source().is_err());
        assert!(tls("cert = 'c.pem'\nkey = 'k.pem'\nstore = 'My'").source().is_err());
        assert!(tls("").source().is_err());
    }

    #[test]
    fn empty_config_has_sane_defaults() {
        let mut cfg: Config = toml::from_str("").unwrap();
        cfg.normalize();
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.delivery.retry_intervals.len(), 6);
        cfg.validate().unwrap();
    }
}
