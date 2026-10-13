//! Blocking client for the Promailer HTTP management API.
//!
//! Every call runs on a background thread (see `task.rs`), never on the UI
//! thread. Response types mirror the server's JSON but only declare the fields
//! the GUI uses, with defaults, so the manager keeps working against older or
//! newer servers.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Large search results and config files are well under this.
const MAX_BODY: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Client {
    base: String,
    key: String,
    agent: ureq::Agent,
    /// DNS checks wait on several upstream lookups.
    slow_agent: ureq::Agent,
}

/// A failed call, with the HTTP status when the server answered.
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: String,
    /// Raw JSON body of an error response (config validation details).
    pub body: Option<serde_json::Value>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .build()
        .into()
}

impl Client {
    pub fn new(base: &str, key: &str) -> Self {
        let mut base = base.trim().trim_end_matches('/').to_string();
        if !base.contains("://") {
            base = format!("http://{base}");
        }
        Self {
            base,
            key: key.trim().to_string(),
            agent: agent(Duration::from_secs(30)),
            slow_agent: agent(Duration::from_secs(120)),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    fn finish<T: DeserializeOwned>(res: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> ApiResult<T> {
        let mut resp = res.map_err(|e| ApiError { status: None, message: describe_transport(&e), body: None })?;
        let status = resp.status().as_u16();
        let text = resp.body_mut().with_config().limit(MAX_BODY).read_to_string().map_err(|e| ApiError {
            status: Some(status),
            message: format!("reading response: {e}"),
            body: None,
        })?;
        if (200..300).contains(&status) {
            return serde_json::from_str(&text).map_err(|e| ApiError {
                status: Some(status),
                message: format!("unexpected response from server: {e}"),
                body: None,
            });
        }
        let body: Option<serde_json::Value> = serde_json::from_str(&text).ok();
        let detail = body.as_ref().and_then(|b| b.get("error")).and_then(|e| e.as_str()).map(str::to_string);
        let message = match (status, detail) {
            (_, Some(d)) => d,
            (401, None) => "invalid or missing API key".into(),
            (403, None) => "access denied (check api.allow and key permissions)".into(),
            (404, None) => "not found (is this a Promailer server of a matching version?)".into(),
            (s, None) => format!("server returned HTTP {s}"),
        };
        Err(ApiError { status: Some(status), message, body })
    }

    fn get<T: DeserializeOwned>(&self, path: &str) -> ApiResult<T> {
        Self::finish(self.agent.get(self.url(path)).header("X-API-Key", &self.key).call())
    }

    fn send<T: DeserializeOwned>(&self, method: &str, path: &str, body: Option<serde_json::Value>) -> ApiResult<T> {
        let url = self.url(path);
        let res = match (method, body) {
            ("POST", Some(b)) => self.agent.post(url).header("X-API-Key", &self.key).send_json(b),
            ("POST", None) => self.agent.post(url).header("X-API-Key", &self.key).send_empty(),
            ("PUT", Some(b)) => self.agent.put(url).header("X-API-Key", &self.key).send_json(b),
            ("DELETE", _) => self.agent.delete(url).header("X-API-Key", &self.key).call(),
            _ => unreachable!("unsupported method {method}"),
        };
        Self::finish(res)
    }

    // ---- endpoints -------------------------------------------------------

    pub fn health(&self) -> ApiResult<Health> {
        Self::finish(self.agent.get(self.url("/health")).call())
    }

    pub fn stats(&self) -> ApiResult<Stats> {
        self.get("/api/v1/stats")
    }

    pub fn stats_history(&self, since: i64) -> ApiResult<StatsHistory> {
        self.get(&format!("/api/v1/stats/history?since={since}"))
    }

    pub fn events(&self, after: u64) -> ApiResult<EventPage> {
        self.get(&format!("/api/v1/events?after={after}&limit=2000"))
    }

    pub fn queue(&self, offset: usize, limit: usize, filter: &str) -> ApiResult<QueuePage> {
        let mut path = format!("/api/v1/queue?offset={offset}&limit={limit}");
        if !filter.trim().is_empty() {
            path.push_str(&format!("&q={}", encode(filter.trim())));
        }
        self.get(&path)
    }

    pub fn queue_headers(&self, id: &str) -> ApiResult<Headers> {
        self.get(&format!("/api/v1/queue/{}/headers", encode(id)))
    }

    pub fn retry(&self, id: &str) -> ApiResult<serde_json::Value> {
        self.send("POST", &format!("/api/v1/queue/{}/retry", encode(id)), None)
    }

    pub fn retry_all(&self) -> ApiResult<serde_json::Value> {
        self.send("POST", "/api/v1/queue/retry", None)
    }

    pub fn delete(&self, id: &str) -> ApiResult<serde_json::Value> {
        self.send("DELETE", &format!("/api/v1/queue/{}", encode(id)), None)
    }

    pub fn search(&self, q: &str, kind: Option<&str>, days: u32, limit: usize) -> ApiResult<SearchResult> {
        let mut path = format!("/api/v1/search?q={}&days={days}&limit={limit}", encode(q.trim()));
        if let Some(k) = kind {
            path.push_str(&format!("&kind={k}"));
        }
        self.get(&path)
    }

    pub fn check(&self, domain: &str, ips: &str) -> ApiResult<CheckReport> {
        let mut path = format!("/api/v1/check/{}", encode(domain.trim()));
        let ips = ips.split([',', ' ']).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(",");
        if !ips.is_empty() {
            path.push_str(&format!("?ip={}", encode(&ips)));
        }
        Self::finish(self.slow_agent.get(self.url(&path)).header("X-API-Key", &self.key).call())
    }

    pub fn config(&self) -> ApiResult<ConfigFile> {
        self.get("/api/v1/config")
    }

    pub fn validate_config(&self, text: &str) -> ApiResult<Validation> {
        self.send("POST", "/api/v1/config/validate", Some(serde_json::json!({ "text": text })))
    }

    pub fn save_config(&self, text: &str, base_sha256: &str) -> ApiResult<SaveResult> {
        self.send("PUT", "/api/v1/config", Some(serde_json::json!({ "text": text, "base_sha256": base_sha256 })))
    }

    pub fn dkim_keys(&self) -> ApiResult<DkimKeys> {
        Self::finish(self.slow_agent.get(self.url("/api/v1/dkim")).header("X-API-Key", &self.key).call())
    }

    /// Generates the key pair on the server; only the public DNS record comes back.
    pub fn dkim_create(&self, req: &NewDkimKey) -> ApiResult<CreatedDkimKey> {
        let body =
            serde_json::to_value(req).map_err(|e| ApiError { status: None, message: e.to_string(), body: None })?;
        Self::finish(self.slow_agent.post(self.url("/api/v1/dkim")).header("X-API-Key", &self.key).send_json(body))
    }

    pub fn dkim_delete(&self, domain: &str, selector: &str) -> ApiResult<serde_json::Value> {
        self.send("DELETE", &format!("/api/v1/dkim/{}/{}", encode(domain), encode(selector)), None)
    }
}

fn describe_transport(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::ConnectionRefused => {
            "connection refused - is the Promailer service running and [api] enabled?".into()
        }
        ureq::Error::Timeout(_) => "the server did not respond in time".into(),
        other => other.to_string(),
    }
}

/// Percent-encode a query or path component.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    #[serde(default)]
    pub hostname: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Stats {
    pub uptime_seconds: u64,
    pub connections_active: usize,
    pub connections_total: u64,
    pub messages_received: u64,
    pub messages_rejected: u64,
    pub recipients_delivered: u64,
    pub recipients_deferred: u64,
    pub recipients_bounced: u64,
    pub ndr_generated: u64,
    pub badmail: u64,
    pub pickup_processed: u64,
    pub api_messages: u64,
    pub queue_size: usize,
    pub deliveries_in_flight: usize,
}

/// Cumulative counters at time `t`; rates come from differences between samples.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct Sample {
    pub t: i64,
    pub received: u64,
    pub delivered: u64,
    pub deferred: u64,
    pub bounced: u64,
    pub queue: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatsHistory {
    pub interval_seconds: u64,
    pub samples: Vec<Sample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Queued,
    Sent,
    Deferred,
    Bounced,
    Expired,
    Deleted,
    Ndr,
    /// Kinds added by newer servers.
    #[serde(other)]
    Other,
}

impl EventKind {
    pub const ALL: [EventKind; 7] = [
        EventKind::Queued,
        EventKind::Sent,
        EventKind::Deferred,
        EventKind::Bounced,
        EventKind::Expired,
        EventKind::Deleted,
        EventKind::Ndr,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Queued => "queued",
            EventKind::Sent => "sent",
            EventKind::Deferred => "deferred",
            EventKind::Bounced => "bounced",
            EventKind::Expired => "expired",
            EventKind::Deleted => "deleted",
            EventKind::Ndr => "ndr",
            EventKind::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    pub time: chrono::DateTime<chrono::Utc>,
    pub id: String,
    pub kind: EventKind,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub relay: Option<String>,
    #[serde(default)]
    pub attempt: Option<u32>,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Event {
    /// Case-insensitive match over all text fields. `needle` must be lowercase.
    pub fn matches(&self, needle: &str) -> bool {
        if needle.is_empty() {
            return true;
        }
        let hit = |s: &str| s.to_lowercase().contains(needle);
        hit(&self.id)
            || hit(&self.from)
            || self.to.as_deref().is_some_and(hit)
            || self.subject.as_deref().is_some_and(hit)
            || self.relay.as_deref().is_some_and(hit)
            || self.detail.as_deref().is_some_and(hit)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventPage {
    pub events: Vec<Event>,
    pub last_seq: u64,
    #[serde(default)]
    pub gap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RcptStatus {
    Pending,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Recipient {
    pub address: String,
    pub status: RcptStatus,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub last_response: Option<String>,
    #[serde(default)]
    pub remote_host: Option<String>,
    #[serde(default)]
    pub updated: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueueEntry {
    pub id: String,
    pub created: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub sender: String,
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub source: serde_json::Value,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub dkim: Vec<String>,
    #[serde(default)]
    pub attempts: u32,
    pub next_attempt: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub last_attempt: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub subject: Option<String>,
}

impl QueueEntry {
    pub fn pending(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients.iter().filter(|r| r.status == RcptStatus::Pending)
    }

    /// Most informative recent error: the last response of a still-pending recipient.
    pub fn last_error(&self) -> Option<&str> {
        self.pending().filter_map(|r| r.last_response.as_deref()).next()
    }

    pub fn source_label(&self) -> String {
        let s = &self.source;
        let field = |k: &str| s.get(k).and_then(|v| v.as_str()).unwrap_or("");
        match field("type") {
            "smtp" => match s.get("user").and_then(|v| v.as_str()) {
                Some(u) => format!("SMTP {} ({u})", field("ip")),
                None => format!("SMTP {}", field("ip")),
            },
            "pickup" => format!("Pickup {}", field("file")),
            "api" => format!("API key '{}'", field("key")),
            "ndr" => format!("NDR for {}", field("original")),
            other => other.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct QueuePage {
    pub total: usize,
    pub offset: usize,
    pub items: Vec<QueueEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Headers {
    pub headers: String,
    pub size: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchResult {
    pub queued: Vec<QueueEntry>,
    pub history: Vec<Event>,
    #[serde(default = "yes")]
    pub history_enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckItem {
    pub check: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CheckReport {
    pub domain: String,
    pub ips: Vec<String>,
    pub items: Vec<CheckItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigFile {
    pub path: String,
    pub sha256: String,
    pub text: String,
    /// Parsed settings with defaults filled in; None if the file is invalid.
    #[serde(default)]
    pub effective: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigIssue {
    pub message: String,
    #[serde(default)]
    pub line: Option<usize>,
    #[serde(default)]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Validation {
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<ConfigIssue>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveResult {
    pub reloaded: bool,
    #[serde(default)]
    pub reload_error: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub backup: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DkimKey {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub private_key: String,
    #[serde(default)]
    pub include_subdomains: bool,
    pub dns_name: String,
    #[serde(default)]
    pub dns_value: Option<String>,
    pub dns_status: CheckStatus,
    #[serde(default)]
    pub dns_detail: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DkimKeys {
    pub keys: Vec<DkimKey>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewDkimKey {
    pub domain: String,
    pub selector: String,
    pub algorithm: String,
    pub bits: usize,
    pub include_subdomains: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatedDkimKey {
    pub domain: String,
    pub selector: String,
    pub dns_name: String,
    pub dns_value: String,
    pub private_key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encoding() {
        assert_eq!(encode("bob@example.com"), "bob%40example.com");
        assert_eq!(encode("a b&c"), "a%20b%26c");
    }

    #[test]
    fn unknown_event_kind_tolerated() {
        let e: Event =
            serde_json::from_str(r#"{"time":"2026-01-01T00:00:00Z","id":"x","kind":"quarantined"}"#).unwrap();
        assert_eq!(e.kind, EventKind::Other);
    }

    #[test]
    fn base_url_normalised() {
        assert_eq!(Client::new("127.0.0.1:8025/", "k").base(), "http://127.0.0.1:8025");
        assert_eq!(Client::new("https://mx:8443", "k").base(), "https://mx:8443");
    }
}
