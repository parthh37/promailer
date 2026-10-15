//! What the tray shows: the Windows service state combined with the
//! unauthenticated `/health` endpoint of the local management API.

use serde::Deserialize;
use std::time::Duration;

/// Queue length above which the icon turns amber.
pub const QUEUE_WARN: u64 = 1000;
const DEFAULT_URL: &str = "http://127.0.0.1:8025";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    NotInstalled,
    Stopped,
    Starting,
    Stopping,
    Running,
    Paused,
    /// The Service Control Manager could not be queried.
    Unknown,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub hostname: String,
    pub queue: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warning,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub service: Service,
    pub health: Result<Health, String>,
}

impl Snapshot {
    pub fn level(&self) -> Level {
        let healthy = matches!(&self.health, Ok(h) if h.status == "ok");
        let backlog = matches!(&self.health, Ok(Health { queue: Some(q), .. }) if *q > QUEUE_WARN);
        match self.service {
            Service::Running if healthy && !backlog => Level::Ok,
            Service::Running | Service::Starting | Service::Stopping | Service::Paused => Level::Warning,
            Service::Stopped => Level::Down,
            // Running in a console (`promailer run`) rather than as a service.
            Service::NotInstalled | Service::Unknown if healthy => Level::Ok,
            Service::NotInstalled | Service::Unknown => Level::Unknown,
        }
    }

    /// First menu line, e.g. "Running" or "Stopped".
    pub fn headline(&self) -> String {
        let api_down = self.health.is_err();
        match self.service {
            Service::Running if api_down => "Running (management API not reachable)".into(),
            Service::Running => match &self.health {
                Ok(h) if h.status != "ok" => format!("Running ({})", h.status),
                _ => "Running".into(),
            },
            Service::Starting => "Starting…".into(),
            Service::Stopping => "Stopping…".into(),
            Service::Paused => "Paused".into(),
            Service::Stopped => "Stopped".into(),
            Service::NotInstalled if !api_down => "Running (console)".into(),
            Service::NotInstalled => "Service not installed".into(),
            Service::Unknown if !api_down => "Running".into(),
            Service::Unknown => "Status unknown".into(),
        }
    }

    /// Second menu line: queue and host name, when the API answered.
    pub fn detail(&self) -> Option<String> {
        let h = self.health.as_ref().ok()?;
        let mut parts = Vec::new();
        if let Some(q) = h.queue {
            parts.push(match q {
                0 => "Queue empty".to_string(),
                1 => "1 message queued".to_string(),
                n => format!("{n} messages queued"),
            });
        }
        if !h.hostname.is_empty() {
            parts.push(h.hostname.clone());
        }
        if !h.version.is_empty() {
            parts.push(format!("v{}", h.version));
        }
        (!parts.is_empty()).then(|| parts.join(" · "))
    }

    /// Notification-area tooltip (Windows truncates at 127 characters).
    pub fn tooltip(&self) -> String {
        let mut t = format!("Promailer: {}", self.headline());
        if let Some(d) = self.detail() {
            t.push('\n');
            t.push_str(&d);
        }
        t.chars().take(127).collect()
    }

    pub fn can_start(&self) -> bool {
        self.service == Service::Stopped
    }

    pub fn can_stop(&self) -> bool {
        matches!(self.service, Service::Running | Service::Paused)
    }
}

/// The Manager's saved server URL, if it points at this machine; the tray only
/// reports on the local service.
pub fn local_api_url() -> String {
    let saved = manager_settings_path()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_string));
    match saved {
        Some(u) if is_local(&u) => u.trim().trim_end_matches('/').to_string(),
        _ => DEFAULT_URL.into(),
    }
}

fn is_local(url: &str) -> bool {
    let rest = url.trim().split_once("://").map_or(url.trim(), |(_, r)| r);
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit_once(':').filter(|(h, _)| !h.ends_with(':')).map_or(host, |(h, _)| h);
    matches!(host.trim_matches(['[', ']']), "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

fn manager_settings_path() -> Option<std::path::PathBuf> {
    let base = std::env::var_os("APPDATA")?;
    Some(std::path::PathBuf::from(base).join("Promailer").join("manager.json"))
}

pub fn probe_health(base: &str) -> Result<Health, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(2)))
        .timeout_global(Some(Duration::from_secs(4)))
        .build()
        .into();
    let mut resp = agent.get(format!("{base}/health")).call().map_err(|e| e.to_string())?;
    resp.body_mut().read_json::<Health>().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(service: Service, health: Option<(&str, u64)>) -> Snapshot {
        Snapshot {
            service,
            health: health
                .map(|(s, q)| Health {
                    status: s.into(),
                    version: "0.1.0".into(),
                    hostname: "mx".into(),
                    queue: Some(q),
                })
                .ok_or_else(|| "connection refused".into()),
        }
    }

    #[test]
    fn levels() {
        assert_eq!(snap(Service::Running, Some(("ok", 3))).level(), Level::Ok);
        assert_eq!(snap(Service::Running, Some(("ok", QUEUE_WARN + 1))).level(), Level::Warning);
        assert_eq!(snap(Service::Running, Some(("stopping", 0))).level(), Level::Warning);
        assert_eq!(snap(Service::Running, None).level(), Level::Warning);
        assert_eq!(snap(Service::Stopped, None).level(), Level::Down);
        assert_eq!(snap(Service::NotInstalled, Some(("ok", 0))).level(), Level::Ok);
        assert_eq!(snap(Service::NotInstalled, None).level(), Level::Unknown);
    }

    #[test]
    fn text() {
        let s = snap(Service::Running, Some(("ok", 12)));
        assert_eq!(s.headline(), "Running");
        assert_eq!(s.detail().unwrap(), "12 messages queued · mx · v0.1.0");
        assert_eq!(s.tooltip(), "Promailer: Running\n12 messages queued · mx · v0.1.0");
        assert!(s.can_stop() && !s.can_start());
        assert_eq!(snap(Service::Stopped, None).detail(), None);
    }

    #[test]
    fn local_urls() {
        assert!(is_local("http://127.0.0.1:8025"));
        assert!(is_local("localhost:8025/"));
        assert!(is_local("http://[::1]:8025"));
        assert!(!is_local("http://mail.example.com:8025"));
        assert!(!is_local("http://10.0.0.5"));
    }
}
