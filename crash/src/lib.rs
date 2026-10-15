//! Crash reports shared by the Promailer service, Manager and tray.
//!
//! A panic hook turns every panic into a [`CrashReport`]: version, platform,
//! panic message and location, scrubbed of addresses and account names, saved
//! as one JSON file in a crash directory. The hook never touches the network.
//! Reports are filed later, either automatically by the service (see
//! [`github::upload`], when an operator configured a token) or by an
//! administrator from a pre-filled GitHub issue page ([`github::new_issue_url`]).

pub mod github;
mod redact;

pub use redact::redact;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Reports kept per directory; the oldest are pruned beyond this.
const KEEP: usize = 50;
/// Reports written per process, so a panic in a hot loop cannot fill the disk.
const MAX_PER_PROCESS: usize = 10;
/// Backtrace lines kept in a report.
const BACKTRACE_LINES: usize = 40;
/// Suffix of reports that have been filed on GitHub (kept for de-duplication).
const REPORTED: &str = ".reported.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    /// File stem; also the API identifier.
    pub id: String,
    /// `promailer`, `promailer-manager` or `promailer-tray`.
    pub app: String,
    pub version: String,
    pub os: String,
    pub arch: String,
    pub time: DateTime<Utc>,
    pub thread: String,
    /// Panic message, scrubbed.
    pub message: String,
    /// `src/file.rs:line:column` of the panic.
    pub location: String,
    /// Scrubbed and trimmed; often unresolved in release builds (no symbols).
    #[serde(default)]
    pub backtrace: String,
    /// Stable identifier of "the same bug", used to de-duplicate issues.
    pub fingerprint: String,
    /// Set once the report was filed on GitHub.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_url: Option<String>,
}

/// What makes two crashes "the same bug" for de-duplication: reports with an
/// equal fingerprint share a single GitHub issue (repeats become comments).
pub fn fingerprint(app: &str, location: &str, message: &str) -> String {
    // TODO(you): choose the de-duplication key. Inputs are already scrubbed.
    // - `location` is "src/queue/mod.rs:432:9": line numbers shift between releases.
    // - `message` can carry variable data (counts, ids, "<ip>" placeholders).
    // Too specific: one bug opens many issues. Too broad: different bugs share one.
    // Keep the result 12 lowercase hex characters (the issue search relies on it).
    let key = format!("{app}|{location}|{message}");
    let digest = Sha256::digest(key.as_bytes());
    digest[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// Values that identify this machine or account and must never be reported.
fn local_secrets() -> Vec<String> {
    ["COMPUTERNAME", "USERNAME", "USERDOMAIN", "HOSTNAME", "USER"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .filter(|v| !v.trim().is_empty())
        // Built-in accounts identify nobody, and scrubbing them would mangle ordinary words.
        .filter(|v| !BUILTIN_ACCOUNTS.iter().any(|b| v.trim().eq_ignore_ascii_case(b)))
        .collect()
}

const BUILTIN_ACCOUNTS: [&str; 7] =
    ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "NT AUTHORITY", "WORKGROUP", "Administrator", "root"];

fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "(non-string panic payload)".into())
}

/// Keep the frames worth reading: drop the panic machinery at the top and cap the length.
fn trim_backtrace(bt: &str) -> String {
    let lines: Vec<&str> = bt.lines().collect();
    let start = lines
        .iter()
        .position(|l| {
            let l = l.trim();
            !(l.is_empty()
                || l.contains("std::panicking")
                || l.contains("core::panicking")
                || l.contains("std::backtrace")
                || l.contains("rust_begin_unwind")
                || l.contains("promailer_crash::")
                || l.starts_with("at /rustc/"))
        })
        .unwrap_or(0);
    lines[start..].iter().take(BACKTRACE_LINES).copied().collect::<Vec<_>>().join("\n")
}

impl CrashReport {
    /// Build a report from panic data. `extra_secrets` (e.g. the server host name)
    /// are scrubbed along with the machine and account names.
    pub fn new(
        app: &str,
        thread: &str,
        message: &str,
        location: &str,
        backtrace: &str,
        extra_secrets: &[&str],
    ) -> Self {
        let owned = local_secrets();
        let secrets: Vec<&str> = owned.iter().map(String::as_str).chain(extra_secrets.iter().copied()).collect();
        let message = redact(message, &secrets);
        let location = redact(location, &secrets);
        let time = Utc::now();
        let fingerprint = fingerprint(app, &location, &message);
        Self {
            id: format!("{app}-{}-{}", time.format("%Y%m%dT%H%M%S%3f"), std::process::id()),
            app: app.into(),
            version: env!("CARGO_PKG_VERSION").into(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            time,
            thread: redact(thread, &secrets),
            backtrace: redact(&trim_backtrace(backtrace), &secrets),
            message,
            location,
            fingerprint,
            issue_url: None,
        }
    }

    fn from_panic(app: &str, info: &std::panic::PanicHookInfo<'_>, extra_secrets: &[&str]) -> Self {
        let location = info.location().map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_default();
        let thread = std::thread::current();
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();
        Self::new(app, thread.name().unwrap_or("unnamed"), &panic_message(info), &location, &backtrace, extra_secrets)
    }

    /// First line of the message, shortened for titles and lists.
    pub fn summary(&self) -> String {
        let line = self.message.lines().next().unwrap_or("").trim();
        if line.chars().count() > 90 {
            format!("{}…", line.chars().take(89).collect::<String>())
        } else {
            line.to_string()
        }
    }

    pub fn is_reported(&self) -> bool {
        self.issue_url.is_some()
    }
}

// ---------------------------------------------------------------------------
// Panic hook
// ---------------------------------------------------------------------------

/// Called after a report was built, with the path it was saved to (if saving worked).
pub type OnCrash = Box<dyn Fn(&CrashReport, Option<&Path>) + Send + Sync>;

static SEEN: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Install a panic hook that saves a report for each distinct panic to `dir`,
/// then runs the previously installed hook (stderr message, etc.).
pub fn install(app: &'static str, dir: PathBuf) {
    install_with(app, dir, Vec::new(), None);
}

/// Like [`install`], with extra values to scrub and a callback (the service logs
/// the crash to the Event Log through it).
pub fn install_with(app: &'static str, dir: PathBuf, extra_secrets: Vec<String>, on_crash: Option<OnCrash>) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let secrets: Vec<&str> = extra_secrets.iter().map(String::as_str).collect();
        let report = CrashReport::from_panic(app, info, &secrets);
        let first = {
            let mut seen = SEEN.lock().unwrap_or_else(|e| e.into_inner());
            let seen = seen.get_or_insert_with(HashSet::new);
            seen.len() < MAX_PER_PROCESS && seen.insert(report.fingerprint.clone())
        };
        // Repeats of a bug already captured by this process are not saved again.
        let saved = if first { save(&dir, &report).ok() } else { None };
        if let Some(cb) = &on_crash {
            cb(&report, saved.as_deref());
        }
        previous(info);
    }));
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// `id` as used in file names and URLs: rejects anything that could escape the directory.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Save atomically (temp file + rename) and prune old reports. Returns the path.
pub fn save(dir: &Path, report: &CrashReport) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let name = if report.is_reported() { format!("{}{REPORTED}", report.id) } else { format!("{}.json", report.id) };
    let path = dir.join(name);
    let tmp = dir.join(format!("{}.tmp", report.id));
    let json = serde_json::to_vec_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    prune(dir);
    Ok(path)
}

/// All reports in `dir`, newest first. Unreadable files are skipped.
pub fn load_all(dir: &Path) -> Vec<CrashReport> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut reports: Vec<CrashReport> = entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| std::fs::read(e.path()).ok())
        .filter_map(|b| serde_json::from_slice(&b).ok())
        .collect();
    reports.sort_by_key(|r| std::cmp::Reverse(r.time));
    reports
}

/// Reports not yet filed on GitHub, newest first.
pub fn pending(dir: &Path) -> Vec<CrashReport> {
    load_all(dir).into_iter().filter(|r| !r.is_reported()).collect()
}

/// Record that a report was filed: it stops being pending but keeps its fingerprint on disk.
pub fn mark_reported(dir: &Path, report: &CrashReport, issue_url: &str) -> std::io::Result<()> {
    let mut r = report.clone();
    r.issue_url = Some(issue_url.to_string());
    save(dir, &r)?;
    let _ = std::fs::remove_file(dir.join(format!("{}.json", report.id)));
    Ok(())
}

/// Delete a report (pending or filed).
pub fn dismiss(dir: &Path, id: &str) -> std::io::Result<bool> {
    if !valid_id(id) {
        return Ok(false);
    }
    let mut removed = false;
    for name in [format!("{id}.json"), format!("{id}{REPORTED}")] {
        match std::fs::remove_file(dir.join(name)) {
            Ok(()) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

fn prune(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    if files.len() <= KEEP {
        return;
    }
    files.sort();
    for (_, p) in &files[..files.len() - KEEP] {
        let _ = std::fs::remove_file(p);
    }
}

/// Per-user crash directory of the desktop apps (Manager and tray share it):
/// `%LOCALAPPDATA%\Promailer\crashes`.
pub fn user_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state")))
    }?;
    Some(base.join("Promailer").join("crashes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(msg: &str) -> CrashReport {
        CrashReport::new("promailer", "main", msg, "src/queue/mod.rs:10:5", "", &["mail.example.com"])
    }

    #[test]
    fn report_is_scrubbed() {
        let r = sample("delivery to bob@example.org via mail.example.com (198.51.100.4) failed");
        assert_eq!(r.message, "delivery to <email> via <redacted> (<ip>) failed");
        assert_eq!(r.fingerprint.len(), 12);
    }

    #[test]
    fn save_list_report_dismiss() {
        let dir = tempfile::tempdir().unwrap();
        let a = sample("first");
        save(dir.path(), &a).unwrap();
        assert_eq!(pending(dir.path()).len(), 1);

        mark_reported(dir.path(), &a, "https://github.com/o/r/issues/1").unwrap();
        assert!(pending(dir.path()).is_empty());
        let all = load_all(dir.path());
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].issue_url.as_deref(), Some("https://github.com/o/r/issues/1"));

        assert!(dismiss(dir.path(), &a.id).unwrap());
        assert!(load_all(dir.path()).is_empty());
        assert!(!dismiss(dir.path(), "../x").unwrap());
    }

    #[test]
    fn backtrace_skips_panic_machinery() {
        let bt = "   0: std::backtrace::Backtrace::force_capture\n   1: std::panicking::begin_panic\n   2: promailer::queue::deliver\n             at ./src/queue/mod.rs:10:5\n";
        assert!(trim_backtrace(bt).starts_with("   2: promailer::queue::deliver"));
    }
}
