//! Turning crash reports into GitHub issues.
//!
//! Without a token, [`new_issue_url`] builds a "new issue" page with the
//! report filled in; the administrator reviews it and clicks Submit. With a
//! token (configured by the operator, never shipped in the binary), [`upload`]
//! files it through the REST API, adding a comment instead when an open issue
//! with the same fingerprint already exists.

use crate::CrashReport;

/// Where reports go unless the configuration says otherwise.
pub const DEFAULT_REPO: &str = "parthh37/promailer";
/// Label put on crash issues.
pub const LABEL: &str = "crash";
/// GitHub rejects longer URLs; the body is shortened to fit.
const MAX_URL: usize = 7500;

/// Percent-encode for a URL query value (RFC 3986 unreserved characters are kept).
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// `owner/name` with GitHub's allowed characters only.
pub fn valid_repo(repo: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    matches!(repo.split_once('/'), Some((o, n)) if ok(o) && ok(n))
}

pub fn issue_title(r: &CrashReport) -> String {
    format!("[crash] {} {}: {}", r.app, r.version, r.summary())
}

/// Text searched for to find an existing issue for the same bug.
fn fingerprint_line(r: &CrashReport) -> String {
    format!("Crash fingerprint: `{}`", r.fingerprint)
}

/// Markdown body. `backtrace_lines` caps the backtrace (0 omits it).
pub fn issue_body(r: &CrashReport, backtrace_lines: usize) -> String {
    let mut b = String::new();
    b.push_str("Promailer hit an internal error (panic). This report was generated automatically; ");
    b.push_str("email addresses, IP addresses, host and account names were removed.\n\n");
    b.push_str("| | |\n|---|---|\n");
    b.push_str(&format!("| Application | `{}` {} |\n", r.app, r.version));
    b.push_str(&format!("| Platform | {} {} |\n", r.os, r.arch));
    b.push_str(&format!("| Time | {} |\n", r.time.format("%Y-%m-%d %H:%M:%S UTC")));
    b.push_str(&format!("| Thread | `{}` |\n", r.thread.replace('|', "\\|")));
    b.push_str(&format!("| Location | `{}` |\n\n", r.location));
    b.push_str("**Message**\n\n```text\n");
    b.push_str(r.message.trim());
    b.push_str("\n```\n\n");
    let bt: Vec<&str> = r.backtrace.lines().take(backtrace_lines).collect();
    if !bt.is_empty() {
        b.push_str("<details><summary>Backtrace</summary>\n\n```text\n");
        b.push_str(&bt.join("\n"));
        b.push_str("\n```\n</details>\n\n");
    }
    b.push_str("**What were you doing when this happened?**\n\n<!-- optional: steps, configuration involved -->\n\n");
    b.push_str(&fingerprint_line(r));
    b.push('\n');
    b
}

/// A github.com "new issue" page with the report filled in.
pub fn new_issue_url(repo: &str, r: &CrashReport) -> String {
    let base = format!("https://github.com/{repo}/issues/new?labels={LABEL}&title={}&body=", encode(&issue_title(r)));
    // Drop backtrace lines until the URL fits.
    let mut lines = r.backtrace.lines().count();
    loop {
        let url = format!("{base}{}", encode(&issue_body(r, lines)));
        if url.len() <= MAX_URL || lines == 0 {
            return url;
        }
        lines = lines.saturating_sub(5);
    }
}

/// A blank bug report with version and platform filled in ("Report a problem").
pub fn report_problem_url(repo: &str, app: &str) -> String {
    let body = format!(
        "**What happened?**\n\n\n**What did you expect?**\n\n\n**Steps to reproduce**\n\n1. \n\n\
         | | |\n|---|---|\n| Application | `{app}` {} |\n| Platform | {} {} |\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    format!("https://github.com/{repo}/issues/new?labels=bug&body={}", encode(&body))
}

// ---------------------------------------------------------------------------
// REST API (service only)
// ---------------------------------------------------------------------------

#[cfg(feature = "upload")]
mod api {
    use super::*;
    use serde_json::{json, Value};
    use std::time::Duration;

    const API: &str = "https://api.github.com";

    fn agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into()
    }

    fn call(req: Result<ureq::http::Response<ureq::Body>, ureq::Error>, what: &str) -> Result<Value, String> {
        let mut resp = req.map_err(|e| format!("{what}: {e}"))?;
        let status = resp.status().as_u16();
        let body: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            return Ok(body);
        }
        let detail = body.get("message").and_then(Value::as_str).unwrap_or("no details");
        Err(match status {
            401 => format!("{what}: GitHub rejected the token (401: {detail})"),
            403 | 404 => format!("{what}: the token cannot write issues in this repository ({status}: {detail})"),
            s => format!("{what}: GitHub returned HTTP {s}: {detail}"),
        })
    }

    /// File `r` in `repo`, or comment on the open issue that has its fingerprint.
    /// Returns the issue's web URL.
    pub fn upload(repo: &str, token: &str, r: &CrashReport) -> Result<String, String> {
        if !valid_repo(repo) {
            return Err(format!("invalid GitHub repository '{repo}' (expected owner/name)"));
        }
        let agent = agent();
        let auth = format!("Bearer {}", token.trim());
        let ua = format!("promailer/{}", env!("CARGO_PKG_VERSION"));
        let get = |url: &str| {
            agent
                .get(url)
                .header("Authorization", &auth)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", &ua)
        };
        let post = |url: &str| {
            agent
                .post(url)
                .header("Authorization", &auth)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .header("User-Agent", &ua)
        };

        let q = format!("repo:{repo} is:issue is:open in:body \"{}\"", r.fingerprint);
        let found = call(get(&format!("{API}/search/issues")).query("q", &q).query("per_page", "1").call(), "search")?;
        let existing = found.get("items").and_then(|i| i.get(0));
        if let Some(issue) = existing {
            let number = issue.get("number").and_then(Value::as_u64).ok_or("search: malformed response")?;
            let url = issue.get("html_url").and_then(Value::as_str).unwrap_or_default().to_string();
            let comment = format!(
                "Seen again: `{}` {} on {} {} at {} (thread `{}`).\n\n```text\n{}\n```",
                r.app,
                r.version,
                r.os,
                r.arch,
                r.time.format("%Y-%m-%d %H:%M:%S UTC"),
                r.thread,
                r.message.trim()
            );
            call(
                post(&format!("{API}/repos/{repo}/issues/{number}/comments")).send_json(json!({ "body": comment })),
                "comment",
            )?;
            return Ok(url);
        }
        let created = call(
            post(&format!("{API}/repos/{repo}/issues")).send_json(json!({
                "title": issue_title(r),
                "body": issue_body(r, usize::MAX),
                "labels": [LABEL],
            })),
            "create issue",
        )?;
        created
            .get("html_url")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "create issue: malformed response".into())
    }
}

#[cfg(feature = "upload")]
pub use api::upload;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
        assert!(valid_repo("parthh37/promailer"));
        assert!(!valid_repo("parthh37"));
        assert!(!valid_repo("a/b/c"));
        assert!(!valid_repo("a/b?x=1"));
    }

    #[test]
    fn issue_url_fits_and_carries_fingerprint() {
        let bt: String = (0..400).map(|i| format!("  {i}: promailer::some::long::function::name::here\n")).collect();
        let r = CrashReport::new("promailer", "main", "boom", "src/x.rs:1:1", &bt, &[]);
        let url = new_issue_url(DEFAULT_REPO, &r);
        assert!(url.len() <= MAX_URL);
        assert!(url.starts_with("https://github.com/parthh37/promailer/issues/new?labels=crash&title=%5Bcrash%5D"));
        assert!(url.contains(&r.fingerprint));
        assert!(issue_body(&r, 0).contains(&format!("Crash fingerprint: `{}`", r.fingerprint)));
    }
}
