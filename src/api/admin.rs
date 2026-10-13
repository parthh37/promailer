//! Administration endpoints: configuration editor and DKIM key management.
//!
//! Every change goes through [`apply_text`]: validate exactly as a reload
//! would, keep a timestamped backup, replace the file atomically, hot-reload.

use super::{authorize, bad, parse_json, ApiError, ApiResult};
use crate::app::App;
use crate::auth::sha256_hex;
use crate::config::{ApiPermission, Config, ConfigError, DkimAlgorithm};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub(super) struct ConfigIssue {
    message: String,
    /// 1-based position of a syntax error, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<usize>,
}

#[derive(Serialize)]
pub(super) struct Validation {
    valid: bool,
    errors: Vec<ConfigIssue>,
    warnings: Vec<String>,
}

/// 1-based (line, column) of a byte offset.
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let mut end = offset.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let before = &text[..end];
    let line = before.matches('\n').count() + 1;
    let col = before.rsplit('\n').next().map(|l| l.chars().count()).unwrap_or(0) + 1;
    (line, col)
}

/// Full validation, exactly as a reload would do it, without applying anything.
fn validate_text(app: &App, text: &str) -> (Option<Config>, Validation) {
    let fail = |e: ConfigIssue| (None, Validation { valid: false, errors: vec![e], warnings: vec![] });
    let issue = |message: String| ConfigIssue { message, line: None, column: None };
    let cfg = match Config::parse(text, &app.config_path) {
        Ok(c) => c,
        Err(ConfigError::Syntax(e)) => {
            let (line, column) = e.span().map(|s| line_col(text, s.start)).unzip();
            return fail(ConfigIssue { message: e.message().trim().to_string(), line, column });
        }
        Err(ConfigError::Invalid(e)) => return fail(issue(format!("{e:#}"))),
    };
    if let Err(e) = crate::app::deep_validate(&cfg) {
        return fail(issue(format!("{e:#}")));
    }
    let mut warnings = cfg.warnings();
    warnings.extend(crate::app::restart_required(&app.cfg(), &cfg));
    (Some(cfg), Validation { valid: true, errors: vec![], warnings })
}

fn read_current(app: &App) -> ApiResult<String> {
    std::fs::read_to_string(&app.config_path)
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("reading config: {e}")))
}

/// Outcome of a successful save.
#[derive(Serialize)]
pub(super) struct Applied {
    saved: bool,
    reloaded: bool,
    reload_error: Option<String>,
    warnings: Vec<String>,
    backup: String,
    sha256: String,
}

pub(super) enum ApplyError {
    Invalid(Validation),
    Api(ApiError),
}

impl IntoResponse for ApplyError {
    fn into_response(self) -> Response {
        match self {
            ApplyError::Invalid(v) => (StatusCode::UNPROCESSABLE_ENTITY, Json(v)).into_response(),
            ApplyError::Api(e) => e.into_response(),
        }
    }
}

impl From<ApiError> for ApplyError {
    fn from(e: ApiError) -> Self {
        ApplyError::Api(e)
    }
}

/// Validate `text`, back up `current`, write atomically and reload.
async fn apply_text(app: &Arc<App>, current: String, text: String, who: &str) -> Result<Applied, ApplyError> {
    let (cfg, validation) = validate_text(app, &text);
    if cfg.is_none() {
        return Err(ApplyError::Invalid(validation));
    }
    let path = app.config_path.clone();
    let sha256 = sha256_hex(text.as_bytes());
    let backup = tokio::task::spawn_blocking(move || save_config(&path, &current, &text))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("saving config: {e:#}")))?;
    info!(key = %who, backup = %backup.display(), "configuration saved via API");
    let (reloaded, reload_error, mut warnings) = match app.reload() {
        Ok(w) => (true, None, w),
        Err(e) => (false, Some(format!("{e:#}")), vec![]),
    };
    for w in validation.warnings {
        if !warnings.contains(&w) {
            warnings.push(w);
        }
    }
    Ok(Applied { saved: true, reloaded, reload_error, warnings, backup: backup.display().to_string(), sha256 })
}

/// Keep a timestamped copy of the previous file (newest 20), then replace atomically.
fn save_config(path: &std::path::Path, previous: &str, text: &str) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    use std::io::Write;
    const KEEP_BACKUPS: usize = 20;
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("promailer");
    let backups = dir.join("config-backups");
    std::fs::create_dir_all(&backups).with_context(|| format!("creating {}", backups.display()))?;
    let backup = backups.join(format!("{stem}-{}.toml", chrono::Utc::now().format("%Y%m%d-%H%M%S%.3f")));
    std::fs::write(&backup, previous).with_context(|| format!("writing {}", backup.display()))?;
    let mut old: Vec<_> = std::fs::read_dir(&backups)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(stem) && n.ends_with(".toml")))
        .collect();
    old.sort();
    for p in old.iter().take(old.len().saturating_sub(KEEP_BACKUPS)) {
        let _ = std::fs::remove_file(p);
    }

    let tmp = dir.join(format!(".{stem}.{}.tmp", ulid::Ulid::new()));
    {
        let mut f = std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    if let Err(e) = crate::queue::store::rename_retry(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", path.display()));
    }
    Ok(backup)
}

// ---------------------------------------------------------------------------
// Configuration editor
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigText {
    text: String,
    /// SHA-256 of the file as loaded by the editor; the save is rejected if the
    /// file changed on disk since (another administrator, a text editor, ...).
    #[serde(default)]
    base_sha256: Option<String>,
}

pub(super) async fn config_get(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let text = read_current(&app)?;
    // Effective settings (defaults filled in) for form-based editors; null if
    // the file on disk is currently invalid.
    let effective = Config::parse(&text, &app.config_path).ok().and_then(|c| serde_json::to_value(c).ok());
    Ok(Json(json!({
        "path": app.config_path.display().to_string(),
        "sha256": sha256_hex(text.as_bytes()),
        "text": text,
        "effective": effective,
    })))
}

pub(super) async fn config_validate(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let req: ConfigText = parse_json(&body)?;
    Ok(Json(validate_text(&app, &req.text).1))
}

pub(super) async fn config_put(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Applied>, ApplyError> {
    let key = authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let req: ConfigText = parse_json(&body)?;
    let current = read_current(&app)?;
    if let Some(base) = &req.base_sha256 {
        if !base.eq_ignore_ascii_case(&sha256_hex(current.as_bytes())) {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "the configuration file was changed by someone else since you opened it; reload it and re-apply your edits".into(),
            )
            .into());
        }
    }
    Ok(Json(apply_text(&app, current, req.text, &key.name).await?))
}

// ---------------------------------------------------------------------------
// DKIM keys
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct DkimKeyInfo {
    domain: String,
    selector: String,
    algorithm: DkimAlgorithm,
    private_key: String,
    include_subdomains: bool,
    /// TXT record to publish.
    dns_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_value: Option<String>,
    /// pass | fail | warn - whether the published record matches.
    dns_status: crate::checks::Status,
    dns_detail: String,
}

pub(super) async fn dkim_list(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let cfg = app.cfg();
    let futs = cfg.dkim.iter().map(|c| {
        let app = app.clone();
        async move {
            let dns_name = crate::dkim::dns_name(&c.domain, &c.selector);
            let c2 = c.clone();
            let derived = tokio::task::spawn_blocking(move || {
                Ok::<_, anyhow::Error>((crate::dkim::dns_record(&c2)?.1, crate::dkim::public_key_bytes(&c2)?))
            })
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
            let (dns_value, dns_status, dns_detail) = match derived {
                Ok((value, public)) => {
                    let (s, d) = crate::checks::dkim_record_status(&app.dns, &dns_name, &public).await;
                    (Some(value), s, d)
                }
                Err(e) => (None, crate::checks::Status::Fail, format!("cannot read key: {e:#}")),
            };
            DkimKeyInfo {
                domain: c.domain.clone(),
                selector: c.selector.clone(),
                algorithm: c.algorithm,
                private_key: c.private_key.display().to_string(),
                include_subdomains: c.include_subdomains,
                dns_name,
                dns_value,
                dns_status,
                dns_detail,
            }
        }
    });
    let keys = futures::future::join_all(futs).await;
    Ok(Json(json!({ "keys": keys })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDkimKey {
    domain: String,
    selector: String,
    #[serde(default = "default_alg")]
    algorithm: DkimAlgorithm,
    #[serde(default = "default_bits")]
    bits: usize,
    #[serde(default)]
    include_subdomains: bool,
}
fn default_alg() -> DkimAlgorithm {
    DkimAlgorithm::RsaSha256
}
fn default_bits() -> usize {
    2048
}

/// DNS-safe label sequence: letters, digits, hyphens, dots; no empty labels.
fn valid_dns_name(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn alg_name(a: DkimAlgorithm) -> &'static str {
    match a {
        DkimAlgorithm::RsaSha256 => "rsa-sha256",
        DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
    }
}

/// Append a `[[dkim]]` table, preserving the rest of the file.
fn add_dkim_entry(text: &str, k: &NewDkimKey, key_path: &str) -> Result<String, String> {
    use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};
    let mut doc: DocumentMut = text.parse().map_err(|e| format!("current configuration has a syntax error: {e}"))?;
    let item = doc.entry("dkim").or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
    let arr = item
        .as_array_of_tables_mut()
        .ok_or("the configuration defines 'dkim' in an unexpected form; add the key in the Advanced editor")?;
    let mut t = Table::new();
    t["domain"] = value(&k.domain);
    t["selector"] = value(&k.selector);
    t["private_key"] = value(key_path);
    t["algorithm"] = value(alg_name(k.algorithm));
    if k.include_subdomains {
        t["include_subdomains"] = value(true);
    }
    arr.push(t);
    Ok(doc.to_string())
}

/// Remove the `[[dkim]]` table for (domain, selector).
fn remove_dkim_entry(text: &str, domain: &str, selector: &str) -> Result<String, String> {
    use toml_edit::DocumentMut;
    let mut doc: DocumentMut = text.parse().map_err(|e| format!("current configuration has a syntax error: {e}"))?;
    let arr = doc.get_mut("dkim").and_then(|i| i.as_array_of_tables_mut()).ok_or("no DKIM keys are configured")?;
    let field = |t: &toml_edit::Table, k: &str| t.get(k).and_then(|v| v.as_str()).map(|s| s.trim().to_lowercase());
    let idx = arr
        .iter()
        .position(|t| {
            field(t, "domain").as_deref() == Some(domain) && field(t, "selector").as_deref() == Some(selector)
        })
        .ok_or_else(|| format!("no DKIM key for {domain} with selector {selector}"))?;
    arr.remove(idx);
    if arr.is_empty() {
        doc.remove("dkim");
    }
    Ok(doc.to_string())
}

pub(super) async fn dkim_create(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApplyError> {
    let key = authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let mut req: NewDkimKey = parse_json(&body)?;
    req.domain = req.domain.trim().trim_end_matches('.').to_lowercase();
    req.selector = req.selector.trim().to_lowercase();
    if !valid_dns_name(&req.domain, 253) || !req.domain.contains('.') {
        return Err(bad(format!("'{}' is not a valid domain name", req.domain)).into());
    }
    if !valid_dns_name(&req.selector, 63) {
        return Err(bad("selector may only contain letters, digits, hyphens and dots").into());
    }
    if app.cfg().dkim.iter().any(|d| d.domain == req.domain && d.selector == req.selector) {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!(
                "a key for {} with selector {} already exists; choose a new selector to rotate keys",
                req.domain, req.selector
            ),
        )
        .into());
    }

    // The private key is created on the server and never leaves it.
    let dir = app.config_path.parent().unwrap_or(std::path::Path::new(".")).join("dkim");
    let file = format!("{}.{}.pem", req.domain, req.selector);
    let path = dir.join(&file);
    let (domain, selector, alg, bits) = (req.domain.clone(), req.selector.clone(), req.algorithm, req.bits);
    let path2 = path.clone();
    let generated = tokio::task::spawn_blocking(move || -> anyhow::Result<crate::dkim::GeneratedKey> {
        use anyhow::Context;
        use std::io::Write;
        let g = crate::dkim::generate(&domain, &selector, alg, bits)?;
        std::fs::create_dir_all(path2.parent().expect("key path has a parent"))?;
        // create_new: never overwrite a live key.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path2)
            .with_context(|| format!("{} already exists; choose another selector", path2.display()))?;
        f.write_all(g.private_pem.as_bytes())?;
        f.sync_all()?;
        Ok(g)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| bad(format!("{e:#}")))?;

    let current = read_current(&app)?;
    let text = match add_dkim_entry(&current, &req, &format!("dkim/{file}")) {
        Ok(t) => t,
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            return Err(bad(e).into());
        }
    };
    match apply_text(&app, current, text, &key.name).await {
        Ok(applied) => {
            info!(domain = %req.domain, selector = %req.selector, "DKIM key created via API");
            Ok(Json(json!({
                "domain": req.domain,
                "selector": req.selector,
                "private_key": path.display().to_string(),
                "dns_name": generated.dns_name,
                "dns_value": generated.dns_value,
                "applied": applied,
            }))
            .into_response())
        }
        Err(e) => {
            // Don't leave an orphaned key behind if the configuration wasn't saved.
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

pub(super) async fn dkim_delete(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path((domain, selector)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApplyError> {
    let key = authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let (domain, selector) = (domain.trim().to_lowercase(), selector.trim().to_lowercase());
    let current = read_current(&app)?;
    let text = remove_dkim_entry(&current, &domain, &selector).map_err(|e| ApiError(StatusCode::NOT_FOUND, e))?;
    let applied = apply_text(&app, current, text, &key.name).await?;
    info!(%domain, %selector, "DKIM key removed via API (key file kept on disk)");
    Ok(Json(json!({ "removed": true, "applied": applied })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_col_positions() {
        let t = "a = 1\nbb = [\nccc";
        assert_eq!(line_col(t, 0), (1, 1));
        assert_eq!(line_col(t, 6), (2, 1));
        assert_eq!(line_col(t, 9), (2, 4));
        assert_eq!(line_col(t, 999), (3, 4));
    }

    #[test]
    fn save_config_backs_up_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("promailer.toml");
        std::fs::write(&path, "old").unwrap();
        let backup = save_config(&path, "old", "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), "old");
        assert!(backup.starts_with(dir.path().join("config-backups")));
    }

    #[test]
    fn dkim_entries_added_and_removed_preserving_comments() {
        let src = "# my server\n[server]\nhostname = \"mx.example.com\" # keep me\n";
        let k = NewDkimKey {
            domain: "example.com".into(),
            selector: "s2026".into(),
            algorithm: DkimAlgorithm::RsaSha256,
            bits: 2048,
            include_subdomains: false,
        };
        let added = add_dkim_entry(src, &k, "dkim/example.com.s2026.pem").unwrap();
        assert!(added.starts_with(src), "existing text and comments must be untouched");
        let cfg: crate::config::Config = toml::from_str(&added).unwrap();
        assert_eq!(cfg.dkim[0].selector, "s2026");
        let removed = remove_dkim_entry(&added, "example.com", "s2026").unwrap();
        assert_eq!(removed.trim_end(), src.trim_end());
        assert!(remove_dkim_entry(src, "example.com", "s2026").is_err());
    }

    #[test]
    fn dns_name_validation() {
        assert!(valid_dns_name("example.com", 253));
        assert!(valid_dns_name("s1", 63));
        assert!(!valid_dns_name("../etc", 253));
        assert!(!valid_dns_name("a..b", 253));
        assert!(!valid_dns_name("Bad_Name", 253));
    }
}
