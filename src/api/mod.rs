//! HTTP management and send API.
//!
//! Authentication: `Authorization: Bearer <key>` or `X-API-Key: <key>`. Keys are
//! stored as SHA-256 hashes in the config and carry permissions (send/queue/admin).

use crate::access;
use crate::app::App;
use crate::auth::{constant_time_eq, sha256_hex};
use crate::config::{ApiKeyConfig, ApiPermission};
use crate::events::{EventKind, EventPage};
use crate::message;
use crate::queue::{NewMessage, QueueOpError, Source};
use crate::stats::Stats;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};

mod admin;
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

#[derive(Debug)]
pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

type ApiResult<T> = Result<T, ApiError>;

/// Bodies are parsed only after authentication so unauthenticated callers
/// learn nothing about request validation.
fn parse_json<T: serde::de::DeserializeOwned>(body: &[u8]) -> ApiResult<T> {
    serde_json::from_slice(body)
        .map_err(|e| ApiError(StatusCode::UNPROCESSABLE_ENTITY, format!("invalid JSON body: {e}")))
}

fn authorize(app: &App, headers: &HeaderMap, peer: SocketAddr, perm: ApiPermission) -> ApiResult<ApiKeyConfig> {
    let cfg = app.cfg();
    if !cfg.api.allow.is_empty() && !access::in_list(&cfg.api.allow, peer.ip()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "client IP not allowed".into()));
    }
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .or_else(|| headers.get("x-api-key").and_then(|v| v.to_str().ok()))
        .map(str::trim)
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "missing API key".into()))?;
    let hash = sha256_hex(presented.as_bytes());
    let key = cfg.api.keys.iter().find(|k| constant_time_eq(&k.key_sha256, &hash)).ok_or_else(|| {
        warn!(ip = %peer.ip(), "API request with invalid key");
        ApiError(StatusCode::UNAUTHORIZED, "invalid API key".into())
    })?;
    if !key.permissions.contains(&perm) && !key.permissions.contains(&ApiPermission::Admin) {
        return Err(ApiError(StatusCode::FORBIDDEN, format!("API key lacks '{perm:?}' permission").to_lowercase()));
    }
    Ok(key.clone())
}

pub fn router(app: Arc<App>) -> Router {
    let limit = app.cfg().api.max_body_size.as_usize();
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/messages", post(send_json))
        .route("/api/v1/messages/raw", post(send_raw))
        .route("/api/v1/queue", get(queue_list))
        .route("/api/v1/queue/retry", post(queue_retry_all))
        .route("/api/v1/queue/{id}", get(queue_get))
        .route("/api/v1/queue/{id}", delete(queue_delete))
        .route("/api/v1/queue/{id}/retry", post(queue_retry))
        .route("/api/v1/queue/{id}/headers", get(queue_headers))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/stats/history", get(stats_history))
        .route("/api/v1/events", get(events))
        .route("/api/v1/search", get(search))
        .route("/api/v1/check/{domain}", get(check_domain))
        .route("/api/v1/reload", post(reload))
        .route("/api/v1/config", get(admin::config_get))
        .route("/api/v1/config", put(admin::config_put))
        .route("/api/v1/config/validate", post(admin::config_validate))
        .route("/api/v1/dkim", get(admin::dkim_list))
        .route("/api/v1/dkim", post(admin::dkim_create))
        .route("/api/v1/dkim/{domain}/{selector}", delete(admin::dkim_delete))
        .route("/api/v1/crashes", get(admin::crashes_list))
        .route("/api/v1/crashes/{id}", delete(admin::crash_delete))
        .layer(DefaultBodyLimit::max(limit))
        .with_state(app)
}

pub async fn serve(app: Arc<App>, listener: TcpListener) {
    let mut shutdown = app.shutdown_rx();
    let addr = listener.local_addr().ok();
    info!(bind = ?addr, "HTTP API started");
    let svc = router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let res = axum::serve(listener, svc)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await;
    if let Err(e) = res {
        tracing::error!(error = %e, "HTTP API stopped with error");
    }
}

async fn health(State(app): State<Arc<App>>) -> impl IntoResponse {
    Json(json!({
        "status": if app.is_shutting_down() { "stopping" } else { "ok" },
        "version": env!("CARGO_PKG_VERSION"),
        // Already public in the SMTP banner; lets the manager label the server.
        "hostname": app.cfg().server.hostname,
        "queue": app.queue.len(),
    }))
}

pub fn snapshot(app: &App) -> crate::stats::StatsSnapshot {
    app.stats.snapshot(
        app.started.elapsed().as_secs(),
        app.connections.active(),
        app.queue.len(),
        app.queue.in_flight(),
    )
}

async fn metrics(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    let cfg = app.cfg();
    if !cfg.api.allow.is_empty() && !access::in_list(&cfg.api.allow, peer.ip()) {
        return StatusCode::FORBIDDEN.into_response();
    }
    ([("content-type", "text/plain; version=0.0.4")], snapshot(&app).to_prometheus()).into_response()
}

async fn stats(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    Ok(Json(snapshot(&app)))
}

#[derive(Deserialize)]
struct SinceQuery {
    /// Unix seconds; only samples newer than this are returned.
    #[serde(default)]
    since: i64,
}

async fn stats_history(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<SinceQuery>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    Ok(Json(json!({
        "interval_seconds": crate::stats::SAMPLE_INTERVAL_SECS,
        "samples": app.stats_history.since(q.since),
    })))
}

// ---------------------------------------------------------------------------
// Events (live delivery log) and search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_limit")]
    limit: usize,
}

async fn events(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<EventPage>> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    Ok(Json(app.events.since(q.after, q.limit.clamp(1, 5000))))
}

#[derive(Deserialize)]
struct SearchQuery {
    /// Case-insensitive text matched against ID, addresses, subject and responses.
    #[serde(default)]
    q: String,
    /// Restrict history to one event kind (sent, bounced, ...).
    #[serde(default)]
    kind: Option<String>,
    /// Days of history to scan, counting today.
    #[serde(default = "default_days")]
    days: u32,
    #[serde(default = "default_limit")]
    limit: usize,
}
fn default_days() -> u32 {
    7
}

async fn search(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<SearchQuery>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    let kind = match q.kind.as_deref().map(str::trim).filter(|k| !k.is_empty() && *k != "all") {
        Some(k) => Some(EventKind::parse(k).ok_or_else(|| bad(format!("unknown event kind '{k}'")))?),
        None => None,
    };
    let needle = q.q.trim().to_lowercase();
    let limit = q.limit.clamp(1, 2000);
    let days = q.days.clamp(1, 366);
    let app2 = app.clone();
    let (queued, history, history_enabled) = tokio::task::spawn_blocking(move || {
        let queued: Vec<_> = if kind.is_none() {
            let store = &app2.queue.store;
            store
                .list_ids()
                .iter()
                .rev()
                .filter_map(|id| store.load_meta(id).ok())
                .filter(|m| m.matches(&needle))
                .take(limit)
                .collect()
        } else {
            Vec::new()
        };
        let pred = |e: &crate::events::Event| kind.is_none_or(|k| e.kind == k) && e.matches(&needle);
        let cfg = app2.cfg();
        let history = if cfg.history.enabled {
            crate::events::search_files(&cfg.history_dir(), days, limit, pred)
        } else {
            app2.events.recent(limit, pred)
        };
        (queued, history, cfg.history.enabled)
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "queued": queued, "history": history, "history_enabled": history_enabled })))
}

// ---------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    filename: String,
    #[serde(default)]
    content_type: Option<String>,
    /// Base64-encoded content.
    content: String,
    /// Set to reference the part from HTML as `cid:<content_id>` (inline image).
    #[serde(default)]
    content_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRequest {
    from: String,
    to: Vec<String>,
    #[serde(default)]
    cc: Vec<String>,
    #[serde(default)]
    bcc: Vec<String>,
    #[serde(default)]
    reply_to: Option<String>,
    subject: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    html: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    attachments: Vec<Attachment>,
    /// Envelope sender (Return-Path / bounce address). Defaults to the From address.
    #[serde(default)]
    envelope_from: Option<String>,
    /// Outbound IP pool.
    #[serde(default)]
    pool: Option<String>,
}

#[derive(Serialize)]
struct SendResponse {
    id: String,
    status: &'static str,
    recipients: usize,
}

/// "Name <a@b.c>" | "<a@b.c>" | "a@b.c"  →  (name, address)
fn parse_named(s: &str) -> ApiResult<(Option<String>, String)> {
    let s = s.trim();
    let (name, addr) = match (s.rfind('<'), s.rfind('>')) {
        (Some(a), Some(b)) if b > a => {
            let name = s[..a].trim().trim_matches('"').trim();
            ((!name.is_empty()).then(|| name.to_string()), s[a + 1..b].trim().to_string())
        }
        _ => (None, s.to_string()),
    };
    if !message::valid_mailbox(&addr) {
        return Err(bad(format!("invalid email address '{s}'")));
    }
    Ok((name, addr))
}

fn valid_header_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 76 && n.bytes().all(|b| b.is_ascii_graphic() && b != b':')
}

fn check_sender_and_rate(app: &App, key: &ApiKeyConfig, sender: &str, rcpts: usize) -> ApiResult<()> {
    let cfg = app.cfg();
    if !key.allowed_sender_domains.is_empty() {
        let d = message::domain_of(sender);
        if !key.allowed_sender_domains.iter().any(|a| a.eq_ignore_ascii_case(&d)) {
            return Err(ApiError(StatusCode::FORBIDDEN, format!("sender domain '{d}' not allowed for this API key")));
        }
    }
    if rcpts == 0 {
        return Err(bad("at least one recipient is required"));
    }
    if rcpts > cfg.limits.max_recipients_per_message {
        return Err(bad(format!("too many recipients (max {})", cfg.limits.max_recipients_per_message)));
    }
    if !app.rate_user.check(&format!("api:{}", key.name), key.messages_per_minute.unwrap_or(0)) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()));
    }
    let max_q = cfg.limits.max_queue_size;
    if max_q > 0 && app.queue.len() >= max_q {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "queue is full, try again later".into()));
    }
    Ok(())
}

fn build_mime(req: &SendRequest, hostname: &str) -> ApiResult<(String, Vec<String>, Vec<u8>)> {
    use mail_builder::headers::address::Address;
    use mail_builder::headers::raw::Raw;
    use mail_builder::MessageBuilder;

    if req.text.is_none() && req.html.is_none() {
        return Err(bad("either 'text' or 'html' is required"));
    }
    if req.subject.contains(['\r', '\n']) {
        return Err(bad("subject must not contain line breaks"));
    }
    let (from_name, from_addr) = parse_named(&req.from)?;
    let mut rcpts = Vec::new();
    let mut list = |items: &[String]| -> ApiResult<Vec<Address<'static>>> {
        items
            .iter()
            .map(|s| {
                let (n, a) = parse_named(s)?;
                rcpts.push(a.clone());
                Ok(Address::new_address(n, a))
            })
            .collect()
    };
    let to = list(&req.to)?;
    let cc = list(&req.cc)?;
    let _bcc = list(&req.bcc)?; // envelope only, never a header

    let mut b = MessageBuilder::new()
        .from(Address::new_address(from_name, from_addr.clone()))
        .subject(req.subject.clone())
        .message_id(message::new_message_id(hostname).trim_matches(['<', '>']).to_string());
    if !to.is_empty() {
        b = b.to(Address::new_list(to));
    }
    if !cc.is_empty() {
        b = b.cc(Address::new_list(cc));
    }
    if let Some(rt) = &req.reply_to {
        let (n, a) = parse_named(rt)?;
        b = b.reply_to(Address::new_address(n, a));
    }
    for (k, v) in &req.headers {
        if !valid_header_name(k) || v.contains(['\r', '\n']) {
            return Err(bad(format!("invalid custom header '{k}'")));
        }
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "from" | "to" | "cc" | "bcc" | "subject" | "message-id" | "content-type" | "mime-version"
        ) {
            return Err(bad(format!("header '{k}' must be set via its dedicated field")));
        }
        b = b.header(k.clone(), Raw::new(v.clone()));
    }
    if let Some(t) = &req.text {
        b = b.text_body(t.clone());
    }
    if let Some(h) = &req.html {
        b = b.html_body(h.clone());
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    for a in &req.attachments {
        let bytes = b64
            .decode(a.content.replace(['\r', '\n', ' '], ""))
            .map_err(|_| bad(format!("attachment '{}' is not valid base64", a.filename)))?;
        let ct = a.content_type.clone().unwrap_or_else(|| guess_content_type(&a.filename).to_string());
        if a.filename.contains(['\r', '\n', '"']) {
            return Err(bad("invalid attachment filename"));
        }
        b = match &a.content_id {
            Some(cid) => b.inline(ct, cid.clone(), bytes),
            None => b.attachment(ct, a.filename.clone(), bytes),
        };
    }
    let data = b.write_to_vec().map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let sender = match &req.envelope_from {
        Some(e) => parse_named(e)?.1,
        None => from_addr,
    };
    Ok((sender, rcpts, data))
}

fn guess_content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().map(|e| e.to_ascii_lowercase()).as_deref() {
        Some("pdf") => "application/pdf",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain",
        Some("csv") => "text/csv",
        Some("html") | Some("htm") => "text/html",
        Some("zip") => "application/zip",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("ics") => "text/calendar",
        _ => "application/octet-stream",
    }
}

async fn send_json(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let key = authorize(&app, &headers, peer, ApiPermission::Send)?;
    let req: SendRequest = parse_json(&body)?;
    let hostname = app.cfg().server.hostname.clone();
    let (sender, rcpts, data) = build_mime(&req, &hostname)?;
    check_sender_and_rate(&app, &key, &sender, rcpts.len())?;
    if data.len() as u64 > app.cfg().limits.max_message_size.0 {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "message exceeds limits.max_message_size".into()));
    }
    let n = rcpts.len();
    let id = crate::queue::enqueue(
        &app,
        NewMessage {
            sender,
            recipients: rcpts,
            data,
            source: Source::Api { key: key.name.clone() },
            pool: req.pool.clone(),
        },
    )
    .await
    .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("could not queue message: {e:#}")))?;
    Stats::inc(&app.stats.api_messages);
    Ok((StatusCode::ACCEPTED, Json(SendResponse { id, status: "queued", recipients: n })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRequest {
    /// Envelope sender; derived from From:/X-Sender when omitted.
    #[serde(default)]
    from: Option<String>,
    /// Envelope recipients; derived from To/Cc/Bcc/X-Receiver when omitted.
    #[serde(default)]
    to: Vec<String>,
    /// Full RFC 5322 message.
    #[serde(default)]
    raw: Option<String>,
    /// Alternative to `raw` for 8-bit/binary content.
    #[serde(default)]
    raw_base64: Option<String>,
    #[serde(default)]
    pool: Option<String>,
}

async fn send_raw(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<impl IntoResponse> {
    let key = authorize(&app, &headers, peer, ApiPermission::Send)?;
    let req: RawRequest = parse_json(&body)?;
    let raw = match (req.raw, req.raw_base64) {
        (Some(r), None) => r.into_bytes(),
        (None, Some(b)) => base64::engine::general_purpose::STANDARD
            .decode(b.replace(['\r', '\n'], ""))
            .map_err(|_| bad("raw_base64 is not valid base64"))?,
        _ => return Err(bad("provide exactly one of 'raw' or 'raw_base64'")),
    };
    if raw.len() as u64 > app.cfg().limits.max_message_size.0 {
        return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, "message exceeds limits.max_message_size".into()));
    }
    let mut env = match crate::pickup::parse_pickup(raw.clone()) {
        Ok(env) => env,
        // The envelope may be supplied explicitly even if the headers lack addresses.
        Err(_) if req.from.is_some() && !req.to.is_empty() => crate::pickup::Envelope {
            sender: String::new(),
            recipients: vec![],
            data: message::remove_header(&message::normalize_crlf(raw), "Bcc"),
        },
        Err(e) => return Err(bad(e)),
    };
    if env.data.is_empty() {
        return Err(bad("message has no content"));
    }
    if let Some(f) = &req.from {
        env.sender = parse_named(f)?.1;
    }
    if !req.to.is_empty() {
        env.recipients = req.to.iter().map(|t| parse_named(t).map(|x| x.1)).collect::<ApiResult<_>>()?;
    }
    check_sender_and_rate(&app, &key, &env.sender, env.recipients.len())?;
    let n = env.recipients.len();
    let id = crate::queue::enqueue(
        &app,
        NewMessage {
            sender: env.sender,
            recipients: env.recipients,
            data: env.data,
            source: Source::Api { key: key.name.clone() },
            pool: req.pool,
        },
    )
    .await
    .map_err(|e| ApiError(StatusCode::SERVICE_UNAVAILABLE, format!("could not queue message: {e:#}")))?;
    Stats::inc(&app.stats.api_messages);
    Ok((StatusCode::ACCEPTED, Json(SendResponse { id, status: "queued", recipients: n })))
}

// ---------------------------------------------------------------------------
// Queue management
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Page {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    /// Optional case-insensitive filter (ID, sender, recipient, subject, last response).
    #[serde(default)]
    q: Option<String>,
}
fn default_limit() -> usize {
    100
}

async fn queue_list(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    let q = app.queue.clone();
    let limit = page.limit.min(1000);
    let needle = page.q.as_deref().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty());
    let (total, items) = tokio::task::spawn_blocking(move || {
        let ids = q.store.list_ids();
        match needle {
            None => {
                let items: Vec<_> =
                    ids.iter().skip(page.offset).take(limit).filter_map(|id| q.store.load_meta(id).ok()).collect();
                (ids.len(), items)
            }
            Some(n) => {
                let all: Vec<_> =
                    ids.iter().filter_map(|id| q.store.load_meta(id).ok()).filter(|m| m.matches(&n)).collect();
                let total = all.len();
                (total, all.into_iter().skip(page.offset).take(limit).collect())
            }
        }
    })
    .await
    .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "total": total, "offset": page.offset, "items": items })))
}

async fn queue_get(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    if ulid::Ulid::from_string(&id).is_err() {
        return Err(ApiError(StatusCode::NOT_FOUND, "not found".into()));
    }
    app.queue.store.load_meta(&id).map(Json).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not found".into()))
}

fn op_err(e: QueueOpError) -> ApiError {
    match e {
        QueueOpError::NotFound => ApiError(StatusCode::NOT_FOUND, "not found".into()),
        QueueOpError::InFlight => {
            ApiError(StatusCode::CONFLICT, "message is being delivered right now; try again shortly".into())
        }
    }
}

async fn queue_delete(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let key = authorize(&app, &headers, peer, ApiPermission::Queue)?;
    let meta = ulid::Ulid::from_string(&id).ok().and_then(|_| app.queue.store.load_meta(&id).ok());
    app.queue.delete(&id).map_err(op_err)?;
    info!(%id, key = %key.name, "queue entry deleted via API");
    if let Some(m) = meta {
        let mut ev = m.event(EventKind::Deleted);
        ev.to = Some(m.pending().map(|r| r.address.as_str()).collect::<Vec<_>>().join(", "));
        ev.detail = Some(format!("deleted by administrator (API key '{}')", key.name));
        app.events.record(ev);
    }
    Ok(Json(json!({ "deleted": id })))
}

/// Header block of a queued message (up to 64 KB) for inspection.
async fn queue_headers(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    if ulid::Ulid::from_string(&id).is_err() {
        return Err(ApiError(StatusCode::NOT_FOUND, "not found".into()));
    }
    let q = app.queue.clone();
    let data = tokio::task::spawn_blocking(move || q.store.load_data(&id))
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|_| ApiError(StatusCode::NOT_FOUND, "not found".into()))?;
    let end = message::header_end(&data).min(64 * 1024);
    Ok(Json(json!({ "headers": String::from_utf8_lossy(&data[..end]), "size": data.len() })))
}

async fn queue_retry(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    app.queue.retry_now(&id).map_err(op_err)?;
    Ok(Json(json!({ "rescheduled": id })))
}

async fn queue_retry_all(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Queue)?;
    Ok(Json(json!({ "rescheduled": app.queue.retry_all() })))
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CheckQuery {
    /// Comma-separated sending IPs to test instead of the configured ones.
    #[serde(default)]
    ip: Option<String>,
}

async fn check_domain(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(q): Query<CheckQuery>,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Admin)?;
    let ips =
        q.ip.unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().parse().map_err(|_| bad(format!("invalid IP '{s}'"))))
            .collect::<ApiResult<Vec<_>>>()?;
    let report = crate::checks::run(&app.dns, &app.cfg(), &app.dkim.load(), &domain, &ips).await;
    Ok(Json(report))
}

async fn reload(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<impl IntoResponse> {
    authorize(&app, &headers, peer, ApiPermission::Admin)?;
    match app.reload() {
        Ok(warnings) => Ok(Json(json!({ "reloaded": true, "warnings": warnings }))),
        Err(e) => Err(bad(format!("reload failed, running configuration unchanged: {e:#}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_address_parsing() {
        assert_eq!(parse_named("Jane Doe <jane@x.com>").ok().unwrap(), (Some("Jane Doe".into()), "jane@x.com".into()));
        assert_eq!(parse_named("\"Doe, J\" <j@x.com>").ok().unwrap().0.unwrap(), "Doe, J");
        assert_eq!(parse_named("j@x.com").ok().unwrap(), (None, "j@x.com".into()));
        assert!(parse_named("not an email").is_err());
    }

    #[test]
    fn mime_build_excludes_bcc_and_includes_all_rcpts() {
        let req: SendRequest = serde_json::from_value(json!({
            "from": "App <app@example.com>",
            "to": ["a@x.org"],
            "bcc": ["hidden@y.org"],
            "subject": "Hello",
            "text": "plain",
            "html": "<b>html</b>",
            "headers": {"X-Campaign": "42"},
            "attachments": [{"filename": "a.txt", "content": "aGVsbG8="}]
        }))
        .unwrap();
        let (sender, rcpts, data) = build_mime(&req, "mx.example.com").unwrap();
        let text = String::from_utf8_lossy(&data);
        assert_eq!(sender, "app@example.com");
        assert_eq!(rcpts, vec!["a@x.org", "hidden@y.org"]);
        assert!(!text.to_lowercase().contains("hidden@y.org"));
        assert!(text.contains("X-Campaign: 42"));
        assert!(text.contains("multipart/"));
    }

    #[test]
    fn header_injection_rejected() {
        let req: SendRequest = serde_json::from_value(json!({
            "from": "app@example.com", "to": ["a@x.org"], "subject": "x", "text": "y",
            "headers": {"X-Evil": "a\r\nBcc: victim@z.org"}
        }))
        .unwrap();
        assert!(build_mime(&req, "h").is_err());
    }
}
