//! IIS-compatible Pickup directory.
//!
//! Any `.eml` (or extension-less / `.txt`) file dropped here is queued. The
//! envelope is taken from leading `X-Sender:` / `X-Receiver:` lines (the format
//! written by System.Net.Mail.SmtpClient with SpecifiedPickupDirectory and by
//! IIS itself); otherwise it's derived from From / To / Cc / Bcc and Bcc is removed.
//!
//! A file is only taken once its writer has finished: it must be older than
//! `settle_time` *and* renamable. On Windows a file still open by its writer
//! (without FILE_SHARE_DELETE) cannot be renamed, which is the same signal IIS uses.

use crate::app::App;
use crate::message;
use crate::queue::{store::rename_retry, NewMessage, Source};
use crate::stats::Stats;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{error, info, warn};

pub struct Envelope {
    pub sender: String,
    pub recipients: Vec<String>,
    pub data: Vec<u8>,
}

/// Parse a pickup file into an envelope and the message to send.
pub fn parse_pickup(raw: Vec<u8>) -> Result<Envelope, String> {
    let raw = message::normalize_crlf(raw);
    let mut sender: Option<String> = None;
    let mut rcpts = Vec::new();
    let mut offset = 0;

    // Leading x-sender / x-receiver lines (case-insensitive), as written by .NET/IIS.
    for line in raw.split_inclusive(|&b| b == b'\n') {
        let text = String::from_utf8_lossy(line);
        let t = text.trim_end();
        let lower = t.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("x-sender:").map(|_| t[9..].trim()) {
            sender = Some(v.trim_matches(['<', '>']).to_string());
        } else if let Some(v) = lower.strip_prefix("x-receiver:").map(|_| t[11..].trim()) {
            rcpts.push(v.trim_matches(['<', '>']).to_string());
        } else {
            break;
        }
        offset += line.len();
    }
    let mut data = raw[offset..].to_vec();
    let hdrs = message::headers(&data);

    if rcpts.is_empty() {
        for h in ["To", "Cc", "Bcc"] {
            for (n, v) in &hdrs {
                if n.eq_ignore_ascii_case(h) {
                    rcpts.extend(message::parse_address_list(v));
                }
            }
        }
    }
    // Bcc must never be transmitted.
    if hdrs.iter().any(|(n, _)| n.eq_ignore_ascii_case("Bcc")) {
        data = message::remove_header(&data, "Bcc");
    }
    let sender = match sender {
        Some(s) => s,
        None => {
            let from = message::header_value(&hdrs, "Sender").or_else(|| message::header_value(&hdrs, "From"));
            from.and_then(|f| message::parse_address_list(&f).into_iter().next())
                .ok_or_else(|| "no X-Sender line and no From: header".to_string())?
        }
    };
    if !sender.is_empty() && !message::valid_mailbox(&sender) {
        return Err(format!("invalid sender address '{sender}'"));
    }
    rcpts.retain(|r| message::valid_mailbox(r));
    if rcpts.is_empty() {
        return Err("no valid recipients (no X-Receiver lines and no To/Cc/Bcc addresses)".into());
    }
    if data.is_empty() {
        return Err("empty message".into());
    }
    Ok(Envelope { sender, recipients: rcpts, data })
}

fn is_candidate(p: &Path) -> bool {
    if !p.is_file() {
        return false;
    }
    match p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()) {
        None => true,
        Some(e) => matches!(e.as_str(), "eml" | "txt" | "msg"),
    }
}

pub async fn run(app: Arc<App>) {
    let mut shutdown = app.shutdown_rx();
    let dir = app.cfg().pickup.dir.clone();
    let work = dir.join(".processing");
    if let Err(e) = std::fs::create_dir_all(&work) {
        error!(dir = %work.display(), error = %e, "cannot create pickup work directory; pickup disabled");
        // Stay alive until shutdown: a restart would not fix this, so it is not a subsystem failure.
        let _ = shutdown.changed().await;
        return;
    }
    // Files left mid-processing by a crash go back to the pickup directory.
    if let Ok(rd) = std::fs::read_dir(&work) {
        for e in rd.flatten() {
            let _ = rename_retry(&e.path(), &dir.join(e.file_name()));
        }
    }
    info!(dir = %dir.display(), "pickup directory watcher started");

    loop {
        let cfg = app.cfg();
        if let Err(e) = scan_once(&app, &dir, &work).await {
            warn!(error = %e, "pickup scan failed");
        }
        tokio::select! {
            _ = tokio::time::sleep(cfg.pickup.poll_interval) => {}
            _ = shutdown.changed() => break,
        }
    }
    info!("pickup directory watcher stopped");
}

async fn scan_once(app: &Arc<App>, dir: &Path, work: &Path) -> std::io::Result<()> {
    let cfg = app.cfg();
    let settle = cfg.pickup.settle_time;
    let mut files: Vec<(SystemTime, PathBuf)> = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        if !is_candidate(&p) {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if SystemTime::now().duration_since(mtime).unwrap_or_default() < settle {
            continue;
        }
        files.push((mtime, p));
    }
    files.sort(); // oldest first, preserves submission order
    for (_, path) in files.into_iter().take(1000) {
        if app.is_shutting_down() {
            break;
        }
        let max_q = cfg.limits.max_queue_size;
        if max_q > 0 && app.queue.len() >= max_q {
            warn!("queue full; pausing pickup");
            break;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let claimed = work.join(&name);
        // Claim: fails while the writer still holds the file open.
        if std::fs::rename(&path, &claimed).is_err() {
            continue;
        }
        process_file(app, &claimed, &name).await;
    }
    Ok(())
}

async fn process_file(app: &Arc<App>, path: &Path, name: &str) {
    let cfg = app.cfg();
    let raw = match tokio::fs::read(path).await {
        Ok(r) => r,
        Err(e) => {
            error!(file = %name, error = %e, "cannot read pickup file");
            return;
        }
    };
    let id = ulid::Ulid::new().to_string();
    if raw.len() as u64 > cfg.limits.max_message_size.0 {
        badmail(
            app,
            path,
            &id,
            &raw,
            &format!("Message size {} exceeds limit {}", raw.len(), cfg.limits.max_message_size.0),
        );
        return;
    }
    let hops = message::count_received(&message::headers(&raw));
    if hops >= cfg.server.max_hop_count {
        badmail(app, path, &id, &raw, "Maximum hop count exceeded");
        return;
    }
    match parse_pickup(raw.clone()) {
        Ok(env) => {
            let msg = NewMessage {
                sender: env.sender,
                recipients: env.recipients,
                data: env.data,
                source: Source::Pickup { file: name.to_string() },
                pool: None,
            };
            match crate::queue::enqueue(app, msg).await {
                Ok(qid) => {
                    Stats::inc(&app.stats.pickup_processed);
                    info!(file = %name, id = %qid, "pickup file queued");
                    if let Err(e) = crate::queue::store::remove_retry(path) {
                        error!(file = %name, error = %e, "queued pickup file could not be deleted (may be sent twice)");
                    }
                }
                Err(e) => {
                    // Put it back for the next scan; nothing is lost.
                    error!(file = %name, error = format!("{e:#}"), "failed to queue pickup file; will retry");
                    let back = path.parent().and_then(|p| p.parent()).map(|p| p.join(name));
                    if let Some(back) = back {
                        let _ = rename_retry(path, &back);
                    }
                }
            }
        }
        Err(reason) => badmail(app, path, &id, &raw, &reason),
    }
}

fn badmail(app: &Arc<App>, path: &Path, id: &str, raw: &[u8], reason: &str) {
    warn!(file = %path.display(), %reason, "pickup file rejected; moved to badmail");
    Stats::inc(&app.stats.badmail);
    if app.queue.store.write_badmail(id, raw, &format!("Pickup file {}: {reason}\r\n", path.display())).is_ok() {
        let _ = crate::queue::store::remove_retry(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotnet_pickup_format() {
        let raw = b"X-Sender: app@example.com\r\nX-Receiver: a@x.org\r\nX-Receiver: b@y.org\r\nFrom: app@example.com\r\nTo: a@x.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
        let env = parse_pickup(raw).unwrap();
        assert_eq!(env.sender, "app@example.com");
        assert_eq!(env.recipients, vec!["a@x.org", "b@y.org"]);
        assert!(env.data.starts_with(b"From:"));
    }

    #[test]
    fn header_derived_envelope_strips_bcc() {
        let raw = b"From: \"App\" <app@example.com>\nTo: a@x.org\nBcc: hidden@z.org\nSubject: hi\n\nbody\n".to_vec();
        let env = parse_pickup(raw).unwrap();
        assert_eq!(env.sender, "app@example.com");
        assert_eq!(env.recipients, vec!["a@x.org", "hidden@z.org"]);
        let text = String::from_utf8(env.data).unwrap();
        assert!(!text.contains("Bcc"));
        assert!(text.contains("\r\n"));
    }

    #[test]
    fn rejects_without_recipients() {
        assert!(parse_pickup(b"From: a@b.com\r\nSubject: x\r\n\r\nhi".to_vec()).is_err());
    }
}
