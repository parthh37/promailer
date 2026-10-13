//! Message lifecycle events (queued, sent, deferred, bounced, ...).
//!
//! Every event goes to two places:
//!
//! * an in-memory ring buffer with monotonically increasing sequence numbers,
//!   polled by `GET /api/v1/events` for the live delivery log;
//! * `<data_dir>/history/YYYY-MM-DD.jsonl` (one JSON object per line), scanned
//!   by `GET /api/v1/search`. Writing happens on a background task fed by a
//!   bounded channel, so a slow disk can never stall delivery.

use crate::app::App;
use chrono::{DateTime, NaiveDate, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, warn};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Queued,
    Sent,
    Deferred,
    Bounced,
    Expired,
    Deleted,
    Ndr,
}

impl EventKind {
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_ascii_lowercase())).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Process-local sequence number; restarts at 1 with the service.
    #[serde(default)]
    pub seq: u64,
    pub time: DateTime<Utc>,
    /// Queue ID of the message.
    pub id: String,
    pub kind: EventKind,
    #[serde(default)]
    pub from: String,
    /// Recipient for per-recipient events; recipient count is in `detail` for `queued`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    /// SMTP response, error or other human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Event {
    pub fn new(id: &str, kind: EventKind, from: &str) -> Self {
        Self {
            seq: 0,
            time: Utc::now(),
            id: id.to_string(),
            kind,
            from: from.to_string(),
            to: None,
            subject: None,
            relay: None,
            attempt: None,
            detail: None,
        }
    }

    /// Case-insensitive substring match against every text field. `needle` must be lowercase.
    pub fn matches(&self, needle: &str) -> bool {
        let hit = |s: &str| s.to_lowercase().contains(needle);
        hit(&self.id)
            || hit(&self.from)
            || self.to.as_deref().is_some_and(hit)
            || self.subject.as_deref().is_some_and(hit)
            || self.relay.as_deref().is_some_and(hit)
            || self.detail.as_deref().is_some_and(hit)
    }
}

pub struct EventLog {
    ring: Mutex<VecDeque<Event>>,
    capacity: usize,
    next_seq: AtomicU64,
    history: Mutex<Option<mpsc::Sender<Event>>>,
    pub dropped: AtomicU64,
}

#[derive(Serialize)]
pub struct EventPage {
    pub events: Vec<Event>,
    /// Sequence number of the newest event (pass as `after` next time).
    pub last_seq: u64,
    /// True when events between `after` and the first returned one were evicted
    /// from memory (the client fell behind or the service restarted).
    pub gap: bool,
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(capacity.min(65_536))),
            capacity: capacity.max(100),
            next_seq: AtomicU64::new(1),
            history: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }

    /// Route future events to the history writer.
    pub fn attach_history(&self, tx: mpsc::Sender<Event>) {
        *self.history.lock() = Some(tx);
    }

    pub fn record(&self, mut ev: Event) {
        {
            let mut ring = self.ring.lock();
            // Assign the sequence under the lock so the ring is always ordered.
            ev.seq = self.next_seq.fetch_add(1, Relaxed);
            if ring.len() >= self.capacity {
                ring.pop_front();
            }
            ring.push_back(ev.clone());
        }
        if let Some(tx) = self.history.lock().as_ref() {
            if tx.try_send(ev).is_err() {
                self.dropped.fetch_add(1, Relaxed);
            }
        }
    }

    /// Events with `seq > after`, oldest first, at most `limit`.
    pub fn since(&self, after: u64, limit: usize) -> EventPage {
        let ring = self.ring.lock();
        let last_seq = ring.back().map(|e| e.seq).unwrap_or(0);
        let first_seq = ring.front().map(|e| e.seq).unwrap_or(last_seq + 1);
        // The client is ahead of us: the service restarted and sequences reset.
        let after = if after > last_seq { 0 } else { after };
        let gap = after > 0 && after + 1 < first_seq;
        let start = ring.partition_point(|e| e.seq <= after);
        let events: Vec<Event> = ring.range(start..).take(limit).cloned().collect();
        EventPage { events, last_seq, gap }
    }

    /// Recent in-memory events matching `pred`, newest first.
    pub fn recent(&self, limit: usize, pred: impl Fn(&Event) -> bool) -> Vec<Event> {
        self.ring.lock().iter().rev().filter(|e| pred(e)).take(limit).cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// History files
// ---------------------------------------------------------------------------

fn file_for(dir: &Path, date: NaiveDate) -> PathBuf {
    dir.join(format!("{}.jsonl", date.format("%Y-%m-%d")))
}

/// Background writer: appends events to the current day's file and prunes old files.
pub async fn run_writer(app: Arc<App>, mut rx: mpsc::Receiver<Event>) {
    let dir = app.cfg().history_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!(dir = %dir.display(), error = %e, "cannot create history directory; message history disabled");
        return;
    }
    let mut shutdown = app.shutdown_rx();
    let mut prune = tokio::time::interval(Duration::from_secs(3600));
    let mut batch = Vec::new();
    loop {
        tokio::select! {
            n = rx.recv_many(&mut batch, 512) => {
                if n == 0 {
                    break;
                }
                let cfg = app.cfg();
                if cfg.history.enabled {
                    let dir = dir.clone();
                    let events = std::mem::take(&mut batch);
                    let res = tokio::task::spawn_blocking(move || append(&dir, &events)).await;
                    if let Ok(Err(e)) | Err(e) = res.map_err(std::io::Error::other) {
                        warn!(error = %e, "failed to write message history");
                    }
                }
                batch.clear();
            }
            _ = prune.tick() => {
                let (dir, days) = (dir.clone(), app.cfg().history.retention_days);
                let _ = tokio::task::spawn_blocking(move || prune_old(&dir, days)).await;
            }
            _ = shutdown.changed() => {
                // Flush whatever is already queued, then stop.
                rx.close();
                while rx.recv_many(&mut batch, 4096).await > 0 {}
                if app.cfg().history.enabled && !batch.is_empty() {
                    let _ = append(&dir, &batch);
                }
                break;
            }
        }
    }
}

fn append(dir: &Path, events: &[Event]) -> std::io::Result<()> {
    let mut current: Option<(NaiveDate, BufWriter<std::fs::File>)> = None;
    for ev in events {
        let date = ev.time.date_naive();
        if current.as_ref().map(|(d, _)| *d) != Some(date) {
            if let Some((_, mut w)) = current.take() {
                w.flush()?;
            }
            let f = std::fs::OpenOptions::new().create(true).append(true).open(file_for(dir, date))?;
            current = Some((date, BufWriter::new(f)));
        }
        let (_, w) = current.as_mut().expect("writer was just opened");
        serde_json::to_writer(&mut *w, ev)?;
        w.write_all(b"\n")?;
    }
    if let Some((_, mut w)) = current {
        w.flush()?;
    }
    Ok(())
}

fn prune_old(dir: &Path, retention_days: u32) {
    let cutoff = Utc::now().date_naive() - chrono::Duration::days(i64::from(retention_days.max(1)));
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(stem) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else { continue };
        if let Ok(d) = NaiveDate::parse_from_str(stem, "%Y-%m-%d") {
            if d < cutoff {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Scan history files newest-day-first for events matching `pred`.
/// Returns at most `limit` events, newest first. Blocking: run off the executor.
pub fn search_files(dir: &Path, days: u32, limit: usize, pred: impl Fn(&Event) -> bool) -> Vec<Event> {
    let today = Utc::now().date_naive();
    let mut out = Vec::new();
    for back in 0..days.max(1) {
        let path = file_for(dir, today - chrono::Duration::days(i64::from(back)));
        let Ok(f) = std::fs::File::open(&path) else { continue };
        let mut day: Vec<Event> = BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str::<Event>(&l).ok())
            .filter(|e| pred(e))
            .collect();
        day.reverse();
        let room = limit - out.len();
        out.extend(day.into_iter().take(room));
        if out.len() >= limit {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: &str, kind: EventKind) -> Event {
        Event::new(id, kind, "a@example.com")
    }

    #[test]
    fn ring_paging_and_gaps() {
        let log = EventLog::new(100);
        for i in 0..150 {
            log.record(ev(&format!("m{i}"), EventKind::Sent));
        }
        let p = log.since(0, 1000);
        assert_eq!(p.events.len(), 100);
        assert_eq!(p.events[0].seq, 51);
        assert_eq!(p.last_seq, 150);
        assert!(!p.gap);
        // Client last saw seq 10, which has been evicted.
        assert!(log.since(10, 10).gap);
        let p = log.since(140, 5);
        assert_eq!(p.events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![141, 142, 143, 144, 145]);
        // Client ahead of server (restart): start over.
        assert_eq!(log.since(9999, 1).events[0].seq, 51);
    }

    #[test]
    fn history_round_trip_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let mut events: Vec<Event> = (0..5).map(|i| ev(&format!("m{i}"), EventKind::Queued)).collect();
        events[3].to = Some("Bob@Example.org".into());
        append(dir.path(), &events).unwrap();
        let all = search_files(dir.path(), 1, 10, |_| true);
        assert_eq!(all.first().unwrap().id, "m4");
        let hits = search_files(dir.path(), 1, 10, |e| e.matches("bob@example"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "m3");
        assert_eq!(search_files(dir.path(), 1, 2, |_| true).len(), 2);
    }

    #[test]
    fn kind_parsing() {
        assert_eq!(EventKind::parse("Bounced"), Some(EventKind::Bounced));
        assert_eq!(EventKind::parse("nope"), None);
    }
}
