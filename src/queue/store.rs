//! Crash-safe filesystem persistence for queued messages.
//!
//! Layout (under `<data_dir>/queue`):
//!
//! * `<id>.eml`  – message bytes (immutable once written)
//! * `<id>.json` – envelope + per-recipient state (atomically replaced on update)
//! * `tmp/`      – staging area; everything is written here, fsynced, then renamed
//!
//! The `.json` file is the commit marker: it is written *after* the `.eml`, and
//! deleted *before* it. A crash at any point therefore leaves either a complete
//! message or an orphan `.eml` that recovery moves to badmail.

use super::QueueEntry;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub struct Store {
    pub dir: PathBuf,
    tmp: PathBuf,
    pub badmail: PathBuf,
    pub drop: PathBuf,
    durable: bool,
}

/// Rename with retries: on Windows, antivirus / indexer / backup agents briefly
/// open new files and cause transient ERROR_SHARING_VIOLATION / ACCESS_DENIED.
pub fn rename_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    let mut delay = Duration::from_millis(20);
    for attempt in 0..8 {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 7 && is_transient_fs_error(&e) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

pub fn remove_retry(path: &Path) -> std::io::Result<()> {
    let mut delay = Duration::from_millis(20);
    for attempt in 0..8 {
        match fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) if attempt < 7 && is_transient_fs_error(&e) => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

fn is_transient_fs_error(e: &std::io::Error) -> bool {
    // 32 = ERROR_SHARING_VIOLATION, 33 = ERROR_LOCK_VIOLATION on Windows.
    e.kind() == std::io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(32) | Some(33))
}

impl Store {
    pub fn open(dir: PathBuf, badmail: PathBuf, drop: PathBuf, durable: bool) -> Result<Self> {
        let tmp = dir.join("tmp");
        for d in [&dir, &tmp, &badmail, &drop] {
            fs::create_dir_all(d).with_context(|| format!("creating directory {}", d.display()))?;
        }
        // Clear staging leftovers from a previous crash.
        if let Ok(rd) = fs::read_dir(&tmp) {
            for e in rd.flatten() {
                let _ = fs::remove_file(e.path());
            }
        }
        Ok(Self { dir, tmp, badmail, drop, durable })
    }

    fn eml_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.eml"))
    }
    fn meta_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn write_atomic(&self, final_path: &Path, data: &[u8]) -> Result<()> {
        let name = final_path.file_name().unwrap().to_string_lossy();
        let tmp = self.tmp.join(format!("{name}.{}.tmp", ulid::Ulid::new()));
        {
            let mut f = File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(data).with_context(|| format!("writing {}", tmp.display()))?;
            if self.durable {
                f.sync_all().context("fsync")?;
            }
        }
        if let Err(e) = rename_retry(&tmp, final_path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("renaming into {}", final_path.display()));
        }
        Ok(())
    }

    pub fn create(&self, entry: &QueueEntry, data: &[u8]) -> Result<()> {
        self.write_atomic(&self.eml_path(&entry.id), data)?;
        let meta = serde_json::to_vec_pretty(entry)?;
        if let Err(e) = self.write_atomic(&self.meta_path(&entry.id), &meta) {
            let _ = remove_retry(&self.eml_path(&entry.id));
            return Err(e);
        }
        Ok(())
    }

    pub fn update(&self, entry: &QueueEntry) -> Result<()> {
        let meta = serde_json::to_vec_pretty(entry)?;
        self.write_atomic(&self.meta_path(&entry.id), &meta)
    }

    pub fn load_meta(&self, id: &str) -> Result<QueueEntry> {
        let raw = fs::read(self.meta_path(id)).with_context(|| format!("reading metadata for {id}"))?;
        serde_json::from_slice(&raw).with_context(|| format!("parsing metadata for {id}"))
    }

    pub fn load_data(&self, id: &str) -> Result<Vec<u8>> {
        fs::read(self.eml_path(id)).with_context(|| format!("reading message {id}"))
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        remove_retry(&self.meta_path(id)).with_context(|| format!("deleting metadata {id}"))?;
        remove_retry(&self.eml_path(id)).with_context(|| format!("deleting message {id}"))?;
        Ok(())
    }

    /// IIS-compatible badmail: `<id>.BAD` holds the message, `<id>.BDR` the reason.
    pub fn write_badmail(&self, id: &str, data: &[u8], reason: &str) -> Result<()> {
        let bad = self.badmail.join(format!("{id}.BAD"));
        let bdr = self.badmail.join(format!("{id}.BDR"));
        fs::write(&bad, data).with_context(|| format!("writing {}", bad.display()))?;
        fs::write(&bdr, reason).with_context(|| format!("writing {}", bdr.display()))?;
        Ok(())
    }

    /// IIS-compatible Drop directory delivery for local domains.
    pub fn write_drop(&self, id: &str, sender: &str, rcpts: &[String], data: &[u8]) -> Result<()> {
        let mut out = Vec::with_capacity(data.len() + 128);
        out.extend_from_slice(format!("x-sender: {sender}\r\n").as_bytes());
        for r in rcpts {
            out.extend_from_slice(format!("x-receiver: {r}\r\n").as_bytes());
        }
        out.extend_from_slice(data);
        let path = self.drop.join(format!("{id}-{}.eml", ulid::Ulid::new()));
        self.write_atomic(&path, &out)
    }

    /// Scan the queue directory at startup. Returns committed entries and moves
    /// orphaned/corrupt files to badmail.
    pub fn recover(&self) -> Result<Vec<QueueEntry>> {
        let mut entries = Vec::new();
        let mut orphans = Vec::new();
        for e in fs::read_dir(&self.dir).with_context(|| format!("reading {}", self.dir.display()))?.flatten() {
            let path = e.path();
            let Some(ext) = path.extension().and_then(|x| x.to_str()) else { continue };
            let Some(id) = path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()) else { continue };
            match ext {
                "json" => match self.load_meta(&id) {
                    Ok(m) if self.eml_path(&id).exists() => entries.push(m),
                    Ok(_) => {
                        tracing::error!(%id, "queue metadata without message body; removing");
                        let _ = remove_retry(&path);
                    }
                    Err(err) => {
                        tracing::error!(%id, error = %err, "corrupt queue metadata; moving to badmail");
                        let data = fs::read(self.eml_path(&id)).unwrap_or_default();
                        let _ = self.write_badmail(&id, &data, &format!("Corrupt queue metadata: {err:#}"));
                        let _ = remove_retry(&path);
                        let _ = remove_retry(&self.eml_path(&id));
                    }
                },
                "eml" if !self.meta_path(&id).exists() => orphans.push((id, path)),
                _ => {}
            }
        }
        for (id, path) in orphans {
            // Only treat as orphan if it is not being written right now.
            let old = fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|t| SystemTime::now().duration_since(t).unwrap_or_default() > Duration::from_secs(60))
                .unwrap_or(true);
            if old {
                tracing::warn!(%id, "orphaned message body (crash during enqueue); moving to badmail");
                let data = fs::read(&path).unwrap_or_default();
                let _ = self.write_badmail(&id, &data, "Incomplete queue entry found during recovery (no envelope)");
                let _ = remove_retry(&path);
            }
        }
        Ok(entries)
    }

    pub fn list_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let p = e.path();
                (p.extension().and_then(|x| x.to_str()) == Some("json"))
                    .then(|| p.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string()))
                    .flatten()
            })
            .collect();
        ids.sort();
        ids
    }
}
