//! Windows Event Log integration: service lifecycle, certificate and error events go to
//! the Application log under the source "Promailer", where SCOM and other monitoring
//! tools pick them up.
//!
//! A tracing event is sent when it carries an ID: `info!(event_id = id::STARTED, "...")`.
//! Untagged errors are sent as ID 1100, rate-limited. Untagged warnings are not sent:
//! many are triggered by remote clients (failed logins, relay attempts) and would flood
//! the log. Event IDs are a public contract that monitoring rules depend on: never
//! renumber them, and keep them inside the message-table range in build.rs.

use crate::logging::{DELIVERY_TARGET, PROTOCOL_TARGET};
use parking_lot::Mutex;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

pub const SOURCE: &str = "Promailer";

/// Field that tags a tracing event for the Event Log.
pub const FIELD: &str = "event_id";

pub mod id {
    pub const STARTED: u32 = 1000;
    pub const STOPPED: u32 = 1001;
    pub const RELOADED: u32 = 1002;
    pub const RELOAD_FAILED: u32 = 1003;
    /// Start-up failure or fatal runtime error; the service stops.
    pub const FATAL: u32 = 1004;
    pub const CERT_EXPIRING: u32 = 1010;
    pub const CERT_INVALID: u32 = 1011;
    /// A different TLS certificate was picked up (renewal, or the config changed).
    pub const CERT_CHANGED: u32 = 1012;
    /// Any other error.
    pub const ERROR: u32 = 1100;
    /// The error rate limit was reached.
    pub const SUPPRESSED: u32 = 1199;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Information,
    Warning,
    Error,
}

/// Destination for events (the Windows Event Log, or a buffer in tests).
pub trait Sink: Send + Sync + 'static {
    fn write(&self, kind: Kind, id: u32, message: &str);
}

/// Untagged errors forwarded per window; the rest go only to promailer.log.
const ERROR_BURST: u32 = 20;
const ERROR_WINDOW: Duration = Duration::from_secs(600);

static LAYER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether tracing events are being forwarded. If not (e.g. the configuration could
/// not be loaded), start-up failures must be reported with [`report`] directly.
pub fn layer_active() -> bool {
    LAYER_ACTIVE.load(Ordering::Relaxed)
}

pub struct EventLogLayer<K: Sink> {
    sink: K,
    window: Mutex<Window>,
}

struct Window {
    started: Option<Instant>,
    count: u32,
}

enum Admit {
    Forward,
    /// First error over the limit: tell the log that further errors are suppressed.
    Announce,
    Drop,
}

impl<K: Sink> EventLogLayer<K> {
    pub fn new(sink: K) -> Self {
        Self { sink, window: Mutex::new(Window { started: None, count: 0 }) }
    }

    fn admit_untagged_error(&self, now: Instant) -> Admit {
        let mut w = self.window.lock();
        if w.started.is_none_or(|s| now.duration_since(s) >= ERROR_WINDOW) {
            *w = Window { started: Some(now), count: 0 };
        }
        w.count += 1;
        match w.count {
            n if n <= ERROR_BURST => Admit::Forward,
            n if n == ERROR_BURST + 1 => Admit::Announce,
            _ => Admit::Drop,
        }
    }
}

impl<S: Subscriber, K: Sink> Layer<S> for EventLogLayer<K> {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if meta.target() == PROTOCOL_TARGET || meta.target() == DELIVERY_TARGET {
            return;
        }
        let kind = match *meta.level() {
            Level::ERROR => Kind::Error,
            Level::WARN => Kind::Warning,
            _ => Kind::Information,
        };
        // Cheap pre-check from static metadata before visiting any fields.
        if kind != Kind::Error && meta.fields().field(FIELD).is_none() {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let id = match fields.event_id {
            Some(id) => id,
            None if kind == Kind::Error => match self.admit_untagged_error(Instant::now()) {
                Admit::Forward => id::ERROR,
                Admit::Announce => {
                    let minutes = ERROR_WINDOW.as_secs() / 60;
                    self.sink.write(
                        Kind::Warning,
                        id::SUPPRESSED,
                        &format!(
                            "More than {ERROR_BURST} errors in {minutes} minutes. Further errors in this period are \
                             written only to promailer.log in the log directory."
                        ),
                    );
                    return;
                }
                Admit::Drop => return,
            },
            None => return,
        };
        self.sink.write(kind, id, &fields.render());
    }
}

#[derive(Default)]
struct Fields {
    event_id: Option<u32>,
    message: String,
    extra: Vec<(&'static str, String)>,
}

impl Fields {
    /// Message first, then one `name: value` line per field, as Event Viewer shows it.
    fn render(&self) -> String {
        let mut out = self.message.clone();
        if !self.extra.is_empty() {
            out.push_str("\r\n");
        }
        for (name, value) in &self.extra {
            let _ = write!(out, "\r\n{name}: {value}");
        }
        out
    }
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            FIELD => self.event_id = u32::try_from(value).ok(),
            name => self.extra.push((name, value.to_string())),
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        match field.name() {
            FIELD => self.event_id = u32::try_from(value).ok(),
            name => self.extra.push((name, value.to_string())),
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "message" => self.message = value.to_string(),
            name => self.extra.push((name, value.to_string())),
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = format!("{value:?}"),
            name => self.extra.push((name, format!("{value:?}"))),
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::*;
    use anyhow::{bail, Result};
    use std::path::Path;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE,
    };

    const SOURCE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Promailer";
    /// ReportEvent accepts at most 31,839 characters per string.
    const MAX_CHARS: usize = 31_000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub struct WindowsSink(HANDLE);

    // SAFETY: event log handles may be used from any thread; ReportEventW is thread-safe.
    unsafe impl Send for WindowsSink {}
    unsafe impl Sync for WindowsSink {}

    impl WindowsSink {
        pub fn open() -> Option<Self> {
            let name = wide(SOURCE);
            // SAFETY: `name` is NUL-terminated and outlives the call.
            let handle = unsafe { RegisterEventSourceW(ptr::null(), name.as_ptr()) };
            (!handle.is_null()).then_some(Self(handle))
        }
    }

    impl Drop for WindowsSink {
        fn drop(&mut self) {
            // SAFETY: the handle came from RegisterEventSourceW and is released once.
            unsafe { DeregisterEventSource(self.0) };
        }
    }

    impl Sink for WindowsSink {
        fn write(&self, kind: Kind, id: u32, message: &str) {
            let kind = match kind {
                Kind::Information => EVENTLOG_INFORMATION_TYPE,
                Kind::Warning => EVENTLOG_WARNING_TYPE,
                Kind::Error => EVENTLOG_ERROR_TYPE,
            };
            let text: String = message.chars().take(MAX_CHARS).collect();
            let text = wide(&text);
            let strings = [text.as_ptr()];
            // SAFETY: one valid NUL-terminated string; no SID and no binary data.
            unsafe {
                ReportEventW(self.0, kind, 0, id, ptr::null_mut(), 1, 0, strings.as_ptr(), ptr::null());
            }
        }
    }

    fn check(code: u32, what: &str) -> Result<()> {
        if code != ERROR_SUCCESS {
            bail!("{what}: {}", std::io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }

    /// Register "Promailer" as an Application-log source whose messages come from `exe`.
    pub fn register_source(exe: &Path) -> Result<()> {
        let mut key: HKEY = ptr::null_mut();
        let subkey = wide(SOURCE_KEY);
        // SAFETY: valid NUL-terminated strings and out-pointer; the key is closed below.
        let code = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        check(code, "registering Event Log source (run as Administrator)")?;
        let file = wide(&exe.display().to_string());
        let types: u32 = 0x7; // error, warning, information
        let name_file = wide("EventMessageFile");
        let name_types = wide("TypesSupported");
        // SAFETY: data pointers and byte lengths describe live buffers.
        let result = unsafe {
            let a = RegSetValueExW(
                key,
                name_file.as_ptr(),
                0,
                REG_EXPAND_SZ,
                file.as_ptr().cast(),
                (file.len() * 2) as u32,
            );
            let b = RegSetValueExW(key, name_types.as_ptr(), 0, REG_DWORD, ptr::from_ref(&types).cast(), 4);
            RegCloseKey(key);
            (a, b)
        };
        check(result.0, "writing EventMessageFile")?;
        check(result.1, "writing TypesSupported")
    }

    pub fn unregister_source() -> Result<()> {
        let subkey = wide(SOURCE_KEY);
        // SAFETY: valid NUL-terminated subkey path.
        let code = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.as_ptr()) };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        check(code, "removing Event Log source")
    }
}

#[cfg(windows)]
pub use sys::{register_source, unregister_source, WindowsSink as PlatformSink};

/// Non-Windows builds have no Event Log; this sink is never constructed.
#[cfg(not(windows))]
pub struct PlatformSink;

#[cfg(not(windows))]
impl Sink for PlatformSink {
    fn write(&self, _kind: Kind, _id: u32, _message: &str) {}
}

/// The tracing layer for the Windows Event Log, or `None` where there is no Event Log.
pub fn layer() -> Option<EventLogLayer<PlatformSink>> {
    #[cfg(windows)]
    {
        let sink = sys::WindowsSink::open()?;
        LAYER_ACTIVE.store(true, Ordering::Relaxed);
        Some(EventLogLayer::new(sink))
    }
    #[cfg(not(windows))]
    None
}

/// Write one event directly, bypassing tracing (best effort, for failures that happen
/// before logging is initialised).
pub fn report(kind: Kind, id: u32, message: &str) {
    #[cfg(windows)]
    if let Some(sink) = sys::WindowsSink::open() {
        sink.write(kind, id, message);
    }
    #[cfg(not(windows))]
    let _ = (kind, id, message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<(Kind, u32, String)>>>);

    impl Sink for Recorder {
        fn write(&self, kind: Kind, id: u32, message: &str) {
            self.0.lock().push((kind, id, message.to_string()));
        }
    }

    fn capture(f: impl FnOnce()) -> Vec<(Kind, u32, String)> {
        let rec = Recorder::default();
        let subscriber = tracing_subscriber::registry().with(EventLogLayer::new(rec.clone()));
        tracing::subscriber::with_default(subscriber, f);
        let out = rec.0.lock().clone();
        out
    }

    #[test]
    fn tagged_events_are_forwarded_with_fields() {
        let events = capture(|| {
            tracing::info!(event_id = id::STARTED, version = "1.2.3", "Promailer started");
        });
        assert_eq!(events.len(), 1);
        let (kind, eid, msg) = &events[0];
        assert_eq!((*kind, *eid), (Kind::Information, id::STARTED));
        assert_eq!(msg, "Promailer started\r\n\r\nversion: 1.2.3");
    }

    #[test]
    fn untagged_info_warnings_and_transcripts_are_not_forwarded() {
        let events = capture(|| {
            tracing::info!("routine");
            tracing::warn!(ip = "203.0.113.9", "SMTP authentication failed");
            tracing::error!(target: "smtp_protocol", "transcript line");
            tracing::error!(target: "delivery", "delivery line");
        });
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn untagged_errors_are_rate_limited() {
        let events = capture(|| {
            for i in 0..(ERROR_BURST + 10) {
                tracing::error!(n = i, "boom");
            }
        });
        assert_eq!(events.len() as u32, ERROR_BURST + 1);
        assert!(events[..ERROR_BURST as usize].iter().all(|e| e.0 == Kind::Error && e.1 == id::ERROR));
        let last = events.last().unwrap();
        assert_eq!((last.0, last.1), (Kind::Warning, id::SUPPRESSED));
    }

    #[test]
    fn rate_limit_window_resets() {
        let layer = EventLogLayer::new(Recorder::default());
        let t0 = Instant::now();
        for _ in 0..ERROR_BURST {
            assert!(matches!(layer.admit_untagged_error(t0), Admit::Forward));
        }
        assert!(matches!(layer.admit_untagged_error(t0), Admit::Announce));
        assert!(matches!(layer.admit_untagged_error(t0), Admit::Drop));
        assert!(matches!(layer.admit_untagged_error(t0 + ERROR_WINDOW), Admit::Forward));
    }

    #[test]
    fn tagged_errors_bypass_the_rate_limit() {
        let events = capture(|| {
            for _ in 0..(ERROR_BURST + 5) {
                tracing::error!("noise");
            }
            tracing::error!(event_id = id::FATAL, "fatal");
        });
        assert_eq!(events.last().map(|e| e.1), Some(id::FATAL));
    }
}
