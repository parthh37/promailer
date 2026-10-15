//! In-process resilience: everything that turns a silent failure into a restart.
//!
//! The Service Control Manager restarts Promailer when the process exits with an error
//! or dies (see `service::apply_settings`). It cannot see a process that is alive but
//! no longer working, so this module makes sure that never lasts:
//!
//! * [`install_panic_hook`] records every panic in promailer.log and the Event Log
//!   (a service has no console, so the default hook's message would be lost).
//! * [`Supervisor`] runs the long-lived subsystems (listeners, delivery scheduler, ...).
//!   If one ends or panics while the server is not shutting down, the server stops
//!   with an error and the SCM starts a fresh process.
//! * [`Watchdog`] ends the process when the async runtime stops responding
//!   (deadlock, runaway blocking code), which the SCM then treats as a crash.

use crate::app::App;
use crate::eventlog;
use futures::FutureExt;
use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Text of a panic payload (`panic!("...")` produces `&str` or `String`).
pub fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

/// Log panics through tracing, then run the default hook (stderr in console mode).
///
/// Untagged on purpose: a panic in an SMTP session may be triggered by remote input, so
/// it goes through the Event Log's error rate limit like any other error.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        tracing::error!(
            thread = thread.name().unwrap_or("unnamed"),
            location = %info.location().map_or_else(|| "unknown".into(), |l| l.to_string()),
            "internal error (panic): {}",
            panic_message(info.payload())
        );
        default(info);
    }));
}

/// Spawns subsystems and reports the first one that stops before shutdown was requested.
pub struct Supervisor {
    shutdown: watch::Receiver<bool>,
    faults: mpsc::UnboundedSender<String>,
}

impl Supervisor {
    /// `shutdown` is the server's shutdown flag; the receiver yields one message per failed subsystem.
    pub fn new(shutdown: watch::Receiver<bool>) -> (Self, mpsc::UnboundedReceiver<String>) {
        let (faults, rx) = mpsc::unbounded_channel();
        (Self { shutdown, faults }, rx)
    }

    pub fn spawn<F>(&self, name: impl Into<String>, fut: F) -> JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let shutdown = self.shutdown.clone();
        let faults = self.faults.clone();
        tokio::spawn(async move {
            let res = AssertUnwindSafe(fut).catch_unwind().await;
            if *shutdown.borrow() {
                return;
            }
            let reason = match res {
                Ok(()) => format!("{name} stopped unexpectedly"),
                Err(payload) => format!("{name} failed with an internal error: {}", panic_message(payload.as_ref())),
            };
            let _ = faults.send(reason);
        })
    }
}

/// How often the runtime proves it is alive, and how often the watchdog checks.
const BEAT_EVERY: Duration = Duration::from_secs(5);
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// Process exit code when the watchdog ends a hung process.
const EXIT_HUNG: u32 = 3;

struct Shared {
    origin: Instant,
    /// Milliseconds after `origin` of the last heartbeat.
    last_beat: AtomicU64,
    armed: AtomicBool,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// Ends the process if the async runtime stops responding. Disarmed when dropped.
pub struct Watchdog {
    shared: Arc<Shared>,
    heartbeat: JoinHandle<()>,
}

impl Watchdog {
    pub fn start(app: Arc<App>) -> std::io::Result<Self> {
        let shared =
            Arc::new(Shared { origin: Instant::now(), last_beat: AtomicU64::new(0), armed: AtomicBool::new(true) });
        let beat = shared.clone();
        let heartbeat = tokio::spawn(async move {
            loop {
                // Taking the queue lock means a deadlock on it also stops the heartbeat.
                let _ = app.queue.len();
                beat.last_beat.store(beat.now_ms(), Ordering::Relaxed);
                tokio::time::sleep(BEAT_EVERY).await;
            }
        });
        let watched = shared.clone();
        // A plain OS thread: it must keep running when every runtime worker is stuck.
        std::thread::Builder::new().name("promailer-watchdog".into()).spawn(move || watch(&watched))?;
        Ok(Self { shared, heartbeat })
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.shared.armed.store(false, Ordering::Relaxed);
        self.heartbeat.abort();
    }
}

fn watch(shared: &Shared) {
    loop {
        let before = Instant::now();
        std::thread::sleep(CHECK_EVERY);
        if !shared.armed.load(Ordering::Relaxed) {
            return;
        }
        let overslept = before.elapsed().saturating_sub(CHECK_EVERY);
        let age = Duration::from_millis(shared.now_ms().saturating_sub(shared.last_beat.load(Ordering::Relaxed)));
        if is_hung(age, overslept) {
            let msg = format!(
                "Promailer stopped responding (no heartbeat for {} seconds). Ending the process so that \
                 Windows restarts the service; queued mail is kept.",
                age.as_secs()
            );
            eventlog::report(eventlog::Kind::Error, eventlog::id::HUNG, &msg);
            eprintln!("{msg}");
            terminate(EXIT_HUNG);
        }
    }
}

/// Decide whether the runtime is hung and the process should be ended.
///
/// * `heartbeat_age`: time since the async runtime last proved it was alive
///   (it beats every `BEAT_EVERY`, so a healthy value is 0-5 seconds).
/// * `overslept`: how much longer than `CHECK_EVERY` the watchdog thread itself slept.
///   A large value means the whole machine or process was paused (sleep/hibernate,
///   VM snapshot or live migration, a debugger break) rather than Promailer hanging,
///   and the heartbeat has not had a chance to catch up yet.
fn is_hung(heartbeat_age: Duration, overslept: Duration) -> bool {
    // Long enough that a heavily loaded server or a large queue scan is never mistaken for a hang.
    const HANG_TIMEOUT: Duration = Duration::from_secs(120);
    // Scheduler jitter is far below this; anything above means the machine itself was paused.
    const PAUSE_TOLERANCE: Duration = Duration::from_secs(10);
    overslept < PAUSE_TOLERANCE && heartbeat_age > HANG_TIMEOUT
}

/// End the process at once: no destructors, atexit handlers or DLL detach notifications,
/// any of which could block on a lock held by the stuck code.
fn terminate(code: u32) -> ! {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
        TerminateProcess(GetCurrentProcess(), code);
    }
    #[cfg(not(windows))]
    let _ = code;
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn next_fault(rx: &mut mpsc::UnboundedReceiver<String>) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.ok().flatten()
    }

    #[tokio::test]
    async fn panicking_subsystem_is_reported() {
        let (_tx, shutdown) = watch::channel(false);
        let (sup, mut faults) = Supervisor::new(shutdown);
        sup.spawn("delivery scheduler", async { panic!("boom") }).await.unwrap();
        let fault = next_fault(&mut faults).await.expect("fault reported");
        assert!(fault.contains("delivery scheduler") && fault.contains("boom"), "{fault}");
    }

    #[tokio::test]
    async fn subsystem_returning_early_is_reported() {
        let (_tx, shutdown) = watch::channel(false);
        let (sup, mut faults) = Supervisor::new(shutdown);
        sup.spawn("SMTP listener 'default'", async {}).await.unwrap();
        let fault = next_fault(&mut faults).await.expect("fault reported");
        assert_eq!(fault, "SMTP listener 'default' stopped unexpectedly");
    }

    #[tokio::test]
    async fn subsystem_ending_during_shutdown_is_not_a_fault() {
        let (tx, shutdown) = watch::channel(false);
        let (sup, mut faults) = Supervisor::new(shutdown);
        tx.send(true).unwrap();
        sup.spawn("housekeeping", async {}).await.unwrap();
        drop(sup);
        assert_eq!(faults.recv().await, None);
    }

    #[test]
    fn hang_policy() {
        let secs = Duration::from_secs;
        // Healthy, or slow but within the timeout.
        assert!(!is_hung(secs(3), secs(0)));
        assert!(!is_hung(secs(110), secs(1)));
        // No heartbeat for over two minutes while the machine was running.
        assert!(is_hung(secs(180), secs(0)));
        // Same age right after sleep/hibernate or a VM pause: the heartbeat has not caught up yet.
        assert!(!is_hung(secs(3600), secs(3595)));
    }

    #[test]
    fn panic_message_handles_both_payload_types() {
        let s: Box<dyn Any + Send> = Box::new("static");
        let owned: Box<dyn Any + Send> = Box::new(String::from("owned"));
        let other: Box<dyn Any + Send> = Box::new(42u8);
        assert_eq!(panic_message(s.as_ref()), "static");
        assert_eq!(panic_message(owned.as_ref()), "owned");
        assert_eq!(panic_message(other.as_ref()), "non-string panic payload");
    }
}
