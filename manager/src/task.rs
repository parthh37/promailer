//! Run blocking API calls off the UI thread.
//!
//! egui redraws the whole UI every frame, so nothing slow may run inside
//! `ui()`. A `Task` runs a closure on its own thread, wakes the UI when it
//! finishes, and is polled once per frame.

use std::sync::mpsc;

pub struct Task<T> {
    rx: mpsc::Receiver<T>,
}

impl<T: Send + 'static> Task<T> {
    pub fn spawn(ctx: &egui::Context, f: impl FnOnce() -> T + Send + 'static) -> Self {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f());
            ctx.request_repaint();
        });
        Self { rx }
    }
}

/// Poll a task slot; when the result is ready, take it and clear the slot.
pub fn poll<T>(slot: &mut Option<Task<T>>) -> Option<T> {
    let task = slot.as_ref()?;
    match task.rx.try_recv() {
        Ok(v) => {
            *slot = None;
            Some(v)
        }
        Err(mpsc::TryRecvError::Empty) => None,
        // The worker panicked; drop the slot so the caller can try again.
        Err(mpsc::TryRecvError::Disconnected) => {
            *slot = None;
            None
        }
    }
}
