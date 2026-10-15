//! Promailer tray - a notification-area icon showing whether the local
//! Promailer service is running, with shortcuts to manage it.
//!
//! Started at sign-in by the installer (`--autostart`). Reads only public
//! information: the service state from the Service Control Manager and the
//! unauthenticated `/health` endpoint. Actions that need administrator rights
//! (start/stop, editing the configuration) go through a UAC prompt.

// No console window on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
#[path = "../../assets/icon.rs"]
mod icon;
#[cfg_attr(not(windows), allow(dead_code))]
mod status;
#[cfg(windows)]
mod tray;

fn main() {
    if let Some(dir) = promailer_crash::user_dir() {
        promailer_crash::install("promailer-tray", dir);
    }
    #[cfg(windows)]
    tray::run();
    #[cfg(not(windows))]
    eprintln!("promailer-tray is only available on Windows");
}
