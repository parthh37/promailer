//! The notification-area icon and its menu (Windows).
//!
//! The UI thread runs a plain Win32 message loop (tray-icon needs one on the
//! thread that owns the icon). A worker thread polls the service every few
//! seconds and posts `WM_REFRESH` when the status changed; menu and icon
//! events are drained after every dispatched message.

use crate::icon;
use crate::status::{self, Level, Service, Snapshot};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::mpsc;
use std::time::Duration;
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
use windows_sys::Win32::System::Registry::{
    RegDeleteKeyValueW, RegGetValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_DWORD, RRF_RT_REG_DWORD,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, GetCurrentThreadId, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, ShellExecuteW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, GetSystemMetrics, PostQuitMessage, PostThreadMessageW, TranslateMessage, MSG,
    SM_CXSMICON, SW_HIDE, SW_SHOWNORMAL, WM_APP,
};

const POLL: Duration = Duration::from_secs(5);
const WM_REFRESH: u32 = WM_APP + 1;
const WEBSITE: &str = "https://parthh37.github.io/promailer/";
const SERVICE_NAME: &str = "Promailer";
/// Per-user opt-out of the all-users sign-in entry the installer creates.
const SETTINGS_KEY: &str = r"Software\Promailer\Tray";
const AUTOSTART_VALUE: &str = "Autostart";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Directory holding promailer.exe and promailer-manager.exe (next to this exe).
fn install_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_default()
}

fn config_path() -> String {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    format!(r"{base}\Promailer\promailer.toml")
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/// Open a file, folder, URL or program the way Explorer would.
fn open(file: &str, params: &str) {
    let (op, f, p) = (wide("open"), wide(file), wide(params));
    let params = if params.is_empty() { null() } else { p.as_ptr() };
    unsafe { ShellExecuteW(null_mut(), op.as_ptr(), f.as_ptr(), params, null(), SW_SHOWNORMAL) };
}

/// Run a program as administrator (UAC prompt) and wait for it to exit.
/// Returns false if it could not be started, e.g. the prompt was cancelled.
fn run_elevated(file: &str, params: &str, show: i32, wait: bool) -> bool {
    let (verb, f, p) = (wide("runas"), wide(file), wide(params));
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = if wait { SEE_MASK_NOCLOSEPROCESS } else { 0 };
    info.lpVerb = verb.as_ptr();
    info.lpFile = f.as_ptr();
    info.lpParameters = p.as_ptr();
    info.nShow = show;
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return false;
    }
    if wait && !info.hProcess.is_null() {
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            CloseHandle(info.hProcess);
        }
    }
    true
}

/// `promailer.exe service <action>` as administrator, off the UI thread; asks
/// the poller for a fresh status when it finishes.
fn service_action(action: &'static str, refresh: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let exe = install_dir().join("promailer.exe");
        run_elevated(&exe.to_string_lossy(), &format!("service {action}"), SW_HIDE, true);
        let _ = refresh.send(());
    });
}

/// Only one tray per user session.
fn first_instance() -> bool {
    let name = wide(r"Local\PromailerTray");
    let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    // The handle is deliberately kept open for the life of the process.
    !handle.is_null() && unsafe { GetLastError() } != ERROR_ALREADY_EXISTS
}

fn autostart_enabled() -> bool {
    let (key, value) = (wide(SETTINGS_KEY), wide(AUTOSTART_VALUE));
    let mut data: u32 = 1;
    let mut size = std::mem::size_of::<u32>() as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    // Missing value (the default) means enabled.
    rc != 0 || data != 0
}

fn set_autostart(enabled: bool) {
    let (key, value) = (wide(SETTINGS_KEY), wide(AUTOSTART_VALUE));
    unsafe {
        if enabled {
            RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), value.as_ptr());
        } else {
            let zero: u32 = 0;
            RegSetKeyValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                REG_DWORD,
                (&zero as *const u32).cast(),
                std::mem::size_of::<u32>() as u32,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Status polling
// ---------------------------------------------------------------------------

fn query_service() -> Service {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return Service::Unknown;
    };
    let svc = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(s) => s,
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
            return Service::NotInstalled
        }
        Err(_) => return Service::Unknown,
    };
    match svc.query_status().map(|s| s.current_state) {
        Ok(ServiceState::Running) => Service::Running,
        Ok(ServiceState::Stopped) => Service::Stopped,
        Ok(ServiceState::StartPending | ServiceState::ContinuePending) => Service::Starting,
        Ok(ServiceState::StopPending | ServiceState::PausePending) => Service::Stopping,
        Ok(ServiceState::Paused) => Service::Paused,
        Err(_) => Service::Unknown,
    }
}

/// Poll until the UI thread goes away; `refresh` forces an immediate poll.
fn spawn_poller(ui_thread: u32, tx: mpsc::Sender<Snapshot>, refresh: mpsc::Receiver<()>) {
    std::thread::spawn(move || {
        let mut last: Option<Snapshot> = None;
        loop {
            let snap = Snapshot { service: query_service(), health: status::probe_health(&status::local_api_url()) };
            if last.as_ref() != Some(&snap) {
                if tx.send(snap.clone()).is_err() {
                    return;
                }
                unsafe { PostThreadMessageW(ui_thread, WM_REFRESH, 0, 0) };
                last = Some(snap);
            }
            match refresh.recv_timeout(POLL) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

struct Items {
    status: MenuItem,
    detail: MenuItem,
    manager: MenuItem,
    start: MenuItem,
    stop: MenuItem,
    restart: MenuItem,
    config: MenuItem,
    event_log: MenuItem,
    services: MenuItem,
    report: MenuItem,
    website: MenuItem,
    autostart: CheckMenuItem,
    exit: MenuItem,
}

impl Items {
    fn new() -> Self {
        let item = |text: &str, enabled: bool| MenuItem::new(text, enabled, None);
        Self {
            status: item("Promailer: checking…", false),
            detail: item("", false),
            manager: item("Open Promailer Manager", true),
            start: item("Start service", false),
            stop: item("Stop service", false),
            restart: item("Restart service", false),
            config: item("Edit configuration…", true),
            event_log: item("View Event Log", true),
            services: item("Open Services", true),
            report: item("Report a problem…", true),
            website: item("Promailer website", true),
            autostart: CheckMenuItem::new("Start at sign-in", true, autostart_enabled(), None),
            exit: item("Exit", true),
        }
    }

    fn menu(&self) -> Menu {
        let menu = Menu::new();
        let sep = PredefinedMenuItem::separator;
        let _ = menu.append_items(&[
            &self.status,
            &self.detail,
            &sep(),
            &self.manager,
            &sep(),
            &self.start,
            &self.stop,
            &self.restart,
            &sep(),
            &self.config,
            &self.event_log,
            &self.services,
            &sep(),
            &self.report,
            &self.website,
            &self.autostart,
            &sep(),
            &self.exit,
        ]);
        menu
    }

    fn apply(&self, s: &Snapshot) {
        self.status.set_text(format!("Promailer: {}", s.headline()));
        self.detail.set_text(s.detail().unwrap_or_else(|| "No status from the management API".into()));
        let installed = !matches!(s.service, Service::NotInstalled | Service::Unknown);
        self.start.set_enabled(s.can_start());
        self.stop.set_enabled(s.can_stop());
        self.restart.set_enabled(installed && s.service != Service::Starting && s.service != Service::Stopping);
    }
}

struct Icons {
    ok: Icon,
    warning: Icon,
    down: Icon,
    unknown: Icon,
}

impl Icons {
    fn new() -> Self {
        // Small-icon size for the current DPI (the manifest makes the process DPI aware).
        let size = (unsafe { GetSystemMetrics(SM_CXSMICON) }).clamp(16, 64) as u32;
        let make = |c| Icon::from_rgba(icon::rgba(size, Some(c)), size, size).expect("valid icon");
        Self { ok: make(icon::GREEN), warning: make(icon::AMBER), down: make(icon::RED), unknown: make(icon::GREY) }
    }

    fn for_level(&self, level: Level) -> Icon {
        match level {
            Level::Ok => self.ok.clone(),
            Level::Warning => self.warning.clone(),
            Level::Down => self.down.clone(),
            Level::Unknown => self.unknown.clone(),
        }
    }
}

enum Next {
    Continue,
    Exit,
}

fn handle_menu(id: &MenuId, items: &Items, refresh: &mpsc::Sender<()>) -> Next {
    let manager = || open(&install_dir().join("promailer-manager.exe").to_string_lossy(), "");
    if id == items.manager.id() {
        manager();
    } else if id == items.start.id() {
        service_action("start", refresh.clone());
    } else if id == items.stop.id() {
        service_action("stop", refresh.clone());
    } else if id == items.restart.id() {
        service_action("restart", refresh.clone());
    } else if id == items.config.id() {
        // The data folder is restricted to administrators.
        run_elevated("notepad.exe", &format!("\"{}\"", config_path()), SW_SHOWNORMAL, false);
    } else if id == items.event_log.id() {
        open("eventvwr.msc", "/c:Application");
    } else if id == items.services.id() {
        open("services.msc", "");
    } else if id == items.report.id() {
        open(&promailer_crash::github::report_problem_url(promailer_crash::github::DEFAULT_REPO, "promailer-tray"), "");
    } else if id == items.website.id() {
        open(WEBSITE, "");
    } else if id == items.autostart.id() {
        set_autostart(items.autostart.is_checked());
    } else if id == items.exit.id() {
        return Next::Exit;
    }
    Next::Continue
}

pub fn run() {
    if !first_instance() {
        return;
    }
    if std::env::args().any(|a| a == "--autostart") && !autostart_enabled() {
        return;
    }

    let items = Items::new();
    let icons = Icons::new();
    let tray: TrayIcon = match TrayIconBuilder::new()
        .with_menu(Box::new(items.menu()))
        .with_menu_on_left_click(true)
        .with_tooltip("Promailer")
        .with_icon(icons.unknown.clone())
        .build()
    {
        Ok(t) => t,
        // No notification area (e.g. a session without Explorer): nothing to do.
        Err(_) => return,
    };

    let (status_tx, status_rx) = mpsc::channel();
    let (refresh_tx, refresh_rx) = mpsc::channel();
    // After the icon exists, so this thread already has a message queue to post to.
    spawn_poller(unsafe { GetCurrentThreadId() }, status_tx, refresh_rx);

    let mut msg: MSG = unsafe { std::mem::zeroed() };
    loop {
        let r = unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) };
        if r == 0 || r == -1 {
            break;
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        while let Ok(snap) = status_rx.try_recv() {
            items.apply(&snap);
            let _ = tray.set_icon(Some(icons.for_level(snap.level())));
            let _ = tray.set_tooltip(Some(snap.tooltip()));
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::DoubleClick { .. } = event {
                open(&install_dir().join("promailer-manager.exe").to_string_lossy(), "");
            }
        }
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if let Next::Exit = handle_menu(event.id(), &items, &refresh_tx) {
                unsafe { PostQuitMessage(0) };
            }
        }
    }
}
