//! Windows service integration (install/uninstall/start/stop and the SCM entry point).
pub const SERVICE_NAME: &str = "Promailer";
pub const DISPLAY_NAME: &str = "Promailer SMTP Server";
pub const DESCRIPTION: &str = "High-performance outbound SMTP server with DKIM, queueing and delivery management.";

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::eventlog;
    use crate::server::{self, Control};
    use anyhow::{Context, Result};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::Service;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceDependency,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType, UserEventCode,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

    /// User-defined control code that asks the service to reload (`sc control Promailer 200`).
    const RELOAD_CODE: u32 = 200;

    define_windows_service!(ffi_service_main, service_main);

    /// Called by `promailer service run --config <path>` (the command line the SCM uses).
    pub fn run_dispatcher(config: PathBuf) -> Result<()> {
        let _ = CONFIG_PATH.set(config);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("failed to connect to the Service Control Manager (run this only via the service)")
    }

    fn service_main(_args: Vec<OsString>) {
        // Errors before the service could report its status (run_service handles the rest).
        if let Err(e) = run_service() {
            report_failure(&e);
        }
    }

    /// Leave a breadcrumb file and, unless the tracing layer already logged the error
    /// (e.g. the configuration could not be loaded), an Event Log entry. Must run before
    /// SERVICE_STOPPED is reported: the SCM may end the process right after it.
    fn report_failure(e: &anyhow::Error) {
        let path = std::env::temp_dir().join("promailer-service-error.log");
        let _ = std::fs::write(&path, format!("{}: {e:#}\n", chrono::Utc::now()));
        if !eventlog::layer_active() {
            eventlog::report(eventlog::Kind::Error, eventlog::id::FATAL, &format!("Promailer could not start: {e:#}"));
        }
    }

    fn run_service() -> Result<()> {
        let config = CONFIG_PATH.get().cloned().context("config path not set")?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let handler_tx = tx.clone();
        let status_handle = service_control_handler::register(SERVICE_NAME, move |event| match event {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                let _ = handler_tx.send(Control::Stop);
                ServiceControlHandlerResult::NoError
            }
            // `sc control Promailer paramchange` (or user code 200) reloads the configuration.
            ServiceControl::ParamChange => {
                let _ = handler_tx.send(Control::Reload);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::UserEvent(code) if code.to_raw() == RELOAD_CODE => {
                let _ = handler_tx.send(Control::Reload);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

        let set = |state: ServiceState, accept: ServiceControlAccept, code: u32, wait: Duration| {
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(code),
                checkpoint: 0,
                wait_hint: wait,
                process_id: None,
            });
        };
        // Generous hint: recovering a very large queue from disk can take a while.
        set(ServiceState::StartPending, ServiceControlAccept::empty(), 0, Duration::from_secs(120));

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("promailer").build()?;
        // A panic must not unwind into the SCM's callback (that aborts the process without
        // a status report); turn it into an error so the failure is reported and restarted.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(server::run(&config, false, rx, || {
                set(
                    ServiceState::Running,
                    ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN | ServiceControlAccept::PARAM_CHANGE,
                    0,
                    Duration::default(),
                );
            }))
        }))
        .unwrap_or_else(|payload| {
            Err(anyhow::anyhow!("internal error: {}", crate::supervisor::panic_message(payload.as_ref())))
        });
        set(ServiceState::StopPending, ServiceControlAccept::empty(), 0, Duration::from_secs(60));
        rt.shutdown_timeout(Duration::from_secs(10));
        drop(tx);
        if let Err(e) = &res {
            report_failure(e);
        }
        // Non-zero exit code makes the SCM apply the configured recovery actions (restart).
        set(ServiceState::Stopped, ServiceControlAccept::empty(), if res.is_ok() { 0 } else { 1 }, Duration::default());
        Ok(())
    }

    pub fn install(config: &Path, account: Option<String>, password: Option<String>) -> Result<()> {
        // std::path::absolute (unlike canonicalize) avoids \\?\ verbatim paths in the service command line.
        let config = std::path::absolute(config)?;
        if !config.is_file() {
            anyhow::bail!("config file {} not found", config.display());
        }
        crate::config::Config::load(&config).context("refusing to install with an invalid configuration")?;
        let exe = std::env::current_exe()?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("cannot open Service Control Manager (run as Administrator)")?;
        let info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: DISPLAY_NAME.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec!["service".into(), "run".into(), "--config".into(), config.clone().into_os_string()],
            dependencies: vec![
                ServiceDependency::Service("Tcpip".into()),
                ServiceDependency::Service("Dnscache".into()),
            ],
            account_name: account.map(Into::into),
            account_password: password.map(Into::into),
        };
        let svc = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("creating service (already installed? use `promailer service uninstall` first)")?;
        apply_settings(&svc)?;
        if let Err(e) = eventlog::register_source(&std::env::current_exe()?) {
            eprintln!("warning: Event Log source not registered ({e:#}); events will show without descriptions");
        }
        println!("Service '{SERVICE_NAME}' installed (config: {}).", config.display());
        println!("Start it with: promailer service start");
        Ok(())
    }

    /// Settings applied after the service exists. Shared by `install` and by the MSI, whose
    /// own failure-action table cannot set restart actions (it opens the service without
    /// SERVICE_START access, which ChangeServiceConfig2 requires for SC_ACTION_RESTART).
    fn apply_settings(svc: &Service) -> Result<()> {
        svc.set_description(DESCRIPTION)?;
        let _ = svc.set_delayed_auto_start(true);
        let _ = svc.set_preshutdown_timeout(Duration::from_secs(60));
        // Recovery: restart after 5s, 30s, then every 60s; reset the counter after a day.
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
            ]),
        })?;
        // Also restart after a fatal error, which the service reports as a non-zero exit code.
        svc.set_failure_actions_on_non_crash_failures(true)?;
        Ok(())
    }

    /// Apply description, delayed start and recovery settings to an existing service.
    pub fn configure() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("cannot open Service Control Manager (run as Administrator)")?;
        let svc = manager
            .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("service not installed")?;
        apply_settings(&svc)?;
        println!("Service '{SERVICE_NAME}' configured.");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager
            .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
            .context("service not installed")?;
        if svc.query_status()?.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            for _ in 0..90 {
                if svc.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        svc.delete()?;
        if let Err(e) = eventlog::unregister_source() {
            eprintln!("warning: {e:#}");
        }
        println!("Service '{SERVICE_NAME}' removed. Queue and logs were kept.");
        Ok(())
    }

    pub fn start() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        svc.start::<&str>(&[])?;
        for _ in 0..30 {
            match svc.query_status()?.current_state {
                ServiceState::Running => {
                    println!("Service started.");
                    return Ok(());
                }
                ServiceState::Stopped => {
                    anyhow::bail!("service stopped during start-up; check the logs in the data directory")
                }
                _ => std::thread::sleep(Duration::from_secs(1)),
            }
        }
        anyhow::bail!("service did not report RUNNING within 30 seconds")
    }

    pub fn stop() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(SERVICE_NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        svc.stop()?;
        for _ in 0..90 {
            if svc.query_status()?.current_state == ServiceState::Stopped {
                println!("Service stopped.");
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        anyhow::bail!("service did not stop within 90 seconds")
    }

    pub fn reload() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = manager.open_service(SERVICE_NAME, ServiceAccess::USER_DEFINED_CONTROL)?;
        svc.notify(UserEventCode::from_raw(RELOAD_CODE).context("invalid reload control code")?)?;
        println!("Reload signal sent; see promailer log for the result.");
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{bail, Result};
    use std::path::{Path, PathBuf};

    const MSG: &str = "Windows service management is only available on Windows; use `promailer run` instead";

    pub fn run_dispatcher(_config: PathBuf) -> Result<()> {
        bail!(MSG)
    }
    pub fn install(_c: &Path, _a: Option<String>, _p: Option<String>) -> Result<()> {
        bail!(MSG)
    }
    pub fn uninstall() -> Result<()> {
        bail!(MSG)
    }
    pub fn configure() -> Result<()> {
        bail!(MSG)
    }
    pub fn start() -> Result<()> {
        bail!(MSG)
    }
    pub fn stop() -> Result<()> {
        bail!(MSG)
    }
    pub fn reload() -> Result<()> {
        bail!(MSG)
    }
}

pub use imp::*;
