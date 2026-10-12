//! Windows service integration (install/uninstall/start/stop and the SCM entry point).
pub const SERVICE_NAME: &str = "Promailer";
pub const DISPLAY_NAME: &str = "Promailer SMTP Server";
pub const DESCRIPTION: &str = "High-performance outbound SMTP server with DKIM, queueing and delivery management.";

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::server::{self, Control};
    use anyhow::{Context, Result};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceDependency,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    /// Called by `promailer service run --config <path>` (the command line the SCM uses).
    pub fn run_dispatcher(config: PathBuf) -> Result<()> {
        let _ = CONFIG_PATH.set(config);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .context("failed to connect to the Service Control Manager (run this only via the service)")
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = run_service() {
            // Logging may not be initialised if config loading failed; leave a breadcrumb.
            let path = std::env::temp_dir().join("promailer-service-error.log");
            let _ = std::fs::write(&path, format!("{}: {e:#}\n", chrono::Utc::now()));
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
            // `sc control Promailer paramchange` reloads the configuration.
            ServiceControl::ParamChange => {
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
        set(ServiceState::StartPending, ServiceControlAccept::empty(), 0, Duration::from_secs(30));

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("promailer").build()?;
        let res = rt.block_on(server::run(&config, false, rx, || {
            set(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::PRESHUTDOWN | ServiceControlAccept::PARAM_CHANGE,
                0,
                Duration::default(),
            );
        }));
        set(ServiceState::StopPending, ServiceControlAccept::empty(), 0, Duration::from_secs(60));
        rt.shutdown_timeout(Duration::from_secs(10));
        drop(tx);
        // Non-zero exit code makes the SCM apply the configured recovery actions (restart).
        set(ServiceState::Stopped, ServiceControlAccept::empty(), if res.is_ok() { 0 } else { 1 }, Duration::default());
        res
    }

    pub fn install(config: &Path, account: Option<String>, password: Option<String>) -> Result<()> {
        let config =
            std::fs::canonicalize(config).with_context(|| format!("config file {} not found", config.display()))?;
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
        svc.set_failure_actions_on_non_crash_failures(true)?;
        println!("Service '{SERVICE_NAME}' installed (config: {}).", config.display());
        println!("Start it with: promailer service start");
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
        let svc = manager.open_service(SERVICE_NAME, ServiceAccess::PAUSE_CONTINUE)?;
        svc.notify(ServiceControl::ParamChange)?;
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
