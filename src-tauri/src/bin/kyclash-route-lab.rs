#[cfg(target_os = "macos")]
mod macos {
    use std::{
        env, fs,
        fs::{File, OpenOptions},
        os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        path::{Path, PathBuf},
        process::Command,
    };

    use app_lib::networking::{
        FileRouteJournal, MacOsReadOnlyRoutePlatform, MacOsRouteLabPlatform, NetworkErrorCode, RouteOrchestrator,
        RoutePlatform as _, RouteSpec,
    };

    const CONFIRMATION_VARIABLE: &str = "KYCLASH_ROUTE_LAB_CONFIRM";
    const CONFIRMATION_VALUE: &str = "authorized-disposable-macos-host";
    const JOURNAL_DIRECTORY: &str = "/var/tmp/net.kysion.kyclash-route-lab";
    const DESTINATION: &str = "192.0.2.0/24";
    const INTERFACE: &str = "lo0";

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Mode {
        Cycle,
        AbortAfterApply,
        LeaveForRecovery,
        Recover,
    }

    impl Mode {
        fn parse(arguments: &[String]) -> Result<Option<Self>, NetworkErrorCode> {
            match arguments {
                [argument] if argument == "--help" || argument == "-h" => Ok(None),
                [argument] if argument == "cycle" => Ok(Some(Self::Cycle)),
                [argument] if argument == "abort-after-apply" => Ok(Some(Self::AbortAfterApply)),
                [argument] if argument == "leave-for-recovery" => Ok(Some(Self::LeaveForRecovery)),
                [argument] if argument == "recover" => Ok(Some(Self::Recover)),
                _ => Err(NetworkErrorCode::InvalidConfiguration),
            }
        }
    }

    struct LabLock {
        _file: File,
    }

    impl LabLock {
        fn acquire() -> Result<Self, NetworkErrorCode> {
            let path = Path::new(JOURNAL_DIRECTORY).join("lab.lock");
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true).mode(0o600);
            let file = options.open(&path).map_err(|_| NetworkErrorCode::PermissionDenied)?;
            file.try_lock().map_err(|_| NetworkErrorCode::PermissionDenied)?;
            Ok(Self { _file: file })
        }
    }

    fn effective_uid_is_root() -> Result<bool, NetworkErrorCode> {
        let output = Command::new("/usr/bin/id")
            .arg("-u")
            .output()
            .map_err(|_| NetworkErrorCode::PermissionDenied)?;
        Ok(output.status.success() && output.stdout == b"0\n")
    }

    fn prepare_lab_directory() -> Result<(), NetworkErrorCode> {
        if !effective_uid_is_root()? {
            return Err(NetworkErrorCode::PermissionDenied);
        }
        let path = Path::new(JOURNAL_DIRECTORY);
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.file_type().is_dir() || metadata.uid() != 0 => {
                return Err(NetworkErrorCode::PermissionDenied);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|_| NetworkErrorCode::PermissionDenied)?;
            }
            Err(_) => return Err(NetworkErrorCode::PermissionDenied),
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| NetworkErrorCode::PermissionDenied)
    }

    fn route() -> RouteSpec {
        RouteSpec {
            destination: DESTINATION.into(),
            interface: INTERFACE.into(),
        }
    }

    fn route_present() -> Result<bool, NetworkErrorCode> {
        Ok(MacOsReadOnlyRoutePlatform::default()
            .list_routes()?
            .iter()
            .any(|existing| existing.destination == DESTINATION && existing.interface == INTERFACE))
    }

    fn journal_path() -> PathBuf {
        Path::new(JOURNAL_DIRECTORY).join("route-journal.json")
    }

    fn run_mode(mode: Mode) -> Result<(), NetworkErrorCode> {
        if env::var(CONFIRMATION_VARIABLE).as_deref() != Ok(CONFIRMATION_VALUE) {
            return Err(NetworkErrorCode::PermissionDenied);
        }
        prepare_lab_directory()?;
        let _lock = LabLock::acquire()?;
        let platform = MacOsRouteLabPlatform::default();
        let journal = FileRouteJournal::new(journal_path());
        let mut orchestrator = RouteOrchestrator::new(platform, journal);

        match mode {
            Mode::Cycle => {
                orchestrator.recover_stale()?;
                if route_present()? {
                    return Err(NetworkErrorCode::RouteConflict);
                }
                orchestrator.apply("route-lab.cycle".into(), "route-lab".into(), vec![route()])?;
                let verification = if route_present()? {
                    Ok(())
                } else {
                    Err(NetworkErrorCode::RouteDiscoveryFailed)
                };
                let rollback = orchestrator.rollback("route-lab.cycle");
                verification?;
                rollback?;
                if route_present()? {
                    return Err(NetworkErrorCode::RouteRollbackFailed);
                }
            }
            Mode::AbortAfterApply | Mode::LeaveForRecovery => {
                orchestrator.recover_stale()?;
                if route_present()? {
                    return Err(NetworkErrorCode::RouteConflict);
                }
                orchestrator.apply("route-lab.recovery".into(), "route-lab".into(), vec![route()])?;
                if !route_present()? {
                    return Err(NetworkErrorCode::RouteDiscoveryFailed);
                }
                if mode == Mode::AbortAfterApply {
                    std::process::abort();
                }
            }
            Mode::Recover => {
                orchestrator.recover_stale()?;
                if route_present()? {
                    return Err(NetworkErrorCode::RouteRollbackFailed);
                }
            }
        }
        Ok(())
    }

    fn usage() {
        println!(
            "Usage: kyclash-route-lab <cycle|abort-after-apply|leave-for-recovery|recover>\n\
             Fixed mutation: {DESTINATION} via {INTERFACE}. Requires root and \
             {CONFIRMATION_VARIABLE}={CONFIRMATION_VALUE}. Disposable macOS hosts only."
        );
    }

    pub fn main() {
        let arguments = env::args().skip(1).collect::<Vec<_>>();
        match Mode::parse(&arguments) {
            Ok(None) => usage(),
            Ok(Some(mode)) => match run_mode(mode) {
                Ok(()) => println!("KyClash route lab completed: {mode:?}"),
                Err(error) => {
                    eprintln!("KyClash route lab failed: {error:?}");
                    std::process::exit(1);
                }
            },
            Err(_) => {
                usage();
                std::process::exit(2);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accepts_only_fixed_modes() {
            assert_eq!(Mode::parse(&["cycle".into()]), Ok(Some(Mode::Cycle)));
            assert_eq!(
                Mode::parse(&["abort-after-apply".into()]),
                Ok(Some(Mode::AbortAfterApply))
            );
            assert_eq!(
                Mode::parse(&["leave-for-recovery".into()]),
                Ok(Some(Mode::LeaveForRecovery))
            );
            assert_eq!(Mode::parse(&["recover".into()]), Ok(Some(Mode::Recover)));
            assert_eq!(Mode::parse(&["--help".into()]), Ok(None));
            assert_eq!(
                Mode::parse(&["cycle".into(), "192.168.0.0/16".into()]),
                Err(NetworkErrorCode::InvalidConfiguration)
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    macos::main();
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("KyClash route lab is available only on macOS");
    std::process::exit(1);
}
