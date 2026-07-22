use crate::core::{CoreManager, handle, manager::RunningMode};
use anyhow::Result;
use async_trait::async_trait;
use clash_verge_logging::{Type, logging};
use once_cell::sync::OnceCell;
#[cfg(unix)]
use std::iter;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt as _;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(unix)]
use std::path::{Component, Path};
use std::{fs, path::PathBuf};
use tauri::Manager as _;

#[cfg(not(feature = "verge-dev"))]
pub static APP_ID: &str = "net.kysion.kyclash";
#[cfg(not(feature = "verge-dev"))]
pub static BACKUP_DIR: &str = "clash-verge-rev-backup";

#[cfg(feature = "verge-dev")]
pub static APP_ID: &str = "net.kysion.kyclash.dev";
#[cfg(feature = "verge-dev")]
pub static BACKUP_DIR: &str = "clash-verge-rev-backup-dev";

pub static PORTABLE_FLAG: OnceCell<bool> = OnceCell::new();

pub static CLASH_CONFIG: &str = "config.yaml";
pub static VERGE_CONFIG: &str = "verge.yaml";
pub static PROFILE_YAML: &str = "profiles.yaml";

/// init portable flag
pub fn init_portable_flag() -> Result<()> {
    use tauri::utils::platform::current_exe;

    let app_exe = current_exe()?;
    if let Some(dir) = app_exe.parent() {
        let dir = PathBuf::from(dir).join(".config/PORTABLE");

        if dir.exists() {
            PORTABLE_FLAG.get_or_init(|| true);
        }
    }
    PORTABLE_FLAG.get_or_init(|| false);
    Ok(())
}

/// get the verge app home dir
pub fn app_home_dir() -> Result<PathBuf> {
    use tauri::utils::platform::current_exe;

    let flag = PORTABLE_FLAG.get().unwrap_or(&false);
    if *flag {
        let app_exe = current_exe()?;
        let app_exe = dunce::canonicalize(app_exe)?;
        let app_dir = app_exe
            .parent()
            .ok_or_else(|| anyhow::anyhow!("failed to get the portable app dir"))?;
        return Ok(PathBuf::from(app_dir).join(".config").join(APP_ID));
    }

    // 避免在Handle未初始化时崩溃
    let app_handle = handle::Handle::app_handle();

    match app_handle.path().data_dir() {
        Ok(dir) => Ok(dir.join(APP_ID)),
        Err(e) => {
            logging!(error, Type::File, "Failed to get the app home directory: {e}");
            Err(anyhow::anyhow!("Failed to get the app homedirectory"))
        }
    }
}

/// get the resources dir
pub fn app_resources_dir() -> Result<PathBuf> {
    // 避免在Handle未初始化时崩溃
    let app_handle = handle::Handle::app_handle();

    match app_handle.path().resource_dir() {
        Ok(dir) => Ok(dir.join("resources")),
        Err(e) => {
            logging!(error, Type::File, "Failed to get the resource directory: {e}");
            Err(anyhow::anyhow!("Failed to get the resource directory"))
        }
    }
}

/// profiles dir
pub fn app_profiles_dir() -> Result<PathBuf> {
    Ok(app_home_dir()?.join("profiles"))
}

/// icons dir
pub fn app_icons_dir() -> Result<PathBuf> {
    Ok(app_home_dir()?.join("icons"))
}

pub fn find_target_icons(target: &str) -> Result<Option<String>> {
    let icons_dir = app_icons_dir()?;
    let icon_path = fs::read_dir(&icons_dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .find(|path| {
            let prefix_matches = path
                .file_prefix()
                .and_then(|p| p.to_str())
                .is_some_and(|prefix| prefix.starts_with(target));
            let ext_matches = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("ico") || ext.eq_ignore_ascii_case("png"));
            prefix_matches && ext_matches
        });

    icon_path.map(|path| path_to_str(&path).map(|s| s.into())).transpose()
}

/// logs dir
pub fn app_logs_dir() -> Result<PathBuf> {
    Ok(app_home_dir()?.join("logs"))
}

/// service logs dir
#[cfg(target_os = "macos")]
pub fn service_logs_root_dir() -> Result<PathBuf> {
    Ok(app_home_dir()?.join("service-logs"))
}

/// service logs dir
#[cfg(not(target_os = "macos"))]
pub fn service_logs_root_dir() -> Result<PathBuf> {
    app_logs_dir()
}

// latest verge log
pub fn app_latest_log() -> Result<PathBuf> {
    Ok(app_logs_dir()?.join("latest.log"))
}

/// local backups dir
pub fn local_backup_dir() -> Result<PathBuf> {
    let dir = app_home_dir()?.join(BACKUP_DIR);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn clash_path() -> Result<PathBuf> {
    Ok(app_home_dir()?.join(CLASH_CONFIG))
}

pub fn verge_path() -> Result<PathBuf> {
    Ok(app_home_dir()?.join(VERGE_CONFIG))
}

pub fn profiles_path() -> Result<PathBuf> {
    Ok(app_home_dir()?.join(PROFILE_YAML))
}

#[cfg(target_os = "macos")]
pub fn service_path() -> Result<PathBuf> {
    let res_dir = app_resources_dir()?;
    Ok(res_dir.join("clash-verge-service"))
}

#[cfg(windows)]
pub fn service_path() -> Result<PathBuf> {
    let res_dir = app_resources_dir()?;
    Ok(res_dir.join("clash-verge-service.exe"))
}

pub fn sidecar_log_dir() -> Result<PathBuf> {
    let log_dir = app_logs_dir()?.join("sidecar");
    let _ = std::fs::create_dir_all(&log_dir);

    Ok(log_dir)
}

pub fn service_log_dir() -> Result<PathBuf> {
    let log_dir = service_logs_root_dir()?.join("service");
    let _ = std::fs::create_dir_all(&log_dir);

    Ok(log_dir)
}

pub fn clash_latest_log() -> Result<PathBuf> {
    match *CoreManager::global().get_running_mode() {
        RunningMode::Service => Ok(service_log_dir()?.join("service_latest.log")),
        RunningMode::Sidecar | RunningMode::NotRunning => Ok(sidecar_log_dir()?.join("sidecar_latest.log")),
    }
}

pub fn path_to_str(path: &PathBuf) -> Result<&str> {
    let path_str = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("failed to get path from {:?}", path))?;
    Ok(path_str)
}

pub fn get_encryption_key() -> Result<Vec<u8>> {
    let app_dir = app_home_dir()?;
    let key_path = app_dir.join(".encryption_key");

    if key_path.exists() {
        // Read existing key
        fs::read(&key_path).map_err(|e| anyhow::anyhow!("Failed to read encryption key: {}", e))
    } else {
        // Generate and save new key
        let mut key = vec![0u8; 32];
        getrandom::fill(&mut key)?;

        // Ensure directory exists
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|e| anyhow::anyhow!("Failed to create key directory: {}", e))?;
        }
        // Save key
        fs::write(&key_path, &key).map_err(|e| anyhow::anyhow!("Failed to save encryption key: {}", e))?;
        Ok(key)
    }
}

#[cfg(unix)]
const IPC_PATH_ENV: &str = "KYCLASH_IPC_PATH";

#[cfg(unix)]
pub fn ensure_mihomo_safe_dir() -> Option<PathBuf> {
    iter::once("/tmp")
        .map(PathBuf::from)
        .find(|path| path.exists())
        .or_else(|| {
            std::env::var_os("HOME").and_then(|home| {
                let home_config = PathBuf::from(home).join(".config");
                if home_config.exists() || fs::create_dir_all(&home_config).is_ok() {
                    Some(home_config)
                } else {
                    logging!(error, Type::File, "Failed to create safe directory: {home_config:?}");
                    None
                }
            })
        })
}

#[cfg(unix)]
pub fn ipc_path() -> Result<PathBuf> {
    if let Ok(override_path) = std::env::var(IPC_PATH_ENV) {
        return validate_ipc_override(&override_path);
    }
    ensure_mihomo_safe_dir()
        .map(|base_dir| base_dir.join("verge").join("verge-mihomo.sock"))
        .or_else(|| {
            app_home_dir()
                .ok()
                .map(|dir| dir.join("verge").join("verge-mihomo.sock"))
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to determine ipc path"))
}

#[cfg(unix)]
fn validate_ipc_override(value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    if value.is_empty() || value.len() > 100 || !path.is_absolute() {
        return Err(anyhow::anyhow!("{IPC_PATH_ENV} must be an absolute Unix socket path"));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(anyhow::anyhow!(
            "{IPC_PATH_ENV} must not contain relative path components"
        ));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("{IPC_PATH_ENV} must use an ASCII socket filename"))?;
    if file_name.len() <= ".sock".len()
        || !file_name.ends_with(".sock")
        || !file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(anyhow::anyhow!("{IPC_PATH_ENV} has an unsafe socket filename"));
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty() && *parent != Path::new("/"))
        .ok_or_else(|| anyhow::anyhow!("{IPC_PATH_ENV} must have a dedicated parent directory"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| anyhow::anyhow!("{IPC_PATH_ENV} parent is unavailable: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!("{IPC_PATH_ENV} parent must be a real directory"));
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(anyhow::anyhow!(
            "{IPC_PATH_ENV} parent must not be group/world writable"
        ));
    }

    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => {}
        Ok(_) => return Err(anyhow::anyhow!("{IPC_PATH_ENV} target must be a Unix socket")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(anyhow::anyhow!("{IPC_PATH_ENV} target is unavailable: {error}")),
    }
    Ok(path)
}

#[cfg(target_os = "windows")]
pub fn ipc_path() -> Result<PathBuf> {
    Ok(PathBuf::from(r"\\.\pipe\verge-mihomo"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::validate_ipc_override;
    use std::{fs, process};

    fn candidate(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("kyclash-ipc-{}-{name}", process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn ipc_override_accepts_existing_parent_and_safe_socket_name() -> anyhow::Result<()> {
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("dev.sock");
        let path = path.to_string_lossy().into_owned();
        assert_eq!(validate_ipc_override(&path)?.to_string_lossy(), path);
        Ok(())
    }

    #[test]
    fn ipc_override_rejects_relative_traversal_and_unsafe_names() {
        assert!(validate_ipc_override("target/kyclash.sock").is_err());
        assert!(validate_ipc_override(&candidate("../escape.sock")).is_err());
        assert!(validate_ipc_override(&candidate("dev.sock;rm")).is_err());
        assert!(validate_ipc_override(&candidate("dev.txt")).is_err());
    }

    #[test]
    fn ipc_override_rejects_missing_parent_and_non_socket_target() -> anyhow::Result<()> {
        let missing_parent = std::env::temp_dir()
            .join(format!("kyclash-ipc-missing-{}", process::id()))
            .join("dev.sock");
        assert!(validate_ipc_override(&missing_parent.to_string_lossy()).is_err());

        let parent = tempfile::tempdir()?;
        let regular_file = parent.path().join(format!("kyclash-ipc-file-{}.sock", process::id()));
        fs::write(&regular_file, b"not a socket")?;
        assert!(validate_ipc_override(&regular_file.to_string_lossy()).is_err());
        Ok(())
    }
}
#[async_trait]
pub trait PathBufExec {
    async fn remove_if_exists(&self) -> Result<()>;
}

#[async_trait]
impl PathBufExec for PathBuf {
    async fn remove_if_exists(&self) -> Result<()> {
        if self.exists() {
            tokio::fs::remove_file(self).await?;
            logging!(info, Type::File, "Removed file: {:?}", self);
        }
        Ok(())
    }
}
