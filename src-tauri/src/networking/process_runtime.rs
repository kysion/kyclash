#[cfg(unix)]
mod unix {
    use std::fs;
    use std::io::{BufRead as _, Write as _};
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::super::{
        NetworkErrorCode, SidecarHandshake, SidecarLaunchContext, SidecarProcessStatus, SidecarRuntime,
    };

    pub struct UnixSidecarRuntime {
        executable: PathBuf,
        runtime_dir: PathBuf,
        child: Option<Child>,
        socket_path: Option<PathBuf>,
        handshake_timeout: Duration,
    }

    impl UnixSidecarRuntime {
        pub const fn new(executable: PathBuf, runtime_dir: PathBuf) -> Self {
            Self {
                executable,
                runtime_dir,
                child: None,
                socket_path: None,
                handshake_timeout: Duration::from_secs(2),
            }
        }

        pub const fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
            self.handshake_timeout = timeout;
            self
        }

        fn prepare_listener(&mut self, instance_id: &str) -> Result<UnixListener, NetworkErrorCode> {
            fs::create_dir_all(&self.runtime_dir).map_err(|_| NetworkErrorCode::PermissionDenied)?;
            fs::set_permissions(&self.runtime_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| NetworkErrorCode::PermissionDenied)?;

            let socket_path = self.runtime_dir.join(format!("{instance_id}.sock"));
            remove_stale_socket(&socket_path)?;
            let listener = UnixListener::bind(&socket_path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            listener
                .set_nonblocking(true)
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            self.socket_path = Some(socket_path);
            Ok(listener)
        }

        fn receive_handshake(&mut self, listener: &UnixListener) -> Result<SidecarHandshake, NetworkErrorCode> {
            let deadline = Instant::now() + self.handshake_timeout;
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let mut line = String::new();
                        std::io::BufReader::new(stream)
                            .read_line(&mut line)
                            .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
                        return serde_json::from_str(&line).map_err(|_| NetworkErrorCode::AuthenticationFailed);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                        if self
                            .child
                            .as_mut()
                            .and_then(|child| child.try_wait().ok())
                            .flatten()
                            .is_some()
                        {
                            return Err(NetworkErrorCode::SidecarUnavailable);
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        return Err(NetworkErrorCode::OperationTimedOut);
                    }
                    Err(_) => return Err(NetworkErrorCode::SidecarUnavailable),
                }
            }
        }
    }

    impl SidecarRuntime for UnixSidecarRuntime {
        fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            if self.child.is_some() {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            let listener = self.prepare_listener(&context.instance_id)?;
            let socket_path = self.socket_path.as_ref().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            let mut child = Command::new(&self.executable)
                .arg(socket_path)
                .arg(&context.instance_id)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            let mut stdin = child.stdin.take().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            stdin
                .write_all(context.auth_token())
                .and_then(|()| stdin.write_all(b"\n"))
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            drop(stdin);
            self.child = Some(child);

            let result = self.receive_handshake(&listener);
            if result.is_err() {
                let _ = self.stop();
            }
            result
        }

        fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            let child = self.child.as_mut().ok_or(NetworkErrorCode::SidecarUnavailable)?;
            match child.try_wait().map_err(|_| NetworkErrorCode::SidecarUnavailable)? {
                None => Ok(SidecarProcessStatus::Running),
                Some(status) => {
                    self.child = None;
                    cleanup_socket(self.socket_path.take());
                    Ok(SidecarProcessStatus::Exited {
                        success: status.success(),
                    })
                }
            }
        }

        fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            if let Some(mut child) = self.child.take() {
                child.kill().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
                child.wait().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
            }
            cleanup_socket(self.socket_path.take());
            Ok(())
        }
    }

    impl Drop for UnixSidecarRuntime {
        fn drop(&mut self) {
            let _ = self.stop();
        }
    }

    fn remove_stale_socket(path: &Path) -> Result<(), NetworkErrorCode> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                fs::remove_file(path).map_err(|_| NetworkErrorCode::PermissionDenied)
            }
            Ok(_) => Err(NetworkErrorCode::PermissionDenied),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(NetworkErrorCode::PermissionDenied),
        }
    }

    fn cleanup_socket(path: Option<PathBuf>) {
        if let Some(path) = path {
            let _ = remove_stale_socket(&path);
        }
    }
}

#[cfg(unix)]
pub use unix::UnixSidecarRuntime;
