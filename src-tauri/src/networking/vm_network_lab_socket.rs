//! Fixed Unix-socket launcher for the VM-backed real-utun networking lab.
//!
//! The guest-side harness owns WireGuard, the loopback carriers, the private
//! echo service, and Mihomo.  The App only transfers the protocol streams over
//! this exact socket.  No command, path, environment, route, or credential is
//! accepted from the UI.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::{NetworkErrorCode, SidecarProcessControl, StdioSidecarLauncher};

/// The only App-to-guest-harness endpoint accepted by this profile.
pub const VM_NETWORK_LAB_SOCKET_PATH: &str = "/var/run/net.kysion.kyclash.vm-network-lab.sock";

#[derive(Debug, Clone)]
pub struct VmNetworkLabSocketLauncher {
    socket_path: PathBuf,
    required_peer_uid: libc::uid_t,
}

impl Default for VmNetworkLabSocketLauncher {
    fn default() -> Self {
        Self::new()
    }
}

impl VmNetworkLabSocketLauncher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from(VM_NETWORK_LAB_SOCKET_PATH),
            required_peer_uid: 0,
        }
    }

    #[cfg(test)]
    const fn injected(socket_path: PathBuf, required_peer_uid: libc::uid_t) -> Self {
        Self {
            socket_path,
            required_peer_uid,
        }
    }

    fn validate_socket(&self) -> Result<(), NetworkErrorCode> {
        validate_socket_metadata(&self.socket_path)
    }
}

fn validate_socket_metadata(path: &Path) -> Result<(), NetworkErrorCode> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.uid() == 0
    {
        return Err(NetworkErrorCode::SidecarUnavailable);
    }
    Ok(())
}

fn socket_peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut credentials = std::mem::MaybeUninit::<libc::xucred>::zeroed();
    let mut length = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: credentials points to writable xucred storage and the stream
    // owns a valid descriptor for this bounded getsockopt call.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(std::mem::size_of::<libc::xucred>()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer credential size",
        ));
    }
    // SAFETY: getsockopt succeeded and returned the complete structure.
    let credentials = unsafe { credentials.assume_init() };
    if credentials.cr_version != libc::XUCRED_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid peer credential version",
        ));
    }
    Ok(credentials.cr_uid)
}

struct VmNetworkLabSocketControl {
    generation: u64,
    input: Option<UnixStream>,
    output: Option<UnixStream>,
    monitor: UnixStream,
}

impl SidecarProcessControl for VmNetworkLabSocketControl {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn try_wait_status(&mut self) -> io::Result<Option<bool>> {
        let mut byte = 0_u8;
        // SAFETY: byte is writable storage for one byte; MSG_PEEK and
        // MSG_DONTWAIT make this a non-consuming liveness probe.
        let result = unsafe {
            libc::recv(
                self.monitor.as_raw_fd(),
                (&raw mut byte).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if result > 0 {
            return Ok(None);
        }
        if result == 0 {
            return Ok(Some(true));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error)
        }
    }

    fn kill_owned(&mut self) -> io::Result<()> {
        match self.monitor.shutdown(std::net::Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.kind(), io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.input
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.output
            .take()
            .map(|stream| Box::new(stream) as Box<dyn Read + Send>)
    }
}

impl StdioSidecarLauncher for VmNetworkLabSocketLauncher {
    fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
        self.validate_socket()?;
        let input = UnixStream::connect(&self.socket_path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        if socket_peer_uid(&input).map_err(|_| NetworkErrorCode::SidecarUnavailable)? != self.required_peer_uid {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        let output = input.try_clone().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let monitor = input.try_clone().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        Ok(Box::new(VmNetworkLabSocketControl {
            generation,
            input: Some(input),
            output: Some(output),
            monitor,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;

    fn socket_fixture(
        mode: u32,
        server: impl FnOnce(UnixStream) + Send + 'static,
    ) -> anyhow::Result<(tempfile::TempDir, PathBuf, thread::JoinHandle<io::Result<()>>)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("vm-network-lab.sock");
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            server(stream);
            Ok(())
        });
        Ok((directory, path, handle))
    }

    #[test]
    fn fixed_launcher_transfers_stream_and_observes_eof() -> anyhow::Result<()> {
        let (directory, path, server) = socket_fixture(0o600, drop)?;
        let mut launcher = VmNetworkLabSocketLauncher::injected(path, unsafe { libc::geteuid() });
        let mut control = launcher
            .launch(11)
            .map_err(|error| anyhow::anyhow!("network lab launcher failed: {error:?}"))?;
        assert_eq!(control.generation(), 11);
        assert!(control.take_stdin().is_some());
        assert!(control.take_stdout().is_some());
        server
            .join()
            .map_err(|_| anyhow::anyhow!("network lab server thread panicked"))??;
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.try_wait_status()? != Some(true) {
            assert!(Instant::now() < deadline, "socket EOF was not observed");
            thread::sleep(Duration::from_millis(5));
        }
        drop(directory);
        Ok(())
    }

    #[test]
    fn launcher_rejects_loose_socket_before_connect() -> anyhow::Result<()> {
        let (_directory, path, server) = socket_fixture(0o660, |_| {})?;
        let mut launcher = VmNetworkLabSocketLauncher::injected(path.clone(), unsafe { libc::geteuid() });
        assert_eq!(launcher.launch(1).err(), Some(NetworkErrorCode::SidecarUnavailable));
        let _ = UnixStream::connect(path);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("rejected-socket server thread panicked"))??;
        Ok(())
    }
}
