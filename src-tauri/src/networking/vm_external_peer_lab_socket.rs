//! Fixed Unix-socket launcher for the two-VirtualMac external-peer lab.
//!
//! The App can connect only to the manually authorized root supervisor at the
//! fixed path below. The launcher validates both filesystem and connected-peer
//! identity before protocol bootstrap; it never accepts a caller-selected
//! path, PID, command, endpoint, or credential.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStringExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{NetworkErrorCode, SidecarProcessControl, StdioSidecarLauncher};

pub const VM_EXTERNAL_PEER_LAB_SOCKET_PATH: &str = "/var/run/net.kysion.kyclash.vm-external-peer-lab.sock";
pub const VM_EXTERNAL_PEER_LAB_SUPERVISOR_PATH: &str =
    "/private/var/tmp/kyclash-vm-external-peer-lab-stage/kyclash-vm-external-peer-lab-supervisor";

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    value: [libc::c_uint; 8],
}

#[link(name = "bsm", kind = "dylib")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> libc::pid_t;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    uid: libc::uid_t,
    mode: u32,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        }
    }
}

#[derive(Debug, Default)]
struct AbortState {
    generation: Option<u64>,
    stream: Option<UnixStream>,
    cancelled: bool,
    hard_aborted: bool,
}

/// Separate cancellation capability retained by the Tauri command state.
///
/// Cancel never waits for, or locks, the worker that is blocked on the
/// startup handshake. Closing this exact stream produces authenticated EOF at
/// the root supervisor and unblocks the protocol reader.
#[derive(Debug, Clone, Default)]
pub struct VmExternalPeerLabSocketAbort {
    state: Arc<Mutex<AbortState>>,
}

impl VmExternalPeerLabSocketAbort {
    fn register(&self, generation: u64, stream: UnixStream) -> Result<(), NetworkErrorCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
        if state.generation.is_some() || state.stream.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        if state.cancelled {
            state.hard_aborted = true;
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(NetworkErrorCode::OperationCancelled);
        }
        state.generation = Some(generation);
        state.stream = Some(stream);
        drop(state);
        Ok(())
    }

    fn clear(&self, generation: u64) {
        if let Ok(mut state) = self.state.lock()
            && state.generation == Some(generation)
        {
            state.stream.take();
            state.generation = None;
        }
    }

    fn is_cancelled(&self) -> Result<bool, NetworkErrorCode> {
        self.state
            .lock()
            .map(|state| state.cancelled)
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)
    }

    /// Returns whether this capability ever had to shut down an authenticated
    /// supervisor socket. A local shutdown unblocks startup, but it is not a
    /// positive remote-cleanup acknowledgement.
    pub fn was_hard_aborted(&self) -> Result<bool, NetworkErrorCode> {
        self.state
            .lock()
            .map(|state| state.hard_aborted)
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)
    }

    pub fn cancel(&self) -> Result<(), NetworkErrorCode> {
        let stream = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
            state.cancelled = true;
            if state.stream.is_some() {
                state.hard_aborted = true;
            }
            state
                .stream
                .as_ref()
                .map(UnixStream::try_clone)
                .transpose()
                .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
        };
        let Some(stream) = stream else {
            return Ok(());
        };
        match stream.shutdown(std::net::Shutdown::Both) {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.kind(), io::ErrorKind::NotConnected | io::ErrorKind::BrokenPipe) => Ok(()),
            Err(_) => Err(NetworkErrorCode::SidecarUnavailable),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmExternalPeerLabSocketLauncher {
    socket_path: PathBuf,
    supervisor_path: PathBuf,
    required_socket_uid: libc::uid_t,
    required_peer_uid: libc::uid_t,
    required_supervisor_uid: libc::uid_t,
    require_arm64: bool,
    abort: VmExternalPeerLabSocketAbort,
}

impl VmExternalPeerLabSocketLauncher {
    #[must_use]
    pub fn new(abort: VmExternalPeerLabSocketAbort) -> Self {
        Self {
            socket_path: PathBuf::from(VM_EXTERNAL_PEER_LAB_SOCKET_PATH),
            supervisor_path: PathBuf::from(VM_EXTERNAL_PEER_LAB_SUPERVISOR_PATH),
            required_socket_uid: unsafe { libc::geteuid() },
            required_peer_uid: 0,
            required_supervisor_uid: 0,
            require_arm64: true,
            abort,
        }
    }

    #[cfg(test)]
    fn injected(
        socket_path: PathBuf,
        supervisor_path: PathBuf,
        required_peer_uid: libc::uid_t,
        abort: VmExternalPeerLabSocketAbort,
    ) -> Self {
        let uid = unsafe { libc::geteuid() };
        Self {
            socket_path,
            supervisor_path,
            required_socket_uid: uid,
            required_peer_uid,
            required_supervisor_uid: uid,
            require_arm64: false,
            abort,
        }
    }
}

fn validate_socket_metadata(path: &Path, required_uid: libc::uid_t) -> Result<FileIdentity, NetworkErrorCode> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != required_uid
        || required_uid == 0
    {
        return Err(NetworkErrorCode::SidecarUnavailable);
    }
    Ok(FileIdentity::from_metadata(&metadata))
}

fn socket_peer_uid(stream: &UnixStream) -> io::Result<libc::uid_t> {
    let mut credentials = std::mem::MaybeUninit::<libc::xucred>::zeroed();
    let mut length = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: credentials is valid writable storage and stream owns the fd.
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

fn socket_peer_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let mut pid = 0_i32;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: pid is valid writable storage and stream owns the fd.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(std::mem::size_of::<libc::pid_t>()) || pid <= 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid peer pid"));
    }
    Ok(pid)
}

fn socket_peer_audit_pid(stream: &UnixStream) -> io::Result<libc::pid_t> {
    let mut token = std::mem::MaybeUninit::<AuditToken>::zeroed();
    let mut length = std::mem::size_of::<AuditToken>() as libc::socklen_t;
    // SAFETY: token is valid writable storage and stream owns the fd.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &raw mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(std::mem::size_of::<AuditToken>()) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid peer audit token"));
    }
    // SAFETY: getsockopt initialized the complete opaque audit token and the
    // BSM routine is the supported interpreter for that token.
    let pid = unsafe { audit_token_to_pid(token.assume_init()) };
    if pid <= 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid audit-token pid"));
    }
    Ok(pid)
}

fn process_path(pid: libc::pid_t) -> io::Result<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer is writable for the advertised size and pid was obtained
    // from the connected Unix socket.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        )
    };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if length >= buffer.len() || buffer[..length].contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    buffer.truncate(length);
    Ok(PathBuf::from(OsString::from_vec(buffer)))
}

fn validate_arm64_macho(path: &Path) -> Result<(), NetworkErrorCode> {
    let mut header = [0_u8; 8];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    const MH_MAGIC_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    if header[..4] != MH_MAGIC_64_LE
        || u32::from_le_bytes(header[4..8].try_into().unwrap_or_default()) != CPU_TYPE_ARM64
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(())
}

fn validate_supervisor(
    stream: &UnixStream,
    expected_path: &Path,
    required_peer_uid: libc::uid_t,
    required_supervisor_uid: libc::uid_t,
    require_arm64: bool,
) -> Result<(), NetworkErrorCode> {
    let peer_uid = socket_peer_uid(stream).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    let peer_pid = socket_peer_pid(stream).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    let audit_pid = socket_peer_audit_pid(stream).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    if peer_uid != required_peer_uid || peer_pid != audit_pid {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }

    let actual_path = process_path(peer_pid).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    if actual_path != expected_path || !expected_path.is_absolute() {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    let before = std::fs::symlink_metadata(expected_path).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.uid() != required_supervisor_uid
        || before.mode() & 0o777 != 0o755
        || before.nlink() != 1
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    let before = FileIdentity::from_metadata(&before);
    if require_arm64 {
        validate_arm64_macho(expected_path)?;
    }
    let after = std::fs::symlink_metadata(expected_path).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    if before != FileIdentity::from_metadata(&after)
        || socket_peer_pid(stream).map_err(|_| NetworkErrorCode::AuthenticationFailed)? != peer_pid
        || socket_peer_audit_pid(stream).map_err(|_| NetworkErrorCode::AuthenticationFailed)? != peer_pid
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(())
}

struct VmExternalPeerLabSocketControl {
    generation: u64,
    input: Option<UnixStream>,
    output: Option<UnixStream>,
    monitor: UnixStream,
    abort: VmExternalPeerLabSocketAbort,
}

impl Drop for VmExternalPeerLabSocketControl {
    fn drop(&mut self) {
        self.abort.clear(self.generation);
    }
}

impl SidecarProcessControl for VmExternalPeerLabSocketControl {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn try_wait_status(&mut self) -> io::Result<Option<bool>> {
        let mut byte = 0_u8;
        // SAFETY: byte is writable and MSG_PEEK|MSG_DONTWAIT is non-consuming
        // and bounded.
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
        self.abort
            .cancel()
            .map_err(|_| io::Error::from(io::ErrorKind::NotConnected))
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

impl StdioSidecarLauncher for VmExternalPeerLabSocketLauncher {
    fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
        if self.abort.is_cancelled()? {
            return Err(NetworkErrorCode::OperationCancelled);
        }
        let before = validate_socket_metadata(&self.socket_path, self.required_socket_uid)?;
        let input = UnixStream::connect(&self.socket_path).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let after = validate_socket_metadata(&self.socket_path, self.required_socket_uid)?;
        if before != after {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        validate_supervisor(
            &input,
            &self.supervisor_path,
            self.required_peer_uid,
            self.required_supervisor_uid,
            self.require_arm64,
        )?;
        let output = input.try_clone().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let monitor = input.try_clone().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let abort_stream = input.try_clone().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        self.abort.register(generation, abort_stream)?;
        Ok(Box::new(VmExternalPeerLabSocketControl {
            generation,
            input: Some(input),
            output: Some(output),
            monitor,
            abort: self.abort.clone(),
        }))
    }

    fn cancel_prepared(&mut self) -> Result<(), NetworkErrorCode> {
        self.abort.cancel()
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
        let path = directory.path().join("external-peer.sock");
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept()?;
            server(stream);
            Ok(())
        });
        Ok((directory, path, handle))
    }

    fn injected_launcher(
        socket_path: PathBuf,
        supervisor_path: PathBuf,
        abort: VmExternalPeerLabSocketAbort,
    ) -> VmExternalPeerLabSocketLauncher {
        VmExternalPeerLabSocketLauncher::injected(socket_path, supervisor_path, unsafe { libc::geteuid() }, abort)
    }

    #[test]
    fn launcher_binds_peer_pid_audit_token_and_exact_executable() -> anyhow::Result<()> {
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let (directory, path, server) = socket_fixture(0o600, move |stream| {
            let _ = release_receiver.recv();
            drop(stream);
        })?;
        let abort = VmExternalPeerLabSocketAbort::default();
        let mut launcher = injected_launcher(path, std::env::current_exe()?, abort);
        let mut control = launcher
            .launch(41)
            .map_err(|error| anyhow::anyhow!("external launcher failed: {error:?}"))?;
        assert_eq!(control.generation(), 41);
        assert!(control.take_stdin().is_some());
        assert!(control.take_stdout().is_some());
        release_sender.send(())?;
        server
            .join()
            .map_err(|_| anyhow::anyhow!("external server panicked"))??;
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.try_wait_status()? != Some(true) {
            assert!(Instant::now() < deadline, "socket EOF was not observed");
            thread::sleep(Duration::from_millis(5));
        }
        drop(directory);
        Ok(())
    }

    #[test]
    fn separate_abort_handle_unblocks_the_owned_connection() -> anyhow::Result<()> {
        let (directory, path, server) = socket_fixture(0o600, |mut stream| {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte);
        })?;
        let abort = VmExternalPeerLabSocketAbort::default();
        let mut launcher = injected_launcher(path, std::env::current_exe()?, abort.clone());
        let _control = launcher
            .launch(5)
            .map_err(|error| anyhow::anyhow!("external launcher failed: {error:?}"))?;
        abort
            .cancel()
            .map_err(|error| anyhow::anyhow!("external cancel failed: {error:?}"))?;
        assert_eq!(abort.was_hard_aborted(), Ok(true));
        server
            .join()
            .map_err(|_| anyhow::anyhow!("external server panicked"))??;
        drop(directory);
        Ok(())
    }

    #[test]
    fn cancellation_before_launch_is_not_lost() -> anyhow::Result<()> {
        let (_directory, path, server) = socket_fixture(0o600, |_| {})?;
        let abort = VmExternalPeerLabSocketAbort::default();
        abort
            .cancel()
            .map_err(|error| anyhow::anyhow!("external cancel failed: {error:?}"))?;
        assert_eq!(abort.was_hard_aborted(), Ok(false));
        let mut launcher = injected_launcher(path.clone(), std::env::current_exe()?, abort);
        assert_eq!(launcher.launch(5).err(), Some(NetworkErrorCode::OperationCancelled));
        let _ = UnixStream::connect(path);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("external server panicked"))??;
        Ok(())
    }

    #[test]
    fn launcher_rejects_loose_socket_before_identity_use() -> anyhow::Result<()> {
        let (_directory, path, server) = socket_fixture(0o660, |_| {})?;
        let mut launcher = injected_launcher(
            path.clone(),
            std::env::current_exe()?,
            VmExternalPeerLabSocketAbort::default(),
        );
        assert_eq!(launcher.launch(1).err(), Some(NetworkErrorCode::SidecarUnavailable));
        let _ = UnixStream::connect(path);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("external server panicked"))??;
        Ok(())
    }

    #[test]
    fn launcher_rejects_a_peer_at_the_wrong_exact_path() -> anyhow::Result<()> {
        let (_directory, path, server) = socket_fixture(0o600, |_| {})?;
        let mut launcher = injected_launcher(
            path,
            PathBuf::from("/private/var/tmp/not-the-supervisor"),
            VmExternalPeerLabSocketAbort::default(),
        );
        assert_eq!(launcher.launch(1).err(), Some(NetworkErrorCode::AuthenticationFailed));
        server
            .join()
            .map_err(|_| anyhow::anyhow!("external server panicked"))??;
        Ok(())
    }

    #[test]
    fn production_constructor_is_fixed_and_root_bound() {
        let launcher = VmExternalPeerLabSocketLauncher::new(VmExternalPeerLabSocketAbort::default());
        assert_eq!(launcher.socket_path, PathBuf::from(VM_EXTERNAL_PEER_LAB_SOCKET_PATH));
        assert_eq!(
            launcher.supervisor_path,
            PathBuf::from(VM_EXTERNAL_PEER_LAB_SUPERVISOR_PATH)
        );
        assert_eq!(launcher.required_peer_uid, 0);
        assert_eq!(launcher.required_supervisor_uid, 0);
        assert!(launcher.require_arm64);
    }
}
