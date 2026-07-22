use std::{
    ffi::c_char,
    fs::File,
    io,
    os::fd::{FromRawFd as _, OwnedFd},
};

use super::{NetworkErrorCode, SidecarProcessControl, StdioSidecarLauncher};

pub const TUNNEL_BROKER_PROTOCOL_VERSION: u8 = 1;
const MAXIMUM_IDENTIFIER_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelBrokerSessionReference {
    pub protocol_version: u8,
    pub generation: u64,
    pub sidecar_instance_id: String,
}

impl TunnelBrokerSessionReference {
    fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != TUNNEL_BROKER_PROTOCOL_VERSION
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.sidecar_instance_id.len() < 8
            || self.sidecar_instance_id.len() > MAXIMUM_IDENTIFIER_BYTES
            || !self
                .sidecar_instance_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
        {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        Ok(())
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NativeReply {
    transport_status: i32,
    protocol_version: i32,
    state: i32,
    error_code: i32,
    broker_generation: u64,
    input_fd: i32,
    output_fd: i32,
    sidecar_instance_id: [c_char; MAXIMUM_IDENTIFIER_BYTES + 1],
}

impl NativeReply {
    #[cfg(test)]
    const fn failure(transport_status: i32) -> Self {
        Self {
            transport_status,
            protocol_version: -1,
            state: -1,
            error_code: -1,
            broker_generation: 0,
            input_fd: -1,
            output_fd: -1,
            sidecar_instance_id: [0; MAXIMUM_IDENTIFIER_BYTES + 1],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelBrokerState {
    Idle,
    Running,
    RouteHeld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelBrokerError {
    InvalidRequest,
    Unavailable,
    AlreadyRunning,
    OwnershipMismatch,
    StaleGeneration,
    RouteHeld,
    HoldMismatch,
    LaunchFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunnelBrokerStatus {
    state: TunnelBrokerState,
    error: Option<TunnelBrokerError>,
}

trait TunnelBrokerGeneration: Send {
    fn start(&mut self) -> NativeReply;
    fn status(&mut self) -> NativeReply;
    fn stop(&mut self) -> NativeReply;
}

trait TunnelBrokerGenerationFactory: Send {
    fn create(&mut self) -> Result<Box<dyn TunnelBrokerGeneration>, NetworkErrorCode>;
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::c_void;

    use super::NativeReply;

    unsafe extern "C" {
        pub fn kyclash_tunnel_broker_client_create() -> *mut c_void;
        pub fn kyclash_tunnel_broker_client_destroy(client: *mut c_void);
        pub fn kyclash_tunnel_broker_client_start(client: *mut c_void) -> NativeReply;
        pub fn kyclash_tunnel_broker_client_status(client: *mut c_void) -> NativeReply;
        pub fn kyclash_tunnel_broker_client_stop(client: *mut c_void) -> NativeReply;
    }
}

struct NativeTunnelBrokerGeneration {
    native: usize,
}

impl NativeTunnelBrokerGeneration {
    fn connect() -> Result<Self, NetworkErrorCode> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: the bridge returns one retained fixed-service client.
            let native = unsafe { platform::kyclash_tunnel_broker_client_create() } as usize;
            if native == 0 {
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            Ok(Self { native })
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }
}

impl TunnelBrokerGeneration for NativeTunnelBrokerGeneration {
    fn start(&mut self) -> NativeReply {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` remains retained until this generation drops.
            unsafe { platform::kyclash_tunnel_broker_client_start(self.native as *mut _) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            NativeReply {
                transport_status: 6,
                protocol_version: -1,
                state: -1,
                error_code: -1,
                broker_generation: 0,
                input_fd: -1,
                output_fd: -1,
                sidecar_instance_id: [0; MAXIMUM_IDENTIFIER_BYTES + 1],
            }
        }
    }

    fn status(&mut self) -> NativeReply {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` remains retained until this generation drops.
            unsafe { platform::kyclash_tunnel_broker_client_status(self.native as *mut _) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.start()
        }
    }

    fn stop(&mut self) -> NativeReply {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `native` remains retained until this generation drops.
            unsafe { platform::kyclash_tunnel_broker_client_stop(self.native as *mut _) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.start()
        }
    }
}

impl Drop for NativeTunnelBrokerGeneration {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.native != 0 {
            // SAFETY: this is the one matching release for `create`.
            unsafe { platform::kyclash_tunnel_broker_client_destroy(self.native as *mut _) };
            self.native = 0;
        }
    }
}

struct NativeTunnelBrokerGenerationFactory;

impl TunnelBrokerGenerationFactory for NativeTunnelBrokerGenerationFactory {
    fn create(&mut self) -> Result<Box<dyn TunnelBrokerGeneration>, NetworkErrorCode> {
        NativeTunnelBrokerGeneration::connect()
            .map(|generation| Box::new(generation) as Box<dyn TunnelBrokerGeneration>)
    }
}

/// Fixed-policy client factory for the privileged macOS tunnel broker.
///
/// This type has no executable path, argv, environment, route, DNS, profile,
/// or secret field. The native bridge can only connect to the compile-time
/// `net.kysion.kyclash.tunnel-broker` Mach service and call its typed
/// `start/status/stop` surface. `prepare` intentionally returns the typed
/// broker reference before the stdio bootstrap is written: production must
/// construct `SidecarLaunchContext.instance_id` from that exact reference.
pub struct TunnelBrokerSidecarLauncher {
    factory: Box<dyn TunnelBrokerGenerationFactory>,
}

impl TunnelBrokerSidecarLauncher {
    #[must_use]
    pub fn new() -> Self {
        Self {
            factory: Box::new(NativeTunnelBrokerGenerationFactory),
        }
    }

    #[cfg(test)]
    fn with_factory(factory: Box<dyn TunnelBrokerGenerationFactory>) -> Self {
        Self { factory }
    }

    pub fn prepare(&mut self, runtime_generation: u64) -> Result<PreparedTunnelBrokerLauncher, NetworkErrorCode> {
        let client = TunnelBrokerClient::with_generation(self.factory.create()?);
        client.start(runtime_generation).map(PreparedTunnelBrokerLauncher::new)
    }
}

impl Default for TunnelBrokerSidecarLauncher {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-use stdio launcher whose broker identity is observable before the
/// protocol-v2 bootstrap. This prevents callers from confusing the Rust
/// runtime counter, the broker generation, and the broker-assigned sidecar ID.
pub struct PreparedTunnelBrokerLauncher {
    process: Option<TunnelBrokerProcessControl>,
    reference: TunnelBrokerSessionReference,
}

impl PreparedTunnelBrokerLauncher {
    fn new(process: TunnelBrokerProcessControl) -> Self {
        Self {
            reference: process.session_reference().clone(),
            process: Some(process),
        }
    }

    #[must_use]
    pub const fn session_reference(&self) -> &TunnelBrokerSessionReference {
        &self.reference
    }
}

impl StdioSidecarLauncher for PreparedTunnelBrokerLauncher {
    fn launch(&mut self, generation: u64) -> Result<Box<dyn SidecarProcessControl>, NetworkErrorCode> {
        let process = self.process.as_ref().ok_or(NetworkErrorCode::InvalidStateTransition)?;
        if generation == 0 || process.runtime_generation != generation {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.process
            .take()
            .map(|process| Box::new(process) as Box<dyn SidecarProcessControl>)
            .ok_or(NetworkErrorCode::InvalidStateTransition)
    }
}

/// One exact fixed-service NSXPC generation before it has launched a child.
///
/// Starting consumes this value, so the native connection and the returned
/// broker reference cannot be detached from the exact process-control handle.
pub struct TunnelBrokerClient {
    broker: Box<dyn TunnelBrokerGeneration>,
}

impl TunnelBrokerClient {
    pub fn connect() -> Result<Self, NetworkErrorCode> {
        NativeTunnelBrokerGeneration::connect().map(|generation| Self {
            broker: Box::new(generation),
        })
    }

    fn with_generation(broker: Box<dyn TunnelBrokerGeneration>) -> Self {
        Self { broker }
    }

    pub fn start(mut self, runtime_generation: u64) -> Result<TunnelBrokerProcessControl, NetworkErrorCode> {
        if runtime_generation == 0 {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let started = decode_start_reply(self.broker.start())?;
        Ok(TunnelBrokerProcessControl {
            runtime_generation,
            session: started.reference,
            broker: self.broker,
            input: Some(File::from(started.input)),
            output: Some(File::from(started.output)),
            reaped: None,
            recovery_only: false,
        })
    }
}

struct StartedTunnelBrokerSession {
    reference: TunnelBrokerSessionReference,
    input: OwnedFd,
    output: OwnedFd,
}

pub struct TunnelBrokerProcessControl {
    runtime_generation: u64,
    session: TunnelBrokerSessionReference,
    broker: Box<dyn TunnelBrokerGeneration>,
    input: Option<File>,
    output: Option<File>,
    reaped: Option<bool>,
    // A stale broker reference means this handle no longer has authoritative
    // ownership of a child.  Keep it quarantined for recovery; in particular,
    // never turn that condition into `Some(false)`, which the stdio runtime
    // interprets as a positively reaped (unsuccessful) child.
    recovery_only: bool,
}

impl TunnelBrokerProcessControl {
    /// The broker-owned identity is deliberately distinct from the stdio
    /// runtime generation. Future route interlock wiring must persist this
    /// exact reference; it must never synthesize it from the runtime counter
    /// or the protocol-v2 bootstrap instance ID.
    #[must_use]
    pub const fn session_reference(&self) -> &TunnelBrokerSessionReference {
        &self.session
    }
}

impl SidecarProcessControl for TunnelBrokerProcessControl {
    fn generation(&self) -> u64 {
        self.runtime_generation
    }

    fn try_wait_status(&mut self) -> io::Result<Option<bool>> {
        if let Some(success) = self.reaped {
            return Ok(Some(success));
        }
        if self.recovery_only {
            return Err(stale_generation_io_error());
        }
        let status = match decode_status_reply(self.broker.status()) {
            Ok(status) => status,
            Err(error) => {
                // A transport/protocol failure leaves the fixed Mach service
                // ownership ambiguous. Quarantine this exact handle so a
                // later retry cannot accidentally address a newer session.
                self.enter_recovery_only();
                return Err(network_error_to_io(error));
            }
        };
        match (status.state, status.error) {
            (_, Some(TunnelBrokerError::StaleGeneration)) => {
                self.enter_recovery_only();
                Err(stale_generation_io_error())
            }
            (TunnelBrokerState::Running | TunnelBrokerState::RouteHeld, None) => Ok(None),
            _ => Err(network_error_to_io(map_broker_status_error(status))),
        }
    }

    fn kill_owned(&mut self) -> io::Result<()> {
        if self.recovery_only {
            return Err(stale_generation_io_error());
        }
        if self.reaped.is_some() {
            return Ok(());
        }
        self.input.take();
        self.output.take();
        let status = match decode_status_reply(self.broker.stop()) {
            Ok(status) => status,
            Err(error) => {
                self.enter_recovery_only();
                return Err(network_error_to_io(error));
            }
        };
        match (status.state, status.error) {
            (_, Some(TunnelBrokerError::StaleGeneration)) => {
                self.enter_recovery_only();
                Err(stale_generation_io_error())
            }
            (TunnelBrokerState::Idle, None) => {
                // The broker replies only after bounded TERM/KILL and exact
                // child reap. This is positive absence for this session.
                self.reaped = Some(true);
                Ok(())
            }
            _ => Err(network_error_to_io(map_broker_status_error(status))),
        }
    }

    fn take_stdin(&mut self) -> Option<Box<dyn io::Write + Send>> {
        self.input
            .take()
            .map(|input| Box::new(input) as Box<dyn io::Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn io::Read + Send>> {
        self.output
            .take()
            .map(|output| Box::new(output) as Box<dyn io::Read + Send>)
    }
}

impl TunnelBrokerProcessControl {
    fn enter_recovery_only(&mut self) {
        // Do not leave protocol handles usable after ownership has become
        // ambiguous.  Dropping them may help the broker observe EOF, but it
        // is not treated as proof that the child was reaped.
        self.input.take();
        self.output.take();
        self.recovery_only = true;
    }
}

fn decode_start_reply(reply: NativeReply) -> Result<StartedTunnelBrokerSession, NetworkErrorCode> {
    // Claim descriptor ownership before inspecting any other field. Every
    // malformed/protocol-error path then closes both descriptors by RAII.
    let input = owned_fd(reply.input_fd);
    let output = owned_fd(reply.output_fd);
    let status = decode_status_reply(reply)?;
    if status.state != TunnelBrokerState::Running || status.error.is_some() {
        return Err(map_broker_status_error(status));
    }
    let input = input.ok_or(NetworkErrorCode::UnsupportedProtocolVersion)?;
    let output = output.ok_or(NetworkErrorCode::UnsupportedProtocolVersion)?;
    let reference = TunnelBrokerSessionReference {
        protocol_version: u8::try_from(reply.protocol_version)
            .map_err(|_| NetworkErrorCode::UnsupportedProtocolVersion)?,
        generation: reply.broker_generation,
        sidecar_instance_id: decode_identifier(&reply.sidecar_instance_id)?,
    };
    reference.validate()?;
    Ok(StartedTunnelBrokerSession {
        reference,
        input,
        output,
    })
}

fn owned_fd(raw: i32) -> Option<OwnedFd> {
    if raw < 0 {
        return None;
    }
    // SAFETY: the native bridge transfers one newly duplicated descriptor in
    // each non-negative field. This function is the sole Rust ownership edge.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn decode_identifier(raw: &[c_char; MAXIMUM_IDENTIFIER_BYTES + 1]) -> Result<String, NetworkErrorCode> {
    let bytes = raw.iter().map(|byte| *byte as u8).collect::<Vec<_>>();
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(NetworkErrorCode::UnsupportedProtocolVersion)?;
    if nul == 0 || bytes[nul + 1..].iter().any(|byte| *byte != 0) {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    }
    std::str::from_utf8(&bytes[..nul])
        .map(str::to_owned)
        .map_err(|_| NetworkErrorCode::UnsupportedProtocolVersion)
}

fn decode_status_reply(reply: NativeReply) -> Result<TunnelBrokerStatus, NetworkErrorCode> {
    match reply.transport_status {
        0 => {}
        1 => return Err(NetworkErrorCode::OperationTimedOut),
        5 => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
        7 => return Err(NetworkErrorCode::InvalidConfiguration),
        2..=4 | 6 => return Err(NetworkErrorCode::SidecarUnavailable),
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    }
    if reply.protocol_version != i32::from(TUNNEL_BROKER_PROTOCOL_VERSION) {
        return Err(NetworkErrorCode::UnsupportedProtocolVersion);
    }
    let state = match reply.state {
        0 => TunnelBrokerState::Idle,
        1 => TunnelBrokerState::Running,
        2 => TunnelBrokerState::RouteHeld,
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    let error = match reply.error_code {
        0 => None,
        1 => Some(TunnelBrokerError::InvalidRequest),
        2 => Some(TunnelBrokerError::Unavailable),
        3 => Some(TunnelBrokerError::AlreadyRunning),
        4 => Some(TunnelBrokerError::OwnershipMismatch),
        5 => Some(TunnelBrokerError::StaleGeneration),
        6 => Some(TunnelBrokerError::RouteHeld),
        7 => Some(TunnelBrokerError::HoldMismatch),
        8 => Some(TunnelBrokerError::LaunchFailed),
        _ => return Err(NetworkErrorCode::UnsupportedProtocolVersion),
    };
    Ok(TunnelBrokerStatus { state, error })
}

const fn map_broker_status_error(status: TunnelBrokerStatus) -> NetworkErrorCode {
    match status.error {
        Some(TunnelBrokerError::InvalidRequest) => NetworkErrorCode::InvalidConfiguration,
        Some(TunnelBrokerError::Unavailable) => NetworkErrorCode::SidecarUnavailable,
        Some(TunnelBrokerError::AlreadyRunning) => NetworkErrorCode::InvalidStateTransition,
        Some(TunnelBrokerError::OwnershipMismatch) => NetworkErrorCode::PermissionDenied,
        Some(TunnelBrokerError::StaleGeneration | TunnelBrokerError::HoldMismatch) => {
            NetworkErrorCode::InvalidStateTransition
        }
        Some(TunnelBrokerError::RouteHeld) => NetworkErrorCode::RouteRollbackFailed,
        Some(TunnelBrokerError::LaunchFailed) => NetworkErrorCode::TunnelStartFailed,
        None => NetworkErrorCode::UnsupportedProtocolVersion,
    }
}

fn network_error_to_io(error: NetworkErrorCode) -> io::Error {
    let kind = match error {
        NetworkErrorCode::OperationTimedOut => io::ErrorKind::TimedOut,
        NetworkErrorCode::SidecarUnavailable => io::ErrorKind::BrokenPipe,
        NetworkErrorCode::PermissionDenied => io::ErrorKind::PermissionDenied,
        NetworkErrorCode::RouteRollbackFailed => io::ErrorKind::WouldBlock,
        NetworkErrorCode::InvalidConfiguration | NetworkErrorCode::InvalidStateTransition => {
            io::ErrorKind::InvalidInput
        }
        _ => io::ErrorKind::InvalidData,
    };
    io::Error::new(kind, format!("tunnel broker error: {error:?}"))
}

fn stale_generation_io_error() -> io::Error {
    // `NotFound` is used as the closest stable std::io classification for a
    // broker-owned session reference that no longer resolves.  Callers must
    // treat this as recovery/quarantine, never as a reap result.
    io::Error::new(
        io::ErrorKind::NotFound,
        "tunnel broker session is stale; exact child reap is not confirmed",
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fs::OpenOptions,
        os::fd::{AsRawFd as _, IntoRawFd as _},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;

    fn encoded_identifier(value: &str) -> [c_char; MAXIMUM_IDENTIFIER_BYTES + 1] {
        let mut encoded = [0; MAXIMUM_IDENTIFIER_BYTES + 1];
        for (slot, byte) in encoded.iter_mut().zip(value.bytes()) {
            *slot = byte as c_char;
        }
        encoded
    }

    fn start_reply() -> io::Result<NativeReply> {
        let input = OpenOptions::new().write(true).open("/dev/null")?;
        let output = File::open("/dev/null")?;
        Ok(NativeReply {
            transport_status: 0,
            protocol_version: i32::from(TUNNEL_BROKER_PROTOCOL_VERSION),
            state: 1,
            error_code: 0,
            broker_generation: 77,
            input_fd: input.into_raw_fd(),
            output_fd: output.into_raw_fd(),
            sidecar_instance_id: encoded_identifier("broker-instance-00000077"),
        })
    }

    const fn status_reply(state: i32, error_code: i32) -> NativeReply {
        NativeReply {
            transport_status: 0,
            protocol_version: TUNNEL_BROKER_PROTOCOL_VERSION as i32,
            state,
            error_code,
            broker_generation: 77,
            input_fd: -1,
            output_fd: -1,
            sidecar_instance_id: [0; MAXIMUM_IDENTIFIER_BYTES + 1],
        }
    }

    struct FakeGeneration {
        start: Option<NativeReply>,
        statuses: VecDeque<NativeReply>,
        stops: VecDeque<NativeReply>,
        stop_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl TunnelBrokerGeneration for FakeGeneration {
        fn start(&mut self) -> NativeReply {
            self.start.take().unwrap_or_else(|| NativeReply::failure(7))
        }

        fn status(&mut self) -> NativeReply {
            self.statuses.pop_front().unwrap_or_else(|| status_reply(1, 0))
        }

        fn stop(&mut self) -> NativeReply {
            self.stop_calls.fetch_add(1, Ordering::AcqRel);
            self.stops.pop_front().unwrap_or_else(|| NativeReply::failure(7))
        }
    }

    impl Drop for FakeGeneration {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct FakeFactory {
        generation: Option<Box<dyn TunnelBrokerGeneration>>,
    }

    impl TunnelBrokerGenerationFactory for FakeFactory {
        fn create(&mut self) -> Result<Box<dyn TunnelBrokerGeneration>, NetworkErrorCode> {
            self.generation.take().ok_or(NetworkErrorCode::SidecarUnavailable)
        }
    }

    fn launcher(
        runtime_generation: u64,
        statuses: VecDeque<NativeReply>,
        stops: VecDeque<NativeReply>,
        stop_calls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    ) -> Result<PreparedTunnelBrokerLauncher, NetworkErrorCode> {
        let mut factory = TunnelBrokerSidecarLauncher::with_factory(Box::new(FakeFactory {
            generation: Some(Box::new(FakeGeneration {
                start: Some(start_reply().map_err(|_| NetworkErrorCode::SidecarUnavailable)?),
                statuses,
                stops,
                stop_calls,
                drops,
            })),
        }));
        factory.prepare(runtime_generation)
    }

    #[test]
    fn start_decodes_typed_reference_and_takes_both_descriptors() -> Result<(), NetworkErrorCode> {
        let started = decode_start_reply(start_reply().map_err(|_| NetworkErrorCode::SidecarUnavailable)?)?;
        assert_eq!(started.reference.protocol_version, TUNNEL_BROKER_PROTOCOL_VERSION);
        assert_eq!(started.reference.generation, 77);
        assert_eq!(started.reference.sidecar_instance_id, "broker-instance-00000077");
        assert!(started.input.as_raw_fd() >= 0);
        assert!(started.output.as_raw_fd() >= 0);
        Ok(())
    }

    #[test]
    fn public_client_exposes_broker_reference_without_aliasing_runtime_generation() -> Result<(), NetworkErrorCode> {
        let client = TunnelBrokerClient::with_generation(Box::new(FakeGeneration {
            start: Some(start_reply().map_err(|_| NetworkErrorCode::SidecarUnavailable)?),
            statuses: VecDeque::new(),
            stops: VecDeque::new(),
            stop_calls: Arc::new(AtomicUsize::new(0)),
            drops: Arc::new(AtomicUsize::new(0)),
        }));
        let process = client.start(9)?;
        assert_eq!(SidecarProcessControl::generation(&process), 9);
        assert_eq!(process.session_reference().generation, 77);
        assert_eq!(
            process.session_reference().sidecar_instance_id,
            "broker-instance-00000077"
        );
        assert_ne!(
            SidecarProcessControl::generation(&process),
            process.session_reference().generation
        );
        Ok(())
    }

    #[test]
    fn launcher_keeps_runtime_generation_and_reaps_exact_session_once() -> Result<(), NetworkErrorCode> {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut launcher = launcher(
            9,
            VecDeque::new(),
            VecDeque::from([status_reply(0, 0)]),
            Arc::clone(&stop_calls),
            Arc::clone(&drops),
        )?;
        assert_eq!(launcher.session_reference().generation, 77);
        assert_eq!(
            launcher.session_reference().sidecar_instance_id,
            "broker-instance-00000077"
        );
        assert_eq!(launcher.launch(8).err(), Some(NetworkErrorCode::InvalidStateTransition));
        let mut process = launcher.launch(9)?;
        assert_eq!(process.generation(), 9);
        assert!(process.take_stdin().is_some());
        assert!(process.take_stdin().is_none());
        assert!(process.take_stdout().is_some());
        assert!(process.take_stdout().is_none());
        process.kill_owned().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        assert_eq!(process.try_wait_status().ok(), Some(Some(true)));
        process.kill_owned().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
        drop(process);
        assert_eq!(drops.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[test]
    fn route_hold_refuses_stop_without_claiming_child_absence() -> Result<(), NetworkErrorCode> {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut launcher = launcher(
            1,
            VecDeque::from([status_reply(2, 0)]),
            VecDeque::from([status_reply(2, 6)]),
            Arc::clone(&stop_calls),
            drops,
        )?;
        let mut process = launcher.launch(1)?;
        assert_eq!(
            process.kill_owned().err().map(|error| error.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        assert_eq!(process.try_wait_status().ok(), Some(None));
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[test]
    fn stale_idle_status_requires_recovery_and_never_claims_reaped() -> Result<(), NetworkErrorCode> {
        let mut launcher = launcher(
            1,
            // A stale reference may be answered with the *current* state of
            // a newer session, not necessarily idle.  It must still enter
            // recovery-only mode.
            VecDeque::from([status_reply(1, 5)]),
            VecDeque::new(),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        )?;
        let mut process = launcher.launch(1)?;
        let first = match process.try_wait_status() {
            Ok(_) => return Err(NetworkErrorCode::InvalidStateTransition),
            Err(error) => error,
        };
        assert_eq!(first.kind(), io::ErrorKind::NotFound);
        let second = match process.try_wait_status() {
            Ok(_) => return Err(NetworkErrorCode::InvalidStateTransition),
            Err(error) => error,
        };
        assert_eq!(second.kind(), io::ErrorKind::NotFound);
        Ok(())
    }

    #[test]
    fn stale_stop_requires_recovery_and_never_claims_reaped() -> Result<(), NetworkErrorCode> {
        let stop_calls = Arc::new(AtomicUsize::new(0));
        let mut launcher = launcher(
            1,
            VecDeque::new(),
            VecDeque::from([status_reply(2, 5)]),
            Arc::clone(&stop_calls),
            Arc::new(AtomicUsize::new(0)),
        )?;
        let mut process = launcher.launch(1)?;
        let stop_error = match process.kill_owned() {
            Ok(()) => return Err(NetworkErrorCode::InvalidStateTransition),
            Err(error) => error,
        };
        assert_eq!(stop_error.kind(), io::ErrorKind::NotFound);
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
        let status_error = match process.try_wait_status() {
            Ok(_) => return Err(NetworkErrorCode::InvalidStateTransition),
            Err(error) => error,
        };
        assert_eq!(status_error.kind(), io::ErrorKind::NotFound);
        // A quarantined handle must not issue a second stop against a newer
        // broker generation that might now occupy the fixed service.
        if process.kill_owned().is_ok() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        assert_eq!(stop_calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[test]
    fn malformed_start_closes_every_transferred_descriptor() -> Result<(), NetworkErrorCode> {
        let mut reply = start_reply().map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
        let input = reply.input_fd;
        let output = reply.output_fd;
        reply.broker_generation = 0;
        assert_eq!(
            decode_start_reply(reply).err(),
            Some(NetworkErrorCode::UnsupportedProtocolVersion)
        );
        // SAFETY: `fcntl` only probes whether these former descriptor numbers
        // still refer to open files; decode_start_reply owns and closed both.
        assert_eq!(unsafe { libc::fcntl(input, libc::F_GETFD) }, -1);
        assert_eq!(unsafe { libc::fcntl(output, libc::F_GETFD) }, -1);
        Ok(())
    }

    #[test]
    fn transport_and_typed_failures_map_without_accepting_a_session() {
        assert_eq!(
            decode_start_reply(NativeReply::failure(1)).err(),
            Some(NetworkErrorCode::OperationTimedOut)
        );
        let reply = status_reply(0, 3);
        assert_eq!(
            decode_start_reply(reply).err(),
            Some(NetworkErrorCode::InvalidStateTransition)
        );
    }
}
