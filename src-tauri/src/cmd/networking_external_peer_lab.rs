//! Async App controller for the locked two-VirtualMac external-peer lab.
//!
//! This sibling command surface is compiled only for the default-off external
//! lab feature. It accepts no frontend authority: the socket, peer label,
//! private route, Mihomo device/route, transport order, and startup budget are
//! constants. The root harness owns and pre-applies the strict endpoint
//! profile, so neither this module nor the frontend receives endpoint URLs,
//! ports, descriptors, certificates, hashes, paths, or peer PIDs.

use std::path::PathBuf;
use std::sync::{
    Arc, Condvar, LazyLock, Mutex,
    atomic::{AtomicBool, AtomicU8, Ordering},
};
use std::time::Duration;

use getrandom::fill as fill_random;
use serde::Serialize;
use zeroize::Zeroize as _;

use crate::networking::{
    IpcRequest, IpcRequestPayload, IpcResponsePayload, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, NetworkHealth,
    NetworkState, SidecarLaunchContext, SidecarLifecycleState, SidecarRuntime as _, StdioSidecarRuntime, TransportKind,
    VM_EXTERNAL_PEER_LAB_SOCKET_PATH, VmExternalPeerLabSocketAbort, VmExternalPeerLabSocketLauncher,
    sidecar_auth_proof,
};

const RUNTIME_MODE: &str = "vm_external_peer_lab";
const TUNNEL_KIND: &str = "darwin_utun";
const SITE_ID: &str = "lab-vm-external-peer";
const SITE_DISPLAY_NAME: &str = "KyClash external-peer VM lab";
const PEER_VM: &str = "kyclash-macos-lab-peer";
const PRIVATE_ROUTE: &str = "10.88.0.2/32";
const MIHOMO_DEVICE: &str = "utun4094";
const MIHOMO_ROUTE: &str = "10.88.0.0/24";
// The Go userspace health operation is bounded at 12 seconds. Keep the Rust
// response deadline above that bound so a fixed carrier impairment is
// returned as a correlated IPC result instead of killing the child locally.
const STEADY_STATE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const STEADY_STATE_HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const IMPAIRMENT_HEALTH_POLL_LIMIT: usize = 3;
const IMPAIRMENT_HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TRANSPORT_ORDER: [TransportKind; 3] = [TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp];
const HANDSHAKE_PENDING: u8 = 0;
const HANDSHAKE_ACTIVE: u8 = 1;
const HANDSHAKE_ABORTING: u8 = 2;

type ExternalPeerRuntime = StdioSidecarRuntime<VmExternalPeerLabSocketLauncher>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPeerLabPhase {
    Disconnected,
    WaitingForValidatedPeer,
    Ready,
    PreparingMihomo,
    PreparingUtun,
    ConnectingQuic,
    ConnectedQuic,
    SwitchingToWss,
    ConnectedWss,
    SwitchingToTcp,
    ConnectedTcp,
    PeerLostCleaningUp,
    Disconnecting,
    Failed,
}

impl ExternalPeerLabPhase {
    const fn network_state(self) -> NetworkState {
        match self {
            Self::Disconnected => NetworkState::Disconnected,
            Self::WaitingForValidatedPeer => NetworkState::FetchingConfig,
            Self::Ready | Self::PreparingMihomo | Self::PreparingUtun => NetworkState::PreparingTunnel,
            Self::ConnectingQuic => NetworkState::ConnectingPrimary,
            Self::ConnectedQuic => NetworkState::ConnectedPrimary,
            Self::SwitchingToWss | Self::SwitchingToTcp => NetworkState::Reconnecting,
            Self::ConnectedWss | Self::ConnectedTcp => NetworkState::DegradedFallback,
            Self::PeerLostCleaningUp | Self::Disconnecting => NetworkState::Disconnecting,
            Self::Failed => NetworkState::Error,
        }
    }

    const fn is_connecting(self) -> bool {
        matches!(
            self,
            Self::WaitingForValidatedPeer
                | Self::Ready
                | Self::PreparingMihomo
                | Self::PreparingUtun
                | Self::ConnectingQuic
                | Self::ConnectedQuic
                | Self::SwitchingToWss
                | Self::ConnectedWss
                | Self::SwitchingToTcp
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalPeerImpairmentReason {
    CarrierUnhealthyObserved,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPeerTransportCheck {
    pub transport: TransportKind,
    pub carrier_healthy: bool,
    pub private_echo_healthy: bool,
    pub mihomo_coexisting: bool,
    pub overlay_ssh_verified: bool,
    pub system_ssh_verified: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: u8,
    pub impairment_reason: Option<ExternalPeerImpairmentReason>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPeerLabStatus {
    pub runtime_mode: &'static str,
    pub tunnel_kind: &'static str,
    pub phase: ExternalPeerLabPhase,
    pub network_state: NetworkState,
    pub sidecar_state: SidecarLifecycleState,
    pub site_id: &'static str,
    pub site_display_name: &'static str,
    pub peer_vm: &'static str,
    pub non_production: bool,
    pub lan_forwarding_enabled: bool,
    pub tunnel_interface: Option<String>,
    pub private_routes: Vec<String>,
    pub routes_installed: bool,
    pub mihomo_interface: Option<String>,
    pub mihomo_route: Option<String>,
    pub active_transport: Option<TransportKind>,
    pub health: Option<NetworkHealth>,
    pub private_echo_healthy: bool,
    pub mihomo_coexisting: bool,
    pub overlay_ssh_verified: bool,
    pub system_ssh_verified: bool,
    pub transport_checks: Vec<ExternalPeerTransportCheck>,
    pub last_error: Option<NetworkErrorCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedStop {
    Cancel,
    Disconnect,
}

#[derive(Debug, Default)]
struct WorkerStopSignal {
    requested: Mutex<Option<RequestedStop>>,
    wake: Condvar,
}

impl WorkerStopSignal {
    fn request(&self, requested: RequestedStop) -> Result<RequestedStop, NetworkErrorCode> {
        let mut current = self
            .requested
            .lock()
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
        let selected = *current.get_or_insert(requested);
        drop(current);
        self.wake.notify_all();
        Ok(selected)
    }

    fn current(&self) -> Result<Option<RequestedStop>, NetworkErrorCode> {
        self.requested
            .lock()
            .map(|requested| *requested)
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)
    }

    fn wait_timeout(&self, timeout: Duration) -> Result<Option<RequestedStop>, NetworkErrorCode> {
        let selected = {
            let requested = self
                .requested
                .lock()
                .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
            let (requested, _) = self
                .wake
                .wait_timeout_while(requested, timeout, |requested| requested.is_none())
                .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
            *requested
        };
        Ok(selected)
    }
}

struct ActiveOperation {
    generation: u64,
    cancel: Arc<AtomicBool>,
    stop_signal: Arc<WorkerStopSignal>,
    handshake_gate: Arc<AtomicU8>,
    socket_abort: VmExternalPeerLabSocketAbort,
}

struct ExternalPeerState {
    generation: u64,
    phase: ExternalPeerLabPhase,
    sidecar_state: SidecarLifecycleState,
    tunnel_interface: Option<String>,
    active_transport: Option<TransportKind>,
    health: Option<NetworkHealth>,
    routes_installed: bool,
    mihomo_coexisting: bool,
    private_echo_healthy: bool,
    overlay_ssh_verified: bool,
    system_ssh_verified: bool,
    transport_checks: Vec<ExternalPeerTransportCheck>,
    last_error: Option<NetworkErrorCode>,
    operation: Option<ActiveOperation>,
}

impl ExternalPeerState {
    const fn disconnected() -> Self {
        Self {
            generation: 0,
            phase: ExternalPeerLabPhase::Disconnected,
            sidecar_state: SidecarLifecycleState::Stopped,
            tunnel_interface: None,
            active_transport: None,
            health: None,
            routes_installed: false,
            mihomo_coexisting: false,
            private_echo_healthy: false,
            overlay_ssh_verified: false,
            system_ssh_verified: false,
            transport_checks: Vec::new(),
            last_error: None,
            operation: None,
        }
    }

    fn clear_run_facts(&mut self) {
        self.tunnel_interface = None;
        self.active_transport = None;
        self.health = None;
        self.routes_installed = false;
        self.mihomo_coexisting = false;
        self.private_echo_healthy = false;
        self.overlay_ssh_verified = false;
        self.system_ssh_verified = false;
        self.transport_checks.clear();
    }

    fn snapshot(&self) -> ExternalPeerLabStatus {
        ExternalPeerLabStatus {
            runtime_mode: RUNTIME_MODE,
            tunnel_kind: TUNNEL_KIND,
            phase: self.phase,
            network_state: self.phase.network_state(),
            sidecar_state: self.sidecar_state,
            site_id: SITE_ID,
            site_display_name: SITE_DISPLAY_NAME,
            peer_vm: PEER_VM,
            non_production: true,
            lan_forwarding_enabled: false,
            tunnel_interface: self.tunnel_interface.clone(),
            private_routes: if self.routes_installed {
                vec![PRIVATE_ROUTE.to_owned()]
            } else {
                Vec::new()
            },
            routes_installed: self.routes_installed,
            mihomo_interface: self.mihomo_coexisting.then(|| MIHOMO_DEVICE.to_owned()),
            mihomo_route: self.mihomo_coexisting.then(|| MIHOMO_ROUTE.to_owned()),
            active_transport: self.active_transport,
            health: self.health.clone(),
            private_echo_healthy: self.private_echo_healthy,
            mihomo_coexisting: self.mihomo_coexisting,
            overlay_ssh_verified: self.overlay_ssh_verified,
            system_ssh_verified: self.system_ssh_verified,
            transport_checks: self.transport_checks.clone(),
            last_error: self.last_error,
        }
    }
}

static EXTERNAL_PEER_STATE: LazyLock<Mutex<ExternalPeerState>> =
    LazyLock::new(|| Mutex::new(ExternalPeerState::disconnected()));

fn lock_state() -> Result<std::sync::MutexGuard<'static, ExternalPeerState>, String> {
    EXTERNAL_PEER_STATE
        .lock()
        .map_err(|_| "invalid_state_transition".to_owned())
}

fn update_operation(generation: u64, update: impl FnOnce(&mut ExternalPeerState)) {
    if let Ok(mut state) = EXTERNAL_PEER_STATE.lock()
        && state
            .operation
            .as_ref()
            .is_some_and(|operation| operation.generation == generation && !operation.cancel.load(Ordering::Acquire))
    {
        update(&mut state);
    }
}

fn random_bytes<const N: usize>() -> Result<Vec<u8>, NetworkErrorCode> {
    let mut bytes = vec![0_u8; N];
    fill_random(&mut bytes).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    Ok(bytes)
}

fn random_instance_id() -> Result<String, NetworkErrorCode> {
    let bytes = random_bytes::<8>()?;
    let mut value = String::with_capacity(32);
    value.push_str("external.ui.");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    }
    Ok(value)
}

type SidecarIpcResult = Result<IpcResponsePayload, NetworkErrorCode>;

fn request_outcome(
    runtime: &mut ExternalPeerRuntime,
    sequence: &mut u64,
    action: &str,
    payload: IpcRequestPayload,
    cancel: &AtomicBool,
) -> Result<SidecarIpcResult, NetworkErrorCode> {
    if cancel.load(Ordering::Acquire) {
        return Err(NetworkErrorCode::OperationCancelled);
    }
    *sequence = sequence
        .checked_add(1)
        .ok_or(NetworkErrorCode::InvalidStateTransition)?;
    let request = IpcRequest {
        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
        request_id: format!("external.ui.{action}.{}", *sequence),
        payload,
    };
    Ok(runtime
        .request_cancellable(&request, cancel)?
        .result
        .map_err(|error| error.code))
}

fn request(
    runtime: &mut ExternalPeerRuntime,
    sequence: &mut u64,
    action: &str,
    payload: IpcRequestPayload,
    cancel: &AtomicBool,
) -> Result<IpcResponsePayload, NetworkErrorCode> {
    request_outcome(runtime, sequence, action, payload, cancel)?
}

fn validate_external_probe(
    probe: crate::networking::PrivateReachability,
    require_system_ssh: bool,
) -> Result<crate::networking::PrivateReachability, NetworkErrorCode> {
    if !probe.reachable
        || probe.mihomo_coexisting != Some(true)
        || probe.overlay_ssh_verified != Some(true)
        || probe.system_ssh_verified != Some(require_system_ssh)
    {
        return Err(NetworkErrorCode::AuthenticationFailed);
    }
    Ok(probe)
}

const fn impairment_reason(transport: TransportKind) -> Option<ExternalPeerImpairmentReason> {
    match transport {
        TransportKind::Quic | TransportKind::Wss => Some(ExternalPeerImpairmentReason::CarrierUnhealthyObserved),
        TransportKind::Tcp => None,
    }
}

fn impairment_poll_pause(cancel: &AtomicBool) -> Result<(), NetworkErrorCode> {
    if cancel.load(Ordering::Acquire) {
        return Err(NetworkErrorCode::OperationCancelled);
    }
    std::thread::sleep(IMPAIRMENT_HEALTH_POLL_INTERVAL);
    if cancel.load(Ordering::Acquire) {
        Err(NetworkErrorCode::OperationCancelled)
    } else {
        Ok(())
    }
}

fn observe_fixed_impairment_with<Sample, Pause>(
    transport: TransportKind,
    cancel: &AtomicBool,
    mut sample_health: Sample,
    mut pause: Pause,
) -> Result<ExternalPeerImpairmentReason, NetworkErrorCode>
where
    Sample: FnMut() -> Result<SidecarIpcResult, NetworkErrorCode>,
    Pause: FnMut(&AtomicBool) -> Result<(), NetworkErrorCode>,
{
    let Some(reason) = impairment_reason(transport) else {
        return Err(NetworkErrorCode::InvalidStateTransition);
    };
    for attempt in 0..IMPAIRMENT_HEALTH_POLL_LIMIT {
        if cancel.load(Ordering::Acquire) {
            return Err(NetworkErrorCode::OperationCancelled);
        }
        match sample_health()? {
            Ok(IpcResponsePayload::Health(health)) if !health.reachable => return Ok(reason),
            Ok(IpcResponsePayload::Health(_)) => {}
            // Only a typed unhealthy health sample proves the fallback gate.
            // A correlated backend error and a runtime/stream error can both
            // have unrelated causes and must never be relabeled as peer
            // impairment evidence.
            Err(error) => return Err(error),
            Ok(_) => return Err(NetworkErrorCode::InvalidStateTransition),
        }
        if attempt + 1 != IMPAIRMENT_HEALTH_POLL_LIMIT {
            pause(cancel)?;
        }
    }
    Err(NetworkErrorCode::OperationTimedOut)
}

fn observe_fixed_impairment(
    runtime: &mut ExternalPeerRuntime,
    sequence: &mut u64,
    transport: TransportKind,
    cancel: &AtomicBool,
) -> Result<ExternalPeerImpairmentReason, NetworkErrorCode> {
    observe_fixed_impairment_with(
        transport,
        cancel,
        || {
            request_outcome(
                runtime,
                sequence,
                "impairment_health",
                IpcRequestPayload::SampleHealth,
                cancel,
            )
        },
        impairment_poll_pause,
    )
}

const fn connected_phase(transport: TransportKind) -> ExternalPeerLabPhase {
    match transport {
        TransportKind::Quic => ExternalPeerLabPhase::ConnectedQuic,
        TransportKind::Wss => ExternalPeerLabPhase::ConnectedWss,
        TransportKind::Tcp => ExternalPeerLabPhase::ConnectedTcp,
    }
}

fn apply_verified_transport_state(
    state: &mut ExternalPeerState,
    transport: TransportKind,
    health: &NetworkHealth,
    probe: &crate::networking::PrivateReachability,
) {
    state.phase = connected_phase(transport);
    state.active_transport = Some(transport);
    state.health = Some(health.clone());
    state.routes_installed = true;
    state.private_echo_healthy = probe.reachable;
    state.mihomo_coexisting = probe.mihomo_coexisting == Some(true);
    state.overlay_ssh_verified = probe.overlay_ssh_verified == Some(true);
    state.system_ssh_verified = probe.system_ssh_verified == Some(true);
}

fn transport_check(
    transport: TransportKind,
    health: &NetworkHealth,
    probe: &crate::networking::PrivateReachability,
    impairment_reason: Option<ExternalPeerImpairmentReason>,
) -> ExternalPeerTransportCheck {
    ExternalPeerTransportCheck {
        transport,
        carrier_healthy: health.reachable,
        private_echo_healthy: probe.reachable,
        mihomo_coexisting: probe.mihomo_coexisting == Some(true),
        overlay_ssh_verified: probe.overlay_ssh_verified == Some(true),
        system_ssh_verified: probe.system_ssh_verified == Some(true),
        latency_ms: health.latency_ms,
        jitter_ms: health.jitter_ms,
        loss_percent: health.loss_percent,
        impairment_reason,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerExit {
    Disconnected,
    Failed(NetworkErrorCode),
}

const fn requested_stop_exit(
    cleanup: Result<(), NetworkErrorCode>,
    hard_aborted: Result<bool, NetworkErrorCode>,
) -> WorkerExit {
    match (cleanup, hard_aborted) {
        (Ok(()), Ok(false)) => WorkerExit::Disconnected,
        (Err(error), _) | (_, Err(error)) => WorkerExit::Failed(error),
        (Ok(()), Ok(true)) => WorkerExit::Failed(NetworkErrorCode::SidecarUnavailable),
    }
}

const fn peer_loss_exit(error: NetworkErrorCode, _cleanup: Result<(), NetworkErrorCode>) -> WorkerExit {
    WorkerExit::Failed(error)
}

fn update_steady_state(
    state: &mut ExternalPeerState,
    health: &NetworkHealth,
    probe: &crate::networking::PrivateReachability,
) {
    apply_verified_transport_state(state, TransportKind::Tcp, health, probe);
    let latest = transport_check(TransportKind::Tcp, health, probe, None);
    if let Some(check) = state
        .transport_checks
        .iter_mut()
        .find(|check| check.transport == TransportKind::Tcp)
    {
        *check = latest;
    } else {
        state.transport_checks.push(latest);
    }
}

fn sample_steady_state(
    runtime: &mut ExternalPeerRuntime,
    sequence: &mut u64,
    cancel: &AtomicBool,
) -> Result<(NetworkHealth, crate::networking::PrivateReachability), NetworkErrorCode> {
    let health = request(
        runtime,
        sequence,
        "steady_health",
        IpcRequestPayload::SampleHealth,
        cancel,
    )?;
    let IpcResponsePayload::Health(health) = health else {
        return Err(NetworkErrorCode::InvalidStateTransition);
    };
    if !health.reachable {
        return Err(NetworkErrorCode::FallbackTransportUnavailable);
    }

    let probe = request(
        runtime,
        sequence,
        "steady_private",
        IpcRequestPayload::SamplePrivateReachability,
        cancel,
    )?;
    let IpcResponsePayload::PrivateReachability(probe) = probe else {
        return Err(NetworkErrorCode::InvalidStateTransition);
    };
    if !probe.reachable
        || probe.mihomo_coexisting != Some(true)
        || probe.overlay_ssh_verified != Some(true)
        || probe.system_ssh_verified != Some(true)
    {
        return Err(NetworkErrorCode::FallbackTransportUnavailable);
    }
    Ok((health, probe))
}

fn request_worker_stop(operation: &ActiveOperation, requested: RequestedStop) -> Result<bool, NetworkErrorCode> {
    operation.stop_signal.request(requested)?;
    operation.cancel.store(true, Ordering::Release);
    Ok(operation
        .handshake_gate
        .compare_exchange(
            HANDSHAKE_PENDING,
            HANDSHAKE_ABORTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_ok())
}

fn connect_worker(
    generation: u64,
    cancel: Arc<AtomicBool>,
    stop_signal: Arc<WorkerStopSignal>,
    handshake_gate: Arc<AtomicU8>,
    socket_abort: VmExternalPeerLabSocketAbort,
) -> WorkerExit {
    let instance_id = match random_instance_id() {
        Ok(instance_id) => instance_id,
        Err(error) => return WorkerExit::Failed(error),
    };
    let mut auth_token = match random_bytes::<32>() {
        Ok(auth_token) => auth_token,
        Err(error) => return WorkerExit::Failed(error),
    };
    let private_key = match random_bytes::<32>() {
        Ok(private_key) => private_key,
        Err(error) => {
            auth_token.zeroize();
            return WorkerExit::Failed(error);
        }
    };
    let expected_auth_proof = sidecar_auth_proof(&auth_token, &instance_id);
    let context = SidecarLaunchContext::new(instance_id.clone(), auth_token.clone()).with_private_key(private_key);
    let launcher = VmExternalPeerLabSocketLauncher::new(socket_abort.clone());
    let mut runtime = StdioSidecarRuntime::with_launcher(PathBuf::from(VM_EXTERNAL_PEER_LAB_SOCKET_PATH), launcher)
        .with_response_timeout(STEADY_STATE_RESPONSE_TIMEOUT);

    let run_result = (|| -> Result<RequestedStop, NetworkErrorCode> {
        let handshake_result = runtime.start_external_peer_lab(&context);
        drop(context);
        auth_token.zeroize();
        let handshake = handshake_result?;
        if handshake.protocol_version != NETWORK_IPC_PROTOCOL_VERSION
            || handshake.instance_id != instance_id
            || handshake.auth_proof != expected_auth_proof
            || handshake.runtime_mode != RUNTIME_MODE
            || handshake.tunnel_kind != TUNNEL_KIND
            || handshake.peer_vm != PEER_VM
            || handshake.mihomo_device != MIHOMO_DEVICE
            || handshake.transport_order != TRANSPORT_ORDER
        {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        if handshake_gate
            .compare_exchange(HANDSHAKE_PENDING, HANDSHAKE_ACTIVE, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return stop_signal.current()?.ok_or(NetworkErrorCode::OperationCancelled);
        }
        if let Some(requested) = stop_signal.current()? {
            return Ok(requested);
        }
        update_operation(generation, |state| {
            state.phase = ExternalPeerLabPhase::Ready;
            state.sidecar_state = SidecarLifecycleState::Running;
        });

        let mut sequence = 0_u64;
        update_operation(generation, |state| state.phase = ExternalPeerLabPhase::PreparingMihomo);
        update_operation(generation, |state| state.phase = ExternalPeerLabPhase::PreparingUtun);
        let request_id = format!("external.ui.prepare.{}", sequence + 1);
        let prepared = request(
            &mut runtime,
            &mut sequence,
            "prepare",
            IpcRequestPayload::PrepareTunnel,
            &cancel,
        )?;
        let IpcResponsePayload::TunnelPrepared(facts) = prepared else {
            return Err(NetworkErrorCode::InvalidStateTransition);
        };
        let valid_interface = facts
            .interface_name
            .strip_prefix("utun")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()));
        if !valid_interface
            || facts.interface_name == MIHOMO_DEVICE
            || facts.instance_id != instance_id
            || facts.operation_id != request_id
            || facts.mtu != 1420
            || !facts.has_ipv4
        {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        update_operation(generation, |state| {
            state.tunnel_interface = Some(facts.interface_name.clone())
        });

        for (index, transport) in TRANSPORT_ORDER.iter().copied().enumerate() {
            let connecting_phase = match transport {
                TransportKind::Quic => ExternalPeerLabPhase::ConnectingQuic,
                TransportKind::Wss => ExternalPeerLabPhase::SwitchingToWss,
                TransportKind::Tcp => ExternalPeerLabPhase::SwitchingToTcp,
            };
            update_operation(generation, |state| {
                state.phase = connecting_phase;
                state.active_transport = None;
            });
            let connected = request(
                &mut runtime,
                &mut sequence,
                "connect",
                IpcRequestPayload::ConnectTransport { transport },
                &cancel,
            )?;
            let expected_state = if transport == TransportKind::Quic {
                NetworkState::ConnectedPrimary
            } else {
                NetworkState::DegradedFallback
            };
            if !matches!(
                connected,
                IpcResponsePayload::Status(status)
                    if status.state == expected_state && status.active_transport == Some(transport)
            ) {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            let health = request(
                &mut runtime,
                &mut sequence,
                "health",
                IpcRequestPayload::SampleHealth,
                &cancel,
            )?;
            let IpcResponsePayload::Health(health) = health else {
                return Err(NetworkErrorCode::InvalidStateTransition);
            };
            if !health.reachable {
                return Err(if transport == TransportKind::Quic {
                    NetworkErrorCode::PrimaryTransportUnavailable
                } else {
                    NetworkErrorCode::FallbackTransportUnavailable
                });
            }
            let probe = request(
                &mut runtime,
                &mut sequence,
                "private",
                IpcRequestPayload::SamplePrivateReachability,
                &cancel,
            )?;
            let IpcResponsePayload::PrivateReachability(probe) = probe else {
                return Err(NetworkErrorCode::InvalidStateTransition);
            };
            let require_system_ssh = transport == TransportKind::Tcp;
            let probe = validate_external_probe(probe, require_system_ssh)?;
            update_operation(generation, |state| {
                apply_verified_transport_state(state, transport, &health, &probe);
            });
            if index + 1 != TRANSPORT_ORDER.len() {
                // The peer injects its locked impairment only after echo and
                // overlay SSH have both succeeded on this exact carrier. Do
                // not manufacture fallback by disconnecting a healthy carrier.
                let observed_reason = observe_fixed_impairment(&mut runtime, &mut sequence, transport, &cancel)?;
                let check = transport_check(transport, &health, &probe, Some(observed_reason));
                update_operation(generation, |state| state.transport_checks.push(check));
                let disconnected = request(
                    &mut runtime,
                    &mut sequence,
                    "disconnect",
                    IpcRequestPayload::DisconnectTransport,
                    &cancel,
                )?;
                if !matches!(
                    disconnected,
                    IpcResponsePayload::Status(status)
                        if status.state == NetworkState::PreparingTunnel && status.active_transport.is_none()
                ) {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
                update_operation(generation, |state| state.active_transport = None);
            } else {
                let check = transport_check(transport, &health, &probe, None);
                update_operation(generation, |state| state.transport_checks.push(check));
            }
        }
        loop {
            if let Some(requested) = stop_signal.wait_timeout(STEADY_STATE_HEALTH_INTERVAL)? {
                return Ok(requested);
            }
            match sample_steady_state(&mut runtime, &mut sequence, &cancel) {
                Ok((health, probe)) => {
                    update_operation(generation, |state| update_steady_state(state, &health, &probe));
                }
                Err(NetworkErrorCode::OperationCancelled) => {
                    if let Some(requested) = stop_signal.current()? {
                        return Ok(requested);
                    }
                    return Err(NetworkErrorCode::OperationCancelled);
                }
                Err(error) => return Err(error),
            }
        }
    })();

    match run_result {
        Ok(_requested) => {
            let cleanup = runtime.stop();
            requested_stop_exit(cleanup, socket_abort.was_hard_aborted())
        }
        Err(error) => {
            if stop_signal.current().ok().flatten().is_some() {
                let cleanup = runtime.stop();
                requested_stop_exit(cleanup, socket_abort.was_hard_aborted())
            } else {
                update_operation(generation, |state| {
                    state.phase = ExternalPeerLabPhase::PeerLostCleaningUp;
                    state.last_error = Some(error);
                });
                // Preserve the peer/runtime failure after cleanup. A later
                // successful stop proves teardown, not recovery of the lost
                // carrier.
                let cleanup = runtime.stop();
                peer_loss_exit(error, cleanup)
            }
        }
    }
}

fn finish_worker(generation: u64, result: WorkerExit) {
    let Ok(mut state) = EXTERNAL_PEER_STATE.lock() else {
        return;
    };
    if state
        .operation
        .as_ref()
        .is_none_or(|operation| operation.generation != generation)
    {
        return;
    }
    state.operation = None;
    state.sidecar_state = SidecarLifecycleState::Stopped;
    state.clear_run_facts();
    match result {
        WorkerExit::Disconnected => {
            state.phase = ExternalPeerLabPhase::Disconnected;
            // The reviewed root supervisor is deliberately one-shot. Cleanup
            // completed, but a new Connect is unavailable until the lab is
            // visibly re-staged/restarted outside this App.
            state.last_error = Some(NetworkErrorCode::SidecarUnavailable);
        }
        WorkerExit::Failed(error) => {
            state.phase = ExternalPeerLabPhase::Failed;
            state.last_error = Some(error);
        }
    }
}

#[tauri::command]
pub fn get_networking_external_peer_lab_status() -> Result<ExternalPeerLabStatus, String> {
    Ok(lock_state()?.snapshot())
}

#[tauri::command]
pub fn connect_networking_external_peer_lab() -> Result<ExternalPeerLabStatus, String> {
    let (generation, cancel, stop_signal, handshake_gate, socket_abort, snapshot) = {
        let mut state = lock_state()?;
        if state.operation.is_some() || state.phase.is_connecting() {
            return Ok(state.snapshot());
        }
        if matches!(
            state.phase,
            ExternalPeerLabPhase::Disconnecting | ExternalPeerLabPhase::PeerLostCleaningUp
        ) {
            return Err("invalid_state_transition".to_owned());
        }
        if state.generation != 0 {
            // The current reviewed root supervisor accepts exactly one App
            // session. Never imply that an in-App reconnect can re-arm it.
            return Err("sidecar_unavailable".to_owned());
        }
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| "invalid_state_transition".to_owned())?;
        let generation = state.generation;
        let cancel = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::new(WorkerStopSignal::default());
        let handshake_gate = Arc::new(AtomicU8::new(HANDSHAKE_PENDING));
        let socket_abort = VmExternalPeerLabSocketAbort::default();
        state.clear_run_facts();
        state.last_error = None;
        state.phase = ExternalPeerLabPhase::WaitingForValidatedPeer;
        state.sidecar_state = SidecarLifecycleState::Starting;
        state.operation = Some(ActiveOperation {
            generation,
            cancel: Arc::clone(&cancel),
            stop_signal: Arc::clone(&stop_signal),
            handshake_gate: Arc::clone(&handshake_gate),
            socket_abort: socket_abort.clone(),
        });
        (
            generation,
            cancel,
            stop_signal,
            handshake_gate,
            socket_abort,
            state.snapshot(),
        )
    };
    if std::thread::Builder::new()
        .name("kyclash-external-peer-runtime".to_owned())
        .spawn(move || {
            let result = connect_worker(generation, cancel, stop_signal, handshake_gate, socket_abort);
            finish_worker(generation, result);
        })
        .is_err()
    {
        let mut state = lock_state()?;
        if state.generation == generation {
            state.operation = None;
            state.phase = ExternalPeerLabPhase::Failed;
            state.sidecar_state = SidecarLifecycleState::Stopped;
            state.last_error = Some(NetworkErrorCode::SidecarUnavailable);
        }
        drop(state);
        return Err("sidecar_unavailable".to_owned());
    }
    Ok(snapshot)
}

#[tauri::command]
pub fn cancel_networking_external_peer_lab() -> Result<ExternalPeerLabStatus, String> {
    let mut state = lock_state()?;
    let Some(operation) = state.operation.as_ref() else {
        return Ok(state.snapshot());
    };
    let hard_abort = request_worker_stop(operation, RequestedStop::Cancel).map_err(|error| format!("{error:?}"))?;
    let abort = hard_abort.then(|| operation.socket_abort.clone());
    state.phase = ExternalPeerLabPhase::Disconnecting;
    let snapshot = state.snapshot();
    drop(state);
    if let Some(abort) = abort {
        abort.cancel().map_err(|error| format!("{error:?}"))?;
    }
    Ok(snapshot)
}

#[tauri::command]
pub fn disconnect_networking_external_peer_lab() -> Result<ExternalPeerLabStatus, String> {
    let (snapshot, abort) = {
        let mut state = lock_state()?;
        if let Some(operation) = state.operation.as_ref() {
            let hard_abort =
                request_worker_stop(operation, RequestedStop::Disconnect).map_err(|error| format!("{error:?}"))?;
            let abort = hard_abort.then(|| operation.socket_abort.clone());
            state.phase = ExternalPeerLabPhase::Disconnecting;
            (state.snapshot(), abort)
        } else {
            return Ok(state.snapshot());
        }
    };
    if let Some(abort) = abort {
        abort.cancel().map_err(|error| format!("{error:?}"))?;
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::PrivateReachability;

    #[test]
    fn disconnected_status_is_redacted_and_non_production() -> anyhow::Result<()> {
        let status = ExternalPeerState::disconnected().snapshot();
        assert_eq!(status.phase, ExternalPeerLabPhase::Disconnected);
        assert!(status.non_production);
        assert!(!status.lan_forwarding_enabled);
        assert!(status.private_routes.is_empty());
        let json = serde_json::to_string(&status)?;
        for forbidden in [
            "endpoint",
            "certificate",
            "public_key",
            "private_key",
            "descriptor",
            "process_id",
            "socket_path",
        ] {
            assert!(!json.contains(forbidden), "status leaked forbidden field {forbidden}");
        }
        Ok(())
    }

    fn private_probe(system_ssh_verified: Option<bool>) -> PrivateReachability {
        PrivateReachability {
            reachable: true,
            latency_ms: 1,
            mihomo_coexisting: Some(true),
            overlay_ssh_verified: Some(true),
            system_ssh_verified,
        }
    }

    fn healthy_carrier() -> NetworkHealth {
        NetworkHealth {
            reachable: true,
            latency_ms: 2,
            jitter_ms: 1,
            loss_percent: 0,
        }
    }

    #[test]
    fn tcp_alone_requires_system_ssh_and_early_carriers_require_pending_false() {
        let legacy = PrivateReachability {
            reachable: true,
            latency_ms: 1,
            mihomo_coexisting: None,
            overlay_ssh_verified: None,
            system_ssh_verified: None,
        };
        assert_eq!(
            validate_external_probe(legacy, false),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        assert!(validate_external_probe(private_probe(Some(false)), false).is_ok());
        assert_eq!(
            validate_external_probe(private_probe(Some(true)), false),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
        assert!(validate_external_probe(private_probe(Some(true)), true).is_ok());
        assert_eq!(
            validate_external_probe(private_probe(Some(false)), true),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
    }

    #[test]
    fn status_and_transport_checks_keep_system_ssh_false_until_tcp() {
        let mut state = ExternalPeerState::disconnected();
        let health = healthy_carrier();

        for (transport, reason) in [
            (
                TransportKind::Quic,
                ExternalPeerImpairmentReason::CarrierUnhealthyObserved,
            ),
            (
                TransportKind::Wss,
                ExternalPeerImpairmentReason::CarrierUnhealthyObserved,
            ),
        ] {
            let probe = private_probe(Some(false));
            apply_verified_transport_state(&mut state, transport, &health, &probe);
            let check = transport_check(transport, &health, &probe, Some(reason));
            assert!(!state.system_ssh_verified);
            assert!(!check.system_ssh_verified);
            assert_eq!(check.impairment_reason, Some(reason));
            state.transport_checks.push(check);
        }

        let tcp_probe = private_probe(Some(true));
        apply_verified_transport_state(&mut state, TransportKind::Tcp, &health, &tcp_probe);
        let tcp_check = transport_check(TransportKind::Tcp, &health, &tcp_probe, None);
        assert!(state.system_ssh_verified);
        assert!(tcp_check.system_ssh_verified);
        assert_eq!(tcp_check.impairment_reason, None);
        state.transport_checks.push(tcp_check);

        let snapshot = state.snapshot();
        assert!(snapshot.system_ssh_verified);
        assert_eq!(snapshot.transport_checks.len(), 3);
        assert!(
            snapshot.transport_checks[..2]
                .iter()
                .all(|check| !check.system_ssh_verified && check.impairment_reason.is_some())
        );
        assert!(
            snapshot.transport_checks[2].system_ssh_verified
                && snapshot.transport_checks[2].impairment_reason.is_none()
        );
    }

    #[test]
    fn healthy_samples_exhaust_impairment_gate_without_advancing() {
        let cancel = AtomicBool::new(false);
        let mut samples = 0;
        let mut pauses = 0;
        let result = observe_fixed_impairment_with(
            TransportKind::Quic,
            &cancel,
            || {
                samples += 1;
                Ok(Ok(IpcResponsePayload::Health(healthy_carrier())))
            },
            |_| {
                pauses += 1;
                Ok(())
            },
        );
        assert_eq!(result, Err(NetworkErrorCode::OperationTimedOut));
        assert_eq!(samples, IMPAIRMENT_HEALTH_POLL_LIMIT);
        assert_eq!(pauses, IMPAIRMENT_HEALTH_POLL_LIMIT - 1);
    }

    #[test]
    fn only_typed_unhealthy_health_opens_the_impairment_gate() {
        let cancel = AtomicBool::new(false);
        let unhealthy = observe_fixed_impairment_with(
            TransportKind::Wss,
            &cancel,
            || {
                Ok(Ok(IpcResponsePayload::Health(NetworkHealth {
                    reachable: false,
                    latency_ms: 0,
                    jitter_ms: 0,
                    loss_percent: 100,
                })))
            },
            |_| Ok(()),
        );
        assert_eq!(unhealthy, Ok(ExternalPeerImpairmentReason::CarrierUnhealthyObserved));

        let correlated_backend_rejection = observe_fixed_impairment_with(
            TransportKind::Quic,
            &cancel,
            || Ok(Err(NetworkErrorCode::SidecarUnavailable)),
            |_| Ok(()),
        );
        assert_eq!(correlated_backend_rejection, Err(NetworkErrorCode::SidecarUnavailable));

        let runtime_failure = observe_fixed_impairment_with(
            TransportKind::Quic,
            &cancel,
            || Err(NetworkErrorCode::SidecarUnavailable),
            |_| Ok(()),
        );
        assert_eq!(runtime_failure, Err(NetworkErrorCode::SidecarUnavailable));
        assert_eq!(
            observe_fixed_impairment_with(
                TransportKind::Tcp,
                &cancel,
                || Ok(Ok(IpcResponsePayload::Health(healthy_carrier()))),
                |_| Ok(()),
            ),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
    }

    #[test]
    fn phase_mapping_keeps_startup_and_fallback_distinct() {
        assert_eq!(
            ExternalPeerLabPhase::WaitingForValidatedPeer.network_state(),
            NetworkState::FetchingConfig
        );
        assert_eq!(
            ExternalPeerLabPhase::ConnectedQuic.network_state(),
            NetworkState::ConnectedPrimary
        );
        assert_eq!(
            ExternalPeerLabPhase::ConnectedTcp.network_state(),
            NetworkState::DegradedFallback
        );
        assert_eq!(ExternalPeerLabPhase::Failed.network_state(), NetworkState::Error);
    }

    #[test]
    fn requested_stop_needs_graceful_cleanup_without_a_socket_abort() {
        assert_eq!(requested_stop_exit(Ok(()), Ok(false)), WorkerExit::Disconnected);
        assert_eq!(
            requested_stop_exit(Ok(()), Ok(true)),
            WorkerExit::Failed(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(
            requested_stop_exit(Err(NetworkErrorCode::RouteRollbackFailed), Ok(false)),
            WorkerExit::Failed(NetworkErrorCode::RouteRollbackFailed)
        );
    }

    #[test]
    fn peer_loss_is_preserved_even_when_cleanup_succeeds() {
        assert_eq!(
            peer_loss_exit(NetworkErrorCode::FallbackTransportUnavailable, Ok(())),
            WorkerExit::Failed(NetworkErrorCode::FallbackTransportUnavailable)
        );
        assert_eq!(
            peer_loss_exit(
                NetworkErrorCode::SidecarUnavailable,
                Err(NetworkErrorCode::RouteRollbackFailed),
            ),
            WorkerExit::Failed(NetworkErrorCode::SidecarUnavailable)
        );
    }

    #[test]
    fn stop_signal_is_idempotent_and_wakes_the_health_wait() {
        let signal = WorkerStopSignal::default();
        assert_eq!(signal.request(RequestedStop::Cancel), Ok(RequestedStop::Cancel));
        assert_eq!(signal.request(RequestedStop::Disconnect), Ok(RequestedStop::Cancel));
        assert_eq!(
            signal.wait_timeout(Duration::from_secs(1)),
            Ok(Some(RequestedStop::Cancel))
        );
    }

    #[test]
    fn steady_state_refreshes_the_single_tcp_proof() {
        let mut state = ExternalPeerState::disconnected();
        let initial_health = healthy_carrier();
        let probe = private_probe(Some(true));
        state
            .transport_checks
            .push(transport_check(TransportKind::Tcp, &initial_health, &probe, None));

        let latest_health = NetworkHealth {
            reachable: true,
            latency_ms: 17,
            jitter_ms: 4,
            loss_percent: 2,
        };
        update_steady_state(&mut state, &latest_health, &probe);

        assert_eq!(state.phase, ExternalPeerLabPhase::ConnectedTcp);
        assert_eq!(state.transport_checks.len(), 1);
        assert_eq!(state.transport_checks[0].latency_ms, 17);
        assert_eq!(state.transport_checks[0].jitter_ms, 4);
        assert_eq!(state.transport_checks[0].loss_percent, 2);
        assert!(state.system_ssh_verified);
    }

    #[test]
    fn fixed_contract_has_no_frontend_selected_authority() {
        assert_eq!(
            VM_EXTERNAL_PEER_LAB_SOCKET_PATH,
            "/var/run/net.kysion.kyclash.vm-external-peer-lab.sock"
        );
        assert_eq!(PEER_VM, "kyclash-macos-lab-peer");
        assert_eq!(PRIVATE_ROUTE, "10.88.0.2/32");
        assert_eq!(MIHOMO_DEVICE, "utun4094");
        assert_eq!(MIHOMO_ROUTE, "10.88.0.0/24");
        assert_eq!(
            TRANSPORT_ORDER,
            [TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp]
        );
        assert_eq!(STEADY_STATE_RESPONSE_TIMEOUT, Duration::from_secs(15));
        assert_eq!(STEADY_STATE_HEALTH_INTERVAL, Duration::from_secs(1));
        assert_eq!(IMPAIRMENT_HEALTH_POLL_LIMIT, 3);
        assert_eq!(IMPAIRMENT_HEALTH_POLL_INTERVAL, Duration::from_millis(100));
    }
}
