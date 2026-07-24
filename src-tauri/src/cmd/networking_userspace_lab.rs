//! Explicit no-sign networking lab commands.
//!
//! This module is intentionally behind `networking-userspace-lab-app`, which
//! implies both `networking-dev` and `networking-system-lab`.  It is the only
//! App-facing path for the unsigned loopback lab candidate.  The path starts
//! the fixed, bundled Go lab sidecar and exercises its userspace WireGuard
//! netstack over QUIC, WSS, and TCP. With the additional default-off
//! `networking-vm-utun-lab-app` feature on macOS, only the launch seam changes
//! to the fixed, manually authorized VirtualMac root socket and the same
//! protocol creates a real utun. The sibling `networking-vm-network-lab-app`
//! profile uses a second fixed socket whose guest harness additionally owns
//! the private echo route and Mihomo coexistence fixture. Neither mode opens
//! the production route helper, reads Keychain, or changes routes/DNS from the
//! App process.

use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
use std::time::Duration;

use getrandom::fill as fill_random;
use reqwest::Url;
use serde::Serialize;
use tauri::{AppHandle, Manager as _, Wry};

use crate::networking::{
    IpcRequest, IpcRequestPayload, IpcResponsePayload, NetworkErrorCode, NetworkHealth, NetworkProfile, NetworkState,
    SidecarLaunchContext, SidecarLifecycleState, SidecarRuntime as _, StdioSidecarRuntime, TransportKind,
    sidecar_auth_proof,
};
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
use crate::networking::{VM_NETWORK_LAB_SOCKET_PATH, VmNetworkLabSocketLauncher};
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
use crate::networking::{VM_UTUN_LAB_SOCKET_PATH, VmUtunLabSocketLauncher};

#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_SIDECAR_RESOURCE: &str = "kyclash-network-sidecar-lab";
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_MODE: &str = "userspace_lab";
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_MODE: &str = "vm_network_lab";
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_MODE: &str = "vm_utun_lab";
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_TUNNEL_KIND: &str = "userspace_netstack";
#[cfg(any(
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
))]
const LAB_TUNNEL_KIND: &str = "darwin_utun";
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_SITE_ID: &str = "lab";
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_SITE_ID: &str = "lab-vm-network";
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_SITE_ID: &str = "lab-vm-utun";
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_SITE_NAME: &str = "KyClash loopback userspace lab";
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_SITE_NAME: &str = "KyClash VM lab · real utun · private route · Mihomo";
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_SITE_NAME: &str = "KyClash VM lab · real utun · no routes";
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
const LAB_PROFILE_ID: &str = "lab.actual-child";
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_PROFILE_ID: &str = "lab.vm-network.actual-child";
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
const LAB_PROFILE_ID: &str = "lab.vm-utun.actual-child";
const LAB_CONNECT_SEQUENCE: [TransportKind; 3] = [TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp];
#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
const VM_NETWORK_LAB_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(all(
    feature = "networking-vm-network-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-utun-lab-app"),
    not(feature = "networking-production"),
))]
type LabSidecarRuntime = StdioSidecarRuntime<VmNetworkLabSocketLauncher>;
#[cfg(all(
    feature = "networking-vm-utun-lab-app",
    target_os = "macos",
    not(feature = "networking-vm-network-lab-app"),
    not(feature = "networking-production"),
))]
type LabSidecarRuntime = StdioSidecarRuntime<VmUtunLabSocketLauncher>;
#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
type LabSidecarRuntime = StdioSidecarRuntime;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct UserspaceLabTransportCheck {
    pub transport: TransportKind,
    pub reachable: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: u8,
    /// The VM-network harness' private echo result for this carrier sample.
    /// Other lab profiles leave it false because they intentionally have no
    /// route mutation or private-network assertion.
    pub private_reachable: bool,
    pub mihomo_coexisting: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserspaceLabStatus {
    pub runtime_mode: &'static str,
    pub tunnel_kind: &'static str,
    pub network_state: NetworkState,
    pub sidecar_state: SidecarLifecycleState,
    pub site_id: String,
    pub site_display_name: String,
    pub private_routes: Vec<String>,
    pub routes_installed: bool,
    pub private_reachable: bool,
    pub mihomo_coexisting: bool,
    pub tunnel_interface: Option<String>,
    pub active_transport: Option<TransportKind>,
    pub health: Option<NetworkHealth>,
    pub transport_checks: Vec<UserspaceLabTransportCheck>,
    pub last_error: Option<NetworkErrorCode>,
}

struct UserspaceLabSession {
    runtime: LabSidecarRuntime,
    profile: NetworkProfile,
    instance_id: String,
    tunnel_interface: Option<String>,
    active_transport: Option<TransportKind>,
    health: Option<NetworkHealth>,
    checks: Vec<UserspaceLabTransportCheck>,
    routes_installed: bool,
    private_reachable: bool,
    mihomo_coexisting: bool,
    request_sequence: u64,
}

struct UserspaceLabRuntime {
    executable: Option<PathBuf>,
    session: Option<UserspaceLabSession>,
    last_error: Option<NetworkErrorCode>,
    last_profile: Option<NetworkProfile>,
}

static LAB_RUNTIME: LazyLock<Mutex<UserspaceLabRuntime>> = LazyLock::new(|| {
    Mutex::new(UserspaceLabRuntime {
        executable: None,
        session: None,
        last_error: None,
        last_profile: None,
    })
});

fn error_code(error: NetworkErrorCode) -> String {
    format!("{error:?}")
}

#[cfg(not(any(
    all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ),
    all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ),
)))]
fn fixed_sidecar_path(app: &AppHandle<Wry>) -> Result<PathBuf, NetworkErrorCode> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let resource = resource_dir.join(LAB_SIDECAR_RESOURCE);
    let metadata = std::fs::symlink_metadata(&resource).map_err(|_| NetworkErrorCode::SidecarUnavailable)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(NetworkErrorCode::SidecarUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return Err(NetworkErrorCode::SidecarUnavailable);
        }
    }
    Ok(resource)
}

fn lab_runtime_identity(app: &AppHandle<Wry>) -> Result<PathBuf, NetworkErrorCode> {
    #[cfg(all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ))]
    {
        let _ = app
            .path()
            .resource_dir()
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        Ok(PathBuf::from(VM_NETWORK_LAB_SOCKET_PATH))
    }
    #[cfg(all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ))]
    {
        // Preserve a real AppHandle/path failure boundary even though this
        // profile intentionally has no bundled sidecar resource.
        let _ = app
            .path()
            .resource_dir()
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        Ok(PathBuf::from(VM_UTUN_LAB_SOCKET_PATH))
    }
    #[cfg(not(any(
        all(
            feature = "networking-vm-utun-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-network-lab-app"),
            not(feature = "networking-production"),
        ),
        all(
            feature = "networking-vm-network-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-utun-lab-app"),
            not(feature = "networking-production"),
        ),
    )))]
    {
        fixed_sidecar_path(app)
    }
}

fn new_lab_runtime(identity: PathBuf) -> LabSidecarRuntime {
    #[cfg(all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ))]
    {
        // Route-table, controller, process-identity, and private-echo
        // inspections all happen inside the fixed root fixture. A busy
        // disposable VM can legitimately exceed the generic two-second stdio
        // timeout, but the lab must still retain a strict per-request bound.
        StdioSidecarRuntime::with_launcher(identity, VmNetworkLabSocketLauncher::new())
            .with_response_timeout(VM_NETWORK_LAB_RESPONSE_TIMEOUT)
    }
    #[cfg(all(
        feature = "networking-vm-utun-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-network-lab-app"),
        not(feature = "networking-production"),
    ))]
    {
        StdioSidecarRuntime::with_launcher(identity, VmUtunLabSocketLauncher::new())
    }
    #[cfg(not(any(
        all(
            feature = "networking-vm-utun-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-network-lab-app"),
            not(feature = "networking-production"),
        ),
        all(
            feature = "networking-vm-network-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-utun-lab-app"),
            not(feature = "networking-production"),
        ),
    )))]
    {
        StdioSidecarRuntime::new(identity)
    }
}

fn valid_lab_interface(interface_name: &str) -> bool {
    #[cfg(any(
        all(
            feature = "networking-vm-utun-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-network-lab-app"),
            not(feature = "networking-production"),
        ),
        all(
            feature = "networking-vm-network-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-utun-lab-app"),
            not(feature = "networking-production"),
        ),
    ))]
    {
        let suffix = interface_name.strip_prefix("utun");
        suffix.is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
    }
    #[cfg(not(any(
        all(
            feature = "networking-vm-utun-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-network-lab-app"),
            not(feature = "networking-production"),
        ),
        all(
            feature = "networking-vm-network-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-utun-lab-app"),
            not(feature = "networking-production"),
        ),
    )))]
    {
        interface_name == "userspace"
    }
}

fn random_bytes<const N: usize>() -> Result<Vec<u8>, NetworkErrorCode> {
    let mut bytes = vec![0_u8; N];
    fill_random(&mut bytes).map_err(|_| NetworkErrorCode::AuthenticationFailed)?;
    Ok(bytes)
}

fn random_instance_id() -> Result<String, NetworkErrorCode> {
    let bytes = random_bytes::<8>()?;
    let mut value = String::with_capacity(24);
    value.push_str("lab.ui.");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    }
    Ok(value)
}

fn is_loopback_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    match url.host_str() {
        Some("127.0.0.1" | "localhost" | "::1") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

fn validate_lab_profile(profile: &NetworkProfile) -> Result<(), NetworkErrorCode> {
    profile.validate()?;
    if profile.profile_id != LAB_PROFILE_ID
        || profile.site.id != LAB_SITE_ID
        || !profile.control_plane.starts_with("https://127.0.0.1/")
        || !profile.site.private_cidrs.iter().any(|cidr| cidr == "10.88.0.2/32")
        || !profile.tunnel.local_addresses.iter().any(|cidr| cidr == "10.88.0.1/32")
        || profile.transports.primary != TransportKind::Quic
        || profile.transports.fallbacks != [TransportKind::Wss, TransportKind::Tcp]
        || profile.transports.endpoints.len() != 3
        || profile
            .transports
            .endpoints
            .iter()
            .any(|endpoint| !is_loopback_url(&endpoint.url))
    {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    Ok(())
}

impl UserspaceLabSession {
    fn next_request_id(&mut self, action: &str) -> String {
        self.request_sequence = self.request_sequence.saturating_add(1);
        format!("lab.ui.{action}.{}", self.request_sequence)
    }

    fn request(&mut self, payload: IpcRequestPayload, action: &str) -> Result<IpcResponsePayload, NetworkErrorCode> {
        let request_id = self.next_request_id(action);
        let response = self.runtime.request(&IpcRequest {
            protocol_version: crate::networking::NETWORK_IPC_PROTOCOL_VERSION,
            request_id,
            payload,
        })?;
        response.result.map_err(|error| error.code)
    }

    fn disconnect_active(&mut self) -> Result<(), NetworkErrorCode> {
        if self.active_transport.take().is_some() {
            let response = self.request(IpcRequestPayload::DisconnectTransport, "disconnect")?;
            if !matches!(response, IpcResponsePayload::Status(status) if status.state == NetworkState::PreparingTunnel && status.active_transport.is_none())
            {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
        }
        self.health = None;
        Ok(())
    }

    /// Observe the exact child handle before sending another IPC request.
    ///
    /// The userspace lab is deliberately a small App-facing harness rather
    /// than the production restart controller, but it still must not report
    /// `running` after its child has exited. `StdioSidecarRuntime::status`
    /// releases only its own generation-bound handle, so this check cannot
    /// accidentally inspect or terminate an unrelated process.
    fn poll_liveness(&mut self) -> Result<(), NetworkErrorCode> {
        match self.runtime.status()? {
            crate::networking::SidecarProcessStatus::Running => Ok(()),
            crate::networking::SidecarProcessStatus::Exited { .. } => Err(NetworkErrorCode::SidecarUnavailable),
        }
    }

    fn stop(mut self) -> Result<(), NetworkErrorCode> {
        let _ = self.disconnect_active();
        if self.tunnel_interface.is_some() {
            let _ = self.request(IpcRequestPayload::StopTunnel, "stop-tunnel");
            self.tunnel_interface = None;
        }
        self.runtime.stop()
    }
}

impl UserspaceLabRuntime {
    fn status(&mut self, executable: Option<PathBuf>) -> Result<UserspaceLabStatus, NetworkErrorCode> {
        if let Some(path) = executable {
            if let Some(existing) = &self.executable {
                if existing != &path {
                    return Err(NetworkErrorCode::InvalidConfiguration);
                }
            } else {
                self.executable = Some(path);
            }
        }
        if self.session.is_some() {
            // Poll the exact child before issuing GetStatus. An EOF or a
            // crashed sidecar must converge to a disconnected, retryable
            // snapshot instead of leaving the UI stuck at
            // `sidecar_state=running` forever.
            let liveness = match self.session.as_mut() {
                Some(session) => session.poll_liveness(),
                None => Ok(()),
            };
            if let Err(error) = liveness {
                if let Some(session) = self.session.take() {
                    let _ = session.stop();
                }
                self.last_error = Some(error);
                return Ok(self.snapshot_disconnected());
            }
        }
        if let Some(session) = self.session.as_mut() {
            let response = session.request(IpcRequestPayload::GetStatus, "status")?;
            if let IpcResponsePayload::Status(status) = response {
                return Ok(self.snapshot_from_sidecar(status));
            }
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        Ok(self.snapshot_disconnected())
    }

    fn snapshot_from_sidecar(&self, status: crate::networking::NetworkStatus) -> UserspaceLabStatus {
        let session = self.session.as_ref();
        let profile = session.map(|value| &value.profile).or(self.last_profile.as_ref());
        UserspaceLabStatus {
            runtime_mode: LAB_MODE,
            tunnel_kind: LAB_TUNNEL_KIND,
            network_state: status.state,
            sidecar_state: if session.is_some() {
                SidecarLifecycleState::Running
            } else {
                SidecarLifecycleState::Stopped
            },
            site_id: profile.map_or_else(|| LAB_SITE_ID.to_owned(), |value| value.site.id.clone()),
            site_display_name: profile
                .map_or_else(|| LAB_SITE_NAME.to_owned(), |value| value.site.display_name.clone()),
            private_routes: profile.map_or_else(Vec::new, |value| value.site.private_cidrs.clone()),
            routes_installed: session.is_some_and(|value| value.routes_installed),
            private_reachable: session.is_some_and(|value| value.private_reachable),
            mihomo_coexisting: session.is_some_and(|value| value.mihomo_coexisting),
            tunnel_interface: session.and_then(|value| value.tunnel_interface.clone()),
            active_transport: session.and_then(|value| value.active_transport),
            health: session.and_then(|value| value.health.clone()),
            transport_checks: session.map_or_else(Vec::new, |value| value.checks.clone()),
            last_error: self.last_error.or(status.last_error),
        }
    }

    fn snapshot_disconnected(&self) -> UserspaceLabStatus {
        UserspaceLabStatus {
            runtime_mode: LAB_MODE,
            tunnel_kind: LAB_TUNNEL_KIND,
            network_state: if self.last_error.is_some() {
                NetworkState::Error
            } else {
                NetworkState::Disconnected
            },
            sidecar_state: SidecarLifecycleState::Stopped,
            site_id: self
                .last_profile
                .as_ref()
                .map_or_else(|| LAB_SITE_ID.to_owned(), |value| value.site.id.clone()),
            site_display_name: self
                .last_profile
                .as_ref()
                .map_or_else(|| LAB_SITE_NAME.to_owned(), |value| value.site.display_name.clone()),
            private_routes: self
                .last_profile
                .as_ref()
                .map_or_else(Vec::new, |value| value.site.private_cidrs.clone()),
            routes_installed: false,
            private_reachable: false,
            mihomo_coexisting: false,
            tunnel_interface: None,
            active_transport: None,
            health: None,
            transport_checks: Vec::new(),
            last_error: self.last_error,
        }
    }

    fn connect(&mut self, executable: PathBuf) -> Result<UserspaceLabStatus, NetworkErrorCode> {
        if self.session.is_some() {
            let status = self.status(Some(executable.clone()))?;
            // `status` may have retired a crashed child. In that case carry
            // on with one fresh lab launch so a single Connect click can
            // recover from an EOF/crash. A live session remains idempotent.
            if self.session.is_some() {
                return Ok(status);
            }
        }
        self.last_error = None;
        self.executable = Some(executable.clone());
        let instance_id = random_instance_id()?;
        let auth_token = random_bytes::<32>()?;
        let private_key = random_bytes::<32>()?;
        let context = SidecarLaunchContext::new(instance_id.clone(), auth_token.clone()).with_private_key(private_key);
        let mut runtime = new_lab_runtime(executable);
        let handshake = runtime.start_lab(&context)?;
        if handshake.protocol_version != crate::networking::NETWORK_IPC_PROTOCOL_VERSION
            || handshake.instance_id != instance_id
            || handshake.auth_proof != sidecar_auth_proof(&auth_token, &instance_id)
        {
            let _ = runtime.stop();
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        if cfg!(all(
            feature = "networking-vm-network-lab-app",
            target_os = "macos",
            not(feature = "networking-vm-utun-lab-app"),
            not(feature = "networking-production"),
        )) && (handshake.runtime_mode.as_deref() != Some("vm_network_lab")
            || handshake.tunnel_kind.as_deref() != Some("darwin_utun")
            || handshake.tunnel_interface.is_some()
            || handshake.mihomo_device.as_deref() != Some("utun4094"))
        {
            let _ = runtime.stop();
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        validate_lab_profile(&handshake.lab_profile)?;
        let mut session = UserspaceLabSession {
            runtime,
            profile: handshake.lab_profile,
            instance_id,
            tunnel_interface: None,
            active_transport: None,
            health: None,
            checks: Vec::new(),
            routes_installed: false,
            private_reachable: false,
            mihomo_coexisting: false,
            request_sequence: 0,
        };
        let result = (|| {
            session.request(
                IpcRequestPayload::ApplyProfile(Box::new(session.profile.clone())),
                "profile",
            )?;
            let prepared = session.request(IpcRequestPayload::PrepareTunnel, "prepare")?;
            let IpcResponsePayload::TunnelPrepared(facts) = prepared else {
                return Err(NetworkErrorCode::InvalidStateTransition);
            };
            if !valid_lab_interface(&facts.interface_name)
                || facts.instance_id != session.instance_id
                || facts.mtu != 1420
            {
                return Err(NetworkErrorCode::AuthenticationFailed);
            }
            session.tunnel_interface = Some(facts.interface_name);
            for (index, transport) in LAB_CONNECT_SEQUENCE.iter().copied().enumerate() {
                let connected = session.request(IpcRequestPayload::ConnectTransport { transport }, "connect")?;
                let expected_state = if transport == TransportKind::Quic {
                    NetworkState::ConnectedPrimary
                } else {
                    NetworkState::DegradedFallback
                };
                if !matches!(connected, IpcResponsePayload::Status(status) if status.state == expected_state && status.active_transport == Some(transport))
                {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
                let health = session.request(IpcRequestPayload::SampleHealth, "health")?;
                let IpcResponsePayload::Health(health) = health else {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                };
                if !health.reachable {
                    return Err(NetworkErrorCode::PrimaryTransportUnavailable);
                }
                // The VM-network profile performs its separate, empty-data
                // typed private echo probe only after carrier health.  The
                // production sidecar rejects this request, and route-free
                // profiles never send it.
                let (private_reachable, mihomo_coexisting) = if cfg!(all(
                    feature = "networking-vm-network-lab-app",
                    target_os = "macos",
                    not(feature = "networking-vm-utun-lab-app"),
                    not(feature = "networking-production"),
                )) {
                    let probe = session.request(IpcRequestPayload::SamplePrivateReachability, "private")?;
                    let IpcResponsePayload::PrivateReachability(fact) = probe else {
                        return Err(NetworkErrorCode::InvalidStateTransition);
                    };
                    if !fact.reachable {
                        return Err(NetworkErrorCode::PrimaryTransportUnavailable);
                    }
                    // The fixed harness only emits this fact after checking
                    // the authenticated Mihomo child/device/covering route.
                    (fact.reachable, true)
                } else {
                    (false, false)
                };
                // Route visibility is set only after the private probe, never
                // at PrepareTunnel or before the first healthy carrier.
                session.checks.push(UserspaceLabTransportCheck {
                    transport,
                    reachable: health.reachable,
                    latency_ms: health.latency_ms,
                    jitter_ms: health.jitter_ms,
                    loss_percent: health.loss_percent,
                    private_reachable,
                    mihomo_coexisting,
                });
                session.health = Some(health);
                session.active_transport = Some(transport);
                session.routes_installed |= private_reachable;
                session.private_reachable = private_reachable;
                session.mihomo_coexisting = mihomo_coexisting;
                if index + 1 != LAB_CONNECT_SEQUENCE.len() {
                    session.disconnect_active()?;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = session.stop();
            self.last_error = Some(error);
            return Err(error);
        }
        self.last_profile = Some(session.profile.clone());
        self.session = Some(session);
        self.status(None)
    }

    fn disconnect(&mut self) -> Result<UserspaceLabStatus, NetworkErrorCode> {
        let Some(session) = self.session.take() else {
            self.last_error = None;
            return Ok(self.snapshot_disconnected());
        };
        let result = session.stop();
        if let Err(error) = result {
            self.last_error = Some(error);
            return Err(error);
        }
        self.last_error = None;
        Ok(self.snapshot_disconnected())
    }
}

fn with_runtime<T>(
    operation: impl FnOnce(&mut UserspaceLabRuntime) -> Result<T, NetworkErrorCode>,
) -> Result<T, String> {
    let mut runtime = LAB_RUNTIME
        .lock()
        .map_err(|_| "userspace lab runtime lock poisoned".to_owned())?;
    operation(&mut runtime).map_err(error_code)
}

fn app_path(app: &AppHandle<Wry>) -> Result<PathBuf, String> {
    lab_runtime_identity(app).map_err(error_code)
}

#[tauri::command]
pub fn get_networking_userspace_lab_status(app: AppHandle<Wry>) -> Result<UserspaceLabStatus, String> {
    let executable = app_path(&app)?;
    with_runtime(|runtime| runtime.status(Some(executable)))
}

#[tauri::command]
pub fn connect_networking_userspace_lab(app: AppHandle<Wry>) -> Result<UserspaceLabStatus, String> {
    let executable = app_path(&app)?;
    with_runtime(|runtime| runtime.connect(executable))
}

#[tauri::command]
pub fn disconnect_networking_userspace_lab(app: AppHandle<Wry>) -> Result<UserspaceLabStatus, String> {
    let _ = app_path(&app)?;
    with_runtime(UserspaceLabRuntime::disconnect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_profile_guard_rejects_non_loopback_or_wrong_identity() -> anyhow::Result<()> {
        let mut profile: NetworkProfile =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))?;
        assert_eq!(
            validate_lab_profile(&profile),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        profile.profile_id = LAB_PROFILE_ID.into();
        assert_eq!(
            validate_lab_profile(&profile),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        Ok(())
    }

    #[test]
    fn lab_status_never_claims_routes_or_keychain() -> anyhow::Result<()> {
        let status = UserspaceLabRuntime {
            executable: None,
            session: None,
            last_error: None,
            last_profile: None,
        }
        .snapshot_disconnected();
        assert_eq!(status.runtime_mode, LAB_MODE);
        assert_eq!(status.tunnel_kind, LAB_TUNNEL_KIND);
        assert!(!status.routes_installed);
        assert!(!status.private_reachable);
        assert!(!status.mihomo_coexisting);
        assert!(status.tunnel_interface.is_none());
        let json = serde_json::to_string(&status)?;
        assert!(!json.contains("keychain"));
        assert!(!json.contains("private_key"));
        Ok(())
    }

    #[test]
    fn lab_interface_contract_matches_the_selected_launcher() {
        #[cfg(any(
            all(
                feature = "networking-vm-utun-lab-app",
                target_os = "macos",
                not(feature = "networking-vm-network-lab-app"),
                not(feature = "networking-production"),
            ),
            all(
                feature = "networking-vm-network-lab-app",
                target_os = "macos",
                not(feature = "networking-vm-utun-lab-app"),
                not(feature = "networking-production"),
            ),
        ))]
        {
            assert!(valid_lab_interface("utun7"));
            assert!(!valid_lab_interface("userspace"));
            assert!(!valid_lab_interface("utun7;route"));
        }
        #[cfg(not(any(
            all(
                feature = "networking-vm-utun-lab-app",
                target_os = "macos",
                not(feature = "networking-vm-network-lab-app"),
                not(feature = "networking-production"),
            ),
            all(
                feature = "networking-vm-network-lab-app",
                target_os = "macos",
                not(feature = "networking-vm-utun-lab-app"),
                not(feature = "networking-production"),
            ),
        )))]
        {
            assert!(valid_lab_interface("userspace"));
            assert!(!valid_lab_interface("utun7"));
        }
    }

    #[cfg(all(
        feature = "networking-vm-network-lab-app",
        target_os = "macos",
        not(feature = "networking-vm-utun-lab-app"),
        not(feature = "networking-production"),
    ))]
    #[test]
    fn vm_network_profile_has_the_locked_identity_and_fixed_socket() {
        assert_eq!(LAB_MODE, "vm_network_lab");
        assert_eq!(LAB_TUNNEL_KIND, "darwin_utun");
        assert_eq!(LAB_SITE_ID, "lab-vm-network");
        assert_eq!(LAB_PROFILE_ID, "lab.vm-network.actual-child");
        assert_eq!(
            VM_NETWORK_LAB_SOCKET_PATH,
            "/var/run/net.kysion.kyclash.vm-network-lab.sock"
        );
        assert_eq!(VM_NETWORK_LAB_RESPONSE_TIMEOUT, Duration::from_secs(10));
    }
}
