use std::sync::{LazyLock, Mutex};

use crate::networking::{
    IpcRequest, IpcRequestPayload, IpcResponsePayload, MockNetworkSidecar, NETWORK_IPC_PROTOCOL_VERSION,
    NetworkErrorCode, NetworkProfile, NetworkState, NetworkingDevHealth, NetworkingDevStatus, SidecarLifecycleState,
};

const DEVELOPMENT_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

static DEVELOPMENT_RUNTIME: LazyLock<Result<Mutex<DevelopmentRuntime>, NetworkErrorCode>> =
    LazyLock::new(|| DevelopmentRuntime::new().map(Mutex::new));

struct DevelopmentRuntime {
    sidecar: MockNetworkSidecar,
    profile: NetworkProfile,
    request_sequence: u64,
}

impl DevelopmentRuntime {
    fn new() -> Result<Self, NetworkErrorCode> {
        let profile = serde_json::from_str::<NetworkProfile>(DEVELOPMENT_PROFILE)
            .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
        profile.validate()?;
        Ok(Self {
            sidecar: MockNetworkSidecar::default(),
            profile,
            request_sequence: 0,
        })
    }

    fn request(&mut self, payload: IpcRequestPayload) -> Result<IpcResponsePayload, NetworkErrorCode> {
        self.request_sequence = self.request_sequence.saturating_add(1);
        self.sidecar
            .handle(IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: format!("networking-dev.{}", self.request_sequence),
                payload,
            })
            .result
            .map_err(|error| error.code)
    }

    fn status(&mut self) -> Result<NetworkingDevStatus, NetworkErrorCode> {
        let IpcResponsePayload::Status(status) = self.request(IpcRequestPayload::GetStatus)? else {
            return Err(NetworkErrorCode::InvalidStateTransition);
        };
        let connected = matches!(
            status.state,
            NetworkState::ConnectedPrimary | NetworkState::DegradedFallback | NetworkState::Reconnecting
        );
        Ok(NetworkingDevStatus {
            network_state: status.state,
            sidecar_state: if connected {
                SidecarLifecycleState::Running
            } else {
                SidecarLifecycleState::Stopped
            },
            site_id: self.profile.site.id.clone(),
            site_display_name: self.profile.site.display_name.clone(),
            private_routes: self.profile.site.private_cidrs.clone(),
            active_transport: status
                .active_transport
                .map(|transport| format!("{transport:?}").to_lowercase()),
            health: connected.then_some(NetworkingDevHealth {
                latency_ms: 24,
                jitter_ms: 3,
                packet_loss_percent: 0,
            }),
            last_error: status.last_error,
        })
    }
}

fn with_runtime<T>(
    operation: impl FnOnce(&mut DevelopmentRuntime) -> Result<T, NetworkErrorCode>,
) -> Result<T, String> {
    let runtime = DEVELOPMENT_RUNTIME.as_ref().map_err(|error| format!("{error:?}"))?;
    let mut runtime = runtime
        .lock()
        .map_err(|_| "networking development runtime lock poisoned".to_owned())?;
    operation(&mut runtime).map_err(|error| format!("{error:?}"))
}

#[tauri::command]
pub fn get_networking_dev_status() -> Result<NetworkingDevStatus, String> {
    with_runtime(DevelopmentRuntime::status)
}

#[tauri::command]
pub fn connect_networking_dev() -> Result<NetworkingDevStatus, String> {
    with_runtime(|runtime| {
        let status = runtime.status()?;
        if status.network_state == NetworkState::Disconnected {
            runtime.request(IpcRequestPayload::ApplyProfile(Box::new(runtime.profile.clone())))?;
            runtime.request(IpcRequestPayload::Connect)?;
        }
        runtime.status()
    })
}

#[tauri::command]
pub fn disconnect_networking_dev() -> Result<NetworkingDevStatus, String> {
    with_runtime(|runtime| {
        if runtime.status()?.network_state != NetworkState::Disconnected {
            runtime.request(IpcRequestPayload::Disconnect)?;
        }
        runtime.status()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_runtime_connects_and_disconnects_without_external_effects() -> Result<(), NetworkErrorCode> {
        let mut runtime = DevelopmentRuntime::new()?;
        assert_eq!(runtime.status()?.network_state, NetworkState::Disconnected);
        runtime.request(IpcRequestPayload::ApplyProfile(Box::new(runtime.profile.clone())))?;
        runtime.request(IpcRequestPayload::Connect)?;
        let connected = runtime.status()?;
        assert_eq!(connected.network_state, NetworkState::ConnectedPrimary);
        assert_eq!(connected.active_transport.as_deref(), Some("quic"));
        assert_eq!(connected.private_routes, ["10.64.0.0/16", "fd00:64::/48"]);
        runtime.request(IpcRequestPayload::Disconnect)?;
        assert_eq!(runtime.status()?.network_state, NetworkState::Disconnected);
        Ok(())
    }
}
