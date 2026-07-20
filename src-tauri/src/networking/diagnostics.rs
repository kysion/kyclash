use serde::{Deserialize, Serialize};

use super::{
    NETWORK_IPC_PROTOCOL_VERSION, NETWORK_SCHEMA_VERSION, NetworkErrorCode, NetworkState, SidecarLifecycleState,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkDiagnosticSnapshot {
    pub schema_version: u8,
    pub ipc_protocol_version: u8,
    pub network_state: NetworkState,
    pub sidecar_state: SidecarLifecycleState,
    pub has_active_profile: bool,
    pub private_route_count: usize,
    pub active_transport: Option<String>,
    pub last_error: Option<NetworkErrorCode>,
}

impl NetworkDiagnosticSnapshot {
    pub fn new(
        network_state: NetworkState,
        sidecar_state: SidecarLifecycleState,
        has_active_profile: bool,
        private_route_count: usize,
        active_transport: Option<&str>,
        last_error: Option<NetworkErrorCode>,
    ) -> Self {
        Self {
            schema_version: NETWORK_SCHEMA_VERSION,
            ipc_protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            network_state,
            sidecar_state,
            has_active_profile,
            private_route_count,
            active_transport: active_transport.map(str::to_owned),
            last_error,
        }
    }
}

#[cfg(feature = "networking-dev")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetworkingDevStatus {
    pub network_state: NetworkState,
    pub sidecar_state: SidecarLifecycleState,
}

#[cfg(feature = "networking-dev")]
pub const fn networking_dev_status(
    network_state: NetworkState,
    sidecar_state: SidecarLifecycleState,
) -> NetworkingDevStatus {
    NetworkingDevStatus {
        network_state,
        sidecar_state,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_allowlist_based_and_contain_no_configuration_secrets() -> anyhow::Result<()> {
        let snapshot = NetworkDiagnosticSnapshot::new(
            NetworkState::ConnectedPrimary,
            SidecarLifecycleState::Running,
            true,
            2,
            Some("quic"),
            None,
        );
        let json = serde_json::to_string(&snapshot)?;
        for forbidden in [
            "private_key",
            "peer_public_key",
            "identity_ref",
            "auth_token",
            "control.example.test",
            "edge.example.test",
        ] {
            assert!(!json.contains(forbidden));
        }
        Ok(())
    }
}
