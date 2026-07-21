use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, NetworkProfile, NetworkState};

pub const NETWORK_IPC_PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRequest {
    pub protocol_version: u8,
    pub request_id: String,
    pub payload: IpcRequestPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcRequestPayload {
    GetStatus,
    ApplyProfile(Box<NetworkProfile>),
    PrepareTunnel,
    StopTunnel,
    ConnectTransport {
        transport: super::TransportKind,
    },
    DisconnectTransport,
    SampleHealth,
    /// Legacy POC request. Production controllers use `ConnectTransport`.
    Connect,
    Disconnect,
    Cancel {
        operation_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcResponse {
    pub protocol_version: u8,
    pub request_id: String,
    pub result: Result<IpcResponsePayload, IpcError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponsePayload {
    Acknowledged,
    Status(NetworkStatus),
    Health(NetworkHealth),
    TunnelPrepared(TunnelDeviceFacts),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelDeviceFacts {
    pub interface_name: String,
    pub mtu: u16,
    pub has_ipv4: bool,
    pub has_ipv6: bool,
    pub instance_id: String,
    pub operation_id: String,
}

impl TunnelDeviceFacts {
    pub fn validate(&self, instance_id: &str, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let suffix = self.interface_name.strip_prefix("utun").unwrap_or_default();
        if self.mtu != 1420
            || suffix.is_empty()
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            || self.instance_id != instance_id
            || self.operation_id != operation_id
        {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkHealth {
    pub reachable: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub loss_percent: u8,
}

impl NetworkHealth {
    pub const fn validate(&self) -> Result<(), NetworkErrorCode> {
        if self.loss_percent <= 100 {
            Ok(())
        } else {
            Err(NetworkErrorCode::InvalidConfiguration)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcError {
    pub code: NetworkErrorCode,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkStatus {
    pub state: NetworkState,
    pub active_profile_id: Option<String>,
    pub active_transport: Option<super::TransportKind>,
    pub last_error: Option<NetworkErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkStateEvent {
    /// Monotonically increasing within one sidecar process lifetime.
    pub sequence: u64,
    pub operation_id: String,
    pub state: NetworkState,
    pub reason: Option<NetworkErrorCode>,
}

impl IpcRequest {
    pub const fn validate_protocol(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version == NETWORK_IPC_PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_protocol_version_fails_closed() {
        let request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION + 1,
            request_id: "request.test".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        assert_eq!(
            request.validate_protocol(),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
    }

    #[test]
    fn response_wire_format_round_trips() -> anyhow::Result<()> {
        let response = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.status".into(),
            result: Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::Disconnected,
                active_profile_id: None,
                active_transport: None,
                last_error: None,
            })),
        };
        let encoded = serde_json::to_string(&response)?;
        let decoded: IpcResponse = serde_json::from_str(&encoded)?;
        assert_eq!(response, decoded);
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v1.status.json"))?;
        assert_eq!(serde_json::to_value(&response)?, fixture);
        Ok(())
    }

    #[test]
    fn health_wire_format_matches_shared_fixture() -> anyhow::Result<()> {
        let response = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.health".into(),
            result: Ok(IpcResponsePayload::Health(NetworkHealth {
                reachable: true,
                latency_ms: 12,
                jitter_ms: 3,
                loss_percent: 1,
            })),
        };
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v1.health.json"))?;
        assert_eq!(serde_json::to_value(response)?, fixture);
        Ok(())
    }

    #[test]
    fn tunnel_facts_require_exact_owner_and_utun_name() {
        let facts = TunnelDeviceFacts {
            interface_name: "utun12".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "instance.test".into(),
            operation_id: "request.prepare".into(),
        };
        assert_eq!(facts.validate("instance.test", "request.prepare"), Ok(()));
        let mut invalid_name = facts.clone();
        invalid_name.interface_name = "utun-owned-by-name".into();
        let mut invalid_mtu = facts.clone();
        invalid_mtu.mtu = 1280;
        let mut invalid_operation = facts.clone();
        invalid_operation.operation_id = "request.other".into();
        for invalid in [invalid_name, invalid_mtu, invalid_operation] {
            assert_eq!(
                invalid.validate("instance.test", "request.prepare"),
                Err(NetworkErrorCode::AuthenticationFailed)
            );
        }
        assert_eq!(
            facts.validate("instance.other", "request.prepare"),
            Err(NetworkErrorCode::AuthenticationFailed)
        );
    }
}
