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
    Connect,
    Disconnect,
    Cancel { operation_id: String },
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
            request_id: "request.test".into(),
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
        Ok(())
    }
}
