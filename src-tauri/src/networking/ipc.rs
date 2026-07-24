use serde::{Deserialize, Serialize};

use super::{NetworkErrorCode, NetworkProfile, NetworkState};

pub const NETWORK_IPC_PROTOCOL_VERSION: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpcRequest {
    pub protocol_version: u8,
    pub request_id: String,
    pub payload: IpcRequestPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case", deny_unknown_fields)]
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
    /// VM-network lab-only probe. Production sidecars reject this request;
    /// the request carries no data and the response is a bounded typed fact.
    SamplePrivateReachability,
    /// Legacy POC request. Production controllers use `ConnectTransport`.
    Connect,
    Disconnect,
    Cancel {
        target_request_id: String,
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
#[serde(tag = "type", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum IpcResponsePayload {
    Acknowledged,
    CancelAccepted { target_request_id: String },
    Status(NetworkStatus),
    Health(NetworkHealth),
    PrivateReachability(PrivateReachability),
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
        self.validate_owner(instance_id, operation_id)?;
        if !super::route_helper::valid_utun_interface(&self.interface_name) {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(())
    }

    fn validate_sidecar_response(&self, instance_id: &str, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.validate_owner(instance_id, operation_id)?;
        if self.interface_name != "userspace" && !super::route_helper::valid_utun_interface(&self.interface_name) {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        Ok(())
    }

    fn validate_owner(&self, instance_id: &str, operation_id: &str) -> Result<(), NetworkErrorCode> {
        if self.mtu != 1420 || self.instance_id != instance_id || self.operation_id != operation_id {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReachability {
    pub reachable: bool,
    pub latency_ms: u32,
    /// Optional lab-only proof bits. Older sidecars omit them; the external
    /// two-VM controller requires explicit Mihomo/overlay success and an
    /// explicit carrier-dependent system-SSH result. It never infers any
    /// independent proof from reachability.
    #[serde(default)]
    pub mihomo_coexisting: Option<bool>,
    #[serde(default)]
    pub overlay_ssh_verified: Option<bool>,
    #[serde(default)]
    pub system_ssh_verified: Option<bool>,
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
    pub fn validate_protocol(&self) -> Result<(), NetworkErrorCode> {
        if self.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if !valid_ipc_id(&self.request_id) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        if let IpcRequestPayload::Cancel { target_request_id } = &self.payload
            && (!valid_ipc_id(target_request_id) || target_request_id == &self.request_id)
        {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        Ok(())
    }
}

impl IpcResponse {
    pub fn validate_protocol(&self, request: &IpcRequest) -> Result<(), NetworkErrorCode> {
        request.validate_protocol()?;
        if self.protocol_version != NETWORK_IPC_PROTOCOL_VERSION {
            return Err(NetworkErrorCode::UnsupportedProtocolVersion);
        }
        if !valid_ipc_id(&self.request_id) || self.request_id != request.request_id {
            return Err(NetworkErrorCode::AuthenticationFailed);
        }
        match &self.result {
            Ok(payload) => validate_response_payload(request, payload),
            Err(error) => validate_ipc_error(error),
        }
    }
}

pub(crate) fn valid_ipc_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (8..=64).contains(&bytes.len())
        && bytes.first() != Some(&b'.')
        && bytes.last() != Some(&b'.')
        && !bytes.windows(2).any(|pair| pair == b"..")
        && bytes
            .iter()
            .copied()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_response_payload(request: &IpcRequest, response: &IpcResponsePayload) -> Result<(), NetworkErrorCode> {
    match (&request.payload, response) {
        (IpcRequestPayload::GetStatus, IpcResponsePayload::Status(status)) => validate_network_status(status),
        (IpcRequestPayload::Connect, IpcResponsePayload::Status(status)) => {
            validate_network_status(status)?;
            require_status(status, NetworkState::ConnectedPrimary, Some(super::TransportKind::Quic))
        }
        (IpcRequestPayload::StopTunnel, IpcResponsePayload::Status(status)) => {
            validate_network_status(status)?;
            require_status(status, NetworkState::Disconnected, None)
        }
        (IpcRequestPayload::ConnectTransport { transport }, IpcResponsePayload::Status(status)) => {
            validate_network_status(status)?;
            let expected_state = if *transport == super::TransportKind::Quic {
                NetworkState::ConnectedPrimary
            } else {
                NetworkState::DegradedFallback
            };
            require_status(status, expected_state, Some(*transport))
        }
        (IpcRequestPayload::DisconnectTransport, IpcResponsePayload::Status(status)) => {
            validate_network_status(status)?;
            require_status(status, NetworkState::PreparingTunnel, None)
        }
        (IpcRequestPayload::ApplyProfile(_), IpcResponsePayload::Acknowledged)
        | (IpcRequestPayload::Disconnect, IpcResponsePayload::Acknowledged) => Ok(()),
        (
            IpcRequestPayload::Cancel { target_request_id },
            IpcResponsePayload::CancelAccepted {
                target_request_id: accepted_target,
            },
        ) if valid_ipc_id(target_request_id)
            && target_request_id != &request.request_id
            && accepted_target == target_request_id =>
        {
            Ok(())
        }
        (IpcRequestPayload::PrepareTunnel, IpcResponsePayload::TunnelPrepared(facts)) => {
            facts
                .validate_sidecar_response(&facts.instance_id, &request.request_id)
                .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            if !valid_ipc_id(&facts.instance_id) || (!facts.has_ipv4 && !facts.has_ipv6) {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            Ok(())
        }
        (IpcRequestPayload::SampleHealth, IpcResponsePayload::Health(health)) => health.validate(),
        (IpcRequestPayload::SamplePrivateReachability, IpcResponsePayload::PrivateReachability(reachability)) => {
            // The VM echo is loopback-backed, so zero latency is valid. Keep
            // the wire fact intentionally bounded to the typed fields above.
            let _ = reachability;
            Ok(())
        }
        _ => Err(NetworkErrorCode::InvalidConfiguration),
    }
}

fn require_status(
    status: &NetworkStatus,
    expected_state: NetworkState,
    expected_transport: Option<super::TransportKind>,
) -> Result<(), NetworkErrorCode> {
    if status.state == expected_state && status.active_transport == expected_transport && status.last_error.is_none() {
        Ok(())
    } else {
        Err(NetworkErrorCode::InvalidConfiguration)
    }
}

fn validate_network_status(status: &NetworkStatus) -> Result<(), NetworkErrorCode> {
    if status
        .active_profile_id
        .as_deref()
        .is_some_and(|profile_id| !valid_profile_id(profile_id))
    {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    let valid_state = match status.state {
        NetworkState::Disconnected => status.active_transport.is_none(),
        NetworkState::PreparingTunnel => status.active_profile_id.is_some() && status.active_transport.is_none(),
        NetworkState::ConnectedPrimary => {
            status.active_profile_id.is_some() && status.active_transport == Some(super::TransportKind::Quic)
        }
        NetworkState::DegradedFallback => {
            status.active_profile_id.is_some()
                && matches!(
                    status.active_transport,
                    Some(super::TransportKind::Wss | super::TransportKind::Tcp)
                )
        }
        NetworkState::Authenticating
        | NetworkState::FetchingConfig
        | NetworkState::ConnectingPrimary
        | NetworkState::Reconnecting
        | NetworkState::Disconnecting
        | NetworkState::Error => false,
    };
    if valid_state {
        Ok(())
    } else {
        Err(NetworkErrorCode::InvalidConfiguration)
    }
}

fn validate_ipc_error(error: &IpcError) -> Result<(), NetworkErrorCode> {
    if error.message.is_empty() || error.message.len() > 512 || error.message.chars().any(char::is_control) {
        Err(NetworkErrorCode::InvalidConfiguration)
    } else {
        Ok(())
    }
}

fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .enumerate()
            .all(|(index, ch)| ch.is_ascii_alphanumeric() || (index > 0 && matches!(ch, '.' | '_' | ':' | '-')))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CancellationScenario {
        primary_request: IpcRequest,
        cancel_request: IpcRequest,
        primary_response: IpcResponse,
        cancel_response: IpcResponse,
    }

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
    fn request_identifier_matches_the_go_sidecar_contract() {
        for invalid in [
            "short",
            "request:colon",
            "request with spaces",
            "request.{debug}",
            ".request.test",
            "request.test.",
            "request..test",
            "request/path",
            r"request\path",
            "request.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.123456789",
        ] {
            let request = IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: invalid.into(),
                payload: IpcRequestPayload::GetStatus,
            };
            assert_eq!(request.validate_protocol(), Err(NetworkErrorCode::InvalidConfiguration));
        }
        let valid = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "kyclash.profile.apply.1".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        assert_eq!(valid.validate_protocol(), Ok(()));
    }

    #[test]
    fn response_validation_checks_version_correlation_and_payload_semantics() {
        let request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.status".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        let response = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::Disconnected,
                active_profile_id: None,
                active_transport: None,
                last_error: None,
            })),
        };
        assert_eq!(response.validate_protocol(&request), Ok(()));

        let mut wrong_version = response.clone();
        wrong_version.protocol_version += 1;
        assert_eq!(
            wrong_version.validate_protocol(&request),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );

        let mut stale = response.clone();
        stale.request_id = "request.stale".into();
        assert_eq!(
            stale.validate_protocol(&request),
            Err(NetworkErrorCode::AuthenticationFailed)
        );

        let mut wrong_payload = response;
        wrong_payload.result = Ok(IpcResponsePayload::Acknowledged);
        assert_eq!(
            wrong_payload.validate_protocol(&request),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
    }

    #[test]
    fn response_validation_rejects_invalid_payload_facts_and_errors() {
        let health_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.health".into(),
            payload: IpcRequestPayload::SampleHealth,
        };
        let invalid_health = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: health_request.request_id.clone(),
            result: Ok(IpcResponsePayload::Health(NetworkHealth {
                reachable: false,
                latency_ms: 0,
                jitter_ms: 0,
                loss_percent: 101,
            })),
        };
        assert_eq!(
            invalid_health.validate_protocol(&health_request),
            Err(NetworkErrorCode::InvalidConfiguration)
        );

        let invalid_error = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: health_request.request_id.clone(),
            result: Err(IpcError {
                code: NetworkErrorCode::SidecarUnavailable,
                message: String::new(),
                retryable: true,
            }),
        };
        assert_eq!(
            invalid_error.validate_protocol(&health_request),
            Err(NetworkErrorCode::InvalidConfiguration)
        );

        let status_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.status".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        let invalid_status = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: status_request.request_id.clone(),
            result: Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::ConnectedPrimary,
                active_profile_id: Some("profile.test".into()),
                active_transport: Some(crate::networking::TransportKind::Tcp),
                last_error: None,
            })),
        };
        assert_eq!(
            invalid_status.validate_protocol(&status_request),
            Err(NetworkErrorCode::InvalidConfiguration)
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
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v2.status.json"))?;
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
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v2.health.json"))?;
        assert_eq!(serde_json::to_value(response)?, fixture);
        Ok(())
    }

    #[test]
    fn cancel_wire_format_and_typed_acceptance_match_shared_fixtures() -> anyhow::Result<()> {
        let request: IpcRequest =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v2.cancel.json"))?;
        assert_eq!(request.protocol_version, NETWORK_IPC_PROTOCOL_VERSION);
        assert_eq!(
            request.payload,
            IpcRequestPayload::Cancel {
                target_request_id: "request.health.123".into(),
            }
        );
        assert_eq!(request.validate_protocol(), Ok(()));

        let response: IpcResponse = serde_json::from_str(include_str!(
            "../../../schemas/fixtures/network-ipc-v2.cancel-accepted.json"
        ))?;
        assert_eq!(response.validate_protocol(&request), Ok(()));
        assert!(matches!(
            response.result,
            Ok(IpcResponsePayload::CancelAccepted { ref target_request_id })
                if target_request_id == "request.health.123"
        ));
        Ok(())
    }

    #[test]
    fn nested_cancel_fields_are_rejected_during_deserialization() {
        for request in [
            r#"{"protocol_version":2,"request_id":"cancel.strict.data","payload":{"type":"cancel","data":{"target_request_id":"request.health.123","unknown":true}}}"#,
            r#"{"protocol_version":2,"request_id":"cancel.strict.outer","payload":{"type":"cancel","data":{"target_request_id":"request.health.123"},"unknown":true}}"#,
        ] {
            assert!(serde_json::from_str::<IpcRequest>(request).is_err());
        }
        for response in [
            r#"{"protocol_version":2,"request_id":"cancel.strict.data","result":{"Ok":{"type":"cancel_accepted","data":{"target_request_id":"request.health.123","unknown":true}}}}"#,
            r#"{"protocol_version":2,"request_id":"cancel.strict.outer","result":{"Ok":{"type":"cancel_accepted","data":{"target_request_id":"request.health.123"},"unknown":true}}}"#,
        ] {
            assert!(serde_json::from_str::<IpcResponse>(response).is_err());
        }
    }

    #[test]
    fn private_reachability_is_an_empty_typed_request_with_a_closed_response() -> anyhow::Result<()> {
        let request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.private.1".into(),
            payload: IpcRequestPayload::SamplePrivateReachability,
        };
        let request_json = serde_json::to_value(&request)?;
        assert_eq!(request_json["payload"]["type"], "sample_private_reachability");
        assert!(
            request_json["payload"]
                .get("data")
                .is_none_or(serde_json::Value::is_null)
        );

        let response = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: Ok(IpcResponsePayload::PrivateReachability(PrivateReachability {
                reachable: true,
                latency_ms: 0,
                mihomo_coexisting: None,
                overlay_ssh_verified: None,
                system_ssh_verified: None,
            })),
        };
        assert_eq!(response.validate_protocol(&request), Ok(()));
        let legacy: IpcResponse = serde_json::from_str(
            r#"{"protocol_version":2,"request_id":"request.private.1","result":{"Ok":{"type":"private_reachability","data":{"reachable":true,"latency_ms":0}}}}"#,
        )?;
        assert_eq!(legacy.validate_protocol(&request), Ok(()));
        let external: IpcResponse = serde_json::from_str(
            r#"{"protocol_version":2,"request_id":"request.private.1","result":{"Ok":{"type":"private_reachability","data":{"reachable":true,"latency_ms":0,"mihomo_coexisting":true,"overlay_ssh_verified":true,"system_ssh_verified":true}}}}"#,
        )?;
        assert_eq!(external.validate_protocol(&request), Ok(()));

        let wrong = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: Ok(IpcResponsePayload::Health(NetworkHealth {
                reachable: true,
                latency_ms: 0,
                jitter_ms: 0,
                loss_percent: 0,
            })),
        };
        assert_eq!(
            wrong.validate_protocol(&request),
            Err(NetworkErrorCode::InvalidConfiguration)
        );
        assert!(serde_json::from_str::<IpcResponse>(
            r#"{"protocol_version":2,"request_id":"request.private.1","result":{"Ok":{"type":"private_reachability","data":{"reachable":true,"latency_ms":0,"unknown":true}}}}"#,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn v1_wire_fixtures_are_rejection_evidence_only() -> anyhow::Result<()> {
        let status: IpcResponse =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v1.status.json"))?;
        let status_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.status".into(),
            payload: IpcRequestPayload::GetStatus,
        };
        assert_eq!(
            status.validate_protocol(&status_request),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );

        let health: IpcResponse =
            serde_json::from_str(include_str!("../../../schemas/fixtures/network-ipc-v1.health.json"))?;
        let health_request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.health".into(),
            payload: IpcRequestPayload::SampleHealth,
        };
        assert_eq!(
            health.validate_protocol(&health_request),
            Err(NetworkErrorCode::UnsupportedProtocolVersion)
        );
        Ok(())
    }

    #[test]
    fn cancellation_race_outcomes_match_shared_fixtures() -> anyhow::Result<()> {
        let cancel_wins: CancellationScenario = serde_json::from_str(include_str!(
            "../../../schemas/fixtures/network-ipc-v2.cancel-wins.json"
        ))?;
        assert_eq!(
            cancel_wins
                .primary_response
                .validate_protocol(&cancel_wins.primary_request),
            Ok(())
        );
        assert_eq!(
            cancel_wins
                .cancel_response
                .validate_protocol(&cancel_wins.cancel_request),
            Ok(())
        );
        assert!(matches!(
            cancel_wins.primary_response.result,
            Err(IpcError {
                code: NetworkErrorCode::OperationCancelled,
                retryable: false,
                ..
            })
        ));
        assert!(matches!(
            cancel_wins.cancel_response.result,
            Ok(IpcResponsePayload::CancelAccepted { ref target_request_id })
                if target_request_id == &cancel_wins.primary_request.request_id
        ));

        let completion_wins: CancellationScenario = serde_json::from_str(include_str!(
            "../../../schemas/fixtures/network-ipc-v2.completion-wins.json"
        ))?;
        assert_eq!(
            completion_wins
                .primary_response
                .validate_protocol(&completion_wins.primary_request),
            Ok(())
        );
        assert_eq!(
            completion_wins
                .cancel_response
                .validate_protocol(&completion_wins.cancel_request),
            Ok(())
        );
        assert!(completion_wins.primary_response.result.is_ok());
        assert!(matches!(
            completion_wins.cancel_response.result,
            Err(IpcError {
                code: NetworkErrorCode::InvalidStateTransition,
                retryable: false,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn cancel_requires_a_distinct_valid_wire_target() {
        for target_request_id in ["short", "cancel.same"] {
            let request = IpcRequest {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: "cancel.same".into(),
                payload: IpcRequestPayload::Cancel {
                    target_request_id: target_request_id.into(),
                },
            };
            assert_eq!(request.validate_protocol(), Err(NetworkErrorCode::InvalidConfiguration));
        }
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
        let mut noncanonical_name = facts.clone();
        noncanonical_name.interface_name = "utun012".into();
        let mut invalid_mtu = facts.clone();
        invalid_mtu.mtu = 1280;
        let mut invalid_operation = facts.clone();
        invalid_operation.operation_id = "request.other".into();
        for invalid in [invalid_name, noncanonical_name, invalid_mtu, invalid_operation] {
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

    #[test]
    fn userspace_tunnel_is_valid_only_at_the_sidecar_response_boundary() {
        let facts = TunnelDeviceFacts {
            interface_name: "userspace".into(),
            mtu: 1420,
            has_ipv4: true,
            has_ipv6: true,
            instance_id: "instance.test".into(),
            operation_id: "request.prepare".into(),
        };
        assert_eq!(
            facts.validate_sidecar_response("instance.test", "request.prepare"),
            Ok(())
        );
        assert_eq!(
            facts.validate("instance.test", "request.prepare"),
            Err(NetworkErrorCode::AuthenticationFailed)
        );

        let request = IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.prepare".into(),
            payload: IpcRequestPayload::PrepareTunnel,
        };
        let response = IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: Ok(IpcResponsePayload::TunnelPrepared(facts)),
        };
        assert_eq!(response.validate_protocol(&request), Ok(()));
    }
}
