use super::{
    IpcError, IpcRequest, IpcRequestPayload, IpcResponse, IpcResponsePayload, NETWORK_IPC_PROTOCOL_VERSION,
    NetworkErrorCode, NetworkProfile, NetworkState, NetworkStatus, TransportKind,
};

#[derive(Debug)]
pub struct MockNetworkSidecar {
    profile: Option<NetworkProfile>,
    state: NetworkState,
    next_connect_error: Option<NetworkErrorCode>,
}

impl Default for MockNetworkSidecar {
    fn default() -> Self {
        Self {
            profile: None,
            state: NetworkState::Disconnected,
            next_connect_error: None,
        }
    }
}

impl MockNetworkSidecar {
    pub const fn fail_next_connect_with(&mut self, error: NetworkErrorCode) {
        self.next_connect_error = Some(error);
    }

    pub fn handle(&mut self, request: IpcRequest) -> IpcResponse {
        let request_id = request.request_id.clone();
        let result = request
            .validate_protocol()
            .and_then(|()| self.handle_payload(request.payload))
            .map_err(|code| IpcError {
                code,
                message: format!("mock sidecar rejected request: {code:?}"),
                retryable: matches!(
                    code,
                    NetworkErrorCode::SidecarUnavailable | NetworkErrorCode::OperationTimedOut
                ),
            });
        IpcResponse {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id,
            result,
        }
    }

    fn handle_payload(&mut self, payload: IpcRequestPayload) -> Result<IpcResponsePayload, NetworkErrorCode> {
        match payload {
            IpcRequestPayload::GetStatus => Ok(IpcResponsePayload::Status(self.status())),
            IpcRequestPayload::ApplyProfile(profile) => {
                profile.validate()?;
                if self.state != NetworkState::Disconnected {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
                self.profile = Some(*profile);
                Ok(IpcResponsePayload::Acknowledged)
            }
            IpcRequestPayload::Connect => {
                if let Some(error) = self.next_connect_error.take() {
                    return Err(error);
                }
                if self.profile.is_none() {
                    return Err(NetworkErrorCode::InvalidConfiguration);
                }
                for next in [
                    NetworkState::Authenticating,
                    NetworkState::FetchingConfig,
                    NetworkState::PreparingTunnel,
                    NetworkState::ConnectingPrimary,
                    NetworkState::ConnectedPrimary,
                ] {
                    self.state.transition_to(next)?;
                }
                Ok(IpcResponsePayload::Status(self.status()))
            }
            IpcRequestPayload::Disconnect => {
                self.state.transition_to(NetworkState::Disconnecting)?;
                self.state.transition_to(NetworkState::Disconnected)?;
                Ok(IpcResponsePayload::Status(self.status()))
            }
            IpcRequestPayload::Cancel { .. } => {
                if self.state == NetworkState::Disconnected {
                    return Ok(IpcResponsePayload::Status(self.status()));
                }
                self.state.transition_to(NetworkState::Disconnecting)?;
                self.state.transition_to(NetworkState::Disconnected)?;
                Ok(IpcResponsePayload::Status(self.status()))
            }
            IpcRequestPayload::PrepareTunnel
            | IpcRequestPayload::StopTunnel
            | IpcRequestPayload::ConnectTransport { .. }
            | IpcRequestPayload::DisconnectTransport
            | IpcRequestPayload::SampleHealth => Err(NetworkErrorCode::SidecarUnavailable),
        }
    }

    fn status(&self) -> NetworkStatus {
        NetworkStatus {
            state: self.state,
            active_profile_id: self.profile.as_ref().map(|profile| profile.profile_id.clone()),
            active_transport: (self.state == NetworkState::ConnectedPrimary).then_some(TransportKind::Quic),
            last_error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

    fn request(payload: IpcRequestPayload) -> IpcRequest {
        IpcRequest {
            protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
            request_id: "request.test".into(),
            payload,
        }
    }

    #[test]
    fn mock_sidecar_requires_profile_then_connects_and_disconnects() -> anyhow::Result<()> {
        let mut sidecar = MockNetworkSidecar::default();
        let rejected = sidecar.handle(request(IpcRequestPayload::Connect));
        assert!(matches!(
            rejected.result,
            Err(IpcError {
                code: NetworkErrorCode::InvalidConfiguration,
                ..
            })
        ));

        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        assert!(
            sidecar
                .handle(request(IpcRequestPayload::ApplyProfile(Box::new(profile))))
                .result
                .is_ok()
        );

        let connected = sidecar.handle(request(IpcRequestPayload::Connect));
        assert!(matches!(
            connected.result,
            Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::ConnectedPrimary,
                active_transport: Some(TransportKind::Quic),
                ..
            }))
        ));

        let disconnected = sidecar.handle(request(IpcRequestPayload::Disconnect));
        assert!(matches!(
            disconnected.result,
            Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::Disconnected,
                active_transport: None,
                ..
            }))
        ));
        Ok(())
    }

    #[test]
    fn cancellation_timeout_and_restart_are_deterministic() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let mut sidecar = MockNetworkSidecar::default();
        assert!(
            sidecar
                .handle(request(IpcRequestPayload::ApplyProfile(Box::new(profile))))
                .result
                .is_ok()
        );

        sidecar.fail_next_connect_with(NetworkErrorCode::OperationTimedOut);
        let timed_out = sidecar.handle(request(IpcRequestPayload::Connect));
        assert!(matches!(
            timed_out.result,
            Err(IpcError {
                code: NetworkErrorCode::OperationTimedOut,
                retryable: true,
                ..
            })
        ));

        let cancelled = sidecar.handle(request(IpcRequestPayload::Cancel {
            operation_id: "operation.test".into(),
        }));
        assert!(matches!(
            cancelled.result,
            Ok(IpcResponsePayload::Status(NetworkStatus {
                state: NetworkState::Disconnected,
                ..
            }))
        ));

        let restarted = MockNetworkSidecar::default();
        assert_eq!(restarted.state, NetworkState::Disconnected);
        assert!(restarted.profile.is_none());
        Ok(())
    }
}
