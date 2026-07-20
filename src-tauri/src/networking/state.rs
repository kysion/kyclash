use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Disconnected,
    Authenticating,
    FetchingConfig,
    PreparingTunnel,
    ConnectingPrimary,
    ConnectedPrimary,
    DegradedFallback,
    Reconnecting,
    Disconnecting,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkErrorCode {
    UnsupportedSchemaVersion,
    UnsupportedProtocolVersion,
    InvalidConfiguration,
    AuthenticationFailed,
    PermissionDenied,
    RouteDiscoveryFailed,
    RouteConflict,
    RouteJournalCorrupted,
    RouteJournalUnavailable,
    RouteRollbackFailed,
    TunnelStartFailed,
    PrimaryTransportUnavailable,
    FallbackTransportUnavailable,
    OperationCancelled,
    OperationTimedOut,
    SidecarUnavailable,
    InvalidStateTransition,
}

impl NetworkState {
    pub const fn can_transition_to(self, next: Self) -> bool {
        use NetworkState::{
            Authenticating, ConnectedPrimary, ConnectingPrimary, DegradedFallback, Disconnected, Disconnecting, Error,
            FetchingConfig, PreparingTunnel, Reconnecting,
        };

        matches!(
            (self, next),
            (Disconnected, Authenticating)
                | (Authenticating, FetchingConfig | Disconnecting | Error)
                | (FetchingConfig, PreparingTunnel | Disconnecting | Error)
                | (PreparingTunnel, ConnectingPrimary | Disconnecting | Error)
                | (
                    ConnectingPrimary,
                    ConnectedPrimary | DegradedFallback | Disconnecting | Error
                )
                | (
                    ConnectedPrimary,
                    DegradedFallback | Reconnecting | Disconnecting | Error
                )
                | (DegradedFallback, Reconnecting | Disconnecting | Error)
                | (
                    Reconnecting,
                    ConnectedPrimary | DegradedFallback | Disconnecting | Error
                )
                | (Disconnecting | Error, Disconnected)
        )
    }

    pub const fn transition_to(&mut self, next: Self) -> Result<(), NetworkErrorCode> {
        if !self.can_transition_to(next) {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_reaches_connected_and_disconnects() -> Result<(), NetworkErrorCode> {
        let mut state = NetworkState::Disconnected;
        for next in [
            NetworkState::Authenticating,
            NetworkState::FetchingConfig,
            NetworkState::PreparingTunnel,
            NetworkState::ConnectingPrimary,
            NetworkState::ConnectedPrimary,
            NetworkState::Disconnecting,
            NetworkState::Disconnected,
        ] {
            state.transition_to(next)?;
        }
        assert_eq!(state, NetworkState::Disconnected);
        Ok(())
    }

    #[test]
    fn invalid_transition_fails_closed_without_mutating_state() {
        let mut state = NetworkState::Disconnected;
        assert_eq!(
            state.transition_to(NetworkState::ConnectedPrimary),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        assert_eq!(state, NetworkState::Disconnected);
    }
}
