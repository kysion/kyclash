use super::{NetworkErrorCode, NetworkProfile, NetworkState, TransportEndpoint, TransportKind, TunnelConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportHealth {
    pub reachable: bool,
    pub latency_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss_percent: u8,
}

impl TransportHealth {
    pub const fn healthy(self) -> bool {
        self.reachable && self.packet_loss_percent < 50
    }
}

pub trait WireGuardAdapter {
    fn start(&mut self, config: &TunnelConfig) -> Result<(), NetworkErrorCode>;
    fn stop(&mut self) -> Result<(), NetworkErrorCode>;
}

pub trait PrivateRouteAdapter {
    fn apply(&mut self, profile: &NetworkProfile) -> Result<(), NetworkErrorCode>;
    fn rollback(&mut self) -> Result<(), NetworkErrorCode>;
}

pub trait TransportAdapter {
    fn connect(&mut self, endpoint: &TransportEndpoint) -> Result<(), NetworkErrorCode>;
    fn disconnect(&mut self, transport: TransportKind) -> Result<(), NetworkErrorCode>;
    fn health(&mut self, transport: TransportKind) -> Result<TransportHealth, NetworkErrorCode>;
}

pub struct DataPlaneController<W, T, R> {
    wireguard: W,
    transport: T,
    routes: R,
    state: NetworkState,
    active_transport: Option<TransportKind>,
    unhealthy_samples: u8,
}

impl<W: WireGuardAdapter, T: TransportAdapter, R: PrivateRouteAdapter> DataPlaneController<W, T, R> {
    pub const fn new(wireguard: W, transport: T, routes: R) -> Self {
        Self {
            wireguard,
            transport,
            routes,
            state: NetworkState::Disconnected,
            active_transport: None,
            unhealthy_samples: 0,
        }
    }

    pub const fn state(&self) -> NetworkState {
        self.state
    }

    pub const fn active_transport(&self) -> Option<TransportKind> {
        self.active_transport
    }

    pub fn connect(&mut self, profile: &NetworkProfile) -> Result<(), NetworkErrorCode> {
        profile.validate()?;
        for next in [
            NetworkState::Authenticating,
            NetworkState::FetchingConfig,
            NetworkState::PreparingTunnel,
        ] {
            self.state.transition_to(next)?;
        }
        if let Err(error) = self.wireguard.start(&profile.tunnel) {
            self.fail_to_disconnected()?;
            return Err(error);
        }
        if let Err(error) = self.routes.apply(profile) {
            self.cleanup_after_failure()?;
            return Err(error);
        }
        self.state.transition_to(NetworkState::ConnectingPrimary)?;
        if self.connect_kind(profile, profile.transports.primary).is_ok() {
            self.state.transition_to(NetworkState::ConnectedPrimary)?;
            return Ok(());
        }
        if self.connect_first_fallback(profile).is_ok() {
            self.state.transition_to(NetworkState::DegradedFallback)?;
            return Ok(());
        }
        self.cleanup_after_failure()?;
        Err(NetworkErrorCode::FallbackTransportUnavailable)
    }

    pub fn sample_health(&mut self, profile: &NetworkProfile) -> Result<TransportHealth, NetworkErrorCode> {
        let active = self.active_transport.ok_or(NetworkErrorCode::InvalidStateTransition)?;
        let health = self.transport.health(active)?;
        if health.healthy() {
            self.unhealthy_samples = 0;
            return Ok(health);
        }
        self.unhealthy_samples = self.unhealthy_samples.saturating_add(1);
        if self.unhealthy_samples < profile.policy.fallback_threshold {
            return Ok(health);
        }
        self.unhealthy_samples = 0;
        self.switch_after_failure(profile, active)?;
        Ok(health)
    }

    pub fn reconnect_after_network_change(&mut self, profile: &NetworkProfile) -> Result<(), NetworkErrorCode> {
        let active = self.active_transport.ok_or(NetworkErrorCode::InvalidStateTransition)?;
        self.state.transition_to(NetworkState::Reconnecting)?;
        self.disconnect_active(active)?;
        if self.connect_kind(profile, profile.transports.primary).is_ok() {
            self.state.transition_to(NetworkState::ConnectedPrimary)?;
            return Ok(());
        }
        self.connect_first_fallback(profile)?;
        self.state.transition_to(NetworkState::DegradedFallback)
    }

    pub fn disconnect(&mut self) -> Result<(), NetworkErrorCode> {
        if self.state == NetworkState::Disconnected {
            return Ok(());
        }
        self.state.transition_to(NetworkState::Disconnecting)?;
        let transport_result = self
            .active_transport
            .map_or(Ok(()), |active| self.disconnect_active(active));
        let route_result = self.routes.rollback();
        let tunnel_result = self.wireguard.stop();
        self.state.transition_to(NetworkState::Disconnected)?;
        transport_result.and(route_result).and(tunnel_result)
    }

    fn switch_after_failure(
        &mut self,
        profile: &NetworkProfile,
        failed: TransportKind,
    ) -> Result<(), NetworkErrorCode> {
        self.disconnect_active(failed)?;
        if failed == profile.transports.primary {
            if let Err(error) = self.connect_first_fallback(profile) {
                self.cleanup_after_failure()?;
                return Err(error);
            }
            return self.state.transition_to(NetworkState::DegradedFallback);
        }
        self.state.transition_to(NetworkState::Reconnecting)?;
        if self.connect_kind(profile, profile.transports.primary).is_ok() {
            return self.state.transition_to(NetworkState::ConnectedPrimary);
        }
        if let Err(error) = self.connect_first_fallback(profile) {
            self.cleanup_after_failure()?;
            return Err(error);
        }
        self.state.transition_to(NetworkState::DegradedFallback)
    }

    fn connect_first_fallback(&mut self, profile: &NetworkProfile) -> Result<(), NetworkErrorCode> {
        for kind in profile.transports.fallbacks.iter().copied() {
            if self.connect_kind(profile, kind).is_ok() {
                return Ok(());
            }
        }
        Err(NetworkErrorCode::FallbackTransportUnavailable)
    }

    fn connect_kind(&mut self, profile: &NetworkProfile, kind: TransportKind) -> Result<(), NetworkErrorCode> {
        let endpoint = profile
            .transports
            .endpoints
            .iter()
            .find(|endpoint| endpoint.transport == kind)
            .ok_or(NetworkErrorCode::InvalidConfiguration)?;
        self.transport.connect(endpoint)?;
        self.active_transport = Some(kind);
        Ok(())
    }

    fn disconnect_active(&mut self, kind: TransportKind) -> Result<(), NetworkErrorCode> {
        self.transport.disconnect(kind)?;
        self.active_transport = None;
        Ok(())
    }

    fn cleanup_after_failure(&mut self) -> Result<(), NetworkErrorCode> {
        self.active_transport = None;
        let route_result = self.routes.rollback();
        let tunnel_result = self.wireguard.stop();
        self.state.transition_to(NetworkState::Error)?;
        self.state.transition_to(NetworkState::Disconnected)?;
        route_result.and(tunnel_result)
    }

    fn fail_to_disconnected(&mut self) -> Result<(), NetworkErrorCode> {
        self.state.transition_to(NetworkState::Error)?;
        self.state.transition_to(NetworkState::Disconnected)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use parking_lot::Mutex;

    use super::*;

    const VALID_PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

    struct FakeWireGuard {
        events: Arc<Mutex<Vec<String>>>,
        fail_start: bool,
    }

    impl WireGuardAdapter for FakeWireGuard {
        fn start(&mut self, _: &TunnelConfig) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("wireguard:start".into());
            if self.fail_start {
                Err(NetworkErrorCode::TunnelStartFailed)
            } else {
                Ok(())
            }
        }

        fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("wireguard:stop".into());
            Ok(())
        }
    }

    struct FakeTransport {
        events: Arc<Mutex<Vec<String>>>,
        fail_connect: Vec<TransportKind>,
        health: VecDeque<TransportHealth>,
    }

    struct FakeRoutes {
        events: Arc<Mutex<Vec<String>>>,
        fail_apply: bool,
        fail_rollback: bool,
    }

    impl PrivateRouteAdapter for FakeRoutes {
        fn apply(&mut self, _: &NetworkProfile) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:apply".into());
            if self.fail_apply {
                Err(NetworkErrorCode::RouteConflict)
            } else {
                Ok(())
            }
        }

        fn rollback(&mut self) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:rollback".into());
            if self.fail_rollback {
                Err(NetworkErrorCode::RouteRollbackFailed)
            } else {
                Ok(())
            }
        }
    }

    impl TransportAdapter for FakeTransport {
        fn connect(&mut self, endpoint: &TransportEndpoint) -> Result<(), NetworkErrorCode> {
            self.events.lock().push(format!("connect:{:?}", endpoint.transport));
            if self.fail_connect.contains(&endpoint.transport) {
                Err(NetworkErrorCode::PrimaryTransportUnavailable)
            } else {
                Ok(())
            }
        }

        fn disconnect(&mut self, transport: TransportKind) -> Result<(), NetworkErrorCode> {
            self.events.lock().push(format!("disconnect:{transport:?}"));
            Ok(())
        }

        fn health(&mut self, _: TransportKind) -> Result<TransportHealth, NetworkErrorCode> {
            self.health.pop_front().ok_or(NetworkErrorCode::OperationTimedOut)
        }
    }

    type FakeController = DataPlaneController<FakeWireGuard, FakeTransport, FakeRoutes>;

    fn controller(
        fail_connect: Vec<TransportKind>,
        health: Vec<TransportHealth>,
    ) -> (FakeController, Arc<Mutex<Vec<String>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (
            DataPlaneController::new(
                FakeWireGuard {
                    events: Arc::clone(&events),
                    fail_start: false,
                },
                FakeTransport {
                    events: Arc::clone(&events),
                    fail_connect,
                    health: health.into(),
                },
                FakeRoutes {
                    events: Arc::clone(&events),
                    fail_apply: false,
                    fail_rollback: false,
                },
            ),
            events,
        )
    }

    #[test]
    fn quic_failure_uses_fallback_and_disconnect_cleans_tunnel() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let (mut controller, events) = controller(vec![TransportKind::Quic], Vec::new());
        controller
            .connect(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(controller.state(), NetworkState::DegradedFallback);
        controller.disconnect().map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let events = events.lock();
        assert_eq!(events.last().map(String::as_str), Some("wireguard:stop"));
        assert!(
            events.iter().position(|event| event == "routes:rollback")
                < events.iter().position(|event| event == "wireguard:stop")
        );
        drop(events);
        Ok(())
    }

    #[test]
    fn unhealthy_threshold_switches_break_before_make() -> anyhow::Result<()> {
        let mut profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        profile.policy.fallback_threshold = 2;
        let unhealthy = TransportHealth {
            reachable: false,
            latency_ms: 900,
            jitter_ms: 300,
            packet_loss_percent: 100,
        };
        let (mut controller, events) = controller(Vec::new(), vec![unhealthy, unhealthy]);
        controller
            .connect(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        controller
            .sample_health(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        controller
            .sample_health(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let events = events.lock();
        let disconnect = events
            .iter()
            .position(|event| event == "disconnect:Quic")
            .ok_or_else(|| anyhow::anyhow!("missing QUIC disconnect"))?;
        let fallback = events
            .iter()
            .position(|event| event == "connect:Wss")
            .ok_or_else(|| anyhow::anyhow!("missing WSS connect"))?;
        assert!(disconnect < fallback);
        drop(events);
        assert_eq!(controller.active_transport(), Some(TransportKind::Wss));
        Ok(())
    }

    #[test]
    fn all_transport_failures_stop_wireguard() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let failures = vec![TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp];
        let (mut controller, events) = controller(failures, Vec::new());
        assert_eq!(
            controller.connect(&profile),
            Err(NetworkErrorCode::FallbackTransportUnavailable)
        );
        assert_eq!(controller.state(), NetworkState::Disconnected);
        let events = events.lock();
        assert_eq!(events.last().map(String::as_str), Some("wireguard:stop"));
        assert!(events.iter().any(|event| event == "routes:rollback"));
        drop(events);
        Ok(())
    }

    #[test]
    fn route_apply_failure_rolls_back_and_stops_wireguard() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let (mut controller, events) = controller(Vec::new(), Vec::new());
        controller.routes.fail_apply = true;
        assert_eq!(controller.connect(&profile), Err(NetworkErrorCode::RouteConflict));
        assert_eq!(controller.state(), NetworkState::Disconnected);
        assert_eq!(
            events.lock().as_slice(),
            ["wireguard:start", "routes:apply", "routes:rollback", "wireguard:stop"]
        );
        Ok(())
    }

    #[test]
    fn failed_fallback_after_health_loss_cleans_routes_and_tunnel() -> anyhow::Result<()> {
        let mut profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        profile.policy.fallback_threshold = 1;
        let unhealthy = TransportHealth {
            reachable: false,
            latency_ms: 0,
            jitter_ms: 0,
            packet_loss_percent: 100,
        };
        let (mut controller, events) = controller(Vec::new(), vec![unhealthy]);
        controller
            .connect(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        controller.transport.fail_connect = profile.transports.fallbacks.clone();
        assert_eq!(
            controller.sample_health(&profile),
            Err(NetworkErrorCode::FallbackTransportUnavailable)
        );
        assert_eq!(controller.state(), NetworkState::Disconnected);
        assert_eq!(events.lock().last().map(String::as_str), Some("wireguard:stop"));
        Ok(())
    }

    #[test]
    fn network_change_reconnects_primary_after_fallback() -> anyhow::Result<()> {
        let profile: NetworkProfile = serde_json::from_str(VALID_PROFILE)?;
        let (mut controller, _) = controller(vec![TransportKind::Quic], Vec::new());
        controller
            .connect(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        controller.transport.fail_connect.clear();
        controller
            .reconnect_after_network_change(&profile)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(controller.state(), NetworkState::ConnectedPrimary);
        assert_eq!(controller.active_transport(), Some(TransportKind::Quic));
        Ok(())
    }
}
