use std::{sync::Arc, time::Duration};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::{
    IpcRequest, IpcRequestPayload, IpcResponsePayload, NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, NetworkHealth,
    NetworkProfile, NetworkState, ProductionControllerHandle, ProductionEvent, SidecarLifecycleState, TransportKind,
};

pub trait ProductionRouteBoundary: Send {
    fn apply(&mut self, profile: &NetworkProfile, operation_id: &str) -> Result<(), NetworkErrorCode>;
    fn rollback(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionSiteSummary {
    pub id: String,
    pub display_name: String,
    pub private_route_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionNetworkStatus {
    pub state: NetworkState,
    pub sidecar_state: SidecarLifecycleState,
    pub site: ProductionSiteSummary,
    pub active_transport: Option<TransportKind>,
    pub health: Option<NetworkHealth>,
    pub operation_id: Option<String>,
    pub last_error: Option<NetworkErrorCode>,
}

pub struct ProductionNetworkingService {
    controller: ProductionControllerHandle,
    profile: NetworkProfile,
    routes: Arc<Mutex<Box<dyn ProductionRouteBoundary>>>,
    status: Arc<Mutex<ProductionNetworkStatus>>,
    timeout: Duration,
    instance_id: String,
}

impl ProductionNetworkingService {
    pub fn new(
        controller: ProductionControllerHandle,
        profile: NetworkProfile,
        routes: Box<dyn ProductionRouteBoundary>,
        instance_id: String,
    ) -> Result<Self, NetworkErrorCode> {
        profile.validate()?;
        let site = ProductionSiteSummary {
            id: profile.site.id.clone(),
            display_name: profile.site.display_name.clone(),
            private_route_count: profile.site.private_cidrs.len(),
        };
        Ok(Self {
            controller,
            timeout: Duration::from_secs(profile.policy.connect_timeout_seconds.into()),
            profile,
            routes: Arc::new(Mutex::new(routes)),
            instance_id,
            status: Arc::new(Mutex::new(ProductionNetworkStatus {
                state: NetworkState::Disconnected,
                sidecar_state: SidecarLifecycleState::Stopped,
                site,
                active_transport: None,
                health: None,
                operation_id: None,
                last_error: None,
            })),
        })
    }

    pub fn status(&self) -> ProductionNetworkStatus {
        self.status.lock().clone()
    }

    pub async fn diagnostics(&self) -> Result<Vec<ProductionEvent>, NetworkErrorCode> {
        self.controller.diagnostics().await
    }

    pub fn cancel(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.status.lock().state = NetworkState::Disconnecting;
        self.controller.cancel(operation_id)
    }

    pub async fn connect(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        if self.status.lock().state != NetworkState::Disconnected {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.set_status(
            NetworkState::Authenticating,
            Some(operation_id.clone()),
            None,
            None,
            None,
        );
        if let Err(error) = self.connect_inner(&operation_id).await {
            let _ = self.cleanup(&operation_id).await;
            self.set_status(NetworkState::Disconnected, None, None, None, Some(error));
            return Err(error);
        }
        Ok(self.status())
    }

    async fn connect_inner(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.controller.start().await?;
        self.status.lock().sidecar_state = SidecarLifecycleState::Running;
        self.request(
            operation_id,
            IpcRequestPayload::ApplyProfile(Box::new(self.profile.clone())),
        )
        .await?;
        self.set_status(
            NetworkState::PreparingTunnel,
            Some(operation_id.into()),
            None,
            None,
            None,
        );
        self.prepare_tunnel(operation_id).await?;
        self.set_status(
            NetworkState::ConnectingPrimary,
            Some(operation_id.into()),
            None,
            None,
            None,
        );

        let mut selected = None;
        let mut last_error = NetworkErrorCode::PrimaryTransportUnavailable;
        for transport in
            std::iter::once(self.profile.transports.primary).chain(self.profile.transports.fallbacks.iter().copied())
        {
            match self.connect_and_gate(operation_id, transport).await {
                Ok(health) => {
                    selected = Some((transport, health));
                    break;
                }
                Err(error) => {
                    last_error = error;
                    let _ = self.request(operation_id, IpcRequestPayload::DisconnectTransport).await;
                }
            }
        }
        let (transport, health) = selected.ok_or(last_error)?;
        self.routes.lock().apply(&self.profile, operation_id)?;
        let state = if transport == self.profile.transports.primary {
            NetworkState::ConnectedPrimary
        } else {
            NetworkState::DegradedFallback
        };
        self.set_status(state, Some(operation_id.into()), Some(transport), Some(health), None);
        Ok(())
    }

    async fn connect_and_gate(
        &self,
        operation_id: &str,
        transport: TransportKind,
    ) -> Result<NetworkHealth, NetworkErrorCode> {
        self.request(operation_id, IpcRequestPayload::ConnectTransport { transport })
            .await?;
        let response = self
            .controller
            .sample_health(
                format!("{operation_id}.health.{transport:?}"),
                request(format!("{operation_id}.health"), IpcRequestPayload::SampleHealth),
                self.timeout,
            )
            .await?;
        let IpcResponsePayload::Health(health) = response.result.map_err(|error| error.code)? else {
            return Err(NetworkErrorCode::InvalidStateTransition);
        };
        health.validate()?;
        if !health.reachable || health.loss_percent >= 50 {
            return Err(NetworkErrorCode::PrimaryTransportUnavailable);
        }
        Ok(health)
    }

    async fn prepare_tunnel(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let request_id = format!("{operation_id}.prepare");
        let response = self
            .controller
            .request(
                operation_id.into(),
                request(request_id.clone(), IpcRequestPayload::PrepareTunnel),
                self.timeout,
            )
            .await?;
        let IpcResponsePayload::TunnelPrepared(facts) = response.result.map_err(|error| error.code)? else {
            return Err(NetworkErrorCode::InvalidStateTransition);
        };
        facts.validate(&self.instance_id, &request_id)
    }

    pub async fn disconnect(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        if self.status.lock().state == NetworkState::Disconnected {
            return Ok(self.status());
        }
        self.set_status(
            NetworkState::Disconnecting,
            Some(operation_id.clone()),
            None,
            None,
            None,
        );
        let result = self.cleanup(&operation_id).await;
        self.set_status(NetworkState::Disconnected, None, None, None, result.err());
        result.map(|()| self.status())
    }

    async fn cleanup(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let route_result = self.routes.lock().rollback(operation_id);
        let carrier_result = self.request(operation_id, IpcRequestPayload::DisconnectTransport).await;
        let tunnel_result = self.request(operation_id, IpcRequestPayload::StopTunnel).await;
        let shutdown_result = self.controller.shutdown().await;
        self.status.lock().sidecar_state = SidecarLifecycleState::Stopped;
        route_result.and(carrier_result).and(tunnel_result).and(shutdown_result)
    }

    async fn request(&self, operation_id: &str, payload: IpcRequestPayload) -> Result<(), NetworkErrorCode> {
        let response = self
            .controller
            .request(
                operation_id.into(),
                request(format!("{operation_id}.{payload:?}"), payload),
                self.timeout,
            )
            .await?;
        match response.result.map_err(|error| error.code)? {
            IpcResponsePayload::Acknowledged => Ok(()),
            _ => Err(NetworkErrorCode::InvalidStateTransition),
        }
    }

    fn set_status(
        &self,
        state: NetworkState,
        operation_id: Option<String>,
        active_transport: Option<TransportKind>,
        health: Option<NetworkHealth>,
        last_error: Option<NetworkErrorCode>,
    ) {
        let mut status = self.status.lock();
        status.state = state;
        status.operation_id = operation_id;
        status.active_transport = active_transport;
        status.health = health;
        status.last_error = last_error;
    }
}

const fn request(request_id: String, payload: IpcRequestPayload) -> IpcRequest {
    IpcRequest {
        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
        request_id,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use async_trait::async_trait;
    use parking_lot::Mutex;

    use super::*;
    use crate::networking::{
        AsyncProductionRuntime, IpcError, IpcResponse, SidecarHandshake, SidecarLaunchContext, SidecarProcessStatus,
        spawn_production_controller,
    };

    const PROFILE: &str = include_str!("../../../schemas/fixtures/network-v1.valid.json");

    struct Runtime {
        events: Arc<Mutex<Vec<String>>>,
        fail_quic: bool,
    }

    #[async_trait]
    impl AsyncProductionRuntime for Runtime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.events.lock().push("authenticate".into());
            Ok(SidecarHandshake {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                instance_id: context.instance_id.clone(),
                auth_proof: "proof".into(),
            })
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            if cancel.load(Ordering::Acquire) {
                return Err(NetworkErrorCode::OperationCancelled);
            }
            let (name, result) = match request.payload {
                IpcRequestPayload::ApplyProfile(_) => ("validate", Ok(IpcResponsePayload::Acknowledged)),
                IpcRequestPayload::PrepareTunnel => (
                    "tunnel:prepare",
                    Ok(IpcResponsePayload::TunnelPrepared(
                        crate::networking::TunnelDeviceFacts {
                            interface_name: "utun42".into(),
                            mtu: 1420,
                            has_ipv4: true,
                            has_ipv6: true,
                            instance_id: "instance.test".into(),
                            operation_id: request.request_id.clone(),
                        },
                    )),
                ),
                IpcRequestPayload::ConnectTransport { transport } => {
                    let result = if transport == TransportKind::Quic && self.fail_quic {
                        Err(IpcError {
                            code: NetworkErrorCode::PrimaryTransportUnavailable,
                            message: "unavailable".into(),
                            retryable: true,
                        })
                    } else {
                        Ok(IpcResponsePayload::Acknowledged)
                    };
                    self.events.lock().push(format!("carrier:connect:{transport:?}"));
                    return Ok(IpcResponse {
                        protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                        request_id: request.request_id,
                        result,
                    });
                }
                IpcRequestPayload::SampleHealth => (
                    "carrier:health",
                    Ok(IpcResponsePayload::Health(NetworkHealth {
                        reachable: true,
                        latency_ms: 4,
                        jitter_ms: 1,
                        loss_percent: 0,
                    })),
                ),
                IpcRequestPayload::DisconnectTransport => ("carrier:disconnect", Ok(IpcResponsePayload::Acknowledged)),
                IpcRequestPayload::StopTunnel => ("tunnel:stop", Ok(IpcResponsePayload::Acknowledged)),
                _ => return Err(NetworkErrorCode::InvalidConfiguration),
            };
            self.events.lock().push(name.into());
            Ok(IpcResponse {
                protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                request_id: request.request_id,
                result,
            })
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            Ok(SidecarProcessStatus::Running)
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("secret:clear".into());
            Ok(())
        }
    }

    struct Routes(Arc<Mutex<Vec<String>>>);

    impl ProductionRouteBoundary for Routes {
        fn apply(&mut self, _: &NetworkProfile, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:apply".into());
            Ok(())
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:rollback".into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn health_precedes_routes_and_cleanup_is_ordered() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let context = SidecarLaunchContext::new("instance.test".into(), vec![7; 32]).with_private_key(vec![8; 32]);
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            context,
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            service
                .connect("operation.connect".into())
                .await
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .state,
            NetworkState::ConnectedPrimary
        );
        service
            .disconnect("operation.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let events = events.lock();
        let position = |value: &str| {
            events
                .iter()
                .position(|event| event == value)
                .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
        };
        assert!(position("authenticate")? < position("validate")?);
        assert!(position("tunnel:prepare")? < position("carrier:connect:Quic")?);
        assert!(position("carrier:health")? < position("routes:apply")?);
        assert!(position("routes:rollback")? < position("tunnel:stop")?);
        assert!(position("tunnel:stop")? < position("secret:clear")?);
        Ok(())
    }

    #[tokio::test]
    async fn fallback_is_selected_only_after_primary_disconnect() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: true,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![1; 32]).with_private_key(vec![2; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(
            service
                .connect("operation.fallback".into())
                .await
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .state,
            NetworkState::DegradedFallback
        );
        let events = events.lock();
        let disconnect = events
            .iter()
            .position(|event| event == "carrier:disconnect")
            .ok_or_else(|| anyhow::anyhow!("missing disconnect"))?;
        let fallback = events
            .iter()
            .position(|event| event == "carrier:connect:Wss")
            .ok_or_else(|| anyhow::anyhow!("missing fallback"))?;
        assert!(disconnect < fallback);
        drop(events);
        Ok(())
    }
}
