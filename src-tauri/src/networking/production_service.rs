use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::{
    ActiveMihomoTunSource, IpcRequest, IpcRequestPayload, IpcResponsePayload, MihomoTunSnapshot,
    NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, NetworkHealth, NetworkProfile, NetworkState, NetworkStatus,
    ProductionControllerHandle, ProductionEvent, SidecarLifecycleState, StaticActiveMihomoTunSource, TransportKind,
    TunnelDeviceFacts, valid_ipc_id,
};

pub trait ProductionRouteBoundary: Send {
    fn apply(
        &mut self,
        profile: &NetworkProfile,
        operation_id: &str,
        tunnel: &TunnelDeviceFacts,
        profile_revision: u64,
        mihomo: &MihomoTunSnapshot,
    ) -> Result<(), NetworkErrorCode>;
    fn heartbeat(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode>;
    fn rollback(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode>;
}

struct RouteHeartbeatTask {
    cancelled: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

struct MonitorCleanupContext {
    status: Arc<Mutex<ProductionNetworkStatus>>,
    routes: Arc<Mutex<Box<dyn ProductionRouteBoundary>>>,
    routes_active: Arc<AtomicBool>,
    controller: ProductionControllerHandle,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    request_sequence: Arc<AtomicU64>,
    timeout: Duration,
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
    mihomo_source: Arc<dyn ActiveMihomoTunSource>,
    routes_active: Arc<AtomicBool>,
    status: Arc<Mutex<ProductionNetworkStatus>>,
    route_heartbeat: Mutex<Option<RouteHeartbeatTask>>,
    route_heartbeat_interval: Duration,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    request_sequence: Arc<AtomicU64>,
    cancel_requested: Arc<AtomicBool>,
    timeout: Duration,
    instance_id: String,
    profile_revision: u64,
}

impl ProductionNetworkingService {
    pub fn new(
        controller: ProductionControllerHandle,
        profile: NetworkProfile,
        routes: Box<dyn ProductionRouteBoundary>,
        instance_id: String,
        profile_revision: u64,
    ) -> Result<Self, NetworkErrorCode> {
        Self::new_with_mihomo_source(
            controller,
            profile,
            routes,
            instance_id,
            profile_revision,
            Arc::new(StaticActiveMihomoTunSource::ready(MihomoTunSnapshot::inactive())),
        )
    }

    pub fn new_with_mihomo_source(
        controller: ProductionControllerHandle,
        profile: NetworkProfile,
        routes: Box<dyn ProductionRouteBoundary>,
        instance_id: String,
        profile_revision: u64,
        mihomo_source: Arc<dyn ActiveMihomoTunSource>,
    ) -> Result<Self, NetworkErrorCode> {
        profile.validate()?;
        if profile_revision == 0 {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let site = ProductionSiteSummary {
            id: profile.site.id.clone(),
            display_name: profile.site.display_name.clone(),
            private_route_count: profile.site.private_cidrs.len(),
        };
        Ok(Self {
            controller,
            timeout: Duration::from_secs(profile.policy.connect_timeout_seconds.into()),
            route_heartbeat_interval: Duration::from_secs(u64::from(profile.policy.health_interval_seconds).min(5)),
            profile,
            routes: Arc::new(Mutex::new(routes)),
            mihomo_source,
            routes_active: Arc::new(AtomicBool::new(false)),
            route_heartbeat: Mutex::new(None),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            request_sequence: Arc::new(AtomicU64::new(0)),
            cancel_requested: Arc::new(AtomicBool::new(false)),
            instance_id,
            profile_revision,
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
        {
            let mut status = self.status.lock();
            if status.operation_id.as_deref() != Some(operation_id) {
                return Err(NetworkErrorCode::OperationCancelled);
            }
            if !matches!(
                status.state,
                NetworkState::Authenticating
                    | NetworkState::FetchingConfig
                    | NetworkState::PreparingTunnel
                    | NetworkState::ConnectingPrimary
                    | NetworkState::Reconnecting
            ) {
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            status.state = NetworkState::Disconnecting;
        }
        self.cancel_requested.store(true, Ordering::Release);
        self.controller.cancel(operation_id)
    }

    pub async fn connect(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        if !valid_production_operation_id(&operation_id) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let _lifecycle = self.lifecycle.lock().await;
        if self.status.lock().state != NetworkState::Disconnected {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        self.cancel_requested.store(false, Ordering::Release);
        self.set_status(
            NetworkState::Authenticating,
            Some(operation_id.clone()),
            None,
            None,
            None,
        );
        if let Err(error) = self.connect_inner(&operation_id).await {
            match self.cleanup(&operation_id).await {
                Ok(()) => {
                    self.set_status(NetworkState::Disconnected, None, None, None, Some(error));
                    return Err(error);
                }
                Err(cleanup_error) => {
                    self.set_status(NetworkState::Error, Some(operation_id), None, None, Some(cleanup_error));
                    return Err(cleanup_error);
                }
            }
        }
        Ok(self.status())
    }

    async fn connect_inner(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.controller.start().await?;
        self.ensure_not_cancelled(operation_id)?;
        self.status.lock().sidecar_state = SidecarLifecycleState::Running;
        self.request(
            operation_id,
            "profile.apply",
            IpcRequestPayload::ApplyProfile(Box::new(self.profile.clone())),
        )
        .await?;
        self.ensure_not_cancelled(operation_id)?;
        self.set_status(
            NetworkState::PreparingTunnel,
            Some(operation_id.into()),
            None,
            None,
            None,
        );
        let tunnel = self.prepare_tunnel(operation_id).await?;
        self.ensure_not_cancelled(operation_id)?;
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
                    self.ensure_not_cancelled(operation_id)?;
                    selected = Some((transport, health));
                    break;
                }
                Err(error) => {
                    last_error = error;
                    // A failed connect may have completed remotely after a
                    // timeout.  Do not try the next carrier until the current
                    // one has been explicitly observed disconnected.
                    self.disconnect_carrier(operation_id).await?;
                }
            }
        }
        let (transport, health) = selected.ok_or(last_error)?;
        self.ensure_not_cancelled(operation_id)?;
        let mihomo = tokio::time::timeout(self.timeout, self.mihomo_source.snapshot(&tunnel.interface_name))
            .await
            .map_err(|_| NetworkErrorCode::OperationTimedOut)??;
        self.ensure_not_cancelled(operation_id)?;
        mihomo.validate_for(&tunnel.interface_name)?;
        self.ensure_not_cancelled(operation_id)?;
        // Mark the route boundary as pending before the first XPC call.  A
        // begin/apply failure can have an ambiguous durable outcome; cleanup
        // must still invoke the idempotent rollback before touching the
        // carrier or tunnel.
        self.routes_active.store(true, Ordering::Release);
        self.apply_routes(operation_id, &tunnel, &mihomo).await?;
        self.ensure_not_cancelled(operation_id)?;
        let state = if transport == self.profile.transports.primary {
            NetworkState::ConnectedPrimary
        } else {
            NetworkState::DegradedFallback
        };
        self.set_status(state, Some(operation_id.into()), Some(transport), Some(health), None);
        self.start_route_heartbeat(operation_id, transport)?;
        Ok(())
    }

    async fn connect_and_gate(
        &self,
        operation_id: &str,
        transport: TransportKind,
    ) -> Result<NetworkHealth, NetworkErrorCode> {
        let status = self
            .request_status(
                operation_id,
                transport_action("carrier", transport),
                IpcRequestPayload::ConnectTransport { transport },
            )
            .await?;
        validate_connected_status(&status, &self.profile, transport)?;
        let health_request_id = self.next_request_id(transport_action("health", transport))?;
        let response = self
            .controller
            .sample_health(
                operation_id.to_owned(),
                request(health_request_id, IpcRequestPayload::SampleHealth),
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

    async fn apply_routes(
        &self,
        operation_id: &str,
        tunnel: &TunnelDeviceFacts,
        mihomo: &MihomoTunSnapshot,
    ) -> Result<(), NetworkErrorCode> {
        let routes = Arc::clone(&self.routes);
        let profile = self.profile.clone();
        let operation_id = operation_id.to_owned();
        let tunnel = tunnel.clone();
        let mihomo = mihomo.clone();
        let profile_revision = self.profile_revision;
        tokio::task::spawn_blocking(move || {
            routes
                .lock()
                .apply(&profile, &operation_id, &tunnel, profile_revision, &mihomo)
        })
        .await
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
    }

    async fn prepare_tunnel(&self, operation_id: &str) -> Result<TunnelDeviceFacts, NetworkErrorCode> {
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
        facts.validate(&self.instance_id, &request_id)?;
        Ok(facts)
    }

    async fn disconnect_carrier(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        match self
            .request_status(
                operation_id,
                "carrier.disconnect",
                IpcRequestPayload::DisconnectTransport,
            )
            .await
        {
            Ok(status) => validate_carrier_disconnected(&status),
            Err(NetworkErrorCode::InvalidStateTransition) => {
                // The sidecar may have rejected the request because the
                // connect failed before activation. Confirm that fact rather
                // than guessing and violating break-before-make.
                let status = self
                    .request_status(operation_id, "carrier.status", IpcRequestPayload::GetStatus)
                    .await?;
                validate_carrier_disconnected(&status)
            }
            Err(error) => Err(error),
        }
    }

    async fn stop_tunnel(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        match self
            .request_status(operation_id, "tunnel.stop", IpcRequestPayload::StopTunnel)
            .await
        {
            Ok(status) => {
                if status.active_transport.is_some() {
                    Err(NetworkErrorCode::InvalidStateTransition)
                } else {
                    Ok(())
                }
            }
            Err(NetworkErrorCode::InvalidStateTransition) => {
                let status = self
                    .request_status(operation_id, "tunnel.status", IpcRequestPayload::GetStatus)
                    .await?;
                if status.active_transport.is_none() {
                    Ok(())
                } else {
                    Err(NetworkErrorCode::InvalidStateTransition)
                }
            }
            Err(error) => Err(error),
        }
    }

    pub async fn disconnect(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        if !valid_production_operation_id(&operation_id) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let active_operation = self.status.lock().operation_id.clone();
        let active_state = self.status.lock().state;
        if matches!(
            active_state,
            NetworkState::Authenticating
                | NetworkState::FetchingConfig
                | NetworkState::PreparingTunnel
                | NetworkState::ConnectingPrimary
                | NetworkState::Reconnecting
        ) && let Some(active) = active_operation.as_deref()
        {
            let _ = self.controller.cancel(active);
        }
        let _lifecycle = self.lifecycle.lock().await;
        if self.status.lock().state == NetworkState::Disconnected {
            self.stop_route_heartbeat().await;
            self.cancel_requested.store(false, Ordering::Release);
            return Ok(self.status());
        }
        // Route ownership is bound to the connect operation, not to the
        // caller's new disconnect request id.
        let cleanup_operation = self
            .status
            .lock()
            .operation_id
            .clone()
            .unwrap_or_else(|| operation_id.clone());
        self.set_status(
            NetworkState::Disconnecting,
            Some(cleanup_operation.clone()),
            None,
            None,
            None,
        );
        let result = self.cleanup(&cleanup_operation).await;
        self.cancel_requested.store(false, Ordering::Release);
        match result {
            Ok(()) => self.set_status(NetworkState::Disconnected, None, None, None, None),
            Err(error) => self.set_status(NetworkState::Error, Some(operation_id), None, None, Some(error)),
        }
        result.map(|()| self.status())
    }

    async fn cleanup(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        self.stop_route_heartbeat().await;
        if self.routes_active.load(Ordering::Acquire) {
            // Routes are the outermost resource: do not tear down the tunnel
            // or sidecar while an owned route lease is still unresolved.
            self.rollback_routes(operation_id).await?;
            self.routes_active.store(false, Ordering::Release);
        }
        let carrier_result = self.disconnect_carrier(operation_id).await;
        let tunnel_result = self.stop_tunnel(operation_id).await;
        let shutdown_result = self.controller.shutdown().await;
        self.status.lock().sidecar_state = SidecarLifecycleState::Stopped;
        // A successful sidecar shutdown is the authoritative final cleanup:
        // the Go child closes its carrier/tunnel even when an earlier
        // idempotent teardown request raced a remote timeout. If shutdown
        // itself fails, preserve the first actionable error.
        match shutdown_result {
            Ok(()) => {
                let _ = (carrier_result, tunnel_result);
                Ok(())
            }
            Err(shutdown_error) => Err(carrier_result
                .err()
                .or_else(|| tunnel_result.err())
                .unwrap_or(shutdown_error)),
        }
    }

    async fn rollback_routes(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let routes = Arc::clone(&self.routes);
        let operation_id = operation_id.to_owned();
        tokio::task::spawn_blocking(move || routes.lock().rollback(&operation_id))
            .await
            .map_err(|_| NetworkErrorCode::RouteRollbackFailed)?
    }

    async fn request(
        &self,
        operation_id: &str,
        action: &str,
        payload: IpcRequestPayload,
    ) -> Result<(), NetworkErrorCode> {
        let request_id = self.next_request_id(action)?;
        let response = self
            .controller
            .request(operation_id.into(), request(request_id, payload), self.timeout)
            .await?;
        match response.result.map_err(|error| error.code)? {
            IpcResponsePayload::Acknowledged => Ok(()),
            _ => Err(NetworkErrorCode::InvalidStateTransition),
        }
    }

    async fn request_status(
        &self,
        operation_id: &str,
        action: &str,
        payload: IpcRequestPayload,
    ) -> Result<NetworkStatus, NetworkErrorCode> {
        let request_id = self.next_request_id(action)?;
        let response = self
            .controller
            .request(operation_id.into(), request(request_id, payload), self.timeout)
            .await?;
        match response.result.map_err(|error| error.code)? {
            IpcResponsePayload::Status(status) => Ok(status),
            _ => Err(NetworkErrorCode::InvalidStateTransition),
        }
    }

    fn next_request_id(&self, action: &str) -> Result<String, NetworkErrorCode> {
        next_request_id(&self.request_sequence, action)
    }

    fn ensure_not_cancelled(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        if self.cancel_requested.load(Ordering::Acquire)
            || self.status.lock().operation_id.as_deref() != Some(operation_id)
            || self.status.lock().state == NetworkState::Disconnecting
        {
            Err(NetworkErrorCode::OperationCancelled)
        } else {
            Ok(())
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

    fn start_route_heartbeat(&self, operation_id: &str, transport: TransportKind) -> Result<(), NetworkErrorCode> {
        let mut slot = self.route_heartbeat.lock();
        if slot.as_ref().is_some_and(|task| task.handle.is_finished()) {
            slot.take();
        }
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let routes = Arc::clone(&self.routes);
        let routes_active = Arc::clone(&self.routes_active);
        let status = Arc::clone(&self.status);
        let controller = self.controller.clone();
        let lifecycle = Arc::clone(&self.lifecycle);
        let request_sequence = Arc::clone(&self.request_sequence);
        let operation_id = operation_id.to_owned();
        let interval = self.route_heartbeat_interval;
        let timeout = self.timeout;
        let health_failure_threshold = self.profile.policy.fallback_threshold;
        let monitor_cleanup = MonitorCleanupContext {
            status: Arc::clone(&status),
            routes: Arc::clone(&routes),
            routes_active: Arc::clone(&routes_active),
            controller: controller.clone(),
            lifecycle: Arc::clone(&lifecycle),
            request_sequence: Arc::clone(&request_sequence),
            timeout,
        };
        let handle = tokio::spawn(async move {
            let mut consecutive_health_failures = 0_u8;
            loop {
                tokio::time::sleep(interval).await;
                if task_cancelled.load(Ordering::Acquire) {
                    break;
                }
                let sidecar_state = match tokio::time::timeout(timeout, controller.poll()).await {
                    Ok(Ok(state)) => state,
                    Ok(Err(error)) => {
                        monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                        break;
                    }
                    Err(_) => {
                        monitor_failure_cleanup(&monitor_cleanup, &operation_id, NetworkErrorCode::OperationTimedOut)
                            .await;
                        break;
                    }
                };
                {
                    let mut current = status.lock();
                    if current.operation_id.as_deref() != Some(operation_id.as_str()) {
                        break;
                    }
                    current.sidecar_state = sidecar_state;
                }
                if sidecar_state != SidecarLifecycleState::Running {
                    monitor_failure_cleanup(&monitor_cleanup, &operation_id, NetworkErrorCode::SidecarUnavailable)
                        .await;
                    break;
                }
                match monitor_carrier_health(&controller, &request_sequence, &operation_id, transport, timeout).await {
                    Ok(health) => {
                        consecutive_health_failures = 0;
                        let mut current = status.lock();
                        if current.operation_id.as_deref() != Some(operation_id.as_str()) {
                            break;
                        }
                        current.health = Some(health);
                    }
                    Err(error)
                        if matches!(
                            error,
                            NetworkErrorCode::PrimaryTransportUnavailable
                                | NetworkErrorCode::FallbackTransportUnavailable
                        ) =>
                    {
                        consecutive_health_failures = consecutive_health_failures.saturating_add(1);
                        if consecutive_health_failures >= health_failure_threshold {
                            monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                            break;
                        }
                    }
                    Err(error) => {
                        monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                        break;
                    }
                }
                let heartbeat_routes = Arc::clone(&routes);
                let heartbeat_operation = operation_id.clone();
                let result = tokio::time::timeout(
                    timeout,
                    tokio::task::spawn_blocking(move || heartbeat_routes.lock().heartbeat(&heartbeat_operation)),
                )
                .await
                .map_err(|_| NetworkErrorCode::RouteRollbackFailed)
                .and_then(|result| result.unwrap_or(Err(NetworkErrorCode::SidecarUnavailable)));
                if let Err(error) = result {
                    monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                    break;
                }
            }
        });
        *slot = Some(RouteHeartbeatTask { cancelled, handle });
        drop(slot);
        Ok(())
    }

    async fn stop_route_heartbeat(&self) {
        let task = self.route_heartbeat.lock().take();
        if let Some(task) = task {
            task.cancelled.store(true, Ordering::Release);
            task.handle.abort();
            let _ = task.handle.await;
        }
    }
}

impl Drop for ProductionNetworkingService {
    fn drop(&mut self) {
        if let Some(task) = self.route_heartbeat.get_mut().take() {
            task.cancelled.store(true, Ordering::Release);
            task.handle.abort();
        }
    }
}

async fn monitor_carrier_health(
    controller: &ProductionControllerHandle,
    request_sequence: &AtomicU64,
    operation_id: &str,
    transport: TransportKind,
    timeout: Duration,
) -> Result<NetworkHealth, NetworkErrorCode> {
    let request_id = next_request_id(request_sequence, transport_action("health", transport))?;
    let response = tokio::time::timeout(
        timeout,
        controller.sample_health(
            operation_id.to_owned(),
            request(request_id, IpcRequestPayload::SampleHealth),
            timeout,
        ),
    )
    .await
    .map_err(|_| NetworkErrorCode::OperationTimedOut)??;
    let IpcResponsePayload::Health(health) = response.result.map_err(|error| error.code)? else {
        return Err(NetworkErrorCode::InvalidStateTransition);
    };
    health.validate()?;
    if !health.reachable || health.loss_percent >= 50 {
        return Err(match transport {
            TransportKind::Quic => NetworkErrorCode::PrimaryTransportUnavailable,
            TransportKind::Wss | TransportKind::Tcp => NetworkErrorCode::FallbackTransportUnavailable,
        });
    }
    Ok(health)
}

async fn monitor_failure_cleanup(context: &MonitorCleanupContext, operation_id: &str, failure: NetworkErrorCode) {
    {
        let mut current = context.status.lock();
        if current.operation_id.as_deref() != Some(operation_id) || current.state == NetworkState::Disconnected {
            return;
        }
        current.state = NetworkState::Error;
        current.last_error = Some(failure);
    }

    let _lifecycle = context.lifecycle.lock().await;
    if !context.routes_active.load(Ordering::Acquire) {
        return;
    }
    if context.status.lock().operation_id.as_deref() != Some(operation_id) {
        return;
    }

    let rollback_routes = Arc::clone(&context.routes);
    let rollback_operation = operation_id.to_owned();
    let rollback = tokio::time::timeout(
        context.timeout,
        tokio::task::spawn_blocking(move || rollback_routes.lock().rollback(&rollback_operation)),
    )
    .await
    .map_err(|_| NetworkErrorCode::RouteRollbackFailed)
    .and_then(|result| result.unwrap_or(Err(NetworkErrorCode::RouteRollbackFailed)));
    match rollback {
        Ok(()) => {
            context.routes_active.store(false, Ordering::Release);
            let cleanup = cleanup_controller(
                &context.controller,
                operation_id,
                context.timeout,
                &context.request_sequence,
            )
            .await;
            let mut current = context.status.lock();
            match cleanup {
                Ok(()) => {
                    current.state = NetworkState::Disconnected;
                    current.operation_id = None;
                    current.active_transport = None;
                    current.health = None;
                    current.sidecar_state = SidecarLifecycleState::Stopped;
                    // Preserve the reason that caused the automatic teardown
                    // so diagnostics do not silently look like a clean exit.
                    current.last_error = Some(failure);
                }
                Err(cleanup_error) => {
                    current.state = NetworkState::Error;
                    current.last_error = Some(cleanup_error);
                }
            }
        }
        Err(rollback_error) => {
            // Keep the route lease and carrier alive when rollback is
            // ambiguous; an explicit disconnect can retry the same owner.
            let mut current = context.status.lock();
            current.state = NetworkState::Error;
            current.last_error = Some(rollback_error);
        }
    }
}

async fn cleanup_controller(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    timeout: Duration,
    request_sequence: &AtomicU64,
) -> Result<(), NetworkErrorCode> {
    let carrier = tokio::time::timeout(
        timeout,
        controller_request_status(
            controller,
            operation_id,
            next_request_id(request_sequence, "carrier.disconnect")?,
            IpcRequestPayload::DisconnectTransport,
            timeout,
        ),
    )
    .await
    .map_err(|_| NetworkErrorCode::OperationTimedOut)
    .and_then(|result| result);
    let tunnel = tokio::time::timeout(
        timeout,
        controller_request_status(
            controller,
            operation_id,
            next_request_id(request_sequence, "tunnel.stop")?,
            IpcRequestPayload::StopTunnel,
            timeout,
        ),
    )
    .await
    .map_err(|_| NetworkErrorCode::OperationTimedOut)
    .and_then(|result| result);
    let shutdown = tokio::time::timeout(timeout, controller.shutdown())
        .await
        .map_err(|_| NetworkErrorCode::OperationTimedOut)
        .and_then(|result| result);
    match shutdown {
        Ok(()) => {
            // The sidecar's bounded shutdown owns final carrier/tunnel
            // teardown and is authoritative when the process already exited
            // before granular cleanup requests could be acknowledged.
            let _ = (carrier, tunnel);
            Ok(())
        }
        Err(shutdown_error) => Err(carrier.err().or_else(|| tunnel.err()).unwrap_or(shutdown_error)),
    }
}

async fn controller_request_status(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    request_id: String,
    payload: IpcRequestPayload,
    timeout: Duration,
) -> Result<(), NetworkErrorCode> {
    let response = controller
        .request(operation_id.to_owned(), request(request_id, payload), timeout)
        .await?;
    match response.result.map_err(|error| error.code)? {
        IpcResponsePayload::Status(_) => Ok(()),
        _ => Err(NetworkErrorCode::InvalidStateTransition),
    }
}

fn next_request_id(sequence: &AtomicU64, action: &str) -> Result<String, NetworkErrorCode> {
    if action.is_empty()
        || action.len() > 32
        || !action
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(NetworkErrorCode::InvalidConfiguration);
    }
    let value = sequence.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let request_id = format!("kyclash.{action}.{value}");
    if valid_ipc_id(&request_id) {
        Ok(request_id)
    } else {
        Err(NetworkErrorCode::InvalidConfiguration)
    }
}

fn transport_action(prefix: &str, transport: TransportKind) -> &'static str {
    match (prefix, transport) {
        ("carrier", TransportKind::Quic) => "carrier.quic",
        ("carrier", TransportKind::Wss) => "carrier.wss",
        ("carrier", TransportKind::Tcp) => "carrier.tcp",
        ("health", TransportKind::Quic) => "health.quic",
        ("health", TransportKind::Wss) => "health.wss",
        ("health", TransportKind::Tcp) => "health.tcp",
        _ => "invalid",
    }
}

fn validate_connected_status(
    status: &NetworkStatus,
    profile: &NetworkProfile,
    transport: TransportKind,
) -> Result<(), NetworkErrorCode> {
    let expected_state = if transport == profile.transports.primary {
        NetworkState::ConnectedPrimary
    } else {
        NetworkState::DegradedFallback
    };
    if status.active_profile_id.as_deref() != Some(profile.profile_id.as_str())
        || status.active_transport != Some(transport)
        || status.state != expected_state
    {
        return Err(NetworkErrorCode::InvalidStateTransition);
    }
    Ok(())
}

const fn validate_carrier_disconnected(status: &NetworkStatus) -> Result<(), NetworkErrorCode> {
    if status.active_transport.is_some() {
        Err(NetworkErrorCode::InvalidStateTransition)
    } else {
        Ok(())
    }
}

fn valid_production_operation_id(value: &str) -> bool {
    (8..=56).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
            request.validate_protocol()?;
            self.events.lock().push(format!("request-id:{}", request.request_id));
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
                        Ok(IpcResponsePayload::Status(NetworkStatus {
                            state: if transport == TransportKind::Quic {
                                NetworkState::ConnectedPrimary
                            } else {
                                NetworkState::DegradedFallback
                            },
                            active_profile_id: Some("profile.test".into()),
                            active_transport: Some(transport),
                            last_error: None,
                        }))
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
                IpcRequestPayload::DisconnectTransport => (
                    "carrier:disconnect",
                    Ok(IpcResponsePayload::Status(NetworkStatus {
                        state: NetworkState::PreparingTunnel,
                        active_profile_id: Some("profile.test".into()),
                        active_transport: None,
                        last_error: None,
                    })),
                ),
                IpcRequestPayload::StopTunnel => (
                    "tunnel:stop",
                    Ok(IpcResponsePayload::Status(NetworkStatus {
                        state: NetworkState::Disconnected,
                        active_profile_id: Some("profile.test".into()),
                        active_transport: None,
                        last_error: None,
                    })),
                ),
                IpcRequestPayload::GetStatus => (
                    "carrier:status",
                    Ok(IpcResponsePayload::Status(NetworkStatus {
                        state: NetworkState::PreparingTunnel,
                        active_profile_id: Some("profile.test".into()),
                        active_transport: None,
                        last_error: None,
                    })),
                ),
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

    struct MonitoredRuntime {
        inner: Runtime,
        health_failure: Arc<AtomicBool>,
        sidecar_exited: Arc<AtomicBool>,
    }

    #[async_trait]
    impl AsyncProductionRuntime for MonitoredRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.inner.start(context).await
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            if self.health_failure.load(Ordering::Acquire)
                && matches!(&request.payload, IpcRequestPayload::SampleHealth)
            {
                self.inner.events.lock().push("carrier:health:failed".into());
                return Ok(IpcResponse {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: Ok(IpcResponsePayload::Health(NetworkHealth {
                        reachable: false,
                        latency_ms: 0,
                        jitter_ms: 0,
                        loss_percent: 100,
                    })),
                });
            }
            self.inner.request(request, cancel).await
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            if self.sidecar_exited.load(Ordering::Acquire) {
                self.inner.events.lock().push("sidecar:exited".into());
                Ok(SidecarProcessStatus::Exited { success: false })
            } else {
                self.inner.status().await
            }
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.inner.stop().await
        }
    }

    struct Routes(Arc<Mutex<Vec<String>>>);

    impl ProductionRouteBoundary for Routes {
        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            tunnel: &TunnelDeviceFacts,
            revision: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            if !tunnel.interface_name.starts_with("utun") || revision == 0 {
                return Err(NetworkErrorCode::InvalidConfiguration);
            }
            self.0.lock().push("routes:apply".into());
            Ok(())
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:rollback".into());
            Ok(())
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:heartbeat".into());
            Ok(())
        }
    }

    struct FailingHeartbeatRoutes(Arc<Mutex<Vec<String>>>);

    impl ProductionRouteBoundary for FailingHeartbeatRoutes {
        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            _: &TunnelDeviceFacts,
            _: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:apply".into());
            Ok(())
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:heartbeat-failed".into());
            Err(NetworkErrorCode::RouteRollbackFailed)
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.0.lock().push("routes:rollback".into());
            Ok(())
        }
    }

    struct ObservedMihomoSource {
        events: Arc<Mutex<Vec<String>>>,
        result: Result<MihomoTunSnapshot, NetworkErrorCode>,
    }

    #[async_trait]
    impl ActiveMihomoTunSource for ObservedMihomoSource {
        async fn snapshot(&self, kyclash_interface: &str) -> Result<MihomoTunSnapshot, NetworkErrorCode> {
            self.events.lock().push("mihomo:observe".into());
            let snapshot = self.result.clone()?;
            snapshot.validate_for(kyclash_interface)?;
            Ok(snapshot)
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
        let service = ProductionNetworkingService::new_with_mihomo_source(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
            42,
            Arc::new(ObservedMihomoSource {
                events: Arc::clone(&events),
                result: Ok(MihomoTunSnapshot::inactive()),
            }),
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
        assert!(position("carrier:health")? < position("mihomo:observe")?);
        assert!(position("mihomo:observe")? < position("routes:apply")?);
        assert!(position("routes:rollback")? < position("tunnel:stop")?);
        assert!(position("tunnel:stop")? < position("secret:clear")?);
        let request_ids = events
            .iter()
            .filter_map(|event| event.strip_prefix("request-id:"))
            .collect::<Vec<_>>();
        assert!(!request_ids.is_empty());
        assert!(request_ids.iter().all(|request_id| valid_ipc_id(request_id)));
        assert!(request_ids.iter().all(|request_id| {
            !request_id.contains("ApplyProfile")
                && !request_id.contains("identity")
                && !request_id.contains('{')
                && !request_id.contains(' ')
        }));
        drop(events);
        Ok(())
    }

    #[tokio::test]
    async fn mihomo_observation_failure_never_mutates_routes() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![9; 32]).with_private_key(vec![10; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let service = ProductionNetworkingService::new_with_mihomo_source(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
            42,
            Arc::new(ObservedMihomoSource {
                events: Arc::clone(&events),
                result: Err(NetworkErrorCode::RouteDiscoveryFailed),
            }),
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        assert_eq!(
            service.connect("operation.mihomo.failure".into()).await,
            Err(NetworkErrorCode::RouteDiscoveryFailed)
        );
        let events = events.lock();
        assert!(events.iter().any(|event| event == "carrier:health"));
        assert!(events.iter().any(|event| event == "mihomo:observe"));
        assert!(!events.iter().any(|event| event == "routes:apply"));
        assert!(!events.iter().any(|event| event == "routes:rollback"));
        assert!(events.iter().any(|event| event == "tunnel:stop"));
        drop(events);
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
            42,
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

    #[tokio::test]
    async fn running_health_failure_rolls_routes_back_before_bounded_cleanup() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let health_failure = Arc::new(AtomicBool::new(false));
        let controller = spawn_production_controller(
            MonitoredRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
                health_failure: Arc::clone(&health_failure),
                sidecar_exited: Arc::new(AtomicBool::new(false)),
            },
            SidecarLaunchContext::new("instance.test".into(), vec![11; 32]).with_private_key(vec![12; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(20);
        service
            .connect("operation.monitor.health".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        health_failure.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                if current.state == NetworkState::Disconnected
                    && current.last_error == Some(NetworkErrorCode::PrimaryTransportUnavailable)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let events = events.lock();
        let position = |value: &str| {
            events
                .iter()
                .position(|event| event == value)
                .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
        };
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "carrier:health:failed")
                .count(),
            3,
            "cleanup must wait for the configured consecutive health threshold"
        );
        assert!(position("carrier:health:failed")? < position("routes:rollback")?);
        assert!(position("routes:rollback")? < position("carrier:disconnect")?);
        assert!(position("routes:rollback")? < position("tunnel:stop")?);
        assert!(position("routes:rollback")? < position("secret:clear")?);
        drop(events);
        Ok(())
    }

    #[tokio::test]
    async fn sidecar_exit_rolls_routes_back_before_bounded_shutdown() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sidecar_exited = Arc::new(AtomicBool::new(false));
        let controller = spawn_production_controller(
            MonitoredRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
                health_failure: Arc::new(AtomicBool::new(false)),
                sidecar_exited: Arc::clone(&sidecar_exited),
            },
            SidecarLaunchContext::new("instance.test".into(), vec![13; 32]).with_private_key(vec![14; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(20);
        service
            .connect("operation.monitor.sidecar".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        sidecar_exited.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                if current.state == NetworkState::Disconnected
                    && current.last_error == Some(NetworkErrorCode::SidecarUnavailable)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let events = events.lock();
        let position = |value: &str| {
            events
                .iter()
                .position(|event| event == value)
                .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
        };
        assert!(position("sidecar:exited")? < position("routes:rollback")?);
        assert!(position("routes:rollback")? < position("secret:clear")?);
        Ok(())
    }

    #[tokio::test]
    async fn active_route_lease_is_heartbeated_until_cleanup() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![3; 32]).with_private_key(vec![4; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(Arc::clone(&events))),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(20);
        service
            .connect("operation.heartbeat".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if events.lock().iter().any(|event| event == "routes:heartbeat") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        service
            .disconnect("operation.heartbeat.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let heartbeat_count = events
            .lock()
            .iter()
            .filter(|event| event.as_str() == "routes:heartbeat")
            .count();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            events
                .lock()
                .iter()
                .filter(|event| event.as_str() == "routes:heartbeat")
                .count(),
            heartbeat_count,
            "heartbeat continued after route cleanup"
        );
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_failure_is_visible_and_cleanup_converges_disconnected() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![5; 32]).with_private_key(vec![6; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(FailingHeartbeatRoutes(Arc::clone(&events))),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(20);
        service
            .connect("operation.heartbeat.failure".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                if current.state == NetworkState::Disconnected
                    && current.last_error == Some(NetworkErrorCode::RouteRollbackFailed)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(service.status().last_error, Some(NetworkErrorCode::RouteRollbackFailed));
        service
            .disconnect("operation.heartbeat.failure.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let events = events.lock();
        let rollback = events
            .iter()
            .position(|event| event == "routes:rollback")
            .ok_or_else(|| anyhow::anyhow!("missing route rollback"))?;
        let shutdown = events
            .iter()
            .position(|event| event == "secret:clear")
            .ok_or_else(|| anyhow::anyhow!("missing controller shutdown"))?;
        assert!(rollback < shutdown);
        drop(events);
        Ok(())
    }
}
