use std::{
    future::Future as _,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::task::noop_waker_ref;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::route_helper_client::RouteRetirementIssuer;
use super::{
    ActiveMihomoTunSource, IpcRequest, IpcRequestPayload, IpcResponsePayload, MihomoTunSnapshot,
    NETWORK_IPC_PROTOCOL_VERSION, NetworkErrorCode, NetworkHealth, NetworkProfile, NetworkState, NetworkStatus,
    ProductionControllerHandle, ProductionEvent, SidecarLifecycleState, StaticActiveMihomoTunSource, TransportKind,
    TunnelDeviceFacts, valid_ipc_id,
};

/// Read-only route-boundary state.  This is an observation only: callers must
/// use `try_retire` for the atomic close decision and may never manufacture a
/// retirement receipt from a prior disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionRouteDisposition {
    Reusable,
    Busy,
    RecoveryOnly,
    Retired,
}

/// Positive route-local proof that one exact boundary incarnation and native
/// route-client generation were closed while they owned no route lease and had
/// no unresolved reconciliation state.
///
/// The fields and issuer are deliberately private outside the networking
/// implementation.  The receipt is not `Clone` or `Copy`, so a later service
/// gate can consume the one authority returned by `try_retire`. This receipt
/// alone never proves that service-level queued tasks, reservations, controller
/// children, or retained service handles are absent.
#[derive(Debug, PartialEq, Eq)]
pub struct ProductionRouteRetirementReceipt {
    boundary_incarnation: u64,
    native_generation: u64,
    _sealed: (),
}

impl ProductionRouteRetirementReceipt {
    pub(super) const fn issued(issuer: &RouteRetirementIssuer, native_generation: u64) -> Self {
        Self {
            boundary_incarnation: issuer.boundary_incarnation(),
            native_generation,
            _sealed: (),
        }
    }

    #[must_use]
    pub const fn boundary_incarnation(&self) -> u64 {
        self.boundary_incarnation
    }

    #[must_use]
    pub const fn native_generation(&self) -> u64 {
        self.native_generation
    }
}

/// Atomic route-boundary retirement outcome.  `AlreadyRetired` never carries
/// a second receipt, and observational `Reusable` alone is not authority to
/// remove or replace a service.
#[derive(Debug, PartialEq, Eq)]
pub enum ProductionRouteRetirementResult {
    Retired(ProductionRouteRetirementReceipt),
    Busy,
    RecoveryOnly,
    AlreadyRetired,
}

pub trait ProductionRouteBoundary: Send {
    fn disposition(&self) -> ProductionRouteDisposition;
    fn try_retire(&mut self) -> ProductionRouteRetirementResult;
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
    wake: Arc<tokio::sync::Notify>,
    handle: tokio::task::JoinHandle<()>,
    runtime: tokio::runtime::Handle,
}

static DROPPED_ROUTE_HEARTBEAT_DRAINS: OnceLock<Mutex<Vec<tokio::task::JoinHandle<()>>>> = OnceLock::new();

struct ProductionOperation {
    id: String,
    epoch: u64,
    cancel_requested: AtomicBool,
    disconnect_requested: AtomicBool,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalCommitGateStage {
    Before,
    After,
}

#[cfg(test)]
struct FinalCommitGate {
    stage: FinalCommitGateStage,
    entered: AtomicBool,
    release: AtomicBool,
}

#[cfg(test)]
impl FinalCommitGate {
    const fn new(stage: FinalCommitGateStage) -> Self {
        Self {
            stage,
            entered: AtomicBool::new(false),
            release: AtomicBool::new(false),
        }
    }

    fn wait(&self, stage: FinalCommitGateStage) {
        if self.stage != stage {
            return;
        }
        self.entered.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl ProductionOperation {
    const fn new(id: String, epoch: u64) -> Self {
        Self {
            id,
            epoch,
            cancel_requested: AtomicBool::new(false),
            disconnect_requested: AtomicBool::new(false),
        }
    }

    fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::Release);
        self.disconnect_requested.store(true, Ordering::Release);
    }

    fn request_disconnect(&self) {
        self.disconnect_requested.store(true, Ordering::Release);
    }

    fn is_stopping(&self) -> bool {
        self.cancel_requested.load(Ordering::Acquire) || self.disconnect_requested.load(Ordering::Acquire)
    }
}

struct MonitorCleanupContext {
    status: Arc<Mutex<ProductionNetworkStatus>>,
    routes: Arc<Mutex<Box<dyn ProductionRouteBoundary>>>,
    routes_active: Arc<AtomicBool>,
    controller: ProductionControllerHandle,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    request_sequence: Arc<AtomicU64>,
    active_operation: Arc<Mutex<Option<Arc<ProductionOperation>>>>,
    operation: Arc<ProductionOperation>,
    timeout: Duration,
    profile: NetworkProfile,
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
    route_heartbeat_join: tokio::sync::Mutex<()>,
    route_heartbeat_interval: Duration,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    request_sequence: Arc<AtomicU64>,
    active_operation: Arc<Mutex<Option<Arc<ProductionOperation>>>>,
    operation_epoch: AtomicU64,
    #[cfg(test)]
    final_commit_gate: Mutex<Option<Arc<FinalCommitGate>>>,
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
            route_heartbeat_join: tokio::sync::Mutex::new(()),
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            request_sequence: Arc::new(AtomicU64::new(0)),
            active_operation: Arc::new(Mutex::new(None)),
            operation_epoch: AtomicU64::new(0),
            #[cfg(test)]
            final_commit_gate: Mutex::new(None),
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
            // `commit_connected` uses the same active -> status order. Holding
            // both locks makes accepted cancellation and final publication one
            // exact either/or decision rather than two racing observations.
            let active = self.active_operation.lock();
            let operation = active
                .as_ref()
                .filter(|operation| operation.id == operation_id)
                .ok_or(NetworkErrorCode::OperationCancelled)?;
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
            operation.request_cancel();
            status.state = NetworkState::Disconnecting;
            drop(status);
            drop(active);
        }
        self.signal_route_heartbeat();
        let _ = self.controller.cancel(operation_id);
        Ok(())
    }

    pub async fn connect(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        if !valid_production_operation_id(&operation_id) {
            return Err(NetworkErrorCode::InvalidConfiguration);
        }
        let _lifecycle = self.lifecycle.lock().await;
        if self.status.lock().state != NetworkState::Disconnected {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        // Disconnected is reusable only after a prior monitor owner has been
        // positively joined. If status publication raced the task's final
        // return, wait here before any new controller or route mutation.
        self.stop_route_heartbeat().await?;
        let epoch = self
            .operation_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1))
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)?
            + 1;
        let operation = Arc::new(ProductionOperation::new(operation_id.clone(), epoch));
        *self.active_operation.lock() = Some(Arc::clone(&operation));
        self.set_status(
            NetworkState::Authenticating,
            Some(operation_id.clone()),
            None,
            None,
            None,
        );
        if let Err(error) = self.connect_inner(&operation).await {
            let error = authoritative_operation_error(error, operation.is_stopping());
            let controller_usable = !fatal_sidecar_error(error);
            match self.cleanup(&operation, controller_usable).await {
                Ok(()) => {
                    self.set_status(NetworkState::Disconnected, None, None, None, Some(error));
                    self.clear_active_operation(&operation);
                    return Err(error);
                }
                Err(cleanup_error) => {
                    let reported = if fatal_sidecar_error(error) {
                        error
                    } else {
                        cleanup_error
                    };
                    self.set_status(NetworkState::Error, Some(operation_id), None, None, Some(reported));
                    return Err(reported);
                }
            }
        }
        Ok(self.status())
    }

    async fn connect_inner(&self, operation: &Arc<ProductionOperation>) -> Result<(), NetworkErrorCode> {
        let operation_id = operation.id.as_str();
        self.controller.start().await?;
        self.ensure_operation_active(operation)?;
        self.status.lock().sidecar_state = SidecarLifecycleState::Running;
        self.request(
            operation_id,
            "profile.apply",
            IpcRequestPayload::ApplyProfile(Box::new(self.profile.clone())),
        )
        .await?;
        self.ensure_operation_active(operation)?;
        self.set_status(
            NetworkState::PreparingTunnel,
            Some(operation_id.into()),
            None,
            None,
            None,
        );
        let tunnel = self.prepare_tunnel(operation_id).await?;
        self.ensure_operation_active(operation)?;
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
                    self.ensure_operation_active(operation)?;
                    selected = Some((transport, health));
                    break;
                }
                Err(NetworkErrorCode::OperationCancelled) => return Err(NetworkErrorCode::OperationCancelled),
                Err(error) if fatal_sidecar_error(error) => return Err(error),
                Err(error) => {
                    last_error = error;
                    // A failed connect may have completed remotely after a
                    // timeout.  Do not try the next carrier until the current
                    // one has been explicitly observed disconnected.
                    self.disconnect_carrier(operation_id).await?;
                    self.ensure_operation_active(operation)?;
                }
            }
        }
        let (transport, health) = selected.ok_or(last_error)?;
        self.ensure_operation_active(operation)?;
        let mihomo = tokio::time::timeout(self.timeout, self.mihomo_source.snapshot(&tunnel.interface_name))
            .await
            .map_err(|_| NetworkErrorCode::OperationTimedOut)??;
        self.ensure_operation_active(operation)?;
        mihomo.validate_for(&tunnel.interface_name)?;
        self.ensure_operation_active(operation)?;
        // Mark the route boundary as pending before the first XPC call.  A
        // begin/apply failure can have an ambiguous durable outcome; cleanup
        // must still invoke the idempotent rollback before touching the
        // carrier or tunnel.
        self.routes_active.store(true, Ordering::Release);
        self.apply_routes(operation_id, &tunnel, &mihomo).await?;
        self.ensure_operation_active(operation)?;
        let state = if transport == self.profile.transports.primary {
            NetworkState::ConnectedPrimary
        } else {
            NetworkState::DegradedFallback
        };
        self.commit_connected(operation, state, transport, health)?;
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
        let (active_operation, primary_error) = {
            // Match `cancel` and `commit_connected`: a disconnect intent must
            // become visible while the exact active generation is pinned.
            let active = self.active_operation.lock();
            let operation = active.as_ref().cloned();
            let mut primary_error = None;
            if let Some(operation) = operation.as_ref() {
                let mut status = self.status.lock();
                primary_error = status.last_error;
                operation.request_disconnect();
                if status.operation_id.as_deref() == Some(operation.id.as_str())
                    && status.state != NetworkState::Disconnected
                {
                    status.state = NetworkState::Disconnecting;
                }
                drop(status);
            }
            drop(active);
            (operation, primary_error)
        };
        if let Some(operation) = active_operation.as_ref() {
            self.signal_route_heartbeat();
            let _ = self.controller.cancel(&operation.id);
            self.stop_route_heartbeat().await?;
        }
        let _lifecycle = self.lifecycle.lock().await;
        if self.status.lock().state == NetworkState::Disconnected {
            if let Some(operation) = active_operation.as_ref() {
                self.clear_active_operation(operation);
            }
            return Ok(self.status());
        }
        let operation = active_operation.ok_or(NetworkErrorCode::InvalidStateTransition)?;
        self.set_status(
            NetworkState::Disconnecting,
            Some(operation.id.clone()),
            None,
            None,
            primary_error,
        );
        let controller_usable = self.status.lock().sidecar_state == SidecarLifecycleState::Running;
        let result = self.cleanup(&operation, controller_usable).await;
        match result {
            Ok(()) => {
                self.set_status(NetworkState::Disconnected, None, None, None, primary_error);
                self.clear_active_operation(&operation);
            }
            Err(error) => self.set_status(
                NetworkState::Error,
                Some(operation.id.clone()),
                None,
                None,
                primary_error.or(Some(error)),
            ),
        }
        result.map(|()| self.status())
    }

    async fn cleanup(
        &self,
        operation: &Arc<ProductionOperation>,
        mut controller_usable: bool,
    ) -> Result<(), NetworkErrorCode> {
        let operation_id = operation.id.as_str();
        self.stop_route_heartbeat().await?;
        if self.routes_active.load(Ordering::Acquire) {
            // Routes are the outermost resource: do not tear down the tunnel
            // or sidecar while an owned route lease is still unresolved.
            self.rollback_routes(operation_id).await?;
            self.routes_active.store(false, Ordering::Release);
        }
        if controller_usable && let Err(error) = self.disconnect_carrier(operation_id).await {
            controller_usable = !fatal_sidecar_error(error);
        }
        if controller_usable {
            let _ = self.stop_tunnel(operation_id).await;
        }
        let shutdown_result = self.controller.shutdown().await;
        self.status.lock().sidecar_state = if shutdown_result.is_ok() {
            SidecarLifecycleState::Stopped
        } else {
            SidecarLifecycleState::CrashLoop
        };
        // A successful exact shutdown/reap is authoritative for carrier and
        // tunnel absence. Earlier granular failures remain in controller
        // diagnostics but must not publish a false unresolved Error state.
        shutdown_result
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

    fn ensure_operation_active(&self, operation: &Arc<ProductionOperation>) -> Result<(), NetworkErrorCode> {
        let active_matches = self.active_operation.lock().as_ref().is_some_and(|active| {
            Arc::ptr_eq(active, operation) && active.epoch == operation.epoch && active.id == operation.id
        });
        if operation.is_stopping()
            || !active_matches
            || self.status.lock().operation_id.as_deref() != Some(operation.id.as_str())
            || self.status.lock().state == NetworkState::Disconnecting
        {
            Err(NetworkErrorCode::OperationCancelled)
        } else {
            Ok(())
        }
    }

    fn clear_active_operation(&self, operation: &Arc<ProductionOperation>) {
        let mut active = self.active_operation.lock();
        if active.as_ref().is_some_and(|current| Arc::ptr_eq(current, operation)) {
            active.take();
        }
    }

    fn commit_connected(
        &self,
        operation: &Arc<ProductionOperation>,
        state: NetworkState,
        transport: TransportKind,
        health: NetworkHealth,
    ) -> Result<(), NetworkErrorCode> {
        #[cfg(test)]
        self.wait_for_final_commit_gate(FinalCommitGateStage::Before);

        {
            // Global nested order for the final publication path:
            // active_operation -> status -> route_heartbeat. `cancel` and
            // `disconnect` take the same prefix, so exactly one side can
            // linearize while the operation is still connecting.
            let active = self.active_operation.lock();
            let active_matches = active.as_ref().is_some_and(|current| {
                Arc::ptr_eq(current, operation) && current.epoch == operation.epoch && current.id == operation.id
            });
            let mut status = self.status.lock();
            if operation.is_stopping()
                || !active_matches
                || status.operation_id.as_deref() != Some(operation.id.as_str())
                || status.state != NetworkState::ConnectingPrimary
            {
                return Err(NetworkErrorCode::OperationCancelled);
            }

            // Install the monitor before publishing Connected. The spawned
            // task cannot pass its active/status checks until these guards are
            // released, and `tokio::spawn` is not synchronously awaited here.
            self.start_route_heartbeat(operation, transport)?;
            status.state = state;
            status.operation_id = Some(operation.id.clone());
            status.active_transport = Some(transport);
            status.health = Some(health);
            status.last_error = None;
            drop(status);
            drop(active);
        }

        #[cfg(test)]
        self.wait_for_final_commit_gate(FinalCommitGateStage::After);
        Ok(())
    }

    #[cfg(test)]
    fn wait_for_final_commit_gate(&self, stage: FinalCommitGateStage) {
        let gate = self.final_commit_gate.lock().clone();
        if let Some(gate) = gate {
            gate.wait(stage);
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

    fn start_route_heartbeat(
        &self,
        operation: &Arc<ProductionOperation>,
        transport: TransportKind,
    ) -> Result<(), NetworkErrorCode> {
        let mut slot = self.route_heartbeat.lock();
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        let task_cancelled = Arc::clone(&cancelled);
        let wake = Arc::new(tokio::sync::Notify::new());
        let task_wake = Arc::clone(&wake);
        let routes = Arc::clone(&self.routes);
        let routes_active = Arc::clone(&self.routes_active);
        let status = Arc::clone(&self.status);
        let controller = self.controller.clone();
        let lifecycle = Arc::clone(&self.lifecycle);
        let request_sequence = Arc::clone(&self.request_sequence);
        let operation_id = operation.id.clone();
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
            active_operation: Arc::clone(&self.active_operation),
            operation: Arc::clone(operation),
            timeout,
            profile: self.profile.clone(),
        };
        let handle = tokio::spawn(async move {
            let mut consecutive_health_failures = 0_u8;
            let mut active_transport = transport;
            loop {
                if task_cancelled.load(Ordering::Acquire)
                    || ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err()
                {
                    break;
                }
                tokio::select! {
                    () = tokio::time::sleep(interval) => {}
                    () = task_wake.notified() => {}
                }
                if task_cancelled.load(Ordering::Acquire) {
                    break;
                }
                if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                    break;
                }
                let poll_result = tokio::time::timeout(timeout, controller.poll()).await;
                if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                    break;
                }
                let sidecar_state = match poll_result {
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
                let health_result =
                    monitor_carrier_health(&controller, &request_sequence, &operation_id, active_transport, timeout)
                        .await;
                if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                    break;
                }
                match health_result {
                    Ok(health) => {
                        consecutive_health_failures = 0;
                        if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                            break;
                        }
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
                            match monitor_fallback_after_health_failure(
                                &monitor_cleanup,
                                &operation_id,
                                active_transport,
                                error,
                                &task_cancelled,
                            )
                            .await
                            {
                                Ok((fallback, health)) => {
                                    if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled)
                                        .is_err()
                                    {
                                        break;
                                    }
                                    active_transport = fallback;
                                    consecutive_health_failures = 0;
                                    let mut current = status.lock();
                                    if current.operation_id.as_deref() != Some(operation_id.as_str()) {
                                        break;
                                    }
                                    current.state = NetworkState::DegradedFallback;
                                    current.active_transport = Some(fallback);
                                    current.health = Some(health);
                                    current.last_error = Some(error);
                                }
                                Err(NetworkErrorCode::OperationCancelled) if task_cancelled.load(Ordering::Acquire) => {
                                    break;
                                }
                                Err(fallback_error) => {
                                    monitor_failure_cleanup(&monitor_cleanup, &operation_id, fallback_error).await;
                                    break;
                                }
                            }
                        }
                    }
                    Err(error) => {
                        monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                        break;
                    }
                }
                if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                    break;
                }
                let heartbeat_routes = Arc::clone(&routes);
                let heartbeat_operation = operation_id.clone();
                let result =
                    tokio::task::spawn_blocking(move || heartbeat_routes.lock().heartbeat(&heartbeat_operation))
                        .await
                        .unwrap_or(Err(NetworkErrorCode::SidecarUnavailable));
                if ensure_monitor_operation_active(&monitor_cleanup, &operation_id, &task_cancelled).is_err() {
                    break;
                }
                if let Err(error) = result {
                    monitor_failure_cleanup(&monitor_cleanup, &operation_id, error).await;
                    break;
                }
            }
        });
        *slot = Some(RouteHeartbeatTask {
            cancelled,
            wake,
            handle,
            runtime: tokio::runtime::Handle::current(),
        });
        drop(slot);
        Ok(())
    }

    fn signal_route_heartbeat(&self) {
        if let Some(task) = self.route_heartbeat.lock().as_ref() {
            task.cancelled.store(true, Ordering::Release);
            task.wake.notify_one();
        }
    }

    async fn stop_route_heartbeat(&self) -> Result<(), NetworkErrorCode> {
        let _join = self.route_heartbeat_join.lock().await;
        self.signal_route_heartbeat();
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            match self.poll_route_heartbeat() {
                Poll::Ready(result) => return result,
                Poll::Pending => {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(NetworkErrorCode::OperationTimedOut);
                    }
                    tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
                }
            }
        }
    }

    fn poll_route_heartbeat(&self) -> Poll<Result<(), NetworkErrorCode>> {
        let mut slot = self.route_heartbeat.lock();
        let Some(task) = slot.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let mut context = Context::from_waker(noop_waker_ref());
        let result = match Pin::new(&mut task.handle).poll(&mut context) {
            Poll::Ready(Ok(())) => {
                slot.take();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                slot.take();
                Poll::Ready(Err(NetworkErrorCode::SidecarUnavailable))
            }
            Poll::Pending => Poll::Pending,
        };
        drop(slot);
        result
    }
}

impl Drop for ProductionNetworkingService {
    fn drop(&mut self) {
        if let Some(task) = self.route_heartbeat.get_mut().take() {
            task.cancelled.store(true, Ordering::Release);
            task.wake.notify_one();
            track_dropped_route_heartbeat(task);
        }
    }
}

fn track_dropped_route_heartbeat(task: RouteHeartbeatTask) {
    let RouteHeartbeatTask {
        cancelled: _,
        wake: _,
        handle,
        runtime,
    } = task;
    let drain = runtime.spawn(async move {
        let _ = handle.await;
    });
    let mut drains = DROPPED_ROUTE_HEARTBEAT_DRAINS
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock();
    drains.retain(|existing| !existing.is_finished());
    drains.push(drain);
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

async fn monitor_fallback_after_health_failure(
    context: &MonitorCleanupContext,
    operation_id: &str,
    failed_transport: TransportKind,
    failure: NetworkErrorCode,
    cancelled: &AtomicBool,
) -> Result<(TransportKind, NetworkHealth), NetworkErrorCode> {
    let _lifecycle = context.lifecycle.lock().await;
    ensure_monitor_operation_active(context, operation_id, cancelled)?;
    {
        let mut current = context.status.lock();
        current.state = NetworkState::Reconnecting;
        current.last_error = Some(failure);
    }

    monitor_route_heartbeat(context, operation_id).await?;
    monitor_disconnect_carrier(context, operation_id).await?;
    {
        let mut current = context.status.lock();
        if current.operation_id.as_deref() != Some(operation_id) {
            return Err(NetworkErrorCode::OperationCancelled);
        }
        current.active_transport = None;
        current.health = None;
    }

    let ordered = std::iter::once(context.profile.transports.primary)
        .chain(context.profile.transports.fallbacks.iter().copied())
        .collect::<Vec<_>>();
    let failed_index = ordered
        .iter()
        .position(|transport| *transport == failed_transport)
        .ok_or(NetworkErrorCode::InvalidConfiguration)?;
    if failed_index + 1 >= ordered.len() {
        return Err(NetworkErrorCode::FallbackTransportUnavailable);
    }

    for transport in ordered.into_iter().skip(failed_index + 1) {
        ensure_monitor_operation_active(context, operation_id, cancelled)?;
        monitor_route_heartbeat(context, operation_id).await?;
        let request_id = next_request_id(&context.request_sequence, transport_action("carrier", transport))?;
        let connect = controller_request_network_status(
            &context.controller,
            operation_id,
            request_id,
            IpcRequestPayload::ConnectTransport { transport },
            context.timeout,
        )
        .await
        .and_then(|status| validate_connected_status(&status, &context.profile, transport));
        match connect {
            Ok(()) => {
                ensure_monitor_operation_active(context, operation_id, cancelled)?;
                match monitor_carrier_health(
                    &context.controller,
                    &context.request_sequence,
                    operation_id,
                    transport,
                    context.timeout,
                )
                .await
                {
                    Ok(health) => {
                        ensure_monitor_operation_active(context, operation_id, cancelled)?;
                        return Ok((transport, health));
                    }
                    Err(NetworkErrorCode::OperationCancelled) => {
                        return Err(NetworkErrorCode::OperationCancelled);
                    }
                    Err(error) if fatal_sidecar_error(error) => return Err(error),
                    Err(_) => {}
                }
            }
            Err(NetworkErrorCode::OperationCancelled) => return Err(NetworkErrorCode::OperationCancelled),
            Err(error) if fatal_sidecar_error(error) => return Err(error),
            Err(_) => {}
        }

        // A connect or health request may have completed remotely after its
        // local deadline.  Confirm the carrier is absent before advancing to
        // the next fallback; never make two carriers concurrently active.
        monitor_disconnect_carrier(context, operation_id).await?;
        {
            let mut current = context.status.lock();
            if current.operation_id.as_deref() != Some(operation_id) {
                return Err(NetworkErrorCode::OperationCancelled);
            }
            current.active_transport = None;
            current.health = None;
        }
    }
    Err(NetworkErrorCode::FallbackTransportUnavailable)
}

fn ensure_monitor_operation_active(
    context: &MonitorCleanupContext,
    operation_id: &str,
    cancelled: &AtomicBool,
) -> Result<(), NetworkErrorCode> {
    let active_matches = context.active_operation.lock().as_ref().is_some_and(|active| {
        Arc::ptr_eq(active, &context.operation)
            && active.epoch == context.operation.epoch
            && active.id == context.operation.id
    });
    if cancelled.load(Ordering::Acquire)
        || context.operation.is_stopping()
        || !active_matches
        || context.status.lock().operation_id.as_deref() != Some(operation_id)
        || context.status.lock().state == NetworkState::Disconnecting
    {
        Err(NetworkErrorCode::OperationCancelled)
    } else {
        Ok(())
    }
}

async fn monitor_route_heartbeat(context: &MonitorCleanupContext, operation_id: &str) -> Result<(), NetworkErrorCode> {
    let routes = Arc::clone(&context.routes);
    let operation_id = operation_id.to_owned();
    tokio::task::spawn_blocking(move || routes.lock().heartbeat(&operation_id))
        .await
        .map_err(|_| NetworkErrorCode::SidecarUnavailable)?
}

async fn monitor_disconnect_carrier(
    context: &MonitorCleanupContext,
    operation_id: &str,
) -> Result<(), NetworkErrorCode> {
    let request_id = next_request_id(&context.request_sequence, "carrier.disconnect")?;
    match controller_request_network_status(
        &context.controller,
        operation_id,
        request_id,
        IpcRequestPayload::DisconnectTransport,
        context.timeout,
    )
    .await
    {
        Ok(status) => validate_carrier_disconnected(&status),
        Err(NetworkErrorCode::InvalidStateTransition) => {
            let request_id = next_request_id(&context.request_sequence, "carrier.status")?;
            let status = controller_request_network_status(
                &context.controller,
                operation_id,
                request_id,
                IpcRequestPayload::GetStatus,
                context.timeout,
            )
            .await?;
            validate_carrier_disconnected(&status)
        }
        Err(error) => Err(error),
    }
}

async fn monitor_failure_cleanup(context: &MonitorCleanupContext, operation_id: &str, failure: NetworkErrorCode) {
    let failure = authoritative_operation_error(failure, context.operation.is_stopping());
    {
        let mut current = context.status.lock();
        if context.operation.is_stopping()
            || current.operation_id.as_deref() != Some(operation_id)
            || matches!(current.state, NetworkState::Disconnected | NetworkState::Disconnecting)
        {
            return;
        }
        current.state = NetworkState::Error;
        current.last_error = Some(failure);
        if fatal_sidecar_error(failure) {
            // A fatal controller result means the exact stdio session is no
            // longer safe for granular IPC. Keep this fail-closed marker
            // until shutdown positively reaps the child.
            current.sidecar_state = SidecarLifecycleState::CrashLoop;
        }
    }

    let _lifecycle = context.lifecycle.lock().await;
    if context.operation.is_stopping() {
        return;
    }
    if !context.routes_active.load(Ordering::Acquire) {
        return;
    }
    if context.status.lock().operation_id.as_deref() != Some(operation_id) {
        return;
    }

    let rollback_routes = Arc::clone(&context.routes);
    let rollback_operation = operation_id.to_owned();
    let rollback = tokio::task::spawn_blocking(move || rollback_routes.lock().rollback(&rollback_operation))
        .await
        .unwrap_or(Err(NetworkErrorCode::RouteRollbackFailed));
    match rollback {
        Ok(()) => {
            context.routes_active.store(false, Ordering::Release);
            let cleanup = cleanup_controller(
                &context.controller,
                operation_id,
                context.timeout,
                &context.request_sequence,
                !fatal_sidecar_error(failure),
            )
            .await;
            let mut current = context.status.lock();
            match cleanup {
                Ok(()) => {
                    // The monitor owns this heartbeat task and therefore
                    // cannot publish the exact Disconnected absence receipt:
                    // an external disconnect must first join this task and
                    // clear the exact active operation. Stay fail-closed until
                    // that explicit owner completes the final join.
                    current.state = NetworkState::Error;
                    current.active_transport = None;
                    current.health = None;
                    current.sidecar_state = SidecarLifecycleState::Stopped;
                    // Preserve the reason that caused the automatic teardown
                    // so diagnostics do not silently look like a clean exit.
                    current.last_error = Some(failure);
                }
                Err(cleanup_error) => {
                    current.state = NetworkState::Error;
                    current.last_error = Some(if fatal_sidecar_error(failure) {
                        failure
                    } else {
                        cleanup_error
                    });
                }
            }
        }
        Err(rollback_error) => {
            // Keep the route lease and carrier alive when rollback is
            // ambiguous; an explicit disconnect can retry the same owner.
            let mut current = context.status.lock();
            current.state = NetworkState::Error;
            current.last_error = Some(if fatal_sidecar_error(failure) {
                failure
            } else {
                rollback_error
            });
        }
    }
}

async fn cleanup_controller(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    timeout: Duration,
    request_sequence: &AtomicU64,
    mut controller_usable: bool,
) -> Result<(), NetworkErrorCode> {
    if controller_usable {
        let carrier = cleanup_controller_disconnect_carrier(controller, operation_id, timeout, request_sequence).await;
        if let Err(error) = carrier {
            controller_usable = !fatal_sidecar_error(error);
        }
    }
    if controller_usable {
        let _ = cleanup_controller_stop_tunnel(controller, operation_id, timeout, request_sequence).await;
    }
    tokio::time::timeout(timeout, controller.shutdown())
        .await
        .map_err(|_| NetworkErrorCode::OperationTimedOut)
        .and_then(|result| result)
}

async fn cleanup_controller_disconnect_carrier(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    timeout: Duration,
    request_sequence: &AtomicU64,
) -> Result<(), NetworkErrorCode> {
    let disconnect = bounded_controller_network_status(
        controller,
        operation_id,
        next_request_id(request_sequence, "carrier.disconnect")?,
        IpcRequestPayload::DisconnectTransport,
        timeout,
    )
    .await;
    match disconnect {
        Ok(status) => validate_carrier_disconnected(&status),
        Err(NetworkErrorCode::InvalidStateTransition) => {
            let status = bounded_controller_network_status(
                controller,
                operation_id,
                next_request_id(request_sequence, "carrier.status")?,
                IpcRequestPayload::GetStatus,
                timeout,
            )
            .await?;
            validate_carrier_disconnected(&status)
        }
        Err(error) => Err(error),
    }
}

async fn cleanup_controller_stop_tunnel(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    timeout: Duration,
    request_sequence: &AtomicU64,
) -> Result<(), NetworkErrorCode> {
    let stopped = bounded_controller_network_status(
        controller,
        operation_id,
        next_request_id(request_sequence, "tunnel.stop")?,
        IpcRequestPayload::StopTunnel,
        timeout,
    )
    .await;
    match stopped {
        Ok(status) => validate_carrier_disconnected(&status),
        Err(NetworkErrorCode::InvalidStateTransition) => {
            let status = bounded_controller_network_status(
                controller,
                operation_id,
                next_request_id(request_sequence, "tunnel.status")?,
                IpcRequestPayload::GetStatus,
                timeout,
            )
            .await?;
            validate_carrier_disconnected(&status)
        }
        Err(error) => Err(error),
    }
}

async fn bounded_controller_network_status(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    request_id: String,
    payload: IpcRequestPayload,
    timeout: Duration,
) -> Result<NetworkStatus, NetworkErrorCode> {
    tokio::time::timeout(
        timeout,
        controller_request_network_status(controller, operation_id, request_id, payload, timeout),
    )
    .await
    .map_err(|_| NetworkErrorCode::OperationTimedOut)?
}

async fn controller_request_network_status(
    controller: &ProductionControllerHandle,
    operation_id: &str,
    request_id: String,
    payload: IpcRequestPayload,
    timeout: Duration,
) -> Result<NetworkStatus, NetworkErrorCode> {
    let response = controller
        .request(operation_id.to_owned(), request(request_id, payload), timeout)
        .await?;
    match response.result.map_err(|error| error.code)? {
        IpcResponsePayload::Status(status) => Ok(status),
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

fn authoritative_operation_error(error: NetworkErrorCode, stopping: bool) -> NetworkErrorCode {
    if error == NetworkErrorCode::OperationCancelled && !stopping {
        // Protocol v2 permits OperationCancelled only after this operation
        // sent and drained its exact correlated Cancel exchange. A spontaneous
        // cancellation is an ambiguous/dead session, not a reusable outcome.
        NetworkErrorCode::SidecarUnavailable
    } else {
        error
    }
}

const fn fatal_sidecar_error(error: NetworkErrorCode) -> bool {
    matches!(
        error,
        NetworkErrorCode::UnsupportedProtocolVersion
            | NetworkErrorCode::AuthenticationFailed
            | NetworkErrorCode::PermissionDenied
            | NetworkErrorCode::OperationTimedOut
            | NetworkErrorCode::SidecarUnavailable
    )
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
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

    struct FirstQuicCancelledRuntime {
        inner: Runtime,
        cancel_first_quic: bool,
    }

    #[async_trait]
    impl AsyncProductionRuntime for FirstQuicCancelledRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.inner.start(context).await
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            if self.cancel_first_quic
                && matches!(
                    &request.payload,
                    IpcRequestPayload::ConnectTransport {
                        transport: TransportKind::Quic
                    }
                )
            {
                request.validate_protocol()?;
                self.cancel_first_quic = false;
                self.inner.events.lock().extend([
                    format!("request-id:{}", request.request_id),
                    "carrier:connect:Quic:cancelled".into(),
                ]);
                return Ok(IpcResponse {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: Err(IpcError {
                        code: NetworkErrorCode::OperationCancelled,
                        message: "operation cancelled".into(),
                        retryable: false,
                    }),
                });
            }
            self.inner.request(request, cancel).await
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            self.inner.status().await
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.inner.stop().await
        }
    }

    struct FatalQuicRuntime {
        inner: Runtime,
    }

    #[async_trait]
    impl AsyncProductionRuntime for FatalQuicRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.inner.start(context).await
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            if matches!(
                &request.payload,
                IpcRequestPayload::ConnectTransport {
                    transport: TransportKind::Quic
                }
            ) {
                request.validate_protocol()?;
                self.inner.events.lock().extend([
                    format!("request-id:{}", request.request_id),
                    "carrier:connect:Quic:fatal".into(),
                ]);
                return Err(NetworkErrorCode::SidecarUnavailable);
            }
            self.inner.request(request, cancel).await
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            self.inner.status().await
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.inner.stop().await
        }
    }

    struct BlockingMonitorHealthRuntime {
        inner: Runtime,
        health_calls: u64,
        monitor_entered: Arc<AtomicBool>,
    }

    #[async_trait]
    impl AsyncProductionRuntime for BlockingMonitorHealthRuntime {
        async fn start(&mut self, context: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            self.inner.start(context).await
        }

        async fn request(
            &mut self,
            request: IpcRequest,
            cancel: Arc<AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            if matches!(&request.payload, IpcRequestPayload::SampleHealth) {
                self.health_calls = self.health_calls.saturating_add(1);
                if self.health_calls > 1 {
                    request.validate_protocol()?;
                    self.inner.events.lock().extend([
                        format!("request-id:{}", request.request_id),
                        "carrier:health:blocked".into(),
                    ]);
                    self.monitor_entered.store(true, Ordering::Release);
                    while !cancel.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    self.inner.events.lock().push("carrier:health:cancelled".into());
                    return Err(NetworkErrorCode::OperationCancelled);
                }
            }
            self.inner.request(request, cancel).await
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            self.inner.status().await
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            self.inner.stop().await
        }
    }

    struct MonitoredRuntime {
        inner: Runtime,
        health_failure: Arc<AtomicBool>,
        sidecar_exited: Arc<AtomicBool>,
        unhealthy_transports: Vec<TransportKind>,
        active_transport: Option<TransportKind>,
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
            let requested_transport = match &request.payload {
                IpcRequestPayload::ConnectTransport { transport } => Some(*transport),
                _ => None,
            };
            if self.health_failure.load(Ordering::Acquire)
                && matches!(&request.payload, IpcRequestPayload::SampleHealth)
                && self
                    .active_transport
                    .is_some_and(|transport| self.unhealthy_transports.contains(&transport))
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
            let disconnecting = matches!(&request.payload, IpcRequestPayload::DisconnectTransport);
            if disconnecting && self.active_transport.is_none() {
                request.validate_protocol()?;
                self.inner.events.lock().extend([
                    format!("request-id:{}", request.request_id),
                    "carrier:disconnect:absent".into(),
                ]);
                return Ok(IpcResponse {
                    protocol_version: NETWORK_IPC_PROTOCOL_VERSION,
                    request_id: request.request_id,
                    result: Err(IpcError {
                        code: NetworkErrorCode::InvalidStateTransition,
                        message: "carrier already absent".into(),
                        retryable: false,
                    }),
                });
            }
            let response = self.inner.request(request, cancel).await?;
            if response.result.is_ok() {
                if let Some(transport) = requested_transport {
                    self.active_transport = Some(transport);
                } else if disconnecting {
                    self.active_transport = None;
                }
            }
            Ok(response)
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
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::RecoveryOnly
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::RecoveryOnly
        }

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
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::RecoveryOnly
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::RecoveryOnly
        }

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

    #[derive(Default)]
    struct BlockingRouteCall {
        entered: AtomicBool,
        release: AtomicBool,
        completed: AtomicBool,
        calls: AtomicUsize,
    }

    impl BlockingRouteCall {
        fn run(&self) {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.store(true, Ordering::Release);
            while !self.release.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            self.completed.store(true, Ordering::Release);
        }
    }

    struct BlockingHeartbeatRoutes {
        events: Arc<Mutex<Vec<String>>>,
        heartbeat: Arc<BlockingRouteCall>,
        rollback_calls: Arc<AtomicUsize>,
        dropped: Arc<AtomicBool>,
    }

    impl Drop for BlockingHeartbeatRoutes {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl ProductionRouteBoundary for BlockingHeartbeatRoutes {
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::RecoveryOnly
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::RecoveryOnly
        }

        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            _: &TunnelDeviceFacts,
            _: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:apply".into());
            Ok(())
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:heartbeat:blocked".into());
            self.heartbeat.run();
            self.events.lock().push("routes:heartbeat:completed".into());
            Ok(())
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.rollback_calls.fetch_add(1, Ordering::AcqRel);
            self.events.lock().push("routes:rollback".into());
            Ok(())
        }
    }

    struct BlockingRollbackRoutes {
        events: Arc<Mutex<Vec<String>>>,
        rollback: Arc<BlockingRouteCall>,
    }

    impl ProductionRouteBoundary for BlockingRollbackRoutes {
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::RecoveryOnly
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::RecoveryOnly
        }

        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            _: &TunnelDeviceFacts,
            _: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:apply".into());
            Ok(())
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:heartbeat:failed".into());
            Err(NetworkErrorCode::RouteRollbackFailed)
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:rollback:blocked".into());
            self.rollback.run();
            self.events.lock().push("routes:rollback:completed".into());
            Ok(())
        }
    }

    struct FailFirstRollbackRoutes {
        events: Arc<Mutex<Vec<String>>>,
        rollback_calls: Arc<AtomicUsize>,
    }

    impl ProductionRouteBoundary for FailFirstRollbackRoutes {
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::RecoveryOnly
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::RecoveryOnly
        }

        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            _: &TunnelDeviceFacts,
            _: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:apply".into());
            Ok(())
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            self.events.lock().push("routes:heartbeat".into());
            Ok(())
        }

        fn rollback(&mut self, operation_id: &str) -> Result<(), NetworkErrorCode> {
            let attempt = self.rollback_calls.fetch_add(1, Ordering::AcqRel) + 1;
            self.events
                .lock()
                .push(format!("routes:rollback:{operation_id}:{attempt}"));
            if attempt == 1 {
                Err(NetworkErrorCode::RouteRollbackFailed)
            } else {
                Ok(())
            }
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

    async fn wait_for_final_commit_gate(gate: &FinalCommitGate) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !gate.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_late_cancel_from_an_old_epoch_cannot_poison_the_next_operation() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![31; 32]).with_private_key(vec![32; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(events)),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let old = Arc::new(ProductionOperation::new("operation.same".into(), 1));
        let current = Arc::new(ProductionOperation::new("operation.same".into(), 2));
        *service.active_operation.lock() = Some(Arc::clone(&current));
        service.status.lock().state = NetworkState::Authenticating;
        service.status.lock().operation_id = Some(current.id.clone());

        old.request_cancel();

        assert_eq!(service.ensure_operation_active(&current), Ok(()));
        assert_eq!(
            service.ensure_operation_active(&old),
            Err(NetworkErrorCode::OperationCancelled)
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_wins_at_the_final_commit_boundary_and_cleanup_is_exact() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![51; 32]).with_private_key(vec![52; 32]),
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
        let gate = Arc::new(FinalCommitGate::new(FinalCommitGateStage::Before));
        *service.final_commit_gate.lock() = Some(Arc::clone(&gate));
        let service = Arc::new(service);
        let operation_id = "operation.final.cancel-wins";
        let connect_service = Arc::clone(&service);
        let connect = tokio::spawn(async move { connect_service.connect(operation_id.into()).await });

        wait_for_final_commit_gate(&gate).await?;
        assert_eq!(service.status().state, NetworkState::ConnectingPrimary);
        assert_eq!(service.cancel(operation_id), Ok(()));
        gate.release.store(true, Ordering::Release);

        let result = tokio::time::timeout(Duration::from_secs(2), connect).await??;
        assert_eq!(result, Err(NetworkErrorCode::OperationCancelled));
        let status = service.status();
        assert_eq!(status.state, NetworkState::Disconnected);
        assert_eq!(status.operation_id, None);
        assert_eq!(status.last_error, Some(NetworkErrorCode::OperationCancelled));
        assert!(!service.routes_active.load(Ordering::Acquire));
        assert!(service.route_heartbeat.lock().is_none());
        assert!(service.active_operation.lock().is_none());

        let events = events.lock();
        let position = |value: &str| {
            events
                .iter()
                .position(|event| event == value)
                .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
        };
        assert!(position("routes:apply")? < position("routes:rollback")?);
        assert!(position("routes:rollback")? < position("secret:clear")?);
        assert!(!events.iter().any(|event| event == "routes:heartbeat"));
        drop(events);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publication_wins_at_the_final_commit_boundary_and_cancel_is_too_late() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![53; 32]).with_private_key(vec![54; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(Routes(events)),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let gate = Arc::new(FinalCommitGate::new(FinalCommitGateStage::After));
        *service.final_commit_gate.lock() = Some(Arc::clone(&gate));
        let service = Arc::new(service);
        let operation_id = "operation.final.publication-wins";
        let connect_service = Arc::clone(&service);
        let connect = tokio::spawn(async move { connect_service.connect(operation_id.into()).await });

        wait_for_final_commit_gate(&gate).await?;
        assert_eq!(service.status().state, NetworkState::ConnectedPrimary);
        assert_eq!(
            service.cancel(operation_id),
            Err(NetworkErrorCode::InvalidStateTransition)
        );
        gate.release.store(true, Ordering::Release);

        let connected = tokio::time::timeout(Duration::from_secs(2), connect)
            .await??
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(connected.state, NetworkState::ConnectedPrimary);
        let disconnected = service
            .disconnect("operation.final.publication-wins.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(disconnected.state, NetworkState::Disconnected);
        assert!(service.route_heartbeat.lock().is_none());
        assert!(service.active_operation.lock().is_none());
        Ok(())
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
    async fn spontaneous_cancelled_response_fail_stops_before_a_new_operation() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            FirstQuicCancelledRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
                cancel_first_quic: true,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![33; 32]).with_private_key(vec![34; 32]),
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
            service.connect("operation.cancelled.first".into()).await,
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(service.status().state, NetworkState::Disconnected);
        assert_eq!(service.status().last_error, Some(NetworkErrorCode::SidecarUnavailable));
        assert!(
            !events
                .lock()
                .iter()
                .any(|event| matches!(event.as_str(), "carrier:connect:Wss" | "carrier:connect:Tcp"))
        );
        let fail_stop = {
            let first_events = events.lock();
            let spontaneous_cancel = first_events
                .iter()
                .position(|event| event == "carrier:connect:Quic:cancelled")
                .ok_or_else(|| anyhow::anyhow!("missing spontaneous cancellation"))?;
            let fail_stop = first_events
                .iter()
                .position(|event| event == "secret:clear")
                .ok_or_else(|| anyhow::anyhow!("missing fail-stop cleanup"))?;
            assert!(spontaneous_cancel < fail_stop);
            drop(first_events);
            fail_stop
        };

        assert_eq!(
            service
                .connect("operation.cancelled.second".into())
                .await
                .map_err(|error| anyhow::anyhow!("{error:?}"))?
                .state,
            NetworkState::ConnectedPrimary
        );
        let next_authentication = events
            .lock()
            .iter()
            .rposition(|event| event == "authenticate")
            .ok_or_else(|| anyhow::anyhow!("missing next child authentication"))?;
        assert!(fail_stop < next_authentication);
        service
            .disconnect("operation.cancelled.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        Ok(())
    }

    #[tokio::test]
    async fn fatal_quic_error_is_authoritative_and_cleanup_sends_no_more_ipc() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let controller = spawn_production_controller(
            FatalQuicRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
            },
            SidecarLaunchContext::new("instance.test".into(), vec![35; 32]).with_private_key(vec![36; 32]),
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
            service.connect("operation.fatal.quic".into()).await,
            Err(NetworkErrorCode::SidecarUnavailable)
        );
        assert_eq!(service.status().last_error, Some(NetworkErrorCode::SidecarUnavailable));
        let events = events.lock();
        let fatal = events
            .iter()
            .position(|event| event == "carrier:connect:Quic:fatal")
            .ok_or_else(|| anyhow::anyhow!("missing fatal boundary"))?;
        assert!(!events[fatal + 1..].iter().any(|event| event.starts_with("request-id:")));
        assert!(!events.iter().any(|event| {
            matches!(
                event.as_str(),
                "carrier:disconnect" | "tunnel:stop" | "carrier:connect:Wss" | "carrier:connect:Tcp"
            )
        }));
        drop(events);
        Ok(())
    }

    #[tokio::test]
    async fn all_runtime_carriers_failing_rolls_routes_back_before_bounded_cleanup() -> anyhow::Result<()> {
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
                unhealthy_transports: vec![TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp],
                active_transport: None,
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
        let owner = "operation.monitor.health";
        service
            .connect(owner.into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        health_failure.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                let heartbeat_finished = service
                    .route_heartbeat
                    .lock()
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if current.state == NetworkState::Error
                    && current.sidecar_state == SidecarLifecycleState::Stopped
                    && current.operation_id.as_deref() == Some(owner)
                    && current.last_error == Some(NetworkErrorCode::FallbackTransportUnavailable)
                    && heartbeat_finished
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!service.routes_active.load(Ordering::Acquire));
        assert!(service.route_heartbeat.lock().is_some());
        assert!(service.active_operation.lock().is_some());

        let diagnostics = service
            .diagnostics()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert!(diagnostics.iter().any(|event| {
            event.kind == super::super::ProductionEventKind::RequestCompleted
                && event.error == Some(NetworkErrorCode::InvalidStateTransition)
        }));

        {
            let events = events.lock().clone();
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
                5,
                "primary uses the configured threshold before each fallback is gated once"
            );
            assert!(position("carrier:health:failed")? < position("routes:rollback")?);
            assert!(position("routes:rollback")? < position("tunnel:stop")?);
            assert!(position("routes:rollback")? < position("secret:clear")?);
        }
        let disconnected = service
            .disconnect("operation.monitor.health.cleanup".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(disconnected.state, NetworkState::Disconnected);
        assert_eq!(
            disconnected.last_error,
            Some(NetworkErrorCode::FallbackTransportUnavailable)
        );
        assert!(service.route_heartbeat.lock().is_none());
        assert!(service.active_operation.lock().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_health_failure_switches_quic_wss_tcp_break_before_make() -> anyhow::Result<()> {
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
                unhealthy_transports: vec![TransportKind::Quic, TransportKind::Wss],
                active_transport: None,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![15; 32]).with_private_key(vec![16; 32]),
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
            .connect("operation.monitor.fallback".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        health_failure.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                if current.state == NetworkState::DegradedFallback
                    && current.active_transport == Some(TransportKind::Tcp)
                    && current.last_error == Some(NetworkErrorCode::PrimaryTransportUnavailable)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        {
            let events = events.lock();
            let position = |value: &str| {
                events
                    .iter()
                    .position(|event| event == value)
                    .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
            };
            let disconnects = events
                .iter()
                .enumerate()
                .filter_map(|(index, event)| (event == "carrier:disconnect").then_some(index))
                .collect::<Vec<_>>();
            assert!(disconnects.len() >= 2);
            assert!(disconnects[0] < position("carrier:connect:Wss")?);
            assert!(disconnects[1] < position("carrier:connect:Tcp")?);
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.as_str() == "carrier:health:failed")
                    .count(),
                4
            );
            assert!(!events.iter().any(|event| event == "routes:rollback"));
            assert_eq!(
                events.iter().filter(|event| event.as_str() == "routes:apply").count(),
                0
            );
            drop(events);
        }

        service
            .disconnect("operation.monitor.fallback.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert!(events.lock().iter().any(|event| event == "routes:rollback"));
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
                unhealthy_transports: vec![TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp],
                active_transport: None,
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
        let owner = "operation.monitor.sidecar";
        service
            .connect(owner.into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        sidecar_exited.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let current = service.status();
                let heartbeat_finished = service
                    .route_heartbeat
                    .lock()
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if current.state == NetworkState::Error
                    && current.sidecar_state == SidecarLifecycleState::Stopped
                    && current.operation_id.as_deref() == Some(owner)
                    && current.last_error == Some(NetworkErrorCode::SidecarUnavailable)
                    && heartbeat_finished
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!service.routes_active.load(Ordering::Acquire));
        assert!(service.route_heartbeat.lock().is_some());
        assert!(service.active_operation.lock().is_some());

        {
            let events = events.lock().clone();
            let position = |value: &str| {
                events
                    .iter()
                    .position(|event| event == value)
                    .ok_or_else(|| anyhow::anyhow!("missing event {value}"))
            };
            assert!(position("sidecar:exited")? < position("routes:rollback")?);
            assert!(position("routes:rollback")? < position("secret:clear")?);
        }
        let disconnected = service
            .disconnect("operation.monitor.sidecar.cleanup".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(disconnected.state, NetworkState::Disconnected);
        assert_eq!(disconnected.last_error, Some(NetworkErrorCode::SidecarUnavailable));
        assert!(service.route_heartbeat.lock().is_none());
        assert!(service.active_operation.lock().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn fatal_monitor_rollback_failure_preserves_primary_and_exact_retry_converges() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sidecar_exited = Arc::new(AtomicBool::new(false));
        let rollback_calls = Arc::new(AtomicUsize::new(0));
        let controller = spawn_production_controller(
            MonitoredRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
                health_failure: Arc::new(AtomicBool::new(false)),
                sidecar_exited: Arc::clone(&sidecar_exited),
                unhealthy_transports: vec![TransportKind::Quic, TransportKind::Wss, TransportKind::Tcp],
                active_transport: None,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![41; 32]).with_private_key(vec![42; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(FailFirstRollbackRoutes {
                events: Arc::clone(&events),
                rollback_calls: Arc::clone(&rollback_calls),
            }),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(10);
        service.timeout = Duration::from_millis(50);
        let owner = "operation.monitor.fatal.rollback";
        service
            .connect(owner.into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();
        sidecar_exited.store(true, Ordering::Release);

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let heartbeat_finished = service
                    .route_heartbeat
                    .lock()
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if heartbeat_finished && rollback_calls.load(Ordering::Acquire) == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let failed = service.status();
        assert_eq!(failed.state, NetworkState::Error);
        assert_eq!(failed.sidecar_state, SidecarLifecycleState::CrashLoop);
        assert_eq!(failed.last_error, Some(NetworkErrorCode::SidecarUnavailable));
        assert!(service.routes_active.load(Ordering::Acquire));
        let retry_boundary = events.lock().len();

        let recovered = service
            .disconnect("operation.retry.fatal.rollback".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(recovered.state, NetworkState::Disconnected);
        assert_eq!(recovered.sidecar_state, SidecarLifecycleState::Stopped);
        assert!(!service.routes_active.load(Ordering::Acquire));
        assert_eq!(rollback_calls.load(Ordering::Acquire), 2);

        let events = events.lock();
        assert!(
            events
                .iter()
                .any(|event| event == &format!("routes:rollback:{owner}:1"))
        );
        assert!(
            events
                .iter()
                .any(|event| event == &format!("routes:rollback:{owner}:2"))
        );
        assert!(
            !events[retry_boundary..]
                .iter()
                .any(|event| event.starts_with("request-id:")),
            "fatal retry issued granular IPC on an unusable controller"
        );
        drop(events);
        Ok(())
    }

    #[tokio::test]
    async fn blocked_heartbeat_join_refuses_later_route_mutation_until_completion() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let heartbeat = Arc::new(BlockingRouteCall::default());
        let rollback_calls = Arc::new(AtomicUsize::new(0));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![43; 32]).with_private_key(vec![44; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(BlockingHeartbeatRoutes {
                events,
                heartbeat: Arc::clone(&heartbeat),
                rollback_calls: Arc::clone(&rollback_calls),
                dropped: Arc::new(AtomicBool::new(false)),
            }),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(10);
        service.timeout = Duration::from_millis(30);
        let service = Arc::new(service);
        service
            .connect("operation.blocked.heartbeat".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let first_disconnect = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.disconnect("operation.blocked.heartbeat.first".into()).await }
        });
        assert_eq!(first_disconnect.await?, Err(NetworkErrorCode::OperationTimedOut));
        assert!(service.route_heartbeat.lock().is_some());
        let second_disconnect = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.disconnect("operation.blocked.heartbeat.second".into()).await }
        });
        assert_eq!(second_disconnect.await?, Err(NetworkErrorCode::OperationTimedOut));
        assert_ne!(service.status().state, NetworkState::Disconnected);
        assert_eq!(heartbeat.calls.load(Ordering::Acquire), 1);
        assert_eq!(rollback_calls.load(Ordering::Acquire), 0);

        heartbeat.release.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let recovered = service
            .disconnect("operation.blocked.heartbeat.final".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(recovered.state, NetworkState::Disconnected);
        assert_eq!(heartbeat.calls.load(Ordering::Acquire), 1);
        assert_eq!(rollback_calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn aborting_heartbeat_join_caller_keeps_live_route_task_owned() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let heartbeat = Arc::new(BlockingRouteCall::default());
        let rollback_calls = Arc::new(AtomicUsize::new(0));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![49; 32]).with_private_key(vec![50; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(BlockingHeartbeatRoutes {
                events,
                heartbeat: Arc::clone(&heartbeat),
                rollback_calls: Arc::clone(&rollback_calls),
                dropped: Arc::new(AtomicBool::new(false)),
            }),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(10);
        service.timeout = Duration::from_millis(30);
        let service = Arc::new(service);
        service
            .connect("operation.abort.heartbeat".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let interrupted = tokio::spawn({
            let service = Arc::clone(&service);
            async move { service.disconnect("operation.abort.disconnect".into()).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while service.status().state != NetworkState::Disconnecting
                || service.route_heartbeat_join.try_lock().is_ok()
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        interrupted.abort();
        let join_error = match interrupted.await {
            Err(error) => error,
            Ok(_) => return Err(anyhow::anyhow!("aborted disconnect unexpectedly completed")),
        };
        assert!(join_error.is_cancelled());
        assert!(service.route_heartbeat.lock().is_some());
        assert!(!heartbeat.completed.load(Ordering::Acquire));
        assert_eq!(rollback_calls.load(Ordering::Acquire), 0);

        assert_eq!(
            service.disconnect("operation.abort.retry".into()).await,
            Err(NetworkErrorCode::OperationTimedOut)
        );
        assert!(service.route_heartbeat.lock().is_some());
        assert_eq!(heartbeat.calls.load(Ordering::Acquire), 1);
        assert_eq!(rollback_calls.load(Ordering::Acquire), 0);

        heartbeat.release.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let recovered = service
            .disconnect("operation.abort.final".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(recovered.state, NetworkState::Disconnected);
        assert_eq!(rollback_calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn blocked_monitor_rollback_stays_owned_and_cannot_be_replayed() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let rollback = Arc::new(BlockingRouteCall::default());
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![45; 32]).with_private_key(vec![46; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(BlockingRollbackRoutes {
                events,
                rollback: Arc::clone(&rollback),
            }),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(10);
        service.timeout = Duration::from_millis(30);
        service
            .connect("operation.blocked.rollback".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            while !rollback.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            service.disconnect("operation.blocked.rollback.first".into()).await,
            Err(NetworkErrorCode::OperationTimedOut)
        );
        assert_ne!(service.status().state, NetworkState::Disconnected);
        assert_eq!(rollback.calls.load(Ordering::Acquire), 1);

        assert_eq!(
            service.disconnect("operation.blocked.rollback.second".into()).await,
            Err(NetworkErrorCode::OperationTimedOut)
        );
        assert_ne!(service.status().state, NetworkState::Disconnected);
        assert_eq!(rollback.calls.load(Ordering::Acquire), 1);

        rollback.release.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !rollback.completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let recovered = service
            .disconnect("operation.blocked.rollback.final".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(recovered.state, NetworkState::Disconnected);
        assert_eq!(rollback.calls.load(Ordering::Acquire), 1);
        Ok(())
    }

    #[tokio::test]
    async fn drop_tracks_a_blocked_heartbeat_until_its_route_owner_finishes() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let heartbeat = Arc::new(BlockingRouteCall::default());
        let rollback_calls = Arc::new(AtomicUsize::new(0));
        let boundary_dropped = Arc::new(AtomicBool::new(false));
        let controller = spawn_production_controller(
            Runtime {
                events: Arc::clone(&events),
                fail_quic: false,
            },
            SidecarLaunchContext::new("instance.test".into(), vec![47; 32]).with_private_key(vec![48; 32]),
            "proof".into(),
        );
        let profile: NetworkProfile = serde_json::from_str(PROFILE)?;
        let mut service = ProductionNetworkingService::new(
            controller,
            profile,
            Box::new(BlockingHeartbeatRoutes {
                events,
                heartbeat: Arc::clone(&heartbeat),
                rollback_calls: Arc::clone(&rollback_calls),
                dropped: Arc::clone(&boundary_dropped),
            }),
            "instance.test".into(),
            42,
        )
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        service.route_heartbeat_interval = Duration::from_millis(10);
        service.timeout = Duration::from_millis(30);
        service
            .connect("operation.drop.heartbeat".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(service);
        assert!(!heartbeat.completed.load(Ordering::Acquire));
        assert!(!boundary_dropped.load(Ordering::Acquire));
        assert_eq!(rollback_calls.load(Ordering::Acquire), 0);

        heartbeat.release.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !heartbeat.completed.load(Ordering::Acquire) || !boundary_dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(heartbeat.calls.load(Ordering::Acquire), 1);
        assert_eq!(rollback_calls.load(Ordering::Acquire), 0);
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
    async fn disconnect_intent_cancels_and_joins_blocked_health_before_cleanup() -> anyhow::Result<()> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let monitor_entered = Arc::new(AtomicBool::new(false));
        let controller = spawn_production_controller(
            BlockingMonitorHealthRuntime {
                inner: Runtime {
                    events: Arc::clone(&events),
                    fail_quic: false,
                },
                health_calls: 0,
                monitor_entered: Arc::clone(&monitor_entered),
            },
            SidecarLaunchContext::new("instance.test".into(), vec![37; 32]).with_private_key(vec![38; 32]),
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
        service.route_heartbeat_interval = Duration::from_millis(10);
        service
            .connect("operation.blocked.health".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        events.lock().clear();

        tokio::time::timeout(Duration::from_secs(1), async {
            while !monitor_entered.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let disconnected = service
            .disconnect("operation.blocked.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        assert_eq!(disconnected.state, NetworkState::Disconnected);
        assert_eq!(disconnected.last_error, None);
        let events = events.lock();
        assert!(events.iter().any(|event| event == "carrier:health:cancelled"));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.as_str(), "carrier:connect:Wss" | "carrier:connect:Tcp"))
        );
        drop(events);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_failure_stays_error_until_explicit_join_converges_disconnected() -> anyhow::Result<()> {
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
                let heartbeat_finished = service
                    .route_heartbeat
                    .lock()
                    .as_ref()
                    .is_some_and(|task| task.handle.is_finished());
                if current.state == NetworkState::Error
                    && current.sidecar_state == SidecarLifecycleState::Stopped
                    && current.operation_id.as_deref() == Some("operation.heartbeat.failure")
                    && current.last_error == Some(NetworkErrorCode::RouteRollbackFailed)
                    && heartbeat_finished
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(service.status().last_error, Some(NetworkErrorCode::RouteRollbackFailed));
        assert!(!service.routes_active.load(Ordering::Acquire));
        assert!(service.route_heartbeat.lock().is_some());
        assert!(service.active_operation.lock().is_some());
        let disconnected = service
            .disconnect("operation.heartbeat.failure.disconnect".into())
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(disconnected.state, NetworkState::Disconnected);
        assert_eq!(disconnected.last_error, Some(NetworkErrorCode::RouteRollbackFailed));
        assert!(service.route_heartbeat.lock().is_none());
        assert!(service.active_operation.lock().is_none());
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
