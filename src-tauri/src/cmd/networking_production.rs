use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use parking_lot::Mutex as ParkingMutex;
use serde::Serialize;
use tauri::{AppHandle, Manager as _, State};
use tokio::sync::{Mutex, RwLock};

use crate::networking::{
    BundleProductionInitializationProvider, NetworkErrorCode, ProductionConnectReservation, ProductionEventKind,
    ProductionInitializationProvider, ProductionNetworkStatus, ProductionNetworkingService,
    ProductionServiceDispositionKind, ProductionServiceFactory, ProductionServiceRetirementReceipt,
    ProductionServiceRetirementResult, ProductionSiteSummary, RouteHelperRegistrationStatus,
    open_route_helper_settings, register_route_helper, route_helper_registration_status, unregister_route_helper,
};

const RETIRED_EVIDENCE_LIMIT: usize = 16;

/// Redacted evidence retained after a service generation has been closed.
///
/// This record intentionally contains only generation/absence facts and typed
/// errors.  It never stores profile, endpoint, Keychain, signature, or route
/// payload material.  Keeping a bounded record prevents a failed rebuild from
/// erasing the proof that the old generation was retired.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RetiredGenerationEvidence {
    service_generation: u64,
    route_boundary_incarnation: u64,
    route_native_generation: u64,
    controller_runtime_generation: u64,
    controller_absence: crate::networking::ControllerAbsenceKind,
    primary_error: Option<NetworkErrorCode>,
    secondary_error: Option<NetworkErrorCode>,
}

struct ConnectTarget {
    service: Arc<ProductionNetworkingService>,
    reservation: ProductionConnectReservation,
}

pub struct ProductionCommandState {
    service: RwLock<Option<Arc<ProductionNetworkingService>>>,
    factory: RwLock<Option<Arc<dyn ProductionServiceFactory>>>,
    provider: RwLock<Option<Arc<dyn ProductionInitializationProvider>>>,
    materialize: Mutex<()>,
    sequence: AtomicU64,
    retired_evidence: ParkingMutex<VecDeque<RetiredGenerationEvidence>>,
}

impl Default for ProductionCommandState {
    fn default() -> Self {
        Self {
            service: RwLock::new(None),
            factory: RwLock::new(None),
            provider: RwLock::new(None),
            materialize: Mutex::new(()),
            sequence: AtomicU64::new(0),
            retired_evidence: ParkingMutex::new(VecDeque::with_capacity(RETIRED_EVIDENCE_LIMIT)),
        }
    }
}

impl ProductionCommandState {
    #[allow(dead_code)]
    pub async fn configure(&self, service: ProductionNetworkingService) -> Result<(), NetworkErrorCode> {
        let _guard = self.materialize.lock().await;
        self.configure_service_locked(service).await
    }

    async fn configure_service_locked(&self, service: ProductionNetworkingService) -> Result<(), NetworkErrorCode> {
        if self.factory.read().await.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let mut slot = self.service.write().await;
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        *slot = Some(Arc::new(service));
        drop(slot);
        Ok(())
    }

    /// Register the deferred factory after a signed policy has been explicitly
    /// verified.  Registration has no Keychain, XPC, sidecar, tunnel, or route
    /// side effects; those occur only in `service_for_connect`.
    #[allow(dead_code)]
    pub async fn configure_factory(&self, factory: Arc<dyn ProductionServiceFactory>) -> Result<(), NetworkErrorCode> {
        let _guard = self.materialize.lock().await;
        self.configure_factory_locked(factory).await
    }

    async fn configure_factory_locked(
        &self,
        factory: Arc<dyn ProductionServiceFactory>,
    ) -> Result<(), NetworkErrorCode> {
        if self.service.read().await.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let mut slot = self.factory.write().await;
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        *slot = Some(factory);
        drop(slot);
        Ok(())
    }

    /// Synchronous setup variant. Tauri setup is not an async command and
    /// must not borrow its short-lived `App` reference into a `'static`
    /// future. `try_write` also makes setup fail closed rather than blocking
    /// the main thread behind a running operation.
    pub fn configure_provider_now(
        &self,
        provider: Arc<dyn ProductionInitializationProvider>,
    ) -> Result<(), NetworkErrorCode> {
        let _guard = self
            .materialize
            .try_lock()
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
        let mut slot = self
            .provider
            .try_write()
            .map_err(|_| NetworkErrorCode::InvalidStateTransition)?;
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        *slot = Some(provider);
        drop(slot);
        Ok(())
    }

    async fn initialize(&self) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        // Initialization and connect materialization share one serialization
        // boundary.  Without this guard two UI mounts (or a mount racing a
        // Connect click) could verify and persist the same policy revision
        // twice; the second revision-store write would then look like a
        // replay even though both callers addressed the same app state.
        let _guard = self.materialize.lock().await;
        if self.factory.read().await.is_none() {
            let provider = self
                .provider
                .read()
                .await
                .clone()
                .ok_or(NetworkErrorCode::InvalidConfiguration)?;
            let factory = provider.initialize().await?;
            // `initialize` already owns `materialize`; use the locked helper
            // to avoid recursively acquiring the non-reentrant mutex.
            self.configure_factory_locked(factory).await?;
        }
        self.status_snapshot()
            .await
            .ok_or(NetworkErrorCode::InvalidConfiguration)
    }

    async fn service(&self) -> Result<Arc<ProductionNetworkingService>, String> {
        self.service
            .read()
            .await
            .clone()
            .ok_or_else(|| code(NetworkErrorCode::InvalidConfiguration))
    }

    /// Select an exact service generation and issue its single-use Connect
    /// reservation while the materialization mutex is held.  The returned
    /// reservation is moved into the spawned task by `connect_networking`; it
    /// cannot be duplicated or silently lost during a replacement race.
    async fn service_for_connect(&self) -> Result<ConnectTarget, NetworkErrorCode> {
        let _guard = self.materialize.lock().await;

        let existing = self.service.read().await.clone();
        if let Some(service) = existing {
            let disposition = service.disposition();
            match disposition.kind() {
                ProductionServiceDispositionKind::Reusable => {
                    let reservation = service.reserve_connect()?;
                    return Ok(ConnectTarget { service, reservation });
                }
                ProductionServiceDispositionKind::TerminalCandidate => {
                    return self
                        .rematerialize_terminal_locked(service, disposition.generation())
                        .await;
                }
                ProductionServiceDispositionKind::Busy
                | ProductionServiceDispositionKind::RecoveryOnly
                | ProductionServiceDispositionKind::Retired => {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
            }
        }

        self.build_install_reserved_locked().await
    }

    /// Build and reserve a service completely off-slot, then publish it with
    /// an empty-slot CAS.  Any failure closes the never-published candidate;
    /// the live slot remains empty so a later Connect can retry safely.
    async fn build_install_reserved_locked(&self) -> Result<ConnectTarget, NetworkErrorCode> {
        let factory = self
            .factory
            .read()
            .await
            .clone()
            .ok_or(NetworkErrorCode::InvalidConfiguration)?;
        let candidate = Arc::new(factory.build().await?);
        let reservation = match candidate.reserve_connect() {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(close_unpublished_service(Arc::clone(&candidate))
                    .await
                    .err()
                    .unwrap_or(error));
            }
        };
        let generation = candidate.service_generation();
        let installed = {
            let mut slot = self.service.write().await;
            if slot.is_none() && candidate.service_generation() == generation {
                *slot = Some(Arc::clone(&candidate));
                true
            } else {
                false
            }
        };
        if !installed {
            reservation.abandon();
            return Err(close_unpublished_service(Arc::clone(&candidate))
                .await
                .err()
                .unwrap_or(NetworkErrorCode::InvalidStateTransition));
        }
        debug_assert_eq!(generation, candidate.service_generation());
        Ok(ConnectTarget {
            service: candidate,
            reservation,
        })
    }

    /// Retire the exact Arc/generation selected under the materialization
    /// mutex, compare-remove it, and only then build a replacement off-slot.
    /// The consumed retirement receipt is retained as redacted evidence even
    /// when the subsequent factory build or install fails.
    async fn rematerialize_terminal_locked(
        &self,
        service: Arc<ProductionNetworkingService>,
        generation: u64,
    ) -> Result<ConnectTarget, NetworkErrorCode> {
        if service.service_generation() != generation {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        let primary_error = service.status().last_error;
        {
            let receipt = match service.try_retire().await {
                ProductionServiceRetirementResult::Retired(receipt) => receipt,
                ProductionServiceRetirementResult::Busy => return Err(NetworkErrorCode::InvalidStateTransition),
                ProductionServiceRetirementResult::RecoveryOnly => {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
                ProductionServiceRetirementResult::AlreadyRetired => {
                    return Err(NetworkErrorCode::InvalidStateTransition);
                }
            };
            self.record_retirement(&receipt, primary_error, None);
            if !self.compare_remove_service(&service, generation).await {
                self.record_secondary_error(generation, NetworkErrorCode::InvalidStateTransition);
                return Err(NetworkErrorCode::InvalidStateTransition);
            }
            // The receipt is intentionally consumed only after the exact
            // Arc/CAS proof has been recorded. Its scope ends before the
            // replacement factory is invoked; all facts remain in the
            // redacted evidence queue.
        }
        match self.build_install_reserved_locked().await {
            Ok(target) => Ok(target),
            Err(error) => {
                self.record_secondary_error(generation, error);
                Err(error)
            }
        }
    }

    async fn compare_remove_service(&self, expected: &Arc<ProductionNetworkingService>, generation: u64) -> bool {
        let mut slot = self.service.write().await;
        let matches = slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, expected) && current.service_generation() == generation);
        if matches {
            slot.take();
        }
        matches
    }

    fn record_retirement(
        &self,
        receipt: &ProductionServiceRetirementReceipt,
        primary_error: Option<NetworkErrorCode>,
        secondary_error: Option<NetworkErrorCode>,
    ) {
        let mut records = self.retired_evidence.lock();
        if records.len() == RETIRED_EVIDENCE_LIMIT {
            records.pop_front();
        }
        records.push_back(RetiredGenerationEvidence {
            service_generation: receipt.service_generation(),
            route_boundary_incarnation: receipt.route_boundary_incarnation(),
            route_native_generation: receipt.route_native_generation(),
            controller_runtime_generation: receipt.controller_runtime_generation(),
            controller_absence: receipt.controller_absence(),
            primary_error,
            secondary_error,
        });
    }

    fn record_secondary_error(&self, generation: u64, error: NetworkErrorCode) {
        if let Some(record) = self
            .retired_evidence
            .lock()
            .iter_mut()
            .rev()
            .find(|record| record.service_generation == generation)
        {
            record.secondary_error = Some(error);
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn retired_evidence_snapshot(&self) -> Vec<RetiredGenerationEvidence> {
        self.retired_evidence.lock().iter().cloned().collect()
    }

    /// Run cancellation against the exact generation selected while the
    /// materialization mutex is held. The service mutation gate performs the
    /// final generation check, so a retired Arc cannot mutate after a
    /// replacement.
    async fn cancel_exact(&self, operation_id: &str) -> Result<(), NetworkErrorCode> {
        let _guard = self.materialize.lock().await;
        let service = self
            .service
            .read()
            .await
            .clone()
            .ok_or(NetworkErrorCode::InvalidConfiguration)?;
        match service.disposition().kind() {
            ProductionServiceDispositionKind::Retired => Err(NetworkErrorCode::InvalidStateTransition),
            _ => service.cancel(operation_id),
        }
    }

    /// Run Disconnect under the same materialization boundary used by
    /// Connect/rematerialization. This prevents replacement CAS from
    /// interleaving with exact service-generation cleanup.
    async fn disconnect_exact(&self, operation_id: String) -> Result<ProductionNetworkStatus, NetworkErrorCode> {
        let _guard = self.materialize.lock().await;
        let service = self
            .service
            .read()
            .await
            .clone()
            .ok_or(NetworkErrorCode::InvalidConfiguration)?;
        if service.disposition().kind() == ProductionServiceDispositionKind::Retired {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        service.disconnect(operation_id).await
    }

    async fn status_snapshot(&self) -> Option<ProductionNetworkStatus> {
        let existing = self.service.read().await.clone();
        if let Some(service) = existing {
            return Some(service.status());
        }
        self.factory
            .read()
            .await
            .as_ref()
            .map(|factory| factory.initial_status())
    }

    async fn status_or_error(&self) -> Result<ProductionNetworkStatus, String> {
        self.status_snapshot()
            .await
            .ok_or_else(|| code(NetworkErrorCode::InvalidConfiguration))
    }

    fn operation_id(&self, action: &str) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        format!("networking.production.{action}.{sequence}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProductionDiagnosticEvent {
    sequence: u64,
    operation_id: Option<String>,
    kind: &'static str,
    error: Option<NetworkErrorCode>,
}

pub fn configure_bundle_provider_now(app: &AppHandle, state: &ProductionCommandState) -> Result<(), NetworkErrorCode> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
    let provider = BundleProductionInitializationProvider::new(resource_dir, app_data_dir)?;
    state.configure_provider_now(Arc::new(provider))
}

#[tauri::command]
pub async fn initialize_networking(
    state: State<'_, ProductionCommandState>,
) -> Result<ProductionNetworkStatus, String> {
    state.initialize().await.map_err(code)
}

#[tauri::command]
pub async fn list_networking_sites(
    state: State<'_, ProductionCommandState>,
) -> Result<Vec<ProductionSiteSummary>, String> {
    Ok(vec![state.status_or_error().await?.site])
}

#[tauri::command]
pub async fn get_networking_status(
    state: State<'_, ProductionCommandState>,
) -> Result<ProductionNetworkStatus, String> {
    state.status_or_error().await
}

#[tauri::command]
pub async fn connect_networking(state: State<'_, ProductionCommandState>) -> Result<ProductionNetworkStatus, String> {
    let operation = state.operation_id("connect");
    let target = state.service_for_connect().await.map_err(code)?;
    let service = Arc::clone(&target.service);
    let task_service = Arc::clone(&service);
    let reservation = target.reservation;
    tauri::async_runtime::spawn(async move {
        // Moving the non-Clone reservation into the task makes publication
        // atomic with admission.  If the task is dropped before polling,
        // `Drop` abandons the reservation and a later Connect may retry.
        let _ = task_service.connect_reserved(operation, reservation).await;
    });
    tokio::task::yield_now().await;
    Ok(service.status())
}

#[tauri::command]
pub async fn cancel_networking_operation(
    operation_id: String,
    state: State<'_, ProductionCommandState>,
) -> Result<(), String> {
    if operation_id.is_empty() || operation_id.len() > 128 {
        return Err(code(NetworkErrorCode::InvalidConfiguration));
    }
    state.cancel_exact(&operation_id).await.map_err(code)
}

#[tauri::command]
pub async fn disconnect_networking(
    state: State<'_, ProductionCommandState>,
) -> Result<ProductionNetworkStatus, String> {
    let operation = state.operation_id("disconnect");
    state.disconnect_exact(operation).await.map_err(code)
}

#[tauri::command]
pub async fn get_networking_diagnostics(
    state: State<'_, ProductionCommandState>,
) -> Result<Vec<ProductionDiagnosticEvent>, String> {
    if state.service.read().await.is_none() {
        // A configured but not-yet-materialized factory has no runtime events;
        // exposing an empty redacted stream keeps status/list usable without
        // starting a sidecar merely to answer diagnostics.
        if state.factory.read().await.is_some() {
            return Ok(Vec::new());
        }
    }
    state.service().await?.diagnostics().await.map_err(code).map(|events| {
        events
            .into_iter()
            .map(|event| ProductionDiagnosticEvent {
                sequence: event.sequence,
                operation_id: event.operation_id,
                kind: match event.kind {
                    ProductionEventKind::Started => "started",
                    ProductionEventKind::RequestCompleted => "request_completed",
                    ProductionEventKind::Cancelled => "cancelled",
                    ProductionEventKind::TimedOut => "timed_out",
                    ProductionEventKind::Restarting => "restarting",
                    ProductionEventKind::CrashLoop => "crash_loop",
                    ProductionEventKind::Stopped => "stopped",
                    ProductionEventKind::Failed => "failed",
                },
                error: event.error,
            })
            .collect()
    })
}

#[tauri::command]
pub fn get_route_helper_registration_status() -> RouteHelperRegistrationStatus {
    route_helper_registration_status()
}

#[tauri::command]
pub fn register_route_helper_service() -> Result<RouteHelperRegistrationStatus, String> {
    register_route_helper().map_err(code)?;
    Ok(route_helper_registration_status())
}

#[tauri::command]
pub fn unregister_route_helper_service() -> Result<RouteHelperRegistrationStatus, String> {
    unregister_route_helper().map_err(code)?;
    Ok(route_helper_registration_status())
}

#[tauri::command]
pub fn open_route_helper_system_settings() {
    open_route_helper_settings();
}

fn code(error: NetworkErrorCode) -> String {
    serde_json::to_string(&error).unwrap_or_else(|_| "\"invalid_configuration\"".into())
}

/// Close a service that has never been published into command state.  Build
/// and install failures must not leave a detached controller, route boundary,
/// or tunnel owner behind.  `try_retire` is the service-level proof boundary;
/// a non-retired result is surfaced as a typed failure rather than silently
/// dropping a potentially live resource owner.
async fn close_unpublished_service(service: Arc<ProductionNetworkingService>) -> Result<(), NetworkErrorCode> {
    match service.try_retire().await {
        ProductionServiceRetirementResult::Retired(_) | ProductionServiceRetirementResult::AlreadyRetired => Ok(()),
        ProductionServiceRetirementResult::Busy | ProductionServiceRetirementResult::RecoveryOnly => {
            Err(NetworkErrorCode::InvalidStateTransition)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::networking::{
        AsyncProductionRuntime, IpcRequest, IpcResponse, MihomoTunSnapshot, NetworkProfile, ProductionRouteBoundary,
        ProductionRouteDisposition, ProductionRouteRetirementResult, SidecarHandshake, SidecarLaunchContext,
        SidecarProcessStatus, TunnelDeviceFacts, spawn_production_controller,
    };

    fn disconnected_status() -> ProductionNetworkStatus {
        ProductionNetworkStatus {
            state: crate::networking::NetworkState::Disconnected,
            sidecar_state: crate::networking::SidecarLifecycleState::Stopped,
            site: ProductionSiteSummary {
                id: "site.test".into(),
                display_name: "Test".into(),
                private_route_count: 1,
            },
            active_transport: None,
            health: None,
            operation_id: None,
            last_error: None,
        }
    }

    struct CountingFactory {
        builds: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProductionServiceFactory for CountingFactory {
        fn initial_status(&self) -> ProductionNetworkStatus {
            disconnected_status()
        }

        async fn build(&self) -> Result<ProductionNetworkingService, NetworkErrorCode> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            Err(NetworkErrorCode::SidecarUnavailable)
        }
    }

    struct CountingProvider {
        initializes: Arc<AtomicUsize>,
        factory: Arc<dyn ProductionServiceFactory>,
    }

    #[async_trait]
    impl ProductionInitializationProvider for CountingProvider {
        async fn initialize(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode> {
            self.initializes.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::clone(&self.factory))
        }
    }

    struct CountingBundleProvider {
        initializes: Arc<AtomicUsize>,
        inner: BundleProductionInitializationProvider,
    }

    /// A never-started controller plus an idle route boundary is sufficient to
    /// exercise command-layer admission/CAS without launching a child or
    /// touching host routes.  The test factory still returns a complete real
    /// `ProductionNetworkingService`, so reservation and generation checks are
    /// not mocked.
    struct IdleRuntime;

    #[async_trait]
    impl AsyncProductionRuntime for IdleRuntime {
        async fn start(&mut self, _: &SidecarLaunchContext) -> Result<SidecarHandshake, NetworkErrorCode> {
            Err(NetworkErrorCode::SidecarUnavailable)
        }

        async fn request(
            &mut self,
            _: IpcRequest,
            _: Arc<std::sync::atomic::AtomicBool>,
        ) -> Result<IpcResponse, NetworkErrorCode> {
            Err(NetworkErrorCode::SidecarUnavailable)
        }

        async fn status(&mut self) -> Result<SidecarProcessStatus, NetworkErrorCode> {
            Ok(SidecarProcessStatus::Exited { success: true })
        }

        async fn stop(&mut self) -> Result<(), NetworkErrorCode> {
            Ok(())
        }
    }

    struct IdleRoutes;

    impl ProductionRouteBoundary for IdleRoutes {
        fn disposition(&self) -> ProductionRouteDisposition {
            ProductionRouteDisposition::Reusable
        }

        fn try_retire(&mut self) -> ProductionRouteRetirementResult {
            ProductionRouteRetirementResult::Retired(crate::networking::test_retirement_receipt(0))
        }

        fn apply(
            &mut self,
            _: &NetworkProfile,
            _: &str,
            _: &TunnelDeviceFacts,
            _: u64,
            _: &MihomoTunSnapshot,
        ) -> Result<(), NetworkErrorCode> {
            Err(NetworkErrorCode::InvalidStateTransition)
        }

        fn heartbeat(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            Err(NetworkErrorCode::InvalidStateTransition)
        }

        fn rollback(&mut self, _: &str) -> Result<(), NetworkErrorCode> {
            Err(NetworkErrorCode::InvalidStateTransition)
        }
    }

    struct RealServiceFactory {
        builds: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ProductionServiceFactory for RealServiceFactory {
        fn initial_status(&self) -> ProductionNetworkStatus {
            disconnected_status()
        }

        async fn build(&self) -> Result<ProductionNetworkingService, NetworkErrorCode> {
            self.builds.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            let profile: NetworkProfile =
                serde_json::from_str(include_str!("../../../schemas/fixtures/network-v1.valid.json"))
                    .map_err(|_| NetworkErrorCode::InvalidConfiguration)?;
            let controller = spawn_production_controller(
                IdleRuntime,
                SidecarLaunchContext::new("cmd-test.instance".into(), vec![1; 32]).with_private_key(vec![2; 32]),
                "proof".into(),
            );
            ProductionNetworkingService::new(controller, profile, Box::new(IdleRoutes), "cmd-test.instance".into(), 1)
        }
    }

    #[async_trait]
    impl ProductionInitializationProvider for CountingBundleProvider {
        async fn initialize(&self) -> Result<Arc<dyn ProductionServiceFactory>, NetworkErrorCode> {
            self.initializes.fetch_add(1, Ordering::SeqCst);
            self.inner.initialize().await
        }
    }

    #[tokio::test]
    async fn initialization_and_status_do_not_materialize_runtime() -> anyhow::Result<()> {
        let builds = Arc::new(AtomicUsize::new(0));
        let initializes = Arc::new(AtomicUsize::new(0));
        let factory: Arc<dyn ProductionServiceFactory> = Arc::new(CountingFactory {
            builds: Arc::clone(&builds),
        });
        let state = ProductionCommandState::default();
        state
            .configure_provider_now(Arc::new(CountingProvider {
                initializes: Arc::clone(&initializes),
                factory: Arc::clone(&factory),
            }))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        let status = state.initialize().await.map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(status.state, crate::networking::NetworkState::Disconnected);
        assert_eq!(initializes.load(Ordering::SeqCst), 1);
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        assert_eq!(
            state
                .status_or_error()
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .site
                .id,
            "site.test"
        );
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_initialization_is_single_flight() -> anyhow::Result<()> {
        let builds = Arc::new(AtomicUsize::new(0));
        let initializes = Arc::new(AtomicUsize::new(0));
        let factory: Arc<dyn ProductionServiceFactory> = Arc::new(CountingFactory { builds });
        let state = Arc::new(ProductionCommandState::default());
        state
            .configure_provider_now(Arc::new(CountingProvider {
                initializes: Arc::clone(&initializes),
                factory,
            }))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        let first_state = Arc::clone(&state);
        let second_state = Arc::clone(&state);
        let (first, second) = tokio::join!(
            tokio::spawn(async move { first_state.initialize().await }),
            tokio::spawn(async move { second_state.initialize().await }),
        );
        first
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        second
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(initializes.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn real_bundle_concurrent_initialize_and_app_restart_are_single_flight_zero_write() -> anyhow::Result<()> {
        use std::{fs, os::unix::fs::MetadataExt as _};

        let directory = tempfile::tempdir()?;
        let resource_dir = directory.path().join("KyClash.app/Contents/Resources");
        let app_data_dir = directory.path().join("app-data");
        fs::create_dir(&app_data_dir)?;
        let (envelope, public_key) = crate::networking::signed_test_policy(42, 100, 200)?;
        crate::networking::write_test_bundle_resources(&resource_dir, &envelope, &public_key, false)?;

        let initializes = Arc::new(AtomicUsize::new(0));
        let first_provider = BundleProductionInitializationProvider::new(resource_dir.clone(), app_data_dir.clone())
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
            .with_now(150);
        let state = Arc::new(ProductionCommandState::default());
        state
            .configure_provider_now(Arc::new(CountingBundleProvider {
                initializes: Arc::clone(&initializes),
                inner: first_provider,
            }))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let first_state = Arc::clone(&state);
        let second_state = Arc::clone(&state);
        let (first, second) = tokio::join!(
            tokio::spawn(async move { first_state.initialize().await }),
            tokio::spawn(async move { second_state.initialize().await }),
        );
        first
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        second
            .map_err(|error| anyhow::anyhow!("{error}"))?
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(initializes.load(Ordering::SeqCst), 1);
        assert!(state.factory.read().await.is_some());
        assert!(state.service.read().await.is_none());

        let record_path = app_data_dir.join("networking/policy-revision.json");
        let before_bytes = fs::read(&record_path)?;
        let before = fs::metadata(&record_path)?;
        let restarted = ProductionCommandState::default();
        let restarted_provider = BundleProductionInitializationProvider::new(resource_dir, app_data_dir)
            .map_err(|error| anyhow::anyhow!("{error:?}"))?
            .with_now(151);
        restarted
            .configure_provider_now(Arc::new(CountingBundleProvider {
                initializes: Arc::clone(&initializes),
                inner: restarted_provider,
            }))
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        let status = restarted
            .initialize()
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(status.state, crate::networking::NetworkState::Disconnected);
        assert!(restarted.service.read().await.is_none());
        let after = fs::metadata(&record_path)?;
        assert_eq!(fs::read(&record_path)?, before_bytes);
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.mtime(), before.mtime());
        assert_eq!(after.mtime_nsec(), before.mtime_nsec());
        assert_eq!(initializes.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test]
    async fn connect_is_the_only_path_that_materializes_a_registered_factory() -> anyhow::Result<()> {
        let builds = Arc::new(AtomicUsize::new(0));
        let factory: Arc<dyn ProductionServiceFactory> = Arc::new(CountingFactory {
            builds: Arc::clone(&builds),
        });
        let state = ProductionCommandState::default();
        state
            .configure_factory(factory)
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        assert_eq!(
            state
                .status_or_error()
                .await
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .state,
            crate::networking::NetworkState::Disconnected
        );
        assert_eq!(builds.load(Ordering::SeqCst), 0);

        assert!(matches!(
            state.service_for_connect().await,
            Err(NetworkErrorCode::SidecarUnavailable)
        ));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_factory_registration_keeps_service_factory_exclusive() -> anyhow::Result<()> {
        let first: Arc<dyn ProductionServiceFactory> = Arc::new(CountingFactory {
            builds: Arc::new(AtomicUsize::new(0)),
        });
        let second: Arc<dyn ProductionServiceFactory> = Arc::new(CountingFactory {
            builds: Arc::new(AtomicUsize::new(0)),
        });
        let state = Arc::new(ProductionCommandState::default());
        let first_state = Arc::clone(&state);
        let second_state = Arc::clone(&state);
        let (first_result, second_result) =
            tokio::join!(async move { first_state.configure_factory(first).await }, async move {
                second_state.configure_factory(second).await
            },);
        let successful = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
        assert_eq!(successful, 1);
        assert!(matches!(
            (first_result, second_result),
            (Err(NetworkErrorCode::InvalidStateTransition), Ok(_))
                | (Ok(_), Err(NetworkErrorCode::InvalidStateTransition))
        ));
        assert!(state.factory.read().await.is_some());
        assert!(state.service.read().await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_connect_selection_issues_at_most_one_generation_reservation() -> anyhow::Result<()> {
        let builds = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(ProductionCommandState::default());
        state
            .configure_factory(Arc::new(RealServiceFactory {
                builds: Arc::clone(&builds),
            }))
            .await
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;

        let first_state = Arc::clone(&state);
        let second_state = Arc::clone(&state);
        let (first, second) = tokio::join!(
            tokio::spawn(async move { first_state.service_for_connect().await }),
            tokio::spawn(async move { second_state.service_for_connect().await }),
        );
        let first = first.map_err(|error| anyhow::anyhow!("{error}"))?;
        let second = second.map_err(|error| anyhow::anyhow!("{error}"))?;
        let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
        assert_eq!(successes, 1, "two Connect calls accepted the same generation");
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        drop(first);
        drop(second);
        assert!(state.service.read().await.is_some());
        Ok(())
    }

    #[test]
    fn production_diagnostic_serialization_is_a_secret_free_allowlist() -> anyhow::Result<()> {
        let event = ProductionDiagnosticEvent {
            sequence: 7,
            operation_id: Some("networking.production.connect.7".into()),
            kind: "failed",
            error: Some(NetworkErrorCode::AuthenticationFailed),
        };
        let encoded = serde_json::to_string(&event)?;
        for forbidden in [
            "profile",
            "endpoint",
            "identity_ref",
            "signature",
            "private_key",
            "keychain:",
            "payload_base64",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded)?
                .as_object()
                .map(|object| object.len()),
            Some(4)
        );
        Ok(())
    }
}
