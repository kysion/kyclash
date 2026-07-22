use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use tauri::{AppHandle, Manager as _, State};
use tokio::sync::{Mutex, RwLock};

use crate::networking::{
    BundleProductionInitializationProvider, NetworkErrorCode, ProductionEventKind, ProductionInitializationProvider,
    ProductionNetworkStatus, ProductionNetworkingService, ProductionServiceFactory, ProductionSiteSummary,
    RouteHelperRegistrationStatus, open_route_helper_settings, register_route_helper, route_helper_registration_status,
    unregister_route_helper,
};

pub struct ProductionCommandState {
    service: RwLock<Option<Arc<ProductionNetworkingService>>>,
    factory: RwLock<Option<Arc<dyn ProductionServiceFactory>>>,
    provider: RwLock<Option<Arc<dyn ProductionInitializationProvider>>>,
    materialize: Mutex<()>,
    sequence: AtomicU64,
}

impl Default for ProductionCommandState {
    fn default() -> Self {
        Self {
            service: RwLock::new(None),
            factory: RwLock::new(None),
            provider: RwLock::new(None),
            materialize: Mutex::new(()),
            sequence: AtomicU64::new(0),
        }
    }
}

impl ProductionCommandState {
    #[allow(dead_code)]
    pub async fn configure(&self, service: ProductionNetworkingService) -> Result<(), NetworkErrorCode> {
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
    pub async fn configure_factory(&self, factory: Arc<dyn ProductionServiceFactory>) -> Result<(), NetworkErrorCode> {
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
            self.configure_factory(factory).await?;
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

    async fn service_for_connect(&self) -> Result<Arc<ProductionNetworkingService>, String> {
        let existing = self.service.read().await.clone();
        if let Some(service) = existing {
            return Ok(service);
        }
        let _guard = self.materialize.lock().await;
        let existing = self.service.read().await.clone();
        if let Some(service) = existing {
            return Ok(service);
        }
        let factory = self
            .factory
            .read()
            .await
            .clone()
            .ok_or_else(|| code(NetworkErrorCode::InvalidConfiguration))?;
        let service = Arc::new(factory.build().await.map_err(code)?);
        *self.service.write().await = Some(Arc::clone(&service));
        Ok(service)
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
    let revision_path = app
        .path()
        .app_data_dir()
        .map_err(|_| NetworkErrorCode::InvalidConfiguration)?
        .join("networking")
        .join("policy-revision.json");
    let provider = BundleProductionInitializationProvider::new(resource_dir, revision_path)?;
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
    let service = state.service_for_connect().await?;
    let task_service = Arc::clone(&service);
    tauri::async_runtime::spawn(async move {
        let _ = task_service.connect(operation).await;
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
    state.service().await?.cancel(&operation_id).map_err(code)
}

#[tauri::command]
pub async fn disconnect_networking(
    state: State<'_, ProductionCommandState>,
) -> Result<ProductionNetworkStatus, String> {
    let operation = state.operation_id("disconnect");
    state.service().await?.disconnect(operation).await.map_err(code)
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;

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
            Err(ref error) if error == &code(NetworkErrorCode::SidecarUnavailable)
        ));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
