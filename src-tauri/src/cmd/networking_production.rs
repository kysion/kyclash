use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde::Serialize;
use tauri::State;
use tokio::sync::RwLock;

use crate::networking::{
    NetworkErrorCode, ProductionEventKind, ProductionNetworkStatus, ProductionNetworkingService, ProductionSiteSummary,
};

#[derive(Default)]
pub struct ProductionCommandState {
    service: RwLock<Option<Arc<ProductionNetworkingService>>>,
    sequence: AtomicU64,
}

impl ProductionCommandState {
    #[allow(dead_code)]
    pub async fn configure(&self, service: ProductionNetworkingService) -> Result<(), NetworkErrorCode> {
        let mut slot = self.service.write().await;
        if slot.is_some() {
            return Err(NetworkErrorCode::InvalidStateTransition);
        }
        *slot = Some(Arc::new(service));
        drop(slot);
        Ok(())
    }

    async fn service(&self) -> Result<Arc<ProductionNetworkingService>, String> {
        self.service
            .read()
            .await
            .clone()
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

#[tauri::command]
pub async fn list_networking_sites(
    state: State<'_, ProductionCommandState>,
) -> Result<Vec<ProductionSiteSummary>, String> {
    Ok(vec![state.service().await?.status().site])
}

#[tauri::command]
pub async fn get_networking_status(
    state: State<'_, ProductionCommandState>,
) -> Result<ProductionNetworkStatus, String> {
    Ok(state.service().await?.status())
}

#[tauri::command]
pub async fn connect_networking(state: State<'_, ProductionCommandState>) -> Result<ProductionNetworkStatus, String> {
    let operation = state.operation_id("connect");
    let service = state.service().await?;
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

fn code(error: NetworkErrorCode) -> String {
    serde_json::to_string(&error).unwrap_or_else(|_| "\"invalid_configuration\"".into())
}
