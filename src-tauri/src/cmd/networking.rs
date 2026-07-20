use crate::networking::{NetworkState, NetworkingDevStatus, SidecarLifecycleState, networking_dev_status};

#[tauri::command]
pub const fn get_networking_dev_status() -> NetworkingDevStatus {
    networking_dev_status(NetworkState::Disconnected, SidecarLifecycleState::Stopped)
}
